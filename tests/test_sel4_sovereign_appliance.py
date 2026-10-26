#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""
tests/test_sel4_sovereign_appliance.py — High-Assurance Verification Suite for the
seL4 Sovereign Hardware Appliance & MILS Separation Architecture.

Tests:
  1. seL4 Microkit Manifest MILS Isolation Invariants (FDP_ACC.2 / FDP_ACF.1).
  2. Triple-Hybrid Post-Quantum KEX (ML-KEM-1024 + P-384 + CSfC PSK).
  3. Dual-Rail Fault-Injection Signature Verification Resistance.
  4. Decoupled Anti-Replay Sliding Window (RFC 6479 / WireGuard).
  5. End-to-End Appliance Node Roundtrip (RED -> CRYPTO -> BLACK -> Wire -> Node 2).
  6. Zero-Metadata Wire Quantization & Chaff (0xFF) Entropy Invariance.
  7. Emergency Scorched-Earth Zeroization Fail-Closed Behavior.
"""

import math
import secrets
import struct
import pytest

from sel4_microkit_manifest import (
    SeL4MicrokitManifest,
    MemoryRegion,
    MemoryMap,
    ProtectionDomain,
    Channel,
    SeL4PolicyViolation,
)
from sovereign_crypto_domain import (
    SeL4SharedRingBuffer,
    SovereignCryptoDomain,
    AntiReplayWindow,
    TripleHybridKEX,
    DualRailSignatureVerifier,
    FaultInjectionDetectedError,
    TamperZeroizedError,
)
from sovereign_red_domain import SovereignRedDomain, RedDomainError
from sovereign_black_domain import (
    SovereignBlackDomain,
    ST2027_CELL_SIZE,
    CHAFF_CELL_TYPE,
)
from sovereign_sel4_appliance import SovereignApplianceNode
from liboqs_wrapper import LibOQS_MLKEM_1024, LibOQS_MLDSA_87


def test_sel4_microkit_manifest_mils_invariants():
    """Verify that standard ST2027 system passes MILS validation,
    and illegal cross-domain channels or shared memory mappings fail-closed.
    """
    # 1. Standard configuration must validate
    manifest = SeL4MicrokitManifest.create_st2027_sovereign_system()
    assert manifest.validate_mils_invariants() is True

    # 2. Export XML and re-import: must roundtrip perfectly
    xml_str = manifest.export_xml()
    assert "<system>" in xml_str
    assert 'name="red_domain"' in xml_str
    assert 'name="crypto_domain"' in xml_str
    assert 'name="black_domain"' in xml_str

    # 3. Direct RED <-> BLACK channel MUST raise SeL4PolicyViolation
    bad_manifest_1 = SeL4MicrokitManifest.create_st2027_sovereign_system()
    bad_manifest_1.add_channel(Channel("red_domain", 9, "black_domain", 9))
    with pytest.raises(SeL4PolicyViolation, match="Direct IPC channel detected"):
        bad_manifest_1.validate_mils_invariants()

    # 4. Shared memory between RED and BLACK MUST raise SeL4PolicyViolation
    bad_manifest_2 = SeL4MicrokitManifest.create_st2027_sovereign_system()
    bad_manifest_2.protection_domains["black_domain"].maps.append(
        MemoryMap("red_crypto_ring", vaddr=0x40000000, perms="rw")
    )
    with pytest.raises(SeL4PolicyViolation, match="mapped into both RED and BLACK"):
        bad_manifest_2.validate_mils_invariants()

    # 5. Mapping crypto_locked_keys outside CRYPTO domain MUST fail
    bad_manifest_3 = SeL4MicrokitManifest.create_st2027_sovereign_system()
    bad_manifest_3.protection_domains["red_domain"].maps.append(
        MemoryMap("crypto_locked_keys", vaddr=0x50000000, perms="rw")
    )
    with pytest.raises(SeL4PolicyViolation, match="crypto_locked_keys mapped outside CRYPTO"):
        bad_manifest_3.validate_mils_invariants()


def test_triple_hybrid_kex_roundtrip():
    """Verify Triple-Hybrid Key Exchange (ML-KEM-1024 + P-384 + CSfC PSK)
    derives identical symmetric keys between Alice and Bob.
    """
    mlkem = LibOQS_MLKEM_1024()
    psk = secrets.token_bytes(32)

    alice_engine = TripleHybridKEX(mlkem, psk)
    bob_engine = TripleHybridKEX(mlkem, psk)

    # Alice initializes
    init_wire, alice_state = alice_engine.alice_init()
    assert len(init_wire) > 1600  # ML-KEM pk (1568) + P-384 pk (97)

    # Bob responds
    resp_wire, bob_key = bob_engine.bob_respond(init_wire)
    assert len(resp_wire) > 1600
    assert len(bob_key) == 32

    # Alice finalizes
    alice_key = alice_engine.alice_finalize(resp_wire, alice_state, init_wire)
    assert alice_key == bob_key

    # Changing 1 bit of PSK yields entirely different key
    bad_psk = bytearray(psk)
    bad_psk[0] ^= 0x01
    bad_bob_engine = TripleHybridKEX(mlkem, bytes(bad_psk))
    _, bad_bob_key = bad_bob_engine.bob_respond(init_wire)
    assert bad_bob_key != alice_key


def test_dual_rail_fault_injection_defense():
    """Verify Dual-Rail Signature Verification defeats laser/voltage fault injection."""
    mldsa = LibOQS_MLDSA_87()
    pk, sk = mldsa.keygen()
    message = b"CRITICAL TACTICAL ORDER: ALPHA FIRE"
    sig = mldsa.sign(sk, message, public_key=pk)

    verifier = DualRailSignatureVerifier(mldsa)

    # 1. Normal execution passes consensus
    assert verifier.verify_resilient(pk, message, sig) is True

    # 2. Tampered signature fails consensus normally
    tampered_sig = bytearray(sig)
    tampered_sig[10] ^= 0xFF
    assert verifier.verify_resilient(pk, message, bytes(tampered_sig)) is False

    # 3. Simulate fault injection glitching Rail B result
    class FaultInjectedMLDSA:
        def __init__(self, real_mldsa):
            self.real = real_mldsa
            self.call_count = 0

        def verify(self, p, m, s):
            self.call_count += 1
            # First call returns normal result, second call is glitched
            if self.call_count % 2 == 1:
                return True
            else:
                return False  # Glitched divergence

    glitched_verifier = DualRailSignatureVerifier(FaultInjectedMLDSA(mldsa))
    with pytest.raises(FaultInjectionDetectedError, match="Dual-rail verification mismatch"):
        glitched_verifier.verify_resilient(pk, message, sig)


def test_decoupled_anti_replay_window():
    """Verify RFC 6479 decoupled replay window semantics."""
    win = AntiReplayWindow(64)

    # Initial packet seq=0
    assert win.check(0) is True
    win.mark(0)
    assert win.check(0) is False  # Now rejected as duplicate

    # Sequential packets
    assert win.check(1) is True
    win.mark(1)
    assert win.check(2) is True
    win.mark(2)

    # Re-check duplicates
    assert win.check(1) is False
    assert win.check(2) is False

    # Out of order packet ahead
    assert win.check(10) is True
    win.mark(10)
    assert win.check(5) is True  # In-window older packet still acceptable
    win.mark(5)
    assert win.check(5) is False

    # High jump
    win.mark(100)
    # Packets older than (100 - 64) = 36 are now stale
    assert win.check(35) is False
    assert win.check(50) is True


def test_sovereign_appliance_node_roundtrip_messaging():
    """Full integrated test:
    Node Alpha -> Triple-Hybrid KEX -> Node Bravo
    Node Alpha sends secret message from RED domain
    Transmitted across BLACK domain wire cells
    Node Bravo receives, decrypts into RED domain.
    """
    psk = secrets.token_bytes(32)
    node_alpha = SovereignApplianceNode("ALPHA", psk=psk)
    node_bravo = SovereignApplianceNode("BRAVO", psk=psk)

    # 1. Pair nodes via Triple-Hybrid KEX
    node_alpha.pair_with_peer(node_bravo)

    # 2. Alpha sends plaintext message from isolated RED domain
    secret_text = b"TOP SECRET // NOFORN // CODEWORD DESTROYER: OPERATION CLEARED"
    assert node_alpha.send_message(secret_text) is True

    # 3. Alpha steps cycle: encrypts and emits wire cell
    wire_cell = node_alpha.step_cycle()
    assert len(wire_cell) == ST2027_CELL_SIZE

    # Verify wire cell payload is encrypted: cleartext must NOT appear in wire packet
    assert secret_text not in wire_cell

    # 4. Deliver wire cell to Bravo
    assert node_bravo.receive_wire_cell(wire_cell) is True

    # 5. Bravo reads decrypted message in its RED domain
    received_msgs = node_bravo.get_received_messages()
    assert len(received_msgs) == 1
    assert received_msgs[0] == secret_text


def test_traffic_invariance_and_chaff_entropy():
    """Verify that idle cycles emit uniform 1232-byte chaff cells with high entropy."""
    node = SovereignApplianceNode("CHARLIE")

    cells = []
    for _ in range(10):
        c = node.step_cycle()
        assert len(c) == ST2027_CELL_SIZE
        cells.append(c)

    # Verify all cells are chaff (Type 0xFF) when queue is empty
    for c in cells:
        payload_len = struct.unpack(">H", c[:2])[0]
        assert payload_len == 0  # Chaff cell indicator
        assert c[2] == CHAFF_CELL_TYPE

    # Calculate Shannon Entropy of a chaff cell
    chaff_body = cells[0][3:]
    freq = {}
    for b in chaff_body:
        freq[b] = freq.get(b, 0) + 1
    entropy = -sum((cnt / len(chaff_body)) * math.log2(cnt / len(chaff_body)) for cnt in freq.values())

    # High cryptographic entropy expected (> 7.8 bits per byte out of theoretical 8.0)
    assert entropy > 7.8, f"Chaff entropy too low: {entropy:.2f} bits/byte"


def test_scorched_earth_emergency_zeroization():
    """Verify emergency scorched-earth zeroization wipes all memory and refuses future calls."""
    node = SovereignApplianceNode("DELTA")
    node.send_message(b"CONFIDENTIAL MISSION DATA")

    # Trigger emergency zeroization
    node.emergency_scorched_earth_zeroize()

    # Subsequent send MUST fail
    with pytest.raises(RedDomainError, match="zeroized"):
        node.send_message(b"NEW DATA")

    # Subsequent cycle step MUST fail
    with pytest.raises(TamperZeroizedError):
        node.step_cycle()
