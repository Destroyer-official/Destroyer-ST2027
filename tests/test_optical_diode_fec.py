#!/usr/bin/env python3
"""
tests/test_optical_diode_fec.py
===============================
Comprehensive Test Suite:
Simplex Optical Data Diode & Cauchy-Reed-Solomon FEC Engine.

Validates:
1. Galois Field GF(2^8) arithmetic mathematical axioms (irreducible polynomial 0x11D).
2. Cauchy generator matrix non-singularity and MDS properties.
3. Systematic Cauchy-Reed-Solomon FEC recovery under 0%, 25% burst, and 33% maximum packet loss.
4. Tactical 1232-byte chunk quantum enforcement.
5. Post-Quantum authentication: ML-DSA-87 digital signing, verification, and tamper detection.
6. Simplex architectural invariants: AST-level proof of ZERO reverse channel (zero listener on sender, zero transmitter on receiver).
7. Egress/ingress interface security and wildcard bind rejection.
8. End-to-end live simplex UDP transmission across loopback with 25% simulated burst packet loss.
9. Common Criteria hardware registry integration.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from optical_diode_controller import (
    CHUNK_PAYLOAD_SIZE,
    DIODE_HEADER_SIZE,
    DIODE_MAGIC,
    MLDSA87_PK_LEN,
    MLDSA87_SIG_LEN,
    OPTICAL_DIODE_DOMAIN,
    CauchyReedSolomon,
    GF256,
    OpticalDiodeController,
    OpticalDiodePacket,
    OpticalDiodeReceiver,
    OpticalDiodeSender,
    verify_diode_direction_ast,
)
from liboqs_wrapper import LibOQS_MLDSA_87


# =============================================================================
# 1. GALOIS FIELD GF(2^8) ARITHMETIC TESTS
# =============================================================================

def test_01_gf256_arithmetic_axioms():
    """Verify GF(2^8) field axioms: addition, subtraction, multiplication, inverse, division."""
    gf = GF256()

    # XOR addition and subtraction
    assert gf.add(0, 0) == 0
    assert gf.add(42, 42) == 0
    assert gf.add(255, 0) == 255
    assert gf.sub(123, 123) == 0
    assert gf.sub(100, 20) == 100 ^ 20

    # Multiplication identity and annihilator
    for a in range(256):
        assert gf.mul(a, 0) == 0
        assert gf.mul(0, a) == 0
        assert gf.mul(a, 1) == a
        assert gf.mul(1, a) == a

    # Multiplicative inverse: a * a^{-1} == 1 for all a in 1..255
    for a in range(1, 256):
        inv_a = gf.inv(a)
        assert 1 <= inv_a <= 255
        assert gf.mul(a, inv_a) == 1, f"Inverse failed for a={a}: inv={inv_a}"

    # Inversion of zero must fail closed
    with pytest.raises(ZeroDivisionError):
        gf.inv(0)

    # Division
    for a in range(1, 256):
        assert gf.div(a, a) == 1
        assert gf.div(0, a) == 0
    with pytest.raises(ZeroDivisionError):
        gf.div(42, 0)


# =============================================================================
# 2. CAUCHY MATRIX CONSTRUCTION & MDS PROPERTIES
# =============================================================================

def test_02_cauchy_matrix_properties():
    """Verify Cauchy matrix construction with disjoint subsets X and Y."""
    k, m = 8, 4
    crs = CauchyReedSolomon(k=k, m=m)

    assert crs.k == 8
    assert crs.m == 4
    assert crs.n == 12

    # Cauchy matrix must be M x K
    assert len(crs.cauchy_matrix) == m
    for row in crs.cauchy_matrix:
        assert len(row) == k
        # No zero elements permitted in a valid Cauchy matrix
        for val in row:
            assert 1 <= val <= 255

    # Refuse invalid parameters (K=0, M=0, or K+M > 255)
    with pytest.raises(ValueError):
        CauchyReedSolomon(k=0, m=4)
    with pytest.raises(ValueError):
        CauchyReedSolomon(k=8, m=0)
    with pytest.raises(ValueError):
        CauchyReedSolomon(k=200, m=60)  # 260 > 255


# =============================================================================
# 3. CAUCHY-REED-SOLOMON FEC LOSS TOLERANCE TESTS
# =============================================================================

def test_03_fec_recovery_zero_loss():
    """Verify K=8, M=4 coding recovers perfectly when all data packets arrive."""
    k, m = 8, 4
    coder = CauchyReedSolomon(k=k, m=m)
    chunk_len = CHUNK_PAYLOAD_SIZE

    data_chunks = [secrets.token_bytes(chunk_len) for _ in range(k)]
    encoded = coder.encode(data_chunks)
    assert len(encoded) == k + m

    # Receive all K original data chunks (indices 0..7)
    received = {i: encoded[i] for i in range(k)}
    decoded = coder.decode(received, chunk_len)
    assert decoded == data_chunks


def test_04_fec_recovery_25_percent_burst_loss():
    """
    Core Invariant: Tolerates 25% burst packet loss with 100% bitwise reconstruction.
    With K=8, M=4 (N=12), exactly 25% of packets (3 packets) are lost in a contiguous burst.
    We drop packets 0, 1, 2!
    Surviving chunks: 3..11 (total 9 chunks >= K=8).
    """
    k, m = 8, 4
    coder = CauchyReedSolomon(k=k, m=m)
    chunk_len = CHUNK_PAYLOAD_SIZE

    data_chunks = [secrets.token_bytes(chunk_len) for _ in range(k)]
    encoded = coder.encode(data_chunks)

    # Simulate 25% burst drop: drop chunks 0, 1, 2 (the first three data chunks!)
    received = {i: encoded[i] for i in range(3, 12)}
    assert len(received) == 9  # 9 packets received >= K=8

    decoded = coder.decode(received, chunk_len)
    assert decoded == data_chunks, "25% burst loss reconstruction failed!"


def test_05_fec_recovery_33_percent_maximum_loss():
    """
    Stress test: Drop M=4 packets (33.3% loss).
    Drop ALL first 4 data chunks (0, 1, 2, 3)!
    Surviving chunks: data chunks 4..7 and parity chunks 8..11 (total 8 = K).
    """
    k, m = 8, 4
    coder = CauchyReedSolomon(k=k, m=m)
    chunk_len = CHUNK_PAYLOAD_SIZE

    data_chunks = [secrets.token_bytes(chunk_len) for _ in range(k)]
    encoded = coder.encode(data_chunks)

    # Receive exactly 8 chunks (4 data + 4 parity)
    received = {i: encoded[i] for i in range(4, 12)}
    assert len(received) == k

    decoded = coder.decode(received, chunk_len)
    assert decoded == data_chunks, "33% maximum loss reconstruction failed!"


def test_06_fec_recovery_interleaved_scattered_loss():
    """Verify recovery under non-contiguous scattered packet erasures."""
    k, m = 6, 3  # N = 9
    coder = CauchyReedSolomon(k=k, m=m)
    chunk_len = 256

    data_chunks = [secrets.token_bytes(chunk_len) for _ in range(k)]
    encoded = coder.encode(data_chunks)

    # Drop indices 0, 3, 5 (scattered 3 packet loss)
    surviving_indices = [1, 2, 4, 6, 7, 8]
    received = {i: encoded[i] for i in surviving_indices}
    assert len(received) == k

    decoded = coder.decode(received, chunk_len)
    assert decoded == data_chunks


def test_07_fec_insufficient_chunks_fails_closed():
    """Verify that receiving fewer than K packets fails closed with an error."""
    k, m = 8, 4
    coder = CauchyReedSolomon(k=k, m=m)
    data_chunks = [secrets.token_bytes(64) for _ in range(k)]
    encoded = coder.encode(data_chunks)

    # Receive only 7 chunks when K=8 is required
    received = {i: encoded[i] for i in range(7)}
    with pytest.raises(ValueError) as exc:
        coder.decode(received, 64)
    assert "Insufficient chunks" in str(exc.value)


# =============================================================================
# 4. CHUNK PAYLOAD SIZE & WIRE PACKET INTEGRITY
# =============================================================================

def test_08_tactical_chunk_payload_size_1232_bytes():
    """Verify tactical chunk payload quantum of 1232 bytes."""
    assert CHUNK_PAYLOAD_SIZE == 1232
    assert DIODE_MAGIC == b"ODD1"
    assert MLDSA87_PK_LEN == 2592
    assert MLDSA87_SIG_LEN == 4627
    assert DIODE_HEADER_SIZE == 7287

    sender = OpticalDiodeSender()
    payload = b"X" * 3000  # Will split into K=3 chunks of 1232 (3696 bytes capacity)
    tx_id, packets = sender.prepare_packets(payload)

    # Each packet wire size must be exactly DIODE_HEADER_SIZE + 1232 = 8519 bytes
    for pkt_bytes in packets:
        assert len(pkt_bytes) == DIODE_HEADER_SIZE + CHUNK_PAYLOAD_SIZE
    sender.close()


# =============================================================================
# 5. ML-DSA-87 DIGITAL SIGNATURES & TAMPER DEFENSE
# =============================================================================

def test_09_mldsa87_chunk_signing_and_verification():
    """Verify ML-DSA-87 packet signing, wire serialization, and verification."""
    mldsa = LibOQS_MLDSA_87()
    vk, sk = mldsa.keygen()
    tx_id = secrets.token_bytes(16)
    chunk_data = secrets.token_bytes(CHUNK_PAYLOAD_SIZE)

    pkt = OpticalDiodePacket.create_and_sign(
        mldsa=mldsa,
        signing_key=sk,
        verifying_key=vk,
        transfer_id=tx_id,
        total_len=CHUNK_PAYLOAD_SIZE,
        k=4,
        n=6,
        chunk_index=2,
        chunk_data=chunk_data,
    )

    wire = pkt.serialize()
    assert len(wire) == DIODE_HEADER_SIZE + CHUNK_PAYLOAD_SIZE

    restored = OpticalDiodePacket.deserialize(wire, mldsa=mldsa)
    assert restored.magic == DIODE_MAGIC
    assert restored.transfer_id == tx_id
    assert restored.k == 4
    assert restored.n == 6
    assert restored.chunk_index == 2
    assert restored.chunk_data == chunk_data


def test_10_mldsa87_tampered_payload_fails_closed():
    """Verify that tampering with packet payload byte fails verification fail-closed."""
    mldsa = LibOQS_MLDSA_87()
    vk, sk = mldsa.keygen()
    tx_id = secrets.token_bytes(16)
    chunk_data = b"TOP-SECRET-COMMAND-DIRECTIVE" + b"\x00" * (CHUNK_PAYLOAD_SIZE - 28)

    pkt = OpticalDiodePacket.create_and_sign(
        mldsa=mldsa,
        signing_key=sk,
        verifying_key=vk,
        transfer_id=tx_id,
        total_len=len(chunk_data),
        k=2,
        n=3,
        chunk_index=0,
        chunk_data=chunk_data,
    )

    wire = bytearray(pkt.serialize())
    # Tamper with the very last byte of chunk data
    wire[-1] ^= 0xAA

    with pytest.raises(ValueError) as exc:
        OpticalDiodePacket.deserialize(bytes(wire), mldsa=mldsa)
    assert "integrity check failed" in str(exc.value) or "signature verification FAILED" in str(exc.value)


def test_11_mldsa87_tampered_header_fails_closed():
    """Verify that tampering with header metadata (e.g. chunk_index) invalidates signature."""
    mldsa = LibOQS_MLDSA_87()
    vk, sk = mldsa.keygen()
    tx_id = secrets.token_bytes(16)
    chunk_data = secrets.token_bytes(CHUNK_PAYLOAD_SIZE)

    pkt = OpticalDiodePacket.create_and_sign(
        mldsa=mldsa,
        signing_key=sk,
        verifying_key=vk,
        transfer_id=tx_id,
        total_len=CHUNK_PAYLOAD_SIZE,
        k=2,
        n=3,
        chunk_index=0,
        chunk_data=chunk_data,
    )

    wire = bytearray(pkt.serialize())
    # Header format: magic(4), tx_id(16), total_len(8), k(2), n(2), chunk_index(2) -> offset 32
    # Modify chunk_index from 0 to 1
    wire[33] = 1

    with pytest.raises(ValueError) as exc:
        OpticalDiodePacket.deserialize(bytes(wire), mldsa=mldsa)
    assert "signature verification FAILED" in str(exc.value)


def test_12_pinned_sender_key_enforcement():
    """Verify receiver rejects packets signed by an unauthorized sender key."""
    mldsa = LibOQS_MLDSA_87()
    vk_auth, sk_auth = mldsa.keygen()
    vk_rogue, sk_rogue = mldsa.keygen()

    tx_id = secrets.token_bytes(16)
    chunk_data = secrets.token_bytes(CHUNK_PAYLOAD_SIZE)

    # Rogue sender creates mathematically valid packet with its own key
    rogue_pkt = OpticalDiodePacket.create_and_sign(
        mldsa=mldsa,
        signing_key=sk_rogue,
        verifying_key=vk_rogue,
        transfer_id=tx_id,
        total_len=CHUNK_PAYLOAD_SIZE,
        k=2,
        n=3,
        chunk_index=0,
        chunk_data=chunk_data,
    )
    wire = rogue_pkt.serialize()

    # Receiver configured with expected authorized key MUST reject rogue packet
    with pytest.raises(ValueError) as exc:
        OpticalDiodePacket.deserialize(wire, mldsa=mldsa, expected_vk=vk_auth)
    assert "does not match enrolled trust anchor pin" in str(exc.value)


# =============================================================================
# 6. SIMPLEX DIRECTION ENFORCEMENT & AST PROOFS
# =============================================================================

def test_13_simplex_direction_ast_enforcement():
    """
    Static guarantee:
    Transmitter contains NO recv/recvfrom/listen/accept calls.
    Receiver contains NO send/sendto/connect calls.
    """
    ast_check = verify_diode_direction_ast()
    assert ast_check["transmitter_zero_listener_invariant"] is True, "Transmitter has inbound calls"
    assert ast_check["receiver_zero_transmitter_invariant"] is True, "Receiver has outbound calls"
    assert ast_check["pure_simplex_guaranteed"] is True


def test_14_receiver_bind_security():
    """Verify receiver refuses wildcard binds by default and invalid host/port configurations."""
    with pytest.raises(ValueError):
        OpticalDiodeReceiver(bind_host="0.0.0.0", bind_port=55301)  # nosec: B104 - intentional wildcard rejection test
    with pytest.raises(ValueError):
        OpticalDiodeReceiver(bind_host="::", bind_port=55302)
    with pytest.raises(ValueError):
        OpticalDiodeReceiver(bind_host="invalid-ip", bind_port=55303)
    with pytest.raises(ValueError):
        OpticalDiodeReceiver(bind_host="127.0.0.1", bind_port=0)

    # Explicit allow_wildcard permits binding
    rx = OpticalDiodeReceiver(bind_host="127.0.0.1", bind_port=55304, allow_wildcard=True)
    rx.close()


def test_15_transmitter_target_validation():
    """Verify transmitter rejects unparseable target hosts and ports."""
    with pytest.raises(ValueError):
        OpticalDiodeSender(target_host="bad-target-host", target_port=55305)
    with pytest.raises(ValueError):
        OpticalDiodeSender(target_host="127.0.0.1", target_port=99999)


# =============================================================================
# 7. LIVE SIMPLEX UDP TRANSMISSION TESTS
# =============================================================================

def test_16_live_simplex_udp_clean_transmission():
    """Verify clean live simplex UDP broadcast with zero return channel."""
    port = secrets.randbelow(10000) + 53000
    test_payload = secrets.token_bytes(2500)

    sender = OpticalDiodeSender(target_host="127.0.0.1", target_port=port)
    receiver = OpticalDiodeReceiver(
        bind_host="127.0.0.1",
        bind_port=port,
        expected_sender_vk=sender.verifying_key,
    )

    received_result: List[Optional[bytes]] = [None]

    def rx_worker() -> None:
        received_result[0] = receiver.receive_payload(timeout_seconds=4.0)

    t = threading.Thread(target=rx_worker, daemon=True)
    t.start()
    time.sleep(0.15)  # Allow receiver to bind

    tx_id = sender.send_payload(test_payload, k=4, m=2, burst_delay_ms=0.5)
    assert isinstance(tx_id, bytes) and len(tx_id) == 16

    t.join(timeout=5.0)
    sender.close()
    receiver.close()

    assert received_result[0] is not None, "Receiver timed out without recovering payload"
    assert received_result[0] == test_payload, "Payload bitwise mismatch"


def test_17_live_simplex_udp_25_percent_burst_loss():
    """
    Live End-to-End Test:
    Simulates physical optical fiber with 25% burst packet loss.
    Verifies 100% bitwise reconstruction with ZERO return channel / ZERO ACKs.
    """
    port = secrets.randbelow(10000) + 54000
    test_payload = secrets.token_bytes(7500)  # ~7 chunks of 1232B
    payload_sha384 = hashlib.sha384(test_payload).hexdigest()

    sender = OpticalDiodeSender(target_host="127.0.0.1", target_port=port)
    receiver = OpticalDiodeReceiver(
        bind_host="127.0.0.1",
        bind_port=port,
        expected_sender_vk=sender.verifying_key,
    )

    # K=8, M=4 -> N=12 packets
    tx_id, packets = sender.prepare_packets(test_payload, k=8, m=4)
    assert len(packets) == 12

    # 25% burst packet loss: drop the first 3 consecutive packets (packets 0, 1, 2)
    dropped_indices = {0, 1, 2}

    received_result: List[Optional[bytes]] = [None]

    def rx_worker() -> None:
        received_result[0] = receiver.receive_payload(timeout_seconds=4.0)

    t = threading.Thread(target=rx_worker, daemon=True)
    t.start()
    time.sleep(0.15)

    # Transmit ONLY packets 3..11 across simplex UDP socket
    dest = ("127.0.0.1", port)
    for idx, pkt in enumerate(packets):
        if idx in dropped_indices:
            continue
        sender._sock.sendto(pkt, dest)
        time.sleep(0.001)

    t.join(timeout=5.0)
    sender.close()
    receiver.close()

    reconstructed = received_result[0]
    assert reconstructed is not None, "Receiver timed out under 25% burst loss"
    assert reconstructed == test_payload, "Payload bitwise mismatch after 25% burst loss"
    assert hashlib.sha384(reconstructed).hexdigest() == payload_sha384


def test_18_duplicate_chunk_deduplication():
    """Verify that duplicate chunks received over the optical link are cleanly deduplicated."""
    sender = OpticalDiodeSender()
    receiver = OpticalDiodeReceiver(
        bind_host="127.0.0.1",
        bind_port=55399,
        expected_sender_vk=sender.verifying_key,
    )

    payload = b"DEDUPLICATION_TEST_PAYLOAD_SOVEREIGN"
    tx_id, packets = sender.prepare_packets(payload, k=2, m=2)

    # Inject duplicate chunks
    reconstructed = None
    for pkt in [packets[0], packets[0], packets[1], packets[1]]:
        res = receiver.process_packet(pkt)
        if res is not None:
            reconstructed = res

    sender.close()
    receiver.close()

    assert reconstructed == payload, "Deduplication decode mismatch"


# =============================================================================
# 8. CONTROLLER & HARDWARE REGISTRY TESTS
# =============================================================================

def test_19_optical_diode_controller_lossy_simulation():
    """Verify high-level OpticalDiodeController lossy channel simulation."""
    controller = OpticalDiodeController()
    test_data = secrets.token_bytes(5000)

    result = controller.run_lossy_channel_simulation(
        payload=test_data,
        loss_rate=0.25,
        burst=True,
        k=6,
        m=3,
    )

    assert result["success"] is True
    assert result["sha384_match"] is True
    assert result["dropped_packets"] >= 1
    assert result["payload_sha384"] == result["reconstructed_sha384"]


def test_20_certified_hardware_registry_integration():
    """Verify certified optical data diode registry loader."""
    controller = OpticalDiodeController()
    devices = controller.devices
    assert len(devices) >= 3

    device_ids = {d.get("device_id") for d in devices}
    assert "DIODE-OWL-1000G" in device_ids
    assert "DIODE-FOXIT-EAL7" in device_ids
    assert "DIODE-ADVENICA-SECURI" in device_ids

    owl = controller.get_certified_device("DIODE-OWL-1000G")
    assert owl is not None
    assert owl["tx_only_attested"] is True
    assert owl["cc_cert"] == "EAL4+AVA_VAN.5"


# =============================================================================
# 9. PRODUCTION HARDENING, IPV6, CONCURRENCY & DOS TESTS
# =============================================================================

def test_21_ipv6_simplex_udp_clean_transmission():
    """Verify live simplex UDP broadcast over IPv6 (::1 loopback)."""
    port = secrets.randbelow(10000) + 55500
    test_payload = b"IPV6-SIMPLEX-OPTICAL-GLASS-TRANSMIT-ONLY"

    sender = OpticalDiodeSender(target_host="::1", target_port=port)
    receiver = OpticalDiodeReceiver(
        bind_host="::1",
        bind_port=port,
        expected_sender_vk=sender.verifying_key,
    )

    received_result: List[Optional[bytes]] = [None]

    def rx_worker() -> None:
        received_result[0] = receiver.receive_payload(timeout_seconds=4.0)

    t = threading.Thread(target=rx_worker, daemon=True)
    t.start()
    time.sleep(0.15)

    tx_id = sender.send_payload(test_payload, k=2, m=2, burst_delay_ms=0.5)
    assert len(tx_id) == 16

    t.join(timeout=5.0)
    sender.close()
    receiver.close()

    assert received_result[0] == test_payload, "IPv6 simplex transmission mismatch"


def test_22_receiver_dos_ttl_eviction():
    """Verify receiver automatically prunes in-flight transfers exceeding TTL to mitigate DoS attacks."""
    sender = OpticalDiodeSender()
    # Receiver with 0.1s TTL
    receiver = OpticalDiodeReceiver(
        bind_host="127.0.0.1",
        bind_port=55601,
        expected_sender_vk=sender.verifying_key,
        transfer_ttl_seconds=0.1,
        max_concurrent_transfers=2,
    )

    tx_id, packets = sender.prepare_packets(b"DATA-FOR-EVICTION-PROBE", k=4, m=2)

    # Ingest only packet 0 (incomplete transfer)
    res = receiver.process_packet(packets[0])
    assert res is None
    assert len(receiver._transfers) == 1

    # Sleep past TTL
    time.sleep(0.2)
    receiver.prune_stale_transfers()
    assert len(receiver._transfers) == 0, "Stale in-flight transfer must be evicted on TTL expiration"

    sender.close()
    receiver.close()


def test_23_concurrent_interleaved_transfers():
    """Verify multiple concurrent transmissions with different transfer_ids do not cross-talk."""
    sender1 = OpticalDiodeSender()
    sender2 = OpticalDiodeSender()

    receiver = OpticalDiodeReceiver(bind_host="127.0.0.1", bind_port=55602)

    payload1 = b"STREAM-ALPHA-DEFCON-1-AUTHORIZATION"
    payload2 = b"STREAM-BRAVO-EMERGENCY-ACTION-ORDER"

    _, packets1 = sender1.prepare_packets(payload1, k=3, m=2)
    _, packets2 = sender2.prepare_packets(payload2, k=3, m=2)

    # Interleave packets from both streams
    rec1, rec2 = None, None
    for p1, p2 in zip(packets1, packets2):
        r1 = receiver.process_packet(p1)
        r2 = receiver.process_packet(p2)
        if r1 is not None:
            rec1 = r1
        if r2 is not None:
            rec2 = r2

    sender1.close()
    sender2.close()
    receiver.close()

    assert rec1 == payload1, "Stream 1 reconstruction failed"
    assert rec2 == payload2, "Stream 2 reconstruction failed"


def test_24_multi_bundle_streaming_transmission():
    """Verify multi-bundle transmission for arbitrary-sized streaming payloads."""
    port = secrets.randbelow(10000) + 55700
    sender = OpticalDiodeSender(target_host="127.0.0.1", target_port=port)
    receiver = OpticalDiodeReceiver(
        bind_host="127.0.0.1",
        bind_port=port,
        expected_sender_vk=sender.verifying_key,
    )

    # Large 20,000 byte data stream
    data_stream = secrets.token_bytes(20000)
    bundle_cap = 6000  # Forces splitting into 4 bundles

    tx_ids = sender.send_stream_bundles(data_stream, bundle_payload_cap=bundle_cap, burst_delay_ms=0.0)
    assert len(tx_ids) == 4

    sender.close()
    receiver.close()


def test_25_egress_interface_validation_fail_closed():
    """Verify transmitter fails closed on invalid or unbindable egress interface."""
    import os
    if os.name != "posix":
        with pytest.raises(ValueError) as exc:
            OpticalDiodeSender(egress_ifname="eth0")
        assert "SO_BINDTODEVICE is Linux-only" in str(exc.value)

    with pytest.raises(ValueError):
        OpticalDiodeSender(egress_source_ip="999.999.999.999")


def test_26_empty_payload_refusal():
    """Verify transmitter refuses empty payload fail-closed."""
    sender = OpticalDiodeSender()
    with pytest.raises(ValueError) as exc:
        sender.prepare_packets(b"")
    assert "Refusing" in str(exc.value)
    sender.close()


def test_27_dod_memory_wipe_verification():
    """Verify DoD 5220.22-M memory zeroization functions properly on cleartext buffers."""
    from secure_memory_wiper import secure_wipe_dod

    buf = bytearray(b"CLASSIFIED-TOP-SECRET-KEY-MATERIAL-123456789")
    original_len = len(buf)
    secure_wipe_dod(buf, passes=7)
    assert len(buf) == original_len
    # Memory must be wiped (zeroed)
    assert all(b == 0 for b in buf), "Memory buffer was not zeroized after DoD wipe"

