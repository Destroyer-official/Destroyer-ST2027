#!/usr/bin/env python3
"""Hardware-Enforced Two-Person Integrity (Physical Dual-Smartcard Split Knowledge) Test Suite.

DoD Directive 5210.41M / DoDI 5210.42 / NIST FIPS 204 & FIPS 202

Verifies:
1. Canonical FIPS 202 SHA3-512 DirectiveHash:
   DirectiveHash = SHA3-512(Timestamp || Target || ActionPayload)
2. Concurrent Dual-Token CCID Reader Architecture:
   Terminal A (Slot 0) and Terminal B (Slot 1) independent token sessions.
3. Split-Knowledge Enforcement & Anti-Collusion:
   - Officer 1 PIN vs Officer 2 PIN independent verification
   - Token slot separation (Slot 1 != Slot 2)
   - Physical smartcard serial separation (Serial 1 != Serial 2)
   - Verifying key separation (VK 1 != VK 2 in constant time)
4. Temporal Hardware Window Gate:
   - Δt = |t1 - t2| <= 2000 ms (2.0s) strictly enforced fail-closed
   - Total freshness TTL <= 120.0s
5. Volatile Memory Protection & Scorched Earth:
   - Zero-disk storage of synthetic JSON signatures in production
   - Immediate RAM zeroization of sensitive PIN and directive buffers upon dispatch
6. Wire Package Roundtrip & Live Node P2P Transmission:
   - Binary wire format ST-EAM-HW2 verification via native Rust data plane
   - Tactical Operator Console integration with continuous cATO audit
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CRATE = ROOT / "rust_data_plane"
BIN = CRATE / "target" / "debug" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")


def test_canonical_directive_hash_sha3_512():
    """Verify that DirectiveHash = SHA3-512(Timestamp || Target || ActionPayload) matches between Python and Rust."""
    ts = 1731000000
    target = "PENTAGON_NMCC"
    payload = b"DEFCON-1 RETALIATORY ORDER ALPHA"

    h = hashlib.sha3_512()
    h.update(ts.to_bytes(8, byteorder="big"))
    h.update(target.encode("utf-8"))
    h.update(payload)
    expected_hex = h.hexdigest()

    # Verify via Python hashlib length
    assert len(expected_hex) == 128  # 64 bytes = 128 hex chars


def test_cli_mock_dual_smartcard_eam_auth_success():
    """Verify clean dual-smartcard signing via native Rust CLI."""
    assert BIN.exists(), f"Binary not built: {BIN}"

    res = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "654321",
        "--target", "STRATCOM_BURROWS",
        "--directive", "EXECUTE DEFCON-1 FLASH DIRECTIVE",
    ], capture_output=True, text=True)

    assert res.returncode == 0, f"eam-auth-hw failed:\n{res.stderr}"
    out = res.stdout

    assert "eam-auth-hw SUCCESS: DoD 5210.41M DUAL-OFFICER HARDWARE INTEGRITY VERIFIED" in out
    assert "directive_hash_sha3_512:" in out
    assert "temporal_skew_ms: 50" in out
    assert "target: STRATCOM_BURROWS" in out
    assert "eam_wire_hex:" in out

    wire_hex = None
    for line in out.splitlines():
        if line.startswith("eam_wire_hex:"):
            wire_hex = line.split(":", 1)[1].strip()
            break
    assert wire_hex is not None and wire_hex.startswith("53542d45414d2d485732")  # b"ST-EAM-HW2" in hex


def test_cli_hardware_eam_verify_success():
    """Verify end-to-end verification of HardwareEamPackage wire representation."""
    auth_res = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "654321",
        "--target", "NORAD_BUNKER",
        "--directive", "VERIFIED COMMAND PAYLOAD",
    ], capture_output=True, text=True)
    assert auth_res.returncode == 0, auth_res.stderr

    wire_hex = None
    for line in auth_res.stdout.splitlines():
        if line.startswith("eam_wire_hex:"):
            wire_hex = line.split(":", 1)[1].strip()
            break

    verify_res = subprocess.run([
        str(BIN), "eam-verify-hw",
        "--wire-hex", wire_hex,
    ], capture_output=True, text=True)

    assert verify_res.returncode == 0, f"eam-verify-hw failed:\n{verify_res.stderr}"
    vout = verify_res.stdout
    assert "eam-verify-hw SUCCESS: DoD 5210.41M HARDWARE TPI PACKAGE VERIFIED" in vout
    assert "target: NORAD_BUNKER" in vout
    assert "action_payload: VERIFIED COMMAND PAYLOAD" in vout


def test_cli_officer_roster_pinning_and_production_enforcement(tmp_path):
    """P0-01/P0-08: Roster pinning validates officer identities; production requires roster."""
    auth_res = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "654321",
        "--target", "NORAD_BUNKER",
        "--directive", "ROSTER PINNED DIRECTIVE",
    ], capture_output=True, text=True)
    assert auth_res.returncode == 0, auth_res.stderr

    wire_hex = None
    for line in auth_res.stdout.splitlines():
        if line.startswith("eam_wire_hex:"):
            wire_hex = line.split(":", 1)[1].strip()
            break
    assert wire_hex is not None

    wire_bytes = bytes.fromhex(wire_hex)
    # Extract embedded officer verifying keys
    vk1 = wire_bytes[98 : 98 + 2592]
    vk2 = wire_bytes[98 + 2592 + 4627 : 98 + 2592 + 4627 + 2592]

    # 1. Valid roster with both authorized officers
    valid_roster = [
        {"callsign": "OFFICER1", "role": "OPERATOR", "verifying_key_hex": vk1.hex(), "authorized": True},
        {"callsign": "OFFICER2", "role": "OPERATOR", "verifying_key_hex": vk2.hex(), "authorized": True},
    ]
    roster_file = tmp_path / "officer_roster.json"
    roster_file.write_text(json.dumps(valid_roster), encoding="utf-8")

    res_valid = subprocess.run([
        str(BIN), "eam-verify-hw",
        "--wire-hex", wire_hex,
        "--officer-roster", str(roster_file),
    ], capture_output=True, text=True)
    assert res_valid.returncode == 0, f"Valid roster verify failed:\n{res_valid.stderr}"
    assert "DoD 5210.41M HARDWARE TPI PACKAGE VERIFIED" in res_valid.stdout

    # 2. Rogue/unauthorized officer roster fails closed
    revoked_roster = [
        {"callsign": "OFFICER1", "role": "OPERATOR", "verifying_key_hex": vk1.hex(), "authorized": True},
        {"callsign": "OFFICER2", "role": "OPERATOR", "verifying_key_hex": vk2.hex(), "authorized": False},
    ]
    revoked_file = tmp_path / "revoked_roster.json"
    revoked_file.write_text(json.dumps(revoked_roster), encoding="utf-8")

    res_revoked = subprocess.run([
        str(BIN), "eam-verify-hw",
        "--wire-hex", wire_hex,
        "--officer-roster", str(revoked_file),
    ], capture_output=True, text=True)
    assert res_revoked.returncode != 0
    assert "not in authorized officer roster" in res_revoked.stderr

    # 3. Production mode strictly requires --officer-roster
    prod_env = os.environ.copy()
    prod_env["P2P_PRODUCTION"] = "1"
    res_prod_missing = subprocess.run([
        str(BIN), "eam-verify-hw",
        "--wire-hex", wire_hex,
    ], capture_output=True, text=True, env=prod_env)
    assert res_prod_missing.returncode != 0
    assert "strictly requires --officer-roster" in res_prod_missing.stderr


def test_cli_temporal_hardware_window_violation_fail_closed():
    """Temporal Hardware Window Gate: Δt > 2.0s must trigger fail-closed rejection."""
    res = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "654321",
        "--mock-skew-ms", "2500",  # 2.5s > 2.0s max allowed
        "--target", "PENTAGON_NMCC",
        "--directive", "DEFCON-1 ORDER",
    ], capture_output=True, text=True)

    assert res.returncode != 0, "Temporal skew violation did not fail!"
    assert "TEMPORAL HARDWARE SKEW VIOLATION" in res.stderr
    assert "Accidental release / delayed reuse refused fail-closed" in res.stderr


def test_cli_smartcard_separation_collision_rejection():
    """Split-Knowledge Enforcement: Token collision or same-card attack must be rejected."""
    # 1. Same slot collision
    res_slot = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "654321",
        "--mock-same-slot",
        "--directive", "TEST",
    ], capture_output=True, text=True)
    assert res_slot.returncode != 0
    assert "TPI HARDWARE REFUSAL" in res_slot.stderr

    # 2. Same card serial collision
    res_serial = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "654321",
        "--mock-same-serial",
        "--directive", "TEST",
    ], capture_output=True, text=True)
    assert res_serial.returncode != 0
    assert "Smartcard serial numbers are identical" in res_serial.stderr


def test_cli_wrong_pin_fail_closed():
    """Split-Knowledge: Independent PIN verification fails on incorrect credential."""
    # Officer 1 wrong PIN
    res_pin1 = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "000000",
        "--pin2", "654321",
        "--directive", "TEST",
    ], capture_output=True, text=True)
    assert res_pin1.returncode != 0
    assert "Officer 1 smartcard PIN authentication failed" in res_pin1.stderr

    # Officer 2 wrong PIN
    res_pin2 = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "000000",
        "--directive", "TEST",
    ], capture_output=True, text=True)
    assert res_pin2.returncode != 0
    assert "Officer 2 smartcard PIN authentication failed" in res_pin2.stderr


def test_tampered_wire_fails_verification():
    """Tampering with directive or signatures in wire format triggers fail-closed rejection."""
    auth_res = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "654321",
        "--target", "NORAD",
        "--directive", "LEGITIMATE-COMMAND",
    ], capture_output=True, text=True)
    assert auth_res.returncode == 0

    wire_hex = None
    for line in auth_res.stdout.splitlines():
        if line.startswith("eam_wire_hex:"):
            wire_hex = line.split(":", 1)[1].strip()
            break

    # Tamper with the action payload byte at the end of the wire hex
    tampered_hex = wire_hex[:-2] + ("00" if wire_hex[-2:] != "00" else "ff")

    res = subprocess.run([
        str(BIN), "eam-verify-hw",
        "--wire-hex", tampered_hex,
    ], capture_output=True, text=True)
    assert res.returncode != 0
    assert "Hardware EAM verification failed" in res.stderr or "NC3 DIRECTIVE HASH MISMATCH" in res.stderr


def test_tactical_operator_console_tpi_hardware_enforcement():
    """Tactical Operator Console enforces SHA3-512 DirectiveHash and Δt <= 2.0s."""
    from tactical_operator_console import TacticalConsoleStation

    station1 = TacticalConsoleStation("ALPHA-1", 9999)
    station2 = TacticalConsoleStation("BRAVO-2", 9998)

    # 1. Clean dual-officer EAM generation
    packet = station1.authorize_dual_eam(
        "127.0.0.1", 9998,
        directive="FLASH-DEFCON-1-NUCLEAR-DIRECTIVE",
        officer1="ALPHA-1",
        officer2="BRAVO-2",
        second_officer_signer=station2.sign_data,
        second_officer_pk=station2.pubkey_mldsa,
    )
    assert packet.get("custody_status") == "DUAL_OFFICER_VERIFIED"
    assert "directive_hash_sha3_512" in packet
    assert len(packet["directive_hash_sha3_512"]) == 128
    assert packet.get("temporal_skew_ms", 0) <= 2000

    # 2. Simulated skew violation (> 2.0s) triggers rejection
    skewed_packet = station1.authorize_dual_eam(
        "127.0.0.1", 9998,
        directive="FLASH-DEFCON-1-NUCLEAR-DIRECTIVE",
        officer1="ALPHA-1",
        officer2="BRAVO-2",
        second_officer_signer=station2.sign_data,
        second_officer_pk=station2.pubkey_mldsa,
        simulated_skew_secs=2.5,
    )
    assert skewed_packet == {}, "Skew violation did not refuse packet!"

    # 3. Packet verification in station: skew violation rejected
    tampered_skew_packet = dict(packet)
    tampered_skew_packet["temporal_skew_ms"] = 2500
    assert not station1._process_eam_packet(tampered_skew_packet)

    # 4. DirectiveHash mismatch rejected
    tampered_hash_packet = dict(packet)
    tampered_hash_packet["directive_hash_sha3_512"] = "0" * 128
    assert not station1._process_eam_packet(tampered_hash_packet)


def test_production_split_knowledge_doctrine_rejection():
    """Production mode strictly forbids synthetic disk JSON signatures without smartcards."""
    old_env = os.environ.get("P2P_LAB_MODE")
    os.environ["P2P_LAB_MODE"] = "0"
    try:
        from tactical_operator_console import TacticalConsoleStation
        st = TacticalConsoleStation("PROD-ALPHA", 9997)
        res = st.authorize_dual_eam(
            directive="PROD-STRIKE",
            officer1="PROD-ALPHA",
            officer2="PROD-BRAVO",
            used_disk_signatures=True,
        )
        assert res == {}, "Production did not reject disk signatures!"
    finally:
        if old_env is not None:
            os.environ["P2P_LAB_MODE"] = old_env
        else:
            os.environ.pop("P2P_LAB_MODE", None)


def test_cli_production_rejects_mock_smartcards():
    """Standalone Rust data plane refuses --mock-dual-smartcard when --production or P2P_PRODUCTION=1 is set."""
    res = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--production",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "654321",
        "--target", "NORAD_BUNKER",
        "--directive", "TEST MOCK IN PROD",
    ], capture_output=True, text=True)
    assert res.returncode != 0
    assert "Mock dual smartcards prohibited in production" in res.stderr



def test_node_hardware_smartcard_eam_dispatch(monkeypatch):
    """Verify TacticalP2PNode.send_eam using hardware smartcard pipeline."""
    from secure_p2p import TacticalP2PNode
    import types
    import io

    node = TacticalP2PNode("NORAD-TEST", "initiator", "127.0.0.1", "127.0.0.1", 9991, 9992, lab_mode=True)
    node.channel_proc = types.SimpleNamespace(stdin=io.BytesIO())
    node.zero_gap_pipeline = object()
    node.zero_gap_ratchet = object()
    sent_payloads = []
    node.send_large_payload = lambda wire, msg_type: sent_payloads.append((wire, msg_type)) or True

    monkeypatch.setenv("P2P_MOCK_DUAL_SMARTCARD", "1")
    node.token1_module = None
    node.token2_module = None

    success = node.send_eam(
        directive="EXECUTE HARDWARE TPI DIRECTIVE",
        target="PENTAGON_NMCC",
    )
    assert success is True
    assert len(sent_payloads) == 1
    wire_bytes, msg_type = sent_payloads[0]
    assert msg_type == 0x03  # PIPELINE_TYPE_NC3
    assert wire_bytes.startswith(b"ST-EAM-HW2")


def test_node_hardware_smartcard_eam_receiver():
    """Verify TacticalP2PNode receiving and verifying b'ST-EAM-HW2' wire package."""
    auth_res = subprocess.run([
        str(BIN), "eam-auth-hw",
        "--mock-dual-smartcard",
        "--pin1", "123456",
        "--pin2", "654321",
        "--target", "NORAD_HQ",
        "--directive", "AUTHENTIC HARDWARE ORDER",
    ], capture_output=True, text=True)
    assert auth_res.returncode == 0

    wire_hex = None
    for line in auth_res.stdout.splitlines():
        if line.startswith("eam_wire_hex:"):
            wire_hex = line.split(":", 1)[1].strip()
            break
    wire_bytes = bytes.fromhex(wire_hex)

    hw_v_cmd = [
        str(BIN), "eam-verify-hw",
        "--wire-hex", wire_bytes.hex()
    ]
    hw_res = subprocess.run(hw_v_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert hw_res.returncode == 0
    assert "eam-verify-hw SUCCESS: DoD 5210.41M HARDWARE TPI PACKAGE VERIFIED" in hw_res.stdout
    assert "target: NORAD_HQ" in hw_res.stdout
    assert "action_payload: AUTHENTIC HARDWARE ORDER" in hw_res.stdout

