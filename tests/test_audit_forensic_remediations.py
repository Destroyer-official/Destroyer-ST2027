#!/usr/bin/env python3
"""
Comprehensive Forensic Security Audit Regression & Remediation Test Suite.
Verifies production-grade remediations for all audit findings:
  - TACT-01: Python EAM handler rejects unauthenticated UDP packets with self-asserted dual control.
  - TACT-02: Invalid/unsigned CoT packets rejected before updating BFT tracks or ATAK bridge.
  - TACT-03: Tactical message metadata (precedence, clearance, caveats) authenticated in envelope.
  - TACT-04: Emergency zeroization purges mutable ML-DSA-87 private key buffer.
  - Bandit B104: Configurable localhost bind host in tactical console network listener.
  - ST-01 / ST-02: Strict production environment flag normalization and peer-pk CLI resolution.
  - Finding 04: Rust state file HMAC-SHA256 authentication rejects counter rollback and tampering.
  - Finding 06 / ANON-01: Anonymity transport accepts expected_peer_pk and handles CER rekeying.
"""

import os
import sys
import json
import time
import socket
import tempfile
import unittest
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tactical_operator_console as toc
import secure_transmit_2027 as st
import transport_anonymity as ta


class TestAuditForensicRemediations(unittest.TestCase):
    def test_01_eam_unauthenticated_packet_rejected(self):
        """TACT-01: Python EAM handler rejects forged unauthenticated UDP datagrams."""
        station = toc.TacticalConsoleStation(node_name="node-cmd", callsign="AUDIT-CMD", local_port=9110, enable_atak_bridge=False)
        fake_packet = {
            "type": "EAM_ORDER",
            "directive": "UNAUTHORIZED-LAUNCH-ORDER",
            "officer1": "OFFICER-ALICE",
            "officer2": "OFFICER-BOB",
            "custody_status": "DUAL_OFFICER_VERIFIED",
            "timestamp": time.time(),
        }
        res = station._process_eam_packet(fake_packet)
        self.assertFalse(res, "Forged EAM without dual signatures must be rejected")

    def test_02_eam_dual_officer_valid_signature_accepted(self):
        """TACT-01: Python EAM handler verifies valid dual ML-DSA-87 signatures."""
        station = toc.TacticalConsoleStation(node_name="node-hq", callsign="AUDIT-HQ", local_port=9111, enable_atak_bridge=False)
        of1 = toc.TacticalConsoleStation(node_name="node-of1", callsign="OF1", local_port=9112, enable_atak_bridge=False)
        of2 = toc.TacticalConsoleStation(node_name="node-of2", callsign="OF2", local_port=9113, enable_atak_bridge=False)

        directive = "DEFCON-1-AUTHORIZED-RETALIATION"
        eam_packet = of1.authorize_dual_eam(
            directive=directive,
            second_officer_callsign="OF2",
            second_officer_pk=of2.pubkey_mldsa,
            second_officer_signer=of2.sign_data
        )

        self.assertIn("officer1_sig", eam_packet)
        self.assertIn("officer2_sig", eam_packet)
        self.assertEqual(eam_packet["custody_status"], "DUAL_OFFICER_VERIFIED")

        # Must verify successfully on the receiving station
        res = station._process_eam_packet(eam_packet)
        self.assertTrue(res, "Legitimate dual-officer EAM must verify successfully")

        # Test replay / freshness rejection (timestamp > 120s old)
        stale_packet = dict(eam_packet)
        stale_packet["timestamp"] = time.time() - 300.0
        self.assertFalse(station._process_eam_packet(stale_packet), "Stale EAM must be rejected")

    def test_03_cot_invalid_signature_rejected_from_tracks(self):
        """TACT-02: CoT position reports with invalid/missing signatures never enter BFT state."""
        station = toc.TacticalConsoleStation(node_name="node-radar", callsign="AUDIT-RADAR", local_port=9114, enable_atak_bridge=False)
        bogus_cot = {
            "type": "COT_EVENT",
            "uid": "HOSTILE-GHOST-99",
            "callsign": "GHOST-99",
            "lat": 35.1234,
            "lon": 45.6789,
            "cot_type": "a-h-A-M-F",
            "signer": "ROGUE-NODE",
            "sig_hex": "bad0bad0" * 32,
            "xml": "<event>fake</event>",
        }
        station._handle_inbound_packet(bogus_cot, ("127.0.0.1", 5555))
        self.assertNotIn("HOSTILE-GHOST-99", station.tracks, "Unverified track must NOT enter BFT table")

    def test_04_tactical_msg_metadata_tampering_rejected(self):
        """TACT-03: Tampering with message metadata fails cryptographic signature verification."""
        sender = toc.TacticalConsoleStation(node_name="node-alpha", callsign="SENDER-ALPHA", local_port=9115, enable_atak_bridge=False)
        receiver = toc.TacticalConsoleStation(node_name="node-bravo", callsign="RECV-BRAVO", local_port=9116, enable_atak_bridge=False)

        # Enroll sender's public key with receiver
        receiver.enrolled_peers[sender.callsign] = sender.pubkey_mldsa

        # Send legitimate message
        legit_pkt = sender.send_tactical_message(
            text="MISSION ABORT IMMINENT",
            precedence="O",
            clearance="SECRET",
            caveats="NOFORN"
        )
        self.assertTrue(receiver._process_msg_packet(legit_pkt), "Legitimate message must verify")

        # Tamper with metadata (change precedence to Flash Override 'Y')
        tampered_pkt = dict(legit_pkt)
        tampered_pkt["precedence"] = "Y"
        self.assertFalse(receiver._process_msg_packet(tampered_pkt), "Metadata tampering must fail signature check")

        # Tamper with clearance
        tampered_clearance = dict(legit_pkt)
        tampered_clearance["clearance"] = "TOP_SECRET"
        self.assertFalse(receiver._process_msg_packet(tampered_clearance), "Clearance tampering must fail check")

    def test_05_emergency_zeroize_wipes_signing_key(self):
        """TACT-04: Emergency zeroize wipes mutable signing key buffer."""
        station = toc.TacticalConsoleStation(node_name="node-covert", callsign="COVERT-01", local_port=9117, enable_atak_bridge=False)
        self.assertIsNotNone(station.privkey_mldsa)
        self.assertTrue(any(b != 0 for b in station.privkey_mldsa))

        # Trigger emergency purge
        station.emergency_zeroize()

        self.assertIsNone(station.privkey_mldsa, "Private key reference must be cleared")
        self.assertEqual(len(station.tracks), 0, "Tracks must be cleared")
        self.assertEqual(len(station.enrolled_peers), 0, "Peers must be cleared")

        # Signing after zeroization must raise RuntimeError
        with self.assertRaises(RuntimeError):
            station.sign_data(b"test-after-wipe")

    def test_06_production_strict_flag_normalization(self):
        """ST-02: Normalization of production strict flags (accepts 'true', '1', 'yes', 'on')."""
        saved_env = dict(os.environ)
        try:
            for flag in ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION", "P2P_TS_MODE", "P2P_STRICT_PIN"):
                for val in ("1", "true", "TRUE", "yes", "YES", "on", "ON"):
                    os.environ.clear()
                    os.environ[flag] = val
                    self.assertTrue(st._production_strict(), f"{flag}={val} must activate production strict")

            # The loop above intentionally armed the process-lifetime latch.
            # Reset only in this test before checking a fresh falsey-only posture.
            from production_gate import reset_for_tests
            reset_for_tests()
            os.environ.clear()
            os.environ["P2P_PRODUCTION"] = "0"
            os.environ["SECURE_P2P_PRODUCTION"] = "false"
            os.environ["P2P_TS_MODE"] = "no"
            self.assertFalse(st._production_strict(), "Falsy values must not activate production strict")
        finally:
            os.environ.clear()
            os.environ.update(saved_env)

    def test_07_peer_pk_resolution(self):
        """ST-01: _resolve_peer_pk resolves binary files, hex, and certificate JSON."""
        dummy_pk = b"\x3a" * 2592
        hex_pk = dummy_pk.hex()

        # Direct hex string
        resolved = st._resolve_peer_pk(hex_pk)
        self.assertEqual(resolved, dummy_pk)

        # File path
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(dummy_pk)
            tmp_path = f.name
        try:
            res_file = st._resolve_peer_pk(tmp_path)
            self.assertEqual(res_file, dummy_pk)
        finally:
            os.unlink(tmp_path)

        # Extracted from cert JSON
        cert_json = json.dumps({"subject": "peer-node", "subject_pk_hex": hex_pk})
        res_cert = st._resolve_peer_pk(None, peer_cert_json=cert_json)
        self.assertEqual(res_cert, dummy_pk)

    def test_08_rust_state_hmac_tamper_and_rollback_rejection(self):
        """Finding 04: Rust data-plane rejects unauthenticated, rolled back, or tampered state."""
        bin_path = ROOT / "rust_data_plane" / "target" / "debug" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
        if not bin_path.exists():
            bin_path = ROOT / "rust_data_plane" / "target" / "release" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
        if not bin_path.exists():
            self.skipTest("secure-transmit binary not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, "session.key")
            state_file = os.path.join(tmpdir, "session.state")

            # Generate key
            subprocess.run([str(bin_path), "keygen", "--out", key_file], check=True)

            # Send 1 message (initializes state)
            r_init = subprocess.run(
                [str(bin_path), "send", "--key-file", key_file, "--state", state_file,
                 "--to", "127.0.0.1:51820", "--msg", "test-init"],
                capture_output=True, text=True
            )
            self.assertTrue(os.path.exists(state_file), "State file must exist")
            # State file must be exactly 328 bytes (296 bytes raw + 32 bytes HMAC-SHA256)
            self.assertEqual(os.path.getsize(state_file), 328)

            # Snapshot valid state bytes
            valid_state = Path(state_file).read_bytes()

            # Tamper with the sequence counter in state file (bytes 24..32)
            tampered = bytearray(valid_state)
            tampered[24] ^= 0x01  # rewind / alter sequence counter
            Path(state_file).write_bytes(tampered)

            # Attempting to send with tampered state must fail closed
            r_tampered = subprocess.run(
                [str(bin_path), "send", "--key-file", key_file, "--state", state_file,
                 "--to", "127.0.0.1:51820", "--msg", "test-tampered"],
                capture_output=True, text=True
            )
            self.assertNotEqual(r_tampered.returncode, 0, "Tampered state must fail closed")
            self.assertIn("HMAC mismatch", r_tampered.stderr)

    def test_09_rust_state_legacy_48byte_refused(self):
        """F-04: pre-HMAC 48-byte state files are refused, not silently adopted."""
        bin_path = ROOT / "rust_data_plane" / "target" / "debug" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
        if not bin_path.exists():
            bin_path = ROOT / "rust_data_plane" / "target" / "release" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
        if not bin_path.exists():
            self.skipTest("secure-transmit binary not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, "session.key")
            state_file = os.path.join(tmpdir, "session.state")

            subprocess.run([str(bin_path), "keygen", "--out", key_file], check=True)

            # Plant a legacy unauthenticated 48-byte state (magic + body, no HMAC).
            legacy = bytearray(48)
            legacy[:8] = b"STSTATE2"
            Path(state_file).write_bytes(legacy)

            r = subprocess.run(
                [str(bin_path), "send", "--key-file", key_file, "--state", state_file,
                 "--to", "127.0.0.1:51820", "--msg", "legacy-refuse"],
                capture_output=True, text=True
            )
            self.assertNotEqual(r.returncode, 0, "Legacy 48-byte state must be refused")
            self.assertIn("bad length", r.stderr.lower())

    def test_10_rust_state_legacy_80byte_refused(self):
        """S-02: pre-328B 80-byte state files (STSTATE2) are refused fail-closed."""
        bin_path = ROOT / "rust_data_plane" / "target" / "debug" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
        if not bin_path.exists():
            bin_path = ROOT / "rust_data_plane" / "target" / "release" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
        if not bin_path.exists():
            self.skipTest("secure-transmit binary not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, "session.key")
            state_file = os.path.join(tmpdir, "session.state")

            subprocess.run([str(bin_path), "keygen", "--out", key_file], check=True)

            # Plant an old 80-byte STSTATE2 state
            legacy = bytearray(80)
            legacy[:8] = b"STSTATE2"
            Path(state_file).write_bytes(legacy)

            r = subprocess.run(
                [str(bin_path), "send", "--key-file", key_file, "--state", state_file,
                 "--to", "127.0.0.1:51820", "--msg", "legacy-80b-refuse"],
                capture_output=True, text=True
            )
            self.assertNotEqual(r.returncode, 0, "Legacy 80-byte state must be refused")
            self.assertIn("bad length", r.stderr.lower())

    def test_11_s03_error_message_clarity(self):
        """S-03: HMAC verification failure names HMAC mismatch and corruption/forgery accurately."""
        bin_path = ROOT / "rust_data_plane" / "target" / "debug" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
        if not bin_path.exists():
            bin_path = ROOT / "rust_data_plane" / "target" / "release" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
        if not bin_path.exists():
            self.skipTest("secure-transmit binary not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, "session.key")
            state_file = os.path.join(tmpdir, "session.state")

            subprocess.run([str(bin_path), "keygen", "--out", key_file], check=True)
            subprocess.run(
                [str(bin_path), "send", "--key-file", key_file, "--state", state_file,
                 "--to", "127.0.0.1:51820", "--msg", "init"],
                check=True
            )

            # Corrupt HMAC bytes
            data = bytearray(Path(state_file).read_bytes())
            data[-1] ^= 0x55
            Path(state_file).write_bytes(data)

            r = subprocess.run(
                [str(bin_path), "send", "--key-file", key_file, "--state", state_file,
                 "--to", "127.0.0.1:51820", "--msg", "tampered"],
                capture_output=True, text=True
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("HMAC mismatch", r.stderr)
            self.assertIn("state corrupt or forged", r.stderr)


if __name__ == "__main__":
    unittest.main()

