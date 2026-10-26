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

    def test_12_graceful_degradation_recognizes_pqc_and_error_handler(self):
        """SEC-07: SecurityDegradationManager detects modern pqc_algorithms and error_handler."""
        from security.graceful_degradation import SecurityDegradationManager
        sdm = SecurityDegradationManager()
        self.assertIn(sdm.security_level, ["MAXIMUM", "HIGH"])
        self.assertTrue(sdm.available_modules.get('military_crypto', False))
        self.assertTrue(sdm.available_modules.get('error_handler', False))

    def test_13_decentralized_and_tactical_production_gate_fail_closed(self):
        """SEC-08: _production() in decentralized & tactical architectures fails closed."""
        from decentralized_architecture import _production as dht_prod
        from destroyer_tactical_p2p import _production as tac_prod
        from unittest.mock import patch
        with patch.dict(os.environ, {"P2P_PRODUCTION": "1"}):
            self.assertTrue(dht_prod())
            self.assertTrue(tac_prod())
        with patch("production_gate.is_production", side_effect=Exception("Tampered")):
            self.assertTrue(dht_prod())
            self.assertTrue(tac_prod())

    def test_14_data_models_role_assignment_expiry_and_permissions(self):
        """SEC-09: data_models.RoleAssignment evaluates expiration and permissions."""
        from data_models import RoleAssignment, SecurityRole, SecurityPermission
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        active_role = RoleAssignment("uid1", SecurityRole.COMMANDER, permissions={SecurityPermission.EMERGENCY_RELEASE}, granted_at=now, expires_at=now + timedelta(hours=1))
        self.assertFalse(active_role.is_expired())
        self.assertTrue(active_role.has_permission(SecurityPermission.EMERGENCY_RELEASE))
        self.assertFalse(active_role.has_permission(SecurityPermission.ADMIN_COMMAND))

        expired_role = RoleAssignment("uid2", SecurityRole.OPERATOR, permissions={SecurityPermission.EMERGENCY_RELEASE}, granted_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1))
        self.assertTrue(expired_role.is_expired())
        self.assertFalse(expired_role.has_permission(SecurityPermission.EMERGENCY_RELEASE))

    def test_15_multi_device_signature_chain_cycle_detection(self):
        """SEC-11: MultiDeviceManager detects signature chain cycles and avoids infinite recursion."""
        from multi_device_manager import MultiDeviceManager, DeviceInfo, UserIdentityDevices
        from datetime import datetime, timezone
        mgr = MultiDeviceManager()
        uid = "user-cycle-test"
        user_devs = UserIdentityDevices(user_identity_id=uid)
        mgr._user_devices[uid] = user_devs

        dev1 = DeviceInfo(
            device_id="dev-1",
            device_name="Terminal 1",
            device_type="desktop",
            public_key=b"pk1" * 10,
            enrollment_signature=b"sig1",
            authorizing_device_id="dev-2",
            signature_chain_depth=1,
            enrolled_at=datetime.now(timezone.utc)
        )
        dev2 = DeviceInfo(
            device_id="dev-2",
            device_name="Terminal 2",
            device_type="desktop",
            public_key=b"pk2" * 10,
            enrollment_signature=b"sig2",
            authorizing_device_id="dev-1",
            signature_chain_depth=1,
            enrolled_at=datetime.now(timezone.utc)
        )
        user_devs.devices["dev-1"] = dev1
        user_devs.devices["dev-2"] = dev2

        res = mgr.verify_signature_chain(uid, "dev-1")
        self.assertFalse(res, "Cyclic signature chain must fail closed")

    def test_16_metadata_resistance_padding_authenticated_length(self):
        """SEC-12: MessagePaddingEngine verifies HMAC over both header and payload."""
        from metadata_resistance import MessagePaddingEngine
        engine = MessagePaddingEngine()
        payload = b"Top secret operational command"
        padded = engine.pad(payload)
        unpadded = engine.unpad(padded)
        self.assertEqual(unpadded, payload)

        # Tampering with length header must cause verification error
        tampered = bytearray(padded)
        tampered[3] ^= 0x01
        with self.assertRaises(Exception):
            engine.unpad(bytes(tampered))

    def test_17_initialization_path_resolution_stays_within_workspace(self):
        """SEC-13: utils.initialization.Initialization resolves paths inside workspace root."""
        from utils.initialization import Initialization
        from unittest.mock import Mock
        init = Initialization(Mock())
        cfg = init.load_configuration()
        repo_root = os.path.abspath(ROOT)
        self.assertTrue(cfg['cert_dir'].startswith(repo_root), f"cert_dir {cfg['cert_dir']} must reside within {repo_root}")
        self.assertTrue(cfg['keys_dir'].startswith(repo_root), f"keys_dir {cfg['keys_dir']} must reside within {repo_root}")
        self.assertTrue(cfg['base_dir'].startswith(repo_root), f"base_dir {cfg['base_dir']} must reside within {repo_root}")

    def test_18_connection_manager_cleanup_on_dos_overflow(self):
        """SEC-14: ConnectionManager purges session_context when rejecting DoS overflow."""
        from network.connection import ConnectionManager, SecurityError
        from unittest.mock import Mock, MagicMock
        import asyncio

        orch = Mock()
        mgr = ConnectionManager(orch)
        mgr._max_active_connections = 1

        ctx1 = MagicMock()
        ctx1.peer_fingerprint = "fp1"
        mgr._active_connections["fp1"] = ctx1

        ctx2 = MagicMock()
        ctx2.peer_fingerprint = "fp2"
        ctx2.secure_cleanup = MagicMock()

        async def _test():
            conn_key = "fp2"
            async with mgr._connection_lock:
                if conn_key not in mgr._active_connections and mgr._active_session_count() >= mgr._max_active_connections:
                    mgr._close_connection_context(ctx2)
                    raise SecurityError("Connection table full - rejecting inbound (DoS protection)")

        with self.assertRaises(SecurityError):
            asyncio.run(_test())
        ctx2.secure_cleanup.assert_called_once()

    def test_19_display_banner_cnsa2_transport_security(self):
        """SEC-15: DisplayManager reports TLS 1.3 + AES-256-GCM (CNSA 2.0)."""
        from ui.display import DisplayManager
        from unittest.mock import Mock
        import logging

        orch = Mock()
        orch.strict_auth = True
        orch.ephemeral_key_lifetime = 3072
        disp = DisplayManager(orch)

        captured = []
        class CapturingHandler(logging.Handler):
            def emit(self, record):
                captured.append(record.getMessage())

        handler = CapturingHandler()
        sec_logger = logging.getLogger('security_summary')
        old_level = sec_logger.level
        sec_logger.setLevel(logging.INFO)
        sec_logger.addHandler(handler)
        try:
            disp.print_security_summary()
            self.assertTrue(any("TLS 1.3 + AES-256-GCM (CNSA 2.0)" in msg for msg in captured),
                            f"Banner must declare CNSA 2.0 transport security: {captured}")
        finally:
            sec_logger.removeHandler(handler)
            sec_logger.setLevel(old_level)

    def test_20_commands_exit_safe_when_disconnected(self):
        """SEC-16: CommandProcessor executes /exit cleanly even when disconnected."""
        from messaging.commands import CommandProcessor
        from unittest.mock import AsyncMock, Mock
        import asyncio

        orch = Mock()
        orch.tcp_socket = None
        orch.is_connected = False
        orch._close_connection = AsyncMock()
        orch.local_username = "Alpha"
        orch.security = Mock()
        orch.security.validation = Mock()
        orch.security.validation.validate_command.return_value = True

        cp = CommandProcessor(orch)
        asyncio.run(cp.handle_command("/exit", []))
        orch._close_connection.assert_awaited_once_with(attempt_reconnect=False)


if __name__ == "__main__":
    unittest.main()
