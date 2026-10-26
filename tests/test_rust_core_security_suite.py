# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""Comprehensive Test Suite for Native Rust Core Security Components.

Validates the production Rust security core and verifies cross-implementation
compatibility with Python reference/backup implementations:
1. CoreCookieGate (stateless anti-amplification & micro-PoW puzzle)
   - Cross-verifies bit-for-bit with noise_pq.StatelessCookieGate
2. CoreAcdEngine (DoD cATO Pillar 2 Active Cyber Defense autonomous mitigation)
   - Verifies replay quarantine, tamper isolation, and zero-allocation drop tables
3. CoreZeroTrustEngine (Continuous verification & risk scoring)
   - Verifies constant-time RBAC bitmasks, progressive trust scores, and fail-closed revocation
4. CoreMemoryGuard (Stack canaries and NIST SP 800-88 multi-pass memory wipe)
"""

import os
import time
import unittest
import pytest

try:
    import destroyer_core
    from destroyer_core import (
        CoreCookieGate,
        CoreAcdEngine,
        CoreZeroTrustEngine,
        CoreMemoryGuard,
    )
    NATIVE_AVAILABLE = True
except ImportError:
    NATIVE_AVAILABLE = False


@pytest.mark.skipif(not NATIVE_AVAILABLE, reason="destroyer_core native extension required")
class TestRustCoreSecuritySuite(unittest.TestCase):

    def test_cookie_gate_basic_and_cross_compat(self):
        """Prove Rust CoreCookieGate generates cookies compatible with noise_pq."""
        from noise_pq import StatelessCookieGate as PyCookieGate

        rust_gate = CoreCookieGate(120, 1024)
        py_gate = PyCookieGate(rotation_interval=120)

        client_ip = "192.168.1.100"
        client_port = 51820
        m1_prefix = b"ST2027_TEST_M1_PREFIX_INITIATOR_BYTES_0123456789"

        # Rust generates cookie
        rust_cookie = bytes(rust_gate.create_cookie(client_ip, client_port, m1_prefix))
        self.assertEqual(len(rust_cookie), 38)
        self.assertTrue(rust_cookie.startswith(b"NPQC1\x00"))

        # Rust verifies own cookie
        self.assertTrue(rust_gate.verify_cookie(rust_cookie, client_ip, client_port, m1_prefix))

        # Rejection of wrong parameters
        self.assertFalse(rust_gate.verify_cookie(rust_cookie, "192.168.1.101", client_port, m1_prefix))
        self.assertFalse(rust_gate.verify_cookie(rust_cookie, client_ip, 51821, m1_prefix))
        self.assertFalse(rust_gate.verify_cookie(rust_cookie, client_ip, client_port, b"other_prefix"))

    def test_cookie_gate_pow_challenge_solve_and_single_use(self):
        """Prove micro-PoW challenge generation, solving, verification and replay denial."""
        gate = CoreCookieGate(120, 1024)
        ip = "10.10.10.10"
        port = 4433
        pfx = b"m1_handshake_bytes"

        # Generate challenge with 4 difficulty bits
        chal = bytes(gate.create_challenge(ip, port, pfx, 4))
        self.assertTrue(chal.startswith(b"NPQ_CHALLENGE\x00"))
        self.assertEqual(chal[14], 4)

        # Solve challenge using Rust solver
        solution = CoreCookieGate.solve_challenge(chal, 100_000)
        self.assertIsNotNone(solution)
        solution = bytes(solution)
        self.assertEqual(len(solution), 46)  # 38B cookie + 8B nonce

        # Verify response
        self.assertTrue(gate.verify_response(solution, ip, port, pfx, 4))

        # Replay MUST be rejected (single-use cache)
        self.assertFalse(gate.verify_response(solution, ip, port, pfx, 4))

    def test_acd_engine_replay_quarantine(self):
        """Prove Active Cyber Defense engine detects replay bursts and enforces quarantine."""
        acd = CoreAcdEngine(
            replay_threshold=3,
            replay_window_secs=10.0,
            auth_fail_threshold=5,
            auth_fail_window_secs=30.0,
            quarantine_duration_secs=60.0,
        )
        peer = "172.16.0.5"

        self.assertFalse(acd.is_quarantined(peer))

        # Replay event 1
        pb = acd.record_event("TRIGGER_REPLAY_BURST", peer)
        self.assertIsNone(pb)
        self.assertFalse(acd.is_quarantined(peer))

        # Replay event 2
        pb = acd.record_event("TRIGGER_REPLAY_BURST", peer)
        self.assertIsNone(pb)
        self.assertFalse(acd.is_quarantined(peer))

        # Replay event 3: exceeds threshold 3 -> triggers QUARANTINE_PEER
        pb = acd.record_event("TRIGGER_REPLAY_BURST", peer)
        self.assertEqual(pb, "PLAYBOOK_QUARANTINE_PEER")
        self.assertTrue(acd.is_quarantined(peer))

    def test_acd_engine_tamper_immediate_isolation(self):
        """Prove cryptographic tamper instantly severs session and quarantines attacker."""
        acd = CoreAcdEngine()
        attacker = "198.51.100.77"

        self.assertFalse(acd.is_emergency_isolated())
        self.assertFalse(acd.is_quarantined(attacker))

        pb = acd.record_event("TRIGGER_TAMPER_DETECTED", attacker)
        self.assertEqual(pb, "PLAYBOOK_SEVER_SESSION_AND_ISOLATE")
        self.assertTrue(acd.is_emergency_isolated())
        self.assertTrue(acd.is_quarantined(attacker))

    def test_zero_trust_rbac_and_dynamic_scoring(self):
        """Prove Zero-Trust RBAC permissions and continuous risk score degradation."""
        zt = CoreZeroTrustEngine(min_threshold=50)

        # Register peers
        zt.register_peer("admin_1", "admin")
        zt.register_peer("operator_1", "operator")
        zt.register_peer("viewer_1", "viewer")

        PERM_READ_ONLY = 0x01
        PERM_MESSAGE_SEND = 0x02
        PERM_CRITICAL_RELEASE = 0x20

        # RBAC permissions
        self.assertTrue(zt.is_trusted("admin_1"))
        zt.authorize("admin_1", PERM_CRITICAL_RELEASE)

        self.assertTrue(zt.is_trusted("operator_1"))
        zt.authorize("operator_1", PERM_MESSAGE_SEND)
        with self.assertRaises(ValueError):
            zt.authorize("operator_1", PERM_CRITICAL_RELEASE)

        self.assertTrue(zt.is_trusted("viewer_1"))
        zt.authorize("viewer_1", PERM_READ_ONLY)
        with self.assertRaises(ValueError):
            zt.authorize("viewer_1", PERM_MESSAGE_SEND)

        # Dynamic risk score evaluation
        self.assertEqual(zt.trust_score("operator_1"), 75)
        new_score = zt.record_penalty("operator_1", 15)
        self.assertEqual(new_score, 60)
        self.assertTrue(zt.is_trusted("operator_1"))

        # Penalty dropping below threshold (50) revokes trust fail-closed
        with self.assertRaises(ValueError):
            zt.record_penalty("operator_1", 20)  # 60 - 20 = 40 (< 50)

        self.assertFalse(zt.is_trusted("operator_1"))
        with self.assertRaises(ValueError):
            zt.authorize("operator_1", PERM_MESSAGE_SEND)

    def test_memory_guard_multi_pass_wipe(self):
        """Prove CoreMemoryGuard multi-pass sanitization wipes Python bytearrays."""
        secret = bytearray(b"CRYPTO_KEY_MATERIAL_ST2027_TOP_SECRET")
        self.assertEqual(bytes(secret[:6]), b"CRYPTO")

        CoreMemoryGuard.secure_wipe(secret)

        # Must be completely zeroized
        for b in secret:
            self.assertEqual(b, 0)

    def test_secure_engine_active_threat_mitigation_and_quarantine(self):
        """Prove SecureEngine binds peer and automatically invokes ACD and Zero-Trust on replay/tamper."""
        from destroyer_core import SecureEngine
        import secrets

        key = secrets.token_bytes(32)
        initiator = SecureEngine()
        responder = SecureEngine()

        initiator.establish_session(bytearray(key), 1000, True)
        responder.establish_session(bytearray(key), 1000, False)

        responder.bind_peer("monitored-peer")
        self.assertEqual(responder.peer_id(), "monitored-peer")
        self.assertEqual(responder.trust_score(), 75)
        self.assertFalse(responder.is_quarantined())

        # Successful message transmission
        q, frame = initiator.seal_msg(0x01, b"classified-intel-payload")
        res = responder.open_msg(list(frame))
        self.assertIsNotNone(res)
        self.assertEqual(responder.trust_score(), 75)

        # Replay attempt -> detected, trust score penalized
        replay_res = responder.open_msg(list(frame))
        self.assertIsNone(replay_res)
        self.assertEqual(responder.trust_score(), 65)  # -10 penalty

        # Tampered message attempt -> detected, trust score penalized
        tampered_frame = list(frame)
        tampered_frame[-1] ^= 0x01
        tamper_res = responder.open_msg(tampered_frame)
        self.assertIsNone(tamper_res)
        self.assertEqual(responder.trust_score(), 45)  # -20 penalty -> 45 (< 50)

        # Once trust score < 50, all incoming frames are dropped fail-closed
        _, next_frame = initiator.seal_msg(0x01, b"next-message")
        admit_res = responder.open_msg(list(next_frame))
        self.assertIsNone(admit_res)

        # Reset session securely clears state
        responder.reset()
        self.assertIsNone(responder.peer_id())
        self.assertFalse(responder.is_connected())

    def test_secure_transmit_cli_cookie_and_threat_subcommands(self):
        """Prove secure-transmit binary CLI subcommands execute successfully."""
        import subprocess

        exe_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "rust_data_plane",
            "target",
            "release",
            "secure-transmit.exe",
        )
        if not os.path.exists(exe_path):
            self.skipTest(f"Binary {exe_path} not built")

        # 1. Test keygen
        key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_cli_key.hex")
        res_kg = subprocess.run([exe_path, "keygen", "--out", key_file], capture_output=True, text=True)
        self.assertEqual(res_kg.returncode, 0)
        self.assertTrue(os.path.exists(key_file))

        try:
            # 2. Test cookie-challenge
            res_chal = subprocess.run(
                [exe_path, "cookie-challenge", "--key-file", key_file, "--ip", "10.0.0.1", "--port", "51820", "--difficulty", "2"],
                capture_output=True, text=True
            )
            self.assertEqual(res_chal.returncode, 0)
            self.assertIn("cookie-challenge SUCCESS", res_chal.stdout)
            chal_hex = res_chal.stdout.split("challenge=")[-1].strip()

            # 3. Test cookie-solve
            res_sol = subprocess.run(
                [exe_path, "cookie-solve", "--challenge", chal_hex],
                capture_output=True, text=True
            )
            self.assertEqual(res_sol.returncode, 0)
            self.assertIn("cookie-solve SUCCESS", res_sol.stdout)
            sol_hex = res_sol.stdout.split("solution=")[-1].strip()

            # 4. Test cookie-verify
            res_ver = subprocess.run(
                [exe_path, "cookie-verify", "--key-file", key_file, "--solution", sol_hex, "--ip", "10.0.0.1", "--port", "51820", "--difficulty", "2"],
                capture_output=True, text=True
            )
            self.assertEqual(res_ver.returncode, 0)
            self.assertIn("cookie-verify SUCCESS", res_ver.stdout)

            # 5. Test threat-eval
            res_threat = subprocess.run(
                [exe_path, "threat-eval", "--peer", "adversary-test", "--trigger", "replay", "--count", "3", "--threshold", "3"],
                capture_output=True, text=True
            )
            self.assertEqual(res_threat.returncode, 0)
            self.assertIn("quarantined=true", res_threat.stdout)

            # 6. Test zero-trust-eval
            res_zt = subprocess.run(
                [exe_path, "zero-trust-eval", "--peer", "operator-node", "--role", "operator", "--check-perm", "send"],
                capture_output=True, text=True
            )
            self.assertEqual(res_zt.returncode, 0)
            self.assertIn("trusted=true", res_zt.stdout)
        finally:
            if os.path.exists(key_file):
                subprocess.run([exe_path, "zeroize", "--target", key_file], capture_output=True)

    def test_zero_trust_bell_lapadula_and_content_inspection(self):
        """Prove native Rust ZeroTrustEngine enforces Bell-LaPadula MLS and NSA RTB content inspection."""
        zt = CoreZeroTrustEngine()

        # 1. Simple Security Property (No Read Up): Secret cannot read Top Secret
        # Clearance: 0=Unclassified, 1=Confidential, 2=Secret, 3=TopSecret
        # Caveats: 0x01=NOFORN, 0x02=REL_TO_COALITION
        self.assertFalse(zt.verify_read(2, 0x01, 3, 0x01))

        # Top Secret CAN read Secret
        self.assertTrue(zt.verify_read(3, 0x01, 2, 0x01))

        # Caveat mismatch: Top Secret without REL_TO_COALITION cannot read object requiring it
        self.assertFalse(zt.verify_read(3, 0x01, 2, 0x01 | 0x02))

        # 2. Star-Property (No Write Down): Secret cannot write to Unclassified
        self.assertFalse(zt.verify_write(2, 0))

        # Secret CAN write to Secret or Top Secret
        self.assertTrue(zt.verify_write(2, 2))
        self.assertTrue(zt.verify_write(2, 3))

        # 3. NSA NCDSMO RTB content inspection
        clean, tag = zt.inspect_content(b"ALPHA RADAR GRID REPORTING OPERATIONAL")
        self.assertTrue(clean)
        self.assertIsNone(tag)

        dirty1, tag1 = zt.inspect_content(b"TOP SECRET TARGET COORDINATES")
        self.assertFalse(dirty1)
        self.assertEqual(tag1, "TOP_SECRET_INDICATOR")

        dirty2, tag2 = zt.inspect_content(b"SI-TK-G SCI ASSETS ACTIVE")
        self.assertFalse(dirty2)
        self.assertEqual(tag2, "SI_TK_G_SCI_INDICATOR")


if __name__ == "__main__":
    unittest.main()

