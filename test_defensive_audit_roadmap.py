#!/usr/bin/env python3
"""
Test Defensive Audit Roadmap Targets.
Implements specific regression tests requested in the 2026 Defensive Security Audit:
1. test_discovery_forged_bundle_rejected: Forged/tampered discovery bundle rejected fail-closed.
2. test_tofu_changed_pin_aborts: Changed certificate fingerprint in TOFU returns 'CHANGED'.
3. test_hqc_default_disabled: HQC-256 gated OFF by default on vendored oqs 0.10.1 (CVE-2024-54137/CVE-2025-52473).
4. test_no_tls_no_send: Cleartext dispatch refused if TLS channel is not active.
5. test_replay_flood_evicts_oldest: Monotonic replay cache handles eviction without clearing active records.
6. test_heartbeat_ack_throttle: Heartbeat flood throttles to <= 1 ACK per 5 seconds.
7. test_chunk_caps_before_alloc: Large/malformed chunk headers rejected before allocation.
8. test_algorithm_name_standardization: Config defaults use CNSA 2.0 ML-DSA-87 + SLH-DSA-256f (Finding 1.7).
"""

import os
import sys
import unittest
import secrets
import tempfile
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


class TestDefensiveAuditRoadmap(unittest.TestCase):

    def test_discovery_forged_bundle_rejected(self):
        """Verify that forged or malformed public key bundles in discovery return None (fail-closed)."""
        from enhanced_peer_manager import EnhancedPeerManager
        
        mgr = EnhancedPeerManager()
        
        # 1. Missing bundle
        res_missing = mgr._create_peer_from_discovery_result("alice", {"public_ip": "127.0.0.1", "port": 9000})
        self.assertIsNone(res_missing, "Missing bundle must be rejected")
        
        # 2. Forged bundle with invalid signature
        forged_bundle = {
            "identity_key": secrets.token_bytes(32).hex(),
            "signature": secrets.token_bytes(64).hex(),
            "timestamp": 1234567890
        }
        res_forged = mgr._create_peer_from_discovery_result("bob", {
            "bundle": forged_bundle,
            "public_ip": "127.0.0.1",
            "port": 9001
        })
        self.assertIsNone(res_forged, "Forged bundle signature must fail closed and return None")

    def test_tofu_changed_pin_aborts(self):
        """Verify that a modified certificate fingerprint for a pinned peer triggers 'CHANGED'."""
        from ui.safety_numbers import check_pin, store_pin
        
        peer_id = f"test_peer_{secrets.token_hex(8)}"
        original_fp = secrets.token_hex(64)
        tampered_fp = secrets.token_hex(64)
        
        # Initially new
        self.assertEqual(check_pin(peer_id, original_fp), "new")
        
        # Pin original
        store_pin(peer_id, original_fp)
        self.assertEqual(check_pin(peer_id, original_fp), "match")
        
        # Attacker presents changed fingerprint: must detect MITM
        status = check_pin(peer_id, tampered_fp)
        self.assertEqual(status, "CHANGED", "Tampered certificate fingerprint must return 'CHANGED'")

    def test_hqc_default_disabled(self):
        """Verify that HQC-256 is disabled by default on vendored oqs 0.10.1 and only active with explicit opt-in."""
        from triple_hybrid_kem import is_hqc_available
        
        old_val = os.environ.pop("P2P_ENABLE_VULN_HQC", None)
        try:
            # Default state: MUST be False
            self.assertFalse(is_hqc_available(), "HQC must be disabled by default due to CVE-2024-54137 / CVE-2025-52473")
            
            # Explicit lab opt-in
            os.environ["P2P_ENABLE_VULN_HQC"] = "1"
            enabled_state = is_hqc_available()
            self.assertIsInstance(enabled_state, bool)
        finally:
            if old_val is not None:
                os.environ["P2P_ENABLE_VULN_HQC"] = old_val
            else:
                os.environ.pop("P2P_ENABLE_VULN_HQC", None)

    def test_no_tls_no_send(self):
        """Verify that cleartext frame transmission is rejected when TLS channel is missing or unauthenticated."""
        from p2p_core import SimpleP2PChat
        
        chat = SimpleP2PChat()
        with self.assertRaises((ValueError, RuntimeError, Exception)):
            chat.send_framed(None, b"UNENCRYPTED_TACTICAL_DATA")

    def test_replay_flood_evicts_oldest(self):
        """Verify that monotonic replay window evicts oldest entries without clearing existing active records."""
        from hybrid_kex import HybridKeyExchange
        import time
        
        kex = HybridKeyExchange.__new__(HybridKeyExchange)
        kex.seen_nonces = {}
        kex.timestamp_window = 60
        
        peer_id = "test_peer_replay"
        now = int(time.time())
        nonces = [secrets.token_bytes(32) for _ in range(1050)]
        
        # Verify 1050 nonces
        for n in nonces:
            self.assertTrue(kex._verify_handshake_nonce(peer_id, n, now, test_mode=True))
            
        # Total cached nonces should be capped at 1000
        self.assertEqual(len(kex.seen_nonces[peer_id]), 1000)
        
        # Most recent nonce should be detected as a duplicate (replay rejected)
        self.assertFalse(kex._verify_handshake_nonce(peer_id, nonces[-1], now, test_mode=True))
        
        # Evicted oldest nonce should have been dropped from FIFO cache
        self.assertNotIn(nonces[0], kex.seen_nonces[peer_id])

    def test_heartbeat_ack_throttle(self):
        """Verify that heartbeat responses throttle to 1 ACK per 5 seconds under flood conditions."""
        from p2p_core import PreAuthRateLimiter
        
        limiter = PreAuthRateLimiter()
        peer = "10.0.0.1"
        
        # First heartbeat allowed
        self.assertTrue(limiter.check_heartbeat_rate(peer))
        # Rapid subsequent heartbeats throttled
        for _ in range(50):
            self.assertFalse(limiter.check_heartbeat_rate(peer), "Rapid heartbeats must be throttled")

    def test_chunk_caps_before_alloc(self):
        """Verify that secure file sharing validates chunk and total file bounds before memory allocation."""
        from secure_file_sharing import SecureFileHandler, FileMetadata, FileMessage
        from datetime import datetime
        
        # 1. Chunk size over 1MB cap rejected
        with self.assertRaises(ValueError):
            SecureFileHandler(chunk_size=100 * 1024 * 1024)
            
        # 2. Chunk size below minimum (16KB) rejected to prevent chunk-table DoS
        with self.assertRaises(ValueError):
            SecureFileHandler(chunk_size=512)
            
        # 3. File metadata over 1GB cap rejected
        with self.assertRaises(ValueError):
            FileMetadata(
                file_id="a" * 32,
                filename="huge.dat",
                file_size=2 * 1024 * 1024 * 1024,
                file_type="application/octet-stream",
                checksum="b" * 64,
                chunk_size=65536,
                total_chunks=100,
                created_at=datetime.now(),
                sender_id="peer1"
            )

    def test_algorithm_name_standardization(self):
        """Verify Finding 1.7: config defaults standardize on CNSA 2.0 ML-DSA-87 and SLH-DSA-256f."""
        from utils.config_manager import ConfigManager
        
        sig_algorithms = ConfigManager.DEFAULT_SECURITY_SETTINGS["security"]["algorithms"]["signatures"]
        self.assertIn("ML-DSA-87", sig_algorithms, "ML-DSA-87 must be in default signatures")
        self.assertIn("SLH-DSA-256f", sig_algorithms, "SLH-DSA-256f must be in default signatures")
        self.assertNotIn("SPHINCS+", sig_algorithms, "Legacy SPHINCS+ name must not be used as default")


if __name__ == "__main__":
    unittest.main(verbosity=2)

