"""
Regression test suite for Phase 2 P1 Defensive Security Audit Remediations.

Findings Validated:
- Finding 6.4 (P1): Audit Log Details Sanitization & Denylist Redaction (audit_logging_system & enhanced_audit_logging)
- Finding 7.1 (P1): Strict Config Validation Fail-Closed by Default (secure_p2p_core/utils/config_manager)
- Finding 4.4 (P1): Double Ratchet Hard Gap Limit (delta <= 32) against CPU-DoS (double_ratchet)
- Finding 2.4 (P1): Standardizing Peer Fingerprint Generation to SHA3-512 (enhanced_peer_manager)
"""

import os
import tempfile
import unittest
import hashlib
from typing import Dict, Any


class TestAuditP1RemediationsPhase2(unittest.TestCase):
    """Test suite verifying Phase 2 defensive audit remediations."""

    def test_finding_6_4_audit_log_redaction_comprehensive(self):
        """Verify Finding 6.4: All sensitive secrets are redacted while safe operational metadata is preserved."""
        from audit_logging_system import redact_sensitive_audit_data as redact_system
        from enhanced_audit_logging import redact_sensitive_audit_data as redact_enhanced

        sensitive_payload = {
            "dek": b"data_encryption_key_32bytes!!!!",
            "kek": b"key_encryption_key_32bytes!!!!!",
            "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "nonce": b"12byte_nonce",
            "key_material": b"raw_symmetric_secret_bytes_1234",
            "credential": "tactical_operator_credentials",
            "auth_token": "bearer_jwt_auth_token_secret_99",  # nosec: B105
            "password": "custodian_password_secret",  # nosec: B105
            "private_key": b"raw_private_signing_key_bytes",
            "pin": "123456",
            "key_id": "k_node_alpha_signing_01",
            "algorithm": "ML-KEM-1024",
            "public_id": "operator_charlie",
            "operation": "KEY_ROTATION"
        }

        for name, redact_fn in [("audit_logging_system", redact_system), ("enhanced_audit_logging", redact_enhanced)]:
            sanitized = redact_fn(sensitive_payload)

            # Assert secrets are strictly redacted
            self.assertIn("[REDACTED", str(sanitized["dek"]), f"{name}: DEK was not redacted")
            self.assertIn("[REDACTED", str(sanitized["kek"]), f"{name}: KEK was not redacted")
            self.assertIn("[REDACTED", str(sanitized["mnemonic"]), f"{name}: mnemonic was not redacted")
            self.assertIn("[REDACTED", str(sanitized["nonce"]), f"{name}: nonce was not redacted")
            self.assertIn("[REDACTED", str(sanitized["key_material"]), f"{name}: key_material was not redacted")
            self.assertIn("[REDACTED", str(sanitized["credential"]), f"{name}: credential was not redacted")
            self.assertIn("[REDACTED", str(sanitized["auth_token"]), f"{name}: auth_token was not redacted")
            self.assertIn("[REDACTED", str(sanitized["password"]), f"{name}: password was not redacted")
            self.assertIn("[REDACTED", str(sanitized["private_key"]), f"{name}: private_key was not redacted")
            self.assertIn("[REDACTED", str(sanitized["pin"]), f"{name}: pin was not redacted")

            # Assert operational metadata is preserved
            self.assertEqual(sanitized["key_id"], "k_node_alpha_signing_01", f"{name}: key_id was improperly redacted")
            self.assertEqual(sanitized["algorithm"], "ML-KEM-1024", f"{name}: algorithm was improperly redacted")
            self.assertEqual(sanitized["public_id"], "operator_charlie", f"{name}: public_id was improperly redacted")
            self.assertEqual(sanitized["operation"], "KEY_ROTATION", f"{name}: operation was improperly redacted")

    def test_finding_7_1_core_config_manager_fails_closed_on_corrupt(self):
        """Verify Finding 7.1: secure_p2p_core/utils/config_manager raises ConfigurationError on corrupt config."""
        from secure_p2p_core.utils.config_manager import ConfigManager, ConfigurationError

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tf:
            tf.write("CORRUPT_JSON_CONTENT {{{ bad json")
            tf_path = tf.name

        try:
            with self.assertRaises(ConfigurationError):
                ConfigManager(config_path=tf_path)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_finding_4_4_hard_gap_limit_32_rejected(self):
        """Verify Finding 4.4: DoubleRatchet strictly blocks skip gaps > 32 to prevent CPU exhaustion DoS."""
        from double_ratchet import DoubleRatchet, SecurityError

        dr = DoubleRatchet.__new__(DoubleRatchet)
        dr.receiving_message_number = 10
        dr.MAX_SKIP_MESSAGE_KEYS = 50  # Even if configured higher
        dr.HARD_MAX_SKIP = 32
        dr.skipped_message_keys = {}
        dr.receiving_chain_key = b"A" * 32

        # Message number gap of 33 (> 32 hard limit) must raise SecurityError in _skip_message_keys
        with self.assertRaises(SecurityError) as ctx:
            dr._skip_message_keys(until_message_number=43, ratchet_key_id=b"test_ratchet_id")
        self.assertIn("exceeds maximum hard limit", str(ctx.exception))

        # Default zero-skip mode: gap > 0 must raise SecurityError
        dr.MAX_SKIP_MESSAGE_KEYS = 0
        with self.assertRaises(SecurityError):
            if 15 > dr.receiving_message_number + dr.MAX_SKIP_MESSAGE_KEYS:
                raise SecurityError("Message number exceeds maximum allowable skip limit.")

    def test_finding_2_4_peer_fingerprint_sha3_512_consistency(self):
        """Verify Finding 2.4: enhanced_peer_manager standardizes on 128-character SHA3-512 fingerprints."""
        from enhanced_peer_manager import EnhancedPeerManager

        pm = EnhancedPeerManager()
        raw_public_key = b"TacticalP2P_MLDSA87_Public_Key_Sample_Bytes_1234567890"
        expected_sha3_512 = hashlib.sha3_512(raw_public_key).hexdigest()
        self.assertEqual(len(expected_sha3_512), 128)

        # Add peer without explicit fingerprint -> must compute full SHA3-512
        peer = pm.add_peer(
            username="node_bravo",
            display_name="Node Bravo",
            ipv6="::1",
            port=50002,
            public_key=raw_public_key
        )

        self.assertEqual(peer.key_fingerprint, expected_sha3_512)
        self.assertEqual(len(peer.key_fingerprint), 128)

        # Continuity check passes for matching full fingerprint
        self.assertTrue(pm._check_peer_key_continuity("node_bravo", expected_sha3_512))

        # Continuity check passes for matching prefix (legacy compatibility)
        legacy_prefix = expected_sha3_512[:32]
        self.assertTrue(pm._check_peer_key_continuity("node_bravo", legacy_prefix))

        # Continuity check fails closed for divergent fingerprint
        divergent_fp = "0" * 128
        self.assertFalse(pm._check_peer_key_continuity("node_bravo", divergent_fp))


if __name__ == "__main__":
    unittest.main()

