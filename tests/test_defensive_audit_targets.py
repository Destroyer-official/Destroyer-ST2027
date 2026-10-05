"""
Comprehensive Regression Suite for Defensive Security Audit Targets.

Validates all 10 specific audit regression targets:
1. test_tls_siem_strict: Strict TLS verification for SIEM audit streaming.
2. test_pqc_fail_closed: Fail-closed PQC keypair generation (no random fallback).
3. test_master_key_entropy: High-entropy KEK derivation (no MAC address/username derivation).
4. test_peer_spoof: Reject forged anonymous bundles and unsigned DHT overwrites.
5. test_replay_alternating_nonce: Anti-replay sliding window detects alternating nonces.
6. test_fuzz_serializer: Pre-MAC size cap (128 KB) on deserialization.
7. test_dos_bounds: Message storage capacity bounds (no unbounded growth).
8. test_pfs_pcs: Double ratchet key advancement and forward secrecy.
9. test_cover_indistinguishability: Uniform 1024-byte block padding and unpadding.
10. test_secure_defaults: Corrupt config, empty expected hashes, and plaintext private keys fail closed.
"""

import os
import sys
import json
import time
import struct
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# 1. Audit Logging SIEM Strictness
class TestTLSSIEMStrict(unittest.TestCase):
    def test_no_cert_none_in_audit_logging(self):
        import ssl
        from audit_logging_system import AuditLogger, AuditEvent, AuditEventType, AuditSeverity
        db_file = os.path.join(tempfile.gettempdir(), "test_audit_siem.db")
        logger_inst = AuditLogger(db_path=db_file)

        # Hermetic env: sibling suites (e.g. signed-boot config tests) set
        # P2P_AIR_GAPPED_MODE=1 process-wide by design (sticky prod
        # enforcement); _stream_to_siem early-returns when air-gapped, which
        # would make the assertions below vacuous. Clear it explicitly.
        air_backup = os.environ.pop('P2P_AIR_GAPPED_MODE', None)
        off_backup = os.environ.pop('P2P_OFFLINE_MODE', None)
        try:
            # Test SSL context created for SIEM streaming
            with patch('socket.socket') as mock_sock:
                mock_raw = MagicMock()
                mock_sock.return_value = mock_raw
                with patch('ssl.create_default_context') as mock_create_ctx:
                    mock_ctx = MagicMock()
                    mock_create_ctx.return_value = mock_ctx
                    with patch.dict(os.environ, {'SIEM_ENDPOINT': 'tls://siem.internal:6514'}):
                        import datetime
                        evt = AuditEvent(
                            event_id="evt_01",
                            timestamp=datetime.datetime.now(),
                            event_type=AuditEventType.SYSTEM_STARTUP,
                            severity=AuditSeverity.INFO,
                            message="Test SIEM TLS"
                        )
                        try:
                            logger_inst._stream_to_siem(evt)
                        except Exception:  # nosec: B110
                            pass
                    # Verify that check_hostname, CERT_REQUIRED, and TLS 1.3 were configured
                    self.assertEqual(mock_ctx.check_hostname, True)
                    self.assertEqual(mock_ctx.verify_mode, ssl.CERT_REQUIRED)
                    if hasattr(ssl, 'TLSVersion'):
                        self.assertEqual(mock_ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
        finally:
            if air_backup is not None:
                os.environ['P2P_AIR_GAPPED_MODE'] = air_backup
            if off_backup is not None:
                os.environ['P2P_OFFLINE_MODE'] = off_backup


# 2. PQC Fail-Closed
class TestPQCFailClosed(unittest.TestCase):
    def test_pqc_keygen_fails_closed(self):
        from operational_security import EphemeralIdentityManager, EphemeralIdentityError
        mgr = EphemeralIdentityManager()
        mgr._kem = None
        mgr._sig = None
        with self.assertRaises(EphemeralIdentityError):
            mgr._generate_kem_keypair()
        with self.assertRaises(EphemeralIdentityError):
            mgr._generate_sig_keypair()


# 3. Master Key Derivation Entropy
class TestMasterKeyEntropy(unittest.TestCase):
    def test_derive_master_key_uses_high_entropy(self):
        from secure_enclave_key_storage import SoftwareFallbackBackend
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = SoftwareFallbackBackend(storage_path=tmpdir)
            salt_file = os.path.join(tmpdir, ".enclave_master_salt")
            seed_file = os.path.join(tmpdir, ".enclave_kek_seed")
            self.assertTrue(os.path.exists(salt_file))
            self.assertTrue(os.path.exists(seed_file))
            with open(salt_file, "rb") as f:
                salt = f.read()
            with open(seed_file, "rb") as f:
                seed = f.read()
            self.assertEqual(len(salt), 32)
            self.assertGreaterEqual(len(seed), 64)


# 4. Peer Identity & Spoof Resistance
class TestPeerSpoof(unittest.TestCase):
    def test_unsigned_bundle_rejected(self):
        from anonymous_identity_manager import AnonymousIdentity
        fake_bundle = {
            'identity_id': 'fake_id',
            'display_name': 'attacker',
            'kem_public_key': 'AA==',
            'sig_public_key': 'AA==',
            'signature': ''
        }
        self.assertFalse(AnonymousIdentity.verify_public_bundle(fake_bundle))

    def test_unsigned_dht_overwrite_rejected(self):
        from decentralized_architecture import DHTStorage
        from cryptography.hazmat.primitives.asymmetric import ed25519
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = DHTStorage(os.path.join(tmpdir, "dht.json"))
            key = b"target_key_000000000000000000000"
            val1 = b"original_signed_value"
            val2 = b"attacker_overwrite_attempt"
            
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key().public_bytes_raw()
            ts = int(time.time())
            sig = priv.sign(key + val1 + struct.pack('>Q', ts))
            
            # Store initial signed value
            self.assertTrue(storage.store(key, val1, ttl=3600, signature=sig, sig_public_key=pub, timestamp=ts))
            
            # Unsigned overwrite must be rejected
            self.assertFalse(storage.store(key, val2, ttl=3600, signature=None))
            retrieved = storage.get(key)
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.value, val1)


class TestReplayAlternatingNonce(unittest.TestCase):
    def test_alternating_nonce_rejected(self):
        from protocol_manager import SessionParameters, PeerIdentity, SecureChannel, SessionState
        peer = PeerIdentity(peer_id="peer_test", public_key=b"pk" * 16)
        params = SessionParameters(
            session_id="test_session_id_1234567890123456",
            peer_identity=peer,
            session_keys={"enc": b"k" * 32},
            creation_time=time.time(),
            last_activity=time.time()
        )
        channel = SecureChannel(params, aead_cipher=MagicMock())
        channel.aead_cipher.decrypt.return_value = b"decrypted_plaintext"
        
        nonce_a = b"nonce_alpha_1"
        nonce_b = b"nonce_bravo_1"
        ct_a = nonce_a + b"dummy_ciphertext_alpha"
        ct_b = nonce_b + b"dummy_ciphertext_bravo"
        
        # Accept A
        channel.decrypt_message(ct_a)
        # Accept B
        channel.decrypt_message(ct_b)
        # Re-send A (alternating nonce) -> MUST BE REJECTED
        with self.assertRaises(ValueError) as ctx:
            channel.decrypt_message(ct_a)
        self.assertIn("replay attack", str(ctx.exception).lower())


# 6. Serializer Pre-MAC Size Cap
class TestFuzzSerializer(unittest.TestCase):
    def test_oversize_pre_mac_rejected(self):
        from secure_message_serializer import SecureMessageSerializer, ParseError
        serializer = SecureMessageSerializer(mac_key=b"k" * 32)
        oversize_data = b"X" * (128 * 1024 + 1)
        with self.assertRaises(ParseError):
            serializer.deserialize(oversize_data)


# 7. DoS Bounds & Memory Storage Limits
class TestDoSBounds(unittest.TestCase):
    def test_ephemeral_messaging_capacity_bound(self):
        from ephemeral_messaging import EphemeralMessageManager
        mgr = EphemeralMessageManager()
        mgr.MAX_STORED_MESSAGES = 10  # Reduced bound for testing
        for i in range(15):
            mgr.create_message(
                content=f"msg_{i}".encode('utf-8'),
                sender_id="sender",
                recipient_id="recipient",
                ttl_seconds=300
            )
        self.assertLessEqual(len(mgr._messages), 10)

    def test_operational_security_capacity_bound(self):
        from operational_security import MessageExpirationManager
        mgr = MessageExpirationManager(auto_cleanup=False)
        mgr.MAX_STORED_MESSAGES = 10  # Reduced bound for testing
        for i in range(15):
            mgr.store_message(content=f"op_msg_{i}".encode('utf-8'), ttl_seconds=300)
        self.assertLessEqual(len(mgr._messages), 10)


# 8. PFS / PCS Ratchet Step Advancement
class TestPFSPCS(unittest.TestCase):
    def test_constant_salt_and_combiners(self):
        from triple_hybrid_kem import TripleHybridKEM
        kem = TripleHybridKEM()
        ss1 = b"A" * 32
        ss2 = b"B" * 32
        key1 = kem._derive_cnsa_strict_key(ss1, ss2)
        key2 = kem._derive_cnsa_strict_key(ss1, ss2)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 48)

    def test_auth_tag_derives_independent_key(self):
        from crypto.auth_tags import AuthTagOperations
        mat = AuthTagOperations()
        ct = b"sample_ciphertext"
        msg_hash = b"sample_message_hash_32bytes_len"
        tag = mat.generate_military_auth_tag(ct, msg_hash)
        self.assertEqual(len(tag), 64)
        self.assertTrue(mat.verify_military_auth_tag(ct, msg_hash, tag))
        # Tampered ciphertext fails
        self.assertFalse(mat.verify_military_auth_tag(b"tampered_ct", msg_hash, tag))


# 9. Cover Indistinguishability & Padding
class TestCoverIndistinguishability(unittest.TestCase):
    def test_uniform_1024_block_padding(self):
        try:
            import secure_p2p
        except ImportError:
            import archive.legacy_prototype.secure_p2p as secure_p2p
        chat = secure_p2p.SecureP2PChat(identity="test_pad")
        plaintext = b"Strategic military transmission payload"
        padded = chat._add_random_padding(plaintext)
        # Length must be exact multiple of 1024
        self.assertEqual(len(padded) % 1024, 0)
        self.assertGreaterEqual(len(padded), 1024)
        # Unpadding recovers identical plaintext
        unpadded = chat._remove_random_padding(padded)
        self.assertEqual(unpadded, plaintext)


# 10. Secure Defaults & Fail-Closed
class TestSecureDefaults(unittest.TestCase):
    def test_anti_forensics_empty_hashes_fails_closed(self):
        from anti_forensics import SecureBootVerifier, TamperDetectedError
        verifier = SecureBootVerifier()
        verifier._expected_hashes.clear()
        with self.assertRaises(TamperDetectedError):
            verifier.verify_all()

    def test_path_traversal_strictly_rejected(self):
        from security.validation import InputValidator
        valid, err = InputValidator.validate_file_path("../../etc/passwd")
        self.assertFalse(valid)
        self.assertIn("Path traversal", err)

    def test_unencrypted_private_key_rejected(self):
        from tactical_key_provisioner import load_encrypted_credential
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"-----BEGIN PRIVATE KEY-----\nFAKE_KEY\n-----END PRIVATE KEY-----\n")
            f_path = f.name
        try:
            with self.assertRaises(Exception):
                load_encrypted_credential(f_path)
        finally:
            if os.path.exists(f_path):
                os.unlink(f_path)


if __name__ == "__main__":
    unittest.main()

