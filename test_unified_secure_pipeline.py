#!/usr/bin/env python3
"""
test_unified_secure_pipeline.py -- Verify the Zero-Gap Defense Pipeline

Tests that every message flows through ALL independent cryptographic layers:
  1. Quantized padding (metadata resistance)
  2. Inner envelope (PQ Double Ratchet)
  3. Outer envelope (Rust Native AEAD)
  4. Pipeline header framing

Also tests:
  - Fail-closed behavior on missing components
  - Backward compatibility with legacy frames
  - Independent layer isolation (breaking one layer does not expose plaintext)
"""

import os
import secrets
import struct
import unittest

from unified_secure_pipeline import (
    UnifiedSecurePipeline,
    PipelineSecurityError,
    PIPELINE_MAGIC,
    PIPELINE_VERSION,
    PIPELINE_TYPE_MSG,
    PIPELINE_TYPE_FILE,
    PIPELINE_TYPE_NC3,
    PAD_QUANTA,
)


class TestQuantizedPadding(unittest.TestCase):
    """Verify metadata-resistant quantized padding."""

    def test_pad_unpad_roundtrip(self):
        """Padding and unpadding must recover the original data exactly."""
        for size in [1, 10, 100, 255, 256, 500, 1000, 4000, 16000]:
            data = secrets.token_bytes(size)
            padded = UnifiedSecurePipeline._quantize_pad(data)
            recovered = UnifiedSecurePipeline._quantize_unpad(padded)
            self.assertEqual(data, recovered, f"Failed for size {size}")

    def test_padded_size_is_quantum(self):
        """Padded output must be exactly one of the fixed quanta."""
        for size in [1, 50, 255, 257, 1000, 4095, 8000]:
            data = secrets.token_bytes(size)
            padded = UnifiedSecurePipeline._quantize_pad(data)
            self.assertIn(len(padded), PAD_QUANTA,
                          f"Size {size} padded to {len(padded)}, not in quanta")

    def test_different_sizes_same_quantum(self):
        """Messages of different lengths within the same quantum produce identical-length output."""
        data_10 = secrets.token_bytes(10)
        data_200 = secrets.token_bytes(200)
        padded_10 = UnifiedSecurePipeline._quantize_pad(data_10)
        padded_200 = UnifiedSecurePipeline._quantize_pad(data_200)
        self.assertEqual(len(padded_10), len(padded_200),
                         "10-byte and 200-byte messages should pad to same quantum (256)")

    def test_unpad_corrupted_length_fails(self):
        """Corrupted length header must be rejected (fail-closed)."""
        # Forge a length header claiming 999999 bytes in a 256-byte frame
        fake = struct.pack(">I", 999999) + secrets.token_bytes(252)
        with self.assertRaises(PipelineSecurityError):
            UnifiedSecurePipeline._quantize_unpad(fake)


class TestPipelineHeader(unittest.TestCase):
    """Verify pipeline header wrap/unwrap."""

    def test_header_roundtrip(self):
        """Wrapping and unwrapping must recover type and data exactly."""
        data = b"CLASSIFIED DIRECTIVE ALPHA-7"
        for msg_type in [PIPELINE_TYPE_MSG, PIPELINE_TYPE_FILE, PIPELINE_TYPE_NC3]:
            frame = UnifiedSecurePipeline._wrap_header(msg_type, data)
            recovered_type, recovered_data = UnifiedSecurePipeline._unwrap_header(frame)
            self.assertEqual(msg_type, recovered_type)
            self.assertEqual(data, recovered_data)

    def test_header_magic_check(self):
        """Invalid magic bytes must be rejected."""
        bad_frame = b"\x00\x00" + PIPELINE_VERSION + b"\x01" + struct.pack(">I", 5) + b"hello"
        with self.assertRaises(PipelineSecurityError):
            UnifiedSecurePipeline._unwrap_header(bad_frame)

    def test_header_version_check(self):
        """Invalid version must be rejected."""
        bad_frame = PIPELINE_MAGIC + b"BADVERS" + b"\x01" + struct.pack(">I", 5) + b"hello"
        with self.assertRaises(PipelineSecurityError):
            UnifiedSecurePipeline._unwrap_header(bad_frame)

    def test_truncated_frame_rejected(self):
        """Truncated frames must be rejected."""
        with self.assertRaises(PipelineSecurityError):
            UnifiedSecurePipeline._unwrap_header(b"\x5A\x47")


class TestFullPipelineSealOpen(unittest.TestCase):
    """End-to-end seal/open through all layers."""

    def _make_mock_ratchet(self):
        """Create a minimal ratchet mock that encrypts/decrypts with AES-GCM."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = secrets.token_bytes(32)
        class MockRatchet:
            def __init__(self, k):
                self._gcm = AESGCM(k)
                self._enc_counter = 0
                self._dec_counter = 0
            def encrypt(self, plaintext):
                nonce = self._enc_counter.to_bytes(12, 'big')
                self._enc_counter += 1
                return nonce + self._gcm.encrypt(nonce, bytes(plaintext), b"mock-ratchet")
            def decrypt(self, ciphertext):
                nonce = ciphertext[:12]
                return self._gcm.decrypt(nonce, ciphertext[12:], b"mock-ratchet")
        return MockRatchet(key), MockRatchet(key)

    def test_seal_open_python_only(self):
        """Full seal/open with Rust layer disabled (inner ratchet only)."""
        pipeline_a = UnifiedSecurePipeline()
        pipeline_b = UnifiedSecurePipeline()
        ratchet_a, ratchet_b = self._make_mock_ratchet()

        plaintext = b"FLASH ORDER: SCRAMBLE FIGHTER WING 12 TO GRID ALPHA-7"
        sealed = pipeline_a.seal(plaintext, ratchet_a)

        # Verify pipeline header is present
        self.assertEqual(sealed[:2], PIPELINE_MAGIC)

        msg_type, recovered = pipeline_b.open(sealed, ratchet_b)
        self.assertEqual(msg_type, PIPELINE_TYPE_MSG)
        self.assertEqual(plaintext, recovered)

    def test_seal_open_with_rust_layer(self):
        """Full seal/open with Rust AEAD outer envelope active."""
        try:
            from destroyer_node import DestroyerNode
        except ImportError:
            self.skipTest("destroyer_core not built")

        pipeline_a = UnifiedSecurePipeline()
        pipeline_b = UnifiedSecurePipeline()

        # Establish Rust layer with a shared root key
        root_key = secrets.token_bytes(32)
        self.assertTrue(pipeline_a.establish_rust_layer(root_key, is_initiator=True))
        self.assertTrue(pipeline_b.establish_rust_layer(root_key, is_initiator=False))
        self.assertTrue(pipeline_a.is_fully_armed)
        self.assertTrue(pipeline_b.is_fully_armed)

        ratchet_a, ratchet_b = self._make_mock_ratchet()

        plaintext = b"NC3/EAM: AUTHENTICATE DELTA-SEVEN-NINER"
        sealed = pipeline_a.seal(plaintext, ratchet_a, msg_type=PIPELINE_TYPE_NC3)

        # The sealed output must NOT contain the plaintext
        self.assertNotIn(plaintext, sealed)

        msg_type, recovered = pipeline_b.open(sealed, ratchet_b)
        self.assertEqual(msg_type, PIPELINE_TYPE_NC3)
        self.assertEqual(plaintext, recovered)

    def test_rust_layer_independence(self):
        """Breaking the Rust outer layer must NOT expose plaintext.

        If an attacker strips the Rust AEAD, they should see only
        the inner ratchet ciphertext (still encrypted).
        """
        try:
            from destroyer_node import DestroyerNode
        except ImportError:
            self.skipTest("destroyer_core not built")

        pipeline = UnifiedSecurePipeline()
        root_key = secrets.token_bytes(32)
        pipeline.establish_rust_layer(root_key, is_initiator=True)

        ratchet_a, _ = self._make_mock_ratchet()
        plaintext = b"TOP SECRET COORDINATES: 38.8977 N, 77.0365 W"
        sealed = pipeline.seal(plaintext, ratchet_a)

        # Strip the pipeline header
        _, outer_data = UnifiedSecurePipeline._unwrap_header(sealed)

        # Even with access to outer_data, plaintext must NOT be visible
        self.assertNotIn(plaintext, outer_data)

        # Strip the Rust AEAD to get the inner ratchet ciphertext
        node_attacker = DestroyerNode()
        node_attacker.establish(
            # Derive same frame key to simulate attacker breaking Rust layer
            self._derive_frame_key(root_key),
            is_initiator=False,
        )
        inner_ciphertext = node_attacker.open_stream(bytes(outer_data))
        # Even after breaking Rust, plaintext is STILL NOT VISIBLE
        # (sealed by the independent PQ ratchet)
        self.assertIsNotNone(inner_ciphertext)
        self.assertNotIn(plaintext, inner_ciphertext)

    @staticmethod
    def _derive_frame_key(root_key):
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        hkdf = HKDF(algorithm=hashes.SHA512(), length=32,
                     salt=b"destroyer-p2p-rust-v1", info=b"destroyer/frame/v1")
        return hkdf.derive(root_key)

    def test_fail_closed_no_ratchet(self):
        """Seal must fail-closed if ratchet is None."""
        pipeline = UnifiedSecurePipeline()
        with self.assertRaises(PipelineSecurityError):
            pipeline.seal(b"test", None)

    def test_fail_closed_empty_plaintext(self):
        """Seal must fail-closed on empty plaintext."""
        pipeline = UnifiedSecurePipeline()
        ratchet_a, _ = self._make_mock_ratchet()
        with self.assertRaises(PipelineSecurityError):
            pipeline.seal(b"", ratchet_a)

    def test_fail_closed_rust_required_but_missing(self):
        """When P2P_DATA_PLANE=rust but Rust is not established, seal must fail."""
        pipeline = UnifiedSecurePipeline()
        ratchet_a, _ = self._make_mock_ratchet()

        os.environ['P2P_DATA_PLANE'] = 'rust'
        try:
            with self.assertRaises(PipelineSecurityError):
                pipeline.seal(b"test", ratchet_a)
        finally:
            os.environ.pop('P2P_DATA_PLANE', None)

    def test_pipeline_status_telemetry(self):
        """Status must reflect pipeline state accurately."""
        pipeline = UnifiedSecurePipeline()
        status = pipeline.status()
        self.assertIn("pipeline_id", status)
        self.assertFalse(status["layer2_rust_active"])
        self.assertEqual(status["sealed_count"], 0)

    def test_multiple_messages_sequential(self):
        """Multiple messages must seal/open correctly in sequence."""
        pipeline_a = UnifiedSecurePipeline()
        pipeline_b = UnifiedSecurePipeline()

        try:
            from destroyer_node import DestroyerNode
            root_key = secrets.token_bytes(32)
            pipeline_a.establish_rust_layer(root_key, is_initiator=True)
            pipeline_b.establish_rust_layer(root_key, is_initiator=False)
        except ImportError:
            pass  # Continue without Rust layer

        ratchet_a, ratchet_b = self._make_mock_ratchet()

        messages = [
            b"Message 1: AUTHENTICATE",
            b"Message 2: FLASH ORDER ALPHA",
            b"Message 3: CONFIRM RECEIPT",
            b"Message 4: EXECUTE OPERATION OMEGA",
            b"Message 5: ACKNOWLEDGE AND COMPLY",
        ]

        for i, msg in enumerate(messages):
            sealed = pipeline_a.seal(msg, ratchet_a)
            msg_type, recovered = pipeline_b.open(sealed, ratchet_b)
            self.assertEqual(msg, recovered, f"Message {i+1} roundtrip failed")

        self.assertEqual(pipeline_a.status()["sealed_count"], 5)
        self.assertEqual(pipeline_b.status()["opened_count"], 5)

    def test_cer_epoch_rotation(self):
        """Verify Continuous Epoch Ratchet (CER) rotates epoch and key chain."""
        pipeline = UnifiedSecurePipeline()
        root_key = secrets.token_bytes(32)
        pipeline.establish_rust_layer(root_key, is_initiator=True)

        self.assertEqual(pipeline.current_epoch, 0)
        new_epoch = pipeline.rotate_epoch()
        self.assertEqual(new_epoch, 1)
        self.assertEqual(pipeline.current_epoch, 1)

        new_epoch_2 = pipeline.rotate_epoch()
        self.assertEqual(new_epoch_2, 2)
        self.assertEqual(pipeline.status()["current_epoch"], 2)

    def test_triple_hybrid_kem_pipeline(self):
        """Verify Triple-Hybrid KEM session establishment for initiator and responder."""
        pipeline_init = UnifiedSecurePipeline()
        pipeline_resp = UnifiedSecurePipeline()

        # Step 1: Responder generates hybrid keypair
        pk, _ = pipeline_resp.establish_from_triple_hybrid(is_initiator=False)
        self.assertGreater(len(pk), 1000)  # P-521 + ML-KEM-1024

        # Step 2: Initiator encapsulates against responder public key
        ct, ss_init = pipeline_init.establish_from_triple_hybrid(is_initiator=True, peer_pubkey=pk)
        self.assertGreater(len(ct), 1000)
        self.assertEqual(len(ss_init), 48)  # HKDF-SHA384 shared secret

        # Step 3: Responder decapsulates ciphertext
        ss_resp = pipeline_resp.complete_triple_hybrid_responder(ct)
        self.assertEqual(ss_init, ss_resp, "Initiator and responder must derive identical shared secret")

        # Step 4: Both pipelines now have active Rust AEAD layer
        self.assertTrue(pipeline_init.is_fully_armed)
        self.assertTrue(pipeline_resp.is_fully_armed)

    def test_teardown_zeroizes_secrets(self):
        """Verify teardown securely cleans up keys and pipeline state."""
        pipeline = UnifiedSecurePipeline()
        root_key = secrets.token_bytes(32)
        pipeline.establish_rust_layer(root_key, is_initiator=True)
        self.assertTrue(pipeline.is_fully_armed)

        pipeline.teardown()
        self.assertFalse(pipeline.is_fully_armed)
        self.assertIsNone(pipeline._epoch_root_key)
        self.assertIsNone(pipeline._rust_node)

    def test_autonomous_defense_ratchet_and_zero_gap_session(self):
        """Verify AutonomousDefenseRatchet and create_zero_gap_session factory."""
        from unified_secure_pipeline import (
            AutonomousDefenseRatchet,
            create_zero_gap_session,
        )

        shared_secret = secrets.token_bytes(32)

        # Test ratchet standalone
        ratch_a = AutonomousDefenseRatchet(shared_secret, is_initiator=True)
        ratch_b = AutonomousDefenseRatchet(shared_secret, is_initiator=False)

        plain1 = b"DIRECTIVE_ALPHA_TRANSMIT_AIR_DEFENSE_CODE"
        ct1 = ratch_a.encrypt(plain1)
        pt1 = ratch_b.decrypt(ct1)
        self.assertEqual(plain1, pt1)

        # Anti-replay: repeating ct1 must raise PipelineSecurityError
        with self.assertRaises(PipelineSecurityError):
            ratch_b.decrypt(ct1)

        # Tampering with MAC must fail closed
        ct_tampered = ct1[:25] + bytes([ct1[25] ^ 0xFF]) + ct1[26:]
        with self.assertRaises(PipelineSecurityError):
            ratch_b.decrypt(ct_tampered)

        # Test factory: create_zero_gap_session
        pipe_init, r_init = create_zero_gap_session(shared_secret, is_initiator=True)
        pipe_resp, r_resp = create_zero_gap_session(shared_secret, is_initiator=False)

        # Multi-message bidirectional exchange
        for i in range(5):
            m_a = f"DEFCON_1_STATUS_CHECK_PACKET_{i}".encode("utf-8")
            s_a = pipe_init.seal(m_a, r_init)
            t_a, dec_a = pipe_resp.open(s_a, r_resp)
            self.assertEqual(m_a, dec_a)

            m_b = f"DEFCON_1_STATUS_ACK_PACKET_{i}".encode("utf-8")
            s_b = pipe_resp.seal(m_b, r_resp)
            t_b, dec_b = pipe_init.open(s_b, r_init)
            self.assertEqual(m_b, dec_b)

        ratch_a.teardown()
        ratch_b.teardown()
        pipe_init.teardown()
        pipe_resp.teardown()


if __name__ == "__main__":
    unittest.main()


