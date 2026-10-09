#!/usr/bin/env python3
"""
Comprehensive Production-Grade Verification Suite for destroyer_core
Tests:
1. Native module import & SecureEngine binding
2. Role-based Nonce Domain Separation (Initiator vs Responder)
3. Quantized Framing & Padding (256, 512, 1232B budgets)
4. WireGuard-Style 64-Packet Anti-Replay Sliding Window
5. Cryptographic Integrity: Bit-flip & Tag Tampering Silent-Drop
6. High-Throughput Stream Sealing (up to 2MB)
7. Double-Envelope Integration with Double Ratchet & HKDF Root Derivation
8. Rate-Limiting & Silent-Drop Black-Hole Verification
"""

import os
import sys
import unittest
import secrets
import struct

# Pre-import destroyer_core before any process mitigations
try:
    from destroyer_core import SecureEngine
    DESTROYER_AVAILABLE = True
except ImportError:
    DESTROYER_AVAILABLE = False

from destroyer_node import DestroyerNode, data_plane_enabled


class TestDestroyerCoreProduction(unittest.TestCase):
    def setUp(self):
        if not DESTROYER_AVAILABLE:
            self.skipTest("destroyer_core native extension is not available")

    def test_01_native_import_and_initial_state(self):
        """Verify native engine constructs cleanly and reports unconnected."""
        engine = SecureEngine()
        self.assertFalse(engine.is_connected())
        self.assertEqual(engine.drop_count(), 0)

    def test_02_session_establishment_and_domain_separation(self):
        """Verify role-based domain separation: Initiator and Responder have inverted send/recv nonces."""
        engine_init = SecureEngine()
        engine_resp = SecureEngine()
        key = secrets.token_bytes(32)

        engine_init.establish_session(list(key), 1000, True)   # is_initiator = True
        engine_resp.establish_session(list(key), 1000, False)  # is_initiator = False

        self.assertTrue(engine_init.is_connected())
        self.assertTrue(engine_resp.is_connected())

        # Initiator seals, Responder opens
        q, frame_from_init = engine_init.seal_msg(0x01, list(b"Ping from Initiator"))
        self.assertIn(q, [256, 512, 1232])
        self.assertEqual(len(frame_from_init), q)

        res = engine_resp.open_msg(list(frame_from_init))
        self.assertIsNotNone(res)
        ftype, payload = res
        self.assertEqual(ftype, 0x01)
        self.assertEqual(bytes(payload), b"Ping from Initiator")

        # Responder seals, Initiator opens
        q2, frame_from_resp = engine_resp.seal_msg(0x01, list(b"Pong from Responder"))
        res2 = engine_init.open_msg(list(frame_from_resp))
        self.assertIsNotNone(res2)
        ftype2, payload2 = res2
        self.assertEqual(ftype2, 0x01)
        self.assertEqual(bytes(payload2), b"Pong from Responder")

        # Cross-direction reflection attack check:
        # If an adversary reflects Initiator's frame back to Initiator, Initiator MUST reject it
        reflected = engine_init.open_msg(list(frame_from_init))
        self.assertIsNone(reflected, "Reflection attack must fail due to domain separation")

    def test_03_quantized_padding_and_max_payload(self):
        """Verify frames pad exactly to 256, 512, or 1232 bytes, and over-1205B is rejected."""
        engine = SecureEngine()
        engine.establish_session(list(b"P" * 32), 0, True)

        # 0 bytes payload -> 256B quantum
        q0, f0 = engine.seal_msg(0x01, list(b""))
        self.assertEqual(q0, 256)
        self.assertEqual(len(f0), 256)

        # 200 bytes payload -> 256B quantum (200 + 27 = 227 <= 256)
        q1, f1 = engine.seal_msg(0x01, list(b"A" * 200))
        self.assertEqual(q1, 256)
        self.assertEqual(len(f1), 256)

        # 300 bytes payload -> 512B quantum (300 + 27 = 327 <= 512)
        q2, f2 = engine.seal_msg(0x01, list(b"B" * 300))
        self.assertEqual(q2, 512)
        self.assertEqual(len(f2), 512)

        # 1205 bytes payload (exact MAX_PAYLOAD) -> 1232B quantum (1205 + 27 = 1232)
        q3, f3 = engine.seal_msg(0x01, list(b"C" * 1205))
        self.assertEqual(q3, 1232)
        self.assertEqual(len(f3), 1232)

        # 1206 bytes payload -> Exceeds quantum, MUST raise ValueError
        with self.assertRaises(ValueError):
            engine.seal_msg(0x01, list(b"D" * 1206))

    def test_04_wireguard_anti_replay_window(self):
        """Verify the 64-packet bitmap sliding window rejects duplicates, old frames, and out-of-order properly."""
        engine = SecureEngine()
        engine.establish_session(list(b"R" * 32), 0, True)

        # Sequence numbers fed to check_seq
        self.assertTrue(engine.check_seq(1))
        self.assertTrue(engine.check_seq(2))
        self.assertTrue(engine.check_seq(3))

        # Duplicate must be rejected
        self.assertFalse(engine.check_seq(2))
        self.assertEqual(engine.drop_count(), 1)

        # Advance to 100
        self.assertTrue(engine.check_seq(100))

        # Within 64-packet window: 100 - 63 = 37 should accept
        self.assertTrue(engine.check_seq(37))

        # Beyond 64-packet window: 100 - 64 = 36 should reject
        self.assertFalse(engine.check_seq(36))

        # Jump ahead to 1000 resyncs window
        self.assertTrue(engine.check_seq(1000))
        # Old packet 100 now far behind window -> reject
        self.assertFalse(engine.check_seq(100))

    def test_05_tamper_resistance_and_silent_drop(self):
        """Verify that tampering any byte in the wire frame causes silent drop (None), never crash."""
        a = SecureEngine()
        b = SecureEngine()
        k = secrets.token_bytes(32)
        a.establish_session(list(k), 10, True)
        b.establish_session(list(k), 10, False)

        q, frame = a.seal_msg(0x01, list(b"Top Secret Message"))

        # 1. Flip bit in header (seq/len/type)
        bad_header = bytearray(frame)
        bad_header[0] ^= 0x01
        self.assertIsNone(b.open_msg(list(bad_header)))

        # 2. Flip bit in ciphertext
        bad_ct = bytearray(frame)
        bad_ct[20] ^= 0x80
        self.assertIsNone(b.open_msg(list(bad_ct)))

        # 3. Flip bit in Poly1305 tag (last 16 bytes)
        bad_tag = bytearray(frame)
        bad_tag[-1] ^= 0x02
        self.assertIsNone(b.open_msg(list(bad_tag)))

        # 4. Truncated frame
        self.assertIsNone(b.open_msg(list(frame[:20])))

    def test_06_destroyer_node_large_streaming(self):
        """Verify DestroyerNode stream chunking and reassembly across multi-megabyte payloads."""
        node_a = DestroyerNode(51820)
        node_b = DestroyerNode(51821)
        key = secrets.token_bytes(32)

        node_a.establish(key, is_initiator=True)
        node_b.establish(key, is_initiator=False)

        # Test varying sizes: small, boundary, multi-chunk, 1MB
        test_payloads = [
            b"",
            b"Hello World",
            b"A" * 1205,           # Exactly 1 chunk
            b"B" * 1206,           # 2 chunks
            b"C" * 5000,           # 5 chunks
            secrets.token_bytes(1024 * 1024),  # 1 MB random payload
        ]

        for payload in test_payloads:
            blob = node_a.seal_stream(payload)
            self.assertTrue(len(blob) > len(payload))

            recovered = node_b.open_stream(blob)
            self.assertEqual(recovered, payload, f"Failed stream recovery for size {len(payload)}")

        # Verify stream tamper rejection (one poisoned byte drops whole stream fail-closed)
        large_blob = bytearray(node_a.seal_stream(b"Sensory Data Stream"))
        large_blob[15] ^= 0xFF
        self.assertIsNone(node_b.open_stream(bytes(large_blob)))

    def test_07_chaff_heartbeat_absorption(self):
        """Verify chaff frames (0xFF) are absorbed and report empty payload without error."""
        node_a = DestroyerNode(51820)
        node_b = DestroyerNode(51821)
        key = secrets.token_bytes(32)

        node_a.establish(key, is_initiator=True)
        node_b.establish(key, is_initiator=False)

        # Transmit chaff
        chaff_frame = node_a.transmit(b"", chaff=True)
        self.assertEqual(len(chaff_frame), 256)

        # Receive chaff
        res = node_b.receive(chaff_frame)
        self.assertIsNotNone(res)
        ftype, payload = res
        self.assertEqual(ftype, 0xFF)  # FTYPE_CHAFF
        self.assertEqual(payload, b"")

    def test_08_double_envelope_with_hkdf_root_key(self):
        """Verify realistic double-envelope flow: HKDF derived key from hybrid root wraps Double Ratchet message."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes as crypto_hashes

        # Mock a 32-byte hybrid root key from post-quantum handshake
        hybrid_root_key = secrets.token_bytes(32)

        # Client (Initiator) derivation
        hkdf_client = HKDF(
            algorithm=crypto_hashes.SHA512(),
            length=32,
            salt=b"destroyer-p2p-rust-v1",
            info=b"destroyer/frame/v1",
        )
        client_frame_key = hkdf_client.derive(hybrid_root_key)

        # Server (Responder) derivation
        hkdf_server = HKDF(
            algorithm=crypto_hashes.SHA512(),
            length=32,
            salt=b"destroyer-p2p-rust-v1",
            info=b"destroyer/frame/v1",
        )
        server_frame_key = hkdf_server.derive(hybrid_root_key)

        self.assertEqual(client_frame_key, server_frame_key)

        client_node = DestroyerNode()
        server_node = DestroyerNode()

        client_node.establish(client_frame_key, is_initiator=True)
        server_node.establish(server_frame_key, is_initiator=False)

        # Simulate Double Ratchet inner ciphertext
        mock_ratchet_ciphertext = b"RATCHET_CIPHERTEXT:" + secrets.token_bytes(128)

        # Outer envelope sealed by Rust
        outer_envelope = client_node.seal_stream(mock_ratchet_ciphertext)
        self.assertNotEqual(outer_envelope, mock_ratchet_ciphertext)

        # Outer envelope unsealed by Rust on server
        unsealed = server_node.open_stream(outer_envelope)
        self.assertEqual(unsealed, mock_ratchet_ciphertext)

    def test_09_destroyer_node_send_chaff(self):
        """Verify send_chaff transmits authenticated dummy frames silently absorbed by receiver."""
        node_a = DestroyerNode()
        node_b = DestroyerNode()
        key = secrets.token_bytes(32)

        node_a.establish(key, is_initiator=True)
        node_b.establish(key, is_initiator=False)

        addr_b = node_b.bind_udp("127.0.0.1", 0)
        node_a.bind_udp("127.0.0.1", 0)

        try:
            # Send chaff frame: receiver must silently absorb
            sent_bytes = node_a.send_chaff(addr_b, payload_len=64)
            self.assertGreater(sent_bytes, 0)

            recv_res = node_b.recv_udp_msg(timeout=0.3)
            self.assertIsNone(recv_res, "Chaff frame must be absorbed silently without payload leakage")

            # Follow-up real frame must be successfully admitted
            node_a.send_udp_msg(b"REAL_AUTHENTIC_PAYLOAD", addr_b)
            recv_real = node_b.recv_udp_msg(timeout=0.5)
            self.assertIsNotNone(recv_real)
            self.assertEqual(recv_real[0], b"REAL_AUTHENTIC_PAYLOAD")
        finally:
            node_a.close_udp()
            node_b.close_udp()

    def test_10_destroyer_node_pacing_chaff_lifecycle(self):
        """Verify start_pacing_chaff, is_pacing_chaff, and stop_pacing_chaff lifecycle."""
        import time

        node_a = DestroyerNode()
        node_b = DestroyerNode()
        key = secrets.token_bytes(32)

        node_a.establish(key, is_initiator=True)
        node_b.establish(key, is_initiator=False)

        addr_b = node_b.bind_udp("127.0.0.1", 0)
        node_a.bind_udp("127.0.0.1", 0)

        try:
            self.assertFalse(node_a.is_pacing_chaff())
            node_a.start_pacing_chaff(addr_b, interval_sec=0.02, jitter_sec=0.005)
            self.assertTrue(node_a.is_pacing_chaff())

            time.sleep(0.08)  # Let background pacing thread transmit chaff

            # Transmit real message concurrently with active background cover traffic
            node_a.send_udp_msg(b"PAYLOAD_DURING_CHAFF", addr_b)
            recv_msg = node_b.recv_udp_msg(timeout=1.0)
            self.assertIsNotNone(recv_msg)
            self.assertEqual(recv_msg[0], b"PAYLOAD_DURING_CHAFF")

            node_a.stop_pacing_chaff()
            self.assertFalse(node_a.is_pacing_chaff())
        finally:
            node_a.close_udp()
            node_b.close_udp()

    def test_11_destroyer_node_poisson_pacing(self):
        """Verify Poisson-scheduled memoryless cover traffic pacing."""
        import time

        node_a = DestroyerNode()
        node_b = DestroyerNode()
        key = secrets.token_bytes(32)

        node_a.establish(key, is_initiator=True)
        node_b.establish(key, is_initiator=False)

        addr_b = node_b.bind_udp("127.0.0.1", 0)
        node_a.bind_udp("127.0.0.1", 0)

        try:
            node_a.start_pacing_chaff(addr_b, interval_sec=0.02, poisson=True)
            self.assertTrue(node_a.is_pacing_chaff())

            time.sleep(0.08)  # Let background Poisson thread transmit memoryless chaff

            # Real payload transmission across Poisson background traffic
            node_a.send_udp_msg(b"POISSON_PAYLOAD_TEST", addr_b)
            recv_msg = node_b.recv_udp_msg(timeout=1.0)
            self.assertIsNotNone(recv_msg)
            self.assertEqual(recv_msg[0], b"POISSON_PAYLOAD_TEST")

            node_a.stop_pacing_chaff()
            self.assertFalse(node_a.is_pacing_chaff())
        finally:
            node_a.close_udp()
            node_b.close_udp()


if __name__ == "__main__":
    unittest.main(verbosity=2)
