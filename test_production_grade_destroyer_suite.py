#!/usr/bin/env python3
"""
PRODUCTION-GRADE VERIFICATION & SOAK TEST SUITE FOR DESTROYER_CORE
===================================================================
Rigorous operational testing for the Rust high-speed data plane
integrated with sovereign post-quantum P2P communications.

Test Coverage:
1. Multi-Megabyte File Transfer & Hash Integrity (SHA3-256/SHA-512)
2. High-Frequency Soak Test (5,000 Frame Exchange & Throughput Measurement)
3. WireGuard-Style 64-Packet Anti-Replay Sliding Window Under Jitter & Reordering
4. Adversarial Attack Simulation: Silent Drop on Tampering, Replays & Nonce Re-use
5. Quantized Wire Invariant Verification (Zero Traffic-Size Side Channels)
6. Live Multi-Process Base-to-Base (NORAD <-> Pentagon) Double-Envelope Execution
"""

import os
import sys
import time
import json
import secrets
import hashlib
import unittest
import subprocess  # nosec: B404
from pathlib import Path

# Preload native extension before any process mitigation locks
try:
    from destroyer_core import SecureEngine
    DESTROYER_AVAILABLE = True
except ImportError:
    DESTROYER_AVAILABLE = False

from destroyer_node import DestroyerNode, data_plane_enabled

PROJECT_ROOT = Path(__file__).resolve().parent


class TestProductionGradeDestroyer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DESTROYER_AVAILABLE:
            raise unittest.SkipTest("destroyer_core native extension is not installed or available")

    def test_01_wire_quanta_invariants_and_zero_size_leakage(self):
        """Verify strict adherence to 256B, 512B, and 1232B quanta with 0 length leakage."""
        engine = SecureEngine()
        key = secrets.token_bytes(32)
        engine.establish_session(list(key), 0, True)

        # Step through every boundary payload size up to 1205B
        test_sizes = [0, 1, 10, 100, 228, 229, 300, 484, 485, 800, 1204, 1205]
        for sz in test_sizes:
            payload = secrets.token_bytes(sz)
            q, frame = engine.seal_msg(0x01, list(payload))
            self.assertIn(q, (256, 512, 1232), f"Invalid quantum {q} for payload size {sz}")
            self.assertEqual(len(frame), q, f"Wire frame size {len(frame)} must match quantum {q}")

            if sz <= 229:
                self.assertEqual(q, 256, f"Payload size {sz} should be in 256B quantum")
            elif sz <= 485:
                self.assertEqual(q, 512, f"Payload size {sz} should be in 512B quantum")
            else:
                self.assertEqual(q, 1232, f"Payload size {sz} should be in 1232B quantum")

        # Exceeding 1205B must raise ValueError immediately (fail-closed)
        with self.assertRaises(ValueError):
            engine.seal_msg(0x01, list(secrets.token_bytes(1206)))

    def test_02_multi_megabyte_file_streaming_and_hash_integrity(self):
        """Verify streaming of multi-megabyte payloads (up to 5MB) with bit-for-bit SHA3-256 match."""
        node_tx = DestroyerNode(51820)
        node_rx = DestroyerNode(51821)
        shared_key = secrets.token_bytes(32)

        node_tx.establish(shared_key, is_initiator=True)
        node_rx.establish(shared_key, is_initiator=False)

        # 5 Megabyte test payload
        file_sizes = [64 * 1024, 512 * 1024, 2 * 1024 * 1024, 5 * 1024 * 1024]
        for fsize in file_sizes:
            data = secrets.token_bytes(fsize)
            orig_sha3 = hashlib.sha3_256(data).hexdigest()
            orig_sha512 = hashlib.sha512(data).hexdigest()

            t0 = time.perf_counter()
            stream_blob = node_tx.seal_stream(data)
            seal_time = time.perf_counter() - t0

            t1 = time.perf_counter()
            recovered = node_rx.open_stream(stream_blob)
            open_time = time.perf_counter() - t1

            self.assertIsNotNone(recovered, f"Failed to unseal {fsize} bytes stream")
            self.assertEqual(len(recovered), fsize)
            self.assertEqual(hashlib.sha3_256(recovered).hexdigest(), orig_sha3)
            self.assertEqual(hashlib.sha512(recovered).hexdigest(), orig_sha512)

            throughput_mb = (fsize / (1024 * 1024)) / (seal_time + open_time)
            print(f"\n  [STREAM TEST] {fsize // 1024} KB: Seal={seal_time*1000:.1f}ms, Open={open_time*1000:.1f}ms | Combined Throughput: {throughput_mb:.1f} MB/s")

    def test_03_high_frequency_soak_and_latency_distribution(self):
        """Execute 5,000 back-to-back frame exchanges; verify 0 drops and measure latency."""
        init = SecureEngine()
        resp = SecureEngine()
        key = secrets.token_bytes(32)

        init.establish_session(list(key), 1000, True)
        resp.establish_session(list(key), 1000, False)

        num_frames = 5000
        latencies_us = []

        for i in range(num_frames):
            msg = f"SOAK_FRAME_PACKET_{i:06d}".encode()
            t0 = time.perf_counter_ns()
            _q, frame = init.seal_msg(0x01, list(msg))
            opened = resp.open_msg(list(frame))
            elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
            latencies_us.append(elapsed_us)

            self.assertIsNotNone(opened)
            ftype, payload = opened
            self.assertEqual(ftype, 0x01)
            self.assertEqual(bytes(payload), msg)

        self.assertEqual(resp.drop_count(), 0, "No drops permitted during clean soak run")
        self.assertEqual(len(latencies_us), num_frames)

        latencies_us.sort()
        p50 = latencies_us[int(num_frames * 0.50)]
        p95 = latencies_us[int(num_frames * 0.95)]
        p99 = latencies_us[int(num_frames * 0.99)]
        avg = sum(latencies_us) / num_frames

        print(f"\n  [SOAK TEST] {num_frames} frames completed with 0 drops:")
        print(f"              Average: {avg:.2f} µs | P50: {p50:.2f} µs | P95: {p95:.2f} µs | P99: {p99:.2f} µs")
        self.assertLess(avg, 500.0, "Average seal+open roundtrip must be under 500 microseconds")

    def test_04_wireguard_anti_replay_jitter_and_window_boundaries(self):
        """Test out-of-order network jitter within the 64-packet window and rejection beyond."""
        engine = SecureEngine()
        engine.establish_session(list(b"W" * 32), 100, True)

        # 1. Sequential feed to advance window to 200
        for seq in range(100, 201):
            self.assertTrue(engine.check_seq(seq))

        # 2. Window is now [200 - 63, 200] -> [137, 200]
        # In-window packet (150) was already seen -> duplicate -> drop
        self.assertFalse(engine.check_seq(150))

        # 3. Behind-window packet (136 = 200 - 64) -> drop
        self.assertFalse(engine.check_seq(136))
        self.assertFalse(engine.check_seq(100))

        # 4. Jump ahead to 10,000 (resets bitmap to 1)
        self.assertTrue(engine.check_seq(10000))

        # 5. Packets [10000 - 63 .. 10000 - 1] arrived out of order (simulate jitter)
        jitter_seqs = list(range(9937, 10000))
        # Shuffle jittered packets (B311: deterministic test-only Random(42), never prod CSPRNG)
        import random  # nosec B311 - deterministic test shuffle only
        rnd = random.Random(42)  # nosec B311 - deterministic test seed
        rnd.shuffle(jitter_seqs)

        for seq in jitter_seqs:
            self.assertTrue(engine.check_seq(seq), f"In-window jittered sequence {seq} must be accepted")

        # Now all in [9937, 10000] are consumed; re-offering any must be rejected as duplicate
        for seq in jitter_seqs[:10]:
            self.assertFalse(engine.check_seq(seq), f"Duplicate sequence {seq} must be rejected")

        # 6. Outside window: 9936 (10000 - 64) must be rejected
        self.assertFalse(engine.check_seq(9936))

    def test_05_adversarial_tampering_and_domain_separation(self):
        """Simulate malicious adversarial attacks: bit flips, cross-direction replay, truncation."""
        alice = SecureEngine()
        bob = SecureEngine()
        key = secrets.token_bytes(32)

        alice.establish_session(list(key), 500, is_initiator=True)
        bob.establish_session(list(key), 500, is_initiator=False)

        q, valid_frame = alice.seal_msg(0x01, list(b"Classified Defcon-1 Intel"))

        # Attack A: Flip random bits across the entire frame
        for offset in [0, 4, 8, 10, 15, len(valid_frame) - 16, len(valid_frame) - 1]:
            corrupted = bytearray(valid_frame)
            corrupted[offset] ^= 0x01
            res = bob.open_msg(list(corrupted))
            self.assertIsNone(res, f"Corrupted byte at offset {offset} must trigger silent drop")

        # Attack B: Replay attack (inject same valid frame a second time)
        res1 = bob.open_msg(list(valid_frame))
        self.assertIsNotNone(res1)
        res2 = bob.open_msg(list(valid_frame))
        self.assertIsNone(res2, "Replayed frame MUST be dropped silently")

        # Attack C: Cross-direction reflection attack (adversary reflects frame back to sender)
        reflected = alice.open_msg(list(valid_frame))
        self.assertIsNone(reflected, "Sender must reject its own reflected frame due to nonce domain separation")

        # Attack D: Truncation attack
        for trunc_len in [0, 10, 26, q - 1]:
            self.assertIsNone(bob.open_msg(list(valid_frame[:trunc_len])), f"Truncated frame of length {trunc_len} must be dropped")

    def test_06_two_terminal_military_base_live_execution(self):
        """Execute full 2-terminal military base communications test under P2P_DATA_PLANE=rust."""
        env = dict(os.environ, P2P_DATA_PLANE="rust", PYTHONUNBUFFERED="1", P2P_ALLOW_LOOPBACK="1")
        test_script = PROJECT_ROOT / "run_two_terminals_secure_p2_test.py"

        print("\n  [2-TERMINAL TEST] Launching live Base Alpha (NORAD) <-> Base Bravo (Pentagon) processes...")
        proc = subprocess.run(  # nosec: B603
            [sys.executable, str(test_script)],
            env=env,
            capture_output=True,
            text=True,
            timeout=180
        )

        output = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 0, f"2-terminal test failed with code {proc.returncode}:\n{output}")
        self.assertIn("Rust data plane session established (outer AEAD envelope active)", output)
        self.assertIn("2-TERMINAL SECURE_P2.PY TEST 100% SUCCESSFUL!", output)
        self.assertIn("Base Alpha successfully received and decrypted Flash Order.", output)
        self.assertIn("Base Bravo successfully received and decrypted Flash ACK.", output)
        print("  [2-TERMINAL TEST] Confirmed 100% end-to-end bidirectional communication over Rust AEAD envelope.")


if __name__ == "__main__":
    unittest.main(verbosity=2)

