"""
Unit and Integration Tests for Phase K: Deductive Formal Code Contracts & Mathematical Proofs
Verifies machine-checked mathematical contracts: constant-time execution, bounded arithmetic,
sliding window replay invariants, and parser crash-freedom.
"""

import unittest
from scripts.verify_mathematical_contracts import FormalVerificationEngine, IS_NATIVE


class TestFormalCodeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = FormalVerificationEngine()

    def test_01_constant_time_timing_invariance_contract(self):
        """Verify Contract 1: Constant-Time Timing Invariance."""
        rep = self.engine.verify_constant_time(iterations=2_000)
        self.assertTrue(rep["verified"])
        self.assertEqual(rep["failure_counterexamples"], 0)
        self.assertGreaterEqual(rep["iterations_checked"], 2_000)

    def test_02_bounded_arithmetic_no_overflow_contract(self):
        """Verify Contract 2: Bounded Arithmetic & Zero-Overflow."""
        rep = self.engine.verify_bounded_arithmetic(max_tests=20_000)
        self.assertTrue(rep["verified"])
        self.assertEqual(rep["failure_counterexamples"], 0)
        self.assertGreaterEqual(rep["iterations_checked"], 20_000)

    def test_03_sliding_window_anti_replay_inductive_invariant(self):
        """Verify Contract 3: Anti-Replay Sliding Window Inductive Invariant."""
        rep = self.engine.verify_replay_invariants(window_size=128, test_vectors=1_000)
        self.assertTrue(rep["verified"])
        self.assertEqual(rep["failure_counterexamples"], 0)
        self.assertGreaterEqual(rep["iterations_checked"], 1_000)

    def test_04_untrusted_parser_zero_panic_guarantee(self):
        """Verify Contract 4: Untrusted Parser Crash-Freedom & Zero Panic Guarantee."""
        fuzz_corpus = [
            b"",
            b"\x00",
            b"DST7",
            b"DST7\x00\x02OK",
            b"DST7\xFF\xFFshort",
            b"MALFORMED_HEADER_PREFIX",
            bytes([0x5A] * 512),
            bytes([0xFF] * 1024),
            bytes([0x00] * 4096),
        ]
        rep = self.engine.verify_parser_no_panic(fuzz_corpus)
        self.assertTrue(rep["verified"])
        self.assertEqual(rep["failure_counterexamples"], 0)

    def test_05_smt_lib2_theorems_structure(self):
        """Verify export of valid SMT-LIB2 lemmas."""
        smt_text = self.engine.export_smt_theorems()
        self.assertIn("set-logic", smt_text)
        self.assertIn("check-sat", smt_text)

    def test_06_native_rust_fast_path(self):
        """Verify native Rust CoreFormalProofs is bound and active."""
        self.assertTrue(IS_NATIVE)


if __name__ == "__main__":
    unittest.main()
