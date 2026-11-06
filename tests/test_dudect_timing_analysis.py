#!/usr/bin/env python3
"""DudeCT Constant-Time Execution & Statistical Timing Leakage Verification Suite.

References:
- Reparaz, Balasch, Verbauwhede (IEEE S&P / ePrint 2016/1123):
  "Dude, is my code constant time?"
- NIST FIPS 203 / FIPS 204 Implementation Guidance (2024-2027):
  Timing side-channel evaluation over lattice polynomial arithmetic and secret-dependent operations.
- CNSA 2.0 Architectural Requirements:
  Absence of microarchitectural timing leakage in secret-handling routines.

Mathematical Methodology:
1. Welford's one-pass algorithm accumulates sample mean and variance for two distributions:
   - Class 0: Fixed secret input (identical input across evaluations)
   - Class 1: Random secret input (pseudo-random bytes per evaluation)
2. Randomized interleaved evaluation orders eliminate systemic clock drift and OS background noise.
3. Welch's two-sample t-statistic is computed:
   t = (mean_0 - mean_1) / sqrt(var_0/N_0 + var_1/N_1)
4. Decision Criteria:
   - |t| < 4.5: Fail to reject H0 (Constant-time behavior verified at p > 99.999%).
   - |t| >= 4.5: Reject H0 (Secret-dependent timing variation detected).
"""

from __future__ import annotations

import hmac
import math
import os
import random
import time
import unittest


class WelfordAccumulator:
    """Welford's algorithm for numerically stable online mean and variance."""

    def __init__(self) -> None:
        self.count: int = 0
        self.mean: float = 0.0
        self.m2: float = 0.0

    def update(self, val: float) -> None:
        self.count += 1
        delta = val - self.mean
        self.mean += delta / self.count
        delta2 = val - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)


def welch_t_statistic(acc0: WelfordAccumulator, acc1: WelfordAccumulator) -> float:
    """Compute Welch's two-sample t-test statistic."""
    if acc0.count < 2 or acc1.count < 2:
        return 0.0
    var0 = acc0.variance
    var1 = acc1.variance
    denom = math.sqrt((var0 / acc0.count) + (var1 / acc1.count))
    if denom == 0.0:
        return 0.0
    return (acc0.mean - acc1.mean) / denom


def leaky_byte_equals(a: bytes, b: bytes) -> bool:
    """Intentionally vulnerable early-exit comparison for positive leakage control."""
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # Early return leaks secret index through timing
    return True


def constant_time_byte_equals(a: bytes, b: bytes) -> bool:
    """Production constant-time comparison using hmac.compare_digest."""
    return hmac.compare_digest(a, b)


class TestDudectConstantTimeAnalysis(unittest.TestCase):
    """DudeCT statistical leakage analysis test suite."""

    def setUp(self) -> None:
        # Pre-allocate secret buffers to avoid allocator jitter during measurement
        self.fixed_secret = b"\x5a" * 64
        self.rng_secrets = [os.urandom(64) for _ in range(1000)]
        self.mismatch_first_byte = b"\xa5" + (b"\x5a" * 63)

    def test_01_welford_accumulator_numerical_stability(self) -> None:
        """Verify Welford's algorithm against known statistical distributions."""
        acc = WelfordAccumulator()
        data = [10.0, 12.0, 23.0, 23.0, 16.0, 23.0, 21.0, 16.0]
        for x in data:
            acc.update(x)

        expected_mean = sum(data) / len(data)
        expected_var = sum((x - expected_mean) ** 2 for x in data) / (len(data) - 1)

        self.assertAlmostEqual(acc.mean, expected_mean, places=6)
        self.assertAlmostEqual(acc.variance, expected_var, places=6)

    def test_02_constant_time_comparison_passes_dudect(self) -> None:
        """Prove hmac.compare_digest exhibits no timing leakage (|t| < 4.5)."""
        acc0 = WelfordAccumulator()
        acc1 = WelfordAccumulator()

        num_samples = 20_000
        # Interleave samples randomly
        choices = [0, 1] * (num_samples // 2)
        random.shuffle(choices)

        # Warm-up cycles to stabilize CPU frequency scaling and cache
        for _ in range(2000):
            constant_time_byte_equals(self.fixed_secret, self.fixed_secret)

        fixed = self.fixed_secret
        rng_list = self.rng_secrets
        num_rng = len(rng_list)

        t_perf = time.perf_counter_ns
        for i, choice in enumerate(choices):
            if choice == 0:
                # Class 0: fixed matching input
                t0 = t_perf()
                res = True
                for _ in range(25):
                    res &= constant_time_byte_equals(fixed, fixed)
                t1 = t_perf()
                acc0.update(t1 - t0)
            else:
                # Class 1: random input
                other = rng_list[i % num_rng]
                t0 = t_perf()
                res = False
                for _ in range(25):
                    res |= constant_time_byte_equals(fixed, other)
                t1 = t_perf()
                acc1.update(t1 - t0)

        t_stat = welch_t_statistic(acc0, acc1)
        print(f"\n[DudeCT] Constant-Time hmac.compare_digest: |t| = {abs(t_stat):.4f} (Threshold = 4.5)")

        # Verify no statistically significant timing difference exists
        self.assertLess(
            abs(t_stat),
            4.5,
            f"Constant-time comparison leaked timing! |t| = {abs(t_stat)} >= 4.5",
        )

    def test_03_leaky_comparison_detected_by_dudect(self) -> None:
        """Prove DudeCT reliably flags early-exit comparison as leaky (|t| > 4.5).

        This test acts as a positive control ensuring the statistical test
        has high sensitivity and does not produce false negatives.
        """
        acc0 = WelfordAccumulator()
        acc1 = WelfordAccumulator()

        num_samples = 20_000
        choices = [0, 1] * (num_samples // 2)
        random.shuffle(choices)

        # Warm-up
        for _ in range(2000):
            leaky_byte_equals(self.fixed_secret, self.fixed_secret)

        fixed = self.fixed_secret
        mismatch_first = self.mismatch_first_byte

        t_perf = time.perf_counter_ns
        for choice in choices:
            if choice == 0:
                # Class 0: full match (loops through all 64 bytes)
                t0 = t_perf()
                res = True
                for _ in range(25):
                    res &= leaky_byte_equals(fixed, fixed)
                t1 = t_perf()
                acc0.update(t1 - t0)
            else:
                # Class 1: mismatch on byte 0 (exits immediately on byte 0)
                t0 = t_perf()
                res = False
                for _ in range(25):
                    res |= leaky_byte_equals(fixed, mismatch_first)
                t1 = t_perf()
                acc1.update(t1 - t0)

        t_stat = welch_t_statistic(acc0, acc1)
        print(f"[DudeCT] Leaky Early-Exit Comparator:       |t| = {abs(t_stat):.4f} (Threshold = 4.5)")

        # The early-exit comparison MUST show statistically significant difference (|t| >= 4.5)
        self.assertGreater(
            abs(t_stat),
            4.5,
            f"DudeCT failed to detect early-exit timing leak! |t| = {abs(t_stat)} <= 4.5",
        )


if __name__ == "__main__":
    unittest.main()
