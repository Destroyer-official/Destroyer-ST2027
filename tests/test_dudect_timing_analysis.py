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


def _cropped_welch_t(samples0: list[int], samples1: list[int]) -> float:
    """Compute Welch's t-statistic after pooled 90th-percentile OS-interrupt cropping (Reparaz et al. §2.2)."""
    pooled = sorted(samples0 + samples1)
    if not pooled:
        return 0.0
    cutoff = pooled[min((len(pooled) * 90) // 100, len(pooled) - 1)]
    acc0 = WelfordAccumulator()
    acc1 = WelfordAccumulator()
    for val in samples0:
        if val <= cutoff:
            acc0.update(float(val))
    for val in samples1:
        if val <= cutoff:
            acc1.update(float(val))
    return welch_t_statistic(acc0, acc1)


def _measure_dudect_t_stat(
    comparator: object,
    fixed: bytes,
    class0_pool: list[bytes],
    class1_pool: list[bytes],
    num_samples: int = 20_000,
    batch_size: int = 50,
) -> float:
    """Measure Welch's t-statistic between two input classes with symmetric bytecode and memory layout."""
    samples: tuple[list[int], list[int]] = ([], [])
    choices = [0, 1] * (num_samples // 2)
    random.shuffle(choices)

    # Warm-up cycles to stabilize CPU frequency scaling, cache lines, and adaptive specialization
    for idx in range(2000):
        comparator(fixed, class0_pool[idx % len(class0_pool)])  # type: ignore[operator]
        comparator(fixed, class1_pool[idx % len(class1_pool)])  # type: ignore[operator]

    pools = (class0_pool, class1_pool)
    pool_len = len(class0_pool)
    t_perf = time.perf_counter_ns
    for i, choice in enumerate(choices):
        other = pools[choice][i % pool_len]
        t0 = t_perf()
        for _ in range(batch_size):
            _res = comparator(fixed, other)  # type: ignore[operator]
        t1 = t_perf()
        samples[choice].append(t1 - t0)

    return _cropped_welch_t(samples[0], samples[1])


class TestDudectConstantTimeAnalysis(unittest.TestCase):
    """DudeCT statistical leakage analysis test suite."""

    def setUp(self) -> None:
        # Interleave Class 0 and Class 1 allocations one-by-one inside a compact pool (128 * 64B = 8 KB/class)
        # so both classes fit inside L1D cache and occupy alternating pymalloc slots.
        # Class 0 differs only on the final byte (63) so both classes return Py_False cleanly while forcing
        # any early-exit comparator to scan all 64 bytes on Class 0 vs ~1 byte on Class 1, eliminating Python 3.11
        # Py_True vs Py_False non-immortal refcount cache-line asymmetry.
        self.fixed_secret = b"\x5a" * 64
        self.mismatch_last_byte = (b"\x5a" * 63) + b"\x00"
        self.mismatch_first_byte = b"\xa5" + (b"\x5a" * 63)
        self.fixed_match_secrets: list[bytes] = []
        self.mismatch_last_secrets: list[bytes] = []
        self.rng_secrets: list[bytes] = []
        self.mismatch_first_secrets: list[bytes] = []
        for _ in range(128):
            self.fixed_match_secrets.append(bytes(bytearray(self.fixed_secret)))
            self.mismatch_last_secrets.append(bytes(bytearray(self.mismatch_last_byte)))
            self.rng_secrets.append(os.urandom(64))
            self.mismatch_first_secrets.append(bytes(bytearray(self.mismatch_first_byte)))

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
        t_stat = _measure_dudect_t_stat(
            constant_time_byte_equals,
            self.fixed_secret,
            self.mismatch_last_secrets,
            self.rng_secrets,
        )
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
        t_stat = _measure_dudect_t_stat(
            leaky_byte_equals,
            self.fixed_secret,
            self.mismatch_last_secrets,
            self.mismatch_first_secrets,
        )
        print(f"[DudeCT] Leaky Early-Exit Comparator:       |t| = {abs(t_stat):.4f} (Threshold = 4.5)")

        # The early-exit comparison MUST show statistically significant difference (|t| >= 4.5)
        self.assertGreater(
            abs(t_stat),
            4.5,
            f"DudeCT failed to detect early-exit timing leak! |t| = {abs(t_stat)} <= 4.5",
        )


if __name__ == "__main__":
    unittest.main()
