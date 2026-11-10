//! DudeCT Statistical Timing Leakage Verification Suite for Rust Data Plane.
//!
//! Grounded in:
//! - Reparaz, Balasch, Verbauwhede (IEEE S&P / ePrint 2016/1123): "Dude, is my code constant time?"
//! - Evaluates whether secret data leaks via CPU timing variation.
//! - Uses Welch's two-sample t-test with interleaved samples over Class 0 (fixed secret)
//!   and Class 1 (random secret).
//! - Decision threshold: |t| < 4.5 (confidence > 99.999% that no timing difference exists).

#![allow(dead_code)]

#[path = "../src/ct.rs"]
mod ct;

#[path = "../src/nostd_microcore.rs"]
mod nostd_microcore;

use std::hint::black_box;
use std::time::Instant;

/// Online accumulator for sample mean and variance (Welford's algorithm).
#[derive(Debug, Clone, Default)]
struct WelfordAccumulator {
    count: usize,
    mean: f64,
    m2: f64,
}

impl WelfordAccumulator {
    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, x: f64) {
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / (self.count as f64);
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / ((self.count - 1) as f64)
        }
    }
}

fn welch_t_statistic(a: &WelfordAccumulator, b: &WelfordAccumulator) -> f64 {
    if a.count < 2 || b.count < 2 {
        return 0.0;
    }
    let var_a = a.variance();
    let var_b = b.variance();
    let denom = ((var_a / (a.count as f64)) + (var_b / (b.count as f64))).sqrt();
    if denom == 0.0 {
        return 0.0;
    }
    (a.mean - b.mean) / denom
}

/// Simple deterministic xorshift64 RNG for reproducible testing without extra dependencies.
fn xorshift64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Intentionally leaky comparator (early exit) for detector validation.
#[inline(never)]
fn leaky_cmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

#[test]
fn dudect_rust_ct_eq_passes_statistical_timing() {
    let mut acc0 = WelfordAccumulator::new();
    let mut acc1 = WelfordAccumulator::new();
    let mut rng: u64 = 0x8842A197D6E35B01;

    let fixed_secret_a = [0x5Au8; 64];
    let fixed_secret_b_match = [0x5Au8; 64];
    let mut random_secrets = Vec::with_capacity(512);
    for _ in 0..512 {
        let mut buf = [0u8; 64];
        for b in buf.iter_mut() {
            *b = (xorshift64(&mut rng) & 0xFF) as u8;
        }
        random_secrets.push(buf);
    }

    // Warm-up cycles to stabilize cache and clock frequency
    for _ in 0..2000 {
        black_box(ct::ct_eq(black_box(&fixed_secret_a), black_box(&fixed_secret_b_match)));
    }

    const BATCH: usize = 200;
    const SAMPLES: usize = 25_000;
    for i in 0..SAMPLES {
        let coin = (xorshift64(&mut rng) & 1) == 0;
        let (in_a, in_b) = if coin {
            (&fixed_secret_a, &fixed_secret_b_match)
        } else {
            (&fixed_secret_a, &random_secrets[i % random_secrets.len()])
        };
        let t0 = Instant::now();
        let mut acc_res = 0u32;
        for _ in 0..BATCH {
            acc_res = acc_res.wrapping_add(ct::ct_eq(black_box(in_a), black_box(in_b)) as u32);
        }
        let elapsed = t0.elapsed().as_nanos() as f64;
        black_box(acc_res);
        if coin {
            acc0.update(elapsed);
        } else {
            acc1.update(elapsed);
        }
    }

    let t = welch_t_statistic(&acc0, &acc1);
    println!("\n[DudeCT-Rust] ct::ct_eq: |t| = {:.4} (Threshold = 4.5)", t.abs());
    assert!(
        t.abs() < 4.5,
        "ct::ct_eq exhibited statistically significant timing leakage! |t| = {}",
        t.abs()
    );
}

#[test]
fn dudect_rust_nostd_stack_secret_ct_eq_passes() {
    let mut acc0 = WelfordAccumulator::new();
    let mut acc1 = WelfordAccumulator::new();
    let mut rng: u64 = 0xFEDCBA9876543210;

    let fixed_secret_a = nostd_microcore::StackSecretBuffer::<32>::from_slice(&[0x42u8; 32]).unwrap();
    let fixed_secret_b_match = nostd_microcore::StackSecretBuffer::<32>::from_slice(&[0x42u8; 32]).unwrap();
    let mut random_secrets = Vec::with_capacity(256);
    for _ in 0..256 {
        let mut buf = [0u8; 32];
        for b in buf.iter_mut() {
            *b = (xorshift64(&mut rng) & 0xFF) as u8;
        }
        random_secrets.push(nostd_microcore::StackSecretBuffer::<32>::from_slice(&buf).unwrap());
    }

    // Warm-up
    for _ in 0..2000 {
        black_box(fixed_secret_a.ct_eq(black_box(&fixed_secret_b_match)));
    }

    const BATCH: usize = 200;
    const SAMPLES: usize = 25_000;
    for i in 0..SAMPLES {
        let coin = (xorshift64(&mut rng) & 1) == 0;
        let (in_a, in_b) = if coin {
            (&fixed_secret_a, &fixed_secret_b_match)
        } else {
            (&fixed_secret_a, &random_secrets[i % random_secrets.len()])
        };
        let t0 = Instant::now();
        let mut acc_res = 0u32;
        for _ in 0..BATCH {
            acc_res = acc_res.wrapping_add(in_a.ct_eq(black_box(in_b)) as u32);
        }
        let elapsed = t0.elapsed().as_nanos() as f64;
        black_box(acc_res);
        if coin {
            acc0.update(elapsed);
        } else {
            acc1.update(elapsed);
        }
    }

    let t = welch_t_statistic(&acc0, &acc1);
    println!("[DudeCT-Rust] StackSecretBuffer::ct_eq: |t| = {:.4} (Threshold = 4.5)", t.abs());
    assert!(
        t.abs() < 4.5,
        "StackSecretBuffer::ct_eq leaked timing! |t| = {}",
        t.abs()
    );
}

#[test]
fn dudect_rust_leaky_comparator_detected_as_positive_control() {
    let mut acc0 = WelfordAccumulator::new();
    let mut acc1 = WelfordAccumulator::new();
    let mut rng: u64 = 0x123456789ABCDEF0;

    let fixed_secret_a = [0x5Au8; 64];
    let fixed_secret_b_match = [0x5Au8; 64];
    let mut mismatch_first = fixed_secret_a;
    mismatch_first[0] ^= 0xFF;

    // Warm-up
    for _ in 0..2000 {
        black_box(leaky_cmp(black_box(&fixed_secret_a), black_box(&fixed_secret_b_match)));
    }

    const BATCH: usize = 200;
    const SAMPLES: usize = 25_000;
    for _ in 0..SAMPLES {
        let coin = (xorshift64(&mut rng) & 1) == 0;
        let (in_a, in_b) = if coin {
            (&fixed_secret_a, &fixed_secret_b_match)
        } else {
            (&fixed_secret_a, &mismatch_first)
        };
        let t0 = Instant::now();
        let mut acc_res = 0u32;
        for _ in 0..BATCH {
            acc_res = acc_res.wrapping_add(leaky_cmp(black_box(in_a), black_box(in_b)) as u32);
        }
        let elapsed = t0.elapsed().as_nanos() as f64;
        black_box(acc_res);
        if coin {
            acc0.update(elapsed);
        } else {
            acc1.update(elapsed);
        }
    }

    let t = welch_t_statistic(&acc0, &acc1);
    println!("[DudeCT-Rust] Leaky comparator: |t| = {:.4} (Threshold = 3.5)", t.abs());
    assert!(
        t.abs() > 3.5,
        "DudeCT detector failed to flag leaky comparator! |t| = {}",
        t.abs()
    );
}
