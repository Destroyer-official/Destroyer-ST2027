//! pacing — constant-rate traffic invariance and synthetic chaff engine.
//!
//! Neutralizes Signals Intelligence (SIGINT) flow correlation, packet timing,
//! and inter-arrival analysis by enforcing constant-rate, constant-size wire cells.
//! When application data is idle, cryptographically indistinguishable synthetic
//! chaff frames (FTYPE_CHAFF = 0xFF) are generated under the active AEAD key.

use crate::aead::{self, FrameKey, DIR_SEND};
use crate::frame::{quantize, FRAME_OVERHEAD, FTYPE_CHAFF};
use std::time::{Duration, Instant};

/// Default wire quantum matching standard IPv6 non-fragmented datagram.
pub const DEFAULT_WIRE_QUANTUM: usize = 1232;

/// High-resolution tick scheduler with drift compensation.
/// Maintains constant wire timing to defeat inter-packet arrival analysis.
#[derive(Debug)]
pub struct PacedScheduler {
    interval: Duration,
    next_tick: Instant,
    ticks_emitted: u64,
}

impl PacedScheduler {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            next_tick: Instant::now() + interval,
            ticks_emitted: 0,
        }
    }

    /// Block until the next scheduled tick.
    /// Accumulates interval steps to prevent clock drift over long sessions.
    pub fn wait_next_tick(&mut self) {
        let now = Instant::now();
        if self.next_tick > now {
            std::thread::sleep(self.next_tick - now);
        }
        self.ticks_emitted += 1;
        self.next_tick += self.interval;
        // If the thread lagged far behind, resync next_tick to prevent burst catching up
        let after = Instant::now();
        if after > self.next_tick + self.interval {
            self.next_tick = after + self.interval;
        }
    }

    pub fn ticks_emitted(&self) -> u64 {
        self.ticks_emitted
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }
}

/// Build a cryptographically indistinguishable synthetic chaff frame.
/// Uses OS CSPRNG to fill payload, seals under active AEAD key with FTYPE_CHAFF.
/// The resulting wire length will exactly equal the requested `quantum`.
pub fn build_chaff_frame(
    key: &FrameKey,
    seq: u64,
    quantum: usize,
) -> Result<Vec<u8>, aes_gcm::aead::Error> {
    let valid_quantum = quantize(quantum).unwrap_or(DEFAULT_WIRE_QUANTUM);
    let payload_len = valid_quantum
        .checked_sub(FRAME_OVERHEAD)
        .ok_or(aes_gcm::aead::Error)?;

    let mut payload = vec![0u8; payload_len];
    getrandom::fill(&mut payload).map_err(|_| aes_gcm::aead::Error)?;

    let frame = aead::seal(key, seq, DIR_SEND, FTYPE_CHAFF, &payload)?;
    debug_assert_eq!(frame.len(), valid_quantum);
    Ok(frame)
}

/// Calculate the Shannon entropy in bits per byte (0.0 to 8.0) of a byte slice.
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{self, DIR_SEND};
    use crate::frame::FRAME_QUANTA;

    #[test]
    fn test_scheduler_timing_and_drift() {
        let mut scheduler = PacedScheduler::new(Duration::from_millis(5));
        assert_eq!(scheduler.ticks_emitted(), 0);
        assert_eq!(scheduler.interval(), Duration::from_millis(5));

        for _ in 0..3 {
            scheduler.wait_next_tick();
        }
        assert_eq!(scheduler.ticks_emitted(), 3);
    }

    #[test]
    fn test_chaff_frame_exact_quantization() {
        let key = FrameKey::from_bytes([0x42u8; 32]);
        for &quantum in &FRAME_QUANTA {
            let frame = build_chaff_frame(&key, 100, quantum).expect("build chaff failed");
            assert_eq!(frame.len(), quantum);

            // Verify authentication and type extraction
            let (seq, ftype, _pt) =
                aead::open_indexed(&key, DIR_SEND, &frame).expect("auth failed");
            assert_eq!(seq, 100);
            assert_eq!(ftype, FTYPE_CHAFF);
        }
    }

    #[test]
    fn test_chaff_frame_shannon_entropy() {
        let key = FrameKey::from_bytes([0x77u8; 32]);
        let frame = build_chaff_frame(&key, 1, 1232).expect("build chaff failed");
        assert_eq!(frame.len(), 1232);

        // Shannon entropy of uniform random distribution over 1232 bytes has finite-sample
        // downward bias: E[H] ~ 8.0 - (255 / (2 * 1232 * ln 2)) ~ 7.85 bits/byte.
        // Single frame must comfortably exceed 7.80 bits/byte.
        let single_entropy = calculate_shannon_entropy(&frame);
        assert!(
            single_entropy > 7.80,
            "Single frame entropy too low ({single_entropy:.4} bits/byte)"
        );

        // Over an 8-frame burst (~9.8 KB), empirical entropy converges to > 7.95 bits/byte.
        let mut burst = Vec::with_capacity(8 * 1232);
        for seq in 2..10 {
            let f = build_chaff_frame(&key, seq, 1232).expect("build chaff failed");
            burst.extend_from_slice(&f);
        }
        let burst_entropy = calculate_shannon_entropy(&burst);
        assert!(
            burst_entropy > 7.95,
            "Burst entropy too low ({burst_entropy:.4} bits/byte), potential pattern leakage"
        );
    }
}
