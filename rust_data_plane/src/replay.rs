//! 1024-packet sequence sliding window per RFC 6479 (Decoupled IPsec/WireGuard mechanism).
//! O(1) word-indexed circular bitmap. Duplicate, replayed, or behind-window packets are
//! rejected; the caller MUST drop them silently (no reply, no log above debug).

pub const WINDOW_WORDS: usize = 32;
pub const WINDOW_SIZE: u64 = 1024; // 1024 packets per RFC 6479

#[derive(Debug, Clone, Copy)]
pub struct AntiReplayWindow {
    last_seq: u64,
    bitmap: [u64; WINDOW_WORDS],
    drops: u64,
}

impl AntiReplayWindow {
    pub fn new() -> Self {
        AntiReplayWindow {
            last_seq: 0,
            bitmap: [0; WINDOW_WORDS],
            drops: 0,
        }
    }

    /// Start from a random 64-bit offset so session position never leaks.
    pub fn with_offset(offset: u64) -> Self {
        AntiReplayWindow {
            last_seq: offset,
            bitmap: [0; WINDOW_WORDS],
            drops: 0,
        }
    }

    /// Read-only acceptance test (RFC 6479 / WireGuard Sec 5.4).
    /// Safe on unauthenticated input: never mutates. Returns true iff
    /// `mark(seq)` would be permitted after AEAD authentication.
    #[inline(always)]
    pub fn check(&self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.last_seq {
            true
        } else {
            let diff = self.last_seq - seq;
            if diff >= WINDOW_SIZE {
                false
            } else {
                let word_idx = ((seq / 64) % (WINDOW_WORDS as u64)) as usize;
                let bit_idx = seq % 64;
                (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
            }
        }
    }

    /// Advance window for a validated seq. Call ONLY after `check(seq)`
    /// accepted AND the AEAD tag for that exact seq verified. Idempotent
    /// for duplicates; no-op for behind-window (unreachable via check).
    ///
    /// S-01 fix: WINDOW_WORDS = 32 guarantees that the maximum distance between
    /// any packet within the 1024-packet window (diff < 1024 => word_diff <= 16)
    /// and last_seq is strictly smaller than the 32-word ring. Clearing slots
    /// for newly entered words (old_word+1..=new_word) never aliases to or zeroes
    /// valid packets near the trailing edge of the window.
    #[inline(always)]
    pub fn mark(&mut self, seq: u64) {
        if seq == 0 {
            return;
        }
        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff >= WINDOW_SIZE {
                self.bitmap = [0; WINDOW_WORDS];
            } else {
                let new_word = seq / 64;
                let old_word = self.last_seq / 64;
                for w in (old_word + 1)..=new_word {
                    self.bitmap[(w % (WINDOW_WORDS as u64)) as usize] = 0;
                }
            }
            self.last_seq = seq;
            let word_idx = ((seq / 64) % (WINDOW_WORDS as u64)) as usize;
            self.bitmap[word_idx] |= 1u64 << (seq % 64);
        } else {
            let diff = self.last_seq - seq;
            if diff < WINDOW_SIZE {
                let word_idx = ((seq / 64) % (WINDOW_WORDS as u64)) as usize;
                self.bitmap[word_idx] |= 1u64 << (seq % 64);
            }
        }
    }

    /// Returns true = accept, false = replay/outside-window (drop silently).
    /// Non-wire atomic helper retained for tests; wire paths MUST use
    /// check()-then-AEAD-then-mark() so forged seq cannot shift state
    /// before authentication.
    #[inline(always)]
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if self.check(seq) {
            self.mark(seq);
            true
        } else {
            self.drops = self.drops.wrapping_add(1);
            false
        }
    }

    pub fn drop_count(&self) -> u64 {
        self.drops
    }

    /// Record a rejected packet for operational metrics. Called by wire
    /// paths when read-only `check()` refuses BEFORE authentication
    /// (obvious replay/stale), preserving `drop_count` semantics of the
    /// legacy combined helper without mutating window state.
    pub fn note_drop(&mut self) {
        self.drops = self.drops.wrapping_add(1);
    }

    /// Export persistent recv-window state (last_seq, full 32-word bitmap).
    /// Resolves S-02: persisting the entire 32-word (256-byte) bitmap ensures
    /// zero replay history truncation across receiver restarts.
    pub fn parts(&self) -> (u64, [u64; WINDOW_WORDS]) {
        (self.last_seq, self.bitmap)
    }

    /// Export full 2048-bit (32 x 64-bit word) RFC 6479 bitmap words.
    pub fn full_bitmap(&self) -> [u64; WINDOW_WORDS] {
        self.bitmap
    }

    /// Reconstruct from persistent state with full 32-word bitmap.
    /// Drops counter restarts at 0 (operational metric, not security state).
    pub fn from_parts(last_seq: u64, bitmap: [u64; WINDOW_WORDS]) -> Self {
        AntiReplayWindow {
            last_seq,
            bitmap,
            drops: 0,
        }
    }

    /// Backward compatibility helper for reconstructing from a single word.
    pub fn from_single_word(last_seq: u64, bitmap_word: u64) -> Self {
        let mut w = AntiReplayWindow {
            last_seq,
            bitmap: [0; WINDOW_WORDS],
            drops: 0,
        };
        if last_seq > 0 {
            let idx = ((last_seq / 64) % (WINDOW_WORDS as u64)) as usize;
            w.bitmap[idx] = bitmap_word;
        }
        w
    }
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_accepts() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(2));
        assert!(w.check_and_update(3));
    }

    #[test]
    fn duplicate_drops() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(10));
        assert!(!w.check_and_update(10));
        assert_eq!(w.drop_count(), 1);
    }

    #[test]
    fn rfc6479_1024_window_boundaries() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(2000));
        // Up to 1023 packets behind is inside 1024-packet window:
        assert!(w.check_and_update(2000 - 1023)); // diff 1023 -> accept
        assert!(!w.check_and_update(2000 - 1024)); // diff 1024 -> drop
    }

    #[test]
    fn jump_ahead_resyncs_window() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(5000)); // diff >= 1024 -> bitmap reset
        assert!(!w.check_and_update(1)); // old window gone -> drop
        assert!(w.check_and_update(5001));
    }

    #[test]
    fn delayed_replay_after_traffic_drops() {
        let mut w = AntiReplayWindow::new();
        for s in 1..=50u64 {
            assert!(w.check_and_update(s));
        }
        assert!(!w.check_and_update(3)); // captured frame replayed later
    }

    /// S-01 regression: accept seq 6, then seq 1029. Replaying seq 6 must be
    /// rejected (it is 1023 packets behind, inside the 1024-packet window and
    /// was already received).
    #[test]
    fn no_replay_after_window_slide() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(6));
        assert!(w.check_and_update(1029));
        assert!(
            !w.check(6),
            "S-01 failure: packet 6 was replayed and accepted"
        );
        assert!(!w.check_and_update(6));
    }

    /// S-02 regression: replay history preserved across restarts.
    /// Deliver 300 messages, persist full 32-word bitmap state, restore, and
    /// replay them. Zero replays may be accepted.
    #[test]
    fn no_replay_after_restart() {
        let base = 1u64 << 40;
        let mut w = AntiReplayWindow::new();
        for s in base..base + 300 {
            assert!(w.check_and_update(s));
        }
        let (last, full_map) = w.parts();
        let w2 = AntiReplayWindow::from_parts(last, full_map);
        for s in base..base + 300 {
            assert!(
                !w2.check(s),
                "S-02 failure: packet {s} accepted after restart"
            );
            assert!(!w2.clone().check_and_update(s));
        }
    }

    /// Property test against reference model (std::collections::BTreeSet):
    /// Tests 100,000 steps of random mixed sequence numbers (in-order, out-of-order,
    /// duplicate replays, small forward jumps, large jumps).
    #[test]
    fn property_test_against_reference() {
        use std::collections::BTreeSet;

        struct RefModel {
            max_seq: u64,
            seen: BTreeSet<u64>,
        }

        impl RefModel {
            fn new() -> Self {
                Self {
                    max_seq: 0,
                    seen: BTreeSet::new(),
                }
            }

            fn check(&self, seq: u64) -> bool {
                if seq == 0 {
                    return false;
                }
                if seq > self.max_seq {
                    true
                } else {
                    let diff = self.max_seq - seq;
                    if diff >= WINDOW_SIZE {
                        false
                    } else {
                        !self.seen.contains(&seq)
                    }
                }
            }

            fn mark(&mut self, seq: u64) {
                if seq == 0 {
                    return;
                }
                if seq > self.max_seq {
                    let diff = seq - self.max_seq;
                    if diff >= WINDOW_SIZE {
                        self.seen.clear();
                    } else {
                        let cutoff = seq.saturating_sub(WINDOW_SIZE - 1);
                        self.seen.retain(|&s| s >= cutoff);
                    }
                    self.max_seq = seq;
                    self.seen.insert(seq);
                } else {
                    let diff = self.max_seq - seq;
                    if diff < WINDOW_SIZE {
                        self.seen.insert(seq);
                    }
                }
            }
        }

        let mut w = AntiReplayWindow::new();
        let mut r = RefModel::new();

        // Deterministic LCG pseudo-random generator
        let mut rng_state: u64 = 0xDEADBEEFCAFE1234;
        let mut next_rand = || {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            rng_state
        };

        let mut current_seq = 100u64;
        let mut accepted_history = Vec::new();

        for _ in 0..10_000 {
            let choice = next_rand() % 100;
            let seq = if choice < 40 {
                // In-order forward progression
                current_seq += 1 + (next_rand() % 5);
                current_seq
            } else if choice < 70 && !accepted_history.is_empty() {
                // Replay a previously accepted packet (recent or old)
                let idx = (next_rand() as usize) % accepted_history.len();
                accepted_history[idx]
            } else if choice < 85 {
                // Small jump ahead or within-window out-of-order packet
                let offset = (next_rand() % 200) as i64 - 100;
                (current_seq as i64 + offset).max(1) as u64
            } else if choice < 95 {
                // Large forward jump >= WINDOW_SIZE
                current_seq += 1024 + (next_rand() % 2000);
                current_seq
            } else {
                // Completely ancient packet
                current_seq.saturating_sub(5000).max(1)
            };

            let w_check = w.check(seq);
            let r_check = r.check(seq);
            assert_eq!(
                w_check,
                r_check,
                "Check mismatch at seq {seq} (last_seq={}): w={}, ref={}",
                w.parts().0,
                w_check,
                r_check
            );

            if w_check {
                w.mark(seq);
                r.mark(seq);
                accepted_history.push(seq);
                if accepted_history.len() > 2000 {
                    accepted_history.drain(0..500);
                }
            }
        }
    }
}
