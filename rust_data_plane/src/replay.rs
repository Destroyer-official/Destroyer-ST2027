//! 1024-packet sequence sliding window per RFC 6479 (Decoupled IPsec/WireGuard mechanism).
//! O(1) word-indexed circular bitmap. Duplicate, replayed, or behind-window packets are
//! rejected; the caller MUST drop them silently (no reply, no log above debug).

pub const WINDOW_WORDS: usize = 16;
pub const WINDOW_SIZE: u64 = (WINDOW_WORDS as u64) * 64; // 1024 packets per RFC 6479

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
    #[inline(always)]
    pub fn mark(&mut self, seq: u64) {
        if seq == 0 {
            return;
        }
        if seq > self.last_seq {
            let new_word = seq / 64;
            let old_word = self.last_seq / 64;
            let diff_words = new_word.saturating_sub(old_word);
            if diff_words >= WINDOW_WORDS as u64 {
                self.bitmap = [0; WINDOW_WORDS];
            } else {
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

    /// Export persistent recv-window state (last_seq, active bitmap word).
    pub fn parts(&self) -> (u64, u64) {
        let active_word = if self.last_seq > 0 {
            self.bitmap[((self.last_seq / 64) % (WINDOW_WORDS as u64)) as usize]
        } else {
            0
        };
        (self.last_seq, active_word)
    }

    /// Export full 1024-bit RFC 6479 bitmap words.
    pub fn full_bitmap(&self) -> [u64; WINDOW_WORDS] {
        self.bitmap
    }

    /// Reconstruct from persistent state. Drops counter restarts at 0
    /// (operational metric, not security state).
    pub fn from_parts(last_seq: u64, bitmap_word: u64) -> Self {
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
}
