//! 64-bit sequence + 64-packet bitmap sliding window (WireGuard mechanism).
//! O(1), branchless masks. Duplicate, replayed, or behind-window packets are
//! rejected; the caller MUST drop them silently (no reply, no log above debug).

#[derive(Debug, Clone, Copy)]
pub struct AntiReplayWindow {
    last_seq: u64,
    bitmap: u64,
    drops: u64,
}

impl AntiReplayWindow {
    pub fn new() -> Self {
        AntiReplayWindow {
            last_seq: 0,
            bitmap: 0,
            drops: 0,
        }
    }

    /// Start from a random 64-bit offset so session position never leaks.
    pub fn with_offset(offset: u64) -> Self {
        AntiReplayWindow {
            last_seq: offset,
            bitmap: 0,
            drops: 0,
        }
    }

    /// Read-only acceptance test (RFC 6479 / WireGuard Sec 5.4).
    /// Safe on unauthenticated input: never mutates. Returns true iff
    /// `mark(seq)` would be permitted after AEAD authentication.
    #[inline(always)]
    pub fn check(&self, seq: u64) -> bool {
        if seq > self.last_seq {
            true
        } else {
            let diff = self.last_seq - seq;
            if diff >= 64 || (self.bitmap & (1 << diff)) != 0 {
                false
            } else {
                true
            }
        }
    }

    /// Advance window for a validated seq. Call ONLY after `check(seq)`
    /// accepted AND the AEAD tag for that exact seq verified. Idempotent
    /// for duplicates; no-op for behind-window (unreachable via check).
    #[inline(always)]
    pub fn mark(&mut self, seq: u64) {
        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            self.bitmap = if diff >= 64 { 0 } else { self.bitmap << diff };
            self.bitmap |= 1;
            self.last_seq = seq;
        } else {
            let diff = self.last_seq - seq;
            if diff < 64 {
                self.bitmap |= 1 << diff;
            }
        }
    }

    /// Returns true = accept, false = replay/outside-window (drop silently).
    /// Non-wire atomic helper retained for tests; wire paths MUST use
    /// check()-then-AEAD-then-mark() so forged seq cannot shift state
    /// before authentication.
    #[inline(always)]
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        let accept = if seq > self.last_seq {
            let diff = seq - self.last_seq;
            self.bitmap = if diff >= 64 { 0 } else { self.bitmap << diff };
            self.bitmap |= 1;
            self.last_seq = seq;
            true
        } else {
            let diff = self.last_seq - seq;
            if diff >= 64 || (self.bitmap & (1 << diff)) != 0 {
                false
            } else {
                self.bitmap |= 1 << diff;
                true
            }
        };
        if !accept {
            self.drops = self.drops.wrapping_add(1);
        }
        accept
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

    /// Export persistent recv-window state (last_seq, bitmap).
    pub fn parts(&self) -> (u64, u64) {
        (self.last_seq, self.bitmap)
    }

    /// Reconstruct from persistent state. Drops counter restarts at 0
    /// (operational metric, not security state).
    pub fn from_parts(last_seq: u64, bitmap: u64) -> Self {
        AntiReplayWindow {
            last_seq,
            bitmap,
            drops: 0,
        }
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
    fn sixty_three_behind_accepts_sixty_four_drops() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(100));
        assert!(w.check_and_update(37)); // diff 63 → accept
        assert!(!w.check_and_update(36)); // diff 64 → drop
    }

    #[test]
    fn jump_ahead_resyncs_window() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(1000)); // diff ≥ 64 → bitmap reset
        assert!(!w.check_and_update(1)); // old window gone → drop
        assert!(w.check_and_update(1001));
    }

    #[test]
    fn delayed_replay_after_5s_equivalent_drops() {
        let mut w = AntiReplayWindow::new();
        for s in 1..=10u64 {
            assert!(w.check_and_update(s));
        }
        assert!(!w.check_and_update(3)); // captured frame replayed later
    }
}
