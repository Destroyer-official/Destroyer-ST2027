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

    /// Returns true = accept, false = replay/outside-window (drop silently).
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
