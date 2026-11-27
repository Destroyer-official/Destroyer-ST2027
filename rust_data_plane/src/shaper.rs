//! Pure-Rust Tamaraw / Constant-Rate Fixed-Cell Shaper (0 extra crates).
//!
//! Designed to mitigate KDE/deep-learning Tor flow correlation attacks
//! (e.g., ESPRESSO, Jeon et al., ACM CCS '26) without pulling unmaintained
//! third-party serialization graphs (such as `bincode 1.3` / `RUSTSEC-2025-0141`).
//!
//! Tor Relay Cell Alignment:
//! Each Tor link cell is 514 bytes carrying at most 498 usable RELAY payload bytes.
//! Because stream-framed ST2027 frames carry a 2-byte big-endian length prefix:
//! - `TOR_QUANTUM_SINGLE = 496` bytes (+ 2B len = 498B -> exact 1 Tor relay cell).
//! - `TOR_QUANTUM_DOUBLE = 994` bytes (+ 2B len = 996B -> exact 2 Tor relay cells).
//!
//! Tamaraw Discipline:
//! Every tick emits one fixed-quantum encrypted frame (`Control`/`Rekey` > `AppData` >
//! `FTYPE_CHAFF` cover). Whenever a real-data burst ends, trailing cover cells
//! continue until the burst count reaches a multiple of `batch_mod_l` (`L`),
//! bounding leaked burst-size entropy cleanly while optional constant-rate cover
//! traffic hides idle/active transitions altogether.

use crate::frame::FRAME_OVERHEAD;

/// Maximum usable payload inside a single Tor v3 RELAY cell.
pub const TOR_RELAY_PAYLOAD_BYTES: usize = 498;
/// Stream frame size aligned to 1 Tor relay cell (496B frame + 2B length = 498B).
pub const TOR_QUANTUM_SINGLE: usize = 496;
/// Stream frame size aligned to 2 Tor relay cells (994B frame + 2B length = 996B).
pub const TOR_QUANTUM_DOUBLE: usize = 994;
/// Default Tamaraw batch alignment parameter `L` (cells).
pub const DEFAULT_TAMARAW_MOD_L: usize = 32;

/// Output decision emitted by `TamarawShaper::next_action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamarawAction {
    EmitControlOrRekey,
    EmitData,
    EmitChaff,
    Idle,
}

/// Deterministic fixed-rate Tamaraw cell emission scheduler.
#[derive(Debug, Clone)]
pub struct TamarawShaper {
    batch_mod_l: usize,
    cells_in_epoch: usize,
    continuous_cover: bool,
    pub real_cells: u64,
    pub chaff_cells: u64,
}

impl TamarawShaper {
    pub fn new(batch_mod_l: usize, continuous_cover: bool) -> Self {
        Self {
            batch_mod_l: batch_mod_l.max(1),
            cells_in_epoch: 0,
            continuous_cover,
            real_cells: 0,
            chaff_cells: 0,
        }
    }

    pub fn batch_mod_l(&self) -> usize {
        self.batch_mod_l
    }

    /// Number of cells emitted in the current incomplete `L`-cell Tamaraw epoch (`0..L`).
    pub fn cells_in_epoch(&self) -> usize {
        self.cells_in_epoch
    }

    /// Select what single fixed-quantum cell to emit on this pacing tick.
    pub fn next_action(&mut self, has_control: bool, has_data: bool) -> TamarawAction {
        if has_control {
            self.real_cells += 1;
            self.cells_in_epoch = (self.cells_in_epoch + 1) % self.batch_mod_l;
            return TamarawAction::EmitControlOrRekey;
        }
        if has_data {
            self.real_cells += 1;
            self.cells_in_epoch = (self.cells_in_epoch + 1) % self.batch_mod_l;
            return TamarawAction::EmitData;
        }
        if self.cells_in_epoch != 0 {
            self.chaff_cells += 1;
            self.cells_in_epoch = (self.cells_in_epoch + 1) % self.batch_mod_l;
            return TamarawAction::EmitChaff;
        }
        if self.continuous_cover {
            self.chaff_cells += 1;
            return TamarawAction::EmitChaff;
        }
        TamarawAction::Idle
    }
}

/// Compute `(quantum, pad_bytes)` when targeting an explicit wire quantum `target_quantum`
/// (supports UDP `[256, 512, 1232]` and Tor-cell-aligned `[496, 994]`).
pub fn pad_to_explicit_quantum(payload_len: usize, target_quantum: usize) -> Option<(usize, usize)> {
    if !is_valid_quantum(target_quantum) {
        return None;
    }
    let total = payload_len.checked_add(FRAME_OVERHEAD)?;
    if total > target_quantum {
        return None;
    }
    Some((target_quantum, target_quantum - total))
}

/// Largest application plaintext payload that fits cleanly inside `quantum`.
pub fn max_payload_for_quantum(quantum: usize) -> Option<usize> {
    if !is_valid_quantum(quantum) {
        return None;
    }
    quantum.checked_sub(FRAME_OVERHEAD)
}

/// True iff `quantum` is a sanctioned fixed framing quantum.
pub fn is_valid_quantum(quantum: usize) -> bool {
    matches!(quantum, 256 | 496 | 512 | 994 | 1232)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_cell_alignment_math_exact() {
        // 2-byte stream length prefix + quantum == exact multiple of 498B Tor relay cell.
        assert_eq!(TOR_QUANTUM_SINGLE + 2, TOR_RELAY_PAYLOAD_BYTES);
        assert_eq!(TOR_QUANTUM_DOUBLE + 2, TOR_RELAY_PAYLOAD_BYTES * 2);
        assert_eq!(max_payload_for_quantum(TOR_QUANTUM_SINGLE), Some(469));
        assert_eq!(max_payload_for_quantum(TOR_QUANTUM_DOUBLE), Some(967));
        assert_eq!(pad_to_explicit_quantum(469, TOR_QUANTUM_SINGLE), Some((496, 0)));
        assert_eq!(pad_to_explicit_quantum(470, TOR_QUANTUM_SINGLE), None);
    }

    #[test]
    fn tamaraw_burst_always_pads_to_multiple_of_l() {
        let mut s = TamarawShaper::new(8, false);
        // Send 3 real frames -> remaining 5 ticks must emit Chaff until modulo 8 hits 0.
        for _ in 0..3 {
            assert_eq!(s.next_action(false, true), TamarawAction::EmitData);
        }
        assert_eq!(s.cells_in_epoch(), 3);
        for _ in 0..5 {
            assert_eq!(s.next_action(false, false), TamarawAction::EmitChaff);
        }
        assert_eq!(s.cells_in_epoch(), 0);
        assert_eq!(s.real_cells + s.chaff_cells, 8);
        assert_eq!(s.next_action(false, false), TamarawAction::Idle);
    }

    #[test]
    fn continuous_cover_never_goes_idle_and_keeps_control_priority() {
        let mut s = TamarawShaper::new(16, true);
        assert_eq!(s.next_action(false, false), TamarawAction::EmitChaff);
        assert_eq!(s.next_action(true, true), TamarawAction::EmitControlOrRekey);
        assert_eq!(s.cells_in_epoch(), 1);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn verify_tor_padding_never_overflows() {
        let payload_len: usize = kani::any();
        let q: usize = kani::any();
        kani::assume(q <= 4096);
        if let Some((quantum, pad)) = pad_to_explicit_quantum(payload_len, q) {
            assert!(is_valid_quantum(quantum));
            assert_eq!(payload_len + FRAME_OVERHEAD + pad, quantum);
        }
    }
}
