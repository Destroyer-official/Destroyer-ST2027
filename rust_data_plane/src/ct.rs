//! Constant-time comparison and selection primitives.
//!
//! Rationale (Layer 1.5): secret-dependent branches and early exits leak
//! through timing, cache, and power channels (see 2025/276 on masked
//! ML-DSA `y` leakage and 2025/582 on rejected-signature leakage: even
//! masked lattice code falls when a fast path depends on secret data).
//! These helpers compare/select in full passes with no secret-dependent
//! control flow. Volatile reads plus `black_box` keep the optimizer from
//! reintroducing early exits; this is best-effort hardening, NOT a
//! machine-checked proof (that requires Kani/Verus harnesses per fn).
//!
//! No new dependencies: core only. The `subtle` crate remains the
//! long-term target once vendored/offline builds allow it.

use core::hint::black_box;
use core::ptr;

/// Constant-time equality: true iff `a` and `b` have equal length and
/// equal contents. Always scans `max(len)` positions; length difference
/// only flips the accumulator (lengths are treated as public).
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u8 = if a.len() == b.len() { 0 } else { 1 };
    let n = a.len().max(b.len());
    for i in 0..n {
        // SAFETY: volatile reads of in-bounds-or-zero bytes; out-of-range
        // side reads zero without branching on the index.
        let x = if i < a.len() {
            unsafe { ptr::read_volatile(a.as_ptr().add(i)) }
        } else {
            0
        };
        let y = if i < b.len() {
            unsafe { ptr::read_volatile(b.as_ptr().add(i)) }
        } else {
            0
        };
        diff |= black_box(x ^ y);
    }
    black_box(diff) == 0
}

/// Constant-time select: returns a copy of `a` when `cond` is true,
/// else a copy of `b` (lengths must match; panics otherwise — lengths
/// are public, contents never steer a branch).
pub fn ct_select(cond: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "ct_select: length mismatch (public)");
    let mask: u8 = if cond { 0xFF } else { 0x00 };
    let mask = black_box(mask);
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| {
            let x = unsafe { ptr::read_volatile(&x) };
            let y = unsafe { ptr::read_volatile(&y) };
            black_box((x & mask) | (y & !mask))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"ab", b"abc"));
    }

    #[test]
    fn ct_select_basic() {
        assert_eq!(ct_select(true, b"aa", b"bb"), b"aa");
        assert_eq!(ct_select(false, b"aa", b"bb"), b"bb");
    }
}
