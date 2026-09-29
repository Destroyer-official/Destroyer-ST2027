//! Kani verification harnesses + `cargo test` property doubles (additive only).
//!
//! - Gated Kani proofs (`#[cfg(kani)]`): run with `cargo kani` (Kani injects
//!   the `kani` crate and `--cfg kani`; no `Cargo.toml` change needed).
//! - Non-Kani doubles (`#[cfg(not(kani))]` plain `#[test]` loops, no new deps):
//!   run with `cargo test --test kani_harness`. They duplicate the same four
//!   properties deterministically.
//!
//! Why `#[path]` includes: `rust_data_plane/Cargo.toml` sets
//! `crate-type = ["cdylib"]` (Python extension), so an integration test in
//! `tests/` cannot `use destroyer_core::...` (no rlib). Including the real
//! sources by path exercises the REAL logic without touching `src/lib.rs`,
//! `src/aead.rs`, or `Cargo.toml` (additive only).
//!
//! Properties covered:
//!  1. frame split/reassemble roundtrip (`frame::split_payload`, bound <=1232)
//!  2. nonce domain separation (`DIR_SEND != DIR_RECV`)
//!  3. replay window monotonic / duplicate + behind-window drops
//!  4. `MAX_STREAM_BYTES` cap (mirror of `destroyer_node.py`, 16 MiB)
//!
//! Run:
//!   cargo test --test kani_harness   # always passes without Kani
//!   cargo kani                       # needs Kani; proves #[kani::proof] fns

// Real sources, included by path (additive-only workaround for cdylib-only).
#![allow(dead_code)]
#[path = "../src/frame.rs"]
mod frame;
#[path = "../src/replay.rs"]
mod replay;
// NOTE: `aead.rs` does `use crate::frame::{FTYPE_CHAFF, FTYPE_MSG};` — that
// resolves here to the `mod frame` above (crate root of THIS test crate),
// so this exercises the real `make_nonce`/seal logic, not a copy.
#[path = "../src/aead.rs"]
mod aead;
#[path = "../src/ct.rs"]
mod ct;
#[path = "../src/nostd_microcore.rs"]
pub mod nostd_microcore;

/// Stream cap mirror: `destroyer_node.py::MAX_STREAM_BYTES = 16 * 1024 * 1024`.
///
/// The Rust data plane has no stream assembler yet (frames only); this const
/// pins the Python-side contract so Kani + `cargo test` guard the bound the
/// future Rust assembler MUST enforce (reject `len > MAX_STREAM_BYTES`).
pub const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;

/// Pure acceptance predicate the future Rust stream assembler must enforce.
pub fn stream_len_ok(len: usize) -> bool {
    len <= MAX_STREAM_BYTES
}

// ---------------------------------------------------------------------------
// Kani proofs (only compiled under `cargo kani`, which sets `--cfg kani`).
// No new dependencies: the `kani` crate is injected by the Kani driver.
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod kani_proofs {
    use super::{aead, frame, replay, MAX_STREAM_BYTES};

    /// 1. Frame split/reassemble roundtrip, payload bound <= 1232 bytes
    /// (largest on-wire quantum; covers 1-chunk and 2-chunk cases).
    #[kani::proof]
    fn kani_frame_split_reassemble_roundtrip() {
        let len: usize = kani::any();
        kani::assume(len <= 1232);
        let fill: u8 = kani::any();
        let payload = vec![fill; len];
        let chunks = frame::split_payload(&payload);
        // Every chunk respects the per-frame cap.
        for c in &chunks {
            kani::assert(c.len() <= frame::CHUNK_MAX, "chunk respects CHUNK_MAX");
        }
        // Chunk count is exactly ceil(len / CHUNK_MAX) (empty => 0 chunks).
        let expected = if len == 0 {
            0
        } else {
            (len + frame::CHUNK_MAX - 1) / frame::CHUNK_MAX
        };
        kani::assert(chunks.len() == expected, "chunk count is ceil(len/CHUNK_MAX)");
        // Reassembly (sequence-order concatenation) is the identity.
        let mut joined = Vec::new();
        for c in &chunks {
            joined.extend_from_slice(c);
        }
        kani::assert(joined == payload, "split/reassemble roundtrips");
    }

    /// 2. Nonce domain separation: same seq under DIR_SEND vs DIR_RECV
    /// MUST yield different nonces; layout is `seq_BE(8) || dir(1) || 0x00(3)`.
    #[kani::proof]
    fn kani_nonce_domain_separation() {
        let seq: u64 = kani::any();
        kani::assert(
            aead::DIR_SEND != aead::DIR_RECV,
            "DIR_SEND != DIR_RECV",
        );
        let n_send = aead::make_nonce(seq, aead::DIR_SEND);
        let n_recv = aead::make_nonce(seq, aead::DIR_RECV);
        kani::assert(n_send != n_recv, "direction bit separates nonce domains");
        // Layout pins (mirrors src/aead.rs::make_nonce).
        let be = seq.to_be_bytes();
        kani::assert(&n_send.as_slice()[..8] == &be[..], "seq occupies nonce[0..8]");
        kani::assert(n_send.as_slice()[8] == aead::DIR_SEND, "dir at nonce[8]");
        kani::assert(
            n_send.as_slice()[9..] == [0u8, 0u8, 0u8],
            "nonce[9..12] zero padding",
        );
    }

    /// 3. Replay window monotonicity: strictly increasing seqs accept,
    /// duplicates drop, `drop_count` is monotonic non-decreasing.
    #[kani::proof]
    fn kani_replay_window_monotonic() {
        let base: u64 = kani::any();
        // Keep headroom so +offsets cannot wrap.
        kani::assume(base < u64::MAX - 256);
        let step: u64 = kani::any();
        kani::assume(step >= 1 && step <= 32);
        let mut w = replay::AntiReplayWindow::with_offset(base);
        let drops_before = w.drop_count();
        kani::assert(w.check_and_update(base + step), "forward seq accepts");
        // Immediate duplicate MUST drop.
        kani::assert(
            !w.check_and_update(base + step),
            "duplicate seq drops",
        );
        kani::assert(
            w.drop_count() == drops_before.wrapping_add(1),
            "drop counter increments monotonically",
        );
        // A further-forward seq still accepts (window slides forward only).
        kani::assert(
            w.check_and_update(base + step + 1),
            "next forward seq accepts after a drop",
        );
    }

    /// 4. `MAX_STREAM_BYTES` cap: accept iff `len <= 16 MiB`; accepted lens
    /// imply a bounded chunk count the assembler can allocate.
    #[kani::proof]
    fn kani_max_stream_bytes_cap() {
        kani::assert(
            MAX_STREAM_BYTES == 16 * 1024 * 1024,
            "cap pinned to 16 MiB (mirrors destroyer_node.py)",
        );
        let len: usize = kani::any();
        kani::assume(len <= MAX_STREAM_BYTES + 4096);
        let ok = super::stream_len_ok(len);
        kani::assert(ok == (len <= MAX_STREAM_BYTES), "cap predicate is exact");
        if ok {
            let n = if len == 0 {
                0
            } else {
                (len + frame::CHUNK_MAX - 1) / frame::CHUNK_MAX
            };
            kani::assert(
                n <= (MAX_STREAM_BYTES + frame::CHUNK_MAX - 1) / frame::CHUNK_MAX,
                "accepted streams need bounded chunks",
            );
        } else {
            kani::assert(len > MAX_STREAM_BYTES, "over-cap streams rejected");
        }
    }

    /// 5. nostd_microcore frame parse memory safety & non-panic proof:
    /// For any arbitrary slice of bytes, parse_stack_frame_in_place never panics.
    #[kani::proof]
    fn kani_nostd_frame_parse_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 64);
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            *b = kani::any();
        }
        let _ = super::nostd_microcore::parse_stack_frame_in_place(&buf);
    }
}

// ---------------------------------------------------------------------------
// `cargo test` doubles (compiled when NOT under Kani). Plain #[test] loops,
// no new deps — deterministic proptest-style sweeps of the same properties.
// ---------------------------------------------------------------------------
#[cfg(not(kani))]
mod property_doubles {
    use super::{aead, ct, frame, replay, MAX_STREAM_BYTES};

    // Simple deterministic xorshift64 for pseudo-random sweeps (no deps).
    fn lcg_next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn frame_split_reassemble_roundtrip_bounded() {
        // Edge lens: empty, 1B, quanta boundaries, CHUNK_MAX +/- 1, >1232.
        for len in [
            0usize, 1, 27, 229, 256, 485, 512, 1204, 1205, 1206, 1232, 1233, 2410, 3615,
            5000,
        ] {
            let payload = vec![0xA5u8; len];
            let chunks = frame::split_payload(&payload);
            for c in &chunks {
                assert!(c.len() <= frame::CHUNK_MAX, "chunk cap len={len}");
            }
            let expected = if len == 0 {
                0
            } else {
                (len + frame::CHUNK_MAX - 1) / frame::CHUNK_MAX
            };
            assert_eq!(chunks.len(), expected, "chunk count len={len}");
            let joined: Vec<u8> = chunks.concat();
            assert_eq!(joined, payload, "roundtrip len={len}");
        }
        // Pseudo-random sweep, payload <= 1232 (Kani bound mirror), 512 iters.
        let mut rng: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..512 {
            let len = (lcg_next(&mut rng) % 1233) as usize;
            let fill = (lcg_next(&mut rng) & 0xFF) as u8;
            let payload = vec![fill; len];
            let chunks = frame::split_payload(&payload);
            let joined: Vec<u8> = chunks.concat();
            assert_eq!(joined, payload, "random roundtrip len={len}");
        }
    }

    #[test]
    fn nonce_domain_separation() {
        assert_ne!(aead::DIR_SEND, aead::DIR_RECV, "dir consts differ");
        for seq in [
            0u64,
            1,
            7,
            8,
            255,
            256,
            0x0102030405060708,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let ns = aead::make_nonce(seq, aead::DIR_SEND);
            let nr = aead::make_nonce(seq, aead::DIR_RECV);
            assert_ne!(ns, nr, "domains differ seq={seq}");
            assert_eq!(&ns.as_slice()[..8], &seq.to_be_bytes(), "seq layout");
            assert_eq!(ns.as_slice()[8], aead::DIR_SEND);
            assert_eq!(&ns.as_slice()[9..], &[0u8, 0u8, 0u8]);
            // Adjacent seqs also separate within one direction.
            let ns1 = aead::make_nonce(seq.wrapping_add(1), aead::DIR_SEND);
            assert_ne!(ns, ns1, "seq separates within dir");
        }
        // Pseudo-random sweep.
        let mut rng: u64 = 0x243F6A8885A308D3;
        for _ in 0..256 {
            let seq = lcg_next(&mut rng);
            assert_ne!(
                aead::make_nonce(seq, aead::DIR_SEND),
                aead::make_nonce(seq, aead::DIR_RECV),
                "random domains differ"
            );
        }
    }

    #[test]
    fn replay_window_monotonic_and_drops() {
        // In-order accepts.
        let mut w = replay::AntiReplayWindow::new();
        for s in 1..=16u64 {
            assert!(w.check_and_update(s), "in-order {s} accepts");
        }
        // Duplicate drops + counter monotonic.
        let d0 = w.drop_count();
        assert!(!w.check_and_update(16), "duplicate drops");
        assert!(!w.check_and_update(3), "old replay drops");
        assert!(w.drop_count() > d0, "drop counter grew");
        // 63-behind accepts, 64-behind drops (window = 64).
        let mut w2 = replay::AntiReplayWindow::new();
        assert!(w2.check_and_update(100));
        assert!(w2.check_and_update(37), "diff 63 accepts");
        assert!(!w2.check_and_update(36), "diff 64 drops");
        // Jump-ahead resyncs; monotonic forward progress preserved.
        let mut w3 = replay::AntiReplayWindow::with_offset(5000);
        assert!(w3.check_and_update(5001));
        assert!(w3.check_and_update(6000), "far jump accepts + resyncs");
        assert!(!w3.check_and_update(5001), "pre-jump window gone");
        assert!(w3.check_and_update(6001));
        // drop_count never decreases across mixed traffic.
        let mut w4 = replay::AntiReplayWindow::new();
        let mut last_drops = w4.drop_count();
        let mut rng: u64 = 0xB7E151628AED2A6B;
        for _ in 0..256 {
            let seq = 1 + (lcg_next(&mut rng) % 200);
            w4.check_and_update(seq);
            assert!(
                w4.drop_count() >= last_drops,
                "drop_count monotonic (wrapping compare via >= on small counts)"
            );
            last_drops = w4.drop_count();
        }
    }

    #[test]
    fn ct_eq_and_select_no_secret_branch() {
        // Equality matrix incl. empty and length-mismatched inputs.
        assert!(ct::ct_eq(b"", b""));
        assert!(ct::ct_eq(b"abc", b"abc"));
        assert!(!ct::ct_eq(b"abc", b"abd"));
        assert!(!ct::ct_eq(b"abc", b"ab"));
        assert!(!ct::ct_eq(b"ab", b"abc"));
        // 32-byte key-shaped sweep (all single-bit flips reject).
        let base = [0x5Au8; 32];
        assert!(ct::ct_eq(&base, &base));
        for i in 0..32 {
            let mut bad = base;
            bad[i] ^= 0x01;
            assert!(!ct::ct_eq(&base, &bad), "bit {i} must reject");
        }
        // Select honors the flag for both outcomes.
        assert_eq!(ct::ct_select(true, b"aa", b"bb"), b"aa");
        assert_eq!(ct::ct_select(false, b"aa", b"bb"), b"bb");
    }

    #[test]
    fn max_stream_bytes_cap_enforced() {        assert_eq!(MAX_STREAM_BYTES, 16 * 1024 * 1024, "cap pinned to 16 MiB");
        assert!(super::stream_len_ok(0));
        assert!(super::stream_len_ok(MAX_STREAM_BYTES));
        assert!(!super::stream_len_ok(MAX_STREAM_BYTES + 1));
        assert!(!super::stream_len_ok(usize::MAX));
        // Accepted lens imply bounded chunk counts (no overflow in ceil div).
        let max_chunks = (MAX_STREAM_BYTES + frame::CHUNK_MAX - 1) / frame::CHUNK_MAX;
        assert_eq!(max_chunks, (16777216 + 1205 - 1) / 1205);
        for len in [0usize, 1, 1205, 1206, 1232, MAX_STREAM_BYTES] {
            assert!(super::stream_len_ok(len));
            let n = if len == 0 {
                0
            } else {
                (len + frame::CHUNK_MAX - 1) / frame::CHUNK_MAX
            };
            assert!(n <= max_chunks, "chunks bounded len={len}");
        }
    }

    #[test]
    fn nostd_frame_parse_never_panics_property_sweep() {
        let mut rng: u64 = 0xD1CEB00B1E5;
        // Test 1000 arbitrary byte vectors of random lengths 0..1500
        for _ in 0..1000 {
            let len = (lcg_next(&mut rng) % 1500) as usize;
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                *b = (lcg_next(&mut rng) & 0xFF) as u8;
            }
            // Must never panic
            let _ = super::nostd_microcore::parse_stack_frame_in_place(&buf);
        }
    }

    #[test]
    fn nostd_stack_secret_ct_eq_property_sweep() {
        let mut rng: u64 = 0xCAFEBABE1234;
        for _ in 0..500 {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            for i in 0..32 {
                a[i] = (lcg_next(&mut rng) & 0xFF) as u8;
                b[i] = (lcg_next(&mut rng) & 0xFF) as u8;
            }
            let sec_a = super::nostd_microcore::StackSecretBuffer::<32>::from_slice(&a).unwrap();
            let sec_b = super::nostd_microcore::StackSecretBuffer::<32>::from_slice(&b).unwrap();
            let sec_a_clone = super::nostd_microcore::StackSecretBuffer::<32>::from_slice(&a).unwrap();

            assert!(sec_a.ct_eq(&sec_a_clone));
            assert_eq!(sec_a.ct_eq(&sec_b), a == b);
        }
    }
}
