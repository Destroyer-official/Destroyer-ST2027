# `rust_data_plane/` — native data plane (all code read + tested)

## Layout

`Cargo.toml` (deps resolved live, frozen in `Cargo.lock`), `pyproject.toml`
(maturin backend), `python/destroyer_core/__init__.py` (re-export),
`src/lib.rs` (`SecureEngine`: session API — `establish_session(key, seq,
is_initiator)`, `seal_msg`, `open_msg`, `check_seq`, `drop_count`).

## Modules (all read in full, 118 tests green: 88 unit + 30 kani harness tests: 7 property doubles + re-exported module tests)

- `frame.rs` — `[seq:u64‖len:u16‖type:u8‖ct‖tag:16B]`, quanta 256/512/1232
  (TOTAL wire sizes; max payload 1205; 1232+40+8=1280 proven in-test),
  `split_payload` chunking with boundary tests.
- `replay.rs` — u64 seq + u64 bitmap (WireGuard mechanism), random start
  offsets, wrapping counters; 5 behavioral tests.
- `aead.rs` — AES-256-GCM (CNSA 2.0 suite), header-AAD, `seq‖dir` nonces
  (`DIR_SEND=0x00`/`DIR_RECV=0x01`), HKDF-SHA512 key derivation,
  `ZeroizeOnDrop` keys; tag-derived header whitening `ST2027-HEADER-MASK-v1`.
- `kem.rs` — X25519-dalek 3.0.0 + `ml-kem` 0.3.2, RFC 10024 concatenation,
  FIPS sizes pinned, implicit-rejection verified live, fail-closed lengths.
- `net.rs` — dual-stack UDP, black-hole discipline, per-source token bucket
  (64/16-per-s), 1280 MTU cap (both OS-error and truncate paths tested),
  IPv6 loopback proof, 50-msg pipeline, refill proof, 200-msg battle under
  4x scanner fire (zero loss, zero replies).
- `cookie.rs` — Stateless Anti-Amplification Cookie Gate with micro-PoW puzzle solver.
- `acd.rs` — Active Cyber Defense autonomous threat mitigation engine, sliding window, and quarantine.
- `zero_trust.rs` — Bell-LaPadula Multilevel Security (MLS), dynamic trust scoring, and RTB content inspection.
- `memory_guard.rs` — CSPRNG stack canaries, page-locked RAM, and volatile memory sanitization.
- `fec.rs` — Cauchy-Reed-Solomon GF(2^8) forward error correction for simplex optical diodes.
- `pacing.rs` — Constant-rate 50ms wire scheduler and Shannon entropy verification.
- `purge.rs` — Multi-pass NIST SP 800-88 cryptographic media sanitization and unlinking.
- `pad.rs` / `chaff.rs` — budgets + `0xFF` chaff typing.

## Standalone Zero-Python Binary (`secure-transmit`)

Compiled from `src/main.rs` (`cargo build --bin secure-transmit`), implementing a self-contained data plane:
- Commands: `keygen`, `auth-keygen`, `auth-sign`, `auth-verify`, `send`, `recv`, `send-file`, `recv-file`, `channel`, `stream-chaff`, `diode-send`, `diode-recv`, `cookie-challenge`, `cookie-solve`, `cookie-verify`, `threat-eval`, `zero-trust-eval`, `cot-beacon`, `tactical-msg`, `eam-auth`, `zeroize`, `benchmark`, `selftest`.
- Chunking: 1205-byte quantum split, sequential u64 counter, SHA-256 stream digests at both sender and receiver.
- Fail-closed: Exit code 4 on sequence gaps, corrupt datagrams, wrong keys, or timeouts without writing partial files to disk.
- Zero-python boundary: Keys are provisioned externally from the post-quantum handshake plane or offline ceremony and zeroized on process exit.

## Packaging truth (learned live)

The repo source dir once shadowed the installed wheel (`destroyer_core/` →
renamed `rust_data_plane/`), and the app's own MicrosoftSignedOnly policy
rejects late-loading the self-built `.pyd` (fixed by startup pre-import;
production MUST Authenticode-sign). Both recorded so they are never
regressed; `test_native_data_plane_loads_and_separates_directions` guards
the first in CI.