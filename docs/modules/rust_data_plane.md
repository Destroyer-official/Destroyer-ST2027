# `rust_data_plane/` — native data plane (all code read + tested)

## Layout

`Cargo.toml` (deps resolved live, frozen in `Cargo.lock`), `pyproject.toml`
(maturin backend), `python/destroyer_core/__init__.py` (re-export),
`src/lib.rs` (`SecureEngine`: session API — `establish_session(key, seq,
is_initiator)`, `seal_msg`, `open_msg`, `check_seq`, `drop_count`).

## Modules (340 `cargo test --locked --no-default-features` tests: 276 unit + 12 DudeCT + 49 Kani/property harness tests + 2 MTU + 1 doc-test; plus 5 tests in sibling crate `tor_transport`)

- `frame.rs` — `[seq:u64‖len:u16‖type:u8‖ct‖tag:16B]`, quanta 256/512/1232 (`MAX_PAYLOAD = 1205`) plus Tor-aligned `496B`/`994B` (`FTYPE_MSG = 0x01`, `FTYPE_REKEY = 0x02`, `FTYPE_DOC = 0x08`, `FTYPE_CHAFF = 0xFF`).
- `replay.rs` — u64 seq + 1024-bit bitmap (`[u64; 32]`, RFC 6479 decoupled `check`/`mark`).
- `aead.rs` — AES-256-GCM (CNSA 2.0 suite), header-AAD, `seq‖dir` nonces (`DIR_SEND=0x00`/`DIR_RECV=0x01`), HKDF-SHA384 header protection key, `ZeroizeOnDrop` keys; tag-derived header whitening `ST2027-HEADER-MASK-v2`.
- `stream_transport.rs` & `shaper.rs` — Cancel-safe split-reader 2-byte big-endian length framing, in-stream `Noise_XXhfs` (`M1 -> M2 -> M3`) in page-locked RAM without temporary `.key` files, and pure-Rust `TamarawShaper` (`496B`/`994B` Tor relay cell alignment + batch-tail `L`).
- `os_hardening.rs` — OS crash-dump suppression (`WerSetFlags`/`SetErrorMode` on Windows, `PR_SET_DUMPABLE=0`/`RLIMIT_CORE=0` on Linux) and process mitigation flags (`ProcessDynamicCodePolicy` / `ProcessExtensionPointDisablePolicy`).
- `doc_transfer.rs` — SHA-384 verified `DOC:<filename>:<sha384>:<base64>` framing with path-traversal/symlink refusal (`--doc`, `--recv-dir`, `/doc <path>` in `cmd_stream_node`).
- `tor_transport/` (`secure-transmit-tor`) — Privilege-separated sibling binary embedding `arti-client 0.48.0` (`ArtiEphemeralKeystore`, `ClientAuthV3` Restricted Discovery, `vanguards = Full`, `native-tls`, `static-sqlite`) connected over anonymous stdin/stdout pipes with mandatory `--tor-bridge-sha384` verification in production.
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