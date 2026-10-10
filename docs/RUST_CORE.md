# Rust Secure Core — Production Path (Python Kept as Reference/Backup)

**Status:** active production target. **Python tree untouched** — `noise_pq.py`,
`double_ratchet.py`, `secure_transmit_2027.py`, `trust_anchor.py`, `ts_attest.py`
and all other `.py` files keep their logic byte-for-byte as the audited
reference and lab/backup path. No Python security logic was rewritten for this
change; only additive Rust code plus this doc were introduced.

## Why Rust-first

Per the audits: CPython immutable `bytes`/GC scatter secret copies across the
heap uncontrollably, pure-Python crypto cannot promise constant-time, and
`mlock`/zeroize in Python is best-effort container sanitization. The Rust core
gives: `ZeroizeOnDrop`/`Zeroizing` secrets (volatile + fences, never optimized
away), heap-boxed page-locked keys (`LockedKey32`: `VirtualLock`/`mlock`),
constant-time compares (`ct.rs`, `subtle`), `getrandom` OS randomness, no
interpreter copies, `panic="abort"` + LTO release profile.

## Module mapping (reference → production)

| Concern | Python reference/backup (kept) | Rust production core (new) |
|---|---|---|
| Fail-closed policy | `cnsa_purity.py`, `nist_level5_policy_engine.py`, env gates | `policy.rs` — always strict, no env opt-outs exist |
| ML-DSA-87 auth | `liboqs_wrapper.py` (`oqs.dll`, ctypes) | `auth.rs` — pure-Rust `ml-dsa` 0.1 (FIPS 204), role-separated domains, verify-before-derive |
| Hybrid KEX | `noise_pq.py` XXhfs, `hybrid_kex.py`, `triple_hybrid_kem.py` | `kex_auth.rs` over existing `kem.rs` — X25519+ML-KEM-1024, SHA-384 transcript of BOTH bundles, HKDF-SHA384 PSK-or-MLDSA binding, SAS OOB |
| PCS ratchet | `double_ratchet.py` v1/v2 negotiation, `secure_transmit_2027.py::rehandshake` | `ratchet.rs` — fresh-KEM-per-step only (no v1 reuse path exists), strict abort is the only behavior |
| Attestation | `ts_attest.py` (`trusted_keys` bound, lab TOFU path) | `attest.rs` — enrollment-bound only (RATS RFC 9334), no TOFU path exists |
| Key custody | `main.rs` key-file/stdin, `trust_anchor.py` ephemeral doctrine | `keystore.rs` — exclusive create, Unix 0600 enforced, Windows share-NONE, hex→`LockedKey32` |
| Framing/AEAD/replay | `transport_anonymity.py`, `secure_message_serializer.py` | existing `aead.rs`/`frame.rs`/`replay.rs`/`net.rs` (quanta-padded, check→verify→mark) |

## Research grounding (fetched Oct 2026)

* NIST FIPS 203 (ML-KEM) / 204 (ML-DSA) finals; CNSA 2.0 suite.
* RFC 10024 hybrid KEMs; OpenSSL 3.5 hybrid-by-default (`X25519MLKEM768`,
  `SecP384r1MLKEM1024`); `SecP384r1MLKEM1024` is the CNSA L5 leg, X25519 an
  interop leg never trusted alone.
* PQXDH analyses (Fiedler/Günther PKC 2025; Bhargavan et al. USENIX 2024):
  KEM binding + transcript coverage required — implemented in `kex_auth.rs`.
* Signal SPQR / Triple Ratchet (Dodis et al. 2025/078, Oct 2025): fresh-KEM
  PCS braid — implemented per-step in `ratchet.rs` (stronger than PQ3 ~50-msg
  cadence).
* RATS RFC 9334 + Endorsements draft 2026-03: verifier trust from an
  independent anchor store — implemented in `attest.rs`/`ts_attest.py`.
* RustCrypto `ml-kem` 0.3.2 / `ml-dsa` 0.1.1 (pure Rust, explicitly
  unaudited — honored via pinned KAT sizes + liboqs cross-checks);
  `zeroize` (volatile intrinsics, heap-box discipline), `subtle`
  (constant-time `Choice`), `secrecy` pattern (no realloc of secrets).

## Honesty boundaries (unchanged)

* Upstream Rust PQ crates are unaudited (their own warning) — no audit claim.
* No FIPS 140-3 CMVP cert, no ATO, no executed Kani proofs (harnesses
  defined; doubles green under `cargo test`), ProVerif models are
  model-scoped (skeleton unproven).
* `oqs.dll` floor stays 0.16.0 for the Python path; the Rust core never
  loads it (no ctypes PQ in production).
* Vendored-binary trust remains self-anchored until a Sigstore/Rekor +
  rebuild-at-0.16.0 ceremony lands; tracked in `docs/liboqs_pin.md`.
* For real secrets today the repo still recommends Signal (audited).

## Verification

```
cargo check --manifest-path rust_data_plane/Cargo.toml
cargo test  --manifest-path rust_data_plane/Cargo.toml --lib   # 65 passed (51 data-plane + 14 secure-core)
python -m pytest tests/test_ts_attest.py -q                    # 8 passed (incl. enrollment-substitution refusal)
git status --short -- '*.py'                                   # clean (none modified this wave)
```

## Next migration steps (not done here — deliberate)

1. `main.rs` kex `write_key_file` → call `keystore::write_key_file_exclusive`
   (identical behavior, single-sourced).
2. Expose `kex_auth`/`ratchet`/`attest` via PyO3 thin wrappers for the
   orchestrator, keeping Python as control-plane only (keys never cross
   into `bytes` longer than one copy-out).
3. Rebuild liboqs at official 0.16.0 + Sigstore/Rekor anchoring for the
   Python backup path; independent cryptographic audit before any
   production-secret claim.
