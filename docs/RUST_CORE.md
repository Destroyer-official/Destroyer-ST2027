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
| ML-DSA-87 auth | `liboqs_wrapper.py` (`oqs.dll`, ctypes) | `auth.rs` — pure-Rust `ml-dsa` 0.1.1 (FIPS 204; floor covers CVE-2026-22705 + hint-dup, see `policy.rs`) |
| Hybrid KEX | `noise_pq.py` XXhfs, `hybrid_kex.py`, `triple_hybrid_kem.py` | `kex_auth.rs` over existing `kem.rs` — X25519+ML-KEM-1024, SHA-384 transcript of BOTH bundles, HKDF-SHA384 PSK-or-MLDSA binding, SAS OOB |
| Full handshake | `noise_pq.py` (P-384 + ML-KEM + ML-DSA, M1/M2/M3) | `handshake.rs` — byte-identical profile (CNSA L5 `SecP384r1MLKEM1024` leg), mandatory pinning, quarantine latch; UNPROVEN sig-substitution stated as in the reference |
| Transport | `noise_pq.transport_send/recv` (seqBE dir NPQ1) | `session.rs` — wire-identical framing + `EstablishedSession` pipeline (frame key, ratchet root). Residual documented in-code: seq prefix + length observable here by design (interop); bulk transit belongs on whitened data-plane frames (`aead.rs`) |
| Data-plane framing | `transport_anonymity.py` (header inside AES-GCM) | existing `aead.rs` — quanta padding + tag-derived header masking (`SHA256("ST2027-HEADER-MASK-v1"‖hp_key‖tag)[..11]`, tag authenticates unmasked AAD); `peek_seq` key-gated; `FrameKey` fields private |
| PCS ratchet | `double_ratchet.py` v1/v2 negotiation, `secure_transmit_2027.py::rehandshake` | `ratchet.rs` — fresh-KEM-per-step only (no v1 reuse path exists), strict abort is the only behavior |
| Attestation | `ts_attest.py` (`trusted_keys` bound, lab TOFU path) | `attest.rs` — enrollment-bound only (RATS RFC 9334), no TOFU path exists |
| Threshold PKI | `trust_anchor.py` (3-of-5 ML-DSA quorum) | `pki.rs` — byte-identical TBS/revocation encodings; revocation requires the full 5-ceremony set (intentionally stricter, documented) |
| Key custody | `main.rs` key-file/stdin, `trust_anchor.py` ephemeral doctrine | `keystore.rs` — exclusive create, Unix 0600 enforced, Windows share-NONE, hex→`LockedKey32` |
| FFI | `liboqs_wrapper.py` ctypes | `ffi.rs` — thin control-plane bindings (`CoreHs*`, `CoreTransport`, `CoreRatchet`, `CoreAttestStore`, TBS/derive helpers) |
| Optional backend | (canonical modules above) | `rust_backend.py` — NEW additive shim ONLY: probes for the compiled extension, else `BackendUnavailable`; zero edits to existing modules |
| Framing/AEAD/replay | `transport_anonymity.py`, `secure_message_serializer.py` | existing `aead.rs`/`frame.rs`/`replay.rs`/`net.rs` (quanta-padded, check→verify→mark) |

## Research grounding (fetched Oct 2026)

* NIST FIPS 203/204/205 final (Aug 2024) — deploy ML-KEM + ML-DSA now;
  FN-DSA/FIPS 206 (Falcon) draft, final ~late 2026/early 2027; HQC
  selected Mar 2025, draft ~2026, final ~2027. DECISION: Falcon/HQC stay
  OUT of the Rust core (draft/unstandardized) and remain quarantined
  agility reserves on the Python side only.
* RFC 10024 hybrids; OpenSSL 3.5 hybrid-by-default (`X25519MLKEM768`,
  `SecP384r1MLKEM1024`); IETF draft-ietf-hpke-pq / MLS PQ ciphersuites
  (Mar 2026): MLKEM1024-P384 is the NIST 192-bit hybrid — the handshake's
  KEM leg. CFRG draft-irtf-cfrg-hybrid-kems: hybrid safe while EITHER
  half holds; key pairs MUST never cross hybrid/non-hybrid uses (fresh
  ephemerals per session); LEAK-BIND-K-PK/CT via transcript hashing.
* PQXDH analyses (Fiedler/Günther PKC 2025; Bhargavan USENIX 2024):
  KEM binding + transcript coverage required — implemented in `kex_auth.rs`
  and `handshake.rs`.
* Noise PQ: PQNoise (Angel et al. CCS 2022, ePrint 2022/539) DH→KEM recipe;
  NoisePQC++ (2026) NIST-compliant hybrid Noise; PQ WireGuard revisit
  (Hashimoto et al. 2025/1758) binding fixes per Cremers CCS'24.
* Signal SPQR / Triple Ratchet (Dodis et al. 2025/078, Oct 2025): fresh-KEM
  PCS braid — implemented per-step in `ratchet.rs` (stronger than PQ3 ~50-msg
  cadence).
* RATS RFC 9334 + Endorsements draft 2026-03: verifier trust from an
  independent anchor store — implemented in `attest.rs`/`ts_attest.py`.
* RustCrypto `ml-kem` 0.3.2 / `ml-dsa` 0.1.1 / `p384` 0.14.0 (pure Rust,
  explicitly unaudited — honored via pinned KAT sizes + liboqs/OpenSSL
  cross-checks in `tests/test_rust_interop.py`); `zeroize` (volatile
  intrinsics, heap-box discipline), `subtle` (constant-time `Choice`),
  `secrecy` pattern (no realloc of secrets).
* NVD/RustSec-verified crate floors: CVE-2026-22705 (ml-dsa Decompose
  timing, fixed ≥0.1.0-rc.3, CVSS 6.4) + hint-duplicate regression (fixed
  ≥0.1.0-rc.4) — locked `ml-dsa 0.1.1` covers both; re-check before every
  release cut (`cargo audit` findings are release blockers).

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
cargo check --manifest-path rust_data_plane/Cargo.toml          # clean, zero warnings
cargo test  --manifest-path rust_data_plane/Cargo.toml          # 75+30 pass (lib incl. handshake/session/pki + kani doubles)
python -m pytest tests/test_ts_attest.py -q                    # 8 passed (incl. enrollment-substitution refusal)
PYTHONPATH=<fresh wheel> python -m pytest tests/test_rust_interop.py -q  # 5 passed live interop
git status --short -- '*.py'                                   # only ADDITIVE files (rust_backend.py, tests/test_rust_interop.py)
```

Strongest evidence — `tests/test_rust_interop.py` (live, real randomness
both sides, Python `noise_pq`/`trust_anchor` ↔ Rust core): M1/M2/M3 lengths
exact both directions; split keys agree crossed; transcripts agree
bit-for-bit; frame keys + ratchet roots agree; transport wires decrypt
cross-implementation both directions (tamper still refused, window
unshifted); ML-DSA verifies BOTH ways (liboqs ↔ ml-dsa crate);
threshold TBS/revocation encodings byte-identical with Rust-signed quorum
verifying under Python `trust_anchor.verify_certificate`/`verify_revocation`.

FFI smoke (`ffi_smoke_test.py`, temp dir, not committed): `maturin build`
wheel loaded directly — ML-DSA sign/verify, KEX PSK agree, KEX ML-DSA legs
agree, forged transcript-sig refused, PCS ratchet step heals epoch 0→1,
enrolled attestation passes, substituted-key + unknown-kid refused, posture
policy ok. ALL PASS.

## Migration status

1. DONE — `main.rs` key I/O single-sourced onto `keystore.rs`:
   `load_key_material` file branch → `read_key_file` (plus a real
   `symlink_metadata` refusal replacing the dead `metadata().is_symlink()`
   check), `write_key_file` → `write_key_file_truncate`, `--psk-file`
   loads → hardened read (0600/no-symlink enforced where previously
   unchecked) with post-KEX stack wipe. Wire formats and KEX KDF vectors
   (v1, Python-plane compatible) deliberately untouched.
2. DONE — `kex_auth`/`ratchet`/`attest`/`auth` exposed via thin `ffi.rs`
   PyO3 wrappers (`CoreMldsaSigner`, `CoreKexResponder`, `CoreKexInitiator`,
   `CoreRatchet`, `CoreAttestStore`); Python stays orchestration-only,
   secrets held in Rust holders, verified by the FFI smoke above.
3. DONE — full handshake (`handshake.rs`, P-384 via `p384` 0.14 + ML-KEM +
   ML-DSA, byte-identical to `noise_pq.py`), transport pipeline
   (`session.rs`), threshold PKI (`pki.rs`), FFI (`CoreHs*`,
   `CoreTransport`, TBS/derive helpers), additive `rust_backend.py` shim,
   and live cross-implementation proof (`tests/test_rust_interop.py`,
   5 passed — no stub vectors, real randomness both sides).
4. OPEN — rebuild liboqs at official 0.16.0 + Sigstore/Rekor anchoring for
   the Python backup path; independent cryptographic audit before any
   production-secret claim.
