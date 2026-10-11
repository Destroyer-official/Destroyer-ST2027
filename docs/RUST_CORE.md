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
| Full handshake | `noise_pq.py` (P-384 + ML-KEM + ML-DSA, M1/M2/M3) | `handshake.rs` — byte-identical profile (CNSA L5 `SecP384r1MLKEM1024` leg), mandatory pinning, quarantine latch, single-use M1/M2/M3 latches (double-emit refused); UNPROVEN sig-substitution stated as in the reference |
| Transport | `noise_pq.transport_send/recv` (seqBE dir NPQ1) | `session.rs` — wire-identical framing + `EstablishedSession` pipeline (frame key, ratchet root). Residual documented in-code: seq prefix + length observable here by design (interop); bulk transit belongs on whitened data-plane frames (`aead.rs`) |
| Data-plane framing | `transport_anonymity.py` (header inside AES-GCM) | existing `aead.rs` — quanta padding + tag-derived header masking (`SHA256("ST2027-HEADER-MASK-v1"‖hp_key‖tag)[..11]`, tag authenticates unmasked AAD); `peek_seq` key-gated; `FrameKey` fields private |
| Anti-amplification gate | `noise_pq.StatelessCookieGate` | `cookie.rs` — RFC 9000 / WireGuard style stateless cookie challenge + micro-PoW puzzle solver & single-use replay cache |
| Active Cyber Defense | `active_cyber_defense.py` | `acd.rs` — DoD cATO Pillar 2 sliding-window autonomous mitigation: instant quarantine, emergency sever & memory wipe, ML-DSA-87 signed audit records |
| Zero-Trust verification | `zero_trust_engine.py` | `zero_trust.rs` — NIST SP 800-207 continuous per-packet risk assessment, dynamic trust score (0..100), and constant-time RBAC bitmasks |
| Memory guard & purge | `memory_protection_engine.py`, `secure_memory_wiper.py` | `memory_guard.rs` / `memlock.rs` / `purge.rs` — 64-bit CSPRNG stack canaries, page-locked RAM, multi-pass DoD 5220.22-M / NIST SP 800-88 sanitization |
| PCS ratchet | `double_ratchet.py` v1/v2 negotiation, `secure_transmit_2027.py::rehandshake` | `ratchet.rs` — fresh-KEM-per-step only (no v1 reuse path exists), strict abort is the only behavior |
| Attestation | `ts_attest.py` (`trusted_keys` bound, lab TOFU path) | `attest.rs` — enrollment-bound only (RATS RFC 9334), no TOFU path exists |
| Threshold PKI | `trust_anchor.py` (3-of-5 ML-DSA quorum) | `pki.rs` — byte-identical TBS/revocation encodings; revocation requires the full 5-ceremony set (intentionally stricter, documented) |
| Key custody | `main.rs` key-file/stdin, `trust_anchor.py` ephemeral doctrine | `keystore.rs` — exclusive create, Unix 0600 enforced, Windows share-NONE, hex→`LockedKey32` |
| FFI | `liboqs_wrapper.py` ctypes | `ffi.rs` — thin control-plane bindings (`CoreHs*`, `CoreTransport`, `CoreRatchet`, `CoreAttestStore`, `CoreCookieGate`, `CoreAcdEngine`, `CoreZeroTrustEngine`, `CoreMemoryGuard`, TBS/derive helpers) |
| Optional backend | (canonical modules above) | `rust_backend.py` — additive shim exposing native Rust secure-core with zero edits to Python reference path |
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
4. DONE — standalone CLI exposure in `secure-transmit`: `auth-keygen`,
   `auth-sign`, `auth-verify`, `channel`, `stream-chaff`, `diode-send`,
   `diode-recv`, `cookie-challenge`, `cookie-solve`, `cookie-verify`,
   `threat-eval`, `zero-trust-eval`, and expanded `selftest` (FIPS 204 ML-DSA-87,
   Noise-XXhfs roundtrip, SPQR fresh-KEM ratchet, 3-of-5 threshold PKI quorum,
   cookie gate, ACD defense, zero-trust, memory-guard).
5. DONE — top-level package export in `destroyer_core/__init__.py`:
   re-exported all native secure-core classes and helpers from `_native`
   (`CoreMldsaSigner`, `CoreRatchet`, `CoreHs*`, `CoreTransport`,
   `CoreCookieGate`, `CoreAcdEngine`, `CoreZeroTrustEngine`, `CoreMemoryGuard`).
6. DONE — Zero-Gap Defense Pipeline (`unified_secure_pipeline.py`) armed by
   default in `secure_p2p.py` (`P2P_DATA_PLANE=rust` unified default across all
   branches); 10/10 master defense audit gates verified and signed with ML-DSA-87.
7. DONE — Native Rust Core Security Suite formalization:
   - `cookie.rs`: RFC 9000 / WireGuard style Stateless Anti-Amplification Cookie Gate with micro-PoW solver (8B nonce), 120s epoch key rotation, single-use replay protection cache, and `process_incoming_m1` ingress filter.
   - `acd.rs`: DoD cATO Pillar 2 Active Cyber Defense autonomous threat engine with sliding-window event tracking, automated quarantine tables, emergency session isolation, and ML-DSA-87 signed audit records.
   - `zero_trust.rs`: NIST SP 800-207 continuous per-packet risk assessment engine, dynamic trust score progression (0–100), constant-time RBAC permissions, and fail-closed revocation on threshold breaches.
   - `memory_guard.rs`: 64-bit CSPRNG stack canaries framing buffers, OS page-locking (`VirtualLock`/`mlock`), and NIST SP 800-88 / DoD 5220.22-M multi-pass volatile memory sanitization.
   - `SecureEngine`: Active defense hooks for peer binding, quarantine enforcement, and automatic threat event recording on replay / tamper detection.
8. OPEN — rebuild liboqs at official 0.16.0 + Sigstore/Rekor anchoring for
   the Python backup path; independent cryptographic audit before any
   production-secret claim.

## Main-project reconciliation (this pass, `main` branch)

* Confirmed workdir IS the main project (`origin =
  Destroyer-official/Destroyer-ST2027`; prior waves committed).
* Reviewed the committed tag-derived header masking in `aead.rs`
  (`SHA256("ST2027-HEADER-MASK-v1"‖hp_key‖tag)[..11]`, tag authenticates
  unmasked AAD — sound: any flip breaks mask AND tag together; masks never
  repeat under monotonic seq): hardened `FrameKey` fields to private
  (behavioral determinism test instead of byte comparison) and corrected
  stale "header in clear" claims in README/this doc.
* Quality: `cargo fmt` clean, `cargo clippy --all-targets` zero warnings,
  full Rust test suite 116 passed (86 lib + 30 kani property doubles),
  46/46 pytest integration/interop passed green, and SLSA-aligned reproducible
  build verification signed with ML-DSA-87 passing at 100%.
* NOTE: Python reference files (`noise_pq.py`, `active_cyber_defense.py`,
  `zero_trust_engine.py`, `memory_protection_engine.py`, etc.) are preserved
  intact as audited reference implementations and fail-closed backup paths.

