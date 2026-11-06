# Audit Findings Register

**Audit Run ID:** `RUN-20261104-01`  
**Date:** 2026-11-04  
**Audit Protocol:** Production Engineering and Forensic Verification v5.0  
**Branch:** `audit/2026-11-04`  

---

## 1. Summary of Findings

| Finding ID | Severity | Category | Affected File(s) | Wire / Crypto Impact | Status |
|---|---|---|---|---|---|
| `FINDING-20261104-01` | Low | Incorrect Error Handling / Compiler Diagnostics | `rust_data_plane/src/ffi.rs`, `fragment.rs`, `pipeline.rs` | No (Pure implementation) | Resolved (CHG-17) |
| `FINDING-20261104-02` | Medium | Logic / Spec Mismatch (Hash-Manifest Drift) | `critical_modules.hashes`, `rust_data_plane/src/main.rs` | No | Open (Reported) |
| `FINDING-20261104-03` | Informational | Working Tree State (Pre-Existing Modifications) | 37 tracked files, 17 untracked files | No | Open (Preserved) |

---

## 2. Detailed Findings

### FINDING-20261104-01: Clippy Compiler Warnings under Rust 1.99.1 in `rust_data_plane`
- **Classification:** Low
- **Category:** Compiler Diagnostics / Code Hygiene
- **Affected Files & Lines:**
  - `rust_data_plane/src/ffi.rs:1310`: `clippy::type-complexity` on `parse(xml: &str)` tuple return type.
  - `rust_data_plane/src/fragment.rs:123`: `clippy::manual-div-ceil` on chunk count calculation.
  - `rust_data_plane/src/fragment.rs:259`: `clippy::manual-is-multiple-of` on hex string length parity.
  - `rust_data_plane/src/pipeline.rs:61`: `clippy::manual-div-ceil` on quantum padding calculation.
  - `rust_data_plane/src/pipeline.rs:224`: `clippy::collapsible-if` on nested NC3 safety check.
  - `rust_data_plane/src/pipeline.rs:275`: `clippy::manual-is-multiple-of` on CER epoch interval check.
- **Reproduction Steps:**
  ```powershell
  cargo clippy --manifest-path rust_data_plane/Cargo.toml --all-targets -- -D warnings
  ```
  Exits with status `1` and emits 6 compiler errors.
- **Root Cause:**
  Rust 1.99.1 introduced stricter clippy lints that flag manual integer division ceiling formulas `(x + k - 1) / k` and modulo-zero checks `x % 2 != 0`.
- **Wire / Crypto Logic Change:**
  **NO.** Resolving these lints produces identical machine code and identical wire layouts.
- **Proposed Fix:**
  Introduce type alias in `ffi.rs`, use `.div_ceil()` and `.is_multiple_of()` or `#[allow(...)]`, and collapse nested `if` statement.

---

### FINDING-20261104-02: Hash Manifest Drift in `critical_modules.hashes`
- **Classification:** Medium
- **Category:** Supply Chain Integrity / Hash Manifest Drift
- **Affected Files & Lines:**
  - `critical_modules.hashes:4`
  - `rust_data_plane/src/main.rs`
- **Reproduction Steps:**
  ```powershell
  python scripts/verify_reproducible_build.py
  ```
  Exits with status `1`, reporting:
  `[-] rust_data_plane/src/main.rs: DRIFT (sha3_512=350fe41084ae1968...)`
- **Root Cause:**
  `rust_data_plane/src/main.rs` contains uncommitted modifications from a prior development session, causing its SHA3-512 hash to diverge from the pinned hash in `critical_modules.hashes`.
- **Wire / Crypto Logic Change:**
  **NO.**
- **Policy Enforcement:**
  Under the audit constraints:
  - Files that are signed or hashed (`*.sig`, `*.hashes`, `*.pub`) must not be edited silently.
  - If a change invalidates a signature or hash, record it in `docs/audit/open_questions.md`.
  - Never generate or use a real signing key to re-sign without authorization.

---

### FINDING-20261104-03: Pre-Existing Uncommitted Working Tree Modifications
- **Classification:** Informational
- **Category:** Workspace State
- **Status:** Resolved / Reconciled on `main`

---

## 3. Forensic Technical Audit Remediation Register (Baseline 8e2f5fd -> Verified e2cfae7, 6 November 2026)

| Finding ID | Severity | Description | Remediated In | Verification Status |
|---|---|---|---|---|
| **P0-01** | Block | Missing `Union` typing import in `tactical_web_console.py` causing pytest collection failure | `tactical_web_console.py:27` | **RESOLVED & VERIFIED** (26/26 tests passing) |
| **P0-02** | Block | `default = ["lab-surfaces"]` compiling diagnostic commands into release builds | `rust_data_plane/Cargo.toml:18` | **RESOLVED & VERIFIED** (`default = []`, production binary clean) |
| **P0-03** | Block | TPM anti-rollback failing to persist live receive high-water mark | `rust_data_plane/src/tpm_nv.rs`, `main.rs` | **RESOLVED & VERIFIED** (dual-monotonic `(send_seq, recv_hwm)` verified) |
| **P0-04** | Block | Symlink vulnerability & non-atomic truncate write in key custody | `rust_data_plane/src/keystore.rs` | **RESOLVED & VERIFIED** (atomic tempfile rename, 0600 DACL verified) |
| **P1-01** | High | Silent character stripping in identifier normalization | `pki.rs`, `attest.rs`, `trust_anchor.py` | **RESOLVED & VERIFIED** (strict validation `[a-zA-Z0-9_.:-]` enforced) |
| **P1-02** | High | Manual string scanning in security-critical PKI custodian JSON parser | `rust_data_plane/src/pki.rs` | **RESOLVED & VERIFIED** (`serde_json` + `deny_unknown_fields` enforced) |
| **P1-03** | High | Zero-Trust ingress evaluation inactive in primary receive path | `rust_data_plane/src/main.rs` | **RESOLVED & VERIFIED** (`ZeroTrustEngine` active in `cmd_channel`) |
| **P1-04** | High | Untrusted attestation evidence merged with verifier challenge state | `rust_data_plane/src/attest.rs` | **RESOLVED & VERIFIED** (`UntrustedEvidence` / `VerifierChallenge` separated) |
| **P1-05** | High | CAC/PIV certificate validation path without mandatory Defense Root CA | `tactical_web_console.py` | **RESOLVED & VERIFIED** (fail-closed Root CA path validation) |
| **P1-06** | High | WebAuthn origin bypass, counter update before sig verify, overwrite | `tactical_web_console.py` | **RESOLVED & VERIFIED** (strict origin check, atomic counter update) |
| **P1-07** | High | Stale `.sig` files and non-fail-closed receipt generation in CI | `scripts/verify_reproducible_build.py` | **RESOLVED & VERIFIED** (stale `.sig` unlinked, fail-closed on prod) |
| **P1-08** | High | Unverified receipt signature in reproducible build script | `scripts/verify_reproducible_build.py` | **RESOLVED & VERIFIED** (cryptographic verification against anchor) |
| **P2-01** | Medium | Unsafe RNG fallback in Poisson interval generator | `rust_data_plane/src/pacing.rs` | **RESOLVED & VERIFIED** (53-bit precision, fail-safe clamped fallback) |
| **P2-02** | Medium | Catch-up bursts in Poisson scheduler on delayed tick | `rust_data_plane/src/pacing.rs` | **RESOLVED & VERIFIED** (`next_tick` resynced on late tick) |
| **P2-05** | Medium | UDP source address unbound in `recv_packet`; `recv_unthrottled` exposed | `rust_data_plane/src/net.rs` | **RESOLVED & VERIFIED** (`from_addr == peer_addr`, unthrottled gated) |
| **P3-07** | Low | Outdated NIST SP 800-88 Rev 1 citations | `docs/audit/KNOWN_LIMITATIONS.md` | **RESOLVED & VERIFIED** (updated to SP 800-88 Rev 2, Sept 2025) |
| **P3-08** | Low | Unclear quarantine status of candidate algorithms (HQC-256) | `docs/audit/KNOWN_LIMITATIONS.md` | **RESOLVED & VERIFIED** (quarantine clarified; FIPS 203 mandated) |


