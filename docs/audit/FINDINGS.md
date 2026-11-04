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
- **Affected Files:**
  - 37 tracked files modified (`secure_p2p.py`, `cnsa2_policy_engine.py`, `rust_data_plane/src/*.rs`, etc.)
  - 17 untracked files (`test_real_uses_dual_terminal_ipv6.py`, `tests/test_military_five_pillars_operational.py`, etc.)
- **Root Cause:**
  Uncommitted development work from previous sessions.
- **Protocol Action:**
  Preserved untouched per the audit rules. Excluded from audit branch commits unless user explicitly authorizes committing them.

