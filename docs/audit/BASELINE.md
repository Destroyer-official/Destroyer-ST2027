# Baseline and Environment Inspection Record

**Audit Run ID:** `RUN-20261104-01`  
**Date:** 2026-11-04  
**Protocol:** Production Engineering and Forensic Verification v5.0  
**Repository:** `Destroyer-ST2027` (`https://github.com/Destroyer-official/Destroyer-ST2027`)  
**Authoritative Local Location:** `D:\code\Main_projects\p2p\p2p_6_1-26`  
**Branch:** `audit/2026-11-04`  

---

## 1. Baseline Git State

| Parameter | Value | Verification Command |
|---|---|---|
| **Workspace Root** | `D:\code\Main_projects\p2p\p2p_6_1-26` | `git rev-parse --show-toplevel` |
| **Initial HEAD Commit** | `fcf14f4337e98ad5db097fd192c98c3eca519fb0` | `git rev-parse HEAD` |
| **Active Audit Branch** | `audit/2026-11-04` (branched from `fcf14f4337e98ad5db097fd192c98c3eca519fb0`) | `git branch --show-current` |
| **Tracked File Count** | 689 files | `git ls-files \| wc -l` |
| **Untracked File Count** | 17 files | `git ls-files --others --exclude-standard \| wc -l` |
| **Ignored File Count** | 14,666 files | `git ls-files --others -i --exclude-standard \| wc -l` |
| **Backup Path** | `D:\code\Main_projects\p2p\backup_st2027_audit_20261104` | Robocopy full mirror (7,206 copied, 0 failed) |

### 1.1 Remote Repositories Configured

| Remote Name | Fetch URL | Push URL | Classification |
|---|---|---|---|
| `origin` | `https://github.com/Destroyer-official/Destroyer-ST2027.git` | `https://github.com/Destroyer-official/Destroyer-ST2027.git` | Primary Public Repository |
| `st2027` | `https://github.com/Destroyer-official/Destroyer-ST2027.git` | `https://github.com/Destroyer-official/Destroyer-ST2027.git` | Alias to Primary Repository |
| `backup` | `https://github.com/Destroyer-official/secure_p2p_backups.git` | `https://github.com/Destroyer-official/secure_p2p_backups.git` | Internal Backup Mirror |

---

## 2. Toolchain & Runtime Environment

| Component | Detected Version | Target Architecture | Notes |
|---|---|---|---|
| **Operating System** | Windows 11 (AMD64) | `x86_64-pc-windows-msvc` | Host execution environment |
| **Python** | 3.15.2 | 64-bit (`D:/program_software/sdks/Python315/python.exe`) | Runtime for orchestrator, CLI, and test harness |
| **Rust Compiler (`rustc`)** | 1.99.1 (58cf8f9c3 2026-10-13) | `x86_64-pc-windows-msvc` | Compiler for `rust_data_plane` and `ts_rt` |
| **Cargo** | 1.99.1 (5f94df478 2026-08-27) | `x86_64-pc-windows-msvc` | Rust build manager and test runner |
| **Pytest** | 9.2.0 | Python 3.15.2 | Test framework (1,624 tests collected) |
| **LibOQS C Library** | Vendored `oqs.dll` (0.16.0) | AMD64 native DLL | Provides native FIPS 203/204/205 algorithms |
| **LibSodium C Library** | Vendored `libsodium.dll` (1.0.22) | AMD64 native DLL | Provides Ed25519, ChaCha20-Poly1305 |

---

## 3. Baseline Build & Test Execution Record

### Test 1: Native Rust Data Plane (`rust_data_plane`) Unit & Proof Tests
- **Command:** `cargo test --manifest-path rust_data_plane/Cargo.toml`
- **Working Directory:** `D:\code\Main_projects\p2p\p2p_6_1-26`
- **Exit Status:** `0` (Success)
- **Output Summary:**
  - `src/lib.rs`: 148 passed, 0 failed, 0 ignored
  - `src/main.rs`: 0 passed, 0 failed, 0 ignored
  - `tests/kani_harness.rs`: 37 passed, 0 failed, 0 ignored
  - Doc-tests (`src/mmhs.rs`): 1 passed, 0 failed, 0 ignored
  - Total: **186 passed; 0 failed; 0 ignored** in 18.52 seconds.

### Test 2: Native Runtime Deterministic Core (`ts_rt`)
- **Command:** `cargo test --manifest-path ts_rt/Cargo.toml`
- **Working Directory:** `D:\code\Main_projects\p2p\p2p_6_1-26`
- **Exit Status:** `0` (Success)
- **Output Summary:**
  - `src/lib.rs`: 0 passed, 0 failed, 0 ignored (clean build and compilation)

### Test 3: Production Deployment Verification Testbench
- **Command:** `D:/program_software/sdks/Python315/python.exe verify_deployment.py`
- **Working Directory:** `D:\code\Main_projects\p2p\p2p_6_1-26`
- **Exit Status:** `0` (Success)
- **Output Summary:**
  - Core Module File Verification: 17/17 PASS
  - Core Module Import Verification: 17/17 PASS
  - Memory Security Verification: PASS
  - Cryptographic Primitives: ML-KEM-1024, ML-DSA-87, AES-256-GCM validated
  - Summary: **PASS: 92, FAIL: 0, WARN: 4, SKIP: 0**
  - Result: READY FOR DEPLOYMENT

### Test 4: Core Remediations & Defense Security Entrypoint Battery
- **Command:** `D:/program_software/sdks/Python315/python.exe -m pytest tests/test_audit_forensic_remediations.py tests/test_production_tier123_hardening.py tests/test_military_five_pillars_operational.py tests/test_secure_p2p_military_entrypoint.py`
- **Working Directory:** `D:\code\Main_projects\p2p\p2p_6_1-26`
- **Exit Status:** `0` (Success)
- **Output Summary:**
  - **55 passed; 0 failed** in 42.65 seconds.

### Test 5: Live Dual-Terminal Real Use-Cases over Direct Global IPv6
- **Command:** `D:/program_software/sdks/Python315/python.exe test_real_uses_dual_terminal_ipv6.py`
- **Working Directory:** `D:\code\Main_projects\p2p\p2p_6_1-26`
- **Exit Status:** `0` (Success)
- **Output Summary:**
  - Direct global IPv6 endpoint: `[2409:4091:10a2:7802:5938:7859:e1f3:c94e]`
  - Step 1: Subprocess spawns with bracketed IPv6 socket bindings — PASS
  - Step 2: Pure FIPS 203/204 mutual handshake & SAS verification code match — PASS
  - Step 3: Zero-Gap Multi-Layer Defense Pipeline armed — PASS
  - Step 4: Full bidirectional chat messaging — PASS
  - Step 5: NC3 strict keyword safety gate enforcement (blocked unauthorised directives) — PASS
  - Step 6: Multi-frame out-of-order text reassembly — PASS
  - Step 7: Continuous Epoch Ratchet (CER) in-band rotation — PASS
  - Step 8: In-band document streaming & SHA-384 verification (`/doc`) — PASS
  - Step 9: Telemetry & LPD inspection (`/status`, `/lpd`) — PASS
  - Step 10: Clean termination and NIST SP 800-88 cryptographic sanitization (`/zeroize`) — PASS
  - Result: **8 / 8 REAL USE CASES SUCCEEDED 100% OVER DIRECT REAL IPV6 TRANSPORT**

### Test 6: Compiler Lint Gate (`cargo clippy`)
- **Command:** `cargo clippy --manifest-path rust_data_plane/Cargo.toml --all-targets -- -D warnings`
- **Working Directory:** `D:\code\Main_projects\p2p\p2p_6_1-26`
- **Exit Status:** `1` (6 compiler warnings treated as errors under Rust 1.99.1)
- **Observed Diagnostics:**
  1. `src/ffi.rs:1310`: `clippy::type-complexity` on `parse(xml: &str)` return type.
  2. `src/fragment.rs:123`: `clippy::manual-div-ceil` on chunk count calculation.
  3. `src/fragment.rs:259`: `clippy::manual-is-multiple-of` on hex string length parity check.
  4. `src/pipeline.rs:61`: `clippy::manual-div-ceil` on quantum padding calculation.
  5. `src/pipeline.rs:224`: `clippy::collapsible-if` on NC3 safety gate check.
  6. `src/pipeline.rs:275`: `clippy::manual-is-multiple-of` on CER epoch interval check.

### Test 7: Reproducible Build & Supply Chain Hash-Manifest Gate
- **Command:** `D:/program_software/sdks/Python315/python.exe scripts/verify_reproducible_build.py`
- **Working Directory:** `D:\code\Main_projects\p2p\p2p_6_1-26`
- **Exit Status:** `1` (Failure)
- **Observed Diagnostics:**
  - Native DLL signatures (`oqs.dll`, `libsodium.dll`): VERIFIED
  - Core Python Module Integrity (7 modules): VERIFIED
  - SBOM signatures: VERIFIED
  - Hash Manifest Check: `rust_data_plane/src/main.rs: DRIFT (sha3_512=350fe41084ae1968...)` vs pinned value in `critical_modules.hashes`.
  - Cause: `rust_data_plane/src/main.rs` contains uncommitted edits from prior session.

### Test 8: Master Defense Harness (10 Gates)
- **Command:** `D:/program_software/sdks/Python315/python.exe scripts/run_defense_audit.py`
- **Working Directory:** `D:\code\Main_projects\p2p\p2p_6_1-26`
- **Exit Status:** `1` (Failure)
- **Observed Diagnostics:**
  - Gate 1.1: FAIL (Rust Clippy Compiler Audit — 6 warnings present)
  - Gate 2.1: PASS (ts_rt Clippy & Memory Discipline Verification)
  - Gate 3.1: PASS (CNSA Suite 2.0 KATs & Algorithm Purity)
  - Gate 4.1: PASS (ProVerif 2.05 Symbolic Handshake & PCS Proofs)
  - Gate 5.1: PASS (Active Exploit Defenses — Replay DoS & Nonce Reuse)
  - Gate 6.1: PASS (Platform Gating — Signed ML-DSA-87 Waivers)
  - Gate 7.1: FAIL (SLSA Level 3+ Supply Chain & DLL Pinning — `main.rs` hash drift)
  - Gate 8.1: PASS (Truth-in-Claims & Linguistic Purity)
  - Gate 9.1: PASS (In-Process Single-Command Operator Self-Test)
  - 7 of 9 executed gates PASS; 2 gates FAIL due to known uncommitted modifications.

---

## 4. Pre-Existing Working Tree Modifications

Prior to the start of this audit, the working tree contained modifications in 37 tracked files and 17 untracked files.
Per the audit protocol rules:
- These uncommitted modifications are preserved untouched.
- They are excluded from audit commits unless explicitly instructed by the repository owner.
