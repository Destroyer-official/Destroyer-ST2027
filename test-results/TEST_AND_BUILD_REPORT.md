# Test and Build Verification Report

**Audit Run ID:** `RUN-20261104-01`  
**Date:** 2026-11-04  
**Audit Protocol:** Production Engineering and Forensic Verification v5.0  
**Branch:** `audit/2026-11-04`  
**Host Environment:** Windows 11 AMD64, Python 3.15.2, Rust 1.99.1, Cargo 1.99.1  

---

## 1. Test Execution Summary

| Test Suite / Command | Scope / Category | Exit Code | Tests Passed | Tests Failed | Latency | Status |
|---|---|---|---|---|---|---|
| `cargo test --manifest-path rust_data_plane/Cargo.toml` | Native Rust Data Plane Unit & Proof Tests | `0` | 186 | 0 | 18.52 s | PASS |
| `cargo test --manifest-path ts_rt/Cargo.toml` | Native Runtime Deterministic Core | `0` | 0 | 0 | 0.09 s | PASS |
| `python verify_deployment.py` | Production Deployment Verification Testbench | `0` | 92 checks | 0 | 1.83 s | PASS |
| `pytest tests/test_audit_forensic_remediations.py ...` | Core Forensic & Defense Security Entrypoint Battery | `0` | 55 | 0 | 42.65 s | PASS |
| `python test_real_uses_dual_terminal_ipv6.py` | Dual-Terminal Direct Global IPv6 Real Use Cases | `0` | 8 use cases | 0 | 25.10 s | PASS |
| `cargo clippy --manifest-path rust_data_plane/Cargo.toml --all-targets -- -D warnings` | Native Rust Clippy Compiler Audit | `0` | Clean | 0 | 4.99 s | PASS (Post-Fix CHG-17) |
| `python scripts/verify_reproducible_build.py` | SLSA Level 3+ Supply Chain & DLL Pinning | `1` | 4 checks | 1 drift | 2.10 s | FAIL (main.rs drift) |
| `python scripts/run_defense_audit.py` | Master Defense Harness (10 Gates) | `1` | 8 gates | 1 gate | 81.17 s | FAIL (Gate 7.1 drift) |

---

## 2. Detailed Command Output

### 2.1 Native Rust Data Plane Test Battery
```
Finished `test` profile [unoptimized + debuginfo] target(s) in 0.27s
Running unittests src\lib.rs (rust_data_plane\target\debug\deps\destroyer_core-e0f4fa3979891229.exe)
running 148 tests
test result: ok. 148 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 17.10s

Running tests\kani_harness.rs (rust_data_plane\target\debug\deps\kani_harness-e97de4f9ec77446e.exe)
running 37 tests
test result: ok. 37 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

Doc-tests destroyer_core
running 1 test
test src\mmhs.rs - mmhs::format_caveats (line 128) ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.15s
```

### 2.2 Production Deployment Verification Testbench
```
============================================================
PROJECT SENTINEL - Production Deployment Verification
Timestamp: 2026-11-04T09:43:58.260824
============================================================
=== Core Module File Verification ===
  17/17 PASS
=== Core Module Import Verification ===
  17/17 PASS
=== CNSA 2.0 (Jan-2027 Gate) Readiness ===
  [PASS] CNSA27: ML-KEM-1024 + ML-DSA-87 validate: mandatory 2027 pair approved
  [PASS] CNSA27: HAWK refused: never-authorized set enforced
  [PASS] CNSA27: HASHML-DSA-87 refused: never-authorized set enforced
  [PASS] CNSA27: FN-DSA-1024 refused: never-authorized set enforced
  [PASS] CNSA27: MAYO refused: never-authorized set enforced
  [PASS] CNSA27: native PQ roundtrip: ML-KEM-1024 + ML-DSA-87 live, sizes pinned
=== Secure Environment & Anti-Downgrade Verification ===
  14/14 PASS
=== Summary ===
  PASS: 92
  FAIL: 0
  WARN: 4
  SKIP: 0
  Overall Status: READY FOR DEPLOYMENT
```

### 2.3 Direct IPv6 Dual-Terminal Real Use-Cases
```
[TEST STEP 1] Both node subprocesses spawned over IPv6.
[TEST STEP 2] Pure FIPS 203/204 mutual handshake & SAS verification code match.
[TEST STEP 3] Zero-Gap Multi-Layer Defense Pipeline armed.
[TEST STEP 4] Full bidirectional chat messaging passed.
[TEST STEP 5] NC3 strict keyword safety gate enforcement passed.
[TEST STEP 6] Multi-frame out-of-order text reassembly passed.
[TEST STEP 7] Continuous Epoch Ratchet (CER) in-band rotation passed.
[TEST STEP 8] Mission document streamed, fragmented, reassembled, and verified via SHA-384.
[TEST STEP 9] Telemetry, pipeline, and LPD telemetry inspected and verified over IPv6.
[TEST STEP 10] Clean termination and NIST SP 800-88 cryptographic sanitization passed.
ALL 8 REAL USE CASES SUCCEEDED 100% OVER DIRECT REAL IPV6 TRANSPORT!
```
