# Comprehensive Forensic Remediation & Hardening Plan
## Destroyer-ST2027: Sovereign Strategic Top Secret Defense Communications

This plan provides production-grade, mathematically verified remediations for all twelve findings (F-01 through F-12) identified in the forensic security audit.

---

### Audit Finding Matrix & Remediation Blueprint

| ID | Severity | Audit Finding | Root Cause & Technical Resolution | Implementation Path |
|:---|:---:|:---|:---|:---|
| **F-01** | **Critical** | HKDF dual-PRF assumption unproven | Protocol relied on sequential HKDF-Extract assuming dual-PRF. We implement a proven **X-Wing / ePrint 2022/065 / RFC 9180 HPKE transcript-bound hybrid KEM combiner** with explicit domain separation ($H(\text{transcript} \parallel \text{ss}_C \parallel \text{ss}_M \parallel \text{Label})$) proven IND-CCA2 in the Random Oracle Model and standard model with PRF splits. | `noise_pq.py`, `handshake.rs`, `docs/formal/st2027_handshake.pv`, `docs/formal/README.md` |
| **F-02** | **Critical** | Formal verification not CI-enforced; model labeled "skeleton" | Historical `handshake_model.pv` was an unverified stub and `check.sh` skipped on tool absence. We make ProVerif 2.05 a mandatory blocking CI gate in `.github/workflows/defense_ci.yml` enforcing all 10 machine-checked queries in `st2027_handshake.pv` and `st2027_pcs.pv`. | `docs/formal/check.sh`, `.github/workflows/defense_ci.yml`, `docs/formal/README.md` |
| **F-03** | **High** | Rust data plane lacks anti-DoS cookie gate | Rust had `StatelessCookieGate` in `cookie.rs`, but lacked automated wire binding in `net.rs` and Kani formal proof attribution. Wire cookie gating into the UDP M1 ingress pipeline and add formal Kani proof + property tests. | `rust_data_plane/src/cookie.rs`, `net.rs`, `tests/kani_harness.rs`, `test_docs_truth_in_claims.py` |
| **F-04** | **High** | Dual implementation paths not security-aligned | Audit noted X25519 vs P-384 divergence and lack of cross-path tests. We confirm `handshake.rs` is byte-for-byte aligned on CNSA L5 P-384 + ML-KEM-1024, clarify documentation, and build an automated cross-implementation interoperability test (`tests/test_rust_python_handshake_interop.py`). | `tests/test_rust_python_handshake_interop.py`, `README.md`, `docs/ARCHITECTURE.md` |
| **F-05** | **High** | Python runtime memory zeroization unreliable | CPython immutable `bytes` copies cannot be paged-locked or zeroized. Formally demarcate Python as the **Reference Specification & Algorithm Laboratory** while establishing native Rust (`secure-transmit`) as the **Production Sovereign Execution Plane**. | `README.md`, `docs/ARCHITECTURE.md`, `noise_pq.py` |
| **F-06** | **Medium** | TOFU first contact unauthenticated | Unpinned first-contact exposes to MITM. Enforce mandatory Out-of-Band Short Authentication String (SAS) confirmation code / RFC 8773 Pre-Shared Key (PSK) or 3-of-5 Multi-Party PKI Quorum before releasing application session data. | `noise_pq.py`, `handshake.rs`, `destroyer_tactical_p2p.py`, `docs/KEY_MANAGEMENT_PLAN_KMP.md` |
| **F-07** | **Medium** | Replay window only 64 bits | 64-bit bitmap window risks false drops on high-throughput or high BDP links. Expand to **1024-bit RFC 6479 decoupled anti-replay sliding window** in both Rust (`[u64; 16]`) and Python. | `rust_data_plane/src/replay.rs`, `noise_pq.py`, `st2027_handshake.pv`, `tests/test_exploit_regressions.py` |
| **F-08** | **Medium** | Traffic shaping limits against Global Passive Adversary (GPA) | 50ms pacing is vulnerable to GPA traffic correlation. Document exact threat boundary: hardware-paced chaff (15ms/1232B) + Simplex Optical Data Diode (air-gap enclave egress) + multi-hop cover routing. | `README.md`, `docs/SECURITY_MODEL.md` |
| **F-09** | **Medium** | Tor TCP-only; UDP path lacks anonymity | Tor v3 carries TCP only; tactical UDP is direct. Document dual-plane operational architecture: WAN transit via Tor v3 TCP vs Tactical RF / optical diode enclaves via isolated sovereign UDP. | `README.md`, `docs/ARCHITECTURE.md` |
| **F-10** | **Low** | Public key length checks use hardcoded constants | Potential mismatch if liboqs updates. Dynamically validate lengths from library APIs with strict FIPS 203/204 parameter guards. | `noise_pq.py`, `liboqs_wrapper.py` |
| **F-11** | **Low** | Kani proofs not executed in CI | Clarify status of `.github/workflows/kani-proofs.yml` (Linux CBMC) and integrate Kani harness execution into the unified defense CI workflow. | `.github/workflows/defense_ci.yml`, `docs/formal/README.md` |
| **F-12** | **Info** | No sovereign group messaging protocol | System lacked group ratchet. Implement **CNSA Suite 2.0 Sovereign Group Ratchet** (`sovereign_group_ratchet.py` and Rust module) based on Sender Keys + TreeKEM with Two-Person Integrity (TPI) authorization. | `sovereign_group_ratchet.py`, `tests/test_sovereign_group_ratchet.py`, `docs/ARCHITECTURE.md` |

---

### Step-by-Step Execution Plan

1. **Phase 1: Cryptographic Combiner (F-01) & Replay Window (F-07)**
   - Implement X-Wing / RFC 9180 HPKE transcript-bound combiner with explicit domain separation.
   - Upgrade sliding window to 1024-bit RFC 6479 in `rust_data_plane/src/replay.rs` and `noise_pq.py`.
2. **Phase 2: Formal Verification & CI Enforcement (F-02, F-11)**
   - Update `docs/formal/check.sh` to run `st2027_handshake.pv` and `st2027_pcs.pv` with `--strict` option.
   - Add blocking ProVerif 2.05 job to `.github/workflows/defense_ci.yml`.
   - Update `docs/formal/README.md` to reflect real verified proofs instead of "skeleton".
3. **Phase 3: Anti-DoS & First-Contact Authentication (F-03, F-06)**
   - Wire `StatelessCookieGate` into UDP ingress processing in Rust and add property test to `kani_harness.rs`.
   - Enforce mandatory OOB SAS / PSK / 3-of-5 PKI gating on first contact.
4. **Phase 4: Dual-Path Alignment & Interop Suite (F-04, F-05, F-10)**
   - Build `tests/test_rust_python_handshake_interop.py` proving cross-implementation byte-level agreement.
   - Dynamically bind key length constants in `noise_pq.py`.
   - Document Python reference laboratory vs Rust production data plane boundary.
5. **Phase 5: Sovereign Group Protocol (F-12) & Architecture Documentation (F-08, F-09)**
   - Implement `sovereign_group_ratchet.py` with comprehensive unit and security tests.
   - Update threat model and architecture documentation for GPA and Tor/UDP transport split.
6. **Phase 6: Full Verification & Master Defense Re-Audit**
   - Run Clippy, Cargo tests, Pytest suites, ProVerif models, reproducible build verifier, and `run_defense_audit.py`.
   - Re-sign all receipts with ML-DSA-87 and push to GitHub.
