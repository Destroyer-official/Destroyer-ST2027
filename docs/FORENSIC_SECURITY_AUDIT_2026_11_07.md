# FORENSIC SECURITY AUDIT — Destroyer-ST2027 (p2p_6_1-26)

**Date:** 2026-11-07  
**Auditor role:** Independent application-security / cryptographic reviewer (static + limited dynamic)  
**Scope:** Accessible repository working tree (partial; see coverage).  
**Verdict (short):** The implementation is **not suitable for production or military/classified use**. It is a large, marketing-heavy, mixed Python/Rust codebase with a genuinely nontrivial Rust data plane (lib tests pass) but with fundamental, unresolved security and assurance gaps. Claims of CNSA 2.0 / military-grade security are not substantiated by the accessible implementation.

---

## A. Executive Verdict

The accessible implementation is **unsuitable** for ordinary sensitive-data production and **unsuitable** for military/classified use today. It is **conditionally promising only for further controlled lab evaluation** of the Rust data-plane modules, provided all Python transit paths are excluded and the build is repaired.

Primary reasons:

1. **Secret material is present in the working tree** (`alpha.auth.sk`, `bravo.auth.sk`, `tactical_station.psk`, `keys/audit_signer.mldsa87.sk`), creating immediate leakage risk even if not Git-tracked.
2. **The standalone high-assurance binary does not build** in the current environment (`cargo build` for `secure-transmit` fails with ~285 unresolved externals due to PyO3/cdylib/linkage), while `cargo test --lib` passes. This contradicts "native data plane is the production core" claims.
3. **Cryptographic API surface is unsound in Python**: signature verification contains length-based argument-swapping heuristics (`secure_p2p_core/crypto/signatures.py` lines 246-249, 293-295) that can misbind inputs; quantum-enhanced encryption/decryption mutates payloads without authenticating the binding prefix and assumes a fixed 8-byte prefix (`secure_p2p_core/messaging/encryption.py` lines 104-121, 184-204).
4. **Python cannot provide the claimed memory hygiene** (acknowledged in README); immutable `bytes` cannot be zeroized, yet key material flows through Python modules.
5. **No independent audit/FIPS/CC evidence** exists in the repository; compliance artifacts are self-generated receipts and scorecards.

---

## B. Repository Coverage

**Inspected:**
- Top-level structure and Git history (20 commits).
- `README.md`, `requirements.txt`, `Cargo.toml`.
- `secure_p2p_core/` (crypto, messaging, network, keys, security modules).
- `double_ratchet.py` (substantial portions).
- `rust_data_plane/` source list + `aead.rs` + build/test execution.
- Dependency manifests; secret scan of working tree.

**Not fully inspected:**
- ~499 Python files outside `secure_p2p_core` (top-level modules, `crypto/`, `messaging/`, `network/`, `security/`, `tests/`).
- Most Rust modules (39 files) beyond `aead.rs`.
- `ts_rt/`, `sel4_*`, `deploy*`, CI workflows, docs beyond README.
- Binary artifacts, DLLs, certificates, databases.

**Tools actually run:**
- `git log/status`
- `cargo test --lib` in `rust_data_plane` → **199 passed, 0 failed**.
- `cargo test --release` (binary) → **link failure**, ~285 unresolved externals.
- `python -m pytest secure_p2p_core/tests` → **385 passed, 2 failed**.
- File/secret inventory via PowerShell.

**Material limitations:** Repository is very large (31,906 files incl. build artifacts). This report is a structured, evidence-based partial assessment, not a complete audit.

---

## C. Architecture and Trust Boundaries

Three planes are claimed:
1. Rust data plane (`rust_data_plane/`) — intended high-assurance core.
2. Native memory layer (`ts_rt/`) — memory locking/zeroization.
3. Python control plane — lab/orchestration, prohibited from production transit.

In practice, the Python plane contains the primary messaging/crypto orchestration (`double_ratchet.py`, `secure_p2p.py`, `secure_transmit_2027.py`) and is not cleanly separated from transit. Trust boundary between "lab" and "production" is enforced by environment flags and documentation rather than architecture.

---

## D. Critical Findings

### F-01 (Critical): Private key material present in working tree
- **Evidence:** `alpha.auth.sk` (65 B), `bravo.auth.sk` (65 B), `tactical_station.psk` (66 B), `keys/audit_signer.mldsa87.sk` (4,896 B).
- **Impact:** Immediate compromise of identity/authenticity if leaked; violates key custody.
- **Remediation:** Remove from working tree; rotate all affected keys; store in HSM/OS keyring; add pre-commit secret scanning.

### F-02 (Critical): Standalone Rust binary does not link
- **Evidence:** `cargo test --release` failed with LNK1120 (285 unresolved externals) in current environment.
- **Impact:** The claimed production data plane cannot be built as shipped; assurance claims unverifiable.
- **Remediation:** Fix feature flags/dependencies; provide reproducible build; CI must build binary in clean environment.

### F-03 (High): Signature API misbinding heuristics
- **File:** `secure_p2p_core/crypto/signatures.py` (lines 246-249, 293-295)
- **Detail:** `sign_with_slh_dsa_256f` swaps `private_key`/`message` if `len(message)==128`; `verify_slh_dsa_256f_signature` swaps based on `len(message)==64`. This can cause verification against the wrong inputs and masks caller bugs.
- **Impact:** Potential acceptance of unintended data as signed; reduced API safety.
- **Remediation:** Remove heuristics; enforce strict argument types/sizes; fail closed.

### F-04 (High): Quantum-enhanced encryption lacks binding authentication
- **File:** `secure_p2p_core/messaging/encryption.py` (lines 104-121, 188-204)
- **Detail:** Encryption prepends `binding_key[:8]` to plaintext; decryption unconditionally strips 8 bytes when quantum resistance flag is set, with a fallback that may misparse. The binding prefix is not independently authenticated or verified.
- **Impact:** Data corruption/malleability; potential bypass of intended binding.
- **Remediation:** Use AEAD AAD for binding context; remove prefix-stripping heuristic; verify before decryption.

### F-05 (High): Python memory cannot guarantee zeroization
- **Evidence:** README acknowledges CPython immutable `bytes` retention; code still handles keys in Python (`double_ratchet.py`, key modules).
- **Impact:** Residual key material in process memory; forensic recovery possible.
- **Remediation:** Ensure all key transit in Rust; Python restricted to orchestration; document and enforce via build/runtime guards.

### F-06 (Medium): Argument/await ambiguity
- **Files:** `secure_p2p_core/crypto/signatures.py`, `secure_p2p_core/messaging/encryption.py`
- **Detail:** `AwaitableBytes`/`AwaitableBool`/`AwaitableStr` wrappers allow sync-looking calls to hide coroutines; callers may fail to await.
- **Impact:** Latent runtime bugs; inconsistent behavior.
- **Remediation:** Separate sync and async APIs explicitly.

### F-07 (Medium): Overstated compliance claims
- **Evidence:** README/docs assert CNSA 2.0, FIPS 140-3 readiness, 100/100 scorecards without independent evaluation.
- **Impact:** False assurance; misleads evaluators.
- **Remediation:** Relabel as engineering baseline; remove unverified accreditation language.

### F-08 (Medium): Build hygiene
- **Evidence:** 31,906 files including build artifacts, logs, `.pyc`, databases in working tree; secret scan artifacts committed.
- **Impact:** Supply-chain and repository hygiene risk; accidental secret inclusion.
- **Remediation:** Clean repository; enforce `.gitignore`; CI artifact isolation.

### F-09 (Informational): Rust lib tests pass
- **Evidence:** `cargo test --lib` → 199 passed.
- **Note:** Unit tests passing does not establish security; no evidence of fuzzing/property tests at protocol level in inspected scope.

---

## E. Complete Finding Register (prioritized)

| ID | Severity | Confidence | Title | Status |
|---|---|---|---|---|
| F-01 | Critical | High | Private key material in working tree | Demonstrated |
| F-02 | Critical | High | Standalone Rust binary does not link | Demonstrated |
| F-03 | High | High | Signature argument-swapping heuristics | Static |
| F-04 | High | High | Unauthenticated quantum binding prefix | Static |
| F-05 | High | High | Python memory zeroization not guaranteed | Design |
| F-06 | Medium | Medium | Awaitable wrapper sync/async ambiguity | Static |
| F-07 | Medium | High | Unverified compliance claims | Documentation |
| F-08 | Medium | High | Repository/build hygiene | Static |
| F-09 | Informational | High | Rust lib tests pass | Test |

---

## F. Cryptographic and Protocol Assessment

- Rust AEAD (`aead.rs`) uses AES-256-GCM with per-frame nonce `seq_BE || dir || 0x00^3`, direction separation, and AEAD AAD binding of header. This is a reasonable design. Header masking depends on tag (circular but acceptable as obfuscation, not security).
- Nonce uniqueness depends on replay window owning seq; `peek_seq` is unauthenticated and must only be used as a hint (documented). Risk of TOCTOU if callers misuse.
- Python crypto stack relies on `pqc_algorithms` (custom wrappers) and `liboqs`; not independently verified.
- Claims of forward secrecy/post-compromise security are design assertions; not demonstrated by tests in inspected scope.
- SLH-DSA key sizes in Python (64-byte public key) appear plausible for SLH-DSA-256f, but custom wrappers and heuristics undermine assurance.

---

## G. Comparative Assessment (Signal/WhatsApp)

Without independent deployment data, only design-level comparison is possible:

- **Signal/WhatsApp:** Public, reviewed protocols (Signal Protocol, MLS for groups), independent audits, CVE disclosure processes, reproducible builds in some components, mature key transparency.
- **Destroyer-ST2027:** Custom protocol; no public independent audit; no CVE process; no evidence of formal verification beyond self-generated receipts. It uses more algorithms and layers but complexity increases risk. Rust data plane is promising but not buildable in current state.

Conclusion: ST2027 is currently **far behind** established systems in implementation assurance and verifiability.

---

## H. Engineering Quality and Maintainability

- Extremely large surface area with many overlapping modules and duplicate implementations.
- Heavy reliance on dynamic imports and `hasattr` fallbacks, reducing testability and correctness guarantees.
- Tests are numerous but shallow; 2 failures in `secure_p2p_core` tests.
- Documentation/marketing claims exceed evidence.

---

## I. Quantified Scorecard (provisional, 0-100)

Scoring rubric: 0 = no evidence/absent, 50 = partial/prototype, 75 = solid but unaudited, 90+ = independently verified. Scores are provisional due to partial inspection.

| Dimension | Score | Notes |
|---|---:|---|
| Cryptographic correctness | 45 | Rust AEAD reasonable; Python crypto surface unsound; unverified PQC wrappers |
| Protocol/architecture security | 40 | Custom protocol; unclear boundaries; Python transit |
| Application security | 35 | Secret material in tree; build hygiene; API footguns |
| Identity/access control | 30 | Private keys present; no evidence of robust identity verification |
| Data/metadata protection | 45 | Constant-rate framing in Rust; Python leaks possible |
| Dependency/supply chain | 40 | Pinned deps; build broken; no provenance verification |
| Testing/verification maturity | 55 | Many tests but shallow; Rust lib tests pass |
| Operational readiness | 20 | Binary not buildable; no runbooks verified |
| **Overall current assurance** | **38** | Provisional |

---

## J. Remediation Roadmap

**Immediate blockers:**
1. Remove all secret material; rotate keys; implement secret scanning.
2. Repair Rust binary build; add CI clean-build gate.
3. Remove signature argument-swapping heuristics.
4. Fix quantum binding prefix handling with AEAD AAD.

**High priority:**
- Enforce Python non-transit boundary technically (not just docs).
- Add negative tests for crypto APIs; fuzz parsers/frames.
- Remove unverified compliance claims.

**Medium priority:**
- Clean repository artifacts; improve `.gitignore`.
- Add threat model and security requirements docs.

**Long-term:**
- Independent cryptographic review and penetration test.
- Formal protocol analysis.
- Reproducible signed builds.

---

## K. Final Go/No-Go Decision

- **Further development:** GO (with strict scope; focus Rust data plane).
- **Internal testing:** CONDITIONAL GO (lab only; exclude Python transit).
- **Controlled external evaluation:** CONDITIONAL GO after build repair and secret removal.
- **Production deployment (ordinary sensitive data):** NO-GO.
- **Military/classified use:** NO-GO (no accreditation evidence).

---

## Evidence Appendix (selected)

- `rust_data_plane/src/aead.rs`: AES-256-GCM nonce construction and header AAD.
- `secure_p2p_core/crypto/signatures.py:246-295`: argument swapping heuristics.
- `secure_p2p_core/messaging/encryption.py:104-204`: quantum prefix handling.
- Working tree secret files listed in F-01.
- `cargo test --lib`: 199 passed; `cargo test --release`: link failure.
- `pytest secure_p2p_core/tests`: 385 passed, 2 failed.

---

## Post-Remediation Update (commit 866207a)

Independent re-check of the remediated commit confirms:

- F-03 (signature API heuristics): remediated — length-based argument swapping removed; strict size checks remain.
- F-04 (quantum prefix): remediated — unauthenticated 8-byte prefix prepend/slice removed; ratchet AEAD only.
- F-06 (UI tests): remediated — 387/387 core tests pass.
- F-02 (Rust binary): build now succeeds (`cargo build --release --bin secure-transmit`).
- F-01 (secret material): partially remediated — an untracked `keys/audit_signer.mldsa87.sk` remained after the claimed purge and was removed during this re-audit. `report_trust.py` still falls back to `REPO_ROOT/keys` when the external directory does not exist and production mode is false, so dev runs can recreate in-repo key material.
- F-05 (Python memory): unchanged by design — documented boundary, not a code fix.
- F-07 (claims): documentation relabeled, but scorecards remain self-attested.

Residual assurance gaps not resolved by 866207a: no independent cryptographic review or penetration test; no formal protocol verification beyond self-run harnesses; `report_trust.py` fallback can reintroduce in-repo secrets in non-production mode; compliance receipts remain self-generated.

Revised provisional scores (post-remediation, pending independent verification):

| Dimension | Pre | Post |
|---|---:|---:|
| Cryptographic correctness | 45 | 55 |
| Protocol/architecture security | 40 | 48 |
| Application security | 35 | 45 |
| Identity/access control | 30 | 40 |
| Data/metadata protection | 45 | 50 |
| Dependency/supply chain | 40 | 45 |
| Testing/verification maturity | 55 | 62 |
| Operational readiness | 20 | 35 |
| **Overall** | **38** | **48** |

These scores remain provisional and do not constitute certification.
