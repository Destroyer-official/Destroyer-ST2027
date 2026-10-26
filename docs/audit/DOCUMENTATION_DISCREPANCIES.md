# Documentation Discrepancies Register

**Audit Run ID:** `RUN-20261025-01`
**Date:** 2026-10-25
**Protocol:** Production Engineering and Forensic Verification v4.0
**Project:** Destroyer-ST2027

---

## 1. Documentation Claims vs. Verified Implementation Reality

| Topic | Documentation Statement | Verified Implementation Reality | Status |
|---|---|---|---|
| **Side-Channel Protection** | Earlier documentation asserted "complete immunity to side-channel and timing attacks." | The implementation utilizes constant-time comparisons (`compare_digest`), memory wiping, and randomized timing jitter (`TimingJitterContext`). While effective against remote network timing analysis, general-purpose superscalar CPUs cannot provide physical side-channel immunity (e.g., power analysis, cache line eviction, EM leakage) without certified hardware tamper boundaries. | **Corrected in documentation; factual boundaries established.** |
| **Python Codebase Status** | `docs/RUST_CORE.md` originally stated: *"Python tree untouched ... keep their logic byte-for-byte as the audited reference ... No Python security logic was rewritten"*. | Python code has been continuously patched during audit remediation (DEF-01, DEF-02, DEF-03, DEF-04, DEF-05). It functions as an active reference/lab/backup path, not a frozen, unmodifiable artifact. | **Updated in `docs/RUST_CORE.md` to reflect active development status.** |
| **Ratchet Post-Compromise Security** | Rust docstrings claimed: *"every step heals ... which is strictly stronger and matches the constant-rate channel transport."* | While the implementation performs fresh ML-KEM-1024 encapsulation on every step, cadence alone does not establish mathematical equivalence to the Dodis et al. 2025/078 Triple Ratchet / Signal SPQR proofs without dedicated independent peer review. | **Corrected in `rust_data_plane/src/ratchet.rs` and `lib.rs`.** |
| **Monolith vs. Modular Package** | Architecture diagrams treat `destroyer.py` and `core/orchestrator.py` as primary, but legacy prototype `secure_p2p.py` (14,886 lines) remains co-located. | Both implementations exist simultaneously. Code fixes in one require manual porting to the other. Roadmap requires formal deprecation of `secure_p2p.py` once 100% modular coverage is demonstrated. | **Documented in `remediation_plan.md` and `open_questions.md`.** |
| **Promotional Terminology** | Codebase historically contained non-technical adjectives (`[BANNED-PREFIX]Crypto`, `[BANNED-PREFIX]_grade_padding`). | Standardized to objective technical nomenclature (`SymmetricCipherEngine`, `_add_fixed_quantum_padding`, `_generate_hmac_auth_tag`). Gate 8.1 verifies 0 marketing buzzwords and 0 emojis across active files. | **Standardized and gated.** |

---

## 2. Standards Compliance vs. Statutory Certification

- **Common Criteria & FIPS 140-3 Submittals:** Artifacts in `compliance_reports/` (`cmvp_fips140_3_submittal.json`, `niap_common_criteria_matrix.json`) represent internal readiness matrices and pre-evaluation self-assessments. They do not constitute statutory NVLAP laboratory certifications or signed government Authorizing Official (AO) Authorities to Operate (ATO).
- **ProVerif Formal Verification:** ProVerif symbolic models prove protocol secrecy and authentication under symbolic mathematical abstractions (perfect cryptography assumptions); they do not model implementation side-channels or memory corruption bugs.

