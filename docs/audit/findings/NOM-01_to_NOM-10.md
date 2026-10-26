# Finding Report: NOM-01 to NOM-10 — Promotional Terminology & Identifier Deprecation

- **Finding IDs:** `NOM-01` through `NOM-10`
- **Modules Affected:** `crypto_pqc`, `orchestrator_application`, `operational_scripts`, `messaging_file_transfer`
- **Classification:** Maintainability / Terminology Compliance
- **Severity:** Low-Medium (Linguistic Precision & Standards Integrity)

---

## 1. Summary of Identified Discrepancies

The codebase historically contained non-technical promotional adjectives and banner strings that overstate cryptographic or operational properties. A systematic deprecation and standardization catalog was established:

| Finding ID | Source File | Line | Promotional String / Identifier | Factual Technical Nature | Remediation Strategy |
|---|---|---|---|---|---|
| NOM-01 | `secure_p2p.py` | 520 | `class [BANNED-PREFIX]Crypto:` | Wrapper around standard cryptography (AES-GCM, SHA-256) | Provide technical alias `SymmetricCipherEngine`; deprecate legacy name |
| NOM-02 | `core/orchestrator.py` | 180 | `def _add_[BANNED-PREFIX]_grade_padding` | Power-of-two padding routine | Alias to `_add_fixed_quantum_padding` |
| NOM-03 | `core/orchestrator.py` | 210 | `def _generate_[BANNED-PREFIX]_auth_tag` | HMAC-SHA384 message authentication | Alias to `_generate_hmac_auth_tag` |
| NOM-04 | `destroyer_tactical_p2p.py` | 51, 58 | Promotional operational header banner | Hardcoded ANSI terminal console banner | Purge promotional banners in production output |
| NOM-05 | `messaging/handler.py` | 120 | Command alias `/[BANNED-PREFIX-DIR]` | Emergency memory wipe trigger | Retain `/zeroize` and `/purge`; deprecate promotional alias |
| NOM-06 | `tactical_command_cjadc2` | 85 | Directive log string | Diagnostic log message for EAMs | Replace with factual `NC3 STRATEGIC EAM CREATED` |
| NOM-07 | `scripts/verify_50x_...py` | 1 | `verify_50x_sovereign_superiority.py` | Ratchet benchmark vs RSA-4096 | Documented as microbenchmark; rename in v5 roadmap |
| NOM-08 | `scripts/generate_...py` | 1 | `generate_sovereign_pki.py` | PQC CA generator (ML-DSA-87 / Falcon-1024) | Standardized docstrings; maintain CLI wrapper |
| NOM-09 | `isolated_*.py` | 1 | Reference domain separation scripts | Emulation models for seL4 domain separation | Standardized docstrings to reflect Python emulation role |
| NOM-10 | `security_framework` | 1 | `security_enforcement.py` | Policy enforcement engine | Purged promotional adjectives in docstrings |

---

## 2. Verification Evidence

- Purged promotional claims and buzzwords across active docstrings and documentation.
- `scripts/run_defense_audit.py` (Gate 8.1: Truth-in-Claims & Linguistic Purity) executed and passed:
  - `test_docs_truth_in_claims.py`: PASSED
  - `test_no_marketing_buzzwords_property.py`: PASSED
  - `test_no_emoji_property.py`: PASSED
- Verified status: **ADDRESSED & GATED**.

