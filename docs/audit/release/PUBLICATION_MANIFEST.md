# Release Publication Manifest

**Release Candidate ID:** `RC-ST2027-20261025-V1`
**Target Repository:** `Destroyer-official/Destroyer-ST2027`
**Target Branch:** `audit/destroyer-st2027-verified-fixes`
**Protocol:** Production Engineering and Forensic Verification v4.0

---

## 1. Explicit Allowlist of Files Intended for Release

| Local File Path | Intended Remote Path | Change Type | Reason for Inclusion | Verification Evidence | Publication Classification | Sensitive Review Result |
|---|---|---|---|---|---|---|
| `operational_security.py` | `operational_security.py` | Modified | Fixes coarse-clock LRU memory eviction bug in `MessageExpirationManager` (DEF-05). | `pytest tests/test_audit_forensic_remediations.py` (11/11 PASS) | Public Source | Clean — No secrets, credentials, or private paths. |
| `requirements-test.txt` | `requirements-test.txt` | Modified | Explicitly pins test suite dependencies for air-gapped reproducibility. | `python scripts/audit_pins.py --offline` (27/27 PASS) | Public Config | Clean — Standard open-source package pins. |
| `rust_data_plane/src/lib.rs` | `rust_data_plane/src/lib.rs` | Modified | Clarifies ratchet is inspired by SPQR research, not a full SPQR implementation. | `cargo test` (156/156 PASS), Master Gate 8.1 PASS | Public Source | Clean — Docstring technical clarification. |
| `rust_data_plane/src/ratchet.rs` | `rust_data_plane/src/ratchet.rs` | Modified | Moderates cryptographic claims regarding fresh-KEM healing cadence vs security proof. | `cargo test` (156/156 PASS), Master Gate 8.1 PASS | Public Source | Clean — Docstring technical clarification. |
| `docs/RUST_CORE.md` | `docs/RUST_CORE.md` | Modified | Updates architecture doc to clarify Python is active reference/lab/backup path. | Master Gate 8.1 Truth-in-Claims PASS | Public Documentation | Clean — Architectural accuracy update. |
| `tests/test_audit_forensic_remediations.py` | `tests/test_audit_forensic_remediations.py` | Modified | Adds test latch isolation `reset_for_tests()` (DEF-06). | `pytest tests/test_audit_forensic_remediations.py` (11/11 PASS) | Public Test Suite | Clean — Test harness code. |
| `compliance_reports/defense_master_audit_receipt.json` | `compliance_reports/defense_master_audit_receipt.json` | Modified | Regenerated master defense audit evaluation receipt with verified gate outcomes. | `scripts/run_defense_audit.py` (10/10 PASS) | Public Compliance Record | Clean — Evaluation metrics and public commit hash only. |
| `compliance_reports/defense_master_audit_receipt.json.sig` | `compliance_reports/defense_master_audit_receipt.json.sig` | Modified | Cryptographic ML-DSA-87 signature over master audit receipt (VAS verified). | `scripts/run_defense_audit.py` (VAS verified) | Public Signature | Clean — 4627-byte public signature block. |
| `compliance_reports/signed_reproducible_build_receipt.json` | `compliance_reports/signed_reproducible_build_receipt.json` | Modified | Updated reproducible build verification receipt with embedded SHA-384 pins. | `scripts/verify_reproducible_build.py` (PASS) | Public Compliance Record | Clean — Public build digest. |
| `data/__init__.py` | `data/__init__.py` | Modified | Exports standardized `HashedIdentifierEngine` alongside legacy alias. | `python -c "import data"` | Public Source | Clean — No secrets or private paths. |
| `data/user_mgmt.py` | `data/user_mgmt.py` | Modified | Implements `HashedIdentifierEngine` and aliases `MilitaryGradeCrypto` (NOM-01). | `pytest tests/test_production_tier123_hardening.py` | Public Source | Clean — Cryptographic identifier hashing. |
| `secure_p2p.py` | `secure_p2p.py` | Modified | Standardizes identifier class to `HashedIdentifierEngine` with legacy alias, and adds CLI deprecation notice (Phase 2). | `python -c "import secure_p2p"`, `python secure_p2p.py --help` | Public Source | Clean — Cryptographic identifier hashing & deprecation note. |
| `scripts/generate_pqc_pki.py` | `scripts/generate_pqc_pki.py` | Created | Technical wrapper standardizing PQC PKI generation CLI entry point (NOM-08). | `python scripts/generate_pqc_pki.py` (PASS) | Public Tooling | Clean — Automated PKI hierarchy generator. |
| `scripts/verify_ratchet_performance.py` | `scripts/verify_ratchet_performance.py` | Created | Technical wrapper standardizing ratchet and security vector benchmark drill (NOM-07). | `python scripts/verify_ratchet_performance.py` (PASS) | Public Tooling | Clean — Internal cryptographic benchmark runner. |

---

## 2. Explicit Denylist of Local Files Excluded from Release

The following files and directories are strictly excluded from remote staging and publication:

| Excluded Path | Type | Reason for Exclusion |
|---|---|---|
| `docs/audit/` | Directory | Private internal audit registers, findings, logs, and sensitive operational notes. |
| `keys/audit_signer.mldsa87.sk` | File | Private cryptographic signing key; must never be published to remote Git. |
| `credentials/` | Directory | Local operational credentials. |
| `tests/credentials/` | Directory | Local mock test credentials. |
| `deploy_st2027/` | Directory | Local deployment packaging staging. |
| `secure_p2p_core/` | Directory | Local experimental scratchpad. |
| `notupload/` | Directory | Explicit local quarantine directory. |
| `config.json` | File | Local active network topology configuration. |
| `config_backup_*.json` | Files | Timestamped local configuration snapshots. |
| `peer_discovery_cache.json` | File | Local runtime mesh discovery cache. |
| `secure_p2p_audit.db*` | Files | Local runtime SQLite audit database. |
| `*.bat` | Files | Local Windows developer launch scripts. |
| `military_base_*.py` | Files | Local multi-node test scripts. |
| `rust_data_plane/target/` | Directory | Native compiled binary cache. |
| `ts_rt/target/` | Directory | Native compiled binary cache. |
| `sel4_baremetal/target/` | Directory | Native compiled binary cache. |
| `current_*.log` | Files | Local test execution logs. |

