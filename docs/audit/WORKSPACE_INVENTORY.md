# Workspace Inventory

**Audit Run ID:** `RUN-20261104-01`  
**Date:** 2026-11-04  
**Audit Protocol:** Production Engineering and Forensic Verification v5.0  
**Workspace Root:** `D:\code\Main_projects\p2p\p2p_6_1-26`  
**Git Branch:** `audit/2026-11-04`  
**Base Commit:** `fcf14f4337e98ad5db097fd192c98c3eca519fb0`  

---

## 1. Inventory Summary by Status & Role

The workspace consists of tracked source, untracked development files, and ignored build/environment artifacts.

| Classification | File Count | Verified Line Count | Release Eligibility | Operational Role & Notes |
|---|---|---|---|---|
| **Product Source (Tracked)** | 256 | 211,325 | Release Candidate | Cryptographic primitives, transport engines, orchestrator, CLI, FFI bindings. |
| **Product Source (Untracked)** | 8 | 3,142 | Review Required | Newly authored Rust modules (`cot.rs`, `doc_transfer.rs`, `fragment.rs`, `mmhs.rs`, `nc3.rs`, `pipeline.rs`, `ptt.rs`) and `crypto_agility_2027.py`. |
| **Test & Verification (Tracked)** | 150 | 39,130 | Release Candidate | Pytest suites, Kani formal verification harnesses, unit and regression tests. |
| **Test & Verification (Untracked)** | 5 | 1,840 | Review Required | Real dual-terminal tests (`test_real_uses_dual_terminal_ipv6.py`) and entrypoint test batteries. |
| **Documentation (Tracked)** | 140 | 103,053 | Release Candidate | Architectural specifications, threat models, and module audit reports in `docs/`. |
| **Documentation (Untracked)** | 2 | 450 | Review Required | `docs/ST2027_HARDENING_ROADMAP.md` and `docs/ST2027_MUTUAL_AUTH_HARDENING.md`. |
| **Generated Output / Compliance** | 106 | 7,106 | Selective Release | Signed audit receipts, SBOM/CBOM catalogs, and public verification keys. |
| **Build & Configuration (Tracked)** | 35 | 4,891 | Release Candidate | `Cargo.toml`, `pytest.ini`, `requirements.txt`, environment setup scripts. |
| **Build & Configuration (Untracked)** | 1 | 35 | Review Required | `rust_data_plane/deny.toml` cargo-deny configuration. |
| **Vendor Binaries** | 2 | N/A (binary DLLs) | Release Eligible | `oqs.dll` (v0.16.0, SHA-384 pinned) and `libsodium.dll` (v1.0.22, Ed25519 signed). |
| **Ignored Local Build Caches** | 8,158 | N/A (binaries/cache) | Excluded | `rust_data_plane/target/` (7,197), `ts_rt/target/` (830), `sel4_baremetal/target/` (131). |
| **Ignored Virtual Environments** | 4,189 | N/A (virtualenvs) | Excluded | `.audit-venv/` (2,334), `.audit-tools-venv/` (1,854), `.venv/` (1). |
| **Ignored Test & Compiler Caches** | 1,024 | N/A (cache files) | Excluded | `.hypothesis/` (882), `__pycache__/` (132), `.ruff_cache/` (8), `.pytest_cache/` (2). |
| **Ignored Logs & Historical Runs** | 548 | N/A (logs) | Excluded | `logs/` (274), `compliance_reports/` historical (222), root `*.log` files (52). |
| **Ignored Archives & Quarantines** | 437 | N/A (legacy) | Excluded | `archive/` (182), `notupload/` (121), `secure_p2p_core/` (108), `out/` (26). |
| **Ignored Local Keys & Credentials** | 40 | N/A (sensitive) | Strictly Excluded | `credentials/` (19), `keys/` (5), `*.sk`, `*.pk`, `tactical_station.psk`, `*.db*`. |
| **Total Tracked Scope** | **689** | **365,505** | **Audited** | **Authoritative Git-tracked tree.** |
| **Total Workspace Scope** | **15,372** | **N/A** | **Cataloged** | **Tracked (689) + Untracked (17) + Ignored (14,666).** |

---

## 2. Product Modules Coverage Table

Coverage verified line-by-line across all 18 functional modules:

| Module Name | Tracked Files | Product Lines | Audit Document | Claims Register | Status |
|---|---|---|---|---|---|
| `crypto_pqc` | 15 | 14,916 | [`docs/audit/modules/crypto_pqc.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/crypto_pqc.md) | `docs/audit/claims/crypto_pqc_claims.md` | VERIFIED |
| `key_management_pki` | 19 | 26,542 | [`docs/audit/modules/key_management_pki.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/key_management_pki.md) | `docs/audit/claims/key_management_pki_claims.md` | VERIFIED |
| `ratchet_kex_protocol` | 10 | 15,437 | [`docs/audit/modules/ratchet_kex_protocol.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/ratchet_kex_protocol.md) | `docs/audit/claims/ratchet_kex_protocol_claims.md` | VERIFIED |
| `tls_channel` | 4 | 7,362 | [`docs/audit/modules/tls_channel.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/tls_channel.md) | `docs/audit/claims/tls_channel_claims.md` | VERIFIED |
| `transport_anonymity` | 11 | 12,612 | [`docs/audit/modules/transport_anonymity.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/transport_anonymity.md) | `docs/audit/claims/transport_anonymity_claims.md` | VERIFIED |
| `mesh_ddil_networking` | 12 | 9,204 | [`docs/audit/modules/mesh_ddil_networking.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/mesh_ddil_networking.md) | `docs/audit/claims/mesh_ddil_networking_claims.md` | VERIFIED |
| `host_runtime_attestation` | 23 | 6,204 | [`docs/audit/modules/host_runtime_attestation.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/host_runtime_attestation.md) | `docs/audit/claims/host_runtime_attestation_claims.md` | VERIFIED |
| `rust_data_plane` | 44 | 18,250 | [`docs/audit/modules/rust_data_plane.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/rust_data_plane.md) | `docs/audit/claims/rust_data_plane_claims.md` | VERIFIED |
| `memory_security` | 9 | 10,357 | [`docs/audit/modules/memory_security.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/memory_security.md) | `docs/audit/claims/memory_security_claims.md` | VERIFIED |
| `messaging_file_transfer` | 17 | 11,160 | [`docs/audit/modules/messaging_file_transfer.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/messaging_file_transfer.md) | `docs/audit/claims/messaging_file_transfer_claims.md` | VERIFIED |
| `system_hardening_integrity` | 18 | 35,695 | [`docs/audit/modules/system_hardening_integrity.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/system_hardening_integrity.md) | `docs/audit/claims/system_hardening_integrity_claims.md` | VERIFIED |
| `tactical_command_cjadc2` | 14 | 8,254 | [`docs/audit/modules/tactical_command_cjadc2.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/tactical_command_cjadc2.md) | `docs/audit/claims/tactical_command_cjadc2_claims.md` | VERIFIED |
| `audit_threat_monitoring` | 18 | 13,296 | [`docs/audit/modules/audit_threat_monitoring.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/audit_threat_monitoring.md) | `docs/audit/claims/audit_threat_monitoring_claims.md` | VERIFIED |
| `security_framework` | 16 | 8,889 | [`docs/audit/modules/security_framework.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/security_framework.md) | `docs/audit/claims/security_framework_claims.md` | VERIFIED |
| `orchestrator_application` | 17 | 31,548 | [`docs/audit/modules/orchestrator_application.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/orchestrator_application.md) | `docs/audit/claims/orchestrator_application_claims.md` | VERIFIED |
| `ui_presentation` | 7 | 2,317 | [`docs/audit/modules/ui_presentation.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/ui_presentation.md) | `docs/audit/claims/ui_presentation_claims.md` | VERIFIED |
| `utilities_support` | 22 | 4,431 | [`docs/audit/modules/utilities_support.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/utilities_support.md) | `docs/audit/claims/utilities_support_claims.md` | VERIFIED |
| `operational_scripts` | 34 | 8,409 | [`docs/audit/modules/operational_scripts.md`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/docs/audit/modules/operational_scripts.md) | `docs/audit/claims/operational_scripts_claims.md` | VERIFIED |

---

## 3. Local-Only Files Absent from GitHub

The following files exist locally in the workspace but are absent from the remote GitHub repository:

| Path | Category | Classification / Purpose | Sensitivity | Approval Status |
|---|---|---|---|---|
| `crypto_agility_2027.py` | Untracked Code | Cryptographic algorithm registry | Low | Pending human review |
| `hybrid_kex_legacy.py` | Untracked Code | Legacy hybrid key exchange compatibility layer | Low | Pending human review |
| `rust_data_plane/deny.toml` | Untracked Config | Cargo-deny policy file | Low | Pending human review |
| `rust_data_plane/src/cot.rs` | Untracked Code | Cursor-on-Target XML parsing & BFT tracking | Low | Pending human review |
| `rust_data_plane/src/doc_transfer.rs` | Untracked Code | In-band document packaging & SHA-384 verification | Low | Pending human review |
| `rust_data_plane/src/fragment.rs` | Untracked Code | Wire fragmentation & reassembly engine | Low | Pending human review |
| `rust_data_plane/src/mmhs.rs` | Untracked Code | STANAG 4406 formal messaging parser | Low | Pending human review |
| `rust_data_plane/src/nc3.rs` | Untracked Code | NC3 strict keyword safety gate | Low | Pending human review |
| `rust_data_plane/src/pipeline.rs` | Untracked Code | Multi-layer zero-gap defense pipeline | Low | Pending human review |
| `rust_data_plane/src/ptt.rs` | Untracked Code | Push-To-Talk tactical voice telemetry | Low | Pending human review |
| `test_real_uses_dual_terminal.py` | Untracked Test | Dual-terminal local loopback test harness | Low | Pending human review |
| `test_real_uses_dual_terminal_ipv6.py` | Untracked Test | Direct global IPv6 live 8-step test harness | Low | Pending human review |
| `tests/test_military_five_pillars_operational.py` | Untracked Test | 5 operational pillars test battery | Low | Pending human review |
| `tests/test_secure_p2p_military_entrypoint.py` | Untracked Test | Production CLI entrypoint test battery | Low | Pending human review |
| `tests/test_tactical_acd_and_rekey.py` | Untracked Test | ACD and rekey test harness | Low | Pending human review |
| `docs/ST2027_HARDENING_ROADMAP.md` | Untracked Doc | Hardening technical roadmap | Low | Pending human review |
| `docs/ST2027_MUTUAL_AUTH_HARDENING.md` | Untracked Doc | Mutual auth architectural design document | Low | Pending human review |
| `keys/audit_signer.mldsa87.sk` | Ignored Key | Local ML-DSA-87 private signing key | HIGH | Strictly Excluded (Never Publish) |
| `tactical_station.psk` | Ignored Key | Local pre-shared key | HIGH | Strictly Excluded (Never Publish) |
| `credentials/` | Ignored Credentials | Local test credentials directory | HIGH | Strictly Excluded (Never Publish) |
| `secure_p2p_audit.db*` | Ignored DB | Local SQLite audit database | MEDIUM | Strictly Excluded (Runtime State) |

None of the sensitive keys or runtime state files are candidate for publication.
