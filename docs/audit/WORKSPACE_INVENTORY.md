# Comprehensive Workspace Inventory

**Audit Run ID:** `RUN-20261025-01`
**Date:** 2026-10-25
**Protocol:** Production Engineering and Forensic Verification v4.0
**Workspace Root:** `D:\code\Main_projects\p2p\p2p_6_1-26`

---

## 1. Inventory Summary by Status & Role

The repository workspace contains tracked source, tests, formal models, documentation, compliance artifacts, and local-only configuration/keys.

| Category | Count | Status | Publication Intent | Role & Operational Function |
|---|---|---|---|---|
| **Product Modules** | 303 | Tracked | Yes (Candidate) | Production source, cryptographic engines, orchestrator, CLI, network transports. |
| **Verification Tests** | 138 | Tracked | Yes (Candidate) | Pytest test suites covering unit, integration, property, and exploit regression checks. |
| **Verification Harnesses** | 4 | Tracked | Yes (Candidate) | CAVP/ACVP runners, master defense audit harness, drill runners. |
| **Formal Models** | 6 | Tracked | Yes (Candidate) | ProVerif 2.05 protocol models (`handshake_model.pv`, `st2027_pcs.pv`, etc.). |
| **Product Documentation** | 70 | Tracked | Yes (Candidate) | Markdown specifications, architectural guides, threat models in `docs/`. |
| **Compliance Artifacts** | 85 | Tracked | Yes (Selective) | CBOM/SBOM catalogs, signed audit receipts, FIPS submittals in `compliance_reports/`. |
| **Local Audit Artifacts** | 40+ | Tracked | Internal / Audit Only | Private audit registers, logs, findings, verification reports in `docs/audit/`. |
| **Ignored Local Build Caches** | Many | Ignored | Excluded | `rust_data_plane/target/`, `ts_rt/target/`, `sel4_baremetal/target/`, `__pycache__/`. |
| **Local Keys & Credentials** | 4+ | Ignored | Strictly Excluded | `credentials/`, `tests/credentials/`, `keys/audit_signer.mldsa87.sk` (private keys). |
| **Local Runtime Config & DB** | 6+ | Ignored | Excluded | `config.json`, `config_backup_*.json`, `secure_p2p_audit.db`, `peer_discovery_cache.json`. |
| **Operational Launch Scripts** | 6+ | Ignored | Excluded | `launch_two_terminals.bat`, `start_terminal_alpha.bat`, `military_base_alpha.py`. |
| **Total Tracked Scope** | **606** | **Tracked** | **Controlled Release** | **Full Git tree tracked and audited.** |

---

## 2. Product Modules Scope & Classification

| Module ID | Module Name | Primary Path / Files | Tracked Files | Role & Dependencies | Inspection Status | Release Status |
|---|---|---|---|---|---|---|
| M-01 | `crypto_pqc` | `pqc_algorithms.py`, `liboqs_wrapper.py`, `cnsa2_policy_engine.py`, `crypto/` | 15 | Native PQC KEM & Signatures (FIPS 203/204/205) via `oqs.dll` | Fully Inspected | Release Eligible |
| M-02 | `key_management_pki` | `sovereign_pki.py`, `sovereign_ca.py`, `pki_manager.py`, `hybrid_kex.py` | 19 | Post-Quantum PKI, Certificate Authority, enrollment, CRL | Fully Inspected | Release Eligible |
| M-03 | `ratchet_kex_protocol` | `double_ratchet.py`, `unified_secure_pipeline.py`, `noise_pq.py`, `ratchet_tree.py` | 10 | Ephemeral KEX, Double Ratchet, Continuous Epoch Ratchet (CER) | Fully Inspected | Release Eligible |
| M-04 | `tls_channel` | `tls_channel_manager.py`, `tls_certificate_pinning.py`, `tls_session_resumption.py` | 4 | Mutual TLS channel wrapping, certificate pinning, session tickets | Fully Inspected | Release Eligible |
| M-05 | `transport_anonymity` | `transport_anonymity.py`, `mixnet_router.py`, `traffic_padding.py`, `anonymity_network.py` | 11 | Mixnet onion routing, constant-rate packetizers, chaff generation | Fully Inspected | Release Eligible |
| M-06 | `mesh_ddil_networking` | `ad_hoc_mesh.py`, `ddil_transport.py`, `dtn_bundle.py`, `mesh_routing.py` | 12 | Disruption-Tolerant Networking (DTN), ad-hoc mesh routing | Fully Inspected | Release Eligible |
| M-07 | `host_runtime_attestation`| `tpm_quote.py`, `tpm_nv_manager.py`, `runtime_attestation.py`, `tee_manager.py` | 23 | TPM 2.0 endorsement quotes, NV anti-rollback, TEE attestation | Fully Inspected | Release Eligible |
| M-08 | `rust_data_plane` | `rust_data_plane/src/*.rs`, `Cargo.toml` | 37 | High-speed native Rust data plane, zero-copy ring buffers | Fully Inspected | Release Eligible |
| M-09 | `memory_security` | `secure_memory_wiper.py`, `memlock.py`, `anti_dump.py`, `process_protector.py` | 9 | DoD 5220.22-M zeroization, `VirtualLock`, memory sanitization | Fully Inspected | Release Eligible |
| M-10 | `messaging_file_transfer` | `file_transfer.py`, `messaging/`, `chunked_transfer.py`, `integrity_verifier.py` | 17 | E2E encrypted messaging, chunked file transfer, resume logic | Fully Inspected | Release Eligible |
| M-11 | `system_hardening_integrity`| `production_gate.py`, `system_hardening.py`, `process_mitigations.py`, `exploit_mitigations.py` | 18 | DEP, ASLR, ACG, CFG exploit mitigations, tamper tripwires | Fully Inspected | Release Eligible |
| M-12 | `tactical_command_cjadc2`| `cjadc2_allied_gateway.py`, `cot_tactical_adapter.py`, `nc3_emergency_action.py` | 14 | Cursor-on-Target (CoT), Emergency Action Messages, NC3 dual custody | Fully Inspected | Release Eligible |
| M-13 | `audit_threat_monitoring`| `audit_logger.py`, `hash_chain.py`, `siem_exporter.py`, `threat_detector.py` | 18 | Tamper-evident hash chaining, SIEM export, intrusion detection | Fully Inspected | Release Eligible |
| M-14 | `security_framework` | `security_policy.py`, `cnsa_purity.py`, `defense_gate.py`, `compliance_engine.py` | 16 | CNSA 2.0 purity rules, classification boundaries, policy gates | Fully Inspected | Release Eligible |
| M-15 | `orchestrator_application`| `destroyer.py`, `core/orchestrator.py`, `secure_p2p.py`, `node.py` | 17 | Core node lifecycle, CLI entry points, daemon orchestration | Fully Inspected | Release Eligible |
| M-16 | `ui_presentation` | `ui/`, `console_dashboard.py`, `terminal_ui.py` | 7 | Curses/rich terminal console, status display | Fully Inspected | Release Eligible |
| M-17 | `utilities_support` | `config_loader.py`, `network_utils.py`, `logger.py`, `helpers.py` | 22 | Configuration parsing, logging formatters, network helpers | Fully Inspected | Release Eligible |
| M-18 | `operational_scripts` | `scripts/` (deploy, audit, drill, verify scripts) | 34 | Automated test harnesses, pin auditors, drills, PKI generators | Fully Inspected | Release Eligible |

---

## 3. Ignored and Local-Only File Register

The following items are ignored by Git or exist locally without remote publication intent:

| Item Path | Type | Sensitivity Assessment | Exclusion Rationale |
|---|---|---|---|
| `keys/audit_signer.mldsa87.sk` | Secret Key | High (Signing Key) | ML-DSA-87 private signing key used for local compliance drill signing; strictly excluded from release. |
| `keys/audit_signer.mldsa87.pk` | Public Key | Low | Public verification key; kept in `keys/` locally. |
| `credentials/` | Directory | High | Local environment and operational test credentials; strictly excluded from publication. |
| `tests/credentials/` | Directory | High | Local mock credentials for automated testing; strictly excluded from publication. |
| `deploy_st2027/` | Directory | Medium | Local deployment packaging staging; excluded from publication. |
| `secure_p2p_core/` | Directory | Medium | Local experimental prototype scratchpad; excluded from publication. |
| `notupload/` | Directory | Medium | Explicit local quarantine folder for non-public assets. |
| `config.json` | Config | Low-Medium | Active node operational configuration; excluded to protect local network topology. |
| `config_backup_*.json` | Config | Low-Medium | Timestamped configuration backups; excluded. |
| `peer_discovery_cache.json` | Cache | Low | Dynamic mesh peer endpoint discovery cache; generated at runtime. |
| `secure_p2p_audit.db*` | SQLite DB | Low-Medium | Local SQLite database recording operational audit logs; runtime data. |
| `launch_two_terminals.bat` | Script | Low | Local developer batch script; excluded from release. |
| `start_terminal_*.bat` | Script | Low | Local developer test launch scripts; excluded from release. |
| `military_base_*.py` | Script | Low-Medium | Local simulated multi-node test harnesses; excluded from release. |
| `rust_data_plane/target/` | Build Cache | None | Compiled native binaries (`.exe`, `.rlib`, `.pdb`); generated by `cargo`. |
| `ts_rt/target/` | Build Cache | None | Compiled native binaries; generated by `cargo`. |
| `sel4_baremetal/target/` | Build Cache | None | Compiled native binaries; generated by `cargo`. |
| `current_*.log` | Log Files | Low | Historical execution logs from test batteries and audits. |

---

## 4. Sensitive Content Review Result

- **No hardcoded secrets, production passwords, or unencrypted private keys** are present in any tracked files intended for release.
- All private cryptographic keys (`audit_signer.mldsa87.sk`, `credentials/`) are explicitly excluded via `.gitignore` and omitted from the publication manifest.
- All compliance affidavits and drill reports in `compliance_reports/` contain only public signatures and evaluation receipts, with zero private key disclosures.

