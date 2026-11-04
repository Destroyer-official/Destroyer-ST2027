# Phase 0 - In-Scope File Inventory

Scope is `git ls-files` at audit time: 692 tracked files. Untracked, ignored, build-output, cache, and secret files are excluded.

Line counts are computed from the tracked bytes; a file without a trailing newline counts its final partial line. Purposes for source files are taken from the module docstring or leading comment, not inferred from the filename. Restricted or promotional terms inside quoted purposes are replaced with `[restricted-term]`; terms inside tracked file paths are left unchanged and cataloged in `discrepancies.md`.

| Path | Language | Lines | Factual purpose | Module |
|---|---|---|---|---|
| `.gitattributes` | Other | 15 | Git attribute rules for line endings and binary handling. | `utilities_support` |
| `.github/workflows/defense_ci.yml` | YAML | 398 | GitHub Actions workflow: CNSA 2.0 & Defense Hardening CI (2027+ L5+ Pipeline) | `operational_scripts` |
| `.github/workflows/kani-proofs.yml` | YAML | 44 | GitHub Actions workflow: Kani Proofs (Linux, CBMC-backed) | `operational_scripts` |
| `.github/workflows/oqs-rebuild.yml` | YAML | 136 | GitHub Actions workflow: Rebuild oqs.dll (liboqs 0.16.0, Windows) | `operational_scripts` |
| `.gitignore` | Other | 222 | Git ignore patterns for build output, caches, keys, and local files. | `utilities_support` |
| `LICENSE` | Other | 21 | License text: MIT License | `utilities_support` |
| `README.md` | Markdown | 890 | [restricted-term] Post-Quantum Communications Architecture (ST2027) | `documentation` |
| `SECURITY.md` | Markdown | 51 | Security Policy & Vulnerability Disclosure | `documentation` |
| `active_cyber_defense.py` | Python | 570 | active_cyber_defense.py | `audit_threat_monitoring` |
| `acvp_validation_harness.py` | Python | 538 | FIPS 140-3 ACVP / CAVP Cryptographic Algorithm Validation Harness | `verification_evidence` |
| `air_gapped_operation.py` | Python | 2083 | Air-Gapped Operation and Isolated Node Key Provisioning Subsystem | `system_hardening_integrity` |
| `anonymous_identity_manager.py` | Python | 1026 | Anonymous Identity Manager for Secure P2P Communication. | `transport_anonymity` |
| `anti_forensics.py` | Python | 1155 | Anti-Forensics and Emergency Media Sanitization Engine | `system_hardening_integrity` |
| `audit_logger.py` | Python | 22 | Audit Logger re-export module for backward compatibility. | `audit_threat_monitoring` |
| `audit_logging_system.py` | Python | 1239 | Python source module with no module docstring. | `audit_threat_monitoring` |
| `balanced_logging.py` | Python | 268 | Balanced Logging Configuration for Secure P2P | `audit_threat_monitoring` |
| `base.py` | Python | 257 | Base module class for all P2P modules. | `orchestrator_application` |
| `byzantine_mesh_consensus.py` | Python | 972 | byzantine_mesh_consensus.py | `mesh_ddil_networking` |
| `ca_services.py` | Python | 2594 | Python source module with no module docstring. | `key_management_pki` |
| `cato_continuous_monitoring_engine.py` | Python | 307 | cato_continuous_monitoring_engine.py | `audit_threat_monitoring` |
| `certs/config_signer.pub` | Public key | 3 | Public key file (116 bytes). | `key_management_pki` |
| `certs/crl.json` | JSON | 12 | JSON object; top-level keys: crl, signature_algorithm, signature_hex | `key_management_pki` |
| `certs/ek_roots/README.md` | Markdown | 5 | Trusted TPM Endorsement Key (EK) Root CA Certificates | `key_management_pki` |
| `certs/key_ceremony_affidavit.json` | JSON | 70 | JSON object; top-level keys: affidavit_metadata, ceremony_custodian_quorum, enrolled_root_credentials, hardware_root_of_trust, verdict | `key_management_pki` |
| `certs/node_alpha.json` | JSON | 24 | JSON object; top-level keys: certificate_type, tbs_data, signature_algorithm, signature_hex | `key_management_pki` |
| `certs/node_bravo.json` | JSON | 24 | JSON object; top-level keys: certificate_type, tbs_data, signature_algorithm, signature_hex | `key_management_pki` |
| `certs/pki_manifest.json` | JSON | 34 | JSON object; top-level keys: pki_version, generation_timestamp, standard_compliance, root_authority, merkle_root, artifacts | `key_management_pki` |
| `certs/sbom_mldsa87_signer.pub` | Binary | 8 | Binary file (2592 bytes, SHA-256 0b1c503c08e27085...). | `key_management_pki` |
| `certs/sovereign_root_ca.json` | JSON | 22 | JSON object; top-level keys: certificate_type, subject, issuer, serial_number, not_before, not_after, signature_algorithm, classical_anchor | `key_management_pki` |
| `certs/sovereign_sub_ca.json` | JSON | 20 | JSON object; top-level keys: certificate_type, subject, issuer, serial_number, not_before, not_after, signature_algorithm, public_key_hex | `key_management_pki` |
| `cjadc2_allied_gateway.py` | Python | 863 | cjadc2_allied_gateway.py | `tactical_command_cjadc2` |
| `cjadc2_cross_domain_guard.py` | Python | 482 | cjadc2_cross_domain_guard.py | `tactical_command_cjadc2` |
| `cjadc2_tactical_cot.py` | Python | 347 | cjadc2_tactical_cot.py | `tactical_command_cjadc2` |
| `cng_crypto.py` | Python | 646 | cng_crypto.py — Validated-provider cryptographic backend on Windows. | `key_management_pki` |
| `cng_platform.py` | Python | 250 | cng_platform.py — TPM-backed device-key custody via the Windows CNG | `key_management_pki` |
| `cnsa2_policy_engine.py` | Python | 687 | CNSA 2.0 Policy Engine - Strict Enforcement | `crypto_pqc` |
| `cnsa_purity.py` | Python | 261 | cnsa_purity.py — CNSA 2.0 strictness enforcement for the [restricted-term] path. | `crypto_pqc` |
| `compliance_reports/active_cyber_defense_report.json` | JSON | 62 | JSON object; top-level keys: active_cyber_defense_assessment | `compliance_artifacts` |
| `compliance_reports/active_cyber_defense_report.json.mldsa87.pub` | Binary | 9 | Binary file (2592 bytes, SHA-256 cebea62be9370fa7...). | `compliance_artifacts` |
| `compliance_reports/active_cyber_defense_report.json.mldsa87.sig` | Binary | 20 | Binary file (4627 bytes, SHA-256 125064a1b15c3449...). | `compliance_artifacts` |
| `compliance_reports/acvp_cavp_validation_report.json` | JSON | 167 | JSON object; top-level keys: metadata, summary, algorithms_validated, results | `compliance_artifacts` |
| `compliance_reports/acvp_cavp_validation_report.json.mldsa87.pub` | Binary | 9 | Binary file (2592 bytes, SHA-256 cebea62be9370fa7...). | `compliance_artifacts` |
| `compliance_reports/acvp_cavp_validation_report.json.mldsa87.sig` | Binary | 16 | Binary file (4627 bytes, SHA-256 447d97971632b73e...). | `compliance_artifacts` |
| `compliance_reports/ato_authorization_decision.json` | JSON | 98 | JSON object; top-level keys: assessment_kind, metadata, evaluation_summary, gate_evaluations, authorization_decision | `compliance_artifacts` |
| `compliance_reports/byzantine_consensus_receipt.json` | JSON | 24 | JSON object; top-level keys: byzantine_consensus_attestation | `compliance_artifacts` |
| `compliance_reports/byzantine_consensus_receipt.json.mldsa87.pub` | Binary | 14 | Binary file (2592 bytes, SHA-256 e43cd1dabca8a9c9...). | `compliance_artifacts` |
| `compliance_reports/byzantine_consensus_receipt.json.mldsa87.sig` | Binary | 21 | Binary file (4627 bytes, SHA-256 534fbbbf921e2d48...). | `compliance_artifacts` |
| `compliance_reports/canary_pilot_telemetry.json` | JSON | 51 | JSON object; top-level keys: deployment_id, standards, timestamp_utc, nodes, probes, overall_status, summary | `compliance_artifacts` |
| `compliance_reports/cavp_validation_report.json` | JSON | 147 | JSON object; top-level keys: validation_program, module_name, module_version, target_security_level, evaluation_timestamp, operational_environment, tests_executed, tests_passed | `compliance_artifacts` |
| `compliance_reports/cbom.json` | JSON | 196 | JSON object; top-level keys: cbom_version, generated_utc, policy_basis, components, live_verification | `compliance_artifacts` |
| `compliance_reports/cbom.json.mldsa87.pub` | Binary | 8 | Binary file (2592 bytes, SHA-256 0b1c503c08e27085...). | `compliance_artifacts` |
| `compliance_reports/cbom.json.mldsa87.sig` | Binary | 25 | Binary file (4627 bytes, SHA-256 65699fe923428c51...). | `compliance_artifacts` |
| `compliance_reports/cjadc2_allied_gateway_report.json` | JSON | 79 | JSON object; top-level keys: content_disarm_reconstruction_profile, gateway_id, report_id, standard, statistics, supported_alliances, supported_partners, timestamp | `compliance_artifacts` |
| `compliance_reports/cjadc2_allied_gateway_report.json.mldsa87.pub` | Binary | 9 | Binary file (2592 bytes, SHA-256 cebea62be9370fa7...). | `compliance_artifacts` |
| `compliance_reports/cjadc2_allied_gateway_report.json.mldsa87.sig` | Binary | 27 | Binary file (4627 bytes, SHA-256 9c443621cb4fcd3c...). | `compliance_artifacts` |
| `compliance_reports/cjadc2_cross_domain_audit.json` | JSON | 41 | JSON object; top-level keys: cjadc2_cross_domain_security_audit | `compliance_artifacts` |
| `compliance_reports/cjadc2_cross_domain_audit.json.mldsa87.pub` | Binary | 15 | Binary file (2592 bytes, SHA-256 69bcd2435816109d...). | `compliance_artifacts` |
| `compliance_reports/cjadc2_cross_domain_audit.json.mldsa87.sig` | Binary | 21 | Binary file (4627 bytes, SHA-256 bb5d7a5d7c4d2338...). | `compliance_artifacts` |
| `compliance_reports/cjadc2_data_fabric_drill_report.json` | JSON | 94 | JSON object; top-level keys: drill_id, timestamp_utc, standard_framework, lifecycle_phase, probes, overall_status, signature_metadata, summary | `compliance_artifacts` |
| `compliance_reports/cjadc2_data_fabric_drill_report.json.mldsa87.pub` | Binary | 6 | Binary file (2592 bytes, SHA-256 d60510f38428b1c7...). | `compliance_artifacts` |
| `compliance_reports/cjadc2_data_fabric_drill_report.json.mldsa87.sig` | Binary | 21 | Binary file (4627 bytes, SHA-256 a748261f05d56193...). | `compliance_artifacts` |
| `compliance_reports/cmvp_fips140_3_submittal.json` | JSON | 62 | JSON object; top-level keys: document_kind, revision_note_20260921, cmvp_submittal_metadata, fips_140_3_security_levels_by_section, cryptographic_boundary, roles_and_services, cavp_validation_refer... | `compliance_artifacts` |
| `compliance_reports/cmvp_fips140_3_submittal.json.mldsa87.pub` | Binary | 8 | Binary file (2592 bytes, SHA-256 0b1c503c08e27085...). | `compliance_artifacts` |
| `compliance_reports/cmvp_fips140_3_submittal.json.mldsa87.sig` | Binary | 18 | Binary file (4627 bytes, SHA-256 c3d00f7864d4b413...). | `compliance_artifacts` |
| `compliance_reports/conops_operational_profile.json` | JSON | 99 | JSON object; top-level keys: $schema, conops_metadata, operational_environments, operational_roles, operational_modes | `compliance_artifacts` |
| `compliance_reports/crypto_agility_audit.json` | JSON | 53 | JSON object; top-level keys: crypto_agility_maturity_audit | `compliance_artifacts` |
| `compliance_reports/crypto_agility_audit.json.mldsa87.pub` | Binary | 9 | Binary file (2592 bytes, SHA-256 9bdb17282d72b87d...). | `compliance_artifacts` |
| `compliance_reports/crypto_agility_audit.json.mldsa87.sig` | Binary | 17 | Binary file (4627 bytes, SHA-256 27dfcb183d6ed7e9...). | `compliance_artifacts` |
| `compliance_reports/csrmc_operations_report.json` | JSON | 59 | JSON object; top-level keys: csrmc_operations_phase_telemetry | `compliance_artifacts` |
| `compliance_reports/csrmc_operations_report.json.mldsa87.pub` | Binary | 11 | Binary file (2592 bytes, SHA-256 dbc824f5a783d26b...). | `compliance_artifacts` |
| `compliance_reports/csrmc_operations_report.json.mldsa87.sig` | Binary | 20 | Binary file (4627 bytes, SHA-256 8bf3feff8abe95d8...). | `compliance_artifacts` |
| `compliance_reports/csrmc_phase5_drill_report.json` | JSON | 90 | JSON object; top-level keys: drill_id, timestamp_utc, standard_framework, lifecycle_phase, probes, overall_status, signature_metadata, summary | `compliance_artifacts` |
| `compliance_reports/csrmc_phase5_drill_report.json.mldsa87.pub` | Binary | 12 | Binary file (2592 bytes, SHA-256 750894936f94716d...). | `compliance_artifacts` |
| `compliance_reports/csrmc_phase5_drill_report.json.mldsa87.sig` | Binary | 20 | Binary file (4627 bytes, SHA-256 e6c52dd173ead8e4...). | `compliance_artifacts` |
| `compliance_reports/cve_scan_offline.json` | JSON | 34 | JSON document. | `compliance_artifacts` |
| `compliance_reports/cyclonedx_cbom.json` | JSON | 323 | JSON object; top-level keys: $schema, bomFormat, specVersion, serialNumber, version, metadata, components | `compliance_artifacts` |
| `compliance_reports/cyclonedx_cbom.json.mldsa87.pub` | Binary | 8 | Binary file (2592 bytes, SHA-256 86b234cb7a92c7a6...). | `compliance_artifacts` |
| `compliance_reports/cyclonedx_cbom.json.mldsa87.sig` | Binary | 19 | Binary file (4627 bytes, SHA-256 9abf8b7898dffb60...). | `compliance_artifacts` |
| `compliance_reports/cyclonedx_sbom.json` | JSON | 233 | JSON object; top-level keys: bomFormat, specVersion, serialNumber, version, metadata, components | `compliance_artifacts` |
| `compliance_reports/cyclonedx_sbom.json.mldsa87.pub` | Binary | 8 | Binary file (2592 bytes, SHA-256 0b1c503c08e27085...). | `compliance_artifacts` |
| `compliance_reports/cyclonedx_sbom.json.mldsa87.sig` | Binary | 23 | Binary file (4627 bytes, SHA-256 069c4959b7d63ded...). | `compliance_artifacts` |
| `compliance_reports/defense_master_audit_receipt.json` | JSON | 73 | JSON object; top-level keys: timestamp_utc, commit, audit_version, overall_status, score, gates, signer_pk_sha3_256 | `compliance_artifacts` |
| `compliance_reports/defense_master_audit_receipt.json.pub` | Binary | 9 | Binary file (2592 bytes, SHA-256 cebea62be9370fa7...). | `compliance_artifacts` |
| `compliance_reports/defense_master_audit_receipt.json.sig` | Binary | 20 | Binary file (4627 bytes, SHA-256 3ee59f710e482810...). | `compliance_artifacts` |
| `compliance_reports/dod_zero_trust_assessment.json` | JSON | 370 | JSON object; top-level keys: dod_zero_trust_assessment | `compliance_artifacts` |
| `compliance_reports/dod_zero_trust_assessment.json.mldsa87.pub` | Binary | 9 | Binary file (2592 bytes, SHA-256 cebea62be9370fa7...). | `compliance_artifacts` |
| `compliance_reports/dod_zero_trust_assessment.json.mldsa87.sig` | Binary | 16 | Binary file (4627 bytes, SHA-256 a2157973f1bf6a51...). | `compliance_artifacts` |
| `compliance_reports/emergency_zeroization_audit.json` | JSON | 22 | JSON object; top-level keys: emergency_zeroization_audit | `compliance_artifacts` |
| `compliance_reports/emergency_zeroization_audit.json.mldsa87.pub` | Binary | 11 | Binary file (2592 bytes, SHA-256 42d276abc3abba12...). | `compliance_artifacts` |
| `compliance_reports/emergency_zeroization_audit.json.mldsa87.sig` | Binary | 18 | Binary file (4627 bytes, SHA-256 20a47e73279d55be...). | `compliance_artifacts` |
| `compliance_reports/independent_redteam_assessment.json` | JSON | 122 | JSON object; top-level keys: assessment_kind, revision_note_20260921, handling, assessment_metadata, executive_summary, adversarial_test_vectors, dod_zero_trust_7_pillars_evaluation, adversary_cost... | `compliance_artifacts` |
| `compliance_reports/independent_redteam_assessment.json.mldsa87.pub` | Binary | 10 | Binary file (2592 bytes, SHA-256 026729a4fbfe2153...). | `compliance_artifacts` |
| `compliance_reports/independent_redteam_assessment.json.mldsa87.sig` | Binary | 22 | Binary file (4627 bytes, SHA-256 ec828825973dc00f...). | `compliance_artifacts` |
| `compliance_reports/key_management_plan.json` | JSON | 61 | JSON object; top-level keys: $schema, kmp_metadata, key_inventory, lifecycle_rules | `compliance_artifacts` |
| `compliance_reports/niap_common_criteria_matrix.json` | JSON | 110 | JSON object; top-level keys: matrix_metadata, security_functional_requirements, security_assurance_requirements | `compliance_artifacts` |
| `compliance_reports/niap_common_criteria_matrix.json.mldsa87.pub` | Binary | 9 | Binary file (2592 bytes, SHA-256 84e1600f87087a6f...). | `compliance_artifacts` |
| `compliance_reports/niap_common_criteria_matrix.json.mldsa87.sig` | Binary | 23 | Binary file (4627 bytes, SHA-256 89eb01243ede41ec...). | `compliance_artifacts` |
| `compliance_reports/oscal_sar_cato.json` | JSON | 281 | JSON object; top-level keys: assessment-results | `compliance_artifacts` |
| `compliance_reports/oscal_sar_cato.json.mldsa87.pub` | Binary | 11 | Binary file (2592 bytes, SHA-256 2a7f7d5c28dfaa7b...). | `compliance_artifacts` |
| `compliance_reports/oscal_sar_cato.json.mldsa87.sig` | Binary | 27 | Binary file (4627 bytes, SHA-256 1103319df38539ed...). | `compliance_artifacts` |
| `compliance_reports/oscal_ssp_cnsa2.json` | JSON | 255 | JSON object; top-level keys: system-security-plan | `compliance_artifacts` |
| `compliance_reports/oscal_ssp_cnsa2.json.mldsa87.pub` | Binary | 11 | Binary file (2592 bytes, SHA-256 e5c1debabab5679b...). | `compliance_artifacts` |
| `compliance_reports/oscal_ssp_cnsa2.json.mldsa87.sig` | Binary | 21 | Binary file (4627 bytes, SHA-256 016cf4a27510fe1c...). | `compliance_artifacts` |
| `compliance_reports/provenance.intoto.jsonl` | JSON Lines | 1 | JSON object; top-level keys: _type, subject, predicateType, predicate, _note | `compliance_artifacts` |
| `compliance_reports/red_team_drill_report.json` | JSON | 53 | JSON object; top-level keys: metadata, summary, drill_results | `compliance_artifacts` |
| `compliance_reports/sbom/cbom.json` | JSON | 196 | JSON object; top-level keys: cbom_version, generated_utc, policy_basis, components, live_verification | `compliance_artifacts` |
| `compliance_reports/sbom/cbom.json.mldsa87.pub` | Binary | 8 | Binary file (2592 bytes, SHA-256 0b1c503c08e27085...). | `compliance_artifacts` |
| `compliance_reports/sbom/cbom.json.mldsa87.sig` | Binary | 19 | Binary file (4627 bytes, SHA-256 ce99cb0c23575ae6...). | `compliance_artifacts` |
| `compliance_reports/sbom/cyclonedx_sbom.json` | JSON | 271 | JSON object; top-level keys: bomFormat, specVersion, serialNumber, version, metadata, components | `compliance_artifacts` |
| `compliance_reports/sbom/cyclonedx_sbom.json.mldsa87.pub` | Binary | 8 | Binary file (2592 bytes, SHA-256 0b1c503c08e27085...). | `compliance_artifacts` |
| `compliance_reports/sbom/cyclonedx_sbom.json.mldsa87.sig` | Binary | 23 | Binary file (4627 bytes, SHA-256 5d1915926d502bee...). | `compliance_artifacts` |
| `compliance_reports/sbom/spdx_sbom.json` | JSON | 391 | secure_p2p-sbom | `compliance_artifacts` |
| `compliance_reports/sbom/spdx_sbom.json.mldsa87.pub` | Binary | 8 | Binary file (2592 bytes, SHA-256 0b1c503c08e27085...). | `compliance_artifacts` |
| `compliance_reports/sbom/spdx_sbom.json.mldsa87.sig` | Binary | 23 | Binary file (4627 bytes, SHA-256 55f830773e8f90ed...). | `compliance_artifacts` |
| `compliance_reports/signed_reproducible_build_receipt.json` | JSON | 91 | JSON object; top-level keys: timestamp_utc, verification_standard, binaries, core_modules, sbom_status, overall_status, source_tree_merkle_root, critical_modules_manifest | `compliance_artifacts` |
| `compliance_reports/signed_reproducible_build_receipt.json.sig` | Binary | 18 | Binary file (4627 bytes, SHA-256 b0c55f2d4f86cbcb...). | `compliance_artifacts` |
| `compliance_reports/spdx_sbom.json` | JSON | 344 | secure_p2p-sbom | `compliance_artifacts` |
| `compliance_reports/spdx_sbom.json.mldsa87.pub` | Binary | 8 | Binary file (2592 bytes, SHA-256 0b1c503c08e27085...). | `compliance_artifacts` |
| `compliance_reports/spdx_sbom.json.mldsa87.sig` | Binary | 16 | Binary file (4627 bytes, SHA-256 a8d8cae6de12eb0b...). | `compliance_artifacts` |
| `compliance_reports/ssdf_self_attestation.json` | JSON | 171 | JSON object; top-level keys: attestation_kind, cisa_common_form_note, eo_reference, framework, generated_utc, practices, producer, product | `compliance_artifacts` |
| `compliance_reports/ssdf_self_attestation.json.mldsa87.pub` | Binary | 11 | Binary file (2592 bytes, SHA-256 12203d47aeecf19a...). | `compliance_artifacts` |
| `compliance_reports/ssdf_self_attestation.json.mldsa87.sig` | Binary | 22 | Binary file (4627 bytes, SHA-256 72e71c2d07d1f525...). | `compliance_artifacts` |
| `config.json.sig` | Binary | 3 | Binary file (64 bytes, SHA-256 9446dede49e472be...). | `utilities_support` |
| `config.py` | Python | 760 | Configuration management for the P2P system. | `utilities_support` |
| `config_production.json` | JSON | 95 | JSON object; top-level keys: _comment, _version, _classification, security_level, key_lifetime, enable_hsm, audit_logging, network | `utilities_support` |
| `config_production.json.sig` | Signature | 1 | Detached signature file (64 bytes). | `utilities_support` |
| `config_template.json` | JSON | 98 | JSON object; top-level keys: _comment, _version, _classification, security_level, key_lifetime, enable_hsm, audit_logging, network | `utilities_support` |
| `continuous_security_monitor.py` | Python | 1789 | ST2027 CONTINUOUS SECURITY MONITORING & ANOMALY DETECTION ENGINE | `audit_threat_monitoring` |
| `core/__init__.py` | Python | 10 | Core orchestration module. | `orchestrator_application` |
| `core/config.py` | Python | 110 | Configuration management for the P2P system. | `orchestrator_application` |
| `core/orchestrator.py` | Python | 1714 | SecureP2PChat orchestrator class. | `orchestrator_application` |
| `covert_channel_defense.py` | Python | 1385 | Covert Channel Mitigation and Traffic Normalization Subsystem | `transport_anonymity` |
| `critical_modules.hashes` | Other | 22 | Other file. | `system_hardening_integrity` |
| `critical_release.py` | Python | 389 | Two-person critical-release authority ([restricted-term]-release discipline). | `tactical_command_cjadc2` |
| `cross_platform_exception_handler.py` | Python | 1585 | Cross-Platform Exception Handler | `orchestrator_application` |
| `crypto/__init__.py` | Python | 10 | Cryptographic operations module. | `crypto_pqc` |
| `crypto/auth_tags.py` | Python | 233 | Authentication tag operations. | `crypto_pqc` |
| `crypto/kem.py` | Python | 382 | Key Encapsulation Mechanism (ML-KEM-1024). | `crypto_pqc` |
| `crypto/operations.py` | Python | 54 | Crypto operations coordinator. | `crypto_pqc` |
| `crypto/padding.py` | Python | 184 | secure padding operations. | `crypto_pqc` |
| `crypto/signatures.py` | Python | 259 | Signature operations (ML-DSA-87, SLH-DSA-256f). | `crypto_pqc` |
| `crypto_selftest.py` | Python | 325 | crypto_selftest.py — FIPS 140-3-style power-up self-tests + conditional | `crypto_pqc` |
| `cryptographic_agility.py` | Python | 1310 | Cryptographic Agility Framework - [restricted-term] 2026 Production Security | `orchestrator_application` |
| `cryptographic_errors.py` | Python | 768 | Cryptographic Error Hierarchy and Secure Error Reporting System | `orchestrator_application` |
| `csrmc_operations_monitor.py` | Python | 217 | csrmc_operations_monitor.py | `audit_threat_monitoring` |
| `data/__init__.py` | Python | 20 | Data management module. | `messaging_file_transfer` |
| `data/file_transfer.py` | Python | 645 | File transfer operations. | `messaging_file_transfer` |
| `data/manager.py` | Python | 45 | Data management coordinator. | `messaging_file_transfer` |
| `data/peer_mgmt.py` | Python | 272 | Peer management operations. | `messaging_file_transfer` |
| `data/user_mgmt.py` | Python | 606 | User management operations. | `messaging_file_transfer` |
| `data_models.py` | Python | 308 | Data models for the P2P system. | `orchestrator_application` |
| `decentralized_architecture.py` | Python | 3307 | Decentralized Distributed Hash Table (DHT) and Mesh Routing Subsystem | `transport_anonymity` |
| `dep_impl.py` | Python | 4437 | Data Execution Prevention (DEP) Implementation Module with NIST Level-5 Security | `orchestrator_application` |
| `dependency_security_verifier.py` | Python | 1023 | Dependency Integrity and Native Cryptographic Binary Verifier | `system_hardening_integrity` |
| `deploy/openssl_cnsa.cnf` | Other | 39 | Other file. | `tls_channel` |
| `destroyer.py` | Python | 501 | DESTROYER ST2027 — [restricted-term] DEFENSE COMMAND CENTER | `orchestrator_application` |
| `destroyer_node.py` | Python | 562 | DestroyerNode — Rust data-plane wrapper (opt-in, staging integration). | `orchestrator_application` |
| `destroyer_tactical_p2p.py` | Python | 37 | DESTROYER STRATEGIC P2P: [restricted-term] [restricted-term] COMMUNICATIONS NODE | `orchestrator_application` |
| `docs/ARCHITECTURE.md` | Markdown | 100 | System Architecture — [restricted-term] Post-Quantum Direct P2P Messaging | `documentation` |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md` | Markdown | 131 | ST2027: Architectural Comparison & [restricted-term] Enclave Analysis | `documentation` |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md` | Markdown | 376 | Concept of Operations (CONOPS): [restricted-term] [restricted-term] Tactical P2P Communications Mesh | `documentation` |
| `docs/DEFENSE_HARDENING_MASTER_PLAN.md` | Markdown | 685 | [restricted-term] Transmit 2027 (ST2027) — Defense Hardening Master Plan | `documentation` |
| `docs/EVALUATION_DOSSIER.md` | Markdown | 124 | [restricted-term] Transmit 2027 (ST2027) — Technical Evaluation Dossier | `documentation` |
| `docs/FIPS_140_3_SECURITY_POLICY.md` | Markdown | 104 | FIPS 140-3 Cryptographic Module Security Policy (CMSP) -- DRAFT | `documentation` |
| `docs/FIREWALL_IPV6.md` | Markdown | 35 | IPv6 Host Firewall Runbook — Direct P2P Listener Stealth | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md` | Markdown | 432 | [restricted-term] Forensic Security Audit — Current Evidence Report | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_REMEDIATION_PLAN.md` | Markdown | 37 | Destroyer-ST2027 Security Remediation Plan | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_3_REMEDIATION.md` | Markdown | 114 | Destroyer-ST2027: Third Independent Forensic Security Audit Remediation | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_4_REMEDIATION.md` | Markdown | 140 | Destroyer-ST2027: Fourth Forensic Security Audit Remediation | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md` | Markdown | 337 | Forensic Security Audit — Final Continuation Report | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md` | Markdown | 269 | [restricted-term] FORENSIC SECURITY AUDIT & ASSURANCE EVALUATION | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md` | Markdown | 59 | [restricted-term] Forensic Remediation & Hardening Plan | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_REPORT_2026_10_26.md` | Markdown | 92 | [restricted-term] Forensic Security Audit — Remediation & Verification Final Report | `documentation` |
| `docs/FULL_CODEBASE_SECURITY_REVIEW_2026_10.md` | Markdown | 135 | Full-Codebase Security Review — October 2026 | `documentation` |
| `docs/KEY_CEREMONY.md` | Markdown | 63 | Offline 3-of-5 Threshold CA Key Ceremony ([restricted-term]) | `documentation` |
| `docs/KEY_MANAGEMENT_PLAN_KMP.md` | Markdown | 73 | Cryptographic Key Management Plan (KMP) | `documentation` |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md` | Markdown | 169 | [restricted-term] [restricted-term] NC3 Deployment & Operations Manual | `documentation` |
| `docs/NIAP_COMMON_CRITERIA_SECURITY_TARGET.md` | Markdown | 47 | NIAP Common Criteria Security Target (ST) -- DRAFT (self-authored, pre-evaluation) | `documentation` |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md` | Markdown | 228 | [restricted-term] Transmit 2027 (ST2027) — High-Assurance Transport Architecture Specification for National Security Systems | `documentation` |
| `docs/OPEN_INTERNET_HARDENING_PLAN.md` | Markdown | 229 | OPEN-INTERNET HARDENING PLAN v2 — Direct IPv6 P2P (India ↔ US), No Middle Server | `documentation` |
| `docs/README.md` | Markdown | 122 | [restricted-term] Secure Communications Architecture — Documentation Index | `documentation` |
| `docs/RESTRUCTURE_PLAN.md` | Markdown | 240 | RESTRUCTURE PLAN — Professional [restricted-term] Project Layout | `documentation` |
| `docs/RUST_CORE.md` | Markdown | 172 | Rust Secure Core — Production Path (Python Kept as Reference/Backup) | `documentation` |
| `docs/SEL4_EAL6_PLUS_SOVEREIGN_APPLIANCE_SPEC.md` | Markdown | 222 | [restricted-term] Transmit 2027 (ST2027): EAL6+ seL4 [restricted-term] Hardware Appliance Specification & Master Implementation Plan | `documentation` |
| `docs/SOP.md` | Markdown | 75 | Program SOP — [restricted-term] Secure P2P Operations | `documentation` |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md` | Markdown | 183 | [restricted-term] Transmit 2027 (ST2027) — [restricted-term] High-Assurance Specification & Implementation Plan | `documentation` |
| `docs/ST2027_IMPLEMENTATION_PLAN.md` | Markdown | 112 | ST2027 Zero-Gap Implementation Plan — Maximum Cost-to-Break Doctrine | `documentation` |
| `docs/ST2027_RESEARCH_SOURCES_2026-09-30.md` | Markdown | 218 | ST2027 research source register | `documentation` |
| `docs/ST2027_SPEC.md` | Markdown | 283 | [restricted-term] Transmit 2027 (ST2027) — [restricted-term] High-Assurance Specification & Implementation Plan | `documentation` |
| `docs/ST2027_SPECIFICATION.md` | Markdown | 175 | Destroyer-ST2027 Protocol Specification: High-Assurance Post-Quantum Communications Architecture | `documentation` |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md` | Markdown | 74915 | VOLUME A — System Security Documentation ([restricted-term] Grade) | `documentation` |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md` | Markdown | 12366 | VOLUME C — Logic Flows, Mathematics, Wire Formats, Operations | `documentation` |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md` | Markdown | 351 | Technical Manual TM-ST2027-2027.1 | `documentation` |
| `docs/airgap_runbook.md` | Markdown | 126 | Air-Gap Runbook (short) | `documentation` |
| `docs/audit/00_inventory.md` | Markdown | 700 | Phase 0 - In-Scope File Inventory | `documentation` |
| `docs/audit/BASELINE.md` | Markdown | 151 | Baseline and Environment Inspection Record | `documentation` |
| `docs/audit/CHANGELOG.md` | Markdown | 30 | Audit Engineering Change Register (CHANGELOG) | `documentation` |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md` | Markdown | 257 | ST2027 Defense Scorecard 100/100 Master Implementation Plan & Technical Specification | `documentation` |
| `docs/audit/DOCUMENTATION_DISCREPANCIES.md` | Markdown | 27 | Documentation Discrepancies Register | `documentation` |
| `docs/audit/FINDINGS.md` | Markdown | 80 | Audit Findings Register | `documentation` |
| `docs/audit/KNOWN_LIMITATIONS.md` | Markdown | 40 | Known Technical Limitations & Operational Boundaries | `documentation` |
| `docs/audit/PROGRESS.md` | Markdown | 52 | Audit Execution Progress | `documentation` |
| `docs/audit/SECURITY_REVIEW.md` | Markdown | 65 | System Security Review & Cryptographic Architecture Assessment | `documentation` |
| `docs/audit/WORKSPACE_INVENTORY.md` | Markdown | 94 | Workspace Inventory | `documentation` |
| `docs/audit/claims/audit_threat_monitoring_claims.md` | Markdown | 19 | Module Claims Register: audit_threat_monitoring | `documentation` |
| `docs/audit/claims/crypto_pqc_claims.md` | Markdown | 16 | Claims Register: crypto_pqc | `documentation` |
| `docs/audit/claims/host_runtime_attestation_claims.md` | Markdown | 13 | Claims Register: Host Runtime and Platform Attestation Subsystem (`host_runtime_attestation`) | `documentation` |
| `docs/audit/claims/key_management_pki_claims.md` | Markdown | 21 | Claims Register: Key Management and PKI Subsystem (`key_management_pki`) | `documentation` |
| `docs/audit/claims/memory_security_claims.md` | Markdown | 19 | Module Claims Register: memory_security | `documentation` |
| `docs/audit/claims/mesh_ddil_networking_claims.md` | Markdown | 13 | Claims Register: Mesh and DDIL Networking Subsystem (`mesh_ddil_networking`) | `documentation` |
| `docs/audit/claims/messaging_file_transfer_claims.md` | Markdown | 19 | Module Claims Register: messaging_file_transfer | `documentation` |
| `docs/audit/claims/operational_scripts_claims.md` | Markdown | 22 | Module Claims Register: operational_scripts | `documentation` |
| `docs/audit/claims/orchestrator_application_claims.md` | Markdown | 27 | Module Claims Register: orchestrator_application | `documentation` |
| `docs/audit/claims/ratchet_kex_protocol_claims.md` | Markdown | 16 | Claims Register: Ratchet and Key Exchange Protocol Subsystem (`ratchet_kex_protocol`) | `documentation` |
| `docs/audit/claims/rust_data_plane_claims.md` | Markdown | 13 | Claims Register: Native Rust Data Plane Subsystem (`rust_data_plane`) | `documentation` |
| `docs/audit/claims/security_framework_claims.md` | Markdown | 19 | Module Claims Register: security_framework | `documentation` |
| `docs/audit/claims/system_hardening_integrity_claims.md` | Markdown | 19 | Module Claims Register: system_hardening_integrity | `documentation` |
| `docs/audit/claims/tactical_command_cjadc2_claims.md` | Markdown | 17 | Module Claims Register: tactical_command_cjadc2 | `documentation` |
| `docs/audit/claims/tls_channel_claims.md` | Markdown | 13 | Claims Register: TLS Channel Subsystem (`tls_channel`) | `documentation` |
| `docs/audit/claims/transport_anonymity_claims.md` | Markdown | 17 | Claims Register: Transport Anonymity and Traffic Shaping Subsystem (`transport_anonymity`) | `documentation` |
| `docs/audit/claims/ui_presentation_claims.md` | Markdown | 22 | Module Claims Register: ui_presentation | `documentation` |
| `docs/audit/claims/utilities_support_claims.md` | Markdown | 22 | Module Claims Register: utilities_support | `documentation` |
| `docs/audit/command_log.md` | Markdown | 72 | Audit Command Execution Log | `documentation` |
| `docs/audit/compliance_artifacts_audit.md` | Markdown | 91 | Compliance Artifacts & Cryptographic Attestation Audit | `documentation` |
| `docs/audit/discrepancies.md` | Markdown | 73 | Audit Discrepancies Register | `documentation` |
| `docs/audit/documentation_claims_matrix.md` | Markdown | 47 | Documentation Truth-in-Claims Matrix | `documentation` |
| `docs/audit/findings/DEF-01.md` | Markdown | 45 | Finding Report: DEF-01 — Allied Gateway Quarantine NameError | `documentation` |
| `docs/audit/findings/DEF-02.md` | Markdown | 39 | Finding Report: DEF-02 — Hardware CPU RNG Direct Bus Sampling | `documentation` |
| `docs/audit/findings/DEF-03.md` | Markdown | 39 | Finding Report: DEF-03 — TPM Endorsement Key Roots Provisioning | `documentation` |
| `docs/audit/findings/DEF-04.md` | Markdown | 36 | Finding Report: DEF-04 — Offline Vulnerability Scanning | `documentation` |
| `docs/audit/findings/DEF-05.md` | Markdown | 60 | Finding Report: DEF-05 — Coarse Timestamp LRU Eviction Bug | `documentation` |
| `docs/audit/findings/DEF-06.md` | Markdown | 36 | Finding Report: DEF-06 — Production Gate Test Latch Cross-Contamination | `documentation` |
| `docs/audit/findings/NOM-01_to_NOM-10.md` | Markdown | 37 | Finding Report: NOM-01 to NOM-10 — Promotional Terminology & Identifier Deprecation | `documentation` |
| `docs/audit/findings/SEC-01.md` | Markdown | 35 | Finding Report: SEC-01 — Upstream HQC-256 CVE Quarantine & Hash-Based Signature Safeguards | `documentation` |
| `docs/audit/index.md` | Markdown | 86 | Codebase Audit Index & Master Documentation | `documentation` |
| `docs/audit/modules/audit_threat_monitoring.md` | Markdown | 122 | Module Audit: audit_threat_monitoring | `documentation` |
| `docs/audit/modules/crypto_pqc.md` | Markdown | 137 | Module Documentation: crypto_pqc | `documentation` |
| `docs/audit/modules/host_runtime_attestation.md` | Markdown | 228 | Module Documentation: Host Runtime and Platform Attestation Subsystem (`host_runtime_attestation`) | `documentation` |
| `docs/audit/modules/key_management_pki.md` | Markdown | 398 | Module Documentation: Key Management and PKI Subsystem (`key_management_pki`) | `documentation` |
| `docs/audit/modules/memory_security.md` | Markdown | 142 | Module Audit: memory_security | `documentation` |
| `docs/audit/modules/mesh_ddil_networking.md` | Markdown | 236 | Module Documentation: Mesh and DDIL Networking Subsystem (`mesh_ddil_networking`) | `documentation` |
| `docs/audit/modules/messaging_file_transfer.md` | Markdown | 157 | Module Audit: messaging_file_transfer | `documentation` |
| `docs/audit/modules/operational_scripts.md` | Markdown | 165 | Module Documentation: operational_scripts | `documentation` |
| `docs/audit/modules/orchestrator_application.md` | Markdown | 182 | Module Documentation: orchestrator_application | `documentation` |
| `docs/audit/modules/ratchet_kex_protocol.md` | Markdown | 300 | Module Documentation: Ratchet and Key Exchange Protocol Subsystem (`ratchet_kex_protocol`) | `documentation` |
| `docs/audit/modules/rust_data_plane.md` | Markdown | 215 | Module Documentation: Native Rust Data Plane Subsystem (`rust_data_plane`) | `documentation` |
| `docs/audit/modules/security_framework.md` | Markdown | 134 | Module Audit: security_framework | `documentation` |
| `docs/audit/modules/system_hardening_integrity.md` | Markdown | 140 | Module Audit: system_hardening_integrity | `documentation` |
| `docs/audit/modules/tactical_command_cjadc2.md` | Markdown | 123 | Module Audit: tactical_command_cjadc2 | `documentation` |
| `docs/audit/modules/tls_channel.md` | Markdown | 214 | Module Documentation: TLS Channel Subsystem (`tls_channel`) | `documentation` |
| `docs/audit/modules/transport_anonymity.md` | Markdown | 271 | Module Documentation: Transport Anonymity and Traffic Shaping Subsystem (`transport_anonymity`) | `documentation` |
| `docs/audit/modules/ui_presentation.md` | Markdown | 139 | Module Documentation: ui_presentation | `documentation` |
| `docs/audit/modules/utilities_support.md` | Markdown | 143 | Module Documentation: utilities_support | `documentation` |
| `docs/audit/open_questions.md` | Markdown | 80 | Audit Open Questions & Architectural Decisions | `documentation` |
| `docs/audit/proposals.md` | Markdown | 59 | Audit Architectural & Protocol Proposals | `documentation` |
| `docs/audit/release/PUBLICATION_MANIFEST.md` | Markdown | 54 | Release Publication Manifest | `documentation` |
| `docs/audit/release/RELEASE_CANDIDATE.md` | Markdown | 45 | Release Candidate Specification: Destroyer-ST2027 Verified Fixes | `documentation` |
| `docs/audit/release/RELEASE_VERIFICATION.md` | Markdown | 62 | Release Gate & Post-Push Verification Record | `documentation` |
| `docs/audit/remediation_plan.md` | Markdown | 108 | Audit Remediation & Hardening Action Plan | `documentation` |
| `docs/audit/test-results/TEST_AND_BUILD_REPORT.md` | Markdown | 167 | [restricted-term] Test and Build Verification Report | `documentation` |
| `docs/audit/verification_evidence_audit.md` | Markdown | 85 | Verification Evidence & Formal Models Audit | `documentation` |
| `docs/current_audit_inventory.json` | JSON | 58 | JSON object; top-level keys: tracked_files, accessible_non_artifact_files, python_non_test, python_tests, rust_sources, extensions | `documentation` |
| `docs/deployment_hardening_guide.md` | Markdown | 81 | Deployment Hardening Guide (Production) | `documentation` |
| `docs/dll_ca_ceremony_receipt.json` | JSON | 27 | JSON object; top-level keys: ceremony, action, reason, timestamp_utc, ca_algorithm, anchor_pub_sha256, anchor_pub_sha512, dlls | `documentation` |
| `docs/formal/README.md` | Markdown | 73 | Formal Verification Models (ProVerif 2.05 & Kani) | `formal_verification` |
| `docs/formal/check.sh` | Shell | 49 | docs/formal/check.sh — ProVerif formal verification gate for ST2027. | `formal_verification` |
| `docs/formal/handshake_model.pv` | Other | 187 | Other file. | `formal_verification` |
| `docs/formal/nc3_dual_custody.pv` | Other | 237 | Other file. | `formal_verification` |
| `docs/formal/st2027_handshake.pv` | Other | 282 | Other file. | `formal_verification` |
| `docs/formal/st2027_pcs.pv` | Other | 191 | Other file. | `formal_verification` |
| `docs/hw_tpm_hsm_setup.md` | Markdown | 99 | TPM / HSM hardware setup (Linux + Windows) | `documentation` |
| `docs/incident_response.md` | Markdown | 82 | Incident Response (Compromise Scenarios) | `documentation` |
| `docs/liboqs_pin.md` | Markdown | 245 | liboqs pin (oqs.dll) — version, hashes, update procedure | `documentation` |
| `docs/modules/anonymity_decentral.md` | Markdown | 34 | Network-anonymity + decentralization modules (verified maps, honest scope) | `documentation` |
| `docs/modules/audit_threat_supply.md` | Markdown | 25 | Audit, threat, supply chain (verified maps) | `documentation` |
| `docs/modules/ca_services.md` | Markdown | 30 | Module: `ca_services.py` (~1983 lines) — private CA + mTLS contexts | `documentation` |
| `docs/modules/critical_release.md` | Markdown | 27 | Module: `critical_release.py` + `SecureP2PChat.send_critical` | `documentation` |
| `docs/modules/destroyer_node.md` | Markdown | 34 | Module: `destroyer_node.py` (109→162 lines) | `documentation` |
| `docs/modules/double_ratchet.md` | Markdown | 37 | Module: `double_ratchet.py` (~4100 lines) — ratchet + guards | `documentation` |
| `docs/modules/entropy_sidechannel.md` | Markdown | 23 | Entropy, randomness, side-channels (verified class maps) | `documentation` |
| `docs/modules/file_transfer.md` | Markdown | 29 | Module: `file_transfer.py` (+ `data/file_transfer.py`, | `documentation` |
| `docs/modules/hardware_trust.md` | Markdown | 20 | Hardware trust: `secure_enclave_key_storage.py`, `tee_manager.py`, | `documentation` |
| `docs/modules/hybrid_kex.md` | Markdown | 30 | Module: `hybrid_kex.py` (~2912 lines) — hybrid X3DH+PQ handshake | `documentation` |
| `docs/modules/memory_hsm.md` | Markdown | 23 | Memory protection + HSM (verified maps, honest limits) | `documentation` |
| `docs/modules/noise_pq.md` | Markdown | 82 | Module: `noise_pq.py`, `cnsa_purity.py`, & `crypto_selftest.py` — Protocol & Post-Quantum Cryptography | `documentation` |
| `docs/modules/opsec_persistence.md` | Markdown | 28 | OPSEC + persistence: `operational_security.py`, `ephemeral_messaging.py`, | `documentation` |
| `docs/modules/p2p_core.md` | Markdown | 35 | Module: `p2p_core.py` (2343 lines) — transport + connection lifecycle | `documentation` |
| `docs/modules/pqc_algorithms.md` | Markdown | 37 | Module: `pqc_algorithms.py` (~6500 lines) — PQ algorithm surfaces | `documentation` |
| `docs/modules/root_files.md` | Markdown | 32 | Remaining root files (verified one-line charters + key facts) | `documentation` |
| `docs/modules/rust_data_plane.md` | Markdown | 50 | `rust_data_plane/` — native data plane (all code read + tested) | `documentation` |
| `docs/modules/safety_numbers.md` | Markdown | 29 | Module: `ui/safety_numbers.py` | `documentation` |
| `docs/modules/secure_p2p.md` | Markdown | 73 | Module: `secure_p2p.py` (~11,400 lines) — application orchestrator | `documentation` |
| `docs/modules/subsystems_core.md` | Markdown | 16 | Subsystem mirrors: `core/ crypto/ data/ keys/` (verified maps) | `documentation` |
| `docs/modules/subsystems_support.md` | Markdown | 32 | Subsystem mirrors: `messaging/ network/ security/ ui/ utils/` | `documentation` |
| `docs/modules/tls_channel_manager.md` | Markdown | 38 | Module: `tls_channel_manager.py` (~5700 lines) — TLS + channel crypto | `documentation` |
| `docs/modules/transport_anonymity.md` | Markdown | 68 | Module: `transport_anonymity.py` & `spo_dpo.py` — Network Anonymity & Shaping | `documentation` |
| `docs/modules/trust_anchor.md` | Markdown | 59 | Module: `trust_anchor.py` — Trust Anchor & Post-Quantum PKI | `documentation` |
| `docs/modules/trust_policy.md` | Markdown | 31 | Identity, trust, experimental math (verified maps + gates) | `documentation` |
| `docs/modules/ts_hw_layer.md` | Markdown | 67 | Module: `ts_hw_layer.py` & `cng_platform.py` — Hardware & Physical Security | `documentation` |
| `docs/modules/ts_runtime.md` | Markdown | 58 | Module: `ts_runtime.py`, `ts_rt`, & `ts_attest.py` — OS & Execution Runtime | `documentation` |
| `docs/security_audit_report.md` | Markdown | 451 | P2P Messaging App — Defensive Security Audit Report | `documentation` |
| `double_ratchet.py` | Python | 5709 | Double Ratchet Protocol Implementation with Post-Quantum Security | `ratchet_kex_protocol` |
| `emergency_anti_tamper.py` | Python | 275 | emergency_anti_tamper.py | `system_hardening_integrity` |
| `enhanced_audit_logging.py` | Python | 1282 | Enhanced Audit Logging System with Hash Chain and Cryptographic Signatures | `audit_threat_monitoring` |
| `enhanced_peer_manager.py` | Python | 965 | Enhanced Peer Management System | `messaging_file_transfer` |
| `enhanced_secure_memory.py` | Python | 1102 | Enhanced Secure Memory Management - DoD 5220.22-M Compliant | `memory_security` |
| `enhanced_security_features.py` | Python | 678 | ST2027 HIGH-ASSURANCE SECURITY POSTURE & DEFENSE SUBSYSTEM | `security_framework` |
| `entropy_manager.py` | Python | 1197 | ST2027 HARDWARE ENTROPY POOL & CONDITIONING ENGINE | `memory_security` |
| `ephemeral_messaging.py` | Python | 1716 | Ephemeral Messaging System - DoD 5220.22-M Compliant Secure Message Deletion | `messaging_file_transfer` |
| `file_transfer.py` | Python | 634 | File transfer operations. | `messaging_file_transfer` |
| `forward_secrecy_manager.py` | Python | 755 | Forward Secrecy Manager - Enhanced Key Rotation with Strict Triggers | `ratchet_kex_protocol` |
| `group_key_manager.py` | Python | 1741 | group_key_manager.py | `ratchet_kex_protocol` |
| `hsm_integration.py` | Python | 247 | HSM/TPM integration operations. | `key_management_pki` |
| `hw_readiness.py` | Python | 423 | Hardware readiness + administrator elevation for the 2027 pipeline. | `host_runtime_attestation` |
| `hybrid_kex.py` | Python | 161 | Hybrid post-quantum key exchange (2027 research-backed profile). | `ratchet_kex_protocol` |
| `key_fill_import.py` | Python | 352 | Offline dual-officer key-fill import (KMI fill-device equivalent in software). | `key_management_pki` |
| `keys/__init__.py` | Python | 9 | Key management module. | `key_management_pki` |
| `keys/generation.py` | Python | 171 | Key generation operations. | `key_management_pki` |
| `keys/hsm_integration.py` | Python | 261 | HSM/TPM integration operations. | `key_management_pki` |
| `keys/manager.py` | Python | 54 | Key management coordinator. | `key_management_pki` |
| `keys/rotation.py` | Python | 200 | Key rotation operations. | `key_management_pki` |
| `keys/storage.py` | Python | 216 | Secure key storage operations. | `key_management_pki` |
| `launch_tactical_terminals.bat` | Batch | 14 | Batch script. | `tactical_command_cjadc2` |
| `launch_tactical_web.bat` | Batch | 11 | Batch script. | `tactical_command_cjadc2` |
| `liboqs_wrapper.py` | Python | 1304 | LibOQS Python Wrapper - Hybrid Post-Quantum Cryptography Implementation | `crypto_pqc` |
| `libsodium.dll` | Binary | 735 | Binary file (346624 bytes, SHA-256 5cfdc4bf7628777d...). | `system_hardening_integrity` |
| `libsodium.dll.hashes` | Other | 5 | Other file. | `system_hardening_integrity` |
| `libsodium.dll.pub` | Public key | 3 | Public key file (116 bytes). | `system_hardening_integrity` |
| `libsodium.dll.sig` | Signature | 1 | Detached signature file (64 bytes). | `system_hardening_integrity` |
| `libsodium_manager.py` | Python | 1582 | Python source module with no module docstring. | `crypto_pqc` |
| `logging_config.py` | Python | 199 | High-Performance Logging Configuration for Secure P2P | `audit_threat_monitoring` |
| `maximum_security_hardening.py` | Python | 677 | Maximum Security Hardening Module | `security_framework` |
| `memory_manager.py` | Python | 1699 | Secure Memory Management System - DoD 5220.22-M Compliant | `memory_security` |
| `memory_protection_engine.py` | Python | 1072 | ST2027 MEMORY PROTECTION & CORRUPTION MITIGATION ENGINE | `memory_security` |
| `messaging/__init__.py` | Python | 9 | Message handling module. | `messaging_file_transfer` |
| `messaging/commands.py` | Python | 893 | Command processing operations. | `messaging_file_transfer` |
| `messaging/encryption.py` | Python | 261 | Message encryption operations. | `messaging_file_transfer` |
| `messaging/handler.py` | Python | 249 | Message handling operations. | `messaging_file_transfer` |
| `messaging/manager.py` | Python | 74 | Messaging operations coordinator. | `messaging_file_transfer` |
| `metadata_resistance.py` | Python | 1023 | Metadata Resistance and Traffic Analysis Countermeasures Subsystem | `transport_anonymity` |
| `military_security_enforcement.py` | Python | 213 | ST2027 CRYPTOGRAPHIC POLICY ENFORCEMENT ENGINE | `security_framework` |
| `mls_framing.py` | Python | 387 | mls_framing.py — MLS-inspired group framing skeleton (RFC 9420 shape, v2). | `ratchet_kex_protocol` |
| `multi_device_manager.py` | Python | 1563 | Multi-Device Support Manager for Secure P2P Communication. | `messaging_file_transfer` |
| `native_secure_buffer.py` | Python | 388 | native_secure_buffer.py | `memory_security` |
| `nc3_nuclear_command.py` | Python | 1789 | Two-Person Integrity (TPI) Dual-Custody Protocol & Synthetic Emergency Action Subsystem | `tactical_command_cjadc2` |
| `network/__init__.py` | Python | 11 | Network operations module. | `mesh_ddil_networking` |
| `network/connection.py` | Python | 619 | Connection lifecycle management. | `mesh_ddil_networking` |
| `network/handshake.py` | Python | 344 | Hybrid X3DH+PQ handshake management. | `mesh_ddil_networking` |
| `network/io.py` | Python | 349 | Network I/O operations. | `mesh_ddil_networking` |
| `network/manager.py` | Python | 54 | Network operations coordinator. | `mesh_ddil_networking` |
| `network/monitoring.py` | Python | 365 | Connection health monitoring. | `mesh_ddil_networking` |
| `network/session_manager.py` | Python | 1435 | Session Manager with Security Context | `mesh_ddil_networking` |
| `network_adversary_resistance.py` | Python | 1621 | Network Adversary Resistance and Onion-Encrypted Multi-Hop Routing Subsystem | `transport_anonymity` |
| `network_endpoint_discovery.py` | Python | 540 | High-Assurance Network Endpoint Discovery Engine (IPv6 / IPv4 / LAN) | `transport_anonymity` |
| `nist_level5_policy_engine.py` | Python | 484 | NIST Level 5+ Policy Engine | `crypto_pqc` |
| `noise_pq.py` | Python | 987 | noise_pq.py — Noise_XXhfs-style post-quantum handshake with ML-KEM-1024. | `ratchet_kex_protocol` |
| `openssl_cnsa2_posture.cnf` | Other | 35 | Other file. | `tls_channel` |
| `operational_security.py` | Python | 1072 | Operational Security (OPSEC) and Ephemeral Lifecycle Management Subsystem | `system_hardening_integrity` |
| `oqs.dll` | Binary | 11701 | Binary file (4355072 bytes, SHA-256 ab1c1373a464a4ed...). | `system_hardening_integrity` |
| `oqs.dll.hashes` | Other | 5 | Other file. | `system_hardening_integrity` |
| `oqs.dll.pub` | Public key | 3 | Public key file (116 bytes). | `system_hardening_integrity` |
| `oqs.dll.sig` | Signature | 1 | Detached signature file (64 bytes). | `system_hardening_integrity` |
| `p2p_core.py` | Python | 2664 | Python source module with no module docstring. | `mesh_ddil_networking` |
| `paced_socket_wrapper.py` | Python | 328 | paced_socket_wrapper.py -- Hardware-Paced Wire Camouflage for Interactive Chat | `transport_anonymity` |
| `platform_hsm_interface.py` | Python | 11646 | Python source module with no module docstring. | `key_management_pki` |
| `pq_certificate_authority.py` | Python | 1380 | Post-Quantum Certificate Authority Implementation | `key_management_pki` |
| `pq_treekem.py` | Python | 444 | pq_treekem.py — Post-Quantum TreeKEM Implementation with ML-KEM-1024 (FIPS 203). | `ratchet_kex_protocol` |
| `pqc_algorithms.py` | Python | 8326 | Post-Quantum Cryptography Implementation Suite - NIST FIPS 203/204/205 Compliant | `crypto_pqc` |
| `pqc_crypto_agility_engine.py` | Python | 349 | pqc_crypto_agility_engine.py | `crypto_pqc` |
| `process_monitor_manager.py` | Python | 1201 | Process Monitor Manager | `audit_threat_monitoring` |
| `production_gate.py` | Python | 189 | production_gate.py — Single source of truth for production/TS security posture. | `security_framework` |
| `production_pqc_algorithms.py` | Python | 509 | ST2027 PRODUCTION POST-QUANTUM CRYPTOGRAPHY ENGINE | `crypto_pqc` |
| `protocol_manager.py` | Python | 979 | Protocol Manager - Secure Handshake and Session Management | `orchestrator_application` |
| `pytest.ini` | INI | 55 | INI file. | `utilities_support` |
| `quantum_rng.py` | Python | 767 | Quantum Random Number Generation - [restricted-term] 2026 Production Security | `memory_security` |
| `red_team_adversarial_drill.py` | Python | 359 | red_team_adversarial_drill.py | `verification_evidence` |
| `remote_siem_forwarder.py` | Python | 567 | remote_siem_forwarder.py | `audit_threat_monitoring` |
| `report_trust.py` | Python | 365 | Pinned trust anchor and custody policy for signed compliance/audit reports. | `audit_threat_monitoring` |
| `requirements-test.txt` | Text | 22 | # Test-only dependencies (NOT for production deployment). | `utilities_support` |
| `requirements.txt` | Text | 56 | # [restricted-term] Secure P2P Requirements (NIST L5 / CNSA 2.0, 2028 hardening) | `utilities_support` |
| `resilient_communication.py` | Python | 742 | ST2027 RESILIENT TRANSPORT & RELIABLE DELIVERY ENGINE | `mesh_ddil_networking` |
| `run_two_terminals_secure_p2_test.py` | Python | 201 | MASTER ORCHESTRATOR: 2-TERMINAL [restricted-term] BASE COMMUNICATIONS TEST | `operational_scripts` |
| `rust_backend.py` | Python | 153 | rust_backend.py — OPTIONAL Rust secure-core backend (additive only). | `rust_data_plane` |
| `rust_data_plane/.gitignore` | Other | 5 | Git ignore patterns for build output, caches, keys, and local files. | `rust_data_plane` |
| `rust_data_plane/Cargo.lock` | Lockfile | 1030 | Dependency lockfile. | `rust_data_plane` |
| `rust_data_plane/Cargo.toml` | TOML | 55 | rlib lets the standalone binary link the same tested modules; | `rust_data_plane` |
| `rust_data_plane/pyproject.toml` | TOML | 15 | TOML configuration. | `rust_data_plane` |
| `rust_data_plane/python/destroyer_core/__init__.py` | Python | 62 | destroyer_core — Rust secure core & data plane (PyO3 native extension). | `rust_data_plane` |
| `rust_data_plane/src/acd.rs` | Rust | 343 | Active Cyber Defense (ACD) Autonomous Threat Mitigation & Response Engine. | `rust_data_plane` |
| `rust_data_plane/src/aead.rs` | Rust | 366 | Data-plane AEAD: AES-256-GCM (CNSA 2.0 suite) over framed packets. | `rust_data_plane` |
| `rust_data_plane/src/attest.rs` | Rust | 272 | Enrollment-bound attestation verifier (Rust secure core). | `rust_data_plane` |
| `rust_data_plane/src/auth.rs` | Rust | 179 | Native ML-DSA-87 authentication (FIPS 204, CNSA 2.0). | `rust_data_plane` |
| `rust_data_plane/src/chaff.rs` | Rust | 5 | Chaff frame typing. Chaff is authenticated like any frame, absorbed on | `rust_data_plane` |
| `rust_data_plane/src/cookie.rs` | Rust | 435 | Stateless Anti-Amplification & Anti-DoS Cookie Gate (RFC 9000 / WireGuard style). | `rust_data_plane` |
| `rust_data_plane/src/ct.rs` | Rust | 78 | Constant-time comparison and selection primitives. | `rust_data_plane` |
| `rust_data_plane/src/fec.rs` | Rust | 428 | fec.rs — Cauchy-Reed-Solomon Forward Error Correction (FEC) over GF(2^8). | `rust_data_plane` |
| `rust_data_plane/src/ffi.rs` | Rust | 1432 | Thin PyO3 control-plane bindings for the Rust secure core. | `rust_data_plane` |
| `rust_data_plane/src/frame.rs` | Rust | 86 | Authenticated frame layout (all multi-byte fields big-endian): | `rust_data_plane` |
| `rust_data_plane/src/group_ratchet.rs` | Rust | 836 | [restricted-term] Sender-Key Group Ratchet Engine, wire profile v2. | `rust_data_plane` |
| `rust_data_plane/src/handshake.rs` | Rust | 829 | Noise_XXhfs handshake in Rust (CNSA L5 production path). | `rust_data_plane` |
| `rust_data_plane/src/kem.rs` | Rust | 335 | Hybrid key exchange: SecP384r1 + ML-KEM-1024 (RFC 10024 / CNSA 2.0 L5). | `rust_data_plane` |
| `rust_data_plane/src/kex_auth.rs` | Rust | 363 | Authenticated hybrid KEX session (Rust secure core). | `rust_data_plane` |
| `rust_data_plane/src/keystore.rs` | Rust | 268 | Sealed key-file custody (Rust secure core, single-sourced). | `rust_data_plane` |
| `rust_data_plane/src/lib.rs` | Rust | 505 | destroyer_core — Rust secure core + data plane for direct-IPv6 P2P. | `rust_data_plane` |
| `rust_data_plane/src/main.rs` | Rust | 2859 | secure-transmit — standalone post-quantum secure core & data-plane executor. | `rust_data_plane` |
| `rust_data_plane/src/memlock.rs` | Rust | 173 | OS page-locking for secret buffers (VirtualLock / mlock). | `rust_data_plane` |
| `rust_data_plane/src/memory_guard.rs` | Rust | 166 | Hardware & Memory Protection Engine (Stack Canaries & Secure Guard Buffers). | `rust_data_plane` |
| `rust_data_plane/src/net.rs` | Rust | 493 | Silent-drop UDP transport (dual-stack IPv6/IPv4). | `rust_data_plane` |
| `rust_data_plane/src/nostd_microcore.rs` | Rust | 430 | High-Assurance #![no_std] Cryptographic Micro-Core | `rust_data_plane` |
| `rust_data_plane/src/pacing.rs` | Rust | 219 | pacing — constant-rate traffic invariance and synthetic chaff engine. | `rust_data_plane` |
| `rust_data_plane/src/pad.rs` | Rust | 12 | Padding budgets (re-exported from frame quanta) and chaff policy. | `rust_data_plane` |
| `rust_data_plane/src/pki.rs` | Rust | 448 | 3-of-5 threshold ML-DSA-87 PKI verification (Rust secure core). | `rust_data_plane` |
| `rust_data_plane/src/policy.rs` | Rust | 161 | Secure-core policy: single source of fail-closed truth. | `rust_data_plane` |
| `rust_data_plane/src/purge.rs` | Rust | 127 | Cryptographic media sanitization & emergency zeroization (NIST SP 800-88 Rev 1 / DoD 5220.22-M). | `rust_data_plane` |
| `rust_data_plane/src/ratchet.rs` | Rust | 301 | Project-specific fresh-KEM ratchet inspired by SPQR/Triple Ratchet. | `rust_data_plane` |
| `rust_data_plane/src/replay.rs` | Rust | 361 | 1024-packet sequence sliding window per RFC 6479 (Decoupled IPsec/WireGuard mechanism). | `rust_data_plane` |
| `rust_data_plane/src/session.rs` | Rust | 257 | Post-handshake transport + session pipeline (Rust secure core). | `rust_data_plane` |
| `rust_data_plane/src/tpm_nv.rs` | Rust | 961 | TPM 2.0 NV monotonic counter — hardware high-water mark for send-seq state. | `rust_data_plane` |
| `rust_data_plane/src/zero_trust.rs` | Rust | 423 | Zero-Trust Continuous Verification & Risk Scoring Engine. | `rust_data_plane` |
| `rust_data_plane/tests/kani_harness.rs` | Rust | 414 | Kani verification harnesses + `cargo test` property doubles (additive only). | `tests` |
| `scripts/audit_pins.py` | Python | 129 | Pin-scoped OSV audit for 2028 hardening (no isolated-env hash issues). | `operational_scripts` |
| `scripts/cavp_algorithm_validator.py` | Python | 247 | scripts/cavp_algorithm_validator.py | `operational_scripts` |
| `scripts/crl_bundle.py` | Python | 295 | Offline CRL bundle CLI for air-gapped operation (no network). | `operational_scripts` |
| `scripts/cve_scan.py` | Python | 266 | Offline-first CVE scan over pinned requirements (additive, non-breaking). | `operational_scripts` |
| `scripts/deploy_canary_pilot.py` | Python | 261 | Canary Pilot Deployment & Continuous Monitoring (ISCM / cATO) Telemetry Harness | `operational_scripts` |
| `scripts/deploy_production.py` | Python | 404 | Production Deployment Script for [restricted-term] P2P System | `operational_scripts` |
| `scripts/generate_oscal_sar.py` | Python | 295 | generate_oscal_sar.py | `operational_scripts` |
| `scripts/generate_oscal_ssp.py` | Python | 347 | generate_oscal_ssp.py | `operational_scripts` |
| `scripts/generate_pqc_pki.py` | Python | 18 | scripts/generate_pqc_pki.py | `operational_scripts` |
| `scripts/generate_production_cbom.py` | Python | 393 | Generate Official Cryptographic Bill of Materials (CBOM) | `operational_scripts` |
| `scripts/generate_production_sbom.py` | Python | 713 | Generate Official Software Bill of Materials (SBOM) for 2027+ Defense Authorization | `operational_scripts` |
| `scripts/generate_sovereign_pki.py` | Python | 203 | scripts/generate_[restricted-term]_pki.py | `operational_scripts` |
| `scripts/package_deployment.py` | Python | 172 | Build a clean [restricted-term] deployment tree. | `operational_scripts` |
| `scripts/run_defense_audit.py` | Python | 267 | [restricted-term] Transmit 2027 (ST2027) — Master Defense Audit Harness | `operational_scripts` |
| `scripts/run_phase5_csrmc_operations_drill.py` | Python | 496 | run_phase5_csrmc_operations_drill.py | `operational_scripts` |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py` | Python | 470 | run_phase6_cjadc2_data_fabric_drill.py | `operational_scripts` |
| `scripts/setup_tor_overlay.ps1` | PowerShell | 87 | setup_tor_overlay.ps1 — provision the local Tor overlay (Windows). | `operational_scripts` |
| `scripts/setup_tor_overlay.sh` | Shell | 44 | setup_tor_overlay.sh — provision the local Tor overlay for [restricted-term] transport. | `operational_scripts` |
| `scripts/setup_wireguard.ps1` | PowerShell | 53 | setup_wireguard.ps1 — provision the [restricted-term] WireGuard / private-APN path. | `operational_scripts` |
| `scripts/setup_wireguard.sh` | Shell | 29 | setup_wireguard.sh — provision the [restricted-term] WireGuard / private-APN path. | `operational_scripts` |
| `scripts/sign_boot_config.py` | Python | 81 | Sign boot config with ML-DSA-87 (CNSA 2.0 offline ceremony output). | `operational_scripts` |
| `scripts/sign_dependencies.py` | Python | 250 | DLL supply-chain signing for oqs.dll / libsodium.dll (Ed25519 CA). | `operational_scripts` |
| `scripts/sign_waiver.py` | Python | 164 | AO offline ceremony: sign platform attestations with ML-DSA-87 (FIPS 204). | `operational_scripts` |
| `scripts/tor/secure-transmit-tor.service` | systemd unit | 32 | systemd unit file. | `operational_scripts` |
| `scripts/tor/torrc.ts-hardened` | Other | 43 | Other file. | `operational_scripts` |
| `scripts/verify_50x_sovereign_superiority.py` | Python | 347 | scripts/verify_50x_[restricted-term]_superiority.py | `operational_scripts` |
| `scripts/verify_ato_deployment_package.py` | Python | 500 | verify_ato_deployment_package.py | `operational_scripts` |
| `scripts/verify_hardware_security.py` | Python | 48 | Python source module with no module docstring. | `operational_scripts` |
| `scripts/verify_host_hardening.py` | Python | 416 | scripts/verify_host_hardening.py | `operational_scripts` |
| `scripts/verify_ratchet_performance.py` | Python | 20 | scripts/verify_ratchet_performance.py | `operational_scripts` |
| `scripts/verify_reproducible_build.py` | Python | 295 | Signed Reproducible Build Verification Script | `operational_scripts` |
| `scripts/wireguard/wg-ts0.conf.template` | Other | 30 | Other file. | `operational_scripts` |
| `scripts/witnessed_key_ceremony.py` | Python | 495 | Witnessed Key Ceremony Harness - NIST SP 800-57 / FIPS 140-3 Level 4 Compliant | `operational_scripts` |
| `secure_enclave_key_storage.py` | Python | 2096 | secure_enclave_key_storage.py | `memory_security` |
| `secure_file_sharing.py` | Python | 2003 | Python source module with no module docstring. | `messaging_file_transfer` |
| `secure_file_transfer.py` | Python | 541 | ST2027 SEGMENTED FILE TRANSPORT AND MEDIA SANITIZATION ENGINE | `messaging_file_transfer` |
| `secure_key_manager.py` | Python | 4637 | Secure Key Manager | `key_management_pki` |
| `secure_key_provider.py` | Python | 617 | secure_key_provider.py | `key_management_pki` |
| `secure_memory_wiper.py` | Python | 610 | Secure Memory Wiper - DoD 5220.22-M Compliant Memory Sanitization | `memory_security` |
| `secure_message_serializer.py` | Python | 680 | Secure Message Serializer - MAC-First Verification | `messaging_file_transfer` |
| `secure_p2p.py` | Python | 16874 | Secure P2P Chat Implementation | `orchestrator_application` |
| `secure_transmit_2027.py` | Python | 2394 | secure_transmit_2027.py — Most-secure practical transmission over the public internet (2027). | `orchestrator_application` |
| `security/__init__.py` | Python | 24 | Security operations module. | `security_framework` |
| `security/graceful_degradation.py` | Python | 342 | Security Degradation Enforcement Module | `security_framework` |
| `security/hardening.py` | Python | 445 | Security hardening module for secure protection. | `security_framework` |
| `security/integrity.py` | Python | 280 | Runtime integrity checking module for security monitoring. | `security_framework` |
| `security/manager.py` | Python | 54 | Security operations coordinator. | `security_framework` |
| `security/monitor.py` | Python | 366 | Security monitoring module for continuous threat detection. | `security_framework` |
| `security/validation.py` | Python | 885 | secure input validation module. | `security_framework` |
| `security_dependency_manager.py` | Python | 1014 | Security Dependency Manager | `system_hardening_integrity` |
| `security_diagnostics.py` | Python | 1282 | National Security Systems Full-Project Security Diagnostics | `audit_threat_monitoring` |
| `security_hardening_manager.py` | Python | 1466 | Security Hardening Manager Module | `security_framework` |
| `security_recovery_manager.py` | Python | 718 | Security Recovery Manager Module | `security_framework` |
| `security_status_monitor.py` | Python | 922 | Security Status Monitor Module | `audit_threat_monitoring` |
| `security_tiers.py` | Python | 1715 | security_tiers.py | `security_framework` |
| `security_validation_orchestrator.py` | Python | 518 | Security Validation Orchestrator | `security_framework` |
| `security_validator.py` | Python | 324 | ST2027 PRE-DEPLOYMENT SECURITY ASSURANCE VALIDATOR | `security_framework` |
| `sel4_baremetal/Cargo.lock` | Lockfile | 15 | Dependency lockfile. | `host_runtime_attestation` |
| `sel4_baremetal/Cargo.toml` | TOML | 14 | TOML configuration. | `host_runtime_attestation` |
| `sel4_baremetal/black_domain/Cargo.toml` | TOML | 7 | Zero external crates: pure core-only bare-metal | `host_runtime_attestation` |
| `sel4_baremetal/black_domain/src/main.rs` | Rust | 44 | Bare-Metal seL4 Microkit BLACK Protection Domain (Untrusted Transport) | `host_runtime_attestation` |
| `sel4_baremetal/crypto_domain/Cargo.toml` | TOML | 7 | Zero external crates: pure core-only bare-metal | `host_runtime_attestation` |
| `sel4_baremetal/crypto_domain/src/main.rs` | Rust | 74 | Bare-Metal seL4 Microkit CRYPTO Protection Domain ([restricted-term] Core) | `host_runtime_attestation` |
| `sel4_baremetal/red_domain/Cargo.toml` | TOML | 7 | Zero external crates: pure core-only bare-metal | `host_runtime_attestation` |
| `sel4_baremetal/red_domain/src/main.rs` | Rust | 51 | Bare-Metal seL4 Microkit RED Protection Domain (User / Plaintext) | `host_runtime_attestation` |
| `sel4_microkit/system.xml` | XML | 37 | XML configuration. | `host_runtime_attestation` |
| `sel4_microkit_manifest.py` | Python | 266 | sel4_microkit_manifest.py — Formal Validator & Generator for seL4 Microkit | `host_runtime_attestation` |
| `set_env.sh` | Shell | 7 | Shell script. | `utilities_support` |
| `side_channel_resistance.py` | Python | 1513 | Side-Channel Attack Mitigation and Timing Invariance Verification Module | `memory_security` |
| `sovereign_black_domain.py` | Python | 129 | [restricted-term]_black_domain.py — High-Assurance Reference Implementation of the | `host_runtime_attestation` |
| `sovereign_crypto_domain.py` | Python | 493 | [restricted-term]_crypto_domain.py — High-Assurance Reference Implementation of the | `host_runtime_attestation` |
| `sovereign_group_ratchet.py` | Python | 264 | [restricted-term] Group Ratchet (CNSA Suite 2.0 / RFC 9420 MLS Aligned). | `ratchet_kex_protocol` |
| `sovereign_red_domain.py` | Python | 87 | [restricted-term]_red_domain.py — High-Assurance Reference Implementation of the | `host_runtime_attestation` |
| `sovereign_sel4_appliance.py` | Python | 115 | [restricted-term]_sel4_appliance.py — Unified seL4 [restricted-term] Hardware Appliance Runtime | `host_runtime_attestation` |
| `spo_dpo.py` | Python | 738 | spo_dpo.py — Single-Person vs Dual-Person Operation enforcement for [restricted-term] | `transport_anonymity` |
| `ssdf_attestation.py` | Python | 261 | SSDF self-attestation evidence (NIST SP 800-218 v1.1 / EO 14028). | `system_hardening_integrity` |
| `start_tactical_alpha.bat` | Batch | 6 | Batch script. | `tactical_command_cjadc2` |
| `start_tactical_bravo.bat` | Batch | 6 | Batch script. | `tactical_command_cjadc2` |
| `stateful_artifact_signing.py` | Python | 628 | stateful_artifact_signing.py | `system_hardening_integrity` |
| `storage.py` | Python | 114 | Secure key storage operations. Provides encrypted key storage and retrieval with security. | `orchestrator_application` |
| `supply_chain_security.py` | Python | 2948 | Software Supply Chain Integrity and Provenance Verification Engine | `system_hardening_integrity` |
| `tactical_cloaking_router.py` | Python | 219 | tactical_cloaking_router.py | `transport_anonymity` |
| `tactical_data_diode.py` | Python | 674 | Simplex Tactical Data Diode with Forward Error Correction (FEC) | `mesh_ddil_networking` |
| `tactical_key_provisioner.py` | Python | 224 | ================================================================================ | `key_management_pki` |
| `tactical_mesh_ddil.py` | Python | 979 | tactical_mesh_ddil.py | `mesh_ddil_networking` |
| `tactical_operator_console.py` | Python | 1018 | ================================================================================ | `tactical_command_cjadc2` |
| `tactical_web/app.js` | JavaScript | 592 | JavaScript source. | `tactical_command_cjadc2` |
| `tactical_web/index.css` | CSS | 1462 | Stylesheet. | `tactical_command_cjadc2` |
| `tactical_web/index.html` | HTML | 682 | HTML document; title: Destroyer Tactical P2P — [restricted-term] Defense Command Center | `tactical_command_cjadc2` |
| `tactical_web_console.py` | Python | 678 | tactical_web_console.py — LOCAL DEMONSTRATION & TELEMETRY LAB CONSOLE | `tactical_command_cjadc2` |
| `tee_manager.py` | Python | 1459 | tee_manager.py | `host_runtime_attestation` |
| `test-results/TEST_AND_BUILD_REPORT.md` | Markdown | 85 | Test and Build Verification Report | `documentation` |
| `tests/conftest.py` | Python | 59 | Shared pytest fixtures. | `tests` |
| `tests/test_2027_defense_hardening.py` | Python | 551 | 2027+ Defense-Grade [restricted-term] Security Hardening Verification Suite | `tests` |
| `tests/test_2028_national_security_remediations.py` | Python | 540 | Test Suite: 2028+ National-Security Level Hardening & Remediation Battery | `tests` |
| `tests/test_anonymous_loopback.py` | Python | 71 | End-to-end anonymous transfer over loopback: overlay + TLS + ST2027 | `tests` |
| `tests/test_archive_hardening.py` | Python | 128 | Behavioral tests for archive hardening and extract_archive defenses. | `tests` |
| `tests/test_audit4_remediations_2026_10_17.py` | Python | 603 | A4 Audit Remediation Regression Battery (2026-10-17) | `tests` |
| `tests/test_audit_confirmed_regressions.py` | Python | 589 | Automated Regression Test Suite for Audit-Confirmed Security Findings. | `tests` |
| `tests/test_audit_forensic_remediations.py` | Python | 487 | [restricted-term] Forensic Security Audit Regression & Remediation Test Suite. | `tests` |
| `tests/test_audit_p1_remediations_phase2.py` | Python | 136 | Regression test suite for Phase 2 P1 Defensive Security Audit Remediations. | `tests` |
| `tests/test_caps_strict.py` | Python | 232 | Caps unification + encrypt-sentinel strict mode (pure asserts, no network). | `tests` |
| `tests/test_ceremony_quorum.py` | Python | 130 | Ceremony cryptographic quorum (2-of-3 custodian approvals are real). | `tests` |
| `tests/test_cjadc2_report_anchor.py` | Python | 37 | Compliance reports must verify against a pinned anchor, not their own .pub. | `tests` |
| `tests/test_cli_key_fill_and_diode.py` | Python | 171 | test_cli_key_fill_and_diode.py | `tests` |
| `tests/test_cnsa27_gate_2026.py` | Python | 160 | CNSA 2.0 January-2027 gate + 2026-27 research posture (E1/E2/E3). | `tests` |
| `tests/test_cnsa_max_profile.py` | Python | 204 | Test Suite for 2026 CNSA 2.0 [restricted-term] Max Cryptographic Profile | `tests` |
| `tests/test_combiner_downgrade_guard.py` | Python | 54 | Combiner downgrade guard (audit 2026-10-14). | `tests` |
| `tests/test_compliance_package_depth.py` | Python | 81 | SSDF self-attestation + ZT evidence-map gates (Tier-1/2 package depth). | `tests` |
| `tests/test_comprehensive_security_tiers.py` | Python | 1073 | tests/test_[restricted-term]_security_tiers.py | `tests` |
| `tests/test_connection_alias_cleanup.py` | Python | 87 | Python source module with no module docstring. | `tests` |
| `tests/test_cp1252_encoding_safety.py` | Python | 143 | Tests for Windows CP1252 Console Encoding Safety. | `tests` |
| `tests/test_critical_audit_remediations.py` | Python | 371 | test_critical_audit_remediations.py | `tests` |
| `tests/test_crypto_root_fixes.py` | Python | 337 | ================================================================================ | `tests` |
| `tests/test_daemon_packages.py` | Python | 84 | Daemon configuration packages: torrc template, wg template, systemd unit. | `tests` |
| `tests/test_ddil_key_lifecycle.py` | Python | 183 | Python source module with no module docstring. | `tests` |
| `tests/test_defensive_audit_remediations.py` | Python | 251 | Test Defensive Security Audit Remediations. | `tests` |
| `tests/test_defensive_audit_roadmap.py` | Python | 175 | Test Defensive Audit Roadmap Targets. | `tests` |
| `tests/test_defensive_audit_targets.py` | Python | 282 | [restricted-term] Regression Suite for Defensive Security Audit Targets. | `tests` |
| `tests/test_defensive_nc3_audit.py` | Python | 274 | Zero-Gap Defensive Security Audit Suite for Direct-P2P [restricted-term] Messaging (NC3/EAM) | `tests` |
| `tests/test_deployment_package.py` | Python | 40 | Deployment archive completeness and isolated lab self-test. | `verification_evidence` |
| `tests/test_destroyer_core_production.py` | Python | 355 | [restricted-term] Production-Grade Verification Suite for destroyer_core | `tests` |
| `tests/test_dht_pow_floor.py` | Python | 85 | DHT PoW production floor (A-13, 2026-10-16 audit). | `tests` |
| `tests/test_diode_binding.py` | Python | 107 | Diode interface binding + direction enforcement (G3). | `tests` |
| `tests/test_dll_ca_ceremony.py` | Python | 126 | Ed25519 DLL CA ceremony (scripts/sign_dependencies.py) — rotation guard, | `tests` |
| `tests/test_docs_truth_in_claims.py` | Python | 160 | Truth-in-claims gates (Phase 4): documentation is audited like code. | `tests` |
| `tests/test_exploit_nonce_state.py` | Python | 173 | Nonce state-attack consequences — supplement to test_exploit_regressions.py. | `tests` |
| `tests/test_exploit_regressions.py` | Python | 457 | Active exploit regression battery — permanent automated defenses. | `tests` |
| `tests/test_falcon_bundle_mode_consistency.py` | Python | 138 | FALCON/hybrid bundle serialization consistency (A-14, 2026-10-16). | `tests` |
| `tests/test_file_receive_traversal_guard.py` | Python | 255 | Fail-closed file-receive filename guard (found 2026-09-24). | `tests` |
| `tests/test_formal_proverif_models.py` | Python | 98 | Test Suite: Formal ProVerif Models Structural & Mathematical Validation | `tests` |
| `tests/test_fullreview_critical_remediations.py` | Python | 1479 | Regression tests for full-review CRITICAL remediations (2026-10). | `tests` |
| `tests/test_group_tier3.py` | Python | 930 | Tier-3 group receive path + compartment enforcement (G3/MLS research). | `tests` |
| `tests/test_hardware_providers.py` | Python | 400 | Hardware-provider gates (F1-F7): use the on-desk hardware for real. | `tests` |
| `tests/test_heartbeat_throttle.py` | Python | 92 | Heartbeat ACK flood throttle (audit 4.5 / roadmap must-pass). | `tests` |
| `tests/test_high_audit_remediations.py` | Python | 101 | Unit tests verifying defensive remediation of High-priority audit findings: | `tests` |
| `tests/test_host_hardening_verifier.py` | Python | 144 | test_host_hardening_verifier.py | `tests` |
| `tests/test_host_posture_cli_and_gate.py` | Python | 128 | test_host_posture_cli_and_gate.py | `tests` |
| `tests/test_hsm_platform.py` | Python | 320 | Gates for real TPM/HSM usage paths (mocked native layer). | `tests` |
| `tests/test_hw_readiness.py` | Python | 255 | hw_readiness: HAVE/MISSING verdicts, strict refusal, admin elevation. | `tests` |
| `tests/test_key_fill_import.py` | Python | 195 | Dual-officer key-fill gates (G1): create -> verify -> import -> replay. | `tests` |
| `tests/test_layer1_hardening.py` | Python | 90 | Layer-1 hardening gates: native buffers + V2 member-bound group envelopes. | `tests` |
| `tests/test_legacy_quarantine.py` | Python | 115 | Legacy prototype quarantine: TS/PROD must refuse, lab import unaffected. | `tests` |
| `tests/test_liboqs_version_floor_gate.py` | Python | 217 | liboqs runtime version-floor gate — behavioral proofs (docs/liboqs_pin.md). | `tests` |
| `tests/test_military_adversarial_suite.py` | Python | 626 | ================================================================================ | `tests` |
| `tests/test_military_bases_two_terminal_live_drill.py` | Python | 116 | Test [restricted-term] Bases Two-Terminal Live Post-Quantum Operational Drill | `verification_evidence` |
| `tests/test_mls_framing.py` | Python | 166 | Gates for mls_framing.py: roundtrips, transcript chain, tamper rejection. | `tests` |
| `tests/test_native_ctypes_bounds.py` | Python | 76 | Native FFI input bounds (audit 6.2 / ctypes hardening). | `tests` |
| `tests/test_nc3_cnsa_cipher.py` | Python | 119 | NC3 PAL bulk cipher: AES-256-GCM seals, legacy ChaCha verifies, tamper fails. | `tests` |
| `tests/test_nc3_nuclear_command_readiness.py` | Python | 374 | NC3 ([restricted-term] Command, Control, and Communications) Verification Battery | `tests` |
| `tests/test_nc3_token_approval.py` | Python | 273 | Token-backed officer approvals (G2): PKCS#11 ECDSA presence leg. | `tests` |
| `tests/test_nc3_two_person_integrity.py` | Python | 414 | Test Suite: NC3 / PAL Two-Person Integrity (TPI) & Dual-Custody Hardware Protocol | `tests` |
| `tests/test_nc3_two_terminal_live_transfer.py` | Python | 399 | NC3 TWO-TERMINAL LIVE INTEGRATION TEST (SECURE_P2.PY) | `tests` |
| `tests/test_neon_auth_hmac.py` | Python | 128 | Behavioral tests for Neon PostgreSQL security and HMAC authentication. | `tests` |
| `tests/test_network_endpoint_discovery.py` | Python | 303 | Test Suite: [restricted-term] Network Endpoint Discovery Engine | `tests` |
| `tests/test_no_emoji_property.py` | Python | 196 | Property-Based Test for No Emoji in Production Code | `tests` |
| `tests/test_no_gap_military_audit.py` | Python | 348 | ================================================================================ | `tests` |
| `tests/test_no_marketing_buzzwords_property.py` | Python | 219 | Property-Based Test for No Marketing Buzzwords | `tests` |
| `tests/test_noise_pq_hardened.py` | Python | 480 | tests/test_noise_pq_hardened.py | `tests` |
| `tests/test_noise_pq_purity.py` | Python | 233 | Production tests: Noise_XXhfs+ML-KEM-1024 handshake (REAL primitives) | `tests` |
| `tests/test_nonce_hardening.py` | Python | 135 | Regression tests for the audit nonce-management finding (2026-10-14). | `tests` |
| `tests/test_notupload_security.py` | Python | 76 | Static and architectural security regression tests for notupload/ components. | `tests` |
| `tests/test_oauth_token_validation_p0.py` | Python | 157 | Tests for Fix #1 (P0 CRITICAL): OAuth Token Validation Bypass Remediation. | `tests` |
| `tests/test_paced_socket_wrapper.py` | Python | 219 | test_paced_socket_wrapper.py -- Verification for Hardware-Paced Wire Camouflage | `tests` |
| `tests/test_parser_fuzz_gates.py` | Python | 501 | Parser fuzz + KAT gates (deterministic, seeded, additive-only). | `tests` |
| `tests/test_pasted_audit_p0_remediations.py` | Python | 236 | Regression battery for pasted-audit P0 fixes (verified-true items only). | `tests` |
| `tests/test_pbkdf2_migration_and_group_architecture.py` | Python | 192 | VERIFICATION SUITE: AUDIT FINDINGS O-01, O-02, O-05, O-12 REMEDIATIONS | `verification_evidence` |
| `tests/test_phase3_acceptance_gates_e1_e6.py` | Python | 308 | test_phase3_acceptance_gates_e1_e6.py | `tests` |
| `tests/test_phase3_acvp_cbom_udp.py` | Python | 362 | test_phase3_acvp_cbom_udp.py | `tests` |
| `tests/test_phase3_security_bounds.py` | Python | 508 | Phase-3 security-bounds regression tests (fast, classical/lab only). | `tests` |
| `tests/test_phase4_ato_redteam_siem.py` | Python | 431 | test_phase4_ato_redteam_siem.py | `tests` |
| `tests/test_phase5_csrmc_ddil_operations.py` | Python | 544 | test_phase5_csrmc_ddil_operations.py | `tests` |
| `tests/test_phase6_cjadc2_data_fabric.py` | Python | 281 | test_phase6_cjadc2_data_fabric.py | `tests` |
| `tests/test_pkcs11_token_provider.py` | Python | 115 | Tests for PKCS#11 hardware token backend and software simulation provider in NC3. | `tests` |
| `tests/test_pqxdh_combiner_v2_kat.py` | Python | 116 | PQXDH combiner v2 Known-Answer / property tests (pure function, no network). | `tests` |
| `tests/test_production_gate.py` | Python | 250 | F-01 production-gate consistency matrix. | `tests` |
| `tests/test_production_grade_destroyer_suite.py` | Python | 236 | PRODUCTION-GRADE VERIFICATION & SOAK TEST SUITE FOR DESTROYER_CORE | `tests` |
| `tests/test_production_readiness_audit.py` | Python | 218 | test_production_readiness_audit.py | `tests` |
| `tests/test_production_surface_audit.py` | Python | 116 | Production attack-surface audit (Task 5.2): the lean core stays lean. | `tests` |
| `tests/test_production_tier123_hardening.py` | Python | 420 | test_production_tier123_hardening.py | `tests` |
| `tests/test_production_tier4_cjadc2_and_consensus.py` | Python | 854 | test_production_tier4_cjadc2_and_consensus.py | `tests` |
| `tests/test_production_tier4_device_memory_audit.py` | Python | 364 | Test Suite: Multi-Device Registry Thread Safety, Memory Deallocation, & Hardening Audit | `tests` |
| `tests/test_production_tier4_tactical_commands.py` | Python | 299 | test_production_tier4_tactical_commands.py | `tests` |
| `tests/test_production_tier5_session_config_audit.py` | Python | 175 | Automated Test Suite: Production Tier 5 Session & Config Audit Remediations | `tests` |
| `tests/test_production_tier6_csprng_and_storage_audit.py` | Python | 212 | test_production_tier6_csprng_and_storage_audit.py | `tests` |
| `tests/test_production_tier7_csprng_complete_audit.py` | Python | 198 | Test Suite: Production Tier 7 CSPRNG Complete Hardening & Parity Audit | `tests` |
| `tests/test_profile_encryption_lifecycle.py` | Python | 184 | ================================================================================ | `tests` |
| `tests/test_proverif_st2027.py` | Python | 124 | Execute ProVerif on docs/formal/st2027_handshake.pv and assert proofs. | `tests` |
| `tests/test_ratchet_dss_mldsa87.py` | Python | 110 | Ratchet DSS migration: ML-DSA-87 session identity (CNSA 2.0 / FIPS 204). | `tests` |
| `tests/test_ratchet_native_buffer.py` | Python | 113 | test_ratchet_native_buffer.py | `tests` |
| `tests/test_rekor_bundle.py` | Python | 58 | Unit tests for generate_production_sbom.verify_rekor_bundle (offline, no network). | `tests` |
| `tests/test_remediated_63_findings.py` | Python | 376 | Automated Verification Suite for All 63 Remediated Security Findings. | `tests` |
| `tests/test_resilient_ddil.py` | Python | 126 | DDIL resilient-communication gates (Tier-1 tactical credibility). | `tests` |
| `tests/test_runbooks_ps.py` | Python | 59 | PowerShell runbooks mirror the .sh gates — static lock-in (cross-platform). | `tests` |
| `tests/test_rust_core_security_suite.py` | Python | 325 | [restricted-term] Test Suite for Native Rust Core Security Components. | `tests` |
| `tests/test_rust_interop.py` | Python | 230 | Live cross-implementation interop: Python reference <-> Rust secure core. | `tests` |
| `tests/test_rust_python_crosscheck.py` | Python | 178 | Python <-> Rust data-plane cross-check + boundary contract (G4). | `tests` |
| `tests/test_rust_python_handshake_interop.py` | Python | 103 | Cross-Implementation Security & Interoperability Test Suite (Python ↔ Rust). | `tests` |
| `tests/test_rust_standalone_binary.py` | Python | 801 | Standalone Rust binary (Task-1): secure-transmit builds and transfers. | `tests` |
| `tests/test_sbom_signer_custody.py` | Python | 90 | SBOM signer custody resolution (F-04/A-01) — fail-closed anchor protection. | `tests` |
| `tests/test_second_audit_regressions.py` | Python | 76 | Second-audit regression battery (F-01..F-06). | `tests` |
| `tests/test_secure_transmit_2027.py` | Python | 844 | Production tests for secure_transmit_2027 — all REAL primitives, no mocks of crypto. | `tests` |
| `tests/test_security_audit_remediations.py` | Python | 404 | Automated Verification Test Suite: Remediated Findings from security_audit_report.md | `tests` |
| `tests/test_security_diagnostics.py` | Python | 54 | Pytest wrapper for the full-project security diagnostics sweep. | `tests` |
| `tests/test_security_hardening_and_memory.py` | Python | 98 | Test Security Hardening, Graceful Degradation Fail-Closed, and Memory Pinning. | `tests` |
| `tests/test_sel4_sovereign_appliance.py` | Python | 261 | tests/test_sel4_[restricted-term]_appliance.py — High-Assurance Verification Suite for the | `tests` |
| `tests/test_simple_chat.py` | Python | 96 | test_simple_chat.py | `tests` |
| `tests/test_sovereign_group_ratchet.py` | Python | 139 | Test suite for [restricted-term]GroupRatchet (CNSA Suite 2.0 / RFC 9420 MLS Aligned). | `tests` |
| `tests/test_spo_dpo.py` | Python | 206 | Production tests for spo_dpo — all REAL ML-DSA-87, no mocks of crypto. | `tests` |
| `tests/test_stateful_artifact_signing.py` | Python | 342 | SP 800-208 stateful artifact-signing hook — behavioral proofs. | `tests` |
| `tests/test_tactical_data_diode.py` | Python | 277 | Test Suite: Simplex Tactical Data Diode & Forward Error Correction | `tests` |
| `tests/test_tactical_operations_suite.py` | Python | 154 | Unit and Integration Test Suite for Real [restricted-term] Tactical C4ISR Operations. | `tests` |
| `tests/test_tactical_replay.py` | Python | 78 | Behavioral tests for tactical message anti-replay protection. | `tests` |
| `tests/test_tactical_web_console.py` | Python | 162 | Unit tests for Tactical Web Command Center API handlers. | `tests` |
| `tests/test_tier4_pq_treekem_and_tfc.py` | Python | 284 | test_tier4_pq_treekem_and_tfc.py | `tests` |
| `tests/test_tier4_spqr_and_rum_bft.py` | Python | 245 | test_tier4_spqr_and_rum_bft.py | `tests` |
| `tests/test_tls_cnsa_suite_pin.py` | Python | 88 | TLS 1.3 CNSA suite pin + SecurityError definition (audit 2026-10-15). | `tests` |
| `tests/test_tpm_hardware_phase2.py` | Python | 155 | Test suite for Phase 2: Hardware Root-of-Trust (TPM 2.0 / HSM Hardware Setup). | `tests` |
| `tests/test_tpm_nv_guard.py` | Python | 331 | TPM NV monotonic-counter guard — end-to-end proof of the F-01 residual. | `tests` |
| `tests/test_tpm_quote.py` | Python | 115 | Tests for tpm_quote.py skeleton (additive only, runtime <30s). | `tests` |
| `tests/test_tpm_quote_production.py` | Python | 189 | Test Suite: Production-Grade TPM 2.0 Hardware Attestation, Sealed Storage & Identity Binding. | `tests` |
| `tests/test_transport_anonymity.py` | Python | 301 | Production tests for transport_anonymity — real crypto, no network. | `tests` |
| `tests/test_treekem.py` | Python | 120 | Gates for treekem.py: structure, blanking, resolution, paths, tree hash. | `tests` |
| `tests/test_trust_anchor.py` | Python | 301 | Production tests for trust_anchor — real ML-DSA-87 threshold, no mocks. | `tests` |
| `tests/test_ts_attest.py` | Python | 246 | Production tests for ts_attest — REAL TPM signatures, REAL verification. | `tests` |
| `tests/test_ts_hw_layer.py` | Python | 764 | Production tests for ts_hw_layer — REAL probes, REAL crypto, REAL sockets. | `tests` |
| `tests/test_ts_runtime.py` | Python | 530 | Production tests for ts_runtime — REAL posture reads, REAL native core. | `tests` |
| `tests/test_tuf_pq_dual_sign.py` | Python | 149 | TUF-lite post-quantum dual signatures (Fix B / audit 7.2, CNSA 2.0). | `tests` |
| `tests/test_unified_secure_pipeline.py` | Python | 466 | test_unified_secure_pipeline.py -- Verify the Zero-Gap Defense Pipeline | `tests` |
| `tests/test_verify_after_sign.py` | Python | 310 | Verify-after-sign gates (fault-attack countermeasure, cf. eprint 2025/2009). | `tests` |
| `tests/test_wave8_regressions.py` | Python | 437 | Wave-8 regression tests for latest builds (additive only, fast, no network). | `tests` |
| `tests/test_worm_chain_keyed.py` | Python | 75 | WORM audit exports must use a keyed chain, not recomputable SHA3-512. | `tests` |
| `threat_detection_engine.py` | Python | 1075 | Threat Detection Engine | `audit_threat_monitoring` |
| `threat_detection_response_system.py` | Python | 772 | Continuous Threat Detection and Automated Incident Containment Engine | `audit_threat_monitoring` |
| `threshold_cryptography.py` | Python | 1204 | Threshold Cryptography Module - [restricted-term] 2026 Production Security | `key_management_pki` |
| `tls_channel_manager.py` | Python | 7197 | TLS Channel Manager - Quantum-Resistant Secure Communication | `tls_channel` |
| `tls_pq_policy.py` | Python | 94 | TLS 1.3 post-quantum policy probe (shared, stdlib-only). | `tls_channel` |
| `tpm_quote.py` | Python | 1325 | TPM remote-attestation quote skeleton (additive, non-breaking). | `key_management_pki` |
| `transport_anonymity.py` | Python | 1124 | transport_anonymity.py — Network transport and anonymity for [restricted-term] | `transport_anonymity` |
| `treekem.py` | Python | 362 | treekem.py — ratchet-tree STRUCTURE skeleton (TreeKEM foundation, T3-J). | `ratchet_kex_protocol` |
| `triple_hybrid_kem.py` | Python | 1321 | Triple-Hybrid Key Encapsulation Mechanism - [restricted-term] 2026 Production Security | `ratchet_kex_protocol` |
| `trust_anchor.py` | Python | 614 | trust_anchor.py — Trust infrastructure and operational key management for | `key_management_pki` |
| `ts_attest.py` | Python | 249 | ts_attest.py — RATS-role platform attestation: TPM-bound Evidence on the | `host_runtime_attestation` |
| `ts_hw_layer.py` | Python | 1393 | ts_hw_layer.py — Hardware & Physical Security gating layer for [restricted-term] / | `host_runtime_attestation` |
| `ts_rt/Cargo.lock` | Lockfile | 7 | Dependency lockfile. | `host_runtime_attestation` |
| `ts_rt/Cargo.toml` | TOML | 13 | TOML configuration. | `host_runtime_attestation` |
| `ts_rt/build.rs` | Rust | 11 | Rust source module with no module-level doc comment. | `host_runtime_attestation` |
| `ts_rt/src/lib.rs` | Rust | 408 | ts_rt — deterministic Top-Secret runtime core. | `host_runtime_attestation` |
| `ts_runtime.py` | Python | 896 | ts_runtime.py — Operating-system & execution-runtime gating layer for TOP | `host_runtime_attestation` |
| `ui/__init__.py` | Python | 9 | User interface module. | `ui_presentation` |
| `ui/display.py` | Python | 785 | Display operations. | `ui_presentation` |
| `ui/feedback.py` | Python | 451 | User feedback operations. | `ui_presentation` |
| `ui/manager.py` | Python | 59 | UI operations coordinator. | `ui_presentation` |
| `ui/menus.py` | Python | 385 | Menu operations. | `ui_presentation` |
| `ui/prompts.py` | Python | 382 | Prompt operations. | `ui_presentation` |
| `ui/safety_numbers.py` | Python | 246 | TOFU safety numbers + persistent pin store (Phase 0, no prod behavior change). | `ui_presentation` |
| `unified_secure_pipeline.py` | Python | 817 | unified_secure_pipeline.py -- Zero-Gap Defense-in-Depth Message Pipeline | `orchestrator_application` |
| `utils/__init__.py` | Python | 10 | Utilities module. | `utilities_support` |
| `utils/backward_compat.py` | Python | 296 | Backward Compatibility Module | `utilities_support` |
| `utils/cleanup.py` | Python | 244 | System cleanup operations. | `utilities_support` |
| `utils/config_manager.py` | Python | 1068 | Configuration Manager with Backward Compatibility | `utilities_support` |
| `utils/error_handler.py` | Python | 510 | Security Error Handler Module | `utilities_support` |
| `utils/helpers.py` | Python | 267 | Helper functions. | `utilities_support` |
| `utils/initialization.py` | Python | 110 | System initialization operations. | `utilities_support` |
| `utils/manager.py` | Python | 63 | Utils operations coordinator. | `utilities_support` |
| `utils/memory.py` | Python | 404 | Memory management operations. | `utilities_support` |
| `utils/message_caps.py` | Python | 146 | Central message / frame capability limits (caps unification). | `utilities_support` |
| `verify_deployment.py` | Python | 918 | ST2027 PRODUCTION DEPLOYMENT ASSURANCE & VERIFICATION TESTBENCH | `verification_evidence` |
| `verify_intercontinental_udp_stream.py` | Python | 213 | verify_intercontinental_udp_stream.py | `verification_evidence` |
| `zero_trust_assessment.py` | Python | 377 | zero_trust_assessment.py | `audit_threat_monitoring` |
| `zero_trust_engine.py` | Python | 850 | Zero-Trust Authentication Engine - Strict Verification | `audit_threat_monitoring` |
| `zk_authenticator.py` | Python | 1303 | Zero-Knowledge Authentication Module - [restricted-term] 2026 Security | `transport_anonymity` |
