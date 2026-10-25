# Codebase Inventory (Phase 0)

Total in-scope files tracked by git: 606.

| Path | Language | Line Count | Factual Purpose | Module |
|---|---|---|---|---|
| `.gitattributes` | Git Configuration | 8 | Defines git attributes and line-ending normalization rules. | `utilities_support` |
| `.github/workflows/defense_ci.yml` | YAML | 398 | Continuous integration workflow executing test batteries and lint checks. | `operational_scripts` |
| `.github/workflows/kani-proofs.yml` | YAML | 44 | Continuous integration workflow executing Kani formal verification harnesses. | `operational_scripts` |
| `.github/workflows/oqs-rebuild.yml` | YAML | 136 | Continuous integration workflow rebuilding native liboqs dynamic libraries. | `operational_scripts` |
| `.gitignore` | Git Configuration | 202 | Specifies patterns for untracked files and build artifacts to ignore. | `utilities_support` |
| `LICENSE` | Plain Text License | 21 | Contains the MIT open-source license terms. | `utilities_support` |
| `README.md` | Markdown | 874 | Top-level documentation outlining system architecture, threat model, and usage. | `documentation` |
| `SECURITY.md` | Markdown | 51 | Defines vulnerability reporting procedures and disclosure policy. | `documentation` |
| `active_cyber_defense.py` | Python | 570 | Monitors connection behavior and temporarily blocks suspicious network sources. | `audit_threat_monitoring` |
| `acvp_validation_harness.py` | Python | 538 | Automated test harness validating post-quantum and classical algorithms against NIST ACVP/CAVP vectors. | `verification_evidence` |
| `air_gapped_operation.py` | Python | 2082 | Facilitates offline data import and export procedures for air-gapped systems. | `system_hardening_integrity` |
| `anonymous_identity_manager.py` | Python | 1026 | Generates and rotates ephemeral cryptographic identifiers to prevent long-term tracking. | `transport_anonymity` |
| `anti_forensics.py` | Python | 1155 | Clears temporary files, shell histories, and system logs to minimize residual footprints. | `system_hardening_integrity` |
| `audit_logger.py` | Python | 22 | Records security events to local append-only log files with timestamps. | `audit_threat_monitoring` |
| `audit_logging_system.py` | Python | 1238 | Coordinates multi-channel audit event logging and structured record formatting. | `audit_threat_monitoring` |
| `balanced_logging.py` | Python | 268 | Balances log verbosity and disk usage by throttling repetitive log messages. | `audit_threat_monitoring` |
| `base.py` | Python | 257 | Defines abstract base classes and foundational interfaces for system components. | `orchestrator_application` |
| `byzantine_mesh_consensus.py` | Python | 972 | Executes Byzantine fault tolerant consensus over mesh network topologies. | `mesh_ddil_networking` |
| `ca_services.py` | Python | 2594 | Provides private certificate authority issuance, revocation, and certificate validation services. | `key_management_pki` |
| `cato_continuous_monitoring_engine.py` | Python | 307 | Collects continuous monitoring metrics supporting ongoing authorization. | `audit_threat_monitoring` |
| `cjadc2_allied_gateway.py` | Python | 863 | Translates and routes tactical messages across allied coalition gateway boundaries. | `tactical_command_cjadc2` |
| `cjadc2_cross_domain_guard.py` | Python | 482 | Inspects and filters messages crossing security classification domains. | `tactical_command_cjadc2` |
| `cjadc2_tactical_cot.py` | Python | 347 | Parses and serializes Cursor-on-Target (CoT) XML tactical location and status events. | `tactical_command_cjadc2` |
| `cng_crypto.py` | Python | 646 | Executes cryptographic operations through Windows CNG native library interfaces. | `key_management_pki` |
| `cng_platform.py` | Python | 250 | Interfaces with Windows Cryptography Next Generation (CNG) Platform Crypto Provider and TPM. | `key_management_pki` |
| `cnsa2_policy_engine.py` | Python | 684 | Enforces cryptographic policy rules requiring CNSA Suite 2.0 compliant algorithms. | `crypto_pqc` |
| `cnsa_purity.py` | Python | 261 | Validates cipher suite parameters against CNSA Suite 2.0 algorithm mandates. | `crypto_pqc` |
| `compliance_reports/active_cyber_defense_report.json` | JSON | 62 | Machine-readable compliance report documenting audit and verification results for active cyber defense report. | `compliance_artifacts` |
| `compliance_reports/active_cyber_defense_report.json.mldsa87.pub` | Cryptographic Public Key | 22 | Public key verifying signature on compliance record compliance_reports/active_cyber_defense_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/active_cyber_defense_report.json.mldsa87.sig` | Binary Signature | 32 | Digital signature validating authenticity of compliance record compliance_reports/active_cyber_defense_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/acvp_cavp_validation_report.json` | JSON | 167 | Machine-readable compliance report documenting audit and verification results for acvp cavp validation report. | `compliance_artifacts` |
| `compliance_reports/acvp_cavp_validation_report.json.mldsa87.pub` | Cryptographic Public Key | 22 | Public key verifying signature on compliance record compliance_reports/acvp_cavp_validation_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/acvp_cavp_validation_report.json.mldsa87.sig` | Binary Signature | 40 | Digital signature validating authenticity of compliance record compliance_reports/acvp_cavp_validation_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/ato_authorization_decision.json` | JSON | 98 | Machine-readable compliance report documenting audit and verification results for ato authorization decision. | `compliance_artifacts` |
| `compliance_reports/byzantine_consensus_receipt.json` | JSON | 24 | Machine-readable compliance report documenting audit and verification results for byzantine consensus receipt. | `compliance_artifacts` |
| `compliance_reports/byzantine_consensus_receipt.json.mldsa87.pub` | Cryptographic Public Key | 24 | Public key verifying signature on compliance record compliance_reports/byzantine_consensus_receipt.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/byzantine_consensus_receipt.json.mldsa87.sig` | Binary Signature | 42 | Digital signature validating authenticity of compliance record compliance_reports/byzantine_consensus_receipt.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/canary_pilot_telemetry.json` | JSON | 51 | Machine-readable compliance report documenting audit and verification results for canary pilot telemetry. | `compliance_artifacts` |
| `compliance_reports/cavp_validation_report.json` | JSON | 147 | Machine-readable compliance report documenting audit and verification results for cavp validation report. | `compliance_artifacts` |
| `compliance_reports/cbom.json` | JSON | 196 | Machine-readable compliance report documenting audit and verification results for cbom. | `compliance_artifacts` |
| `compliance_reports/cbom.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/cbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cbom.json.mldsa87.sig` | Binary Signature | 46 | Digital signature validating authenticity of compliance record compliance_reports/cbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cjadc2_allied_gateway_report.json` | JSON | 79 | Machine-readable compliance report documenting audit and verification results for cjadc2 allied gateway report. | `compliance_artifacts` |
| `compliance_reports/cjadc2_allied_gateway_report.json.mldsa87.pub` | Cryptographic Public Key | 22 | Public key verifying signature on compliance record compliance_reports/cjadc2_allied_gateway_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cjadc2_allied_gateway_report.json.mldsa87.sig` | Binary Signature | 35 | Digital signature validating authenticity of compliance record compliance_reports/cjadc2_allied_gateway_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cjadc2_cross_domain_audit.json` | JSON | 41 | Machine-readable compliance report documenting audit and verification results for cjadc2 cross domain audit. | `compliance_artifacts` |
| `compliance_reports/cjadc2_cross_domain_audit.json.mldsa87.pub` | Cryptographic Public Key | 29 | Public key verifying signature on compliance record compliance_reports/cjadc2_cross_domain_audit.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cjadc2_cross_domain_audit.json.mldsa87.sig` | Binary Signature | 39 | Digital signature validating authenticity of compliance record compliance_reports/cjadc2_cross_domain_audit.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cjadc2_data_fabric_drill_report.json` | JSON | 94 | Machine-readable compliance report documenting audit and verification results for cjadc2 data fabric drill report. | `compliance_artifacts` |
| `compliance_reports/cjadc2_data_fabric_drill_report.json.mldsa87.pub` | Cryptographic Public Key | 17 | Public key verifying signature on compliance record compliance_reports/cjadc2_data_fabric_drill_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cjadc2_data_fabric_drill_report.json.mldsa87.sig` | Binary Signature | 38 | Digital signature validating authenticity of compliance record compliance_reports/cjadc2_data_fabric_drill_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cmvp_fips140_3_submittal.json` | JSON | 62 | Machine-readable compliance report documenting audit and verification results for cmvp fips140 3 submittal. | `compliance_artifacts` |
| `compliance_reports/cmvp_fips140_3_submittal.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/cmvp_fips140_3_submittal.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cmvp_fips140_3_submittal.json.mldsa87.sig` | Binary Signature | 38 | Digital signature validating authenticity of compliance record compliance_reports/cmvp_fips140_3_submittal.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/conops_operational_profile.json` | JSON | 99 | Machine-readable compliance report documenting audit and verification results for conops operational profile. | `compliance_artifacts` |
| `compliance_reports/crypto_agility_audit.json` | JSON | 53 | Machine-readable compliance report documenting audit and verification results for crypto agility audit. | `compliance_artifacts` |
| `compliance_reports/crypto_agility_audit.json.mldsa87.pub` | Cryptographic Public Key | 22 | Public key verifying signature on compliance record compliance_reports/crypto_agility_audit.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/crypto_agility_audit.json.mldsa87.sig` | Binary Signature | 42 | Digital signature validating authenticity of compliance record compliance_reports/crypto_agility_audit.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/csrmc_operations_report.json` | JSON | 59 | Machine-readable compliance report documenting audit and verification results for csrmc operations report. | `compliance_artifacts` |
| `compliance_reports/csrmc_operations_report.json.mldsa87.pub` | Cryptographic Public Key | 23 | Public key verifying signature on compliance record compliance_reports/csrmc_operations_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/csrmc_operations_report.json.mldsa87.sig` | Binary Signature | 39 | Digital signature validating authenticity of compliance record compliance_reports/csrmc_operations_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/csrmc_phase5_drill_report.json` | JSON | 90 | Machine-readable compliance report documenting audit and verification results for csrmc phase5 drill report. | `compliance_artifacts` |
| `compliance_reports/csrmc_phase5_drill_report.json.mldsa87.pub` | Cryptographic Public Key | 23 | Public key verifying signature on compliance record compliance_reports/csrmc_phase5_drill_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/csrmc_phase5_drill_report.json.mldsa87.sig` | Binary Signature | 37 | Digital signature validating authenticity of compliance record compliance_reports/csrmc_phase5_drill_report.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cve_scan_offline.json` | JSON | 34 | Machine-readable compliance report documenting audit and verification results for cve scan offline. | `compliance_artifacts` |
| `compliance_reports/cyclonedx_cbom.json` | JSON | 323 | Machine-readable compliance report documenting audit and verification results for cyclonedx cbom. | `compliance_artifacts` |
| `compliance_reports/cyclonedx_cbom.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/cyclonedx_cbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cyclonedx_cbom.json.mldsa87.sig` | Binary Signature | 38 | Digital signature validating authenticity of compliance record compliance_reports/cyclonedx_cbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cyclonedx_sbom.json` | JSON | 233 | Machine-readable compliance report documenting audit and verification results for cyclonedx sbom. | `compliance_artifacts` |
| `compliance_reports/cyclonedx_sbom.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/cyclonedx_sbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/cyclonedx_sbom.json.mldsa87.sig` | Binary Signature | 44 | Digital signature validating authenticity of compliance record compliance_reports/cyclonedx_sbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/defense_master_audit_receipt.json` | JSON | 73 | Machine-readable compliance report documenting audit and verification results for defense master audit receipt. | `compliance_artifacts` |
| `compliance_reports/defense_master_audit_receipt.json.pub` | Cryptographic Public Key | 22 | Public key verifying signature on compliance record compliance_reports/defense_master_audit_receipt.json. | `compliance_artifacts` |
| `compliance_reports/defense_master_audit_receipt.json.sig` | Binary Signature | 42 | Digital signature validating authenticity of compliance record compliance_reports/defense_master_audit_receipt.json. | `compliance_artifacts` |
| `compliance_reports/dod_zero_trust_assessment.json` | JSON | 370 | Machine-readable compliance report documenting audit and verification results for dod zero trust assessment. | `compliance_artifacts` |
| `compliance_reports/dod_zero_trust_assessment.json.mldsa87.pub` | Cryptographic Public Key | 22 | Public key verifying signature on compliance record compliance_reports/dod_zero_trust_assessment.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/dod_zero_trust_assessment.json.mldsa87.sig` | Binary Signature | 26 | Digital signature validating authenticity of compliance record compliance_reports/dod_zero_trust_assessment.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/emergency_zeroization_audit.json` | JSON | 22 | Machine-readable compliance report documenting audit and verification results for emergency zeroization audit. | `compliance_artifacts` |
| `compliance_reports/emergency_zeroization_audit.json.mldsa87.pub` | Cryptographic Public Key | 23 | Public key verifying signature on compliance record compliance_reports/emergency_zeroization_audit.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/emergency_zeroization_audit.json.mldsa87.sig` | Binary Signature | 43 | Digital signature validating authenticity of compliance record compliance_reports/emergency_zeroization_audit.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/independent_redteam_assessment.json` | JSON | 122 | Machine-readable compliance report documenting audit and verification results for independent redteam assessment. | `compliance_artifacts` |
| `compliance_reports/independent_redteam_assessment.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/independent_redteam_assessment.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/independent_redteam_assessment.json.mldsa87.sig` | Binary Signature | 25 | Digital signature validating authenticity of compliance record compliance_reports/independent_redteam_assessment.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/key_management_plan.json` | JSON | 61 | Machine-readable compliance report documenting audit and verification results for key management plan. | `compliance_artifacts` |
| `compliance_reports/niap_common_criteria_matrix.json` | JSON | 110 | Machine-readable compliance report documenting audit and verification results for niap common criteria matrix. | `compliance_artifacts` |
| `compliance_reports/niap_common_criteria_matrix.json.mldsa87.pub` | Cryptographic Public Key | 23 | Public key verifying signature on compliance record compliance_reports/niap_common_criteria_matrix.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/niap_common_criteria_matrix.json.mldsa87.sig` | Binary Signature | 45 | Digital signature validating authenticity of compliance record compliance_reports/niap_common_criteria_matrix.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/oscal_sar_cato.json` | JSON | 281 | Machine-readable compliance report documenting audit and verification results for oscal sar cato. | `compliance_artifacts` |
| `compliance_reports/oscal_sar_cato.json.mldsa87.pub` | Cryptographic Public Key | 19 | Public key verifying signature on compliance record compliance_reports/oscal_sar_cato.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/oscal_sar_cato.json.mldsa87.sig` | Binary Signature | 46 | Digital signature validating authenticity of compliance record compliance_reports/oscal_sar_cato.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/oscal_ssp_cnsa2.json` | JSON | 255 | Machine-readable compliance report documenting audit and verification results for oscal ssp cnsa2. | `compliance_artifacts` |
| `compliance_reports/oscal_ssp_cnsa2.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/oscal_ssp_cnsa2.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/oscal_ssp_cnsa2.json.mldsa87.sig` | Binary Signature | 32 | Digital signature validating authenticity of compliance record compliance_reports/oscal_ssp_cnsa2.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/provenance.intoto.jsonl` | JSON Lines | 1 | Machine-readable compliance report documenting audit and verification results for provenance.intoto. | `compliance_artifacts` |
| `compliance_reports/red_team_drill_report.json` | JSON | 53 | Machine-readable compliance report documenting audit and verification results for red team drill report. | `compliance_artifacts` |
| `compliance_reports/sbom/cbom.json` | JSON | 196 | Machine-readable compliance report documenting audit and verification results for cbom. | `compliance_artifacts` |
| `compliance_reports/sbom/cbom.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/sbom/cbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/sbom/cbom.json.mldsa87.sig` | Binary Signature | 32 | Digital signature validating authenticity of compliance record compliance_reports/sbom/cbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/sbom/cyclonedx_sbom.json` | JSON | 271 | Machine-readable compliance report documenting audit and verification results for cyclonedx sbom. | `compliance_artifacts` |
| `compliance_reports/sbom/cyclonedx_sbom.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/sbom/cyclonedx_sbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/sbom/cyclonedx_sbom.json.mldsa87.sig` | Binary Signature | 43 | Digital signature validating authenticity of compliance record compliance_reports/sbom/cyclonedx_sbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/sbom/spdx_sbom.json` | JSON | 391 | Machine-readable compliance report documenting audit and verification results for spdx sbom. | `compliance_artifacts` |
| `compliance_reports/sbom/spdx_sbom.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/sbom/spdx_sbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/sbom/spdx_sbom.json.mldsa87.sig` | Binary Signature | 42 | Digital signature validating authenticity of compliance record compliance_reports/sbom/spdx_sbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/signed_reproducible_build_receipt.json` | JSON | 91 | Machine-readable compliance report documenting audit and verification results for signed reproducible build receipt. | `compliance_artifacts` |
| `compliance_reports/signed_reproducible_build_receipt.json.sig` | Binary Signature | 38 | Digital signature validating authenticity of compliance record compliance_reports/signed_reproducible_build_receipt.json. | `compliance_artifacts` |
| `compliance_reports/spdx_sbom.json` | JSON | 344 | Machine-readable compliance report documenting audit and verification results for spdx sbom. | `compliance_artifacts` |
| `compliance_reports/spdx_sbom.json.mldsa87.pub` | Cryptographic Public Key | 20 | Public key verifying signature on compliance record compliance_reports/spdx_sbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/spdx_sbom.json.mldsa87.sig` | Binary Signature | 27 | Digital signature validating authenticity of compliance record compliance_reports/spdx_sbom.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/ssdf_self_attestation.json` | JSON | 171 | Machine-readable compliance report documenting audit and verification results for ssdf self attestation. | `compliance_artifacts` |
| `compliance_reports/ssdf_self_attestation.json.mldsa87.pub` | Cryptographic Public Key | 18 | Public key verifying signature on compliance record compliance_reports/ssdf_self_attestation.json.mldsa87. | `compliance_artifacts` |
| `compliance_reports/ssdf_self_attestation.json.mldsa87.sig` | Binary Signature | 32 | Digital signature validating authenticity of compliance record compliance_reports/ssdf_self_attestation.json.mldsa87. | `compliance_artifacts` |
| `config.json.sig` | Binary Signature | 5 | Cryptographic signature verifying authenticity of config.json. | `utilities_support` |
| `config.py` | Python | 760 | Provides configuration management class and environment variable loaders. | `utilities_support` |
| `config_production.json` | JSON | 95 | Production configuration parameters specifying ports, timeouts, and security gates. | `utilities_support` |
| `config_production.json.sig` | Binary Signature | 1 | Cryptographic signature verifying authenticity of config_production.json. | `utilities_support` |
| `config_template.json` | JSON | 98 | Template configuration file with placeholder connection and key settings. | `utilities_support` |
| `continuous_security_monitor.py` | Python | 1789 | Periodically evaluates system security health indicators and daemon status. | `audit_threat_monitoring` |
| `core/__init__.py` | Python | 10 | Package initialization file exposing core application interfaces. | `orchestrator_application` |
| `core/config.py` | Python | 110 | Centralizes application configuration properties and environment overrides. | `orchestrator_application` |
| `core/orchestrator.py` | Python | 1714 | Coordinates core subsystem initialization, lifecycle transitions, and shutdown sequences. | `orchestrator_application` |
| `covert_channel_defense.py` | Python | 1385 | Inspects and sanitizes protocol headers to prevent covert channel data leakage. | `transport_anonymity` |
| `critical_modules.hashes` | Hash Manifest | 22 | Hash manifest containing SHA-256 digests of core product files. | `system_hardening_integrity` |
| `critical_release.py` | Python | 382 | Enforces two-person rule approval workflows before releasing authorization directives. | `tactical_command_cjadc2` |
| `cross_platform_exception_handler.py` | Python | 1585 | Normalizes exception handling and error reporting across Windows and POSIX systems. | `orchestrator_application` |
| `crypto/__init__.py` | Python | 10 | Package initialization file exposing cryptographic operation classes. | `crypto_pqc` |
| `crypto/auth_tags.py` | Python | 233 | Computes and verifies HMAC and GMAC authentication tags for message integrity. | `crypto_pqc` |
| `crypto/kem.py` | Python | 382 | Implements key encapsulation mechanism operations wrapping post-quantum KEM functions. | `crypto_pqc` |
| `crypto/operations.py` | Python | 54 | Provides symmetric encryption and decryption operations using AES-256-GCM. | `crypto_pqc` |
| `crypto/padding.py` | Python | 184 | Applies cryptographic padding and length-hiding transformations to payloads. | `crypto_pqc` |
| `crypto/signatures.py` | Python | 259 | Generates and verifies digital signatures using post-quantum and classical algorithms. | `crypto_pqc` |
| `crypto_selftest.py` | Python | 317 | Executes known-answer tests (KAT) and self-tests for cryptographic implementations at startup. | `crypto_pqc` |
| `cryptographic_agility.py` | Python | 1310 | Provides dynamic algorithm substitution interfaces while enforcing minimum security levels. | `orchestrator_application` |
| `cryptographic_errors.py` | Python | 768 | Defines custom exception hierarchy for cryptographic and policy validation failures. | `orchestrator_application` |
| `csrmc_operations_monitor.py` | Python | 217 | Tracks supply chain risk management controls and component provenance metrics. | `audit_threat_monitoring` |
| `data/__init__.py` | Python | 19 | Package initialization file exposing data management interfaces. | `messaging_file_transfer` |
| `data/file_transfer.py` | Python | 645 | Tracks active file transfer metadata and progress indicators. | `messaging_file_transfer` |
| `data/manager.py` | Python | 45 | Provides high-level data storage and retrieval interfaces. | `messaging_file_transfer` |
| `data/peer_mgmt.py` | Python | 272 | Stores and queries peer profiles, addresses, and cryptographic credentials. | `messaging_file_transfer` |
| `data/user_mgmt.py` | Python | 602 | Manages local user credentials, account parameters, and profile data. | `messaging_file_transfer` |
| `data_models.py` | Python | 295 | Defines dataclass models for messages, peer credentials, and session state. | `orchestrator_application` |
| `decentralized_architecture.py` | Python | 3306 | Manages peer-to-peer overlay network topology and distributed peer discovery. | `transport_anonymity` |
| `dep_impl.py` | Python | 4437 | Provides fallback implementations and compatibility shims for external dependencies. | `orchestrator_application` |
| `dependency_security_verifier.py` | Python | 1023 | Verifies hashes and digital signatures of third-party libraries before execution. | `system_hardening_integrity` |
| `deploy/openssl_cnsa.cnf` | OpenSSL Configuration | 39 | OpenSSL configuration profile specifying CNSA Suite 2.0 cipher suites. | `tls_channel` |
| `destroyer.py` | Python | 499 | Application launcher coordinating node initialization, CLI commands, and event loops. | `orchestrator_application` |
| `destroyer_node.py` | Python | 562 | Encapsulates peer node lifecycle, session management, and UI coordination. | `orchestrator_application` |
| `destroyer_tactical_p2p.py` | Python | 820 | Coordinates tactical peer-to-peer transport sessions and message delivery. | `orchestrator_application` |
| `docs/ARCHITECTURE.md` | Markdown | 100 | Technical specification detailing system architecture and security boundaries. | `documentation` |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md` | Markdown | 131 | Technical analysis document comparing system protocols against alternative architectures. | `documentation` |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md` | Markdown | 376 | Operational concept document outlining deployment procedures in constrained networks. | `documentation` |
| `docs/DEFENSE_HARDENING_MASTER_PLAN.md` | Markdown | 685 | Hardening roadmap specifying criteria for defense operating environments. | `documentation` |
| `docs/EVALUATION_DOSSIER.md` | Markdown | 124 | Technical evaluation dossier compiling verification criteria for laboratory assessment. | `documentation` |
| `docs/FIPS_140_3_SECURITY_POLICY.md` | Markdown | 104 | Security policy document defining cryptographic module interfaces and roles. | `documentation` |
| `docs/FIREWALL_IPV6.md` | Markdown | 35 | Firewall configuration guide detailing IPv6 packet filtering rules. | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_REMEDIATION_PLAN.md` | Markdown | 37 | Technical document describing FORENSIC SECURITY AUDIT 2026 10 24 REMEDIATION PLAN. | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_3_REMEDIATION.md` | Markdown | 114 | Technical document describing FORENSIC SECURITY AUDIT 3 REMEDIATION. | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_4_REMEDIATION.md` | Markdown | 140 | Technical document describing FORENSIC SECURITY AUDIT 4 REMEDIATION. | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md` | Markdown | 337 | Technical document describing FORENSIC SECURITY AUDIT FINAL 2026 10 21. | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md` | Markdown | 269 | Technical document describing FORENSIC SECURITY AUDIT FINAL 2026 10 24. | `documentation` |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md` | Markdown | 59 | Technical document describing FORENSIC SECURITY AUDIT REMEDIATION PLAN. | `documentation` |
| `docs/FULL_CODEBASE_SECURITY_REVIEW_2026_10.md` | Markdown | 135 | Technical document describing FULL CODEBASE SECURITY REVIEW 2026 10. | `documentation` |
| `docs/KEY_CEREMONY.md` | Markdown | 63 | Standard operating procedure detailing threshold root key generation ceremony. | `documentation` |
| `docs/KEY_MANAGEMENT_PLAN_KMP.md` | Markdown | 73 | Cryptographic key management plan defining key generation, distribution, and destruction. | `documentation` |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md` | Markdown | 169 | Operational guide detailing deployment requirements for high-assurance command terminals. | `documentation` |
| `docs/NIAP_COMMON_CRITERIA_SECURITY_TARGET.md` | Markdown | 47 | Security target document defining protection profile compliance objectives. | `documentation` |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md` | Markdown | 228 | Architecture specification for high-assurance national security communication systems. | `documentation` |
| `docs/OPEN_INTERNET_HARDENING_PLAN.md` | Markdown | 229 | Hardening guide detailing configuration for open network deployment. | `documentation` |
| `docs/README.md` | Markdown | 122 | Documentation index cataloging engineering specifications and modules. | `documentation` |
| `docs/RESTRUCTURE_PLAN.md` | Markdown | 240 | Codebase restructuring plan detailing module isolation procedures. | `documentation` |
| `docs/RUST_CORE.md` | Markdown | 172 | Architecture specification for the native Rust data plane implementation. | `documentation` |
| `docs/SEL4_EAL6_PLUS_SOVEREIGN_APPLIANCE_SPEC.md` | Markdown | 222 | Technical document describing SEL4 EAL6 PLUS autonomous APPLIANCE SPEC. | `documentation` |
| `docs/SOP.md` | Markdown | 75 | Standard operating procedures defining operator roles and administration checklists. | `documentation` |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md` | Markdown | 183 | Technical specification and state machine definitions for defense transit protocol. | `documentation` |
| `docs/ST2027_IMPLEMENTATION_PLAN.md` | Markdown | 112 | Engineering implementation plan outlining component migration phases. | `documentation` |
| `docs/ST2027_RESEARCH_SOURCES_2026-09-30.md` | Markdown | 218 | Literature survey compiling academic citations and standards references. | `documentation` |
| `docs/ST2027_SPEC.md` | Markdown | 283 | Wire format and state machine specification for the transport protocol. | `documentation` |
| `docs/ST2027_SPECIFICATION.md` | Markdown | 175 | Technical document describing ST2027 SPECIFICATION. | `documentation` |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md` | Markdown | 74914 | Technical specification describing system security tiers and enforcement mechanisms. | `documentation` |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md` | Markdown | 12367 | Technical specification detailing mechanical logic flows and parameter catalog. | `documentation` |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md` | Markdown | 351 | Technical manual detailing configuration and operation of tactical communication nodes. | `documentation` |
| `docs/airgap_runbook.md` | Markdown | 126 | Operational runbook for installing and operating nodes in air-gapped facilities. | `documentation` |
| `docs/current_audit_inventory.json` | JSON | 58 | Technical document describing current audit inventory. | `documentation` |
| `docs/deployment_hardening_guide.md` | Markdown | 81 | Host configuration guide detailing operating system hardening procedures. | `documentation` |
| `docs/dll_ca_ceremony_receipt.json` | JSON | 27 | Technical document describing dll ca ceremony receipt. | `documentation` |
| `docs/formal/README.md` | Markdown | 73 | Documentation describing formal verification models, assumptions, and proof results. | `formal_verification` |
| `docs/formal/check.sh` | Shell Script | 49 | Shell script executing ProVerif formal verification models against security queries. | `formal_verification` |
| `docs/formal/handshake_model.pv` | ProVerif Model | 187 | ProVerif formal verification model specifying protocol processes and secrecy queries for handshake model. | `formal_verification` |
| `docs/formal/nc3_dual_custody.pv` | ProVerif Model | 237 | ProVerif formal verification model specifying protocol processes and secrecy queries for nc3 dual custody. | `formal_verification` |
| `docs/formal/st2027_handshake.pv` | ProVerif Model | 282 | ProVerif formal verification model specifying protocol processes and secrecy queries for st2027 handshake. | `formal_verification` |
| `docs/formal/st2027_pcs.pv` | ProVerif Model | 191 | ProVerif formal verification model specifying protocol processes and secrecy queries for st2027 pcs. | `formal_verification` |
| `docs/hw_tpm_hsm_setup.md` | Markdown | 99 | Hardware setup guide for configuring TPM 2.0 and PKCS#11 cryptographic tokens. | `documentation` |
| `docs/incident_response.md` | Markdown | 82 | Incident response plan outlining post-incident containment and recovery actions. | `documentation` |
| `docs/liboqs_pin.md` | Markdown | 245 | Provenance document recording commit hash and verification digests for native liboqs. | `documentation` |
| `docs/modules/anonymity_decentral.md` | Markdown | 34 | Specification document detailing design claims and interfaces for anonymity decentral module. | `documentation` |
| `docs/modules/audit_threat_supply.md` | Markdown | 25 | Specification document detailing design claims and interfaces for audit threat supply module. | `documentation` |
| `docs/modules/ca_services.md` | Markdown | 30 | Specification document detailing design claims and interfaces for ca services module. | `documentation` |
| `docs/modules/critical_release.md` | Markdown | 27 | Specification document detailing design claims and interfaces for critical release module. | `documentation` |
| `docs/modules/destroyer_node.md` | Markdown | 34 | Specification document detailing design claims and interfaces for destroyer node module. | `documentation` |
| `docs/modules/double_ratchet.md` | Markdown | 37 | Specification document detailing design claims and interfaces for double ratchet module. | `documentation` |
| `docs/modules/entropy_sidechannel.md` | Markdown | 23 | Specification document detailing design claims and interfaces for entropy sidechannel module. | `documentation` |
| `docs/modules/file_transfer.md` | Markdown | 29 | Specification document detailing design claims and interfaces for file transfer module. | `documentation` |
| `docs/modules/hardware_trust.md` | Markdown | 20 | Specification document detailing design claims and interfaces for hardware trust module. | `documentation` |
| `docs/modules/hybrid_kex.md` | Markdown | 30 | Specification document detailing design claims and interfaces for hybrid kex module. | `documentation` |
| `docs/modules/memory_hsm.md` | Markdown | 23 | Specification document detailing design claims and interfaces for memory hsm module. | `documentation` |
| `docs/modules/noise_pq.md` | Markdown | 82 | Specification document detailing design claims and interfaces for noise pq module. | `documentation` |
| `docs/modules/opsec_persistence.md` | Markdown | 28 | Specification document detailing design claims and interfaces for opsec persistence module. | `documentation` |
| `docs/modules/p2p_core.md` | Markdown | 35 | Specification document detailing design claims and interfaces for p2p core module. | `documentation` |
| `docs/modules/pqc_algorithms.md` | Markdown | 37 | Specification document detailing design claims and interfaces for pqc algorithms module. | `documentation` |
| `docs/modules/root_files.md` | Markdown | 32 | Specification document detailing design claims and interfaces for root files module. | `documentation` |
| `docs/modules/rust_data_plane.md` | Markdown | 50 | Specification document detailing design claims and interfaces for rust data plane module. | `documentation` |
| `docs/modules/safety_numbers.md` | Markdown | 29 | Specification document detailing design claims and interfaces for safety numbers module. | `documentation` |
| `docs/modules/secure_p2p.md` | Markdown | 73 | Specification document detailing design claims and interfaces for secure p2p module. | `documentation` |
| `docs/modules/subsystems_core.md` | Markdown | 16 | Specification document detailing design claims and interfaces for subsystems core module. | `documentation` |
| `docs/modules/subsystems_support.md` | Markdown | 32 | Specification document detailing design claims and interfaces for subsystems support module. | `documentation` |
| `docs/modules/tls_channel_manager.md` | Markdown | 38 | Specification document detailing design claims and interfaces for tls channel manager module. | `documentation` |
| `docs/modules/transport_anonymity.md` | Markdown | 68 | Specification document detailing design claims and interfaces for transport anonymity module. | `documentation` |
| `docs/modules/trust_anchor.md` | Markdown | 59 | Specification document detailing design claims and interfaces for trust anchor module. | `documentation` |
| `docs/modules/trust_policy.md` | Markdown | 31 | Specification document detailing design claims and interfaces for trust policy module. | `documentation` |
| `docs/modules/ts_hw_layer.md` | Markdown | 67 | Specification document detailing design claims and interfaces for ts hw layer module. | `documentation` |
| `docs/modules/ts_runtime.md` | Markdown | 58 | Specification document detailing design claims and interfaces for ts runtime module. | `documentation` |
| `docs/security_audit_report.md` | Markdown | 451 | Audit report documenting security findings and remediation verification records. | `documentation` |
| `double_ratchet.py` | Python | 5709 | Implements the Double Ratchet protocol for forward secrecy and break-in recovery in messaging sessions. | `ratchet_kex_protocol` |
| `emergency_anti_tamper.py` | Python | 275 | Detects hardware tampering or debugger attachment and triggers state zeroization. | `system_hardening_integrity` |
| `enhanced_audit_logging.py` | Python | 1282 | Generates cryptographically linked audit log entries with integrity hashes. | `audit_threat_monitoring` |
| `enhanced_peer_manager.py` | Python | 965 | Tracks peer identities, connection status, latency, and trust ratings. | `messaging_file_transfer` |
| `enhanced_secure_memory.py` | Python | 1102 | Provides secure memory allocation wrapper with page locking and canaries. | `memory_security` |
| `enhanced_security_features.py` | Python | 678 | Provides feature toggles and guards for high-assurance security options. | `security_framework` |
| `entropy_manager.py` | Python | 1126 | Gathers and evaluates system entropy from multiple hardware and OS sources. | `memory_security` |
| `ephemeral_messaging.py` | Python | 1716 | Handles ephemeral message expiration, timer-based deletion, and memory purging. | `messaging_file_transfer` |
| `file_transfer.py` | Python | 634 | Handles file chunking, reassembly, and progress tracking across network channels. | `messaging_file_transfer` |
| `forward_secrecy_manager.py` | Python | 755 | Manages session key ratcheting intervals and ephemeral key disposal. | `ratchet_kex_protocol` |
| `group_key_manager.py` | Python | 1741 | Coordinates symmetric group keys and sender keys for multi-party group sessions. | `ratchet_kex_protocol` |
| `hsm_integration.py` | Python | 247 | Interacts with PKCS#11 hardware security modules for cryptographic operations and key storage. | `key_management_pki` |
| `hw_readiness.py` | Python | 423 | Checks availability and readiness of hardware security modules and platform cryptographic providers. | `host_runtime_attestation` |
| `hybrid_kex.py` | Python | 3467 | Performs hybrid key exchange combining classical elliptic curve Diffie-Hellman with ML-KEM-1024. | `ratchet_kex_protocol` |
| `key_fill_import.py` | Python | 352 | Imports pre-shared keys and electronic key material from offline key fill files. | `key_management_pki` |
| `keys/__init__.py` | Python | 9 | Package initialization file exposing key management interfaces. | `key_management_pki` |
| `keys/generation.py` | Python | 171 | Generates symmetric and asymmetric cryptographic key pairs. | `key_management_pki` |
| `keys/hsm_integration.py` | Python | 261 | Provides HSM key generation and storage helper functions. | `key_management_pki` |
| `keys/manager.py` | Python | 54 | Coordinates key storage, lookup, and lifecycle states. | `key_management_pki` |
| `keys/rotation.py` | Python | 200 | Executes scheduled and event-driven cryptographic key rotation procedures. | `key_management_pki` |
| `keys/storage.py` | Python | 216 | Persists encrypted key material to filesystem storage. | `key_management_pki` |
| `launch_tactical_terminals.bat` | Batch Script | 14 | Batch script launching dual terminal instances for local communication testing. | `tactical_command_cjadc2` |
| `launch_tactical_web.bat` | Batch Script | 11 | Batch script launching web console backend and browser interface. | `tactical_command_cjadc2` |
| `liboqs_wrapper.py` | Python | 1288 | Provides ctypes bindings to native liboqs C shared library for post-quantum operations. | `crypto_pqc` |
| `libsodium.dll` | Dynamic Link Library | 1334 | Vendored dynamic link library binary providing libsodium cryptographic routines. | `system_hardening_integrity` |
| `libsodium.dll.hashes` | Hash Manifest | 5 | Hash manifest recording SHA-256 and SHA-512 digests of libsodium.dll. | `system_hardening_integrity` |
| `libsodium.dll.pub` | Cryptographic Public Key | 3 | Public key file used to verify digital signatures on libsodium.dll. | `system_hardening_integrity` |
| `libsodium.dll.sig` | Binary Signature | 1 | Digital signature verifying authenticity and integrity of libsodium.dll. | `system_hardening_integrity` |
| `libsodium_manager.py` | Python | 1582 | Manages ctypes bindings and invocation of libsodium cryptographic functions. | `crypto_pqc` |
| `logging_config.py` | Python | 199 | Configures Python standard logging formatters, log levels, and destination handlers. | `audit_threat_monitoring` |
| `maximum_security_hardening.py` | Python | 677 | Enforces strict configuration parameters disabling all optional legacy fallbacks. | `security_framework` |
| `memory_manager.py` | Python | 1699 | Allocates, locks, and zeroizes memory buffers holding sensitive cryptographic keys. | `memory_security` |
| `memory_protection_engine.py` | Python | 1072 | Enforces operating system memory protection attributes and prevents memory dumps. | `memory_security` |
| `messaging/__init__.py` | Python | 9 | Package initialization file exposing messaging interfaces. | `messaging_file_transfer` |
| `messaging/commands.py` | Python | 888 | Parses and executes user chat slash commands and administrative actions. | `messaging_file_transfer` |
| `messaging/encryption.py` | Python | 261 | Applies per-message encryption and decryption transformations. | `messaging_file_transfer` |
| `messaging/handler.py` | Python | 249 | Dispatches incoming chat and system messages to registered handler callbacks. | `messaging_file_transfer` |
| `messaging/manager.py` | Python | 74 | Coordinates messaging state machines, message queues, and active chats. | `messaging_file_transfer` |
| `metadata_resistance.py` | Python | 1022 | Strips identifiable metadata and normalizes message framing across network links. | `transport_anonymity` |
| `military_security_enforcement.py` | Python | 213 | Validates operational parameters against high-assurance defense baseline requirements. | `security_framework` |
| `mls_framing.py` | Python | 387 | Encodes and parses Messaging Layer Security (MLS) protocol frame formats. | `ratchet_kex_protocol` |
| `multi_device_manager.py` | Python | 1557 | Syncs message history and cryptographic session keys across multiple user devices. | `messaging_file_transfer` |
| `native_secure_buffer.py` | Python | 388 | Implements ctypes buffer allocation with VirtualLock and explicit memset zeroization. | `memory_security` |
| `nc3_nuclear_command.py` | Python | 1786 | Implements dual-person authorization and two-terminal confirmation protocols for critical commands. | `tactical_command_cjadc2` |
| `network/__init__.py` | Python | 11 | Package initialization file exposing network management interfaces. | `mesh_ddil_networking` |
| `network/connection.py` | Python | 615 | Manages individual peer TCP and UDP socket connection lifecycles. | `mesh_ddil_networking` |
| `network/handshake.py` | Python | 344 | Executes cryptographic handshake sequence between connecting network peers. | `mesh_ddil_networking` |
| `network/io.py` | Python | 349 | Performs non-blocking socket input/output operations. | `mesh_ddil_networking` |
| `network/manager.py` | Python | 54 | Coordinates active network connections and interface bindings. | `mesh_ddil_networking` |
| `network/monitoring.py` | Python | 365 | Monitors network throughput, latency, and socket error rates. | `mesh_ddil_networking` |
| `network/session_manager.py` | Python | 1435 | Maintains session state tables and connection association mappings. | `mesh_ddil_networking` |
| `network_adversary_resistance.py` | Python | 1621 | Monitors network connections for traffic correlation and packet manipulation. | `transport_anonymity` |
| `network_endpoint_discovery.py` | Python | 540 | Discovers network peer endpoints via local broadcast and distributed lookup. | `transport_anonymity` |
| `nist_level5_policy_engine.py` | Python | 484 | Restricts key exchange and signature algorithms to NIST Security Level 5 parameter sets. | `crypto_pqc` |
| `noise_pq.py` | Python | 987 | Implements Noise protocol framework handshakes hybridized with post-quantum KEMs. | `ratchet_kex_protocol` |
| `openssl_cnsa2_posture.cnf` | OpenSSL Configuration | 35 | Configuration file for OpenSSL enforcing CNSA 2.0 cryptographic posture. | `tls_channel` |
| `operational_security.py` | Python | 1072 | Applies operational security policies restricting network exposure and storage. | `system_hardening_integrity` |
| `oqs.dll` | Dynamic Link Library | 23862 | Vendored dynamic link library binary providing liboqs post-quantum algorithms. | `system_hardening_integrity` |
| `oqs.dll.hashes` | Hash Manifest | 5 | Hash manifest recording SHA-256 and SHA-512 digests of oqs.dll. | `system_hardening_integrity` |
| `oqs.dll.pub` | Cryptographic Public Key | 3 | Public key file used to verify digital signatures on oqs.dll. | `system_hardening_integrity` |
| `oqs.dll.sig` | Binary Signature | 2 | Digital signature verifying authenticity and integrity of oqs.dll. | `system_hardening_integrity` |
| `p2p_core.py` | Python | 2664 | Core networking engine managing TCP/UDP sockets, packet framing, and peer connection state. | `mesh_ddil_networking` |
| `paced_socket_wrapper.py` | Python | 328 | Wraps network sockets to transmit packets at fixed time intervals. | `transport_anonymity` |
| `platform_hsm_interface.py` | Python | 11641 | Provides abstraction layer interfacing with hardware security modules and cryptographic tokens. | `key_management_pki` |
| `pq_certificate_authority.py` | Python | 1306 | Generates and verifies X.509-style certificates signed with post-quantum signature schemes. | `key_management_pki` |
| `pq_treekem.py` | Python | 444 | Applies post-quantum key encapsulation mechanisms to TreeKEM group state updates. | `ratchet_kex_protocol` |
| `pqc_algorithms.py` | Python | 8320 | Implements post-quantum cryptographic primitives including ML-KEM, ML-DSA, SLH-DSA, and hybrid combinations. | `crypto_pqc` |
| `pqc_crypto_agility_engine.py` | Python | 349 | Selects and negotiates post-quantum algorithm suites based on configured security posture. | `crypto_pqc` |
| `process_monitor_manager.py` | Python | 1201 | Monitors local operating system process integrity and detects unauthorized child processes. | `audit_threat_monitoring` |
| `production_gate.py` | Python | 189 | Enforces fail-closed validation gates preventing execution with development settings in production. | `security_framework` |
| `production_pqc_algorithms.py` | Python | 509 | Restricts cryptographic algorithm selection to CNSA Suite 2.0 algorithms for production environments. | `crypto_pqc` |
| `protocol_manager.py` | Python | 979 | Coordinates protocol version negotiation and handler dispatch. | `orchestrator_application` |
| `pytest.ini` | INI Configuration | 55 | Configures pytest execution options, test paths, and markers. | `utilities_support` |
| `quantum_rng.py` | Python | 767 | Interfaces with hardware random number generators and validates statistical randomness. | `memory_security` |
| `red_team_adversarial_drill.py` | Python | 359 | Simulates adversarial network attacks to test defensive response mechanisms. | `verification_evidence` |
| `remote_siem_forwarder.py` | Python | 567 | Forwards encrypted audit event records to remote SIEM collection endpoints. | `audit_threat_monitoring` |
| `report_trust.py` | Python | 365 | Validates digital signatures and cryptographic anchors on generated report documents. | `audit_threat_monitoring` |
| `requirements-test.txt` | Plain Text | 9 | Defines pinned Python dependencies required for running test suites. | `utilities_support` |
| `requirements.txt` | Plain Text | 54 | Defines pinned Python runtime dependencies and cryptographic packages. | `utilities_support` |
| `resilient_communication.py` | Python | 742 | Provides transport failover across alternative network interfaces and radio links. | `mesh_ddil_networking` |
| `rust_backend.py` | Python | 153 | Python wrapper interfacing with native Rust data plane dynamic library. | `rust_data_plane` |
| `rust_data_plane/.gitignore` | Git Configuration | 5 | Git ignore file for rust_data_plane build output. | `rust_data_plane` |
| `rust_data_plane/Cargo.lock` | Cargo Lockfile | 1030 | Cargo lockfile recording exact dependency versions for rust_data_plane. | `rust_data_plane` |
| `rust_data_plane/Cargo.toml` | TOML | 47 | Cargo manifest defining dependencies and build profiles for native Rust data plane. | `rust_data_plane` |
| `rust_data_plane/pyproject.toml` | TOML | 15 | PyO3 build system configuration for building destroyer_core Python extension. | `rust_data_plane` |
| `rust_data_plane/python/destroyer_core/__init__.py` | Python | 47 | Python module exposing native Rust PyO3 bindings. | `rust_data_plane` |
| `rust_data_plane/src/acd.rs` | Rust | 320 | Active defense module detecting and countering abnormal network patterns in Rust. | `rust_data_plane` |
| `rust_data_plane/src/aead.rs` | Rust | 366 | Authenticated encryption and decryption wrappers using AES-256-GCM. | `rust_data_plane` |
| `rust_data_plane/src/attest.rs` | Rust | 272 | Platform attestation quote validation logic implemented in Rust. | `rust_data_plane` |
| `rust_data_plane/src/auth.rs` | Rust | 178 | Authentication tag verification and identity assertion validation. | `rust_data_plane` |
| `rust_data_plane/src/chaff.rs` | Rust | 5 | Generates and injects dummy chaff traffic to obscure transmission volume. | `rust_data_plane` |
| `rust_data_plane/src/cookie.rs` | Rust | 432 | SYN-flood and replay resistance cookie generation and validation. | `rust_data_plane` |
| `rust_data_plane/src/ct.rs` | Rust | 78 | Constant-time cryptographic utility functions preventing timing side channels. | `rust_data_plane` |
| `rust_data_plane/src/fec.rs` | Rust | 428 | Cauchy-Reed-Solomon erasure coding forward error correction implementation. | `rust_data_plane` |
| `rust_data_plane/src/ffi.rs` | Rust | 1003 | C-compatible and Python PyO3 foreign function interface declarations. | `rust_data_plane` |
| `rust_data_plane/src/frame.rs` | Rust | 86 | Network frame parsing, serialization, and fixed-size cell packing. | `rust_data_plane` |
| `rust_data_plane/src/group_ratchet.rs` | Rust | 460 | Multi-party group ratchet state and symmetric key tree derivation. | `rust_data_plane` |
| `rust_data_plane/src/handshake.rs` | Rust | 829 | State machine implementing cryptographic handshake exchange. | `rust_data_plane` |
| `rust_data_plane/src/kem.rs` | Rust | 304 | Key encapsulation mechanism operations wrapping ML-KEM-1024. | `rust_data_plane` |
| `rust_data_plane/src/kex_auth.rs` | Rust | 362 | Authenticated key exchange validation and signature verification. | `rust_data_plane` |
| `rust_data_plane/src/keystore.rs` | Rust | 268 | In-memory protected storage for active session keys. | `rust_data_plane` |
| `rust_data_plane/src/lib.rs` | Rust | 490 | Crate root exposing library functions and PyO3 module bindings. | `rust_data_plane` |
| `rust_data_plane/src/main.rs` | Rust | 2634 | Standalone executable command-line interface and daemon process. | `rust_data_plane` |
| `rust_data_plane/src/memlock.rs` | Rust | 173 | Virtual memory page locking preventing paging of sensitive cryptographic data. | `rust_data_plane` |
| `rust_data_plane/src/memory_guard.rs` | Rust | 164 | RAII memory guard ensuring volatile zeroization upon deallocation. | `rust_data_plane` |
| `rust_data_plane/src/net.rs` | Rust | 493 | Non-blocking UDP socket management and network packet dispatch. | `rust_data_plane` |
| `rust_data_plane/src/nostd_microcore.rs` | Rust | 430 | Minimal no-std core components designed for bare-metal execution. | `rust_data_plane` |
| `rust_data_plane/src/pacing.rs` | Rust | 219 | Constant-interval packet scheduler preventing inter-arrival timing correlation. | `rust_data_plane` |
| `rust_data_plane/src/pad.rs` | Rust | 12 | Frame padding implementation ensuring uniform cell wire length. | `rust_data_plane` |
| `rust_data_plane/src/pki.rs` | Rust | 448 | Public key infrastructure certificate verification and anchor validation. | `rust_data_plane` |
| `rust_data_plane/src/policy.rs` | Rust | 155 | Security policy rule evaluation and mandatory access gating. | `rust_data_plane` |
| `rust_data_plane/src/purge.rs` | Rust | 127 | Emergency memory wiping and cryptographic state zeroization. | `rust_data_plane` |
| `rust_data_plane/src/ratchet.rs` | Rust | 303 | Symmetric key ratchet progression for per-frame forward secrecy. | `rust_data_plane` |
| `rust_data_plane/src/replay.rs` | Rust | 354 | Sliding-window replay detection filter tracking received sequence numbers. | `rust_data_plane` |
| `rust_data_plane/src/session.rs` | Rust | 257 | Session state tracking combining handshake, ratchets, and transport queues. | `rust_data_plane` |
| `rust_data_plane/src/tpm_nv.rs` | Rust | 956 | TPM 2.0 non-volatile index read and write operations. | `rust_data_plane` |
| `rust_data_plane/src/zero_trust.rs` | Rust | 414 | Continuous zero-trust authorization check on all incoming network frames. | `rust_data_plane` |
| `rust_data_plane/tests/kani_harness.rs` | Rust | 414 | Kani model checking proof harnesses verifying memory safety invariants in Rust. | `tests` |
| `scripts/audit_pins.py` | Python | 93 | Verifies dependency pinning consistency across requirements files. | `operational_scripts` |
| `scripts/cavp_algorithm_validator.py` | Python | 247 | Validates cryptographic implementations against NIST CAVP test vectors. | `operational_scripts` |
| `scripts/crl_bundle.py` | Python | 295 | Generates and signs certificate revocation list (CRL) distribution bundles. | `operational_scripts` |
| `scripts/cve_scan.py` | Python | 266 | Scans dependencies against known vulnerability databases. | `operational_scripts` |
| `scripts/deploy_canary_pilot.py` | Python | 261 | Deploys canary test instances for staged rollout verification. | `operational_scripts` |
| `scripts/deploy_production.py` | Python | 404 | Packages and verifies production deployment releases. | `operational_scripts` |
| `scripts/generate_oscal_sar.py` | Python | 295 | Generates OSCAL Security Assessment Results (SAR) machine-readable documents. | `operational_scripts` |
| `scripts/generate_oscal_ssp.py` | Python | 347 | Generates OSCAL System Security Plan (SSP) control compliance documentation. | `operational_scripts` |
| `scripts/generate_production_cbom.py` | Python | 393 | Generates Cryptography Bill of Materials (CBOM) inventory in JSON format. | `operational_scripts` |
| `scripts/generate_production_sbom.py` | Python | 713 | Generates CycloneDX Software Bill of Materials (SBOM) for installed dependencies. | `operational_scripts` |
| `scripts/generate_sovereign_pki.py` | Python | 203 | Generates root and intermediate PKI certificates for testing environments. | `operational_scripts` |
| `scripts/package_deployment.py` | Python | 169 | Packages application binaries and configuration assets into distribution archives. | `operational_scripts` |
| `scripts/run_defense_audit.py` | Python | 267 | Executes automated compliance audit checks and security policy verification. | `operational_scripts` |
| `scripts/run_phase5_csrmc_operations_drill.py` | Python | 496 | Runs automated operational drill verifying supply chain security controls. | `operational_scripts` |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py` | Python | 468 | Runs automated drill verifying tactical data fabric message routing. | `operational_scripts` |
| `scripts/setup_tor_overlay.ps1` | PowerShell Script | 87 | PowerShell script configuring local Tor daemon and hidden service endpoints. | `operational_scripts` |
| `scripts/setup_tor_overlay.sh` | Shell Script | 44 | Shell script configuring Tor daemon and onion service routing. | `operational_scripts` |
| `scripts/setup_wireguard.ps1` | PowerShell Script | 53 | PowerShell script configuring WireGuard tunnel interfaces on Windows. | `operational_scripts` |
| `scripts/setup_wireguard.sh` | Shell Script | 29 | Shell script configuring WireGuard tunnel interfaces on Linux. | `operational_scripts` |
| `scripts/sign_boot_config.py` | Python | 81 | Signs boot configuration manifests using post-quantum signature schemes. | `operational_scripts` |
| `scripts/sign_dependencies.py` | Python | 250 | Signs third-party library dependencies with Ed25519 and ML-DSA signatures. | `operational_scripts` |
| `scripts/sign_waiver.py` | Python | 164 | Generates cryptographically signed authorization waivers for lab deviations. | `operational_scripts` |
| `scripts/tor/secure-transmit-tor.service` | Text | 32 | Systemd service definition for managing hardened Tor daemon. | `operational_scripts` |
| `scripts/tor/torrc.ts-hardened` | Text | 43 | Tor configuration file enforcing hardened routing and onion-only transport. | `operational_scripts` |
| `scripts/verify_50x_sovereign_superiority.py` | Python | 347 | Runs comparative benchmark tests evaluating cryptographic throughput and security attributes. | `operational_scripts` |
| `scripts/verify_ato_deployment_package.py` | Python | 500 | Verifies integrity and completeness of deployment authorization package artifacts. | `operational_scripts` |
| `scripts/verify_hardware_security.py` | Python | 48 | Validates presence and configuration of required hardware security mechanisms. | `operational_scripts` |
| `scripts/verify_host_hardening.py` | Python | 416 | Checks host operating system configuration against security hardening checklists. | `operational_scripts` |
| `scripts/verify_reproducible_build.py` | Python | 295 | Verifies binary build reproducibility by comparing artifact hashes. | `operational_scripts` |
| `scripts/wireguard/wg-ts0.conf.template` | Text | 30 | Configuration template for secure WireGuard network tunnel interface. | `operational_scripts` |
| `scripts/witnessed_key_ceremony.py` | Python | 495 | Guides multi-party witnessed key generation ceremony with threshold signatures. | `operational_scripts` |
| `secure_enclave_key_storage.py` | Python | 2080 | Protects cryptographic keys inside software or hardware enclave boundaries. | `memory_security` |
| `secure_file_sharing.py` | Python | 2003 | Manages encrypted file storage, access permissions, and peer-to-peer distribution. | `messaging_file_transfer` |
| `secure_file_transfer.py` | Python | 541 | Transfers files over encrypted P2P channels with chunking and hash verification. | `messaging_file_transfer` |
| `secure_key_manager.py` | Python | 4636 | Manages cryptographic key lifecycle including generation, derivation, storage, and zeroization. | `key_management_pki` |
| `secure_key_provider.py` | Python | 617 | Supplies cryptographic keys from configured storage backends to requesting components. | `key_management_pki` |
| `secure_memory_wiper.py` | Python | 610 | Overwrites memory regions containing keys or plaintext with multiple wiping passes. | `memory_security` |
| `secure_message_serializer.py` | Python | 680 | Serializes and deserializes structured protocol messages with schema validation. | `messaging_file_transfer` |
| `secure_p2p.py` | Python | 14886 | Prototype communications engine managing sessions, cryptographic handshakes, and UI. | `orchestrator_application` |
| `secure_transmit_2027.py` | Python | 2394 | Master orchestration entry point configuring and executing high-assurance communication pipelines. | `orchestrator_application` |
| `security/__init__.py` | Python | 24 | Package initialization file exposing security management interfaces. | `security_framework` |
| `security/graceful_degradation.py` | Python | 337 | Controls system behavior when optional security components are unavailable. | `security_framework` |
| `security/hardening.py` | Python | 445 | Configures operating system security parameters and access permissions. | `security_framework` |
| `security/integrity.py` | Python | 280 | Verifies runtime code and configuration integrity against cryptographic hashes. | `security_framework` |
| `security/manager.py` | Python | 54 | Coordinates security subsystem components and enforces operational policies. | `security_framework` |
| `security/monitor.py` | Python | 366 | Monitors security alert feeds and tracks active security violations. | `security_framework` |
| `security/validation.py` | Python | 885 | Validates configuration schemas and security attribute assignments. | `security_framework` |
| `security_dependency_manager.py` | Python | 1014 | Monitors and validates installed Python package versions and hash provenance. | `system_hardening_integrity` |
| `security_diagnostics.py` | Python | 1275 | Executes diagnostic health checks on cryptographic, network, and storage components. | `audit_threat_monitoring` |
| `security_hardening_manager.py` | Python | 1466 | Applies host operating system configuration hardening settings. | `security_framework` |
| `security_recovery_manager.py` | Python | 718 | Orchestrates component recovery workflows following security faults or connection drops. | `security_framework` |
| `security_status_monitor.py` | Python | 922 | Maintains real-time status summary of active security subsystems. | `audit_threat_monitoring` |
| `security_tiers.py` | Python | 1715 | Defines security operational tiers and associated cryptographic requirements. | `security_framework` |
| `security_validation_orchestrator.py` | Python | 518 | Sequences validation steps across cryptographic and protocol layers. | `security_framework` |
| `security_validator.py` | Python | 324 | Validates incoming message structures and cryptographic parameters against policy. | `security_framework` |
| `sel4_baremetal/Cargo.lock` | Cargo Lockfile | 15 | Cargo lockfile for bare-metal seL4 domain crates. | `host_runtime_attestation` |
| `sel4_baremetal/Cargo.toml` | TOML | 14 | Cargo workspace manifest for bare-metal seL4 protection domains. | `host_runtime_attestation` |
| `sel4_baremetal/black_domain/Cargo.toml` | TOML | 7 | Cargo manifest for seL4 black domain untrusted network component. | `host_runtime_attestation` |
| `sel4_baremetal/black_domain/src/main.rs` | Rust | 44 | Entry point for bare-metal seL4 black domain handling untrusted network packets. | `host_runtime_attestation` |
| `sel4_baremetal/crypto_domain/Cargo.toml` | TOML | 7 | Cargo manifest for seL4 cryptographic domain component. | `host_runtime_attestation` |
| `sel4_baremetal/crypto_domain/src/main.rs` | Rust | 74 | Entry point for bare-metal seL4 cryptographic isolation domain. | `host_runtime_attestation` |
| `sel4_baremetal/red_domain/Cargo.toml` | TOML | 7 | Cargo manifest for seL4 red domain handling protected plaintext. | `host_runtime_attestation` |
| `sel4_baremetal/red_domain/src/main.rs` | Rust | 51 | Entry point for bare-metal seL4 red domain application layer. | `host_runtime_attestation` |
| `sel4_microkit/system.xml` | XML | 37 | Architecture descriptor defining seL4 microkit protection domains and communication channels. | `host_runtime_attestation` |
| `sel4_microkit_manifest.py` | Python | 265 | Generates and parses seL4 microkit system manifest configuration files. | `host_runtime_attestation` |
| `set_env.sh` | Shell Script | 6 | Shell environment script setting required library and python paths. | `utilities_support` |
| `side_channel_resistance.py` | Python | 1513 | Provides constant-time comparison and timing jitter insertion routines. | `memory_security` |
| `sovereign_black_domain.py` | Python | 129 | Implements public-facing external network communication processing for isolated domain architectures. | `host_runtime_attestation` |
| `sovereign_crypto_domain.py` | Python | 493 | Executes cryptographic transformations isolated from network and application layers. | `host_runtime_attestation` |
| `sovereign_group_ratchet.py` | Python | 264 | Manages multi-party ratchet state progression for group communications. | `ratchet_kex_protocol` |
| `sovereign_red_domain.py` | Python | 87 | Manages sensitive data and user interfaces isolated from unencrypted external networks. | `host_runtime_attestation` |
| `sovereign_sel4_appliance.py` | Python | 115 | Coordinates domain communication across microkernel protection boundaries. | `host_runtime_attestation` |
| `spo_dpo.py` | Python | 738 | Implements traffic shaping and packet scheduling to counter timing-based network analysis. | `transport_anonymity` |
| `ssdf_attestation.py` | Python | 261 | Generates NIST SP 800-218 Secure Software Development Framework attestation records. | `system_hardening_integrity` |
| `start_tactical_alpha.bat` | Batch Script | 6 | Batch script launching primary tactical node terminal instance. | `tactical_command_cjadc2` |
| `start_tactical_bravo.bat` | Batch Script | 6 | Batch script launching secondary tactical node terminal instance. | `tactical_command_cjadc2` |
| `stateful_artifact_signing.py` | Python | 628 | Signs release artifacts using hash-based stateful signature schemes. | `system_hardening_integrity` |
| `storage.py` | Python | 114 | Provides persistent key-value and structured record storage interfaces. | `orchestrator_application` |
| `supply_chain_security.py` | Python | 2948 | Validates software bill of materials (SBOM) and dependency cryptographic signatures. | `system_hardening_integrity` |
| `tactical_cloaking_router.py` | Python | 219 | Routes traffic across dynamic network paths to obscure communication endpoints. | `transport_anonymity` |
| `tactical_data_diode.py` | Python | 674 | Enforces unidirectional data transfer using Cauchy-Reed-Solomon forward error correction. | `mesh_ddil_networking` |
| `tactical_key_provisioner.py` | Python | 221 | Provisions offline cryptographic keys and initial credentials for deployed nodes. | `key_management_pki` |
| `tactical_mesh_ddil.py` | Python | 979 | Implements store-and-forward routing for disconnected, intermittent, and limited bandwidth networks. | `mesh_ddil_networking` |
| `tactical_operator_console.py` | Python | 992 | Console user interface for operators monitoring tactical network node status. | `tactical_command_cjadc2` |
| `tactical_web/app.js` | JavaScript | 592 | JavaScript application driving tactical operator web dashboard interface. | `tactical_command_cjadc2` |
| `tactical_web/index.css` | CSS | 1462 | Stylesheet defining UI presentation rules for tactical web dashboard. | `tactical_command_cjadc2` |
| `tactical_web/index.html` | HTML | 681 | HTML document structuring tactical operator web interface. | `tactical_command_cjadc2` |
| `tactical_web_console.py` | Python | 630 | Local HTTP server providing web-based dashboard for node management. | `tactical_command_cjadc2` |
| `tee_manager.py` | Python | 1459 | Interfaces with Trusted Execution Environments for protected enclave processing. | `host_runtime_attestation` |
| `tests/conftest.py` | Python | 59 | Defines shared pytest fixtures, test environment setup, and teardown routines. | `tests` |
| `tests/test_2027_defense_hardening.py` | Python | 551 | Automated test suite verifying functional properties and regression bounds for 2027 defense hardening. | `tests` |
| `tests/test_2028_national_security_remediations.py` | Python | 540 | Automated test suite verifying functional properties and regression bounds for 2028 national security remediations. | `tests` |
| `tests/test_anonymous_loopback.py` | Python | 71 | Automated test suite verifying functional properties and regression bounds for anonymous loopback. | `tests` |
| `tests/test_archive_hardening.py` | Python | 128 | Automated test suite verifying functional properties and regression bounds for archive hardening. | `tests` |
| `tests/test_audit4_remediations_2026_10_17.py` | Python | 601 | Automated test suite verifying functional properties and regression bounds for audit4 remediations 2026 10 17. | `tests` |
| `tests/test_audit_confirmed_regressions.py` | Python | 589 | Automated test suite verifying functional properties and regression bounds for audit confirmed regressions. | `tests` |
| `tests/test_audit_forensic_remediations.py` | Python | 312 | Automated test suite verifying functional properties and regression bounds for audit forensic remediations. | `tests` |
| `tests/test_audit_p1_remediations_phase2.py` | Python | 136 | Automated test suite verifying functional properties and regression bounds for audit p1 remediations phase2. | `tests` |
| `tests/test_caps_strict.py` | Python | 232 | Automated test suite verifying functional properties and regression bounds for caps strict. | `tests` |
| `tests/test_ceremony_quorum.py` | Python | 130 | Automated test suite verifying functional properties and regression bounds for ceremony quorum. | `tests` |
| `tests/test_cjadc2_report_anchor.py` | Python | 37 | Automated test suite verifying functional properties and regression bounds for cjadc2 report anchor. | `tests` |
| `tests/test_cli_key_fill_and_diode.py` | Python | 171 | Automated test suite verifying functional properties and regression bounds for cli key fill and diode. | `tests` |
| `tests/test_cnsa27_gate_2026.py` | Python | 160 | Automated test suite verifying functional properties and regression bounds for cnsa27 gate 2026. | `tests` |
| `tests/test_cnsa_max_profile.py` | Python | 204 | Automated test suite verifying functional properties and regression bounds for cnsa max profile. | `tests` |
| `tests/test_combiner_downgrade_guard.py` | Python | 54 | Automated test suite verifying functional properties and regression bounds for combiner downgrade guard. | `tests` |
| `tests/test_compliance_package_depth.py` | Python | 81 | Automated test suite verifying functional properties and regression bounds for compliance package depth. | `tests` |
| `tests/test_comprehensive_security_tiers.py` | Python | 1073 | Automated test suite verifying functional properties and regression bounds for extended security tiers. | `tests` |
| `tests/test_connection_alias_cleanup.py` | Python | 87 | Automated test suite verifying functional properties and regression bounds for connection alias cleanup. | `tests` |
| `tests/test_cp1252_encoding_safety.py` | Python | 143 | Automated test suite verifying functional properties and regression bounds for cp1252 encoding safety. | `tests` |
| `tests/test_critical_audit_remediations.py` | Python | 371 | Automated test suite verifying functional properties and regression bounds for critical audit remediations. | `tests` |
| `tests/test_crypto_root_fixes.py` | Python | 337 | Automated test suite verifying functional properties and regression bounds for crypto root fixes. | `tests` |
| `tests/test_daemon_packages.py` | Python | 84 | Automated test suite verifying functional properties and regression bounds for daemon packages. | `tests` |
| `tests/test_ddil_key_lifecycle.py` | Python | 183 | Automated test suite verifying functional properties and regression bounds for ddil key lifecycle. | `tests` |
| `tests/test_defensive_audit_remediations.py` | Python | 251 | Automated test suite verifying functional properties and regression bounds for defensive audit remediations. | `tests` |
| `tests/test_defensive_audit_roadmap.py` | Python | 175 | Automated test suite verifying functional properties and regression bounds for defensive audit roadmap. | `tests` |
| `tests/test_defensive_audit_targets.py` | Python | 282 | Automated test suite verifying functional properties and regression bounds for defensive audit targets. | `tests` |
| `tests/test_defensive_nc3_audit.py` | Python | 274 | Automated test suite verifying functional properties and regression bounds for defensive nc3 audit. | `tests` |
| `tests/test_destroyer_core_production.py` | Python | 355 | Automated test suite verifying functional properties and regression bounds for destroyer core production. | `tests` |
| `tests/test_dht_pow_floor.py` | Python | 85 | Automated test suite verifying functional properties and regression bounds for dht pow floor. | `tests` |
| `tests/test_diode_binding.py` | Python | 107 | Automated test suite verifying functional properties and regression bounds for diode binding. | `tests` |
| `tests/test_dll_ca_ceremony.py` | Python | 126 | Automated test suite verifying functional properties and regression bounds for dll ca ceremony. | `tests` |
| `tests/test_docs_truth_in_claims.py` | Python | 160 | Automated test suite verifying functional properties and regression bounds for docs truth in claims. | `tests` |
| `tests/test_exploit_nonce_state.py` | Python | 173 | Automated test suite verifying functional properties and regression bounds for exploit nonce state. | `tests` |
| `tests/test_exploit_regressions.py` | Python | 457 | Automated test suite verifying functional properties and regression bounds for exploit regressions. | `tests` |
| `tests/test_falcon_bundle_mode_consistency.py` | Python | 138 | Automated test suite verifying functional properties and regression bounds for falcon bundle mode consistency. | `tests` |
| `tests/test_file_receive_traversal_guard.py` | Python | 255 | Automated test suite verifying functional properties and regression bounds for file receive traversal guard. | `tests` |
| `tests/test_formal_proverif_models.py` | Python | 98 | Automated test suite verifying functional properties and regression bounds for formal proverif models. | `tests` |
| `tests/test_fullreview_critical_remediations.py` | Python | 1479 | Automated test suite verifying functional properties and regression bounds for fullreview critical remediations. | `tests` |
| `tests/test_group_tier3.py` | Python | 930 | Automated test suite verifying functional properties and regression bounds for group tier3. | `tests` |
| `tests/test_hardware_providers.py` | Python | 400 | Automated test suite verifying functional properties and regression bounds for hardware providers. | `tests` |
| `tests/test_heartbeat_throttle.py` | Python | 92 | Automated test suite verifying functional properties and regression bounds for heartbeat throttle. | `tests` |
| `tests/test_high_audit_remediations.py` | Python | 101 | Automated test suite verifying functional properties and regression bounds for high audit remediations. | `tests` |
| `tests/test_host_hardening_verifier.py` | Python | 144 | Automated test suite verifying functional properties and regression bounds for host hardening verifier. | `tests` |
| `tests/test_host_posture_cli_and_gate.py` | Python | 128 | Automated test suite verifying functional properties and regression bounds for host posture cli and gate. | `tests` |
| `tests/test_hsm_platform.py` | Python | 320 | Automated test suite verifying functional properties and regression bounds for hsm platform. | `tests` |
| `tests/test_hw_readiness.py` | Python | 255 | Automated test suite verifying functional properties and regression bounds for hw readiness. | `tests` |
| `tests/test_key_fill_import.py` | Python | 195 | Automated test suite verifying functional properties and regression bounds for key fill import. | `tests` |
| `tests/test_layer1_hardening.py` | Python | 90 | Automated test suite verifying functional properties and regression bounds for layer1 hardening. | `tests` |
| `tests/test_legacy_quarantine.py` | Python | 115 | Automated test suite verifying functional properties and regression bounds for legacy quarantine. | `tests` |
| `tests/test_liboqs_version_floor_gate.py` | Python | 217 | Automated test suite verifying functional properties and regression bounds for liboqs version floor gate. | `tests` |
| `tests/test_military_adversarial_suite.py` | Python | 626 | Automated test suite verifying functional properties and regression bounds for defense adversarial suite. | `tests` |
| `tests/test_mls_framing.py` | Python | 166 | Automated test suite verifying functional properties and regression bounds for mls framing. | `tests` |
| `tests/test_native_ctypes_bounds.py` | Python | 76 | Automated test suite verifying functional properties and regression bounds for native ctypes bounds. | `tests` |
| `tests/test_nc3_cnsa_cipher.py` | Python | 119 | Automated test suite verifying functional properties and regression bounds for nc3 cnsa cipher. | `tests` |
| `tests/test_nc3_nuclear_command_readiness.py` | Python | 374 | Automated test suite verifying functional properties and regression bounds for nc3 strategic command readiness. | `tests` |
| `tests/test_nc3_token_approval.py` | Python | 271 | Automated test suite verifying functional properties and regression bounds for nc3 token approval. | `tests` |
| `tests/test_nc3_two_person_integrity.py` | Python | 414 | Automated test suite verifying functional properties and regression bounds for nc3 two person integrity. | `tests` |
| `tests/test_nc3_two_terminal_live_transfer.py` | Python | 399 | Automated test suite verifying functional properties and regression bounds for nc3 two terminal live transfer. | `tests` |
| `tests/test_neon_auth_hmac.py` | Python | 128 | Automated test suite verifying functional properties and regression bounds for neon auth hmac. | `tests` |
| `tests/test_network_endpoint_discovery.py` | Python | 303 | Automated test suite verifying functional properties and regression bounds for network endpoint discovery. | `tests` |
| `tests/test_no_emoji_property.py` | Python | 196 | Automated test suite verifying functional properties and regression bounds for no emoji property. | `tests` |
| `tests/test_no_gap_military_audit.py` | Python | 348 | Automated test suite verifying functional properties and regression bounds for no gap defense audit. | `tests` |
| `tests/test_no_marketing_buzzwords_property.py` | Python | 219 | Automated test suite verifying functional properties and regression bounds for no marketing buzzwords property. | `tests` |
| `tests/test_noise_pq_hardened.py` | Python | 480 | Automated test suite verifying functional properties and regression bounds for noise pq hardened. | `tests` |
| `tests/test_noise_pq_purity.py` | Python | 233 | Automated test suite verifying functional properties and regression bounds for noise pq purity. | `tests` |
| `tests/test_nonce_hardening.py` | Python | 135 | Automated test suite verifying functional properties and regression bounds for nonce hardening. | `tests` |
| `tests/test_notupload_security.py` | Python | 76 | Automated test suite verifying functional properties and regression bounds for notupload security. | `tests` |
| `tests/test_oauth_token_validation_p0.py` | Python | 157 | Automated test suite verifying functional properties and regression bounds for oauth token validation p0. | `tests` |
| `tests/test_paced_socket_wrapper.py` | Python | 219 | Automated test suite verifying functional properties and regression bounds for paced socket wrapper. | `tests` |
| `tests/test_parser_fuzz_gates.py` | Python | 501 | Automated test suite verifying functional properties and regression bounds for parser fuzz gates. | `tests` |
| `tests/test_pasted_audit_p0_remediations.py` | Python | 236 | Automated test suite verifying functional properties and regression bounds for pasted audit p0 remediations. | `tests` |
| `tests/test_phase3_acceptance_gates_e1_e6.py` | Python | 308 | Automated test suite verifying functional properties and regression bounds for phase3 acceptance gates e1 e6. | `tests` |
| `tests/test_phase3_acvp_cbom_udp.py` | Python | 362 | Automated test suite verifying functional properties and regression bounds for phase3 acvp cbom udp. | `tests` |
| `tests/test_phase3_security_bounds.py` | Python | 506 | Automated test suite verifying functional properties and regression bounds for phase3 security bounds. | `tests` |
| `tests/test_phase4_ato_redteam_siem.py` | Python | 431 | Automated test suite verifying functional properties and regression bounds for phase4 ato redteam siem. | `tests` |
| `tests/test_phase5_csrmc_ddil_operations.py` | Python | 544 | Automated test suite verifying functional properties and regression bounds for phase5 csrmc ddil operations. | `tests` |
| `tests/test_phase6_cjadc2_data_fabric.py` | Python | 281 | Automated test suite verifying functional properties and regression bounds for phase6 cjadc2 data fabric. | `tests` |
| `tests/test_pkcs11_token_provider.py` | Python | 115 | Automated test suite verifying functional properties and regression bounds for pkcs11 token provider. | `tests` |
| `tests/test_pqxdh_combiner_v2_kat.py` | Python | 116 | Automated test suite verifying functional properties and regression bounds for pqxdh combiner v2 kat. | `tests` |
| `tests/test_production_gate.py` | Python | 250 | Automated test suite verifying functional properties and regression bounds for production gate. | `tests` |
| `tests/test_production_grade_destroyer_suite.py` | Python | 236 | Automated test suite verifying functional properties and regression bounds for production grade destroyer suite. | `tests` |
| `tests/test_production_readiness_audit.py` | Python | 218 | Automated test suite verifying functional properties and regression bounds for production readiness audit. | `tests` |
| `tests/test_production_surface_audit.py` | Python | 116 | Automated test suite verifying functional properties and regression bounds for production surface audit. | `tests` |
| `tests/test_production_tier123_hardening.py` | Python | 418 | Automated test suite verifying functional properties and regression bounds for production tier123 hardening. | `tests` |
| `tests/test_production_tier4_cjadc2_and_consensus.py` | Python | 854 | Automated test suite verifying functional properties and regression bounds for production tier4 cjadc2 and consensus. | `tests` |
| `tests/test_production_tier4_device_memory_audit.py` | Python | 364 | Automated test suite verifying functional properties and regression bounds for production tier4 device memory audit. | `tests` |
| `tests/test_production_tier4_tactical_commands.py` | Python | 299 | Automated test suite verifying functional properties and regression bounds for production tier4 tactical commands. | `tests` |
| `tests/test_production_tier5_session_config_audit.py` | Python | 175 | Automated test suite verifying functional properties and regression bounds for production tier5 session config audit. | `tests` |
| `tests/test_production_tier6_csprng_and_storage_audit.py` | Python | 212 | Automated test suite verifying functional properties and regression bounds for production tier6 csprng and storage audit. | `tests` |
| `tests/test_production_tier7_csprng_complete_audit.py` | Python | 198 | Automated test suite verifying functional properties and regression bounds for production tier7 csprng complete audit. | `tests` |
| `tests/test_profile_encryption_lifecycle.py` | Python | 184 | Automated test suite verifying functional properties and regression bounds for profile encryption lifecycle. | `tests` |
| `tests/test_proverif_st2027.py` | Python | 124 | Automated test suite verifying functional properties and regression bounds for proverif st2027. | `tests` |
| `tests/test_ratchet_dss_mldsa87.py` | Python | 110 | Automated test suite verifying functional properties and regression bounds for ratchet dss mldsa87. | `tests` |
| `tests/test_ratchet_native_buffer.py` | Python | 113 | Automated test suite verifying functional properties and regression bounds for ratchet native buffer. | `tests` |
| `tests/test_rekor_bundle.py` | Python | 58 | Automated test suite verifying functional properties and regression bounds for rekor bundle. | `tests` |
| `tests/test_remediated_63_findings.py` | Python | 376 | Automated test suite verifying functional properties and regression bounds for remediated 63 findings. | `tests` |
| `tests/test_resilient_ddil.py` | Python | 126 | Automated test suite verifying functional properties and regression bounds for resilient ddil. | `tests` |
| `tests/test_runbooks_ps.py` | Python | 59 | Automated test suite verifying functional properties and regression bounds for runbooks ps. | `tests` |
| `tests/test_rust_core_security_suite.py` | Python | 325 | Automated test suite verifying functional properties and regression bounds for rust core security suite. | `tests` |
| `tests/test_rust_interop.py` | Python | 230 | Automated test suite verifying functional properties and regression bounds for rust interop. | `tests` |
| `tests/test_rust_python_crosscheck.py` | Python | 178 | Automated test suite verifying functional properties and regression bounds for rust python crosscheck. | `tests` |
| `tests/test_rust_python_handshake_interop.py` | Python | 103 | Automated test suite verifying functional properties and regression bounds for rust python handshake interop. | `tests` |
| `tests/test_rust_standalone_binary.py` | Python | 667 | Automated test suite verifying functional properties and regression bounds for rust standalone binary. | `tests` |
| `tests/test_sbom_signer_custody.py` | Python | 90 | Automated test suite verifying functional properties and regression bounds for sbom signer custody. | `tests` |
| `tests/test_second_audit_regressions.py` | Python | 76 | Automated test suite verifying functional properties and regression bounds for second audit regressions. | `tests` |
| `tests/test_secure_transmit_2027.py` | Python | 844 | Automated test suite verifying functional properties and regression bounds for secure transmit 2027. | `tests` |
| `tests/test_security_audit_remediations.py` | Python | 404 | Automated test suite verifying functional properties and regression bounds for security audit remediations. | `tests` |
| `tests/test_security_diagnostics.py` | Python | 54 | Automated test suite verifying functional properties and regression bounds for security diagnostics. | `tests` |
| `tests/test_security_hardening_and_memory.py` | Python | 98 | Automated test suite verifying functional properties and regression bounds for security hardening and memory. | `tests` |
| `tests/test_sel4_sovereign_appliance.py` | Python | 261 | Automated test suite verifying functional properties and regression bounds for sel4 autonomous appliance. | `tests` |
| `tests/test_simple_chat.py` | Python | 96 | Automated test suite verifying functional properties and regression bounds for simple chat. | `tests` |
| `tests/test_sovereign_group_ratchet.py` | Python | 139 | Automated test suite verifying functional properties and regression bounds for autonomous group ratchet. | `tests` |
| `tests/test_spo_dpo.py` | Python | 206 | Automated test suite verifying functional properties and regression bounds for spo dpo. | `tests` |
| `tests/test_stateful_artifact_signing.py` | Python | 342 | Automated test suite verifying functional properties and regression bounds for stateful artifact signing. | `tests` |
| `tests/test_tactical_data_diode.py` | Python | 277 | Automated test suite verifying functional properties and regression bounds for tactical data diode. | `tests` |
| `tests/test_tactical_operations_suite.py` | Python | 154 | Automated test suite verifying functional properties and regression bounds for tactical operations suite. | `tests` |
| `tests/test_tactical_replay.py` | Python | 78 | Automated test suite verifying functional properties and regression bounds for tactical replay. | `tests` |
| `tests/test_tactical_web_console.py` | Python | 146 | Automated test suite verifying functional properties and regression bounds for tactical web console. | `tests` |
| `tests/test_tier4_pq_treekem_and_tfc.py` | Python | 284 | Automated test suite verifying functional properties and regression bounds for tier4 pq treekem and tfc. | `tests` |
| `tests/test_tier4_spqr_and_rum_bft.py` | Python | 245 | Automated test suite verifying functional properties and regression bounds for tier4 spqr and rum bft. | `tests` |
| `tests/test_tls_cnsa_suite_pin.py` | Python | 88 | Automated test suite verifying functional properties and regression bounds for tls cnsa suite pin. | `tests` |
| `tests/test_tpm_hardware_phase2.py` | Python | 155 | Automated test suite verifying functional properties and regression bounds for tpm hardware phase2. | `tests` |
| `tests/test_tpm_nv_guard.py` | Python | 331 | Automated test suite verifying functional properties and regression bounds for tpm nv guard. | `tests` |
| `tests/test_tpm_quote.py` | Python | 115 | Automated test suite verifying functional properties and regression bounds for tpm quote. | `tests` |
| `tests/test_tpm_quote_production.py` | Python | 189 | Automated test suite verifying functional properties and regression bounds for tpm quote production. | `tests` |
| `tests/test_transport_anonymity.py` | Python | 301 | Automated test suite verifying functional properties and regression bounds for transport anonymity. | `tests` |
| `tests/test_treekem.py` | Python | 120 | Automated test suite verifying functional properties and regression bounds for treekem. | `tests` |
| `tests/test_trust_anchor.py` | Python | 301 | Automated test suite verifying functional properties and regression bounds for trust anchor. | `tests` |
| `tests/test_ts_attest.py` | Python | 246 | Automated test suite verifying functional properties and regression bounds for ts attest. | `tests` |
| `tests/test_ts_hw_layer.py` | Python | 764 | Automated test suite verifying functional properties and regression bounds for ts hw layer. | `tests` |
| `tests/test_ts_runtime.py` | Python | 530 | Automated test suite verifying functional properties and regression bounds for ts runtime. | `tests` |
| `tests/test_tuf_pq_dual_sign.py` | Python | 149 | Automated test suite verifying functional properties and regression bounds for tuf pq dual sign. | `tests` |
| `tests/test_unified_secure_pipeline.py` | Python | 466 | Automated test suite verifying functional properties and regression bounds for unified secure pipeline. | `tests` |
| `tests/test_verify_after_sign.py` | Python | 310 | Automated test suite verifying functional properties and regression bounds for verify after sign. | `tests` |
| `tests/test_wave8_regressions.py` | Python | 437 | Automated test suite verifying functional properties and regression bounds for wave8 regressions. | `tests` |
| `tests/test_worm_chain_keyed.py` | Python | 75 | Automated test suite verifying functional properties and regression bounds for worm chain keyed. | `tests` |
| `threat_detection_engine.py` | Python | 1075 | Analyzes event streams to detect protocol anomalies and potential intrusion attempts. | `audit_threat_monitoring` |
| `threat_detection_response_system.py` | Python | 772 | Triggers automated defensive responses upon detection of security policy violations. | `audit_threat_monitoring` |
| `threshold_cryptography.py` | Python | 1204 | Implements Shamir secret sharing and threshold signature generation schemes. | `key_management_pki` |
| `tls_channel_manager.py` | Python | 7194 | Establishes and manages mutual TLS 1.3 channels configured with post-quantum cipher suites. | `tls_channel` |
| `tls_pq_policy.py` | Python | 94 | Enforces cipher suite and signature algorithm restrictions on TLS connections. | `tls_channel` |
| `tpm_quote.py` | Python | 1303 | Generates and verifies TPM 2.0 platform configuration register (PCR) quotes and attestations. | `key_management_pki` |
| `transport_anonymity.py` | Python | 1124 | Orchestrates traffic anonymization via onion routing proxies and dummy packet injection. | `transport_anonymity` |
| `treekem.py` | Python | 362 | Implements TreeKEM protocol for logarithmic-cost group key agreement. | `ratchet_kex_protocol` |
| `triple_hybrid_kem.py` | Python | 1321 | Combines three key encapsulation mechanisms into a single composite shared secret. | `ratchet_kex_protocol` |
| `trust_anchor.py` | Python | 614 | Manages trust anchors, root certificate verification, and public key pinning. | `key_management_pki` |
| `ts_attest.py` | Python | 249 | Collects system platform measurements and validates integrity attestations against known baselines. | `host_runtime_attestation` |
| `ts_hw_layer.py` | Python | 1393 | Verifies hardware security features including TPM 2.0, secure boot, and hardware crypto devices. | `host_runtime_attestation` |
| `ts_rt/Cargo.lock` | Cargo Lockfile | 7 | Cargo lockfile for ts_rt runtime support crate. | `host_runtime_attestation` |
| `ts_rt/Cargo.toml` | TOML | 13 | Cargo manifest for ts_rt native runtime library. | `host_runtime_attestation` |
| `ts_rt/build.rs` | Rust | 11 | Build script configuring compilation and link settings for ts_rt. | `host_runtime_attestation` |
| `ts_rt/src/lib.rs` | Rust | 408 | Native runtime library implementing memory locking, zeroization, and constant-time comparisons. | `host_runtime_attestation` |
| `ts_runtime.py` | Python | 896 | Enforces process isolation, memory locking, and anti-tamper controls in the OS execution environment. | `host_runtime_attestation` |
| `ui/__init__.py` | Python | 9 | Package initialization file exposing user interface components. | `ui_presentation` |
| `ui/display.py` | Python | 785 | Formats and renders text screens, banners, and status messages to the console. | `ui_presentation` |
| `ui/feedback.py` | Python | 451 | Displays user feedback notifications, error alerts, and progress indicators. | `ui_presentation` |
| `ui/manager.py` | Python | 59 | Manages console UI layout, screen switching, and active view state. | `ui_presentation` |
| `ui/menus.py` | Python | 385 | Defines interactive terminal menus and navigation prompts. | `ui_presentation` |
| `ui/prompts.py` | Python | 382 | Collects user input from terminal prompts with input validation. | `ui_presentation` |
| `ui/safety_numbers.py` | Python | 246 | Formats and displays out-of-band identity safety numbers for manual verification. | `ui_presentation` |
| `unified_secure_pipeline.py` | Python | 808 | Integrates Python protocol ratchets with native Rust data plane execution. | `orchestrator_application` |
| `utils/__init__.py` | Python | 10 | Package initialization file exposing utility helper functions. | `utilities_support` |
| `utils/backward_compat.py` | Python | 296 | Provides compatibility adaptors for legacy interface conventions. | `utilities_support` |
| `utils/cleanup.py` | Python | 244 | Executes cleanup routines for temporary files and socket descriptors. | `utilities_support` |
| `utils/config_manager.py` | Python | 1068 | Manages reading, validation, and updating of local configuration files. | `utilities_support` |
| `utils/error_handler.py` | Python | 509 | Provides standardized logging and handling for unhandled exceptions. | `utilities_support` |
| `utils/helpers.py` | Python | 267 | General helper routines for string formatting, encoding, and path resolution. | `utilities_support` |
| `utils/initialization.py` | Python | 110 | Performs startup environment checks and dependency verification. | `utilities_support` |
| `utils/manager.py` | Python | 63 | Coordinates utility subsystems and shared helper singletons. | `utilities_support` |
| `utils/memory.py` | Python | 404 | Utility functions for memory inspection and buffer management. | `utilities_support` |
| `utils/message_caps.py` | Python | 146 | Enforces maximum size caps and rate limits on processed messages. | `utilities_support` |
| `verify_deployment.py` | Python | 912 | Verifies environment configuration and dependencies prior to node deployment. | `verification_evidence` |
| `verify_intercontinental_udp_stream.py` | Python | 213 | Tests long-distance UDP stream transmission stability and packet loss recovery. | `verification_evidence` |
| `zero_trust_assessment.py` | Python | 377 | Assesses node posture against zero-trust compliance benchmarks. | `audit_threat_monitoring` |
| `zero_trust_engine.py` | Python | 850 | Evaluates contextual risk scores and enforces zero-trust policy decisions. | `audit_threat_monitoring` |
| `zk_authenticator.py` | Python | 1303 | Implements zero-knowledge proof verification for peer authentication without revealing identities. | `transport_anonymity` |
