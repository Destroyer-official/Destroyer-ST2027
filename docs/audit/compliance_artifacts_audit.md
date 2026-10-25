# Compliance Artifacts & Cryptographic Attestation Audit

Independent evaluation of machine-readable compliance catalogs, OSCAL submittals, Software Bill of Materials (SBOM), Cryptographic Bill of Materials (CBOM), and post-quantum digital signature verification across all 85 tracked compliance files.

---

## 1. Compliance Repository Structure & Metrics

The `compliance_reports/` directory contains 85 git-tracked files (6,238 lines):

| Artifact Type | Count | Extension | Cryptographic Protection | Primary Regulatory Framework |
|---|---|---|---|---|
| **JSON Reports & Submittals** | 33 | `.json` | Primary data payload | NIST SP 800-53 Rev. 5, NIST SP 800-218 (SSDF), CNSA 2.0 |
| **Digital Signature Files** | 26 | `.mldsa87.sig`, `.sig` | FIPS 204 ML-DSA-87 binary signature | Non-repudiation and tamper detection |
| **Public Verification Keys** | 25 | `.mldsa87.pub`, `.pub` | Raw 2,592-byte public key | Standalone signature verification |
| **Audit Logs** | 1 | `.jsonl` | Append-only event sequence | Hash-chained event integrity |
| **Total Tracked Artifacts** | **85** | — | **Post-quantum digital attestation** | **NIST / NSA CNSA 2.0 Compliance** |

---

## 2. Digital Signature Verification Audit (ML-DSA-87)

Every paired compliance report was audited by executing direct ML-DSA-87 signature verification (`EnhancedMLDSA_87.verify(public_key, message, signature)`) against active `liboqs` cryptographic engines.

### 2.1 Verification Outcome Summary

- **Total Paired Signed Artifacts Tested:** 24 reports.
- **Cryptographically Verified (PASS):** 16 reports (66.7%).
- **Signature Mismatch / Desynchronized (FAIL):** 8 reports (33.3%).

### 2.2 Verified Compliance Submittals (16 Reports)

The following reports verify against their corresponding ML-DSA-87 signatures and public keys:

1. `active_cyber_defense_report.json` — Verified against `active_cyber_defense_report.json.mldsa87.sig`.
2. `acvp_cavp_validation_report.json` — Verified against `acvp_cavp_validation_report.json.mldsa87.sig`.
3. `byzantine_consensus_receipt.json` — Verified against `byzantine_consensus_receipt.json.mldsa87.sig`.
4. `cjadc2_allied_gateway_report.json` — Verified against `cjadc2_allied_gateway_report.json.mldsa87.sig`.
5. `cjadc2_cross_domain_audit.json` — Verified against `cjadc2_cross_domain_audit.json.mldsa87.sig`.
6. `crypto_agility_audit.json` — Verified against `crypto_agility_audit.json.mldsa87.sig`.
7. `csrmc_operations_report.json` — Verified against `csrmc_operations_report.json.mldsa87.sig`.
8. `cyclonedx_cbom.json` — Verified against `cyclonedx_cbom.json.mldsa87.sig`.
9. `defense_master_audit_receipt.json` — Verified against `defense_master_audit_receipt.json.mldsa87.sig`.
10. `dod_zero_trust_assessment.json` — Verified against `dod_zero_trust_assessment.json.mldsa87.sig`.
11. `emergency_zeroization_audit.json` — Verified against `emergency_zeroization_audit.json.mldsa87.sig`.
12. `oscal_sar_cato.json` — Verified against `oscal_sar_cato.json.mldsa87.sig`.
13. `oscal_ssp_cnsa2.json` — Verified against `oscal_ssp_cnsa2.json.mldsa87.sig`.
14. `sbom/cbom.json` — Verified against `sbom/cbom.json.mldsa87.sig`.
15. `sbom/cyclonedx_sbom.json` — Verified against `sbom/cyclonedx_sbom.json.mldsa87.sig`.
16. `ssdf_self_attestation.json` — Verified against `ssdf_self_attestation.json.mldsa87.sig`.

### 2.3 Desynchronized Signatures Root-Cause Analysis (8 Reports)

The following 8 reports failed cryptographic signature verification:
- `cbom.json`
- `cjadc2_data_fabric_drill_report.json`
- `cmvp_fips140_3_submittal.json`
- `csrmc_phase5_drill_report.json`
- `cyclonedx_sbom.json`
- `independent_redteam_assessment.json`
- `niap_common_criteria_matrix.json`
- `spdx_sbom.json`

**Root Cause:**
Git commit analysis (`git log -S liboqs 8078b6b`) indicates that these 8 reports were edited during the LibOQS 0.16.0 integration swap (`8078b6b: oqs 0.16.0 swap + trust-anchor rotation`). As part of this commit, operational signing keys were migrated to offline custody. Consequently, the updated JSON payloads were committed to the repository without regenerating the corresponding ML-DSA-87 digital signatures, creating an unverified delta.

---

## 3. Standards & Framework Compliance Mapping

### 3.1 NIST SP 800-53 Rev. 5 & OSCAL Submittals
- **`oscal_ssp_cnsa2.json` (11,229 bytes):**
  - Formats system implementation details into the NIST Open Security Controls Assessment Language (OSCAL) System Security Plan (SSP) format.
  - Formally documents implemented controls across families:
    - **AC (Access Control):** Zero-trust mutual certificate authentication.
    - **SC (System and Communications Protection):** Post-quantum hybrid KEM and CNSA 2.0 cipher suites.
    - **SI (System and Information Integrity):** DEP, ASLR, CFG, and anti-tamper debugger traps.
- **`oscal_sar_cato.json` (8,412 bytes):**
  - Security Assessment Report (SAR) recording automated control verification results for Continuous Authority to Operate (cATO).

### 3.2 Supply Chain Transparency (CycloneDX & SPDX)
- **`cyclonedx_sbom.json` and `spdx_sbom.json`:**
  - Machine-readable bill of materials cataloging runtime dependencies (`cryptography`, `pycparser`, `cffi`, `liboqs`, `libsodium`).
  - Includes package URLs (purls), versions, and cryptographic hashes (SHA-256).
- **`cyclonedx_cbom.json` (Cryptographic Bill of Materials):**
  - Catalogs cryptographic assets, quantum vulnerability profiles, algorithm classifications, and NIST security levels (Level 5 for ML-KEM-1024, ML-DSA-87, and SLH-DSA-256f).

### 3.3 NIST Secure Software Development Framework (SSDF / NIST SP 800-218)
- **`ssdf_self_attestation.json` (6,150 bytes):**
  - Attestation report confirming compliance with Executive Order 14028.
  - Documents practices: PO.1 (security requirements), PS.1 (software integrity), PW.1 (secure coding practices), RV.1 (vulnerability handling).

---

## 4. Key Attestation Gotchas & Recommendations

1. **Re-Signing After Trust-Anchor Rotation:**
   - The 8 desynchronized compliance reports must be re-signed using the current offline ML-DSA-87 release key to restore full repository attestation integrity.
2. **Standardized Signature Extension:**
   - Signatures are stored with `.mldsa87.sig` extensions. Automated ingestion tools should enforce consistent extension mapping across root and sub-directories.
