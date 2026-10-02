# NIAP Common Criteria Security Target (ST) -- DRAFT (self-authored, pre-evaluation)
## Target of Evaluation (TOE): Secure P2P Defense Communications Platform v2.0.0-CNSA2-2027

> Pre-evaluation preparation document. NOT a NIAP evaluation; no CCTL
> engaged; no certificate exists. SFR mappings below are the authors'
> self-mapping to implementation files and in-repo suites.

### 1. Document Control & Identification
- **Document ID:** `NIAP-NDcPP-PQC-ST-2027-V1`
- **Protection Profile:** Collaborative Protection Profile for Network Devices (NDcPP) v3.0 with Post-Quantum Cryptography Extended Package
- **Assurance Level:** TARGET Common Criteria EAL4+ (`ALC_FLR.3`, `AVA_VAN.5`) -- not assessed
- **Evaluation Facility:** NONE ENGAGED (contract a NVLAP-accredited CCTL against the PP above)

---

## 2. Security Functional Requirements (SFRs) Traceability

| SFR Identifier | Title | Standard & Baseline | Implementation Architecture |
| :--- | :--- | :--- | :--- |
| **`FCS_CKM.1/PQC`** | Cryptographic Key Generation | FIPS 203 (ML-KEM-1024), FIPS 204 (ML-DSA-87), RFC 10024 | `noise_pq.py`, `cnsa_purity.py`, `trust_anchor.py`, `cng_platform.py` |
| **`FCS_COP.1/SYM`** | Cryptographic Operation (Symmetric) | FIPS 197 / NIST SP 800-38D (AES-256-GCM) | `secure_transmit_2027.py`, `ts_rt/src/lib.rs`, `rust_data_plane/src/aead.rs` |
| **`FCS_COP.1/HASH`** | Cryptographic Operation (Hash & KDF) | FIPS 180-4 (SHA-384, SHA-512), RFC 5869 (HKDF-SHA384) | `crypto_selftest.py`, `noise_pq.py`, `cnsa_purity.py` |
| **`FCS_RBG_EXT.1`** | Random Bit Generation | NIST SP 800-90A / Hardware Entropy Conditioning | Windows CNG `BCryptGenRandom`, `platform_hsm_interface.py`, `crypto_selftest.py` |
| **`FIA_X509_EXT.1`** | Certificate Validation (PQ PKI) | RFC 9881 / Offline 3-of-5 Threshold ML-DSA-87 Root | `trust_anchor.py`, `pq_certificate_authority.py` |
| **`FPT_TST_EXT.1`** | TSF Self-Test (Power-Up KATs) | FIPS 140-3 Known Answer Tests at Boot (Fail-Closed) | `crypto_selftest.py`, `acvp_validation_harness.py` |
| **`FPT_TUD_EXT.1`** | Trusted Update & Supply Chain | SLSA Level 3+ / Ed25519 & ML-DSA-87 Signing | `scripts/verify_reproducible_build.py`, `generate_production_cbom.py` |
| **`FAU_GEN.1`** | Audit Data Generation | NIST SP 800-53 Rev 5 AU-2, AU-3 / HMAC-SHA384 Chaining | `remote_siem_forwarder.py`, `audit_logging_system.py` |
| **`FAU_STG.1/WORM`** | Protected Audit Trail Storage | NIST SP 800-53 AU-9 / Head Anchor Tail Locking | `logs/siem_audit_head.anchor.json`, `secure_p2p_audit.db` |
| **`FIA_UAU.1`** | Timing of Authentication & Two-Person Rule | DoD Zero Trust / DoD S-5210.41M Dual Persona Rule | `spo_dpo.py`, `ts_attest.py`, `zero_trust_engine.py` |
| **`FTP_TRP.1/ANON`** | Trusted Path Network Obfuscation | SOCKS5 Tor v3 / Interface Pinning / 50ms Cell Shaping | `transport_anonymity.py`, `tactical_cloaking_router.py` |
| **`FPT_PHP.3`** | Physical Tamper & Zeroization Resistance | NATO SDIP-27/28/29 TEMPEST & Simplex Diode Framing | `ts_hw_layer.py`, `ts_runtime.py`, `secure_memory_wiper.py` |

---

## 3. Security Assurance Requirements (SARs) -- TARGETS (not assessed)

The Target of Evaluation (TOE) is being prepared toward the following augmented assurance components. Each is a self-assessed readiness claim for lab evaluation, not a lab finding:

1. **`ALC_FLR.3` (Systematic Flaw Remediation)**:
   - Automated vulnerability monitoring and regression test suites.
   - 63 historical security findings remediated in-repo with gate suites (`test_remediated_63_findings.py`).
2. **`AVA_VAN.5` (Advanced Vulnerability Analysis)**:
   - NOT ASSESSED. Requires accredited-lab penetration testing. In-repo adversarial drill outcomes live in `compliance_reports/independent_redteam_assessment.json` (self-conducted).
3. **`ADV_FSP.4` (Complete Functional Specification)**:
   - Draft functional specification of security functions, interfaces, and state transitions within the cryptographic boundary.
4. **`ATE_FUN.1` (Functional Testing)**:
   - In-repo gate suites maintained green (see deployment verification reports for current counts, not a fixed percentage).
