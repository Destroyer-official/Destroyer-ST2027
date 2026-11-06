# Known Technical Limitations & Operational Boundaries

**Audit Run ID:** `RUN-20261025-01`
**Date:** 2026-10-25
**Protocol:** Production Engineering and Forensic Verification v4.0
**Project:** Destroyer-ST2027

---

## 1. Cryptographic & Physical Boundaries

1. **Physical Side-Channel Resistance:**
   Software constant-time routines and randomized timing jitter contexts provide remote network timing mitigation. They cannot prevent physical side-channel leakage (power analysis, electromagnetic emanations, acoustic analysis, cache-timing attacks) without certified physical hardware boundaries (FIPS 140-3 Level 3/4 enclosures, TEMPEST SDIP-27 shielding).

2. **Statutory Authority to Operate (ATO):**
   Technical evaluation receipts (`compliance_reports/defense_master_audit_receipt.json`) and OSCAL documentation are technical compliance evidence, not statutory government accreditations. Live defense deployment requires formal laboratory evaluation (NIST CMVP FIPS 140-3, NIAP NDcPP) and a signed ATO from a designated Authorizing Official.

---

## 2. Infrastructure & Deployment Dependencies

1. **Air-Gapped Hardware Attestation Provisioning:**
   TPM 2.0 quote verification in air-gapped networks requires that vendor intermediate and root CA certificates be pre-provisioned into `certs/ek_roots/` or pointed to via `P2P_TPM_EK_DIR`. Similarly, AMD SEV-SNP and ARM TrustZone require local VCEK / device key certificates. Unprovisioned field nodes will fail closed.

2. **Quarantine of Non-Standardized KEM Candidates (HQC-256):**
   Primary operations strictly mandate pure ML-KEM-1024 conforming to CNSA Suite 2.0 and NIST FIPS 203. Non-standardized Round-4 candidate algorithms (such as HQC-256, historically associated with CVE-2024-54137 decapsulation timing variations) are permanently quarantined and disabled by default. Production deployments rely solely on FIPS 203 ML-KEM-1024 and FIPS 204 ML-DSA-87, eliminating reliance on candidate-round decapsulation paths.

3. **Media Sanitization Standard:**
   Media and volatile memory zeroization protocols conform to NIST SP 800-88 Revision 2 (September 2025: Guidelines for Media Sanitization) and DoD 5220.22-M multi-pass overwrite sequences. Fixed-pass cryptographic overwrites apply to unmanaged magnetic and volatile structures; flash and wear-leveled SSD media require cryptographic erase (CE) via drive firmware or physical destruction per SP 800-88 Rev 2 Section 4.

3. **Stateful Hash-Based Signatures (XMSS/LMS):**
   Custom Python state-advancement implementations of XMSS and LMS are quarantined as unaudited. Production deployments are restricted to stateless SLH-DSA-256f and ML-DSA-87.

---

## 3. Architecture & Dual-Stack Maintenance

1. **Prototype Monolith Co-Existence:**
   The monolithic prototype `secure_p2p.py` (14,886 lines) co-exists with the modular package `core/orchestrator.py` (1,714 lines). Changes to session handling and protocol logic must currently be maintained in both implementations until the monolith is formally retired.

2. **Platform Specificity:**
   Native x86_64 CPU assembly for hardware entropy sampling (`entropy_manager.py`) and memory page locking (`memlock.py`) are tailored for Windows AMD64 systems via Win32 APIs (`VirtualAlloc`, `VirtualLock`). Deployment to Linux/seL4 requires native POSIX bindings (`mlock`, `getrandom`).

