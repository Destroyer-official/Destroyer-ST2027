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

2. **Upstream LibOQS Agility Reserve (HQC-256):**
   Vendored `oqs.dll` binaries (version 0.16.0) predate upstream patches for CVE-2024-54137 and CVE-2025-52473. HQC-256 is quarantined and blocked by default. While primary operations rely strictly on pure ML-KEM-1024, re-enabling HQC-256 requires recompiling and vendor-signing updated LibOQS >= 0.16.1 binaries.

3. **Stateful Hash-Based Signatures (XMSS/LMS):**
   Custom Python state-advancement implementations of XMSS and LMS are quarantined as unaudited. Production deployments are restricted to stateless SLH-DSA-256f and ML-DSA-87.

---

## 3. Architecture & Dual-Stack Maintenance

1. **Prototype Monolith Co-Existence:**
   The monolithic prototype `secure_p2p.py` (14,886 lines) co-exists with the modular package `core/orchestrator.py` (1,714 lines). Changes to session handling and protocol logic must currently be maintained in both implementations until the monolith is formally retired.

2. **Platform Specificity:**
   Native x86_64 CPU assembly for hardware entropy sampling (`entropy_manager.py`) and memory page locking (`memlock.py`) are tailored for Windows AMD64 systems via Win32 APIs (`VirtualAlloc`, `VirtualLock`). Deployment to Linux/seL4 requires native POSIX bindings (`mlock`, `getrandom`).

