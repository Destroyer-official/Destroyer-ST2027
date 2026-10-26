# Finding Report: SEC-01 — Upstream HQC-256 CVE Quarantine & Hash-Based Signature Safeguards

- **Finding ID:** `SEC-01`
- **Module:** `crypto_pqc`
- **Affected File & Line:** [`pqc_algorithms.py:6355-6410`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/pqc_algorithms.py#L6355-L6410)
- **Classification:** Cryptographic Risk Management / Fail-Closed Policy Gate
- **Severity:** High (Upstream Vulnerability Exposure in Non-Primary Ciphersuites)

---

## 1. Observed Behavior & Evidence

1. **HQC-256 Upstream Vulnerability:**
   Vendored `oqs.dll` binaries in the workspace predate upstream fixes for CVE-2024-54137 and CVE-2025-52473. While ML-KEM-1024 is the primary CNSA 2.0 KEM, HQC-256 was present in the agility registry.
   The codebase explicitly quarantines HQC-256: instantiation raises a warning/error and is blocked unless the operator explicitly sets `P2P_ENABLE_VULN_HQC=1` (agility-reserve research only).

2. **Stateful Hash-Based Signatures (XMSS/LMS):**
   Stateful hash-based signature schemes (`EnhancedXMSS`, `EnhancedLMS`) carry strict state-advancement requirements: reusing a one-time signing key index destroys private key security. Custom Python state-advancement logic was marked unaudited and disabled by default, requiring `P2P_ENABLE_EXPERIMENTAL=1` to instantiate, with the system directing operators to stateless SLH-DSA-256f.

---

## 2. Technical Consequences

- Prevents side-channel and lattice fault vulnerabilities from compromising nodes via auxiliary KEM negotiation.
- Prevents catastrophic one-time private key reuse in stateful signature implementations.

---

## 3. Remediation & Verification

- Enforced fail-closed policy gates in `pqc_algorithms.py:6355-6410`.
- Verified in `pytest tests/test_production_tier123_hardening.py` (test `test_pqc_factory_degrades_per_member` confirms HQC and XMSS/LMS are properly skipped/quarantined).
- Verified in Master Defense Audit Gate 3.1.
- Verified status: **ENFORCED & VERIFIED**.

