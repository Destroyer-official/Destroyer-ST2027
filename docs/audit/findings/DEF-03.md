# Finding Report: DEF-03 — TPM Endorsement Key Roots Provisioning

- **Finding ID:** `DEF-03`
- **Module:** `host_runtime_attestation`
- **Affected File & Line:** [`tpm_quote.py:38-42,185-215`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/tpm_quote.py#L38-L42)
- **Classification:** Confirmed Defect / Deployment Blocker (Remediated)
- **Severity:** High (Attestation Failure in Air-Gapped Field Deployments)

---

## 1. Observed Behavior & Evidence

In `tpm_quote.py:38-42`, the table of TPM Endorsement Key root certificates was initialized empty (`EK_ROOTS = {}`). Because production mode enforces strict fail-closed rejection of unverified TPM endorsement quotes, field nodes deployed in air-gapped environments failed quote verification unless certificates were manually patched directly into the Python source code.

---

## 2. Technical Consequences

- Nodes could not complete hardware platform attestation during initial boot in disconnected networks.
- Production gates locked nodes out of network participation.

---

## 3. Remediation

Implemented an automated directory-based certificate loader:
1. Scans `P2P_TPM_EK_DIR` environment variable and `certs/ek_roots/` directory.
2. Ingests `.crt`, `.pem`, `.der`, and `.cer` files using `cryptography.x509`.
3. Computes SHA-256 fingerprints and registers them automatically into `trusted_fps`.
4. Created `certs/ek_roots/README.md` documenting field root provisioning.

---

## 4. Verification Evidence

- Executed `pytest tests/test_production_tier123_hardening.py -v`.
- All 14 tests passed, confirming air-gapped root certificate discovery and endorsement quote verification.
- Verified status: **REMEDIATED & VERIFIED**.

