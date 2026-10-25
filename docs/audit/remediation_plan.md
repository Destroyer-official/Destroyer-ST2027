# Audit Remediation & Hardening Action Plan

Technical engineering specifications and non-breaking remediation designs addressing defects, dormant code, desynchronized signatures, and nomenclature discrepancies cataloged during the workspace code audit.

> [!NOTE]
> In accordance with the audit mandate, no source code files were modified during this task. This document details the exact engineering diffs and remediation procedures for development teams to apply in subsequent releases.

---

## 1. High-Priority Implementation Defect Remediations

### 1.1 Remediation for DEF-01: Allied Gateway Quarantine NameError

- **Target Location:** `cjadc2_allied_gateway.py:184`
- **Issue Description:** `is_env_true` is referenced without being imported, crashing non-production quarantine checks with `NameError`.
- **Engineering Remediation Specification:**
  Import `is_production` from `production_gate` and utilize standard environment evaluation:
  ```python
  # Proposed patch for cjadc2_allied_gateway.py
  from production_gate import is_production

  def is_quarantine_enforced() -> bool:
      if is_production():
          return True
      val = os.environ.get("P2P_GATEWAY_QUARANTINE", "").strip().lower()
      return val in ("1", "true", "yes", "on")
  ```

---

### 1.2 Remediation for DEF-02: Hardware CPU RNG Direct Bus Sampling

- **Target Location:** `entropy_manager.py:270`
- **Issue Description:** `HardwareRNGSource` checks CPU architecture but delegates to Python `secrets.token_bytes()`, lacking direct hardware bus execution.
- **Engineering Remediation Specification:**
  Integrate ctypes binding to native CPU assembly instructions via C/Rust data plane FFI, or invoke native CPU intrinsics (`_rdrand64_step` / `_rdseed64_step`), falling back to `secrets.token_bytes()` with clear diagnostic telemetry when hardware instructions are unsupported:
  ```python
  # Proposed patch for entropy_manager.py
  def _get_hardware_entropy(num_bytes: int) -> bytes:
      try:
          if sys.platform == "win32" and HAS_NATIVE_RDRAND:
              return native_rdrand_bytes(num_bytes)
      except Exception:
          pass
      return secrets.token_bytes(num_bytes)
  ```

---

### 1.3 Remediation for DEF-03: TPM Endorsement Key Roots Provisioning

- **Target Location:** `tpm_quote.py:38-42`
- **Issue Description:** `EK_ROOTS = {}` dictionary is unpopulated, causing production attestation to fail closed unless provisioned out-of-band.
- **Engineering Remediation Specification:**
  Add configurable certificate store loader reading from a trusted path:
  ```python
  # Proposed patch for tpm_quote.py
  EK_ROOT_DIR = os.environ.get("P2P_TPM_EK_DIR", "certs/ek_roots")

  def load_ek_roots() -> Dict[str, bytes]:
      roots = {}
      if os.path.isdir(EK_ROOT_DIR):
          for fname in os.listdir(EK_ROOT_DIR):
              if fname.endswith(".crt") or fname.endswith(".pem"):
                  with open(os.path.join(EK_ROOT_DIR, fname), "rb") as f:
                      roots[fname] = f.read()
      return roots
  ```

---

### 1.4 Remediation for DEF-04: Offline Vulnerability Scanning

- **Target Location:** `scripts/audit_pins.py:25`
- **Issue Description:** Queries public OSV endpoint `https://api.osv.dev/v1/query`, which fails in air-gapped field deployments.
- **Engineering Remediation Specification:**
  Add `--offline-mirror <path>` flag allowing field nodes to evaluate package hashes against local JSON vulnerability snapshots without network calls.

---

## 2. Cryptographic Compliance Re-Signing Procedure

- **Target Location:** `compliance_reports/` (8 desynchronized reports identified in `docs/audit/compliance_artifacts_audit.md`).
- **Issue Description:** Reports modified during LibOQS 0.16.0 swap require signature regeneration under the current offline custodian key.
- **Execution Procedure:**
  1. Transfer reports to secure air-gapped signing workstation:
     - `compliance_reports/cbom.json`
     - `compliance_reports/cjadc2_data_fabric_drill_report.json`
     - `compliance_reports/cmvp_fips140_3_submittal.json`
     - `compliance_reports/csrmc_phase5_drill_report.json`
     - `compliance_reports/cyclonedx_sbom.json`
     - `compliance_reports/independent_redteam_assessment.json`
     - `compliance_reports/niap_common_criteria_matrix.json`
     - `compliance_reports/spdx_sbom.json`
  2. Execute ML-DSA-87 batch signing tool using hardware token:
     ```bash
     python scripts/sign_boot_config.py --input compliance_reports/<report>.json --key /path/to/offline_mldsa87.key
     ```
  3. Validate signature match with `EnhancedMLDSA_87.verify(public_key, message, signature)`.
  4. Commit regenerated `.sig` files back into git tracking.

---

## 3. Deprecation & Standardization Roadmap for Source Identifiers

To eliminate promotional and non-technical adjectives in production code while maintaining backwards compatibility:

| Current Source Identifier | File & Line | Recommended Technical Name | Deprecation Strategy |
|---|---|---|---|
| `class [BANNED-PREFIX]Crypto:` | `secure_p2p.py:520` | `class SymmetricCipherEngine:` | Retain legacy name as alias; emit deprecation warning on import. |
| `def _add_[BANNED-PREFIX]_grade_padding` | `core/orchestrator.py:180` | `def _add_fixed_quantum_padding` | Alias old method name to new method. |
| `def _generate_[BANNED-PREFIX]_auth_tag` | `core/orchestrator.py:210` | `def _generate_hmac_auth_tag` | Alias old method name to new method. |
| `verify_50x_[PROMOTIONAL]_superiority.py` | `scripts/` | `verify_ratchet_performance.py` | Create symlink / wrapper forwarding CLI arguments. |
| `generate_[PROMOTIONAL]_pki.py` | `scripts/` | `generate_pqc_pki.py` | Create wrapper forwarding CLI arguments. |

---

## 4. Architectural Convergence: Prototype Monolith Retirement

1. **Phase 1 (Audit & Telemetry):**
   Mark `secure_p2p.py` as legacy prototype. Verify all test suites point to `core/orchestrator.py` and `destroyer.py`.
2. **Phase 2 (Deprecation Notice):**
   Add runtime warning when `secure_p2p.py` is invoked directly via CLI, redirecting operators to `destroyer.py`.
3. **Phase 3 (Retirement):**
   Remove monolithic duplicate once 100% test coverage is demonstrated on modular packages (`core/`, `messaging/`, `transports/`).
