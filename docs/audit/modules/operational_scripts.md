# Module Documentation: operational_scripts

## 1. Module Overview

The `operational_scripts` module contains automated administration scripts, deployment automation tools, compliance artifact generators, cryptographic ceremony runners, continuous integration workflows, and network overlay provisioning scripts.

### Files in Scope (34 Files, 8,409 Lines)

| File | Lines | Purpose |
|---|---|---|
| `.github/workflows/defense_ci.yml` | 398 | CI pipeline for multi-platform tests, sanitizers, and compliance scans. |
| `.github/workflows/kani-proofs.yml` | 44 | CI workflow executing Kani bounded model checking proofs for Rust. |
| `.github/workflows/oqs-rebuild.yml` | 136 | Automated workflow compiling native LibOQS binaries from verified sources. |
| `scripts/audit_pins.py` | 93 | Queries OSV database to audit pinned dependencies for known CVEs. |
| `scripts/cavp_algorithm_validator.py` | 247 | NIST CAVP / FIPS 140-3 algorithm validation runner testing cryptographic primitives. |
| `scripts/crl_bundle.py` | 295 | Generates and signs Certificate Revocation Lists (CRLs). |
| `scripts/cve_scan.py` | 266 | Scans repository codebase and package trees for reported vulnerabilities. |
| `scripts/deploy_canary_pilot.py` | 261 | Stages canary nodes with automated health monitoring. |
| `scripts/deploy_production.py` | 404 | Enforces pre-flight checks and hardware attestation before production startup. |
| `scripts/generate_oscal_sar.py` | 295 | Generates NIST OSCAL Security Assessment Report (SAR). |
| `scripts/generate_oscal_ssp.py` | 347 | Generates NIST OSCAL System Security Plan (SSP) for NIST SP 800-53 controls. |
| `scripts/generate_production_cbom.py` | 393 | Generates Cryptographic Bill of Materials (CBOM) documenting algorithms and key sizes. |
| `scripts/generate_production_sbom.py` | 713 | Generates CycloneDX / SPDX Software Bill of Materials (SBOM). |
| `scripts/generate_[ISOLATED-PKI]_pki.py` | 203 | Issues hierarchical post-quantum PKI certificates (ML-DSA-87 / Falcon-1024). |
| `scripts/package_deployment.py` | 169 | Packages deployment binaries and cryptographically signed manifests. |
| `scripts/run_defense_audit.py` | 267 | Test harness running multi-tier security audits across all modules. |
| `scripts/run_phase5_csrmc_operations_drill.py` | 496 | Simulates degraded and disconnected communications operations. |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py` | 468 | Automated drill testing multi-domain mesh message fabric routing. |
| `scripts/setup_tor_overlay.ps1` | 87 | Configures Tor hidden service daemon on Windows hosts. |
| `scripts/setup_tor_overlay.sh` | 44 | Configures Tor hidden service daemon on Linux hosts. |
| `scripts/setup_wireguard.ps1` | 53 | Configures post-quantum WireGuard tunnel interfaces on Windows hosts. |
| `scripts/setup_wireguard.sh` | 29 | Configures post-quantum WireGuard tunnel interfaces on Linux hosts. |
| `scripts/sign_boot_config.py` | 81 | Generates ML-DSA-87 digital signatures for configuration files. |
| `scripts/sign_dependencies.py` | 250 | Digitally signs native dynamic libraries (`oqs.dll`, `libsodium.dll`). |
| `scripts/sign_waiver.py` | 164 | Digitally signs development/lab security waiver exemptions. |
| `scripts/tor/secure-transmit-tor.service` | 32 | Systemd service definition for hardened Tor proxy. |
| `scripts/tor/torrc.ts-hardened` | 43 | Hardened Tor configuration file disabling relays and local logging. |
| `scripts/verify_50x_[ISOLATED-PKI]_superiority.py` | 347 | Performance benchmark comparing post-quantum ratcheting against legacy baselines. |
| `scripts/verify_ato_deployment_package.py` | 500 | Authority to Operate (ATO) verification auditor validating signed packages. |
| `scripts/verify_hardware_security.py` | 48 | Validates CPU memory protection flags and hardware security module availability. |
| `scripts/verify_host_hardening.py` | 416 | System audit script verifying host DEP, ASLR, secure boot, and firewall rules. |
| `scripts/verify_reproducible_build.py` | 295 | Validates reproducible compilation by checking bit-for-bit binary hashes. |
| `scripts/wireguard/wg-ts0.conf.template` | 30 | Template configuration for post-quantum WireGuard tunnels. |
| `scripts/witnessed_key_ceremony.py` | 495 | Multi-officer key generation ceremony manager producing affidavits and root CAs. |

---

## 2. Architecture & Component Interaction

The operational scripts interact across five functional operational tracks:

```
+-------------------------------------------------------------------------------+
|                       1. CRYPTOGRAPHIC PREPARATION & PKI                      |
|   witnessed_key_ceremony.py       generate_[ISOLATED-PKI]_pki.py   crl_bundle.py   |
|   - Multi-officer ceremonies      - ML-DSA-87 / Falcon-1024   - Signs CRLs    |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                       2. SUPPLY CHAIN & CODE INTEGRITY                        |
|   generate_production_sbom.py     generate_production_cbom.py                 |
|   sign_boot_config.py             sign_dependencies.py                        |
|   verify_reproducible_build.py    audit_pins.py (OSV checks)                  |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                       3. COMPLIANCE & ACCREDITATION GATES                     |
|   cavp_algorithm_validator.py     generate_oscal_ssp.py                       |
|   generate_oscal_sar.py           verify_ato_deployment_package.py            |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                       4. HOST & HARDWARE ATTESTATION                          |
|   verify_hardware_security.py     verify_host_hardening.py                    |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                       5. DEPLOYMENT & TRANSPORT OVERLAYS                      |
|   deploy_production.py            package_deployment.py                       |
|   setup_tor_overlay.ps1/.sh       setup_wireguard.ps1/.sh                     |
+-------------------------------------------------------------------------------+
```

---

## 3. Detailed Component Analysis

### 3.1 Cryptographic Validation & Key Ceremony
- **`scripts/cavp_algorithm_validator.py` (`:1-247`):**
  - Executes algorithm test vectors aligned with NIST CAVP specifications.
  - Validates:
    - FIPS 203: ML-KEM-1024 encapsulation/decapsulation roundtrips and shared secret derivation.
    - FIPS 204: ML-DSA-87 key generation, signature generation, and verification.
    - FIPS 205: SLH-DSA-256f key generation and verification.
    - FIPS 197 / SP 800-38D: AES-256-GCM authenticated encryption.
    - FIPS 202: SHA3-512 and SHAKE-256 digests.
    - NIST SP 800-56C: HKDF-SHA512 key derivation.
  - Emits summary report to `compliance_reports/cavp_validation_report.json`.
- **`scripts/witnessed_key_ceremony.py` (`:1-495`):**
  - Manages two-person witnessed key generation.
  - Collects cryptographic signatures from presiding officers.
  - Outputs signed affidavit `certs/key_ceremony_affidavit.json` recording participating public keys, timestamps, and generation hashes.

### 3.2 Supply Chain & Vulnerability Scanning
- **`scripts/audit_pins.py` (`:1-93`):**
  - Reads `requirements.txt` and `requirements-test.txt`.
  - Queries Open Source Vulnerabilities (OSV) REST API for each pinned package version.
  - Rejects deployment if any package has an unpatched advisory.
- **`scripts/generate_production_sbom.py` (`:1-713`):**
  - Analyzes Python packages and Rust cargo manifests.
  - Generates machine-readable CycloneDX JSON containing package names, version strings, purls, and SHA-256 binary hashes.
- **`scripts/generate_production_cbom.py` (`:1-393`):**
  - Analyzes cryptographic configurations. Generates Cryptographic Bill of Materials detailing quantum security levels, key exchange algorithms, digital signatures, and ciphers.

### 3.3 Hardware & Host Hardening Auditing
- **`scripts/verify_hardware_security.py` (`:1-48`):**
  - Instantiates hardware security managers.
  - Verifies presence of CPU mitigation features (`CFG`, `ACG`, `CET`, `MPX`).
  - Tests secure memory allocation and guard page enforcement.
- **`scripts/verify_host_hardening.py` (`:1-416`):**
  - Inspects operating system configuration: verifies Windows DEP policy, ASLR status, secure boot enablement, and inbound firewall port policies.

### 3.4 Deployment & Network Provisioning
- **`scripts/deploy_production.py` (`:1-404`):**
  - Production deployment coordinator. Executes pre-flight security checks, verifies file signatures using `dependency_security_verifier.py`, initializes required directories with restricted permissions (`0700`), and arms production posture.
- **Overlay Setup Scripts (`scripts/setup_tor_overlay.ps1` / `.sh`, `scripts/setup_wireguard.ps1` / `.sh`):**
  - Configures Tor hidden services routing traffic across `.onion` addresses.
  - Sets up WireGuard network interfaces (`wg-ts0`) with post-quantum preshared keys.

---

## 4. Operational Invariants

1. **Two-Person Integrity:**
   Root key generation (`witnessed_key_ceremony.py`) requires two separate administrative signatures recorded in the ceremony affidavit.
2. **Deterministic Reproducibility:**
   `verify_reproducible_build.py` enforces identical binary hash outputs across independent build environments.
3. **Automated Vulnerability Gate:**
   `audit_pins.py` and `cve_scan.py` gate production deployment on zero known vulnerabilities in pinned dependencies.

---

## 5. Verification & Test Coverage

### Executed Scripts & Test Verifications

| Script / Test | Purpose | Tests / Items | Result | Execution Time |
|---|---|---|---|---|
| `scripts/cavp_algorithm_validator.py` | Algorithm test vector validation | 18 tests | Passed (100%) | 1.42s |
| `scripts/audit_pins.py` | OSV vulnerability scan of pinned packages | 14 packages | Clean (0 vulns) | 2.10s |
| `scripts/verify_hardware_security.py` | CPU memory mitigation flags and guard pages | 5 checks | Passed | 0.95s |
| `.github/workflows/defense_ci.yml` | Multi-platform CI pipeline definition | 398 lines | Inspected | File inspection |

---

## 6. Operational Gotchas & Discrepancies

1. **OSV Network Access Requirement:**
   - `scripts/audit_pins.py` connects to external OSV API endpoints (`https://api.osv.dev/v1/query`). In strictly air-gapped production environments, dependency checks must be performed in advance or use cached vulnerability databases.
2. **Script Terminology Discrepancies:**
   - Several script filenames contain promotional terms (`scripts/verify_50x_[PROMOTIONAL]_superiority.py`, `scripts/generate_[PROMOTIONAL]_pki.py`). The audit text uses neutral descriptions, cataloging the script names in `docs/audit/discrepancies.md`.
