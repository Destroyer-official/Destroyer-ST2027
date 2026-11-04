# Module Documentation: operational_scripts

## 1. Purpose
The `operational_scripts` module provides automated verification scripts, supply chain compliance generators, cryptographic ceremony runners, continuous integration workflows, and host hardening auditors (`scripts/run_defense_audit.py:1-267`, `scripts/sign_dependencies.py:1-250`, `scripts/verify_reproducible_build.py:1-295`). It validates that repository artifacts, dependency hashes, and runtime configurations comply with post-quantum security requirements (`scripts/audit_pins.py:1-93`).

## 2. Public Interface

### 2.1 Scripts and Key Functions

#### `scripts/run_defense_audit.py` (`scripts/run_defense_audit.py:1-267`)
- `run_defense_audit() -> bool`: Executes 9-gate defense audit battery across Rust compiler lints (`cargo clippy`), unit tests (`cargo test`), Python deployment tests (`verify_deployment.py`), reproducible build hashes, and live end-to-end communication channels (`:50-240`). Returns `True` if all gates pass; returns `False` on any gate failure.

#### `scripts/verify_deployment.py` (`verify_deployment.py:1-380`)
- `run_deployment_checks() -> bool`: Executes 92 individual deployment assertions validating PQC algorithm availability, file permissions (0600 on sensitive keys), liboqs dynamic link loader status, and security policy rules (`:110-340`). Returns boolean indicating deployment readiness.

#### `scripts/audit_pins.py` (`scripts/audit_pins.py:25-93`)
- `audit_dependencies(requirements_path: str = "requirements.txt", offline: bool = False, mirror_path: Optional[str] = None) -> List[dict]`: Parses pinned dependency versions and queries Open Source Vulnerabilities (OSV) database (`:35-80`). In air-gapped environments (`offline=True`), queries local JSON vulnerability mirror. Returns list of reported vulnerabilities; raises `VulnerabilityDetectedError` if unpatched high-severity CVEs exist.

#### `scripts/sign_dependencies.py` (`scripts/sign_dependencies.py:40-240`)
- `sign_binary(binary_path: str, signing_key_path: str, out_sig_path: str) -> None`: Signs binary file (`oqs.dll` or `libsodium.dll`) using ML-DSA-87 digital signature (`:60-120`). Writes signature bytes to `out_sig_path`.
- `generate_hashes_manifest(binary_path: str, out_hashes_path: str) -> None`: Computes SHA-256 and SHA-512 over binary and writes manifest format (`:130-185`).

#### `scripts/verify_reproducible_build.py` (`scripts/verify_reproducible_build.py:35-220`)
- `verify_build_receipt(receipt_path: str = "compliance_reports/signed_reproducible_build_receipt.json") -> bool`: Validates build timestamps, compiler versions, and target binary hashes against signed receipt envelope (`:50-180`). Returns `True` if current binary matches receipt.

## 3. Data Formats and Byte Layouts

### 3.1 Binary Hashes Manifest Layout (`*.hashes`)
Manifest files (`libsodium.dll.hashes`, `oqs.dll.hashes`) format hashes as structured key-value lines:
- Format:
  ```text
  SHA256: <64-hex-characters>
  SHA512: <128-hex-characters>
  ```
- Arithmetic Verification:
  - Line 1: `len("SHA256: ") + 64 + len("\n") = 8 + 64 + 1 = 73` bytes.
  - Line 2: `len("SHA512: ") + 128 + len("\n") = 8 + 128 + 1 = 137` bytes.
  - Total Manifest Size: $73 + 137 = 210$ bytes. Sum matches code arithmetic.

### 3.2 ML-DSA-87 Detached Signature Layout (`*.sig`)
- Detached binary signature files contain raw signature bytes emitted by `OQS_SIG_sign`:
  - Exactly 4,627 bytes (`liboqs_wrapper.py:551`).

## 4. Algorithms and Pinned Libraries
- ML-DSA-87: NIST FIPS 204. Dependency and receipt signing provided by native `oqs.dll` version 0.16.0 (`scripts/sign_dependencies.py:35`).
- SHA-256 & SHA-512: NIST FIPS 180-4. Binary checksumming provided by standard library `hashlib` (`scripts/sign_dependencies.py:22`).
- CycloneDX / SPDX SBOM: Formatted via `scripts/generate_production_sbom.py:45`.
- NIST OSCAL 1.0.0: XML/JSON schemas for SAR and SSP generated via `scripts/generate_oscal_ssp.py:60`.

## 5. Dependencies and Hardware Requirements
- Native toolchains: `rustc 1.99.1`, `cargo 1.99.1`, `python 3.10+`.
- Operating System APIs: PowerShell 5.1+ (Windows) or GNU bash (Linux) for shell automation scripts (`scripts/setup_wireguard.ps1`, `scripts/setup_wireguard.sh`).

## 6. Failure Behavior
- Any failed gate in `scripts/run_defense_audit.py` causes the script to print failure diagnostics and exit with non-zero exit code (1) (`scripts/run_defense_audit.py:255`).
- Unverified dependency signature or hash mismatch raises `SecurityVerificationError` and exits with code 2 (`scripts/sign_dependencies.py:195`).
- Offline dependency scan with missing local mirror raises `FileNotFoundError` (`scripts/audit_pins.py:42`).
- Reproducible build hash divergence causes `verify_reproducible_build.py` to exit with code 1 (`scripts/verify_reproducible_build.py:185`).

## 7. Configuration and Environment Variables
- `P2P_OFFLINE_MIRROR`: Path to local offline JSON vulnerability mirror for `audit_pins.py`. Default: unset (`scripts/audit_pins.py:30`).
- `P2P_SIGNING_KEY`: Path to ML-DSA-87 private signing key. Default: unset (`scripts/sign_dependencies.py:45`).
- `CI`: When set to `'true'`, skips interactive confirmations and forces strict non-zero exits on warnings (`.github/workflows/defense_ci.yml:45`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - Defense master audit execution: verified via `python scripts/run_defense_audit.py` (9/9 gates pass).
  - Core deployment assurance assertions: verified via `python verify_deployment.py` (92/92 pass).
  - Offline dependency scanning with mock database: verified in `tests/test_deployment_package.py` (4 tests).
- NOT Covered:
  - Hardware TPM attestation execution in continuous integration runner environments (GitHub Actions runners lack physical TPM chips).
  - Production air-gapped data diode hardware burning ceremonies.

## 9. Not Implemented / External Dependencies
- Public OSV Vulnerability API: Online dependency checks in `scripts/audit_pins.py` require access to `api.osv.dev`; air-gapped environments must supply `--offline` and `--mirror` parameters (`DEF-04`).
- Physical Hardware Security Modules: Key ceremonies in `scripts/witnessed_key_ceremony.py` fall back to software keypairs if physical PKCS#11 HSMs are not attached.

## 10. Known Limitations and Residual Risks
- Public Network Calls in Older Scripts: Prior to remediation `DEF-04`, `scripts/audit_pins.py` attempted public network connections, failing when executed on air-gapped networks.
- Manifest Hash Drift: `critical_modules.hashes` contains recorded SHA3-512 hashes that must be re-signed after modifying tracked source files (`FINDING-20261104-02`).

## 11. Discrepancies
- Promotional terms in script file names: `scripts/verify_50x_[PROMOTIONAL]_superiority.py` and `scripts/generate_[PROMOTIONAL]_pki.py` cataloged in `docs/audit/discrepancies.md`.

## 12. Open Questions for the Author
- Should `scripts/sign_dependencies.py` be executed automatically as part of the post-build Cargo release profile?
