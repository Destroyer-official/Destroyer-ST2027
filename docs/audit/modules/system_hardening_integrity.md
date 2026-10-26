# Module Audit: system_hardening_integrity

## 1. Overview and Scope
The `system_hardening_integrity` module governs binary provenance validation, dependency integrity verification, anti-tampering defenses, air-gapped data transfers, anti-forensic sanitization, supply chain security, and stateful artifact signing across the repository.

The module comprises 18 product files totaling 35,695 verified lines across source code, manifests, public keys, and vendored dynamic libraries:

| File Name | Lines | Verified Purpose | Primary Classes / Artifact Type |
| :--- | :--- | :--- | :--- |
| `air_gapped_operation.py` | 2,082 | Manages offline data transport, diode file bundles, and physical media exchange | `AirGappedManager`, `AirGappedBundle`, `DiodeTransferChannel` |
| `anti_forensics.py` | 1,155 | Sanitizes disk footprints, bytecode caches, temporary files, and process memory | `AntiForensicsEngine`, `SanitizationProfile`, `secure_shred_file` |
| `critical_modules.hashes` | 22 | JSON hash manifest storing SHA-512 and SHA3-512 digests of core runtime files | JSON Hash Manifest |
| `dependency_security_verifier.py` | 1,023 | Verifies hashes, digital signatures, and version floors of native dependencies | `DependencySecurityVerifier`, `SecurityVerificationError` |
| `emergency_anti_tamper.py` | 275 | Detects debugger attachments or memory hooks and triggers immediate zeroization | `AntiTamperMonitor`, `trigger_emergency_zeroize` |
| `libsodium.dll` | 1,334 | Vendored native dynamic link library binary providing libsodium primitives | Dynamic Link Library Binary |
| `libsodium.dll.hashes` | 5 | Text manifest recording SHA-256 and SHA-512 digests of `libsodium.dll` | SHA-256/SHA-512 Manifest |
| `libsodium.dll.pub` | 3 | Public key file for signature verification of `libsodium.dll` | Cryptographic Public Key |
| `libsodium.dll.sig` | 1 | Digital signature verifying the integrity and provenance of `libsodium.dll` | Binary Digital Signature |
| `operational_security.py` | 1,072 | Enforces operational security rules, token redactions, and log hygiene | `OperationalSecurityEngine`, `OPSECPolicy` |
| `oqs.dll` | 23,862 | Vendored native dynamic link library binary providing liboqs post-quantum algorithms | Dynamic Link Library Binary |
| `oqs.dll.hashes` | 5 | Text manifest recording SHA-256 and SHA-512 digests of `oqs.dll` | SHA-256/SHA-512 Manifest |
| `oqs.dll.pub` | 3 | Public key file for signature verification of `oqs.dll` | Cryptographic Public Key |
| `oqs.dll.sig` | 2 | Digital signature verifying the integrity and provenance of `oqs.dll` | Binary Digital Signature |
| `security_dependency_manager.py` | 1,014 | Validates installed Python package versions and hash provenance against lockfiles | `SecurityDependencyManager`, `DependencyIntegrityRecord` |
| `ssdf_attestation.py` | 261 | Generates NIST SP 800-218 Secure Software Development Framework attestation records | `SSDFAttestationGenerator`, `AttestationRecord` |
| `stateful_artifact_signing.py` | 628 | Implements Leighton-Micali Signatures (LMS) for forward-secure release signing | `StatefulArtifactSigner`, `LMSKeyManager` |
| `supply_chain_security.py` | 2,948 | Validates Software Bill of Materials (SBOM) and TUF dual-signed update manifests | `SupplyChainValidator`, `TUFMetadataVerifier` |

---

## 2. Architecture and Subsystem Mechanics

### 2.1 Native Dependency Verification and Version Floor Gating
In `dependency_security_verifier.py`:
- **Binary Hash Validation (`dependency_security_verifier.py:120-210`):**
  - Prior to invoking native APIs, `DependencySecurityVerifier.verify_binary` reads `oqs.dll.hashes` and `libsodium.dll.hashes`.
  - It computes SHA-256 and SHA-512 digests over the on-disk binaries using streaming chunk buffers (`chunk_size = 65536`).
  - If either digest diverges from the manifest, `SecurityVerificationError` is raised, preventing DLL dynamic loading.
- **Signature Verification (`dependency_security_verifier.py:215-280`):**
  - The verifier loads signature files (`oqs.dll.sig`, `libsodium.dll.sig`) and verifies them against the pinned public key files (`oqs.dll.pub`, `libsodium.dll.pub`).
- **Core Product File Verification (`dependency_security_verifier.py:285-308`):**
  - Reads `critical_modules.hashes` and validates size in bytes, SHA-512, and SHA3-512 for core files (`secure_transmit_2027.py`, `rust_data_plane/src/main.rs`, `ts_runtime.py`, `dependency_security_verifier.py`).
- **LibOQS Version Floor Gating (`dependency_security_verifier.py:310-330`):**
  - Calls `oqs_version()` from the loaded DLL.
  - Enforces version floor `(0, 16, 0)`: versions below 0.16.0 raise `SecurityVerificationError`, blocking execution.

### 2.2 Emergency Anti-Tamper and Debugger Monitoring
In `emergency_anti_tamper.py`:
- **Attachment Probing (`emergency_anti_tamper.py:75-115`):**
  - On Windows: Queries `kernel32.IsDebuggerPresent()` and `CheckRemoteDebuggerPresent()`.
  - On Linux: Probes `/proc/self/status` for `TracerPid != 0` and issues `ptrace(PTRACE_TRACEME, 0, 1, 0)`.
- **Zeroization Execution (`emergency_anti_tamper.py:140-185`):**
  - `trigger_emergency_zeroize()` immediately iterates through registered memory buffers, invokes DoD multi-pass sanitization routines via `secure_memory_wiper.py`, invalidates active ratchet keys, and executes `os._exit(1)`.

### 2.3 Air-Gapped Operation and Offline Transport
In `air_gapped_operation.py`:
- **Socket Isolation:** When operating in air-gapped mode (`P2P_AIR_GAPPED=1` or offline configuration), network sockets are disabled.
- **Transfer Envelopes:** Payloads are serialized into self-contained file bundles with manifest digests, sender certificates, and digital signatures for physical media transfer (e.g. data diodes, removable drives, optical media).
- **Network Call Avoidance:** Modules such as `libsodium_manager.py:663` explicitly branch when in air-gapped mode to skip external network calls.

### 2.4 Anti-Forensic Sanitization
In `anti_forensics.py`:
- **Filesystem Sanitization (`anti_forensics.py:180-260`):**
  - Removes ephemeral spool files and temporary chat directories using multi-pass file shredding (`secure_shred_file`).
  - Purges Python bytecode caches (`__pycache__` directories and `.pyc` files).
- **Process Memory Hygiene:**
  - Clears cached environment variables, unlinks lock files, and zeroizes internal log queues prior to process termination.

### 2.5 Supply Chain Security and The Update Framework (TUF)
In `supply_chain_security.py`:
- **Dual-Signature Scheme (`supply_chain_security.py:410-490`):**
  - Update manifests enforce post-quantum dual-signing: every release artifact must contain a valid classical digital signature (Ed25519) and a post-quantum digital signature (ML-DSA-87).
  - Single-signature updates or signatures with mismatched keys are rejected fail-closed.
- **Software Bill of Materials (SBOM):**
  - Parses and validates CycloneDX JSON SBOM manifests, checking component versions, package URLs, and cryptographic hashes against known pinned baselines.

### 2.6 Stateful Artifact Signing (LMS)
In `stateful_artifact_signing.py`:
- **Leighton-Micali Signatures:** Implements stateful hash-based signatures per RFC 8554 and NIST SP 800-208 using parameter set `LMS_sha3_512_M32_H15`.
- **OTS State Tracking:** Strictly tracks One-Time Signature (OTS) index advancement to prevent state reuse, storing private key trees with monotonic index increments.

### 2.7 SSDF Compliance Attestation
In `ssdf_attestation.py`:
- Generates structured JSON records tracking compliance with NIST SP 800-218 (Secure Software Development Framework).
- Records toolchain versions, Git commit provenance, build environment parameters, and test verification summaries.

---

## 3. Interfaces and Public API Surface

### 3.1 `DependencySecurityVerifier` (`dependency_security_verifier.py`)
- `verify_all_dependencies() -> bool`: Verifies DLL hashes, signatures, version floor, and critical module digests.
- `verify_binary(binary_path: Path, hash_manifest: Path, sig_file: Path, pub_key: Path) -> bool`: Verifies single binary artifact.
- `verify_critical_modules() -> bool`: Compares file sizes and digests against `critical_modules.hashes`.

### 3.2 `AntiTamperMonitor` (`emergency_anti_tamper.py`)
- `check_debugger() -> bool`: Returns True if debugger is attached.
- `trigger_emergency_zeroize(reason: str) -> None`: Wipes memory and terminates process.
- `register_sensitive_buffer(buffer: bytearray) -> None`: Adds buffer to zeroization registry.

### 3.3 `SupplyChainValidator` (`supply_chain_security.py`)
- `verify_update_manifest(manifest_path: Path, root_keys: Dict[str, bytes]) -> bool`: Validates TUF dual-signed update.
- `validate_sbom(sbom_path: Path) -> bool`: Validates SBOM component tree.

### 3.4 `StatefulArtifactSigner` (`stateful_artifact_signing.py`)
- `generate_key_pair() -> Tuple[bytes, bytes]`: Generates LMS public/private key tree.
- `sign_artifact(artifact_path: Path, private_key: bytes) -> bytes`: Generates LMS signature.
- `verify_artifact(artifact_path: Path, signature: bytes, public_key: bytes) -> bool`: Verifies LMS signature.

---

## 4. Test Evidence and Verification Results

### 4.1 Passing Test Suites
Audit verification executed the following test suites directly verifying system hardening and integrity:

1. **Stateful Signing, TUF Dual-Signing, Version Floor, and CSRMC Operations:**
   - Command: `pytest tests/test_stateful_artifact_signing.py tests/test_tuf_pq_dual_sign.py tests/test_liboqs_version_floor_gate.py tests/test_phase5_csrmc_ddil_operations.py -q`
   - Result: 79 passed, 1 skipped in 24.69s.
   - Verified behaviors:
     - LMS signature generation, parameter validation, and verification (`test_stateful_artifact_signing.py`).
     - TUF dual-signing with Ed25519 and ML-DSA-87, threshold enforcement, and downgrade refusal (`test_tuf_pq_dual_sign.py`).
     - Hard liboqs version floor enforcement (version 0.16.0 minimum) across 44 test cases (`test_liboqs_version_floor_gate.py`).
     - Anti-tamper emergency shredding, air-gapped transfer modes, and mission drill reports (`test_phase5_csrmc_ddil_operations.py`).
2. **Hardware Layer and Supply Chain Tests:**
   - Command: `pytest tests/test_ts_hw_layer.py tests/test_compliance_package_depth.py -q`
   - Verified behaviors:
     - Third-party library signature checking and critical module hash matching.
     - NIST SP 800-218 SSDF attestation structure generation and verification.

---

## 5. Discrepancies, Limitations, and Technical Debt

1. **Vendored Binary Tracking:**
   - `oqs.dll` (23,862 lines recorded in inventory / 4.2MB binary) and `libsodium.dll` (1,334 lines recorded in inventory / 540KB binary) are checked directly into git tracking. While tracked alongside cryptographic signature and hash manifests, tracking dynamic libraries directly in source repositories complicates multi-platform reproducible builds.
2. **Critical Module Manifest Drift Risk:**
   - `critical_modules.hashes` records exact file sizes and SHA-512/SHA3-512 digests for 4 files (`secure_transmit_2027.py`, `rust_data_plane/src/main.rs`, `ts_runtime.py`, `dependency_security_verifier.py`). Any maintenance commit touching these files requires manual regeneration of `critical_modules.hashes`, otherwise `dependency_security_verifier.py` raises `SecurityVerificationError` on startup.
3. **Stateful LMS OTS State Management:**
   - `stateful_artifact_signing.py` requires persistent non-volatile monotonic storage for LMS one-time signature counters. If the local state file is restored from a backup or snapshot, private key reuse could compromise hash-based signature security.

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
