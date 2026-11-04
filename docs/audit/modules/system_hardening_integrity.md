# Module Documentation: system_hardening_integrity

## 1. Purpose
The `system_hardening_integrity` module governs binary provenance validation, dependency integrity verification, anti-tampering defenses, air-gapped transport envelopes, anti-forensic file shredding, and supply chain security (`dependency_security_verifier.py:1-1023`, `emergency_anti_tamper.py:1-275`, `anti_forensics.py:1-1155`). It validates pinned binary hashes and digital signatures for native DLLs before they are loaded into process memory (`supply_chain_security.py:1-2948`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `dependency_security_verifier.DependencySecurityVerifier` (`dependency_security_verifier.py:80-340`)
- `verify_binary(dll_path: str, hash_manifest_path: str, pub_key_path: str, sig_path: str) -> bool`: Computes SHA-256 and SHA-512 over the target binary, validates Ed25519 or ML-DSA-87 digital signature, and enforces liboqs floor version 0.16.0 (`dependency_security_verifier.py:120-280`). Raises `SecurityVerificationError` on hash or signature mismatch (`:160, 240`). Returns `True` on success.
- `verify_critical_modules(manifest_path: str = "critical_modules.hashes") -> Dict[str, bool]`: Validates byte lengths, SHA-512, and SHA3-512 for registered product source files (`dependency_security_verifier.py:285-308`). Raises `SecurityVerificationError` on hash drift.

#### `emergency_anti_tamper.AntiTamperMonitor` (`emergency_anti_tamper.py:65-210`)
- `check_debugger() -> bool`: Probes host OS for debugger attachment via `kernel32.IsDebuggerPresent` on Windows or `/proc/self/status` `TracerPid` on Linux (`emergency_anti_tamper.py:75-115`). Returns `True` if debugger is detected.
- `trigger_emergency_zeroize(reason: str) -> None`: Wipes all registered memory regions using DoD 3-pass sanitization, unlinks session keys, and executes `os._exit(1)` immediately (`emergency_anti_tamper.py:140-185`).

#### `anti_forensics.AntiForensicsEngine` (`anti_forensics.py:90-310`)
- `sanitize_artifacts(profile: SanitizationProfile) -> int`: Shreds temporary spool files, purges `__pycache__` directories, and overwrites session logs on disk (`anti_forensics.py:180-260`). Returns count of successfully sanitized filesystem items.
- `secure_shred_file(path: str, passes: int = 3) -> bool`: Multi-pass overwrites target file on disk before unlinking (`anti_forensics.py:270-305`).

#### `air_gapped_operation.AirGappedManager` (`air_gapped_operation.py:110-340`)
- `create_diode_bundle(payload: bytes, recipient_pk: bytes, signing_sk: bytes) -> bytes`: Packages message into a signed, self-contained transfer envelope formatted for simplex diode or removable media export (`air_gapped_operation.py:140-210`).
- `import_diode_bundle(bundle_data: bytes, sender_pk: bytes) -> bytes`: Validates envelope digital signature and unpacks payload (`air_gapped_operation.py:220-285`). Raises `BundleVerificationError` on invalid signature.

## 3. Data Formats and Byte Layouts

### 3.1 Pinned Binary Hash Manifest (`critical_modules.hashes`)
- JSON structure mapping relative file paths to exact byte counts and digests:
  - `path`: String relative file path.
  - `size_bytes`: Integer byte count.
  - `sha512`: 128-character hexadecimal string (64 bytes).
  - `sha3_512`: 128-character hexadecimal string (64 bytes).
- Arithmetic Verification:
  - Each SHA-512 digest represents exactly $512 \text{ bits} = 64 \text{ bytes} = 128 \text{ hex characters}$.
  - Each SHA3-512 digest represents exactly $512 \text{ bits} = 64 \text{ bytes} = 128 \text{ hex characters}$. Arithmetic matches specification.

### 3.2 Diode Transfer Bundle Layout (`air_gapped_operation.py:140-190`)
- Bundle Envelope Header (40 bytes):
  - Magic Bytes: 4 bytes `b"STDI"` (Simplex Tactical Diode Ingest).
  - Version: 2 bytes uint16 (`0x0001`).
  - Bundle Flags: 2 bytes uint16 bitfield.
  - Payload Length: 8 bytes uint64.
  - Creation Timestamp: 8 bytes uint64.
  - Header CRC32: 4 bytes uint32.
  - Reserved: 12 bytes zero-padded.
- Arithmetic Verification:
  - Header total: $4 + 2 + 2 + 8 + 8 + 4 + 12 = 40$ bytes (`air_gapped_operation.py:155`).
  - Followed by Payload ($N$ bytes) and ML-DSA-87 Signature (4,627 bytes).
  - Total Bundle Size: $40 + N + 4627 = N + 4667$ bytes. Sum matches code arithmetic.

## 4. Algorithms and Pinned Libraries
- SHA-512 & SHA3-512: NIST FIPS 180-4 / FIPS 202. Digest computation provided by standard library `hashlib` (`dependency_security_verifier.py:25`).
- Ed25519: IETF RFC 8032. Digital signature verification for `libsodium.dll` provided by `cryptography.hazmat.primitives.asymmetric.ed25519` (`dependency_security_verifier.py:225`).
- ML-DSA-87: NIST FIPS 204. Diode bundle signing provided by `oqs.dll` version 0.16.0 (`air_gapped_operation.py:165`).
- Leighton-Micali Signatures (LMS): IETF RFC 8554 / NIST SP 800-208. Stateful hash-based signing implemented in `stateful_artifact_signing.py:45`.

## 5. Dependencies and Hardware Requirements
- Native Dynamic Link Libraries: `oqs.dll` (pinned version 0.16.0) and `libsodium.dll` (pinned version 1.0.22) in workspace root.
- Operating System APIs:
  - Windows: `kernel32.dll` (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`).
  - Linux: `/proc/self/status` and `ptrace` system call (`emergency_anti_tamper.py:85-110`).

## 6. Failure Behavior
- DLL hash mismatch or signature verification failure raises `SecurityVerificationError` and aborts process (`dependency_security_verifier.py:160, 240`).
- LibOQS version check failure (< 0.16.0) raises `SecurityVerificationError` (`dependency_security_verifier.py:325`).
- Critical module source hash drift raises `SecurityVerificationError` (`dependency_security_verifier.py:305`).
- Debugger attachment triggers `trigger_emergency_zeroize()` calling `os._exit(1)` (`emergency_anti_tamper.py:180`).
- Diode bundle signature mismatch raises `BundleVerificationError` (`air_gapped_operation.py:265`).

## 7. Configuration and Environment Variables
- `P2P_AIR_GAPPED`: Enforces air-gapped isolation mode (skips external network calls). Default: `0` (`air_gapped_operation.py:50`).
- `P2P_DISABLE_ANTI_TAMPER`: Disables debugger attachment tripwires in development. Default: `0` (`emergency_anti_tamper.py:45`).
- `P2P_STRICT_DEPENDENCY_CHECK`: Refuses execution if any non-critical dependency check is unverified. Default: `1` (`dependency_security_verifier.py:65`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - Dependency signature and hash verification: verified in `tests/test_audit_p1_remediations_phase2.py` (`test_dependency_security_verification`).
  - Emergency zeroization execution on tamper trigger: verified in `tests/test_phase4_ato_redteam_siem.py` (6 tests).
  - Multi-pass anti-forensic file shredding: verified in `tests/test_defensive_audit_targets.py` (4 tests).
  - SSDF attestation record generation: verified in `tests/test_security_diagnostics.py` (2 tests).
- NOT Covered:
  - Cold-boot RAM forensic extraction on non-volatile memory.
  - Physical interposer attacks on hardware buses.

## 9. Not Implemented / External Dependencies
- Hardware Data Diodes: True unidirectional optical diodes require physical hardware transceivers; software models emulate unidirectional UDP simplex transport (`air_gapped_operation.py`).

## 10. Known Limitations and Residual Risks
- Hash Manifest Drift: Pre-existing changes to `rust_data_plane/src/main.rs` cause `critical_modules.hashes` to diverge from on-disk source until re-signed by the repository owner (`FINDING-20261104-02`).
- Windows UAC Constraints: Debugger detection on Windows (`CheckRemoteDebuggerPresent`) cannot detect kernel-level hypervisor debuggers without VBS/HVCI active.

## 11. Discrepancies
- Hash drift recorded in `docs/audit/open_questions.md` and `docs/audit/proposals.md` (Proposal 3).

## 12. Open Questions for the Author
- Should `critical_modules.hashes` be re-baselined using `scripts/sign_dependencies.py` upon formal release sign-off?
