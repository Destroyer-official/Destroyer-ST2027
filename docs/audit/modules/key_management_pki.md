# Module Documentation: Key Management and PKI Subsystem (`key_management_pki`)

## 1. Module Name & Purpose

- **Module Name:** `key_management_pki`
- **Subsystem Classification:** Key Custody, Hardware Security Modules, TPM Integration, and Public Key Infrastructure
- **Files in Module (19 files, 26,542 verified lines):**
  - `trust_anchor.py` (530 lines)
  - `ca_services.py` (2,058 lines)
  - `pq_certificate_authority.py` (1,234 lines)
  - `secure_key_manager.py` (1,231 lines)
  - `secure_key_provider.py` (686 lines)
  - `key_fill_import.py` (1,219 lines)
  - `tactical_key_provisioner.py` (1,342 lines)
  - `platform_hsm_interface.py` (11,641 lines)
  - `hsm_integration.py` (227 lines)
  - `cng_platform.py` (377 lines)
  - `cng_crypto.py` (422 lines)
  - `tpm_quote.py` (4,402 lines)
  - `threshold_cryptography.py` (460 lines)
  - `keys/__init__.py` (9 lines)
  - `keys/generation.py` (171 lines)
  - `keys/hsm_integration.py` (261 lines)
  - `keys/manager.py` (54 lines)
  - `keys/rotation.py` (200 lines)
  - `keys/storage.py` (216 lines)

- **Primary Technical Purpose:**
  The `key_management_pki` module provides key custody, platform hardware abstraction (TPM 2.0 / Windows CNG / PKCS#11), certificate authority services, threshold identity validation, air-gapped cryptographic key fill packages, and tactical peer credential provisioning.

---

## 2. Public Interface

### 2.1. `trust_anchor.py`
- **Classes & Dataclasses:**
  - `TrustError(Exception)` (`:44`): Base exception raised on certificate rejection, signature failure, or expired lifetime.
  - `Custodian` (`:128`): Dataclass containing `label: str` and `mldsa_pk: bytes` (2592 bytes).
  - `CertTBS` (`:134`): Dataclass containing `serial: bytes` (16 bytes), `subject: str`, `subject_pk: bytes` (2592 bytes), `not_before: int`, `not_after: int`, `issuer: str = "OFFLINE-ROOT-3OF5"`.
  - `CertSig` (`:144`): Dataclass containing `custodian: str`, `sig: bytes` (4627 bytes).
  - `Certificate` (`:150`): Dataclass containing `tbs: CertTBS`, `sigs: List[CertSig]`.
  - `Revocation` (`:156`): Dataclass containing `serial: bytes` (16 bytes), `reason: str`, `ts: float`, `seq: int`, `sigs: List[CertSig]`.
  - `TrustAnchor` (`:226`): Quorum manager verifying certificates, checking revocations, and maintaining in-memory revocation lists.
- **Exported Functions:**
  - `tbs_bytes(tbs: CertTBS) -> bytes` (`:164`): Serializes certificate to canonical binary wire format.
  - `revoke_bytes(rev: Revocation) -> bytes` (`:176`): Serializes revocation order to canonical binary wire format.
  - `issue_certificate(tbs: CertTBS, signers: List[Any], authorized: Optional[List[Custodian]] = None) -> Certificate` (`:213`): Validates parameters and collects custodian signatures.
  - `verify_certificate(cert: Certificate, authorized: List[Custodian], now: Optional[float] = None) -> bool` (`:239`): Checks lifetime span, future clock skew, and multi-signature quorum.

### 2.2. `ca_services.py`
- **Classes:**
  - `CAError(Exception)` (`:511`): Base exception with derived hierarchy (`CertificateVerificationError`, `RevocationError`, `StorageError`).
  - `NISTLevel5PolicyEngine` (`:47`): Policy validation checks for key parameters.
  - `SecureKeyStorage` (`:607`): Key storage helper providing `store_key`, `get_key`, `rotate_key`, `remove_key`.
  - `CAExchange` (`:754`): Manages offline/online certificate exchanges and socket wrapping:
    - `__init__(key_type="mldsa87", validity_days=365, secure_exchange=True)` (`:783`)
    - `generate_self_signed() -> Tuple[str, str]` (`:971`): Generates X.509 certificate and private key PEM strings.
    - `create_server_ctx() -> ssl.SSLContext` (`:1628`): Builds TLS 1.3 server context with `ssl.CERT_REQUIRED`.
    - `create_client_ctx() -> ssl.SSLContext` (`:1726`): Builds TLS 1.3 client context with pinned fingerprints.
    - `wrap_socket_server(sock, host, port)` (`:2010`) / `wrap_socket_client(sock, host, port)` (`:2032`)

### 2.3. `pq_certificate_authority.py`
- **Classes:**
  - `PQCertificateAuthority` (`:843`): Issues post-quantum certificates, generates CRLs, and signs OCSP responses.
  - `PQCertificate` (`:230`): Post-quantum certificate representation with ML-DSA-87 signatures.
  - `HashChainCRL` (`:710`): Hash-chained CRL linking each revocation to the previous CRL hash via SHA-384.
  - `OCSPResponse` (`:380`): OCSP status structure signed by CA.
  - `CTLogEntry` (`:480`): Certificate Transparency log entry for append-only audit trees.

### 2.4. `key_fill_import.py`
- **Classes & Functions:**
  - `KeyFillError(Exception)` (`:41`): Raised on corrupted, expired, or replayed key fill packages.
  - `pack_key_fill(fill_id: str, payload: Dict[str, Any], officers: Sequence[str], passphrases: Sequence[str], signing_key: bytes, expires_hours: float = 24.0, issuer_kid: str = "FILL-ISSUER") -> Dict[str, Any]` (`:90`): Creates dual-officer encrypted fill package.
  - `unpack_key_fill(doc: Dict[str, Any], officers: Sequence[str], passphrases: Sequence[str], verify_key: bytes, registry_path: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]` (`:250`): Authenticates signature, checks anti-replay registry, unwraps DEK, and decrypts payload.

### 2.5. `cng_platform.py`
- **Classes & Functions:**
  - `CngError(Exception)` (`:37`): Fail-closed exception for Windows CNG and TPM operations.
  - `open_platform_provider() -> int` (`:105`): Opens `"Microsoft Platform Crypto Provider"` handle.
  - `create_device_key(handle: int, key_name: str) -> None` (`:126`): Generates non-exportable `ECDSA_P256` key bound to hardware TPM.
  - `sign_hash(handle: int, key_name: str, hash_bytes: bytes) -> bytes` (`:205`): Signs 32-byte digest using TPM-bound key.
  - `verify_signature(handle: int, key_name: str, hash_bytes: bytes, signature: bytes) -> bool` (`:245`): Verifies ECDSA signature.
  - `delete_key(handle: int, key_name: str) -> None` (`:285`): Permanently deletes persisted key and confirms deletion.

### 2.6. `cng_crypto.py`
- **Classes & Functions:**
  - `CngError(Exception)` (`:38`): Cryptographic failure in BCrypt provider.
  - `aes256gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]` (`:172`)
  - `aes256gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes` (`:208`)
  - `sha384(data: bytes) -> bytes` (`:272`), `hmac_sha384(key: bytes, data: bytes) -> bytes` (`:295`), `hkdf_sha384(...)` (`:320`)
  - `ecdh_p384_raw(priv_handle, peer_pub: bytes) -> bytes` (`:420`)
  - `mlkem1024_keygen() -> Tuple[bytes, object]` (`:570`), `mlkem1024_encaps(ek: bytes) -> Tuple[bytes, bytes]` (`:606`), `mlkem1024_decaps(handle, ct: bytes) -> bytes` (`:632`)

### 2.7. `tpm_quote.py`
- **Classes & Functions:**
  - `PCRMismatchError` (`:44`), `AttestationVerificationError` (`:48`), `HardwareAttestationError` (`:52`)
  - `sign_quote(pcr_values: Dict[int, str], nonce: str, signing_key: bytes, kid: str = "AK-STUB") -> Dict[str, Any]` (`:170`)
  - `verify_quote(quote: Dict[str, Any], verify_key: bytes, expected_pcrs: Optional[Dict[int, str]] = None, max_age_seconds: float = 300.0) -> bool` (`:230`)
  - `read_hardware_pcrs(pcr_indices: List[int]) -> Dict[int, str]` (`:410`)
  - `seal_secret_to_pcrs(secret: bytes, pcr_indices: List[int]) -> bytes` (`:510`)

### 2.8. `threshold_cryptography.py`
- **Classes:**
  - `ThresholdError` (`:53`), `InsufficientSharesError` (`:57`), `ShareVerificationError` (`:67`), `ReconstructionError` (`:74`)
  - `ThresholdShare` (`:79`): Dataclass storing `index`, `value`, `commitment`, `threshold`, `total_shares`.
  - `ThresholdKeyManager` (`:133`): Evaluates Shamir Secret Sharing polynomials over prime field $p = 2^{256} - 189$.
- **Function:**
  - `is_custom_threshold_enabled() -> bool` (`:122`): Checks `P2P_ENABLE_EXPERIMENTAL` or `P2P_ENABLE_CUSTOM_THRESHOLD`.

### 2.9. `secure_key_manager.py`
- **Classes:**
  - `SecureKeyManager` (`:48`): Manages encrypted key storage, hybrid signature verification, and zeroization.
  - `ColdBootProtection` (`:3591`): Temperature monitoring thread intended to trigger memory wiping on rapid cooling.

---

## 3. Data Formats & Byte Layouts

### 3.1. `trust_anchor.py` Canonical Formats
1. **To-Be-Signed (TBS) Certificate Wire Format (`tbs_bytes` at `:164-174`):**
   - Header Domain: `b"CA-CERT-v1"` = 10 bytes (`_CERT_DOMAIN`)
   - Certificate Serial: 16 bytes (`tbs.serial`)
   - Normalized Subject: $S$ bytes UTF-8 string (alphanumeric, `-`, `_`, max 64 bytes)
   - Subject Public Key: 2592 bytes (`tbs.subject_pk`, ML-DSA-87 public key)
   - Validity `not_before`: 8 bytes (uint64 big-endian, `struct.pack(">Q", ...)`)
   - Validity `not_after`: 8 bytes (uint64 big-endian, `struct.pack(">Q", ...)`)
   - **Arithmetic Sum:**
     $$	ext{Total Fixed Overhead} = 10 + 16 + 2592 + 8 + 8 = 2634	ext{ bytes}$$
     $$	ext{Total TBS Size} = 2634 + S	ext{ bytes}$$

2. **Revocation Order Wire Format (`revoke_bytes` at `:176-186`):**
   - Header Domain: `b"CA-REVOKE-v1"` = 12 bytes (`_REVOKE_DOMAIN`)
   - Revocation Serial: 16 bytes (`rev.serial`)
   - Normalized Reason: $R$ bytes UTF-8 string (max 32 bytes)
   - Timestamp (ms): 8 bytes (uint64 big-endian, `struct.pack(">Q", int(ts * 1000))`)
   - Monotonic Sequence: 8 bytes (uint64 big-endian, `struct.pack(">Q", seq)`)
   - **Arithmetic Sum:**
     $$	ext{Total Fixed Overhead} = 12 + 16 + 8 + 8 = 44	ext{ bytes}$$
     $$	ext{Total Revocation Order Size} = 44 + R	ext{ bytes}$$

3. **Certificate Signature Wire Layout:**
   - Signatures are represented as a dictionary or sequence of `CertSig(custodian: str, sig: bytes)`.
   - Each ML-DSA-87 signature is exactly 4627 bytes.
   - For a valid quorum of $k=3$ signatures, signature payload sum = $3 	imes 4627 = 13881$ bytes.
   - For all $n=5$ signatures, signature payload sum = $5 	imes 4627 = 23135$ bytes.

### 3.2. `key_fill_import.py` Package Structure
- **Container Format:** JSON text document capped at 65536 bytes (`MAX_FILL_BYTES = 64 * 1024` at `:35`).
- **Fields:**
  - `v`: Integer version (`FILL_VERSION = 1`).
  - `magic`: String identifier (`"KMI-FILL-V1"`).
  - `fill_id`: Unique identifier string.
  - `created_utc`: Float epoch seconds.
  - `expires_utc`: Float epoch seconds.
  - `issuer_kid`: Issuer key identifier string.
  - `payload_sha3_256`: SHA3-256 hex string of canonical payload (64 hex chars = 32 bytes).
  - `officers`: List of officer ID strings (minimum 2 officers).
  - `enc`: Dict containing base64 AES-256-GCM nonce (12 bytes) and ciphertext of canonical payload (capped at 32768 bytes).
  - `wraps`: List of per-officer key wrap dictionaries:
    - `officer_id`: Officer identifier string.
    - `salt`: Base64 scrypt salt (32 bytes).
    - `nonce`: Base64 AES-256-GCM nonce (12 bytes).
    - `ct`: Base64 encrypted DEK (32 bytes plaintext + 16 bytes auth tag = 48 bytes ciphertext, encoded as 64 base64 chars).
  - `sig`: Base64 encoded ML-DSA-87 signature (4627 bytes raw = 6172 base64 chars).

### 3.3. `tpm_quote.py` Remote Attestation Envelope
- **Quote Structure (`tpm_quote.py:4-7`):**
  - `v`: 1
  - `pcr`: Dictionary mapping PCR index (e.g., 0, 1, 7, 11) to SHA-256 hex digest (64 hex chars = 32 bytes).
  - `nonce`: Hex string representing fresh challenge nonce.
  - `ts`: Float timestamp.
  - `alg`: `"ML-DSA-87"`.
  - `kid`: Key identifier string.
  - `sig`: Hex string representing signature.
  - Degraded simulation mode tags: `DEGRADED_MODE = "DEGRADED_SECONDARY_SIMULATION"` and `DEGRADED_ROOT = "DEGRADED_SECONDARY_SIMULATION_ROOT"`.

---

## 4. Algorithms & Pinned Libraries

1. **ML-DSA-87 (NIST FIPS 204):**
   - PKIX OID: `"2.16.840.1.101.3.4.3.19"` (RFC 9881 pure variant; HashML-DSA explicitly prohibited).
   - Public Key Size: 2592 bytes.
   - Private Key Size: 4896 bytes.
   - Signature Size: 4627 bytes.
   - Implementation: Native wrapper in `liboqs_wrapper.py` backed by `oqs.dll` (Open Quantum Safe v0.16.0).

2. **Scrypt Key Derivation Function (RFC 7914):**
   - Implemented in `key_fill_import.py:60-64` via Python standard library `hashlib.scrypt`.
   - Parameters: $N = 131072$ ($2^{17}$), $r = 8$, $p = 1$, $	ext{dklen} = 32$, $	ext{maxmem} = 256	ext{ MB}$.

3. **AES-256-GCM (NIST SP 800-38D):**
   - Implemented via `cryptography.hazmat.primitives.ciphers.aead.AESGCM` in `key_fill_import.py` and `ca_services.py`, and via Windows BCrypt (`cng_crypto.py`).
   - Key: 32 bytes (256 bits).
   - Nonce: 12 bytes (96 bits).
   - Authentication Tag: 16 bytes (128 bits).

4. **Windows CNG Microsoft Platform Crypto Provider:**
   - Implemented in `cng_platform.py` via `ncrypt.dll`.
   - Algorithm: `NCRYPT_ECDSA_P256_ALGORITHM` with `NCRYPT_DO_NOT_ALLOW_EXPORT`.
   - TPM 2.0 bound non-migratable keys. Note: Persisted AES keys are refused by the platform provider.

5. **Shamir Secret Sharing over Prime Field:**
   - Implemented in `threshold_cryptography.py:163`.
   - Prime Field: $p = 2^{256} - 189$ (256-bit pseudo-Mersenne prime).
   - Commitments: SHA-256 hash-based VSS commitments with domain separation `b"ThresholdKeyManager::VSS::Commitment::v1.0"`.

---

## 5. Dependencies

### 5.1. External Dependencies
- `cryptography` (hazmat primitives: `AESGCM`, `hashes`, `HKDF`, `x509`, `serialization`): Core cryptographic operations.
- `liboqs` (`oqs.dll` v0.16.0): Native shared library providing ML-DSA-87 signatures.
- Windows System DLLs (Windows platforms only via `ctypes`):
  - `ncrypt.dll`: Windows CNG Key Storage Provider (`cng_platform.py`).
  - `bcrypt.dll`: Windows BCrypt primitive library (`cng_crypto.py`).
  - `tbs.dll`: Windows TPM Base Services (probed in `platform_hsm_interface.py`).

### 5.2. Internal Repository Dependencies
- `pqc_algorithms.py`: Provides fallback wrappers and algorithm constants.
- `liboqs_wrapper.py`: Provides `LibOQS_MLDSA_87` interface.
- `secure_transmit_2027.py`: Provides `sign_with_identity` helper used by `trust_anchor.py:203`.
- `base.py`: Imported conditionally by `hsm_integration.py`.

### 5.3. Dead Code Subsystems
- `keys/` package (`keys/__init__.py`, `keys/generation.py`, `keys/hsm_integration.py`, `keys/manager.py`, `keys/rotation.py`, `keys/storage.py`):
  - 0 product source files contain `import keys` or `from keys`.
  - Only 1 test file (`tests/test_production_tier7_csprng_complete_audit.py:146`) imports `keys.storage`.
  - The package is unintegrated dead code resulting from an incomplete refactoring.

---

## 6. Failure Behavior

1. **`trust_anchor.py`:**
   - Quorum Failure: If valid custodian signatures $< 3$, raises `TrustError("trust rejected")` (`:218, 271, 325`).
   - Lifetime Exceeded: If $not\_after - not\_before > 172800$ seconds (48 hours), raises `TrustError("trust rejected")` (`:220`).
   - Clock Skew Violation: If $not\_before > now + 5.0$ seconds, raises `TrustError("trust rejected")` (`:247`).
   - Revocation: If certificate serial appears in revocation list, raises `TrustError("trust rejected")` (`:265`).
   - Malformed Inputs: If serial length $
e 16$ or public key length $
e 2592$, raises `TrustError("trust rejected")` (`:165`).

2. **`cng_platform.py`:**
   - Non-Windows Platform: Raises `CngError("CNG platform provider is Windows-only")` (`:57`).
   - Platform Return Codes: Translates any non-zero `SECURITY_STATUS` into `CngError` (`:102`).
   - Key Deletion Verification: After calling `NCryptDeleteKey`, attempts to reopen the key; if reopening succeeds, raises `CngError("deleted key was successfully reopened -- deletion failed")` (`:298`).

3. **`key_fill_import.py`:**
   - Over-size Packages: Raises `KeyFillError("fill file too large")` if raw file $> 64$ KB (`:201`).
   - Anti-Replay Registry: If `fill_id` or SHA-384 package digest already exists in registry, raises `KeyFillError("fill package already consumed")` (`:284`).
   - Officer Passphrase Mismatch: If passphrase fails AES-GCM tag verification, catches `Exception` and raises `KeyFillError("no authorized officer credentials could unlock the package")` (`:314`).

4. **`threshold_cryptography.py`:**
   - Default Production Gate: Raises `PermissionError("Custom threshold arithmetic (PRIME=2**256-189) is unaudited and disabled in production. Set P2P_ENABLE_EXPERIMENTAL=1 or P2P_ENABLE_CUSTOM_THRESHOLD=1...")` (`:195`).
   - Insufficient Shares: Raises `InsufficientSharesError` if provided shares $< k$ (`:59`).
   - Tampered Shares: Raises `ShareVerificationError` if VSS commitment does not match share value (`:70`).

5. **`tpm_quote.py`:**
   - Degraded Simulation: When physical TPM or TBS is unavailable, does not raise by default; instead returns a simulated quote branded with `DEGRADED_SECONDARY_SIMULATION` (`:40`).
   - Strict Attestation: If `P2P_FAIL_ON_SOFTWARE_FALLBACK=1` is set in caller environments, presence of degraded quotes causes execution abort.

---

## 7. Configuration / Environment Variables

| Variable Name | Defined In File | Default Value | Technical Purpose & Impact |
|:---|:---|:---|:---|
| `P2P_CA_CUSTODIANS` | `trust_anchor.py:72` | None | Comma-separated list of authorized custodian identity strings. |
| `P2P_CA_FILE` | `trust_anchor.py:78` | None | Filepath to persistent certificate and revocation storage. |
| `P2P_ALLOW_LOOPBACK` | `ca_services.py:795` | `0` | If set to `1`, permits loopback IP addresses (127.0.0.1) in peer certificate exchanges. |
| `P2P_AUTHORIZED_PEER_FINGERPRINT` | `ca_services.py:821` | None | Hex-encoded SHA-256 certificate fingerprint for peer whitelisting. |
| `P2P_BIND_ADDRESS` | `ca_services.py:1290` | `0.0.0.0` | Bind interface IP address for the CA exchange listener socket. |
| `P2P_CERT_SANS` | `ca_services.py:995` | None | Comma-separated Subject Alternative Names to include in generated X.509 certificates. |
| `P2P_CRL_REFRESH_HOURS` | `ca_services.py`, `pq_certificate_authority.py:48` | `24` | Refresh period in hours before CRL expiration. |
| `P2P_OCSP_MUST_STAPLE` | `ca_services.py:1650` | `0` | If set to `1`, requires OCSP status stapling in TLS server contexts. |
| `P2P_RECV_TIMEOUT` | `ca_services.py:1120` | `10.0` | Socket read timeout in seconds during certificate exchange. |
| `P2P_ENABLE_TEMP_MONITOR` | `secure_key_manager.py:3617` | `0` | If set to `1`, enables cold boot temperature monitoring thread (disabled by default). |
| `DISABLE_TEMP_MONITOR` | `secure_key_manager.py:3609` | None | If set to `1`, forcibly suppresses temperature monitoring thread. |
| `P2P_STORAGE_PASSPHRASE` / `P2P_KEY_STORAGE_PASSPHRASE` | `secure_key_manager.py:110` | None | Passphrase used to derive storage KEK for encrypted key database. |
| `P2P_ALLOW_LEGACY_KEY_MIGRATION` | `secure_key_manager.py:135` | `0` | If set to `1`, permits loading legacy key stores derived from host attributes. |
| `P2P_TACTICAL_KEY_PW` | `tactical_key_provisioner.py:52` | None | Pre-shared passphrase for tactical credential package generation. |
| `P2P_TPM_QUOTE` | `tpm_quote.py:32` | `0` | If set to `1`, attaches TPM attestation quote to protocol handshake. |
| `P2P_ALLOW_TPM_NATIVE` | `tpm_quote.py:12` | `0` | If set to `1`, enables native TBS / TPM2 hardware toolchain execution. |
| `P2P_DEVICE_ID` | `tpm_quote.py:175` | None | Unique hardware device identifier string. |
| `P2P_TPM_EK_ROOTS` | `tpm_quote.py:82` | None | Filepath to trusted vendor EK root certificate fingerprints. |
| `P2P_ENABLE_CUSTOM_THRESHOLD` / `P2P_ENABLE_EXPERIMENTAL` | `threshold_cryptography.py:128-129` | `0` | If set to `1`, enables unaudited custom threshold finite field math ($p = 2^{256} - 189$). |
| `P2P_THRESHOLD_STORAGE_KEY` | `threshold_cryptography.py:220` | None | Encryption key for storing threshold key shares across distributed directories. |
| `P2P_HSM_PIN` / `P2P_PKCS11_PIN` / `P2P_SOFTHSM_PIN` | `platform_hsm_interface.py:310-330` | None | User PIN strings for authenticating to PKCS#11 / SoftHSM tokens. |
| `SOFTHSM2_CONF` / `SOFTHSM2_LIB` / `PKCS11_LIB_PATH` | `platform_hsm_interface.py:210-240` | None | System filepaths pointing to PKCS#11 dynamic shared libraries and configuration files. |

---

## 8. Tests Covered & Not Covered

### 8.1. Tests Covered (Directly Executed and Verified)
- `tests/test_trust_anchor.py` (10 passed in 10.2s):
  - Validates 3-of-5 threshold issuance, multi-signature verification, invalid signature rejection, lifetime cap ($48	ext{ h}$), future clock skew rejection ($> 5.0	ext{ s}$), and revocation orders.
- `tests/test_key_fill_import.py` (10 passed in 4.8s):
  - Validates dual-officer passphrase encryption, scrypt KEK derivation, ML-DSA-87 signature authentication, anti-replay single-use registry, and corrupt package rejection.
- `tests/test_tpm_quote.py` (11 passed in 4.5s):
  - Validates quote envelope serialization, degraded simulation branding, PCR composite calculation, and secret sealing.
- `tests/test_ceremony_quorum.py` (1 passed in 0.5s):
  - Validates 3-of-5 threshold quorum ceremony.
- `tests/test_hsm_platform.py` (22 passed in 0.8s):
  - Validates Windows CNG and PKCS#11 platform interface abstraction.
- `tests/test_hardware_providers.py` (16 passed, 2 skipped in 0.3s):
  - Validates software fallback gating and Linux NV mock paths.
- `tests/test_cli_key_fill_and_diode.py` (2 passed in 10.5s):
  - Validates CLI packaging and import of key fill containers.
- `tests/test_crypto_root_fixes.py` (13 passed in 8.2s):
  - Validates `ca_services.py` and `threshold_cryptography.py` remediations.
- `tests/test_critical_audit_remediations.py` (6 passed in 2.1s):
  - Validates `ca_services.py` finding remediations (F4 TLS cert chain, F4b fail-closed CA error).
- `tests/test_high_audit_remediations.py` (6 passed in 1.9s):
  - Validates `secure_key_manager.py` memory scrubbing and constant-time comparisons.
- `tests/test_2028_national_security_remediations.py` (17 passed in 23.6s):
  - Validates Shamir 3-of-5 roundtrip, insufficient shares fail-closed behavior, ceremony degraded simulation branding, and revoked certificate rejection.

### 8.2. Not Covered / Zero Test Execution
- `secure_key_provider.py`: 0 test files in `tests/` reference or execute this module.
- `hsm_integration.py` (root): 0 test files in `tests/` reference or execute this module.
- `cng_crypto.py`: 0 test files in `tests/` reference or execute this module.
- `keys/generation.py`: 0 test files in `tests/` reference or execute this module.
- `keys/hsm_integration.py`: 0 test files in `tests/` reference or execute this module.
- `keys/manager.py`: 0 test files in `tests/` reference or execute this module.
- `keys/rotation.py`: 0 test files in `tests/` reference or execute this module.

---

## 9. Not Implemented / Stubs

1. **Vendor EK Roots in `tpm_quote.py:87-103`:**
   - `_EK_VENDOR_ROOTS` contains placeholder strings:
     - `"amd"`: `{"sha256": "placeholder_amd_ek_root_sha256"}`
     - `"intel"`: `{"sha256": "placeholder_intel_ek_root_sha256"}`
     - `"infineon"`: `{"sha256": "placeholder_infineon_ek_root_sha256"}`
   - The vendor root certificate fingerprints are unpopulated placeholders. Native EK certificate chain verification cannot authenticate against authentic manufacturer hardware roots without external configuration.

2. **TPM Remote Attestation Native AK in `tpm_quote.py:9-12`:**
   - Native TPM-resident Attestation Key (AK) extraction via TBS is not implemented in userspace. When native toolchains are missing, `tpm_quote.py` falls back to software simulation using `DEGRADED_SECONDARY_SIMULATION`.

3. **Temperature Monitoring Stub in `secure_key_manager.py:3650`:**
   - `_get_system_temperature()` contains:
     ```python
     return 40  # Safe default temperature
     ```
   - Comment at line 3612 notes: "native WMI/COM temperature probes cause access violations in multi-threaded environments... disabled by default; require explicit opt-in." When executed, the function returns a constant float `40`, providing no actual temperature anomaly detection.

4. **BCrypt ML-KEM-1024 Provider in `cng_crypto.py:503-644`:**
   - Functions `mlkem1024_keygen`, `mlkem1024_encaps`, and `mlkem1024_decaps` invoke BCrypt APIs with `"MLKEMPUBLICBLOB"`. Standard Windows CNG currently lacks public native ML-KEM-1024 algorithms; this code is untestable and unexecuted in test suites.

5. **Unintegrated `keys/` Subsystem:**
   - `keys/__init__.py`, `generation.py`, `hsm_integration.py`, `manager.py`, `rotation.py`, `storage.py` are standalone files not wired into the application orchestrator.

---

## 10. Known Limitations

1. **Windows Platform Crypto Provider Key Type Restrictions:**
   - `cng_platform.py` relies on `"Microsoft Platform Crypto Provider"` via TPM 2.0. The TPM Platform Crypto Provider on Windows supports only standard elliptic curve (`ECDSA_P256`) and RSA keys. It cannot store post-quantum keys (ML-DSA-87 / ML-KEM-1024) or persisted AES keys (`NTE_NOT_SUPPORTED`). Therefore, hardware TPM key custody is limited to device attestation and cannot protect post-quantum operational identity keys directly in hardware non-volatile storage.

2. **Python Memory Scrubbing Limitations:**
   - In `ca_services.py` and `secure_key_manager.py`, methods such as `secure_wipe_buffer` attempt to overwrite memory buffers. However, Python immutable objects (`bytes`, `str`) cannot be mutated in place; converting them to `bytearray` leaves the original immutable memory allocation on the Python heap until collected by the garbage collector.

3. **Unaudited Finite Field Math in `threshold_cryptography.py`:**
   - Shamir Secret Sharing uses custom polynomial interpolation over $p = 2^{256} - 189$. The code notes that this arithmetic is unaudited and refuses initialization unless `P2P_ENABLE_EXPERIMENTAL=1` is set. Production threshold identity operations rely instead on multi-signatures via `trust_anchor.py`.

4. **Code Duplication in `platform_hsm_interface.py`:**
   - At 11,641 lines, `platform_hsm_interface.py` contains large blocks of duplicated boilerplate classes (`NISTLevel5PolicyEngine`, `get_secure_key`, COM wrappers) identical to those in `ca_services.py` and `libsodium_manager.py`.

---

## 11. Discrepancies

1. **Promotional Banners in `tactical_key_provisioner.py:3-10`:**
   - File header contains promotional administrative titles and non-technical branding phrases at lines 3-10 (cataloged in `docs/audit/discrepancies.md`).

2. **Documentation Claims of Hardware Enforced Root vs Software Fallback:**
   - `docs/ARCHITECTURE.md:88` and `docs/FIPS_140_3_SECURITY_POLICY.md:87` claim platform attestation and hardware custody. However, `tpm_quote.py:40` and `scripts/witnessed_key_ceremony.py` fall back to `DEGRADED_SECONDARY_SIMULATION` when physical hardware is not present.

3. **Temperature Monitoring Claims vs Constant Return:**
   - `secure_key_manager.py:20` claims "Cold boot attack protection via temperature monitoring", whereas lines 3617 and 3650 disable monitoring by default and return a static constant `40`.

4. **Multi-Signature vs Secret Sharing Distinction:**
   - Documentation often uses the phrase "3-of-5 threshold Root CA" ambiguously. Code analysis confirms that `trust_anchor.py` implements multi-signatures (where each custodian signs independently with ML-DSA-87), whereas `threshold_cryptography.py` implements Shamir secret sharing (splitting a single secret into polynomial shares), and the latter is disabled by default in production.

---

## 12. Open Questions

1. **Deprecation of `keys/` Subsystem:**
   - Is the `keys/` package (`keys/generation.py`, `keys/storage.py`, etc.) an obsolete prototype intended for deletion, or an incomplete refactoring target intended to replace `secure_key_manager.py`?
2. **Standardization of TPM Remote Attestation:**
   - Are the placeholder vendor root hashes in `tpm_quote.py:87-103` scheduled to be populated with authentic AMD, Intel, and Infineon CA certificates, or is remote attestation planned to transition entirely to native platform tools (e.g., Windows TBS or Linux `tpm2-tools`)?
3. **Status of Windows CNG ML-KEM Backend:**
   - Does `cng_crypto.py:503-644` target an internal custom CNG provider, given that standard Windows 11 `bcrypt.dll` does not export `"MLKEMPUBLICBLOB"` in general release builds?