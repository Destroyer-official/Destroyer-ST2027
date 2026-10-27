# Module Documentation: TLS Channel Subsystem (`tls_channel`)

## 1. Module Name & Purpose

- **Module Name:** `tls_channel`
- **Subsystem Classification:** Transport Layer Security, Post-Quantum TLS 1.3 Configuration, Channel Encapsulation, and Nonce Protection
- **Files in Module (4 files, 7,362 verified lines):**
  - `tls_channel_manager.py` (7,194 lines)
  - `tls_pq_policy.py` (94 lines)
  - `deploy/openssl_cnsa.cnf` (39 lines)
  - `openssl_cnsa2_posture.cnf` (35 lines)

- **Primary Technical Purpose:**
  The `tls_channel` module provides transport-layer security abstractions for authenticated node-to-node channels. It configures and wraps Python `ssl.SSLContext` instances to enforce TLS 1.3 exclusively, pins post-handshake cipher suites to `TLS_AES_256_GCM_SHA384` (CNSA 2.0), detects RFC 10024 hybrid post-quantum key-exchange groups via `ssl.MemoryBIO` ClientHello probing, applies OpenSSL configuration overlays, and enforces counter-based nonce exhaustion boundaries.

---

## 2. Public Interface

### 2.1. `tls_channel_manager.py`
- **Classes:**
  - `SecurityError(Exception)` (`:130`): Raised on security policy breaches, downgrade proposals, or invalid ciphers.
  - `TlsChannelException(Exception)` (`:150`): Base transport failure exception.
  - `TLSSecureChannel` (`:1706`): Primary channel coordinator managing TLS socket lifetimes:
    - `_create_client_context() -> ssl.SSLContext` (`:3799`): Builds TLS 1.3 client context with `verify_mode = ssl.CERT_REQUIRED`.
    - `_create_server_context() -> ssl.SSLContext` (`:4525`): Builds TLS 1.3 server context with mutual authentication.
    - `wrap_socket_server(sock: socket.socket) -> ssl.SSLSocket` (`:3264`)
    - `wrap_socket_client(sock: socket.socket, server_hostname: Optional[str] = None) -> ssl.SSLSocket` (`:3328`)
    - `do_handshake(sock: ssl.SSLSocket) -> None` (`:3470`): Executes TLS handshake and verifies negotiated cipher suite against pinned policy.
    - `send_secure(sock: ssl.SSLSocket, data: bytes) -> None` (`:3550`)
    - `recv_secure(sock: ssl.SSLSocket, bufsize: int = 4096) -> bytes` (`:3580`)
    - `_validate_certificate_with_dane(cert_der: bytes, hostname: str)` (`:4904`): TLSA record verification when DNSSEC is available.
  - `TLSRecordLayer` (`:5074`): Manages application record fragmentation, symmetric encryption, and key rotation.
  - `CounterBasedNonceManager` (`:5320`): Tracks per-session nonce generation and enforces strict counter exhaustion limits.
  - `NonceManager` (`:590`): Sliding-window nonce tracker managing IV freshness.
  - `OAuth2DeviceFlowAuth` (`:1068`): Opt-in OAuth2 device authorization flow for cloud identity federation; disabled in production air-gapped environments.
  - `PostQuantumCrypto` (`:294`): Thin facade wrapping KEM and signature operations.
  - `XChaCha20Poly1305` (`:686`): Software fallback AEAD implementation using 192-bit nonces.
  - `DirectX25519KeyExchange` (`:5232`) & `Ed25519Signer` (`:5262`): Standalone classical primitives declared in module; verified as dead code without references.

### 2.2. `tls_pq_policy.py`
- **Functions:**
  - `client_offers_hybrid_group() -> bool` (`:41`): Emits a default TLS 1.3 ClientHello into an `ssl.MemoryBIO` buffer, parses the `supported_groups` extension (extension type 10), and returns `True` if any RFC 10024 hybrid group codepoint is present.
  - `reset_cache_for_tests() -> None` (`:89`): Clears the cached probe result for test isolation.
- **Constants:**
  - `RFC10024_HYBRID_GROUP_CODEPOINTS = (0x11EC, 0x11ED, 0x11EB)` (`:22`): Codepoints for `X25519MLKEM768`, `SecP384r1MLKEM1024`, `SecP256r1MLKEM768`.
  - `RFC10024_HYBRID_GROUP_NAMES` (`:25`): Canonical OpenSSL group names and legacy aliases.

### 2.3. Configuration Files
- `deploy/openssl_cnsa.cnf` (`:1-39`): OpenSSL posture overlay enforcing `MinProtocol = TLSv1.3`, `MaxProtocol = TLSv1.3`, and `Groups = X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768`.
- `openssl_cnsa2_posture.cnf` (`:1-35`): Template restricting `CipherSuites = TLS_AES_256_GCM_SHA384` and `Groups = SecP384r1MLKEM1024:X25519MLKEM768:secp384r1`.

---

## 3. Data Formats & Byte Layouts

### 3.1. TLS 1.3 ClientHello Memory BIO Parsing (`tls_pq_policy.py:56-83`)
- **Record Layer Header (5 bytes):**
  - ContentType: 1 byte (`0x16` = Handshake)
  - Legacy Version: 2 bytes (`0x03 0x03` = TLS 1.2 compatibility version)
  - Record Length: 2 bytes (uint16 big-endian)
- **Handshake Header (4 bytes):**
  - Handshake Type: 1 byte (`0x01` = ClientHello)
  - Length: 3 bytes (uint24 big-endian)
- **ClientHello Body:**
  - Client Version: 2 bytes (`0x03 0x03`)
  - Random: 32 bytes
  - Legacy Session ID: 1 byte length ($sid$) + $sid$ bytes
  - Cipher Suites: 2 bytes length ($cs$) + $cs$ bytes (array of uint16)
  - Compression Methods: 1 byte length ($cm$) + $cm$ bytes
  - Extensions Length: 2 bytes (uint16 big-endian)
  - Extensions Sequence:
    - Extension Type: 2 bytes (uint16 big-endian). Target: `0x000A` (Type 10 = `supported_groups`).
    - Extension Data Length: 2 bytes (uint16 big-endian).
    - Supported Groups List Length: 2 bytes (uint16 big-endian).
    - Named Group Codepoints: Array of uint16 big-endian values. Checked against:
      - `0x11EC`: `X25519MLKEM768`
      - `0x11ED`: `SecP384r1MLKEM1024`
      - `0x11EB`: `SecP256r1MLKEM768`

### 3.2. Record Framing and Nonce Layout
- **Record Envelope:** 5-byte header + encrypted payload + 16-byte authentication tag.
- **Counter-Based Nonce (96 bits / 12 bytes):**
  - High 32 bits (4 bytes): Fixed session salt.
  - Low 64 bits (8 bytes): Monotonically incrementing message sequence counter (`struct.pack(">Q", counter)`).
  - Maximum window threshold: $2^{32} - 1$ or configured ceiling; raises `SecurityError` upon exhaustion.

---

## 4. Algorithms & Pinned Libraries

1. **TLS Protocol Version:**
   - Strictly TLS 1.3 (RFC 8446). TLS 1.2 and earlier versions are disabled across client and server contexts.

2. **Symmetric Cipher Suite:**
   - `TLS_AES_256_GCM_SHA384` (IANA codepoint `0x1302`): 256-bit AES in Galois/Counter Mode with SHA-384 hashing (CNSA 2.0 mandate).

3. **Hybrid Key Exchange Groups (RFC 10024):**
   - `X25519MLKEM768` (`0x11EC`): X25519 + ML-KEM-768 hybrid group.
   - `SecP384r1MLKEM1024` (`0x11ED`): NIST P-384 + ML-KEM-1024 Level 5 hybrid group.

4. **Underlying Cryptographic Engines:**
   - CPython `ssl` module linked against OpenSSL 3.5.7.
   - Fallback symmetric cryptography provided by Python `cryptography` hazmat primitives (`AESGCM`, `XChaCha20Poly1305`).

---

## 5. Dependencies

### 5.1. External Dependencies
- `ssl`: Standard library TLS implementation.
- `socket`: Standard network socket interface.
- `struct`: Binary unpacking of ClientHello TLS extensions.
- `cryptography`: Hazmat primitives for fallback record encryption.

### 5.2. Internal Repository Dependencies
- `tls_pq_policy`: Imported by `tls_channel_manager.py:1903` and `platform_hsm_interface.py:8723` to probe runtime hybrid group support.
- `pqc_algorithms`: Imported for post-quantum key representations.

### 5.3. Dead Code Classes
- `DirectX25519KeyExchange` (`tls_channel_manager.py:5232`): Declares direct X25519 key exchange without hybrid binding; 0 external references.
- `Ed25519Signer` (`tls_channel_manager.py:5262`): Declares standalone Ed25519 signing; 0 external references.

---

## 6. Failure Behavior

1. **Protocol Downgrade Attempt:**
   - If a remote peer proposes TLS 1.2 or earlier, OpenSSL rejects the handshake with `SSLV3_ALERT_HANDSHAKE_FAILURE`.

2. **Cipher Suite Discrepancy:**
   - In `TLSSecureChannel.do_handshake()`, the negotiated cipher suite is inspected via `sslobj.cipher()`. If the negotiated cipher is not `TLS_AES_256_GCM_SHA384`, `SecurityError` is raised immediately, and the connection is closed.

3. **Nonce Space Exhaustion:**
   - If `CounterBasedNonceManager` detects that the message counter reaches the maximum safe threshold, subsequent calls to generate a nonce raise `SecurityError("Nonce space exhausted")` fail-closed to prevent IV reuse.

4. **Mutual Authentication Failure:**
   - Both client and server contexts enforce `ssl.CERT_REQUIRED`. If the peer does not present an authorized certificate rooted in the designated CA, the handshake terminates with an `SSLError`.

5. **External Identity Token Validation Failure:**
   - When OAuth2 device flow authentication is attempted in production or air-gapped modes, `OAuth2DeviceFlowAuth` aborts with `SecurityError`.

---

## 7. Configuration / Environment Variables

| Variable Name | Defined In File | Default Value | Technical Purpose & Impact |
|:---|:---|:---|:---|
| `OPENSSL_CONF` | System environment | None | Absolute path to `openssl_cnsa2_posture.cnf` or `deploy/openssl_cnsa.cnf`, forcing OpenSSL to restrict groups and protocols globally. |
| `CNSA_2027_STRICT` | `tls_channel_manager.py:210` | `0` | If set to `1`, enforces strict CNSA 2.0 cipher suites and aborts on non-compliant configurations. |
| `P2P_CERT_PATH` | `tls_channel_manager.py:1750` | None | Filepath to local node X.509 certificate. |
| `P2P_KEY_PATH` | `tls_channel_manager.py:1755` | None | Filepath to local node private key. |
| `P2P_CA_PATH` | `tls_channel_manager.py:1760` | None | Filepath to trusted Root CA bundle. |
| `P2P_NONCE_WINDOW` | `tls_channel_manager.py:595` | `1000` | Sliding window size for replay prevention and nonce tracking. |
| `P2P_OCSP_MUST_STAPLE` | `tls_channel_manager.py:4560` | `0` | If set to `1`, requires valid OCSP staple in TLS server handshake. |
| `P2P_CRL_REFRESH_HOURS` | `tls_channel_manager.py:4575` | `24` | Refresh interval in hours for CRL updates. |
| `P2P_ENVIRONMENT` | `tls_channel_manager.py:1100` | `"production"` | Operational environment selector (`"production"`, `"test"`, `"airgap"`). |
| `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` | `tls_channel_manager.py:1080` | None | Client credentials for OAuth2 device authorization flow. |

---

## 8. Tests Covered & Not Covered

### 8.1. Tests Covered (Directly Executed and Verified)
- `tests/test_tls_cnsa_suite_pin.py` (2 passed):
  - Validates `SecurityError` definition and pins `TLS_AES_256_GCM_SHA384` during `do_handshake()`.
- `tests/test_nonce_hardening.py` (9 passed):
  - Validates counter-based nonce stability, non-repetition, exhaustion fail-closed enforcement, window flushing, and salt re-drawing on rotation.
- `tests/test_oauth_token_validation_p0.py` (10 passed):
  - Validates rejection of empty/oversized tokens, external OAuth blocking in production, provider response error handling, and authentication acceptance/rejection.
- `tests/test_critical_audit_remediations.py` (6 passed):
  - Validates TLS certificate chain enforcement and fail-closed error handling.
- `tests/test_crypto_root_fixes.py` (13 passed):
  - Validates TLS context parameter checks and buffer ceiling enforcement.

### 8.2. Not Covered / Zero Test Execution
- `tls_pq_policy.py`: 0 dedicated test files in `tests/`, though verified via runtime execution during audit.
- `DirectX25519KeyExchange` and `Ed25519Signer` classes in `tls_channel_manager.py`: 0 test files (dead code).

---

## 9. Not Implemented / Stubs

1. **Dead Code Stubs in `tls_channel_manager.py:5232, 5262`:**
   - `DirectX25519KeyExchange` and `Ed25519Signer` are fully declared but have no caller in the codebase.
2. **DANE Resolution in Air-Gapped Environments:**
   - `_validate_certificate_with_dane` (`:4904`) requires an active DNSSEC resolver. In air-gapped or tactical networks lacking DNSSEC infrastructure, DANE validation is bypassed or disabled.

---

## 10. Known Limitations

1. **CPython Standard Library TLS API Constraints:**
   - CPython's `ssl.SSLContext` exposes neither `set_groups()` nor `get_negotiated_group()`. Consequently, python code cannot programmatically specify or verify the negotiated key exchange group via public API calls; enforcement relies on `OPENSSL_CONF` environment files or memory BIO ClientHello probing.
2. **Memory Scrubbing Limitations in Python:**
   - Symmetric keys and decrypted record plaintext reside in Python heap objects that cannot be guaranteed scrubbed from memory without process termination or native Rust zeroization.

---

## 11. Discrepancies

1. **Line Count Discrepancy in Documentation:**
   - `docs/modules/tls_channel_manager.md:1` lists `tls_channel_manager.py` as `~5700 lines`, whereas the actual line count is 7,194 lines.
2. **Persistence of Dead Classical Cryptographic Classes:**
   - `docs/modules/tls_channel_manager.md:28-31` noted that `DirectX25519KeyExchange` and `Ed25519Signer` were "scheduled for deletion". However, both classes remain present in `tls_channel_manager.py`.

---

## 12. Open Questions

1. **Timeline for Excising Dead Classical Stubs:**
   - When will `DirectX25519KeyExchange` and `Ed25519Signer` be permanently removed from `tls_channel_manager.py`?
2. **Standardization of OpenSSL Configuration Files:**
   - Does `openssl_cnsa2_posture.cnf` supersede `deploy/openssl_cnsa.cnf`, or do they serve distinct production deployment architectures?