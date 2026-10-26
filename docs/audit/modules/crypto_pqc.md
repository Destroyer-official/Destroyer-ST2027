# Module Documentation: crypto_pqc

## 1. Purpose
The `crypto_pqc` module implements post-quantum and hybrid cryptographic operations, algorithm agility state transitions, self-tests, and policy checks (`pqc_algorithms.py:1-40`, `liboqs_wrapper.py:1-39`). It provides key encapsulation mechanisms (KEM), digital signature verification, authenticated symmetric encryption, and policy gating conforming to CNSA Suite 2.0 specifications (`cnsa2_policy_engine.py:8-13`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `liboqs_wrapper.LibOQS_MLKEM_1024` (`liboqs_wrapper.py:355-408`)
- `keygen() -> Tuple[bytes, bytes]`: Generates ML-KEM-1024 keypair (`liboqs_wrapper.py:370-377`). Returns `(public_key, secret_key)` where `len(public_key) == 1568` bytes and `len(secret_key) == 3168` bytes (`liboqs_wrapper.py:365-366`).
- `encaps(public_key: bytes) -> Tuple[bytes, bytes]`: Encapsulates a shared secret (`liboqs_wrapper.py:379-388`). Parameter `public_key` must be 1568 bytes; raises `ValueError` if size differs (`liboqs_wrapper.py:380-381`). Returns `(ciphertext, shared_secret)` where `len(ciphertext) == 1568` bytes and `len(shared_secret) == 32` bytes (`liboqs_wrapper.py:367-368`).
- `decaps(secret_key: bytes, ciphertext: bytes) -> bytes`: Decapsulates a shared secret (`liboqs_wrapper.py:390-405`). Parameters: `secret_key` (3168 bytes), `ciphertext` (1568 bytes); raises `ValueError` if sizes differ (`liboqs_wrapper.py:392-397`). Returns 32-byte shared secret (`liboqs_wrapper.py:368`). Raises `RuntimeError` if native decapsulation returns non-zero (`liboqs_wrapper.py:403`).

#### `liboqs_wrapper.LibOQS_MLDSA_87` (`liboqs_wrapper.py:543-596`)
- `keygen() -> Tuple[bytes, bytes]`: Generates ML-DSA-87 keypair (`liboqs_wrapper.py:554-560`). Returns `(public_key, secret_key)` where `len(public_key) == 2592` bytes and `len(secret_key) == 4896` bytes (`liboqs_wrapper.py:549-550`).
- `sign(secret_key: bytes, message: bytes, public_key: Optional[bytes] = None) -> bytes`: Computes signature over `message` (`liboqs_wrapper.py:561-578`). Parameter `secret_key` must be 4896 bytes; raises `ValueError` otherwise (`liboqs_wrapper.py:562-563`). Parameter `message` cannot exceed 8,388,608 bytes (`liboqs_wrapper.py:60`, `liboqs_wrapper.py:73-77`). Returns signature bytes of maximum length 4627 (`liboqs_wrapper.py:551`). If `public_key` is supplied, executes verify-after-sign validation, raising `RuntimeError` on verification failure (`liboqs_wrapper.py:573-577`).
- `verify(public_key: bytes, message: bytes, signature: bytes) -> bool`: Verifies signature against message (`liboqs_wrapper.py:584-593`). Parameter `public_key` must be 2592 bytes; raises `ValueError` otherwise (`liboqs_wrapper.py:585-586`). Returns `True` if signature is valid, `False` otherwise (`liboqs_wrapper.py:593`).

#### `liboqs_wrapper.LibOQS_SLH_DSA_256f` (`liboqs_wrapper.py:599-653`)
- `keygen() -> Tuple[bytes, bytes]`: Generates SLH-DSA-PURE-SHAKE-256f keypair (`liboqs_wrapper.py:611-616`). Returns `(public_key, secret_key)` where `len(public_key) == 64` bytes and `len(secret_key) == 128` bytes (`liboqs_wrapper.py:606-607`).
- `sign(secret_key: bytes, message: bytes, public_key: Optional[bytes] = None) -> bytes`: Computes signature (`liboqs_wrapper.py:618-635`). Secret key must be 128 bytes; returns signature bytes of length 49,856 (`liboqs_wrapper.py:608`).
- `verify(public_key: bytes, message: bytes, signature: bytes) -> bool`: Verifies signature (`liboqs_wrapper.py:641-650`). Public key must be 64 bytes (`liboqs_wrapper.py:642-643`). Returns boolean.

#### `liboqs_wrapper.LibOQS_Falcon_1024` (`liboqs_wrapper.py:656-710`)
- `keygen() -> Tuple[bytes, bytes]`: Generates Falcon-1024 keypair (`liboqs_wrapper.py:667-672`). Returns `(public_key, secret_key)` where `len(public_key) == 1793` bytes and `len(secret_key) == 2305` bytes (`liboqs_wrapper.py:662-663`).
- `sign(secret_key: bytes, message: bytes, public_key: Optional[bytes] = None) -> bytes`: Generates signature of maximum length 1462 bytes (`liboqs_wrapper.py:664`, `liboqs_wrapper.py:674-691`).
- `verify(public_key: bytes, message: bytes, signature: bytes) -> bool`: Verifies signature (`liboqs_wrapper.py:697-706`). Public key must be 1793 bytes (`liboqs_wrapper.py:698-699`).

#### `liboqs_wrapper.HybridKEM` (`liboqs_wrapper.py:747-939`)
- `keygen() -> Tuple[bytes, bytes]`: Concatenates ML-KEM-1024 and Classic McEliece-8192128f keys (`liboqs_wrapper.py:831-848`). Returns `(public_key, secret_key)` where public key is 1,359,392 bytes (1568 + 1,357,824) and secret key is 17,288 bytes (3168 + 14,120) (`liboqs_wrapper.py:840-845`).
- `encaps(public_key: bytes) -> Tuple[bytes, bytes]`: Encapsulates using both KEMs and combines shared secrets using HKDF-SHA384 (`liboqs_wrapper.py:850-873`). Returns `(ciphertext, hybrid_shared_secret)` where ciphertext is 1,776 bytes (1568 + 208) and `hybrid_shared_secret` is 48 bytes (`liboqs_wrapper.py:871-873`, `liboqs_wrapper.py:928`).
- `decaps(secret_key: bytes, ciphertext: bytes) -> bytes`: Decapsulates both components and combines them via HKDF-SHA384 (`liboqs_wrapper.py:875-904`). Returns 48-byte shared secret (`liboqs_wrapper.py:904`).

#### `liboqs_wrapper.HybridSignature` (`liboqs_wrapper.py:944-1055`)
- `__init__(mode: str = 'fast')`: Sets mode to `'fast'`, `'secure'`, or `'dual'`; raises `ValueError` if invalid (`liboqs_wrapper.py:965-968`).
- `keygen() -> Tuple[dict, dict]`: Returns dictionaries containing keys for `'mldsa'` and `'slhdsa'` (`liboqs_wrapper.py:974-996`).
- `sign(secret_keys: dict, message: bytes) -> dict`: Returns dictionary with `'mldsa'` signature (in fast or dual mode) and `'slhdsa'` signature (in secure or dual mode) (`liboqs_wrapper.py:998-1020`).
- `verify(public_keys: dict, message: bytes, signatures: dict) -> bool`: Verifies required signatures according to configured mode (`liboqs_wrapper.py:1022-1052`).

#### `cnsa2_policy_engine.CNSA2PolicyEngine` (`cnsa2_policy_engine.py:82-290`)
- `validate_algorithm(algorithm: str, category: AlgorithmCategory = None) -> bool`: Checks if `algorithm` belongs to approved frozen sets (`cnsa2_policy_engine.py:245-285`). Raises `SecurityPolicyViolation` on unapproved algorithms (`cnsa2_policy_engine.py:284-285`).
- `is_cnsa_2027_strict() -> bool`: Returns boolean indicating if strict 2027 procurement gate is active (`cnsa2_policy_engine.py:288-290`).

#### `crypto.kem.hybrid_combine_v2` (`crypto/kem.py:290-383`)
- `hybrid_combine_v2(dh_list: list, ss_hybrid: bytes, transcript: bytes) -> bytes`: Combines 4 classical DH outputs with post-quantum hybrid shared secret `ss_hybrid` and transcript bytes (`crypto/kem.py:290-336`). Returns 32-byte derived symmetric key (`crypto/kem.py:370-382`). Raises `ValueError` if `dh_list` does not contain exactly 4 non-empty secrets (`crypto/kem.py:334-341`). Raises `TypeError` if inputs are not bytes-like (`crypto/kem.py:338-349`).

## 3. Data Formats and Byte Layouts

### 3.1 Key and Ciphertext Sizes (Arithmetic Verification)

| Algorithm | Public Key (bytes) | Secret Key (bytes) | Ciphertext / Signature (bytes) | Shared Secret (bytes) | Source Citation |
|---|---|---|---|---|---|
| ML-KEM-1024 | 1,568 | 3,168 | 1,568 | 32 | `liboqs_wrapper.py:365-368`, `pqc_algorithms.py:3838-3841` |
| Classic McEliece-8192128f | 1,357,824 | 14,120 | 208 | 32 | `liboqs_wrapper.py:412-415` |
| Composite Hybrid KEM | 1,359,392 | 17,288 | 1,776 | 48 | `liboqs_wrapper.py:833-836`, `pqc_algorithms.py:3833-3836` |
| ML-DSA-87 | 2,592 | 4,896 | 4,627 | N/A | `liboqs_wrapper.py:549-551` |
| SLH-DSA-256f | 64 | 128 | 49,856 | N/A | `liboqs_wrapper.py:606-608` |
| Falcon-1024 | 1,793 | 2,305 | 1,462 | N/A | `liboqs_wrapper.py:662-664`, `pqc_algorithms.py:5025-5027` |
| HQC-256 | 2,249 | 2,289 | 4,481 | 32 | `pqc_algorithms.py:2411-2415`, `liboqs_wrapper.py:494-497` |

### 3.2 Composite Hybrid KEM Sum Verification
- Public Key: $1,568 + 1,357,824 = 1,359,392$ bytes (`pqc_algorithms.py:3833`). Sum matches code arithmetic.
- Secret Key: $3,168 + 14,120 = 17,288$ bytes (`pqc_algorithms.py:3834`). Sum matches code arithmetic.
- Ciphertext: $1,568 + 208 = 1,776$ bytes (`pqc_algorithms.py:3835`). Sum matches code arithmetic.
- Derived Shared Secret: 48 bytes via HKDF-SHA384 (`liboqs_wrapper.py:928`).

### 3.3 Random Padding Wire Layout (`crypto/padding.py:81-105`)
- Payload data: Variable length $N$ bytes (`crypto/padding.py:81`).
- Padding bytes: Random bytes generated via `secrets.token_bytes(L)` where $1 \le L \le 32$ (`crypto/padding.py:100-101`).
- Length indicator: Exactly 1 byte encoding $L$ (`crypto/padding.py:102`).
- Total padded length: $N + L + 1$ bytes (`crypto/padding.py:105`). Verification: minimum addition is $1 + 1 = 2$ bytes; maximum addition is $32 + 1 = 33$ bytes.

## 4. Algorithms and Pinned Libraries
- ML-KEM-1024: NIST FIPS 203 (August 2024). Provided by native dynamic library `oqs.dll` (pinned version 0.16.0, `dependency_security_verifier.py:240-245`, `crypto_selftest.py:16`).
- ML-DSA-87: NIST FIPS 204 (August 2024). Provided by native `oqs.dll` (`liboqs_wrapper.py:546-548`).
- SLH-DSA-256f: NIST FIPS 205 (August 2024), pure SHAKE variant. Provided by native `oqs.dll` (`liboqs_wrapper.py:603-605`).
- Falcon-1024: NIST Round 3 finalist / FIPS 206 draft baseline. Provided by native `oqs.dll` (`liboqs_wrapper.py:659-661`).
- Classic McEliece-8192128f: Code-based KEM. Provided by native `oqs.dll` (`liboqs_wrapper.py:410-412`).
- AES-256-GCM: NIST FIPS 197 / NIST SP 800-38D. Provided by `cryptography.hazmat.primitives.ciphers.aead.AESGCM` (`liboqs_wrapper.py:718-725`).
- HKDF-SHA384: IETF RFC 5869. Provided by `cryptography.hazmat.primitives.kdf.hkdf.HKDF` (`liboqs_wrapper.py:926-933`).
- HMAC-SHA3-512: NIST FIPS 202 / FIPS 198-1. Provided by standard library `hmac` and `hashlib.sha3_512` (`crypto/auth_tags.py:21-22`).

## 5. Dependencies and Hardware Requirements
- Native binaries: `oqs.dll` (Windows x86_64, SHA-384 pin enforced in `dependency_security_verifier.py:240-245`) and `libsodium.dll` (`libsodium_manager.py:88-100`).
- Python libraries: `cryptography>=42.0.0`, `pycryptodome>=3.20.0` (`requirements.txt:2-7`).
- Operating systems: Windows (validated via CNG interfaces), Linux (supported via dynamic link loader fallback), macOS (supported via ctypes fallback) (`production_pqc_algorithms.py:84-92`).
- Hardware entropy: Requires non-repeating entropy from `os.urandom` and `secrets` (`crypto_selftest.py:274-282`).

## 6. Failure Behavior
- Key size mismatch raises `ValueError` in `liboqs_wrapper.py:381, 393, 396, 563, 586, 620, 643, 676, 699`.
- Non-zero native return code from `OQS_KEM_encaps`, `OQS_KEM_decaps`, `OQS_SIG_sign`, or `OQS_SIG_keypair` raises `RuntimeError` (`liboqs_wrapper.py:386, 404, 558, 570`).
- Verify-after-sign failure raises `RuntimeError` with alert: `"FAIL-CLOSED: Verify-After-Sign (VAS) failed... potential fault-injection attack"` (`liboqs_wrapper.py:574-577, 631-634, 687-690`).
- Policy violation in algorithm selection raises `cnsa2_policy_engine.SecurityPolicyViolation` (`cnsa2_policy_engine.py:49, 285`).
- Power-up test failure raises `crypto_selftest.SelfTestError` and permanently sets `_FAILED = True`, blocking subsequent session starts (`crypto_selftest.py:46, 309-317`).
- Native buffer length check failure raises `ValueError` when message exceeds `_NATIVE_MAX_MESSAGE_BYTES` (8,388,608 bytes) (`liboqs_wrapper.py:60, 76`).

## 7. Configuration and Environment Variables
- `P2P_ENABLE_VULN_HQC`: Controls instantiation of `LibOQS_HQC_256`. Default: unset (raises `RuntimeError`). When set to `'1'`, `'true'`, `'yes'`, or `'on'`, permits HQC-256 execution (`liboqs_wrapper.py:482-486`).
- `P2P_ALLOW_CLASSICAL`: Opt-in toggle to bypass strict post-quantum requirements in non-production environments. Default: unset (`README.md:95`, `pqc_algorithms.py:1895`).
- `P2P_PRODUCTION`: Sticky enforcement gate enabling strict CNSA Suite 2.0 restrictions (`README.md:91-100`, `production_gate.py:20-45`).

## 8. Tests and Coverage Assessment
- Automated suites executing `crypto_pqc` functionality:
  - `tests/test_falcon_bundle_mode_consistency.py` (7 tests pass, validates Falcon/ML-DSA bundle serialization). Output: `7 passed in 3.31s` (command: `pytest tests/test_falcon_bundle_mode_consistency.py`).
  - `tests/test_combiner_downgrade_guard.py` (passes, verifies rejection of downgraded combiners).
  - `tests/test_crypto_root_fixes.py` (passes, verifies key sizes and fault injection guards).
  - `tests/test_cnsa27_gate_2026.py` (passes, verifies CNSA Suite 2.0 policy enforcement).
  - `tests/test_noise_pq_purity.py` (passes, verifies tokenizer scan and purity gates).
  - `tests/test_ratchet_dss_mldsa87.py` (passes, verifies ML-DSA-87 wire signatures).
  - `tests/test_pqxdh_combiner_v2_kat.py` (5 tests pass, verifies HKDF combiner test vectors).
  - Batch command `pytest tests/test_combiner_downgrade_guard.py tests/test_crypto_root_fixes.py tests/test_cnsa27_gate_2026.py tests/test_noise_pq_purity.py tests/test_ratchet_dss_mldsa87.py tests/test_pqxdh_combiner_v2_kat.py` produced: `37 passed in 32.33s`.
  - Self-test execution: `python -c "import crypto_selftest; print(crypto_selftest.run_powerup_selftests())"` produced green results across 9 checks: `aes_gcm`, `entropy`, `hashes`, `hkdf_sha384`, `mldsa_pct`, `mlkem_pct`, `p384`, `weak_rng_scan`, `x25519`.
  - Compliance validation execution: `python acvp_validation_harness.py --verify` returned: `[PASS] Cryptographic verification: ACVP Report signature VERIFIED with ML-DSA-87 (FIPS 204)`.
- What the tests do NOT cover:
  - `production_pqc_algorithms.py` has 0 test files referencing it in `tests/` (verified via repository scan in `scratch/find_crypto_tests.py`).
  - `nist_level5_policy_engine.py` has 0 test files referencing it in `tests/` (verified via repository scan in `scratch/find_crypto_tests.py`).
  - Hardware TPM acceleration is tested via mocks/fallbacks in unit environments, not physical FIPS 140-3 Level 3 tokens.

## 9. Not Implemented / External Dependencies
- Platform-specific acceleration hooks in `production_pqc_algorithms.py`: `_init_windows_cng()` (`production_pqc_algorithms.py:94-110`), `_init_linux_openssl()` (`production_pqc_algorithms.py:112-120`), and `_init_macos_security()` return `False` with comment `# Not implemented yet`.
- CMVP Certificate: The codebase implements algorithms specified by FIPS 203, FIPS 204, and FIPS 205, but possesses no NIST CMVP certificate number (acknowledged in `crypto_selftest.py:22-27` and `README.md:38-39`).

## 10. Known Limitations and Residual Risks
- Falcon-1024 wire format: Uses pre-standard Falcon implementation from liboqs, which is not guaranteed to be byte-compatible with the final NIST FIPS 206 (FN-DSA) standard expected in 2026/2027 (`cnsa2_policy_engine.py:200-203`).
- Classic McEliece key size: Public keys require 1,357,824 bytes, creating memory and bandwidth overhead during key exchange (`liboqs_wrapper.py:412`, `pqc_algorithms.py:3833`).
- In-memory key exposure: Python `bytes` objects are immutable and cannot be zeroized in-place, relying on process termination or garbage collection unless native buffers (`native_secure_buffer.py`) are explicitly used (`crypto/kem.py:375-377`).

## 11. Discrepancies
1. Document Claim vs Implementation (`docs/modules/pqc_algorithms.md:29-30` vs `liboqs_wrapper.py:656-660`): `docs/modules/pqc_algorithms.md` claims that `EnhancedFALCON_1024` only labels a hybrid ML-DSA+SLH-DSA construction and no `OQS_SIG_new("Falcon-*")` call exists. In reality, `liboqs_wrapper.py:660` directly calls `liboqs.OQS_SIG_new(b"Falcon-1024")`, and `pqc_algorithms.py:5024` instantiates `LibOQS_Falcon_1024()`.
2. Document Line Count vs Actual (`docs/modules/pqc_algorithms.md:1` vs `pqc_algorithms.py`): Document states `pqc_algorithms.py (~6500 lines)`. Actual file length is 8,321 lines.
3. Promotional Log Statements (`pqc_algorithms.py:3809, 4936, 5020`): Log statements and comments include promotional uppercase validation banners (cataloged in discrepancies.md).
4. Stated Acceleration vs Code Stub (`production_pqc_algorithms.py:6-20` vs `production_pqc_algorithms.py:106, 119`): Header claims multi-platform acceleration; implementation methods return `False` ("Not implemented yet").

## 12. Open Questions for the Author
1. Is `production_pqc_algorithms.py` intended to be deprecated in favor of `pqc_algorithms.py` and `liboqs_wrapper.py`, given that it currently has zero test coverage?
2. Should `EnhancedFALCON_1024` in `pqc_algorithms.py` be renamed or formally separated to avoid ambiguity between the native Falcon-1024 wrapper and the hybrid ML-DSA+SLH-DSA fallback?

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
