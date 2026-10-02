# FIPS 140-3 Cryptographic Module Security Policy (CMSP) -- DRAFT
## Secure P2P Sovereign Cryptographic Module v2.0.0-CNSA2-2027

> Self-authored policy draft for CMVP preparation. NOT validated, NOT
> submitted; no laboratory engaged. Levels below are TARGETS.

### 1. Module Overview & Cryptographic Boundary
- **Module Name:** Secure P2P Sovereign Cryptographic Module
- **Module Version:** 2.0.0-CNSA2-2027
- **Target Security Level:** FIPS 140-3 Level 4 Overall (ISO/IEC 19790:2012) -- TARGET, not assessed
- **Module Type:** Multi-Chip Standalone / Hardware-Bound Software Module
- **Testing Laboratory:** NONE ENGAGED (a NVLAP-accredited CST laboratory must be contracted before submittal)
- **Validation Status:** NO CMVP CERTIFICATE EXISTS. This document supports future validation; it confers none.

The cryptographic boundary encompasses:
1. **Physical Boundary:** Host platform enclosing a physical TPM 2.0 (ISO/IEC 11889) or PKCS#11 Level 4 HSM with active physical tamper detection and zeroization circuitry.
2. **Logical Boundary:** Native shared libraries (`oqs.dll`, `libsodium.dll`, native Rust data plane `destroyer_core`) and Python cryptographic policy enforcement engines (`pqc_algorithms.py`, `platform_hsm_interface.py`, `secure_p2p.py`).

---

## 2. FIPS 140-3 Security Levels by Section

| Section | Title | Target Level |
| :--- | :--- | :--- |
| **1** | Cryptographic Module Specification | Level 4 |
| **2** | Cryptographic Module Interfaces | Level 4 |
| **3** | Roles, Services, and Authentication | Level 4 |
| **4** | Software / Firmware Security | Level 4 |
| **5** | Operational Environment | Level 4 |
| **6** | Physical Security | Level 4 |
| **7** | Non-Invasive Security | Level 4 |
| **8** | Sensitive Parameter Management | Level 4 |
| **9** | Cryptographic Algorithm Security | Level 4 |
| **10** | Electromagnetic Interference / Compatibility (EMI/EMC) | Level 4 |
| **11** | Life-Cycle Assurance | Level 4 |
| **12** | Mitigation of Other Attacks | Level 4 |

---

## 3. Approved Cryptographic Algorithms (NSA CNSA 2.0 Strict)

All legacy and non-quantum algorithms (RSA, DH, ECDSA, ECDH, DES, 3DES, RC4, MD5, SHA-1) are completely disabled. The module operates strictly in the Approved CNSA 2.0 Mode:

| Function | Algorithm | Standards Reference | Self-Test Status (in-repo KAT; not lab validation) |
| :--- | :--- | :--- | :--- |
| **Key Encapsulation (KEM)** | ML-KEM-1024 | FIPS 203 | SELF-TEST PASS (AFT, KAT) |
| **Digital Signatures** | ML-DSA-87 | FIPS 204 | SELF-TEST PASS (AFT, KAT) |
| **Stateless Signatures** | SLH-DSA-256f | FIPS 205 | SELF-TEST PASS (AFT, KAT) |
| **Symmetric Bulk AEAD** | AES-256-GCM | FIPS 197 / NIST SP 800-38D | SELF-TEST PASS (KAT Vector 15, SP 800-38D) |
| **Key Derivation (KDF)** | HKDF-SHA384 | RFC 5869 / NIST SP 800-56C | SELF-TEST PASS |
| **Cryptographic Hash** | SHA-384, SHA-512 | FIPS 180-4 | SELF-TEST PASS (MCT, KAT) |
| **Extendable Output** | SHA3-512, SHAKE-256 | FIPS 202 | SELF-TEST PASS (MCT, KAT) |

---

## 4. Roles, Services, and Authentication

The module enforces identity-based authentication for all operators and roles without exception:

1. **Cryptographic Officer (CO)**:
   - *Authentication:* Multi-factor quorum with hardware-backed credentials (2-of-3 quorum).
   - *Authorized Services:* Root key generation ceremonies, TPM 2.0 PCR attestation measurement, firmware update authorization, emergency zeroization.
2. **Tactical User**:
   - *Authentication:* Mutual post-quantum certificate validation (ML-DSA-87 / Ed25519) and TOFU safety numbers.
   - *Authorized Services:* Double Ratchet encrypted messaging, WireGuard-style UDP streaming, file transfer, ephemeral telemetry.

---

## 5. Self-Tests (FIPS 140-3 IG 10.3.A & ISO/IEC 19790 §7.10)

### 5.1 Power-Up Self-Tests (Implemented in `crypto_selftest.py`)
Synchronous power-up Known Answer Tests (KATs) run automatically prior to cryptographic initialization in the 2027 Top Secret pipeline (`secure_transmit_2027.py` via `run_powerup_kats()`). The data plane is blocked until all KATs pass; any single discrepancy immediately sets `_FAILED = True`, raises `SelfTestError`, and aborts execution fail-closed:

1. **Cryptographic Algorithm Known Answer Tests (KATs):**
   - **AES-256-GCM:** Cross-implementation KAT comparing OpenSSL (`cryptography`) against `pycryptodome` (independent implementations) for encryption equivalence, 16-byte authentication tag verification, and single-bit tamper rejection.
   - **HKDF-SHA384:** Cross-implementation KAT verifying deterministic 32-byte record key and IV derivation matching RFC 5869.
   - **SHA-384 / HMAC-SHA384:** Cross-engine hash and MAC equivalence tests against reference test vectors.
   - **X25519:** RFC 7748 §5.2 Vector 1 and §6.1 Diffie-Hellman test vector validation.
   - **P-384 ECDH:** OpenSSL vs `pycryptodome` shared secret equality.

2. **Firmware & Native Library Integrity Verification:**
   - Ed25519 digital signature validation over raw DLL bytes (`oqs.dll.sig`, `libsodium.dll.sig`) using pinned public anchors (`oqs.dll.pub`, `libsodium.dll.pub`).
   - Cryptographic SHA-512 and SHA3-512 hash integrity checks (`oqs.dll.hashes`, `libsodium.dll.hashes`).
   - In-toto build provenance and CycloneDX / SPDX Software Bill of Materials (SBOM) verification.

3. **Critical Functions & Hardware Status Checks:**
   - Physical TPM 2.0 PCR register quote validation (`ts_hw_layer.py` / `tpm_quote.py`).
   - FIPS provider availability verification via dynamic probe (`ts_hw_layer.require_fips_module()`).

### 5.2 Conditional Self-Tests
1. **Pairwise Consistency Tests (PCT):**
   - **ML-KEM-1024:** Keypair encapsulation followed by decapsulation; validates that shared secret match is exact before any session key derivation occurs.
   - **ML-DSA-87:** Keypair signature generation and verification; validates that signature verifies true on original payload and false on 1-byte tampered payload.
2. **Entropy Source & Continuous RNG Policy:**
   - Continuous verification that all session randomness derives strictly from cryptographically secure hardware-backed sources (`os.urandom` / Windows CNG `BCryptGenRandom`).
   - Static AST inspection via `crypto_selftest.check_no_weak_rng()` strictly forbidding import or use of Python's pseudo-random `random` module in the Top Secret session path.

---

## 6. Sensitive Parameter Management & Zeroization

- **Storage:** Private keys are sealed in non-volatile memory bound to TPM 2.0 PCR registers (0, 1, 2, 7).
- **In-Transit RAM Hygiene:** Session keys in Rust are wrapped in `ZeroizeOnDrop` structures. Python mutable bytearrays are zeroed (`0x00`) immediately upon session termination.
- **Zeroization Protocol:** Invocation of `sodium_memzero` or emergency zeroization signal permanently wipes all ephemeral and persistent key material across all address spaces.
