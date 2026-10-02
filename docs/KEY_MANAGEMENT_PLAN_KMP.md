# Cryptographic Key Management Plan (KMP)

## 1. Governance & Standards Authority
- **Document ID:** `KMP-P2P-2028-CNSA2-V1`
- **Applicable Standards:**
  - NIST SP 800-57 Part 1 Rev 5: *Recommendation for Key Management*
  - NIST SP 800-57 Part 2 Rev 1: *Best Practices for Key Management Organization*
  - NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0 Strict)
  - FIPS 140-3 Cryptographic Module Security Requirements
- **System Impact Level:** FIPS 199 High-High-High

---

## 2. Cryptographic Algorithm Mandates

Per NSA CNSA 2.0 requirements for National Security Systems (NSS) operating past the January 2027 gate, the 2027 Top-Secret transmission path (`secure_transmit_2027.py`, `cnsa_purity.py`) strictly enforces the following suite:

| Cryptographic Function | 2027 Top-Secret Mandatory Algorithm | Specification Standard | Legacy Research Profile (Quarantined) |
| :--- | :--- | :--- | :--- |
| **Post-Quantum KEM** | **ML-KEM-1024** | NIST FIPS 203 | Classic-McEliece-8192128f (quarantined from 2027 TS wire) |
| **Classical Hedge KEX**| **SecP384r1 (P-384 ECDH)** | NIST SP 800-56A Rev 3 | X25519 (quarantined from 2027 TS wire) |
| **Hybrid Combiner** | **SecP384r1MLKEM1024** | RFC 10024 Level 5 Profile | Dual-hybrid KEM combiner |
| **Digital Signatures** | **ML-DSA-87** | NIST FIPS 204 | Falcon-1024 / SLH-DSA-256f (quarantined from 2027 TS wire) |
| **Symmetric Bulk AEAD**| **AES-256-GCM** | FIPS 197 / NIST SP 800-38D | ChaCha20-Poly1305 (legacy data plane only) |
| **Key Derivation (KDF)**| **HKDF-SHA384** | RFC 5869 / SP 800-56C Rev 2 | HKDF-SHA3-512 |
| **Cryptographic Hash** | **SHA-384** | FIPS 180-4 | SHA3-512 / SHAKE-256 |
| **Audit Chaining** | **HMAC-SHA384** | FIPS 198-1 | HMAC-SHA512 |

> **CNSA 2.0 Purity Rule (`cnsa_purity.py`):** Any attempt to negotiate Falcon-1024, Classic-McEliece, X25519, or ChaCha20-Poly1305 in the 2027 Top-Secret session path raises `CNSAPurityViolation` and immediately aborts the handshake fail-closed.

---

## 3. Key Inventory & Cryptoperiod Lifecycle

### 3.1 Root Identity Signature Keys
- **Algorithm**: ML-DSA-87 (pk=2592B, sk=4896B)
- **Cryptoperiod**: 365 Days (1 Year)
- **Storage**: Hardware TPM 2.0 non-volatile storage or PKCS#11 hardware security module.
- **Revocation**: Triggered by Cryptographic Officer through ML-DSA-87 signed CRL and distributed to peer mesh.

### 3.2 Medium-Term Signed Prekeys
- **Algorithm**: Hybrid ML-KEM-1024 + Classic-McEliece-8192128f
- **Cryptoperiod**: 30 Days
- **Storage**: AES-256-GCM encrypted vault sealed to TPM 2.0 PCR registers (0, 1, 2, 7).
- **Rollover**: Automatically re-generated every 30 days and signed by the node's Root Identity Key.

### 3.3 Ephemeral Session KEM Keys
- **Algorithm**: ML-KEM-1024 (FIPS 203)
- **Cryptoperiod**: Maximum 1 Hour or 50,000 transmitted datagrams.
- **Storage**: Volatile RAM only. Memory buffers protected by anti-debugging hooks and zeroized immediately upon ratchet initialization.

### 3.4 Double Ratchet Message Keys
- **Algorithm**: 256-bit symmetric keys for AES-256-GCM AEAD (and legacy research prototype ChaCha20-Poly1305).
- **Cryptoperiod**: Exactly 1 message frame.
- **Forward Secrecy**: Once a frame is encrypted or decrypted, the message key is permanently purged from memory via native Rust `ZeroizeOnDrop`.

---

## 4. Hardware Root-of-Trust & Key Protection

1. **TPM 2.0 PCR Binding**:
   - Private keys are sealed against Platform Configuration Registers (PCRs 0, 1, 2, 7). Any boot configuration modification, unauthorized firmware load, or kernel tampering prevents unsealing.
2. **Memory Hygiene & Zeroization**:
   - Zeroization is implemented in accordance with FIPS 140-3 Section 7.9.
   - Rust data plane uses `zeroize::ZeroizeOnDrop` to guarantee immediate scrubbing of stack and heap buffers upon deallocation.
   - Python wrappers scrub mutable bytearrays with zeroes (`0x00`) before garbage collection.

---

## 5. Post-Compromise Recovery Protocol
In the event that an ephemeral ratchet key is intercepted:
- The system guarantees **Post-Compromise Security (PCS)**.
- In the next Diffie-Hellman ratchet exchange with fresh post-quantum KEM encapsulation, full cryptographic secrecy is restored automatically without administrative intervention.
