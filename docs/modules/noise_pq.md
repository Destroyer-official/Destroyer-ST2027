# Module: `noise_pq.py`, `cnsa_purity.py`, & `crypto_selftest.py` — Protocol & Post-Quantum Cryptography

[Back to Documentation Index](../README.md) | [System Architecture](../ARCHITECTURE.md)

This module implements **Pillar 3: Cryptography & Protocol Architecture** for the 2027 Top-Secret transmission pipeline. It provides post-quantum hybrid key exchange (`Noise_XXhfs`), strict NSA CNSA Suite 2.0 algorithmic purity, power-up known answer test (KAT) self-tests, and machine-checked formal verification in ProVerif 2.05.

---

## 1. Core Source Files & Responsibilities

| Source File | Lines | Primary Security Responsibilities |
|---|---|---|
| [`noise_pq.py`](noise_pq.py) | ~450 | `Noise_XXhfs` hybrid handshake using `SecP384r1MLKEM1024` and `ML-DSA-87` mutual authentication. |
| [`cnsa_purity.py`](cnsa_purity.py) | ~260 | CNSA 2.0 policy enforcer; validates token purity and quarantines non-CNSA algorithms. |
| [`crypto_selftest.py`](crypto_selftest.py) | ~320 | FIPS 140-3 synchronous power-up KATs, conditional PCTs, and AST entropy enforcement. |
| [`docs/formal/st2027_handshake.pv`](docs/formal/st2027_handshake.pv) | ~140 | Formal ProVerif 2.05 model for payload secrecy and injective mutual authentication. |
| [`docs/formal/st2027_pcs.pv`](docs/formal/st2027_pcs.pv) | ~150 | Formal ProVerif 2.05 model for post-compromise security (PCS) healing. |

---

## 2. Key Subsystems & Implementations

### 2.1. Hybrid Handshake: `Noise_XXhfs` (`noise_pq.py`)
- **Protocol Pattern:** Noise Protocol Framework `XXhfs` pattern (mutual authentication, both parties transmit ephemeral and static keys, hybrid forward secrecy).
- **Key Encapsulation:** Dual hybrid combining `SecP384r1` (classical NIST P-384 ECDH) with `ML-KEM-1024` (NIST FIPS 203) conforming to RFC 10024 Level 5 Profile:
  $$SS = \text{HKDF-SHA384}(SS_{\text{classical}} \mathbin{\Vert} SS_{\text{ML-KEM-1024}} \mathbin{\Vert} pk_{\text{classical}} \mathbin{\Vert} ct_{\text{ML-KEM-1024}})$$
- **Transcript Binding:** Handshake hash $h$ binds every exchanged public key, ciphertext, and identity certificate.
- **Identity Authentication:** Static public keys are signed and verified using `ML-DSA-87` (NIST FIPS 204).

### 2.2. NSA CNSA Suite 2.0 Purity Engine (`cnsa_purity.py`)
To prevent cryptographic downgrade attacks, the purity engine intercepts all proposed cipher suites and token requests:
- **Permitted Cryptographic Primitives:**
  - KEM: `ML-KEM-1024` (FIPS 203)
  - Signature: `ML-DSA-87` (FIPS 204)
  - Symmetric Cipher: `AES-256-GCM` (FIPS 197 / NIST SP 800-38D)
  - Hash & KDF: `SHA-384` (FIPS 180-4) / `HKDF-SHA384` (RFC 5869)
- **Quarantined Algorithms:** Falcon-1024, Classic-McEliece, X25519, and ChaCha20-Poly1305 are strictly forbidden on the 2027 Top-Secret transmission path. Any attempt to negotiate them immediately raises `CNSAPurityViolation` and aborts.

### 2.3. Power-Up & Conditional Self-Tests (`crypto_selftest.py`)
Conforming to FIPS 140-3 Section 10 and ISO/IEC 19790:
- **Synchronous Power-Up KATs:**
  - Cross-engine AES-256-GCM encryption, decryption, tag verification, and single-bit tamper rejection comparing OpenSSL (`cryptography`) against `pycryptodome`.
  - HKDF-SHA384 test vector verification.
  - RFC 7748 X25519 Section 5.2/6.1 reference vector tests.
  - P-384 ECDH cross-engine shared-secret equality.
  - SHA-384 and HMAC-SHA384 verification.
- **Conditional Pairwise Consistency Tests (PCT):**
  - ML-KEM-1024: Encapsulate followed by decapsulate equality before session key use.
  - ML-DSA-87: Sign followed by verify; tamper rejection verification.
- **Entropy Policy Verification:**
  - Enforces that session randomness originates from `os.urandom` (Windows CNG `BCryptGenRandom`).
  - Statically inspects the session code via `ast` to ensure the Python `random` pseudo-random module is never imported or used.

### 2.4. Machine-Checked Formal Verification (ProVerif 2.05)
Formal models in `docs/formal/` are executed directly by ProVerif under the Dolev-Yao unbounded attacker model:
1. **Secrecy:**
   ```proverif
   query attacker(secret_payload_A).
   (* RESULT not attacker(secret_payload_A[]) is true. *)
   ```
2. **Mutual Authentication:**
   ```proverif
   query sess: bitstring, kA: pkey, kB: pkey;
     inj-event(endB(kA, kB, sess)) ==> inj-event(beginA(kA, kB, sess)).
   (* RESULT inj-event(endB(...)) ==> inj-event(beginA(...)) is true. *)
   ```
3. **Post-Compromise Security (PCS):**
   ```proverif
   query attacker(post_ratchet_secret).
   (* RESULT not attacker(post_ratchet_secret[]) is true. *)
   ```

---

## 3. Test Coverage

- **Suites:**
  - `test_noise_pq_purity.py`] (4 tests)
  - `test_proverif_st2027.py`] (2 tests)
  - `test_secure_transmit_2027.py`] (24 tests)
- **Pass Rate:** **30 of 30 tests passing (100%)**
- **Tested Behaviors:** Handshake key exchange, CNSA 2.0 token purity enforcement, KAT execution and failure tripping, ProVerif Dolev-Yao model execution, and full transmission lifecycle.
