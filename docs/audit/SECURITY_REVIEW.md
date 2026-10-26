# System Security Review & Cryptographic Architecture Assessment

**Audit Run ID:** `RUN-20261025-01`
**Date:** 2026-10-25
**Protocol:** Production Engineering and Forensic Verification v4.0
**Project:** Destroyer-ST2027
**Scope:** Active production codebase, cryptographic data plane, key exchange, and platform defense gates

---

## 1. Threat Model & Security Boundaries

The system is evaluated against an advanced adversary model operating under hostile network and host assumptions:
1. **Dolev-Yao Network Adversary:** Controls all network communications; can intercept, inject, modify, replay, drop, and reorder packets.
2. **Post-Quantum Cryptanalytic Adversary:** Has access to cryptanalytically relevant quantum computers (CRQC) capable of breaking discrete logarithm and integer factorization problems (RSA, ECC, Diffie-Hellman).
3. **Local Hostile Endpoint / Co-Located Observer:** Capable of observing remote network timing, packet sizes, and traffic patterns, but bounded by host operating system process isolation.
4. **Physical Capture / Compromise Adversary:** Capable of obtaining physical access to host memory or storage after a mission window, necessitating post-compromise security (PCS) healing and tamper-triggered zeroization.

### Boundaries and Non-Claims:
- Software cannot achieve physical immunity to hardware-level side-channel attacks (power analysis, acoustic, or electromagnetic emanations) without dedicated hardware tamper boundaries (FIPS 140-3 Level 3/4 enclosures).
- Algorithm implementation conformance is distinct from statutory laboratory certification (NIST CMVP FIPS 140-3 validation or NIAP Common Criteria evaluation).

---

## 2. Cryptographic Constructions & Parameter Selection

### 2.1 Post-Quantum Key Encapsulation (KEM)
- **Primary Standard:** ML-KEM-1024 (FIPS 203, Category 5 security). Public key: 1,568 bytes; Ciphertext: 1,568 bytes; Shared secret: 32 bytes.
- **Hybrid Wire Exchange:** ML-KEM-1024 paired with Classic McEliece-8192128f or classical ephemeral Diffie-Hellman (X25519 / P-384).
- **Domain Separation:** KDF uses HKDF-SHA384 or HKDF-SHA512 with explicit domain-separated info labels (`ST2027-WIRE-KEY-V1`, `ST2027-PCS-RATCHET`).
- **Agility Safeguards:** Upstream-vulnerable HQC-256 (CVE-2024-54137, CVE-2025-52473) is quarantined and refused by default.

### 2.2 Digital Signatures & Authentication
- **Primary Standard:** ML-DSA-87 (FIPS 204, Category 5 security). Public key: 2,592 bytes; Private key: 4,896 bytes; Signature: 4,627 bytes.
- **Stateless Hash-Based Backup:** SLH-DSA-PURE-SHAKE-256f (FIPS 205).
- **Mandatory Verify-After-Sign (VAS):** In `liboqs_wrapper.py:573-577`, signing routines verify the newly produced signature against the public key prior to returning the buffer to caller, preventing fault-injection key extraction.

### 2.3 Symmetric Wire Encryption & Framing
- **Wire AEAD:** AES-256-GCM. 256-bit key, 96-bit nonce, 128-bit authentication tag.
- **Nonce Derivation:** 64-bit strictly monotonic packet sequence number XOR'd with a 96-bit directional salt. Nonce reuse triggers immediate fail-closed pipeline latching.
- **Header Whitening:** Sequence numbers and frame types are whitened on the wire using a derived PRF stream to defeat passive traffic classification.

---

## 3. Ratchet & Post-Compromise Security (PCS)

- **Double Ratchet Pipeline:** Implements continuous symmetric ratchet advancing per packet, combined with Continuous Epoch Ratchet (CER).
- **PCS Healing Cadence:** Every 128 frames (or upon receiving an out-of-order epoch rekey frame), a fresh ephemeral ML-KEM-1024 key encapsulation is injected into the root key.
- **Formal Verification:** Verified under ProVerif 2.05 in `docs/formal/st2027_pcs.pv` and `handshake_model.pv`. ProVerif formally proves injectivity of events (`inj-event`) and session key secrecy (`query attacker(secret_key) ==> false`).

---

## 4. Replay Protection & Monotonic State

- **RFC 6479 Sliding Window:** Implemented in `rust_data_plane/src/replay.rs` and Python fallback. A 1024-packet bitmap tracks accepted sequence numbers without packet loss under network jitter.
- **Hardware NV Anti-Rollback:** TPM 2.0 NV index counter tracking (`tpm_nv.rs`) anchors monotonic send sequences into hardware non-volatile storage, preventing VM checkpoint or disk-snapshot rollback attacks.

---

## 5. Platform Hardening & Memory Sanitation

- **Exploit Mitigations:** Windows process mitigation policies enforce Data Execution Prevention (DEP), Arbitrary Code Guard (ACG), Control Flow Guard (CFG), and High-Entropy ASLR.
- **Memory Pinning:** Sensitive key buffers are pinned in physical RAM using `VirtualLock` (`memlock.py`, `memlock.rs`) to prevent swapping to disk pagefiles.
- **Purge & Zeroization:** Multi-pass overwriting complying with NIST SP 800-88 and DoD 5220.22-M sanitization patterns, followed by compiler barrier memory sanitization (`zeroize` crate in Rust, `ctypes.memset` in Python).

