# Module: `trust_anchor.py` — Trust Anchor & Post-Quantum PKI

[Back to Documentation Index](../README.md) | [System Architecture](../ARCHITECTURE.md)

This module implements **Pillar 5: Trust Infrastructure & Post-Quantum PKI** for the 2027 Top-Secret transmission pipeline. It provides an offline 3-of-5 threshold ML-DSA-87 hardware-rooted Certificate Authority (RFC 9881), eliminates Trust-On-First-Use (TOFU) vulnerabilities, enforces threshold revocation in uniform cells, and maintains a zero-plaintext-disk amnesia profile.

---

## 1. Core Source Files & Responsibilities

| Source File | Lines | Primary Security Responsibilities |
|---|---|---|
| [`trust_anchor.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/trust_anchor.py) | ~530 | 3-of-5 threshold ML-DSA-87 Root CA, strict certificate issuance/validation, threshold CRL revocation, and amnesia storage. |

---

## 2. Key Subsystems & Implementations

### 2.1. Offline 3-of-5 Threshold ML-DSA-87 Hardware Root CA
- **Standards Alignment:** RFC 9881 (*Post-Quantum PKI Profiles*) & NIST FIPS 204.
- **Custodian Quorum Architecture:**
  - The Root CA consists of 5 designated Crypto Officers (`CUSTODIAN-01` through `CUSTODIAN-05`).
  - Each custodian generates and protects an independent ML-DSA-87 keypair inside an evaluated physical HSM or TPM 2.0 (`generate_identity_hsm`).
  - Private signing keys are non-exportable and never exist together on a single host.
- **Threshold Signing Quorum:**
  - Validating or issuing an identity certificate requires a minimum threshold quorum of **3 out of 5** valid cryptographic signatures:
    $$\text{Valid}(\text{Cert}) \iff \sum_{i=1}^{5} \text{Verify}_{\text{ML-DSA-87}}(pk_i, \text{CertTBS}, \sigma_i) \ge 3$$
  - Eliminates single-officer compromise and rogue issuance risks.

### 2.2. Short-Lived Ephemeral Validity (48-Hour Cap)
- **Security Requirement:** To limit exposure windows for compromised endpoints, certificates enforce an absolute maximum validity window of **48 hours** (`_MAX_CERT_LIFETIME = 172800`).
- **Clock Skew Enforcement:** Reject certificates whose `not_before` or `not_after` drift exceeds 5.0 seconds from synchronized secure hardware time (`_MAX_SKEW_FUTURE`).
- **Fail-Closed Rejection:** Expired certificates are rejected immediately without administrative override.

### 2.3. Strict Mode Elimination of TOFU (Trust-On-First-Use)
- **Vulnerability Eliminated:** Classical P2P systems rely on Trust-On-First-Use (TOFU) or safety number verification, exposing the link to initial-contact active MITM interception.
- **Strict Mode Enforcement (`strict_mode=True`):**
  - All peer identity public keys MUST be signed by the 3-of-5 threshold root.
  - First-contact peers lacking a valid threshold certificate are rejected with `UntrustedPeerError`.
  - Self-signed certificates and unauthenticated public keys are dropped fail-closed.

### 2.4. Threshold CRL Revocation in Uniform Cells
- **Revocation Authority:** Replicating certificate issuance, revocation of any compromised serial requires 3 of 5 custodian signatures.
- **Monotonic Anti-Replay Sequencing:** Each revocation broadcast includes a strictly increasing sequence counter per certificate serial. Stale or replayed revocation broadcasts are ignored.
- **Uniform Cell Transport:** Revocation payloads are packaged into standard 1232-byte shaped cells, preventing eavesdroppers from identifying revocation events via traffic volume changes.
- **Persistence:** Revocations persist permanently in memory and are replicated across all nodes.

### 2.5. Zero-Plaintext-Disk Amnesia Profile
- **Storage Policy:** Private keys and decrypted identity vaults reside solely in volatile memory pages locked via `VirtualLock` / `mlock`.
- **Prohibition:** The runtime strictly forbids persisting unencrypted keys, intermediate certificates, or session records to physical hard drives or non-volatile flash storage.
- **Session Teardown:** Upon station power-down or node termination, all credentials in volatile memory are immediately wiped via volatile compiler fences (`ts_rt.dll`).

---

## 3. Test Coverage

- **Suite:** `test_trust_anchor.py`]
- **Pass Rate:** **19 of 19 tests passing (100%)**
- **Tested Behaviors:** 3-of-5 threshold signature quorum validation, rejection of insufficient signatures (1-of-5, 2-of-5), 48h expiration rejection, clock skew enforcement, strict mode unauthenticated peer rejection, threshold CRL revocation broadcasting, replay prevention, and amnesia memory handling.
