# System Architecture & Authority Boundary: Control Plane vs Data Plane

**Document Reference:** `docs/audit/modules/authority_boundary.md`  
**Standard Compliance:** NIST SP 800-207 (Zero Trust Architecture), DoD Zero Trust Reference Architecture 2.0  
**Authority Boundary Version:** 2027.1  

---

## 1. Executive Authority Model

The Destroyer-ST2027 codebase enforces a strict separation of concerns between the **Signaling / Control Plane (Python)** and the **High-Assurance Data Plane (Rust)**.

```
+-------------------------------------------------------------------------+
|                  CONTROL PLANE / SIGNALING (Python 3.11+)               |
|                                                                         |
|  - CLI Orchestration (destroyer.py, secure_p2p.py)                      |
|  - Mutual Identity & PKI Governance (trust_anchor.py, pq_ca.py)        |
|  - Ephemeral Key Exchange Orchestration (hybrid_kex.py, noise_pq.py)    |
|  - Posture & Hardware Attestation (tpm_quote.py, hw_readiness.py)       |
|  - Tamper-Evident SIEM Ledger (remote_siem_forwarder.py)                |
+-------------------------------------------------------------------------+
                                    |
                     IPC / FFI Authority Boundary
         (Explicit Key Handoff & Memory Zeroization via LockedKey32)
                                    v
+-------------------------------------------------------------------------+
|                  DATA PLANE / HIGH ASSURANCE (Rust 2021)                 |
|                                                                         |
|  - Native Engine: rust_data_plane / destroyer_core (maturin FFI)       |
|  - Wire Framing & Monotonic Anti-Replay Sliding Window                  |
|  - Constant-Time AEAD (AES-256-GCM, ChaCha20-Poly1305)                 |
|  - Double Ratchet & Group Ratchet State (group_ratchet.rs)              |
|  - DOD 5220.22-M Zeroization & VirtualLock / mlock Memory Pools         |
+-------------------------------------------------------------------------+
```

---

## 2. Plane Responsibilities and Authority Matrix

| Functionality | Control Plane (Python) | Data Plane (Rust) | Authoritative Enforcer |
|---|---|---|---|
| **Identity Anchoring & Fingerprint Panning** | Authoritative: Checks pinned fingerprints, PKI custodian certs, and TOFU gates. | Passive consumer: Receives validated peer public keys and derives shared secrets. | Python (`trust_anchor.py`, `hybrid_kex.py`) |
| **KEX Negotiation & Handshake Transcript** | Drives state machine (`noise_pq.py`, `hybrid_kex.py`); computes transcript bindings. | Provides native constant-time KEM/Signature implementations via `oqs.dll`/`liboqs.so`. | Dual: Handshake orchestrated in Python; native crypto primitives executed via FFI. |
| **Session Key Injection & Lifecycle** | Hands off 32-byte session secret (`LockedKey32`) to Rust runtime and zeroizes local copy. | Locks key memory in non-pageable RAM (`VirtualLock`/`mlock`), manages message ratchets, zeroizes on drop. | Rust (`rust_data_plane/src/crypto.rs`) |
| **Wire Packet Framing & AEAD Encryption** | Inactive in production. | Authoritative: Packs, tags, encrypts, and sends/receives raw UDP frames. | Rust (`rust_data_plane/src/packet.rs`) |
| **Replay Protection** | Inactive in production. | Authoritative: Sliding window monotonic sequence validator (`rust_data_plane/src/replay.rs`). | Rust (`rust_data_plane`) |
| **Group Ratchet State & Skipped Keys** | Inactive in production. | Authoritative: Enforces authenticated tag verification before state mutation (`group_ratchet.rs`). | Rust (`rust_data_plane/src/group_ratchet.rs`) |
| **Audit Journaling & Forwarding** | Authoritative: Appends HMAC-SHA256 authenticated event chains to SIEM ledger. | Emits low-latency audit records over IPC pipe. | Python (`remote_siem_forwarder.py`) |

---

## 3. Production Gate & Fail-Closed Enforcement

Under production posture (`SECURE_P2P_PRODUCTION="1"`):
1. **Rust Data-Plane Mandatory:** `P2P_DATA_PLANE=rust` is the default and only permitted operational mode.
2. **Missing Binary Refusal:** If `destroyer_core` (FFI module) or `secure-transmit` (Rust compiled executable) is absent, unbuilt, or fails hash verification against `critical_modules.hashes`, the node **fails closed** immediately and aborts session startup.
3. **Python Fallback Quarantine:** The pure-Python data plane (`network/session_manager.py` fallback streaming) is quarantined and strictly disallowed for sensitive/production traffic. It is restricted exclusively to headless integration unit tests.
4. **Secret Handover Cleanliness:** Once session secrets are passed across the FFI boundary to the Rust data plane, all intermediate Python key variables MUST invoke `.destroy()` or `secure_memory_wiper` to prevent lingering in garbage-collected heaps.

---

## 4. Cross-References

- **Remediation Findings:** `docs/audit/findings/F-01_to_F-04.md`
- **Audit Discrepancies:** `docs/audit/discrepancies.md` (Section 4)
- **Rust Architecture Plan:** `RUST_MIGRATION_PLAN.md`

