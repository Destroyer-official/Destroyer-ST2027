# Destroyer-ST2027 Protocol Specification: High-Assurance Post-Quantum Communications Architecture

**Version:** 2027.1-SPEC  
**Classification:** Open Architecture / High-Assurance Engineering Baseline  
**Date:** October 2026  
**Target Compliance:** NSA CNSA Suite 2.0, NIST FIPS 203/204/197, NIST SP 800-56C, RFC 6479, RFC 9420  

---

## 1. Executive Protocol Scope & Threat Model

Destroyer-ST2027 is a dual-profile, post-quantum communication system engineered for hostile network environments under active surveillance by nation-state adversaries equipped with both classical supercomputers and Cryptanalytically Relevant Quantum Computers (CRQC).

The system explicitly rejects "security through algorithmic sprawl." Instead of attempting to support dozens of unverified experimental primitives, ST2027 enforces a strictly bounded, mathematically specified cryptographic core implemented in memory-safe Rust with physical hardware root of trust.

### 1.1 Threat Model
The protocol assumes an adversary $\mathcal{A}$ with complete control over the network fabric (Dolev-Yao model):
1. **Global Passive Wiretapping (Harvest Now, Decrypt Later):** $\mathcal{A}$ records all ciphertext, metadata, packet sizes, and inter-arrival timings indefinitely.
2. **Active Network Manipulation:** $\mathcal{A}$ injects, reorders, duplicates, delays, drops, or alters frames at wire speed.
3. **Transient Host Compromise:** $\mathcal{A}$ may compromise endpoint ephemeral state at epoch $E$. The protocol must guarantee **Post-Compromise Security (PCS)** at epoch $E+1$ and **Forward Secrecy (FS)** for all epochs prior to $E$.
4. **Side-Channel & Cold-Boot Analysis:** $\mathcal{A}$ has physical access to dump system RAM or analyze memory bus timings. Secret keys must be hardware-locked (`VirtualLock`/`mlock`) and deterministically zeroized.

---

## 2. Dual Protocol Profiles: Tactical vs. Deniable

To resolve the fundamental contradiction between **military command provenance** (non-repudiation) and **human private messaging** (cryptographic deniability), ST2027 formalizes two separate, non-interfering operational profiles:

```
                                  ┌───────────────────────────────┐
                                  │      DESTROYER-ST2027         │
                                  └──────────────┬────────────────┘
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼                                                 ▼
        ┌───────────────────────────────┐                 ┌───────────────────────────────┐
        │          ST2027-TAC           │                 │         ST2027-HUMAN          │
        │   (Tactical Defense & C2)     │                 │   (Deniable E2EE Messaging)   │
        ├───────────────────────────────┤                 ├───────────────────────────────┤
        │ • Non-Repudiation (ML-DSA-87) │                 │ • Symmetric MAC (Deniability) │
        │ • Monotonic Ratchet (MAX_SKIP=0)│               │ • Triple Ratchet (SPQR-style) │
        │ • Hardware Custody (TPM 2.0)  │                 │ • Ephemeral PQXDH Handshake   │
        │ • Fixed 1420B Constant Traffic│                 │ • Store-and-Forward Tolerant  │
        │ • Sensor/Drone/Telemetry Link │                 │ • Peer-to-Peer Human Chat     │
        └───────────────────────────────┘                 └───────────────────────────────┘
```

### 2.1 Profile Summary Table

| Security Property | `ST2027-TAC` (Tactical / C2) | `ST2027-HUMAN` (Deniable Messaging) |
| :--- | :--- | :--- |
| **Operational Target** | Unmanned systems, telemetry, command & control | Confidential peer-to-peer human dialogue |
| **Authentication Primitive** | `ML-DSA-87` (FIPS 204) Digital Signatures | `Poly1305` / `AES-GMAC` Dual-Keyed MAC |
| **Legal/Evidentiary Property** | Non-repudiation (Signed audit trail) | Plausible cryptographic deniability |
| **Ratchet In-Order Policy** | Strict monotonic counter (`MAX_SKIP=0`) | Decoupled skipped-key cache (Out-of-order OK) |
| **Packet Loss Handling** | Immediate session sever & alarm trigger | Automatic resync via ratchet advancement |
| **Hardware Custody** | Mandated TPM 2.0 PCR attestation / HSM | Optional hardware token / Software fallback |
| **Wire Traffic Analysis** | Constant-rate UDP/IPv6 fixed cells (1420B) | Padded burst-mode frames |

---

## 3. Cryptographic Primitives (CNSA Suite 2.0 Frozen Baseline)

ST2027 deprecates all non-FIPS post-quantum candidates. The operational baseline is locked to NSA CNSA Suite 2.0 standards:

1. **Key Encapsulation Mechanism (KEM):**
   - **Primary:** `ML-KEM-1024` (NIST FIPS 203, Parameter Set Category 5).
   - **Hybrid Classical Hedge:** `SecP384r1` (FIPS 186-5 ECDH) combined via dual-PRF HKDF.
   - Public Key Size: 1,568 bytes. Ciphertext Size: 1,568 bytes. Shared Secret: 32 bytes.
2. **Digital Signatures:**
   - **Primary:** `ML-DSA-87` (NIST FIPS 204, Parameter Set Category 5).
   - Public Key Size: 2,592 bytes. Signature Size: 4,627 bytes.
   - Separated Signature Domains: `ST2027-TAC-INIT-V1` (initiator) and `ST2027-TAC-RESP-V1` (responder).
3. **Payload AEAD:**
   - `AES-256-GCM` (NIST SP 800-38D) with 128-bit authentication tag.
   - Nonce construction: 64-bit monotonic sequence counter $\parallel$ 8-bit direction identifier $\parallel$ 24-bit zero padding.
4. **Key Derivation Function (KDF):**
   - `HKDF-SHA384` (RFC 5869 / NIST SP 800-56C Rev 2).
   - All secret derivation strictly adheres to Extract-then-Expand paradigm with explicit domain info tags.

---

## 4. Handshake Specification: `Noise_XXhfs` Post-Quantum Profile

The authenticated handshake follows the Noise Protocol Framework extended with Hybrid Forward Secrecy (`XXhfs`):

$$\text{Profile: } \texttt{Noise\_XXhfs\_P384\_MLKEM1024\_MLDSA87\_AES256GCM\_SHA384}$$

### 4.1 Message Exchange Sequence

```
Initiator (Alice)                                    Responder (Bob)
   │                                                       │
   │ ─── M1: e_pub (97B) || ml_ek (1568B) ───────────────> │
   │                                                       │
   │ <── M2: e_pub (97B) || ml_ct (1568B) ||               │
   │         enc(sig_r_pk (2592B)) || enc(sig_r (4627B)) ──│
   │                                                       │
   │ ─── M3: enc(sig_i_pk (2592B)) || enc(sig_i (4627B)) ─> │
   │                                                       │
   ▼                                                       ▼
[Transport Key Derive: k_ir, k_ri]           [Transport Key Derive: k_ir, k_ri]
```

### 4.2 Handshake Step Verification Rules
1. **M1 Generation (Initiator):**
   - Generate ephemeral P-384 pair $(d_e, Q_e)$ and ML-KEM-1024 pair $(sk_{kem}, ek_{kem})$.
   - Transmit in clear: $M_1 = Q_e \parallel ek_{kem}$ (Total: 1,665 bytes).
   - Handshake hash: $h_1 = \text{SHA-384}(\text{PROTOCOL\_NAME} \parallel M_1)$.
2. **M2 Generation (Responder):**
   - Generate ephemeral P-384 pair $(d_{er}, Q_{er})$ and encapsulate $ct_{kem}, ss_{kem} = \text{ML-KEM-Encaps}(ek_{kem})$.
   - Derive classical DH shared secret: $ss_{dh} = \text{ECDH}(d_{er}, Q_e)$.
   - Chained KDF: MixKey with $ss_{dh} \parallel ss_{kem}$.
   - Generate ML-DSA-87 signature over handshake hash $h_2$ with domain separator `ST2027-SIG-RESP`.
   - Encrypt responder identity and signature under current chaining key using AES-256-GCM.
3. **M3 Generation (Initiator):**
   - Decapsulate $ss_{kem}$, compute $ss_{dh}$, and mirror KDF chaining.
   - Decrypt and verify responder's ML-DSA-87 signature fail-closed.
   - Generate ML-DSA-87 signature over handshake hash $h_3$ with domain separator `ST2027-SIG-INIT`.
   - Encrypt initiator identity and signature under updated chaining key.
4. **Split Phase:**
   - Both sides compute transport keys:
     $$(k_{ir}, k_{ri}) = \text{HKDF-Expand}(ck, \text{"ST2027-TRANSPORT-KEYS"}, 64)$$
   - Direction separation: Initiator seals with $k_{ir}$ and opens with $k_{ri}$; Responder seals with $k_{ri}$ and opens with $k_{ir}$. Nonce reuse between directions is physically impossible.

---

## 5. Pure Rust Data Plane & Memory Protection Architecture

All security-critical data-plane operations are implemented in Rust (`rust_data_plane/src/`):

```
       USER INTERFACE / CLI / PLUMBING
            ┌─────────────────────┐
            │    Python 3.11+     │ (Control Plane: non-sensitive UI/CLI)
            └──────────┬──────────┘
                       │ PyO3 / C-FFI (No raw secrets cross)
            ┌──────────▼──────────┐
            │   destroyer_core    │ (Data Plane: Pure Rust)
            │  ┌───────────────┐  │
            │  │  memlock.rs   ├──┼──► OS Page Locking (VirtualLock / mlock)
            │  │ nostd_microcore  │──┼──► Stack-allocated, Zero-heap framing
            │  │   aead.rs     ├──┼──► AES-256-GCM hardware acceleration
            │  │   replay.rs   ├──┼──► RFC 6479 64-bit Anti-Replay Window
            │  │   pacing.rs   ├──┼──► Fixed-rate Chaff & Cell Pacing
            │  └───────────────┘  │
            └─────────────────────┘
```

### 5.1 Memory Protection Invariants
1. **Zero Heap Allocation in Fast Path (`nostd_microcore.rs`):** Data frames are processed entirely in bounded stack buffers (`StackFrameBuffer<1232>`) with constant-time parsing.
2. **Physical Page Locking (`memlock.rs`):** Session keys are encapsulated in `LockedKey32`. Memory pages are locked in physical RAM using `VirtualLock` (Windows) or `mlock` (Linux) to prevent memory paging to swap or hibernation files.
3. **Multi-Pass Volatile Zeroization:** All buffers implementing `Drop` write `0x00` via volatile memory pointers, preventing compiler optimization dead-code elimination.

---

## 6. Traffic Concealment: Fixed-Cell Quantization & Pacing

To resist traffic analysis by global passive adversaries:
1. **Fixed MTU Cell Quantization:** Every wire frame is padded to exactly 1,420 bytes (`frame.rs` / `pacing.rs`). An observer cannot distinguish a 1-byte command from a 1,000-byte file chunk.
2. **Cover Traffic (Chaff Ingestion):** When no user payload is pending, `pacing.rs` injects cryptographically indistinguishable chaff cells (`FTYPE_CHAFF`) at configured time intervals.
3. **Entropy Uniformity:** Chaff cells are sealed with AES-256-GCM under the current frame key. Ciphertext entropy matches pure random noise ($> 7.999$ bits per byte Shannon entropy), defeating statistical deep packet inspection (DPI).

---

## 7. Compliance and Verification Traceability

| Requirement | Implementation Artifact | Formal Verification / Test Evidence |
| :--- | :--- | :--- |
| **FIPS 203 (ML-KEM-1024)** | `pqc_algorithms.py`, `rust_data_plane/src/kem.rs` | Gate 3.1 KATs, `tests/test_pqxdh_combiner_v2_kat.py` |
| **FIPS 204 (ML-DSA-87)** | `pqc_algorithms.py`, `liboqs_wrapper.py` | Gate 3.1 KATs, `tests/test_crypto_root_fixes.py` |
| **FIPS 197 (AES-256-GCM)** | `rust_data_plane/src/aead.rs` | Gate 1.1 Kani harness, NIST KAT empty vector |
| **Memory Sanitization** | `rust_data_plane/src/memlock.rs`, `nostd_microcore.rs` | Gate 1.1 / Gate 2.1 zeroize-on-drop verified |
| **Anti-Replay Resistance** | `rust_data_plane/src/replay.rs` | Gate 5.1 RFC 6479 decoupled window tests |
| **Symbolic Proofs** | `docs/formal/proverif_handshake.pv` | Gate 4.1 ProVerif 2.05 secrecy & inj-event TRUE |
