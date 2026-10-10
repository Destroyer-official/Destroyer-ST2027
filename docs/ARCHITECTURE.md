# System Architecture — Sovereign Post-Quantum Direct P2P Messaging

## 1. Thesis

Confidential government/military messaging over the public internet without
intermediate servers, secure against (a) present network adversaries
(ISP/backbone intercept, port harvesters, traffic analysis) and (b) future
cryptanalytic quantum computers (harvest-now-decrypt-later). Design rule:
**asymmetric cryptography must be post-quantum; symmetric cryptography at
256 bits already is** (Grover gives only a square-root speedup:
AES-256 → 2¹²⁸ operations, physically infeasible).

## 2. Threat model

| Adversary | Capability | Countered by |
|---|---|---|
| Backbone/ISP passive | capture all packets, store for decades | PQ handshake (no Shor-able exchange), AES-256 DEM, forward secrecy |
| Backbone/ISP active | inject/modify/replay packets, strip layers | Signatures pre-decaps, AEAD tags, 64-bit replay window, no-plaintext negotiation |
| Botnet/scanner | port sweeps, banner grabs, handshake probing | Silent-drop, no beacon strings, peer-prefix firewall |
| Endpoint seizure | disk/RAM forensics | Ephemeral+in-memory defaults, sealed storage (scrypt), DoD wipe, memory locking |
| CRQC (future) | Shor breaks RSA/ECDH, Grover halves symmetric | ML-KEM-1024/McEliece KEMs, ML-DSA-87/SLH-DSA signatures, AES-256-GCM DEM (CNSA 2.0; ChaCha20 quarantined to legacy prototype) |
| Insider/operator error | weak config, skipped verification | Fail-closed policy engines, secure defaults, TOFU pin continuity |

Out of scope for code alone (operational tracks): HSM attestation, WORM/SIEM
audit, Sigstore releases, ATO package, Tor/private-APN carriage. "Impossible
to hack" is unachievable; the target is maximum attacker cost with detection
and recovery.

## 3. Protocol Stacks

### A. 2027 Sovereign Top-Secret Pipeline (`secure_transmit_2027.py`)
This is the formal, fail-closed production target conforming to CNSA Suite 2.0 and RFC 10024 Level 5:

```
[0] Anonymity Overlay (Tor v3 SOCKS5 / Sovereign APN / WireGuard) ... transport_anonymity.py
[1] Constant-Rate Traffic Shaping (50ms tick, 1232B uniform cells) ... transport_anonymity.py
[2] Stream Whitening (AES-256-CTR cryptographic uniform noise) ...... transport_anonymity.py
[3] Outer TLS 1.3 Transport (TLS_AES_256_GCM_SHA384 only) ........... secure_transmit_2027.py
[4] Inner Hybrid Handshake (Noise_XXhfs / SecP384r1MLKEM1024) ....... noise_pq.py / secure_transmit_2027.py
[5] Transcript & Identity Authentication (ML-DSA-87 FIPS 204) ....... noise_pq.py / cnsa_purity.py
[6] Two-Person Integrity Gate (DoD S-5210.41M 2.0s DPO) ............. spo_dpo.py
[7] Trust Anchor (Offline 3-of-5 Threshold ML-DSA-87 Hardware CA) ... trust_anchor.py
[8] Native Memory Defense (OS-locked pages, volatile zeroize) ....... ts_rt/src/lib.rs (Rust cdylib)
[9] Hardware & Platform Gating (FIPS 140-3, TEMPEST, seL4/VBS) ...... ts_hw_layer.py + ts_runtime.py
```

### B. Legacy P2P Research Prototype (`secure_p2.py` / `secure_p2p.py`)
Maintained for multi-party chat research and experimental comparison (contains non-CNSA Falcon/McEliece algorithms):
```
[0] IPv6 direct transport (TCP/UDP) ................................. p2p_core.py
[1] Mutual TLS 1.3 (TLS_AES_256_GCM_SHA384) ........................ tls_channel_manager.py
[2] Hybrid X3DH+PQ Handshake (X25519 + ML-KEM-1024 + Falcon) ........ hybrid_kex.py
[3] Double Ratchet (HKDF-SHA512, AES-256-GCM) ....................... double_ratchet.py
[4] Legacy Python Envelope (ChaCha20-Poly1305 / AES-GCM) ............ archive/legacy_prototype/
```

### C. Zero-Gap Multi-Layer Defense Pipeline (`unified_secure_pipeline.py`)
Binds independent cryptographic barriers into an atomic, fail-closed multi-layer pipeline:
```
[Layer 1 - Inner] Post-Quantum Double Ratchet (ML-KEM-1024 + McEliece KEM braid; ML-DSA-87 + SLH-DSA dual signatures) ... double_ratchet.py
[Layer 2 - Outer] Bare-Metal Rust AEAD Envelope (destroyer_core: AES-256-GCM + tag PRF whitening + decoupled replay) ... rust_data_plane/src/lib.rs
[Layer 3 - Meta]  Fixed Quanta Padding (256/512/1232B) & Hardware Memory Locking (VirtualLock/mlock + ZeroizeOnDrop) ... unified_secure_pipeline.py
```


## 4. KEM-DEM Data Flow (2027 Top-Secret Path)

```
Payload → DPO 2-Person Approval → Fragment into 1205B Chunks
→ Authenticated 1232B Cell (AES-256-GCM) → AES-256-CTR Whitening
→ Constant-Rate Scheduler (50ms / 20 cells/sec) → SOCKS5 Tor / Sovereign Tunnel
→ Outer TLS 1.3 Session → Wire
```

## 5. Standards Mapping (2027 Top-Secret Path)

| Function | Implementation | Standard Specification |
|---|---|---|
| **Primary KEM** | ML-KEM-1024 | NIST FIPS 203, CNSA 2.0 |
| **Classical Hedge** | SecP384r1 (P-384 ECDH) | NIST SP 800-56A Rev 3 |
| **Hybrid Combiner** | SecP384r1MLKEM1024 | RFC 10024 (Level 5 Profile) |
| **Signatures & Identity** | ML-DSA-87 | NIST FIPS 204, CNSA 2.0 |
| **Bulk AEAD Encryption** | AES-256-GCM | NIST SP 800-38D, FIPS 197 |
| **Key Derivation (KDF)** | HKDF-SHA384 | RFC 5869, NIST SP 800-56C Rev 2 |
| **Formal Verification** | Machine-Checked ProVerif 2.05 | RFC 9420 / Noise-PQ formal models |
| **Two-Person Rule** | Dual-Person Operation (DPO) | DoD Directive S-5210.41M, CJCSI 3265.01 |
| **Platform Attestation** | TPM-Bound Evidence Envelope | IETF RATS (RFC 9334) |
| **Hardware Custody** | Windows CNG / PKCS#11 v3.2 | FIPS 140-3 Level 3/4 Physical Enclosure |
| **Facility Shielding** | TEMPEST Accreditation Registry | NATO SDIP-27/3, SDIP-28/3, SDIP-29 |
| **Unidirectional Boundary** | Hardware Optical Diode Gate | Common Criteria ISO/IEC 15408 EAL4+/EAL7+ |
| **Anonymity Overlay** | Tor v3 SOCKS5 / Sovereign APN | RFC 1928, Loopix / Sphinx Packet Design |

## 6. Security Properties (Formally Verified)

- **Cryptographic Confidentiality:** Formally proved in ProVerif 2.05 (`docs/formal/st2027_handshake.pv`). Queries prove that no passive or active polynomial-time adversary can obtain the payload ciphertext.
- **Mutual Authentication:** Injective agreement proved for both initiator (`inj-event(S_Accepts)`) and responder (`inj-event(R_Receives)`).
- **Post-Compromise Security (PCS) & Forward Secrecy:** Formally proved in `docs/formal/st2027_pcs.pv`. Ephemeral key leakage in Epoch $N$ does not compromise Epoch $N-1$ (PFS) and is actively healed in Epoch $N+1$ upon fresh hybrid re-keying (PCS).
- **Continuous Epoch Ratchet (CER) with hybrid ML-KEM-1024 / P-384 interleaving:** the primary tactical channel (`secure_transmit_2027.py: Channel`) rotates epochs via a fresh ephemeral Noise_XXhfs exchange interleaved into the session key chain (old epoch key zeroized) every **128 sealed records / 1 MiB / 15 min idle, whichever first** (`CER_EPOCH_MESSAGES`, `SESSION_REKEY_BYTES`, `SESSION_REKEY_SECONDS`). Per-record AES-GCM with monotonic nonces gives per-record forward secrecy; the symmetric chain alone has no PCS (deterministic KDF — Signal Double Ratchet decomposition), so the epoch ratchet is the healing mechanism: transient compromise heals within one epoch. PQ ratchet material is ~71x bulkier than classical DH (NIST PQC-Signal analysis), hence message-counted epochs rather than per-message PQ operations — stated cost/healing tradeoff.
- **Traffic Analysis Resistance:** 50ms tick constant-rate emission with 1232-byte uniform noise cells conceals packet lengths, message boundaries, and idle/burst patterns from backbone SIGINT taps.
- **Fail-Closed Execution:** Any deviation in hardware posture, missing FIPS provider, unaccredited facility record, memory corruption, or signature failure immediately triggers emergency zeroization and aborts.
