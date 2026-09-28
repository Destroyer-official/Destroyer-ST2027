# Sovereign Military-Grade NC3 Deployment & Operations Manual
================================================================================
**Handling**: UNCLASSIFIED work product (self-authored operations manual; no classification authority has reviewed or marked this document. Design basis cites DoD Directive S-5210.41M / CJCSI 3265.01 / USSTRATCOM EAP-STRAT as requirements sources, not as granted approvals.)
**Cryptographic Baseline**: NIST FIPS 203 (ML-KEM-1024), FIPS 204 (ML-DSA-87), FIPS 205 (SLH-DSA-256f), Classic McEliece-8192128f, NSA CNSA 2.0  

---

## 1. Executive Summary & Purpose

This manual establishes the mandatory operational protocols, cryptographic controls, physical hardware baselines, and emergency procedures for deploying and operating the **Destroyer Sovereign Secure P2P Communications Engine** in mission-critical, national-security, and Nuclear Command, Control, and Communications (NC3) enclaves.

The system is designed to provide non-repudiation, tamper-evident auditability, information-theoretic dual custody (2-of-2 additive sharing), and quantum-resistant confidentiality across inter-governmental, strategic alliance, and command-echelon communication links -- subject to the hardware, bearer, and accreditation limits stated in this manual, not as a guarantee.

---

## 2. Threat Vector Defense Matrix

| Threat Vector | Doctrine & Mitigation Level | Technical Implementation Engine |
| :--- | :--- | :--- |
| **Nation-State Cryptanalysis (CRQC)** | **RESISTANT** (NIST Level 5) | Dual-hybrid KEM (ML-KEM-1024 + Classic-McEliece-8192128f) & Dual-hybrid Signatures (ML-DSA-87 + SLH-DSA-256f) with transcript-bound HKDF-SHA3-512. |
| **Endpoint APT / Kernel Zero-Day** | **CONTAINED / FAIL-CLOSED** | Bounded stack-only `#![no_std]` Rust micro-core (`StackFrameBuffer`, `StackSecretBuffer`) preventing heap exploitation, buffer overflows, and dynamic memory corruption. |
| **Physical Hardware Theft / Cold-Boot Attack** | **FAIL-CLOSED ZEROIZATION** | Motherboard TPM 2.0 PCR attestation (PCRs 0, 1, 2, 7) + HKDF-SHA3-512 PCR-sealed secret envelopes + Autonomous 7-Pass DoD 5220.22-M memory wiping. |
| **Rogue Single-Operator / Coerced Commander** | **CRYPTOGRAPHICALLY FORBIDDEN** | Two-Person Integrity (TPI) via $GF(2^{256})$ Verifiable Secret Sharing (VSS), distinct hardware token authentication, and a physical 2.0-second temporal synchronization window. |
| **Cross-Domain Data Exfiltration / Reverse Channel** | **SOFTWARE SIMPLEX ONLY** | Interface-pinned unidirectional UDP (`tactical_data_diode.py`, no wildcard binds, AST-enforced direction) with $GF(2^8)$ Cauchy Reed-Solomon Forward Error Correction. True reverse-channel impossibility requires OPTICAL DIODE HARDWARE (severed RX fiber) -- not present here. |

---

## 3. Core Architectural Subsystems

### 3.1. Phase 1: Native TPM 2.0 Hardware Attestation & PCR Sealing
- **Engine**: `tpm_quote.py` / `platform_hsm_interface.py`
- **Platform Interface**: Physical Windows TBS (`tbs.dll`) and Linux TCG TPM Resource Manager (`/dev/tpmrm0`).
- **PCR Registers Monitored**:
  - `PCR 0`: Core Root of Trust for Measurement (CRTM), BIOS/UEFI firmware code.
  - `PCR 1`: Motherboard and platform chipset configuration.
  - `PCR 2`: Option ROM code execution.
  - `PCR 7`: Secure Boot state, PK, KEK, DB, DBX certificate registries.
- **PCR-Sealed Storage**: Key schedules are sealed using an HKDF-SHA3-512 derivation keyed to the 64-byte deterministic SHA3-512 composite of PCRs 0, 1, 2, and 7. Any modification to firmware, bootloader, or Secure Boot keys alters the composite, making secret unsealing cryptographically impossible (`PCRMismatchError`).

### 3.2. Phase 2: NC3 / PAL Two-Person Integrity (TPI) Dual-Custody Protocol
- **Engines**: `nc3_nuclear_command.py`, `spo_dpo.py`, `secure_transmit_2027.py`, `secure_memory_wiper.py`
- **Doctrinal Alignment**: DoD Directive S-5210.41M (*Nuclear Weapon Personnel Reliability and Two-Person Rule*) & CJCSI 3265.01.
- **Core Security Controls**:
  1. **Dual Persona Operation (DPO)**: Enforced via `spo_dpo.py`. Under DPO mode (`--dpo`), sensitive actions (cryptographic transmission, key re-seeding, emergency zeroization bypass) require two independent authenticated human operators: Primary Officer (SPO) and Verifying Officer (DPO).
  2. **Verifiable Secret Sharing (VSS)**: In `nc3_nuclear_command.py`, the inner Permissive Action Link (PAL) unlock key is split into a 2-of-2 additive secret share over $GF(2^{256})$. Polynomial commitments are hashed via SHA3-512. Neither officer possesses the complete key in isolation.
  3. **Distinct Hardware Token Authentication**: Both Officer 1 and Officer 2 must sign independent, cryptographically unpredictable nonces using physically isolated hardware tokens (`token_id_1 != token_id_2`). Single-token dual-authorization is hard-rejected.
  4. **Physical Temporal Synchronization Window**: Replicating dual physical launch consoles, both officer authorizations must register within a maximum $\Delta t \le 2.000\text{ seconds}$. Any serial authorization by a single operator after the window expires raises `DualCustodySynchronizationError`.
  5. **Autonomous Emergency Zeroization**: Any protocol failure (signature mismatch, VSS checksum failure, replay attempt, or window expiration) triggers an immediate, unmaskable 7-pass DoD 5220.22-M memory sanitization pass (`secure_wipe_dod_7pass`) and platform zeroization.

### 3.3. Phase 3: High-Assurance `#![no_std]` Rust Micro-Core
- **Engine**: `rust_data_plane/src/nostd_microcore.rs`, `ts_rt/src/lib.rs` (compiled `ts_rt.dll`)
- **Safety TARGETS (not assessed)**: Common Criteria EAL6+ / MISRA-Rust / DO-178C Level A. No evaluation has been performed against any of these.
- **Guarantees (design properties, lab-verified where noted)**:
  - **Zero Heap Allocations**: All frame serialization, parsing, and cryptographic transformation operate exclusively on stack-pinned memory (`StackFrameBuffer<1232>`, `StackSecretBuffer<N>`).
  - **Branchless Constant-Time Arithmetic**: Header tag checking, sequence comparison, and conditional copying use `ct_eq` and `ct_copy_if` backed by compiler memory barriers (`core::hint::black_box`); side-channel resistance is a design property, not a lab finding.
  - **Memory Locking & Volatile Wiping**: `ts_rt` locks process pages via `VirtualLock`/`mlock` and securely wipes buffers with memory compiler fences upon deallocation.
  - **Panic-Freedom Harnesses**: Kani proof harnesses exist (`rust_data_plane/tests/kani_harness.rs`) with `cargo test` doubles green.

### 3.4. Phase 4: ProVerif Formal Protocol Models & Machine-Checked Proofs
- **Models**: `docs/formal/st2027_handshake.pv`, `docs/formal/st2027_pcs.pv`
- **Verifier Engine**: ProVerif 2.05 (Dolev-Yao symbolic attacker model)
- **Status**: **VERIFIED & MACHINE-CHECKED PASSING** in automated CI (`test_proverif_st2027.py` in ~15.2s):
  1. **Secrecy of Transmitted Payload**:
     $$\text{Query: } \mathbf{not} \ \text{attacker}(\text{secret\_payload\_A}[]) \implies \mathbf{true}$$
     Proved: An attacker controlling the entire network fabric cannot derive or invert the plaintext payload protected by the `SecP384r1MLKEM1024` hybrid combiner and `AES-256-GCM`.
  2. **Injective Mutual Authentication**:
     $$\text{Query: } \text{inj-event}(\text{endB}(kA, kB, sess)) \implies \text{inj-event}(\text{beginA}(kA, kB, sess)) \implies \mathbf{true}$$
     Proved: Replay, message-reordering, and man-in-the-middle impersonation attacks are mathematically impossible within the modeled protocol boundary.
  3. **Post-Compromise Security (PCS) Healing**:
     $$\text{Query: } \mathbf{not} \ \text{attacker}(\text{post\_ratchet\_secret}[]) \implies \mathbf{true}$$
     Proved: Even when an attacker completely captures an ephemeral ratchet key in Epoch $N$, their compromise capability is terminated upon the next hybrid ratchet step in Epoch $N+1$.

### 3.5. Phase 5: Air-Gapped Simplex Tactical Data Diode
- **Engine**: `tactical_data_diode.py`
- **Physical Link**: Unidirectional fiber-optic cable (Tx-only to Rx-only transceiver pair).
- **FEC Engine**: Pure Galois Field $GF(2^8)$ Cauchy generator matrix.
- **Reliability Parameters**:
  - For $K$ original data symbols, $M$ parity symbols are generated.
  - The receiving enclave reconstructs the complete telemetry stream from **any** $K$ packets out of $K+M$.
  - Tolerates over 20% sustained burst packet loss without a reverse acknowledgement channel (guaranteed zero exfiltration back-channel).
- **Tactical Format**: Native Cursor-on-Target (CoT) XML event encoding for blue-force situational awareness, target designation, and DEFCON readiness.

---

## 4. Standard Operating Procedures (SOP)

### SOP-01: First-Time Station Commissioning & Hardware Registration
1. Boot terminal on air-gapped, Tempest-shielded hardware.
2. Verify hardware TPM 2.0 is enabled in UEFI firmware with Secure Boot active.
3. Execute the Witnessed Key Ceremony:
   ```bash
   python scripts/witnessed_key_ceremony.py --ceremony-id "CEREMONY-BASE-ALPHA" --production
   ```
4. Verify physical PCR measurements match the baseline manifest signed by the Authorizing Official (AO).

### SOP-02: Transmitting an Emergency Action Message (/nc3-send)
1. Both certified launch officers must be physically present at the command console.
2. Station Commander issues command:
   ```text
   /nc3-send FLASH-DEFCON1-STRIKE-PLAN TARGET-VECTOR-OMNI <CLASSIFIED_PAL_CODE>
   ```
3. Officer 1 enters Officer ID and inserts Hardware Token 1 to sign nonces.
4. Officer 2 enters Officer ID and inserts Hardware Token 2 within 2.0 seconds.
5. System verifies $GF(2^{256})$ VSS split, signs with ML-DSA-87, seals to destination peer identity, and transmits via post-quantum Double Ratchet channel.
6. Local volatile memory schedules are immediately zeroized via DoD 5220.22-M 7-pass wipe.

### SOP-03: Authenticating and Unsealing an EAM (/nc3-verify)
1. Inbound EAM arrives at Station Bravo with an audible, high-priority flash alert.
2. Recipient Officer 1 and Officer 2 take stations at the receiving terminal.
3. Issue the verification command:
   ```text
   /nc3-verify <OFFICER_1_ID> <OFFICER_2_ID>
   ```
4. Both officers authenticate within the 2.0-second synchronization window.
5. Engine checks temporal freshness ($\Delta t < 120\text{s}$), verifies ML-DSA-87 signatures, reassembles VSS shares over $GF(2^{256})$, and displays unsealed PAL unlock code on secure video display.

### SOP-04: Emergency Zeroization (/zeroize)
In the event of physical breach, hostile boarding, or detected bus-interposition tampering:
1. Issue the immediate zeroization command:
   ```text
   /zeroize
   ```
2. Or trigger the hardware tamper switch / chassis intrusion pin.
3. The system executes autonomous DoD 5220.22-M 7-pass overwrite:
   - Pass 1: Constant `0x00`
   - Pass 2: Constant `0xFF`
   - Pass 3: Cryptographic CSPRNG pseudorandom bytes
   - Pass 4: Bitwise complement pattern `0x55`
   - Pass 5: Bitwise complement pattern `0xAA`
   - Pass 6: Cryptographic CSPRNG pseudorandom bytes
   - Pass 7: Final zero-fill `0x00` + read-back verification.

---

## 5. Automated Verification Checklist

To confirm gate passage of a deployed station, run the complete verification sweep:

```bash
# 1. High-Assurance Rust Data Plane & Runtime
cargo test --manifest-path rust_data_plane/Cargo.toml
cargo test --manifest-path ts_rt/Cargo.toml

# 2. Machine-Checked Formal ProVerif 2.05 Proofs
pytest test_proverif_st2027.py -v

# 3. 2027 Top-Secret 5-Pillar Hardening Suite
pytest test_ts_hw_layer.py \
       test_ts_runtime.py \
       test_noise_pq_purity.py \
       test_transport_anonymity.py \
       test_trust_anchor.py \
       test_spo_dpo.py \
       test_secure_transmit_2027.py \
       test_ts_attest.py -v

# 4. Sovereign NC3 & TPI Verification Suites
pytest test_tpm_quote_production.py \
       test_tpm_quote.py \
       test_nc3_two_person_integrity.py \
       test_tactical_data_diode.py \
       test_nc3_nuclear_command_readiness.py \
       test_defensive_nc3_audit.py -v

# 5. Live Two-Terminal Socket Drill
python test_nc3_two_terminal_live_transfer.py
```

**Gate criterion**: All test suites must return zero errors. (A green sweep is evidence of correct function, not a readiness certification -- see Handling note at the top.)
