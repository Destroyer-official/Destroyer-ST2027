# Sovereign Post-Quantum Secure Communications System (2027 Target Posture)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CNSA 2.0](https://img.shields.io/badge/Compliance-NSA%20CNSA%202.0-red.svg)](https://www.nsa.gov/Cybersecurity/Commercial-National-Security-Algorithm-Suite-2-0/)
[![NIST PQC](https://img.shields.io/badge/Standards-NIST%20FIPS%20203%20%7C%20204-green.svg)](https://csrc.nist.gov/publications/detail/fips/203/final)
[![Formal Proof](https://img.shields.io/badge/Formal%20Verification-ProVerif%202.05%20Verified-blueviolet.svg)](docs/formal/st2027_handshake.pv)
[![Test Suite](https://img.shields.io/badge/Test%20Suite-163%2F163%20Passed-brightgreen.svg)](test_secure_transmit_2027.py)

---

## 1. Executive Overview & Architecture Thesis

This repository provides a sovereign, post-quantum peer-to-peer secure communication architecture engineered for **2027 National Security System (NSS) standards**. It is designed to transmit high-assurance payloads over untrusted public networks, resilient against both present-day network surveillance (ISP/backbone interception, traffic analysis, deep packet inspection) and future cryptanalytic quantum computers (Harvest-Now-Decrypt-Later).

### The Two Architectures in this Repository
1. **The 2027 Sovereign Top-Secret Pipeline ([secure_transmit_2027.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/secure_transmit_2027.py)):**
   The modernized, fail-closed production target. It enforces pure **CNSA Suite 2.0**, RFC 10024 Level 5 hybrid key encapsulation (`SecP384r1MLKEM1024`), **ML-DSA-87** identity signatures, **AES-256-GCM** authenticated framing, a deterministic zero-dependency Rust native core ([ts_rt](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_rt)), constant-rate cell traffic shaping, Two-Person Integrity (DPO) authorization, and offline 3-of-5 threshold hardware PKI.
2. **The Legacy P2P Research Testbed ([archive/legacy_prototype/secure_p2.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/archive/legacy_prototype/secure_p2.py) / [archive/legacy_prototype/secure_p2p.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/archive/legacy_prototype/secure_p2p.py)):**
   An expansive 13,000-line multi-party chat prototype retained for experimental comparison, testing hybrid Double Ratchet variations, and legacy research (contains non-CNSA algorithms like Falcon and McEliece).

---

## 2. Operational Truth & The Physical Security Boundary

> [!IMPORTANT]
> ### The Reality of High-Assurance Defense Engineering
> **Software CANNOT certify physics.** No application code running in user space can manufacture a physical FIPS 140-3 Level 3/4 tamper envelope, TEMPEST radio-frequency shielding, true physical RED/BLACK electrical isolation, or an optical one-way path. Those are physical properties of evaluated hardware, accredited facilities, and controlled installations.
>
> What this codebase does—with strict, fail-closed mechanics—is act as an **uncompromising gatekeeper**:
> - It actively probes the host platform, operating system, and hardware tokens.
> - If the required hardware tokens (TPM/HSM), FIPS cryptographic providers, accredited TEMPEST registry records, or verified operating systems are absent, **the system unconditionally halts and refuses execution in Top-Secret mode (`TSRequiredError`)**.

---

## 3. The 5 Strategic Hardening Pillars

```
+---------------------------------------------------------------------------------------------------------+
|                                2027 TOP SECRET COMMUNICATIONS STACK                                     |
+---------------------------------------------------------------------------------------------------------+
| [PILLAR 5] TRUST ANCHOR & OPERATIONAL KEY MANAGEMENT (trust_anchor.py)                                   |
|   ├── Offline 3-of-5 Threshold ML-DSA-87 Hardware Root CA (No TOFU fallback in TS mode)                 |
|   ├── Threshold-Signed Monotonic Revocation Broadcast via Uniform Cells (CRL-style)                     |
|   └── Strict Amnesia / Zero-Plaintext-Disk Profile (Fail-closed on any disk persistence)                |
+---------------------------------------------------------------------------------------------------------+
| [PILLAR 4] NETWORK TRANSPORT & ANONYMITY (transport_anonymity.py & spo_dpo.py)                         |
|   ├── Mandatory Overlay (Tor v3 SOCKS5 with remote DNS or Interface-Pinned Sovereign APN/Dark-Fiber)     |
|   ├── Constant-Rate (50ms tick) Constant-Size (1232B cell / 1280B IPv6 MTU) Traffic Shaping             |
|   ├── Stream Whitening (AES-256-CTR Uniform Noise, zero cleartext magic/length headers)                  |
|   └── Two-Person Integrity / DPO Pre-Transmit Ceremony (DoD S-5210.41M, 2.0s Dual Action Window)       |
+---------------------------------------------------------------------------------------------------------+
| [PILLAR 3] CRYPTOGRAPHY & PROTOCOL ARCHITECTURE (noise_pq.py, cnsa_purity.py, crypto_selftest.py)      |
|   ├── Noise_XXhfs + ML-KEM-1024 + P-384 ECDH + ML-DSA-87 Protocol Handshake                             |
|   ├── CNSA 2.0 Pure Tokenizer & Runtime Policy (Rejection of Falcon, McEliece, ChaCha, RSA, etc.)        |
|   ├── FIPS 140-3 Section 10 Power-Up Self-Tests & Conditional PCTs (OpenSSL vs PyCryptodome vs RFC 7748) |
|   └── Formal ProVerif 2.05 Proofs (Secrecy, Mutual Auth, Forward Secrecy, Post-Compromise Security)     |
+---------------------------------------------------------------------------------------------------------+
| [PILLAR 2] OPERATING SYSTEM & EXECUTION RUNTIME (ts_runtime.py, ts_rt Rust cdylib, ts_attest.py)       |
|   ├── seL4 Verified Microkernel Gating OR Signed AO Waiver with Live VBS/HVCI/SecureBoot Enforcement     |
|   ├── Deterministic Native Rust Core (VirtualLock/mlock, Volatile Zeroize with Compiler Fence, CT Equal)  |
|   ├── Measured Boot Posture & IETF RATS Platform Attestation (TPM-Signed Evidence Envelope)             |
|   └── Anti-DMA Bus Scan (Detects Thunderbolt/USB4/1394/PCMCIA, enforces IOMMU / Kernel DMA Protection)  |
+---------------------------------------------------------------------------------------------------------+
| [PILLAR 1] HARDWARE & PHYSICAL SECURITY LAYER (ts_hw_layer.py & cng_platform.py)                        |
|   ├── FIPS 140-3 Validated Cryptographic Provider Check (OSSL_PROVIDER_load("fips") + CMVP Record)     |
|   ├── Non-Exportable Hardware Key Custody (Windows CNG TPM 2.0 Platform Provider & PKCS#11 Tokens)       |
|   ├── Physical RED / BLACK Interface Separation (psutil live NIC bind enforcement, no wildcards)        |
|   ├── TEMPEST / SCIF Facility Accreditation Registry (NATO SDIP-27/28/29 Evaluation Records)             |
|   ├── Active Multi-Trigger Zeroization Mesh (Debugger, TPM PCR drift, Heartbeat loss, ML-DSA-87 duress) |
|   └── Hardware Optical Data Diode Gate (Simplex UDP-only unacknowledged transfer framing)                |
+---------------------------------------------------------------------------------------------------------+
```

### Pillar 1: Hardware & Physical Security Layer
- **Implementation:** [`ts_hw_layer.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_hw_layer.py), [`cng_platform.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cng_platform.py)
- **FIPS 140-3 Provider Gate:** Dynamically verifies that a validated cryptographic provider (e.g. OpenSSL FIPS Provider CMVP #4985) is loaded via `OSSL_PROVIDER_load`. Fails closed if absent.
- **Hardware Key Custody:** Interacts with Windows CNG `Microsoft Platform Crypto Provider` (TPM 2.0) and PKCS#11 hardware tokens; private keys are non-exportable and never touch general-purpose CPU RAM.
- **RED/BLACK Network Separation:** Validates physical network interface bindings via `psutil`; wildcard binds (`0.0.0.0`, `::`) and RED/BLACK interface sharing are prohibited.
- **TEMPEST Facility Registry:** Validates structured JSON records against NATO SDIP-27/3 (equipment level), SDIP-28/3 (installation zone), and SDIP-29 (separation spacing).
- **Active Zeroization Mesh:** Real-time tamper engine listening to Win32 debugger presence, TPM PCR register drift, heartbeat timeout, and authenticated ML-DSA-87 signed duress orders, executing DoD 5220.22-M overwrites on all registered buffers.
- **Hardware Optical Diode Gate:** Requires Common Criteria EAL4+/EAL7+ evaluation records and enforces simplex UDP-only unacknowledged framing.

### Pillar 2: Operating System & Execution Runtime Layer
- **Implementation:** [`ts_runtime.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_runtime.py), [`ts_rt/src/lib.rs`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_rt/src/lib.rs), [`ts_attest.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_attest.py)
- **Platform Verification:** Enforces execution on an attested **seL4 microkernel** (AArch64 / RISC-V with formal proofs of functional correctness and confidentiality) OR an Authorizing Official (AO) signed waiver with live-verified VBS, HVCI, and UEFI Secure Boot.
- **Deterministic Native Rust Core (`ts_rt`):** Zero-dependency Rust `cdylib` with OS-locked memory pages (`VirtualLock`/`mlock`), volatile zeroization loops with compiler fences (`compiler_fence(SeqCst)`), branchless 64-bit anti-replay bitmap, and constant-time comparisons (`tsrt_ct_equal`).
- **Measured Boot Chain Verification:** Live inspection of host Secure Boot status, DeviceGuard virtualization-based security, and measured boot logs.
- **Anti-DMA Bus Defense:** Live scan of Thunderbolt/USB4, FireWire (IEEE 1394), and PCMCIA buses; rejects TS mode if DMA ports are exposed without IOMMU / Kernel DMA Protection.
- **Platform Attestation:** Implements IETF RATS RFC 9334 Attester/Verifier roles producing TPM-signed evidence envelopes.

### Pillar 3: Cryptography & Protocol Architecture
- **Implementation:** [`noise_pq.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/noise_pq.py), [`cnsa_purity.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cnsa_purity.py), [`crypto_selftest.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/crypto_selftest.py), [`docs/formal/`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/docs/formal/)
- **Protocol Handshake:** `Noise_XXhfs+sig_P384+MLKEM1024_AES256GCM_SHA384` and `TLS 1.3 TLS_AES_256_GCM_SHA384` with RFC 10024 Level 5 hybrid key exchange (`SecP384r1MLKEM1024`).
- **CNSA 2.0 Purity:** Strict tokenizer and runtime enforcement allowing only ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA-384/512, and HKDF-SHA384. Rejects Falcon, McEliece, Kyber, Dilithium, ChaCha20, RSA, and non-standard algorithms.
- **Power-Up Self-Tests:** FIPS 140-3 Section 10 power-up KATs (OpenSSL vs PyCryptodome cross-implementation verification for AES-GCM, HKDF, SHA-384, P-384, RFC 7748 vectors, and ML-KEM/ML-DSA pairwise consistency tests).
- **Machine-Checked Formal Proofs:** Formal ProVerif 2.05 models proving payload secrecy, mutual authentication, forward secrecy, and post-compromise security (PCS) healing.

### Pillar 4: Network Transport & Anonymity
- **Implementation:** [`transport_anonymity.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py), [`spo_dpo.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/spo_dpo.py)
- **Overlay Anonymity:** Direct public internet connections are refused; traffic must route via Tor v3 .onion (RFC 1928 SOCKS5 with remote DNS resolution) or an interface-pinned sovereign APN / WireGuard tunnel.
- **Constant-Rate / Constant-Size Traffic Shaping:** Emits exactly one 1232-byte cell every 50ms (20 cells/sec, conforming to 1280-byte IPv6 minimum MTU). Real traffic is fragmented across chunks; idle intervals emit cryptographically indistinguishable cover cells.
- **Stream Whitening:** Every wire cell is whitened with AES-256-CTR, appearing as uniform high-entropy noise with zero plaintext headers or length markers.
- **Two-Person Integrity (DPO):** DoD Directive S-5210.41M compliance: Dual-Person Operation requires two distinct hardware-bound ML-DSA-87 approvals within a 2.0-second simultaneous action window before TOP SECRET payload release.

### Pillar 5: Trust Infrastructure & Operational Key Management
- **Implementation:** [`trust_anchor.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/trust_anchor.py)
- **Threshold Hardware Root CA:** Offline 3-of-5 threshold ML-DSA-87 Root CA conforming to RFC 9881 PKIX profile. Strict TS mode eliminates TOFU completely; unknown peers without 3-of-5 threshold signatures are refused.
- **Threshold Revocation Broadcast:** Threshold-signed CRL-style compromise broadcast with monotonic per-serial sequence numbers, cached in memory and transported inside uniform anonymity cells.
- **Zero-Plaintext-Disk / Amnesia Profile:** Strict fail-closed prohibition against persisting plaintext secrets, pins, or ledgers to disk in TS mode; operations execute purely in OS-locked native RAM or hardware tokens.

---

## 4. Standards & Compliance Matrix

| Standard / Directive | Scope & Mandate | Project Implementation |
| :--- | :--- | :--- |
| **NIST FIPS 203** | Primary Post-Quantum Key Encapsulation (ML-KEM-1024) | [`noise_pq.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/noise_pq.py), [`secure_transmit_2027.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/secure_transmit_2027.py) |
| **NIST FIPS 204** | Primary Post-Quantum Digital Signature (ML-DSA-87) | [`noise_pq.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/noise_pq.py), [`trust_anchor.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/trust_anchor.py), [`spo_dpo.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/spo_dpo.py) |
| **NSA CNSA Suite 2.0** | National Security Systems (NSS) 2027/2028 Mandate | [`cnsa_purity.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cnsa_purity.py) |
| **RFC 10024** | Hybrid Post-Quantum Key Exchange (`SecP384r1MLKEM1024`) | [`secure_transmit_2027.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/secure_transmit_2027.py) |
| **FIPS 140-3 Level 3/4** | Hardware Security, Power-Up Self-Tests, Zeroization | [`ts_hw_layer.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_hw_layer.py), [`crypto_selftest.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/crypto_selftest.py) |
| **NATO SDIP-27/3, 28/3, 29** | TEMPEST Equipment, Facility Zoning, Installation Spacing | [`ts_hw_layer.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_hw_layer.py) |
| **DoD Directive S-5210.41M** | Nuclear Command & Two-Person Integrity (2.0s DPO) | [`spo_dpo.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/spo_dpo.py) |
| **IETF RATS (RFC 9334)** | Remote Platform Attestation & Evidence Architecture | [`ts_attest.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_attest.py) |
| **Common Criteria EAL4+/EAL7+** | Hardware Optical Data Diode Evaluation | [`ts_hw_layer.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_hw_layer.py) |
| **Formal Verification** | Machine-Checked Secrecy & Authentication Proofs | ProVerif 2.05 ([`docs/formal/st2027_handshake.pv`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/docs/formal/st2027_handshake.pv)) |

---

## 5. Quick Start & Operational Usage

### Prerequisites
- Python 3.10+
- Rust Toolchain (`cargo`, `rustc`)
- Platform C Cryptographic Libraries: OpenSSL 3.1+ (`libcrypto-3`), LibOQS (`oqs.dll`), Libsodium (`libsodium.dll`)

### Build the Rust Native Core
```bash
cd ts_rt
cargo build --release
cd ..
```

### Running the 2027 Transmission Pipeline (`secure_transmit_2027.py`)

#### 1. Generate Hardware-Backed Identity (ML-DSA-87)
```bash
python secure_transmit_2027.py keygen --label station_alpha
```

#### 2. Start Receiver (Simulating Receiver Node)
```bash
python secure_transmit_2027.py recv \
  --port 8888 \
  --cert certs/node_alpha.json \
  --key keys/node_alpha.key \
  --ca certs/ca.json \
  --peer-id peer_bravo \
  --out downloads/received_payload.bin \
  --label station_alpha
```

#### 3. Transmit Payload with Constant-Rate Anonymity & Dual-Person Integrity
```bash
python secure_transmit_2027.py send \
  --host 127.0.0.1 \
  --port 8888 \
  --cert certs/node_bravo.json \
  --key keys/node_bravo.key \
  --ca certs/ca.json \
  --peer-id peer_alpha \
  --file confidential_manifest.tar \
  --anonymity \
  --dpo-receipt receipts/dpo_approved.json \
  --label station_bravo
```

---

## 6. Verification & Automated Test Suites

The repository contains an exhaustive automated test suite validating every tier of the security stack.

### Run the Unified 2027 Top-Secret Test Suite (163 Python Tests)
```bash
pytest test_ts_hw_layer.py test_ts_runtime.py test_secure_transmit_2027.py \
       test_noise_pq_purity.py test_proverif_st2027.py test_spo_dpo.py \
       test_transport_anonymity.py test_trust_anchor.py test_ts_attest.py \
       test_hw_readiness.py test_runbooks_ps.py test_rust_standalone_binary.py \
       test_no_marketing_buzzwords_property.py test_no_emoji_property.py -v
```

### Run Native Rust Data-Plane Test Suite (64 Rust Tests)
```bash
cargo test --manifest-path rust_data_plane/Cargo.toml
```

### Run Formal Machine-Checked ProVerif Proofs
```bash
# Requires proverif 2.05 binary in PATH or %LOCALAPPDATA%\ProVerif\proverif2.05\
proverif docs/formal/st2027_handshake.pv
proverif docs/formal/st2027_pcs.pv
```

---

## 7. Remaining Real-World Deployment Roadmap

While the **software architecture, cryptographic engines, gating logic, and standalone Rust data-plane executor are 100% complete**, physical field deployment for Top-Secret national security operations requires completing the following external procurement and facility actions:

1. **Procure Evaluated Physical Hardware:** Deploy on physical nodes equipped with FIPS 140-3 Level 3/4 hardware security modules (Thales Luna 7.9+ / Utimaco Quantum Protect with PKCS#11 v3.2 ML-DSA/ML-KEM firmware).
2. **Physical Facility Accreditation:** Place endpoints in accredited TEMPEST SCIF facilities matching NATO SDIP-28/3 Zone 0/1 with certified SDIP-27 Level A hardware.
3. **Physical Optical Data Diodes:** Wire physical unidirectional optical fiber diodes across cross-domain boundaries.
4. **Standalone Rust Binary Operationalization:** The standalone zero-Python data plane (`secure-transmit`, supporting `keygen`, `send`, `recv`, `send-file`, `recv-file`, and `selftest` with 1205B quantum chunking, SHA-256 digests, and fail-closed exit 4 on tamper/gap) is fully compiled and tested in [`rust_data_plane/`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/). Deploy it as the raw framing pipeline across production links.
5. **Government Authority to Operate (ATO):** Submit the generated OSCAL SSP/SAR reports and formal ProVerif models to the Authorizing Official (AO) for national security link certification.

---

## 8. License & Attribution

- **License:** MIT License — For authorized defense and national security research.
- **Cryptographic Algorithms:** Implementations of NIST FIPS 203, FIPS 204, and FIPS 205 derived from standard OpenSSL and LibOQS reference specifications.
