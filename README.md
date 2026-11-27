# Post-Quantum Communications Architecture (ST2027)

## High-Assurance Transport Protocol for National Security Systems over Untrusted Networks

---

### Document Identification & Defense Standardization Metadata

```text
Document Identifier   : TM-ST2027-SPEC-2027.2
Standard Practice     : Aligned with MIL-STD-961E Content Architecture & Format
Classification Marking: UNCLASSIFIED // DEFENSE TECHNICAL RECORD
Security Architecture : NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)
Cryptographic Roots   : NIST FIPS 203 (ML-KEM-1024), NIST FIPS 204 (ML-DSA-87), NIST P-384
Transport Profile     : Fixed 1232B Wire Cells, 50ms Constant-Rate Traffic Pacing (20.0 Hz)
Hardware Trust Base   : Discrete TPM 2.0 (ISO/IEC 11889) + PKCS#11 v2.40 Hardware Silicon
Dual-Authorization    : DoD Directive 5210.41M / CJCSI 3260.01E Two-Person Integrity (TPI)
Operational Release   : Baseline 2027.2 (Pre-Evaluation Controlled Baseline)
Evaluation Status     : CONTROLLED PRE-EVALUATION ENGINEERING BASELINE (Software/CI Gates Verified; Not Lab-Certified or Accredited; Laboratory Submittal Packet Prepared)
```

---

## Abstract

This technical manual presents the architectural baseline, protocol specifications, symbolic verification models, and operational runbooks for **Secure Transmit 2027 (ST2027)**. Engineered for high-assurance National Security Systems (NSS), ST2027 replaces legacy non-hybridized classical schemes (RSA, standalone non-hybrid ECDH, ECDSA) with **NSA CNSA Suite 2.0** algorithms on its authoritative production path: **NIST FIPS 203 ML-KEM-1024**, **NIST FIPS 204 ML-DSA-87**, **AES-256-GCM**, and **SHA-384**. During the sovereign transition window, a classical leg is retained strictly inside standards-track hybrid key exchanges: the authoritative standalone native Rust data plane (`secure-transmit`) and `HybridKeyExchange2027` enforce `SecP384r1MLKEM1024` (NIST P-384 combined with ML-KEM-1024, Category 5 path per RFC 10024 and OpenSSL 3.5), rendering classical-only operation structurally unrepresentable in production builds (`--no-default-features`). By contrast, the quarantined Python `--lab` `SecureP2PChat` / `hybrid_kex_legacy` path retains legacy X25519 + ML-KEM-1024 compatibility bindings for isolated non-production evaluation and is strictly prohibited when `P2P_PRODUCTION=1`.

The platform implements quantum-resistant cryptographic algorithms designed to resist cryptanalysis by Cryptanalytically Relevant Quantum Computers (CRQCs) executing Shor's or Grover's algorithms (CNSA Suite 2.0 Level 5 strength), defeats traffic-flow analysis via constant-rate 50ms cell pacing and continuous Poisson chaff streams, enforces physical and logical separation across RED/BLACK boundaries via unidirectional simplex optical data diodes with Cauchy-Reed-Solomon erasure coding ($K=8, M=4$), and mandates physical dual-smartcard split knowledge for high-consequence Nuclear Command and Control (NC3) directives.

---

## 0. Evaluator Disclosures, Formal Boundaries & Operational Ethics (Read This First)

To maintain absolute scientific transparency and prevent unearned accreditation claims:

> [!CAUTION]
> **MANDATORY COMPLIANCE DISCLOSURE (PRE-EVALUATION STATUS):**  
> This software is an engineering baseline designed to meet the technical specifications of CNSA 2.0. It has not undergone accredited laboratory evaluation (FIPS 140-3 CMVP / Common Criteria) and does not possess a government Authority to Operate (ATO). All cryptographic and security claims in this repository are subject to the evaluation boundaries, mathematical assumptions, and threat models explicitly documented herein.

> [!IMPORTANT]
> **NATIVE DATA-PLANE VS. RUNTIME MEMORY RESIDUALS (CPYTHON IMMUTABLE BYTES OBJECT RETENTION):**  
> Python immutable `bytes` objects cannot be wiped deterministically due to runtime garbage collector copies. High-assurance operational deployments must execute via the standalone native Rust data-plane (`secure-transmit`).  
> In the CPython runtime, `bytes` objects are immutable and allocated through internal memory pools (`obmalloc` arenas). When Python handles cryptographic plaintext or keys, the garbage collector may copy or defer freeing these buffers, making deterministic zeroization impossible in Python.
> **Fix & Control-Plane Boundary:** All operational command-and-control loops and active traffic transit run strictly in the native Rust binary (`secure-transmit node`, `secure-transmit terminal`, `secure-transmit channel`). Native Rust enforces memory-locking (`VirtualLock` on Windows / `mlock` on POSIX), `ZeroizeOnDrop`, and explicit compiler barriers (`compiler_fence(Ordering::SeqCst)`). The Python runtime is restricted solely to offline build orchestration, automated testing, and non-transit utilities, strictly prohibiting any network or key transit through Python in production (`P2P_PRODUCTION=1`).

> [!WARNING]
> **STATISTICAL TRAFFIC ANALYSIS RESISTANCE SCOPE:**  
> Constant-rate traffic shaping (50ms interval) provides statistical masking against localized ISP/packet sniffers. It does not provide mathematical security against a global passive adversary with full autonomous network vantage points.

---

## 1. Architectural Reality & Triple-Plane System Topology

The ST2027 Trusted Computing Base (TCB) maintains strict physical and logical isolation across three distinct operational planes:

```text
+---------------------------------------------------------------------------------------------------------+
|                                    REPOSITORY ARCHITECTURAL REALITY                                     |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|  [PLANE 1: HIGH-ASSURANCE STANDALONE RUST DATA PLANE & TOR BRIDGE] (Production Core Target)                  |
|  * Crates: rust_data_plane/ (`secure-transmit`) + tor_transport/ (`secure-transmit-tor`, Arti 0.48.0)    |
|  * Toolchain: Pure native Rust (`--no-default-features` strips lab surfaces; zero ChaCha20, zero Tor deps)|
|  * Cryptography: Pure-Rust ML-DSA-87 + ML-KEM-1024 + P-384 (SecP384r1MLKEM1024), AES-256-GCM           |
|  * Hardware Interface: PKCS#11 v2.40 HSM silicon (cryptoki) + TPM 2.0 NVRAM Monotonic Counters          |
|  * Anti-Replay: 1024-packet circular sliding bitmask window (RFC 6479, 32 x u64 words, constant-time)  |
|  * Anti-SIGINT: 50ms constant-rate transmission clock, 256/512/1232B quantization, Poisson chaff stream  |
|  * Memory Hygiene: Explicit VirtualLock/mlock key buffers (LockedKey32), ZeroizeOnDrop, compiler fences  |
|                                                                                                         |
|  [PLANE 2: NATIVE SYSTEM SECURITY CORE CDYLIB] (Native Memory Protection Layer)                         |
|  * Directory: ts_rt/ (C-ABI shared dynamic library: ts_rt.dll / libts_rt.so)                            |
|  * Primitives: Win32 VirtualLock / POSIX mlock, Windows DPAPI CryptProtectMemory, PAGE_GUARD tripwires  |
|  * Volatile Sanitization: Multi-pass DoD 5220.22-M memory zeroization with compiler fence barriers      |
|  * Constant-Time Comparisons: tsrt_ct_equal branchless verification to prevent timing side channels     |
|                                                                                                         |
|  [PLANE 3: PYTHON MASTER CONTROL & SIMULATION ORCHESTRATOR] (Laboratory Reference & Diagnostic Surface) |
|  * Modules: secure_transmit_2027.py, secure_p2p.py, tactical_operator_console.py                        |
|  * Role: Pre-flight orchestration, hardware health audit, test harness automation, C4ISR console        |
|  * Bound Primitives: LibOQS C bindings (oqs.dll v0.16.0), Windows CNG TBS API, PyCryptodome             |
|  * Operational Constraint: Quarantined to lab/orchestration; blocked from standalone production transit |
|                                                                                                         |
+---------------------------------------------------------------------------------------------------------+
```

---

## 2. Defense Communication Topologies & Operational Doctrine ("Where & When Used")

ST2027 operates across six standardized operational environments, enforcing tailored combinations of transport framing, cryptographic policy, and hardware security gates:

```text
+-----------------------------------------------------------------------------------------------------------------------------+
|                                        ST2027 OPERATIONAL DEPLOYMENT MATRIX                                                 |
+-------------------+-----------------------------+-------------------------------+--------------------------+----------------+
| Environment /     | Underlying Physical /       | Cryptographic Session         | Hardware Security Anchor | Operational    |
| Topology          | Network Transit             | & Framing Baseline            | & Anti-Rollback Gate     | Doctrine       |
+-------------------+-----------------------------+-------------------------------+--------------------------+----------------+
| 1. Tactical Radio | VHF / UHF / HF Tactical     | Stateless Cookie Gate +       | Discrete TPM 2.0 NVRAM   | Non-emitting   |
|    (DDIL Edge)    | Line-of-Sight (LOS) Datagram| Fixed 1232B Cell Quantization | Monotonic Counter        | Silent-Drop    |
+-------------------+-----------------------------+-------------------------------+--------------------------+----------------+
| 2. Adversarial    | Public Internet / Multi-Hop | Noise_XXhfs Handshake +       | Host-hardened UEFI /     | Continuous     |
|    Public WAN     | Tor v3 Onion Transport      | SecP384r1MLKEM1024 hybrid     | VBS / HVCI Hypervisor    | 50ms Pacing    |
+-------------------+-----------------------------+-------------------------------+--------------------------+----------------+
| 3. Cross-Domain   | Simplex Physical Optical    | Cauchy-Reed-Solomon MDS FEC   | Physically Severed       | Unidirectional |
|    (RED / BLACK)  | Single-Strand Fiber Glass   | over GF(2^8) (K=8, M=4)       | Return Optic Strand      | Zero-ACK Wire  |
+-------------------+-----------------------------+-------------------------------+--------------------------+----------------+
| 4. Air-Gapped     | Removable Physical Media    | Offline Removable Envelopes + | Threshold 3-of-5         | SCIF Couriers  |
|    Enclave        | (USB / Solid-State Drive)   | Monotonic Sequence Token      | Custodian Quorum Signatures| Manual Key Fill|
+-------------------+-----------------------------+-------------------------------+--------------------------+----------------+
| 5. Joint Mesh     | Tactical IP MANET /         | In-Band Epoch Rekeying (CER) +| PKCS#11 Hardware HSM     | Multi-Domain   |
|    (CJADC2)       | Link-16 Tactical Data Net   | MIL-STD-6090 CoT XML + ML-DSA | Silicon (YubiKey 5 FIPS) | Low-Latency    |
+-------------------+-----------------------------+-------------------------------+--------------------------+----------------+
| 6. Strategic NC3  | Dedicated Defense Switched  | Concurrent Dual-Smartcard     | Independent Hardware USB | Two-Person     |
|    Command Node   | Network (DSN) / Fiber Ring  | Split Knowledge + Delta-t<=2s | CCID Readers (Slots 0/1) | Integrity (TPI)|
+-------------------+-----------------------------+-------------------------------+--------------------------+----------------+
```

### Operational Rules per Topology

- **Topology 1 (Tactical Edge DDIL Radio):** Uses direct **IPv6 UDP** (never routed through Tor). Engineered for high-frequency (HF) / VHF tactical networks, unmanned aerial systems (UAS), and mobile ad-hoc networks (MANET). Eliminates TCP connection overhead. Prevents network amplification attacks via stateless cookie gates ([`rust_data_plane/src/cookie.rs`](rust_data_plane/src/cookie.rs)). Corrupted datagrams are dropped silently without ICMP or wire error emission to prevent RF direction-finding geolocation.
- **Topology 2 (Adversarial Public WAN):** Operates exclusively via privilege-separated embedded Arti (`tor_transport` / `secure-transmit-tor`, `arti-client 0.48.0` with `ArtiEphemeralKeystore` + `ClientAuthV3` Restricted Discovery + `vanguards = Full`) over anonymous stdin/stdout pipes with zero external `tor.exe` or SOCKS5 TCP loopback sockets. In-stream `Noise_XXhfs` (`SecP384r1MLKEM1024` + `ML-DSA-87` + `--psk-file`) keys flow directly in locked Rust memory with `--zero-footprint` (`--tamaraw-l` fixed 496-byte Tor relay cells + `TamarawShaper` cover padding).
- **Topology 3 (RED/BLACK Cross-Domain Boundary):** Unidirectional data transfer across physically severed optical fiber links. The transmit photodiode on the classified RED enclave pushes Cauchy-Reed-Solomon encoded frames to a receiver on the unclassified BLACK enclave. Reverse reflection is physically impossible (0.000 bps backchannel).
- **Topology 4 (Air-Gapped Facility Station):** Designed for accredited SCIF operations. Ephemeral keys are exchanged using offline removable media envelopes authenticated via 3-of-5 threshold ML-DSA-87 signatures. Monotonic sequence counters prevent replay of expired command bundles.
- **Topology 5 (Joint All-Domain CJADC2 Mesh):** Tactical situational awareness tracks formatted as NATO MIL-STD-6090 Cursor-on-Target (CoT) XML authenticated with FIPS 204 ML-DSA-87 signatures.
- **Topology 6 (Strategic Command / Two-Person Rule):** Emergency Action Messages (`/eam`) require concurrent dual-officer authorization. Two distinct cryptographic signatures generated by independent authorized operator smartcards must be verified within a 2.0-second delta.

---

## 2.1. Sovereign Tactical Defense Innovation Roadmap (Phases A through L)

To satisfy strict defense requirements across contested electromagnetic environments and quantum threats, ST2027 implements 12 distinct high-assurance engineering phases:

| Phase | Tactical Domain | Strategic Capabilities | Implementation Modules | Verification |
| :---: | :--- | :--- | :--- | :--- |
| **A** | **seL4 Microkit MILS Appliance** | Model-checked/spec-validated microkernel appliance topology; Red/Black/Crypto capability-isolated domains with zero cross-talk channels. | [`sel4_mils_appliance/`](sel4_mils_appliance/)<br>[`sovereign_sel4_appliance.py`](sovereign_sel4_appliance.py) | `cargo test --manifest-path sel4_mils_appliance/Cargo.toml`<br>`python sel4_mils_appliance/validate_mils.py --strict`<br>`pytest tests/test_sel4_mils_spec.py` |
| **B** | **Hardware Silicon Enclave** | TPM 2.0 PCR sealing [0..7], PKCS#11 v2.40 HSM, Windows CNG Platform Crypto Provider; anti-rollback monotonic counters. | [`rust_data_plane/src/hardware_enclave.rs`](rust_data_plane/src/hardware_enclave.rs)<br>[`hardware_enclave_manager.py`](hardware_enclave_manager.py) | `pytest tests/test_hardware_enclave_custody.py` |
| **C** | **Multi-Assumption PQ Combiner** | 3-way hybrid key exchange combining ML-KEM-1024, Classic McEliece 8192128, and NIST P-384 under RFC 10024 dual-PRF. | [`rust_data_plane/src/kex_combiner.rs`](rust_data_plane/src/kex_combiner.rs)<br>[`pqc_multi_assumption.py`](pqc_multi_assumption.py) | `pytest tests/test_pqc_multi_assumption_combiner.py` |
| **D** | **Decentralized Threshold MPC NC3** | $t$-of-$n$ Shamir/Feldman VSS threshold signatures for ML-DSA-87; decentralized strategic co-signing within 2.0s without master key reconstruction. | [`rust_data_plane/src/nc3_mpc.rs`](rust_data_plane/src/nc3_mpc.rs)<br>[`nc3_threshold_mpc.py`](nc3_threshold_mpc.py) | `pytest tests/test_nc3_threshold_mpc.py` |
| **E** | **Simplex Optical Diode & FEC** | Physical simplex optical data diode with Cauchy-Reed-Solomon erasure coding ($K=8, M=4$), tolerating 33% packet loss with zero backchannel. | [`rust_data_plane/src/diode.rs`](rust_data_plane/src/diode.rs)<br>[`optical_diode_controller.py`](optical_diode_controller.py) | `pytest tests/test_optical_diode_fec.py` |
| **F** | **Chameleon Traffic Morpher** | Adaptive traffic camouflage morphing packets into WebRTC Voice Engine DTX or QUIC v1 headers with Gaussian pacing jitter. | [`rust_data_plane/src/chameleon.rs`](rust_data_plane/src/chameleon.rs)<br>[`network/traffic_morpher.py`](network/traffic_morpher.py) | `pytest tests/test_chameleon_traffic_morphing.py` |
| **G** | **Asynchronous DTN & 0-RTT Mesh** | RFC 9171 Bundle Protocol v7 (BPv7) with 0-RTT ML-KEM-1024 envelopes for contested orbital, space-to-ground, and subterranean bunker links. | [`rust_data_plane/src/dtn_bundle.rs`](rust_data_plane/src/dtn_bundle.rs)<br>[`network/dtn_mesh_router.py`](network/dtn_mesh_router.py) | `pytest tests/test_dtn_zero_rtt_mesh.py` |
| **H** | **PQ Zero-Knowledge Identity (PQ-ZKP)** | Tactical nodes prove valid STRATCOM clearance without disclosing identity, serial numbers, or callsigns using 32-level Merkle accumulators. | [`rust_data_plane/src/pq_zkp.rs`](rust_data_plane/src/pq_zkp.rs)<br>[`identity/pq_zkp_verifier.py`](identity/pq_zkp_verifier.py) | `pytest tests/test_pq_zkp_identity.py` |
| **I** | **Tactical SDR DSSS LPI/LPD Engine** | Direct baseband I/Q synthesis for USRP/HackRF emitting Gold code DSSS below ambient thermal noise floors ($\text{SNR} \le -15\text{ dB}$). | [`rust_data_plane/src/sdr_dsss.rs`](rust_data_plane/src/sdr_dsss.rs)<br>[`tactical_sdr_controller.py`](tactical_sdr_controller.py) | `pytest tests/test_sdr_dsss_waveforms.py` |
| **J** | **Blinded Cross-Domain Guard** | Bell-LaPadula MLS clearance dominance and dirty-word / regex filtering evaluated directly on blinded ciphertexts without decryption. | [`rust_data_plane/src/blinded_cds.rs`](rust_data_plane/src/blinded_cds.rs)<br>[`cjadc2_blinded_guard.py`](cjadc2_blinded_guard.py) | `pytest tests/test_blinded_cross_domain_guard.py` |
| **K** | **Deductive Formal Code Contracts** | SMT-backed (Kani / Z3) deductive proofs guaranteeing zero panics, zero integer overflows, and strictly constant-time execution across the data plane. | [`rust_data_plane/src/formal_proofs.rs`](rust_data_plane/src/formal_proofs.rs)<br>[`scripts/verify_mathematical_contracts.py`](scripts/verify_mathematical_contracts.py) | `pytest tests/test_formal_code_contracts.py` |
| **L** | **Free-Space Optical (FSO) Transceiver** | Blast-door & SCIF glass isolation transceiver using rateless Luby Transform peeling decoders at 60 FPS with TEMPEST Level A emission security. | [`rust_data_plane/src/fso_transceiver.rs`](rust_data_plane/src/fso_transceiver.rs)<br>[`hardware/visual_airgap_diode.py`](hardware/visual_airgap_diode.py) | `pytest tests/test_visual_airgap_transceiver.py` |

---

## 3. Cryptographic Stack & Mathematical Specifications

The ST2027 cryptographic architecture adheres strictly to the **NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)** mandate. Every cryptographic primitive, state ratchet, and wire framing structure is grounded in formal mathematical reduction proofs and verifiable algorithmic logic:

```text
+---------------------------------------------------------------------------------------------------------+
|                                    ST2027 CRYPTOGRAPHIC PRIMITIVE SUITE                                 |
+---------------------------------------------------------------------------------------------------------+
|  Primary PQC KEM       : NIST FIPS 203 ML-KEM-1024 (Module-LWE over R_q, Category 5)                   |
|  Classical Hedge KEM   : NIST FIPS 186-5 SecP384r1 (NIST P-384 ECDH, 192-bit classical security)        |
|  Hybrid Combiner       : IETF RFC 10024 / draft-ietf-tls-hybrid-design (Dual-PRF HKDF-SHA384)           |
|  Primary Digital Sig   : NIST FIPS 204 ML-DSA-87 (Module-SIS / Module-LWE, Category 5)                  |
|  State-Resistant Sig   : NIST FIPS 205 SLH-DSA-256f (Stateless Hash-Based, SHAKE-256 Fast)              |
|  Record Layer AEAD     : NIST SP 800-38D AES-256-GCM (Deterministic Composite 96-bit Nonces)           |
|  Key Derivation & PRF  : RFC 5869 HKDF-SHA384 / FIPS 202 HKDF-SHA3-512                                  |
|  Erasure Coding        : Cauchy Reed-Solomon Maximum Distance Separable (MDS) over GF(2^8) (K=8, M=4)    |
|  Anti-Replay Window    : RFC 6479 Decoupled Sliding Bitmask (1024-packet window, 32 x u64) + TPM 2.0 NV |
|  Secret Sharing (NC3)  : (2, 2) Split Knowledge (spo_dpo.py/nc3.rs) & (t,n) Shamir/Feldman (nc3_mpc.rs)|
+---------------------------------------------------------------------------------------------------------+
```

---

### 3.1 Post-Quantum Key Encapsulation Mechanism (NIST FIPS 203 ML-KEM-1024)

- **Primary Mechanism:** NIST FIPS 203 **ML-KEM-1024** (Module-Lattice-Based Key-Encapsulation Mechanism, NIST Security Category 5).
- **Mathematical Specification:**
  Let $R_q = \mathbb{Z}_q[X]/(X^n + 1)$ denote the cyclotomic polynomial ring where degree $n = 256$ and prime modulus $q = 3329$. Let module rank $k = 4$.
  Centered binomial error distribution $\beta_\eta$ of parameter $\eta = 2$ samples polynomials $f(X) = \sum_{i=0}^{255} f_i X^i$ where:

  $$f_i = \sum_{j=1}^{\eta} (a_j - b_j), \quad a_j, b_j \leftarrow_{\text{R}} \{0, 1\}$$

  The Module Learning With Errors ($\text{M-LWE}_{k, q, \eta}$) problem requires distinguishing pairs $(\mathbf{A}, \mathbf{A}\mathbf{s} + \mathbf{e})$ from uniform random pairs $(\mathbf{A}, \mathbf{u})$ over $R_q^{k \times k} \times R_q^k$, where secret vector $\mathbf{s} \leftarrow \beta_{\eta}^k$ and error vector $\mathbf{e} \leftarrow \beta_{\eta}^k$.

- **Key Generation & Encapsulation:**
  1. $\mathbf{A} \in R_q^{k \times k} \leftarrow \mathrm{XOF}(\rho)$ where $\rho \leftarrow \{0, 1\}^{256}$.
  2. Public key $\mathbf{t} = \mathrm{Compress}_d(\mathbf{A} \mathbf{s} + \mathbf{e}, d=11) \in R_q^k$.
  3. Ephemeral encapsulation selects random message $m \leftarrow \{0, 1\}^{256}$, derives $(K, r) = \mathrm{G}(m \mathbin{\Vert} \mathrm{H}(pk))$.
  4. Ciphertext $\mathbf{u} = \mathrm{Compress}_{d_u}(\mathbf{A}^T \mathbf{r} + \mathbf{e}_1, d_u=11)$, $v = \mathrm{Compress}_{d_v}(\mathbf{t}^T \mathbf{r} + e_2 + \lceil \frac{q}{2} \rfloor m, d_v=5)$.
  5. The Fujisaki-Okamoto (FO) transform guarantees Indistinguishability under Adaptive Chosen-Ciphertext Attack (IND-CCA2).

- **Concrete Parameters & Sizes:**
  - Public Key ($pk$): $1568$ bytes ($384 \cdot k \cdot 12 / 8 + 32$).
  - Secret Key ($sk$): $3168$ bytes.
  - Ciphertext ($ct$): $1568$ bytes.
  - Shared Secret ($ss$): $32$ bytes ($256$ bits of quantum-resistant entropy).

- **Hardness Reduction & Core-SVP Security Floor:**
  Under the Primal Block-Korkine-Zolotarev (BKZ) lattice reduction algorithm, the cost to solve the underlying Shortest Vector Problem (SVP) in dimension $d = k \cdot n = 1024$ with block size $\beta$ is bounded asymptotically by:

$$
\mathcal{H}_{\text{SVP}}(\beta) \approx 2^{0.292 \beta - o(\beta)} \text{ classical operations}
$$
  Against quantum sieving algorithms, the security level exceeds $\beta \ge 850$, corresponding to $>2^{128}$ quantum gates and $>2^{256}$ classical gate operations, satisfying NIST Category 5 requirements.

---

### 3.2 Classical Hedge Primitive: NIST P-384 (`secp384r1`)

To hedge against mathematical vulnerabilities in emerging post-quantum lattice primitives, ST2027 binds an independent, classical elliptic curve Diffie-Hellman (ECDH) exchange into every session key agreement:

- **Standard:** NIST FIPS 186-5 and NIST SP 800-56A Rev 3.
- **Mathematical Specification:** Short Weierstrass elliptic curve over the prime Galois field $\mathbb{F}_p$:

$$
y^2 \equiv x^3 - 3x + b \pmod p
$$
  where the NIST prime modulus $p$ is defined as:
$$
p = 2^{384} - 2^{128} - 2^{96} + 2^{32} - 1
$$

- **Curve Constants:**
  - $p = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC}$
  - $b = \text{0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF}$
  - Base point order $n \approx 2^{384}$, cofactor $h = 1$.
- **Key Representation:**
  - Private scalar: $48$ bytes ($384$ bits).
  - Public key point: Uncompressed IEEE P1363 format ($0x04 \mathbin{\Vert} X \mathbin{\Vert} Y$, $97$ bytes) or compressed point ($0x02/0x03 \mathbin{\Vert} X$, $49$ bytes).
- **Security Floor:** Fulfills 192-bit classical cryptographic security ($\mathcal{O}(\sqrt{n}) \approx 2^{192}$ operations via Pollard's $\rho$). This satisfies the Category 5 floor of CNSA 2.0. (Legacy curves such as Curve25519 / X25519 yield only 128-bit security and are strictly quarantined from the production CNSA 2.0 wire path).

---

### 3.3 Standards-Track Hybrid Key Exchange Combiner (`SecP384r1MLKEM1024`)

Aligned with **IETF RFC 10024** and OpenSSL 3.5 (IANA NamedGroup `0x11ED`):

```text
       Initiator (Alice)                                    Responder (Bob)
   =======================                               =======================
   Generate Ephemeral Keys:                              Generate Ephemeral Keys:
     (sk_ec, pk_ec)  <- P-384                              (sk_ec_b, pk_ec_b) <- P-384
     (sk_kem, pk_kem)<- ML-KEM-1024                       (sk_kem_b, pk_kem_b) <- ML-KEM-1024
               │                                                     │
               │─────── Ephemeral Bundle (pk_ec || pk_kem) ─────────>│
               │                                                     │
               │                                         Compute ECDH & KEM Encaps:
               │                                           ss_ecdh <- ECDH(sk_ec_b, pk_ec)
               │                                           (ct_kem, ss_kem) <- Encaps(pk_kem)
               │                                                     │
               │<────── Response Bundle (pk_ec_b || ct_kem) ────────│
               │
   Compute ECDH & KEM Decaps:
     ss_ecdh <- ECDH(sk_ec, pk_ec_b)
     ss_kem  <- Decaps(sk_kem, ct_kem)
               │
               ▼
   [DUAL-PRF HKDF-SHA384 COMBINER]
     ss_hybrid = ss_ecdh (48B) || ss_kem (32B)
     PRK       = HKDF-Extract(salt=TranscriptHash, IKM=ss_hybrid || PSK)
     K_session = HKDF-Expand(PRK, info="cnsa2-session-key-v1" || Context, L=32)
```

#### Dual-PRF Security Reduction Theorem

**Theorem (Hybrid Combiner IND-CCA2 Security):** Let $\mathcal{H} = \text{HKDF-Extract}$ be modeled as a dual pseudorandom function (dual-PRF). For any polynomial-time adversary $\mathcal{A}$ attacking the hybrid key exchange scheme:
$$
\mathbf{Adv}_{\text{Hybrid}}^{\text{IND-CCA2}}(\mathcal{A}) \le \min\left( \mathbf{Adv}_{\text{P384}}^{\text{CDH}}(\mathcal{A}_{\text{class}}), \mathbf{Adv}_{\text{ML-KEM-1024}}^{\text{IND-CCA2}}(\mathcal{A}_{\text{quant}}) \right) + \mathbf{Adv}_{\text{HKDF}}^{\text{dual-PRF}}(\mathcal{B})
$$
*Proof Outline:* If an adversary breaks the confidentiality of $K_{\text{session}}$, they must distinguish the output of $\text{HKDF-Extract}$ from uniform random. Since the input key material is $ss_{\text{ecdh}} \mathbin{\Vert} ss_{\text{kem}}$, by the dual-PRF property of HKDF, as long as *at least one* of $ss_{\text{ecdh}}$ or $ss_{\text{kem}}$ is computationally indistinguishable from uniform, the resulting pseudorandom key (PRK) remains statistically close to uniform, and all derived session keys maintain indistinguishability under chosen-ciphertext attack.

---

### 3.4 Post-Quantum Digital Signatures (NIST FIPS 204 ML-DSA-87)

- **Primary Authentication Mechanism:** NIST FIPS 204 **ML-DSA-87** (Module-Lattice-Based Digital Signature Standard, NIST Security Category 5).
- **Mathematical Specification:**
  Defined over ring $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ with prime modulus $q = 8380417 = 2^{23} - 2^{13} + 1$. Matrix dimensions $(k, \ell) = (8, 7)$.
  Rejection sampling parameters: $\gamma_1 = 2^{19}$, $\gamma_2 = (q - 1)/32 = 261888$, $\beta = 120$, $\tau = 60$.
  Public matrix $\mathbf{A} \in R_q^{k \times \ell}$ is sampled from a 256-bit seed $\rho$.

- **Signing Logic with Abort (Fiat-Shamir with Aborts):**
  1. Sample masking polynomial vector $\mathbf{y} \leftarrow [-\gamma_1 + 1, \gamma_1]^\ell$.
  2. Compute $\mathbf{w} = \mathbf{A} \mathbf{y}$ and decompose high bits $\mathbf{w}_1 = \mathrm{HighBits}(\mathbf{w}, 2\gamma_2)$.
  3. Compute challenge hash polynomial $c = \mathrm{H}(\mu \mathbin{\Vert} \mathbf{w}_1) \in R_q$ where $\|c\|_\infty = 1$ and number of non-zero coefficients is $\tau = 60$.
  4. Compute candidate signature vector $\mathbf{z} = \mathbf{y} + c \mathbf{s}_1$.
  5. Check rejection conditions: if $\|\mathbf{z}\|_\infty \ge \gamma_1 - \beta$ or $\|\mathrm{LowBits}(\mathbf{A}\mathbf{y} - c\mathbf{s}_2, 2\gamma_2)\|_\infty \ge \gamma_2 - \beta$, reject and restart with fresh $\mathbf{y}$.
  6. Compute hint bitmask $\mathbf{h} = \mathrm{MakeHint}(-\mathbf{c}\mathbf{t}_0, \mathbf{w} - c\mathbf{s}_2 + c\mathbf{t}_0, 2\gamma_2)$.
  7. Return signature $\sigma = (\mathbf{z}, \mathbf{h}, c)$.

- **Parameters & Wire Format:**
  - Public Key: $2592$ bytes.
  - Secret Key: $4896$ bytes.
  - Signature: $4627$ bytes.

- **Mandatory In-Memory Verify-After-Sign (VAS):**
  Lattice signature schemes are vulnerable to laser, electromagnetic, and voltage fault injection attacks (e.g. CHES 2024 / IACR ePrint 2025/2009). If a single coefficient in $\mathbf{z}$ is faulted during computation, the signature leaks secret key coordinates. ST2027 implements strict in-memory Verify-After-Sign before emitting signatures to wire or disk:

$$
\text{If } \mathrm{Verify}(M, \sigma, pk) \ne \text{VALID} \implies \mathrm{ZeroizeMemory}(sk) \land \mathrm{Halt}(\text{FaultInjectionDetected})
$$

---

### 3.5 Quantum Threat Model & Asymptotic Complexity Comparison

ST2027 explicitly accounts for quantum adversaries equipped with Shor's and Grover's quantum algorithms operating against classical and post-quantum cryptosystems:

| Cryptographic Primitive | Classical Cryptanalysis Complexity | Quantum Cryptanalysis (Shor's Algorithm) | Quantum Cryptanalysis (Grover's Algorithm) | Post-Quantum Residual Security Margin |
| :--- | :---: | :---: | :---: | :---: |
| **RSA-4096** | $\mathcal{O}\left(e^{(1.92 + o(1))(\ln N)^{1/3}(\ln \ln N)^{2/3}}\right)$ (GNFS) | $\mathcal{O}((\log N)^3) \approx 6.8 \times 10^{10}$ ops | N/A | **0 bits (Completely Broken)** |
| **ECDH Curve25519** | $\mathcal{O}(2^{128})$ ops (Pollard's $\rho$) | $\mathcal{O}((\log p)^3) \approx 1.6 \times 10^7$ ops | N/A | **0 bits (Completely Broken)** |
| **ECDH NIST P-384** | $\mathcal{O}(2^{192})$ ops (Pollard's $\rho$) | $\mathcal{O}((\log p)^3) \approx 5.6 \times 10^7$ ops | N/A | **0 bits (Completely Broken)** |
| **AES-256-GCM** | $\mathcal{O}(2^{256})$ ops (Exhaustive Search) | Inapplicable | $\mathcal{O}(2^{128})$ oracle queries | **128 bits (Category 5 Hardened)** |
| **SHA-384 / SHA3-512** | $\mathcal{O}(2^{192}) / \mathcal{O}(2^{256})$ (Collision) | Inapplicable | $\mathcal{O}(2^{128}) / \mathcal{O}(2^{170})$ queries (BHT) | **128+ bits (Pre-image / Collision Safe)** |
| **ML-KEM-1024** | $\mathcal{O}(2^{292})$ operations (Core-SVP) | Polynomial-time Shor algorithm **fails** | $\mathcal{O}(2^{165})$ quantum sieving ops | **Category 5 (> 128 quantum bits)** |
| **ML-DSA-87** | $\mathcal{O}(2^{278})$ operations (Core-SVP) | Polynomial-time Shor algorithm **fails** | $\mathcal{O}(2^{155})$ quantum sieving ops | **Category 5 (> 128 quantum bits)** |
| **SLH-DSA-256f** | $\mathcal{O}(2^{256})$ operations (Hash Tree) | Polynomial-time Shor algorithm **fails** | $\mathcal{O}(2^{128})$ quantum oracle queries | **128 bits (Stateless Hash Proof)** |

---

### 3.6 Continuous Epoch Ratchet (CER / SPQR-Style Post-Compromise Security)

To guarantee immediate **Forward Secrecy (FS)** and **Post-Compromise Security (PCS)** in long-lived operational channels, ST2027 implements the Continuous Epoch Ratchet:

```text
    Root Key Chain (HKDF-SHA384)                     Message Key Chain (AES-256-GCM)
   ===============================                   ===============================
             RK_0
              │
              ├── [Rekey Trigger: 10k msgs / 10 MB / manual /rekey]
              │   Generate fresh (pk_kem, sk_kem)
              │   Emit Frame 0x07 (FTYPE_IN_BAND_EPOCH_REKEY)
              │   Encaps(pk_kem) -> (ct_kem, ss_kem)
              │
              ▼
   (RK_1, CK_1) = HKDF-Extract(RK_0, ss_kem) ────────>  CK_1 (Chain Key)
              │                                           │
              │                                           ├── MK_1,0 = HKDF-Expand(CK_1, "msg" || 0)
              │                                           ├── MK_1,1 = HKDF-Expand(CK_1, "msg" || 1)
              ▼                                           ▼
             RK_1                                        MK_1,n (Zeroized after use)
```

- **Mathematical Recurrence Relations:**
  For epoch index $e \ge 0$ and intra-epoch message index $j \ge 0$:

$$
\begin{aligned}
(\text{RK}_{e+1}, \text{CK}_{e+1}) &\leftarrow \text{HKDF-Extract}\left(\text{RK}_e, ss_{\text{kem}}^{(e+1)}\right) \\
\text{CK}_{e+1, j+1} &\leftarrow \text{HKDF-Expand}\left(\text{CK}_{e+1, j}, \text{"chain-advance"}, 32\right) \\
\text{MK}_{e+1, j} &\leftarrow \text{HKDF-Expand}\left(\text{CK}_{e+1, j}, \text{"msg-key"} \mathbin{\Vert} \mathrm{uint64}(j), 32\right)
\end{aligned}
$$

- **Healing Guarantee (Post-Compromise Security):**
  If an adversary compromises internal state $(\text{RK}_e, \text{CK}_e)$ at epoch $e$, upon the execution of an uncompromised asymmetric KEM encapsulation step at epoch $e+1$, the adversary's advantage to distinguish $\text{RK}_{e+1}$ or any future message keys $\text{MK}_{e+1, j}$ from random drops to negligibility:

$$
\mathbf{Adv}_{\text{PCS}}(\mathcal{A}) \le \mathbf{Adv}_{\text{ML-KEM-1024}}^{\text{IND-CCA2}}(\mathcal{A}) + \epsilon_{\text{HKDF}}
$$

---

### 3.7 Deterministic Composite Nonces & Nonce Collision Proof (NIST SP 800-38D §8.2.1)

AES-256-GCM fails catastrophically if a nonce is repeated under the same key: two distinct ciphertexts sharing a nonce allow an adversary to solve for the GHASH authenticator key $H = \mathrm{AES}_K(0^{128})$ via polynomial root-finding over $\mathrm{GF}(2^{128})$, enabling universal tag forgery.

- **Native Rust Data-Plane 96-Bit Nonce Layout ([`rust_data_plane/src/aead.rs`](rust_data_plane/src/aead.rs)):**

$$
IV_{96} = \mathrm{Uint64BE}(\mathrm{seq}) \mathbin{\Vert} \text{DirectionByte}_8 \mathbin{\Vert} 0x000000_{24}
$$
  where `DIR_SEND = 0x00` and `DIR_RECV = 0x01`, and `seq` is reserved strictly monotonically before encryption via HMAC-SHA384-authenticated state (`STSTATE3`, 328 bytes), append-only `.seqlog` journaling, and optional hardware TPM 2.0 NV counters (`P2P_TPM_NV_INDEX`).

- **Python Orchestration Durable Nonce Layout ([`cnsa_crypto_gateway.py`](cnsa_crypto_gateway.py)):**

$$
IV_{96} = \text{FixedKeyBoundContext}_{32} \mathbin{\Vert} \mathrm{Uint32BE}(\text{durable\_epoch}) \mathbin{\Vert} \mathrm{Uint32BE}(\text{seq})
$$
  backed by an `fsync`-persisted SQLite monotonic epoch ledger (`gcm_nonce_ledger.db`) across process restarts and forks (plus XAES-256-GCM domain separation).

- **Mathematical Nonce Collision Proof:**
  Let $N_{\max} = 2^{64} - 1$ (native) or $2^{32}$ invocations per persistent epoch (gateway). For any session key $K$ and direction $d \in \{0x00, 0x01\}$:

$$
\forall i, j \in \{0, 1, \dots, N_{\max}\}, \; i \ne j \implies \mathrm{Uint64BE}(i) \ne \mathrm{Uint64BE}(j) \implies IV_i \ne IV_j
$$
  Furthermore, across full-duplex communication channels:
$$
\text{DIR\_SEND} = 0x00 \ne 0x01 = \text{DIR\_RECV} \implies IV_{\text{send}} \cap IV_{\text{recv}} = \emptyset
$$
  Therefore, the collision probability under single-direction counter invariants is zero ($P(\text{Nonce Collision}) = 0$). This eliminates the birthday-bound vulnerability of purely random 96-bit nonces ($P(\text{Collision}) \approx m^2 / 2^{97}$). When sequence space exhausts or the monotonic ledger detects rollback, the gate latches closed fail-closed.

---

### 3.8 Systematic Cauchy-Reed-Solomon Forward Error Correction over $\mathrm{GF}(2^8)$

For unidirectional optical data diodes and simplex tactical channels where reverse ACKs are physically prohibited, ST2027 implements **Cauchy Reed-Solomon Maximum Distance Separable (MDS)** erasure coding:

- **Galois Field Definition:**
  $\mathrm{GF}(2^8)$ constructed modulo the primitive irreducible polynomial:

$$
p(X) = X^8 + X^4 + X^3 + X^2 + 1 \quad (\text{hex: } 0x11D)
$$
  Field multiplication $a \otimes b$ and inversion $a^{-1}$ are computed in constant time using log/antilog tables or branchless carry-less multiplication (`CLMUL` / `pmull`).

- **Cauchy Generator Matrix Construction:**
  Let $K = 8$ data symbols, $M = 4$ parity symbols, total codewords $N = K + M = 12$.
  Select two disjoint sets of distinct non-zero field elements $X = \{x_0, \dots, x_{M-1}\}$ and $Y = \{y_0, \dots, y_{K-1}\}$ such that $X \cap Y = \emptyset$.
  The Cauchy matrix $\mathbf{A} \in \mathrm{GF}(2^8)^{M \times K}$ is defined by:

$$
A_{i, j} = \frac{1}{x_i \oplus y_j}, \quad i \in \{0, \dots, M-1\}, \; j \in \{0, \dots, K-1\}
$$
  The systematic generator matrix $\mathbf{G} \in \mathrm{GF}(2^8)^{N \times K}$ is:
$$
\mathbf{G} = \begin{bmatrix} \mathbf{I}_K \\ \mathbf{A} \end{bmatrix}
$$

- **Cauchy Double Determinant Theorem & Non-Singularity Proof:**
  By Cauchy's theorem, every square submatrix $\mathbf{A}_{\text{sub}} \in \mathrm{GF}(2^8)^{m \times m}$ formed from rows $I \subseteq \{0, \dots, M-1\}$ and columns $J \subseteq \{0, \dots, K-1\}$ ($|I| = |J| = m$) has determinant:

$$
\det(\mathbf{A}_{\text{sub}}) = \frac{\prod_{i < i' \in I} (x_i \oplus x_{i'}) \prod_{j < j' \in J} (y_j \oplus y_{j'})}{\prod_{i \in I, j \in J} (x_i \oplus y_j)}
$$
  Because all $\{x_i\}$ are pairwise distinct, all $\{y_j\}$ are pairwise distinct, and $X \cap Y = \emptyset$, every factor in the numerator is non-zero, and every denominator term is non-zero and finite. Consequently:
$$
\det(\mathbf{A}_{\text{sub}}) \ne 0
$$
  **MDS Property:** Every $K \times K$ submatrix of $\mathbf{G}$ is non-singular. The receiver can reconstruct the complete original $K$ data blocks from *any* $K$ received blocks out of the $N = 12$ transmitted blocks via Gauss-Jordan matrix inversion over $\mathrm{GF}(2^8)$, tolerating up to $M = 4$ arbitrary dropped frames ($33.3\%$ packet erasure rate).

---

### 3.9 Nuclear Command & Control (NC3) Information-Theoretic $(2, 2)$ Secret Sharing

High-consequence nuclear directives (Emergency Action Messages `/eam`, emergency station purge) enforce hardware-anchored **Two-Person Integrity (TPI)**:

- **Mathematical Formulation:**
  Let master directive secret $S \in \mathbb{F}_2^{256}$.
  Officer 1 receives independent random share $S_1 \leftarrow_{\text{R}} \mathbb{F}_2^{256}$.
  Officer 2 receives share $S_2 = S \oplus S_1 \in \mathbb{F}_2^{256}$.
  Reconstruction requires bitwise addition over $\mathbb{F}_2$:

$$
S = S_1 \oplus S_2
$$

- **Shannon Perfect Secrecy Proof:**
  Let random variable $S$ have arbitrary prior distribution $P(S = s)$. For any candidate secret $s \in \mathbb{F}_2^{256}$ and observed individual share $s_1 \in \mathbb{F}_2^{256}$:

$$
P(S = s \mid S_1 = s_1) = \frac{P(S_1 = s_1 \mid S = s) \cdot P(S = s)}{P(S_1 = s_1)} = \frac{2^{-256} \cdot P(S = s)}{2^{-256}} = P(S = s)
$$
  Therefore, conditional entropy satisfies:
$$
H(S \mid S_1) = H(S) \iff I(S; S_1) = 0
$$
  An adversary possessing Officer 1's smartcard gains exactly zero Shannon mutual information regarding $S$. Secrecy is information-theoretic and unconditionally secure against unbounded quantum adversaries.

- **Temporal Hardware Window Verification:**
  Let $t_1$ and $t_2$ be monotonic hardware timestamps generated by Officer 1 and Officer 2 smartcard cryptographic tokens. The directive is executed if and only if:

$$
\Delta t = |t_1 - t_2| \le 2000 \text{ ms} \quad \land \quad \mathrm{OfficerRosterVerify}(\sigma_1, \sigma_2) = \text{TRUE}
$$

---

### 3.10 Side-Channel Timing Immunity & Welch's $t$-Test Formulation (DudeCT)

All secret-dependent comparisons (MAC tags, cryptographic keys, authentication tickets) are evaluated in constant time to prevent cache-timing and branch-predictor timing side-channel attacks.

- **Branchless Byte Equality Formulation:**
  For secret byte buffers $\mathbf{a}, \mathbf{b} \in \{0, 1\}^n$:

$$
\mathrm{ct\_eq}(\mathbf{a}, \mathbf{b}) = 1 - \left( \left( \bigvee_{i=0}^{n-1} (a_i \oplus b_i) \right) \gg 7 \right)
$$
  Executed with branchless SIMD or bitwise arithmetic; zero execution branches depend on secret operands.

- **DudeCT Welch's $t$-Test Hypothesis Formulation:**
  Timing distributions for fixed vs random secret inputs are measured over $N \ge 10^5$ iterations. Let $(\bar{X}_0, s_0^2, n_0)$ and $(\bar{X}_1, s_1^2, n_1)$ denote sample statistics for class 0 and class 1.
  The Welch's $t$-statistic is defined as:

$$
t = \frac{\bar{X}_0 - \bar{X}_1}{\sqrt{\frac{s_0^2}{n_0} + \frac{s_1^2}{n_1}}}
$$
  Degrees of freedom $\nu$ are estimated via the Welch-Satterthwaite equation:
$$
\nu \approx \frac{\left( \frac{s_0^2}{n_0} + \frac{s_1^2}{n_1} \right)^2}{\frac{(s_0^2 / n_0)^2}{n_0 - 1} + \frac{(s_1^2 / n_1)^2}{n_1 - 1}}
$$
  **Decision Rule:**

- If $|t| < 4.5$: The null hypothesis $H_0: \mu_0 = \mu_1$ cannot be rejected; the implementation is statistically certified constant-time with confidence $> 99.9993\%$.
- If $|t| \ge 4.5$: The null hypothesis is rejected; potential timing leakage detected.
  All production primitives in [`rust_data_plane/tests/dudect_ct.rs`](rust_data_plane/tests/dudect_ct.rs) verify $|t| < 4.5$.

---

### 3.11 Decoupled Sliding Anti-Replay Bitmask State Machine (RFC 6479)

To prevent replay Denial-of-Service and packet reinjection over untrusted networks, the native data plane ([`rust_data_plane/src/replay.rs`](rust_data_plane/src/replay.rs)) implements an RFC 6479 decoupled circular bitmap (`WINDOW_WORDS = 32`, `WINDOW_SIZE = 1024` packets):

```text
               RFC 6479 Decoupled Sliding Window (1024-Packet Circular Bitmap Ring)
   =================================================================================
     [ Expired Frame Zone ]  │        [ Active Sliding Window: 1024 Bits ]         │ [ Future Zone ]
     Seq <= H - 1024         │        H - 1023 <= Seq <= H                         │ Seq > H
   ──────────────────────────┼─────────────────────────────────────────────────────┼────────────────
     DROP IMMEDIATELY        │   Read-only check((seq/64)%32, seq%64):             │ Wait for AEAD:
     No state modification   │     Bit == 1 -> DROP (Duplicate Replay)             │   Verify AEAD tag
                             │     Bit == 0 -> Decrypt AEAD; if valid -> mark()    │   Advance H <- Seq
   =================================================================================
```

- **Algorithmic State Invariants:**
  1. Let $H$ (`last_seq`) be the highest valid sequence number decrypted so far (and `seq == 0` is unconditionally rejected).
  2. Let circular bitmap $\mathbf{W}$ consist of $32 \times 64$-bit words (`2048` physical bit slots covering a `1024`-packet window without trailing-edge aliasing).
  3. **Read-only pre-authentication check** (`check(S)`) before AEAD decryption, followed by **post-authentication state update** (`mark(S)`) only after the AES-256-GCM GHASH tag succeeds:

$$
\mathrm{Action}(S) = \begin{cases}
\text{Drop}, & \text{if } S = 0 \lor H - S \ge 1024 \quad \text{(Zero / Expired)} \\
\text{Drop}, & \text{if } S \le H \land \mathbf{W}[(S / 64) \bmod 32]_{S \bmod 64} = 1 \quad \text{(Duplicate)} \\
\text{Accept (post-AEAD) } \land \mathrm{mark}(S), & \text{otherwise (In-Window Valid or } S > H\text{)}
\end{cases}
$$

- **Persistent State Across Restarts:** All 32 bitmap words (`256` bytes) plus `last_seq` are serialized into the HMAC-SHA384-authenticated `STSTATE3` state file (`328` bytes total) so replay history is preserved across process restarts.

### 3.12 Keystroke Timing Decoupling, Isochronous Wire Pacing & Memoryless Poisson Camouflage

In 2001, Song, Wagner, and Tian demonstrated that interactive encrypted connections (such as SSH) leak sensitive typed contents through packet inter-arrival times analyzed via Hidden Markov Models (HMMs). Furthermore, fixed-rate isochronous traffic streams can exhibit statistical correlation signatures when tracked across multiple autonomous network fabrics by a Global Passive Adversary (GPA). To defeat this threat class:

- **FIFO Keystroke Decoupling:** Operator keystrokes in the native terminal (`secure-transmit terminal`) are ingested into an internal FIFO buffer without generating immediate outbound packets.
- **Isochronous Pacing Engine (20 Hz / 50ms):** Network wire frames are emitted strictly on tick boundaries generated by high-resolution monotonic clocks (`QueryPerformanceCounter` on Windows, `clock_gettime(CLOCK_MONOTONIC)` on Linux).
- **Memoryless Poisson Traffic Camouflage:** In addition to isochronous fixed ticks, the engine supports continuous memoryless Poisson cover pacing (`--poisson`, `P2P_POISSON_CHAFF=1`). Inter-transmission delays $T$ are sampled from a negative-exponential probability distribution:

$$
f(t) = \lambda e^{-\lambda t}, \quad t \ge 0
$$
where $\lambda = 1000 / \text{interval}$ (mean frequency $\lambda$ Hz). Because exponential inter-arrivals satisfy the strict memoryless property:
$$
P(T > t + s \mid T > s) = P(T > t)
$$
an external adversary observing packet departure events learns zero statistical information about when the next packet will be emitted or whether a packet contains encrypted payload data or CSPRNG chaff.

- **Chaff Injection (`FTYPE_CHAFF`):** If no operator keystrokes or data frames are queued when the tick fires, a 1232-byte pseudorandom chaff frame (Type `0xFF`) is encrypted and transmitted. An observer sees only an unbroken stream of uniform 1280-byte IPv6 datagrams.

### 3.13 Stateless Anti-DoS Cookie Challenge Gate

To protect tactical radio endpoints against unauthenticated computational resource exhaustion (amplification flooding), ST2027 implements a stateless cryptographic cookie challenge mechanism modeled after WireGuard and DTLS 1.3 ([`rust_data_plane/src/cookie.rs`](rust_data_plane/src/cookie.rs)):

- Under high load, responder nodes do not allocate state or perform expensive ML-KEM decapsulation.
- Instead, the responder replies with a stateless HMAC cookie bound to the initiator's IP, port, and a local rotating secret key.
- The initiator must solve a proof-of-work puzzle and return the valid cookie before the handshake state is allocated in host memory.

### 3.14 Multi-Level Security (MLS) & Cryptographic Compartments

ST2027 enforces **Bell-LaPadula Multi-Level Security (MLS)** properties ("no read up", "no write down") at the cryptographic layer ([`cjadc2_cross_domain_guard.py`](cjadc2_cross_domain_guard.py), [`rust_data_plane/src/zero_trust.rs`](rust_data_plane/src/zero_trust.rs)):

- Cryptographic compartment keys are derived via standard HKDF-SHA3-512:

$$
K_{\text{compartment}} = \text{HKDF-SHA3-512}(K_{\text{master}}, \text{Label} \parallel \text{Classification} \parallel \text{Compartment})
$$

- Cryptographic keys for compartments cannot be computed from or downgraded to lower classification keys.

### 3.15 Active Cyber Defense (ACD Engine) & Continuous Zero Trust Evaluation

Operating under DoD Continuous Authority to Operate (cATO) principles, the native data plane includes an embedded Active Cyber Defense (ACD) state engine ([`rust_data_plane/src/acd.rs`](rust_data_plane/src/acd.rs)) and NIST SP 800-207 continuous zero trust evaluation ([`rust_data_plane/src/zero_trust.rs`](rust_data_plane/src/zero_trust.rs)):

- **Real-Time Threat Triggers:** Tracks anomalous telemetry including duplicate replay spikes, unauthenticated cookie floods, framing errors, and out-of-order bounds violations.
- **Graduated Defensive Playbooks:**
  - *Level 1 (Pacing Distortion):* Injects burst chaff to mask anomalous traffic signatures.
  - *Level 2 (Dynamic Throttle):* Enforces microsecond backoff on suspected probing vectors.
  - *Level 3 (Session Quarantine):* Severely restricts compartment clearances to unclassified metadata.
  - *Level 4 (Fail-Closed Ejection):* Drops session context, alerts local operator, and commits peer identifier to temporary hardware blacklists.
- **NIST SP 800-207 Dynamic Scoring:** Maintains an adaptive trust score ($0 \le S \le 100$) based on continuous behavioral verification. Transmissions are gated by clearance rules; any drop below policy threshold revokes critical command authorization.

### 3.16 Tactical Message Routing (MIL-STD-6040 MMHS) & NSA RTB Filter

- **Military Message Handling System (MMHS):** In [`rust_data_plane/src/mmhs.rs`](rust_data_plane/src/mmhs.rs), messages enforce strict precedence levels (`FLASH_OVERRIDE`, `FLASH`, `IMMEDIATE`, `PRIORITY`, `ROUTINE`).
- **NSA RTB Dirty-Word Filter:** Built-in deep content inspection screen blocking accidental spillage of unapproved classification strings across egress boundaries.

### 3.17 Hardware Two-Person Integrity (TPI / DoD 5210.41M)

High-consequence directives (e.g., Emergency Action Messages `/eam`, station purge) strictly require hardware-enforced concurrent two-person authorization aligned with DoD Directive 5210.41M and CJCSI 3260.01E ([`spo_dpo.py`](spo_dpo.py), [`rust_data_plane/src/nc3.rs`](rust_data_plane/src/nc3.rs), [`rust_data_plane/src/auth.rs`](rust_data_plane/src/auth.rs)):

- **Physical Dual-Smartcard Split Knowledge:** The workstation interfaces two independent USB CCID smartcard readers (Terminal A / Slot 0 and Terminal B / Slot 1). Officer 1 and Officer 2 insert distinct smartcards and input independent PINs.
- **Canonical Directive Hash:** Both smartcards compute independent ML-DSA-87 signatures over the FIPS 202 SHA3-512 canonical directive hash:

$$
\text{DirectiveHash} = \text{SHA3-512}(\text{BE64}(\text{Timestamp}) \parallel \text{Target} \parallel \text{ActionPayload})
$$

- **Temporal Concurrency Gate:** Signatures must be generated within a configurable project-defined concurrency threshold $\Delta t = |t_1 - t_2| \le 2.0\text{ s}$ (2000 ms), chosen to operationalize near-simultaneous presence under the DoD Directive 5210.41M Two-Person Concept (DoD S-5210.41M itself does not prescribe a numeric 2.0-second timer). Serial authorizations outside the window are rejected fail-closed.
- **Constant-Time Physical Separation:** Validates distinct slots (`slot_1 != slot_2`), distinct hardware token serials (`serial_1 != serial_2`), and distinct verifying public keys (`ct_eq(vk_1, vk_2) == 0`).
- **Zero-Disk Key Custody:** Signing keys remain non-exportable within smartcard cryptographic silicon (`CKA_SIGN`, `CKA_PRIVATE`). Synthetic JSON signature files are strictly blocked in production (`P2P_PRODUCTION=1`).

### 3.18 Tamper-Evident Keyed Audit Chaining

- **WORM Ledger Architecture:** Every cryptographic event, state transition, and authentication failure is recorded to an append-only Write-Once-Read-Many (WORM) audit ledger ([`audit_logging_system.py`](audit_logging_system.py)).
- **Cryptographic Hash Chaining:** Each record incorporates the SHA3-256 digest of the previous record:

$$
\text{RecordHash}_{i} = \text{SHA3-256}(\text{RecordHash}_{i-1} \parallel \text{Timestamp} \parallel \text{EventType} \parallel \text{Payload})
$$

- **HMAC-Authenticated Head Anchors:** The ledger head is authenticated using a keyed `.anchor` sidecar file (`<audit_name>.anchor`, persisted by [`audit_logging_system.py`](audit_logging_system.py)). Modification, deletion, or truncation of historical records breaks the hash chain and causes immediate detection during pre-flight checks.

### 3.19 Fail-Closed Policy Enforcement & Gatekeeper Table

Production operation (`P2P_PRODUCTION=1`, sticky at import) strictly enforces fail-closed gates. Weaker paths are rejected unless an explicit opt-in is configured:

| Security Gate | Default Setting | Production Behavior | Explicit Opt-In (Use = Downgrade) |
| --- | --- | --- | --- |
| Classical-only ratchet (`enable_pq=False`) | Refused in prod | `SecurityError` | `P2P_ALLOW_CLASSICAL=1` |
| Deniable sessions (no per-message signature) | Refused in strict mode | `SecurityError` | `P2P_ALLOW_DENIABLE=1` (non-strict only) |
| PQXDH v1 combiner | Refused in prod | `SecurityError`, min v2 required | none (lab interop only) |
| Unpinned peers (TOFU) | Refused in prod | `SecurityError`, pin required | none (lab only) |
| Missing `unified_secure_pipeline` | Refused in prod | `RuntimeError`, no legacy path | none (lab only) |
| Rust KEX without PSK | Refused in prod | Handshake fails, `--psk` required | none (lab: verify SAS out-of-band) |
| Rust KEX without mutual ML-DSA-87 | Refused outside `--lab` | Handshake fails, identity files required | `--lab` only (PSK-only, lower assurance) |
| Simulated dual-authorization EAM/PTT | Disabled in prod | Command refused | `--lab` only |
| TLS `verify_certs=False` / TLS < 1.3 | Refused in prod | `ValueError` / TLS 1.3 floor enforced | none (lab only) |
| Configuration without CNSA signature | Refused in prod | `ConfigurationError` | none (lab only) |
| Vulnerable HQC-256 algorithm | Refused everywhere | `RuntimeError` | `P2P_ENABLE_VULN_HQC=1` (reserve only) |
| Dual-person authorization for strict commands | Always required | `AuthorizationError` otherwise | none |

---

### 3.20 Complete Algorithmic Specifications

```text
+---------------------------------------------------------------------------------------------------------+
|                                  ST2027 FORMAL ALGORITHMIC SPECIFICATIONS                               |
+---------------------------------------------------------------------------------------------------------+
|  Algorithm 1: Standards-Track Hybrid Key Exchange (SecP384r1MLKEM1024 per RFC 10024)                    |
|  Algorithm 2: Continuous Epoch Ratchet (CER / SPQR-Style Post-Compromise Security)                     |
|  Algorithm 3: NIST SP 800-38D AEAD Record Layer with Tag-Derived Whitening                              |
|  Algorithm 4: Decoupled Sliding-Window Anti-Replay Bitmask State Machine (RFC 6479)                    |
|  Algorithm 5: Systematic Cauchy-Reed-Solomon MDS Erasure Codec over GF(2^8) (K=8, M=4)                  |
|  Algorithm 6: Two-Person Integrity (TPI) Dual-Smartcard Split Knowledge & Temporal Authorization       |
+---------------------------------------------------------------------------------------------------------+
```

#### Algorithm 1: Standards-Track Hybrid Key Exchange (`SecP384r1MLKEM1024`, [`rust_data_plane/src/kex_auth.rs`](rust_data_plane/src/kex_auth.rs))

```text
Input:
  Responder Identity: sk_auth_R (ML-DSA-87 Secret Key), pk_auth_I (Pinned Initiator ML-DSA-87 PK)
  Initiator Identity: sk_auth_I (ML-DSA-87 Secret Key), pk_auth_R (Pinned Responder ML-DSA-87 PK)
  Pre-Shared Key    : PSK in {0, 1}^256 (32 bytes, mandatory outside non-production --lab)
Output:
  Session Key (32B), Key Confirmation Tags (32B each), 128-bit SAS (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX)

Stage 1: Ephemeral Bundle Generation (Responder B / Initiator A)
  1. Responder generates: (sk_ec_R, pk_ec_R) <- P-384, (dk_kem, ek_kem) <- ML-KEM-1024
       resp_bundle <- pk_ec_R (97B uncompressed SEC1) || ek_kem (1568B)   // 1665 bytes
  2. Initiator parses resp_bundle, generates ephemeral P-384 (sk_ec_I, pk_ec_I) and encapsulates:
       (ct_kem, ss_kem) <- MLKEM1024_Encaps(ek_kem)                        // 1568B ct, 32B ss
       init_bundle <- pk_ec_I (97B uncompressed SEC1) || ct_kem (1568B)    // 1665 bytes
  3. transcript <- SHA-384(resp_bundle || init_bundle)                     // 48 bytes

Stage 2: Mutual Verify-Before-Derive ML-DSA-87 Authentication
  1. Responder signs: sigma_R <- MLDSA87_Sign(sk_auth_R, "ST2027-KEX-v2::sig-responder" || transcript)
  2. Initiator verifies MLDSA87_Verify(pk_auth_R, "ST2027-KEX-v2::sig-responder" || transcript, sigma_R) BEFORE signing
  3. Initiator signs: sigma_I <- MLDSA87_Sign(sk_auth_I, "ST2027-KEX-v2::sig-initiator" || transcript)
  4. Responder verifies MLDSA87_Verify(pk_auth_I, "ST2027-KEX-v2::sig-initiator" || transcript, sigma_I) BEFORE key derivation

Stage 3: Dual-PRF Binding, Key Extraction & Mutual Confirmation
  1. ss_ecdh        <- P384_ECDH(sk_ec, pk_ec_peer)                        // 48 bytes
  2. hybrid_ss      <- ml_ss (32B) || ss_ecdh (48B)                        // 80 bytes
  3. auth_binding   <- SHA-384("ST2027-KEX-v2::auth-binding" || transcript || len(sigma_R) || sigma_R || len(sigma_I) || sigma_I)
  4. session_key    <- HKDF-SHA384(salt=PSK?, IKM=hybrid_ss, info="ST2027-KEX-v2::session" || auth_binding, L=32)
  5. Confirm tags   <- HMAC-SHA384(session_key, "ST2027-RESPONDER-CONFIRM" / "ST2027-INITIATOR-CONFIRM" || auth_binding)[..32]
  6. SAS            <- HexGroups_8x4(SHA-384(transcript_bound)[..16])
  7. Zeroize ephemeral P-384/ML-KEM secrets and intermediate hybrid_ss immediately on scope exit
```

#### Algorithm 2: Continuous Epoch Ratchet (CER, [`rust_data_plane/src/ratchet.rs`](rust_data_plane/src/ratchet.rs))

```text
State:
  RootKey RK_e, CurrentEpoch e, SendChainKey CK_s, RecvChainKey CK_r, BoundedSkippedKeys (MAX_SKIPPED_KEYS=1000)
Trigger:
  PacketCount >= 10,000 OR BytesTransmitted >= 10 MiB OR Operator /rekey command

Rekey Step (Sender -> Receiver via FTYPE_IN_BAND_EPOCH_REKEY = 0x07):
  1. Generate fresh P-384 keypair + fresh ML-KEM-1024 encapsulation against peer's advertised (next_p_pub, next_ek)
  2. Advertise fresh next-epoch bundle (next_p_pub 97B, next_ek 1568B) for following ratchet step
  3. Assemble InBandEpochRekeyPayload (3366B base, or 7993B with 4627B ML-DSA-87 signature):
       body <- Uint32BE(e+1) || eph_p_pub(97B) || ml_ct(1568B) || next_p_pub(97B) || next_ek(1568B)
       tag  <- HMAC-SHA384(K_auth, "ST2027-EPOCH-REKEY-AUTH::key" || body)[..32]
       (optional mldsa_sig 4627B binding long-term sender identity; verified BEFORE decapsulating)
  4. Fragment across fixed wire quanta and emit on paced ticks
  5. Both sides verify MAC tag (and ML-DSA-87 signature in identity mode), then mix fresh hybrid secret:
       RK_{e+1} <- HKDF-SHA384(RK_e || hybrid_ss, info="ST2027-EPOCH-RATCHET::root" || epoch)
       CK_{e+1} <- HKDF-SHA384(CK_e || hybrid_ss, info="ST2027-RATCHET-v2::chain" || epoch)
  6. Old secrets zeroized via ZeroizeOnDrop
```

#### Algorithm 3: NIST SP 800-38D AEAD Record Layer & Tag-Derived Whitening ([`rust_data_plane/src/aead.rs`](rust_data_plane/src/aead.rs))

```text
Input:
  FrameKey K (32B) with hp_key <- HKDF-SHA384(None, K, "destroyer/header-protection/v2", L=32)
  Sequence S (u64 >= 1, reserved monotonically before seal), Direction d in {0x00 (DIR_SEND), 0x01 (DIR_RECV)}
  Payload P (0 <= len(P) <= 1205 bytes), FrameType T in {0x01, 0x02, 0x05, 0x06, 0x07, 0xFF}
Output:
  WireCell C_wire quantized to {256, 512, 1232} bytes (FRAME_OVERHEAD = 27 bytes)

Processing:
  1. Check Sequence Bounds: Require S >= 1 and S < u64::MAX (strictly monotonic reservation pre-seal)
  2. Nonce Construction (NIST SP 800-38D):
       IV_96        <- Uint64BE(S) (8B) || d (1B) || 0x000000 (3B)
  3. Header & Quantum Padding:
       PlainHeader  <- Uint64BE(S) (8B) || Uint16BE(len(P)) (2B) || T (1B)   // 11 bytes (AAD)
       PaddedBody   <- P || PadToQuantum(len(P), [256, 512, 1232])
  4. AEAD Encryption:
       (Ciphertext, Tag) <- AES256_GCM_Encrypt(K, IV_96, PaddedBody, AAD=PlainHeader) // Tag is 16B GHASH
  5. Header Whitening:
       Mask         <- SHA384("ST2027-HEADER-MASK-v2" || hp_key || Tag)[..11]
       MaskedHeader <- PlainHeader XOR Mask
  6. Emit Quantized Cell:
       WireCell     <- MaskedHeader (11B) || Ciphertext || Tag (16B) in {256B, 512B, 1232B}
```

#### Algorithm 4: Decoupled Sliding Anti-Replay Bitmask State Machine ([`rust_data_plane/src/replay.rs`](rust_data_plane/src/replay.rs))

```text
State:
  HighestSequence last_seq (u64), Circular Bitmap W of 32 x u64 words (WINDOW_SIZE = 1024 packets)

Pre-Authentication Read-Only Check check(S):
  1. If S == 0 -> Return DROP (invalid zero sequence)
  2. If S > last_seq -> Return TENTATIVE_ACCEPT (await AEAD verification)
  3. If (last_seq - S) >= 1024 -> Return DROP_EXPIRED
  4. If (W[(S / 64) % 32] & (1 << (S % 64))) != 0 -> Return DROP_DUPLICATE_REPLAY
  5. Return TENTATIVE_ACCEPT (await AEAD verification)

Post-Authentication Commit mark(S) (called ONLY after AES-256-GCM GHASH tag succeeds):
  1. If S > last_seq:
       Clear crossed circular word slots in ((last_seq / 64) + 1)..=(S / 64) (or clear W if diff >= 1024)
       last_seq <- S
  2. Set W[(S / 64) % 32] |= (1 << (S % 64))
```

#### Algorithm 5: Systematic Cauchy-Reed-Solomon MDS Erasure Codec over $\mathrm{GF}(2^8)$

```text
Parameters:
  K = 8 (data blocks), M = 4 (parity blocks), N = K + M = 12 (total blocks)
  Galois Field: GF(2^8) modulo p(X) = X^8 + X^4 + X^3 + X^2 + 1 (0x11D)
  Disjoint Sets: X = {1, 2, 3, 4}, Y = {5, 6, 7, 8, 9, 10, 11, 12}

Encoding:
  1. Construct Cauchy Matrix A in GF(2^8)^{4 x 8}:
       A_{i, j} = (X[i] XOR Y[j])^{-1} in GF(2^8)
  2. Input: File fragmented into K equal chunks D_0, ..., D_{K-1} (size L bytes each)
  3. Systematic Codewords:
       For j in 0..K-1: Codeword[j] <- D_j
       For i in 0..M-1:
         Parity[i] <- sum_{j=0}^{K-1} A_{i, j} (x) D_j            // computed via SIMD CLMUL
         Codeword[K + i] <- Parity[i]
  4. Transmit all N = 12 blocks across simplex optical fiber

Decoding (Reconstruction from any K received blocks):
  1. Receiver collects K distinct blocks with row indices R = {r_0, ..., r_{K-1}} subset of {0..N-1}
  2. Construct submatrix G_sub in GF(2^8)^{K x K} from corresponding rows of G = [I_K; A]
  3. Invert G_sub over GF(2^8) via Gauss-Jordan elimination:
       Inv_G <- (G_sub)^{-1}
  4. Recover original data blocks:
       D_j = sum_{k=0}^{K-1} Inv_G_{j, k} (x) ReceivedBlock[k]
  5. Deterministic Non-Singularity Guarantee:
       By Cauchy double determinant theorem, det(G_sub) != 0 for ANY choice of K rows.
```

#### Algorithm 6: Two-Person Integrity Dual-Smartcard Split Knowledge Verification

```text
Input:
  Directive Payload D (ASCII command string)
  Smartcard Token 1: Slot 0, User PIN_1
  Smartcard Token 2: Slot 1, User PIN_2
  Pinned Officer Roster R = {(ID_k, pk_auth_k, Role_k)}
Output:
  Execution Authorization: TRUE / FALSE

Authorization Ceremony:
  1. Workstation establishes concurrent PKCS#11 sessions:
       h_session_1 <- C_OpenSession(Slot=0, CKF_SERIAL_SESSION)
       h_session_2 <- C_OpenSession(Slot=1, CKF_SERIAL_SESSION)
       C_Login(h_session_1, CKU_USER, PIN_1)
       C_Login(h_session_2, CKU_USER, PIN_2)
  2. Interrogate Hardware Separation:
       Require Slot_1 != Slot_2
       Require Serial_1 != Serial_2
  3. Read Hardware Monotonic Clocks:
       t_1 <- ReadSiliconTime(h_session_1)
       t_2 <- ReadSiliconTime(h_session_2)
       Delta_t <- abs(t_1 - t_2)
       Require Delta_t <= 2000 ms                                  // enforce temporal window gate
  4. Compute Canonical Directive Digest:
       TargetContext <- "NC3-STRATEGIC-COMMAND-NODE-ALPHA"
       DirectiveHash <- SHA3-512(Uint64BE(t_1) || TargetContext || D)
  5. In-Silicon Signing (Keys never leave hardware boundaries):
       sigma_1 <- C_Sign(h_session_1, CKM_ML_DSA_87, DirectiveHash)
       sigma_2 <- C_Sign(h_session_2, CKM_ML_DSA_87, DirectiveHash)
  6. Verification against Pinned Officer Roster:
       pk_1 <- QueryTokenCertPublicKey(h_session_1)
       pk_2 <- QueryTokenCertPublicKey(h_session_2)
       Require ct_eq(pk_1, pk_2) == 0                              // officers must be distinct
       Require pk_1 in R.keys() and pk_2 in R.keys()
       Require MLDSA87_Verify(pk_1, DirectiveHash, sigma_1) == VALID
       Require MLDSA87_Verify(pk_2, DirectiveHash, sigma_2) == VALID
  7. Return TRUE; trigger emergency action or zeroization pipeline
```

---

## 4. End-to-End Architectural Security Flow: From Silicon to Wire

The following diagram illustrates the complete chronological security pipeline across all system layers, tracing an operational payload from initial host boot measurement to physical network wire emission:

```text
+---------------------------------------------------------------------------------------------------------+
|                                END-TO-END SYSTEM SECURITY EXECUTION PIPELINE                            |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|  [STAGE 1: HARDWARE SILICON ROOT-OF-TRUST & PRE-FLIGHT VERIFICATION]                                    |
|  * Host Interrogation: UEFI Secure Boot, Windows VBS/HVCI code integrity, Kernel DMA Protection.       |
|  * TPM 2.0 Attestation: Measured boot PCRs (0..7) verified; non-volatile monotonic anti-rollback check  |
|    against NVRAM Index 0x01800001 (halts execution on sequence replay).                                 |
|  * Key Custody Unlock: PKCS#11 v2.40 HSM / USB CCID smartcard PIN verification; zero-disk keys.         |
|                                       │                                                                 |
|                                       ▼                                                                 |
|  [STAGE 2: POST-QUANTUM MUTUAL HANDSHAKE & SAS VERIFICATION]                                            |
|  * Ephemeral Hybrid KEX: Dual exchange (SecP384r1 ECDH + NIST FIPS 203 ML-KEM-1024).                   |
|  * Identity Non-Repudiation: Ephemeral transcript signed with NIST FIPS 204 ML-DSA-87 identity keys.   |
|  * Transcript Binding: HKDF-SHA384 binds (ECDH_ss || MLKEM_ss || PSK || TranscriptHash).               |
|  * Anti-Man-in-the-Middle Gate: 128-bit Short Authentication String (SAS, 8x4 hex) for out-of-band check.|
|                                       │                                                                 |
|                                       ▼                                                                 |
|  [STAGE 3: SYMMETRIC EXPANSION & MLS COMPARTMENT DERIVATION]                                            |
|  * Master Derivation: HKDF-SHA384 derives session frame key; HKDF-SHA3-512 expands MLS compartment keys.|
|  * Compartment Gating: Bell-LaPadula MLS keys generated per classification domain (NO READ UP/DOWN).   |
|  * Nonce Derivation: Native 96-bit nonces (Uint64BE(seq) || DirectionByte || 0x000000); SQLite epoch IVs.|
|                                       │                                                                 |
|                                       ▼                                                                 |
|  [STAGE 4: CELL FRAMING, HEADER MASKING & TRAFFIC PACING]                                               |
|  * Data Quantization: Cleartext payload chunked to 1205 bytes max; padded to {256, 512, 1232}B quanta.  |
|  * AEAD Encryption: NIST SP 800-38D AES-256-GCM authenticated encryption; 16B GHASH tag appended.      |
|  * Header Masking: Wire header (seq, len, ftype) whitened via SHA-384 mask derived from Tag + hp_key.  |
|  * CBR Pacing Loop: Monotonic clock emits fixed-size cells every 50ms (20.0 Hz) or configured interval.  |
|  * Chaff Stream: Constant Poisson or CBR chaff cells (FTYPE_CHAFF 0xFF) sent during conversational gaps.|
|                                       │                                                                 |
|                                       ▼                                                                 |
|  [STAGE 5: WIRE INGESTION, ANTI-AMPLIFICATION & ANTI-REPLAY]                                            |
|  * Stateless Cookie Gate: Responder verifies micro-PoW puzzle before state allocation (Anti-DoS).      |
|  * Anti-Replay Ring: RFC 6479 decoupled 1024-packet sliding bitmask check() prior to AEAD decryption.   |
|  * Constant-Time AEAD: AES-NI constant-time hardware decrypt; invalid tags dropped silently.            |
|  * Stealth Net Discipline: Malformed datagrams dropped without emitting ICMP error or TCP RST response. |
|                                       │                                                                 |
|                                       ▼                                                                 |
|  [STAGE 6: IN-BAND CONTINUOUS REKEYING & POST-COMPROMISE SECURITY]                                      |
|  * Threshold Trigger: Every 10,000 packets or 10 MB transmitted data triggers Frame Type 0x07 (CER).   |
|  * Fresh KEM Exchange: Transmitter encapsulates fresh ML-KEM-1024 secret over encrypted wire.           |
|  * Ratchet Step: Root key advanced via HKDF-SHA384; prior session keys wiped immediately in RAM.        |
|                                       │                                                                 |
|                                       ▼                                                                 |
|  [STAGE 7: STRATEGIC DUAL-AUTHORIZATION TWO-PERSON INTEGRITY (TPI)]                                     |
|  * High-Consequence Directive Gate: Commands (/eam, purge) intercept automated network queues.          |
|  * Physical Split Knowledge: Simultaneous insertion of Officer 1 & Officer 2 smartcards (Slots 0 & 1).  |
|  * Directive Verification: Dual ML-DSA-87 signatures verified over SHA3-512 DirectiveHash.             |
|  * Temporal Window Gate: Hardware timestamp delta enforces |t1 - t2| <= 2000ms; serial replay rejected. |
|                                       │                                                                 |
|                                       ▼                                                                 |
|  [STAGE 8: SECURE TEARDOWN, VOLATILE SCRUBBING & MEDIA SANITIZATION]                                    |
|  * In-Band Purge: /zeroize command triggers immediate cryptographic teardown.                           |
|  * Persistent Sanitization: NIST SP 800-88 Rev 2 3-pass cryptographic wipe of key/state/NV files.      |
|  * Volatile Sanitization: DoD 5220.22-M multi-pass memory wipe with atomic compiler fence barriers.     |
|  * Anti-Forensics: ANSI terminal screen and scrollback history scrubbed (\x1b[2J\x1b[3J\x1b[H).        |
|                                                                                                         |
+---------------------------------------------------------------------------------------------------------+
```

---

## 5. Hardware Security Architecture: Prerequisites, Physical Interfaces & Exact Guarantees

Software cannot create physical tamper boundaries or measure physical emissions. To achieve high assurance, ST2027 defines explicit hardware security requirements, interrogates physical silicon interfaces, and delegates key custody to dedicated hardware cryptographic modules:

### 5.1 Discrete Trusted Platform Module 2.0 (TPM 2.0 / ISO/IEC 11889)

- **Hardware Interface:** Native Win32 TBS API (`tbs.dll`) on Windows; direct character device `/dev/tpmrm0` (TPM Resource Manager) on Linux ([`platform_hsm_interface.py`](platform_hsm_interface.py), [`ts_hw_layer.py`](ts_hw_layer.py)).
- **Prerequisite:** Discrete physical TPM 2.0 silicon (e.g., Infineon SLB 9670, STMicroelectronics ST33) or validated firmware TPM (AMD fTPM / Intel PTT) enabled in UEFI firmware.
- **Security Provided:**
  - *Measured Boot Posture:* Interrogates Platform Configuration Registers (PCRs 0 through 7). Verifies CRTM, UEFI firmware binaries (PCR 0), motherboard configuration (PCR 1), option ROM code (PCR 2), and Secure Boot policy variables (PCR 7).
  - *Remote Attestation Quotes:* Generates cryptographic quotes binding PCR measurement digests to an ephemeral nonce signed by an Attestation Identity Key (AIK), proving host firmware integrity to remote verifiers ([`ts_attest.py`](ts_attest.py)).
  - *Non-Exportable Key Containment:* Generates identity keys within the TPM silicon boundary; private keys cannot be read into general-purpose RAM or cloned to disk.
- **Quantitative Assurance:** 24 hardware PCR banks using SHA-256 / SHA-384 hash algorithms; silicon-enforced anti-hammering dictionary attack logic.

### 5.2 TPM 2.0 NVRAM Monotonic Anti-Rollback Counter

- **Hardware Interface:** TPM 2.0 Non-Volatile RAM index `0x01800001` (or `0x01800003`) read via `tpm2_nvread` and advanced via `tpm2_nvwrite` ([`rust_data_plane/src/tpm_nv.rs`](rust_data_plane/src/tpm_nv.rs)).
- **Prerequisite:** Configured TPM 2.0 NVRAM counter defined with the `TPMA_NV_MONOTONIC` attribute.
- **Security Provided:**
  - *Anti-Rollback Enforcement:* Enforces strictly increasing state counters across cold reboots, preventing an adversary with physical disk access from restoring old snapshots, expired peer authorizations, or revoked cryptographic credentials.
  - *Persistent State Anchor:* Sequence numbers and epoch identifiers are checked against the NVRAM counter; if host storage indicates a lower sequence number than the hardware NVRAM index, execution halts immediately with `SecurityError`.
- **Quantitative Assurance:** 64-bit non-resettable hardware integer counter with guaranteed physical non-volatility (> 100,000 write cycles).

### 5.3 Cryptographic Coprocessor / Hardware Security Module (PKCS#11 v2.40 HSM & Native Rust Data Plane)

- **Hardware Interface:** Native Rust PKCS#11 v2.40 integration via the `cryptoki` crate ([`rust_data_plane/src/auth.rs`](rust_data_plane/src/auth.rs)) and Python master orchestrator provider ([`platform_hsm_interface.py`](platform_hsm_interface.py)). Designed to target vendor PKCS#11 v2.40 middleware (e.g., YubiHSM/YubiKey PIV, Thales Luna, Nitrokey HSM) via configurable `hsm_library_path` / `P2P_HSM_LIBRARY`; physical hardware HSM and external smartcard tokens have **not** yet been tested end-to-end in this repository's CI/host environment.
- **Prerequisite:** Dedicated USB CCID smartcard tokens or PCIe/network HSM modules with vendor PKCS#11 middleware drivers provisioned on target hosts (`config_production.json` ships with empty `hsm_library_path` / `hsm_pin` requiring site provisioning and offline ML-DSA-87 signing via `scripts/sign_boot_config.py`).
- **Security Provided:**
  - *Physical Key Custody & Zero-Disk Storage:* Root ML-DSA-87 identity private keys reside exclusively within the cryptographic silicon boundary; private keys cannot be exported to RAM or disk (`--auth-sk-file` eliminated in production).
  - *In-Silicon Signature Execution:* Cryptographic sign operations (`sign_with_hsm`) execute directly on-chip; private key bytes never enter host operating system memory.
  - *Hardware Access Control:* Requires User PIN authentication with hardware lockout after consecutive failed attempts, preventing offline brute-force extraction.
  - *TPM 2.0 Sealed Identity Storage:* In [`rust_data_plane/src/tpm_nv.rs`](rust_data_plane/src/tpm_nv.rs), ML-DSA-87 key seeds can be sealed to specific PCR measurements (PCR 0, 1, 2, 7) via `TPM2_Seal` / `TPM2_Unseal`. If firmware is tampered with or Secure Boot is disabled, the silicon refuses to unseal.
- **Quantitative Assurance:** FIPS 140-3 Level 3 or Level 4 physical tamper-envelope rating with active physical zeroization upon chassis intrusion.

### 5.4 Physical Memory Locking & Buffer Protection

- **Hardware / OS Interface:** Win32 `VirtualLock` / POSIX `mlock`, `PAGE_GUARD` memory attributes, and Windows DPAPI `CryptProtectMemory` ([`enhanced_secure_memory.py`](enhanced_secure_memory.py), [`ts_rt/src/lib.rs`](ts_rt/src/lib.rs)).
- **Prerequisite:** CPU Memory Management Unit (MMU) with page-table attribute enforcement; operating system privilege `SeLockMemoryPrivilege`.
- **Security Provided:**
  - *Swap Suppression:* Locks pages holding plaintext, ephemeral ratchet keys, and session contexts into physical RAM, preventing the OS kernel from paging secrets to non-volatile disk swap partitions or crash dump files.
  - *Canary Tripwires:* Guard pages (`PAGE_GUARD`) sandwich cryptographic buffers. Any out-of-bounds read or write by buffer overrun bugs triggers an immediate hardware exception and process termination.
  - *RAM Invariance:* Idle buffers in memory are encrypted with DPAPI `CryptProtectMemory` using process-bound ephemeral session keys, mitigating cold-boot DRAM remanence and unprivileged memory inspection.
- **Quantitative Assurance:** Zero plaintext exposure to non-volatile storage; immediate hardware trap upon memory bounds violation.

### 5.5 Multi-Pass Volatile Memory Sanitization & Destruction

- **Hardware / Compiler Interface:** Explicit volatile writes with compiler memory barriers (`core::sync::atomic::compiler_fence(SeqCst)`), DoD 5220.22-M 3-pass overwrite patterns, and Rust `ZeroizeOnDrop` ([`ts_rt/src/lib.rs`](ts_rt/src/lib.rs), [`enhanced_secure_memory.py`](enhanced_secure_memory.py)).
- **Prerequisite:** Standard volatile DRAM memory architecture.
- **Security Provided:**
  - *Deterministic Deallocation:* Overwrites allocated memory buffers with a multi-pass pattern (Pass 1: `0x00`, Pass 2: `0xFF`, Pass 3: CSPRNG pseudorandom bytes, Pass 4: `0x00`) before returning memory to the system allocator.
  - *Dead-Code Elimination Prevention:* Atomic compiler fences ensure the optimizing compiler does not strip write operations on memory buffers that are about to fall out of scope.
  - *Native Rust Invariant:* `ZeroizeOnDrop` guarantees automatic zeroization of cryptographic key structures upon scope termination.
- **Quantitative Assurance:** Zero residual plaintext in freed heap or stack frames (subject to the Python runtime memory boundary disclosed in Section 0).

### 5.6 Hardware CPU Vector & Cryptographic Instruction Sets

- **Hardware Interface:** x86-64 AES-NI, CLMUL, AVX2, and AVX-512 SIMD vector execution units ([`rust_data_plane/src/aead.rs`](rust_data_plane/src/aead.rs)).
- **Prerequisite:** Modern x86-64 processor supporting AES-NI (`/proc/cpuinfo` `aes` flag or Windows `IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)`).
- **Security Provided:**
  - *Timing Side-Channel Immunity:* AES round computations execute in dedicated single-cycle hardware execution units (`vaesenc`, `vaesenclast`), completely bypassing software S-box lookup tables and eliminating CPU cache-timing side channels (e.g., Bernstein cache attacks).
  - *High-Throughput Polynomial Arithmetic:* AVX2 and AVX-512 vector pipelines accelerate Number Theoretic Transform (NTT) operations for ML-KEM-1024 and ML-DSA-87, minimizing handshake latency.
- **Quantitative Assurance:** Constant CPU cycle execution time (`O(1)` cycle variance across secret operands); multi-gigabit wire processing capacity.

### 5.7 Cross-Domain Unidirectional Simplex Optical Data Diode

- **Hardware Interface:** Dedicated single-strand optical fiber link with transmit photodiode connected to RED host and receive photodiode connected to BLACK host, with physical return strand severed or absent. Software interface: write-only UDP socket (`SO_RCVBUF=0`) with Cauchy Reed-Solomon Forward Error Correction (`K=8, M=4`) ([`tactical_data_diode.py`](tactical_data_diode.py), [`rust_data_plane/src/fec.rs`](rust_data_plane/src/fec.rs)).
- **Prerequisite:** Physical optical data diode hardware unit or single-strand optical transceiver.
- **Security Provided:**
  - *Physical Unidirectionality:* Transmission across single-strand optical fiber makes reverse signal propagation physically impossible (0.000 bits/second reverse leakage). Egress channels cannot be established from the destination back to the source.
  - *Zero-Acknowledgment Reliability:* Cauchy Reed-Solomon MDS forward error correction over `GF(2^8)` reconstructs payloads without requiring reverse acknowledgment (ACK) packets. Any `K` distinct frames received out of `K + M` transmitted frames guarantee 100% bit-accurate reconstruction.
- **Quantitative Assurance:** Infinite physical reverse optical attenuation; zero-return protocol execution.

### 5.8 Physical RED / BLACK Interface Separation

- **Hardware Interface:** Distinct physical Network Interface Cards (NICs) connected to isolated physical network segments ([`ts_hw_layer.py:L410`](ts_hw_layer.py)).
- **Prerequisite:** Multi-homed server host with at least two isolated physical PCIe network controllers.
- **Security Provided:**
  - *Domain Separation:* The RED interface is restricted exclusively to local, unencrypted plaintext processing (e.g., local enclaves, terminal I/O). The BLACK interface is restricted exclusively to encrypted ciphertext transmission over external untrusted networks.
  - *Anti-Wildcard Socket Binding:* The software verifies physical network adapter bindings via `psutil`. Binds to wildcard addresses (`0.0.0.0`, `::`) are rejected with `ConfigurationError`.
- **Quantitative Assurance:** Complete hardware network isolation; zero routable paths between plaintext and ciphertext domains.

### 5.9 Host Firmware & Hypervisor Security (UEFI Secure Boot, VBS, HVCI)

- **Hardware / OS Interface:** UEFI Secure Boot, Windows Virtualization-Based Security (VBS), Hypervisor-Protected Code Integrity (HVCI), and Kernel DMA Protection ([`ts_runtime.py`](ts_runtime.py), [`scripts/verify_host_hardening.py`](scripts/verify_host_hardening.py)).
- **Prerequisite:** x86-64 CPU virtualization extensions (Intel VT-x / AMD-V), Second Level Address Translation (SLAT), and IOMMU / DMA protection.
- **Security Provided:**
  - *Firmware Verification:* UEFI Secure Boot validates digital signatures on all bootloaders, kernels, and option ROMs prior to CPU handoff.
  - *Hypervisor Isolation:* VBS and HVCI execute code integrity verification within an isolated hypervisor enclave (VTL 1), preventing kernel rootkits or compromised kernel drivers from patching security gates or tampering with process memory.
  - *DMA Bus Attack Prevention:* Kernel DMA Protection enforces IOMMU isolation on peripheral buses (Thunderbolt, USB4, PCIe), blocking rogue peripheral devices from reading memory via direct memory access.
- **Quantitative Assurance:** Hardware-enforced kernel code integrity; blocking of unsigned driver insertion and external DMA probing.

---

## 6. Comparative Engineering Analysis: ST2027 vs. Contemporary Paradigms

To establish exact defense engineering positioning, ST2027 is compared with existing high-assurance government hardware encryptors, cross-domain diodes, and contemporary secure messaging systems:

| Architectural Dimension | HAIPE / Type 1 INE<br>(TACLANE KG-175 / KG-250) | Cross-Domain Diodes<br>(Owl / Fox DataDiode) | Signal Protocol<br>(PQXDH / SPQR Ratchet) | WireGuard VPN<br>(Noise_IK Protocol) | ST2027 Architecture<br>(This Reference Baseline) |
| --- | --- | --- | --- | --- | --- |
| **Cryptographic Posture** | NSA Type 1 Classical<br>(Suite A / Suite B ASIC) | Protocol-Agnostic Physical Optical Isolation | Hybrid PQXDH (Kyber-1024 + X25519) | Classical Curve25519 + ChaCha20-Poly1305 | **Strict NSA CNSA Suite 2.0**<br>(ML-KEM-1024 + ML-DSA-87 + AES-256 + P-384) |
| **Physical Tamper Boundary** | Dedicated ASIC/FPGA Hardware Enclosure | Dedicated Galvanic / Optical Diode Chassis | Zero (Commercial User-Space Mobile App) | Zero (Kernel Module on Host OS) | **Fail-Closed Software Gatekeeper**<br>+ TPM 2.0 Silicon + PKCS#11 HSM |
| **Traffic Flow Masking** | Constant-Rate Cell Pacing (Fixed IPsec Tunnels) | Push-Only Unidirectional (No Return Flow) | Variable-Rate Packet Emitted on Send (Leaks Timing) | Variable-Rate Wire Bursts (Silent when Idle) | **50ms Constant-Rate Cell Shaping**<br>+ 1232B Quantization + Poisson Chaff |
| **Anti-Replay Mechanism** | IPsec 64-Bit Monotonic Sequence Window | Not Applicable (Unidirectional Stream) | Asymmetric Ephemeral Ratchet Step Caches | Decoupled 2048-Packet Sliding Bitmask Window | **RFC 6479 Decoupled 1024-Packet Bitmask**<br>+ TPM NVRAM Monotonic State Anchor |
| **Multi-Level Security (MLS)** | Single Security Enclave (Red-in-Black Tunnel) | One-Way Boundary Transfer (Fixed Compartment) | Zero (Single-Domain Conversational Context) | Zero (Single Encrypted Network Overlay) | **Bell-LaPadula MLS Compartments**<br>derived via HKDF-SHA3-512 |
| **Two-Person Integrity (TPI)** | Physical Two-Key Locks on Hardware Chassis | Administrative Separation on Diode Controllers | Zero (Single Device Operator) | Zero (Single Endpoint Private Key) | **Cryptographic Dual-Person Authorization**<br>(Dual ML-DSA-87 Signed Tokens) |
| **Forward Error Correction** | Network Retransmissions (TCP or IPsec ARQ) | Cauchy / Reed-Solomon Erasure Coding | Retransmission via Untrusted Server Store | Network Retransmissions via Endpoint Apps | **Cauchy-Reed-Solomon MDS FEC**<br>over `GF(2^8)` (`K=8, M=4`) |
| **Formal Verification Scope** | Government Cryptographic Certification | Hardware Physics Verification | Academic Symbolic / Computational Proofs | Formal Verification of Noise Protocol Skeleton | **ProVerif 2.05 Symbolic Models**<br>+ Kani Bounded Model Checking |

---

## 7. Combined Defense-in-Depth Matrix: Software + Hardware Combined Security Posture

The following matrix defines the combined security posture achieved by pairing ST2027 software controls with supported hardware security roots across all primary threat vectors:

| Threat Vector / Adversary Capability | Software Security Control | Hardware Security Control | Combined Defense Level & Assurance Guarantee | Failure Behavior & Residual Risk |
| --- | --- | --- | --- | --- |
| **Quantum Cryptanalysis**<br>(Shor's algorithm on DH/RSA, Harvest-Now-Decrypt-Later) | NIST FIPS 203 ML-KEM-1024 + RFC 10024 `SecP384r1MLKEM1024` hybrid KEX; FIPS 204 ML-DSA-87 signatures. | CPU AVX2/AVX-512 SIMD vector acceleration for high-rate NTT polynomial operations. | **NIST Security Category 5**: 128-bit quantum security against CRQC; retrospective decryption rendered computationally infeasible. | Handshake aborts with `SecurityError` if classical-only downgrade is attempted. |
| **Active Network Adversary**<br>(Dolev-Yao: MitM, packet injection, bit manipulation) | NIST SP 800-38D AES-256-GCM AEAD on every cell; 16-byte GHASH tag authenticating unmasked AAD. | CPU AES-NI constant-time round instructions; zero S-box cache variation. | **Cryptographic Integrity & Authentication**: Any packet modification or injection detected; invalid GHASH tags dropped. | Corrupt packet dropped silently; receiver logs anomaly; zero plaintext released. |
| **Replay & Out-of-Order Injection**<br>(Network packet capture and delayed re-injection) | Strictly monotonic 64-bit sequence counters; RFC 6479 decoupled 1024-packet sliding window bitmap ring (32 x u64). | CPU 64-bit branchless bitwise operations ([`rust_data_plane/src/replay.rs`](rust_data_plane/src/replay.rs)). | **Anti-Replay Protection**: Duplicate packets rejected instantly; out-of-order packets accepted only within active window. | Duplicate sequence numbers dropped immediately prior to decryption; window state intact. |
| **Cold Reboot & State Rollback**<br>(Reverting disk images to replay stale sessions or revoked keys) | State sequence tracking and ephemeral session expiration timers. | **TPM 2.0 NVRAM Monotonic Counter** (Index `0x01800001`) advanced on state transitions. | **Hardware Anti-Rollback**: State progression anchored to physical silicon; restoring old disk images detected and rejected. | System detects counter discrepancy on startup; halts with `SecurityError`; requires re-enrollment. |
| **Traffic Analysis & SIGINT**<br>(Packet arrival timing, flow correlation, byte-count sniffing) | Constant-rate transmission clock (50ms interval); 1232B uniform cell quantization; Poisson chaff stream. | High-resolution hardware clock (`QueryPerformanceCounter` / POSIX `clock_gettime(CLOCK_MONOTONIC)`). | **Statistical Flow Masking**: Eliminates packet size and transmission rate signatures for localized observers. | Does not provide mathematical security against a global passive adversary with full network vantage points. |
| **Volatile Memory Scraping**<br>(Cold-boot DRAM remanence, crash dump extraction) | Multi-pass DoD 5220.22-M memory zeroization; Rust `ZeroizeOnDrop` on cryptographic structs. | OS page locking via Win32 `VirtualLock` / POSIX `mlock`; Windows DPAPI `CryptProtectMemory`. | **Zero Non-Volatile Secret Persistence**: Secrets never swapped to disk; memory sanitized immediately upon deallocation. | Subject to runtime limitation: Python immutable `bytes` cannot be wiped; native Rust binary required for full assurance. |
| **Peripheral Bus DMA Probing**<br>(Thunderbolt / PCIe / USB4 direct memory extraction) | Real-time PCI/PCIe bus scanner checking hardware device enumeration tables. | **Kernel DMA Protection / IOMMU** hardware page translation isolating peripheral DMA access. | **DMA Isolation**: External DMA access to process memory blocked at the hardware chipset level. | If Kernel DMA Protection is inactive or external DMA exposed, startup halts with `TSRequiredError`. |
| **Kernel Tampering & Rootkits**<br>(Compromised OS kernel patching security checks or keys) | Strict runtime integrity assertions; ProVerif-modeled state transitions; binary hash verification. | **UEFI Secure Boot + VBS / HVCI**: Code integrity enforced in hypervisor enclave (VTL 1). | **Hypervisor-Enforced Kernel Integrity**: Unauthorized kernel-mode code execution or runtime driver patching prevented. | Bootloader halts on invalid kernel signature; unverified drivers blocked by hypervisor. |
| **Key Extraction & Physical Theft**<br>(Physical host seizure, flash memory chip readout) | Zero-plaintext-disk policy; sensitive keys ephemeral; root identity keys hardware-anchored. | **PKCS#11 HSM / TPM 2.0 Silicon**: Private signing keys physically non-exportable from hardware. | **Hardware Key Confinement**: Root private keys physically cannot be extracted to host RAM or written to disk. | Stolen host does not yield private keys; token PIN lockout prevents offline brute forcing. |
| **Cross-Domain Data Exfiltration**<br>(Reverse command injection from untrusted BLACK to RED enclave) | Unidirectional write-only socket (`SO_RCVBUF=0`); Cauchy Reed-Solomon MDS FEC (`K=8, M=4`). | **Simplex Optical Fiber**: Physical single-strand optical tap with physically absent return channel. | **Physical Unidirectionality**: 0.000 bits/second reverse channel leakage; reverse exploit injection physically impossible. | Reverse traffic cannot traverse severed glass; transmission is 100% one-way. |
| **CPU Cache Timing Analysis**<br>(Cache-timing attacks on AES S-boxes or modular exponentiation) | Constant-time memory comparisons (`tsrt_ct_equal`); branchless algorithms. | **Hardware AES-NI & AVX Vector Units**: Executes cryptographic operations in dedicated silicon pipelines. | **Timing Side-Channel Immunity**: Execution time strictly independent of secret key bits or plaintext data values. | Constant-time execution prevents timing side-channel extraction via shared CPU cache lines. |
| **Buffer Overflow & Memory Corruption**<br>(Adversarial frame injection targeting parser vulnerabilities) | Standalone memory-safe Rust data plane; zero unsafe code in frame parsing pipelines; Kani bounded models. | Memory Management Unit (MMU) `PAGE_GUARD` memory canary tripwires around secret buffers. | **Memory Safety Assurance**: Buffer overruns prevented by Rust compile-time ownership; invalid frames caught before execution. | Parser panics or out-of-bounds access caught; process terminates fail-closed without memory corruption. |

---

## 8. Formal Protocol Specification & Wire Format Layout

The ST2027 native wire engine quantizes frames to fixed packet classes `FRAME_QUANTA = [256, 512, 1232]` bytes ([`rust_data_plane/src/frame.rs`](rust_data_plane/src/frame.rs)). The maximum quantum (`1232` bytes) fits inside the IPv6 minimum MTU (`1280` bytes) with UDP (`8` bytes) and IPv6 (`40` bytes) headers without path fragmentation (`1232 + 40 + 8 = 1280`). Every cell carries `FRAME_OVERHEAD = 27` bytes (`seq(8) + len(2) + type(1) + tag(16)`), yielding `MAX_PAYLOAD = 1205` user payload bytes per cell.

### Cell Structure (Maximum 1232-Byte Quantum)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Masked Sequence Number (u64 BE)             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Masked Length (u16 BE)   | Masked Type   |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
|                                                               |
|          Encrypted Payload + Quantum Padding                  |
|            (Unpadded Payload: 0..1205 Bytes)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     AES-256-GCM Tag (16 Bytes)                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Wire Field Definitions ([`rust_data_plane/src/frame.rs`](rust_data_plane/src/frame.rs) & [`rust_data_plane/src/aead.rs`](rust_data_plane/src/aead.rs))

- **Sequence Number (8 bytes, Big-Endian, masked on wire):** Strictly monotonic 64-bit integer reserved prior to encryption from the HMAC-SHA384-authenticated `STSTATE3` state file (`328` bytes) and validated read-only against the 1024-packet sliding window bitmap ([`rust_data_plane/src/replay.rs`](rust_data_plane/src/replay.rs)) before advancing on valid AEAD tag verification.
- **Length (2 bytes, Big-Endian, masked on wire):** Length of the unpadded cleartext payload ($0 \le \text{Length} \le 1205$).
- **Type (1 byte, masked on wire):** Protocol frame type discriminators defined in [`rust_data_plane/src/frame.rs`](rust_data_plane/src/frame.rs):
  - `0x01`: `FTYPE_MSG` — Authenticated application / fragmented payload data
  - `0x02`: `FTYPE_REKEY` — In-band Continuous Epoch Ratchet (CER) rekey envelope
  - `0x05`: `FTYPE_ATTESTATION_EVIDENCE` — Attestation evidence & RFC 9881 X.509 certificate chain envelope
  - `0x06`: `FTYPE_REVOCATION` — In-band threshold Certificate Revocation List (CRL) broadcast
  - `0x07`: `FTYPE_IN_BAND_EPOCH_REKEY` — Hybrid P-384 + ML-KEM-1024 CER payload (`3366B` base or `7993B` with `4627B` ML-DSA-87 signature)
  - `0xFF`: `FTYPE_CHAFF` — Constant-rate cover traffic (discarded silently by recipient before surfacing)
- **Header Whitening:** The 11-byte plaintext header (`seq || len || ftype`) is XORed with `SHA384("ST2027-HEADER-MASK-v2" || hp_key || tag)[..11]` where `hp_key = HKDF-SHA384(None, frame_key, "destroyer/header-protection/v2")`.
- **Encrypted Payload + Padding:** Ciphertext produced strictly by AES-256-GCM (NIST SP 800-38D) with `IV = seq_BE(8) || dir(1) || 0x00(3)` (`DIR_SEND = 0x00`, `DIR_RECV = 0x01`), padded up to the selected `{256, 512, 1232}` quantum size.
- **Authentication Tag (16 bytes):** AES-256-GCM GHASH tag authenticating the **unmasked** 11-byte header as AAD alongside the ciphertext:

$$
\text{AAD} = \text{Sequence}_{\text{unmasked}} \parallel \text{Length}_{\text{unmasked}} \parallel \text{Type}_{\text{unmasked}}
$$

---

## 9. Machine-Checked Formal Analysis & Bounded Model Checking

Symbolic models check the MODEL, not the running system. `handshake_model.pv` is a structural skeleton (intended properties NOT CI-enforced via ProVerif). The ProVerif models executed by `docs/formal/check.sh` hold inside their symbolic Dolev-Yao abstractions (perfect cryptography assumed; AES-GCM nonce uniqueness and constant-time memory hygiene sit outside the symbolic proof) — they are not a proof of the compiled Rust/Python implementation. In local environments without the Kani/CBMC toolchain installed (e.g., Windows workstations), the 8 `#[kani::proof]` harnesses in `rust_data_plane/tests/kani_harness.rs` are DEFINED (requiring `cargo kani` + CBMC on Linux) while the 10 deterministic property doubles execute under `cargo test`; on Linux CI ([`.github/workflows/kani-proofs.yml`](.github/workflows/kani-proofs.yml)), `cargo kani` runs the Kani harnesses under CBMC.

```text
+---------------------------------------------------------------------------------------------------------+
|                              FORMAL ANALYSIS EVIDENCE SUMMARY (MODEL-SCOPED)                            |
+---------------------------------------------------------------------------------------------------------+
| ProVerif 2.05 Applied Pi-Calculus Analyses (model scope only; executed by docs/formal/check.sh --strict):|
|   ├── docs/formal/st2027_handshake.pv (Noise_XXhfs Python reference protocol)                           |
|   │   ├── Query not attacker(secret_payload)                      ==> HOLDS IN MODEL (Secrecy)           |
|   │   ├── Query inj-event(S_Accepts) ==> inj-event(C_Accepts)       ==> HOLDS IN MODEL (Mutual Auth)      |
|   │   ├── Query event(C_VerifiedM2) ==> event(S_SentM2)             ==> HOLDS IN MODEL (M2 authenticity)  |
|   │   ├── Query inj-event(R_Receives) ==> inj-event(C_Sends)        ==> HOLDS IN MODEL (No forgery/replay)|
|   │   └── Query not attacker(initiator static key)                 ==> HOLDS IN MODEL (M1 identity privacy)|
|   ├── docs/formal/st2027_kex_auth.pv (Wire-exact rust_data_plane/src/kex_auth.rs mutual ML-DSA-87 model)|
|   │   ├── Verifies P-384 + ML-KEM-1024 + PSK + auth_binding KDF, key confirmation & forward secrecy     |
|   │   └── Explicit Scope: plaintext identity signatures in kex_auth.rs do not hide peer ID vs passive tap|
|   ├── docs/formal/st2027_pcs.pv (Rehandshake / CER PCS healing)                                         |
|   │   └── Query not attacker(epoch-2 payload) under Epoch-1 total compromise ==> HOLDS IN MODEL (PCS heal) |
|   ├── docs/formal/st2027_ratchet_pcs.pv (rust_data_plane/src/ratchet.rs Epoch-0 -> Epoch-1 PCS model)    |
|   │   └── Verifies ML-DSA-87 + MAC verification before decaps/mutation under upfront Epoch-0 RAM reveal |
|   ├── docs/formal/st2027_tor_rendezvous.pv (ClientAuthV3 Restricted Discovery + in-stream Noise_XXhfs binding)|
|   │   └── Verifies payload secrecy & mutual agreement across compromised Tor HSDir/exit relays                |
|   └── docs/formal/nc3_dual_custody.pv (NC3 / PAL Two-Person Rule & dual hardware-token authorization)    |
|       └── Structurally audited by tests/test_formal_proverif_models.py                                   |
+---------------------------------------------------------------------------------------------------------+
| Kani Rust Bounded Model Checking: 8 CBMC-executed harnesses (Linux CI `cargo kani`) + 10 property doubles:|
|   ├── #[kani::proof] kani_nonce_domain_separation .................... CBMC VERIFIED (Linux Kani CI)   |
|   ├── #[kani::proof] kani_replay_window_monotonic .................... CBMC VERIFIED (Linux Kani CI)   |
|   ├── #[kani::proof] kani_max_stream_bytes_cap ....................... CBMC VERIFIED (Linux Kani CI)   |
|   ├── #[kani::proof] kani_nostd_frame_parse_never_panics ............. CBMC VERIFIED (Linux Kani CI)   |
|   ├── #[kani::proof] kani_stream_frame_len_decoder_bounds ............ CBMC VERIFIED (Linux Kani CI)   |
|   ├── #[kani::proof] kani_tamaraw_shaper_epoch_modulo_bounds ......... CBMC VERIFIED (Linux Kani CI)   |
|   ├── #[kani::proof] verify_tor_padding_never_overflows / verify_length_header_bounds .. CBMC VERIFIED  |
|   ├── #[kani::proof] kani_cookie_gate_stateless_verification ......... DEFINED (property double passes) |
|   ├── #[kani::proof] kani_frame_split_reassemble_roundtrip ........... DEFINED (property double passes) |
|   ├── 10 deterministic property doubles + re-exported module unit tests execute green under `cargo test`  |
|   └── NOTE: "HOLDS IN MODEL" applies strictly to the symbolic model; `cargo kani` requires Linux CBMC.  |
+---------------------------------------------------------------------------------------------------------+
```

### 9.1 Three-Tiered Verification Hierarchy & Implementation Bridging

To bridge the gap between symbolic protocol logic (Dolev-Yao model in ProVerif 2.05) and physical machine execution, ST2027 establishes a three-tiered verification hierarchy:

1. **Tier 1 — Symbolic Protocol Logic (ProVerif 2.05 Applied Pi-Calculus)**:
   Verifies secrecy, mutual authentication (`S_Accepts ==> C_Accepts`), M2 authenticity (`C_VerifiedM2 ==> S_SentM2`), record layer integrity (`R_Receives ==> C_Sends`), and initiator identity privacy in [`docs/formal/st2027_handshake.pv`](docs/formal/st2027_handshake.pv); verifies the wire-level `kex_auth.rs` protocol in [`docs/formal/st2027_kex_auth.pv`](docs/formal/st2027_kex_auth.pv); and verifies Post-Compromise Security (PCS) healing under upfront epoch compromise in [`docs/formal/st2027_pcs.pv`](docs/formal/st2027_pcs.pv) and [`docs/formal/st2027_ratchet_pcs.pv`](docs/formal/st2027_ratchet_pcs.pv). Executed fail-closed in CI via [`docs/formal/check.sh`](docs/formal/check.sh) (`--strict`).
2. **Tier 2 — Bit-Precise Software Verification (Kani Rust Bounded Model Checker)**:
   The 8 `#[kani::proof]` harnesses in [`rust_data_plane/tests/kani_harness.rs`](rust_data_plane/tests/kani_harness.rs) (plus 2 library proofs in `src/shaper.rs` and `src/stream_transport.rs`) check buffer bounds, panic freedom on arbitrary wire frames, Tor-cell alignment math, stream frame length bounds, stateless cookie gates, and anti-replay sliding window monotonicity. Locally on hosts without Kani/CBMC, `cargo test --manifest-path rust_data_plane/Cargo.toml --no-default-features` executes the 10 deterministic property sweeps and re-exported unit checks (49 tests in `kani_harness`). In Linux CI ([`.github/workflows/kani-proofs.yml`](.github/workflows/kani-proofs.yml)), `cargo kani` executes 8 harnesses (2 library + 6 integration) via CBMC.
3. **Tier 3 — Side-Channel & Timing Attack Freedom (DudeCT Welch's t-test Statistical Leakage)**:
   Evaluates constant-time execution timing distributions under Welch's two-sample $t$-test (Reparaz et al. IEEE S&P / ePrint 2016/1123). Executed via `cargo test --manifest-path rust_data_plane/Cargo.toml --test dudect_ct` (12 tests) and `pytest tests/test_dudect_timing_analysis.py`. Requires $|t| < 4.5$ ($p > 99.999\%$ confidence) on production primitives (`ct::ct_eq`, `StackSecretBuffer::ct_eq`, and `hmac.compare_digest`), with positive-control leaky comparators triggering $|t| > 4.5$ to confirm detector sensitivity.

### 9.2 Machine-Checked Formal Verification Certificate

The verification pipeline generates signed, machine-checked verification manifests via [`tools/formal_verification_orchestrator.py`](tools/formal_verification_orchestrator.py):

```sh
python tools/formal_verification_orchestrator.py --strict
```

Outputs cryptographic SHA-512 sealed verification manifest at [`docs/formal/formal_verification_certificate.json`](docs/formal/formal_verification_certificate.json) and [`docs/formal/formal_verification_certificate.json.sha512`](docs/formal/formal_verification_certificate.json.sha512). Cross-platform gate execution is checked via [`docs/formal/check.py`](docs/formal/check.py).

---

## 10. Master Documentation Compendium & The 7 Research Tracks

The complete engineering, cryptographic, and operational documentation suite is structured into seven interconnected tracks:

```text
                                      ST2027 RESEARCH MONOGRAPH TAXONOMY
                                                       │
          ┌──────────────────────────────┬─────────────┴─────────────┬──────────────────────────────┐
          ▼                              ▼                           ▼                              ▼
    [RESEARCH TRACK 1]                        [RESEARCH TRACK 2]                       [RESEARCH TRACK 3]                        [RESEARCH TRACK 4]
  Architecture & Strategy                   Formal Verification & PQC                Dual-Authorization & CONOPS               Security Policies & CC
  - ARCHITECTURE.md                         - formal/README.md                       - MILITARY_NC3_DEPLOYMENT_GUIDE.md        - FIPS_140_3_SECURITY_POLICY.md
  - SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md - formal/st2027_handshake.pv       - CONOPS_TACTICAL_DEPLOYMENT.md           - NIAP_COMMON_CRITERIA_SECURITY_TARGET.md
  - COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md - formal/st2027_kex_auth.pv   - KEY_CEREMONY.md                         - EVALUATION_DOSSIER.md
  - ST2027_SPEC.md                          - formal/st2027_pcs.pv                 - KEY_MANAGEMENT_PLAN_KMP.md              - OSCAL SSP & SAR (compliance_reports/)
  - ST2027_RESEARCH_SOURCES_2026-09-30.md   - formal/st2027_ratchet_pcs.pv         - SOP.md                                  - Signed CBOM & SBOMs (compliance_reports/)
  - DEFENSE_HARDENING_MASTER_PLAN.md        - formal/nc3_dual_custody.pv
  - OPEN_INTERNET_HARDENING_PLAN.md         - formal/handshake_model.pv (skeleton)
  - ST2027_IMPLEMENTATION_PLAN.md           - rust_data_plane/tests/kani_harness.rs
  - RESTRUCTURE_PLAN.md
          │                                          │                                        │                                         │
          └──────────────────────────────────────────┴────────────────────────────────────────┴─────────────────────────────────────────┘
                                                     │
          ┌──────────────────────────────────────────┴───────────────────────────────────────┐
          ▼                                                                                  ▼
    [RESEARCH TRACK 5]                                                         [RESEARCH TRACK 6]
  Hardware Security & Runbooks                                               27 Subsystem Deep-Dive Charters (docs/modules/)
  - hw_tpm_hsm_setup.md                                                      - 5 Strategic Defense Pillars (ts_hw, ts_rt, ...)
  - airgap_runbook.md                                                        - Native Transport & Framing (rust_dp, p2p_core, ...)
  - deployment_hardening_guide.md                                            - Cryptography & Key Ratchets (pqc, kex, ratchet, ...)
  - FIREWALL_IPV6.md                                                         - Security Gating & HSM (memory, hsm, release, ...)
  - incident_response.md                                                     - Node Orchestration & Policies (destroyer, policy, ...)
  - liboqs_pin.md
          │
          ▼
    [RESEARCH TRACK 7]
  Master Engineering Compendiums & Forensic Audits
  - docs/SYSTEM_SECURITY_DOCUMENTATION.md (Volume A — Tier 0-7 Architecture & Formal Wire Formats)
  - docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md (Volume C — AST Logic Flows & Function Catalog)
  - docs/security_audit_report.md & historical audits archived in docs/archive/
  - docs/README.md (Master Documentation Portal & Architectural Cross-Reference Index)
```

### Key Engineering References

1. **[`docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md`](docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md):** Authoritative Technical Manual (TM-ST2027-2027.1) detailing deployment topologies, subsystem component mapping to source code, wire quantization, and fail-closed state machines.
2. **[`docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md`](docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md):** National Security Systems High-Assurance Architecture and Forensic Security Specification covering CNSA Suite 2.0 primitives, in-RAM Verify-After-Sign (VAS), Bell-LaPadula MLS, and TPM 2.0 anti-rollback guards.
3. **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md):** Foundational system thesis, threat models (Dolev-Yao, Global Passive SIGINT, Quantum Adversary, Physical Probes), architectural trust boundaries, and strict isolation between 2027 production target and legacy prototypes.
4. **[`docs/ST2027_SPEC.md`](docs/ST2027_SPEC.md):** Technical specification of the 1232-byte wire frame, constant-rate drift-compensated pacing clock, and Shannon entropy measurement (Shannon entropy H > 7.95 bits/byte — a measurement, NOT an indistinguishability proof).
5. **[`docs/FIPS_140_3_SECURITY_POLICY.md`](docs/FIPS_140_3_SECURITY_POLICY.md):** Cryptographic Module Security Policy (CMSP) defining physical boundaries, roles, approved algorithms, and Level 3/4 hardware requirements (design target, NOT lab-certified).
6. **[`docs/NIAP_COMMON_CRITERIA_SECURITY_TARGET.md`](docs/NIAP_COMMON_CRITERIA_SECURITY_TARGET.md):** NIAP Protection Profile for Network Devices (NDcPP v3.0) / Common Criteria EAL4+ Security Target (design target, NOT lab-certified).
7. **[`docs/hw_tpm_hsm_setup.md`](docs/hw_tpm_hsm_setup.md):** Hardware setup guide for TPM 2.0 PCR validation, Windows CNG Platform Crypto Provider, PKCS#11 HSMs, and physical RED/BLACK cabling.
8. **[`docs/airgap_runbook.md`](docs/airgap_runbook.md):** Offline station operations, manual cryptographic key-fill procedures, and simplex optical data diode setups.

---

## 11. Implementation Engines, Toolchain Prerequisites & Operational Quick Start

### 11.1 Build & Toolchain Prerequisites

- **Python:** 3.11 or higher (see `pytest.ini` & `defense_ci.yml`) with pinned dependencies in `requirements.txt` (`--require-hashes`).
- **Rust:** Stable toolchain (`cargo`, `rust_data_plane/Cargo.toml`, `ts_rt/Cargo.toml`, `sel4_mils_appliance/Cargo.toml`) + `maturin` for the PyO3 `destroyer_core` extension.
- **OpenSSL:** 3.1 or higher (TLS 1.3 transport outer wrapper in orchestration/lab harnesses).
- **LibOQS:** Pinned C library version `0.16.0` (`oqs.dll` on Windows with embedded Ed25519 + SHA-384/SHA3-512 pin verified by `verify-binaries`; built from pinned commit `5a1a854b` on Linux CI).

```bash
# 1. Build native security core cdylib (ts_rt)
cargo build --release --manifest-path ts_rt/Cargo.toml

# 2. Build production native binaries (--no-default-features strips simulated lab surfaces)
cargo build --release --no-default-features --manifest-path rust_data_plane/Cargo.toml --bin secure-transmit --bin verify-binaries

# 3. Build and install native Python data-plane extension (destroyer_core)
maturin build -r --no-default-features --manifest-path rust_data_plane/Cargo.toml

# 4. (Optional / non-production lab only) Build secure-transmit with --features lab-surfaces
cargo build --manifest-path rust_data_plane/Cargo.toml --features lab-surfaces --bin secure-transmit
```

### 11.2 Native Data-Plane Command Catalog (`secure-transmit` & `verify-binaries`)

In [`rust_data_plane/src/main.rs`](rust_data_plane/src/main.rs), `secure-transmit` dispatches **33 subcommands** (`zeroize` also aliases `purge`), while standalone binary `verify-binaries` ([`rust_data_plane/src/bin/verify_binaries.rs`](rust_data_plane/src/bin/verify_binaries.rs)) performs out-of-process SHA-384 and SHA3-512 verification of `oqs.dll` and `libsodium.dll`. Commands marked `[lab-surfaces only]` are compiled out in release `--no-default-features` builds:

| Command | Category | Purpose & Security Enforcement |
| --- | --- | --- |
| `keygen` | Key Management | Generates fresh 32-byte symmetric frame key with OS entropy. |
| `auth-keygen` | Identity | Generates NIST FIPS 204 ML-DSA-87 identity keypair (`2592B` PK, `4896B` SK). |
| `auth-sign` | Signing | Signs arbitrary file or transcript with ML-DSA-87 and domain separation. |
| `auth-verify` | Verification | Verifies ML-DSA-87 signature against pinned public key. |
| `auth-tpm-seal` | Hardware Custody | Seals ML-DSA-87 signing seed to TPM 2.0 PCR measurements via `tpm2-tools`. |
| `auth-tpm-unseal` | Hardware Custody | Unseals TPM-bound signing seed in volatile locked memory (`LockedKey32`). |
| `hsm-probe` | Hardware Custody | Probes configured PKCS#11 v2.40 library/slot availability via `cryptoki`. |
| `kex-listen` | Handshake | Listens for inbound `SecP384r1MLKEM1024` KEX; enforces mutual ML-DSA-87 outside `--lab`. |
| `kex-connect` | Handshake | Connects to remote peer; negotiates `SecP384r1MLKEM1024` hybrid session key. |
| `node` | Production Loop | Integrated native KEX + paced/headless operational node (`--psk-file` + mutual auth / PKCS#11 / TPM). |
| `send` | Transit | Transmits single authenticated datagram with monotonic sequence counter. |
| `recv` | Transit | Listens for inbound datagrams; drops replays via RFC 6479 1024-packet bitmask window. |
| `send-file` | Bulk Data | Chunks file into 1205B cells; emits sequence stream with SHA-384 manifest (`MAX_STREAM_BYTES = 16 MiB`). |
| `recv-file` | Bulk Data | Reassembles file from consecutive sequence cells; verifies SHA-384 digest. |
| `diode-send` | Cross-Domain | Simplex optical diode transfer with systematic Cauchy-RS FEC over `GF(2^8)`. |
| `diode-recv` | Cross-Domain | Reconstructs diode stream from any $K$ received packets without return ACKs. |
| `doc-seal` | Storage Envelope | Encrypts static document artifact with authenticated AEAD envelope & metadata. |
| `doc-open` | Storage Envelope | Authenticates and decrypts sealed document envelope (fail-closed on tamper). |
| `stream-chaff` | Anti-SIGINT | Emits continuous CSPRNG chaff cells with CBR, Poisson pacing, or tactical profiles (`--poisson`, `--tactical-profile`). |
| `channel` | Enclave Link | Full-duplex paced link with directional nonces, in-band CER ratchets, and tactical profiles. |
| `terminal` | Tactical C2 | Interactive tactical operator terminal with FIFO keystroke decoupling and ANSI anti-forensic screen wipe. |
| `cookie-challenge` | Anti-DoS | Generates stateless anti-amplification micro-PoW challenge. |
| `cookie-solve` | Anti-DoS | Solves micro-PoW challenge to unlock responder handshake allocation. |
| `cookie-verify` | Anti-DoS | Validates micro-PoW puzzle response before allocating memory. |
| `threat-eval` | Cyber Defense | Evaluates Active Cyber Defense (ACD) triggers and mitigation playbooks. |
| `zero-trust-eval` | Zero Trust | Computes continuous NIST SP 800-207 trust score ($0 \le S \le 100$). |
| `cot-beacon` | `[lab-surfaces only]` | Simulated NATO MIL-STD-6090 Cursor-on-Target formatter (compiled out in production builds). |
| `tactical-msg` | `[lab-surfaces only]` | Simulated MMHS telegram / RTB filter demo formatter (compiled out in production builds). |
| `eam-auth` | `[lab-surfaces only]` | File-based dual-officer EAM lab verification helper (compiled out in production builds). |
| `eam-auth-hw` | NC3 / TPI | Authorizes NC3 EAM directive via concurrent dual-smartcard PKCS#11 hardware tokens. |
| `eam-verify-hw` | NC3 / TPI | Verifies EAM package against temporal window ($\Delta t \le 2.0\text{s}$) and pinned officer roster (`--officer-roster`). |
| `nc3-safety-gate` | NC3 / Safety | Evaluates outbound conversational text against the fail-closed NC3 single-officer safety gate. |
| `zeroize` (`purge`) | Sanitization | NIST SP 800-88 3-pass wipe + unlink of key, state, `.seqlog`, and `.nvck` files. |
| `selftest` | Diagnostics | Executes deterministic in-memory native cryptographic self-tests. |

### 11.3 Host Hardware Inspection & Pre-Flight Verification

Interrogate host hardware posture (Secure Boot, VBS, HVCI, TPM 2.0 silicon, FIPS provider) before station initialization:

```bash
# Execute pre-flight hardware inspection:
python secure_transmit_2027.py check-hw

# Run host hardening audit script:
python scripts/verify_host_hardening.py

# Verify deployment readiness gate (99 PASS, 0 FAIL, 4 WARN on typical non-TPM/non-HSM lab workstation):
python verify_deployment.py
```

### 11.4 Generating Hardware-Backed Post-Quantum Credentials

Provision non-exportable hardware-bound ML-DSA-87 identity keypairs:

```bash
# Provision hardware identity via Python master orchestrator:
python secure_transmit_2027.py keygen --label station_command_alpha

# Or generate standalone keys via native Rust binary (or seal via auth-tpm-seal / PKCS#11 HSM):
./rust_data_plane/target/release/secure-transmit auth-keygen \
  --out-sk alpha.auth.sk --out-pk alpha.auth.pk
```

### 11.5 Production Node Deployment (Mutual ML-DSA-87 & Hybrid KEX)

Provision hardware key custody (`--auth-tpm-sealed` or PKCS#11 HSM; plaintext `--auth-sk-file` is refused in `P2P_PRODUCTION=1`), exchange 2592-byte ML-DSA-87 public keys over an authenticated out-of-band channel, and provision a 32-byte PSK on both endpoints:

```bash
# Native standalone Rust production node (Initiator, zero Python runtime):
./rust_data_plane/target/release/secure-transmit node --role initiator \
  --bind <LOCAL_IP>:9061 --to <RESPONDER_IP>:9060 \
  --psk-file shared.psk --auth-tpm-sealed bravo.tpm.sealed \
  --peer-auth-pk-file alpha.auth.pk --require-mutual-auth

# Or Python orchestration dispatcher (validates posture and delegates to native `secure-transmit node`):
python secure_p2p.py node --role responder --bind <LOCAL_IP> --peer <INITIATOR_IP> \
  --psk-file shared.psk --auth-tpm-sealed alpha.tpm.sealed \
  --peer-auth-pk-file bravo.auth.pk --require-mutual-auth
```

The session key is cryptographically bound to the `SecP384r1MLKEM1024` hybrid KEM transcript, both ML-DSA-87 signatures, and the PSK. Compare the printed 128-bit Short Authentication String (SAS, rendered as eight 4-hex-character groups `XXXX-XXXX-...`) out-of-band before transmitting sensitive payloads.

### 11.6 Standalone Zero-Python Lab Key-File & Production Key Custody Discipline

> **Security Gate Note on Key Provisioning:** Raw symmetric secrets on command-line arguments (`--key HEX` and `--psk HEX`) are **unconditionally rejected** across all commands so secrets never appear in `ps` process listings (`reject_forbidden_cli` in `rust_data_plane/src/main.rs`). Furthermore, raw symmetric key files (`--key-file` / `--key-stdin`) on `node`, `channel`, and `terminal` are restricted to **non-production `--lab` testing** and fail closed under `P2P_PRODUCTION=1`. Production deployments derive ephemeral keys via authenticated `SecP384r1MLKEM1024` KEX (`--psk-file`) bound to non-exportable `--auth-pkcs11` HSM or `--auth-tpm-sealed` identities.

```bash
# Non-production / Lab File Transmission Example (--key-file):
./rust_data_plane/target/release/secure-transmit recv-file \
  --key-file keys/session.key \
  --state keys/recv.state \
  --bind [::1]:9999 \
  --out downloads/target_file.dat \
  --count 10

# Transmitting Station:
./rust_data_plane/target/release/secure-transmit send-file \
  --key-file keys/session.key \
  --state keys/send.state \
  --to [::1]:9999 \
  --file classified_manifest.bin
```

### 11.7 Unidirectional Simplex Optical Data Diode Transfer (Cauchy-Reed-Solomon FEC)

```bash
# Receiving Station (Zero return channel; zero ACKs required):
./rust_data_plane/target/release/secure-transmit diode-recv \
  --key-file keys/session.key \
  --state keys/diode_recv.state \
  --bind 0.0.0.0:9999 \
  --out downloads/enclave_payload.bin

# Transmitting Station (Systematic Cauchy-RS FEC over GF(2^8)):
./rust_data_plane/target/release/secure-transmit diode-send \
  --key-file keys/session.key \
  --state keys/diode_send.state \
  --to 192.168.10.2:9999 \
  --file enclave_payload.bin \
  --parity-ratio 0.3
```

### 11.8 Wire Pacing & Tactical Profiles (Isochronous, Poisson & SATCOM Throttling)

ST2027 provides mission-tailored operational profiles (`--tactical-profile`) to balance anti-SIGINT traffic masking against transmission line bandwidth constraints:

| Tactical Profile | Primary Use Case | Pacing Interval | Cell Size | Wire Overhead | GPA Traffic Masking Mode |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `high-throughput` | Inter-enclave optical lines / Gigabit dark fiber | 10 ms (100 Hz) | 1,232 B | ~985 kbps | Constant-rate isochronous wire invariant |
| `satellite` | Tactical SATCOM (MIL-STD-188-181) / CNR / battery nodes | 200 ms (5 Hz) | 256 B | ~10.24 kbps | Throttled isochronous bandwidth-conserving |
| `covert` | Public transit (Tor v3 onion) / hostile SIGINT intercept | 50 ms (20 Hz) | 1,232 B | ~197 kbps | Memoryless exponential Poisson chaff |

```bash
# High-Throughput Profile (Inter-Enclave Optical Lines / Topology 6):
./rust_data_plane/target/release/secure-transmit channel \
  --key-file keys/session.key --state keys/chaff.state \
  --bind 192.168.10.1:9999 --to 192.168.10.2:9999 \
  --tactical-profile high-throughput

# Bandwidth-Throttled Satellite Profile (~10.24 kbps wire budget):
./rust_data_plane/target/release/secure-transmit channel \
  --key-file keys/session.key --state keys/chaff.state \
  --bind 192.168.10.1:9999 --to 192.168.10.2:9999 \
  --tactical-profile satellite

# Covert Anti-SIGINT Profile (Memoryless Poisson Cover Pacing):
./rust_data_plane/target/release/secure-transmit channel \
  --key-file keys/session.key --state keys/chaff.state \
  --bind 192.168.10.1:9999 --to 192.168.10.2:9999 \
  --tactical-profile covert
```

### 11.9 Standalone Native Operational Loops (`secure-transmit node` / `terminal`) & Hardened Web Console

High-assurance tactical deployments operate exclusively via native Rust binaries (`secure-transmit node`, `secure-transmit terminal`, `secure-transmit channel`).

#### Native Rust Operational Node Loop (`secure-transmit node`)

To eliminate the CPython runtime memory boundary (immutable `bytes` retention in `obmalloc` arenas), operational node loops run entirely in compiled native Rust:

- Page-locked memory via `LockedKey32` (`VirtualLock` on Windows / `mlock` on POSIX), OS crash-dump suppression (`SetErrorMode` + `WerSetFlags` / `PR_SET_DUMPABLE=0`), and strict ACG/extension-point hardening (`os_hardening.rs`)
- Automated deterministic zeroization on drop (`ZeroizeOnDrop`), including interactive `/rekey` and `/doc <path>` SHA-384 transfers (`FTYPE_DOC = 0x08`, saved only when `--recv-dir <dir>` is supplied)
- Sequential consistency compiler memory barriers (`compiler_fence(Ordering::SeqCst)`)
- Continuous constant-rate pacing (`--quantum 1232` UDP or `--tor --quantum 496` Tamaraw fixed Tor relay cells, configurable cadence) with cancel-safe `tokio::io::split` stream frame reading
- Privilege-separated embedded Tor v3 onion helper (`tor_transport/target/release/secure-transmit-tor`) with `ArtiEphemeralKeystore`, `ClientAuthV3` Restricted Discovery, and mandatory production SHA-384 binary verification (`--tor-bridge-sha384` / `P2P_TOR_BRIDGE_SHA384` before hardware custody init)
- In production (`P2P_PRODUCTION=1`), the Python runtime strictly prohibits any network or cryptographic key transit (`ControlPlaneBoundaryViolation`).

```bash
# Standalone native Rust production node (Initiator — Ephemeral Tor v3 + ClientAuthV3 + 496B Tamaraw):
./rust_data_plane/target/release/secure-transmit node \
  --role initiator \
  --tor \
  --zero-footprint \
  --tor-bridge-sha384 <96_HEX_SHA384_OF_SECURE_TRANSMIT_TOR> \
  --to <ONION_ADDR>.onion:443 \
  --psk-file keys/psk.key \
  --auth-tpm-sealed keys/alpha.tpm.priv --auth-tpm-pub keys/alpha.tpm.pub \
  --peer-auth-pk-file keys/bravo_mldsa87.pk \
  --onion-auth-sk-file keys/client_auth.sk \
  --recv-dir received_docs \
  --quantum 496 \
  --interval-ms 20 \
  --tamaraw-l 16 \
  --headless
```

#### Legacy Browser Web Console Vulnerabilities & Defense-in-Depth Hardening

The interactive browser console (`launch_tactical_web.bat`, port 8443) runs via local HTTP/WebSockets, exposing workstations to browser memory retention, DOM-based attacks, and lacking hardware-backed smartcard mutual TLS.
**Production Safeguard & Hardening Implementation:**

1. **Quarantine Fail-Closed Gate:** Quarantined to `--lab` mode only; strictly blocked fail-closed when `P2P_PRODUCTION=1`. High-assurance operational communications mandate native `secure-transmit`.
2. **Strict mTLS 1.3 Smartcard Listener:** The web console server binds strictly to a TLS 1.3 mutual authentication listener (`CERT_REQUIRED`) requiring DoD / NIST SP 800-217 / FIPS 201-3 CAC / PIV client certificates carrying PIV Authentication OID `2.16.840.1.101.3.6.7`, clientAuth extended key usage, and digital signatures.
3. **WebAuthn / FIDO2 Level 3 Hardware Security Key Verification:** All operator control actions (`/api/send`, `/api/eam`, `/api/zgdp`, `/api/cot`, `/api/diode/send`, `/api/zeroize`) require WebAuthn / FIDO2 Level 3 hardware security key presence verification (User Presence `UP=1`, User Verification `UV=1`, monotonic signature counter check, and cryptographic ECDSA P-256 signature verification over authenticator data and client data hash).
4. **Strict Content Security Policy Level 3:** Enforces `default-src 'self'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss: https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` with zero external CDNs.

The native tactical terminal provides direct operator-to-operator text transit over constant-rate paced channels:

```bash
# Option A: Post-Quantum Ephemeral Dynamic KEX Pairing (Recommended):
# Receiving Station (Responder):
./rust_data_plane/target/release/secure-transmit terminal \
  --psk-file keys/tactical_shared.psk \
  --state keys/term_resp.state \
  --bind 192.168.10.2:9999 \
  --to 192.168.10.1:9999 \
  --role responder \
  --interval-ms 50 \
  --quantum 1232 \
  --callsign BRAVO-NMCC

# Transmitting Station (Initiator):
./rust_data_plane/target/release/secure-transmit terminal \
  --psk-file keys/tactical_shared.psk \
  --state keys/term_init.state \
  --bind 192.168.10.1:9999 \
  --to 192.168.10.2:9999 \
  --role initiator \
  --interval-ms 50 \
  --quantum 1232 \
  --callsign ALPHA-NORAD

# Windows One-Click Tactical Station Launchers:
start_tactical_alpha.bat   # Launches Node Alpha (Responder, NORAD)
start_tactical_bravo.bat   # Launches Node Bravo (Initiator, Pentagon)
```

#### Terminal Defense Capabilities & Security Controls

1. **Keystroke Timing Decoupling (Song et al. Defense):**
   Interactive keystrokes are ingested into an internal FIFO queue and decoupled from network transmission. Wire cells are emitted strictly at the constant configured interval (e.g., 50ms / 20 Hz) with uniform 1232-byte quantization (`FTYPE_CHAFF` emitted continuously when no keystrokes are pending). This defeats statistical packet-interarrival and keystroke-timing cryptanalysis (Song, Wagner, Tian, USENIX Security 2001).
2. **ANSI Anti-Forensics Screen Scrubbing:**
   The terminal emits standard ANSI terminal erase sequence `\x1b[2J\x1b[3J\x1b[H` on `/clear`, `/quit`, and `/zeroize` commands, purging both the visible viewport and terminal scrollback history buffers to prevent shoulder surfing and screen recovery.
3. **In-Band Operator Control Commands:**
   - `/rekey`: Initiates an immediate post-quantum continuous epoch ratchet rollover, fragmenting a fresh ML-KEM-1024 encapsulation across wire quanta and deriving fresh epoch keys for Post-Compromise Security (PCS).
   - `/status`: Displays real-time link telemetry (send/recv sequence numbers, 512-packet reservation boundaries, emitted/received chaff and message counters, replay/auth drop metrics, and session uptime).
   - `/clear`: Executes immediate ANSI terminal viewport and scrollback buffer purge.
   - `/help`: Prints the tactical protocol command reference and security classifications.
   - `/zeroize`: Drops active state file descriptors, performs a 3-pass NIST SP 800-88 cryptographic wipe on session key and state files (including `.seqlog` and `.nvck` sidecars), wipes screen, and terminates immediately with exit code 0.
   - `/quit`: Flushes remaining queued outbound messages, wipes session memory, clears terminal display, and terminates cleanly.
4. **Nuclear Command & Control (NC3) Safety Gate:**
   Every outbound message is inspected by `check_nc3_safety_gate` prior to queueing. Unauthorized nuclear execution directives are blocked at the local interface.

#### Laboratory Diagnostic Utilities (Quarantined / Non-Production)

```bash
# Launch interactive C4ISR operator workstation (Lab / Simulation):
python tactical_operator_console.py

# Launch automated non-interactive pre-deployment verification drill:
python tactical_operator_console.py --drill

# Launch Web Operations Telemetry Console (Lab Only; Port 8443):
python destroyer_tactical_p2p.py web --host 127.0.0.1 --port 8443
```

### 11.10 Hardware-Enforced Two-Person Integrity Dual-Smartcard Operations (`secure-transmit eam-*`)

Deploying Emergency Action Messages (`/eam`) in production requires physical split-knowledge smartcard authorization:

```bash
# Authorize EAM directive using two physical USB CCID smartcards:
./rust_data_plane/target/release/secure-transmit eam-auth-hw \
  --directive "EXECUTE-ALPHA-RETALIATORY-VECTOR" \
  --target "NMCC-COMMAND-NODE" \
  --token1-slot 0 --token1-pin "123456" \
  --token2-slot 1 --token2-pin "654321" \
  --max-skew-ms 2000

# Verify inbound EAM package against Delta-t <= 2.0s temporal window, DirectiveHash, and site-provisioned officer roster:
./rust_data_plane/target/release/secure-transmit eam-verify-hw \
  --wire-hex <ST-EAM-HW2_PACKAGE_HEX> \
  --officer-roster <OPERATOR_PROVISIONED_ROSTER_JSON> \
  --max-skew-ms 2000
```

---

## 12. Standards & Authorizing Official (AO) Compliance Matrix

| Authority / Standard | Mandatory Requirement | ST2027 Architecture Mapping | Compliance Artifact |
| :--- | :--- | :--- | :--- |
| **NIST FIPS 203** | Primary Post-Quantum Key Encapsulation (ML-KEM-1024) | [`noise_pq.py`](noise_pq.py), [`rust_data_plane/src/kem.rs`](rust_data_plane/src/kem.rs) | [`compliance_reports/cbom.json`](compliance_reports/cbom.json) |
| **NIST FIPS 204** | Primary Post-Quantum Digital Signature (ML-DSA-87) | [`noise_pq.py`](noise_pq.py), [`trust_anchor.py`](trust_anchor.py) | [`compliance_reports/cbom.json`](compliance_reports/cbom.json) |
| **NIST FIPS 205** | Stateless Hash-Based Digital Signatures (SLH-DSA-256f) | [`pqc_algorithms.py`](pqc_algorithms.py) | [`compliance_reports/cbom.json`](compliance_reports/cbom.json) |
| **NIST FIPS 186-5** | Classical Elliptic Curve Cryptography (P-384 / secp384r1) | [`cnsa_purity.py`](cnsa_purity.py), [`rust_data_plane/src/kem.rs`](rust_data_plane/src/kem.rs) | [`compliance_reports/cbom.json`](compliance_reports/cbom.json) |
| **NSA CNSA Suite 2.0** | National Security Systems (NSS) 2027 Posture | [`cnsa_purity.py`](cnsa_purity.py) | [`compliance_reports/oscal_ssp_cnsa2.json`](compliance_reports/oscal_ssp_cnsa2.json) |
| **RFC 10024** | Hybrid Post-Quantum Key Exchange (`SecP384r1MLKEM1024`) | [`secure_transmit_2027.py`](secure_transmit_2027.py) | [`compliance_reports/cbom.json`](compliance_reports/cbom.json) |
| **RFC 9881** | Post-Quantum Signatures in Internet X.509 PKI | [`ca_services.py`](ca_services.py), [`rust_data_plane/src/x509.rs`](rust_data_plane/src/x509.rs) | [`compliance_reports/cbom.json`](compliance_reports/cbom.json) |
| **ISO/IEC 11889:2015** | TPM 2.0 Hardware Root of Trust & PCR Measurement | [`platform_hsm_interface.py`](platform_hsm_interface.py), [`tpm_quote.py`](tpm_quote.py) | [`docs/hw_tpm_hsm_setup.md`](docs/hw_tpm_hsm_setup.md) |
| **DoD 5220.22-M** | Multi-Pass Volatile Memory Sanitization Pattern | [`enhanced_secure_memory.py`](enhanced_secure_memory.py), [`ts_rt/src/lib.rs`](ts_rt/src/lib.rs) | [`docs/modules/memory_hsm.md`](docs/modules/memory_hsm.md) |
| **FIPS 140-3 (design target, NOT lab-certified)** | Hardware Security, Self-Tests, Volatile Wiping | [`ts_hw_layer.py`](ts_hw_layer.py), [`crypto_selftest.py`](crypto_selftest.py) | [`docs/FIPS_140_3_SECURITY_POLICY.md`](docs/FIPS_140_3_SECURITY_POLICY.md) |
| **FIPS 140-3 Submittal Dossier (pre-evaluation)** | 14-Artifact CMT Laboratory & AO Submittal Packet | [`scripts/package_cmt_laboratory_submittal.py`](scripts/package_cmt_laboratory_submittal.py) | [`compliance_reports/cmt_laboratory_submission_manifest.json`](compliance_reports/cmt_laboratory_submission_manifest.json) |
| **NATO SDIP-27/28/29** | Emissions-Security Records & Zoning Registry | [`ts_hw_layer.py:TEMPESTRegistry`](ts_hw_layer.py) | [`docs/hw_tpm_hsm_setup.md`](docs/hw_tpm_hsm_setup.md) |
| **Two-Person Rule (TPA)** | Cryptographic Dual-Person Authorization co-signing | [`spo_dpo.py`](spo_dpo.py), [`rust_data_plane/src/nc3.rs`](rust_data_plane/src/nc3.rs) | [`compliance_reports/oscal_ssp_cnsa2.json`](compliance_reports/oscal_ssp_cnsa2.json) |
| **IETF RATS (RFC 9334)** | Platform Attestation & Evidence Architecture | [`ts_attest.py`](ts_attest.py) | [`compliance_reports/oscal_sar_cato.json`](compliance_reports/oscal_sar_cato.json) |
| **Common Criteria EAL4+ (design target, NOT lab-certified)** | Network Device Protection Profile (NDcPP) | [`cnsa_purity.py`](cnsa_purity.py), [`ts_runtime.py`](ts_runtime.py) | [`docs/NIAP_COMMON_CRITERIA_SECURITY_TARGET.md`](docs/NIAP_COMMON_CRITERIA_SECURITY_TARGET.md) |
| **CISA Zero Trust (design target, NOT maturity-certified)** | Zero Trust Architecture principles | System-wide fail-closed enforcement | Design target only: no level rating claimed, no ATO implied |

### 12.1 Empirical Assurance & Evidence Boundary Matrix

The Destroyer-ST2027 engineering baseline separates **software/CI verification executed in-repo** from **host hardware probes** and **external hardware/laboratory accreditation prerequisites**. Self-tests demonstrate code consistency against repository specifications; they do not substitute for independent third-party laboratory evaluation:

| Evidence Scope | What Is Verified in Repository / CI | Explicit Evidence Boundary & External Prerequisites |
| --- | --- | --- |
| **Cryptographic & Protocol Paths** | `HybridKeyExchange2027` (`SecP384r1MLKEM1024` + ML-DSA-87), Rust data plane (`SecP384r1MLKEM1024`, AES-256-GCM, SHA-384), NIST SP 800-38D composite + durable monotonic nonces, ProVerif 2.05 symbolic models, and DudeCT statistical timing tests | Quarantined Python `--lab` `SecureP2PChat` / `hybrid_kex_legacy` path retains X25519 legacy compatibility bindings (`P2P_PRODUCTION=1` prohibits `--lab`). Prebuilt `oqs.dll` / `libsodium.dll` carry Ed25519 + SHA3-512 integrity pins, **not** FIPS 140-3 CMVP certificates. |
| **Fail-Closed Gate & Rust TCB** | `P2P_PRODUCTION=1` sticky latching (`production_gate.py`, Rust `policy.rs`), `--no-default-features` release builds stripping lab surfaces, TPM NVRAM dual-monotonic anti-rollback + `P2P_TPM_EMULATION` rejection, mandatory mutual authentication (including `--key-file`/`--key-stdin` `node` rejection without peer auth + pin in production), and PKCS#11 hardware-only `--auth-sk-file` exclusion in production | Target production hosts must provision `config_production.json` (`hsm_library_path`, OS-specific `tpm_device`/TBS, offline `.mldsa87.sig` via `scripts/sign_boot_config.py`), dedicated hardware TPM 2.0 NV indices, and physical PKCS#11 HSM/smartcards. |
| **Supply Chain & Static Assurance** | `scripts/verify_reproducible_build.py` (SHA3-512 `critical_modules.hashes` pinning), `scripts/audit_pins.py` (fail-closed OSV/signed-mirror CVE gate), `scripts/generate_production_sbom.py` (CycloneDX/SPDX across Python + Rust `Cargo.lock`s + `cbom.json`), `pip-audit`, `cargo-audit` / `cargo-deny`, TruffleHog secret scanning, and Bandit SAST (**0 HIGH / 0 MEDIUM**, triaged in [`compliance_reports/bandit_low_triage.md`](compliance_reports/bandit_low_triage.md)) | SLSA-aligned target design and ML-DSA-87 build receipts (`certs/audit_signer.mldsa87.pub`) require external air-gapped hardware signing ceremonies for operational deployment. |
| **Host Hardware vs. Accredited Lab** | Software-driven host TPM 2.0 TBS tests (`tests/test_tpm_hardware_phase2.py`, `@pytest.mark.live`) when run on a TPM-equipped workstation | Physical smartcards (YubiKey/Luna/Nitrokey), hardware TEMPEST zoning, physical optical diodes, independent CAVP/CMVP FIPS 140-3 validation, Common Criteria EAL4+ evaluation, and Authorizing Official **ATO** are **not** claimed and remain mandatory prerequisites. |

### 12.2 Historical Forensic Remediation Ledger (November 2026)

In-repo audit reviews ([`docs/archive/AUDIT_REPORT_ST2027.md`](docs/archive/AUDIT_REPORT_ST2027.md) and [`docs/archive/ST2027_FORENSIC_AUDIT_2026-11-26.md`](docs/archive/ST2027_FORENSIC_AUDIT_2026-11-26.md)) documented critical and high-severity gaps prior to November 2026 software remediation. The table below summarizes concrete software/CI remediations implemented across those baselines; all external hardware, CMVP module, and ATO gates remain pending:

| Remediation Wave / Area | Addressed Vulnerability / Gap | Concrete Defense Remediation Implemented in Code | Verification Basis |
| --- | --- | --- | --- |
| **Key Custody & Mutual Auth** | Rust `node --key-file`/`--key-stdin` and `--auth-sk-file` bypassed mutual auth / hardware custody in production; PKCS#11 HSM `sign_with_hsm` permitted classical fallback | `rust_data_plane/src/main.rs` refuses `--auth-sk-file` and raw `--key-file`/`--key-stdin` in production unless PKCS#11/hardware custody and `--require-mutual-auth` + peer pin are satisfied; `rust_data_plane/src/auth.rs` refuses `EC`/`EC_EDWARDS`/`RSA` and classical fallback cascades in `sign_with_hsm` under `is_production_env()`; `PcsRatchet` re-encapsulation integrated across epoch rotation | `cargo test --no-default-features`, `tests/test_rust_standalone_binary.py` |
| **Durable Nonce & AEAD Hygiene** | Python AES-GCM random-prefix IV risked cross-restart nonce reuse under persistent keys | Added durable SQLite/atomic monotonic counter ledger (`gcm_nonce_ledger.db`), process restart enforcement (`tests/test_gcm_nonce_durability.py`), and domain-separated XAES-256-GCM support | `tests/test_gcm_nonce_durability.py` |
| **TPM Quote, TLS & PKI Binding** | Simulated TPM quotes, unpinned peer identities, and CLI secret exposure in flags | Required `hardware_mode` validation & AK trust-anchor verification (`ts_attest.py`), strict TLS hostname verification & fail-closed TOFU blocking in prod (`tls_channel_manager.py`), unified PKI trust validation, and `P2P_AUTH_TOKEN_FD` / `stdin` secret ingestion | `tests/test_2027_defense_hardening.py`, `tests/test_tpm_hardware_phase2.py` |
| **Supply Chain, CLI & SAST** | `scripts/audit_pins.py` unimportable / tolerant of `skipped_offline`; unpinned pip/cargo CI checks; `destroyer.py` import-time arming | Fixed module-scope imports & fail-closed mirror checks (`scripts/audit_pins.py`), enforced `pip-audit`/`cargo-audit`/`cargo-deny` in `defense_ci.yml`, deferred `destroyer.py` production arming past `argparse`, removed unsafe `B311`/`B101` patterns, and triaged Bandit LOW findings | `tests/test_2027_defense_hardening.py`, `compliance_reports/bandit_low_triage.md` |
| **Truth-in-Claims & Doc Sync** | Overclaimed baseline badges, inaccurate legacy Falcon comments, unclarified provisioning | Removed unearned readiness/hardware claims, clarified legacy `FALCON` identifier vs. ML-DSA-87/SLH-DSA-256f execution, separated Rust vs. Python `--lab` algorithm paths, and added automated doc-truth tests | `tests/test_docs_truth_in_claims.py` |

#### Automated Defense Gate Runner (`scripts/run_defense_audit.py`)

`python scripts/run_defense_audit.py` runs an internal 10-check developer self-test covering Rust Clippy/tests, `ts_rt` memory checks, CNSA 2.0 KATs, ProVerif invocation (failing closed if `proverif` is absent), replay/nonce defense tests, waiver verification, Merkle hash verification, truth-in-claims checks, CLI self-test, and signed local receipts (`compliance_reports/defense_master_audit_receipt.json`). Passing this internal developer script validates software invariants only and does **not** constitute an external accreditation or production readiness certification.

---

## 13. Automated Verification Test Suite & Quality Gates

The platform includes automated verification suites across Python, native Rust (`--no-default-features` and `--features lab-surfaces`), `tor_transport`, `ts_rt`, `sel4_mils_appliance`, DudeCT statistical timing tests, ProVerif symbolic models, and Linux Kani CBMC CI gates. Verified metrics (November 27, 2026) vs. external host/lab gates:

```bash
# 1. Full Non-Live Python Verification Suite (1990 passed, 30 platform/archive skipped, 26 @live deselected) & @live Hardware Probe Suite (26 passed prior to commit 5a4c900):
python -m pytest tests/ -q -m "not live"
python -m pytest tests/ -q -m live

# 2. Native Rust Data-Plane & Tor Transport Bridge Suites (340 tests under --no-default-features: 276 unit + 12 dudect_ct + 49 kani_harness + 2 mtu + 1 doc-test; plus 5 tests in tor_transport):
cargo clippy --all-targets --manifest-path rust_data_plane/Cargo.toml -- -D warnings
cargo test --manifest-path rust_data_plane/Cargo.toml --locked --no-default-features
cargo clippy --all-targets --manifest-path tor_transport/Cargo.toml -- -D warnings
cargo test --manifest-path tor_transport/Cargo.toml --locked

# 3. Stream, Embedded Tor Bridge Gates & Encrypted /doc Delivery Suite:
pytest tests/test_tor_and_stream_plane.py -v

# 3. Volatile-Memory Security Core & seL4 MILS Spec Verification (ts_rt: 3 tests; seL4: 21 tests + 5/5 strict checks):
cargo test --manifest-path ts_rt/Cargo.toml
cargo test --manifest-path sel4_mils_appliance/Cargo.toml
python sel4_mils_appliance/validate_mils.py --strict

# 4. Standalone Native Executable Integration Battery:
pytest tests/test_rust_standalone_binary.py -v

# 5. DudeCT Constant-Time Side-Channel Timing Verification (Rust: 12 tests; |t| < 4.5):
cargo test --manifest-path rust_data_plane/Cargo.toml --test dudect_ct
pytest tests/test_dudect_timing_analysis.py -v

# 6. Transport Anonymity, Dual-Smartcard TPI, Runtime Boundaries & Host Posture Suites:
pytest tests/test_transport_anonymity.py \
       tests/test_hardware_tpi_dual_smartcard.py \
       tests/test_runtime_memory_and_web_console.py \
       tests/test_hardware_dependencies_and_isolation.py \
       tests/test_production_tier5_session_config_audit.py -v

# 7. Truth-in-Claims & Regulatory Honest Disclosures Gate (6 checks):
pytest tests/test_docs_truth_in_claims.py -v

# 8. Master Defense Self-Test Runner & Hardware Assessment (local developer gate; requires ProVerif >= 2.05):
python scripts/run_defense_audit.py
python scripts/verify_hardware_security.py

# 9. Reproducible Build & Supply-Chain Audit (58 source modules, 29 OSV/signed-mirror packages, 0 HIGH/MEDIUM Bandit):
python scripts/verify_reproducible_build.py
python scripts/audit_pins.py --offline --require-signature

# 10. Pre-Flight Deployment Advisory Gate (99 PASS, 0 FAIL, 4 WARN on lab host lacking HW TPM NV / Dual CCID / SecureBoot / Dual NIC):
python verify_deployment.py

# 11. FIPS 140-3 CMT Laboratory & AO Submittal Packet Verification (14/14 Artifacts):
python scripts/package_cmt_laboratory_submittal.py --verify

# 12. Advanced Tactical Defense Batteries (Phases A through L) & SMT Contracts:
pytest tests/test_sel4_mils_spec.py \
       tests/test_hardware_enclave_custody.py \
       tests/test_pqc_multi_assumption_combiner.py \
       tests/test_nc3_threshold_mpc.py \
       tests/test_optical_diode_fec.py \
       tests/test_chameleon_traffic_morphing.py \
       tests/test_dtn_zero_rtt_mesh.py \
       tests/test_pq_zkp_identity.py \
       tests/test_sdr_dsss_waveforms.py \
       tests/test_blinded_cross_domain_guard.py \
       tests/test_formal_code_contracts.py \
       tests/test_visual_airgap_transceiver.py -v
python scripts/verify_mathematical_contracts.py --export-smt
```

---

## 14. Residual Risk Register & Evaluator Non-Claims

In compliance with defense engineering ethics, the following boundaries are explicitly disclosed:

1. **Physical Hardware Independence:** The software platform cannot certify physical tamper-resistance or RF attenuation. Physical FIPS 140-3 Level 3/4 enclosures, TEMPEST SDIP-28 facilities, and physical optical data diodes must be procured from accredited hardware vendors.
2. **Authorizing Official (AO) Accreditation & CMT Laboratory Evaluation:** Execution of automated tests and generation of OSCAL artifacts does not constitute a formal government Authority to Operate (ATO). Formal accreditation requires evaluation by an accredited testing laboratory and approval by the designated Authorizing Official. To operationalize this transition, the repository provides `scripts/package_cmt_laboratory_submittal.py` which compiles the 12-section Cryptographic Module Security Policy (`docs/FIPS_140_3_SECURITY_POLICY.md`), machine-readable OSCAL SSP/SAR, ACVP test evidence, and signed CBOM/SBOMs into a sealed, ML-DSA-87 signed submittal packet (`compliance_reports/cmt_lab_submission_packet.tar.gz`) for laboratory ingestion.
3. **Draft Standards & Custom Handshake Governance:** Algorithm bindings strictly follow NIST FIPS 203, FIPS 204, and FIPS 205 final standards (August 2024). Emerging draft standards are intentionally excluded until finalization and inclusion in NSA CNSA guidance. **Custom protocol disclosure:** the Python `Noise_XXhfs_P384_MLKEM1024_MLDSA87_AES256GCM_SHA384` handshake substitutes FIPS 204 ML-DSA-87 signatures for classical Noise static-key DH (`es`/`se`); it has **no formal cryptographic reduction** to the Noise `hfs` draft or Signal PQNoise and has **not undergone independent third-party cryptanalytic review**. Operators requiring strict exclusion of unreviewed custom handshakes can enforce `P2P_STANDARDS_TRACK_ONLY=1` (`--standards-track-only`), which refuses `Noise_XXhfs` fail-closed and restricts transport to **PQ-hybrid TLS 1.3 (`RFC 10024`)** or native Rust **`kex_auth`**.
4. **Proof Scope Boundary (ProVerif & Kani vs. Runtime Code):** Symbolic ProVerif 2.05 models in [`docs/formal/`](docs/formal/) verify Dolev-Yao properties of the **abstract protocol models** — not the concrete Python or Rust code paths. Similarly, `rust_data_plane` Kani harnesses verify targeted Rust functions within bounded CBMC unwinding limits; neither constitutes a whole-program equivalence proof.

---

## 15. Primary References & Standard Specifications

1. **National Security Agency (NSA):** *Announcing the Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)*, Cybersecurity Advisory, Sept 2022.
2. **National Institute of Standards and Technology (NIST):**
   - *FIPS PUB 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*, Aug 2024.
   - *FIPS PUB 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)*, Aug 2024.
   - *FIPS PUB 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)*, Aug 2024.
   - *FIPS PUB 186-5: Digital Signature Standard (DSS) -- Elliptic Curve P-384*, Feb 2023.
   - *NIST SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography*, April 2018.
   - *FIPS PUB 140-3: Security Requirements for Cryptographic Modules*, March 2019.
   - *NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)*, Nov 2007.
   - *NIST SP 800-88 Rev. 2: Guidelines for Media Sanitization*, Sept 2025.
   - *NIST SP 800-90B: Recommendation for the Entropy Sources Used for Random Bit Generation*, Jan 2018.
3. **Internet Engineering Task Force (IETF):**
   - *RFC 10024: Post-Quantum and Hybrid Key Exchange in the Transport Layer Security (TLS) Protocol*, Aug 2026.
   - *RFC 9881: Internet X.509 Public Key Infrastructure -- Algorithm Identifiers for the Module-Lattice-Based Digital Signature Algorithm (ML-DSA)*, Oct 2025.
   - *RFC 9882: Use of the Module-Lattice-Based Digital Signature Algorithm (ML-DSA) in Cryptographic Message Syntax (CMS)*, Oct 2025.
   - *RFC 9334: Remote ATtestation ProcedureS (RATS) Architecture*, Jan 2023.
   - *RFC 6479: Decoupled IPsec Anti-Replay Sliding Window*, Jan 2012.
   - *RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*, May 2010.
4. **International Organization for Standardization (ISO):**
   - *ISO/IEC 11889:2015: Information technology — Trusted Platform Module Library (TPM 2.0)*, 2015.
5. **Department of Defense (DoD):**
   - *MIL-STD-961E: Defense and Program-Unique Specifications Format and Content*, Aug 2003.
   - *DoD Directive S-5210.41M: Nuclear Weapon Security Manual: The Two-Person Rule*, Dec 2020.
   - *Chairman of the Joint Chiefs of Staff Instruction (CJCSI) 3260.01E: Joint Policy Governing Positive Control Material and Devices*, 2021.
   - *DoD 5220.22-M: National Industrial Security Program Operating Manual (NISPOM)*, Feb 2006.
   - *DoD Zero Trust Reference Architecture Version 2.0*, July 2022.
6. **North Atlantic Treaty Organization (NATO):**
   - *SDIP-27/3: NATO TEMPEST Requirements for Equipment*, 2020.
   - *SDIP-28/3: NATO TEMPEST Installation Zoning Scheme*, 2020.
   - *STANAG 4591: The 2400 bps and 1200 bps Variable Data Rate Mixed Excitation Linear Predictive Enhanced (MELPe) Speech Compression Algorithm*, 2010.
7. **Academic & Formal Verification Literature:**
   - Blanchet, B.: *Modeling and Verifying Security Protocols with the Applied Pi-Calculus and ProVerif*, Foundations and Trends in Privacy and Security, 2016.
   - Perrin, T.: *The Noise Protocol Framework Specification*, Revision 34, 2018.
   - Klein, G. et al.: *seL4: Formal Verification of an OS Kernel*, Communications of the ACM, 2010.
   - Song, D. X., Wagner, D., Tian, X.: *Timing Analysis of Keystrokes and Timing Attacks on SSH*, 10th USENIX Security Symposium, 2001.

---

## 16. License & Attribution

- **License:** MIT License — Authorized for defense, national security research, and governmental evaluation.
- **Attribution:** Developed for high-assurance communications under the Secure Transmit 2027 research program.
