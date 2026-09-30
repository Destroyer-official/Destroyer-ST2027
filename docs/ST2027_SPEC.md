# Sovereign Transmit 2027 (ST2027) — Military High-Assurance Specification & Implementation Plan

## Next-Generation Sovereign Information Exchange Architecture for Classified & Tactical Operations

**Author:** Sovereign Defense Communications Group
**Target Standard:** NSA CNSA Suite 2.0 (January 1, 2027 NSS Procurement Gate)
**Security Baseline:** NIST FIPS 203 (ML-KEM-1024), NIST FIPS 204 (ML-DSA-87), IETF RFC 10024, seL4 Microkernel Gating (hardware where deployed, signed waiver otherwise)
**Document Revision:** 2.1 (Post-Research Hardened Baseline, 2026-09-29)
**Status:** Engineering baseline targeting CNSA 2.0 technical specifications. Not lab-certified (FIPS 140-3 CMVP / Common Criteria), no Authority to Operate. See §5.

---

## 1. Executive Defense Summary: Why Consumer Messengers Fail in Military Theaters

Consumer end-to-end encrypted (E2EE) messaging systems such as **Signal** and **WhatsApp** were engineered for
commercial smartphones, consumer battery life, and public cellular networks. In a state-level electronic warfare (EW)
and signals-intelligence (SIGINT) combat theater, commercial design trade-offs introduce failure modes that no
amount of message-content encryption removes. Honesty note: Signal has deployed post-quantum forward secrecy
(PQXDH, Kret/Schmidt, rev. 3) — the critique below therefore rests on centralization, identity, traffic shape,
endpoint custody, and release authority, not on "no PQ."

```
+========================================================================================================+
|                       CIVILIAN DESIGN FLAW vs. SOVEREIGN MILITARY DEFENSE                              |
+========================================================================================================+
| 1. Centralized Cloud Infrastructure:                                                                  |
|    - Civilian: Relies on Amazon AWS, Microsoft Azure, or Meta servers. Single point of kinetic/cyber   |
|      failure; vulnerable to national-level IP blocking, server seizures, and lawful intercept.        |
|    - ST2027 Sovereign: Zero central servers. Pure point-to-point (P2P), tactical radio links, dark     |
|      fiber, or decentralized Tor v3 onion services (rend-spec-v3).                                    |
+--------------------------------------------------------------------------------------------------------+
| 2. Identity & Subscriber Metadata (E.164 Phone Numbers):                                              |
|    - Civilian: Mandatory phone numbers / SMS activation. Vulnerable to SS7 telecom interception,       |
|      IMSI catchers, base station spoofing, and carrier subscriber records.                            |
|    - ST2027 Sovereign: Zero phone numbers, zero user accounts. Identities are non-exportable hardware-  |
|      bound ML-DSA-87 cryptographic tokens sealed in TPM 2.0 silicon (CNG Platform Provider / PKCS#11). |
+--------------------------------------------------------------------------------------------------------+
| 3. Traffic Analysis & Flow Correlation (The SIGINT Threat):                                           |
|    - Civilian: Variable packet sizes and transmission bursts correlate directly with human typing and  |
|      message timing. A Global Passive Adversary (GPA) watching internet exchanges identifies who is    |
|      communicating with whom without breaking encryption.                                             |
|    - ST2027 Sovereign: Strict 50.0 ms (20 Hz) constant-rate clock emitting uniform 1232-byte cells.    |
|      Continuous cryptographically indistinguishable chaff cells. The wire profile is flat by design.    |
|      (Tamaraw-family regularization; see §2.7. Stated limit: statistical masking vs. local observers,  |
|      not mathematical security vs. a GPA — see traffic disclosure, §5.)                               |
+--------------------------------------------------------------------------------------------------------+
| 4. Endpoint Platform Seizure & Mobile OS Forensics:                                                   |
|    - Civilian: Keys stored in iOS/Android software keystores; vulnerable to forensic kits (Cellebrite,  |
|      GrayKey, Pegasus) and cold-boot physical RAM dumps.                                              |
|    - ST2027 Sovereign: OS-level non-pageable memory locking (VirtualLock/mlock in ts_rt; best-effort   |
|      in Python SecureBytes — see §3.2), TPM PCR state-drift sealing, PnP-enumerated anti-DMA posture   |
|      refusing execution without Kernel DMA Protection, and multi-trigger volatile zeroization.          |
+--------------------------------------------------------------------------------------------------------+
| 5. Single-Operator Coercion:                                                                          |
|    - Civilian: Any individual who unlocks the handset can transmit unauthorized messages.             |
|    - ST2027 Sovereign: Dual-Person Authorization (two-person control per DoD surety doctrine, §2.9)     |
|      requiring cryptographic co-signing with two independent hardware-bound ML-DSA-87 tokens.           |
+--------------------------------------------------------------------------------------------------------+
| 6. Bi-Directional Network Infiltration:                                                               |
|    - Civilian: Bi-directional TCP/IP requiring the receiver to acknowledge packets, allowing reverse   |
|      penetration into secure enclaves.                                                                |
|    - ST2027 Sovereign: Optical data-diode simplex path (no ACKs; Reed-Solomon FEC reconstruction)      |
|      with attested-device gating. Diode hardware is procured separately; without it the path refuses.  |
+========================================================================================================+
```

### The 3 Laws of Military Crypto Systems (adjudication rules used throughout)

1. **Radical minimalism.** The accredited core must be tiny (the Rust record core is 2,509 lines — inside the
   WireGuard-precedent band of <4,000). Experimental NC3 prototypes and research spikes stay in `archive/` and
   `quarantine/`, never in the accredited path.
2. **Zero secrets in user-space runtimes.** Confidential keys live in OS-locked non-pageable RAM or TPM/HSM
   silicon, zeroized immediately after use. Python `bytes` copies are short-lived, audited, and explicitly
   documented as non-wipeable (see limitation disclosures, §5).
3. **Provable invariants over marketing claims.** Every assurance states tool, version, query, and scope
   (e.g., "ProVerif 2.05 proves mutual injective agreement against Dolev-Yao in the symbolic model, excluding
   nonce discipline, which is enforced in code + tests"). No accreditation badges without a laboratory.

---

## 2. Theoretical Grounding & Academic Citations (2024–2026 Research)

1. **NIST FIPS 203 (August 2024):** *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM).*
   ML-KEM-1024 mandated for NIST Category 5 (256-bit classical and quantum margin). Sizes pinned in code and
   tests: ek 1568, dk 3168, ct 1568, ss 32.
2. **NIST FIPS 204 (August 2024):** *Module-Lattice-Based Digital Signature Standard (ML-DSA).* ML-DSA-87
   mandated for Category 5 signatures. Sizes pinned: pk 2592, sk 4896, sig 4627. Pre-hash variant
   (HashML-DSA) is prohibited by CNSA profiles and never used here.
3. **IETF RFC 10024 (August 2026, Standards Track):** *PQ/T Hybrid Key Agreement for TLS 1.3* —
   `X25519MLKEM768` (0x11EC/4588), `SecP256r1MLKEM768` (0x11EB/4587), `SecP384r1MLKEM1024` (0x11ED/4589).
   The outer envelope targets the L5 group (P-384 + ML-KEM-1024); security holds if *either* leg holds
   (combiner framework: RFC 9954, July 2026; terminology: RFC 9794). Only these three hybrid groups exist;
   phantom names formerly present in policy tables were removed during verification (see Appendix B).
4. **Noise Protocol Framework rev. 34 (Perrin, 2018-07-11, official/unstable):** XX
   (`-> e / <- e, ee, s, es / -> s, se`), "the most generically useful" mutual-auth pattern. HFS extension
   (`noise_hfs_spec`, rev. 1, unofficial draft — not peer-reviewed): `e1`/`ekem1` tokens. Our profile follows
   that skeleton with one documented custom substitution (es/se → ML-DSA-87 transcript signatures,
   SIGMA-style, unproven — stated as assumption). Peer-reviewed KEM-Noise generally: PQNoise (Angel et al.,
   CCS 2022).
5. **Signal specifications (contrast reference):** X3DH rev. 1 (2016), Double Ratchet rev. 4 (2025), PQXDH
   rev. 3. Formal analyses: Cohn-Gordon et al., J. Cryptology 2020; Alwen et al., EUROCRYPT 2019.
6. **Minimalism precedent:** WireGuard at under 4,000 lines (Dowling–Paterson 2018; CERIAS 2021; Noise_IK).
   Recorded counterpoint: WireGuard's suite (ChaCha20-Poly1305/BLAKE2s) is not CNSA-admissible — minimalism
   and CNSA-strictness are independent axes; the Iron Core targets both.
7. **Traffic-analysis defense:** Tamaraw (Cai et al., CCS 2014) — constant-rate fixed-size cells give an
   information-theoretic bound on website-fingerprinting success at 199–687% bandwidth overhead; Adaptive
   Tamaraw (NDSS 2026) retains bounds at reduced cost. Loopix (USENIX Security 2017, Piotrowska et al.) —
   Poisson mixing plus cover loops; third-party sender/receiver unobservability against a GPA. Our shaping
   is Tamaraw-family; Loopix bounds the honest statement of what cover traffic does and does not buy.
8. **Tor v3 onion services** (rend-spec-v3, proposal 224; ed25519 56-char addresses; offline keys; client
   authorization) carried over **RFC 1928 SOCKS5** (port 1080, CONNECT, domain-name addressing — hostname
   resolved by the proxy, no local DNS leak). Tor resists local observers, not entry/exit correlation by a GPA.
9. **Two-person control:** DoD nuclear surety doctrine — the two-person rule as "the most important aspect of
   procedural security" (NMHB 2020), DoDI 3150.02 (Dec 2024 reissue), DoDM 5210.42 PRP. Cryptographic
   embodiment: SPO single hardware-bound approval; DPO two distinct hardware-bound approvals over one fresh
   challenge (`spo_dpo.py`). Root CA: 3-of-5 multi-signature quorum (mislabeled "Shamir" in an earlier README
   revision — corrected; Shamir+VSS is correctly used for key *backup* in `threshold_cryptography.py`).
10. **One-way transfer:** Fort Fox FFHDD EAL7+ Security Target (CC portal, 2023), BAE Data Diode EAL7+
    (NIAP), Owl XDE EAL4+; BAE's sequenced-UDP reconstruction validates FEC-over-simplex design.
    Implementation: Cauchy Reed-Solomon GF(2^8) erasure coding (any K of K+M), signed manifest framing,
    zero-feedback discipline (`tactical_data_diode.py`).
11. **Memory & attestation:** TCG TPM 2.0 (measured boot, PCRs); IETF RATS RFC 9334 (Jan 2023, Informational —
    Attester/Verifier/Relying Party; Passport and Background-Check models); FIPS 140-3 (ISO/IEC 19790; CMVP
    certificate #4985, OpenSSL 3.1.2, active to 2030-03-10). Symmetric/hash/KDF standards: AES-256-GCM
    (FIPS 197 / SP 800-38D), SHA-384 (FIPS 180-4, CNSA-preferred), HKDF-SHA384 (RFC 5869).
12. **Machine-checked methods:** ProVerif (Blanchet, Inria — fully automatic, unbounded sessions, Dolev-Yao;
    applied to Signal and TLS); Kani (Delmas et al., ASE 2026; CBMC engine per Kroening & Tautschnig 2014;
    16,000-harness std-verification campaign; install targets Linux/Mac — our proofs are defined in-repo,
    execution requires that toolchain).

Excluded with prejudice (verified non-standard or draft): Classic McEliece (Round-4 unselected; HQC selected
Mar 2025, IR 8545, FIPS 207 in development), pre-standard Falcon/FN-DSA (FIPS 206 draft; FN-DSA ≠ Falcon
wire format), SLH-DSA as a CNSA claim (FIPS 205 final but not CNSA-listed — kept only as documented
defense-in-depth secondary, never as the acquisition claim), ChaCha20-Poly1305, Kyber/Dilithium pre-standard
names (ML-KEM/ML-DSA are not wire-compatible with them).

---

## 3. Architecture: Iron Core, Session Layer, and the Three Tactical Modes

### 3.1 The Iron Core (`rust_data_plane/`, 2,509 lines)

Modules: `aead` (AES-256-GCM framing), `replay` (branchless 64-bit anti-replay window, RFC 6479 discipline),
`frame` (1232B quanta, split/reassemble), `kem` (X25519+ML-KEM interop surface — library only, never the
binary path), `net` (UDP datagrams, 1280B cap), `nostd_microcore` (no_std stack-allocated framing),
`ct` (constant-time compare/select; best-effort hardening, not machine-checked — stated in-file),
`chaff`/`pad` (chaff typing, padding budgets), `main` (`secure-transmit` binary: pre-shared-key AEAD
transport with `STSTATE1` 48-byte monotonic state under OS file locking, `--key-file`/`--key-stdin` only —
CLI key/nonce reuse refused by construction).

Binary reality (PE-verified 2026-09-29): release build produced (`target/release/secure-transmit.exe`,
406 KB, LTO + `panic=abort`, 54 s build). It imports the VC++ runtime (`VCRUNTIME140.dll` + CRT API
sets) alongside system libraries: single-file executable, **not** a zero-dependency static binary.
OS page-locking IMPLEMENTED 2026-09-29 (`src/memlock.rs`: `LockedKey32` heap-stable guard, VirtualLock /
mlock port of the `ts_rt` pattern, zero new dependencies; `main.rs` key path rewired 1:1 with identical
key lifetime; release selftest reports `memlock-probe locked`; UDP loopback verified through the locked
path). Remaining: static-CRT bin-crate split (dynamic CRT confirmed in release PE).

### 3.2 Session Layer (Python-orchestrated; boundary stated)

The full session — XXhfs handshake (`noise_pq.py`), PKI/quorum (`trust_anchor.py`), Tor overlay
(`transport_anonymity.py`), dual-person release (`spo_dpo.py`) — is Python-orchestrated. "Python-free"
applies strictly to the pre-shared-key record-layer tool. Porting the handshake into the Iron Core is
roadmap item 3. Python secret hygiene: short-lived `bytes`, `SecureBytes` destruction on all exit paths,
no secret logging, documented GC-copy limitation.

### 3.3 The Three Tactical Modes

| Mode | Mechanism | Module mapping | Honesty note |
|---|---|---|---|
| A Diode (highest tier) | Simplex UDP, manifest framing, RS-FEC any-K-of-(K+M), HW-custody-signed packages, ceremony-established keys (interactive handshake forbidden across the diode) | `tactical_data_diode.py`, `ts_hw_layer.py` TS-5 gate | Software path complete; diode *devices* require procurement + registry attestation, else refuse |
| B Direct P2P / dark fiber | 1232B cells on a strict 50 ms (20 Hz) clock, cover cells when idle, AES-256-CTR whitening | `transport_anonymity.py` pacer + `rust_data_plane` framing | The strict clock is the Python pacer; Rust `net.rs` uses 50 ms as a receive timeout and Rust chaff is random-interval — credited jointly |
| C Tor onion (hostile internet) | Tor v3 via local SOCKS5, overlay-required gate, constant-rate uniform cells inside the tunnel | `transport_anonymity.py` | Live daemon mandatory; GPA entry/exit correlation limits disclosed |

### 3.4 Dual-Person Authorization

SPO: one hardware-bound ML-DSA-87 approval over a fresh challenge. DPO: two distinct hardware-bound
approvals over the same challenge within a 2-second window; software passphrases alone never authorize in
production; refusal is fail-closed and logged without oracle detail.

---

## 4. Formal Verification Scope (exact)

- `docs/formal/st2027_handshake.pv` (ProVerif 2.05, executed in 4.0 s on 2026-09-29): payload secrecy vs.
  active Dolev-Yao attacker, mutual injective agreement on (session key, full transcript), forward secrecy
  under post-session long-term compromise, no-forgery/no-replay on the record layer; PCS model with
  negative control (compromise provably takes effect on the control query, healing on the live query).
  Documented abstractions: HKDF dual-PRF assumption, one-way symbolic KDF, symbolic AEAD (nonce discipline
  enforced in code + tests, not in proof), sizes/padding abstracted, outer TLS unmodeled (inner proven
  standalone), TOFU scoping conditioned on honest peer keys.
- `rust_data_plane/tests/kani_harness.rs`: 5 `#[kani::proof]` harnesses (defined; execution requires the
  Kani+CBMC toolchain on Linux/Mac) plus 7 deterministic property doubles executed green under `cargo test`.
- Master audit `scripts/run_defense_audit.py`: 9 gates (Rust clippy+tests, ts_rt, KATs/purity, ProVerif,
  exploit battery, platform gates, supply chain, truth-in-claims, selftest) — all green on 2026-09-29 in
  about 60 seconds with an ML-DSA-87-signed receipt
  (`compliance_reports/defense_master_audit_receipt.json` + `.sig`).

---

## 5. Evaluation Boundary (stated, not footnoted)

This software is an engineering baseline designed to meet the technical specifications of CNSA 2.0. It has
not undergone accredited laboratory evaluation (FIPS 140-3 CMVP / Common Criteria) and does not possess a
government Authority to Operate (ATO). Python immutable `bytes` objects cannot be wiped deterministically
due to runtime garbage collector copies — high-assurance deployments must execute record transport via the
native Rust data-plane. Constant-rate shaping provides statistical masking against local observers only.
Blocked on procurement/process (not code): HSM deployment, SCIF/TEMPEST accreditation, diode devices, seL4
hardware target, CMVP validation of the Rust core, AO authorization.

---

## 6. Roadmap (sequenced)

Execution order lives in `docs/ST2027_IMPLEMENTATION_PLAN.md` (zero-gap doctrine, cost ledger,
pillar mapping, phase acceptance criteria). Status deltas below.

1. Release build of `secure-transmit` — DONE 2026-09-29 (406 KB, LTO, `panic=abort`).
   Static-CRT scoping remains: dynamic CRT confirmed in the release PE, so the bin-crate split
   (bin static, `cdylib` dynamic — dual-CRT hazard otherwise) is still pending. Mechanism verified
   (RFC 1721: `target-feature=+crt-static`).
2. OS page-locking for Iron Core secret buffers — DONE 2026-09-29 (`src/memlock.rs`, 4 unit tests;
   gate counts updated 35→39 lib; live `locked` probe + loopback green).
3. XXhfs handshake port boundary documented as architecture; port as follow-on.
4. Kani proof execution on Linux CI (harnesses already defined).
5. CMVP/FIPS module path, Common Criteria engagement, ATO sponsorship.
6. Standards tracking (monitor-only, never drafts in the session path):
   - FIPS 207 (HQC): no final standard (Sept 2026); draft expected 2026, final 2027. Active development:
     NIST leans toward **seed-only** private keys (Robinson, Aug 2026; Bernstein opposes a caching ban,
     Westerbaan/Connolly want caching freedom) — wire formats *will* change at IPD. Our HQC quarantine
     (disabled by default, CVE-gated on oqs 0.10.1) stays until final. Consistency note: our baked
     HQC-256 sizes (pk 7245 / sk 2289 seed-form / ct 14421 / ss 64) match published Round-4 figures.
   - FIPS 206 (FN-DSA): Initial Public Draft published; final anticipated early 2027. Sizes identical to
     Falcon (1024: 1280/1793/2305) but behavior differs (randomized-only signing, no seed export,
     exact-KAT float discipline) — migration opens only at final.
   - Overhead research: Adaptive Tamaraw evaluation for future pacing work (see Appendix C).

---

## Appendix A — Research Bibliography (all sources fetched and verified, September 2026)

NIST FIPS 203/204/205 (final Aug 13, 2024); NIST IR 8545 (HQC selection, Mar 2025); IETF RFC 10024, RFC 9954,
RFC 9794, RFC 9881, RFC 9334, RFC 1928, RFC 5869; NSA CNSA 2.0 Steady (IETF CNSA2 profiles for SSH/PKIX/S/MIME/CMC);
Perrin, Noise rev. 34 (2018) and `noise_hfs_spec` rev. 1; Angel et al., PQNoise, CCS 2022; Signal X3DH rev. 1,
Double Ratchet rev. 4, PQXDH rev. 3; Cohn-Gordon et al., J. Cryptology 2020; Alwen et al., EUROCRYPT 2019;
Dowling–Paterson 2018 (WireGuard analysis); Cai et al., Tamaraw, CCS 2014; Adaptive Tamaraw, NDSS 2026;
Piotrowska et al., Loopix, USENIX Security 2017; Tor rend-spec-v3; Blanchet, ProVerif (Inria) + Blanchet
2022 Horn-clause survey; Delmas et al., Kani, ASE 2026; Kroening & Tautschnig 2014 (CBMC); Fort Fox FFHDD
EAL7+ Security Target (2023); BAE Data Diode EAL7+; Owl XDE EAL4+; DoDI 3150.02 (2024); DoDM 5210.42;
NMHB 2020 (two-person rule); OpenSSL 3.5 release notes (Apr 2025); CMVP certificate #4985; seL4 Foundation
(AArch64 proofs complete Aug 2026).

## Appendix B — Claim-Correction Log (verification-driven changes)

2026-09-29 research + audit pass: (1) outer-TLS group gate reworked — `set_ecdh_curve` cannot control TLS 1.3
groups (CPython NID table; no `set_groups`; no group-observation exports in this build); TS posture now keys
on OpenSSL ≥ 3.5 hybrid-preferring defaults with the residual documented. (2) HFS citations corrected to
`e1`/`ekem1`, `noise_hfs_spec` rev. 1 (unofficial draft, no proofs); es/se→signature substitution stated as
custom assumption. (3) Phantom TLS groups (`SecP521r1MLKEM1024`, `X25519MLKEM1024`, `X25519+ML-KEM-1024`)
and squatted codepoints purged from policy engines, channel manager, and docs; real RFC 10024 groups and
codepoints (0x11EB/0x11EC/0x11ED) installed. (4) "CNSA 2.0 Sovereign Max" branding removed (fabricated tier).
(5) Root CA mechanism corrected to multi-signature quorum. (6) CBOM/SLH-DSA CNSA claim and Falcon/FN-DSA
labels corrected. (7) This spec records binary/locking/Python-boundary/pacer realities from PE and source
evidence rather than aspiration.

## Appendix C — Constant-Rate Overhead Analysis (from verified design parameters)

Design: 1232-byte cells at 20 Hz per direction (independent ρ_out = ρ_in = 50 ms).
Idle burn: 1232 × 20 = 24,640 B/s ≈ **2.13 GB/day per direction** (≈ 4.3 GB/day bidirectional) —
the price of presence concealment, which website-fingerprinting defenses do not buy.
Bulk transfer at line rate: cover fraction tends to zero, so marginal overhead vanishes; the stream
is uniformly shaped regardless. Comparison honest framing: Tamaraw (Cai et al., CCS 2014) proves an
information-theoretic bound on *website-classification* success at 199–687% bandwidth overhead with
tuned asymmetric rates; our threat model is *presence/unobservability*, where the uniform-rate
mechanism removes size and timing features entirely (stronger for those features) at constant burn.
The Tamaraw ε-bound does not transfer to our model — claimed family resemblance only, plus a stated
open evaluation: benchmark Adaptive Tamaraw (NDSS 2026) parameters against this profile.

## Appendix D — Deep-Research Log (second wave, 2026-09-29)

FIPS 207 IPD-watch (seed-only direction, wire-change risk); FIPS 206 IPD publication; RFC 1721
crt-static mechanism + cdylib dual-CRT constraint; in-repo VirtualLock precedent (`ts_rt/src/lib.rs`);
HQC-256 size consistency check; overhead arithmetic above. Prior wave: Appendix A/B provenance.
