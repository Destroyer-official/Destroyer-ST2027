# ST2027 Zero-Gap Implementation Plan — Maximum Cost-to-Break Doctrine

**Document:** Full implementation plan, Rev. 1.0 (2026-09-29)
**Doctrine (binding):** *"Making an unhackable system is impossible; therefore, every single transmission
is made so computationally and physically expensive to break that even millions of coordinated AI agents
armed with exascale quantum supercomputers cannot justify the cost. Every normal message is sealed with
the exact same rigor as a nuclear command directive."*
**Companion:** `docs/ST2027_SPEC.md` (architecture + research bibliography). This document is the execution order.

---

## 0. Adversary Model (who we price against)

| Adversary | Capability | Priced counter |
|---|---|---|
| A1. Global passive (GPA) | Backbone taps, ISP records, entry/exit correlation | 20 Hz uniform 1232B cells + cover; Tor v3; stated GPA limits disclosed, never claimed away |
| A2. CRQC operator (2030s) | Shor vs RSA/ECC (RSA-2048: <1M noisy qubits, <1 week — Gidney 2025, down from 20M/8h in 2019); Grover vs AES (2^128 floor) | Zero RSA/ECC/DH in session path; ML-KEM-1024 + ML-DSA-87 (Level 5 = AES-256-equivalent, 2^128 quantum floor); AES-256-GCM records; harvest-now-decrypt-later-proof by construction |
| A3. AI cryptanalysis swarm | Publishable breaks now ~USD 100k + 1 week model time (HAWK precedent, Jul 2026: Mythos halved lattice-reduction block size, 2^150→2^108 gate cost; team withdrew in 24h; 7-round AES-128 research record also fell) | Finalized-standards-only in session path; McEliece/Falcon/HQC quarantined; NEVER_AUTHORIZED gate (IR 8610 round-3, HashML-DSA, FN-DSA-as-primary); structural-attack monitoring (McEliece TII-252 AI-assisted record noted, ePrint 2026/1339) |
| A4. Supply-chain attacker | Malicious dep, build tamper, Vortex-style implants | Pinned/hashed DLLs + Ed25519, SBOM signatures, reproducible-build gate, hash-manifest CI on concurrently edited files |
| A5. Insider / coercion | Single operator backmail, theft, duress | DPA two-person rule (DoDI 3150.02 lineage); 3-of-5 CA quorum; duress handling; no single custodian can sign, revoke, or transmit |
| A6. Physical / endpoint | Cold boot, DMA, debuggers, seizure | VirtualLock/mlock + volatile wipe + PnP DMA scan + IOMMU requirement + RED/BLACK bind + TEMPEST registry + zero-plaintext-disk |
| A7. Implementation bugs | Memory unsafety (~70% of vulns industry-wide), logic flaws | Rust Iron Core (2,509 lines) + clippy `-D warnings` + Kani harnesses + ProVerif models + exploit regression battery + 9-gate audit |

## 1. Cost-to-Break Ledger (per transmission — every leg independent)

An attacker must pay for **each** leg; breaking one buys nothing (hybrid combiners hold if *either* input
is secret; independent languages, vendors, math families, and physical domains):

1. **Math leg (quantum):** ML-KEM-1024 + P-384 ECDHE → need BOTH a lattice break AND an elliptic-curve
   break; then AES-256-GCM at 2^128 quantum floor. No classical public-key anywhere in the path.
2. **Math leg (classical/AI):** Level-5 lattice + hash-based secondary where deployed; AI-swarm economics
   (~$100k/break) defeated by finalized-standards-only + agility (CSWP 39) + monitoring.
3. **Authentication leg:** ML-DSA-87 signatures, verify-before-decaps/derive, 48 h certs, quorum revocation.
4. **Transport leg:** 20 Hz uniform cells (≈2.13 GB/day/direction idle burn — the defender pays constant
   cost so the attacker gains zero signal); Tor v3 + no-local-DNS; diode simplex where deployed.
5. **Endpoint leg:** OS-locked pages, volatile wipe, DMA scan + IOMMU refusal, HSM custody refusal without
   hardware, anti-debug mesh.
6. **Human leg:** two-person cryptographic release; 3-of-5 quorum; witnessed ceremonies with receipts.
7. **Supply leg:** every binary pinned, every build reproduced, every critical file hash-gated.

## 2. DoD Zero Trust Pillar Mapping (Target Level by end FY2027 per DTM 25-003; NSS may require Advanced)

| Pillar | ST2027 embodiment |
|---|---|
| 1 User | Hardware-bound ML-DSA-87 identity tokens; no passwords alone authorize (production) |
| 2 Device | Attested platform preflight (SecureBoot/VBS/HVCI/DMA/CNG-TPM); seL4 gating or signed AO waiver |
| 3 App/Workload | Minimal Iron Core (2,509 lines); policy engines fail closed; no fallback code paths |
| 4 Data (central) | AES-256-GCM + PQ-hybrid key establishment; 48 h certs; CRL-style revocation; amnesia profile |
| 5 Network | Diode simplex / dark fiber / Tor; overlay-required gate; RED/BLACK bind; no wildcards |
| 6 Automation | 9-gate master audit with signed receipt; CI gates (clippy, KATs, ProVerif, Kani, loopback) |
| 7 Visibility | Audit events, ceremony receipts, Merkle-chained logs; duress and tamper telemetry |

## 3. Execution Phases

### Phase 0 — Doctrine lock (DONE 2026-09-29)
Adversary model, cost ledger, pillar mapping, this plan. Acceptance: this file merged.

### Phase 1 — Iron Core completion (IN PROGRESS)
- [x] `memlock.rs` page-locking guard + 4 unit tests (lib 35→39); live `locked` probe; loopback green.
- [x] Release build (406 KB, LTO, `panic=abort`); dynamic CRT confirmed by PE parse.
- [ ] Bin-crate split for static CRT (bin static, `cdylib` dynamic — dual-CRT hazard documented).
- [ ] Kani execution on Linux CI (workflow added `.github/workflows/kani-proofs.yml`; awaiting runner proof).
- [ ] Release selftest + loopback smoke in `defense_ci.yml` (added this turn — pending CI green).
Acceptance: master audit 10/10 + CI green + PE re-verification of release artifact.

### Phase 2 — Diversity & agility (PARTIAL — McEliece/Frodo/HQC legs exist, quarantined)
- [ ] HQC integration plan gated on FIPS 207 FINAL (seed-only direction tracked; no pre-standard wire use).
- [ ] FN-DSA integration plan gated on FIPS 206 FINAL (IPD published; sizes match Falcon but behavior differs).
- [ ] McEliece structural-attack watch (TII-252 AI-assisted record): quarterly review log.
- [ ] CSWP 39 second-transition readiness: pure-PQ-inner already positioned; outer hybrid retained while
      classical holds (explicitly per CSWP 39 §3 — hybrids kept, not silently dropped).
Acceptance: each leg has a named standard-or-quarantine status; no draft touches the session path (gated).

### Phase 3 — Verification completion
- [x] ProVerif handshake + PCS with negative control (4.0 s, TRUE).
- [x] Kani harnesses defined + doubles green.
- [ ] Kani execution proof from CI (Phase 1 workflow).
- [ ] Annual model refresh procedure (new attack classes → new queries; HAWK-lesson: re-run analyses,
      AI-swarm economics reviewed yearly).
Acceptance: gates 1, 4, 5, 8 green + CI Kani green.

### Phase 4 — Supply chain (DONE — maintain)
Pinned DLLs, SBOM signatures, reproducible-build gate, hash-manifest CI, OSV pin audit, Bandit SAST.
Acceptance: gate 7 green every run; drift fails loudly (proven: caught an authorized edit mid-turn).

### Phase 5 — Operations (DONE in code — pending hardware)
HSM ceremony, diode registry, Tor runbooks, DPA enforcement, TEMPEST registry. Pending: physical
procurement (HSM, SCIF, diode devices, seL4 hardware).
Acceptance: gates 2, 6, 9 green; hardware-present drills when equipped.

### Phase 6 — Accreditation
CMVP module path for the Rust core → Common Criteria engagement → ATO sponsorship. Entry criterion:
Phases 1–3 complete with 12 months of green CI history.

## 4. Zero-Gap Rules (binding on all future work)

1. No new session-path primitive below final-standard status — drafts quarantine by default (HAWK rule).
2. No new dependency without pin + hash + CVE watch (oqs floor 0.10.1 pattern).
3. No new TLS group name without RFC codepoint (phantom-purge rule).
4. No capability claim without a gate that executes it (ProVerif/Kani/memlock precedent).
5. No count, badge, or "PROVEN" string without the exact artifact (truth-in-claims gates enforce).
6. Every concurrent-edit surface gets a hash manifest (drift fails loudly, proven in combat).
7. Complexity budget: session path stays minimal; experiments live in `archive/`/`quarantine/`.
8. Annual review: quantum estimates, AI-break economics, McEliece/HQC/FN-DSA status, Tamaraw follow-ons.

## 5. Metrics That Matter (reviewed quarterly)

- Cost-to-break delta: track Gidney-style estimates vs. our 2^128 floor; any drop triggers agility review.
- AI-break economics: track $/break trend (HAWK baseline: ~$100k + 1 week, Jul 2026).
- Gate health: 9/9 local + CI green rate; Kani execution proof; ProVerif re-run on model change.
- Idle burn vs. cover ratio; loopback latency; audit duration (~60 s baseline).
- Time-to-quarantine for newly broken primitives (HAWK precedent: <30 days from disclosure to gate).
