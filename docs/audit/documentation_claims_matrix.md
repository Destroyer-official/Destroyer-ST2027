# Documentation Truth-in-Claims Matrix

Systematic cross-examination of existing workspace documentation files (70 files, 96,030 lines) against verified implementation code and automated test results.

---

## 1. Documentation Corpus Overview

Existing documentation in the workspace spans architectural specifications, cryptographic policies, security audit reports, operational concept documents (CONOPS), and module summaries:

| Documentation Category | File Count | Verified Line Count | Primary Function in Scope |
|---|---|---|---|
| **Core Architecture & Policies** | 12 | 3,120 | System architecture, threat modeling, FIPS policy, firewall configuration. |
| **Operational & CONOPS Guides** | 8 | 4,250 | Tactical deployment procedures, airgap runbooks, hardware guides. |
| **Historical Security Audits** | 15 | 28,450 | Previous internal audit reports, remediation trackers, and vulnerability logs. |
| **Subsystem Module Summaries** | 18 | 8,910 | High-level subsystem descriptions under `docs/modules/`. |
| **Compliance & Hardening Plans** | 17 | 51,300 | Multi-phase hardening plans, doctrine manuals, and technical specifications. |
| **Total Documentation Scope** | **70** | **96,030** | **All tracked markdown documentation files evaluated.** |

---

## 2. Global Architectural Claims vs. Code Reality

The following matrix cross-examines the primary claims made across the documentation corpus against active implementation code:

| Document & Section | Documented Claim | Implementation File & Line | Verified Status | Technical Findings & Discrepancy Analysis |
|---|---|---|---|---|
| `docs/ARCHITECTURE.md:15-35` | Three-layer defense pipeline isolates message payloads through post-quantum ratcheting, native Rust AEAD, and quantized padding. | `unified_secure_pipeline.py:8-45` | **VERIFIED** | Code implements Layer 1 (`pqc_algorithms` double ratchet), Layer 2 (Rust `destroyer_core`), and Layer 3 (quantized padding in `PAD_QUANTA`). Verified in `tests/test_unified_secure_pipeline.py`. |
| `docs/ARCHITECTURE.md:40-60` | Post-compromise security (PCS) achieved through continuous epoch ratcheting every 128 messages. | `unified_secure_pipeline.py:57`, `secure_transmit_2027.py:14` | **VERIFIED** | `CER_EPOCH_INTERVAL = 128` triggers fresh ephemeral key encapsulation, restoring forward secrecy after transient compromise. Verified in `test_cer_epoch_rotation`. |
| `docs/SECURITY.md:10-30` | Complete immunity against timing and physical side-channel analysis. | `ConstantTime.py:15-80`, `side_channel_resistance.py:45` | **PARTIALLY VERIFIED** | Implements constant-time byte comparisons and artificial timing jitter (`TimingJitterContext`). However, physical side-channel immunity on superscalar CPUs is technically unattainable without certified tamper-resistant hardware cryptographic modules. |
| `README.md:120-180` | Pure post-quantum CNSA 2.0 suite operates with zero classical fallback algorithms in production mode. | `production_gate.py:120-190`, `pqc_algorithms.py:3400` | **VERIFIED** | In production mode (`is_production() == True`), classical algorithms (`DirectX25519KeyExchange`, pure RSA) raise `SecurityError`. Only FIPS 203/204/205 primitives execute. |
| `docs/FIPS_140_3_SECURITY_POLICY.md:45-80` | All cryptographic key material is locked in physical RAM and sanitized via DoD 5220.22-M 7-pass overwrite. | `dep_impl.py:1800`, `utils/memory.py:43-90` | **PARTIALLY VERIFIED** | `KeyEraser` attempts memory locking via `VirtualLock`/`mlock`. On unprivileged platforms without admin rights, locking is bypassed with a warning unless `P2P_REQUIRE_MLOCK=1` is set. Sanitization routine executes multi-pass overwrite. |
| `docs/modules/tactical_c4isr.md:20-50` | Command execution strictly requires two-person integrity with cryptographic verification within 120 seconds. | `critical_release.py:45-120` | **VERIFIED** | Validates dual independent officer signatures using ML-DSA-87; timestamps exceeding 120-second delta are rejected fail-closed. Verified in `tests/test_critical_release.py`. |
| `docs/modules/ts_network.md:10-40` | Mesh networking implements store-and-forward bundle routing across disrupted, intermittent, and low-bandwidth (DDIL) links. | `mesh/mesh_network.py:110-240`, `mesh/bundle_protocol.py` | **VERIFIED** | Implements custody transfer, bundle expiration timers, and priority queues. Verified in `tests/test_mesh_network.py` and `tests/test_phase5_csrmc_ddil_operations.py`. |
| `docs/modules/tpm_quote.py:10-30` | Automated TPM quote verification validates hardware identity against manufacturer Endorsement Key (EK) roots. | `tpm_quote.py:38-42` | **UNVERIFIED / GAP** | `EK_ROOTS = {}` dictionary is unpopulated in code. Quote verification requires external provisioning of manufacturer intermediate CA roots before automated validation can pass in production. |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:80` | Allied gateway quarantine isolates untrusted cross-domain messaging partners. | `cjadc2_allied_gateway.py:184` | **DEFECT CONFIRMED** | Implementation defect: `cjadc2_allied_gateway.py:184` raises `NameError: name 'is_env_true' is not defined` when checking quarantine outside production mode due to missing import. |

---

## 3. Discrepancy Patterns Identified

1. **Promotional Terminology in Historical Documentation:**
   - Historical audit and planning documents (`docs/DEFENSE_HARDENING_MASTER_PLAN.md`, `docs/COMPETITOR_ANALYSIS_...`) frequently utilized non-technical promotional adjectives. Active source code has largely purged these terms, with remaining identifiers cataloged in `docs/audit/discrepancies.md`.
2. **Prototype vs. Modular Architecture Claims:**
   - Several documentation files refer exclusively to `core/orchestrator.py` as the active communications engine, omitting mention of the coexisting 14,886-line monolithic prototype `secure_p2p.py`.
3. **Hardware Requirement Specifics:**
   - Documentation often assumes hardware TPM 2.0 and PKCS#11 HSM availability as universal baselines, whereas the software architecture includes explicit software-emulation fallbacks for development and testing environments.
