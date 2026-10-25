# Audit Discrepancies Register

Cross-check findings comparing workspace documentation claims, formal compliance assertions, and active implementation behavior across all 606 tracked files.

---

## 1. Verified Implementation Defects

The following defects were verified through code analysis and test execution:

| Finding ID | Component | File & Line | Verified Defect Description | Impact & Severity |
|---|---|---|---|---|
| DEF-01 | Allied Gateway Quarantine | `cjadc2_allied_gateway.py:184` | Unbound identifier `is_env_true`. When validating untrusted gateway peers outside production mode, `is_env_true` raises `NameError` because it was not imported from `production_gate`. | High: Crashes quarantine check function on non-production runs. |
| DEF-02 | Hardware Entropy Delegation | `entropy_manager.py:270` | `HardwareRNGSource` checks CPU architecture (x86/x64) but delegates to Python `secrets.token_bytes()` rather than invoking native CPU instructions (`RDRAND` / `RDSEED`). | Medium: Lacks direct hardware CPU bus sampling; relies entirely on OS CSPRNG. |
| DEF-03 | TPM Endorsement Key Roots | `tpm_quote.py:38-42` | Root certificate authority table `EK_ROOTS = {}` is initialized empty. In production, TPM quotes fail closed unless populated out-of-band with hardware vendor certificates. | Medium: Blocks automated quote verification in air-gapped production without pre-staged certificates. |
| DEF-04 | Offline Dependency Verification | `scripts/audit_pins.py:25-45` | Dependency scanner queries public REST API `https://api.osv.dev/v1/query`. In air-gapped operational environments, scanner fails unless network access is available or local cache is mounted. | Low: Prevents automated dependency auditing during disconnected field operations. |

---

## 2. Terminology and Naming Discrepancies

Documentation files and source code identifiers contain non-technical promotional adjectives and restricted operational classifications. The following table catalogs these occurrences in product files:

| Catalog ID | Source File | Line | Identifier / Text in Code | Factual Technical Nature | Audit Classification |
|---|---|---|---|---|---|
| NOM-01 | `secure_p2p.py` | 520 | `class [BANNED-PREFIX]Crypto:` | Wrapper around standard cryptography library (AES-GCM, SHA-256) | Promotional Class Name |
| NOM-02 | `core/orchestrator.py` | 180 | `def _add_[BANNED-PREFIX]_grade_padding` | Fixed-size PKCS#7 / power-of-two padding routine | Promotional Method Name |
| NOM-03 | `core/orchestrator.py` | 210 | `def _generate_[BANNED-PREFIX]_auth_tag` | HMAC-SHA384 message authentication tag generation | Promotional Method Name |
| NOM-04 | `destroyer_tactical_p2p.py` | 51, 58 | `[RESTRICTED-BANNER // CNSA 2.0 // NOFORN ...]` | Hardcoded ANSI terminal console banner string | Promotional Operational Header |
| NOM-05 | `messaging/handler.py` | 120 | Command alias `/[BANNED-PREFIX-DIR]` | Emergency wipe trigger invoking `secure_memory_wiper` | Promotional Command Alias |
| NOM-06 | `tactical_command_cjadc2` | 85 | `[DIRECTIVE-STRING] EAM CREATED` | Diagnostic log message for emergency action messages | Promotional Log String |
| NOM-07 | `scripts/verify_50x_...py` | 1 | `verify_50x_[PROMOTIONAL]_superiority.py` | Microbenchmark measuring ratchet rekey latency vs RSA-4096 | Promotional File Name |
| NOM-08 | `scripts/generate_...py` | 1 | `generate_[PROMOTIONAL]_pki.py` | Certificate authority generator using ML-DSA-87 / Falcon-1024 | Promotional File Name |
| NOM-09 | `isolated_*.py` | 1 | `[PROMOTIONAL]_red_domain.py`, `[PROMOTIONAL]_sel4_appliance.py` | Python reference models for seL4 domain separation | Promotional File Prefix |
| NOM-10 | `security_framework` | 1 | `[BANNED-PREFIX]_security_enforcement.py` | Policy enforcement engine checking cipher bit-lengths | Promotional File Name |

---

## 3. Dead, Disabled, and Transitional Code

The audit confirmed several blocks of dormant, quarantined, or disabled code within the repository:

| Entity | Location | Operational Status | Technical Rationale |
|---|---|---|---|
| `keys/` test keys | `keys/` directory (root) | Dormant / Quarantined | Pre-dates PQC PKI structure. Contains deprecated test certificates. Production gate strictly blocks keys originating from this path. |
| `DirectX25519KeyExchange` | `hybrid_kex.py:310` | Disabled in Production | Classical X25519 exchange retained for backwards compatibility. Production mode raises `SecurityError` if classical-only exchange is attempted. |
| `Ed25519Signer` | `pqc_algorithms.py:7100` | Restricted Use | Classical Ed25519 digital signature scheme. Permitted solely in TUF dual-signature verification (`supply_chain_security.py`) paired with ML-DSA-87. |
| `EnhancedXMSS` & `EnhancedLMS` | `pqc_algorithms.py:6355` | Disabled by Default | Stateful hash-based signatures. Custom state-advancement logic is unaudited; skipped in favor of stateless SLH-DSA-256f unless `P2P_ENABLE_EXPERIMENTAL=1` is asserted. |
| `HQC-256` KEM | `pqc_algorithms.py:6396` | Quarantined / Refused | Vendored `oqs.dll` predates upstream fixes for CVE-2024-54137 and CVE-2025-52473. Instantiation blocked unless `P2P_ENABLE_VULN_HQC=1` is set. |

---

## 4. Architectural Duplication & Prototype Twins

| Component | Prototype Twin | Modular Production Package | Synchronicity Analysis |
|---|---|---|---|
| Communications Engine | `secure_p2p.py` (14,886 lines) | `core/orchestrator.py` (1,714 lines) + `messaging/` | Overlapping session management and encryption logic. Changes made to one must be manually ported to the other. |
| seL4 Microkernel Separation | `sel4_baremetal/` (Rust native target) | `[PROMOTIONAL]_sel4_appliance.py` and domain twins | `sel4_baremetal/` provides native Microkit Rust implementations; Python twins provide reference emulation executed by test suites. |
| Data Plane Network Transport | `destroyer_node.py` (Python fallback) | `rust_data_plane/` (`libdestroyer_data_plane`) | When compiled Rust libraries are present, high-throughput UDP packet processing is delegated to native code; Python fallback operates in development mode. |

---

## 5. Documentation Claims vs. Implementation Reality

1. **Side-Channel "Immunity" Claims:**
   - *Claim:* Existing markdown documentation (`docs/SECURITY.md`, `docs/ARCHITECTURE.md`) asserts "complete immunity to side-channel and timing attacks."
   - *Reality:* The implementation applies constant-time byte comparisons (`ConstantTime.compare_digest`), memory wiping, and randomized timing jitter (`TimingJitterContext`). While these techniques substantially raise the barrier against remote network timing analysis, software running on general-purpose superscalar x86/ARM CPUs cannot provide physical side-channel immunity (such as power analysis, cache eviction, or electromagnetic leakage) without certified hardware cryptographic boundaries.
2. **Post-Quantum Key Exchange:**
   - *Claim:* Documentation claims "hybrid post-quantum confidentiality across all layers."
   - *Reality:* Confirmed in code. Wire transports utilize ML-KEM-1024 hybrid encapsulation (FIPS 203) paired with X25519 or SecP384r1. Classical-only modes are strictly blocked fail-closed when `is_production()` is asserted.
3. **Continuous Forward Secrecy:**
   - *Claim:* Documentation claims "healing after physical memory capture."
   - *Reality:* Confirmed via Continuous Epoch Ratchet (CER) in `unified_secure_pipeline.py:57` and `secure_transmit_2027.py:14`. Every 128 messages, a fresh ephemeral key exchange is injected into the ratchet chain, achieving post-compromise security (PCS) healing.
