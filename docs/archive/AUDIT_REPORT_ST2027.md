# SECURITY AUDIT & REMEDIATION RECORD — DESTROYER-ST2027

**Repository:** D:\code\Main_projects\p2p\p2p_6_1-26  
**Updated:** 2026-11-26  
**Scope:** Application-level code, cryptographic protocols, FFI boundaries, seL4 MILS domains, tests, and build/assurance tooling  
**Classification:** UNCLASSIFIED — Internal Engineering & Pre-Accreditation Audit Document

> **Note on Document Structure:** **Section A** and **Sections I–K** state the current post-remediation assessment (including Waves 1–5 remediations of [`ST2027_FORENSIC_AUDIT_2026-11-26.md`](ST2027_FORENSIC_AUDIT_2026-11-26.md)). **Sections B–H** preserve the historical `2026-11-09` pre-remediation baseline snapshot as an immutable engineering archive; findings listed in Sections B–H do not describe the current remediated codepaths except where carried over into Section A's external prerequisites.

---

## A. EXECUTIVE VERDICT & ACCREDITATION BOUNDARY

**Verdict: SOFTWARE REMEDIATION COMPLETE FOR TESTED CODEPATHS — NOT EXTERNALLY ACCREDITED FOR HIGH-ASSURANCE / DEFENSE PRODUCTION USE.**

1. **Completed In-Repository Software & Protocol Remediations (including 2026-11-26 Forensic Audit F-01..F-15):**
   - **Fail-Closed Gates & Native Binding Boundaries:** `production_gate.py`, `destroyer.py` (post-`argparse` production arming), `destroyer_node.py`, `destroyer_core` (`_FailClosedNativeStub`), and `--no-default-features` release builds fail closed without runtime package installs or unsafe fallback stubs.
   - **Native Rust Key Custody, Mutual Auth & PCS Ratchet (`rust_data_plane`):** Production `node`/`terminal`/`channel` flows reject unauthenticated `--key-file`/`--key-stdin` and raw `--auth-sk-file` without hardware PKCS#11 custody; `PcsRatchet` performs per-epoch ML-KEM-1024 re-encapsulation across `main.rs` and `pipeline.rs`.
   - **Durable Nonces & XAES-256-GCM:** `p2p_core.py` and `platform_hsm_interface.py` enforce durable atomic monotonic counters (`gcm_nonce_ledger.db`) across restarts alongside SP 800-38D composite IVs and XAES-256-GCM support.
   - **TPM Attestation, TLS, PKI & Auth Binding:** `ts_attest.py` enforces `hardware_mode` and AK trust-anchor checks; `tls_channel_manager.py` restores strict hostname validation and blocks unpinned TOFU in production; `certs/` manifest, `scripts/sign_boot_config.py`, and `P2P_AUTH_TOKEN_FD`/stdin eliminate CLI secret exposure.
   - **Supply-Chain & SAST:** `scripts/audit_pins.py` is importable and fails closed on stale/unsigned/`skipped_offline` mirrors; `.github/workflows/defense_ci.yml` executes `pip-audit`, `cargo-audit`, and `cargo-deny`; Bandit SAST holds 0 HIGH / 0 MEDIUM (`compliance_reports/bandit_low_triage.md`).
   - **Fail-Closed Gates & Native Binding Boundaries:** `production_gate.py`, `destroyer.py`, `destroyer_node.py`, `destroyer_core` (`_FailClosedNativeStub`), and `--no-default-features` release builds fail closed without runtime package installs or unsafe fallback stubs.
   - **Real Cryptographic Implementations:**
     - `pq_zkp.rs` implements a sound classical Ristretto255 `bLSAG` ring signature (`IS_POST_QUANTUM = false`, refusing `strict_pq=True`) instead of the earlier insecure hash construction.
     - `nc3_threshold_mpc.py` + `rust_data_plane/src/nc3_mpc.rs` enforce blinded P-384 Schnorr proofs (`[z_i]G == R_i + [c_i]Q_i`), genesis ML-DSA-87 ceremony binding, optional 2-round `FROST_P384_V2`, and `Mldsa87VerifyingKey` quorum checks; `key_fill_import.py` uses 2-of-2 DEK XOR splitting so single-officer wrap blobs cannot decrypt payloads.
     - `hardware_enclave.rs` & `hardware_enclave_manager.py` fail closed in production/strict mode without hardware TPM/PKCS#11 roots and use ephemeral randomized keys (`Ristretto255` / `ECDSA_P256`) strictly restricted to non-production lab tests.
     - `sel4_mils_appliance` enforces `Aes256Gcm`, CSPRNG ChaCha20 chaff/padding, and constant-time redaction tags in `#![no_std]` code.
     - `pipeline.rs`, `unified_secure_pipeline.py`, `sovereign_group_ratchet.py`, `tactical_web_console.py`, `x509.rs`, `tpm_nv.rs`, `main.rs`, `ca_services.py`, `memory_guard.rs`, `cnsa_crypto_gateway.py`, `platform_hsm_interface.py`, and `dependency_security_verifier.py` were hardened against state mutation prior to AEAD verification, unauthenticated WebAuthn/CSRF bypasses, tautological canary checks, POSIX digest bypasses, and fail-open CRL/KEX/CLI secret flags.
   - **Honest Verification Tooling:** Synthetic `ProVerif` passes and throwaway self-signed compliance attestations (`run_formal_verification.py`, `docs/formal/check.sh`) now fail closed (`NOT_VERIFIED_PROVERIF_MISSING` / `UNSIGNED_NO_EPHEMERAL_SELF_SIGNING`) unless the real ProVerif verifier and an authority signing key are present.

2. **Mandatory External Prerequisites Before Defense / Operational Production Deployment:**
   - **FIPS 140-3 CMVP Validation:** Replace unvalidated prebuilt shared libraries (`oqs.dll` / `libsodium.dll`) with CMVP-validated cryptographic modules.
   - **Hardware Provisioning:** Provision dedicated TPM 2.0 NV monotonic indices (`P2P_TPM_NV_INDEX` / `P2P_TPM_CRL_INDEX`), physical PKCS#11 HSM/smartcards, and offline 3-of-5 CA custodian keys.
   - **Independent Formal Verification Execution:** Run `ProVerif >= 2.05` cleanly in Linux/CI against the updated models (`docs/formal/*.pv`).
   - **Independent Red-Team & DAA/DAO ATO:** Complete accredited third-party cryptographic review, hardware side-channel lab evaluation, and formal Authorizing Official Authorization to Operate (ATO).

---

## B. HISTORICAL BASELINE INVENTORY (2026-11-09)

### B.1 Inspected Components

The following components were inspected through source code review:

| Component | Files | Purpose | Security Relevance |
| --- | --- | --- | --- |
| Main P2P Chat | `secure_p2p.py` (919 KB) | Primary application entry point, handshake, Double Ratchet session management | **TCB candidate** — implements the main chat protocol |
| Core Networking | `p2p_core.py` (119 KB) | IPv6 transport, AES-GCM encryption, connection management | Crypto implementation |
| Double Ratchet | `double_ratchet.py` (281 KB) | Custom PQ Double Ratchet, message encryption/decryption | **Core crypto TCB** |
| Hybrid KEX | `hybrid_kex.py` (9 KB) | P-384 + ML-KEM-1024 hybrid KEX (new, unused by main path) | Claimed CNSA 2.0 KEX |
| Legacy Hybrid KEX | `hybrid_kex_legacy.py` (192 KB) | X25519 + Ed25519 + ML-KEM + FALCON (USED by main path) | **Actual KEX used** |
| Noise PQ | `noise_pq.py` (44 KB) | Noise_XXhfs-style PQ handshake (claimed path in secure_transmit_2027) | Alternate handshake |
| Secure Transmit | `secure_transmit_2027.py` (1.1 MB) | TLS 1.3 + Noise_XXhfs outer transport | Claimed production path |
| PQC Algorithms | `pqc_algorithms.py` (350 KB) | LibOQS wrapper for ML-KEM/ML-DSA/FALCON | PQC primitive access |
| LibOQS Wrapper | `liboqs_wrapper.py` (72 KB) | ctypes bindings to oqs.dll | Native PQC FFI |
| Platform HSM | `platform_hsm_interface.py` (528 KB) | RNG, TPM, HSM, key storage abstraction | Entropy source |
| TLS Channel | `tls_channel_manager.py` (335 KB) | TLS 1.3 context, mTLS, certificate validation | Transport security |
| Rust Data Plane | `rust_data_plane/src/*.rs` (28 files) | Native Rust AEAD, ratchet, handshake, framing | Claimed high-assurance plane |
| Config | `config.json`, `config.py` | Configuration, production gate | Security policy |
| Production Gate | `production_gate.py` | Sticky production latch, fail-closed enforcement | Security mode control |
| Tests | `tests/*.py` (~200 files, 4+ MB) | Self-written test suite | Internal validation only |
| CI/CD | `.github/workflows/*.yml` | Build, test, audit pipelines | Supply chain |
| Audit Artifacts | `audit_*.json`, `audit_*.log` | Prior audit outputs | Historical findings |

### B.2 Uninspected or Partially Inspected Components

| Component | Limitation |
| --- | --- |
| `archive/` directory | Contains quarantined legacy prototypes; not inspected in depth |
| `notupload/` directory | Not inspected |
| `scratch/` directory | Not inspected |
| `redesign/` directory | Not inspected |
| `sel4_baremetal/` and `sel4_microkit/` | seL4 microkernel references; source not available for review |
| `rust_data_plane/target/` | Build artifacts present but Rust source was inspected; binaries not reverse-engineered |
| `oqs.dll` / `libsodium.dll` | Prebuilt native binaries; signatures present but not cryptographically verified in this audit |
| `.audit-download/`, `.audit-venv/`, `.audit-tools-venv/` | Audit tool directories; contents not inspected |
| Git LFS objects | No LFS pointers found outside tracked files; binaries (oqs.dll, libsodium.dll) are tracked directly |
| Git history beyond last 50 commits | Partially reviewed; recent commits show extensive audit remediation activity |
| Compiled `.pyc` files | Not inspected (build artifacts) |
| `compliance_reports/` | Contains self-attestation artifacts; not independently verified |
| `cert/` and `certs/` directories | Synthetic test certificates; not production CA infrastructure |

### B.3 Test Coverage

- Approximately 200 test files in `tests/` and `tests/security/` directories
- Tests are self-written by the project authors; no third-party test authorship
- Test categories include: crypto unit tests, protocol state tests, fuzz gates, hardware integration, production gate tests, adversarial drills
- **Limitation:** Tests validate internal consistency against the implementation's own claims; they do not validate against external standards or independent threat models
- No evidence of independent penetration testing or red-team assessment
- No formal verification evidence beyond ProVerif models (`test_formal_proverif_models.py`, `test_proverif_st2027.py`) which abstract the KDF as one-way (stronger than the actual implementation)

### B.4 Tools Actually Used in This Audit

- Source code review (manual static analysis) of all Python and Rust source files listed above
- PowerShell filesystem and content search for hardcoded secrets, weak RNG, and configuration patterns
- No dynamic execution of the codebase was performed (no test runs, no fuzzing, no network testing)
- No dependency vulnerability scanning (e.g., `cargo audit`, `pip audit`, `bandit`) was independently executed; pre-existing audit logs (`audit_bandit.json`, `audit_secret_scan.json`) exist but are self-generated

---

## C. ARCHITECTURE AND TRUST BOUNDARIES

### C.1 Declared Architecture (Three-Plane Model)

The README describes three planes:

| Plane | Component | Location | Claimed Role |
| --- | --- | --- | --- |
| Plane 1 | Native Rust Data Plane | `rust_data_plane/target/release/secure-transmit` | High-assurance production core; AES-256-GCM, ML-DSA-87, ML-KEM-1024, memory locking, zeroization |
| Plane 2 | Native System Security Core CDyLib | `ts_rt/` | Memory protection, mlock, constant-time comparisons |
| Plane 3 | Python Master Control Orchestrator | `secure_p2p.py`, `secure_transmit_2027.py` | Lab/diagnostic only; quarantined from production transit |

### C.2 Actual Architecture (What the Code Does)

The primary application entry point is `secure_p2p.py`, which:

1. Imports `destroyer_core` (best-effort, may fail silently)
2. Uses `HybridKeyExchange` imported from `hybrid_kex`, which re-exports the **legacy** `HybridKeyExchange` from `hybrid_kex_legacy.py` — an **X25519 + Ed25519 + ML-KEM-1024 + FALCON-1024** construction
3. Derives `hybrid_root_key` from this legacy key exchange
4. Instantiates `DoubleRatchet(self.hybrid_root_key, ...)` which uses **X25519 + ChaCha20-Poly1305 + HKDF-SHA3-512 + FALCON-1024/ML-DSA-87**
5. Optionally initializes a `UnifiedSecurePipeline` to bridge to the Rust data plane

The Rust data plane binary exists at `rust_data_plane/target/release/secure-transmit.exe` (and debug), but the Python code treats it as an optional bridge (`try/except` around pipeline initialization), not a mandatory enforcement boundary.

### C.3 Trust Boundaries

| Boundary | Description | Enforcement |
| --- | --- | --- |
| Control plane vs data plane | Python control plane vs Rust data plane | `production_gate.py` `enforce_control_plane_boundary()` — only active when `P2P_PRODUCTION=1` |
| Lab vs production | `P2P_PRODUCTION=1` env var | Opt-in sticky latch; not default |
| Classical vs PQ | `enable_pq=False` allowed in lab | Refused in production without `P2P_ALLOW_CLASSICAL=1` |
| Peer trust | PSK file + optional ML-DSA-87 mutual auth | Mandatory outside lab mode; PSK-only in lab |
| TLS verification | `verify_certs=False` | Refused in production; TLS 1.3 floor enforced |

### C.4 Most Consequential Design Decisions

1. **Multiple parallel crypto implementations** with no clear single TCB. At least four distinct cryptographic stacks exist:
   - `double_ratchet.py`: X25519 + ML-KEM-1024 + ChaCha20-Poly1305 + FALCON/ML-DSA
   - `noise_pq.py` + `secure_transmit_2027.py`: P-384 + ML-KEM-1024 + AES-256-GCM + ML-DSA-87 (claimed CNSA 2.0)
   - `p2p_core.py`: X25519/ECDH + AES-256-GCM (random IV)
   - `rust_data_plane/`: Claimed ML-KEM-1024 + ML-DSA-87 + AES-256-GCM

2. **Production hardening is opt-in.** The default mode is lab/development with permissive settings (classical-only allowed, TOFU permitted, deniable mode available).

3. **No clear separation between the "claimed" production path and the "actual" implementation path.** The README's described CNSA 2.0 path exists in `noise_pq.py` and `secure_transmit_2027.py` but is not what `secure_p2p.py` (the main entry point) uses.

---

## D. CRITICAL FINDINGS

### Summary of Highest-Risk Findings

| ID | Title | Severity | Fundamental Security Claim Undermined? |
| --- | --- | --- | --- |
| F-01 | Algorithm mismatch: README claims CNSA 2.0 but main code path uses X25519/ChaCha20/FALCON | Critical | **Yes** — core cryptographic suite does not match documented claims |
| F-02 | Legacy X25519 key exchange used by `secure_p2p.py` instead of claimed P-384 + ML-KEM-1024 | Critical | **Yes** — classical-only hedge not actually hybridized in main path |
| F-03 | Production security posture is opt-in, not default | High | Partial — weaker lab configuration is the default |
| F-04 | Random IV for AES-GCM (`secrets.token_bytes(12)`) — birthday-bound collision risk | High | Partial — nonce reuse under same key |
| F-05 | PQ ratchet v1 provides no fresh post-compromise security between DH steps | High | Partial — PCS claim not met in default configuration |
| F-06 | Deniable mode eliminates per-message signatures — no non-repudiation | Medium | Partial — authentication weakened in opt-in mode |

**F-01 and F-02 together undermine the project's fundamental security claim** that it implements NSA CNSA Suite 2.0 cryptography. The main application path does not use P-384, AES-256-GCM, SHA-384, or ML-DSA-87 as documented. It uses X25519, ChaCha20-Poly1305, SHA3-512/HKDF-SHA3-512, and FALCON-1024/ML-DSA-87.

---

## E. COMPLETE FINDING REGISTER

### F-01: Algorithm Mismatch Between Documentation and Implementation

**Severity:** Critical  
**Confidence:** High (direct code comparison)  
**Location:** README.md (claims), `secure_p2p.py` (actual usage), `double_ratchet.py` (actual implementation), `hybrid_kex_legacy.py` (actual KEX)

**Description:** The README and `secure_transmit_2027.py` docstring claim the system implements NSA CNSA Suite 2.0: NIST P-384 ECDH, ML-KEM-1024 KEM, AES-256-GCM symmetric encryption, SHA-384 hash, ML-DSA-87 signatures. However, the primary application entry point `secure_p2p.py` imports `HybridKeyExchange` from `hybrid_kex`, which re-exports the legacy `HybridKeyExchange` from `hybrid_kex_legacy.py` — an **X25519 + Ed25519 + ML-KEM-1024 + FALCON-1024** construction. The `DoubleRatchet` class uses **X25519 + ChaCha20-Poly1305 + HKDF-SHA3-512 + FALCON-1024/ML-DSA-87**. The code itself admits at `double_ratchet.py:2344-2348`: "this messenger path is a hybrid-transition prototype... NOT the CNSA-pure session set."

**Violated Property:** Cryptographic suite integrity; truth-in-advertising of security properties.

**Attack Prerequisites:** Attacker observes or targets the actual implementation rather than the documented one. The system provides different security properties than claimed (e.g., X25519 = ~128-bit classical security, not P-384's ~192-bit; ChaCha20-Poly1305 has different nonce constraints than AES-256-GCM; FALCON-1024 is not in CNSA 2.0).

**Exploit Steps:**

1. Observer identifies the system claims CNSA 2.0 compliance based on README
2. Actual traffic uses X25519 (~128-bit classical security) instead of P-384 (~192-bit)
3. Attacker with quantum capability targets ML-KEM-1024 while classical computer targets X25519 (~2^128 Pollard's rho)
4. The hybrid combiner in `hybrid_kex_legacy.py` mixes X25519 and ML-KEM-1024 secrets, but the classical component is weaker than claimed

**Impact:** The system does not provide the claimed 192-bit classical security level or CNSA 2.0 compliance. A classical attacker has ~128-bit security against the X25519 component instead of ~192-bit against P-384.

**Remediation:** Either (a) align implementation with documentation by using `HybridKeyExchange2027` (P-384 + ML-KEM-1024) + AES-256-GCM + SHA-384 + ML-DSA-87 in `secure_p2p.py`, or (b) update documentation to accurately describe the X25519 + ChaCha20-Poly1305 + FALCON stack actually implemented.

**Regression Test:** Verify that `secure_p2p.py` instantiates `HybridKeyExchange2027` (not legacy `HybridKeyExchange`) and that `DoubleRatchet` is configured with AES-256-GCM (not ChaCha20-Poly1305) when production mode is active.

---

### F-02: Legacy X25519 Key Exchange Used by Main Application Path

**Severity:** Critical  
**Confidence:** High (direct import chain trace)  
**Location:** `secure_p2p.py:342` (`from hybrid_kex import HybridKeyExchange`), `hybrid_kex.py:32-43` (re-exports from `hybrid_kex_legacy`), `hybrid_kex_legacy.py:75` (X25519 imports), `secure_p2p.py:4969` (`DoubleRatchet(self.hybrid_root_key, ...)`)

**Description:** `secure_p2p.py` imports `HybridKeyExchange` from `hybrid_kex`. The `hybrid_kex.py` module's docstring states: "the legacy X25519-based ``HybridKeyExchange`` and its helpers are re-exported from ``hybrid_kex_legacy`` so existing callers (including the quarantined ``SecureP2PChat``) keep working. New code should use ``HybridKeyExchange2027``." This means the main chat application uses the **legacy X25519-based key exchange**, not the newer `HybridKeyExchange2027` which implements P-384 + ML-KEM-1024 per RFC 10024.

The `HybridKeyExchange2027` class exists but is **not used** by `secure_p2p.py`. The `secure_p2p.py` handshake at lines 4827 and 5361 calls `self.hybrid_kex.initiate_handshake()` / `respond_to_handshake()` on the legacy X25519-based object, then derives `hybrid_root_key` which seeds the DoubleRatchet.

**Violated Property:** Cryptographic suite alignment; hybrid key exchange as documented.

**Attack Prerequisites:** Attacker can perform classical cryptanalysis against X25519 (~2^128 operations via Pollard's rho) instead of P-384 (~2^192).

**Impact:** Classical security level is ~128 bits instead of the claimed ~192 bits. The hybrid construction still provides some protection (ML-KEM-1024 component), but the classical hedge is weaker than documented.

**Remediation:** Change `secure_p2p.py` to import and use `HybridKeyExchange2027` from `hybrid_kex` instead of the legacy `HybridKeyExchange`.

**Regression Test:** Unit test verifying that `SecureP2PChat.hybrid_kex` is an instance of `HybridKeyExchange2027`, not `HybridKeyExchange` from `hybrid_kex_legacy`.

---

### F-03: Production Security Posture is Opt-In, Not Default

**Severity:** High  
**Confidence:** High (environment variable gating throughout codebase)  
**Location:** `production_gate.py`, `config.py:15-50`, `double_ratchet.py:2113-2117`, `secure_p2p.py:2169-2171`

**Description:** Production security posture (`P2P_PRODUCTION=1`) is opt-in via environment variable. The default mode is lab/development with permissive settings:

- `enable_pq=False` is allowed (classical-only X25519, no PQ PCS)
- `deniable=True` is allowed (no per-message signatures)
- PQ ratchet v1 (legacy KEM reuse) is allowed (no fresh PQ PCS between DH steps)
- `verify_certs=False` is allowed (TLS without certificate validation)

The production gate (`production_gate.py`) is well-designed with a sticky latch and fail-closed behavior, but it only activates when the operator explicitly sets `P2P_PRODUCTION=1`. There is no secure-by-default configuration.

**Violated Property:** Secure defaults; fail-closed by default.

**Attack Prerequisites:** Attacker targets a deployment where the operator did not set `P2P_PRODUCTION=1` (the default).

**Exploit Steps:**

1. Deploy system without `P2P_PRODUCTION=1`
2. System operates in lab mode with classical-only key exchange, no PQ PCS, deniable sessions
3. Attacker performs classical MITM or key compromise without triggering production-mode alarms

**Impact:** System operates with significantly reduced security by default. Operators may mistakenly believe the system is production-hardened when it is not.

**Remediation:** Make production mode the default with explicit opt-out for lab/testing. Or require explicit `P2P_LAB_MODE=1` to enable weaker configurations.

**Regression Test:** Verify that without any environment variables, `is_production()` returns `False` and that key security checks (PQ required, cert verification required) fail-closed in the default configuration.

---

### F-04: Random IV for AES-GCM — Birthday-Bound Collision Risk

**Severity:** High  
**Confidence:** High (direct code inspection)  
**Location:** `p2p_core.py:52` (`iv = secrets.token_bytes(12)`), `platform_hsm_interface.py:41` (`iv = secrets.token_bytes(12)`)

**Description:** AES-GCM encryption uses randomly generated 96-bit IVs via `secrets.token_bytes(12)` rather than counter-based nonces. Under NIST SP 800-38D, random nonces for AES-GCM have a birthday-bound collision probability of approximately 2^32 invocations with the same key. After ~2^32 encryptions under a single key, the probability of nonce reuse exceeds negligible bounds, causing catastrophic failure of both confidentiality and authenticity (GCM tag forgery and plaintext recovery become possible upon nonce reuse).

The `DoubleRatchet` class uses `CounterBasedNonceManager` (salt + counter) which is correct, but `p2p_core.py` and `platform_hsm_interface.py` use random IVs independently.

**Violated Property:** AEAD nonce uniqueness; AES-GCM security bound.

**Attack Prerequisites:** Attacker observes ~2^32 or more AES-GCM encryptions under the same key in `p2p_core.py` or `platform_hsm_interface.py` code paths.

**Impact:** Upon nonce reuse, an attacker can recover the authentication key and forge arbitrary messages, and potentially recover plaintext from XOR of two ciphertexts encrypted with the same nonce.

**Remediation:** Replace random IV generation with counter-based nonce management (like `CounterBasedNonceManager`) or use XChaCha20-Poly1305 with random nonces (192-bit nonce, safe for random generation). Ensure each key instance has a strictly monotonic nonce counter.

**Regression Test:** Encrypt 2^16+ messages under the same key using `p2p_core.secure_encrypt_aes_256_gcm` and verify no IV repetition (or switch to counter-based nonces).

---

### F-05: PQ Ratchet v1 Provides No Fresh Post-Compromise Security Between DH Steps

**Severity:** High  
**Confidence:** High (code logic inspection)  
**Location:** `double_ratchet.py:2164-2170` (v1 refused in strict mode), `double_ratchet.py:2524-2531` (v1 reuses `_synchronized_kem_secret`), `double_ratchet.py:2216-2227` (v1 default when protocol_version < 2)

**Description:** The Double Ratchet has two PQ ratchet versions:

- **v1 (legacy):** Reuses `_synchronized_kem_secret` across DH steps. Provides NO fresh post-compromise security between ratchet steps. If the KEM secret is compromised, all past and future messages remain decryptable until a new DH exchange with fresh KEM encaps occurs.
- **v2 (fresh):** Performs fresh ML-KEM-1024 encaps per DH step, mixed via `hybrid_combine_v2`. Provides PQ PCS healing.

The default `protocol_version` is 1, so `pq_ratchet_version` defaults to `PQ_RATCHET_VERSION_LEGACY` (v1) unless the caller explicitly sets `protocol_version >= 2`. Production/TS mode (`_strict_ratchet`) refuses v1, but lab/default mode permits it.

**Violated Property:** Post-compromise security (PCS) as claimed in README section 3.7.

**Attack Prerequisites:** Attacker compromises the `_synchronized_kem_secret` or KEM private key in a v1 session.

**Exploit Steps:**

1. Establish v1 Double Ratchet session (default)
2. Attacker exfiltrates `_synchronized_kem_secret` from memory or storage
3. All messages encrypted under chains derived from this KEM secret are decryptable, past and future, until the next DH ratchet step (which still reuses the same KEM secret in v1)
4. PCS never occurs because the KEM secret is never refreshed between DH steps

**Impact:** No post-compromise security in default configuration. Key compromise is permanent for the session lifetime.

**Remediation:** Default to `protocol_version=2` and `pq_ratchet_version=2` (fresh KEM per DH step). Require v2 in all non-lab modes.

**Regression Test:** Verify that a DoubleRatchet with default parameters has `pq_ratchet_version == 2` and that `_synchronized_kem_secret` is refreshed on each DH ratchet step.

---

### F-06: Deniable Mode Eliminates Per-Message Signatures

**Severity:** Medium  
**Confidence:** High (code logic inspection)  
**Location:** `double_ratchet.py:2137-2142` (deniable flag), `double_ratchet.py:3573-3574` (signature skipped when deniable), `double_ratchet.py:3947-3952` (signature not required on decrypt when deniable)

**Description:** When `deniable=True`, the Double Ratchet skips per-message DSS signatures entirely. Authentication relies solely on the ChaCha20-Poly1305 AEAD tag under the shared chain key. Since both parties share the chain key, either party could have produced any message — providing repudiability but no non-repudiation. The `deniable` flag can be set via `P2P_DENIABLE_MESSAGING=1` or `P2P_DENIABLE=1` environment variables.

**Violated Property:** Message origin authentication with non-repudiation.

**Attack Prerequisites:** Attacker is one of the communicating parties, or has compromised the chain key.

**Impact:** A malicious party can repudiate messages they sent. A third party cannot cryptographically verify message origin. This is inappropriate for NC3/military use cases requiring non-repudiation.

**Remediation:** Deniable mode should require explicit opt-in with `P2P_DENIABLE=1` AND should be refused in production/TS mode. Default should be non-repudiable (signed) mode.

**Regression Test:** Verify that `DoubleRatchet(deniable=True)` produces messages without signatures, and that `DoubleRatchet()` (default) requires signatures when `enable_pq=True`.

---

### F-07: Multiple Parallel Cryptographic Implementations with No Clear TCB

**Severity:** High  
**Confidence:** High (architectural inspection)  
**Location:** `double_ratchet.py`, `noise_pq.py`, `secure_transmit_2027.py`, `p2p_core.py`, `rust_data_plane/src/`

**Description:** At least four distinct cryptographic stacks exist in the repository:

1. `double_ratchet.py`: X25519 + ML-KEM-1024 + ChaCha20-Poly1305 + HKDF-SHA3-512 + FALCON-1024 (USED by `secure_p2p.py`)
2. `noise_pq.py` + `secure_transmit_2027.py`: P-384 + ML-KEM-1024 + AES-256-GCM + SHA-384 + ML-DSA-87 (claimed CNSA 2.0)
3. `p2p_core.py`: ECDH + AES-256-GCM with random IV
4. `rust_data_plane/src/`: Claimed ML-KEM-1024 + ML-DSA-87 + AES-256-GCM (Rust, may not be built/used)

There is no single documented Trusted Computing Base. The README describes Plane 3 (Python) as "quarantined to lab/orchestration" but `secure_p2p.py` (Plane 3) is the primary application entry point. This creates confusion about which implementation provides actual security.

**Violated Property:** TCB clarity; architectural integrity.

**Impact:** Operators and evaluators cannot determine which cryptographic path is actually securing their communications. Security analysis must cover all four stacks instead of one well-defined TCB.

**Remediation:** Define a single TCB. Either make the Rust data plane mandatory for all production traffic (enforced by `production_gate.py`), or consolidate all crypto into one well-audited implementation. Remove or quarantine unused crypto stacks.

**Regression Test:** Verify that `enforce_control_plane_boundary()` prevents Python crypto transit when `P2P_PRODUCTION=1` and that the Rust data plane is the mandatory encryption path.

---

### F-08: Python Memory Zeroization Cannot Be Deterministic

**Severity:** Medium  
**Confidence:** High (CPython runtime limitation, acknowledged in code)  
**Location:** `double_ratchet.py:178-203` (`_wipe_secret_best_effort`), `README.md:38-41` (acknowledgment), `production_gate.py:195-232` (control plane boundary)

**Description:** CPython immutable `bytes` objects cannot be deterministically zeroized due to garbage collector copies, obmalloc arena allocation, and interpreter-internal buffering. The code acknowledges this limitation (`double_ratchet.py:183-184: "CPython bytes are immutable... CANNOT be wiped") but still handles key material in Python (root keys, chain keys, message keys, KEM shared secrets) in`double_ratchet.py`,`secure_p2p.py`, and`p2p_core.py`. The`production_gate.py`attempts to enforce a control plane boundary (`enforce_control_plane_boundary()`) but it is only active when`P2P_PRODUCTION=1` and does not prevent Python from handling keys during handshake setup.

**Violated Property:** Key material zeroization; memory forensics resistance.

**Attack Prerequisites:** Attacker with local forensic access (memory dump, swap file, core dump, hibernation file) to a host running the Python runtime.

**Impact:** Cryptographic key material may remain recoverable in physical RAM, swap, or hibernation files after the application releases it. Cold boot attacks and memory forensics can recover session keys.

**Remediation:** All operational key handling and network transit must occur in the native Rust data plane with `mlock`/`VirtualLock` and `ZeroizeOnDrop`. Python must be restricted to orchestration only, enforced unconditionally (not just when `P2P_PRODUCTION=1`).

**Regression Test:** Verify that no long-lived key material exists as Python `bytes` objects outside of short-lived handshake processing when production mode is active.

---

### F-09: Prebuilt Native Binaries (oqs.dll, libsodium.dll) Without Independent Verification

**Severity:** Medium  
**Confidence:** Medium (binaries present, signatures present but unverified)  
**Location:** `oqs.dll` (4.3 MB), `libsodium.dll` (346 KB), `.sig`, `.pub`, `.hashes` files

**Description:** Prebuilt native DLLs are checked into the repository with accompanying signature (`.sig`) and public key (`.pub`) files. However, there is no evidence in the repository that these binaries were independently built from source or that the signing keys are trusted. The `liboqs_wrapper.py` attempts version verification (`verify_liboqs_native_version`) but does not cryptographically verify the DLL signatures before loading. DLL hijacking is partially mitigated by anchoring to the repository directory (`liboqs_wrapper.py:245-249`), but supply-chain integrity of the binaries themselves is unproven.

**Violated Property:** Supply-chain integrity; binary provenance.

**Impact:** A compromised `oqs.dll` or `libsodium.dll` could subvert all PQC operations, key generation, and random number generation.

**Remediation:** Provide reproducible build instructions for native binaries, sign releases with project keys, and verify signatures at load time before any native function is called.

**Regression Test:** Verify that `liboqs_wrapper.py` validates DLL signatures against a trusted public key before calling any native function.

---

### F-10: No Independent Cryptographic or Protocol Review Evidence

**Severity:** Informational  
**Confidence:** High (no external audit reports in repository)  
**Location:** Repository-wide (absence of evidence)

**Description:** The repository contains self-generated audit artifacts (`audit_bandit.json`, `audit_secret_scan.json`, test logs) but no independent third-party cryptographic review, formal protocol verification (beyond ProVerif models that abstract the KDF), or penetration testing evidence. The README's "Evaluator Disclosures" section acknowledges: "This software is an engineering baseline... It has not undergone accredited laboratory evaluation (FIPS 140-3 CMVP / Common Criteria) and does not possess a government Authority to Operate (ATO)."

**Violated Property:** Independent assurance evidence.

**Impact:** All security claims are self-attested. No external validation of cryptographic correctness, protocol security, or implementation quality exists.

**Remediation:** Commission independent cryptographic review, formal protocol analysis (e.g., ProVerif, Tamarin, or CryptoVerif with concrete models, not abstracted KDF), and penetration testing before any production deployment.

**Regression Test:** N/A — requires external assessment.

---

## F. CRYPTOGRAPHIC AND PROTOCOL ASSESSMENT

### F.1 Encryption and Authenticated Encryption

| Component | Algorithm | Mode | Nonce Handling | Assessment |
| --- | --- | --- | --- | --- |
| `double_ratchet.py` | ChaCha20-Poly1305 | AEAD | Counter + salt (`CounterBasedNonceManager`) | **Good** — counter-based nonces prevent reuse |
| `p2p_core.py` | AES-256-GCM | AEAD | Random 96-bit IV (`secrets.token_bytes(12)`) | **Weak** — birthday-bound collision risk (F-04) |
| `platform_hsm_interface.py` | AES-256-GCM | AEAD | Random 96-bit IV (`secrets.token_bytes(12)`) | **Weak** — same as above |
| `secure_transmit_2027.py` (claimed) | AES-256-GCM | AEAD | Counter-based (claimed in README) | Unverified — not the actual code path |

### F.2 Key Establishment and Key Derivation

| Component | KEX | KDF | Authentication | Assessment |
| --- | --- | --- | --- | --- |
| `double_ratchet.py` (main path) | X25519 + ML-KEM-1024 | HKDF-SHA3-512 (root), HMAC-SHA512 (chain) | FALCON-1024 / ML-DSA-87 | **Non-standard** — deviates from documented CNSA 2.0 |
| `hybrid_kex_legacy.py` (used by `secure_p2p.py`) | X25519 + ML-KEM-1024 | HKDF-SHA3-512 | Ed25519 / FALCON-1024 | **Not the claimed P-384 hybrid** |
| `hybrid_kex.py` `HybridKeyExchange2027` (unused) | P-384 + ML-KEM-1024 | HKDF-SHA384 | ML-DSA-87 | **Matches documentation but unused** |
| `noise_pq.py` (claimed path) | P-384 + ML-KEM-1024 | HKDF-SHA384 | ML-DSA-87 | **Matches documentation but unused by `secure_p2p.py`** |

**Chain ratchet deviation:** Signal's Double Ratchet uses HKDF for chain key derivation. This implementation uses HMAC-SHA512 with info strings (`double_ratchet.py:3325-3338`). While HMAC-based KDF is cryptographically acceptable, it deviates from the standard construction and has not been independently analyzed.

**Root key derivation:** `_initialize_chain_keys` (`double_ratchet.py:4424`) uses a two-step HKDF derivation with domain-separated info strings. This is reasonable but the use of `hashlib.sha3_512` to combine DH and KEM secrets (`double_ratchet.py:4447`) before HKDF is a non-standard combiner.

### F.3 Random Number Generation

| Source | Location | Assessment |
| --- | --- | --- |
| `secrets.token_bytes()` / `os.urandom()` | `platform_hsm_interface.py:3198` | CSPRNG, software-only unless hardware RNG available |
| `X25519PrivateKey.generate()` | `cryptography` library | Uses OpenSSL's RNG |
| ML-KEM keygen | `liboqs_wrapper` via `oqs.dll` | Depends on liboqs internal RNG |

The `get_secure_random()` function in `platform_hsm_interface.py:3186` falls back to `secrets.token_bytes(num_bytes)` when hardware RNG is unavailable. This is acceptable for software-only deployments but does not provide hardware-backed entropy as claimed for TPM/HSM configurations.

### F.4 Nonce and IV Handling

- **Double Ratchet:** `CounterBasedNonceManager` uses salt + counter (8-byte counter + 4-byte salt = 12-byte nonce). Fail-closed at 1% counter exhaustion. **Good practice.**
- **p2p_core.py / platform_hsm_interface.py:** Random 96-bit IVs for AES-GCM. **Weak** — birthday-bound collision risk (F-04).
- **Noise PQ (claimed):** `seq(8BE)||dir(1)||zero(3)` — counter-based. **Good** (if actually used).

### F.5 Forward Secrecy and Post-Compromise Security

| Property | Claimed | Actual (default) | Actual (production/TS) |
| --- | --- | --- | --- |
| Forward Secrecy | Yes | Yes (via DH ratchet + chain keys) | Yes |
| Post-Compromise Security | Yes (PQ double ratchet + CER) | **No** (v1 reuses KEM secret) | Yes (v2 fresh KEM per DH step) |
| Continuous Epoch Ratchet | Yes (every 10K packets / 10 MB) | Unverified (Rust data plane) | Unverified |

The default configuration (v1 PQ ratchet) does **not** provide post-compromise security between DH ratchet steps. Production/TS mode requires v2, but this is not the default.

### F.6 Identity Verification and Authentication

| Mode | Authentication | Non-repudiation | MITM Protection |
| --- | --- | --- | --- |
| Lab (default) | PSK + optional TOFU | No | Weak (TOFU) |
| Production | PSK + ML-DSA-87 mutual | Yes (ML-DSA-87 signatures) | Strong (pinned peer keys + root CA) |
| Deniable | AEAD only | No | Weak |

The `TacticalP2PNode.negotiate_hybrid_kex()` (`secure_p2p.py:14409`) requires mutual ML-DSA-87 authentication outside lab mode, with optional Root CA verification. This is strong when configured correctly, but the `secure_p2p.py` `SecureP2PChat` class uses FALCON-1024 signatures (not ML-DSA-87) for per-message authentication in the Double Ratchet.

### F.7 Algorithm Agility and Downgrade Resistance

The codebase has multiple downgrade paths:

- `enable_pq=False` (classical-only) — refused in production, allowed in lab
- `deniable=True` (no signatures) — allowed via env var
- `PQ ratchet v1` (no fresh PCS) — default, refused in strict mode
- `P2P_ALLOW_CLASSICAL=1` — explicit classical-only opt-in
- `P2P_ENABLE_VULN_HQC=1` — vulnerable HQC-256 opt-in

These are appropriately gated behind environment variables and production-mode checks, but the existence of multiple downgrade paths increases the attack surface for misconfiguration.

### F.8 Cryptographic Error Handling

- **Fail-closed:** Most cryptographic failures raise `SecurityError` and abort operations
- **Oracle reduction:** Generic error messages on the wire, details in local log only (`secure_transmit_2027.py:58-59`)
- **InvalidTag handling:** `double_ratchet.py:3703-3705` raises `SecurityError("Message authentication failed")` on tag verification failure
- **KDF self-verification:** `double_ratchet.py:3409-3419` verifies KDF output by re-deriving — catches library corruption

### F.9 Quantum Resistance Assessment

| Component | Classical Security | Post-Quantum Security | Quantum-Resistant? |
| --- | --- | --- | --- |
| X25519 (used) | ~128 bits | Broken by Shor's | **No** |
| P-384 (claimed, unused) | ~192 bits | Broken by Shor's | **No** |
| ML-KEM-1024 (used) | N/A | Category 5 | **Yes** |
| ML-DSA-87 (claimed, partially used) | N/A | Category 5 | **Yes** |
| FALCON-1024 (used) | N/A | Category 5 (IPD track, not finalized) | **Yes (candidate)** |
| ChaCha20-Poly1305 | 256-bit key | Grover's reduces to 128-bit | **Partially** |
| AES-256-GCM | 256-bit key | Grover's reduces to 128-bit | **Partially** |

The hybrid construction (X25519 + ML-KEM-1024) provides "dual security": secrecy holds if either the discrete log problem or Module-LWE remains intractable. However, the classical component (X25519) is weaker than the claimed P-384 (~128-bit vs ~192-bit classical security).

---

## G. COMPARATIVE ASSESSMENT

| Security Dimension | Destroyer-ST2027 (Actual Code) | Signal Protocol | WhatsApp (Signal-based) |
| --- | --- | --- | --- |
| **End-to-end encryption** | Double Ratchet + optional TLS 1.3 outer | Double Ratchet (Signal Protocol) | Double Ratchet (Signal Protocol) |
| **Coverage** | Chat messages (Double Ratchet); file transfer; NC3 directives | All messages, calls, attachments | All messages, calls, attachments |
| **Exceptions** | Lab mode allows classical-only, deniable sessions | None (default configuration) | None |
| **Key establishment** | X25519 + ML-KEM-1024 hybrid (legacy path); P-384 + ML-KEM-1024 (claimed, unused) | X3DH (X25519) + optional PQXDH | X3DH (X25519) + optional PQXDH |
| **Authentication** | FALCON-1024 / ML-DSA-87 signatures + pinned peer keys | Safety Numbers (SAS) + optional PIN | Safety Numbers (SAS) |
| **Forward secrecy** | Yes (via DH ratchet) | Yes (per-message DH ratchet) | Yes |
| **Post-compromise security** | **No (v1 default); Yes (v2, production only)** | Yes (DH ratchet heals on new message from peer) | Yes |
| **Group messaging** | `group_key_manager.py` + `treekem.py` (MLS-like) | MLS (Signal is transitioning) | MLS (in development) |
| **Identity verification** | SAS (6-digit) + pinned ML-DSA-87 keys | Safety Numbers | Safety Numbers |
| **Key-change notifications** | Ratchet key ID changes in header | Yes (new sender key in header) | Yes |
| **Metadata protection** | Constant-rate pacing (50ms), Poisson chaff, header masking | Limited (Sealed Sender) | Limited |
| **Server trust** | P2P (no central server claimed); TLS 1.3 outer | Signal service (limited metadata) | WhatsApp/Meta servers |
| **Local data protection** | In-memory only (default); secure wipe | Encrypted local database | Encrypted local database |
| **Independent audits** | **None (self-attested only)** | Multiple (NCC Group, Cure53, etc.) | Multiple |
| **Formal verification** | ProVerif models (abstracted KDF) | ProVerif, Tamarin (Signal Protocol) | N/A |
| **Reproducible builds** | Not evidenced | Yes (Signal) | No |
| **Supply chain** | Prebuilt DLLs (unverified provenance) | Signed releases, reproducible builds | Signed releases |

### Key Comparative Findings

1. **Post-compromise security:** Signal provides PCS through its DH ratchet — every new message from a peer triggers a DH step that heals compromise. Destroyer-ST2027's default configuration (PQ ratchet v1) does **not** provide fresh PCS between DH steps. Only the v2 configuration (required in production/TS mode) provides this.

2. **Independent audit:** Signal has undergone multiple independent security audits (NCC Group 2016, Cure53 2021, etc.). Destroyer-ST2027 has only self-generated audit artifacts.

3. **Cryptographic suite:** Destroyer-ST2027 claims CNSA 2.0 (P-384 + ML-KEM-1024 + AES-256-GCM + SHA-384 + ML-DSA-87) but implements X25519 + ML-KEM-1024 + ChaCha20-Poly1305 + HKDF-SHA3-512 + FALCON-1024. Signal uses X25519 + AES-256-GCM + SHA-256/HKDF-SHA256 (well-analyzed, standard).

4. **Metadata protection:** Destroyer-ST2027 claims stronger metadata protection (constant-rate pacing, header masking, Poisson chaff) than Signal/WhatsApp, but this is unverified in the Python code path and depends on the Rust data plane which may not be the mandatory enforcement point.

---

## H. ENGINEERING QUALITY AND MAINTAINABILITY

### H.1 Code Organization

**Strengths:**

- Extensive modularization with clear separation of concerns
- Comprehensive error handling with custom exception hierarchy (`cryptographic_errors.py`)
- Fail-closed design patterns throughout security-critical paths
- Sticky production latch prevents accidental downgrade
- Constant-time comparison utilities (`ConstantTime.compare`)
- Replay protection with sliding window and expiry

**Weaknesses:**

- **~200 Python files** with overlapping functionality (multiple crypto stacks, multiple auth systems, multiple network layers)
- **486 KB `platform_hsm_interface.py`** — monolithic file handling RNG, TPM, HSM, key storage, attestation, audit logging
- **281 KB `double_ratchet.py`** — combines protocol logic, threat detection, canary protection, side-channel countermeasures
- **335 KB `tls_channel_manager.py`** — TLS context management with many code paths
- No clear layering or module dependency diagram
- Circular import risks (e.g., `double_ratchet.py` imports `tls_channel_manager` for nonce manager)

### H.2 Dependency Management

**Strengths:**

- `requirements.txt` uses pinned versions with SHA-256 hashes (`--require-hashes` compatible)
- `cryptography==50.0.1` (recent, patched)
- `pycryptodome==3.23.0` (recent)
- LibOQS pinned to 0.16.0 with known SHA

**Weaknesses:**

- Prebuilt `oqs.dll` and `libsodium.dll` without reproducible build evidence
- Multiple Python crypto libraries (`cryptography`, `pycryptodome`, `libsodium`) increase supply chain surface
- No `cargo.lock` or `Cargo.toml` checksum verification evidence for Rust dependencies

### H.3 Error Handling

**Strengths:**

- Fail-closed on cryptographic failures
- Generic error messages on wire, details in local log
- KDF self-verification catches library corruption
- InvalidTag handling raises SecurityError (no oracle)

**Weaknesses:**

- Some `except Exception: pass` blocks swallow errors (e.g., `liboqs_wrapper.py:294`, `double_ratchet.py:3201-3203`)
- Best-effort wipe functions never raise (`_wipe_secret_best_effort`) — failures are silently logged
- Silent fallback when `destroyer_core` import fails (`secure_p2p.py:56-59`)

### H.4 Secure Defaults

**Weaknesses:**

- Production mode is opt-in (`P2P_PRODUCTION=1`)
- Default PQ ratchet is v1 (no fresh PCS)
- Classical-only key exchange allowed in lab
- Deniable mode allowed via env var
- `verify_certs=False` allowed in non-production

### H.5 Testability

**Strengths:**

- ~200 test files covering many security aspects
- Conftest with fixtures for test isolation (`reset_for_tests()`)
- Negative test paths (replay attacks, tampered messages, invalid signatures)
- Fuzz gate tests (`test_parser_fuzz_gates.py`)

**Weaknesses:**

- Tests are self-written, not independent
- No evidence of mutation testing or coverage thresholds
- No integration tests against external implementations
- Test execution was not performed in this audit

### H.6 Configuration Management

**Strengths:**

- `config.json` with production and template variants
- Configuration signatures (`config.json.sig`, `config_production.json.sig`)
- Environment variable overrides with validation
- Sticky production latch

**Weaknesses:**

- Multiple config backups with potentially different settings (`config_backup_20261001_*.json`)
- Configuration signature verification not traced in this audit
- No evidence of configuration drift detection

### H.7 Likelihood of Security Regressions

**High risk** due to:

1. Multiple parallel crypto implementations that can drift apart
2. Opt-in production mode that operators may forget to enable
3. Environment-variable-based security toggles that can be misconfigured
4. No single TCB — changes to one stack may not be reflected in others
5. Self-written tests that validate implementation behavior, not external standards

---

## I. REMEDIATION & PRE-ACCREDITATION SCORECARD

### Scoring Rubric (0-100)

Each score reflects the implementation state **as verified in-repo**, explicitly capped where external hardware, CMVP-validated binaries, or accredited third-party verification are absent:

- **90-100:** Externally accredited, hardware-provisioned, and independently verified
- **75-89:** Software & protocol controls remediated and test-verified in-repo; external accreditation/hardware prerequisites pending
- **50-74:** Notable software/protocol weaknesses requiring remediation before controlled evaluation
- **0-49:** Critical failures or non-functional security boundary

### Scores (Post-Remediation In-Repo State)

| Dimension | Score | Basis |
| --- | --- | --- |
| **Cryptographic Correctness** | **82** | CNSA Suite 2.0 hybrid KEX (`HybridKeyExchange2027`: P-384 + ML-KEM-1024 + ML-DSA-87), NIST SP 800-38D composite nonces, sound Ristretto255 `bLSAG` ring signatures (`pq_zkp.rs`, explicitly marked classical), and fail-closed `ThresholdKeyManager` / DDIL key pinning; capped pending CMVP-validated replacements for prebuilt `oqs.dll` / `libsodium.dll` |
| **Protocol and Architecture Security** | **84** | DoubleRatchet v2 default with per-epoch ML-KEM-1024 PCS healing, verify-before-mutate AEAD handling across Python/Rust pipelines, fail-closed `production_gate`, and seL4 MILS 3-domain separation (`validate_mils.py --strict`); capped pending Linux CI `ProVerif >= 2.05` & `cargo kani` execution against current models |
| **Application Security** | **84** | Native Rust `rust_data_plane` data plane with RFC 6479 replay windows, authenticated WebAuthn/CSRF/RBAC fixes, zero tracked Bandit medium/high findings on active modules, and Clippy `-D warnings` clean; capped pending full parser fuzzing campaigns under external QA |
| **Identity and Access Control** | **82** | Mutual ML-DSA-87 authentication, fail-closed CRL/OCSP handling, SAS out-of-band verification, and P-384/ML-DSA-87 NC3 multi-party custody binding; capped pending physical PKCS#11 token / smartcard provisioning on target hosts |
| **Data and Metadata Protection** | **80** | Constant-rate pacing, 1232-byte packet quantization, AES-256-GCM field-level audit DB encryption, `#![no_std]` MILS filtering, and `ZeroizeOnDrop`/`VirtualLock`/`mlock` scrubbing; capped pending physical TEMPEST/optical diode & SecureBoot/DMA host enforcement |
| **Dependency and Supply-Chain Security** | **80** | Embedded Ed25519 + SHA3-512 native library pinning, strict LibOQS POSIX SHA-384 pinning in CI, locked `cargo-deny`, CycloneDX/SPDX SBOM generation, and `critical_modules.hashes`; capped pending air-gapped hermetic signing & CMVP module provenance |
| **Testing and Verification Maturity** | **83** | Comprehensive Python pytest suite and Rust unit/adversarial suites passing, strict `ts_rt` & `sel4_mils_appliance` tests, and honest fail-closed verification harnesses (no synthetic `PASS` for missing ProVerif or simulated hardware); external CAVP/CMVP lab testing not yet executed |
| **Operational Readiness** | **65** | Deployment scripts (`verify_deployment.py`) enforce fail-closed posture under `P2P_PRODUCTION=1` and emit `WARN` under non-production simulation fallbacks; target hardware provisioning (TPM 2.0 NV, UEFI SecureBoot, physical two-person tokens, air-gap diodes) and ATO remain prerequisites |
| **Overall In-Repo Assurance** | **80 / 100** | **SOFTWARE REMEDIATION COMPLETE FOR TESTED CODEPATHS — EXTERNAL HARDWARE & ACCREDITATION GATES PENDING** |

---

## J. REMEDIATION ROADMAP STATUS

All identified in-repo software defects (J-01 through J-10 plus follow-up audit remediations) have been implemented in source code:

| ID | Action | Status | Verification Evidence |
| --- | --- | --- | --- |
| **J-01** | Align application paths to use `HybridKeyExchange2027` (P-384 + ML-KEM-1024) | **COMPLETE (SW)** | `tests/test_cnsa2_hybrid_kex_2027.py`, `hybrid_kex.py`, `unified_secure_pipeline.py` |
| **J-02** | Enforce AES-256-GCM and verify-before-mutate AEAD handling | **COMPLETE (SW)** | `double_ratchet.py`, `rust_data_plane/src/pipeline.rs`, `sovereign_group_ratchet.py` |
| **J-03** | Enforce deterministic NIST SP 800-38D nonces & eliminate nonce collisions | **COMPLETE (SW)** | `p2p_core.py`, `platform_hsm_interface.py`, `cnsa_crypto_gateway.py`, `threshold_cryptography.py` |
| **J-04** | Enforce fail-closed production posture across entry points and CI | **COMPLETE (SW)** | `production_gate.py`, `destroyer.py`, `destroyer_node.py`, `verify_deployment.py`, `.github/workflows/defense_ci.yml` |
| **J-05** | Enforce PQ ratchet v2 (fresh ML-KEM-1024 per epoch) as unconditional default | **COMPLETE (SW)** | `double_ratchet.py` (`protocol_version=2`) |
| **J-06** | Consolidate Rust data plane & harden DDIL/threshold/MILS boundaries | **COMPLETE (SW)** | `rust_data_plane`, `tactical_mesh_ddil.py`, `threshold_cryptography.py`, `sel4_mils_appliance` |
| **J-07** | Memory zeroization via `VirtualLock`/`mlock`, `ZeroizeOnDrop`, and canary checks | **COMPLETE (SW)** | `ts_rt`, `rust_data_plane/src/memory_guard.rs` |
| **J-08** | Remove synthetic audit/formal bypasses and self-signed epistemic inflation | **COMPLETE (SW)** | `run_formal_verification.py`, `docs/formal/check.sh`, `verify_deployment.py` |
| **J-09** | Author accurate ProVerif 2.05 / Kani proofs for Linux CI verification | **IN PROGRESS (CI GATE)** | `docs/formal/*.pv`, `.github/workflows/defense_ci.yml`, `.github/workflows/kani-proofs.yml` |
| **J-10** | FIPS 140-3 CMVP modules, hardware provisioning, and external ATO | **EXTERNAL PREREQUISITE** | Target hardware TPM 2.0 NV, physical PKCS#11 HSMs, CMVP vendor modules, DAO/DAA sign-off |

---

## K. FINAL GO/NO-GO DECISION

### 1. Further Development & Regression Testing

**Decision: GO**  
Codebase architecture, fail-closed boundaries, and automated test suites are stabilized and maintainable in CI.

### 2. Controlled Internal Lab / Evaluation Testing

**Decision: GO (LAB MODE ONLY — DO NOT HANDLE LIVE SENSITIVE DATA)**  
Non-production evaluation (`P2P_PRODUCTION=0`) clearly surfaces hardware/simulation fallbacks as `WARN` rather than masking missing hardware.

### 3. Controlled External Accredited Lab Evaluation

**Decision: CONDITIONAL GO**  
Ready for third-party code review, ProVerif/Kani CI runs, and pre-accreditation assessment once target Linux CI workflows complete cleanly.

### 4. Production Deployment with Sensitive Data

**Decision: NO-GO PENDING HARDWARE & MODULE PREREQUISITES**  
Requires provisioned host UEFI SecureBoot + IOMMU/DMA protection, hardware TPM 2.0 NV (`P2P_TPM_NV_INDEX`), physical PKCS#11 tokens/HSMs, CMVP-validated cryptographic libraries, and `P2P_PRODUCTION=1` passing with zero failures/warnings.

### 5. Military or Classified Sovereign Use

**Decision: NO-GO PENDING FORMAL ACCREDITATION (ATO)**  
Cannot be authorized solely from internal software tests. Requires independent cryptographic validation, TEMPEST/physical optical diode verification, CMVP-validated crypto, verified formal proofs in CI, and Authorizing Official ATO.

## LIMITATIONS & EVIDENCE BOUNDARY

1. **Software vs. Operational Assurance:** Static analysis and unit/integration tests executed on a Windows workstation cannot validate physical hardware security (TPM 2.0 NV hardware, PKCS#11 smartcards, UEFI SecureBoot, physical optical diodes, TEMPEST shielding).
2. **External Verification Tools:** `proverif` and `cargo kani` require the Linux CI environment (`.github/workflows/defense_ci.yml`, `.github/workflows/kani-proofs.yml`) and were not locally installed on Windows during this cycle.
3. **Cryptographic Module Provenance:** Prebuilt native DLLs (`oqs.dll`, `libsodium.dll`) are pinned by SHA3-512/Ed25519 integrity checks in-repo but are not FIPS 140-3 CMVP-validated binaries.
4. **Live Adversarial Network Testing:** Dynamic testing covers in-repo Python/Rust test harnesses (`-m "not live"`); full multi-node WAN/RF EW testing requires dedicated test range infrastructure.

---

**End of Report**

Updated 2026-11-26 following software remediation verification (Waves 1–5 of `ST2027_FORENSIC_AUDIT_2026-11-26.md`) on D:\code\Main_projects\p2p\p2p_6_1-26. This document makes no claim of external accreditation or absolute security.
