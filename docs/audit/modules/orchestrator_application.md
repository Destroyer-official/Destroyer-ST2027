# Module Documentation: orchestrator_application

## 1. Module Overview

The `orchestrator_application` module encompasses the primary execution engines, application launchers, protocol state orchestrators, and high-level message pipelines. It integrates cryptographic algorithms, key management, transport layers, and host security primitives into cohesive operational runtime nodes.

### Files in Scope (17 Files, 31,548 Lines)

| File | Lines | Purpose |
|---|---|---|
| `base.py` | 257 | Base abstract class and standardized error hierarchy for system components. |
| `core/__init__.py` | 10 | Package initialization exposing orchestrator and configuration managers. |
| `core/config.py` | 110 | Configuration loading, validation, and caching manager. |
| `core/orchestrator.py` | 1,714 | Modular decomposition of the communications engine coordinating keys, protocol, and network. |
| `cross_platform_exception_handler.py` | 1,585 | Platform-specific fault supervisor preventing credential leakage during crashes. |
| `cryptographic_agility.py` | 1,310 | Version-tagged cipher suite negotiator and signed runtime policy updater. |
| `cryptographic_errors.py` | 768 | Structured error definitions, error codes, and security severity ratings. |
| `data_models.py` | 295 | Core dataclasses for handshake state, user profiles, peer metadata, and security roles. |
| `dep_impl.py` | 4,437 | System exploit mitigations (DEP, ASLR, ACG, CFG) and memory page protection via Win32/POSIX. |
| `destroyer.py` | 499 | Primary CLI launcher, environment probe, and command dispatcher. |
| `destroyer_node.py` | 562 | High-throughput node driver bridging Python control logic to the native Rust data plane. |
| `destroyer_tactical_p2p.py` | 820 | Operational console node coordinating mesh communication and emergency sanitization. |
| `protocol_manager.py` | 979 | Handshake state machine and session key derivation controller. |
| `secure_p2p.py` | 14,886 | Monolithic prototype engine combining chat interface, networking, and security layers. |
| `secure_transmit_2027.py` | 2,394 | High-assurance public internet transport coordinating TLS 1.3 and Noise_XXhfs handshakes. |
| `storage.py` | 114 | Key persistence interface with cryptographic validation. |
| `unified_secure_pipeline.py` | 808 | Multi-barrier message pipeline linking post-quantum ratchets, Rust AEAD, and traffic quantization. |

---

## 2. Architecture & Component Interaction

The orchestrator and application layer operates across three operational patterns:

```
+-----------------------------------------------------------------------------------+
|                            APPLICATION ENTRY POINTS                               |
|   destroyer.py (CLI Coordinator)        destroyer_tactical_p2p.py (Console Node)  |
+------------------------------------------+----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                         CORE ORCHESTRATION PIPELINES                              |
|   unified_secure_pipeline.py             secure_transmit_2027.py                  |
|   +-------------------------------+      +------------------------------------+   |
|   | Layer 1: PQC Double Ratchet   |      | Inner: Noise_XXhfs Handshake       |   |
|   | Layer 2: Rust Data Plane AEAD |      | Outer: TLS 1.3 Mutual ML-DSA-87    |   |
|   | Layer 3: Quantized Padding    |      | Continuous Epoch Ratchet (128 msg) |   |
|   +-------------------------------+      +------------------------------------+   |
+------------------------------------------+----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                        SESSION & PROTOCOL STATE ENGINES                           |
|   protocol_manager.py (Handshake State)     cryptographic_agility.py (Agility)    |
|   core/orchestrator.py (Subsystems)         secure_p2p.py (Prototype Engine)     |
+------------------------------------------+----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                        HOST HARDENING & EXPLOIT MITIGATION                        |
|   dep_impl.py (DEP, ACG, CFG, ASLR)         cross_platform_exception_handler.py   |
|   data_models.py (Data Entities)            cryptographic_errors.py (Exceptions)  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Detailed Component Analysis

### 3.1 `unified_secure_pipeline.py`
- **Class `UnifiedSecurePipeline` (`:62`):**
  - Connects Layer 1 post-quantum double ratchet encryption with Layer 2 native Rust AEAD encapsulation (`destroyer_node.py`).
  - Method `seal(plaintext: bytes, aad: bytes = b'') -> bytes`:
    1. Pads payload to discrete sizes in `PAD_QUANTA = (256, 512, 1024, 2048, 4096, 8192, 16384)`.
    2. Encrypts payload with Layer 1 double ratchet (`pqc_algorithms` + `double_ratchet.py`).
    3. Derives Layer 2 domain-separated frame key via HKDF-SHA512 using `LAYER2_HKDF_SALT = b"destroyer-p2p-rust-v1"`.
    4. Encapsulates inner ciphertext inside Layer 2 Rust AEAD (AES-256-GCM) with monotonically incrementing nonce.
  - Method `open(frame: bytes, aad: bytes = b'') -> bytes`:
    1. Strips and validates outer Layer 2 frame header and MAC.
    2. Decrypts inner Layer 1 double ratchet ciphertext.
    3. Unpads quantized padding; invalid padding triggers fail-closed `PipelineSecurityError`.
- **Class `AutonomousDefenseRatchet` (`:410`):**
  - Implements Continuous Epoch Ratchet (CER): increments message counter on every frame; triggers re-keying and epoch rotation when counter reaches `CER_EPOCH_INTERVAL = 128`.

### 3.2 `secure_transmit_2027.py`
- **Class `Channel` (`:512`):**
  - Manages dual-layer network transport over the public internet.
  - Outer Layer: TLS 1.3 socket with single allowable cipher suite `TLS_AES_256_GCM_SHA384` and mutual post-quantum certificate verification.
  - Inner Layer: Noise_XXhfs 3-message handshake executing ephemeral SecP384r1 + ML-KEM-1024 hybrid key exchange.
  - Transcripts signed with ML-DSA-87 (FIPS 204); M1 message transmits ephemeral public keys only, ensuring no identity disclosure to passive network observers.
- **Class `ReplayWindow` (`:230`):**
  - Implements RFC 6479 decoupled sliding-window anti-replay filter using a 2048-bit bitmap tracking received sequence numbers.

### 3.3 `destroyer.py` and `destroyer_node.py`
- **`destroyer.py` CLI Coordinator (`:1-499`):**
  - Primary execution entry point. Parses command-line arguments (`--node`, `--tactical`, `--web`, `--audit`, `--zeroize`).
  - Executes `probe_hardware_and_environment()` before running any network service, validating availability of hardware entropy sources and system memory protection.
- **`destroyer_node.py` Data Plane Driver (`:1-562`):**
  - `DestroyerNode` (`:45`) initializes native Rust data plane via FFI (`destroyer_core`).
  - Implements traffic camouflaging via `send_chaff()` and continuous Poisson-distributed pacing (`start_pacing_chaff()`), injecting random dummy packets indistinguishable from encrypted traffic.

### 3.4 `dep_impl.py`
- **Class `EnhancedDEP` (`:110`):**
  - Enforces platform-specific hardware Data Execution Prevention (DEP).
  - Windows Platform: Calls `SetProcessDEPPolicy(1)` and invokes `SetProcessMitigationPolicy` for:
    - `ProcessASLRPolicy`: Enforces high-entropy 64-bit ASLR (`HighEntropy = 1`).
    - `ProcessDynamicCodePolicy`: Enables Arbitrary Code Guard (ACG), blocking dynamic code generation (`ProhibitDynamicCode = 1`).
    - `ProcessControlFlowGuardPolicy`: Enforces Control Flow Guard (`EnableControlFlowGuard = 1`).
  - Linux Platform: Utilizes `mprotect()` with strict `PROT_READ | PROT_WRITE` or `PROT_READ | PROT_EXEC` (strict W^X enforcement).
  - Function `secure_erase(data)` (`:1800`): Overwrites memory buffers with multi-pass random and inverted patterns.

### 3.5 `cryptographic_agility.py`
- **Class `AlgorithmNegotiator` (`:210`):**
  - Manages version-tagged cipher suite negotiation between endpoints.
  - Enforces signed configuration updates: any change to active cipher suites must be digitally signed with the administrative ML-DSA-87 root key.
  - Rejects unsigned configuration files fail-closed (`UnsignedConfigurationError`).
  - Maintains deprecation timers: emits warning logs 90 days before an algorithm is scheduled for operational removal.

### 3.6 `protocol_manager.py`
- **Class `ProtocolManager` (`:110`):**
  - Controls handshake state transitions: `INIT` -> `HANDSHAKE_INITIATED` -> `HANDSHAKE_RESPONDED` -> `ESTABLISHED` -> `REKEYING` -> `CLOSED`.
  - Coordinates ML-KEM-1024 encapsulation/decapsulation and verifies peer identity certificates via `tls_channel_manager`.
  - Derives directional session keys ($K_{send}, K_{recv}$) using HKDF-SHA512.

### 3.7 `cross_platform_exception_handler.py`
- **Classes `WindowsExceptionHandler` (`:180`) and `LinuxExceptionHandler` (`:290`):**
  - Implements low-level fault trapping (Win32 structured exception handling and POSIX signals `SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGILL`).
  - Sanitizes exception traces to prevent in-memory cryptographic keys from being written to unencrypted crash logs or core dumps.
  - Triggers memory zeroization before process termination.

### 3.8 `secure_p2p.py`
- **Class `SecureP2PChat` (`:500-14886`):**
  - Monolithic reference implementation containing complete user management, networking, file transfer, and cryptographic state machines in a single file.
  - Serves as the functional template from which modular components (`core/orchestrator.py`, `messaging/`, `transports/`) were factored out.

---

## 4. Cryptographic & Security Mechanisms

1. **Defense-in-Depth Framing:**
   Outbound messages processed through `unified_secure_pipeline.py` are subjected to three distinct mathematical and structural barriers:
   $$	ext{Wire Frame} = 	ext{Rust-AEAD}_{K_{L2}}\Big(	ext{DoubleRatchet}_{K_{L1}}ig(	ext{Pad}(	ext{Payload})ig)\Big)$$
2. **Fixed Padding Quanta:**
   Payload lengths are quantized into discrete buckets ($256, 512, 1024, 2048, 4096, 8192, 16384$ bytes). Messages exceeding 16,384 bytes must be chunked into separate frames.
3. **Continuous Epoch Ratchet (CER):**
   Every 128 frames, `AutonomousDefenseRatchet` injects fresh ephemeral key exchange entropy into the ratchet root, providing post-compromise security recovery.
4. **Anti-Replay Verification:**
   `ReplayWindow` in `secure_transmit_2027.py` and `destroyer_core` validates monotonic sequence numbers across a 2048-packet sliding window. Replayed or late frames are dropped silently.

---

## 5. Verification & Test Coverage

### Test Suites Executed

| Test Suite | Purpose | Tests | Result | Execution Time |
|---|---|---|---|---|
| `tests/test_unified_secure_pipeline.py` | Quantized padding, frame headers, dual-layer AEAD, CER rotation | 25 | Passed | 2.14s |
| `tests/test_destroyer_core_production.py` | Anti-replay window, chaff absorption, Poisson pacing, Rust bridge | 8 | Passed | 1.82s |
| `tests/test_secure_transmit_2027.py` | TLS 1.3 + Noise_XXhfs handshake, midstream rekey, replay window | 43 | Passed | 4.11s |
| `tests/test_defensive_audit_targets.py` | DEP enforcement, anti-forensics, path traversal rejection | 18 | Passed | 8.56s |

### Verification Evidence Summary
- Quantized padding roundtrips, multi-block payloads, and corrupted length rejections verified in `TestQuantizedPadding`.
- Post-compromise security epoch advancement verified in `test_cer_epoch_rotation`.
- Decoupled anti-replay window verified in `test_04_wireguard_anti_replay_window`.
- Strict path traversal rejection and encrypted key requirement verified in `TestSecureDefaults`.

---

## 6. Operational Gotchas & Discrepancies

1. **Embedded Promotional Identifiers:**
   - `secure_p2p.py:520` declares class `[BANNED-PREFIX]Crypto` (contains prohibited prefix).
   - `core/orchestrator.py:180, 210` declares methods `_add_[BANNED-PREFIX]_grade_padding` and `_generate_[BANNED-PREFIX]_auth_tag`.
   - `destroyer_tactical_p2p.py:51, 58` emits operational classification strings (`[BANNED-HEADER]`) in terminal banners.
   - Cataloged for formal recording in `docs/audit/discrepancies.md`.
2. **Prototype and Modular Twin Structure:**
   - `secure_p2p.py` (14,886 lines) and `core/orchestrator.py` (1,714 lines) maintain overlapping orchestration logic. Changes made to one must be synchronized or the monolithic prototype deprecated.
3. **Rust Data Plane Requirement:**
   - In production environments (`SECURE_P2P_PRODUCTION=1`), `unified_secure_pipeline.py:240` requires compiled Rust binaries (`destroyer_core`). If unavailable, execution raises `PipelineSecurityError` (fail-closed).