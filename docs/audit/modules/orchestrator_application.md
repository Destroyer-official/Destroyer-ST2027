# Module Documentation: orchestrator_application

## 1. Purpose
The `orchestrator_application` module coordinates runtime execution, application entry points, handshake state machines, multi-barrier encryption pipelines, and system process hardening (`destroyer.py:1-499`, `secure_p2p.py:1-16874`, `unified_secure_pipeline.py:1-808`). It binds post-quantum algorithms, native Rust data plane acceleration, and transport sockets into active communication nodes (`secure_transmit_2027.py:512-650`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `unified_secure_pipeline.UnifiedSecurePipeline` (`unified_secure_pipeline.py:62-380`)
- `__init__(l1_ratchet: Any, l2_key: bytes, role: str = "initiator")`: Initializes dual-layer encryption pipeline (`unified_secure_pipeline.py:68-110`). Parameter `l2_key` must be 32 bytes; raises `ValueError` if length differs (`unified_secure_pipeline.py:75-78`). Parameter `role` must be `"initiator"` or `"responder"` (`unified_secure_pipeline.py:82`).
- `seal(plaintext: bytes, aad: bytes = b"") -> bytes`: Encapsulates plaintext across two cryptographic barriers (`unified_secure_pipeline.py:120-185`). Pads payload to quantized boundary in `PAD_QUANTA` (`:130`). Computes Layer 1 double ratchet encryption (`:140`). Computes Layer 2 frame encryption with AES-256-GCM and monotonic sequence counter (`:155-175`). Returns complete wire frame bytes.
- `open(frame: bytes, aad: bytes = b"") -> bytes`: Authenticates Layer 2 AEAD tag, validates frame sequence against replay, decrypts Layer 1 double ratchet, and strips quantized padding (`unified_secure_pipeline.py:190-260`). Raises `PipelineSecurityError` on tag mismatch, replay, or invalid padding (`:205, 230, 255`).

#### `unified_secure_pipeline.AutonomousDefenseRatchet` (`unified_secure_pipeline.py:410-520`)
- `__init__(initial_root_key: bytes, epoch_interval: int = 128)`: Initializes Continuous Epoch Ratchet (`unified_secure_pipeline.py:415-430`). Parameter `initial_root_key` must be 32 bytes (`:418`).
- `step(remote_eph_pub: Optional[bytes] = None) -> bytes`: Advances ratchet state by 1 message (`unified_secure_pipeline.py:435-475`). Increments internal counter `msg_count`. When `msg_count >= epoch_interval`, executes post-compromise security re-keying via fresh ephemeral exchange (`:450-465`). Returns 32-byte derived message encryption key.

#### `secure_transmit_2027.Channel` (`secure_transmit_2027.py:512-650`)
- `connect(peer_host: str, peer_port: int, timeout_sec: float = 30.0) -> bool`: Establishes outer TLS 1.3 channel and initiates inner Noise_XXhfs handshake (`secure_transmit_2027.py:520-560`). Returns `True` on success; raises `ConnectionError` or `TimeoutError` on failure (`:555`).
- `send(payload: bytes) -> int`: Encrypts and transmits framed message across active channel (`secure_transmit_2027.py:565-590`). Returns number of wire bytes emitted.
- `recv(timeout_sec: Optional[float] = None) -> bytes`: Blocks until next authenticated frame arrives, decrypts payload, and validates anti-replay window (`secure_transmit_2027.py:595-630`). Returns decrypted payload bytes.
- `close() -> None`: Shuts down transport sockets and invokes secure memory zeroization on session keys (`secure_transmit_2027.py:635-648`).

#### `protocol_manager.ProtocolManager` (`protocol_manager.py:110-380`)
- `advance_state(event: str, context: dict) -> HandshakeState`: Advances handshake finite state machine across `INIT`, `HANDSHAKE_INITIATED`, `HANDSHAKE_RESPONDED`, `ESTABLISHED`, `REKEYING`, `CLOSED` (`protocol_manager.py:130-190`). Raises `InvalidStateTransitionError` on illegal transition (`:145`).
- `derive_session_keys(shared_secret: bytes, transcript: bytes) -> Tuple[bytes, bytes]`: Derives directional symmetric keys using HKDF-SHA512 (`protocol_manager.py:240-275`). Returns `(send_key, recv_key)` where each key is 32 bytes (`:270`).

#### `cryptographic_agility.AlgorithmNegotiator` (`cryptographic_agility.py:210-420`)
- `negotiate_ciphersuite(peer_suites: List[str]) -> str`: Matches peer offerings against local approved policy (`cryptographic_agility.py:230-270`). Raises `CipherSuiteMismatchError` if no compliant post-quantum suite is mutually supported (`:265`).
- `apply_signed_policy(policy_json: str, signature: bytes, public_key: bytes) -> bool`: Verifies ML-DSA-87 digital signature over policy document before updating active runtime cipher parameters (`cryptographic_agility.py:310-355`). Raises `UnsignedConfigurationError` on signature failure (`:345`).

## 3. Data Formats and Byte Layouts

### 3.1 Quantized Frame Layout (`unified_secure_pipeline.py:120-175`)
Outbound messages are quantized into discrete block sizes to prevent traffic analysis:
- `PAD_QUANTA = (256, 512, 1024, 2048, 4096, 8192, 16384)` (`unified_secure_pipeline.py:34`).
- Arithmetic verification of wire frame:
  - Header: 4-byte big-endian payload length $L_{plain}$ (`:128`).
  - Payload: $L_{plain}$ bytes (`:130`).
  - Quantized Padding: $L_{pad} = Q - (L_{plain} + 4)$ random bytes where $Q \in \text{PAD\_QUANTA}$ (`:132`).
  - Inner Ratchet Tag: 16 bytes Poly1305 / AES-GCM (`:142`).
  - Outer Layer 2 Header: 8-byte big-endian frame sequence counter (`:158`).
  - Outer Layer 2 AEAD Tag: 16 bytes AES-256-GCM (`:172`).
  - Total Wire Frame Length: $8 + Q + 16 + 16 = Q + 40$ bytes.
  - For $Q = 256$, total wire size is $256 + 40 = 296$ bytes. For $Q = 1024$, total wire size is $1024 + 40 = 1064$ bytes. Sum matches code arithmetic.

### 3.2 Decoupled Anti-Replay Sliding Window (`secure_transmit_2027.py:230-295`)
- Window capacity: 2,048 packets tracking sequence numbers (`secure_transmit_2027.py:235`).
- Bitmap structure: Array of 32 unsigned 64-bit integers ($32 \times 64 = 2,048$ bits = 256 bytes) (`secure_transmit_2027.py:238`).
- Offset calculation: `word_index = (seq % 2048) // 64`, `bit_index = seq % 64`.

## 4. Algorithms and Pinned Libraries
- AES-256-GCM: NIST FIPS 197 / SP 800-38D. Provided by `destroyer_core` Rust native library (`rust_data_plane/src/aead.rs`) with fallback to `cryptography.hazmat.primitives.ciphers.aead.AESGCM` (`unified_secure_pipeline.py:42-50`).
- HKDF-SHA512: IETF RFC 5869. Provided by `hashlib` and `cryptography.hazmat.primitives.kdf.hkdf` (`unified_secure_pipeline.py:88-95`).
- Noise_XXhfs Handshake: Noise Protocol Framework revision 34. Ephemeral hybrid key exchange using SecP384r1 (RFC 5903) and ML-KEM-1024 (FIPS 203) (`secure_transmit_2027.py:515-540`).
- ML-DSA-87: NIST FIPS 204. Identity signature scheme provided by `oqs.dll` version 0.16.0 (`cryptographic_agility.py:320-330`).
- Continuous Epoch Ratchet (CER): Post-compromise security rotation every 128 messages (`unified_secure_pipeline.py:410-430`).

## 5. Dependencies and Hardware Requirements
- Native binaries: `rust_data_plane/target/release/destroyer_core.dll` (Windows) or `libdestroyer_core.so` (Linux).
- Operating System APIs:
  - Windows: `kernel32.dll` (`SetProcessDEPPolicy`, `SetProcessMitigationPolicy` for HighEntropy ASLR, ACG, CFG in `dep_impl.py:110-180`).
  - POSIX: `sys/mman.h` (`mprotect`, `mlock` in `dep_impl.py:210-250`).
- Hardware entropy: Hardware RNG via `os.urandom` and CPU instructions (`RDRAND`/`RDSEED` in `entropy_manager.py`).

## 6. Failure Behavior
- Frame validation failure (tag mismatch, corrupted ciphertext) raises `PipelineSecurityError` (`unified_secure_pipeline.py:45, 205`).
- Frame sequence replay detected raises `PipelineSecurityError("Replay detected")` (`unified_secure_pipeline.py:230`).
- Quantized padding corruption raises `PipelineSecurityError("Invalid padding boundary")` (`unified_secure_pipeline.py:255`).
- Unsigned or invalid policy signature raises `cryptographic_agility.UnsignedConfigurationError` (`cryptographic_agility.py:115, 345`).
- Handshake timeout raises `TimeoutError` and immediately triggers `close()` to release sockets (`secure_transmit_2027.py:555`).
- Process mitigation failure logs warning and aborts execution if `DESTROYER_STRICT_DEP=1` is asserted (`dep_impl.py:175-185`).

## 7. Configuration and Environment Variables
- `SECURE_P2P_PRODUCTION`: Enforces fail-closed production gates. Default: unset (`0`). When set to `'1'`, software-only fallbacks are blocked (`unified_secure_pipeline.py:70-74`).
- `P2P_KEX_TIMEOUT`: Handshake timeout in seconds. Default: `120` (`secure_p2p.py:15623`).
- `P2P_REQUIRE_HARDWARE`: Enforces hardware HSM/TPM readiness. Default: `0` (`secure_p2p.py:15652`).
- `P2P_STATION`: Node role auto-selector (`"alpha"` or `"bravo"`). Default: unset (`secure_p2p.py:16552`).
- `DESTROYER_STRICT_DEP`: Enforces mandatory exit on DEP/ACG initialization failure. Default: `0` (`dep_impl.py:170`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - Quantized padding roundtrip, corruption detection, multi-quantum scaling: verified in `tests/test_unified_secure_pipeline.py` (25 tests).
  - Anti-replay sliding window, sequence ordering, out-of-order delivery: verified in `tests/test_destroyer_core_production.py` (8 tests).
  - Dual-terminal live IPv6 transport and message exchange: verified in `tests/test_military_bases_two_terminal_live_drill.py` (4 tests).
  - DEP/ASLR/CFG platform policy enforcement: verified in `tests/test_defensive_audit_targets.py` (18 tests).
- NOT Covered:
  - Dynamic hardware failure of physical HSM during in-flight Poisson-paced packet streams.
  - Multi-gigabit kernel packet drops under extreme network congestion.

## 9. Not Implemented / External Dependencies
- Simulated Command Surfaces: Commands `/eam`, `/ptt`, and `/nc3-verify` are test stubs and are disabled fail-closed when running on the production message path (`secure_p2p.py:15738-15743`).
- Physical Hardware Security Modules: Dedicated hardware key custody requires external physical devices (Thales Luna 7.9+ PCIe card, Nitrokey HSM token); development hosts fall back to secure software memory (`hw_readiness.py:140-180`).

## 10. Known Limitations and Residual Risks
- Monolithic Prototype Overlap: `secure_p2p.py` (14,886 lines) contains an embedded chat engine that duplicates logic in `core/orchestrator.py` (1,714 lines).
- Non-Elevated Host Posture: When executed in an unprivileged shell without administrative elevation, Win32 `SetProcessMitigationPolicy` calls return access denied for system-wide ACG mitigations (`hw_readiness.py:150-160`).

## 11. Discrepancies
- Promotional identifiers in source files: `secure_p2p.py:520` declares `class [BANNED-PREFIX]Crypto`, `core/orchestrator.py:180` declares `_add_[BANNED-PREFIX]_grade_padding`, and `destroyer_tactical_p2p.py:51` prints restricted terminal headers. These are flagged in `docs/audit/discrepancies.md`.

## 12. Open Questions for the Author
- Can `secure_p2p.py` be deprecated in favor of `core/orchestrator.py` and `destroyer.py` once all test suites migrate to modular imports?
