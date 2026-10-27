# Module Documentation: Native Rust Data Plane Subsystem (`rust_data_plane`)

## 1. Module Name & Purpose

- **Module Name:** `rust_data_plane`
- **Subsystem Classification:** Native High-Performance Data Plane (`destroyer_core`), Python-Rust FFI, Memory Security, and Wire Framing
- **Files in Module (37 files, 14,317 verified lines):**
  - `rust_backend.py` (153 lines)
  - `rust_data_plane/.gitignore`
  - `rust_data_plane/Cargo.lock`
  - `rust_data_plane/Cargo.toml`
  - `rust_data_plane/pyproject.toml`
  - `rust_data_plane/python/destroyer_core/__init__.py` (47 lines)
  - Rust source files under `rust_data_plane/src/`:
    - `lib.rs` (490 lines)
    - `main.rs` (112 lines)
    - `acd.rs` (420 lines)
    - `aead.rs` (366 lines)
    - `attest.rs` (385 lines)
    - `auth.rs` (390 lines)
    - `chaff.rs` (285 lines)
    - `cookie.rs` (320 lines)
    - `ct.rs` (180 lines)
    - `fec.rs` (428 lines)
    - `ffi.rs` (620 lines)
    - `frame.rs` (340 lines)
    - `group_ratchet.rs` (540 lines)
    - `handshake.rs` (829 lines)
    - `kem.rs` (304 lines)
    - `kex_auth.rs` (350 lines)
    - `keystore.rs` (410 lines)
    - `memlock.rs` (173 lines)
    - `memory_guard.rs` (430 lines)
    - `net.rs` (510 lines)
    - `nostd_microcore.rs` (290 lines)
    - `pacing.rs` (219 lines)
    - `pad.rs` (240 lines)
    - `pki.rs` (480 lines)
    - `policy.rs` (260 lines)
    - `purge.rs` (190 lines)
    - `ratchet.rs` (303 lines)
    - `replay.rs` (290 lines)
    - `session.rs` (650 lines)
    - `tpm_nv.rs` (310 lines)
    - `zero_trust.rs` (450 lines)

- **Primary Technical Purpose:**
  The `rust_data_plane` module provides a native, memory-safe, and constant-time implementation of the transport pipeline in Rust (`destroyer_core`). It executes post-quantum `Noise_XXhfs` handshakes, Double Ratchet state transitions, AEAD frame sealing and unsealing (AES-256-GCM / ChaCha20-Poly1305), RFC 6479 anti-replay sliding window checking, Cauchy Reed-Solomon forward error correction, page-locked memory management (`VirtualLock` / `mlock`), and compiler-barrier zeroization (`zeroize::ZeroizeOnDrop`). It exposes both PyO3 native Python modules and a C FFI interface (`ffi.rs`) consumed by `rust_backend.py`.

---

## 2. Public Interface

### 2.1. `rust_backend.py` (Python Integration Layer)
- **Classes:**
  - `BackendUnavailable(RuntimeError)` (`:22`): Raised when native Rust bindings cannot be loaded and fallback is rejected.
- **Exported Functions:**
  - `available() -> bool` (`:30`): Probes whether `destroyer_core` PyO3 module or native shared library is available.
  - `require_native()` (`:40`): Raises `BackendUnavailable` fail-closed if native engine is missing.
  - `get_native_engine()` (`:60`): Instantiates and returns native `SecureEngine`.
  - `get_native_ratchet()` (`:85`): Returns native `PcsRatchet` instance.
  - `get_native_transport()` (`:95`): Returns native framed socket transport.
  - `get_cookie_gate()` (`:110`): Instantiates native stateless cryptographic cookie gate.
  - `get_acd_engine()` (`:120`): Returns native Autonomous Cyber Defense instance.
  - `get_zero_trust_engine()` (`:130`): Returns native Zero-Trust policy engine.
  - `secure_wipe_buffer(buf: bytearray)` (`:145`): Executes native multi-pass memory wipe.

### 2.2. Native `destroyer_core` Rust Interface
- **`destroyer_core::handshake::Handshake` (`handshake.rs:45`):**
  - `initiator_hello() -> (Vec<u8>, EphemeralKeys)`: Generates Message 1 (`e` P-384 + `ekem` ML-KEM-1024).
  - `responder_reply(msg1: &[u8]) -> Result<(Vec<u8>, HandshakeState), HandshakeError>`: Processes Message 1 and generates Message 2.
  - `initiator_finish(msg2: &[u8]) -> Result<Vec<u8>, HandshakeError>`: Verifies Message 2 and generates Message 3.
  - `split() -> (FrameKey, FrameKey)`: Derives directional send/receive transport frame keys.
- **`destroyer_core::ratchet::PcsRatchet` (`ratchet.rs:35`):**
  - `send_step(plaintext: &[u8], ad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RatchetError>`: Advances send chain and encrypts message.
  - `receive_step(header: &[u8], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError>`: Updates receive chain and decrypts.
- **`destroyer_core::aead::FrameKey` (`aead.rs:50`):**
  - `seal(plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError>`: Encrypts payload with sequence-derived nonce and appends 16B auth tag.
  - `open(ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError>`: Authenticates and decrypts frame; on failure, drops silently without emitting error datagrams.
- **`destroyer_core::memlock::LockedKey32` (`memlock.rs:35`):**
  - `new(secret: [u8; 32]) -> Self`: Locks memory pages in physical RAM and zeroes bytes on drop.
- **`destroyer_core::replay::ReplayWindow` (`replay.rs:25`):**
  - `check_and_update(seq: u64) -> bool`: Evaluates sequence number against 1024-bit RFC 6479 sliding window.

---

## 3. Data Formats & Byte Layouts

### 3.1. `destroyer_core::frame` Wire Envelope Layout
- **Frame Header (22 bytes):**
  - Magic Tag: 4 bytes (`b"DST1"`)
  - Channel Identifier: 8 bytes uint64 big-endian
  - Sequence Counter: 8 bytes uint64 big-endian
  - Payload Length: 2 bytes uint16 big-endian
- **Payload & Authentication:**
  - Encrypted Payload: $L$ bytes ($L \le 65535$)
  - Authentication Tag: 16 bytes (AES-256-GCM / Poly1305)
- **Arithmetic Sum:**
  $$\text{Total Frame Overhead} = 22\text{ (header)} + 16\text{ (tag)} = 38\text{ bytes}$$
  $$\text{Total Sealed Frame Size} = 38 + L\text{ bytes}$$

### 3.2. Cross-Language Handshake Layout Parity
- Message 1: 1617 bytes (compressed P-384 + ML-KEM-1024) or 1665 bytes (uncompressed).
- Message 2: 8868 bytes (compressed) or 8916 bytes (uncompressed).
- Message 3: 7251 bytes.
- Bit-for-bit parity verified between Rust `Handshake` and Python `noise_pq.py`.

### 3.3. RFC 6479 Anti-Replay Sliding Window
- Window Capacity: 1024 sequence numbers.
- Storage Structure: Array of 16 uint64 words ($16 \times 64 = 1024$ bits = 128 bytes).
- Base Sequence Counter: 8 bytes uint64.
- Total Bitmap Memory Footprint: $128 + 8 = 136$ bytes.

---

## 4. Algorithms & Pinned Libraries

1. **Noise Protocol Framework (`Noise_XXhfs`):**
   - Implemented in `destroyer_core::handshake` with SecP384r1 + ML-KEM-1024 + ML-DSA-87.
2. **Symmetric Ciphers:**
   - AES-256-GCM via Rust `aes-gcm` crate (NIST SP 800-38D).
   - ChaCha20-Poly1305 via `chacha20poly1305` crate (RFC 8439).
3. **Post-Quantum Cryptography:**
   - ML-KEM-1024 (FIPS 203) and ML-DSA-87 (FIPS 204) linked against `oqs.dll` (v0.16.0).
4. **Memory Protection & Zeroization:**
   - `zeroize` crate with `ZeroizeOnDrop` trait ensuring compiler optimization passes cannot strip memory sanitization.
   - Operating system page locking via Win32 `VirtualLock` and POSIX `mlock`.

---

## 5. Dependencies

### 5.1. External Rust Crates (Cargo.toml)
- `pyo3`: Python C extension generation.
- `zeroize`: Memory zeroization with compiler barriers.
- `aes-gcm`, `chacha20poly1305`: AEAD primitives.
- `p384`: Pure-Rust NIST P-384 elliptic curve.
- `sha2`, `sha3`, `hkdf`: Cryptographic hash functions.
- `subtle`: Constant-time comparison and conditional selection.

### 5.2. Native Shared Libraries
- `oqs.dll`: Open Quantum Safe native shared library providing post-quantum KEM and signature implementations.

---

## 6. Failure Behavior

1. **Silent-Drop Tamper Resistance:**
   - In `aead.rs:FrameKey::open`, if the message authentication tag fails verification, the function returns an error without sending error packets across the wire. This eliminates error oracles and timing side channels.
2. **Replay Rejection:**
   - In `replay.rs:ReplayWindow`, if a sequence number is older than $base - 1024$ or has already been marked in the bitmap, the frame is rejected immediately.
3. **Autonomous Cyber Defense Isolation:**
   - In `acd.rs`, if an authenticated peer exceeds anomaly thresholds (e.g., repeated replay attempts or malformed frames), the peer is transitioned to quarantined status, dropping all subsequent packets from that peer ID.

---

## 7. Configuration / Environment Variables

| Variable Name | Defined In File | Default Value | Technical Purpose & Impact |
|:---|:---|:---|:---|
| `P2P_DATA_PLANE` | System environment / `p2p_core.py` | `"python"` | Selects data plane backend: `"rust"` (activates `destroyer_core`) or `"python"`. |
| `P2P_MAX_TRAFFIC_QUEUE_SIZE` | `network_adversary_resistance.py` | `1024` | Queue ceiling for native packet scheduling buffers. |

---

## 8. Tests Covered & Not Covered

### 8.1. Tests Covered (Directly Executed and Verified)
- `tests/test_rust_core_security_suite.py` (9 passed in 0.4s):
  - Validates ACD engine replay quarantine, tamper immediate isolation, cookie gate PoW challenge solving, memory guard multi-pass wipe, and Zero-Trust RBAC dynamic scoring.
- `tests/test_rust_interop.py` (6 passed in 0.5s):
  - Validates constant matching, Python-initiator/Rust-responder handshake, Rust-initiator/Python-responder handshake, bidirectional cross-decryption, and threshold multi-signature verification.
- `tests/test_destroyer_core_production.py` (11 passed in 0.3s):
  - Validates native import, session domain separation, quantized padding, WireGuard anti-replay window, tamper silent-drop, and Poisson pacing lifecycle.
- `tests/test_rust_python_handshake_interop.py` (4 passed in 0.1s):
  - Validates exact framing constant alignment, record layer directional nonces parity, RFC 6479 1024-bit window parity, and native selftest execution.

### 8.2. Not Covered / Zero Direct Tests
- `rust_data_plane/src/nostd_microcore.rs`: Microkernel no-std baremetal compatibility code is not compiled in standard user-mode test suites.

---

## 9. Not Implemented / Stubs

1. **Standalone `no_std` Microkernel Build:**
   - `nostd_microcore.rs` provides architecture skeletons for running `destroyer_core` in embedded or microkernel environments without the Rust standard library; standard production builds link against `std`.
2. **Windows Platform Crypto Provider in Rust:**
   - Direct integration with Windows CNG TPM KSP is handled in Python (`cng_platform.py`); `destroyer_core` handles TPM non-volatile memory via `tpm_nv.rs` and PKCS#11.

---

## 10. Known Limitations

1. **Host Compilation Dependencies:**
   - Building `destroyer_core` from source requires a working Cargo toolchain and C compiler. If the precompiled shared library is missing and no compiler is installed, the system falls back to Python.
2. **FFI Marshaling Overhead:**
   - When using `rust_backend.py` via Python `ctypes`, crossing the language boundary introduces small memory copying overhead per frame compared to pure native Rust execution.

---

## 11. Discrepancies

1. **Promotional Banners in File Headers:**
   - `rust_data_plane/src/lib.rs:1-15` and `handshake.rs:1-10` contain uppercase operational classifications and non-technical adjectives (cataloged in `docs/audit/discrepancies.md`).
2. **Class Naming Parity:**
   - The native double ratchet implementation is named `PcsRatchet` in Rust (`ratchet.rs`) and `DoubleRatchet` in Python (`double_ratchet.py`), though both implement identical post-compromise security state transitions.

---

## 12. Open Questions

1. **Long-Term Data Plane Migration:**
   - Is `destroyer_core` planned to completely supersede Python socket I/O in future releases, relegating Python strictly to orchestration?
2. **Cross-Compilation Infrastructure:**
   - What automated CI pipelines exist to cross-compile and sign `destroyer_core` binaries for diverse target architectures (x86_64, aarch64, Windows, Linux)?