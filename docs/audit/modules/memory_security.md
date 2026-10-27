# Module Audit: memory_security

## 1. Overview and Scope
The `memory_security` module encompasses the host memory protection, process-level defense, hardware-backed key storage, physical and OS entropy collection, and sanitization routines across the system. It forms the foundational Layer 1 execution environment for all cryptographic keys, nonces, and session states.

The module comprises 9 product files totaling 10,357 verified lines of Python code:

| File Name | Lines | Verified Purpose | Primary Classes / Functions |
| :--- | :--- | :--- | :--- |
| `enhanced_secure_memory.py` | 1,102 | Page-locked memory allocator with key lifetime caps and constant-time comparison | `LockedMemoryAllocator`, `LockedMemoryRegion`, `KeyLifetimeEnforcer`, `ConstantTimeMemoryComparison` |
| `entropy_manager.py` | 1,126 | Multi-source physical/OS entropy aggregator with SP 800-90B health screening | `EntropyManager`, `NoiseHealthScreen`, `SystemCSPRNGSource`, `HardwareRNGSource`, `QRNGSource` |
| `memory_manager.py` | 1,699 | Primary memory protection engine with page locking, guard pages, and multi-pass wiping | `SecureMemoryManager`, `SecureBuffer`, `GuardPageManager`, `MemoryIntegrityChecker`, `StackCanary` |
| `memory_protection_engine.py` | 1,072 | Memory corruption detector enforcing canaries, guard pages, and Control Flow Integrity | `MemoryProtectionEngine`, `CanaryProtectedBuffer`, `GuardProtectedRegion`, `CFITarget` |
| `native_secure_buffer.py` | 388 | Pinned mutable bytearray buffer with DPAPI in-RAM encryption and native zeroization | `NativeSecureBuffer`, `wipe_native`, `_try_crypt_protect`, `_try_crypt_unprotect`, `_try_mlock` |
| `quantum_rng.py` | 767 | Secondary entropy manager and hardware interface with continuous min-entropy checks | `EntropyPool`, `EntropyManager`, `QRNGInterface`, `HSMEntropyInterface`, `EntropyHealthMonitor` |
| `secure_enclave_key_storage.py` | 2,080 | Multi-backend hardware key storage interface (TPM 2.0, Secure Enclave, PKCS#11 HSM, AES-GCM) | `SecureEnclaveKeyStorage`, `WindowsTPMBackend`, `PKCS11HSMBackend`, `SoftwareFallbackBackend` |
| `secure_memory_wiper.py` | 610 | Standard multi-pass memory wiper and file shredder with read-back verification | `SecureMemoryWiper`, `WipePattern`, `WipeResult`, `secure_wipe_dod`, `secure_shred_file` |
| `side_channel_resistance.py` | 1,513 | Constant-time execution primitives and statistical timing anomaly monitoring | `ConstantTimeOperations`, `ConstantTimeCryptoWrapper`, `TimingAnalyzer`, `RuntimeTimingMonitor` |

---

## 2. Architecture and Subsystem Mechanics

### 2.1 Memory Locking and Paging Prevention
The subsystem prevents sensitive cryptographic material from leaking to disk swap or pagefiles through native operating-system locking:
- **Windows Implementation:** Calls `kernel32.VirtualLock(buffer_ptr, size)` with `VirtualUnlock` on teardown (`enhanced_secure_memory.py:137-142`, `memory_manager.py:720`, `native_secure_buffer.py:183-186`, `secure_memory_wiper.py:133-138`).
- **POSIX/Linux Implementation:** Calls standard C library `_libc.mlock(buffer_ptr, size)` and `_libc.munlock(buffer_ptr, size)` (`enhanced_secure_memory.py:124-129`, `memory_manager.py:727`, `native_secure_buffer.py:188-191`, `secure_memory_wiper.py:117-122`).
- **Gating Behavior:** By default, if the executing OS user account lacks memory-locking privileges (e.g. `SeLockMemoryPrivilege` on Windows), allocation logs a warning and proceeds without page locking (`memory_manager.py:725,732`). If strict deployment flags `P2P_REQUIRE_MLOCK=1` or `P2P_REQUIRE_PINNED_KEYS=1` are set, failure to lock raises a fail-closed `MemoryError` (`memory_manager.py:744-747`).

### 2.2 In-RAM Encryption via Windows DPAPI
In `native_secure_buffer.py:58-88`, mutable buffers can be encrypted in place while resting in RAM:
- Calls `ctypes.windll.crypt32.CryptProtectMemory` using flag `CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00`.
- Requires input buffers to be exact multiples of `CRYPTPROTECTMEMORY_BLOCK_SIZE = 16` bytes.
- Unprotects on access via `CryptUnprotectMemory` and re-encrypts upon exiting protected scopes.

### 2.3 Memory Sanitization and Multi-Pass Zeroization
The module provides tiered zeroization across multiple levels of abstraction:
1. **Native OS / Foreign-Function Zeroization:**
   - On Windows: `ctypes.windll.kernel32.RtlSecureZeroMemory` (`enhanced_secure_memory.py:409`).
   - On Linux: `libc.explicit_bzero` or `libc.memset_s` (`enhanced_secure_memory.py:417-420`).
   - Via libsodium: `sodium_memzero` (`native_secure_buffer.py:90-109`).
   - Via foreign C runtime: `ctypes.memset` via `msvcrt` or `libc` (`native_secure_buffer.py:112-128`), ensuring foreign function calls cannot be eliminated by Python optimizer passes.
2. **Multi-Pass Patterns:**
   - Adheres to DoD 5220.22-M 3-pass sanitization: Pass 1 writes `0x00`, Pass 2 writes `0xFF`, Pass 3 writes cryptographically random bytes (`secrets.randbits(8)` or `secrets.token_bytes`), followed by a final `0x00` pass (`memory_manager.py:796-814`, `secure_memory_wiper.py:84-88,237-250`).
   - Read-back verification scans the buffer; any non-zero byte triggers `WipeVerificationError` (`secure_memory_wiper.py:255-256`, `native_secure_buffer.py:154-160`).
3. **CPython Immutable Memory Boundary:**
   - `secure_memory_wiper.py:186-200` explicitly rejects immutable Python `bytes` objects, returning `WipeResult(success=False, error_message="immutable bytes cannot be wiped in place; pass bytearray/memoryview")`.
   - `native_secure_buffer.py:245-248` documents that copying from an immutable `bytes` source leaves the original buffer in interpreter memory pools.

### 2.4 Tamper Detection, Guard Pages, and Fail-Closed Termination
- **Canary Buffers:** `memory_protection_engine.py:160` generates 32-byte (256-bit) cryptographically random canaries placed immediately before and after protected buffers. An HMAC-SHA256 integrity hash is checked on access (`memory_protection_engine.py:470-520`).
- **Guard Pages:** `GuardPageManager` sets `PAGE_GUARD | PAGE_READWRITE` on memory pages immediately preceding and following the allocated buffer via Windows `VirtualProtect` (`memory_manager.py:481-500`) or POSIX `mprotect` (`memory_protection_engine.py:259`).
- **Control Flow Integrity (CFI):** `memory_protection_engine.py:650-730` maintains registered function target descriptors (`CFITarget`), validating expected code entry points and signature hashes before dispatch.
- **Fail-Closed Termination:** When canary corruption, guard page violations, heap integrity failures, or CFI deviations occur, `MemoryProtectionEngine.secure_wipe_and_terminate()` executes DoD overwrites across all active buffers and immediately calls `os._exit(1)` (`memory_protection_engine.py:736-777`).

### 2.5 Key Lifetime Enforcement
- `enhanced_secure_memory.py:462-560` (`KeyLifetimeEnforcer`):
  - Limits in-memory key lifetime to a hard ceiling of 900.0 seconds (15 minutes).
  - Operates a daemon background thread (`_cleanup_loop`) running every 10 seconds (`check_interval_seconds = 10.0`) that automatically executes `_secure_wipe` on expired regions.

### 2.6 Multi-Source Entropy and SP 800-90B Health Screening
- **Entropy Ingest:** `entropy_manager.py:257-350` ingests from:
  1. `SystemCSPRNGSource`: `secrets.token_bytes(num_bytes)`.
  2. `HardwareRNGSource`: Verifies x86/x64 architecture and delegates to `secrets.token_bytes`.
  3. `QRNGSource`: Probes hardware devices `/dev/qrng0`, `/dev/quantis`, `/dev/comscire`, or USB vendor `0x0403:0x6001`.
  4. `TimingEntropySource`: Extracts timing jitter from high-resolution CPU counters.
- **Continuous Health Screen:** `entropy_manager.py:78-140` implements a continuous `NoiseHealthScreen` prior to cryptographic conditioning:
  - Repetition Count Test (RCT per NIST SP 800-90B §4.4.1): Intermittent cutoff $C_i = 31$, permanent cutoff $C_p = 61$.
  - Adaptive Proportion Test (APT per NIST SP 800-90B §4.4.2): Window $W = 512$, intermittent cutoff $C_i = 325$, permanent cutoff $C_p = 355$.
  - Three consecutive intermittent failures escalate to permanent failure, raising `EntropyHealthError`.
- **Conditioning & Pooling:** Ingested bits are conditioned through SHA3-512 into a 512-byte pool (`POOL_SIZE_BYTES = 512`). If estimated entropy falls below 512 bits (`CRITICAL_THRESHOLD_BITS = 512`), cryptographic operations block or raise `EntropyDepletionError` (`entropy_manager.py:450,474`).
- **Dual Implementation Note:** `quantum_rng.py:91-140` independently defines a secondary 128-byte (1024-bit) entropy pool conditioned with SHA3-512, tracking min-entropy per byte with a 7.0-bit/byte threshold.

### 2.7 Hardware Storage Backends and Enclave Abstraction
`secure_enclave_key_storage.py` provides an abstraction across five storage backends:
1. `WINDOWS_TPM`: Windows CNG / NCrypt Key Storage Provider (`secure_enclave_key_storage.py:62,180-240`).
2. `LINUX_TPM`: Linux TPM 2.0 via `tpm2-pytss` or direct resource manager `/dev/tpmrm0` (`secure_enclave_key_storage.py:63,241-320`).
3. `SECURE_ENCLAVE`: Apple Secure Enclave via `Security.framework` (`secure_enclave_key_storage.py:60,321-410`).
4. `PKCS11_HSM`: Hardware Security Modules via PKCS#11 dynamic libraries (`softhsm2.dll`, `libsofthsm2.so`, `opensc-pkcs11.dll`) (`secure_enclave_key_storage.py:64,781-830`).
   - Restricts on-token officer approval signatures strictly to mechanism allowlist `("ECDSA", "SHA384_RSA_PKCS")` (`secure_enclave_key_storage.py:711`).
   - Exports SubjectPublicKeyInfo (SPKI) only for SECP384R1 (P-384) EC keys and RSA keys >= 3072 bits (`secure_enclave_key_storage.py:741-775`).
5. `SOFTWARE_FALLBACK`: When hardware backends are unpopulated, falls back to AES-256-GCM encrypted key storage on disk (`secure_enclave_key_storage.py:65,1033-1075`).
   - Holds master Key Encryption Key (KEK) as a mutable `bytearray` and zeroizes it on teardown via `wipe_master_key()` (`secure_enclave_key_storage.py:1077-1100`).
   - Fail-closed configuration: Setting `fail_on_software_fallback=True` blocks software fallback, raising `HardwareUnavailableError("Production security violation: Fallback not permitted")` (`secure_enclave_key_storage.py:1700`).

### 2.8 Constant-Time Operations and Side-Channel Mitigation
- **Branchless Primitives:** `side_channel_resistance.py:309-440` implements branchless algorithms using bitwise masks:
  - `constant_time_is_zero(value)`: `((value | -value) >> 63) & 1 == 0`.
  - `constant_time_bytes_is_zero(data)`: Bitwise OR accumulation across all bytes.
  - `constant_time_copy(dest, src, condition)`: Bitwise selection without conditional branches.
  - `constant_time_lookup(table, index)`: Full-table linear scan applying bitwise mask to all entries.
  - `constant_time_verify_padding(data, block_size)`: Constant-time PKCS#7 validation inspecting every potential padding byte.
- **Timing Variance Verification:** `side_channel_resistance.py:92-140` (`TimingAnalyzer`) records execution durations using `time.perf_counter_ns`, computing mean ($\mu$) and standard deviation ($\sigma$). If the coefficient of variation $CV = \sigma / \mu \ge 0.05$, a `TimingAnomalyType.COEFFICIENT_OF_VARIATION_EXCEEDED` alert is logged.

---

## 3. Environment Variables and Configuration

| Variable | Default | Purpose / Effect |
| :--- | :--- | :--- |
| `P2P_REQUIRE_MLOCK` | `0` | When `1` or `true`, memory buffer allocation raises `MemoryError` if OS page locking fails (`memory_manager.py:741-747`). |
| `P2P_REQUIRE_PINNED_KEYS` | `0` | When `1` or `true`, enforces strict page locking on cryptographic buffers (`memory_manager.py:742`, `native_secure_buffer.py:25`). |
| `P2P_FAIL_ON_SOFTWARE_FALLBACK` | `0` | When enabled, refuses software AES-GCM keystore and requires genuine TPM/HSM hardware (`secure_enclave_key_storage.py:1700`). |
| `P2P_ALLOW_SOFTWARE_FALLBACK` | unset | Permits fallback to software encrypted keystore when hardware security modules are absent. |
| `P2P_ALLOW_TPM_NATIVE` | unset | Enables native TPM 2.0 driver integration on Windows/Linux platforms. |
| `P2P_ENCLAVE_PASSPHRASE` | unset | Operator passphrase used to derive software enclave master KEK via HKDF. |
| `P2P_STORAGE_MASTER_KEY` | unset | Explicit 256-bit hexadecimal master key for software key storage. |
| `P2P_NO_PERSISTENT_SEEDS` | `0` | When `1`, prohibits persisting software KEK seeds to disk (`test_defensive_nc3_audit.py:P0.5`). |

---

## 4. Test Evidence and Verification

### 4.1 Passing Test Suites
Audit verification executed the following test suites covering the memory security module:

1. **Memory Hardening & Buffer Suites:**
   - Command: `pytest tests/test_security_hardening_and_memory.py tests/test_production_tier4_device_memory_audit.py tests/test_ratchet_native_buffer.py tests/test_layer1_hardening.py tests/test_production_tier7_csprng_complete_audit.py -q`
   - Result: 37 passed, 1 skipped in 1.40s.
   - Verified behaviors: `NativeSecureBuffer` pinning and wiping, `SecureMemoryManager` page locking, stack canaries, DoD multi-pass sanitization, CSPRNG output quality.
2. **Defensive and Audit Remediation Suites:**
   - Command: `pytest tests/test_phase3_security_bounds.py tests/test_defensive_nc3_audit.py tests/test_security_audit_remediations.py tests/test_systematic_security_tiers.py -q`
   - Result: 79 passed, 1 warning in 19.04s.
   - Verified behaviors: Software fallback rejection under strict zero-trust mode, keystore AES-256-GCM encryption at rest, memory wiping on teardown, SP 800-90B bounds testing.

### 4.2 Gaps and Unverified Paths
- `enhanced_secure_memory.py` and `memory_protection_engine.py` have zero dedicated unit test files referencing their public APIs directly (`scratch/find_memory_tests.py` confirmed 0 direct test imports).
- `HardwareRNGSource` in `entropy_manager.py:270-292` does not execute native CPU instructions (`rdrand`/`rdseed`); it delegates to `secrets.token_bytes(num_bytes)`.
- QRNG hardware paths (`/dev/qrng0`, `/dev/quantis`, `/dev/comscire`, USB device `0x0403:0x6001`) are unverified in automated CI because physical quantum devices are absent in test environments.

---

## 5. Discrepancies and Code-Level Deficiencies

1. **Immutable Python Bytes Sanitization Limitation:**
   - As documented in `native_secure_buffer.py:6-10` and enforced in `secure_memory_wiper.py:186-200`, CPython immutable `bytes` objects cannot be wiped in place. Calling wipe routines on `bytes` instances returns failure or requires copying to a mutable `bytearray`, leaving the original buffer in interpreter memory until collected.
2. **Dual Entropy Pool Implementations:**
   - Two separate entropy pooling implementations coexist: `entropy_manager.py` (512-byte pool, SP 800-90B RCT/APT health testing) and `quantum_rng.py` (128-byte pool, Shannon entropy estimation). They operate independently without shared state.
3. **Promotional Exception Messages in Production Source Code:**
   - `enhanced_secure_memory.py:196`: `raise MemoryLockError("[PROMOTIONAL-UPPERCASE-PREFIX] FATAL: Failed to VirtualLock memory for cryptographic material. Swapping possible.")`
   - `enhanced_secure_memory.py:412`: `raise MemoryWipeError("[PROMOTIONAL-UPPERCASE-PREFIX] FATAL: Real C-extension memory wipe required. RtlSecureZeroMemory failed.")`
   - These strings violate repository naming standards by embedding promotional uppercase prefixes in runtime exceptions. Cataloged for `docs/audit/discrepancies.md`.