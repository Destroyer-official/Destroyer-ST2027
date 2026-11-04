# Module Documentation: memory_security

## 1. Purpose
The `memory_security` module provides page-locked heap allocation, in-RAM DPAPI encryption, stack canaries, guard page isolation, multi-pass memory zeroization, and SP 800-90B entropy health validation (`enhanced_secure_memory.py:1-1102`, `memory_manager.py:1-1699`, `entropy_manager.py:1-1126`). It isolates cryptographic secrets in memory and prevents sensitive key material from leaking to disk swap, crash logs, or unprivileged memory spaces (`secure_memory_wiper.py:1-610`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `enhanced_secure_memory.LockedMemoryAllocator` (`enhanced_secure_memory.py:65-210`)
- `allocate(size: int) -> LockedMemoryRegion`: Allocates a locked memory region (`enhanced_secure_memory.py:75-120`). Calls `kernel32.VirtualLock` on Windows (`:137`) or `libc.mlock` on POSIX (`:124`). Returns `LockedMemoryRegion` wrapping a mutable `bytearray`. Raises `MemoryError` if size exceeds available memory.
- `free(region: LockedMemoryRegion) -> None`: Wipes buffer with multi-pass zeroization and unlocks page via `VirtualUnlock` or `munlock` (`enhanced_secure_memory.py:145-180`).

#### `native_secure_buffer.NativeSecureBuffer` (`native_secure_buffer.py:45-210`)
- `__init__(size: int, pin: bool = True)`: Allocates pinned buffer (`native_secure_buffer.py:50-75`). Parameter `size` must be a positive integer; rounds up to multiple of 16 if Windows DPAPI encryption is used (`:60`).
- `protect() -> bool`: Encrypts buffer in place using `CryptProtectMemory` with `CRYPTPROTECTMEMORY_SAME_PROCESS` (`native_secure_buffer.py:80-105`). Returns `True` on success.
- `unprotect() -> bool`: Decrypts buffer in place using `CryptUnprotectMemory` (`native_secure_buffer.py:110-135`). Returns `True` on success.
- `wipe() -> None`: Invokes native C `memset` or libsodium `sodium_memzero` across buffer (`native_secure_buffer.py:140-165`).

#### `secure_memory_wiper.SecureMemoryWiper` (`secure_memory_wiper.py:55-290`)
- `wipe(target: Any, pattern: WipePattern = WipePattern.DOD_5220_22_M) -> WipeResult`: Executes multi-pass overwrites on mutable buffer (`secure_memory_wiper.py:80-160`). Rejects immutable Python `bytes` objects, returning `WipeResult(success=False)` (`:186-200`). Returns `WipeResult(success=True, passes_completed=N)`.
- `secure_shred_file(filepath: str, passes: int = 3) -> bool`: Overwrites file contents on disk with random bytes before unlinking (`secure_memory_wiper.py:220-270`). Raises `FileNotFoundError` if path does not exist.

#### `memory_protection_engine.MemoryProtectionEngine` (`memory_protection_engine.py:85-320`)
- `create_guarded_buffer(size: int) -> GuardProtectedRegion`: Allocates buffer flanked by guard pages (`PAGE_GUARD | PAGE_READWRITE`) and 32-byte canaries (`memory_protection_engine.py:110-180`).
- `verify_canaries(region: GuardProtectedRegion) -> bool`: Validates HMAC-SHA256 integrity tag over buffer canaries (`memory_protection_engine.py:210-250`).
- `secure_wipe_and_terminate(reason: str) -> None`: Wipes all registered buffers and immediately terminates host process via `os._exit(1)` upon tamper detection (`memory_protection_engine.py:736-777`).

#### `entropy_manager.EntropyManager` (`entropy_manager.py:257-410`)
- `get_entropy(num_bytes: int) -> bytes`: Ingests entropy across available CSPRNG, CPU, and QRNG sources (`entropy_manager.py:270-330`). Applies continuous SP 800-90B health checks. Raises `EntropyHealthError` on health test failure (`:315`). Returns `num_bytes` conditioned entropy.

## 3. Data Formats and Byte Layouts

### 3.1 Guarded Canary Memory Layout (`memory_protection_engine.py:160-220`)
- Layout of guarded memory allocation:
  - Leading Guard Page: 4,096 bytes marked `PAGE_GUARD` (`:170`).
  - Leading Canary: 32 bytes cryptographically random bytes (`:175`).
  - Protected Data Payload: $N$ bytes (allocated buffer) (`:180`).
  - Trailing Canary: 32 bytes cryptographically random bytes (`:185`).
  - Trailing Guard Page: 4,096 bytes marked `PAGE_GUARD` (`:190`).
- Arithmetic Verification:
  - Canary size: Exactly $32 + 32 = 64$ bytes.
  - Guard page size: Exactly $4096 + 4096 = 8192$ bytes.
  - Total allocated span: $8192 + 64 + N = 8256 + N$ bytes. Sum matches code arithmetic.

### 3.2 DoD 5220.22-M Zeroization Pass Layout (`secure_memory_wiper.py:84-88, 237-250`)
- Pass 1: Fixed character `0x00` across all $N$ bytes (`:238`).
- Pass 2: Inverted character `0xFF` across all $N$ bytes (`:242`).
- Pass 3: CSPRNG pseudorandom bytes generated via `secrets.token_bytes(N)` (`:246`).
- Read-back verification: Validates that buffer memory matches target state after final wipe pass (`:255`).

## 4. Algorithms and Pinned Libraries
- DoD 5220.22-M: 3-pass memory sanitization standard. Implemented via ctypes calls to `kernel32.RtlSecureZeroMemory` or `libc.explicit_bzero` (`enhanced_secure_memory.py:409-420`).
- Windows DPAPI Memory Protection: `CryptProtectMemory` and `CryptUnprotectMemory` via `ctypes.windll.crypt32` (`native_secure_buffer.py:58-88`).
- NIST SP 800-90B: Health testing for entropy sources. Implemented in `NoiseHealthScreen`:
  - Repetition Count Test (RCT §4.4.1): Cutoff $C_i = 31$, $C_p = 61$ (`entropy_manager.py:85`).
  - Adaptive Proportion Test (APT §4.4.2): Window $W = 512$, Cutoff $C_i = 325$, $C_p = 355$ (`entropy_manager.py:92`).
- HMAC-SHA256: Canary integrity tagging via standard library `hmac` and `hashlib.sha256` (`memory_protection_engine.py:475`).

## 5. Dependencies and Hardware Requirements
- Native Operating System APIs:
  - Windows: `kernel32.dll` (`VirtualLock`, `VirtualUnlock`, `VirtualProtect`, `RtlSecureZeroMemory`), `crypt32.dll` (`CryptProtectMemory`).
  - POSIX / Linux: Standard C runtime `libc` (`mlock`, `munlock`, `mprotect`, `explicit_bzero`).
  - Native libsodium: `sodium_memzero` via `libsodium.dll` (`native_secure_buffer.py:90`).
- Hardware entropy: CPU machine instructions `RDRAND`/`RDSEED` on x86_64 (`entropy_manager.py:270`).

## 6. Failure Behavior
- Memory allocation failure raises standard `MemoryError` (`enhanced_secure_memory.py:115`).
- Read-back zeroization mismatch raises `WipeVerificationError` (`secure_memory_wiper.py:255`).
- Guard page touch triggers OS access violation exception (`STATUS_GUARD_PAGE_VIOLATION` on Windows, `SIGSEGV` on Linux) caught by crash supervisors (`memory_manager.py:495`).
- Canary modification or CFI integrity deviation triggers immediate `secure_wipe_and_terminate()` calling `os._exit(1)` (`memory_protection_engine.py:777`).
- Entropy health failure (RCT or APT permanent cutoff exceeded) raises `EntropyHealthError` (`entropy_manager.py:135`).

## 7. Configuration and Environment Variables
- `P2P_REQUIRE_MLOCK`: Enforces mandatory page locking. Default: unset (`0`). When set to `'1'`, inability to lock pages raises `MemoryError` (`memory_manager.py:744`).
- `P2P_REQUIRE_PINNED_KEYS`: Requires all secret keys to reside in locked memory. Default: unset (`0`) (`memory_manager.py:746`).
- `P2P_ENABLE_TEMP_MONITOR`: Opt-in toggle to activate hardware temperature monitoring. Default: `0` (`secure_key_manager.py:122`).
- `P2P_MAX_KEY_LIFETIME_SEC`: Hard ceiling for in-memory key retention before automated wiping. Default: `900` (15 minutes) (`enhanced_secure_memory.py:470`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - DoD 5220.22-M 3-pass zeroization and read-back verification: verified in `tests/test_audit_p1_remediations_phase2.py` (`test_secure_memory_wiping_dod`).
  - In-RAM DPAPI CryptProtectMemory roundtrip: verified in `tests/test_audit_p1_remediations_phase2.py` (`test_native_secure_buffer_dpapi`).
  - SP 800-90B RCT and APT health tests: verified in `tests/test_audit_p1_remediations_phase2.py` (`test_entropy_health_screening`).
  - Canary corruption detection: verified in `tests/test_defensive_audit_targets.py` (8 tests).
- NOT Covered:
  - Physical cold-boot attacks against DRAM modules after host system power-off.
  - Hardware DMA probing when IOMMU Kernel DMA protection is disabled in UEFI firmware.

## 9. Not Implemented / External Dependencies
- External QRNG Devices: Hardware quantum random number generators (`/dev/qrng0`, USB Quantis) require physical attached peripherals; if absent, the system falls back to CPU RDRAND and OS CSPRNG (`entropy_manager.py:320-350`).
- Immutable Python Objects: Standard Python `bytes` objects cannot be modified in place; callers must allocate `bytearray` or `NativeSecureBuffer` (`secure_memory_wiper.py:190`).

## 10. Known Limitations and Residual Risks
- CPython Interpreter Pools: When string or bytes conversions occur in Python code, temporary intermediate buffers remain in interpreter memory until collected by garbage collection.
- Privilege Requirements: `VirtualLock` on Windows requires sufficient working set quota; unprivileged processes may fail to lock large allocations without `SeLockMemoryPrivilege`.

## 11. Discrepancies
- Promotional identifiers in test files and helper methods: `core/orchestrator.py:180` contains references to prohibited terms cataloged in `docs/audit/discrepancies.md`.

## 12. Open Questions for the Author
- Should `enhanced_secure_memory.py` enforce `NativeSecureBuffer` exclusively for all session key objects to prevent Python interpreter memory retention?
