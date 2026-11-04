# Module Documentation: utilities_support

## 1. Purpose
The `utilities_support` module provides shared utility routines, configuration managers, structured error supervisors, memory cleanup handlers, message size caps, and project environment manifests (`config.py:1-760`, `utils/memory.py:1-404`, `utils/message_caps.py:1-146`). It enforces sticky production configuration latches, sanitizes exception traces to prevent secret leakage, and zeroes temporary buffers upon context exit (`utils/cleanup.py:1-244`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `config.Config` (`config.py:65-310`)
- `load_config(path: Optional[str] = None) -> dict`: Loads, parses, and validates JSON configuration (`config.py:85-140`). Verifies digital signature if `path.sig` exists. Latches `is_production()` if configuration enables production settings (`:120`).
- `get(key: str, default: Any = None) -> Any`: Retrieves configuration parameter with type coercion and default fallback (`config.py:150-185`).
- `is_production() -> bool`: Returns boolean state of sticky production latch (`config.py:210-225`). Once set to `True`, cannot be reverted to `False` at runtime.

#### `utils.memory.KeyEraser` (`utils/memory.py:45-160`)
- `__enter__()`: Enters protected context managing mutable key buffers (`utils/memory.py:55-80`).
- `__exit__(exc_type, exc_val, exc_tb)`: Executes DoD 3-pass zeroization over all registered key buffers and releases memory locks (`utils/memory.py:85-120`).
- `pin_buffer(buf: bytearray) -> bool`: Invokes `VirtualLock` on Windows or `mlock` on Linux to prevent paging (`utils/memory.py:130-155`).

#### `utils.message_caps.MessageCaps` (`utils/message_caps.py:25-95`)
- `assert_within_limits(payload_len: int, phase: str = "pre_auth") -> None`: Validates message byte count against layered Denial-of-Service ceilings (`utils/message_caps.py:35-70`). CEILINGS: `PRE_AUTH = 65536` (64 KB), `POST_AUTH = 524288` (512 KB), `WIRE_FRAME = 4194304` (4 MB) (`:28-32`). Raises `MessageSizeExceededError` if limit is exceeded (`:65`).

#### `utils.cleanup.CleanupManager` (`utils/cleanup.py:40-180`)
- `register_resource(resource: Any, cleanup_fn: Callable) -> None`: Registers active socket, file descriptor, or buffer for teardown (`utils/cleanup.py:55-85`).
- `execute_cleanup() -> int`: Iterates registered resources in reverse LIFO order, invoking cleanup handlers and catching exceptions (`utils/cleanup.py:90-145`). Returns count of successfully released resources.

## 3. Data Formats and Byte Layouts

### 3.1 Layered Message Size Boundaries (`utils/message_caps.py:28-32`)
- Explicit byte ceilings enforced across transport boundaries:
  - Pre-Authentication Payload: Exactly 65,536 bytes ($64 \text{ KB} = 64 \times 1024$).
  - Post-Authentication Message: Exactly 524,288 bytes ($512 \text{ KB} = 512 \times 1024$).
  - Wire Frame Maximum: Exactly 4,194,304 bytes ($4 \text{ MB} = 4 \times 1024 \times 1024$).
- Arithmetic Verification:
  - $64 \times 1024 = 65,536$ bytes.
  - $512 \times 1024 = 524,288$ bytes.
  - $4 \times 1024 \times 1024 = 4,194,304$ bytes. Arithmetic matches code constants.

### 3.2 Configuration JSON Schema (`config_production.json`)
- Mandatory keys:
  - `"crypto"`: Object defining KEM (`"ML-KEM-1024"`), signature (`"ML-DSA-87"`), AEAD (`"AES-256-GCM"`), KDF (`"HKDF-SHA384"`).
  - `"network"`: Object defining bind ports, pacing intervals (`20`), and quantum (`1232`).
  - `"security"`: Object defining sticky production flag (`true`), hardware strictness (`true`), and audit logging (`true`).

## 4. Algorithms and Pinned Libraries
- ML-DSA-87: NIST FIPS 204. Configuration profile signature verification provided by `oqs.dll` version 0.16.0 (`config.py:45`).
- DoD 5220.22-M: Sanitization routine for temporary memory allocations (`utils/memory.py:95`).
- SHA-256 / SHA-384: NIST FIPS 180-4. Configuration file checksums provided by standard library `hashlib` (`config.py:30`).

## 5. Dependencies and Hardware Requirements
- Native Operating System APIs: Win32 `VirtualLock`/`VirtualUnlock` (`kernel32.dll`) or POSIX `mlock`/`munlock` (`libc`) (`utils/memory.py:135`).
- File permissions: Local configuration and secret files must adhere to 0600 mode permissions (`config.py:75`).

## 6. Failure Behavior
- Message length exceeding cap raises `utils.message_caps.MessageSizeExceededError` (`utils/message_caps.py:65`).
- Corrupted or unverified configuration signature raises `config.ConfigurationSecurityError` (`config.py:135`).
- Unhandled exceptions passing through `utils.error_handler` sanitize traceback strings, stripping secrets matching regex patterns before logging (`utils/error_handler.py:85-120`).

## 7. Configuration and Environment Variables
- `P2P_CONFIG_FILE`: Explicit path to JSON configuration profile. Default: `"config.json"` (`config.py:40`).
- `P2P_STRICT_CONFIG`: Requires signed configuration manifests; rejects unsigned JSON. Default: `0` (`config.py:42`).
- `P2P_MAX_FRAME_BYTES`: Override for maximum wire frame ceiling. Default: `4194304` (4 MB) (`utils/message_caps.py:32`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - Layered message size boundary enforcement: verified in `tests/test_defensive_nc3_audit.py` (`test_preauth_frame_ceiling_rejects_oversized_frame`).
  - `KeyEraser` context manager zeroization: verified in `tests/test_audit_p1_remediations_phase2.py` (`test_key_eraser_wiping`).
  - Configuration loading, schema validation, and signature verification: verified in `tests/test_security_diagnostics.py` (4 tests).
- NOT Covered:
  - Memory leak detection under 100,000 continuous configuration re-loads.

## 9. Not Implemented / External Dependencies
- Dynamic Remote Configuration Distribution: Configuration updates must be provisioned locally or pushed via signed files; remote configuration daemon is not implemented.

## 10. Known Limitations and Residual Risks
- Process Environment Inheritance: Child processes spawned by the Python runtime inherit environment variables unless explicitly filtered by caller.

## 11. Discrepancies
- Inconsistent error hierarchies: `utils/error_handler.py` maintains an error taxonomy that partially overlaps with `cryptographic_errors.py`; cataloged in `docs/audit/discrepancies.md`.

## 12. Open Questions for the Author
- Should `utils/message_caps.py` enforce separate caps for IPv4 versus IPv6 datagram fragments?
