# Module Claims Register: utilities_support

Claims verification register for utility and support components (`utilities_support`).

| Claim ID | Claimed Capability / Invariant | Source Document & Line | Implementation File & Line | Verification Method | Verification Status | Observed Behavior & Test Evidence |
|---|---|---|---|---|---|---|
| UTS-01 | Layered message ceiling model (`utils/message_caps.py`) enforces strict boundaries: 4MB wire frame, 512KB post-auth, 64KB pre-auth frame, 64KB chat payload. | `docs/modules/utilities.md:14`, `utils/message_caps.py:5-18` | `utils/message_caps.py:10-35` | Code Inspection & Test Execution | Verified | `MAX_FRAME=4MB`, `POST_AUTH_MAX=512KB`, `PRE_AUTH_MAX=64KB`, `MAX_MESSAGE_PAYLOAD=64KB`. Tested in `tests/test_caps_strict.py::TestCapsConsistency` (4 passed). |
| UTS-02 | Production mode latching in `config.py` and `utils/config_manager.py` operates sticky and fail-closed; clearing environment variables does not unset production mode. | `config.py:25-55`, `utils/config_manager.py:34-55` | `config.py:34-54`, `utils/config_manager.py:42-55` | Code Inspection & Test Execution | Verified | `_STICKY_PROD` latches True once asserted. Attempting to unset production logs CRITICAL and retains production mode. Tested in `tests/test_caps_strict.py::TestStrictEncryptSentinel::test_production_auto_enables_strict`. |
| UTS-03 | Context-managed key erasure (`KeyEraser` in `utils/memory.py`) locks memory pages via `VirtualLock`/`mlock` and executes multi-pass sanitization upon scope exit. | `utils/memory.py:21-42` | `utils/memory.py:43-120` | Code Inspection & Test Execution | Verified | Context manager pins memory address to prevent OS swapping; exit hook overwrites buffer and triggers garbage collection. |
| UTS-04 | System resource cleanup (`utils/cleanup.py`) terminates monitoring threads, wipes cryptographic contexts, and closes sockets without double-close corruption. | `utils/cleanup.py:19-45` | `utils/cleanup.py:47-110` | Code Inspection & Test Execution | Verified | Safely disconnects connections and wipes session tables. Tested in `tests/test_connection_alias_cleanup.py::TestConnectionAliasCleanup` (4 passed). |
| UTS-05 | Error handler (`utils/error_handler.py`) translates system exceptions into sanitized diagnostic records, preventing stack memory exposure to untrusted peers. | `utils/error_handler.py:4-11` | `utils/error_handler.py:32-90` | Code Inspection & Test Execution | Verified | Encapsulates exceptions into `ErrorContext` and forwards telemetry to `audit_logging_system` without leaking in-memory state. Tested in `tests/test_cp1252_encoding_safety.py::test_error_handler_cp1252_compatibility`. |
| UTS-06 | Production configuration manifest (`config_production.json`) specifies NIST Level 5 post-quantum algorithms (ML-KEM-1024, ML-DSA-87) and ephemeral in-memory storage. | `config_production.json:1-35` | `config_production.json:15-32` | File & Signature Inspection | Verified | Specifies `ML-KEM-1024`, `ML-DSA-87`, `AES-256-GCM`, `in_memory_only: true`, `key_rotation_interval: 1800`. Integrity verified against digital signature `config_production.json.sig`. |
| UTS-07 | Backward compatibility engine (`utils/backward_compat.py`) preserves legacy CLI commands, error codes, and function signatures across API revisions. | `utils/backward_compat.py:2-10` | `utils/backward_compat.py:20-80` | Code Inspection | Verified | `BackwardCompatibilityManager` registers and resolves legacy error mappings and CLI options. |

## Verification Notes and Traceability

1. **Test Suite Execution Evidence:**
   - `pytest tests/test_caps_strict.py`: 12 passed in 0.45s.
   - `pytest tests/test_connection_alias_cleanup.py`: 4 passed in 0.25s.
   - `pytest tests/test_cp1252_encoding_safety.py`: 5 passed in 0.82s.
2. **Signature Files:**
   - `config.json.sig` and `config_production.json.sig` contain cryptographic signatures for verifying configuration files prior to process startup.

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
