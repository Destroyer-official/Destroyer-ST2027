# Module Documentation: utilities_support

## 1. Module Overview

The `utilities_support` module supplies common utility routines, configuration managers, process cleanup handlers, memory wiping contexts, message capability bounds, and project configuration manifests.

### Files in Scope (22 Files, 4,431 Lines)

| File | Lines | Purpose |
|---|---|---|
| `.gitattributes` | 8 | Line ending and export filtering configuration. |
| `.gitignore` | 202 | Repository ignore patterns for build artifacts, virtualenvs, and secrets. |
| `LICENSE` | 21 | MIT software license text. |
| `config.json.sig` | 5 | ML-DSA-87 signature for verifying default configuration integrity. |
| `config.py` | 760 | Central configuration loader and sticky production posture enforcement. |
| `config_production.json` | 95 | Hardened production configuration profile. |
| `config_production.json.sig` | 1 | Cryptographic signature verifying `config_production.json`. |
| `config_template.json` | 98 | Template configuration profile with parameter definitions. |
| `pytest.ini` | 55 | Test runner configuration, test markers, and warning filters. |
| `requirements-test.txt` | 9 | Test execution package dependencies. |
| `requirements.txt` | 54 | Production runtime dependencies. |
| `set_env.sh` | 6 | Environment variable setup shell script. |
| `utils/__init__.py` | 10 | Package exports for utility modules. |
| `utils/backward_compat.py` | 296 | Backward compatibility manager for legacy commands and errors. |
| `utils/cleanup.py` | 244 | Central resource cleanup and thread termination manager. |
| `utils/config_manager.py` | 1,068 | Schema-validating configuration manager with backward compatibility. |
| `utils/error_handler.py` | 509 | Sanitized exception handler and audit logger integration. |
| `utils/helpers.py` | 267 | String, networking, and byte conversion helper functions. |
| `utils/initialization.py` | 110 | Subsystem bootstrapping coordinator. |
| `utils/manager.py` | 63 | Unified facade managing utilities. |
| `utils/memory.py` | 404 | Memory pinning and `KeyEraser` context manager. |
| `utils/message_caps.py` | 146 | Layered message size limits and DoS mitigation ceilings. |

---

## 2. Architecture & Component Interaction

The utilities layer supports all operational modules across initialization, runtime execution, and teardown:

```
+-------------------------------------------------------------------------------+
|                            CONFIGURATION & BOOTSTRAP                          |
|   config.py / utils/config_manager.py  <-- config_production.json[.sig]       |
|   - Validates JSON schema & signatures                                        |
|   - Latches sticky production mode (cannot be unset)                          |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                              RUNTIME ENFORCEMENT                              |
|   utils/message_caps.py                     utils/memory.py                   |
|   - Wire frame: max 4MB                     - KeyEraser context manager       |
|   - Post-auth: max 512KB                    - VirtualLock / mlock RAM pinning |
|   - Pre-auth: max 64KB                      - DoD 5220.22-M sanitization      |
|   - Chat payload: max 64KB                                                    |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                             FAULT & TEARDOWN CONTROL                          |
|   utils/error_handler.py                    utils/cleanup.py                  |
|   - Sanitizes exception traces              - Closes connections              |
|   - Dispatches to audit logger              - Terminates worker threads       |
|   - Applies backoff retry                   - Zeroizes session tables         |
+-------------------------------------------------------------------------------+
```

---

## 3. Detailed Component Analysis

### 3.1 `utils/message_caps.py`
- Enforces strict message size ceilings across network and serialization boundaries:
  - `MAX_FRAME = 4 * 1024 * 1024` (4MB): Absolute wire frame limit enforced in socket receive loops (`recv_exact`, `receive_framed`). Frames exceeding this are rejected immediately to prevent heap exhaustion.
  - `POST_AUTH_MAX = 512 * 1024` (512KB): Maximum allowed size for authenticated message frames.
  - `PRE_AUTH_MAX = 64 * 1024` (64KB): Maximum allowed frame size during pre-authentication handshakes.
  - `PRE_AUTH_HYBRID_BUNDLE_MAX = 2 * 1024 * 1024` (2MB): Permitted exception specifically for the initial public key bundle exchange (ML-KEM-1024 + McEliece-8192128f public keys and signatures, measured at ~1.8MB).
  - `MAX_MESSAGE_PAYLOAD = 64 * 1024` (64KB): Upper ceiling for standard chat messages.

### 3.2 `config.py` and `utils/config_manager.py`
- **Sticky Production Latching (`_is_production`):**
  - Reads `is_production()` from `production_gate.py` at initial import.
  - Latches `_STICKY_PROD = True` once asserted.
  - Any subsequent attempt to unset environment variables (`P2P_PRODUCTION`, `SECURE_P2P_PRODUCTION`) is blocked; the process logs a `CRITICAL` alert and remains locked in production mode.
- **Configuration Loading:**
  - `ConfigManager.load_config()` merges user configuration files with secure defaults, ensuring required cryptographic parameters are never omitted.

### 3.3 `utils/memory.py`
- **Class `KeyEraser` (`:21`):**
  - Context manager designed to handle temporary plaintext cryptographic keys.
  - `__enter__()`: Attempts to pin underlying memory via `VirtualLock` (Windows) or `mlock` (Linux) to prevent memory pages from being written to swap or hibernation files.
  - `__exit__()`: Overwrites memory buffers with multiple passes of pseudorandom and zero bytes, clears references, and triggers Python garbage collection (`gc.collect()`).

### 3.4 `utils/cleanup.py`
- **Class `Cleanup` (`:19`):**
  - Inherits from `BaseModule`. Orchestrates graceful shutdown of operational nodes.
  - Method `cleanup()` executes three sequential phases:
    1. Stops background monitoring loops and heartbeat threads.
    2. Zeroizes cryptographic key material and session tables.
    3. Closes active network sockets, preventing file descriptor leaks.

### 3.5 `utils/error_handler.py`
- **Class `ErrorContext` (`:32`):**
  - Encapsulates error metadata: `error_type`, `error_message`, `peer_id`, `operation`, `timestamp`, `retry_count`, `recoverable`.
  - Strips local path variables and sensitive in-memory parameters before outputting messages to UI or log files.
  - Interfaces directly with `audit_logging_system.py` when available.

---

## 4. Security Invariants

1. **Fail-Closed Production Posture:**
   Once a node enters production mode, the posture is irreversible for the duration of the operating system process lifetime.
2. **Layered Size Ceilings:**
   Strict hierarchy: $	ext{Wire Frame (4MB)} > 	ext{Hybrid Bundle (2MB)} > 	ext{Post-Auth (512KB)} > 	ext{Pre-Auth / Chat (64KB)}$.
3. **Defense Against Swap Extraction:**
   Sensitive buffers inside `KeyEraser` are locked into physical RAM using operating system memory-locking APIs.

---

## 5. Verification & Test Coverage

### Test Suites Executed

| Test Suite | Purpose | Tests | Result | Execution Time |
|---|---|---|---|---|
| `tests/test_caps_strict.py` | Verification of unified message size caps and strict encryption | 12 | Passed | 0.45s |
| `tests/test_connection_alias_cleanup.py` | Connection teardown, alias deduplication, clean socket closure | 4 | Passed | 0.25s |
| `tests/test_cp1252_encoding_safety.py` | Character set compatibility and sanitized error logging | 5 | Passed | 0.82s |

### Verification Evidence Summary
- Message caps consistency verified across serializer and transport sockets in `test_canonical_values_and_layering` and `test_serializer_enforces_unified_chat_cap`.
- Sticky production latching verified in `test_production_auto_enables_strict`.
- Memory wiping and connection alias closure verified in `test_disconnect_removes_all_aliases_and_wipes_once`.

---

## 6. Operational Gotchas & Discrepancies

1. **Privileged Memory Locking:**
   - `utils/memory.py:46-55` attempts `VirtualLock` or `mlock`. On non-administrative Windows accounts or unprivileged Linux containers, the call emits a warning and continues without physical RAM locking unless `P2P_REQUIRE_MLOCK=1` is asserted.
2. **Configuration Signature Enforcement:**
   - In laboratory or test mode, unsigned JSON configurations can be loaded; in production mode (`SECURE_P2P_PRODUCTION=1`), unsigned configurations are rejected.

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
