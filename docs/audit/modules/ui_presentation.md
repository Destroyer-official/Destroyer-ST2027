# Module Documentation: ui_presentation

## 1. Module Overview

The `ui_presentation` module provides terminal user interface formatting, status presentation, user input dialogues, and Trust-On-First-Use (TOFU) identity key verification (safety numbers). It is designed to operate predictably across constrained Windows consoles (CP1252 character encoding) and POSIX terminal environments without emitting Unicode emojis or unsupported control sequences.

### Files in Scope (7 Files, 2,317 Lines)

| File | Lines | Purpose |
|---|---|---|
| `ui/__init__.py` | 9 | Package exports exposing UI managers and safety number functions. |
| `ui/display.py` | 785 | Terminal display manager rendering banners, chat history, and system status. |
| `ui/feedback.py` | 451 | Feedback and notification manager handling warning alerts and spinners. |
| `ui/manager.py` | 59 | Unified facade coordinating display, feedback, menu, and prompt subsystems. |
| `ui/menus.py` | 385 | Interactive CLI menu manager for action selection and navigation. |
| `ui/prompts.py` | 382 | User input prompter handling masked passphrase inputs and confirmation prompts. |
| `ui/safety_numbers.py` | 246 | TOFU safety number calculation and persistent HMAC-authenticated pin store. |

---

## 2. Architecture & Component Interaction

The presentation layer interacts with user inputs and cryptographic state through structured components:

```
+-------------------------------------------------------------------------------+
|                                USER INPUT / TTY                               |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                            UI FACADE (ui/manager.py)                          |
|   Coordinates display, alerts, menus, and input prompts through UIManager     |
+-------+--------------------+---------------------+--------------------+-------+
        |                    |                     |                    |
        v                    v                     v                    v
+---------------+    +---------------+     +---------------+    +---------------+
| ui/display.py |    | ui/feedback.py|     |  ui/menus.py  |    | ui/prompts.py |
| Screen Output |    | Error Alerts  |     | Nav Menus     |    | Masked Inputs |
| CP1252 Safe   |    | Status Banners|     | Selection     |    | Confirmations |
+---------------+    +---------------+     +---------------+    +---------------+
                                                           |
                                                           v
                                     +------------------------------------------+
                                     |           ui/safety_numbers.py           |
                                     | - Canonical 7-field SHA3-512 bundle      |
                                     | - Grouped 48-digit decimal safety number |
                                     | - Persistent pin store (~/.secure_p2p)   |
                                     | - HMAC validation via P2P_PIN_KEK        |
                                     +------------------------------------------+
```

---

## 3. Detailed Component Analysis

### 3.1 `ui/safety_numbers.py`
- **Function `fingerprint_bundle(bundle: dict) -> str` (`:40`):**
  - Extracts exactly 7 stable public key fields from identity bundles:
    1. `identity`
    2. `static_key`
    3. `signing_key`
    4. `signed_prekey`
    5. `prekey_signature`
    6. `kem_public_key`
    7. `falcon_public_key`
  - Canonicalizes keys as JSON with `sort_keys=True` and calculates SHA3-512 hex digest. Excludes ephemeral session keys, nonces, and bundle signatures to ensure deterministic identity continuity.
- **Function `safety_numbers(key_a: bytes, key_b: bytes) -> str` (`:65`):**
  - Sorts key inputs canonically: `first_pk, second_pk = sorted([key_a, key_b])`.
  - Calculates digest: $	ext{digest} = 	ext{SHA3-512}(	ext{first\_pk} \parallel 	ext{"||"} \parallel 	ext{second\_pk})$.
  - Converts digest integer to 48 decimal digits ($12 	ext{ groups} 	imes 4 	ext{ digits}$), formatted with space delimiters (e.g., `1234 5678 9012 ...`). Truncation bias is mathematically negligible ($pprox 2^{-353}$).
- **Pin Store Management (`check_pin`, `store_pin`, `revoke_pin`) (`:110-245`):**
  - Stored at `Path.home() / ".secure_p2p" / "pins.json"` with restricted file permissions (`0600`).
  - Supports entry authentication with `_PIN_KEK` (derived from `P2P_PIN_KEK` or `P2P_STORAGE_PASSPHRASE`). If configured, entries without valid HMAC-SHA384 tags are rejected as tampered.
  - Rejects loopback and unpinnable targets (`_INVALID_PIN_HOSTS = {"::", "0.0.0.0", "127.0.0.1", "::1", "localhost", "*"}`).

### 3.2 `ui/display.py`
- **Class `DisplayManager` (`:25`):**
  - Renders colored text output using ANSI escape codes with automatic fallback to uncolored text on terminals lacking ANSI color support.
  - Replaces non-ASCII symbols with plain ASCII text markers (e.g., `[INFO]`, `[WARN]`, `[ERROR]`, `[OK]`) to guarantee correct display in CP1252 Windows command shells (`cmd.exe` and `powershell.exe`).
  - Formats chat transcripts, message metadata, cryptographic parameters, and network statistics.

### 3.3 `ui/feedback.py`
- **Class `FeedbackManager` (`:20`):**
  - Provides standardized diagnostic and feedback mechanisms: operation success, non-critical warnings, critical alerts, and transient progress indicators.
  - Integrates clean error reporting avoiding internal stack trace exposure to standard output unless debug mode is explicitly asserted.

### 3.4 `ui/menus.py`
- **Class `MenuManager` (`:22`):**
  - Manages hierarchical CLI menu navigation.
  - Validates numeric and alphanumeric menu selections with bounded input ranges, preventing invalid selections or control character injection.

### 3.5 `ui/prompts.py`
- **Class `PromptManager` (`:24`):**
  - Manages console input dialogues for text entry, multi-line messages, and confirmation checks (`confirm_action(prompt: str) -> bool`).
  - Implements masked password entry via `getpass.getpass` to prevent shoulder-surfing and terminal echo of passphrases.
- **Class `ProgressIndicator` (`:210`):**
  - Implements thread-safe ASCII progress animation for long-running cryptographic operations (such as multi-pass memory zeroization or heavy key generation).

### 3.6 `ui/manager.py`
- **Class `UIManager` (`:15`):**
  - Central aggregation class providing unified access to `display`, `feedback`, `menus`, and `prompts` instances.

---

## 4. Encoding & Safety Invariants

1. **CP1252 / ASCII Purity:**
   No unicode emoji characters (e.g., emojis in range `😀-🙏` or misc symbols `☀-⛿`) are permitted in console output strings. All operational statuses use ASCII brackets `[PASS]`, `[FAIL]`, `[INFO]`, `[WARN]`.
2. **Symmetric Out-of-Band Agreement:**
   `safety_numbers()` canonically sorts peer keys prior to hashing, ensuring both initiating and receiving parties compute identical 48-digit strings regardless of handshake order.
3. **Loopback Pinning Prevention:**
   Local test addresses (`127.0.0.1`, `localhost`, `0.0.0.0`) cannot be pinned in `.secure_p2p/pins.json`, preventing test fixtures from corrupting production peer authenticators.

---

## 5. Verification & Test Coverage

### Test Suites Executed

| Test Suite | Purpose | Tests | Result | Execution Time |
|---|---|---|---|---|
| `tests/test_cp1252_encoding_safety.py` | Console character encoding safety and Unicode restriction | 5 | Passed | 0.82s |
| `tests/test_no_emoji_property.py` | Universal property testing verifying absence of emojis across codebase | 5 | Passed | 2.60s |
| `tests/test_audit_confirmed_regressions.py` | Safety number out-of-band verification and loopback pinning rejection | 2 | Passed | 1.45s |

### Verification Evidence Summary
- Absence of Unicode emojis and compatibility with CP1252 verified across all UI modules in `test_ui_display_cp1252_compatibility`, `test_ui_feedback_cp1252_compatibility`, and `test_ui_prompts_cp1252_compatibility`.
- Out-of-band TOFU safety number calculation and unverified contact rejection verified in `test_finding_12_tofu_blocks_pinning_unverified`.
- Rejection of loopback interface hostnames in key pin store verified in `test_finding_47_tls_hostname_check_and_loopback_pinning`.

---

## 6. Operational Gotchas & Discrepancies

1. **Storage Location Default:**
   - `ui/safety_numbers.py:24` defaults `PIN_STORE` to `~/.secure_p2p/pins.json`. In multi-user or service container environments without persistent user home directories, pins must be explicitly redirected via configuration or environment variables.
2. **HMAC Key Requirement for Offline Tamper Resistance:**
   - If `P2P_PIN_KEK` or `P2P_STORAGE_PASSPHRASE` is not set, pins in `pins.json` are stored with `"mac": null`, relying strictly on OS filesystem permissions (`0600`) for integrity.

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
