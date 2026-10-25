# Module Claims Register: ui_presentation

Claims verification register for the user interface presentation layer (`ui_presentation`).

| Claim ID | Claimed Capability / Invariant | Source Document & Line | Implementation File & Line | Verification Method | Verification Status | Observed Behavior & Test Evidence |
|---|---|---|---|---|---|---|
| UIP-01 | Terminal presentation modules enforce strict CP1252 and ASCII encoding safety, eliminating Unicode emojis to prevent Windows console rendering faults. | `docs/modules/ui.md:15`, `ui/display.py:20-60` | `ui/display.py:1-785`, `ui/feedback.py:1-451` | Code Inspection & Test Execution | Verified | Output strings use standard ASCII brackets and markers; verified zero forbidden unicode glyphs. Tested in `tests/test_cp1252_encoding_safety.py` (5 passed) and `tests/test_no_emoji_property.py` (5 passed). |
| UIP-02 | Safety numbers module calculates a deterministic 48-digit decimal fingerprint grouped in 12 blocks of 4 digits from SHA3-512 over canonical identity keys. | `docs/modules/ui.md:28`, `ui/safety_numbers.py:25-30` | `ui/safety_numbers.py:65-75` | Code Inspection & Test Execution | Verified | Sorts both peer keys canonically ($\min(A, B) \parallel 	ext{"||"} \parallel \max(A, B)$) producing symmetric safety numbers. Tested in `tests/test_audit_confirmed_regressions.py::TestAuditConfirmedRegressions::test_finding_12_tofu_blocks_pinning_unverified`. |
| UIP-03 | Host identity pinning rejects unpinnable loopback, unspecified, and wildcard addresses (`127.0.0.1`, `::1`, `localhost`, `0.0.0.0`) fail-closed. | `docs/modules/ui.md:40`, `ui/safety_numbers.py:77-85` | `ui/safety_numbers.py:77-105` | Code Inspection & Test Execution | Verified | `is_unpinnable_target()` verifies target host against `_INVALID_PIN_HOSTS`; attempts to pin loopback addresses are refused. Tested in `tests/test_audit_confirmed_regressions.py::TestAuditConfirmedRegressions::test_finding_47_tls_hostname_check_and_loopback_pinning`. |
| UIP-04 | Persistent pin store verifies entry authenticity via HMAC-SHA384 when `P2P_PIN_KEK` is provided; tampered entries are rejected as modified. | `ui/safety_numbers.py:32-38` | `ui/safety_numbers.py:120-190` | Code Inspection | Verified | `_mac_entry()` computes HMAC over target and digest; mismatch marks entry as modified (fail-closed) preventing offline tampering of pins.json. |
| UIP-05 | Canonical identity fingerprinting (`fingerprint_bundle`) binds exactly 7 stable public key fields while excluding ephemeral handshake elements. | `ui/safety_numbers.py:40-63` | `ui/safety_numbers.py:53-63` | Code Inspection | Verified | Includes `identity`, `static_key`, `signing_key`, `signed_prekey`, `prekey_signature`, `kem_public_key`, `falcon_public_key`; excludes ephemeral keys and nonces for deterministic continuity. |
| UIP-06 | User prompt manager masks sensitive cryptographic passphrase inputs and provides non-blocking progress indicators. | `ui/prompts.py:10-40` | `ui/prompts.py:45-120` | Code Inspection | Verified | Uses `getpass` fallback with masked terminal input routines and clean terminal recovery. |
| UIP-07 | Unified user interface manager (`UIManager`) provides a single facade consolidating display formatting, feedback alerts, menus, and input prompts. | `ui/manager.py:10-30` | `ui/manager.py:20-58` | Code Inspection | Verified | Instantiates and delegates to `DisplayManager`, `FeedbackManager`, `MenuManager`, and `PromptManager`. |

## Verification Notes and Traceability

1. **Test Suite Execution Evidence:**
   - `pytest tests/test_cp1252_encoding_safety.py`: 5 passed in 0.82s.
   - `pytest tests/test_no_emoji_property.py`: 5 passed in 2.60s.
   - `pytest tests/test_audit_confirmed_regressions.py -k "safety or pin"`: 2 passed in 1.45s.
2. **Phase 0 Status of Trust-On-First-Use Pin Store:**
   - `ui/safety_numbers.py:10-13` notes that the pin store computes and stores TOFU pins; full automatic connection refusal across all transport layers is enforced through `security_tiers.py` and `tls_channel_manager.py`.
