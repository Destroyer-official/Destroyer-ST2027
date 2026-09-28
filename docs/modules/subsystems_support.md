# Subsystem mirrors: `messaging/ network/ security/ ui/ utils/`

## `messaging/`

`CommandProcessor`, `MessageEncryption` (ratchet + optional binding; labels
verified non-plaintext), `MessageHandler` (post-decrypt dispatch),
`MessagingManager`. No independent crypto.

## `network/`

`ConnectionManager`, `HandshakeManager`, `NetworkIO`, `NetworkManager`,
`ConnectionMonitoring`, `SessionContext/SessionManager`. TCP lifecycle under
the TLS+PQ envelope; no separate trust decisions.

## `security/`

`SecurityManager/Monitor/Hardening`, `IntegrityChecks`, `InputValidator`.
`graceful_degradation.py`: `BasicEncryptionHandler.__init__` RAISES
(fail-closed, verified) — the module documents what is FORBIDDEN, and
`can_proceed_with_connection` refuses `BASIC`. No degraded path executes.

## `ui/`

`Display/Feedback/UI/Menu/Prompt` managers + `safety_numbers.py` (own doc).
Menus never handle key material except usernames.

## `utils/`

`BackwardCompatibilityManager`, `Cleanup` (DoD wipe on exit),
`ConfigManager` (all fallbacks `False`), `SecurityErrorHandler` (memory-only
unsent queue default + sealed opt-in — verified), `NonceManager/Helpers`,
`Initialization` (auth default true), `UtilsManager`, `KeyEraser/MemoryManager`.
