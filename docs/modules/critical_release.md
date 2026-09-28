# Module: `critical_release.py` + `SecureP2PChat.send_critical`

Two-person critical-release authority for the CRITICAL message class
(nuclear-release discipline, technical enforcement layer).

## `CriticalReleaseAuthority` (verified: 4 unit tests green)

- `enroll(operator_id, passphrase)` — exactly 2 distinct operators;
  PBKDF2-SHA512/210k verifiers, RAM-only.
- `authorize(id1, pw1, id2, pw2)` — constant-time checks, distinctness
  enforced, 5-failure lockout with verifier wipe, fail-closed always.
- `reset()` — session-end wipe. `session_environ_ready()` — requires
  `P2P_REQUIRE_AUTH=true` + `P2P_DATA_PLANE=rust`.
- Honest limit documented: passphrases arrive as `str` (use getpass, del+GC).

## `send_critical` (verified: gate tests green on unconnected instance)

Gates in order: live session → peer pin MUST be `match` (TOFU-new refused)
→ Rust envelope mandatory → `P2P_REQUIRE_HSM` hardware gate when set →
joint ceremony (getpass, no echo) → send → audit hash-only. Failures are
NEVER queued. Receive path: CRITICAL content skips history, hash-only logs,
RAM-only banner display.

## What code cannot do (stated plainly)

Clearances, witnessed handling, dedicated endpoints, ATO — institutional
controls this module assumes and documents, never claims to replace.
