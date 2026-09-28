# Identity, trust, experimental math (verified maps + gates)

## `anonymous_identity_manager.py`, `multi_device_manager.py`

Ephemeral identities (fail-closed without PQC in production mode),
device chains with ML-DSA-87 signature links (max 5, revocation lists).
Self-signed roots are offline-provisioned trust anchors, never blind TOFU.

## `zero_trust_engine.py`

Per-message verification + SHA3-512 cert pins; audit-logging required in
production (fail-closed when absent).

## `zk_authenticator.py`, `threshold_cryptography.py` — GATED, NOT PROD

Custom `PRIME=2**256-189` arithmetic is unaudited: both classes refuse to
construct without `P2P_ENABLE_EXPERIMENTAL=1` (verified gates). Use ML-DSA
multisig in production until external audit. Zero right-pad length handling
documented as known weakness inside the gated code.

## `forward_secrecy_manager.py`

Rotation schedules (message-count + 900s), DoD wipe on rotation, session
termination wipes. Fail-closed rotation errors.

## `cryptographic_agility.py`, `cnsa2_policy_engine.py`,
`nist_level5_policy_engine.py`, `protocol_manager.py`

Frozen approved sets, L3 suites REMOVED (verified 0 hits), hybrid-only
classical exceptions with logged justification, fail-closed negotiation
(no downgrade path).
