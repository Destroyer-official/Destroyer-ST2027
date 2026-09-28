# OPSEC + persistence: `operational_security.py`, `ephemeral_messaging.py`,
`resilient_communication.py`, `anti_forensics.py` (verified maps)

## `operational_security.py`

1024B-block `TrafficAnalysisResistancePadding` (verified implementation),
ephemeral identities with TTL disposal, expiring messages with managers.
Padding is real block-boundary logic, not a stub.

## `ephemeral_messaging.py`

TTL/read-once messages, DoD wipe on expiry, deletion sync, screenshot
notification hooks. Deletion is best-effort against forensic imaging —
documented limit, not a deniability proof.

## `resilient_communication.py`

Offline queue (1000/peer), exponential backoff, SHA3 dedup. Queue plaintext
risk CLOSED: `utils/error_handler.py` persists only when
`P2P_PERSIST_QUEUE=true`, sealed AES-256-GCM (SHA512 KDF), hashed filenames;
default is memory-only.

## `anti_forensics.py`

Deniable containers, duress passwords, dead-man switch (5-min command
expiry), tamper-triggered wipe, remote wipe with authentication. HMAC-SHA512
throughout. Deniability holds only against casual inspection; laboratory
forensics is out of scope for software claims.
