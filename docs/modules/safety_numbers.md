# Module: `ui/safety_numbers.py`

TOFU ceremony primitives + persistent pin store. Standard library only
(no crypto imports beyond `hashlib`), so it can load anywhere including
inside the handshake hot path.

## Functions (all verified)

- `safety_numbers(mldsa_pk: bytes, ecdh_pk: bytes) -> str` — `SHA3-512`
  over `mldsa||"||"||ecdh`, rendered as 12 groups of 4 decimal digits
  (192 bits shown). Deterministic; any key change avalanches the display.
- `load_pins() -> dict` — reads `~/.secure_p2p/pins.json` (`{}` if absent).
- `check_pin(peer_id, fingerprint) -> 'new' | 'match' | 'CHANGED'`.
- `store_pin(peer_id, fingerprint)` — writes JSON, `chmod 0o600`
  (POSIX-effective; on Windows ACLs apply — documented, not assumed).

## Callers (verified)

- `secure_p2p.py: SecureP2PChat._check_peer_key_continuity` — invoked after
  bundle-signature verification on BOTH client and server paths, before any
  handshake computation. `CHANGED` raises `SecurityError` (aborts session);
  `new` logs numbers + stores; store failure fails closed.
- Live evidence: both terminals printed distinct 12-group numbers and pinned
  during the two-terminal runs.

## Operational rule (SOP §4.5)

Numbers MUST be compared over an independent channel on first contact.
A later `CHANGED` is treated as active MITM until re-verified OOB.
