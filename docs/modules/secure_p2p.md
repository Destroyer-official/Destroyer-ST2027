# Module: `secure_p2p.py` (~11,400 lines) — application orchestrator

`SecureP2PChat` owns identity, handshake roles, message path, files,
heartbeats, rotation, monitoring, and shutdown. Entry via `secure_p2.py` shim.

## 1. Module-level pieces (verified)

- `SecurityError` (`:224-248`) — severity/attack-vector/mitigation contexts,
  audit-logged on construction.
- `KeyEraser` (`:492-668`) — pin (`VirtualLock`/`mlock`), multi-pass erase,
  shutdown-safe basic fallback. Documented Python-copy limits apply.
- `InputValidator` (`:946-1431`) — strict username/message/IP/port/command
  validation, mandatory rejection, attack-pattern lists.
- `serialize/deserialize_hybrid_key|signature|falcon_public_key`
  (`:741-848`) — bytes-or-dict hybrid codecs (legacy + ML-DSA/SLH-DSA).
- `secure_memory_wipe`, `secure_shred_file` — platform wipe + DoD file shred.

## 2. Identity & profiles (`:1511-2070`)

`UserProfile` (`create_ephemeral_user`, `_derive_key` PBKDF2-SHA512,
`_get_passphrase`, `exists/load/save`, `create_new_user`, `automatic_login`,
`update_endpoint`, `get_profile/save_profile`), discovery helpers
(`_ensure_api_client`, `_ensure_discovery_service`), `PeerManager`
(`lookup_peer_by_username`, `add/get/list_peers`, `update_peer_connection`,
`cleanup`), enhanced profile/peer accessors (`:4116-4172`).

## 3. Init & hardening (`:2091-3480`)

`__init__` (`:2091`), hardening manager init, anti-debugging + detector
thread (`:2635-2732`), validation framework + periodic checks
(`:2732-3137`), NIST enforcement per operation
(`enforce_nist_level5_for_operation`, `:2925`; fail-closed b'' on violation),
`_emergency_wipe` / `_secure_erase` (`:3419-3480`), configuration
(`_initialize_configuration`, `:3480`; auth default true).

## 4. Handshake roles (`:4306-5400`)

- `_check_peer_key_continuity` (`:4306`) — TOFU pins both paths (added;
  proven live with safety numbers on both terminals).
- `_exchange_hybrid_keys_client` (`:4356`) / `_server` (`:4829`) —
  version → bundle → verify → pin → handshake → root-key auth.
- Rendezvous token replaces `CERT_READY` beacon (no fixed strings remain).
- `_connect_to_peer` (`:5404`), `handle_connections` (`:6048`).

## 5. Message path (`:7578-7847`)

`_add_random_padding` (uniform 1024B blocks, `:7578`) /
`_remove_random_padding` (`:7602`) → `_encrypt_message` (`:7664`: validate →
pad → ratchet → **optional Rust outer envelope** when
`P2P_DATA_PLANE=rust`, fail-closed) → `_decrypt_message` (`:7763`: try Rust
open, fall back to legacy path for mixed fleets) → `_rust_plane` (`:7618`:
HKDF-SHA512-bound session, re-binds on rotation fingerprint).

## 6. Sessions, heartbeats, files

`_chat_session` (`:7848`), `_send_heartbeats` + `_send_heartbeat` (jittered;
`:8096`,`:10826`), `_send_cover_traffic` (`:8149`, 4–8s jitter),
`_receive_messages` (`:6673`), file pipeline `_handle_file_*`,
`_start/complete_file_reception`, `send_file` (`:9241-9904`; 10MB cap,
traversal-sanitized output), `_refresh_stun`, `_print_banner`.

## 7. Rotation, keys, monitoring, shutdown

`_rotate_keys` / `_handle_key_rotation` (`:8965-9151`),
`_secure_key_storage` / `_verify_key_storage`, `_handle_command`,
memory/canary/integrity/intrusion loops (`:8342-8905`), connection health
(`:10710-10917`), user management (`:10994-11361`), `cleanup` + `__del__`
(zeroization + GC).

## Verified live behaviors

Two-terminal 100% in BOTH modes (default byte-identical; flag-on double
envelope with sessions both ends). Suites 10+5 green.
