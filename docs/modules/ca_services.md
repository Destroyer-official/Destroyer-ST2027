# Module: `ca_services.py` (~1983 lines) — private CA + mTLS contexts

## 1. Policy + errors (verified)

- `NISTLevel5PolicyEngine` (`:47`), exception tree (`CAError` family,
  `SecurityError`, `InputValidationError`, `:511-754`).
- `SecureKeyStorage` (`:607`: store/get/rotate/remove/cleanup).

## 2. `CAExchange` (`:754`, verified)

- Init + whitelist: `__init__` (`:783`), `add_authorized_fingerprint`,
  `load_authorized_peers`, `_calculate_cert_fingerprint`.
- Identity: `generate_self_signed` (`:971`) — self-signed roots are normal
  PKI anchors ONLY because fingerprints are pre-shared offline via
  `tactical_key_provisioner.py`; never TOFU-accepted blindly.
- Exchange: `_encrypt/decrypt_data`, `_recv_all`, `_validate_exchange_params`,
  `_setup_exchange_socket`, `exchange_certs(role, host, port)` (`:1282`,
  server listens `port+1`, rendezvous-token coordinated).
- Contexts: `create_server_ctx` (`:1628`), `create_client_ctx` (`:1726`) —
  TLS 1.3-only, `CERT_REQUIRED` against pinned peer cert + fingerprint
  whitelist; `check_hostname=False` is IP-tactical scoping (documented),
  not open trust.
- Hygiene: `_secure_delete`, `secure_wipe_buffer`, `secure_cleanup`,
  memory/HW self-checks, `wrap_socket_server/client` (`:2010/2032`).

## Verified properties

`ALLOWED_KEY_TYPES={mldsa87,ec384}` (identity `mldsa87`-only in practice),
fail-closed CA-load, mutual authentication, temp-file cleanup, stealth-knock
(HMAC-SHA512) gating.
