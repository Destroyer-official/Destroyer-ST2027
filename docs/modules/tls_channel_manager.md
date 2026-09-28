# Module: `tls_channel_manager.py` (~5700 lines) — TLS + channel crypto

## 1. Helpers (verified)

- `verify_key_material`, `secure_erase` (`:194-206`).
- `PostQuantumCrypto` (`:294`: kem keygen/encaps/decaps, signatures,
  hybrid exchange, cleanup).
- `NonceManager` (`:590`: rotation policy), `XChaCha20Poly1305` (`:686`),
  `MultiCipherSuite` (`:822`: layered encrypt/decrypt, `_rotate_keys`),
  `OAuth2DeviceFlowAuth` (`:1068`: opt-in only, hard client-ID requirement),
  `SecureEnclaveManager` (`:1443`: TPM/Enclave probes per OS).

## 2. `TLSSecureChannel` (`:1706`, verified)

Contexts (`_create_client_context` `:3799`, `_create_server_context`
`:4525`) enforce TLS 1.3-only + `CERT_REQUIRED`; `CERT_NONE` appears solely
in fail-closed raise paths. Wrapping (`wrap_socket_server/client`,
`:3264/3328`), handshake loops (`do_handshake`, `_do_handshake`),
`send/recv_secure`, nonce/rotation monitors, DANE validation
(`_validate_certificate_with_dane`, `:4904`), OCSP, self-signed generators
(provisioning paths only — production uses pre-shared ML-DSA-87 certs).
Auth flows (`authenticate_user`, `send/accept_authentication`).

## 3. `TLSRecordLayer` (`:5074`) — encrypt/decrypt/rotate records.

## 4. Dead code note (verified: zero references outside definitions)

`DirectX25519KeyExchange` (`:5232`) and `Ed25519Signer` (`:5262`) exist but
are never instantiated or imported anywhere (whole-repo grep: 2 hits, both
the class lines). Standalone classical primitives MUST NOT be wired without
hybrid binding — scheduled for deletion, not a live vulnerability.
Hybrid groups (`X25519MLKEM768`, `SecP384r1MLKEM1024`, `:1738`) are the
enforced path per RFC 10024 (L5 = SecP384r1MLKEM1024).

## Verified properties

Fail-closed CA loading, strict version pinning, mutual authentication,
rotation discipline, DANE where configured.
