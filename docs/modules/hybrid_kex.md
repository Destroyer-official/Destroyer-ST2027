# Module: `hybrid_kex.py` (~2912 lines) — hybrid X3DH+PQ handshake

## Key classes (signatures verified)

- `class MLKEM` — liboqs ML-KEM-1024 facade
  (`keygen`, `encaps`, `decaps`, `:161-230`).
- `class FALCON` — hybrid ML-DSA/SLH-DSA signature facade, bytes-or-dict keys
  (`keygen`, `sign`, `verify`, `:232-313`).
- `class QuantumResistanceModule` — algorithm registry + HKDF derivation
  (`hybrid_key_derivation`, identity keygen, `:315-575`).
- `class HybridKeyExchange` — session owner (`:674`):
  - Key lifecycle: `_load_or_generate_keys`, `_generate_keys`,
    `_save_keys` (AES-256-GCM sealed manifest, scrypt KDF — plaintext era
    ended), `_get_or_create_sealed_master_secret`, `_derive_storage_key`,
    `generate_identity_keys`, `rotate_keys`, `check_key_expiration`,
    `generate_ephemeral_identity`, `secure_cleanup`.
  - Identity: `get_public_bundle` (`:1321`), `verify_public_bundle` (`:1514`)
    — signature-checked before any use; TOFU pins applied by caller.
  - Handshake: `_generate_handshake_nonce` / `_verify_handshake_nonce`
    (±60s window, `:1633-1700`), `initiate_handshake` (`:1701`, signs full
    canonical message incl. `kem_ciphertext`+nonce+timestamp with ephemeral
    key `:2044-2078`, itself long-term-signed `:1845`), `respond_to_handshake`
    (`:2091`, verifies chain `:2264-2297` + message `:2317` BEFORE decaps
    `:2425`).
  - `_derive_shared_secret`, `_filter_key_components`.

## Verified properties (executed + read)

FIPS sizes (1568/1568/32), implicit rejection live-tested in Rust twin,
malformed inputs fail closed, rotation/expiry enforced, secrets wiped.
