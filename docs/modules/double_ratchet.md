# Module: `double_ratchet.py` (~4100 lines) — ratchet + guards

## 1. Support machinery (verified signatures)

- `SecureHardwareManager` (`:332`: TPM/SGX/Enclave interfaces, HW random)
- `ConstantTime` (`:599`: compare/select), `CanaryProtector` (`:672`),
  `SideChannelProtection` (`:734`), `ThreatDetection` (`:807`),
  `EntropyVerifier` (`:918`: Shannon/block entropy, pattern detect),
  `KeyShare` Shamir split/combine (`:1501-1561`; custom prime — gated).
- `MessageHeader` (`:1631`: encode/decode, `generate` `:1730`).
- `DoubleRatchetDefaults` (`:3603`), `ReplayCache` (`:3676`),
  `DuplicateDetectionManager` (`:3885`, window 1000),
  `AntiReplayMechanisms` (`:3972`, 300s timestamp window).

## 2. `DoubleRatchet` (`:1748`, verified)

- Init + keygen: `__init__` (`:1856`), `_generate_dh_keypair` (`:2007`),
  `_generate_pq_keypairs` (`:2019`), `_setup_secure_memory` (`:2053`).
- Steps: `_dh_ratchet_step` (`:2113`), `_update_receiving/sending_chain`
  (`:2192/:2237`), `_chain_ratchet_step` HMAC-SHA512 (`:2274`),
  `_kdf` HKDF (`:2335`).
- Crypto: `_encrypt_with_cipher` / `_encrypt` / `encrypt`
  (`:2398/:2449/:2547`), `_decrypt_with_cipher` / `decrypt`
  (`:2591/:2649`), `_ratchet_encrypt/decrypt` (`:2761/:2786`).
- Chains: `_store_skipped_message_keys` (`:2950`, `MAX_SKIP=0` strict),
  `_create_new_receiving_chain` (`:2991`), `_initialize_chain_keys`
  (`:3117`), `_skip_message_keys` (`:3360`).
- Keys/identity: `get_public_key`, `get_kem_public_key/ciphertext`,
  `process_kem_ciphertext`, `get_dss_public_key`, `set_remote_public_key`,
  `_compare_public_keys`, `_secure_verify`, `get_info`, `is_initialized`,
  `secure_cleanup`.

## Verified properties

Per-message keys, DH+PQ combined steps, strict skip policy, timestamp/nonce
anti-replay, constant-time compares, secure cleanup. Rust twin (bitmap
window) covers wire replay at O(1).
