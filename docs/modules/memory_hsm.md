# Memory protection + HSM (verified maps, honest limits)

## `secure_memory_wiper.py`

`WipePattern`, `WipeResult`, `SecureMemoryWiper` (`wipe` 3-pass DoD + verify,
`_wipe_pass`, `_memory_barrier`, `_verify_wipe`, `_lock/unlock_memory`,
`wipe_key_material`). Honest documented limit (read in code): immutable
`bytes` are copied to `bytearray` for wiping — the original Python object,
plus C/SSL/socket-buffer copies, cannot be wiped from Python. True RAM
guarantees live in `rust_data_plane/` (`ZeroizeOnDrop`).

## `enhanced_secure_memory.py`, `memory_protection_engine.py`

Locked regions with TTL (`LockedMemoryRegion.is_expired`), platform
allocators, canary/integrity loops. Hygiene layer, same Python limits.

## `hsm_integration.py`, `platform_hsm_interface.py` (~8000 lines),
`secure_enclave_key_storage.py`, `tee_manager.py`

CNG/TPM/PKCS#11 probes, key store/retrieve/sign, attestation flows.
Fail-closed where enforced; software fallbacks only where explicitly
documented. Production requires witnessed HSM attestation + sealed keys
(operational track, not yet evidenced in repo).
