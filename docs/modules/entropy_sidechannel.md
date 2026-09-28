# Entropy, randomness, side-channels (verified class maps)

## `entropy_manager.py` / `quantum_rng.py`

`EntropyError` tree, `QRNGUnavailableError`, source types (SYSTEM CSPRNG /
hardware / QRNG / timing), health reports, 512-bit pools, SHA3-512
conditioning, block-if-low + `qrng_required` fail-closed paths, HSM injection.
Verified: no silent auto-replenish bypass; QRNG optional with explicit
unavailable errors (not fake "QRNG available" claims).

## `side_channel_resistance.py`

`TimingMeasurement/Statistics/Alert/Analyzer`, `ConstantTimeOperations`,
`ConstantTimeCryptoWrapper`, `TimingConsistencyVerifier` (CV < 0.05),
`SideChannelResistanceEngine`, `RuntimeTimingMonitor`. Python-level timing
hygiene + anomaly detection; constant-time guarantees live in RustCrypto
backends + `destroyer_core`.

## `secure_message_serializer.py`

`SecureMessage` header (version/type/flags/len/seq/timestamp/sender binding)
+ HMAC, `SecureMessageSerializer`. Used by file-chunk path; chat path uses
ratchet framing. MAC-then-parse ordering enforced.
