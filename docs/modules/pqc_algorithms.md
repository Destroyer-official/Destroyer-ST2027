# Module: `pqc_algorithms.py` (~6500 lines) — PQ algorithm surfaces

LibOQS-backed implementations + policy wrappers. Real Dilithium/Kyber
predecessor names appear only in FORBIDDEN lists and migration comments.

## Classes (verified)

- Errors: `DecapsulationError`, `SecurityError` (`:203/:208`).
- `SecurityPolicyEnforcer` (`:1886`), `KeySeparationManager` (`:2110`,
  HKDF-SHA3_512 domain separation), `HQCCryptoEngine` (`:2298`, authentic
  LibOQS HQC-256; fake-expansion prohibited by construction),
  `CryptoAgilityManager` (`:2428`), `PostQuantumTestVectors` (`:2593`),
  `ConstantTime` (`:2741`), `HardcodedKeyScanner` (`:3132`),
  `NISTLevel5Enforcer` (`:3318`).
- KEMs: `EnhancedHybridKEM` (`:3514`), `EnhancedMLKEM_1024` (`:3612`),
  `EnhancedHQC` (`:5145`), `HybridKEX` (`:5181`).
- Signatures: `EnhancedSPHINCS_256s` (`:4716`), `EnhancedHybridSignature`
  (`:4818`), `EnhancedFALCON_1024` (`:1222` + `:4928`, hybrid ML-DSA/SLH-DSA
  naming — see note), `EnhancedMLDSA_87` (`:6493`), `EnhancedXMSS` (`:6785`),
  `EnhancedLMS` (`:7139`) — both with authentic Merkle verification (suite
  Phase 1 green).
- Protection: `SecureAESGCM` (`:4632`), `SecureMemory` (`:6237`, AES-256-GCM
  at-rest), `SideChannelProtection` (`:4306`), `NISTTestVectorValidator`
  (`:7498`), `HybridCryptographyManager` (`:7760`),
  `BreakInRecoveryManager` (`:7859`), `SecurityTest` (`:5508`).

## Naming note (verified, not a vuln)

`EnhancedFALCON_1024` labels a hybrid ML-DSA+SLH-DSA construction; no
`OQS_SIG_new("Falcon-*")` call exists. Primary identity signatures are
ML-DSA-87 (CNSA-required); Falcon/FN-DSA stays experimental until FIPS 206
finalizes (late 2026/early 2027).

## Verified properties

Fail-closed imports, size-validated keygen (1568/3168/1568/32), KATs,
tamper-rejection, sealed manifests, entropy verification.
