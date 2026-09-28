# Subsystem mirrors: `core/ crypto/ data/ keys/` (verified maps)

These `BaseModule` trees mirror the root implementations for the composed
orchestrator (`core/orchestrator.py: SecureP2PChat` delegates; `core/config.py:
ConfigManager` centralizes flags incl. all-`False` fallbacks).

- `crypto/`: `AuthTagOperations`, `KEMOperations`, `CryptoOperations`,
  `PaddingOperations` (32B random pad), `SignatureOperations` — same
  primitives as root, no divergent algorithms (verified: no fallback/stub
  markers in these files).
- `data/`: `FileTransferManager`, `DataManager`, `EnhancedPeerManager`,
  `MilitaryGradeCrypto` + `EnhancedUserManager` (PBKDF2-SHA512).
- `keys/`: `KeyGeneration`, `HSMIntegration`, `KeysManager`, `KeyRotation`,
  `KeyStorage` — rotation/expiry/sealed persistence semantics match root.
- `secure_p2p_core/` mirrors the same layout for the packaged distribution;
  behavior parity is enforced by the shared suites (any drift fails tests).
