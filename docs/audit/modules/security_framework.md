# Module Documentation: security_framework

## 1. Purpose
The `security_framework` module establishes security policy architecture, operational execution gates, anti-downgrade controls, input schema validation, runtime integrity checks, and host hardening enforcement (`production_gate.py:1-189`, `security_tiers.py:1-1715`, `security/manager.py:1-54`). It enforces fail-closed execution when operating in production mode, blocking unauthenticated endpoints, default test keys, or algorithmic downgrades (`cnsa2_policy_engine.py:8-13`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `production_gate.is_production` (`production_gate.py:25-50`)
- `is_production() -> bool`: Evaluates runtime environment (`P2P_ENV == "production"`, `P2P_PRODUCTION == "1"`, or config `"production": true`). Returns `True` if production mode is active; otherwise returns `False`.
- `fail_if_production(feature_name: str) -> None`: Raises `ProductionGateViolation` if `is_production()` is `True` (`production_gate.py:75-110`). Used to guard mock cryptography, debug surfaces, and insecure fallbacks.

#### `security_tiers.SecurityTierProfile` (`security_tiers.py:35-120`)
- `__init__(tier: SecurityTier, min_enforced_tier: SecurityTier)`: Initializes tier enforcement policy (`security_tiers.py:45-70`). `SecurityTier` enum values: `LOW = 1`, `BASIC = 2`, `MEDIUM = 3`, `HIGH = 4`, `CRITICAL = 5` (`:38-43`).
- `negotiate_peer_tier(offered_tier: SecurityTier) -> SecurityTier`: Compares incoming peer tier against `min_enforced_tier` (`security_tiers.py:210-260`). If `offered_tier < min_enforced_tier`, raises `AntiDowngradeRefusal` and terminates session (`:235`). Returns negotiated tier if compliant.

#### `security.validation.InputValidator` (`security/validation.py:45-210`)
- `validate_message(message: str) -> bool`: Enforces UTF-8 compliance, strips unprintable control characters, and checks maximum message length `MAX_MESSAGE_PAYLOAD = 65536` bytes (`security/validation.py:70-110`). Returns `True` if valid; raises `ValidationError` on malformed inputs (`:95`).
- `validate_callsign(name: str) -> bool`: Validates station identifier against regex `^[A-Z0-9_-]{1,64}$` (`security/validation.py:130-155`).

#### `security.integrity.CodeIntegrityVerifier` (`security/integrity.py:40-180`)
- `verify_file_hash(file_path: str, expected_sha384: str) -> bool`: Computes SHA-384 over file and compares against manifest digest (`security/integrity.py:55-90`). Returns `True` if hash matches; raises `IntegrityError` on mismatch (`:85`).
- `verify_all_modules(manifest_path: str) -> Dict[str, bool]`: Validates all registered product binaries and scripts against pinned hash manifest (`security/integrity.py:110-165`).

## 3. Data Formats and Byte Layouts

### 3.1 Security Tier Handshake Packet Layout (`security_tiers.py:140-190`)
- Tier negotiation carries a 16-byte fixed binary descriptor:
  - Protocol Version: 1 byte (`0x01`) at offset 0.
  - Enforced Tier: 1 byte (`SecurityTier` enum 1-5) at offset 1.
  - Required Posture Flags: 2 bytes uint16 bitfield at offset 2 (`0x0001` ML-KEM, `0x0002` Pacing, `0x0004` TPI).
  - Nonce: 8 bytes CSPRNG random bytes at offset 4.
  - CRC32 Checksum: 4 bytes big-endian CRC32 at offset 12.
- Arithmetic Verification:
  - Total length: $1 + 1 + 2 + 8 + 4 = 16$ bytes. Arithmetic matches code.

## 4. Algorithms and Pinned Libraries
- SHA-384: NIST FIPS 180-4. Module integrity verification provided by standard library `hashlib.sha384` (`security/integrity.py:22`).
- ML-DSA-87: NIST FIPS 204. Security policy envelope signatures provided by `oqs.dll` version 0.16.0 (`cnsa2_policy_engine.py:35`).
- AES-256-GCM: NIST SP 800-38D. Symmetric policy store encryption provided by `cryptography.hazmat.primitives.ciphers.aead.AESGCM` (`maximum_security_hardening.py:50`).

## 5. Dependencies and Hardware Requirements
- Native Operating System APIs: Win32 process mitigation calls and POSIX file system permission checks (`security/hardening.py:80-120`).
- Integrity Manifest: Requires `critical_modules.hashes` or `signed_reproducible_build_receipt.json` on disk (`security/integrity.py:45`).

## 6. Failure Behavior
- Mock crypto or debug flag used in production raises fatal `production_gate.ProductionGateViolation` (`production_gate.py:95`).
- Downgrade attack attempt raises `security_tiers.AntiDowngradeRefusal` and logs `[ANTI-DOWNGRADE ENFORCEMENT REFUSAL]` (`security_tiers.py:235`).
- Input validation failure raises `security.validation.ValidationError` (`security/validation.py:95`).
- File integrity mismatch raises `security.integrity.IntegrityError` (`security/integrity.py:85`).

## 7. Configuration and Environment Variables
- `P2P_ENV`: Execution environment name (`"production"`, `"staging"`, `"development"`). Default: `"development"` (`production_gate.py:30`).
- `P2P_PRODUCTION`: Production flag toggle (`"1"` or `"0"`). Default: `"0"` (`production_gate.py:32`).
- `P2P_MIN_TIER`: Minimum acceptable security tier for peer connections (`"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`). Default: `"BASIC"` (`security_tiers.py:55`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - Production gate fail-closed refusal of debug surfaces: verified in `tests/test_production_readiness_audit.py` (14 tests).
  - Anti-downgrade refusal during tier negotiation: verified in `tests/test_production_tier4_tactical_commands.py` (8 tests).
  - Schema validation bounds on input messages: verified in `tests/test_parser_fuzz_gates.py` (10 tests).
- NOT Covered:
  - Real-time kernel modification during active process execution (requires physical hardware root of trust).

## 9. Not Implemented / External Dependencies
- Hardware Security Module Quorum: Multi-party threshold key ceremonies for tier elevation require external physical HSMs; software fallback runs on local node (`hw_readiness.py`).

## 10. Known Limitations and Residual Risks
- Process Memory Inspection: Root/administrator users on the host machine can inspect memory via debug APIs (`OpenProcess` with `PROCESS_VM_READ`) unless VBS/HVCI kernel isolation is active.

## 11. Discrepancies
- Promotional file names and class identifiers: Filename `[banned-term-in-name]_security_enforcement.py` contains restricted terms; cataloged in `docs/audit/discrepancies.md`.

## 12. Open Questions for the Author
- Can `production_gate.py` be merged into `cnsa2_policy_engine.py` to unify all policy enforcement under a single engine?
