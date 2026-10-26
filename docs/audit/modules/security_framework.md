# Module Audit: security_framework

## 1. Overview and Scope
The `security_framework` module establishes the core security policy architecture, operational execution gates, tiered security parameters, anti-downgrade controls, input schema validation, runtime integrity checking, host hardening policies, and security fault recovery across the node.

The module comprises 16 product files totaling 8,889 verified lines of Python code:

| File Name | Lines | Verified Purpose | Primary Classes / Interface |
| :--- | :--- | :--- | :--- |
| `enhanced_security_features.py` | 678 | Provides configurable feature toggles and guards for advanced security options | `EnhancedSecurityFeatures`, `SecurityFeatureToggle` |
| `maximum_security_hardening.py` | 677 | Enforces strict host hardening parameters and disables debug capabilities | `MaximumSecurityHardening`, `HardeningProfile` |
| `[banned-term-in-name]_security_enforcement.py` | 213 | Validates operational parameters against high-assurance baseline requirements (filename note: code embeds prohibited term) | `SecurityEnforcer`, `PolicyValidationEngine` |
| `production_gate.py` | 189 | Enforces fail-closed validation gates preventing mock crypto or debug bypasses in production | `is_production`, `fail_if_production`, `ProductionGateViolation` |
| `security/__init__.py` | 24 | Package initialization exporting security management interfaces | Package init |
| `security/graceful_degradation.py` | 337 | Controls degradation behavior when optional platform hardware is absent | `GracefulDegradationManager`, `DegradationPolicy` |
| `security/hardening.py` | 445 | Sets host operating system process mitigations and execution policies | `HostHardening`, `ProcessMitigations` |
| `security/integrity.py` | 280 | Compares runtime code and configuration files against cryptographic hashes | `IntegrityChecker`, `CodeIntegrityVerifier` |
| `security/manager.py` | 54 | Unified facade coordinating validation, hardening, monitor, and degradation components | `SecurityManager` |
| `security/monitor.py` | 366 | Collects and aggregates security violation alerts across subsystem components | `SecurityMonitor`, `ViolationAlert` |
| `security/validation.py` | 885 | Implements schema and regular-expression input validation rules | `InputValidator`, `SchemaValidator` |
| `security_hardening_manager.py` | 1,466 | Applies operating system configuration hardening and registry protections | `SecurityHardeningManager`, `SystemHardener` |
| `security_recovery_manager.py` | 718 | Orchestrates component recovery workflows following security faults | `SecurityRecoveryManager`, `RecoveryAction` |
| `security_tiers.py` | 1,715 | Defines operational security tiers (LOW to CRITICAL) and anti-downgrade guards | `SecurityTier`, `SecurityTierProfile`, `AntiDowngradeRefusal` |
| `security_validation_orchestrator.py` | 518 | Coordinates validation passes across cryptographic and protocol modules | `SecurityValidationOrchestrator` |
| `security_validator.py` | 324 | Validates cryptographic parameters and certificates against policy | `SecurityValidator` |

---

## 2. Architecture and Subsystem Mechanics

### 2.1 Production Gating and Fail-Closed Validation
In `production_gate.py:5-120`:
- **Production Detection (`production_gate.py:25-45`):** `is_production()` evaluates multiple triggers: environment variable `P2P_ENV == "production"`, `P2P_PRODUCTION == "1"`, or configuration parameter `"production": true`.
- **Fail-Closed Execution (`production_gate.py:75-110`):**
  - Rejects mock implementations: functions such as `fail_if_production(feature_name)` raise a fatal `ProductionGateViolation` if mock cryptography, unauthenticated endpoints, default test keys, or debug shims execute in production mode.
  - Rejects unencrypted metadata: in production, `secure_message_serializer.py:220` requires an AEAD envelope key to prevent plaintext sender IDs or sequence numbers on the wire.

### 2.2 Operational Security Tiers and Anti-Downgrade Guards
In `security_tiers.py`:
- **Tier Definitions (`security_tiers.py:35-80`):**
  - `LOW`: Baseline point-to-point datalink with AES-256-GCM AEAD.
  - `BASIC`: Adds post-quantum key encapsulation (ML-KEM-1024) and memory protection (`VirtualLock` + DPAPI).
  - `MEDIUM`: Adds Signal SPQR Triple Ratchet forward secrecy and post-compromise security.
  - `HIGH`: Adds DAITA traffic camouflage (Poisson chaff) and 64-bit anti-replay bitmask windows.
  - `CRITICAL`: Enforces Two-Person Integrity (TPI) dual-operator authorization, cross-domain isolation guards, and emergency multi-pass memory zeroization.
- **Anti-Downgrade Refusal (`security_tiers.py:210-260`):**
  - Peer handshake negotiations compare the offered operational tier against the local minimum enforced tier (`min_enforced_tier`).
  - If a peer attempts to negotiate a lower security level (e.g. initiating LOW when local minimum is CRITICAL), the engine triggers an `AntiDowngradeRefusal`, logs `[ANTI-DOWNGRADE ENFORCEMENT REFUSAL]`, and aborts the connection. Upward tier transitions are permitted.

### 2.3 Post-Quantum Suite Enforcement
In the security enforcement module (`[banned-term-in-name]_security_enforcement.py`):
- **Algorithm Allowlist:** Enforces CNSA 2.0 / FIPS requirements:
  - Key Encapsulation: pure ML-KEM-1024 (`FIPS 203`).
  - Digital Signatures: pure ML-DSA-87 (`FIPS 204`) or hybrid ML-DSA-87 + SLH-DSA-256f (`FIPS 205`).
  - Symmetric AEAD: AES-256-GCM or ChaCha20-Poly1305 (256-bit keys minimum).
  - Hash Functions: SHA3-512, SHA-384, or BLAKE2b-512.
- **Legacy Rejection:** Explicitly rejects classical RSA, DSA, and standard ECC curves (e.g. secp256r1) when operating in post-quantum enforcement mode, preventing algorithmic downgrade.

### 2.4 Unified Security Management Facade
In `security/manager.py:20-54`:
- Coordinates sub-components under `self.orchestrator.security`:
  - `self.hardening`: Manages OS-level protections via `security/hardening.py`.
  - `self.integrity`: Validates file and configuration digests via `security/integrity.py`.
  - `self.monitor`: Aggregates active alert feeds via `security/monitor.py`.
  - `self.validation`: Sanitizes inputs and chat commands via `security/validation.py`.
  - `self.graceful_degradation`: Regulates non-production fallbacks via `security/graceful_degradation.py`.

### 2.5 Input Schema and Command Sanitization
In `security/validation.py`:
- `InputValidator.validate_message(message: str) -> bool`: Checks message byte length (max 64KB) and scans for control characters and malformed UTF-8 sequences.
- `InputValidator.validate_command(command: str) -> bool`: Enforces command syntax rules, rejecting shell metacharacters (`;`, `&`, `|`, `$`, backticks) to prevent command injection.

### 2.6 Graceful Degradation and Host Hardening
- **Graceful Degradation (`security/graceful_degradation.py`):**
  - Allows non-critical features (such as hardware temperature sensors or optional GUI themes) to degrade gracefully when platform drivers are missing.
  - Prohibits cryptographic degradation in production: attempts to degrade cryptographic algorithms or bypass signature checks raise unrecoverable errors.
- **Host Hardening (`security_hardening_manager.py`, `maximum_security_hardening.py`):**
  - Configures Windows process mitigation policies: Data Execution Prevention (DEP), Control Flow Guard (CFG), Arbitrary Code Guard (ACG), and restricted handle creation.

---

## 3. Interfaces and Public API Surface

### 3.1 `production_gate` (`production_gate.py`)
- `is_production() -> bool`: Returns True if node is in production mode.
- `fail_if_production(feature_name: str) -> None`: Raises `ProductionGateViolation` if called in production.

### 3.2 `SecurityTiers` (`security_tiers.py`)
- `get_tier_profile(tier: SecurityTier) -> SecurityTierProfile`: Returns requirement profile for given tier.
- `validate_tier_transition(current: SecurityTier, target: SecurityTier) -> bool`: Verifies transition adheres to anti-downgrade policy.

### 3.3 `InputValidator` (`security/validation.py`)
- `validate_message(msg: str) -> bool`: Validates chat message content.
- `validate_command(cmd: str) -> bool`: Validates slash command format.
- `validate_peer_id(peer_id: str) -> bool`: Validates 64-character hexadecimal peer ID.

### 3.4 `SecurityRecoveryManager` (`security_recovery_manager.py`)
- `handle_security_fault(fault_type: str, context: dict) -> bool`: Executes automated recovery actions after a fault.

---

## 4. Test Evidence and Verification Results

### 4.1 Passing Test Suites
Audit verification executed the following test suites directly verifying security framework components:

1. **Production Gate, DHT Proof-of-Work Floor, and Exploit Regressions:**
   - Command: `pytest tests/test_production_gate.py tests/test_dht_pow_floor.py tests/test_exploit_regressions.py -q`
   - Result: 150 passed in 22.77s.
   - Verified behaviors:
     - 132 tests in `test_production_gate.py` asserting fail-closed behavior on mock cryptography, development keys, unverified certificates, and test bypasses.
     - DHT proof-of-work difficulty floor enforcement in `test_dht_pow_floor.py`.
     - Regression tests in `test_exploit_regressions.py` verifying legacy cipher rejection and algorithmic binding.
2. **Security Tiers and Anti-Downgrade Testing:**
   - Command: `pytest tests/test_production_tier4_tactical_commands.py -q`
   - Verified behaviors:
     - Inspection of active tier status via `/tier` command.
     - Upward tier transition from BASIC to CRITICAL.
     - Anti-downgrade refusal blocking downward transition proposals (CRITICAL to LOW).

---

## 5. Discrepancies, Limitations, and Technical Debt

1. **Promotional Terminology in Code Filename:**
   - Source file `[banned-term-in-name]_security_enforcement.py` embeds prohibited terminology directly in its filename. Cataloged for `docs/audit/discrepancies.md`.
2. **Dead and Unreferenced Code Modules:**
   - `security_validation_orchestrator.py` (518 lines) and `security_validator.py` (324 lines) have zero unit test references in the test directory, acting as legacy wrappers superseded by `security/validation.py`.
3. **Fragmented Hardening Implementations:**
   - Host hardening logic is split across three overlapping files:
     - `security/hardening.py` (445 lines): Modular hardening interface for orchestrator.
     - `maximum_security_hardening.py` (677 lines): Static profile enforcer.
     - `security_hardening_manager.py` (1,466 lines): Direct Win32 API process mitigation manager.
   - These files duplicate mitigation definitions (DEP/ASLR/CFG flags) without unified configuration inheritance.

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
