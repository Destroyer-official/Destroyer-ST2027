# Module Documentation: Host Runtime and Platform Attestation Subsystem (`host_runtime_attestation`)

## 1. Module Name & Purpose

- **Module Name:** `host_runtime_attestation`
- **Subsystem Classification:** Hardware Root-of-Trust, Platform Attestation, seL4 Microkernel Domain Isolation, Native Runtime Security, and TEE Interfacing
- **Files in Module (23 files, 6,204 verified lines):**
  - `hw_readiness.py` (423 lines)
  - `sel4_baremetal/Cargo.lock` (15 lines)
  - `sel4_baremetal/Cargo.toml` (14 lines)
  - `sel4_baremetal/black_domain/Cargo.toml` (7 lines)
  - `sel4_baremetal/black_domain/src/main.rs` (44 lines)
  - `sel4_baremetal/crypto_domain/Cargo.toml` (7 lines)
  - `sel4_baremetal/crypto_domain/src/main.rs` (74 lines)
  - `sel4_baremetal/red_domain/Cargo.toml` (7 lines)
  - `sel4_baremetal/red_domain/src/main.rs` (51 lines)
  - `sel4_microkit/system.xml` (37 lines)
  - `sel4_microkit_manifest.py` (265 lines)
  - `[ISOLATED]_black_domain.py` (129 lines)
  - `[ISOLATED]_crypto_domain.py` (493 lines)
  - `[ISOLATED]_red_domain.py` (87 lines)
  - `[ISOLATED]_sel4_appliance.py` (115 lines)
  - `tee_manager.py` (1,459 lines)
  - `ts_attest.py` (249 lines)
  - `ts_hw_layer.py` (1,393 lines)
  - `ts_rt/Cargo.lock` (7 lines)
  - `ts_rt/Cargo.toml` (13 lines)
  - `ts_rt/build.rs` (11 lines)
  - `ts_rt/src/lib.rs` (408 lines)
  - `ts_runtime.py` (896 lines)

- **Primary Technical Purpose:**
  The `host_runtime_attestation` module provides host platform integrity verification, platform attestation (IETF RATS / RFC 9334), hardware custody enforcement, seL4 microkernel domain separation, native deterministic memory security (`ts_rt`), and Trusted Execution Environment (TEE) interfacing. It validates firmware Secure Boot, Windows Virtualization-Based Security (VBS) and Hypervisor-Protected Code Integrity (HVCI), binds device identity keys to physical TPM 2.0 chips, separates plaintext (Red), cryptographic (Crypto), and network (Black) processing domains, and allocates page-locked non-swappable memory buffers.

---

## 2. Public Interface

### 2.1. `ts_attest.py`
- **Classes:**
  - `AttestError(Exception)` (`:35`): Base attestation evaluation exception.
  - `AttestationResult` (`:55`): Dataclass encapsulating evaluation outcome, appraisal timestamp, and verified claims.
- **Exported Functions:**
  - `produce_evidence(nonce: bytes) -> Dict[str, Any]` (`:75`): Collects local platform PCR claims, binds fresh nonce, and signs envelope via TPM device key.
  - `appraise_evidence(evidence: Dict[str, Any], expected_nonce: bytes, max_age_s: float = 300.0) -> AttestationResult` (`:150`): Authenticates TPM signature and validates nonce freshness.
  - `evaluate_policy(claims: Dict[str, Any], required_posture: str) -> bool` (`:190`): Evaluates platform posture claims against policy rules.

### 2.2. `ts_hw_layer.py`
- **Classes:**
  - `TSError(Exception)`, `TSRequiredError(TSError)` (`:45-55`)
  - `CustodyAttestation` (`:120`): Dataclass recording hardware custody backend (TPM 2.0 / PKCS#11).
  - `ZeroizeMesh` (`:310`): Emergency zeroization coordinator triggering memory scrubbing upon tamper events.
  - `TamperOrder` (`:260`): Cryptographically authenticated tamper/zeroization order.
- **Exported Functions:**
  - `probe_hardware_custody() -> CustodyAttestation` (`:420`): Detects TPM 2.0 or PKCS#11 hardware keys.
  - `require_hardware_custody()` (`:460`): Aborts fail-closed if hardware custody is absent.
  - `check_fips_provider() -> bool` (`:160`): Probes OpenSSL for loaded FIPS providers.
  - `check_cmvp_record(record_path: Optional[str] = None) -> bool` (`:210`): Parses CMVP compliance record.

### 2.3. `ts_runtime.py` & Native `ts_rt`
- **Classes:**
  - `LockedBuffer` (`:180`): Memory-locked buffer wrapper wrapping `tsrt_alloc_locked` and zeroizing on release.
  - `NativeReplay` (`:270`): Anti-replay bitmap window backed by `tsrt_replay_check_mark`.
- **Exported Functions:**
  - `load_native() -> ctypes.CDLL` (`:75`): Loads compiled `ts_rt` dynamic library (`ts_rt.dll` or `libts_rt.so`).
  - `read_platform_posture() -> Dict[str, Any]` (`:380`): Queries OS Device Guard, HVCI, VBS, and Code Integrity status.

### 2.4. `hw_readiness.py`
- **Classes & Functions:**
  - `Verdict(Enum)` (`:35`): Status values (`HAVE`, `MISSING`, `UNKNOWN`).
  - `is_admin() -> bool` (`:55`): Checks if process possesses administrative privileges.
  - `ensure_admin(elevate: bool = True) -> bool` (`:90`): Relaunches process elevated via UAC if needed.
  - `check_secure_boot() -> Tuple[Verdict, str]` (`:140`): Queries UEFI Secure Boot status.
  - `check_vbs_hvci() -> Tuple[Verdict, str]` (`:180`): Queries VBS and HVCI hypervisor integrity.

### 2.5. `tee_manager.py`
- **Classes:**
  - `TEEManager` (`:720`): High-level TEE coordinator selecting available hardware backends.
  - `IntelSGXBackend` (`:280`), `ARMTrustZoneBackend` (`:410`), `AMDSEVBackend` (`:540`): Concrete hardware TEE adapters.

### 2.6. seL4 Subsystem
- `sel4_microkit_manifest.py`: `SeL4MicrokitManifest` (`:120`) validates memory maps and channel topologies.
- `[ISOLATED]_sel4_appliance.py`: `[ISOLATED]ApplianceNode` (`:45`) ties together red, crypto, and black domain instances.
- `[ISOLATED]_red_domain.py`, `[ISOLATED]_crypto_domain.py`, `[ISOLATED]_black_domain.py`: Python reference models for domain separation.
- `sel4_baremetal/`: Rust microkit crates (`red_domain`, `crypto_domain`, `black_domain`).

---

## 3. Data Formats & Byte Layouts

### 3.1. `ts_attest.py` Canonical Evidence Wire Format
- Format: Canonical JSON dictionary:
  - `v`: 1 (version uint8)
  - `nonce`: Hex string representing 32-byte fresh challenge nonce.
  - `ts`: Float timestamp (seconds since Unix epoch).
  - `kid`: Key identifier string of TPM device key.
  - `claims`: Sub-dictionary containing `device_id`, `pcr` dictionary (PCR index to hex hash), and `posture`.
  - `sig`: Hex string representing ECDSA-P256 signature (64 bytes raw: $r$ 32B + $s$ 32B).

### 3.2. `ts_rt/src/lib.rs` Native Memory & Replay Layouts
- **Page-Locked Allocation (`tsrt_alloc_locked`):**
  - Invokes `VirtualAlloc(MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)` followed by `VirtualLock` on Windows.
  - Invokes `mmap(PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)` followed by `mlock` on POSIX.
  - Prevents pages from being paged out to swapfiles or hibernation storage.
- **Bitmap Anti-Replay Structure (`tsrt_replay_check_mark`):**
  - Window Size: 1024 sequence numbers (128 bytes bitmap = 1024 bits).
  - Header: Base sequence counter (uint64, 8 bytes).
  - Check logic: Drops packets with sequence numbers older than base $- 1024$; checks and sets bit within active window.

### 3.3. `sel4_microkit/system.xml` Memory Regions
- Shared Ring Buffers:
  - `red_crypto_ring`: Physical size `0x10000` (65,536 bytes = 64 KB), page size `0x1000` (4096 bytes = 4 KB).
  - `crypto_black_ring`: Physical size `0x10000` (65,536 bytes = 64 KB), page size `0x1000` (4096 bytes = 4 KB).
- Non-Overlapping Access Constraints:
  - `red_domain`: Read/Write access to `red_crypto_ring`; ZERO access to `crypto_black_ring`.
  - `black_domain`: Read/Write access to `crypto_black_ring`; ZERO access to `red_crypto_ring`.
  - `crypto_domain`: Read/Write access to both rings, serving as the sole cryptographic transformation conduit.

---

## 4. Algorithms & Pinned Libraries

1. **IETF RATS Architecture (RFC 9334):**
   - Platform attestation roles: Attester (`ts_attest.py:produce_evidence`), Verifier / Relying Party (`ts_attest.py:appraise_evidence`).
2. **ECDSA-P256 (NIST FIPS 186-5):**
   - TPM 2.0 hardware-backed device attestation keys created via `cng_platform.py`.
3. **Volatile Memory Scrubbing:**
   - Volatile compiler-barrier zeroization (`ts_rt/src/lib.rs:volatile_zero`) preventing compiler dead-store elimination.
4. **MILS (Multiple Independent Levels of Security):**
   - Enforced by seL4 microkernel capability spaces and memory region mapping.

---

## 5. Dependencies

### 5.1. External Dependencies
- `ctypes`: Foreign function interface to `ts_rt.dll` / `libts_rt.so` and Windows system DLLs.
- `json`, `socket`, `struct`, `hashlib`, `hmac`: Standard library serialization and verification.
- Rust Compiler (`cargo` / `rustc`): Required to build `ts_rt` and `sel4_baremetal` components.

### 5.2. Internal Repository Dependencies
- `cng_platform.py`: Provides TPM 2.0 key handles for attestation signatures.
- `platform_hsm_interface.py`: Probed for hardware custody.

---

## 6. Failure Behavior

1. **`ts_attest.py`:**
   - Tampered Evidence: If any field in the evidence envelope is altered, signature verification fails and raises `AttestError("evidence signature verification failed")`.
   - Stale Evidence: If evidence age exceeds `max_age_s` (default: 300 seconds), raises `AttestError("evidence timestamp expired")`.
   - Unanchored Keys: If device public key is not enrolled in authorized trust list, raises `AttestError("device key not in authorized trust bundle")`.

2. **`ts_hw_layer.py`:**
   - Missing Hardware Custody: If hardware custody is required and neither TPM nor HSM answers, raises `TSRequiredError` and aborts session.
   - Tamper Detection: If a tamper event is signaled to `ZeroizeMesh`, it immediately invokes key zeroization callbacks, clears registered memory buffers, and sets status to zeroized.

3. **`[ISOLATED]_crypto_domain.py`:**
   - Dual-Rail Verification Mismatch: If primary and secondary signature verifications produce divergent results, raises `FaultInjectionDetectedError`.

---

## 7. Configuration / Environment Variables

| Variable Name | Defined In File | Default Value | Technical Purpose & Impact |
|:---|:---|:---|:---|
| `P2P_LAB_MODE` | `ts_attest.py:40` | `0` | If set to `1`, permits software simulated attestation keys for test environments. |
| `P2P_RED_BIND` | `ts_hw_layer.py:110` | `127.0.0.1:5001` | IP address and port binding for isolated Plaintext Red domain. |
| `P2P_BLACK_BIND` | `ts_hw_layer.py:115` | `0.0.0.0:5002` | IP address and port binding for Ciphertext Black network domain. |
| `P2P_FIPS_RECORD` | `ts_hw_layer.py:215` | None | Filepath to CMVP validation metadata JSON file. |
| `P2P_TEMPEST_REGISTRY` | `ts_hw_layer.py:250` | None | Filepath to TEMPEST shielding compliance registry. |
| `P2P_TS_CLASS` | `ts_hw_layer.py:95` | None | Classification string to enforce during session startup. |
| `P2P_TS_ZONE` | `ts_hw_layer.py:100` | None | TEMPEST zone containment string. |
| `P2P_PLATFORM_WAIVER` | `ts_runtime.py:140` | None | Cryptographic operator waiver string overriding missing hardware gates. |
| `P2P_TS_RT_LIB` | `ts_runtime.py:80` | None | Absolute filepath override for compiled `ts_rt` native library. |

---

## 8. Tests Covered & Not Covered

### 8.1. Tests Covered (Directly Executed and Verified)
- `tests/test_ts_hw_layer.py` (14 passed in 1.4s):
  - Validates tamper injection refusal, immutable buffer rejection, unknown role refusal, diode parameter enforcement, CNG TPM non-export proof, custody tier reporting, and hardware gating.
- `tests/test_ts_attest.py` (8 passed in 0.5s):
  - Validates signed evidence roundtrip, tampered evidence rejection, stale evidence rejection, policy evaluation, envelope validation, and unanchored key refusal.
- `tests/test_hw_readiness.py` (23 passed in 1.8s):
  - Validates missing hardware reporting, administrator elevation handling, Secure Boot detection, VBS/HVCI detection, and CLI gate wiring.
- `tests/test_sel4_[ISOLATED]_appliance.py` (9 passed in 8.9s):
  - Validates seL4 Microkit manifest MILS invariants, triple hybrid KEX roundtrip, dual-rail fault injection defense, anti-replay window, appliance node messaging, and scorched-earth emergency zeroization.

### 8.2. Not Covered / Zero Direct Tests
- `sel4_baremetal/` native Rust target compilation: Tested via Python reference twin (`[ISOLATED]_sel4_appliance.py`); baremetal compilation requires target seL4 cross-compiler toolchains.

---

## 9. Not Implemented / Stubs

1. **Baremetal seL4 Microkernel Target Execution:**
   - `sel4_baremetal/` contains the native Rust source code (`main.rs`) and cargo manifests for running as an seL4 microkit root task. In the current workspace, testing and execution take place via the Python reference models (`[ISOLATED]_red_domain.py`, `[ISOLATED]_crypto_domain.py`, `[ISOLATED]_black_domain.py`, `[ISOLATED]_sel4_appliance.py`).
2. **CMVP Certificate Absence:**
   - `docs/FIPS_140_3_SECURITY_POLICY.md:13` explicitly notes: "NO CMVP CERTIFICATE EXISTS. This document supports future validation". Code checking CMVP records (`check_cmvp_record`) verifies local metadata schemas rather than active NIST certificates.

---

## 10. Known Limitations

1. **Administrator Elevation Requirement on Windows:**
   - Windows security APIs (reading UEFI Secure Boot variables via `GetFirmwareEnvironmentVariableW`, querying WMI DeviceGuard HVCI status, opening TPM TBS context) require elevated administrator privileges. Non-elevated execution reports `UNKNOWN` for these checks.
2. **TEE Server Dependency:**
   - Hardware TEE quote validation (Intel SGX, AMD SEV) requires remote attestation server verification, which is unavailable in air-gapped deployments without on-premises caching proxies.

---

## 11. Discrepancies

1. **Promotional Headers in Hardware Layer Comments:**
   - `ts_hw_layer.py:3-10` and `[ISOLATED]_sel4_appliance.py:3-8` contain uppercase operational classifications and non-technical adjectives (cataloged in `docs/audit/discrepancies.md`).
2. **CMVP Compliance Claims vs Policy Disclaimer:**
   - Code comments mention FIPS 140-3 validation, whereas `docs/FIPS_140_3_SECURITY_POLICY.md` plainly states that no certificate exists.

---

## 12. Open Questions

1. **seL4 Target Hardware Platform:**
   - What specific hardware boards (e.g., Sabre Lite i.MX6, Raspberry Pi 4, Odroid-C4) are targeted for baremetal deployment of `sel4_baremetal/`?
2. **Native Runtime Binary Distribution:**
   - How are `ts_rt.dll` and `libts_rt.so` compiled and distributed across deployment images that lack Cargo/Rust toolchains?

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
