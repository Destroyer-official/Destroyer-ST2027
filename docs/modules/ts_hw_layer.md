# Module: `ts_hw_layer.py` & `cng_platform.py` — Hardware & Physical Security

[Back to Documentation Index](../README.md) | [System Architecture](../ARCHITECTURE.md)

This module implements **Pillar 1: Hardware & Physical Security** for the 2027 Top-Secret transmission pipeline. It enforces physical cryptographic boundaries, hardware-rooted key non-exportability, network interface isolation, and unmaskable platform zeroization.

---

## 1. Core Source Files & Responsibilities

| Source File | Lines | Primary Security Responsibilities |
|---|---|---|
| [`ts_hw_layer.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_hw_layer.py) | ~1,100 | OpenSSL FIPS provider probe, RED/BLACK interface separation, TEMPEST registry, optical data diode framing, zeroization mesh. |
| [`cng_platform.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cng_platform.py) | ~250 | Microsoft Windows Cryptography API: Next Generation (CNG) TPM 2.0 non-exportable hardware key custody. |

---

## 2. Key Subsystems & Implementations

### 2.1. OpenSSL FIPS Provider Live Dynamic Probe (`require_fips_module`)
- **Mechanism:** Direct C-ABI dynamic interrogation via `ctypes` (`libcrypto-3.dll` on Windows / `libcrypto.so` on Linux).
- **Probed Symbols:** `OSSL_PROVIDER_load`, `OSSL_PROVIDER_is_available`, `OSSL_PROVIDER_available`, `FIPS_mode`.
- **Enforcement:** In production (`P2P_PRODUCTION=1`), fails closed immediately if the validated OpenSSL FIPS provider (CMVP Certificate #4985 family) cannot be dynamically loaded or verified active.

### 2.2. Windows CNG TPM 2.0 Non-Exportable Key Storage (`cng_platform.py`)
- **Mechanism:** Integrates with `ncrypt.dll` using the Microsoft Platform Crypto Provider (`MS_PLATFORM_CRYPTO_PROVIDER`).
- **Flags Enforced:**
  - `NCRYPT_MACHINE_KEY_FLAG`: Key resides in local machine TPM hierarchy.
  - `NCRYPT_PERSISTENT_KEY_FLAG`: Enforces storage within TPM non-volatile RAM.
  - Prohibits exportable key policy: Private keys cannot be extracted from the silicon enclosure by design.
- **Fail-Closed Fallback:** In the absence of an active TPM chip or administrator privileges, the provider logs explicit degradation diagnostics and raises `HardwareSecurityError`.

### 2.3. RED/BLACK Interface Separation (`verify_red_black_separation`)
- **Doctrinal Alignment:** NSA/CSS Policy Manual 3-16 and DoD cryptographic enclave zoning.
- **Mechanism:** Inspects host network adapters via `psutil.net_if_addrs()` and route tables.
- **Enforcement:**
  - Enforces that plain RED traffic (internal classified data) and encrypted BLACK traffic (external transport) traverse distinct, physically separated network interface cards (NICs).
  - Flags any interface bridging or shared routing gateways as an immediate isolation violation (`REDBlackIsolationError`).

### 2.4. NATO SDIP-27/28/29 TEMPEST Enclave Verification
- **Mechanism:** Verifies cryptographic facility shielding records against the host hardware configuration.
- **Validation:** Validates that the node is executing within an accredited RF-attenuated Faraday enclosure with filtered power and uncompromised physical perimeter controls.

### 2.5. CC EAL-Evaluated Optical Data Diode Simplex Framing
- **Mechanism:** Software simplex enforcement layer emulating physical unidirectional fiber-optic links (severed receive photodiode on transmitter, severed transmit laser on receiver).
- **Enforcement:**
  - Unidirectional UDP framing rejecting all bidirectional control sockets.
  - Ingress filters discard any packet attempting to emit a reverse ACK/NACK channel.

### 2.6. Multi-Trigger Zeroization Mesh
- **Triggers:**
  - Hardware chassis intrusion switch detection.
  - Cryptographic self-test failure (`SelfTestError`).
  - Out-of-bounds temperature / bus interposition alert.
  - Operator emergency zeroization command (`/zeroize`).
- **Sanitization Protocol:**
  - Overwrites active RAM keys with zero patterns using volatile memory compiler fences (`sodium_memzero` and `ts_rt` volatile wipe).
  - Invalidates active TPM session handles.
  - Destroys ephemeral and persistent credential vaults.

---

## 3. Test Coverage

- **Suite:** [`test_ts_hw_layer.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/test_ts_hw_layer.py)
- **Pass Rate:** **33 of 33 tests passing (100%)**
- **Tested Behaviors:** FIPS provider load/fail logic, CNG TPM 2.0 key operations, RED/BLACK interface validation, TEMPEST registry parser, optical diode simplex frame flow, and zeroization mesh triggers.
