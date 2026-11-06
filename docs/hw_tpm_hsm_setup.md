# TPM / HSM hardware setup (Linux + Windows)

Goal: make the machine's TPM/HSM actually USED, not merely detected.
Default posture is software-only (all native probes gated off); each
section below shows how to opt a host in and how to verify it.

## Environment matrix (both OSes)

| Variable | Value | Effect |
|---|---|---|
| `P2P_ALLOW_TPM_NATIVE=1` | opt-in | Enables ALL native TPM/CNG/WMI probes. Default `0` = degraded software path, crash-free. Production TPM hosts MUST set this. |
| `P2P_FAIL_ON_SOFTWARE_FALLBACK=1` | prod | Any hardware-backend failure raises instead of falling back to software. |
| `P2P_ENABLE_TEMP_MONITOR=1` | opt-in | Enables the WMI/COM cold-boot temperature thread. Default off (native COM faults are uncatchable). |
| `P2P_REQUIRE_PINNED_KEYS=1` | prod | `NativeSecureBuffer.require_pinned()` fail-closes when `mlock`/`VirtualLock` unavailable. |
| `P2P_TPM_QUOTE=1` | opt-in | `tpm_quote.attach_quote_to_handshake()` emits quotes (needs native + AK). Peers treat missing/degraded quotes as unauthenticated unless whitelisted. |

## Linux

1. Kernel/device: need `/dev/tpmrm0` (preferred, resource manager) or
   `/dev/tpm0`. Check: `ls -l /dev/tpm*`. Add user to `tpm` group if
   permission denied (never run as root to fix perms).
2. Tooling (only if you want CLI attestation/PCR paths):
   `apt install tpm2-tools` (provides `tpm2_pcrread`, `tpm2_quote`,
   `tpm2_createprimary`). The code requests the `sha256` PCR bank
   (universally implemented); `sha3_512` banks do not exist on real TPMs.
   Set `TPM2TOOLS_TCTI=device:/dev/tpmrm0`.
3. Python bindings (only if you want FAPI paths):
   `pip install tpm2-pytss`. First use on a fresh TPM requires a ONE-TIME
   `Fapi_Provision()` (needs root, destroys existing hierarchies — never
   run per-call; the code never provisions automatically).
4. PKCS#11 tokens (YubiKey/Nitrokey/TPM2-PKCS#11): install vendor module
   (`opensc`, `tpm2-pkcs11`), point config at the `.so`
   (`/usr/lib/x86_64-linux-gnu/pkcs11/...`). Default PIN `1234` MUST be
   changed; SoftHSM entries in the search list are lab-only.
5. Verify: `P2P_ALLOW_TPM_NATIVE=1 python -c
   "from platform_hsm_interface import is_tpm_available;
   print(is_tpm_available())"` must print `True`. Then run
   `pytest test_hsm_platform.py` (mocked, no hardware needed).

What Linux actually uses when enabled: `LinuxTPMBackend` (FAPI keys under
`/HS/SRK`, quote over PCR 0,1,2,3,7), ESAPI RNG via `tpmrm0` (libsodium
stays primary RNG — TPM RNG is opportunistic), `tpm2_pcrread`/`tpm2_quote`
CLIs. No sealed-to-PCR storage yet (documented gap); file fallback stays
AES-GCM + 0600.

## Windows

1. Firmware: enable TPM 2.0 (or Intel PTT / AMD fTPM) in UEFI; confirm
   with `tpm.msc` or `Get-Tpm`. The code uses the MS Platform Crypto
   Provider via CNG — no extra driver install needed.
2. DPAPI sealing is USER scope (`CRYPTPROTECT_UI_FORBIDDEN`, no prompt);
   it does NOT roam and does NOT cover services running as another user.
   Machine-scope sealing is reserved for enterprise multi-user service deployment.
3. WMI/COM probes (`Win32_ComputerSystemProduct` UUID, `Win32_Tpm`) are
   skipped unless native is allowed; `Get-WmiObject` is gone on
   PowerShell 7 / Win11 default — UUID falls back to registry/file ID.
4. Verify: with `P2P_ALLOW_TPM_NATIVE=1`, `init_hsm()` should report
   provider `windows_cng` (not `windows_cng_file_fallback`); RSA keygen
   persists via Platform KSP (AES keys are NOT persistable there —
   routed to logged software fallback by design).

## Precedence (both OSes)

`SecureEnclaveKeyStorage`: TPM backend → PKCS#11 → software fallback
(silent unless `fail_on_software_fallback` / `P2P_FAIL_ON_SOFTWARE_FALLBACK=1`,
which raises). `get_secure_random`: libsodium → CNG/BCrypt (Windows) →
TBS TPM2_GetRandom → TPM ESAPI (Linux, `tpmrm0` first) → PKCS#11 → `secrets.token_bytes`.
Provider labels never claim hardware on fallback paths
(`*_file_fallback`, `DEGRADED_SECONDARY_SIMULATION`).

## Direct provider APIs (F-batch)

- Windows: `_windows_tbs_get_random(n)` (TPM2_GetRandom via TBS;
  the old `Tbsi_GetRandom` alias never existed and disabled TBS
  everywhere — fixed), `_windows_tbs_read_pcrs` (TPM2_PCR_Read),
  `read_ek_evidence_windows` (`Get-TpmEndorsementKeyInfo`, evidence only).
- Linux: `_read_linux_pcr_sysfs` (no exec; before `tpm2_pcrread`),
  `read_ek_certificate_linux` (`tpm2_nvread 0x01c00002`, offline only),
  `store/retrieve_key_kernel_keyring` (TPM-sealed trusted keys; fails
  honest when root/TPM/`CONFIG_TRUSTED_KEYS` missing — never mislabeled).
- Sealing honesty: `seal_secret_to_pcrs` = `software-pcr-bound`
  envelope; `seal_secret_tpm2_tools` = `tpm2-tools-sealed` (real PCR
  policy object; secret ≤128 bytes, i.e. seal DEKs).
- DPAPI: user scope default; `P2P_DPAPI_MACHINE_SCOPE=1` for service
  accounts only (any local process can unseal — disk-theft protection).
- Posture: `get_host_security_posture()` (SecureBoot, TPM, VBS/HVCI,
  lockdown) + `verify_host_posture` deployment gate (WARN lab,
  FAIL prod).

## Troubleshooting

## Unified Hardware Credential Policy (P2-09)

To ensure cryptographic compliance under DoD 5210.41M and NIST SP 800-161:
1. **Operator PIN Precedence:**
   - Explicit CLI parameter (`--token1-pin`, `--token2-pin`) > Environment variables (`P2P_HSM_PIN`, `P2P_PKCS11_PIN`, `P2P_TOKEN1_PIN`).
   - In production mode (`P2P_PRODUCTION=1`), default or hardcoded PINs (`1234`, `123456`) are strictly rejected fail-closed.
2. **Lockout Policy & Retries:**
   - Cryptographic smartcards enforce hardware retry caps (typically 3 attempts). Exceeding this limit returns `CKR_PIN_LOCKED`, locking the cryptographic silicon until physical security officer unblocking.
3. **Zero-Disk Secret Custody:**
   - Authentication PINs and private keys are held in volatile memory locked with `mlock` (Linux) or `VirtualLock` (Windows) via `StackSecretBuffer` / `LockedKey32`. Secrets are zeroized immediately upon drop (`ZeroizeOnDrop`) and are never written to disk or audit logs.

- `ImportError: DLL load failed ... digital signature` for
  `destroyer_core._native`: stale maturin install in site-packages;
  rebuild with `maturin develop -r -m rust_data_plane/Cargo.toml`.
- `Win32 exception ... IUnknown` in old runs: fixed by gating
  (2026-09-19); never re-enable unguarded COM in threads/`__del__`.
- `tpm2_pcrread` empty output: bank name wrong — code now uses `sha256`.
- Slow first key ops on Windows: McEliece-8192128f keygen is seconds;
  deferred to first use by design.

---

## Hardware Dependencies & Physical Isolation (2026/2027 Production Baseline)

### 1. Host Hardening & Hypervisor Isolation (UEFI Secure Boot, VBS, HVCI, DMA)
To eliminate pre-flight warnings (`SecureBoot DISABLED`, `VBS=False`, `HVCI=False`) and satisfy fail-closed production gates:
- **Windows Deployment Hosts**:
  1. Enable UEFI Secure Boot and IOMMU (Intel VT-d / AMD-Vi) in the motherboard firmware.
  2. Run the automated DISA STIG / Device Guard configuration script:
     ```powershell
     powershell -ExecutionPolicy Bypass -File scripts/apply_host_hardening_windows.ps1
     ```
  3. Verify with `python scripts/verify_host_hardening.py --strict`.
- **Linux Deployment Hosts**:
  1. Enable IOMMU and Kernel Lockdown via GRUB:
     ```bash
     sudo bash scripts/apply_host_hardening_linux.sh
     ```
  2. Verify with `python scripts/verify_host_hardening.py --strict`.

### 2. TPM 2.0 Monotonic Counter (Index `0x01800001`) Provisioning
TCG standard handle `0x01800001` provides a hardware-enforced rollback barrier in discrete TPM 2.0 silicon (`nt=counter`), permanently eliminating file-based `.nvck` state sidecars:
- **Provision the Counter**:
  ```bash
  python scripts/provision_tpm2_nv_counter.py --provision --index 0x01800001
  ```
  Or via `tpm2-tools`:
  ```bash
  tpm2_nvdefine -C o -s 8 -a "ownerread|ownerwrite|authread|authwrite|nt=counter" 0x01800001
  ```
- **Verify Monotonic Increment**:
  ```bash
  python scripts/provision_tpm2_nv_counter.py --verify --index 0x01800001
  ```
- **Bind Data Plane**:
  Set environment variable `P2P_TPM_NV_INDEX=0x01800001`.

### 3. DoD 5210.41M Two-Person Integrity (TPI) Hardware Tokens
In production (`P2P_PRODUCTION=1`), software simulation is refused fail-closed (`AuthorizationError`). Operations require two physical cryptographic tokens (YubiKey 5 FIPS / Nitrokey HSM) across distinct USB CCID slots:
- **Attach Physical Tokens**: Connect Officer 1 and Officer 2 hardware smartcards to distinct USB ports.
- **Verify Dual-Token Posture**:
  ```bash
  python scripts/verify_hardware_tokens.py --strict
  ```

### 4. Physical TEMPEST & Optical Data Diode Boundaries
- **TEMPEST SDIP-28/29 Accreditation**: Stations processing TOP SECRET data in NATO Zone 0/1 must be housed in accredited Level A/B enclosures. Certification records are managed in `config/tempest_accredited_registry.json`.
- **Certified Simplex Optical Data Diodes**: Cross-domain transfers must traverse Common Criteria EAL4+ / EAL7+ certified hardware simplex diodes (Owl Cyber Defense / Fox-IT) using Cauchy Reed-Solomon (K=8, M=4) forward error correction. Device records are managed in `config/data_diode_certified_registry.json`.
- **Run Master Isolation Verification**:
  ```bash
  python scripts/verify_physical_isolation.py
  ```
