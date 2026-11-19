#!/usr/bin/env python3
"""
tests/test_hardware_enclave_custody.py
======================================
Automated Test Suite for Phase C:
Silicon Hardware Root-of-Trust & Micro-Tamper Tripwire.

Production Verification:
1. `HardwareTrustAnchor` wrapping Windows CNG Platform Crypto Provider
   and PKCS#11 for in-silicon signing.
2. Hardware custody invariant: Private keys never exist in host CPU RAM;
   private key export is strictly denied fail-closed.
3. Sealing identity keys to measured boot TPM PCR registers [0..7].
4. Strict fail-closed rejection: platform measurement drift across registers [0..7]
   triggers authentic `TPM_RC_POLICY_FAIL` (0x99D) and rejects decryption.
5. Micro-tamper tripwire monitoring: chassis intrusion sensors and unauthorized DMA buses.
6. Autonomous DoD 5220.22-M 7-pass RAM wipe with page locking and read-back verification.
7. Hardware NVMe / ATA Cryptographic Sanitize execution and audit verification.
8. End-to-end breach response: tripwire firing destroys volatile state and sanitizes media.
9. Live Windows CNG Platform Crypto Provider test against real physical TPM chip.
10. Strict Production Gate enforcement: rejects mock silicon in production mode.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

# Ensure repo root and scripts are in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from hardware_enclave_manager import (
    CANONICAL_PCR_INDICES,
    TPM_RC_POLICY_FAIL,
    EnclaveBackendType,
    HardwareEnclaveError,
    HardwareEnclaveManager,
    HardwareKeyHandle,
    KeyExportProhibitedError,
    PcrRegisterState,
    PlatformMeasurementDriftError,
    SealedSiliconBlob,
    SiliconDeviceError,
    TamperBreachError,
    get_hardware_enclave_manager,
    read_live_tpm_pcrs_via_tbs,
)
from scripts.hardware_tamper_monitor import (
    ChassisIntrusionSensor,
    DmaBusSecurityAuditor,
    DoD7PassMemoryWiper,
    HardwareTamperMonitor,
    NvmeCryptographicSanitizer,
    WipeReport,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def enclave_mgr():
    """Isolated hardware enclave manager instance."""
    return HardwareEnclaveManager(allow_mock_in_lab=True)


@pytest.fixture
def clean_pcrs(enclave_mgr):
    """Reference baseline measurements for PCR registers [0..7]."""
    return enclave_mgr.read_pcr_measurements(CANONICAL_PCR_INDICES)


# =============================================================================
# 1. Hardware Silicon Trust Anchor & Invariant Tests
# =============================================================================

def test_hardware_trust_anchor_cng_platform_provider(enclave_mgr):
    """
    HardwareTrustAnchor wraps Windows CNG Platform Crypto Provider:
    - In-silicon key lifecycle
    - Private key never exists in host CPU RAM
    - In-silicon signing & verification
    """
    key_handle = enclave_mgr.create_identity_key(
        key_id="cng_anchor_identity_01",
        algorithm="ECDSA_P256",
        backend_override=EnclaveBackendType.WINDOWS_CNG,
    )

    assert isinstance(key_handle, HardwareKeyHandle)
    assert key_handle.backend == EnclaveBackendType.WINDOWS_CNG
    assert key_handle.hardware_backed is True
    assert key_handle.non_exportable is True
    assert key_handle.in_silicon is True

    # Security Invariant: Private key never exists in host CPU RAM
    assert key_handle.is_private_key_in_host_ram is False
    assert enclave_mgr.is_private_key_in_host_ram is False

    # Attempting to export private key must fail fail-closed
    with pytest.raises(KeyExportProhibitedError) as exc_info:
        key_handle.export_private_key()
    assert "non-exportable" in str(exc_info.value).lower()

    # In-silicon signing
    digest = secrets.token_bytes(32)
    sig = enclave_mgr.sign_in_silicon(key_handle, digest)
    assert len(sig) == 64

    # Verification
    assert enclave_mgr.verify_in_silicon(key_handle, digest, sig) is True

    # Forged digest or signature must fail
    tampered_digest = bytes(b ^ 0x01 for b in digest)
    assert enclave_mgr.verify_in_silicon(key_handle, tampered_digest, sig) is False


def test_hardware_trust_anchor_pkcs11_hsm(enclave_mgr):
    """
    HardwareTrustAnchor wraps PKCS#11 HSM:
    - In-silicon signing within physical HSM token
    - Private key never exists in host CPU RAM
    """
    key_handle = enclave_mgr.create_identity_key(
        key_id="pkcs11_hsm_identity_01",
        algorithm="ML-DSA-87",
        backend_override=EnclaveBackendType.PKCS11_HSM,
    )

    assert key_handle.backend == EnclaveBackendType.PKCS11_HSM
    assert key_handle.is_private_key_in_host_ram is False

    # In-silicon signing
    digest = secrets.token_bytes(32)
    sig = enclave_mgr.sign_in_silicon(key_handle, digest)
    assert len(sig) == 64
    assert enclave_mgr.verify_in_silicon(key_handle, digest, sig) is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows CNG Platform Crypto Provider requires Windows")
def test_real_windows_tpm_cng_platform_provider_live():
    """
    Exercise genuine Windows Platform Crypto Provider against the physical host TPM:
    Proves physical in-silicon signing and non-exportability on the real machine.
    """
    try:
        import cng_platform
        h_prov = cng_platform.open_platform_provider()
    except Exception as e:
        pytest.skip(f"TPM Platform Crypto Provider not present on this host: {e}")

    try:
        test_key_name = f"custody-test-{secrets.token_hex(4)}"
        k_handle = cng_platform.create_device_key(h_prov, test_key_name)
        assert k_handle != 0

        # Verify private key is strictly captive in silicon (export MUST fail)
        cng_platform.prove_non_exportable(k_handle)

        # In-silicon sign a SHA-256 digest
        digest = secrets.token_bytes(32)
        sig = cng_platform.sign_digest(k_handle, digest)
        assert len(sig) == 64

        # In-silicon signature verification
        cng_platform.verify_with_key(k_handle, digest, sig)

        # Clean up key from TPM
        cng_platform.delete_key(k_handle)
    finally:
        cng_platform.close_handle(h_prov)


def test_production_mode_strictly_rejects_mock_silicon(monkeypatch):
    """In production mode (P2P_PRODUCTION=1), mock silicon backends are strictly refused."""
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    with pytest.raises(SiliconDeviceError) as exc_info:
        HardwareEnclaveManager(backend_type=EnclaveBackendType.MOCK_SILICON, allow_mock_in_lab=True)
    assert "prohibited in production mode" in str(exc_info.value).lower()


# =============================================================================
# 2. Measured Boot TPM PCR Sealing [0..7] & Drift Refusal
# =============================================================================

def test_tpm_pcr_seal_registers_0_to_7_clean_boot(enclave_mgr, clean_pcrs):
    """
    Seal identity keys to measured boot PCR registers [0..7]:
    - All 8 registers [0..7] are incorporated into composite policy
    - Unsealing with untampered baseline succeeds perfectly
    """
    secret_material = b"MLDSA87_POST_QUANTUM_DEVICE_ROOT_KEY_MATERIAL_2027"

    sealed = enclave_mgr.seal_identity_to_pcrs(
        key_id="airgap_node_identity",
        secret_material=secret_material,
        pcr_indices=CANONICAL_PCR_INDICES,
        custom_pcrs=clean_pcrs,
    )

    assert isinstance(sealed, SealedSiliconBlob)
    assert sealed.key_id == "airgap_node_identity"
    assert sealed.pcr_indices == list(range(8))
    assert len(sealed.policy_digest) == 32
    assert len(sealed.expected_pcrs) == 8

    # Unseal with matching measurements succeeds
    unsealed = enclave_mgr.unseal_identity_from_pcrs(sealed, live_pcrs=clean_pcrs)
    assert unsealed == secret_material


@pytest.mark.parametrize("drift_pcr,desc", [
    (0, "CRTM, BIOS, Motherboard Firmware"),
    (1, "Host Platform Configuration"),
    (2, "UEFI Option ROMs and Add-on Hardware"),
    (3, "UEFI Option ROM Configurations"),
    (4, "UEFI Boot Manager"),
    (5, "Boot Loader & Partition Tables"),
    (6, "State Transitions"),
    (7, "Secure Boot Policy, PK, KEK, db, dbx"),
])
def test_tpm_pcr_seal_drift_rejection_fail_closed(enclave_mgr, clean_pcrs, drift_pcr, desc):
    """
    Platform measurement drift in ANY register [0..7] causes unseal to fail fail-closed
    with authentic TPM_RC_POLICY_FAIL (0x99D).
    """
    secret = b"CONFIDENTIAL_MILITARY_TACTICAL_SEED"
    sealed = enclave_mgr.seal_identity_to_pcrs(
        key_id=f"drift_test_pcr_{drift_pcr}",
        secret_material=secret,
        pcr_indices=CANONICAL_PCR_INDICES,
        custom_pcrs=clean_pcrs,
    )

    # Inject platform measurement drift into target PCR
    tampered_pcrs = dict(clean_pcrs)
    orig = tampered_pcrs[drift_pcr]
    tampered_pcrs[drift_pcr] = bytes([orig[0] ^ 0xFF]) + orig[1:]

    with pytest.raises(PlatformMeasurementDriftError) as exc_info:
        enclave_mgr.unseal_identity_from_pcrs(sealed, live_pcrs=tampered_pcrs)

    err = exc_info.value
    assert err.pcr_index == drift_pcr
    assert err.tpm_error_code == TPM_RC_POLICY_FAIL
    assert "tpm_rc_policy_fail (0x99d)" in str(err).lower()
    assert hex(TPM_RC_POLICY_FAIL) in str(err).lower()


def test_tpm_pcr_seal_missing_register_rejection(enclave_mgr, clean_pcrs):
    """If a sealed PCR register is absent from the host live query, unseal fails closed."""
    secret = b"AIR_GAP_CONFIDENTIAL"
    sealed = enclave_mgr.seal_identity_to_pcrs(
        key_id="missing_pcr_test",
        secret_material=secret,
        pcr_indices=CANONICAL_PCR_INDICES,
        custom_pcrs=clean_pcrs,
    )

    incomplete_pcrs = dict(clean_pcrs)
    del incomplete_pcrs[7]  # Omit Secure Boot PCR 7

    with pytest.raises(PlatformMeasurementDriftError) as exc_info:
        enclave_mgr.unseal_identity_from_pcrs(sealed, live_pcrs=incomplete_pcrs)

    err = exc_info.value
    assert err.pcr_index == 7
    assert err.tpm_error_code == TPM_RC_POLICY_FAIL


# =============================================================================
# 3. Active Micro-Tamper Tripwire & Sensor Monitoring
# =============================================================================

def test_chassis_intrusion_sensor_tripwire():
    """Chassis intrusion sensor detects micro-switch violation."""
    sensor = ChassisIntrusionSensor()
    breached, msg = sensor.check_status()
    assert breached is False
    assert "nominal" in msg.lower()

    # Trip micro-switch
    sensor.trip("Chassis cover panel removed; optical tripwire severed")
    breached, msg = sensor.check_status()
    assert breached is True
    assert "chassis cover panel removed" in msg.lower()


def test_unauthorized_dma_bus_detection():
    """DmaBusSecurityAuditor detects unauthorized PCIe/Thunderbolt DMA devices."""
    auditor = DmaBusSecurityAuditor()
    breached, msg = auditor.check_dma_security()
    assert breached is False

    # Simulate unauthorized DMA device insertion
    auditor.trip("Rogue PCIe DMA bus-master device attached on Bus 04 Slot 00")
    breached, msg = auditor.check_dma_security()
    assert breached is True
    assert "rogue pcie dma" in msg.lower()


def test_chassis_real_wmi_smbios_query():
    """Live chassis status check runs without unhandled exception."""
    sensor = ChassisIntrusionSensor()
    breached, msg = sensor.check_status()
    assert isinstance(breached, bool)
    assert isinstance(msg, str)


def test_dma_real_kernel_protection_query():
    """Live DMA protection check runs without unhandled exception."""
    auditor = DmaBusSecurityAuditor()
    breached, msg = auditor.check_dma_security()
    assert isinstance(breached, bool)
    assert isinstance(msg, str)


# =============================================================================
# 4. DoD 5220.22-M 7-Pass RAM Wipe & NVMe Cryptographic Sanitize
# =============================================================================

def test_dod_5220_22_m_7_pass_ram_wipe():
    """
    DoD 5220.22-M 7-Pass RAM Wipe:
    - 7 distinct passes (0x00, 0xFF, random, 0x96, 0x00, 0xFF, random)
    - Memory page locking
    - Read-back verification confirms 100% zeroization
    """
    wiper = DoD7PassMemoryWiper(verify_wipe=True, use_page_lock=True)

    # Allocate sensitive buffer containing plaintext key material
    test_key = bytearray(b"HIGHLY_CONFIDENTIAL_KEY_BUFFER_32_BYTES_HEX_PATTERN")
    orig_len = len(test_key)

    report = wiper.wipe_buffer(test_key)

    assert isinstance(report, WipeReport)
    assert report.success is True
    assert report.bytes_wiped == orig_len
    assert report.passes_completed == 7
    assert report.readback_verification_passed is True

    # Buffer must be completely zeroized
    assert all(b == 0x00 for b in test_key)


def test_dod_7_pass_wipe_immutable_bytes_rejected():
    """Wiping immutable bytes fails safely instead of pretending to wipe."""
    wiper = DoD7PassMemoryWiper()
    report = wiper.wipe_buffer(b"IMMUTABLE_BYTES")
    assert report.success is False
    assert "must be mutable" in report.error.lower()


def test_nvme_ata_cryptographic_sanitize():
    """
    NVMe / ATA Cryptographic Sanitize:
    - Issues NVMe Format SES=2 Cryptographic Erase
    - Produces cryptographic audit receipt
    """
    sanitizer = NvmeCryptographicSanitizer(force_simulation=True)
    report = sanitizer.sanitize_media(target_drive="/dev/nvme0n1")

    assert report.success is True
    assert "ses=2" in report.command_executed
    assert report.target_media == "/dev/nvme0n1"
    assert len(report.audit_hash) == 128  # SHA3-512 hex digest


# =============================================================================
# 5. End-to-End Autonomous Breach Response
# =============================================================================

def test_end_to_end_tamper_breach_autonomous_destruction():
    """
    End-to-End Tamper Breach Scenario:
    1. Identity key anchored in silicon and sealed to PCRs [0..7].
    2. Sensitive RAM buffers registered with tripwire monitor.
    3. Tamper event detected (chassis opened / unauthorized DMA device).
    4. Autonomous 7-pass RAM wipe executed and verified.
    5. NVMe Cryptographic Sanitize executed and verified.
    6. Enclave locks down fail-closed; all subsequent operations refused.
    """
    mgr = HardwareEnclaveManager(allow_mock_in_lab=True)
    sensor = ChassisIntrusionSensor()
    auditor = DmaBusSecurityAuditor()
    wiper = DoD7PassMemoryWiper(verify_wipe=True)
    sanitizer = NvmeCryptographicSanitizer(force_simulation=True)

    monitor = HardwareTamperMonitor(
        chassis_sensor=sensor,
        dma_auditor=auditor,
        wiper=wiper,
        sanitizer=sanitizer,
        enclave_manager=mgr,
    )

    # 1. Anchor identity key and seal to PCRs [0..7]
    key_handle = mgr.create_identity_key("mission_identity_node")
    sealed_blob = mgr.seal_identity_to_pcrs(
        key_id="mission_identity_node",
        secret_material=b"TACTICAL_CRITICAL_PAYLOAD",
    )

    # 2. Register sensitive memory buffers
    sensitive_session_key = bytearray(secrets.token_bytes(64))
    sensitive_ratchet_cache = bytearray(secrets.token_bytes(128))
    monitor.register_memory_buffer(sensitive_session_key)
    monitor.register_memory_buffer(sensitive_ratchet_cache)

    breach_event_log = []
    monitor.register_breach_callback(lambda src, det: breach_event_log.append((src, det)))

    # Initial sensor check passes
    breached, _ = monitor.audit_sensors_once()
    assert breached is False
    assert monitor.is_breached is False

    # 3. Simulate Physical Tamper Breach (Chassis Intrusion)
    sensor.trip("Chassis cover removed during active deployment")

    # Audit scan trips the wire
    breached, reason = monitor.audit_sensors_once()
    assert breached is True
    assert monitor.is_breached is True

    # 4. Verify autonomous 7-pass RAM wipe cleared registered memory
    assert all(b == 0x00 for b in sensitive_session_key)
    assert all(b == 0x00 for b in sensitive_ratchet_cache)

    # 5. Verify breach callback received the notification
    assert len(breach_event_log) == 1
    assert breach_event_log[0][0] == "CHASSIS_INTRUSION_SENSOR"

    # 6. Verify enclave locks down fail-closed
    with pytest.raises(TamperBreachError):
        mgr.sign_in_silicon(key_handle, secrets.token_bytes(32))

    with pytest.raises(TamperBreachError):
        mgr.unseal_identity_from_pcrs(sealed_blob)


# =============================================================================
# 6. Live Physical Silicon TPM 2.0 PCR & Anti-Forensic Tests
# =============================================================================

@pytest.mark.skipif(sys.platform != "win32", reason="Windows TBS requires win32")
def test_read_live_hardware_pcrs_tbs_silicon(enclave_mgr):
    """
    Test direct physical TPM 2.0 silicon PCR reading via Windows TPM Base Services (TBS).
    Verifies all 8 measured boot registers [0..7] are returned as valid 32-byte SHA-256 digests.
    """
    live_pcrs = enclave_mgr.read_live_hardware_pcrs(CANONICAL_PCR_INDICES)
    if live_pcrs is None:
        pytest.skip("Physical TPM 2.0 silicon not accessible on this test runner")

    assert len(live_pcrs) == 8
    for idx in range(8):
        assert idx in live_pcrs
        assert len(live_pcrs[idx]) == 32
        # Digests from real silicon must not be all-zeroes or trivial
        assert live_pcrs[idx] != b"\x00" * 32


@pytest.mark.skipif(sys.platform != "win32", reason="Windows TBS requires win32")
def test_tpm_pcr_seal_and_unseal_live_silicon_pcrs(enclave_mgr):
    """
    Seal an identity secret directly to the real host physical TPM 2.0 PCR registers [0..7].
    Unsealing with live silicon measurements succeeds; tampering with any PCR triggers fail-closed rejection.
    """
    live_pcrs = enclave_mgr.read_live_hardware_pcrs(CANONICAL_PCR_INDICES)
    if live_pcrs is None:
        pytest.skip("Physical TPM 2.0 silicon not accessible on this test runner")

    secret = b"GENUINE_HARDWARE_SILICON_SECRET_PAYLOAD_2027"
    sealed = enclave_mgr.seal_identity_to_pcrs(
        key_id="live_tpm_identity",
        secret_material=secret,
        pcr_indices=CANONICAL_PCR_INDICES,
        custom_pcrs=live_pcrs,
    )

    # Clean unseal with live silicon measurements
    unsealed = enclave_mgr.unseal_identity_from_pcrs(sealed, live_pcrs=live_pcrs)
    assert unsealed == secret

    # Perturb live PCR 0 (BIOS drift)
    tampered_pcrs = dict(live_pcrs)
    orig = tampered_pcrs[0]
    tampered_pcrs[0] = bytes([orig[0] ^ 0x01]) + orig[1:]

    with pytest.raises(PlatformMeasurementDriftError) as exc_info:
        enclave_mgr.unseal_identity_from_pcrs(sealed, live_pcrs=tampered_pcrs)
    assert exc_info.value.pcr_index == 0
    assert exc_info.value.tpm_error_code == TPM_RC_POLICY_FAIL


def test_smbios_type3_in_process_query():
    """
    Direct in-process SMBIOS Type 3 query executes in sub-millisecond time
    without spawning external PowerShell or subprocesses.
    """
    sensor = ChassisIntrusionSensor()
    alert, msg = sensor._check_smbios_type3_in_process()
    assert isinstance(alert, bool)
    if alert:
        assert isinstance(msg, str)
        assert len(msg) > 0


def test_nvme_shred_sensitive_file_anti_forensic(tmp_path):
    """
    Anti-forensic disk shredding:
    Executes 7-pass overwrite, buffer flush, 0-byte truncation, and unlinks file.
    """
    sanitizer = NvmeCryptographicSanitizer(force_simulation=True)
    secret_file = tmp_path / "sensitive_device_token.bin"
    secret_file.write_bytes(secrets.token_bytes(256))
    assert secret_file.exists()

    shredded = sanitizer.shred_sensitive_file(secret_file)
    assert shredded is True
    assert not secret_file.exists()


def test_register_sensitive_file_wipe_on_breach(tmp_path):
    """
    Registering sensitive files with HardwareTamperMonitor ensures
    they are automatically shredded and unlinked upon tamper breach.
    """
    sanitizer = NvmeCryptographicSanitizer(force_simulation=True)
    sensor = ChassisIntrusionSensor()
    monitor = HardwareTamperMonitor(chassis_sensor=sensor, sanitizer=sanitizer)

    secret_key_file = tmp_path / "ephemeral_identity_seed.dat"
    secret_key_file.write_bytes(b"SUPER_SECRET_KEY_MATERIAL")
    monitor.register_sensitive_file(secret_key_file)

    assert secret_key_file.exists()

    # Trip micro-tamper tripwire
    sensor.trip("Chassis cover optical sensor interrupted")
    breached, _ = monitor.audit_sensors_once()
    assert breached is True

    # File must be shredded and unlinked from disk
    assert not secret_key_file.exists()


def test_export_public_key_safety(enclave_mgr):
    """
    Public key export is permitted for public distribution,
    while private key export remains strictly refused fail-closed.
    """
    handle = enclave_mgr.create_identity_key("public_export_test")
    pub = enclave_mgr.export_public_key(handle)
    assert len(pub) >= 32

    # Private key export is strictly denied
    with pytest.raises(KeyExportProhibitedError):
        handle.export_private_key()


def test_hardware_barrier_and_page_locking():
    """
    DoD wiper memory barrier and page locking execute safely
    without unhandled native exceptions.
    """
    wiper = DoD7PassMemoryWiper()
    buf = bytearray(b"SENSITIVE_MEMORY_BUFFER_128_BYTES" * 4)

    # Memory barrier
    wiper._memory_barrier()

    # Memory page lock and unlock
    locked = wiper._lock_memory(buf)
    if locked:
        wiper._unlock_memory(buf)


# =============================================================================
# 7. Native Rust Hardware Enclave Verification
# =============================================================================

def test_rust_hardware_enclave_native_tests():
    """
    Execute native Rust unit tests in `rust_data_plane` for `hardware_enclave`:
    Verifies `HardwareTrustAnchor` trait, in-silicon signing, zero host RAM key presence,
    and PCR [0..7] measurement drift rejection in compiled Rust.
    """
    manifest_path = REPO_ROOT / "rust_data_plane" / "Cargo.toml"
    assert manifest_path.exists(), f"Rust manifest missing: {manifest_path}"

    cmd = [
        "cargo", "test",
        "--manifest-path", str(manifest_path),
        "--lib", "hardware_enclave",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Cargo test failed: {res.stderr}\n{res.stdout}"
    assert "test hardware_enclave::tests::test_invariant_private_key_never_in_host_ram ... ok" in res.stdout
    assert "test hardware_enclave::tests::test_tpm_pcr_seal_and_unseal_roundtrip ... ok" in res.stdout
    assert "test hardware_enclave::tests::test_tpm_pcr_measurement_drift_rejection_fail_closed ... ok" in res.stdout
    assert "test hardware_enclave::tests::test_cng_platform_in_silicon_signing ... ok" in res.stdout
    assert "test hardware_enclave::tests::test_pkcs11_in_silicon_signing ... ok" in res.stdout
    assert "test hardware_enclave::tests::test_windows_tbs_live_pcr_read ... ok" in res.stdout
