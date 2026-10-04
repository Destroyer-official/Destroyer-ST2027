#!/usr/bin/env python3
"""
Test suite for Phase 2: Hardware Root-of-Trust (TPM 2.0 / HSM Hardware Setup).
Validates:
1. Native Windows TPM Base Services (tbs.dll) direct API.
2. Direct interrogation of physical PCR registers (0, 1, 2, 7) via raw TPM2 commands.
3. Non-admin hardware readiness probe without UAC elevation barriers.
4. TPM remote attestation quotes with genuine physical PCR digests and HARDWARE_ROOT_ENFORCED.
5. Anti-replay nonce binding and quote validation.
6. Display status reporting.
"""

from __future__ import annotations

import os
import platform
import secrets
import pytest

# Ensure native TPM is allowed for this hardware test
_TPM_NATIVE_SNAPSHOT = os.environ.get("P2P_ALLOW_TPM_NATIVE")
os.environ["P2P_ALLOW_TPM_NATIVE"] = "1"


@pytest.fixture(autouse=True, scope="module")
def _module_env_guard():
    """Module-scoped TPM_NATIVE opt-in must not leak: native TPM access in
    later suites must remain an explicit operator choice, not test residue."""
    yield
    if _TPM_NATIVE_SNAPSHOT is None:
        os.environ.pop("P2P_ALLOW_TPM_NATIVE", None)
    else:
        os.environ["P2P_ALLOW_TPM_NATIVE"] = _TPM_NATIVE_SNAPSHOT

import platform_hsm_interface as phi


@pytest.fixture(autouse=True)
def _enable_native_tpm(monkeypatch):
    monkeypatch.setenv("P2P_ALLOW_TPM_NATIVE", "1")
    # Reset cached results
    if hasattr(phi.is_tpm_available, "cached_result"):
        del phi.is_tpm_available.cached_result
    yield


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows TBS requires Windows platform")
def test_windows_tbs_available_and_device_info():
    """Verify that native Windows TBS is accessible without admin privileges."""
    assert phi._windows_tbs_available() is True  # nosec: B101
    dev_info = phi._windows_tbs_get_device_info()
    assert isinstance(dev_info, dict)  # nosec: B101
    assert dev_info.get("tpm_present") is True  # nosec: B101
    assert dev_info.get("tpm_version") == "2.0"  # nosec: B101
    assert dev_info.get("raw_tpm_version") == 2  # nosec: B101
    assert dev_info.get("interface_type") in ("CRB", "FIFO", "TIS")  # nosec: B101


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows TBS requires Windows platform")
def test_windows_tbs_physical_pcr_read():
    """Verify raw TPM2_PCR_Read reads physical PCR registers 0, 1, 2, 7."""
    pcrs = phi._windows_tbs_read_pcrs([0, 1, 2, 7])
    assert isinstance(pcrs, dict)  # nosec: B101
    assert 0 in pcrs  # nosec: B101
    assert 1 in pcrs  # nosec: B101
    assert 2 in pcrs  # nosec: B101
    assert 7 in pcrs  # nosec: B101

    for pcr_num, digest in pcrs.items():
        assert isinstance(digest, str)  # nosec: B101
        assert len(digest) == 64, f"PCR {pcr_num} digest should be 64-char hex SHA-256"  # nosec: B101
        # PCR value should not be empty/all-zero on active machine
        pcr_bytes = bytes.fromhex(digest)
        assert len(pcr_bytes) == 32  # nosec: B101

    # PCR 7 (Secure Boot) must be active and non-zero on this platform
    pcr7_bytes = bytes.fromhex(pcrs[7])
    assert any(b != 0 for b in pcr7_bytes), "PCR 7 should not be all-zero"  # nosec: B101


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows TPM probe requires Windows")
def test_check_windows_pqc_tpm_support_non_admin():
    """Verify physical TPM readiness check succeeds without admin privilege."""
    support = phi._check_windows_pqc_tpm_support()
    assert support is True  # nosec: B101


def test_tpm_availability_with_native_allowed():
    """Verify is_tpm_available returns True on host machine with TPM 2.0."""
    assert phi.is_tpm_available() is True  # nosec: B101


def test_tpm_remote_attestation_hardware_enforced():
    """Verify TPMRemoteAttestation produces HARDWARE_ROOT_ENFORCED with physical PCRs."""
    att_service = phi.TPMRemoteAttestation()
    att_service._initialize()
    assert att_service.attestation_enabled is True  # nosec: B101

    test_nonce = b"military_hardware_test_nonce_32b"
    att = att_service.generate_attestation(nonce=test_nonce)
    assert att is not None  # nosec: B101
    assert att.get("hardware_mode") == "HARDWARE_ROOT_ENFORCED"  # nosec: B101
    assert att.get("tpm_version") == "2.0"  # nosec: B101
    assert att.get("nonce") == test_nonce.hex()  # nosec: B101

    pcr_values = att.get("pcr_values", {})
    assert "0" in pcr_values or 0 in pcr_values  # nosec: B101
    assert "7" in pcr_values or 7 in pcr_values  # nosec: B101

    # Verify quote computation
    assert att.get("quote") is not None  # nosec: B101
    assert len(att.get("quote")) == 128  # SHA3-512 hex string  # nosec: B101


def test_tpm_attestation_verification_valid_and_tamper():
    """Verify attestation quote verification and anti-tampering."""
    att_service = phi.TPMRemoteAttestation()
    test_nonce = b"fresh_session_nonce_for_verify__"
    att = att_service.generate_attestation(nonce=test_nonce)
    assert att is not None  # nosec: B101

    # Verification with correct nonce should succeed (in test mode without signature)
    assert att_service.verify_attestation(att, expected_nonce=test_nonce) is True  # nosec: B101

    # Verification with replay/wrong nonce must fail
    wrong_nonce = b"wrong_attacker_replay_nonce_123"
    assert att_service.verify_attestation(att, expected_nonce=wrong_nonce) is False  # nosec: B101

    # Tampering with PCR value must fail quote verification
    tampered_att = dict(att)
    tampered_pcrs = dict(att["pcr_values"])
    tampered_pcrs["0"] = "00" * 32
    tampered_att["pcr_values"] = tampered_pcrs
    assert att_service.verify_attestation(tampered_att, expected_nonce=test_nonce) is False  # nosec: B101


def test_get_tpm_attestation_top_level_api():
    """Verify top-level get_tpm_attestation API returns genuine hardware quote."""
    test_nonce = secrets.token_bytes(32)
    att = phi.get_tpm_attestation(nonce=test_nonce)
    assert att is not None  # nosec: B101
    assert att.get("hardware_mode") == "HARDWARE_ROOT_ENFORCED"  # nosec: B101
    assert att.get("nonce") == test_nonce.hex()  # nosec: B101
    assert len(att.get("pcr_values", {})) >= 4  # nosec: B101


def test_secure_p2p_and_display_tpm_status():
    """Verify UI and Chat Node display routines report hardware TPM status."""
    from ui.display import DisplayManager

    dm = DisplayManager()
    status = dm.check_tpm_status()
    assert "Available and ready" in status  # nosec: B101
    assert "Hardware TPM" in status or "2.0" in status  # nosec: B101

