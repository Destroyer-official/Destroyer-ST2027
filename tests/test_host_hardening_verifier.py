#!/usr/bin/env python3
"""
test_host_hardening_verifier.py

Unit tests for HostHardeningVerifier in scripts/verify_host_hardening.py:
- Secure Boot detection (enabled vs disabled vs unsupported)
- VBS & HVCI detection
- Kernel DMA Protection (IOMMU)
- Radio Silence / RF emission scanning
- Chassis anti-tamper telemetry
- Scoring and strict evaluation modes
"""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

# Ensure scripts directory is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
from verify_host_hardening import HostHardeningVerifier


def test_verifier_structure_and_run_all():
    """Verify that run_all_checks returns a complete and valid evaluation report."""
    verifier = HostHardeningVerifier(strict=False)
    report = verifier.run_all_checks()

    assert "overall_passed" in report  # nosec: B101
    assert "readiness_score" in report  # nosec: B101
    assert "summary" in report  # nosec: B101
    assert report["summary"]["total"] == 5  # nosec: B101

    checks = report["checks"]
    for required in ["secure_boot", "vbs_and_hvci", "kernel_dma_protection", "radio_silence", "chassis_anti_tamper"]:
        assert required in checks  # nosec: B101
        assert "status" in checks[required]  # nosec: B101
        assert checks[required]["status"] in ["PASS", "WARN", "FAIL", "INFO"]  # nosec: B101


def test_secure_boot_mock_enabled():
    """Verify Secure Boot detection when enabled."""
    verifier = HostHardeningVerifier()
    verifier.os_type = "windows"

    with patch("verify_host_hardening.winreg.OpenKey", return_value=MagicMock()), \
         patch("verify_host_hardening.winreg.QueryValueEx", return_value=(1, 4)), \
         patch("verify_host_hardening.winreg.CloseKey"):
        res = verifier.check_secure_boot()
        assert res["status"] == "PASS"  # nosec: B101
        assert res["enabled"] is True  # nosec: B101


def test_secure_boot_mock_disabled():
    """Verify Secure Boot detection when disabled."""
    verifier = HostHardeningVerifier()
    verifier.os_type = "windows"

    with patch("verify_host_hardening.winreg.OpenKey", return_value=MagicMock()), \
         patch("verify_host_hardening.winreg.QueryValueEx", return_value=(0, 4)), \
         patch("verify_host_hardening.winreg.CloseKey"):
        res = verifier.check_secure_boot()
        assert res["status"] == "FAIL"  # nosec: B101
        assert res["enabled"] is False  # nosec: B101


def test_vbs_and_hvci_mock_active():
    """Verify VBS and HVCI detection when configured."""
    verifier = HostHardeningVerifier()
    verifier.os_type = "windows"

    with patch("verify_host_hardening.winreg.OpenKey", return_value=MagicMock()), \
         patch("verify_host_hardening.winreg.QueryValueEx", side_effect=[(1, 4), (1, 4)]), \
         patch("verify_host_hardening.winreg.CloseKey"):
        res = verifier.check_vbs_and_hvci()
        assert res["status"] == "PASS"  # nosec: B101
        assert res["vbs_enabled"] is True  # nosec: B101
        assert res["hvci_enabled"] is True  # nosec: B101


def test_radio_silence_mock_active_wifi_violation():
    """Verify radio silence check flags active WiFi connection."""
    verifier = HostHardeningVerifier(strict=True)
    verifier.os_type = "windows"

    fake_output = b"There is 1 interface on the system:\n    Name                   : Wi-Fi\n    State                  : connected\n"
    with patch("subprocess.check_output", return_value=fake_output):
        res = verifier.check_radio_silence()
        assert res["status"] == "FAIL"  # nosec: B101
        assert res["compliant"] is False  # nosec: B101
        assert len(res["detected"]) > 0  # nosec: B101


def test_radio_silence_mock_clean():
    """Verify radio silence check passes when no wireless interface is active."""
    verifier = HostHardeningVerifier(strict=True)
    verifier.os_type = "windows"

    fake_output = b"There is no wireless interface on the system.\n"
    with patch("subprocess.check_output", return_value=fake_output):
        res = verifier.check_radio_silence()
        assert res["status"] == "PASS"  # nosec: B101
        assert res["compliant"] is True  # nosec: B101
        assert len(res["detected"]) == 0  # nosec: B101


def test_strict_mode_fails_on_warn():
    """Verify strict mode fails closed if any warning exists."""
    verifier = HostHardeningVerifier(strict=True)
    with patch.object(verifier, "check_secure_boot", return_value={"status": "PASS"}), \
         patch.object(verifier, "check_vbs_and_hvci", return_value={"status": "WARN"}), \
         patch.object(verifier, "check_kernel_dma_protection", return_value={"status": "PASS"}), \
         patch.object(verifier, "check_radio_silence", return_value={"status": "PASS"}), \
         patch.object(verifier, "check_chassis_intrusion_and_anti_tamper", return_value={"status": "PASS"}):
        report = verifier.run_all_checks()
        assert report["overall_passed"] is False  # Strict fails on WARN  # nosec: B101


# ------------------------------------------------------------------
# dep_impl.check_dep_status reporting honesty (no-demo rule):
# every value must be a real boolean; the report must be ABLE to
# read False (a previous revision stored bound-method objects that
# were truthy even with DEP off).
# ------------------------------------------------------------------

def test_dep_status_reports_real_booleans():
    import dep_impl
    st = dep_impl.check_dep_status()
    for key in ("enabled", "hardware_support", "software_support",
                "cfg_enabled", "admin_privileges"):
        assert isinstance(st[key], bool), f"{key} is not a real bool: {st[key]!r}"  # nosec: B101
    assert isinstance(st["platform"], str)  # nosec: B101


def test_dep_status_can_read_false():
    """A fresh instance with nothing enabled must report enabled=False."""
    import dep_impl
    inst = dep_impl.EnhancedDEP()
    inst.is_standard_dep_enabled = False
    inst.is_enhanced_dep_enabled = False
    with patch.object(dep_impl, "_enhanced_dep_instance", inst):
        st = dep_impl.check_dep_status()
        assert st["enabled"] is False  # nosec: B101

