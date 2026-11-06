#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_hardware_dependencies_and_isolation.py
=================================================
Automated Test Suite for Hardware Dependencies & Physical Isolation:
- Host Hardening Warnings & Remediation (Secure Boot, VBS, HVCI, Kernel DMA Protection)
- Hardware Tokens & TPM 2.0 Monotonic Counter 0x01800001 (DoD 5210.41M TPI, Anti-Rollback)
- Physical TEMPEST & Optical Boundaries (NATO SDIP-27/28/29, CC EAL4+/EAL7+ Simplex Diodes)
"""

import os
import sys
import json
import pytest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from verify_host_hardening import HostHardeningVerifier
from provision_tpm2_nv_counter import TPM2NvCounterProvisioner, CANONICAL_COUNTER_INDEX
from verify_hardware_tokens import HardwareTokenVerifier
from verify_physical_isolation import PhysicalIsolationVerifier


# ==============================================================================
# 1. Host Hardening Tests (Item 3)
# ==============================================================================

@pytest.mark.hermetic
def test_host_hardening_verifier_lab_advisory(monkeypatch):
    """Test host posture verifier in development/lab mode: produces advisory WARN without failing."""
    monkeypatch.delenv("P2P_STRICT_HOST_POSTURE", raising=False)
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    
    verifier = HostHardeningVerifier(strict=False)
    report = verifier.run_all_checks()
    
    assert "checks" in report
    assert "readiness_score" in report
    assert report["readiness_score"] >= 0.0
    # In non-strict mode, warnings do not fail overall execution unless there are actual FAILs
    if report["summary"]["failed"] == 0:
        assert report["overall_passed"] is True


@pytest.mark.hermetic
def test_host_hardening_verifier_strict_fail_closed(monkeypatch):
    """Test host posture verifier in strict mode: any unmitigated warning triggers fail-closed."""
    monkeypatch.setenv("P2P_STRICT_HOST_POSTURE", "1")
    
    verifier = HostHardeningVerifier(strict=True)
    report = verifier.run_all_checks()
    
    # On a commercial workstation without active SecureBoot or VBS, strict mode must fail
    if report["summary"]["warned"] > 0 or report["summary"]["failed"] > 0:
        assert report["overall_passed"] is False


@pytest.mark.hermetic
def test_host_hardening_device_guard_info_structure():
    """Verify device guard posture extraction structure."""
    verifier = HostHardeningVerifier(strict=False)
    info = verifier._get_windows_device_guard_info()
    assert isinstance(info, dict)
    assert "vbs_val" in info
    assert "hvci_val" in info
    assert "available_properties" in info


# ==============================================================================
# 2. Hardware Tokens & TPM 2.0 Monotonic Counter Tests (Item 4)
# ==============================================================================

@pytest.mark.hermetic
def test_tpm2_counter_canonical_index():
    """Verify standard TCG monotonic counter handle 0x01800001."""
    assert CANONICAL_COUNTER_INDEX == 0x01800001
    provisioner = TPM2NvCounterProvisioner(index=CANONICAL_COUNTER_INDEX)
    assert provisioner.index_hex == "0x01800001"


@pytest.mark.hermetic
def test_tpm2_counter_simulation_in_lab(monkeypatch):
    """Verify TPM 2.0 monotonic counter simulation succeeds in lab mode."""
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    
    provisioner = TPM2NvCounterProvisioner(index=0x01800001, allow_simulation=True)
    ok_prov, msg_prov = provisioner.provision_counter()
    assert ok_prov is True
    
    res = provisioner.verify_monotonic_assurance()
    assert res["verified"] is True
    assert res["strictly_monotonic"] is True
    assert res["incremented_value"] == res["initial_value"] + 1


@pytest.mark.hermetic
def test_tpm2_counter_simulation_refused_in_production(monkeypatch):
    """Verify TPM 2.0 software simulation is strictly refused fail-closed in production."""
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    
    provisioner = TPM2NvCounterProvisioner(index=0x01800001, allow_simulation=True)
    with pytest.raises(RuntimeError) as exc:
        provisioner.read_counter()
    assert "refused fail-closed in production" in str(exc.value)


@pytest.mark.hermetic
def test_hardware_token_verifier_simulation_in_lab(monkeypatch):
    """Verify dual-token DoD 5210.41M TPI simulation in lab mode."""
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    
    verifier = HardwareTokenVerifier(strict=False, allow_simulation=True)
    res = verifier.verify_two_person_integrity()
    
    assert res["compliant"] is True
    assert res["readers_found"] == 2
    assert res["distinct_slots"] is True
    assert res["distinct_serials"] is True


@pytest.mark.hermetic
def test_hardware_token_verifier_simulation_refused_in_production(monkeypatch):
    """Verify synthetic hardware token simulation is strictly refused fail-closed in production."""
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    
    verifier = HardwareTokenVerifier(strict=True, allow_simulation=True)
    # When no physical readers exist on test machine, must fail-closed in production
    if not verifier.probe_readers():
        with pytest.raises(RuntimeError) as exc:
            verifier.verify_two_person_integrity()
        assert "Production mode (P2P_PRODUCTION=1) strictly requires two physical" in str(exc.value)


# ==============================================================================
# 3. Physical TEMPEST & Optical Boundaries Tests (Item 5)
# ==============================================================================

@pytest.mark.hermetic
def test_tempest_registry_schema_and_resolution():
    """Verify accredited TEMPEST registry file format and SDIP-28/29 level mapping."""
    verifier = PhysicalIsolationVerifier(strict=False)
    assert verifier.tempest_path.exists()
    
    report = verifier.check_tempest_accreditation(zone=1, classification="TOP SECRET")
    assert report["status"] == "PASS"
    assert report["level"] == "A"  # Zone 1 TOP SECRET requires Level A
    assert report["facility"] != ""
    assert report["zone_report"] != ""
    assert report["install_ref"] != ""


@pytest.mark.hermetic
def test_data_diode_certified_registry_resolution():
    """Verify Common Criteria certified simplex optical data diode registry."""
    verifier = PhysicalIsolationVerifier(strict=False)
    assert verifier.diode_path.exists()
    
    report = verifier.check_data_diode_hardware(device_id="DIODE-OWL-1000G")
    assert report["status"] == "PASS"
    assert "EAL4+" in report["cc_cert"] or "EAL7+" in report["cc_cert"]
    assert report["tx_only_attested"] is True
    assert report["install_ref"] != ""


@pytest.mark.live
def test_simplex_diode_cauchy_rs_transmission_loop():
    """Verify live simplex Cauchy-RS transmission loopback."""
    verifier = PhysicalIsolationVerifier(strict=False)
    res = verifier.test_simplex_transmission_loop()
    assert res["status"] == "PASS"
    assert res["fec_scheme"] == "Cauchy Reed-Solomon (K=8, M=4)"
    assert res["bytes_verified"] > 0


@pytest.mark.hermetic
def test_physical_isolation_full_report_structure():
    """Verify full physical isolation inspection report structure."""
    verifier = PhysicalIsolationVerifier(strict=False)
    report = verifier.run_all_checks()
    
    assert "readiness_score" in report
    assert "checks" in report
    assert "red_black_separation" in report["checks"]
    assert "tempest_accreditation" in report["checks"]
    assert "data_diode_hardware" in report["checks"]
    assert "rf_discipline" in report["checks"]


# ==============================================================================
# 4. Master Hardware Security & Deployment Verifier Integration Tests
# ==============================================================================

@pytest.mark.hermetic
def test_master_hardware_security_verifier_lab(monkeypatch):
    """Verify master hardware security verifier in lab mode passes all 5 pillars."""
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("P2P_STRICT_HOST_POSTURE", raising=False)
    from verify_hardware_security import verify_all_hardware_security

    report = verify_all_hardware_security(strict=False, production_override=False)
    assert report["mode"] == "LAB_ADVISORY"
    assert report["summary"]["total_pillars"] == 5
    assert report["summary"]["failed"] == 0
    assert report["summary"]["compliant"] is True
    assert "pillar_1_memory" in report["pillars"]
    assert "pillar_2_host_posture" in report["pillars"]
    assert "pillar_3_tpm_counter" in report["pillars"]
    assert "pillar_4_tokens" in report["pillars"]
    assert "pillar_5_physical_isolation" in report["pillars"]


@pytest.mark.hermetic
def test_master_hardware_security_verifier_strict_fails_closed(monkeypatch):
    """Verify master hardware security verifier strictly fails closed without hardware."""
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    from verify_hardware_security import verify_all_hardware_security

    report = verify_all_hardware_security(strict=True, production_override=True)
    assert report["mode"] == "PRODUCTION_STRICT"
    # When physical tokens and physical TPM 2.0 tools are absent, must fail
    assert report["summary"]["failed"] > 0
    assert report["summary"]["compliant"] is False


@pytest.mark.hermetic
def test_verify_deployment_hardware_posture_methods(monkeypatch):
    """Verify DeploymentVerifier's hardware tokens, physical isolation, and TPM monotonic counter methods."""
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    from verify_deployment import DeploymentVerifier, VerificationStatus

    v = DeploymentVerifier()
    # In lab mode: all three should return True (advisory warnings only, zero FAILs)
    assert v.verify_hardware_tokens_posture() is True
    assert v.verify_physical_isolation_posture() is True
    assert v.verify_tpm_monotonic_counter_posture() is True

    # Confirm results contain expected check names and statuses
    check_names = [r.check_name for r in v.results]
    assert "Hardware Tokens: Two-Person Integrity" in check_names
    assert "Physical Isolation: NATO SDIP / Simplex Diode" in check_names
    assert "TPM Monotonic Counter: 0x01800001" in check_names
    assert not any(r.status == VerificationStatus.FAIL for r in v.results)


@pytest.mark.hermetic
def test_verify_deployment_hardware_posture_fails_closed_in_production(monkeypatch):
    """Verify DeploymentVerifier fails closed on hardware checks in production."""
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    from verify_deployment import DeploymentVerifier, VerificationStatus

    v = DeploymentVerifier()
    # In production without physical tokens/tools, checks must fail
    res_tokens = v.verify_hardware_tokens_posture()
    res_tpm = v.verify_tpm_monotonic_counter_posture()

    assert res_tokens is False
    assert res_tpm is False
    fails = [r for r in v.results if r.status == VerificationStatus.FAIL]
    assert len(fails) >= 2

