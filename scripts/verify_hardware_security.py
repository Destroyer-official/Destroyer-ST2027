#!/usr/bin/env python3
"""
verify_hardware_security.py
Master Hardware Security, Memory Protection, Physical Isolation & Cryptographic Token Verifier.

Executes a comprehensive, multi-pillar hardware security assessment:
- Pillar 1: Hardware Memory Protections (CFG, ACG, CET, MPX, Guard Pages, DoD 5220.22-M wiping)
- Pillar 2: Host Firmware & Hypervisor Posture (UEFI SecureBoot, VBS, HVCI, Kernel DMA Protection)
- Pillar 3: TPM 2.0 Silicon & Hardware Monotonic Counter (Canonical Index 0x01800001)
- Pillar 4: Hardware Security Tokens & Two-Person Integrity (DoD 5210.41M / CJCSI 3260.01E CCID Smartcards)
- Pillar 5: Physical TEMPEST (NATO SDIP-27/28/29) & Simplex Optical Data Diode Registries

Fail-closed in production (P2P_PRODUCTION=1 / --strict / --production).
Advisory warnings permitted on commercial development workstations in lab mode.
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

# Resolve project root and paths
REPO_ROOT = Path(__file__).resolve().parent.parent if Path(__file__).resolve().parent.name == "scripts" else Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# Suppress debug logs
logging.basicConfig(level=logging.CRITICAL)
logging.getLogger().setLevel(logging.CRITICAL)
logging.getLogger('platform_hsm_interface').setLevel(logging.WARNING)
logging.getLogger('pqc_algorithms').setLevel(logging.WARNING)

from platform_hsm_interface import (
    run_hardware_memory_diagnostics,
    get_hardware_memory_protector,
    get_host_security_posture,
)
from production_gate import is_production

try:
    from verify_hardware_tokens import HardwareTokenVerifier
except ImportError:
    from scripts.verify_hardware_tokens import HardwareTokenVerifier

try:
    from verify_physical_isolation import PhysicalIsolationVerifier
except ImportError:
    from scripts.verify_physical_isolation import PhysicalIsolationVerifier

try:
    from provision_tpm2_nv_counter import TPM2NvCounterProvisioner, CANONICAL_COUNTER_INDEX
except ImportError:
    from scripts.provision_tpm2_nv_counter import TPM2NvCounterProvisioner, CANONICAL_COUNTER_INDEX


def verify_all_hardware_security(strict: bool = False, production_override: bool = False) -> Dict[str, Any]:
    """Execute all five hardware security verification pillars."""
    prod = production_override or is_production() or strict

    results: Dict[str, Any] = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "PRODUCTION_STRICT" if prod else "LAB_ADVISORY",
        "pillars": {},
        "summary": {
            "total_pillars": 5,
            "passed": 0,
            "warned": 0,
            "failed": 0,
            "compliant": True,
        }
    }

    # -------------------------------------------------------------------------
    # Pillar 1: Hardware Memory Protections & Cryptographic Wiping
    # -------------------------------------------------------------------------
    print("Running Hardware Security Verification...")
    try:
        protector = get_hardware_memory_protector()
        print("[OK] Hardware Memory Protector initialized.")
        mem_results = run_hardware_memory_diagnostics()

        print("\n--- Diagnostic Results ---")
        print(f"Secure Allocation: {mem_results.get('secure_memory_allocation')}")
        print(f"Integrity Check:   {mem_results.get('memory_integrity_verification')}")
        print(f"Guard Pages:       {mem_results.get('guard_page_protection')}")
        print(f"Hardware Features: {mem_results.get('hardware_features')}")
        print(f"Wiping Success:    {mem_results.get('cryptographic_wiping', 'N/A')}")

        if mem_results.get('error_details'):
            print("\n[WARNING] Errors encountered:")
            for err in mem_results['error_details']:
                print(f"  - {err}")

        mem_ok = bool(mem_results.get('secure_memory_allocation') and mem_results.get('memory_integrity_verification'))
        results["pillars"]["pillar_1_memory"] = {
            "name": "Hardware Memory & Anti-Tamper Protections",
            "status": "PASS" if mem_ok else "FAIL",
            "details": mem_results
        }
        if mem_ok:
            results["summary"]["passed"] += 1
            print("\n[SUCCESS] Hardware Security Verification PASSED")
        else:
            results["summary"]["failed"] += 1
            results["summary"]["compliant"] = False
            print("\n[FAILURE] Hardware Security Verification FAILED")
    except Exception as e:
        results["pillars"]["pillar_1_memory"] = {
            "name": "Hardware Memory & Anti-Tamper Protections",
            "status": "FAIL",
            "error": str(e)
        }
        results["summary"]["failed"] += 1
        results["summary"]["compliant"] = False
        print(f"\n[CRITICAL FAILURE] Memory verification crashed: {e}")

    # -------------------------------------------------------------------------
    # Pillar 2: Host Firmware & Hypervisor Posture (UEFI, VBS, HVCI, DMA)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("PILLAR 2: Host Firmware & Hypervisor Posture (UEFI, VBS, HVCI, DMA)")
    print("=" * 70)
    try:
        host_posture = get_host_security_posture()
        sb = host_posture.get("secure_boot")
        dma = host_posture.get("dma_capable")
        vbs = host_posture.get("vbs")
        hvci = host_posture.get("hvci")
        tpm = host_posture.get("tpm_present")

        print(f"  [*] UEFI Secure Boot:     {'ENABLED' if sb else 'DISABLED'}")
        print(f"  [*] Kernel DMA / IOMMU:   {'ACTIVE' if dma else 'INACTIVE'}")
        print(f"  [*] Virtualization VBS:   {vbs}")
        print(f"  [*] Code Integrity HVCI:  {hvci}")
        print(f"  [*] TPM Hardware Silicon: {tpm}")

        host_fail = False
        host_warn = False
        if prod:
            if not sb or not tpm or not dma:
                host_fail = True
        else:
            if not sb or not dma:
                host_warn = True

        status = "FAIL" if host_fail else ("WARN" if host_warn else "PASS")
        results["pillars"]["pillar_2_host_posture"] = {
            "name": "Host Firmware & Hypervisor Posture",
            "status": status,
            "details": host_posture
        }
        if status == "PASS":
            results["summary"]["passed"] += 1
            print("  [PASS] Host posture meets baseline security requirements")
        elif status == "WARN":
            results["summary"]["warned"] += 1
            print("  [WARN] Advisory: Enable Secure Boot and HVCI via scripts/apply_host_hardening_windows.ps1")
        else:
            results["summary"]["failed"] += 1
            results["summary"]["compliant"] = False
            print("  [FAIL] Strict host posture failure: Secure Boot, TPM, or Kernel DMA missing in production")
    except Exception as e:
        results["pillars"]["pillar_2_host_posture"] = {
            "name": "Host Firmware & Hypervisor Posture",
            "status": "FAIL",
            "error": str(e)
        }
        results["summary"]["failed"] += 1
        results["summary"]["compliant"] = False
        print(f"  [FAIL] Error querying host posture: {e}")

    # -------------------------------------------------------------------------
    # Pillar 3: TPM 2.0 Silicon & Monotonic Counter (Canonical Index 0x01800001)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("PILLAR 3: TPM 2.0 Silicon & Monotonic Counter (Index 0x01800001)")
    print("=" * 70)
    try:
        allow_sim = not prod
        tpm_prov = TPM2NvCounterProvisioner(index=CANONICAL_COUNTER_INDEX, allow_simulation=allow_sim)
        prereqs = tpm_prov.check_tpm_prerequisites()
        assurance = tpm_prov.verify_monotonic_assurance()

        print(f"  [*] TPM Device Silicon:   {prereqs.get('tpm_device_present')}")
        print(f"  [*] tpm2-tools CLI:       {prereqs.get('tpm_tools_installed')}")
        print(f"  [*] Canonical Handle:     {prereqs.get('canonical_index')}")
        print(f"  [*] Strictly Monotonic:   {assurance.get('strictly_monotonic')}")
        print(f"  [*] Status Message:       {assurance.get('message')}")

        if prod:
            if prereqs.get("tpm_device_present") and prereqs.get("tpm_tools_installed") and assurance.get("strictly_monotonic"):
                status = "PASS"
                results["summary"]["passed"] += 1
                print("  [PASS] Hardware TPM 2.0 Monotonic Counter validated")
            else:
                status = "FAIL"
                results["summary"]["failed"] += 1
                results["summary"]["compliant"] = False
                print("  [FAIL] Production mandates physical TPM 2.0 NV counter 0x01800001")
        else:
            if assurance.get("strictly_monotonic"):
                status = "PASS" if prereqs.get("tpm_tools_installed") else "WARN"
                if status == "PASS":
                    results["summary"]["passed"] += 1
                    print("  [PASS] Hardware TPM 2.0 Monotonic Counter validated")
                else:
                    results["summary"]["warned"] += 1
                    print("  [WARN] Monotonic counter validated via simulation fallback (production mandates physical TPM)")
            else:
                status = "FAIL"
                results["summary"]["failed"] += 1
                results["summary"]["compliant"] = False
                print("  [FAIL] Monotonic counter validation failed")

        results["pillars"]["pillar_3_tpm_counter"] = {
            "name": "TPM 2.0 Monotonic Counter (0x01800001)",
            "status": status,
            "prerequisites": prereqs,
            "assurance": assurance
        }
    except Exception as e:
        results["pillars"]["pillar_3_tpm_counter"] = {
            "name": "TPM 2.0 Monotonic Counter (0x01800001)",
            "status": "FAIL",
            "error": str(e)
        }
        results["summary"]["failed"] += 1
        results["summary"]["compliant"] = False
        print(f"  [FAIL] TPM monotonic counter error: {e}")

    # -------------------------------------------------------------------------
    # Pillar 4: Hardware Tokens & Two-Person Integrity (DoD 5210.41M)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("PILLAR 4: Hardware Security Tokens & Two-Person Integrity (DoD 5210.41M)")
    print("=" * 70)
    try:
        tok_verifier = HardwareTokenVerifier(strict=prod)
        tok_res = tok_verifier.verify_two_person_integrity()

        print(f"  [*] CCID Readers Found:   {tok_res.get('readers_found')}")
        print(f"  [*] Distinct Serials:     {tok_res.get('distinct_serials')}")
        print(f"  [*] Two-Person Rule:      {'COMPLIANT' if tok_res.get('compliant') else 'NON-COMPLIANT'}")
        print(f"  [*] Details:              {tok_res.get('details')}")

        if tok_res.get("compliant"):
            status = "PASS"
            results["summary"]["passed"] += 1
            print("  [PASS] Dual physical CCID hardware tokens verified (DoD 5210.41M / CJCSI 3260.01E)")
        elif not prod:
            status = "WARN"
            results["summary"]["warned"] += 1
            print("  [WARN] Hardware token simulation fallback in lab; attach YubiKey 5 FIPS / Nitrokey HSM for production")
        else:
            status = "FAIL"
            results["summary"]["failed"] += 1
            results["summary"]["compliant"] = False
            print("  [FAIL] Dual physical hardware tokens missing in production")

        results["pillars"]["pillar_4_tokens"] = {
            "name": "Hardware Tokens & Two-Person Integrity",
            "status": status,
            "details": tok_res
        }
    except Exception as e:
        results["pillars"]["pillar_4_tokens"] = {
            "name": "Hardware Tokens & Two-Person Integrity",
            "status": "FAIL",
            "error": str(e)
        }
        results["summary"]["failed"] += 1
        results["summary"]["compliant"] = False
        print(f"  [FAIL] Token verification error: {e}")

    # -------------------------------------------------------------------------
    # Pillar 5: Physical TEMPEST & Simplex Optical Diode Isolation
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("PILLAR 5: Physical TEMPEST (NATO SDIP-27/28/29) & Simplex Optical Diode Isolation")
    print("=" * 70)
    try:
        iso_verifier = PhysicalIsolationVerifier(strict=prod)
        iso_res = iso_verifier.run_all_checks()
        summary = iso_res.get("summary", {})
        failed = summary.get("failed", 0)
        warned = summary.get("warned", 0)
        score = iso_res.get("readiness_score", 0.0)

        print(f"  [*] Isolation Score:      {score:.1f}%")
        print(f"  [*] Checks Passed:        {summary.get('passed', 0)}")
        print(f"  [*] Checks Warned:        {warned}")
        print(f"  [*] Checks Failed:        {failed}")

        if failed == 0:
            status = "PASS" if warned == 0 else "WARN"
            if status == "PASS":
                results["summary"]["passed"] += 1
                print("  [PASS] Physical boundary and certified registries verified")
            else:
                results["summary"]["warned"] += 1
                print("  [WARN] Physical boundaries compliant with advisory warnings (lab mode)")
        else:
            status = "FAIL"
            results["summary"]["failed"] += 1
            results["summary"]["compliant"] = False
            print(f"  [FAIL] Failed {failed} physical isolation boundary checks")

        results["pillars"]["pillar_5_physical_isolation"] = {
            "name": "Physical TEMPEST & Simplex Optical Diode Isolation",
            "status": status,
            "summary": summary,
            "readiness_score": score,
            "checks": iso_res.get("checks", [])
        }
    except Exception as e:
        results["pillars"]["pillar_5_physical_isolation"] = {
            "name": "Physical TEMPEST & Simplex Optical Diode Isolation",
            "status": "FAIL",
            "error": str(e)
        }
        results["summary"]["failed"] += 1
        results["summary"]["compliant"] = False
        print(f"  [FAIL] Physical isolation error: {e}")

    # -------------------------------------------------------------------------
    # Master Summary
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("HARDWARE SECURITY ASSESSMENT MASTER SUMMARY")
    print("=" * 70)
    print(f"  Mode:           {results['mode']}")
    print(f"  Passed Pillars: {results['summary']['passed']} / {results['summary']['total_pillars']}")
    print(f"  Warned Pillars: {results['summary']['warned']} / {results['summary']['total_pillars']}")
    print(f"  Failed Pillars: {results['summary']['failed']} / {results['summary']['total_pillars']}")
    status_label = "COMPLIANT (PRODUCTION READY)" if (results['summary']['failed'] == 0 and results['summary']['warned'] == 0) else (
        "COMPLIANT - ADVISORY WARNINGS PRESENT" if results['summary']['failed'] == 0 else "NON-COMPLIANT - FAILURES DETECTED"
    )
    print(f"  Overall Status: {status_label}")
    print("=" * 70)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Master Hardware Security, Memory Protection, Physical Isolation & Cryptographic Token Verifier."
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enforce fail-closed policy (fail if any advisory warning or missing hardware exists).",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Simulate strict production mode (P2P_PRODUCTION=1).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON report.",
    )
    args = parser.parse_args()

    results = verify_all_hardware_security(
        strict=args.strict,
        production_override=args.production,
    )

    if args.json:
        print("\n" + json.dumps(results, indent=2))

    if results["summary"]["failed"] > 0:
        sys.exit(1)
    elif args.strict and results["summary"]["warned"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
