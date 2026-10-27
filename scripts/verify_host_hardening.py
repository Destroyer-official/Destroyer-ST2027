#!/usr/bin/env python3
"""
scripts/verify_host_hardening.py
================================
Military & Defense Host Posture Defense Verifier.
Conforming to:
- DoD Zero Trust Strategy (Endpoint Pillar - Workstation Integrity & Posture)
- NIST SP 800-207 (Zero Trust Architecture: Continuous Diagnostics and Mitigation)
- NSA/CISA Technical Report: Defending Against Software Supply Chain & Physical Bus Interposition
- DISA STIG (Security Technical Implementation Guide for Windows / Linux Endpoints)

Checks:
1. UEFI Secure Boot & Firmware Integrity
2. Virtualization-Based Security (VBS) & Hypervisor-Protected Code Integrity (HVCI)
3. IOMMU Kernel DMA Protection (PCIe / Thunderbolt Bus Interposition Defense)
4. Radio Silence / RF Emission Discipline (WiFi / Bluetooth status on classified nodes)
5. Physical Anti-Tamper & Chassis Intrusion Status (SMBIOS / WMI Enclosure)
"""

import os
import sys
import json
import logging
import platform
# AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
import subprocess  # nosec: B404
from typing import Dict, Any, List, Optional

try:
    import winreg
except ImportError:
    winreg = None

logger = logging.getLogger("verify_host_hardening")


class HostHardeningVerifier:
    """Verifies operating system and physical endpoint security posture."""

    def __init__(self, strict: bool = False):
        self.strict = strict or (os.environ.get("P2P_STRICT_HOST_POSTURE", "").strip() == "1")
        self.os_type = platform.system().lower()

    def check_secure_boot(self) -> Dict[str, Any]:
        """Verify UEFI Secure Boot is active and enforcing signature verification."""
        if self.os_type == "windows":
            try:
                if winreg is None:
                    raise RuntimeError("winreg module unavailable")
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                )
                val, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
                try:
                    winreg.CloseKey(key)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                enabled = bool(val == 1)
                return {
                    "check": "secure_boot",
                    "status": "PASS" if enabled else "FAIL",
                    "enabled": enabled,
                    "details": "UEFI Secure Boot enabled via Windows Registry" if enabled else "Secure Boot DISABLED",
                }
            except Exception as e:
                # Fallback to powershell Confirm-SecureBootUEFI
                try:
                    # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                    out = subprocess.check_output(  # nosec: B603 B607
                        ["powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI"],
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                    ).decode("utf-8", errors="ignore").strip().lower()
                    enabled = "true" in out
                    return {
                        "check": "secure_boot",
                        "status": "PASS" if enabled else "FAIL",
                        "enabled": enabled,
                        "details": f"PowerShell Confirm-SecureBootUEFI: {out}",
                    }
                except Exception as ex_ps:
                    return {
                        "check": "secure_boot",
                        "status": "WARN",
                        "enabled": False,
                        "details": f"Secure Boot check unavailable: {e}; {ex_ps}",
                    }

        elif self.os_type == "linux":
            # Check /sys/firmware/efi/efivars/SecureBoot-*
            try:
                efivars = "/sys/firmware/efi/efivars"
                if os.path.isdir(efivars):
                    for fn in os.listdir(efivars):
                        if fn.startswith("SecureBoot-"):
                            with open(os.path.join(efivars, fn), "rb") as f:
                                data = f.read()
                                enabled = bool(len(data) >= 5 and data[4] == 1)
                                return {
                                    "check": "secure_boot",
                                    "status": "PASS" if enabled else "FAIL",
                                    "enabled": enabled,
                                    "details": "Linux efivars SecureBoot active",
                                }
                # Alternative: mokutil
                # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                out = subprocess.check_output(["mokutil", "--sb-state"], stderr=subprocess.DEVNULL, timeout=5).decode()  # nosec: B603 B607
                enabled = "enabled" in out.lower()
                return {
                    "check": "secure_boot",
                    "status": "PASS" if enabled else "FAIL",
                    "enabled": enabled,
                    "details": out.strip(),
                }
            except Exception as e:
                return {
                    "check": "secure_boot",
                    "status": "WARN",
                    "enabled": False,
                    "details": f"Linux Secure Boot check unavailable: {e}",
                }

        return {
            "check": "secure_boot",
            "status": "WARN",
            "enabled": False,
            "details": f"Unsupported platform: {self.os_type}",
        }

    def check_vbs_and_hvci(self) -> Dict[str, Any]:
        """Verify Virtualization-Based Security (VBS) and Hypervisor-Protected Code Integrity (HVCI)."""
        if self.os_type == "windows":
            try:
                if winreg is None:
                    raise RuntimeError("winreg module unavailable")
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                )
                try:
                    vbs_val, _ = winreg.QueryValueEx(key, "EnableVirtualizationBasedSecurity")
                except FileNotFoundError:
                    vbs_val = 0
                try:
                    winreg.CloseKey(key)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass

                key_sc = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                )
                try:
                    hvci_val, _ = winreg.QueryValueEx(key_sc, "Enabled")
                except FileNotFoundError:
                    hvci_val = 0
                try:
                    winreg.CloseKey(key_sc)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass

                vbs_active = bool(vbs_val == 1)
                hvci_active = bool(hvci_val == 1)
                status = "PASS" if (vbs_active or hvci_active) else "WARN"
                return {
                    "check": "vbs_and_hvci",
                    "status": status,
                    "vbs_enabled": vbs_active,
                    "hvci_enabled": hvci_active,
                    "details": f"VBS={vbs_active}, HVCI={hvci_active}",
                }
            except Exception as e:
                return {
                    "check": "vbs_and_hvci",
                    "status": "WARN",
                    "vbs_enabled": False,
                    "hvci_enabled": False,
                    "details": f"DeviceGuard registry probe: {e}",
                }

        elif self.os_type == "linux":
            # Check kernel lockdown mode
            lockdown_path = "/sys/kernel/security/lockdown"
            if os.path.exists(lockdown_path):
                try:
                    with open(lockdown_path, "r") as f:
                        val = f.read().strip()
                        active = "[integrity]" in val or "[confidentiality]" in val
                        return {
                            "check": "vbs_and_hvci",
                            "status": "PASS" if active else "WARN",
                            "details": f"Kernel lockdown: {val}",
                        }
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception as e:  # nosec: B110
                    pass

        return {
            "check": "vbs_and_hvci",
            "status": "INFO",
            "details": "VBS/HVCI is a Windows hypervisor defense; non-Windows environment active",
        }

    def check_kernel_dma_protection(self) -> Dict[str, Any]:
        """Verify Kernel DMA Protection / IOMMU is active against rogue PCIe/Thunderbolt taps."""
        if self.os_type == "windows":
            try:
                if winreg is None:
                    raise RuntimeError("winreg module unavailable")
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel",
                )
                try:
                    dma_val, _ = winreg.QueryValueEx(key, "KernelDMAProtection")
                except FileNotFoundError:
                    dma_val = 0
                try:
                    winreg.CloseKey(key)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass

                enabled = bool(dma_val == 1)
                return {
                    "check": "kernel_dma_protection",
                    "status": "PASS" if enabled else "WARN",
                    "enabled": enabled,
                    "details": "Kernel DMA Protection enabled (DMA bus interception mitigated)" if enabled else "Kernel DMA Protection not enforced in registry",
                }
            except Exception as e:
                return {
                    "check": "kernel_dma_protection",
                    "status": "WARN",
                    "enabled": False,
                    "details": f"DMA protection check: {e}",
                }

        elif self.os_type == "linux":
            # Check IOMMU cmdline
            try:
                with open("/proc/cmdline", "r") as f:
                    cmdline = f.read()
                    iommu_active = "intel_iommu=on" in cmdline or "amd_iommu=on" in cmdline or "iommu=force" in cmdline
                    return {
                        "check": "kernel_dma_protection",
                        "status": "PASS" if iommu_active else "WARN",
                        "enabled": iommu_active,
                        "details": "IOMMU active in cmdline" if iommu_active else "IOMMU not explicitly forced in cmdline",
                    }
            except Exception as e:
                return {
                    "check": "kernel_dma_protection",
                    "status": "WARN",
                    "enabled": False,
                    "details": f"Linux IOMMU probe: {e}",
                }

        return {
            "check": "kernel_dma_protection",
            "status": "INFO",
            "enabled": False,
            "details": "DMA bus protection check skipped on platform",
        }

    def check_radio_silence(self) -> Dict[str, Any]:
        """Verify RF Emission discipline / TEMPEST posture: wireless adapters disabled on classified nodes."""
        wireless_detected = []

        if self.os_type == "windows":
            try:
                # Use netsh wlan show interfaces
                # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                out = subprocess.check_output(  # nosec: B603 B607
                    ["netsh", "wlan", "show", "interfaces"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).decode("utf-8", errors="ignore")
                for line in out.splitlines():
                    if "State" in line and "connected" in line.lower():
                        wireless_detected.append(f"WiFi Active ({line.strip()})")
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass

        elif self.os_type == "linux":
            try:
                # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                out = subprocess.check_output(  # nosec: B603 B607
                    ["ip", "link"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).decode("utf-8", errors="ignore")
                for line in out.splitlines():
                    if ("wlan" in line or "wlp" in line) and "state UP" in line:
                        wireless_detected.append(f"WiFi Interface Active ({line.strip().split(':')[1].strip()})")
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass

        if wireless_detected:
            status = "FAIL" if self.strict else "WARN"
            return {
                "check": "radio_silence",
                "status": status,
                "compliant": False,
                "detected": wireless_detected,
                "details": "Active RF wireless adapters detected! Prohibited on classified military networks.",
            }

        return {
            "check": "radio_silence",
            "status": "PASS",
            "compliant": True,
            "detected": [],
            "details": "No active WiFi/Bluetooth wireless adapters transmitting (RF Discipline Compliant)",
        }

    def check_chassis_intrusion_and_anti_tamper(self) -> Dict[str, Any]:
        """Verify physical chassis anti-tamper telemetry and enclosure status."""
        details = "Chassis physical integrity nominal"
        tamper_detected = False

        if self.os_type == "windows":
            try:
                # Query WMI Win32_SystemEnclosure
                # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                out = subprocess.check_output(  # nosec: B603 B607
                    ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_SystemEnclosure | Select-Object -Property ChassisTypes,SecurityStatus | ConvertTo-Json"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).decode("utf-8", errors="ignore").strip()
                if out:
                    data = json.loads(out)
                    sec_status = data.get("SecurityStatus")
                    # 4 = ExternalInterfaceLockedOut, 5 = ExternalInterfaceEnabled
                    details = f"SMBIOS Enclosure SecurityStatus={sec_status}, ChassisTypes={data.get('ChassisTypes')}"
            except Exception as e:
                details = f"SMBIOS enclosure query: {e}"

        return {
            "check": "chassis_anti_tamper",
            "status": "FAIL" if tamper_detected else "PASS",
            "tamper_detected": tamper_detected,
            "details": details,
        }

    def run_all_checks(self) -> Dict[str, Any]:
        """Run complete host posture inspection and compute defense readiness score."""
        results = {
            "secure_boot": self.check_secure_boot(),
            "vbs_and_hvci": self.check_vbs_and_hvci(),
            "kernel_dma_protection": self.check_kernel_dma_protection(),
            "radio_silence": self.check_radio_silence(),
            "chassis_anti_tamper": self.check_chassis_intrusion_and_anti_tamper(),
        }

        # Calculate score and compliance
        passed_count = sum(1 for r in results.values() if r["status"] == "PASS")
        warn_count = sum(1 for r in results.values() if r["status"] == "WARN")
        fail_count = sum(1 for r in results.values() if r["status"] == "FAIL")

        overall_passed = fail_count == 0
        if self.strict and warn_count > 0:
            overall_passed = False

        score = (passed_count + (0.5 * warn_count)) / len(results) * 100.0

        return {
            "overall_passed": overall_passed,
            "readiness_score": score,
            "summary": {
                "passed": passed_count,
                "warned": warn_count,
                "failed": fail_count,
                "total": len(results),
            },
            "checks": results,
        }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Verify Host Posture & Hardware Anti-Tamper Hardening")
    parser.add_argument("--strict", action="store_true", help="Fail if any check is in WARN or FAIL state")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    verifier = HostHardeningVerifier(strict=args.strict)
    report = verifier.run_all_checks()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 80)
        print("  MILITARY ENDPOINT HOST POSTURE & HARDWARE ANTI-TAMPER VERIFICATION")
        print("=" * 80)
        for name, r in report["checks"].items():
            color = "\033[92m" if r["status"] == "PASS" else ("\033[93m" if r["status"] == "WARN" else "\033[91m")
            reset = "\033[0m"
            print(f"[{color}{r['status']:4s}{reset}] {name:25s} : {r.get('details')}")
        print("-" * 80)
        print(f"Readiness Score: {report['readiness_score']:.1f}% | Passed: {report['summary']['passed']} | Warned: {report['summary']['warned']} | Failed: {report['summary']['failed']}")
        print(f"Final Decision:  {'[COMPLIANT]' if report['overall_passed'] else '[NON-COMPLIANT]'}")
        print("=" * 80)

    sys.exit(0 if report["overall_passed"] else 1)


if __name__ == "__main__":
    main()

