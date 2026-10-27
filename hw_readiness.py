#!/usr/bin/env python3
"""Hardware readiness + administrator elevation for the 2027 pipeline.

Two operator promises, enforced:

1. EVERY hardware check reports HAVE / MISSING / UNKNOWN in plain language.
   Missing hardware is TOLD to the user ("YOU DON'T HAVE THIS"), never
   silent, never a bare traceback. Strict mode (TS sessions, --strict)
   refuses when required hardware is missing.

2. Administrator rights are REQUESTED, never taken. ensure_admin() explains
   WHY elevation is needed, asks consent on an interactive terminal, then
   relaunches elevated (UAC runas on Windows, sudo re-exec on POSIX) and
   propagates the child's exit code. Non-interactive shells, --no-elevate,
   or a declined prompt continue WITHOUT elevation (existing fail-closed
   gates still enforce); --require-admin turns decline/failure into refusal.

Probes are REUSED from ts_runtime / ts_hw_layer / platform_hsm_interface
(no duplication); every product import is lazy so `--help` stays instant
and unit tests never touch hardware. This module is stdlib-only at import.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field

HAVE = "HAVE"
MISSING = "MISSING"
UNKNOWN = "UNKNOWN"

ELEVATED_EXIT_SPAWN_FAILED = 3


@dataclass
class Verdict:
    """One hardware item, judged."""
    id: str
    label: str
    status: str  # HAVE | MISSING | UNKNOWN
    detail: str
    action: str  # what the operator must do when not HAVE
    ts_required: bool = False

    def headline(self) -> str:
        if self.status == HAVE:
            return f"[HAVE]    {self.label} — in use ({self.detail})"
        if self.status == MISSING:
            return (f"[MISSING] {self.label} — YOU DON'T HAVE THIS: "
                    f"{self.detail} ACTION: {self.action}")
        return (f"[UNKNOWN] {self.label} — could not be determined "
                f"({self.detail}) ACTION: {self.action}")


# ---------------------------------------------------------------------------
# Administrator detection + elevation (stdlib only, no product imports)
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    """True when the process already runs elevated."""
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return bool(os.geteuid() == 0)
    except Exception:
        return False


def _relaunch_elevated_windows(argv, timeout_s: int) -> int:
    """Relaunch via UAC runas, wait, propagate the child exit code."""
    from ctypes import wintypes

    class _SEI(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD),
                    ("fMask", wintypes.ULONG),
                    ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR),
                    ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int),
                    ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", wintypes.LPVOID),
                    ("lpClass", wintypes.LPCWSTR),
                    ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD),
                    ("hIcon", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]

    SEE_MASK_NOCLOSEPROCESS = 0x40
    SW_SHOWNORMAL = 1
    WAIT_TIMEOUT = 0x102
    # ERROR_CANCELLED (1223) = operator declined at the OS consent prompt.
    sei = _SEI()
    sei.cbSize = ctypes.sizeof(_SEI)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = argv[0]
    sei.lpParameters = subprocess.list2cmdline(argv[1:]) or None
    sei.lpDirectory = None
    sei.nShow = SW_SHOWNORMAL
    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    if not shell32.ShellExecuteExW(ctypes.byref(sei)):
        raise OSError("UAC relaunch refused by the OS "
                      f"(err={ctypes.windll.kernel32.GetLastError()})")
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        waited = kernel32.WaitForSingleObject(
            sei.hProcess, int(timeout_s * 1000))
        if waited == WAIT_TIMEOUT:
            raise TimeoutError("elevated child still running past timeout; "
                               "not killing another operator's session")
        code = wintypes.DWORD(0)
        if not kernel32.GetExitCodeProcess(sei.hProcess,
                                           ctypes.byref(code)):
            raise OSError("could not read elevated child exit code")
        return int(code.value)
    finally:
        try:
            ctypes.windll.kernel32.CloseHandle(sei.hProcess)
        except Exception:
            pass


def _relaunch_elevated_posix(argv) -> int:
    """sudo re-exec replaces this process: exit code flows naturally."""
    os.execvp("sudo", ["sudo", "-E", *argv])
    raise OSError("sudo exec failed to replace process")  # pragma: no cover


def ensure_admin(assume_yes: bool = False, no_elevate: bool = False,
                 timeout_s: int = 1800, argv=None) -> str:
    """Ensure elevation, asking first. Returns already|elevated|skipped|declined.

    Raises SystemExit with the child's code after a successful relaunch
    (the parent never continues twice), and with
    ELEVATED_EXIT_SPAWN_FAILED when elevation was demanded but impossible.
    Callers choose the policy: --require-admin treats skipped/declined as
    refusal; advisory paths warn and continue (existing gates enforce).
    """
    if is_admin():
        print("[HAVE]    Administrator rights — already elevated.", flush=True)
        return "already"
    if no_elevate:
        print("[MISSING] Administrator rights — elevation disabled by "
              "--no-elevate; admin-gated checks (TPM TBS, DeviceGuard, HSM "
              "admin ops) report UNKNOWN. Continuing without elevation.",
              flush=True)
        return "skipped"
    print("[MISSING] Administrator rights — YOU DON'T HAVE THIS in this "
          "process.", flush=True)
    print("  WHY elevation matters: full TPM/TBS reads, DeviceGuard "
          "(VBS/HVCI/DMA) verification, HSM admin operations and OS "
          "mitigation queries require it. Without it those checks report "
          "UNKNOWN (never assumed present).", flush=True)
    interactive = sys.stdin.isatty()
    if not interactive and not assume_yes:
        print("  Non-interactive shell: will NOT prompt; continuing without "
              "elevation.", flush=True)
        return "skipped"
    consent = "y" if assume_yes else input(
        "  Elevate to Administrator now (OS will ask again)? [y/N]: "
    ).strip().lower()
    if consent not in ("y", "yes"):
        print("  Elevation declined by operator; continuing without it.",
              flush=True)
        return "declined"
    argv = argv if argv is not None else [sys.executable, *sys.argv]
    try:
        if os.name == "nt":
            code = _relaunch_elevated_windows(argv, timeout_s)
        else:
            code = _relaunch_elevated_posix(argv)
    except Exception as exc:
        print(f"  Elevation failed: {exc}.", flush=True)
        raise SystemExit(ELEVATED_EXIT_SPAWN_FAILED)
    print(f"  Elevated session finished (exit={code}).", flush=True)
    raise SystemExit(code)


# ---------------------------------------------------------------------------
# Hardware probes (each: HAVE/MISSING/UNKNOWN, never raises, lazy imports)
# ---------------------------------------------------------------------------

def _v_have(i, label, detail, ts_required=False, action=""):
    return Verdict(i, label, HAVE, detail, action, ts_required)


def _v_missing(i, label, detail, action, ts_required=False):
    return Verdict(i, label, MISSING, detail, action, ts_required)


def _v_unknown(i, label, detail, action, ts_required=False):
    return Verdict(i, label, UNKNOWN, detail, action, ts_required)


def check_admin() -> Verdict:
    if is_admin():
        return _v_have("admin", "Administrator rights",
                       "elevated process", ts_required=True,
                       action="none — already elevated")
    return _v_missing(
        "admin", "Administrator rights",
        "process is not elevated; admin-gated reads report UNKNOWN",
        "re-run elevated (you will be asked), or pass --no-elevate to "
        "accept reduced posture explicitly", ts_required=True)


def check_secure_boot() -> Verdict:
    try:
        from ts_runtime import read_platform_posture
        sb = read_platform_posture().get("secure_boot")
    except Exception as exc:
        return _v_unknown("secure_boot", "UEFI Secure Boot",
                          f"posture read failed: {exc}",
                          "run elevated; verify UEFI firmware settings",
                          ts_required=True)
    if sb is True:
        return _v_have("secure_boot", "UEFI Secure Boot", "enabled",
                       ts_required=True, action="none")
    if sb is False:
        return _v_missing("secure_boot", "UEFI Secure Boot",
                          "DISABLED in firmware",
                          "enable Secure Boot in UEFI setup, enroll platform "
                          "keys; TS sessions refused until on",
                          ts_required=True)
    return _v_unknown("secure_boot", "UEFI Secure Boot",
                      "unreadable (non-Windows host or locked registry)",
                      "run on Windows 11 UEFI host, elevated",
                      ts_required=True)


def check_vbs_hvci() -> Verdict:
    try:
        from ts_runtime import read_platform_posture
        p = read_platform_posture()
        vbs, hvci = p.get("vbs_status"), p.get("hvci_running")
    except Exception as exc:
        return _v_unknown("vbs_hvci", "VBS + HVCI",
                          f"posture read failed: {exc}",
                          "run elevated on Windows 11", ts_required=True)
    # VBS_MAP: 0=Off, 1=Configured, 2=Running.
    if hvci is True and vbs == 2:
        return _v_have("vbs_hvci", "VBS + HVCI",
                       "VBS running, HVCI enforcing", ts_required=True,
                       action="none")
    if vbs is None and hvci is None:
        return _v_unknown("vbs_hvci", "VBS + HVCI", "unreadable",
                          "run elevated on Windows 11", ts_required=True)
    return _v_missing(
        "vbs_hvci", "VBS + HVCI",
        f"not enforcing (VBS status={vbs}, HVCI running={hvci})",
        "enable Virtualization-Based Security + Memory Integrity "
        "(Windows Security > Device security), reboot; TS refused until "
        "HVCI enforcing", ts_required=True)


def check_dma_protection() -> Verdict:
    try:
        from ts_runtime import read_platform_posture
        dma = read_platform_posture().get("dma_capable")
    except Exception as exc:
        return _v_unknown("dma", "Kernel DMA Protection",
                          f"posture read failed: {exc}",
                          "run elevated on Windows 11", ts_required=True)
    if dma is True:
        return _v_have("dma", "Kernel DMA Protection",
                       "IOMMU/DMA protection available", ts_required=True,
                       action="none")
    if dma is False:
        return _v_missing("dma", "Kernel DMA Protection",
                          "no DMA protection reported; Thunderbolt/USB4/1394 "
                          "ports are DMA-capable attack surface",
                          "enable Kernel DMA Protection in UEFI; physically "
                          "remove or IOMMU-isolate DMA ports", ts_required=True)
    return _v_unknown("dma", "Kernel DMA Protection", "unreadable",
                      "run elevated on Windows 11", ts_required=True)


def check_tpm() -> Verdict:
    try:
        from ts_hw_layer import probe_tpm_device
        att = probe_tpm_device()
    except Exception as exc:
        return _v_unknown("tpm", "TPM 2.0 device",
                          f"probe failed: {exc}",
                          "run elevated; check UEFI TPM switch",
                          ts_required=True)
    if att is not None:
        return _v_have("tpm", "TPM 2.0 device",
                       str(getattr(att, "detail", att))[:100],
                       ts_required=True, action="none — used for PCR reads "
                       "and measured-boot evidence")
    return _v_missing("tpm", "TPM 2.0 device",
                      "no TPM 2.0 responded (TBS/CNG/provider probes empty)",
                      "enable TPM 2.0 + measured boot in UEFI; TS sessions "
                      "refused without a live TPM", ts_required=True)


def check_hsm_token() -> Verdict:
    try:
        from ts_hw_layer import probe_hardware_custody, probe_pqc_token
        cust = probe_hardware_custody()
        tok = probe_pqc_token()
    except Exception as exc:
        return _v_unknown("hsm", "Hardware key custody (HSM/PKCS#11 token)",
                          f"probe failed: {exc}",
                          "attach Luna/Utimaco/Nitrokey, install vendor "
                          "PKCS#11 library", ts_required=True)
    hits = [a for a in (cust, tok)
            if a is not None and bool(getattr(a, "hardware", False))]
    if hits:
        best = hits[0]
        return _v_have("hsm", "Hardware key custody (HSM/PKCS#11 token)",
                       f"{getattr(best, 'provider_type', '?')} "
                       f"tier={getattr(best, 'tier', '?')}",
                       ts_required=True,
                       action="none — keys stay non-exportable in hardware")
    return _v_missing(
        "hsm", "Hardware key custody (HSM/PKCS#11 token)",
        "no PKCS#11/CNG hardware backend answered; keys would live in "
        "software RAM",
        "attach Thales Luna 7.9+ / Utimaco Quantum Protect / Nitrokey HSM, "
        "install vendor driver; run the witnessed 3-of-5 ceremony; TS key "
        "custody refused until hardware answers", ts_required=True)


def check_fips() -> Verdict:
    try:
        from ts_hw_layer import check_fips_provider
        st = check_fips_provider()
    except Exception as exc:
        return _v_unknown("fips", "FIPS 140-3 provider",
                          f"probe failed: {exc}",
                          "install OpenSSL FIPS provider + CMVP record",
                          ts_required=True)
    if bool(getattr(st, "provider_loaded", False)):
        extra = (" CMVP record ok" if getattr(st, "cmvp_record_ok", False)
                 else " (CMVP record unverified)")
        return _v_have("fips", "FIPS 140-3 provider",
                       f"{getattr(st, 'openssl_version', '?')}{extra}",
                       ts_required=True, action="none")
    return _v_missing("fips", "FIPS 140-3 provider",
                      "no loaded FIPS provider in libcrypto",
                      "install the validated OpenSSL FIPS provider and CMVP "
                      "record #4985; TS crypto refused without it",
                      ts_required=True)


ALL_CHECKS = (check_admin, check_secure_boot, check_vbs_hvci,
              check_dma_protection, check_tpm, check_hsm_token, check_fips)


def collect() -> list:
    """Run every check; a crashing probe becomes UNKNOWN, never an exception."""
    out = []
    for fn in ALL_CHECKS:
        try:
            out.append(fn())
        except Exception as exc:  # fail-closed reporting, not fail-loud
            out.append(Verdict(fn.__name__, fn.__name__, UNKNOWN,
                               f"probe crashed: {exc}",
                               "re-run elevated; report if persistent"))
    return out


def strict_ok(verdicts) -> bool:
    return all(v.status == HAVE for v in verdicts if v.ts_required)


def render(verdicts, out=None) -> None:
    out = out if out is not None else sys.stderr
    print("== HARDWARE READINESS (2027 pipeline) ==", file=out, flush=True)
    for v in verdicts:
        print(v.headline(), file=out, flush=True)
    missing = [v for v in verdicts
               if v.ts_required and v.status != HAVE]
    if missing:
        print(f"TS-REQUIRED NOT MET: {len(missing)} item(s): "
              + ", ".join(v.id for v in missing), file=out, flush=True)
    else:
        print("TS-REQUIRED: all met.", file=out, flush=True)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="hw_readiness",
        description="Hardware readiness checklist + admin elevation. "
                    "Missing hardware is reported, never silent.")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 unless every TS-required item reports HAVE")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable report on stdout")
    ap.add_argument("--no-elevate", action="store_true",
                    help="never relaunch elevated")
    ap.add_argument("--assume-yes", action="store_true",
                    help="answer yes to the elevation consent prompt")
    a = ap.parse_args(argv)
    verdicts = collect()
    if a.json:
        print(json.dumps({
            "admin": is_admin(),
            "strict_ok": strict_ok(verdicts),
            "items": [vars(v) for v in verdicts]}, indent=2))
        return 0 if (strict_ok(verdicts) or not a.strict) else 1
    render(verdicts)
    if a.strict and not strict_ok(verdicts):
        print("STRICT REFUSAL: provision the missing hardware, then re-run.",
              flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
