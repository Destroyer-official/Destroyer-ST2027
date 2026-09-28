#!/usr/bin/env python3
"""
ts_runtime.py — Operating-system & execution-runtime gating layer for TOP
SECRET communications (component #2).

SCOPE (what software can and cannot do here):

  This code cannot replace the running kernel, cannot fabricate a verified
  microkernel, and cannot disable physical buses without privilege/firmware
  cooperation. What it DOES, really and fail-closed:

    RT-1  Verifies the execution PLATFORM: either an attested seL4-family
          node (verified configuration only — see allow-list below) or an
          explicit, expiring, audited AO waiver bound to live-verified
          mitigations (VBS enforced + HVCI running + Secure Boot on).
    RT-2  Provides + REQUIRES the deterministic native core (ts_rt Rust
          cdylib, zero external deps): locked pages, volatile zeroize,
          replay bitmap, constant-time compare, built-in self-test. In TS
          mode the native core must load and self-test green; the CPython
          fallback is refused.
    RT-3  Enforces the measured-boot chain from live OS state: UEFI Secure
          Boot on, measured-boot log present, VBS/HVCI enforced. (Remote
          TPM-quote verification remains an operator verifier duty —
          see ts_hw_layer RATS notes; TBS is absent on Win11 build 26200.)
    RT-4  Enforces anti-DMA posture: enumerates external DMA-capable buses
          (Thunderbolt/USB4, 1394, PCMCIA/CardBus/ExpressCard) live; any
          present hostile device refuses TS unless named-accepted in the
          waiver + DMA-protection capability present. Disabling hardware
          is emitted as exact operator remediation (UEFI/Disable-PnpDevice/
          DmaGuard policy), not pretended from user mode.

Research grounding (live-fetched, Sept 2026):
  [SEL4] seL4 16.0.0 (22 Jul 2026); AArch64 confidentiality proof COMPLETE
    (Proofcraft, Aug 2026 — functional correctness + integrity +
    confidentiality = full isolation stack); MCS functional correctness
    proved on RISC-V (Jun 2026, DARPA PROVERS porting to AArch64 ongoing);
    rust-sel4 5.0.0, Microkit 2.3.0. Verified configs: AArch64/ARM/RISC-V
    families (+HYP); x86-64 is NOT verified — encoded below as refusal.
  [FERROCENE] Ferrocene qualified Rust toolchain: ISO 26262 ASIL-D,
    IEC 61508 SIL 3, IEC 62304 Class C (TUV SUD); core-library subset SIL 2
    (Dec 2025, Ferrocene 25.11.0). ts_rt is built to be qualification-
    friendly (dep-free, deny(unsafe_op_in_unsafe_fn), panic=abort); this
    box builds it with upstream rustc (recorded in tsrt_version), with the
    Ferrocene-qualified build as the documented qualification path.
  [VBS] Windows 11: VBS+HVCI on by default on capable clean installs;
    HVCI state via DeviceGuard registry/WMI; Win32_DeviceGuard services:
    1=CredentialGuard, 2=HVCI, 3=SystemGuard Secure Launch;
    AvailableSecurityProperties: 1=BaseVirt, 2=SecureBoot, 3=DMAProtection,
    4=MOR, 5=UEFICodeReadonly, 6=SMM mitigations, 7=MBEC.
  [DMA] Kernel DMA Protection (1803+, IOMMU VT-d/AMD-Vi, firmware DMAR/
    IVRS opt-in, pre-boot BME clearing); does NOT cover 1394/PCMCIA/
    CardBus/ExpressCard; Thunderbolt user/secure levels + IOMMU
    iommu_dma_protection (Linux). Thunderclap (NDSS'19): unprotected DMA
    = full memory compromise in seconds — hence fail-closed here.

Live posture of THIS box (verified during implementation, not assumed):
  UEFI firmware, Secure Boot registry 0 (OFF/unprovisioned), VBS services
  configured {0} running {0} (nothing enforced), available {1,3,5,6},
  HyperVisorPresent True (WSL2 hypervisor, no VBS enforcement), no
  Thunderbolt/1394/PCMCIA devices present, measured-boot log dir present
  (contents admin-gated), EK info admin-gated. Verdict: consumer posture —
  the TS gate correctly refuses it (proven by tests).
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import struct
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("ts_runtime")


class TSError(Exception):
    """Base for runtime-layer failures (fail-closed, generic)."""


class TSRequiredError(TSError):
    """TOP SECRET operation refused on unqualified runtime/platform."""


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _expired(valid_through: str) -> bool:
    import datetime
    return datetime.date.fromisoformat(valid_through) < datetime.date.today()


# ---------------------------------------------------------------------------
# RT-2 — deterministic native core (ts_rt Rust cdylib)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent
_DEFAULT_LIB = _REPO_ROOT / "ts_rt" / "target" / "release" / (
    "ts_rt.dll" if os.name == "nt" else "libts_rt.so")

_native_lib: Optional[ctypes.CDLL] = None
_native_lock = threading.Lock()
_native_version: str = ""


def _lib_path() -> Path:
    override = os.environ.get("P2P_TS_RT_LIB", "").strip()
    return Path(override) if override else _DEFAULT_LIB


def load_native() -> ctypes.CDLL:
    """Load ts_rt + run its built-in self-test. Fail-closed, cached."""
    global _native_lib, _native_version
    with _native_lock:
        if _native_lib is not None:
            return _native_lib
        path = _lib_path()
        if not path.exists():
            raise TSRequiredError(
                f"deterministic native core missing at {path} — build ts_rt "
                f"(cargo build --release --offline); CPython fallback refused in TS mode")
        try:
            lib = ctypes.CDLL(str(path))
        except OSError as e:
            raise TSRequiredError(f"native core unloadable: {e}")
        try:
            lib.tsrt_alloc_locked.restype = ctypes.c_void_p
            lib.tsrt_alloc_locked.argtypes = [ctypes.c_size_t]
            lib.tsrt_write.restype = ctypes.c_int
            lib.tsrt_write.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ubyte]
            lib.tsrt_free.restype = None
            lib.tsrt_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            lib.tsrt_ct_eq.restype = ctypes.c_int
            lib.tsrt_ct_eq.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.c_void_p, ctypes.c_size_t]
            lib.tsrt_replay_new.restype = ctypes.c_void_p
            lib.tsrt_replay_new.argtypes = [ctypes.c_uint64]
            lib.tsrt_replay_check_mark.restype = ctypes.c_int
            lib.tsrt_replay_check_mark.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
            lib.tsrt_replay_free.restype = None
            lib.tsrt_replay_free.argtypes = [ctypes.c_void_p]
            lib.tsrt_selftest.restype = ctypes.c_int
            lib.tsrt_selftest.argtypes = []
            lib.tsrt_version.restype = ctypes.c_char_p
            lib.tsrt_version.argtypes = []
        except AttributeError as e:
            raise TSRequiredError(f"native core ABI mismatch (not ts_rt): {e}")
        step = lib.tsrt_selftest()
        if step != 0:
            raise TSRequiredError(f"native core self-test FAILED at step {step}")
        _native_version = lib.tsrt_version().decode("ascii", "replace")
        _native_lib = lib
        return lib


def native_version() -> str:
    load_native()
    return _native_version


class LockedBuffer:
    """OS-locked, volatile-wiped secret buffer (context manager).

    with LockedBuffer(32) as b: b.fill(0xA5); ...  # wiped+freed on exit
    Raw address access is deliberately NOT exposed; use fill()/seal_into()
    style helpers so key bytes never become Python `bytes` objects.
    """

    def __init__(self, size: int) -> None:
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= (64 << 20):
            raise TSError("locked buffer size violation")
        lib = load_native()
        ptr = lib.tsrt_alloc_locked(size)
        if not ptr:
            raise TSError("locked allocation failed (no unlocked fallback)")
        self._lib = lib
        self._ptr = ptr
        self._size = size
        self._closed = False

    @property
    def size(self) -> int:
        return self._size

    def fill(self, value: int) -> None:
        if self._closed:
            raise TSError("buffer already destroyed")
        if not 0 <= value <= 255:
            raise TSError("fill value violation")
        if self._lib.tsrt_write(self._ptr, self._size, value) != 0:
            raise TSError("buffer fill failed")

    def compare(self, other: bytes) -> bool:
        """Constant-time compare against a bytes-like (returns bool only)."""
        if self._closed:
            raise TSError("buffer already destroyed")
        if not isinstance(other, (bytes, bytearray)) or len(other) != self._size:
            return False
        buf = ctypes.create_string_buffer(bytes(other), len(other))
        return self._lib.tsrt_ct_eq(self._ptr, self._size, buf, len(other)) == 1

    def close(self) -> None:
        if not self._closed:
            self._lib.tsrt_free(self._ptr, self._size)
            self._closed = True
            self._ptr = None

    def __enter__(self) -> "LockedBuffer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):  # best effort; close() is authoritative
        try:
            self.close()
        except Exception:
            pass


class NativeReplay:
    """Replay window backed by the native core.

    NOTE: `start` is marked seen at creation (native constructor
    semantics); the Python ReplayWindow starts empty. Cross-checks must
    pre-mark the same sequence on both sides before comparing verdicts.
    """

    def __init__(self, start: int) -> None:
        lib = load_native()
        h = lib.tsrt_replay_new(start)
        if not h:
            raise TSError("native replay allocation failed")
        self._lib = lib
        self._h = h

    def check_and_mark(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq < (1 << 64):
            raise TSError("sequence violation")
        rc = self._lib.tsrt_replay_check_mark(self._h, seq)
        if rc != 1:
            raise TSError("replay rejected")

    def close(self) -> None:
        if self._h:
            self._lib.tsrt_replay_free(self._h)
            self._h = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def require_native_runtime() -> str:
    """TS gate: native deterministic core present AND self-tested."""
    load_native()
    return _native_version


# ---------------------------------------------------------------------------
# RT-1/RT-3 — live platform posture (Windows; non-admin readable)
# ---------------------------------------------------------------------------

# Win32_DeviceGuard value maps (Microsoft + CimSweep, verified live fetch).
AVAILABLE_MAP = {1: "BaseVirtualizationSupport", 2: "SecureBoot",
                 3: "DMAProtection", 4: "SecureMemoryOverwrite",
                 5: "UEFICodeReadonly", 6: "SMMSecurityMitigations",
                 7: "ModeBasedExecutionControl"}
SERVICES_MAP = {1: "CredentialGuard", 2: "HVCI", 3: "SystemGuardSecureLaunch",
                4: "SMMFirmwareMeasurement", 5: "KernelStackProtection"}
VBS_MAP = {0: "Off", 1: "Configured", 2: "Running"}


def _reg_dword(root: str, subkey: str, value: str) -> Optional[int]:
    """Read a REG_DWORD without privilege. None when absent/unreadable."""
    if os.name != "nt":
        return None
    try:
        import winreg
        roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE}
        with winreg.OpenKey(roots[root], subkey) as k:
            v, t = winreg.QueryValueEx(k, value)
            if t == winreg.REG_DWORD and isinstance(v, int):
                return v
    except Exception as e:
        log.debug("registry read failed %s\\%s!%s: %r", root, subkey, value, e)
    return None


def _cim_device_guard() -> Dict[str, Any]:
    """Win32_DeviceGuard via powershell CIM (read-only, non-admin)."""
    out: Dict[str, Any] = {"available": None, "configured": None,
                           "running": None, "vbs_status": None}
    if os.name != "nt":
        return out
    try:
        import subprocess  # nosec: fixed argv, no shell
        ps = ("Get-CimInstance -Namespace 'root\\Microsoft\\Windows\\DeviceGuard'"
              " -ClassName Win32_DeviceGuard | Select-Object -Property"
              " AvailableSecurityProperties,SecurityServicesConfigured,"
              "SecurityServicesRunning,VirtualizationBasedSecurityStatus"
              " | ConvertTo-Json -Compress")
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", ps],
                           capture_output=True, text=True, timeout=30)
        if p.returncode != 0 or not p.stdout.strip():
            return out
        data = json.loads(p.stdout)
        if isinstance(data, list):
            data = data[0] if data else {}
        if not isinstance(data, dict):
            return out

        def ints(v):
            if v is None:
                return None
            vals = v if isinstance(v, list) else [v]
            return [int(x) for x in vals]

        out["available"] = ints(data.get("AvailableSecurityProperties"))
        out["configured"] = ints(data.get("SecurityServicesConfigured"))
        out["running"] = ints(data.get("SecurityServicesRunning"))
        vbs = data.get("VirtualizationBasedSecurityStatus")
        out["vbs_status"] = int(vbs) if vbs is not None else None
    except Exception as e:
        log.debug("deviceguard CIM failed: %r", e)
    return out


def _ci_activity_24h() -> Optional[int]:
    """Count user-mode CodeIntegrity evaluations in the last 24h (REAL log read).

    Events 3033/3089 = UMCI load evaluations (proven live: Chrome vulkan-1.dll
    evaluations present on this box). This evidences an ACTIVE CI
    infrastructure, but it is USER-mode CI — never confused with kernel HVCI,
    which is read separately from Win32_DeviceGuard. None when unreadable.
    """
    if os.name != "nt":
        return None
    try:
        import subprocess  # nosec: fixed argv, no shell
        ps = ("Get-WinEvent -FilterHashtable @{LogName="
              "'Microsoft-Windows-CodeIntegrity/Operational'; ID=3033,3089;"
              " StartTime=(Get-Date).AddDays(-1)} -MaxEvents 500"
              " -ErrorAction SilentlyContinue | Measure-Object |"
              " Select-Object -ExpandProperty Count")
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", ps],
                           capture_output=True, text=True, timeout=60)
        if p.returncode != 0 or not p.stdout.strip():
            return None
        return max(0, int(p.stdout.strip()))
    except Exception as e:
        log.debug("ci activity read failed: %r", e)
        return None


def read_platform_posture() -> Dict[str, Any]:
    """Read live OS security posture. Unknown fields are None, never guessed."""
    posture: Dict[str, Any] = {
        "os": platform.system(), "os_version": platform.version(),
        "arch": platform.machine().lower(),
        "secure_boot": None, "vbs_status": None, "hvci_running": None,
        "credguard_running": None, "dma_capable": None,
        "measured_boot_log": None, "hvci_policy": None,
        "umci_24h": None,  # user-mode CI evaluations/24h (informational, not HVCI proof)
    }
    if os.name != "nt":
        return posture
    sb = _reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                    "UEFISecureBootEnabled")
    posture["secure_boot"] = None if sb is None else bool(sb)
    dg = _cim_device_guard()
    avail = dg["available"] or []
    posture["dma_capable"] = 3 in avail
    posture["vbs_status"] = dg["vbs_status"]
    running = dg["running"] or []
    posture["hvci_running"] = 2 in running
    posture["credguard_running"] = 1 in running
    posture["hvci_policy"] = _reg_dword(
        "HKLM", r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
                r"\HypervisorEnforcedCodeIntegrity", "Enabled")
    try:
        logdir = Path(r"C:\Windows\Logs\MeasuredBoot")
        if not logdir.exists():
            posture["measured_boot_log"] = False
        else:
            try:
                posture["measured_boot_log"] = (
                    True if any(logdir.iterdir()) else False)
            except OSError:
                # Present but admin-gated: recorded as UNKNOWN, and the boot
                # gate below treats anything but True as failure (presence
                # alone is not evidence).
                posture["measured_boot_log"] = "present-unreadable"
    except Exception:
        posture["measured_boot_log"] = None
    posture["umci_24h"] = _ci_activity_24h()
    return posture


# ---------------------------------------------------------------------------
# RT-1 — verified-platform gate (seL4 attestation or expiring waiver)
# ---------------------------------------------------------------------------

SEL4_MIN_VERSION = (16, 0, 0)  # 16.0.0 carries the critical cache-maintenance
                               # + VM-escape fixes; older is refused for TS.
# Verified configuration families per seL4 docs + 16.0.0 release notes:
# AArch64/ARM/RISC-V verified (+HYP); x86-64 NEVER verified; MCS proved on
# RISC-V only (AArch64 MCS still in progress under DARPA PROVERS).
SEL4_VERIFIED_FAMILIES = ("AARCH64_verified", "ARM_verified", "RISCV64_verified",
                          "AARCH64_HYP_verified", "ARM_HYP_verified",
                          "RISCV64_HYP_verified", "RISCV64_MCS_verified")
SEL4_ARCHES = ("aarch64", "arm", "riscv64")


def _version_tuple(v: str) -> Tuple[int, ...]:
    parts = str(v).strip().split(".")
    if len(parts) != 3:
        raise ValueError("version must be X.Y.Z")
    return tuple(int(p) for p in parts)


def load_sel4_record(path: Path) -> Dict[str, Any]:
    """Strict-validate an seL4 deployment attestation record (pure logic)."""
    try:
        rec = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        raise TSError(f"seL4 record unreadable: {e}")
    if not isinstance(rec, dict):
        raise TSError("seL4 record shape violation")
    for k in ("board", "arch", "sel4_version", "config",
              "verification_report_ref", "measured_boot_binding"):
        if not rec.get(k):
            raise TSError(f"seL4 record missing {k}")
    arch = str(rec["arch"]).lower()
    if arch == "x86_64" or arch not in SEL4_ARCHES:
        raise TSError("seL4 x86_64/unlisted arch refused (no verified config)")
    try:
        ver = _version_tuple(rec["sel4_version"])
    except (ValueError, TypeError):
        raise TSError("seL4 version violation (need X.Y.Z)")
    if ver < SEL4_MIN_VERSION:
        raise TSError(f"seL4 {rec['sel4_version']} predates {SEL4_MIN_VERSION} fixes")
    cfg = str(rec["config"])
    if cfg not in SEL4_VERIFIED_FAMILIES:
        raise TSError(f"seL4 config {cfg} not in verified set")
    if "MCS" in cfg and not cfg.startswith("RISCV64"):
        raise TSError("MCS verification complete on RISC-V only (AArch64 ongoing)")
    fam_arch = cfg.split("_")[0].lower()
    if fam_arch == "riscv64" and arch != "riscv64":
        raise TSError("seL4 config/arch mismatch")
    if fam_arch in ("aarch64", "arm") and arch not in ("aarch64", "arm"):
        raise TSError("seL4 config/arch mismatch")
    return {"tier": "SEL4-VERIFIED", "arch": arch, "config": cfg,
            "version": rec["sel4_version"], "board": rec["board"]}


def load_waiver(path: Path) -> Dict[str, Any]:
    """Strict-validate an AO risk-acceptance waiver (expiring, explicit)."""
    try:
        rec = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        raise TSError(f"waiver unreadable: {e}")
    if not isinstance(rec, dict):
        raise TSError("waiver shape violation")
    for k in ("justification", "ao", "expires", "mitigations"):
        if not rec.get(k):
            raise TSError(f"waiver missing {k}")
    try:
        if _expired(rec["expires"]):
            raise TSError("waiver expired")
    except ValueError:
        raise TSError("waiver expiry date violation (YYYY-MM-DD)")
    if not isinstance(rec["mitigations"], list):
        raise TSError("waiver mitigations must be a list")
    return rec


def _live_arch_family() -> str:
    """Normalize the LIVE host arch to an seL4 arch family (or 'unknown')."""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64", "x86", "i386", "i686"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    if m.startswith("arm"):
        return "arm"
    if m.startswith("riscv"):
        return "riscv64"
    return "unknown"


def require_verified_platform(posture: Optional[Dict[str, Any]] = None,
                              audit_cb: Optional[Callable[[str, dict], None]] = None
                              ) -> Dict[str, Any]:
    """TS platform gate: verified seL4 node, else live-verified waiver, else refuse."""
    post = posture or read_platform_posture()
    sel4_path = os.environ.get("P2P_SEL4_RECORD", "").strip()
    if sel4_path:
        rec = load_sel4_record(Path(sel4_path))
        # Bind the record to THIS host: an attestation for another board/
        # arch must never authorize the local process. (On x86_64 hosts this
        # always refuses — seL4 has no verified x86_64 configuration.)
        live = _live_arch_family()
        if live == "unknown" or rec["arch"] != live:
            raise TSRequiredError(
                f"seL4 record arch {rec['arch']} does not match live host {live}")
        if audit_cb:
            audit_cb("platform_sel4_ok", {"config": rec["config"]})
        return rec
    waiver_path = os.environ.get("P2P_PLATFORM_WAIVER", "").strip()
    if not waiver_path:
        raise TSRequiredError(
            "no verified-microkernel attestation and no platform waiver — "
            "TOP SECRET refused (seL4 verified config or AO waiver required)")
    waiver = load_waiver(Path(waiver_path))
    import re as _re
    claimed = {_re.sub(r"[^a-z0-9]", "", str(m).lower()) for m in waiver["mitigations"]}
    for needed in ("vbs", "hvci", "secureboot"):
        if needed not in claimed:
            raise TSError(
                f"waiver does not cover required mitigation '{needed}'")
    live = {"vbs": post.get("vbs_status") == 2,
            "hvci": post.get("hvci_running") is True,
            "secure_boot": post.get("secure_boot") is True,
            "dma_cap": post.get("dma_capable") is True}
    missing = [k for k, ok in live.items() if not ok]
    if missing:
        raise TSRequiredError(
            f"waiver mitigations NOT live-verified ({', '.join(missing)}) — "
            f"TOP SECRET refused")
    if audit_cb:
        audit_cb("platform_waiver_ok", {"ao": waiver["ao"], "expires": waiver["expires"]})
    return {"tier": "VBS-WAIVER", "ao": waiver["ao"], "expires": waiver["expires"],
            "note": "interim risk acceptance — NOT equivalent to a verified microkernel"}


# ---------------------------------------------------------------------------
# RT-3 — measured-boot chain gate (live OS state)
# ---------------------------------------------------------------------------

def require_boot_chain(posture: Optional[Dict[str, Any]] = None,
                       audit_cb: Optional[Callable[[str, dict], None]] = None
                       ) -> Dict[str, Any]:
    """Enforce boot-chain state from live reads. No record = no trust.

    Requires: UEFI Secure Boot ON, measured-boot log present, VBS running,
    HVCI running. Remote TPM-quote verification is an operator-verifier
    duty (RATS/Keylime pattern); TBS is absent on Win11 build 26200, so no
    local quote path is claimed.
    """
    post = posture or read_platform_posture()
    failures = []
    if post.get("secure_boot") is not True:
        failures.append("secure-boot-off-or-unknown")
    if post.get("measured_boot_log") is not True:
        # Strict True only: "present-unreadable" and False/None all fail.
        # A log whose contents cannot be verified is not evidence.
        failures.append("measured-boot-unverified")
    if post.get("vbs_status") != 2:
        failures.append("vbs-not-enforced")
    if post.get("hvci_running") is not True:
        failures.append("hvci-not-running")
    if failures:
        raise TSRequiredError(
            f"boot chain unqualified ({', '.join(failures)}) — TOP SECRET refused")
    if audit_cb:
        audit_cb("boot_chain_ok", {"secure_boot": True, "hvci": True})
    return {"ok": True, "secure_boot": True, "hvci": True,
            "measured_boot_log": post.get("measured_boot_log"),
            "note": "local state only; remote TPM-quote verification is operator duty"}


# ---------------------------------------------------------------------------
# RT-4 — anti-DMA posture
# ---------------------------------------------------------------------------

# External DMA-capable bus signatures. Thunderbolt/USB4 controller device
# IDs are Intel-assigned: a match counts ONLY with VEN_8086 present, because
# the same hex IDs collide with other vendors (proven live: AMD VEN_1022
# DEV_15E8 host bridge and DEV_15D3 root port are NOT Thunderbolt — matching
# them would wrongly refuse healthy AMD hosts).
_TBT_INTEL_IDS = ("DEV_15D2", "DEV_15D3", "DEV_15D9", "DEV_15E7", "DEV_15E8",
                  "DEV_1137", "DEV_1136", "DEV_9A1B", "DEV_9A1D", "DEV_9A1F",
                  "DEV_9A21", "DEV_A76E", "DEV_A77E")
_DMA_NAME_PATTERNS = ("thunderbolt", "usb4 host router", "1394", "firewire",
                      "ohci1394", "pcmcica", "pcmcia", "cardbus", "expresscard")


def is_external_dma_device(dev: Dict[str, Any]) -> bool:
    """Pure classifier: is this PnP device an external DMA-capable bus?

    Thunderbolt/USB4 controller IDs count ONLY with the Intel vendor prefix
    (numeric IDs collide across vendors — AMD VEN_1022 DEV_15E8/15D3 are
    host bridges, proven live). Legacy 1394/PCMCIA/CardBus/ExpressCard match
    by class or name. Single decision point for enumeration AND posture.
    """
    if not isinstance(dev, dict):
        return False

    def _field(*names: str) -> str:
        for n in names:
            v = dev.get(n)
            if v:
                return str(v)
        return ""

    # Accept BOTH shapes: raw PnP dicts (FriendlyName/DeviceID/...) and the
    # normalized records enumerate_external_dma() itself produces
    # (name/device_id/...). A shape mismatch here silently blinds the gate.
    blob = " ".join((_field("FriendlyName", "name"),
                     _field("Class", "class"),
                     _field("DeviceID", "device_id"),
                     _field("InstanceId", "instance_id", "instanceid"))).upper()
    if any(pat.upper() in blob for pat in _DMA_NAME_PATTERNS):
        # "PCMCIA" as a bare substring is distinctive; keep class-exact too.
        return True
    if "VEN_8086" in blob and any(i in blob for i in _TBT_INTEL_IDS):
        return True
    cls = _field("Class", "class")
    return cls in ("PCMCIA", "MTD")


def enumerate_external_dma() -> Dict[str, Any]:
    """Enumerate present external DMA-capable devices (REAL PnP scan).

    Returns {"devices": [...], "scan_ok": bool}. A FAILED scan reports
    scan_ok False — which the posture gate treats as refusal, because an
    unscanned host cannot assert a clean DMA posture (absence of evidence
    is not evidence of absence).
    """
    found: List[Dict[str, str]] = []
    if os.name != "nt":
        return {"devices": found, "scan_ok": False}
    try:
        import subprocess  # nosec: fixed argv, no shell
        ps = ("Get-PnpDevice | Where-Object { $_.Status -ne 'Unknown' } |"
              " Select-Object FriendlyName,Status,Class,DeviceID,InstanceId |"
              " ConvertTo-Json -Compress -Depth 2")
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", ps],
                           capture_output=True, text=True, timeout=60)
        if p.returncode != 0 or not p.stdout.strip():
            return {"devices": found, "scan_ok": False}
        devs = json.loads(p.stdout)
        if isinstance(devs, dict):
            devs = [devs]
        if not isinstance(devs, list):
            return {"devices": found, "scan_ok": False}
        for d in devs:
            if is_external_dma_device(d):
                found.append({"name": str(d.get("FriendlyName", d.get("name", "?"))),
                              "status": str(d.get("Status", d.get("status", "?"))),
                              "class": str(d.get("Class", d.get("class", "?"))),
                              "device_id": str(d.get("DeviceID", d.get("device_id", "?")))})
    except Exception as e:
        log.debug("dma enumeration failed: %r", e)
        return {"devices": found, "scan_ok": False}
    return {"devices": found, "scan_ok": True}


def require_dma_posture(posture: Optional[Dict[str, Any]] = None,
                        devices: Optional[List[Dict[str, str]]] = None,
                        waiver_dma_accepted: Optional[List[str]] = None,
                        audit_cb: Optional[Callable[[str, dict], None]] = None
                        ) -> Dict[str, Any]:
    """Refuse TS when unprotected external DMA exists.

    `devices` are CANDIDATES: the scan dict from enumerate_external_dma()
    (preferred — carries scan_ok), or a plain list for unit checks. Each
    candidate runs through is_external_dma_device(), so benign numeric
    collisions (AMD bridges) never refuse. A FAILED scan refuses outright:
    an unscanned host cannot assert a clean posture. Hostile present ->
    require DMA-protection capability AND explicit per-device acceptance
    (waiver dma_accepted instance IDs); otherwise refuse with exact
    remediation (unplug, Disable-PnpDevice, UEFI Thunderbolt off, DmaGuard
    MDM enumeration policy). Kernel DMA enforcement state is not reliably
    readable from user mode, so enforcement beyond capability+acceptance is
    an operator/firmware duty — labeled as such, never claimed.
    """
    post = posture or read_platform_posture()
    if devices is None:
        scan = enumerate_external_dma()
        if not scan.get("scan_ok"):
            raise TSRequiredError(
                "DMA device scan failed — posture unverifiable, TOP SECRET refused")
        candidates = scan["devices"]
    elif isinstance(devices, dict) and "devices" in devices:
        # Scan-dict form: honor scan_ok (a failed scan must refuse even if
        # its device list happens to be empty).
        if not devices.get("scan_ok"):
            raise TSRequiredError(
                "DMA device scan failed — posture unverifiable, TOP SECRET refused")
        candidates = devices["devices"]
        if not isinstance(candidates, list):
            raise TSError("dma devices parameter violation")
    elif isinstance(devices, list):
        candidates = devices
    else:
        raise TSError("dma devices parameter violation")
    devs = [d for d in candidates if is_external_dma_device(d)]
    if not devs:
        if audit_cb:
            audit_cb("dma_posture_ok", {"external_dma_devices": 0,
                                        "devices_scanned": len(candidates)})
        return {"ok": True, "external_dma_devices": [],
                "devices_scanned": len(candidates)}
    accepted = set(waiver_dma_accepted or [])
    unaccepted = [d for d in devs
                  if d.get("device_id", "?") not in accepted
                  and d.get("name", "?") not in accepted]
    if unaccepted and not post.get("dma_capable"):
        raise TSRequiredError(
            f"external DMA devices without IOMMU capability "
            f"({len(unaccepted)} found) — TOP SECRET refused; remediation: "
            f"unplug, UEFI Thunderbolt off, or DmaGuard enumeration policy")
    if unaccepted:
        def _label(d):
            return str(d.get("name", "") or d.get("FriendlyName", "?"))
        raise TSRequiredError(
            f"unaccepted external DMA devices {[_label(d) for d in unaccepted]} — "
            f"TOP SECRET refused; name instance IDs in waiver dma_accepted or remove")
    if audit_cb:
        audit_cb("dma_posture_ok", {"external_dma_devices": len(devs), "accepted": True})
    return {"ok": True, "external_dma_devices": devs, "accepted": True,
            "note": "acceptance + capability verified; firmware enforcement is operator duty"}


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def require_ts_runtime(audit_cb: Optional[Callable[[str, dict], None]] = None
                       ) -> Dict[str, Any]:
    """Full #2 preflight: native core -> platform -> boot chain -> anti-DMA."""
    report: Dict[str, Any] = {"ts_runtime": True}
    report["native"] = native_version()
    post = read_platform_posture()
    report["posture"] = {k: post.get(k) for k in
                         ("os", "arch", "secure_boot", "vbs_status",
                          "hvci_running", "dma_capable", "measured_boot_log")}
    report["platform"] = require_verified_platform(post, audit_cb)
    report["boot"] = require_boot_chain(post, audit_cb)
    waiver_dma: List[str] = []
    wpath = os.environ.get("P2P_PLATFORM_WAIVER", "").strip()
    if wpath:
        try:
            waiver_dma = list(load_waiver(Path(wpath)).get("dma_accepted", []) or [])
        except TSError:
            waiver_dma = []
    report["dma"] = require_dma_posture(post, None, waiver_dma, audit_cb)
    if audit_cb:
        audit_cb("ts_runtime_ok", {"native": report["native"]})
    return report
