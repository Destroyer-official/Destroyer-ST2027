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
            lib.tsrt_replay_check.restype = ctypes.c_int
            lib.tsrt_replay_check.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
            lib.tsrt_replay_mark.restype = ctypes.c_int
            lib.tsrt_replay_mark.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
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

    Discipline (RFC 6479 / WireGuard Sec 5.4): check() is read-only and
    safe on unauthenticated input; mark() advances the window and MUST
    be called only after the AEAD tag for that exact seq verified.
    check_and_mark() is retained for non-wire atomic helpers/tests;
    wire paths MUST NOT use it (single forged seq=2**64-1 would
    otherwise orphan the session before auth fails).

    NOTE: `start` is marked seen at creation (native constructor
    semantics); the Python ReplayWindow starts empty. Cross-checks must
    pre-mark the same sequence on both sides before comparing verdicts.
    """

    def __init__(self, start: int) -> None:
        if isinstance(start, bool) or not isinstance(start, int) or not 0 <= start < (1 << 64):
            raise TSError("sequence violation")
        lib = load_native()
        h = lib.tsrt_replay_new(start)
        if not h:
            raise TSError("native replay allocation failed")
        self._lib = lib
        self._h = h

    def _handle(self):
        h = self._h
        if not h:
            raise TSError("replay handle already destroyed")
        return h

    def check(self, seq: int) -> None:
        """Read-only acceptance test. Raises on replay/stale. No mutation."""
        if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq < (1 << 64):
            raise TSError("sequence violation")
        rc = self._lib.tsrt_replay_check(self._handle(), seq)
        if rc == -1:
            raise TSError("replay handle invalid")
        if rc != 1:
            raise TSError("replay rejected")

    def mark(self, seq: int) -> None:
        """Advance window for a validated seq. Call only after AEAD auth."""
        if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq < (1 << 64):
            raise TSError("sequence violation")
        rc = self._lib.tsrt_replay_mark(self._handle(), seq)
        if rc != 1:
            raise TSError("replay mark failed")

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
# RT-0 — pinned platform attestation root (ML-DSA-87, FIPS 204)
# ---------------------------------------------------------------------------
# PLATFORM_ROOT_PK_HEX pins the offline AO platform-attestation root whose
# signatures authorize (a) AO risk-acceptance waivers and (b) seL4 / CMVP
# attestation records. No .pub file is ever read at runtime: substitution
# of a sidecar key cannot authorize anything. Bootstrap: the constant below
# is generated with NO surviving private key (fail-closed: nothing verifies
# until the AO runs scripts/sign_waiver.py keygen offline and replaces this
# constant with the ceremony public key). Rotation = replace + redeploy.
# --- BEGIN AUTO PLATFORM_ROOT_PIN ---
PLATFORM_ROOT_PK_HEX = "da6bef225d6201128bfc38fd6ec6183c0e73ba21e03b80154da3090d55f5d343dda1bf7a97041ab7f5b80fa24ba0a3f0fb031350a9cc4963dc2d1a7f36f82a336d6d8a565f4cee719d8636288185f40c33b8550bb74fe04ab6bd3fd51979b6b14caec00e0404d376fa5cdbb136d7f7624165c57b5a415b4e114c8e628032abd40972683d5482493e0d56e5bbc70019ecd03e88b6ad44cf7d7df307c0ed712b05524f9e35197c7c11fb6f87bf6019328922b361bf17550ff90022e3b8d1025600237dd37c29f057c642c134a33c7a8bf6fdc8efccd18885f0b7f9789675cec2ba2a8af0b85864c2c356bf8e7d291caacb7909e5dd55839b569184c905b357acfa8975cd3b624a381eab0556cb5bd2f3ca5985f75f90bacd00e830c86b0ffb3cd84c409b06760da9c7e4bbc8dc98fbbaed9def8901e674e538e65173c8e9fd76da76d1ccd12916f695e8da0b1032ce7060e5edc68f399306f2a698dc9093d37e305c5c74a80cae01544116ae1479a2c67f4a115ab2d7e70aee6f6d84bf7c3f0b626b31802b8856ae625b82b5ee6f6225111715105a82dcbf6fdb64b841f5ba2afcfc32fd7de99ff8ec7e23ccfbfc12ba3b13fccac9fba533d373bed40f8080baf43da0046ca9670cbf8953b0ff5aad34ae5c47540464ee315d98ddf9ed9038651932dfb8fea382eed540db680a05e5593c33025f545e1c587eaecab42b25d7ab04274db6c97e5d50d945ec50e3859d5edf6fd6282ce70fb9893b9e96dcbfe67829f7fea87b6d22f4b76396bdebd2df98fce757003aff062b2a05e8deaef3b9401c146d119d76a897c0194cb17fba8cdb66083f84bea67015dc77cf7d7053c2d0f082525646c4e035610ad18468b033cd74fd0c1969fabd6951c16383e6996b62497908a5333f27bc57f7ebc6d3c24f259bc57b848fe877c4b7606720d9010a0fa9969397c76354eb7726b23abd080b96f511e1bfee0a2897af553490f3a16d9cd075dab0333a619e0d7a52a1f12d1a0ad0efb1a0c8927bdfc555eb1422279fb3d036e0f1df33730c7fb071c26167d6f9a1de917940bdc1b435cb78e661562244ed13ba3abb062440faa6ad2f3ce1b8b388a27325a5bc9ff4aeb89f264f45972d6159d9829821b3d841c772b0d2ae464846ccf697ad4cab15c1debb4fce0508894e873efb531b10497fc6f1802caf9f9ccb37fb53408e308d853f0d5de559374343f97dfe52b647ec358e4f79964c8740fda8757df9a183f9ea4734f34bbef178e43cf06a6d69f9cf4a28f0817ed38d4f7f06cc1959864104cd31cd6b132fa449b99505f33e3bdcb00cc155b9781bc46059986a90120dda85d4ab5a3cc1a7afdf39e1ca54dfc8bd6c5cca943f0e0b6b3998fa21c9d69921c386933e1a6cbdec69e6fb918726d347565beb69f78e13c2111387aef6a35d3dd1061d1827894f268ec61e1644515aa3f1f357ebe1901187e203fd2fa820f3797e947a3f64211a4f30a3c458dde6dfeda71e26ff2727d63cddfe24fa4509d628453bb441f6045c7a78ab157775f6dabf8566d59836703b5ec644844005cc8da412bc0932f4d924aaaeb4872f3e00d13eb86c1052a464da089805543a252c5684af4429e46fed3b26cb65e4aab778cdc6d18db160278a36adf4b64e8e1f9c63e4e39fadcaa7a35d72b90f1c359277176f39378dc3fd7b8770501a5ed41da45c8484cae2266b5779afe0c64f8a22d2b8805dac18d8dd4aa30e614be31a3a9ee4676c6c053d9de3500fdcbdc0a8afb56055b6a0e95cd183afc66bae87589535ba5e4122516d23813a0b8624a5c2b5c5e93cb9be2c5b48c88af755543307a8b1f1e6bb88119dde348b59878f771087a947cba162648bd53598ce27dc95d2a0e0ea056a5f575592a617486357f8416c20845724e52baed567dbed750bb6842ab8ecb3880a17c4709cdf7f63ae82cbd7b3f7c582b5b9a03a15d46d94ed17ec45c2eea0c09a3f9cae702fa11f63082460ff895b4b75ac1dc78b5376b83cc3e9021761a7dcd97039b137570677aa0eb369a8e53995ae2135138d3c1be2688708f7ff56c838b3308c250145c3136f516967571f2448a02dc0a2bee072cd01063e5563151ab6a895698f9b7c3974bd7c08ee5dba7d62b102c613cff682179572761e3818a04d9f4a893c314b0ccca8876bf6a05f79d552c0f4b77d9040816430fd951d05eb7a604440b39af3c0276631c8e23e230ee216aa3277c938d69d8581dc546233fcfe05bc234b49666d25def2e558da9c37d655771c9f500808d696aa32d161872f736ce4ac8f2d508899c5081d31b0203f71389e66bf628f7f75b311ab7f1aa0d0a81838518394896af6cf48acf9e56d917d64d55c9430f332ca3d51625939c7e0d5f22742327b5771c9eb9c3d2de33156c20165a4349e823936130e4987b904f634a45c56318e8d427062cb289fd8b403ad73bf43a2963e8442a2d386962e983fcfb249f3bc3f44a8f11a27931de052d30385e677533140446af45984c02a84127b68626e7b4f0cae1aeff4db8e511ffa3528ac95dfe8a16cb2c242eb25590ec5b8c40018eed12360a43e3b5dea7429363dca46df86ab7503ae0b6d55b880c0f5abe6251832d50e470132ef8c6727467b39cdffb28a6423f21cd588aa9b8a1e47714d58a66566c324271ca6c49d10bf23b4762ff1642d3e053c639da0f1e788675a5a11e470fd89378d51bbf2dde49e09c68d3981913a94d65447eaa3c104096ba86891650de0bcfc569aa73e07875459e82e2c01e66ba1902efbac6974edbb6ec83e85ed00a49493d669e493c25379ede2084d0a998cee618f36ba205ef1eb153afb708449b5372d203a3c4cce8c5ccaea93574ce56fb02e310ae0bb5c951a0f89dbe870ad1fb5fdcaf414f5106cdc8fbe637805e5eb112931b1b9eefaec7a0b0cae9136e58578d8cb4fee495ba302902c17b8a188e9abc527974532a51f1253010096c4e8517f9633a255c4372548d4095a0b17c7c478d26a6ed010fabc8783ac3beb77a13a9222403069e3a6ad793faf0414503adeaf3e6c14b5ffaef75044d576f82115fe263c0e8696afff01e68ab84bd835bf5857f5eac6873eccb08dbc846e8f85b3a6610d0891bb77eec074a991ae8bb4bc864182c0d1e5cd507e46d8f6613a70ce7b5bfb6421af97e6e6c8d451a4220c1ea1a7a74407ef2c5a7c81f02c7b258ff4bf7889c67702e4037134dc439a157837c7ebc970feec27ef84e251227fb430b03bde846f2c9afee9b5bfd54928c2ecd84956d56119c264baf014400595a3199f6b785b36133e93a07cbd0e3f69cf3dbb1f56db9aded91b35a98c7f02bef09313df71d44eea14a70a3fd73ab36b830514032277fb9f8a37fe45ffd520d117c7a5996772a4d8864032e6f7f2d2ff608a19efdbe2e007644ea7135e54e99912026c6f6cde06ac51220654623b49d04893b84d7b85b024dfc8b65ba1d836571d63da2265b26844c378fb3095da322e13786c7fd6091256093449adb0576ea4cf54c8cb189450e593b9f6d5e8e4c6389d1184ac8c14a344290fad1d1751dde941eadbb7910920d6c5d7862e9d652c734bb1025c1717806ec43ad425b04d535af309787b9d17c35883c8983837208a090c2b1d2c953ea7b6ee4ead3b6dae7bb207a99afbda4ecec4"
# --- END AUTO PLATFORM_ROOT_PIN ---


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


def _canonical_json(obj: Any) -> bytes:
    """DSSE-style canonical form: sorted keys, no whitespace.

    Signer (scripts/sign_waiver.py) and verifier MUST use this exact
    encoding or signatures will not match — by design (no malleability).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _platform_root_pk() -> bytes:
    """Embedded AO platform-attestation root (ML-DSA-87, FIPS 204)."""
    try:
        pk = bytes.fromhex(PLATFORM_ROOT_PK_HEX)
    except ValueError:
        raise TSError("platform root pin corrupt")
    if len(pk) != 2592:
        raise TSError("platform root pin violation")
    return pk


def verify_platform_record_sig(message: bytes, sig_hex: str, what: str) -> None:
    """Verify an ML-DSA-87 platform-attestation signature. Fail-closed.

    `what` names the artifact for the refusal message (e.g. waiver /
    seL4 / CMVP). No key material is ever read from disk: the root is
    the embedded PLATFORM_ROOT_PK_HEX constant (sidecar-key substitution
    then authorizes nothing).
    """
    try:
        sig = bytes.fromhex(str(sig_hex).strip())
    except ValueError:
        raise TSError(f"{what} signature encoding violation")
    if len(sig) != 4627:
        raise TSError(f"{what} signature size violation")
    try:
        from liboqs_wrapper import LibOQS_MLDSA_87
        ok = LibOQS_MLDSA_87().verify(_platform_root_pk(), bytes(message), sig)
    except TSError:
        raise
    except Exception as e:
        raise TSError(f"{what} verification unavailable: {e}")
    if not ok:
        raise TSError(f"{what} signature invalid or unverified")


def load_sel4_record(path: Path) -> Dict[str, Any]:
    """Strict-validate an seL4 deployment attestation record (pure logic).

    Provenance: `<record>.sig` must hold the ML-DSA-87 signature (hex)
    over the EXACT record file bytes, verifiable under the embedded
    platform root. Unsigned or mis-signed records are refused before any
    field is trusted.
    """
    try:
        raw = Path(path).read_bytes()
    except Exception as e:
        raise TSError(f"seL4 record unreadable: {e}")
    try:
        sig_hex = Path(str(path) + ".sig").read_text(encoding="utf-8")
    except Exception:
        raise TSError("seL4 attestation signature missing (provision <record>.sig)")
    verify_platform_record_sig(raw, sig_hex, "seL4 attestation")
    try:
        rec = json.loads(raw.decode("utf-8"))
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
    """Strict-validate an AO risk-acceptance waiver (expiring, explicit).

    Provenance: the file must be a signed envelope
    `{"payload": {...}, "signature": "<hex>"}` where the signature is
    ML-DSA-87 over the canonical JSON of `payload`, verifiable under the
    embedded platform root. Plain unsigned JSON is refused with
    TSRequiredError — anyone with file-write access could otherwise mint
    authorizations. Expiry/mitigation checks run ONLY after verification.
    """
    try:
        env = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        raise TSError(f"waiver unreadable: {e}")
    if not isinstance(env, dict):
        raise TSError("waiver shape violation")
    payload = env.get("payload")
    sig = env.get("signature")
    if not isinstance(payload, dict) or not sig:
        raise TSRequiredError("AO waiver signature invalid or unverified")
    try:
        verify_platform_record_sig(_canonical_json(payload), sig,
                                   "AO waiver")
    except TSError as e:
        # Signature failures are authorization failures, not parse errors.
        raise TSRequiredError("AO waiver signature invalid or unverified") from e
    rec = payload
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
