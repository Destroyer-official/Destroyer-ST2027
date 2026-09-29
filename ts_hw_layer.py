#!/usr/bin/env python3
"""
ts_hw_layer.py — Hardware & Physical Security gating layer for TOP SECRET /
Strategic communications over the public internet (2027 target posture).

SCOPE (read this first — it defines what software can and cannot do):

  Software CANNOT certify physics. No Python module can create a FIPS 140-3
  Level 3/4 tamper envelope, TEMPEST shielding, RED/BLACK electrical isolation,
  or a one-way optical path. Those are properties of evaluated HARDWARE,
  accredited FACILITIES, and controlled INSTALLATIONS, certified by CST labs,
  National TEMPEST Authorities (NTAs), and NSA — never by application code.

  What this module DOES (and all of it is real, enforced, fail-closed):

    TS-1  Verifies a FIPS 140-3 validated cryptographic PROVIDER is actually
          loaded (real OSSL_PROVIDER_load probe), gates the OpenSSL series,
          and requires an operator CMVP record pinning the exact validated
          build. Refuses TOP SECRET operation on software-only Level-1
          embodiment and states plainly that software alone never reaches
          Level 3/4 physical security.
    TS-1b Verifies long-term keys live in HARDWARE custody (PKCS#11 /
          CNG / TPM-backed, non-exportable) and refuses operation when keys
          would exist in general-purpose CPU RAM.
    TS-2  Enforces RED/BLACK network separation as code: interface-pinned
          binds verified against live psutil enumeration, wildcard binds
          refused, RED and BLACK on the same interface refused.
    TS-3  Requires accredited TEMPEST facility/equipment approval (registry
          of SDIP-27 Level A/B/C certificates per SDIP-28 Zones 0/1/2 with
          SDIP-29 installation references) before TOP SECRET processing, and
          reports software-side emission-hygiene advisories.
    TS-4  Arms an active zeroization mesh: real tamper-event sources
          (debugger presence, TPM PCR mismatch, heartbeat loss, ML-DSA-87
          signed duress/revocation orders) driving the scorched-earth engine
          with a zeroization indicator, per FIPS 140-3 zeroization semantics.
    TS-5  Gates cross-domain transfer on an attested hardware data diode
          (CC EAL record + TX-only/RX-only + single-interconnect declaration)
          and provides the correct UDP-only, no-handshake transfer framing
          over it (an interactive handshake physically cannot cross a diode).

Research grounding (live-fetched, Sept 2026):
  [FIPS140-3] NIST FIPS 140-3 (ISO/IEC 19790:2012, tests per ISO/IEC 24759 /
    SP 800-140x, IG updated 2026-08-19). L3: identity auth, tamper response +
    zeroization circuitry where doors/covers/maintenance exist, hard opaque
    coatings/potting, SPA protection. L4: tamper envelope + response/
    zeroization, EFP/EFT. FIPS 140-2 -> CMVP Historical 21 Sep 2026.
  [OPENSSL-FIPS] OpenSSL FIPS Provider 3.1.2, CMVP #4985, Active through
    10 Mar 2030, usable across the 3.x series; durable target OpenSSL 3.5 LTS.
    NOTE verified from the #4985 security policy: the provider itself is
    overall Level 1 (software) — Level 3/4 physical security REQUIRES a
    hardware embodiment. This module enforces that distinction.
  [SDIP] SECAN SDIP-27/3 + SDIP-28/3 (24 Nov 2024): Level A/Zone 0 (1 m),
    Level B/Zone 1 (20 m), Level C/Zone 2 (100 m); SDIP-29 installation incl.
    RED/BLACK cable separation; NIAPC certified vendors, biennial audits.
    US equivalents: NSTISSAM Level I/II/III. The 1 m RED-BLACK minimum comes
    from NSTISSAM TEMPEST/2-95 as reported in open literature (the primary
    is classified; cf. Antic et al., Appl. Sci. 2024).
  [CSFC] NSA CSfC MA CP v2.8.0 + KM/SKM Annexes v3.0.0 (27 Mar 2026):
    layered Outer+Inner tunnels, CNSA 2.0 objective requirements,
    PSK/RFC-8784 quantum-resistant protection. Per the NSA CSfC FAQ, CSfC
    "has not replaced Type 1" — it is an approved ALTERNATIVE for defined
    mission profiles; Type 1 (NSA certification, EPL) remains mandatory for
    NSS SECRET and above where no CSfC profile applies. FIPS 140-3 alone
    does NOT qualify for NSS.
  [DIODE] CC evaluations: OPSWAT UGW EAL4+ (Apr 2025); ST Eng 5282/5283
    EAL4+AVA_VAN.5 (SCCS, valid to 7 Jul 2027); Fort Fox FFHDD EAL7+ (fixed
    function HW, no firmware/memory). SFRs FDP_IFC.2/FDP_IFF.1/FPT_FLS.1;
    TX-only/RX-only SFP+ pairs, independent power, fail-secure;
    OE.NETWORK (TOE = sole interconnect); UDP-style protocols only —
    no handshakes across the diode.
  [RATS] IETF RATS arch RFC 9334; RFC 9683/9684 (TPM network-device
    attestation, CHARRA YANG); EAT measured-component (2026 draft);
    Keylime model: nonce challenge -> AK-signed TPM quote over PCRs +
    IMA measurement log replayed against PCR10 + whitelist.
  [PKCS11-PQC] OASIS PKCS#11 v3.2 standardizes CKM_ML_DSA (6.67) and
    CKM_ML_KEM (6.68). Shipping firmware: Thales Luna 7.9.0 (Jul 2025) /
    7.9.2 (Feb 2026, +FIPS 140-3 L3 candidate) and Luna T-Series 7.15.0
    (Sep 2025, CNSA 2.0 signing); Utimaco Quantum Protect (ML-KEM/ML-DSA/
    LMS/XMSS, SLH-DSA roadmap). Tier-A probes match these; unknown tokens
    default-deny.
  [HOST-TPM] Verified live: TPM 2.0 present but TBS service absent on
    Windows 11 build 26200 (sc query tbs -> 1060), so TBS passthrough is
    structurally unavailable there; the CNG Microsoft Platform Crypto
    Provider works on the same host (TPM-backed ECDSA create/sign/verify/
    delete proven, private export refused, AES refused). TBS code is kept
    for TBS-equipped hosts; CNG is the live path here.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("ts_hw_layer")


# ---------------------------------------------------------------------------
# Errors + small helpers
# ---------------------------------------------------------------------------

class TSError(Exception):
    """Base for Top-Secret hardware-layer failures (fail-closed, generic)."""


class TSRequiredError(TSError):
    """Raised when TOP SECRET operation is attempted on unqualified platform."""


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _utcnow() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _expired(valid_through: str) -> bool:
    import datetime
    return datetime.date.fromisoformat(valid_through) < datetime.date.today()


# ---------------------------------------------------------------------------
# TS-1 — FIPS 140-3 validated-provider gate
# ---------------------------------------------------------------------------

FIPS_MIN_OPENSSL = (3, 1)          # validated provider family starts at 3.1.2
FIPS_KNOWN_GOOD_MODULE = "OpenSSL FIPS Provider"
FIPS_KNOWN_GOOD_VERSION = "3.1.2"
FIPS_KNOWN_GOOD_CERT = "4985"      # CMVP #4985, Active through 2030-03-10


@dataclass
class FipsStatus:
    openssl_version: str
    openssl_info: tuple
    provider_loaded: bool
    provider_name: str = "fips"
    cmvp_record_ok: bool = False
    cmvp_record: Dict[str, Any] = field(default_factory=dict)


def _libcrypto_path() -> Optional[str]:
    base = Path(sys.base_prefix)
    for cand in (base / "DLLs" / "libcrypto-3.dll",
                 base / "DLLs" / "libcrypto-3-x64.dll"):
        if cand.exists():
            return str(cand)
    found = ctypes.util.find_library("crypto")
    return found


def check_fips_provider() -> FipsStatus:
    """Probe the live OpenSSL for a loaded FIPS provider (REAL check).

    Uses OSSL_PROVIDER_available(NULL, "fips") via ctypes against the
    libcrypto backing this interpreter: a pure availability QUERY with no
    load side effects (unlike OSSL_PROVIDER_load). Returns a status object;
    never raises. 0 means no FIPS provider is installed/available here.
    """
    st = FipsStatus(openssl_version=ssl.OPENSSL_VERSION,
                    openssl_info=ssl.OPENSSL_VERSION_INFO,
                    provider_loaded=False)
    if ssl.OPENSSL_VERSION_INFO < FIPS_MIN_OPENSSL:
        return st
    try:
        path = _libcrypto_path()
        lib = ctypes.CDLL(path) if path and Path(str(path)).exists() else None
        if lib is None:
            try:
                lib = ctypes.CDLL("libcrypto.so.3")
            except OSError:
                return st
        if not hasattr(lib, "OSSL_PROVIDER_available"):
            return st
        lib.OSSL_PROVIDER_available.restype = ctypes.c_int
        lib.OSSL_PROVIDER_available.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        st.provider_loaded = bool(lib.OSSL_PROVIDER_available(None, b"fips"))
    except Exception as e:  # probe only; verdicts are made by callers
        log.debug("fips probe failed: %r", e)
    return st


def check_fips_cipher() -> Dict[str, Any]:
    """Prove AES-256-GCM resolves to the FIPS provider (REAL C API check).

    Fetches with the task-mandated "?fips=yes" property query, then reads
    back the ACTUAL provider name via EVP_CIPHER_get0_provider /
    OSSL_PROVIDER_get0_name and requires "fips". The name check is what
    makes this enforcing: "?" marks the clause preferred-but-optional per
    OpenSSL property(7), so a fetch alone could silently return the
    default provider — we refuse unless the implementation IS fips.
    (OSSL_PROVIDER-FIPS(7): "fips=yes" is mandatory for FIPS-approved
    operation.) Never raises; callers fail closed on ok False.
    """
    try:
        path = _libcrypto_path()
        lib = ctypes.CDLL(path) if path and Path(str(path)).exists() else None
        if lib is None:
            try:
                lib = ctypes.CDLL("libcrypto.so.3")
            except OSError:
                return {"ok": False, "reason": "libcrypto unloadable"}
        for fn in ("EVP_CIPHER_fetch", "EVP_CIPHER_get0_provider",
                   "OSSL_PROVIDER_get0_name", "EVP_CIPHER_free"):
            if not hasattr(lib, fn):
                return {"ok": False, "reason": f"C API {fn} absent"}
        lib.EVP_CIPHER_fetch.restype = ctypes.c_void_p
        lib.EVP_CIPHER_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                         ctypes.c_char_p]
        lib.EVP_CIPHER_get0_provider.restype = ctypes.c_void_p
        lib.EVP_CIPHER_get0_provider.argtypes = [ctypes.c_void_p]
        lib.OSSL_PROVIDER_get0_name.restype = ctypes.c_char_p
        lib.OSSL_PROVIDER_get0_name.argtypes = [ctypes.c_void_p]
        lib.EVP_CIPHER_free.restype = None
        lib.EVP_CIPHER_free.argtypes = [ctypes.c_void_p]
        cipher = lib.EVP_CIPHER_fetch(None, b"AES-256-GCM", b"?fips=yes")
        if not cipher:
            return {"ok": False,
                    "reason": "AES-256-GCM unfetchable under ?fips=yes"}
        try:
            prov = lib.EVP_CIPHER_get0_provider(cipher)
            name = lib.OSSL_PROVIDER_get0_name(prov) if prov else None
        finally:
            lib.EVP_CIPHER_free(cipher)
        if isinstance(name, bytes):
            name = name.decode("ascii", "replace")
        if name == "fips":
            return {"ok": True, "provider": name}
        return {"ok": False,
                "reason": f"AES-256-GCM resolved to provider {name!r}, not fips"}
    except Exception as e:  # probe only; verdicts are made by callers
        log.debug("fips cipher probe failed: %r", e)
        return {"ok": False, "reason": f"cipher probe error: {e}"}


def check_cmvp_record(record_path: Optional[Path] = None) -> Dict[str, Any]:
    """Validate the operator's CMVP record pinning the exact FIPS build.

    Record JSON: {"module", "version", "cmvp_cert", "valid_through"}.
    Provenance: `<record>.sig` must hold the ML-DSA-87 signature (hex)
    over the EXACT record file bytes, verifiable under the embedded
    platform root (shared with ts_runtime AO/seL4 gates) — an unsigned
    operator assertion authorizes nothing. An absent/expired/mismatched/
    mis-signed record fails closed in TS mode. (Pinning the live provider
    build string itself requires the operator's installed-provider
    inventory; the signed record is that inventory.)
    """
    path = Path(record_path) if record_path else Path(
        os.environ.get("P2P_FIPS_RECORD", ""))
    if str(path) in ("", "."):
        return {"ok": False, "reason": "no CMVP record provisioned"}
    try:
        raw = path.read_bytes()
    except Exception as e:
        return {"ok": False, "reason": f"unreadable CMVP record: {e}"}
    try:
        sig_hex = Path(str(path) + ".sig").read_text(encoding="utf-8")
    except Exception:
        return {"ok": False,
                "reason": "CMVP attestation signature missing (provision <record>.sig)"}
    try:
        from ts_runtime import verify_platform_record_sig
        verify_platform_record_sig(raw, sig_hex, "CMVP attestation")
    except Exception as e:
        return {"ok": False, "reason": f"CMVP signature invalid or unverified: {e}"}
    try:
        rec = json.loads(raw.decode("utf-8"))
    except Exception as e:
        return {"ok": False, "reason": f"unreadable CMVP record: {e}"}
    if not isinstance(rec, dict):
        return {"ok": False, "reason": "CMVP record shape violation (need object)"}
    for k in ("module", "version", "cmvp_cert", "valid_through"):
        if not rec.get(k):
            return {"ok": False, "reason": f"CMVP record missing {k}"}
    try:
        if _expired(rec["valid_through"]):
            return {"ok": False, "reason": "CMVP record expired"}
    except ValueError:
        return {"ok": False, "reason": "bad valid_through date (YYYY-MM-DD)"}
    known = (rec["module"] == FIPS_KNOWN_GOOD_MODULE
             and rec["version"] == FIPS_KNOWN_GOOD_VERSION
             and str(rec["cmvp_cert"]) == FIPS_KNOWN_GOOD_CERT)
    return {"ok": True, "record": rec, "known_good": known,
            "note": ("CMVP #4985 family; software embodiment is Level 1 — "
                     "L3/4 physical security requires hardware (see custody gate)")
            if known else "operator-asserted build; AO must confirm CMVP Active status"}


def require_fips_module(record_path: Optional[Path] = None) -> FipsStatus:
    """Fail-closed FIPS gate for TOP SECRET operation."""
    st = check_fips_provider()
    if not st.provider_loaded:
        raise TSRequiredError(
            "no FIPS 140-3 provider loaded in this OpenSSL — TOP SECRET "
            "operation refused (install the validated provider, e.g. CMVP "
            "#4985 family on OpenSSL 3.5 LTS)")
    if st.openssl_info < FIPS_MIN_OPENSSL:
        raise TSRequiredError("OpenSSL series predates the validated provider family")
    cipher = check_fips_cipher()
    if not cipher.get("ok"):
        raise TSRequiredError(
            f"AES-256-GCM not served by the FIPS provider (?fips=yes): "
            f"{cipher.get('reason')}")
    rec = check_cmvp_record(record_path)
    st.cmvp_record_ok = bool(rec.get("ok"))
    st.cmvp_record = rec.get("record", {})
    if not st.cmvp_record_ok:
        raise TSRequiredError(f"CMVP record unacceptable: {rec.get('reason')}")
    return st


# ---------------------------------------------------------------------------
# TS-1b — Hardware custody for keys (never in general-purpose CPU RAM)
# ---------------------------------------------------------------------------

_HARDWARE_PROVIDER_TYPES = ("pkcs11", "windows_cng", "tpm", "cng", "hsm")


@dataclass
class CustodyAttestation:
    hardware: bool
    provider_type: Optional[str]
    pkcs11_libs: List[str]
    detail: str
    tier: str = "NONE"  # PQC-HW | KEK-WRAP | TPM-DEVICE | NONE (see below)


def probe_hardware_custody() -> CustodyAttestation:
    """Probe for a real hardware custody backend (REAL check, never raises)."""
    libs: List[str] = []
    ptype: Optional[str] = None
    active = False
    try:
        import platform_hsm_interface as hsm
        try:
            # NOTE: this API returns a DICT keyed by platform; the library
            # list lives under "current_platform". list() on the dict itself
            # would yield key names (always truthy) — a misread that would
            # fabricate custody. Extract the real list.
            res = hsm.get_available_pkcs11_libraries() or {}
            libs = list(res.get("current_platform") or [])
        except Exception:
            libs = []
        ptype = getattr(hsm, "_hsm_provider_type", None)
        active = bool(getattr(hsm, "_hardware_security_active", False))
    except Exception as e:
        log.debug("hsm probe failed: %r", e)
    hw = bool(active and (ptype in _HARDWARE_PROVIDER_TYPES or bool(libs)))
    # A bare PKCS#11 library file without an active provider is NOT custody.
    if libs and not active:
        hw = False
    return CustodyAttestation(hardware=hw, provider_type=ptype,
                              pkcs11_libs=libs,
                              detail=("hardware custody active" if hw else
                                      "no active hardware custody backend"))


def require_hardware_custody(purpose: str,
                               mesh: Optional[ZeroizeMesh] = None) -> CustodyAttestation:
    """Fail-closed, tiered custody gate for TOP SECRET key material.

    Tiers (strongest first):
      TIER-A "PQC-HW": ML-DSA/ML-KEM private operations inside the token
        (PKCS#11 v3.2 CKM_ML_DSA/CKM_ML_KEM class devices, e.g. Thales Luna
        fw >= 7.9, T-Series >= 7.15, Utimaco + Quantum Protect). Accepted
        outright for the data plane.
      TIER-B "KEK-WRAP": hardware AES key-wrapping KEK with PQ keys wrapped
        at rest (CSfC SKM pattern). Accepted for the data plane ONLY with an
        ARMED zeroize mesh covering in-use keys (locked memory + mesh).
      TIER-DEV "TPM-DEVICE": TPM-bound ECDSA device key (CNG Platform
        provider). Device-identity/attestation signatures ONLY — never data
        plane (non-PQ). Recorded opportunistically, never sufficient alone.

    Rationale (FIPS 140-3 L3/L4 + Type 1 baseline): at TOP SECRET, plaintext
    keys in general-purpose RAM violate the physical-security embodiment
    requirements. Software keystores are Level-1-at-best and refused here.
    """
    pqc = probe_pqc_token()
    if pqc is not None:
        return pqc
    kek = probe_kek_wrap()
    if kek is not None:
        if mesh is not None and mesh.armed:
            return kek
        raise TSRequiredError(
            f"KEK-wrap hardware found ({kek.detail}) but no ARMED zeroize "
            f"mesh covers in-use keys — TOP SECRET data plane refused")
    dev = probe_tpm_device()
    found = []
    if dev is not None:
        found.append(f"TPM device anchor present ({dev.detail}) — auth-only, not data-plane")
    raise TSRequiredError(
        f"no hardware cryptographic module for {purpose}: keys would "
        f"exist in CPU RAM — TOP SECRET operation refused (FIPS 140-3 "
        f"Level 3/4 or NSA Type-1 custody required)"
        + ("; " + "; ".join(found) if found else ""))


# ---------------------------------------------------------------------------
# Tier probes: PQC-HW (A) / KEK-WRAP (B) / TPM-DEVICE (DEV)
# ---------------------------------------------------------------------------

# Built-in PQC-capable token identification (documented firmware floors):
# Thales Luna fw >= 7.9.0 and T-Series >= 7.15.0 expose CKM_ML_KEM /
# CKM_ML_DSA (PKCS#11 v3.2 class); Utimaco Quantum Protect likewise.
# Operators extend via P2P_PQC_TOKENS JSON: [{manufacturer_substr,
# model_substr, min_fw: [major, minor], note}]. Unknown tokens default-deny.
_PQC_TOKEN_ALLOWLIST = [
    {"manufacturer_substr": "thales", "model_substr": "luna",
     "min_fw": [7, 9], "note": "Luna fw>=7.9 ML-KEM/ML-DSA"},
    {"manufacturer_substr": "utimaco", "model_substr": "",
     "min_fw": None, "note": "Utimaco Quantum Protect (operator must confirm)"},
]


def _token_allowlist() -> list:
    extra = []
    raw = os.environ.get("P2P_PQC_TOKENS", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                extra = [e for e in parsed if isinstance(e, dict)]
        except Exception as e:
            log.debug("P2P_PQC_TOKENS unreadable: %r", e)
    return _PQC_TOKEN_ALLOWLIST + extra


def _iter_token_infos(libs: List[str]):
    """Yield (lib_path, manufacturer, model, fw_major, fw_minor) per slot.

    Uses python-pkcs11 (already a repo dependency); read-only calls only
    (no login, no key handles): get_slots -> token info + mechanism list.
    Any failure yields nothing — absence of evidence is never custody.
    """
    try:
        import pkcs11 as _pkcs11
    except Exception:
        return
    for lib_path in libs:
        try:
            lib = _pkcs11.lib(lib_path)
            for slot in lib.get_slots(token_present=True):
                try:
                    ti = slot.get_token_info()
                    mechs = set()
                    try:
                        mechs = set(slot.get_mechanisms())
                    except Exception:
                        mechs = set()
                    fv_raw = ti.firmware_version or (0, 0)
                    if isinstance(fv_raw, str):
                        fv = tuple(int(x) for x in fv_raw.split(".")[:2])
                    else:
                        fv = tuple(int(x) for x in list(fv_raw)[:2])
                    yield (lib_path, str(ti.manufacturer_id or "").strip(),
                           str(ti.model or "").strip(), fv, mechs)
                except Exception:
                    continue
        except Exception:
            continue


def probe_pqc_token() -> Optional[CustodyAttestation]:
    """TIER-A: token performing ML-DSA/ML-KEM private ops in hardware."""
    base = probe_hardware_custody()
    if not base.pkcs11_libs:
        return None
    for _lib_path, mfr, model, fw, _mechs in _iter_token_infos(base.pkcs11_libs):
        for rule in _token_allowlist():
            if rule.get("manufacturer_substr", "").lower() not in mfr.lower():
                continue
            want_model = str(rule.get("model_substr", "") or "").lower()
            if want_model and want_model not in model.lower():
                continue
            min_fw = rule.get("min_fw")
            if min_fw and tuple(fw) < tuple(min_fw):
                continue
            return CustodyAttestation(
                hardware=True, provider_type="pkcs11",
                pkcs11_libs=base.pkcs11_libs, tier="PQC-HW",
                detail=f"PQC-capable token: {mfr} {model} fw {'.'.join(map(str, fw))} "
                       f"({rule.get('note', '')})")
    return None


def probe_kek_wrap() -> Optional[CustodyAttestation]:
    """TIER-B: hardware AES key-wrapping KEK (CSfC SKM pattern)."""
    base = probe_hardware_custody()
    if base.pkcs11_libs:
        try:
            import pkcs11 as _pkcs11
            need = {"AES_KEY_GEN", "AES_KW"}
            for _lib_path, mfr, model, _fw, mechs in _iter_token_infos(base.pkcs11_libs):
                names = {getattr(m, "name", str(m)) for m in mechs}
                if need.issubset(names):
                    return CustodyAttestation(
                        hardware=True, provider_type="pkcs11",
                        pkcs11_libs=base.pkcs11_libs, tier="KEK-WRAP",
                        detail=f"wrap-capable token: {mfr} {model} (AES_KEY_GEN+AES_KW)")
        except Exception as e:
            log.debug("kek token probe failed: %r", e)
    # CNG platform provider: proven live here to REFUSE persisted AES
    # (NTE_NOT_SUPPORTED), so no CNG KEK path exists on such hosts.
    return None


def probe_tpm_device() -> Optional[CustodyAttestation]:
    """TIER-DEV: TPM-bound ECDSA device key available (auth-only tier)."""
    try:
        import cng_platform
        h = cng_platform.open_platform_provider()
    except Exception as e:
        log.debug("tpm device probe failed: %r", e)
        return None
    try:
        cng_platform.close_handle(h)
    except Exception:
        pass
    return CustodyAttestation(hardware=True, provider_type="cng-tpm",
                              pkcs11_libs=[], tier="TPM-DEVICE",
                              detail="CNG Platform Crypto Provider (TPM-bound ECDSA device key)")


# ---------------------------------------------------------------------------
# TS-2 — RED/BLACK separation enforcement
# ---------------------------------------------------------------------------

@dataclass
class RedBlackConfig:
    red_bind: str = "127.0.0.1"     # RED plaintext side: loopback/internal only
    black_bind: str = ""            # BLACK ciphertext side: pinned external IP
    red_allow_nets: Tuple[str, ...] = ("127.0.0.0/8", "::1/128")
    black_port: int = 8888


def _local_iface_of(ip_str: str) -> Optional[str]:
    """Interface name owning ip_str, from live psutil enumeration."""
    import psutil
    target = ipaddress.ip_address(ip_str.strip().strip("[]"))
    for ifname, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            try:
                if ipaddress.ip_address(a.address) == target:
                    return ifname
            except ValueError:
                continue
    return None


def verify_red_black(cfg: RedBlackConfig) -> Dict[str, Any]:
    """Verify RED/BLACK interface separation against the live host.

    Rules (NSTISSAM TEMPEST/2-95 + SDIP-29 installation practice, as code):
      - RED binds loopback/internal allow-listed nets only (never external).
      - BLACK binds one pinned literal IP (never wildcard, never loopback in
        strict operation — loopback BLACK is a lab-only relaxation).
      - RED and BLACK must live on DIFFERENT interfaces (no single-NIC
        bridging of plaintext and ciphertext sides).
    """
    import psutil  # noqa: F401 — live enumeration below
    try:
        red_ip = ipaddress.ip_address(cfg.red_bind.strip().strip("[]"))
        black_ip = ipaddress.ip_address(cfg.black_bind.strip().strip("[]"))
    except ValueError:
        raise TSError("RED/BLACK binds must be literal IPs")
    if black_ip.is_unspecified or red_ip.is_unspecified:
        raise TSError("wildcard RED/BLACK bind refused")
    try:
        nets = [ipaddress.ip_network(n, strict=False) for n in cfg.red_allow_nets]
    except ValueError:
        raise TSError("RED allow-list network violation")
    if not any(red_ip in n for n in nets):
        raise TSError("RED bind outside allow-listed internal nets")
    red_if = _local_iface_of(str(red_ip))
    black_if = _local_iface_of(str(black_ip))
    if red_if is None:
        raise TSError("RED bind is not a local interface address")
    if black_if is None:
        raise TSError("BLACK bind is not a local interface address")
    if black_ip.is_loopback:
        raise TSError("BLACK side on loopback refused in separated operation")
    if red_if == black_if:
        raise TSError("RED and BLACK share one interface — bridging refused")
    if isinstance(cfg.black_port, bool) or not 1 <= cfg.black_port <= 65535:
        raise TSError("BLACK port violation")
    return {"ok": True, "red_iface": red_if, "black_iface": black_if,
            "red": str(red_ip), "black": str(black_ip)}


def enforce_bind(role: str, host: str, strict_black_loopback: bool = True) -> str:
    """Validate a single bind before listen/connect. Returns normalized IP."""
    if role.upper() not in ("RED", "BLACK"):
        raise TSError("bind role must be RED or BLACK")
    try:
        ip = ipaddress.ip_address(host.strip().strip("[]"))
    except ValueError:
        raise TSError(f"{role} bind must be a literal IP")
    if ip.is_unspecified:
        raise TSError(f"{role} wildcard bind refused")
    if role.upper() == "RED" and not (ip.is_loopback or ip.is_private):
        raise TSError("RED bind must be loopback or internal")
    if role.upper() == "BLACK" and strict_black_loopback and ip.is_loopback:
        raise TSError("BLACK bind on loopback refused (lab: strict_black_loopback=False)")
    return str(ip)


# ---------------------------------------------------------------------------
# TS-3 — TEMPEST facility/equipment approval registry
# ---------------------------------------------------------------------------

# Zone -> minimum SDIP-27 equipment level (SDIP-27/3 + SDIP-28/3, 24 Nov 2024).
ZONE_MIN_LEVEL = {0: "A", 1: "B", 2: "C"}
_LEVEL_RANK = {"C": 1, "B": 2, "A": 3}
TOP_SECRET_MIN_LEVEL = "A"   # TOP SECRET processing requires Level A equipment


@dataclass
class TempestCert:
    facility: str
    zone: int
    level: str                 # A/B/C per SDIP-27
    standard: str = "SDIP-27/3"
    nta_ref: str = ""
    vendor_niapc_ref: str = ""
    issued: str = ""
    expires: str = ""          # YYYY-MM-DD
    zone_report_ref: str = ""  # SDIP-28 zoning procedure report
    install_ref: str = ""      # SDIP-29 installation record
    classifications: Tuple[str, ...] = ("TOP SECRET",)


def load_tempest_registry(path: Path) -> List[TempestCert]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        raise TSError(f"TEMPEST registry unreadable: {e}")
    if not isinstance(raw, dict) or not isinstance(raw.get("certs", []), list):
        raise TSError("TEMPEST registry shape violation (need {certs: [...]})")
    certs = []
    for c in raw["certs"]:
        try:
            if not isinstance(c, dict):
                raise ValueError("entry must be an object")
            zone = c["zone"]
            if isinstance(zone, bool) or zone not in (0, 1, 2):
                raise ValueError("zone must be integer 0, 1, or 2")
            classes = c.get("classifications", ["TOP SECRET"])
            if not isinstance(classes, list) or not classes \
                    or not all(isinstance(x, str) for x in classes):
                raise ValueError("classifications must be a non-empty string list")
            certs.append(TempestCert(
                facility=str(c["facility"]), zone=zone,
                level=str(c["level"]).upper(), standard=c.get("standard", "SDIP-27/3"),
                nta_ref=c.get("nta_ref", ""), vendor_niapc_ref=c.get("vendor_niapc_ref", ""),
                issued=c.get("issued", ""), expires=c.get("expires", ""),
                zone_report_ref=c.get("zone_report_ref", ""),
                install_ref=c.get("install_ref", ""),
                classifications=tuple(classes)))
        except (KeyError, ValueError) as e:
            raise TSError(f"TEMPEST registry bad entry: {e}")
    return certs


def require_tempest_approval(zone: int, classification: str,
                             registry_path: Optional[Path] = None,
                             audit_cb: Optional[Callable[[str, dict], None]] = None) -> TempestCert:
    """Require accredited TEMPEST approval covering zone+classification.

    Physics is certified by NTAs and accredited labs, never by this code;
    this gate enforces that such an approval EXISTS, is CURRENT, and COVERS
    the intended operation — and refuses TOP SECRET processing otherwise.
    """
    if isinstance(zone, bool) or zone not in ZONE_MIN_LEVEL:
        raise TSError("zone must be 0, 1, or 2 per SDIP-28")
    path = Path(registry_path) if registry_path else Path(
        os.environ.get("P2P_TEMPEST_REGISTRY", ""))
    if str(path) in ("", "."):
        raise TSRequiredError("no TEMPEST registry provisioned — TOP SECRET refused")
    need = TOP_SECRET_MIN_LEVEL if classification.strip().upper() == "TOP SECRET" \
        else ZONE_MIN_LEVEL[zone]
    for cert in load_tempest_registry(path):
        if cert.zone != zone:
            continue
        if classification.strip().upper() not in [c.upper() for c in cert.classifications]:
            continue
        if _LEVEL_RANK.get(cert.level, 0) < _LEVEL_RANK[need]:
            continue
        try:
            if _expired(cert.expires):
                continue
        except ValueError:
            continue
        if not cert.zone_report_ref or not cert.install_ref:
            continue  # SDIP-28 zone report + SDIP-29 install record mandatory
        if audit_cb:
            audit_cb("tempest_approval_ok", {"facility": cert.facility,
                                             "zone": zone, "level": cert.level})
        return cert
    raise TSRequiredError(
        f"no current TEMPEST approval for zone {zone}/{classification} "
        f"(need Level {need}+ with SDIP-28/29 refs) — TOP SECRET refused")


def emission_hygiene() -> List[Dict[str, str]]:
    """Software-side emission-hygiene advisories (NOT shielding evidence).

    Honest labeling: these reduce accidental emanation risk in software;
    none of them constitutes TEMPEST compliance, which is a facility and
    equipment property certified by an NTA/accredited lab.
    """
    notes = [
        {"id": "AES-EVP", "status": "ENFORCED",
         "note": "bulk crypto via OpenSSL EVP (no userspace table AES)"},
        {"id": "NO-RED-LOG", "status": "POLICY",
         "note": "RED plaintext must never be written to logs; audit only metadata"},
        {"id": "SHIELDING", "status": "FACILITY-REQUIRED",
         "note": "radiated/conducted emanation control is a property of the "
                 "SDIP-27 evaluated enclosure + SDIP-29 installation, attested "
                 "in the registry — software cannot assert it"},
    ]
    notes.append({"id": "OPENSSL",
                  "status": "ENFORCED" if ssl.OPENSSL_VERSION_INFO >= (3, 5) else "ADVISORY",
                  "note": f"runtime OpenSSL {ssl.OPENSSL_VERSION}"})
    return notes


# ---------------------------------------------------------------------------
# TS-4 — Active zeroization mesh
# ---------------------------------------------------------------------------

class TamperSource:
    CHASSIS_INTRUSION = "CHASSIS_INTRUSION"
    DEBUG_INTERFACE = "DEBUG_INTERFACE"
    TPM_PCR_MISMATCH = "TPM_PCR_MISMATCH"
    HEARTBEAT_LOSS = "HEARTBEAT_LOSS"
    OPERATOR_DURESS = "OPERATOR_DURESS"
    REMOTE_REVOCATION = "REMOTE_REVOCATION"


@dataclass
class TamperEvent:
    source: str
    detail: str = ""
    ts: float = field(default_factory=time.time)


def probe_debug_interface() -> Optional[bool]:
    """True if a debugger/tracer is attached (REAL checks). None if unknown."""
    try:
        if os.name == "nt":
            import ctypes as _ct
            return bool(_ct.windll.kernel32.IsDebuggerPresent())
        with open("/proc/self/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    return int(line.split()[1]) != 0
    except Exception as e:
        log.debug("debug probe failed: %r", e)
    return None


def probe_chassis_intrusion() -> Optional[bool]:
    """Best-effort chassis-intrusion probe. None = no readable switch.

    Intrusion switches are board-specific (IPMI OEM sensors / WMI vendor
    extensions); absence of a readable switch is reported as UNKNOWN, never
    as "safe". Positive assertions only.
    """
    try:
        if os.name == "nt":
            import subprocess  # nosec: fixed argv, no shell
            p = subprocess.run(
                ["wmic", "path", "Win32_SystemEnclosure", "get", "SecurityBreach"],
                capture_output=True, text=True, timeout=10)
            if p.returncode != 0:
                return None
            # Strict line parse: SecurityBreach is a vendor-extension enum;
            # value 3 historically means intrusion asserted. Substring matching
            # here would false-positive on any "3" in headers/whitespace and
            # wrongly trigger scorched-earth zeroization — compare exact lines.
            for line in p.stdout.splitlines():
                if line.strip() == "3":
                    return True
            return None
    except Exception as e:
        log.debug("chassis probe failed: %r", e)
    return None


def read_tpm_pcrs(indices: Tuple[int, ...] = tuple(range(24))) -> Optional[Dict[int, str]]:
    """Read SHA-256 PCR digests from a real hardware TPM (or None).

    Windows path: TBS passthrough (Tbsi_Context_Create ->
    Tbsip_Submit_Command(TPM2_PCR_Read)). POSIX path: /dev/tpm0 resource
    manager is out of scope for this host build and returns None.
    Any failure (no TPM, no TBS context, TPM error) returns None, which
    callers must treat as UNKNOWN — never as trusted. Verified live: this
    dev box exposes no TPM (empty Win32_Tpm, TBS context refused), so this
    correctly returns None here and real digests on TPM-equipped hosts.
    """
    if os.name != "nt":
        return None
    for i in indices:
        if not 0 <= i <= 23:
            raise TSError("PCR index violation")
    try:
        tbs = ctypes.windll.LoadLibrary("tbs.dll")

        class TBS_CONTEXT_PARAMS(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32)]

        h = ctypes.c_void_p()
        if (tbs.Tbsi_Context_Create(ctypes.byref(TBS_CONTEXT_PARAMS(1)),
                                    ctypes.byref(h)) & 0xFFFFFFFF) != 0:
            return None
        try:
            mask = [0, 0, 0]
            for i in indices:
                mask[i // 8] |= 1 << (i % 8)
            sel = struct.pack(">IHB", 1, 0x000B, 3) + bytes(mask)
            cmd = struct.pack(">HII", 0x8001, 0, 0x17E) + sel
            cmd = cmd[:2] + struct.pack(">I", len(cmd)) + cmd[6:]
            out = ctypes.create_string_buffer(2048)
            outlen = ctypes.c_uint32(2048)
            tbs.Tbsip_Submit_Command.restype = ctypes.c_uint32
            rc = tbs.Tbsip_Submit_Command(h, 0, 100, cmd, len(cmd),
                                          out, ctypes.byref(outlen)) & 0xFFFFFFFF
            if rc != 0:
                return None
            data = out.raw[:outlen.value]
            if len(data) < 14 or struct.unpack(">I", data[6:10])[0] != 0:
                return None
            off = 14
            (cnt,) = struct.unpack(">I", data[off:off + 4]); off += 4
            idxs: List[int] = []
            for _ in range(cnt):
                _halg, sz = struct.unpack(">HB", data[off:off + 3]); off += 3
                selb = data[off:off + sz]; off += sz
                for b in range(sz * 8):
                    if selb[b // 8] >> (b % 8) & 1:
                        idxs.append(b)
            (dcnt,) = struct.unpack(">I", data[off:off + 4]); off += 4
            digests: Dict[int, str] = {}
            for n in range(dcnt):
                (dlen,) = struct.unpack(">H", data[off:off + 2]); off += 2
                if n < len(idxs):
                    digests[idxs[n]] = data[off:off + dlen].hex()
                off += dlen
            return digests or None
        finally:
            try:
                tbs.Tbsip_Context_Close(h)
            except Exception:
                pass
    except Exception as e:
        log.debug("tpm pcr read failed: %r", e)
        return None


def check_tpm_pcr(expected: Dict[int, str]) -> Optional[bool]:
    """Compare live TPM PCRs against operator-pinned expectations.

    Returns True (match), False (MISMATCH = positive tamper evidence), or
    None (no TPM readable — UNKNOWN, never trusted). Comparison is
    constant-time per PCR. Pinned values live in the operator's measured-boot
    policy (RATS/Keylime model: quote + IMA log + whitelist); this is the
    local PCR leg of that verification.
    """
    if not expected or not isinstance(expected, dict):
        raise TSError("PCR expectation must be a non-empty {index: hex} dict")
    for idx in expected:
        if isinstance(idx, bool) or not isinstance(idx, int) or not 0 <= idx <= 23:
            raise TSError("PCR index violation")
    live = read_tpm_pcrs(tuple(sorted(expected)))
    if live is None:
        return None
    for idx, want in expected.items():
        got = live.get(idx)
        if got is None:
            return False
        try:
            if not hmac.compare_digest(bytes.fromhex(got), bytes.fromhex(want)):
                return False
        except ValueError:
            raise TSError("PCR expectation encoding violation")
    return True


@dataclass
class TamperOrder:
    """ML-DSA-87-signed duress/revocation order (verified, replay-bound)."""
    action: str
    nonce: str
    ts: float
    sig: str = ""


_USED_ORDER_NONCES: set = set()
_ORDER_NONCE_FIFO: list = []  # eviction order for the cap below
_ORDER_LOCK = threading.Lock()
ORDER_MAX_AGE_S = 300.0
ORDER_NONCE_CAP = 8192  # bound replay memory for long uptimes (FIFO evict)


def verify_tamper_order(order: Dict[str, Any], authority_pub_hex: str) -> TamperOrder:
    """Verify a signed OPERATOR_DURESS / REMOTE_REVOCATION order (REAL sig).

    Envelope: {"action","nonce","ts","sig"} with sig = ML-DSA-87 over
    b"TS-TAMPER-v1" || action || nonce || struct(">Q", ts_ms). Rejects
    replays (used-nonce set) and stale orders (>300 s skew).
    """
    from liboqs_wrapper import LibOQS_MLDSA_87
    try:
        action = str(order["action"])
        nonce = str(order["nonce"])
        ts = float(order["ts"])
        sig = bytes.fromhex(order["sig"])
        pub = bytes.fromhex(authority_pub_hex)
    except (KeyError, ValueError, TypeError):
        raise TSError("malformed tamper order")
    if action not in (TamperSource.OPERATOR_DURESS, TamperSource.REMOTE_REVOCATION):
        raise TSError("tamper order action refused")
    if abs(time.time() - ts) > ORDER_MAX_AGE_S:
        raise TSError("stale tamper order")
    with _ORDER_LOCK:
        if nonce in _USED_ORDER_NONCES:
            raise TSError("replayed tamper order")
        body = b"TS-TAMPER-v1" + action.encode() + nonce.encode() + struct.pack(">Q", int(ts * 1000))
        if not LibOQS_MLDSA_87().verify(pub, body, sig):
            raise TSError("tamper order signature invalid")
        _USED_ORDER_NONCES.add(nonce)
        _ORDER_NONCE_FIFO.append(nonce)
        while len(_ORDER_NONCE_FIFO) > ORDER_NONCE_CAP:
            _USED_ORDER_NONCES.discard(_ORDER_NONCE_FIFO.pop(0))
    return TamperOrder(action=action, nonce=nonce, ts=ts, sig=order["sig"])


class ZeroizeMesh:
    """Active zeroization mesh: tamper events -> scorched-earth engine.

    FIPS 140-3 zeroization semantics: on trigger, ALL plaintext CSPs held by
    registered buffers/callbacks are destroyed, and the engine's audit file
    serves as the indicator of zeroization (IG 9.7.B).
    """

    def __init__(self, audit_cb: Optional[Callable[[str, dict], None]] = None,
                 audit_dir: Optional[Path] = None,
                 engine: Optional[Any] = None,
                 pcr_expected: Optional[Dict[int, str]] = None) -> None:
        from emergency_anti_tamper import get_emergency_zeroization_engine
        self.engine = engine if engine is not None else get_emergency_zeroization_engine()
        if audit_dir is not None:
            self.engine.audit_dir = Path(audit_dir)
        self.audit_cb = audit_cb
        self._lock = threading.Lock()
        self.armed = False
        self.last_event: Optional[TamperEvent] = None
        self._last_heartbeat = time.monotonic()
        self.pcr_expected = dict(pcr_expected) if pcr_expected else None

    def arm(self) -> None:
        with self._lock:
            self.armed = True
        self._audit("mesh_armed", {})

    def register_buffer(self, buf: bytearray) -> None:
        # Type-enforced: the engine shreds by index assignment, which raises
        # TypeError on immutable bytes INSIDE its per-buffer handler — a bytes
        # object here would be silently left unshredded. Refuse it loudly.
        if not isinstance(buf, bytearray):
            raise TSError("zeroize buffers must be mutable bytearray")
        self.engine.register_sensitive_buffer(buf)

    def register_callback(self, cb: Callable[[], None]) -> None:
        self.engine.register_cleanup_callback(cb)

    def note_heartbeat(self) -> None:
        with self._lock:
            self._last_heartbeat = time.monotonic()

    def check_heartbeat(self, max_age_s: float) -> None:
        if time.monotonic() - self._last_heartbeat > max_age_s:
            self.dispatch(TamperEvent(TamperSource.HEARTBEAT_LOSS,
                                      f"no heartbeat for >{max_age_s}s"))

    def poll_sensors(self) -> None:
        """Poll positive-assertion sensors; UNKNOWN never triggers."""
        if probe_debug_interface() is True:
            self.dispatch(TamperEvent(TamperSource.DEBUG_INTERFACE, "tracer attached"))
            return
        if probe_chassis_intrusion() is True:
            self.dispatch(TamperEvent(TamperSource.CHASSIS_INTRUSION, "switch asserted"))
            return
        if self.pcr_expected:
            pcr = check_tpm_pcr(self.pcr_expected)
            if pcr is False:  # positive mismatch evidence (None = unknown, ignore)
                self.dispatch(TamperEvent(TamperSource.TPM_PCR_MISMATCH,
                                          "live PCRs differ from pinned policy"))
                return

    def dispatch(self, event: TamperEvent) -> Dict[str, Any]:
        with self._lock:
            if not self.armed:
                raise TSError("zeroize mesh not armed")
            self.last_event = event
        self._audit("tamper_event", {"source": event.source, "detail": event.detail})
        report = self.engine.execute_scorched_earth_zeroization(
            trigger=event.source, operator_id="ZEROIZE_MESH", terminate_process=False)
        self._audit("zeroized", {"source": event.source,
                                 "indicator": str(self.engine.audit_dir)})
        return report

    def _audit(self, event: str, fields: dict) -> None:
        if self.audit_cb:
            try:
                self.audit_cb(f"ts_mesh:{event}", fields)
            except Exception as e:
                log.debug("mesh audit failed: %r", e)

    @property
    def zeroized(self) -> bool:
        return bool(self.engine.zeroized)


def inject_test_tamper(mesh: ZeroizeMesh, source: str = TamperSource.CHASSIS_INTRUSION) -> Dict[str, Any]:
    """Test-only tamper injector. REFUSED in production (fail-closed).

    Tamper *inputs* (switch assertions) are test-injectable; the crypto and
    shredding underneath are always real. Requires TS_MESH_TEST_ARM=1 and
    P2P_PRODUCTION unset AND P2P_TS_MODE unset — a fake tamper source must
    never exist in any production or TOP SECRET posture.
    """
    if _env_true("P2P_PRODUCTION") or _env_true("P2P_TS_MODE"):
        raise TSError("test tamper injection refused in production/TS mode")
    if os.environ.get("TS_MESH_TEST_ARM", "") != "1":
        raise TSError("test injector not armed (TS_MESH_TEST_ARM=1)")
    return mesh.dispatch(TamperEvent(source, "test injection"))


# ---------------------------------------------------------------------------
# TS-5 — Hardware data-diode gate + no-handshake transfer framing
# ---------------------------------------------------------------------------

@dataclass
class DiodeDevice:
    device_id: str
    vendor: str
    model: str
    cc_cert: str = ""          # e.g. "EAL4+AVA_VAN.5"
    cc_id: str = ""
    tx_only_attested: bool = False   # TX-only / RX-only SFP+ pair attested
    install_ref: str = ""      # single-interconnect (OE.NETWORK) record
    valid_through: str = ""    # YYYY-MM-DD
    direction: str = "low-to-high"


def load_diode_registry(path: Path) -> List[DiodeDevice]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        raise TSError(f"diode registry unreadable: {e}")
    if not isinstance(raw, dict) or not isinstance(raw.get("devices", []), list):
        raise TSError("diode registry shape violation (need {devices: [...]})")
    devs = []
    for d in raw["devices"]:
        try:
            if not isinstance(d, dict):
                raise ValueError("entry must be an object")
            if not isinstance(d.get("device_id"), str) or not d["device_id"]:
                raise ValueError("device_id must be a non-empty string")
            devs.append(DiodeDevice(
                device_id=d["device_id"], vendor=str(d.get("vendor", "")),
                model=str(d.get("model", "")), cc_cert=str(d.get("cc_cert", "")),
                cc_id=str(d.get("cc_id", "")), tx_only_attested=bool(d.get("tx_only_attested")),
                install_ref=str(d.get("install_ref", "")),
                valid_through=str(d.get("valid_through", "")),
                direction=str(d.get("direction", "low-to-high"))))
        except (KeyError, ValueError) as e:
            raise TSError(f"diode registry bad entry: {e}")
    return devs


def require_diode(device_id: str,
                  registry_path: Optional[Path] = None,
                  audit_cb: Optional[Callable[[str, dict], None]] = None) -> DiodeDevice:
    """Require an attested hardware diode as the SOLE cross-domain path.

    Enforces the evaluated configuration: TX-only/RX-only optics attested,
    single-interconnect installation record (OE.NETWORK), current validity.
    Software simplex alone is NEVER sufficient at TOP SECRET.
    """
    path = Path(registry_path) if registry_path else Path(
        os.environ.get("P2P_DIODE_REGISTRY", ""))
    if not str(path) or str(path) == ".":
        raise TSRequiredError("no diode registry provisioned — TOP SECRET refused")
    for dev in load_diode_registry(path):
        if dev.device_id != device_id:
            continue
        if not dev.tx_only_attested or not dev.install_ref:
            continue
        try:
            if _expired(dev.valid_through):
                continue
        except ValueError:
            continue
        if audit_cb:
            audit_cb("diode_approved", {"device": device_id, "cc": dev.cc_cert})
        return dev
    raise TSRequiredError(
        f"no valid attested diode {device_id} (need TX-only optics + "
        f"single-interconnect record, unexpired) — TOP SECRET refused")


DIODE_MANIFEST_VERSION = 1


def _diode_body(blob: bytes) -> Tuple[bytes, bytes]:
    digest = hashlib.sha3_512(blob).digest()
    return digest, b"TS-DIODE-v1" + digest + struct.pack(">Q", len(blob))


def _diode_package(blob: bytes, signer_sk: bytes, kid: str) -> bytes:
    """Manifest-framed package (raw-software-key path; see diode_send).

    Manifest: {v, sha3_512(blob), bytes, kid, sig} with sig = ML-DSA-87 over
    b"TS-DIODE-v1" || sha3_512(blob) || len(8BE). The receiver verifies the
    signature AND the hash before releasing the blob — authenticity and
    integrity without any reverse channel.
    """
    from liboqs_wrapper import LibOQS_MLDSA_87
    digest, body = _diode_body(blob)
    sig = LibOQS_MLDSA_87().sign(signer_sk, body)
    return _diode_wrap(blob, digest, kid, sig)


def _diode_package_with_signer(blob: bytes, sign_fn: Callable[[bytes], bytes], kid: str) -> bytes:
    """Manifest-framed package using a caller-provided signer (e.g. HSM)."""
    digest, body = _diode_body(blob)
    return _diode_wrap(blob, digest, kid, sign_fn(body))


def _diode_wrap(blob: bytes, digest: bytes, kid: str, sig: bytes) -> bytes:
    manifest = {"v": DIODE_MANIFEST_VERSION, "sha3_512": digest.hex(),
                "bytes": len(blob), "kid": kid, "sig": sig.hex()}
    mblob = json.dumps(manifest, sort_keys=True).encode("utf-8")
    return struct.pack(">I", len(mblob)) + mblob + blob


def _diode_open(package: bytes, verifier_pk: bytes) -> bytes:
    from liboqs_wrapper import LibOQS_MLDSA_87
    if not isinstance(package, (bytes, bytearray)) or len(package) < 4:
        raise TSError("diode package too short")
    (mlen,) = struct.unpack(">I", package[:4])
    if mlen == 0 or mlen > 65536 or len(package) < 4 + mlen:
        raise TSError("diode manifest violation")
    try:
        manifest = json.loads(package[4:4 + mlen].decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be an object")
        blob = bytes(package[4 + mlen:])
        digest = bytes.fromhex(manifest["sha3_512"])
        sig = bytes.fromhex(manifest["sig"])
        blen = int(manifest["bytes"])
    except (ValueError, KeyError, TypeError) as e:
        raise TSError(f"diode manifest corrupt: {e}")
    if manifest.get("v") != DIODE_MANIFEST_VERSION:
        raise TSError("diode manifest version refused")
    if len(digest) != 64 or len(blob) != blen or len(blob) == 0:
        raise TSError("diode length violation")
    if not hmac.compare_digest(hashlib.sha3_512(blob).digest(), digest):
        raise TSError("diode integrity failed")
    body = b"TS-DIODE-v1" + digest + struct.pack(">Q", len(blob))
    try:
        verified = LibOQS_MLDSA_87().verify(bytes(verifier_pk), body, sig)
    except Exception as e:
        raise TSError(f"diode manifest verification failed: {e}")
    if not verified:
        raise TSError("diode manifest signature invalid")
    return blob


def diode_send(blob: bytes, signer: Any, kid: str, target_host: str,
               target_port: int, egress_source_ip: Optional[str] = None,
               k: int = 8, m: int = 4) -> bytes:
    """Send a manifest-framed package over UDP simplex (REAL send).

    signer is either raw ML-DSA-87 sk bytes (LAB ONLY — refused when
    hardware custody is required) or an IdentityHandle whose key lives in
    HSM/TPM custody (signed via the hardware path, never extracted).
    No handshake, no ACKs, no retransmit requests can exist here: a true
    diode has no reverse channel (cf. Fort Fox EAL7 rationale — protocols
    requiring handshakes do not function across it). Reliability comes from
    Reed-Solomon FEC (any K of K+M), NOT from feedback. The interactive
    secure_transmit_2027 handshake therefore MUST NOT be run across a diode;
    session keys for diode payloads are established by out-of-band ceremony.
    """
    from tactical_data_diode import DiodeTransmitter
    if not isinstance(blob, (bytes, bytearray)) or not blob or len(blob) > 50 * 1024 * 1024:
        raise TSError("diode payload size violation")
    if not isinstance(kid, str) or not kid or len(kid) > 128:
        raise TSError("diode kid violation")
    for name, val, lo, hi in (("k", k, 1, 64), ("m", m, 0, 64)):
        if isinstance(val, bool) or not isinstance(val, int) or not lo <= val <= hi:
            raise TSError(f"diode FEC parameter {name} violation")
    blob = bytes(blob)  # normalize: manifest framing needs immutable bytes
    if isinstance(signer, (bytes, bytearray)):
        if _env_true("P2P_REQUIRE_HARDWARE_IDENTITY") or _env_true("P2P_PRODUCTION"):
            raise TSRequiredError("diode manifest needs hardware-custody signing in TS mode")
        from liboqs_wrapper import LibOQS_MLDSA_87
        sk = bytes(signer)
        package = _diode_package_with_signer(
            blob, lambda body: LibOQS_MLDSA_87().sign(sk, body), kid)
    elif hasattr(signer, "sig_pk") and hasattr(signer, "stored_in_hsm"):
        from secure_transmit_2027 import sign_with_identity  # lazy: no import cycle
        package = _diode_package_with_signer(
            blob, lambda body: sign_with_identity(signer, body), kid)
    else:
        raise TSError("diode signer must be ML-DSA-87 sk bytes or IdentityHandle")
    tx = DiodeTransmitter(target_host=target_host, target_port=target_port,
                          egress_source_ip=egress_source_ip)
    try:
        return tx.send_payload(package, k=k, m=m)
    finally:
        tx.close()


def diode_receive(bind_host: str, bind_port: int, verifier_pk: bytes,
                  timeout_seconds: float = 30.0) -> bytes:
    """Receive + verify a manifest-framed package over UDP simplex."""
    from tactical_data_diode import DiodeReceiver
    try:
        ipaddress.ip_address(bind_host)
    except ValueError:
        raise TSError("diode bind must be a literal IP")
    if isinstance(bind_port, bool) or not isinstance(bind_port, int) \
            or not 1 <= bind_port <= 65535:
        raise TSError("diode port violation")
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) \
            or not 0 < timeout_seconds <= 3600:
        raise TSError("diode timeout violation")
    rx = DiodeReceiver(bind_host=bind_host, bind_port=bind_port)
    try:
        package = rx.receive_payload(timeout_seconds=timeout_seconds)
    finally:
        rx.close()
    if package is None:
        raise TSError("diode receive timeout")
    return _diode_open(package, verifier_pk)


# ---------------------------------------------------------------------------
# Aggregator: full TOP SECRET hardware-layer preflight
# ---------------------------------------------------------------------------

@dataclass
class TSLayerProfile:
    zone: int = 1
    classification: str = "TOP SECRET"
    redblack: RedBlackConfig = field(default_factory=RedBlackConfig)
    tempest_registry: str = ""
    diode_id: str = ""           # empty = no cross-domain path required
    diode_registry: str = ""
    fips_record: str = ""
    tamper_auth_pub: str = ""    # hex ML-DSA-87 pk for duress/revocation orders


def profile_from_env() -> TSLayerProfile:
    try:
        zone = int(os.environ.get("P2P_TS_ZONE", "1"))
    except (ValueError, TypeError):
        raise TSError("P2P_TS_ZONE must be 0, 1, or 2")
    if zone not in (0, 1, 2):
        raise TSError("P2P_TS_ZONE must be 0, 1, or 2")
    try:
        black_port = int(os.environ.get("P2P_BLACK_PORT", "8888"))
    except (ValueError, TypeError):
        raise TSError("P2P_BLACK_PORT must be 1..65535")
    return TSLayerProfile(
        zone=zone,
        classification=os.environ.get("P2P_TS_CLASS", "TOP SECRET"),
        redblack=RedBlackConfig(
            red_bind=os.environ.get("P2P_RED_BIND", "127.0.0.1"),
            black_bind=os.environ.get("P2P_BLACK_BIND", ""),
            black_port=black_port),
        tempest_registry=os.environ.get("P2P_TEMPEST_REGISTRY", ""),
        diode_id=os.environ.get("P2P_DIODE_ID", ""),
        diode_registry=os.environ.get("P2P_DIODE_REGISTRY", ""),
        fips_record=os.environ.get("P2P_FIPS_RECORD", ""),
        tamper_auth_pub=os.environ.get("P2P_TAMPER_AUTH_PUB", ""))


def require_ts_layer(profile: Optional[TSLayerProfile] = None,
                     mesh: Optional[ZeroizeMesh] = None,
                     audit_cb: Optional[Callable[[str, dict], None]] = None) -> Dict[str, Any]:
    """Full TOP SECRET hardware-layer preflight. First failure aborts.

    Order: armed mesh -> FIPS provider -> hardware custody (tiered) ->
    RED/BLACK -> TEMPEST -> diode (if required). Returns an evidence
    report dict. The mesh is armed FIRST because KEK-wrap custody (Tier-B)
    is only acceptable with an armed mesh covering in-use keys.
    """
    prof = profile or profile_from_env()
    report: Dict[str, Any] = {"ts_mode": True, "classification": prof.classification}

    if mesh is None:
        # TOP SECRET mandates an ARMED mesh; auto-provision one bound to this
        # preflight so the gate is self-contained. The operator's run loop
        # must still call mesh.poll_sensors() / mesh.note_heartbeat() and
        # register live key buffers via mesh.register_buffer(); the returned
        # handle is exposed in the report for exactly that wiring.
        mesh = ZeroizeMesh(audit_cb=audit_cb)
        mesh.arm()
    if not mesh.armed:
        raise TSRequiredError("zeroize mesh not armed")
    report["mesh"] = {"armed": True, "zeroized": mesh.zeroized}
    report["mesh_handle"] = mesh

    fips = require_fips_module(Path(prof.fips_record) if prof.fips_record else None)
    report["fips"] = {"provider": fips.provider_name, "openssl": fips.openssl_version,
                      "cmvp_cert": fips.cmvp_record.get("cmvp_cert")}

    custody = require_hardware_custody("TOP SECRET session keys", mesh=mesh)
    report["custody"] = {"provider": custody.provider_type, "tier": custody.tier,
                         "detail": custody.detail}

    # Opportunistic device anchor: TPM-bound ECDSA identity for attestation
    # evidence (RATS device-identity leg). Auth-only, never data-plane, never
    # mandatory (HSM-only hosts have no TPM) — recorded when present.
    dev = probe_tpm_device()
    report["device_anchor"] = {"present": dev is not None,
                               "detail": dev.detail if dev else "no TPM device anchor"}

    rb = verify_red_black(prof.redblack)
    report["red_black"] = rb

    cert = require_tempest_approval(prof.zone, prof.classification,
                                    Path(prof.tempest_registry) if prof.tempest_registry else None,
                                    audit_cb)
    report["tempest"] = {"facility": cert.facility, "level": cert.level, "zone": cert.zone}

    if prof.diode_id:
        dev = require_diode(prof.diode_id,
                            Path(prof.diode_registry) if prof.diode_registry else None,
                            audit_cb)
        report["diode"] = {"device": dev.device_id, "cc": dev.cc_cert}

    if audit_cb:
        audit_cb("ts_layer_ok", {"zone": prof.zone, "class": prof.classification})
    return report
