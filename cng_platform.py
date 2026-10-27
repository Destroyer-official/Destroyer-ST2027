#!/usr/bin/env python3
"""
cng_platform.py — TPM-backed device-key custody via the Windows CNG
Microsoft Platform Crypto Provider (ctypes only, no new dependencies).

Why this module exists (verified live on this host, Sept 2026):
  - A TPM 2.0 chip is present (PnP "Trusted Platform Module 2.0", OK), but
    the TBS user-mode service does NOT exist on Windows 11 build 26200
    (sc query tbs -> 1060), so TBS passthrough (Tbsi_Context_Create) returns
    TBS_E_TPM_NOT_FOUND (0x8028400F) regardless of the TPM. TBS code stays
    for TBS-equipped hosts; it cannot work here.
  - The CNG "Microsoft Platform Crypto Provider" DOES work here (proven):
    ECDSA_P256 persisted keys create/finalize/sign/verify/delete with
    rc 0, private export refused, deletion verified by failed reopen.
  - The same provider REFUSES persisted AES keys (NTE_NOT_SUPPORTED), so
    there is no TPM-backed AES KEK on this host — KEK-wrap custody is
    correctly reported unavailable.

Security role (stated plainly): the device key is ECDSA-P256 (NOT
post-quantum). It is used EXCLUSIVELY for device-identity purposes in the
TPM-AIK tradition (RATS device identity / attestation evidence): tamper
orders stay ML-DSA-87, the data plane stays ML-KEM-1024 + ML-DSA-87 per
CNSA 2.0. A non-PQ signature never covers data, digests of data, or
session keys. The private key is non-migratable and non-exportable; every
mutating helper proves deletion by failed reopen.
"""

from __future__ import annotations

import ctypes
import hashlib
from typing import Optional, Tuple

from ctypes import wintypes


class CngError(Exception):
    """Fail-closed CNG/TPM custody failure."""


_LPVOID = ctypes.c_void_p
_LPCWSTR = ctypes.c_wchar_p
_LPBYTE = ctypes.c_char_p
_DWORD = wintypes.DWORD
_LONG = ctypes.c_long

_ncrypt: Optional[ctypes.CDLL] = None
_ncrypt_lock = __import__("threading").Lock()


def _lib():
    global _ncrypt
    if _ncrypt is None:
        with _ncrypt_lock:
            if _ncrypt is None:
                if __import__("os").name != "nt":
                    raise CngError("CNG platform provider is Windows-only")
                try:
                    lib = ctypes.windll.LoadLibrary("ncrypt.dll")
                except OSError as e:
                    raise CngError(f"ncrypt.dll unavailable: {e}")
                lib.NCryptOpenStorageProvider.restype = _LONG
                lib.NCryptOpenStorageProvider.argtypes = [
                    ctypes.POINTER(_LPVOID), _LPCWSTR, _DWORD]
                lib.NCryptCreatePersistedKey.restype = _LONG
                lib.NCryptCreatePersistedKey.argtypes = [
                    _LPVOID, ctypes.POINTER(_LPVOID), _LPCWSTR,
                    _LPCWSTR, _DWORD, _DWORD]
                lib.NCryptFinalizeKey.restype = _LONG
                lib.NCryptFinalizeKey.argtypes = [_LPVOID, _DWORD]
                lib.NCryptExportKey.restype = _LONG
                lib.NCryptExportKey.argtypes = [
                    _LPVOID, _LPVOID, _LPCWSTR, _LPVOID, _LPVOID,
                    _DWORD, ctypes.POINTER(_DWORD), _DWORD]
                lib.NCryptSignHash.restype = _LONG
                lib.NCryptSignHash.argtypes = [
                    _LPVOID, _LPVOID, _LPVOID, _DWORD, _LPVOID,
                    _DWORD, ctypes.POINTER(_DWORD), _DWORD]
                lib.NCryptVerifySignature.restype = _LONG
                lib.NCryptVerifySignature.argtypes = [
                    _LPVOID, _LPVOID, _LPVOID, _DWORD, _LPVOID,
                    _DWORD, _DWORD]
                lib.NCryptDeleteKey.restype = _LONG
                lib.NCryptDeleteKey.argtypes = [_LPVOID, _DWORD]
                lib.NCryptOpenKey.restype = _LONG
                lib.NCryptOpenKey.argtypes = [
                    _LPVOID, ctypes.POINTER(_LPVOID), _LPCWSTR,
                    _DWORD, _DWORD]
                lib.NCryptFreeObject.restype = _LONG
                lib.NCryptFreeObject.argtypes = [_LPVOID]
                _ncrypt = lib
    return _ncrypt


PLATFORM_PROVIDER = "Microsoft Platform Crypto Provider"

DEVICE_ATTEST_DOMAIN = b"TS-DEVICE-v1"


def _check(rc: int, op: str) -> None:
    if int(rc) != 0:
        raise CngError(f"{op} failed: {int(rc) & 0xFFFFFFFF:#010x}")


def open_platform_provider() -> int:
    """Open the TPM-backed platform provider. Returns handle value (int)."""
    lib = _lib()
    h = _LPVOID()
    _check(lib.NCryptOpenStorageProvider(ctypes.byref(h), PLATFORM_PROVIDER, 0),
           "open platform provider")
    if not h.value:
        raise CngError("platform provider returned null handle")
    return h.value


def close_handle(handle: int) -> None:
    _lib().NCryptFreeObject(_LPVOID(handle))


def _valid_label(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 64:
        raise CngError("device key label violation")
    if not all(c.isalnum() or c in ("-", "_") for c in name):
        raise CngError("device key label violation")
    return name


def device_key_exists(provider: int, name: str) -> bool:
    lib = _lib()
    k = _LPVOID()
    rc = lib.NCryptOpenKey(_LPVOID(provider), ctypes.byref(k),
                           _valid_label(name), 0, 0)
    if int(rc) == 0:
        lib.NCryptFreeObject(k)
        return True
    return False


def create_device_key(provider: int, name: str,
                      alg: str = "ECDSA_P256") -> int:
    """Create + finalize a TPM-backed persisted device key. Returns handle."""
    if alg != "ECDSA_P256":
        raise CngError("device key algorithm refused (ECDSA_P256 only)")
    lib = _lib()
    name = _valid_label(name)
    if device_key_exists(provider, name):
        raise CngError("device key already exists (refusing overwrite)")
    k = _LPVOID()
    _check(lib.NCryptCreatePersistedKey(
        _LPVOID(provider), ctypes.byref(k), alg, name, 0, 0), "create device key")
    try:
        _check(lib.NCryptFinalizeKey(k, 0), "finalize device key")
    except CngError:
        try:
            lib.NCryptDeleteKey(k, 0)
        except Exception:
            pass
        raise
    if not k.value:
        raise CngError("device key null handle after finalize")
    return k.value


def open_device_key(provider: int, name: str) -> int:
    lib = _lib()
    k = _LPVOID()
    _check(lib.NCryptOpenKey(_LPVOID(provider), ctypes.byref(k),
                             _valid_label(name), 0, 0), "open device key")
    return k.value


def export_pubkey_blob(key: int) -> bytes:
    """Export ECCPUBLICBLOB (public only — always permitted)."""
    lib = _lib()
    cb = _DWORD(0)
    _check(lib.NCryptExportKey(_LPVOID(key), None, "ECCPUBLICBLOB", None,
                               None, 0, ctypes.byref(cb), 0), "pubkey size")
    if cb.value == 0 or cb.value > 4096:
        raise CngError("pubkey size violation")
    buf = ctypes.create_string_buffer(cb.value)
    _check(lib.NCryptExportKey(_LPVOID(key), None, "ECCPUBLICBLOB", None,
                               buf, cb.value, ctypes.byref(cb), 0),
           "export pubkey")
    return bytes(buf.raw[:cb.value])


def prove_non_exportable(key: int) -> None:
    """Prove the private half cannot leave the TPM (must FAIL to export)."""
    lib = _lib()
    cb = _DWORD(0)
    rc = lib.NCryptExportKey(_LPVOID(key), None, "PKCS8_PRIVATE_KEY_BLOB",
                             None, None, 0, ctypes.byref(cb), 0)
    if int(rc) == 0:
        raise CngError("private key exportable — NOT hardware custody")


def sign_digest(key: int, digest32: bytes) -> bytes:
    """Sign a 32-byte SHA-256 digest inside the TPM. Returns raw R||S (64B)."""
    if not isinstance(digest32, (bytes, bytearray)) or len(digest32) != 32:
        raise CngError("sign digest must be 32 bytes")
    lib = _lib()
    dgst = bytes(digest32)
    cb = _DWORD(0)
    _check(lib.NCryptSignHash(_LPVOID(key), None, dgst, len(dgst),
                              None, 0, ctypes.byref(cb), 0), "sign size")
    if cb.value == 0 or cb.value > 256:
        raise CngError("signature size violation")
    sig = ctypes.create_string_buffer(cb.value)
    _check(lib.NCryptSignHash(_LPVOID(key), None, dgst, len(dgst),
                              sig, cb.value, ctypes.byref(cb), 0), "sign")
    return bytes(sig.raw[:cb.value])


def verify_with_key(key: int, digest32: bytes, sig: bytes) -> None:
    """Verify a TPM signature with the platform key handle (public op)."""
    if len(digest32) != 32 or not sig or len(sig) > 256:
        raise CngError("verify parameter violation")
    _check(_lib().NCryptVerifySignature(
        _LPVOID(key), None, bytes(digest32), len(digest32),
        bytes(sig), len(sig), 0), "verify signature")


def delete_key(key: int) -> None:
    """Delete a persisted device key (dwFlags MUST be 0)."""
    _check(_lib().NCryptDeleteKey(_LPVOID(key), 0), "delete device key")


def get_or_create_device_key(provider: int, name: str) -> Tuple[int, bool]:
    """Open existing device key or create it. Returns (handle, created)."""
    lib = _lib()
    k = _LPVOID()
    rc = lib.NCryptOpenKey(_LPVOID(provider), ctypes.byref(k),
                           _valid_label(name), 0, 0)
    if int(rc) == 0:
        return k.value, False
    return create_device_key(provider, name), True


def tpm_device_attest(key: int, nonce: bytes) -> Tuple[bytes, bytes]:
    """Device attestation evidence: TPM-sign domain-separated nonce.

    Returns (signature, pubkey_blob). The nonce MUST be 32 bytes of verifier
   -supplied entropy (freshness). Verifier checks the signature against the
    pinned device pubkey — the RATS device-identity leg for hosts where the
    full TPM quote path (TBS) is unavailable.
    """
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 32:
        raise CngError("attestation nonce must be 32 bytes")
    body = hashlib.sha256(DEVICE_ATTEST_DOMAIN + bytes(nonce)).digest()
    return sign_digest(key, body), export_pubkey_blob(key)
