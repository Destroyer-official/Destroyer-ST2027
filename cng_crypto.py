#!/usr/bin/env python3
"""
cng_crypto.py — Validated-provider cryptographic backend on Windows.

All operations execute inside Microsoft's CMVP-validated Cryptographic
Primitives Library (bcryptprimitives.dll; e.g. CMVP #5410, FIPS 140-3,
Active through 2031-08-30: AES-GCM, SHS, HMAC, KDF SP 800-108, KAS,
DRBG) via CNG (bcrypt.dll), using ctypes only — no new dependencies.

This is the answer to "uncertified oqs.dll via ctypes": the symmetric /
hash / KDF / ECDH operations here run in a lab-certified module instead
of an uncertified one. PQC (ML-KEM/ML-DSA) runs in CNG where available
(Windows 11 24H2+, same validated-module family — approval scope for
the PQ mechanisms is an operator CMVP-record check, not asserted here).

Critical CNG fact encoded (verified live, cost hours to find): chaining
mode VALUES are full strings — BCRYPT_CHAIN_MODE_GCM is L"ChainingModeGCM",
not L"GCM". GetProperty("ChainingMode") returns e.g. "ChainingModeCBC".

Cross-provider bit-equality (OpenSSL == CNG == pycryptodome where
applicable) is asserted by crypto_selftest.py additions, not just here.
"""

from __future__ import annotations

import ctypes
import logging
import struct
from typing import Optional, Tuple

log = logging.getLogger("cng_crypto")

LP = ctypes.c_void_p
DW = ctypes.c_uint32
NT = ctypes.c_long
W = ctypes.c_wchar_p

_bcrypt: Optional[ctypes.CDLL] = None


class CngError(Exception):
    """Fail-closed CNG operation failure (NTSTATUS hex preserved)."""


def _lib():
    global _bcrypt
    if _bcrypt is None:
        if __import__("os").name != "nt":
            raise CngError("CNG validated provider is Windows-only")
        try:
            lib = ctypes.windll.LoadLibrary("bcrypt.dll")
        except OSError as e:
            raise CngError(f"bcrypt.dll unavailable: {e}")
        lib.BCryptOpenAlgorithmProvider.restype = NT
        lib.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(LP), W, W, DW]
        lib.BCryptCloseAlgorithmProvider.restype = NT
        lib.BCryptCloseAlgorithmProvider.argtypes = [LP, DW]
        lib.BCryptGetProperty.restype = NT
        lib.BCryptGetProperty.argtypes = [LP, W, LP, DW, ctypes.POINTER(DW), DW]
        lib.BCryptSetProperty.restype = NT
        lib.BCryptSetProperty.argtypes = [LP, W, LP, DW, DW]
        lib.BCryptGenerateSymmetricKey.restype = NT
        lib.BCryptGenerateSymmetricKey.argtypes = [
            LP, ctypes.POINTER(LP), LP, DW, LP, DW, DW]
        lib.BCryptEncrypt.restype = NT
        lib.BCryptEncrypt.argtypes = [LP, LP, DW, LP, LP, DW, LP, DW,
                                       ctypes.POINTER(DW), DW]
        lib.BCryptDecrypt.restype = NT
        lib.BCryptDecrypt.argtypes = [LP, LP, DW, LP, LP, DW, LP, DW,
                                      ctypes.POINTER(DW), DW]
        lib.BCryptDestroyKey.restype = NT
        lib.BCryptDestroyKey.argtypes = [LP]
        lib.BCryptCreateHash.restype = NT
        lib.BCryptCreateHash.argtypes = [LP, ctypes.POINTER(LP), LP, DW,
                                         LP, DW, DW]
        lib.BCryptHashData.restype = NT
        lib.BCryptHashData.argtypes = [LP, LP, DW, DW]
        lib.BCryptFinishHash.restype = NT
        lib.BCryptFinishHash.argtypes = [LP, LP, DW, DW]
        lib.BCryptDestroyHash.restype = NT
        lib.BCryptDestroyHash.argtypes = [LP]
        lib.BCryptKeyDerivation.restype = NT
        lib.BCryptKeyDerivation.argtypes = [LP, LP, LP, DW,
                                            ctypes.POINTER(DW), DW]
        lib.BCryptGenerateKeyPair.restype = NT
        lib.BCryptGenerateKeyPair.argtypes = [LP, ctypes.POINTER(LP), DW, DW]
        lib.BCryptFinalizeKeyPair.restype = NT
        lib.BCryptFinalizeKeyPair.argtypes = [LP, DW]
        lib.BCryptExportKey.restype = NT
        lib.BCryptExportKey.argtypes = [LP, LP, W, LP, DW,
                                        ctypes.POINTER(DW), DW]
        lib.BCryptImportKeyPair.restype = NT
        lib.BCryptImportKeyPair.argtypes = [LP, LP, W, ctypes.POINTER(LP),
                                            LP, DW, DW]
        lib.BCryptSecretAgreement.restype = NT
        lib.BCryptSecretAgreement.argtypes = [LP, LP, ctypes.POINTER(LP), DW]
        lib.BCryptDeriveKey.restype = NT
        lib.BCryptDeriveKey.argtypes = [LP, W, LP, LP, DW,
                                        ctypes.POINTER(DW), DW]
        lib.BCryptDestroySecret.restype = NT
        lib.BCryptDestroySecret.argtypes = [LP]
        lib.BCryptCreateHash.restype = NT
        lib.BCryptCreateHash.argtypes = [LP, ctypes.POINTER(LP), LP, DW,
                                         LP, DW, DW]
        lib.BCryptHashData.restype = NT
        lib.BCryptHashData.argtypes = [LP, LP, DW, DW]
        lib.BCryptFinishHash.restype = NT
        lib.BCryptFinishHash.argtypes = [LP, LP, DW, DW]
        lib.BCryptDestroyHash.restype = NT
        lib.BCryptDestroyHash.argtypes = [LP]
        lib.BCryptKeyDerivation.restype = NT
        lib.BCryptKeyDerivation.argtypes = [LP, LP, LP, DW,
                                            ctypes.POINTER(DW), DW]
        lib.BCryptGenerateKeyPair.restype = NT
        lib.BCryptGenerateKeyPair.argtypes = [LP, ctypes.POINTER(LP), DW, DW]
        lib.BCryptFinalizeKeyPair.restype = NT
        lib.BCryptFinalizeKeyPair.argtypes = [LP, DW]
        lib.BCryptExportKey.restype = NT
        lib.BCryptExportKey.argtypes = [LP, LP, W, LP, DW,
                                        ctypes.POINTER(DW), DW]
        lib.BCryptImportKeyPair.restype = NT
        lib.BCryptImportKeyPair.argtypes = [LP, LP, W, ctypes.POINTER(LP),
                                            LP, DW, DW]
        lib.BCryptSecretAgreement.restype = NT
        lib.BCryptSecretAgreement.argtypes = [LP, LP, ctypes.POINTER(LP), DW]
        lib.BCryptDeriveKey.restype = NT
        lib.BCryptDeriveKey.argtypes = [LP, W, LP, LP, DW,
                                        ctypes.POINTER(DW), DW]
        lib.BCryptDestroySecret.restype = NT
        lib.BCryptDestroySecret.argtypes = [LP]
        lib.BCryptEncapsulate.restype = NT
        lib.BCryptEncapsulate.argtypes = [LP, LP, DW, ctypes.POINTER(DW),
                                          LP, DW, ctypes.POINTER(DW), DW]
        lib.BCryptDecapsulate.restype = NT
        lib.BCryptDecapsulate.argtypes = [LP, LP, DW, LP, DW,
                                          ctypes.POINTER(DW), DW]
        lib.BCryptSignHash.restype = NT
        lib.BCryptSignHash.argtypes = [LP, LP, LP, DW, LP, DW,
                                       ctypes.POINTER(DW), DW]
        lib.BCryptVerifySignature.restype = NT
        lib.BCryptVerifySignature.argtypes = [LP, LP, LP, DW, LP, DW, DW]
        _bcrypt = lib
    return _bcrypt


def _check(rc: int, op: str) -> None:
    if int(rc) != 0:
        raise CngError(f"{op} failed: {int(rc) & 0xFFFFFFFF:#010x}")


def _wsz(s: str) -> Tuple[ctypes.Array, int]:
    raw = s.encode("utf-16-le") + b"\x00\x00"
    return ctypes.create_string_buffer(raw, len(raw)), len(raw)


class _AuthInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", DW), ("dwInfoVersion", DW),
        ("pbNonce", LP), ("cbNonce", DW),
        ("pbAuthData", LP), ("cbAuthData", DW),
        ("pbTag", LP), ("cbTag", DW),
        ("pbMacContext", LP), ("cbMacContext", DW),
        ("cbAAD", DW), ("cbData", ctypes.c_uint64), ("dwFlags", DW),
    ]


assert ctypes.sizeof(_AuthInfo) == 88, "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO layout"


def _open_aes_gcm():
    lib = _lib()
    halg = LP()
    _check(lib.BCryptOpenAlgorithmProvider(ctypes.byref(halg), "AES", None, 0),
           "open AES provider")
    try:
        mode, mlen = _wsz("ChainingModeGCM")
        _check(lib.BCryptSetProperty(halg, "ChainingMode", mode, mlen, 0),
               "set ChainingModeGCM")
        return halg
    except CngError:
        lib.BCryptCloseAlgorithmProvider(halg, 0)
        raise


def _new_aes_key(halg, key: bytes):
    if len(key) != 32:
        raise CngError("AES-256 requires 32-byte key")
    lib = _lib()
    cbobj = DW(0)
    cbr = DW(0)
    _check(lib.BCryptGetProperty(halg, "ObjectLength", ctypes.byref(cbobj),
                                 4, ctypes.byref(cbr), 0), "AES object length")
    hkey = LP()
    obj = ctypes.create_string_buffer(cbobj.value)
    _check(lib.BCryptGenerateSymmetricKey(halg, ctypes.byref(hkey), obj,
                                          cbobj.value, key, len(key), 0),
           "AES import key")
    return hkey, obj  # keep obj alive with the key!


def _auth_info(nonce: bytes, aad: bytes, tag_buf=None, tag_len: int = 16):
    ai = _AuthInfo()
    ai.cbSize = ctypes.sizeof(_AuthInfo)
    ai.dwInfoVersion = 1
    nbuf = ctypes.create_string_buffer(bytes(nonce))
    abuf = ctypes.create_string_buffer(bytes(aad)) if aad else None
    ai.pbNonce, ai.cbNonce = ctypes.addressof(nbuf), len(nonce)
    if abuf is not None:
        ai.pbAuthData, ai.cbAuthData = ctypes.addressof(abuf), len(aad)
    if tag_buf is not None:
        ai.pbTag, ai.cbTag = ctypes.addressof(tag_buf), tag_len
    # Buffers must outlive the call: stash refs on the struct.
    ai._keepalive = (nbuf, abuf, tag_buf)
    return ai


def aes256gcm_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> Tuple[bytes, bytes]:
    """AES-256-GCM via the validated provider. Returns (ct, tag16)."""
    if len(nonce) != 12 or len(pt) > 64 * 1024 * 1024:
        raise CngError("AES-GCM parameter violation")
    lib = _lib()
    halg = _open_aes_gcm()
    try:
        hkey, _obj = _new_aes_key(halg, bytes(key))
        try:
            cblen = DW(0)
            ai0 = _auth_info(nonce, aad)
            _check(lib.BCryptEncrypt(hkey, pt, len(pt), ctypes.byref(ai0),
                                     None, 0, None, 0, ctypes.byref(cblen), 0),
                   "AES-GCM size")
            ct = ctypes.create_string_buffer(cblen.value)
            tag = ctypes.create_string_buffer(16)
            ai = _auth_info(nonce, aad, tag, 16)
            _check(lib.BCryptEncrypt(hkey, pt, len(pt), ctypes.byref(ai),
                                     None, 0, ct, cblen.value,
                                     ctypes.byref(cblen), 0), "AES-GCM encrypt")
            return bytes(ct.raw[:cblen.value]), bytes(tag.raw)
        finally:
            lib.BCryptDestroyKey(hkey)
    finally:
        lib.BCryptCloseAlgorithmProvider(halg, 0)


def aes256gcm_decrypt(key: bytes, nonce: bytes, aad: bytes,
                      ct: bytes, tag: bytes) -> bytes:
    """AES-256-GCM decrypt (tag verified inside the module)."""
    if len(nonce) != 12 or len(tag) != 16:
        raise CngError("AES-GCM parameter violation")
    lib = _lib()
    halg = _open_aes_gcm()
    try:
        hkey, _obj = _new_aes_key(halg, bytes(key))
        try:
            pt = ctypes.create_string_buffer(len(ct))
            tbuf = ctypes.create_string_buffer(bytes(tag), 16)
            ai = _auth_info(nonce, aad, tbuf, 16)
            cblen = DW(0)
            _check(lib.BCryptDecrypt(hkey, ct, len(ct), ctypes.byref(ai),
                                     None, 0, pt, len(ct),
                                     ctypes.byref(cblen), 0), "AES-GCM decrypt")
            return bytes(pt.raw[:cblen.value])
        finally:
            lib.BCryptDestroyKey(hkey)
    finally:
        lib.BCryptCloseAlgorithmProvider(halg, 0)


def aes256gcm_decrypt(key: bytes, nonce: bytes, aad: bytes,
                      ct: bytes, tag: bytes) -> bytes:
    """AES-256-GCM decrypt (tag verified inside the module)."""
    if len(nonce) != 12 or len(tag) != 16:
        raise CngError("AES-GCM parameter violation")
    lib = _lib()
    halg = _open_aes_gcm()
    try:
        hkey, _obj = _new_aes_key(halg, bytes(key))
        try:
            pt = ctypes.create_string_buffer(len(ct))
            tbuf = ctypes.create_string_buffer(bytes(tag), 16)
            ai = _auth_info(nonce, aad, tbuf, 16)
            cblen = DW(0)
            _check(lib.BCryptDecrypt(hkey, ct, len(ct), ctypes.byref(ai),
                                     None, 0, pt, len(ct),
                                     ctypes.byref(cblen), 0), "AES-GCM decrypt")
            return bytes(pt.raw[:cblen.value])
        finally:
            lib.BCryptDestroyKey(hkey)
    finally:
        lib.BCryptCloseAlgorithmProvider(halg, 0)


_BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008


def _open_hash_alg(hmac: bool = False):
    lib = _lib()
    halg = LP()
    flags = _BCRYPT_ALG_HANDLE_HMAC_FLAG if hmac else 0
    _check(lib.BCryptOpenAlgorithmProvider(ctypes.byref(halg), "SHA384",
                                           None, flags), "open SHA384")
    return halg


def sha384(data: bytes) -> bytes:
    """SHA-384 via the validated provider."""
    lib = _lib()
    halg = _open_hash_alg()
    try:
        cbobj = DW(0)
        cbr = DW(0)
        _check(lib.BCryptGetProperty(halg, "ObjectLength", ctypes.byref(cbobj),
                                     4, ctypes.byref(cbr), 0), "hash object length")
        hhash = LP()
        obj = ctypes.create_string_buffer(cbobj.value)
        _check(lib.BCryptCreateHash(halg, ctypes.byref(hhash), obj,
                                    cbobj.value, None, 0, 0), "create hash")
        try:
            _check(lib.BCryptHashData(hhash, data, len(data), 0), "hash data")
            out = ctypes.create_string_buffer(48)
            _check(lib.BCryptFinishHash(hhash, out, 48, 0), "finish hash")
            return bytes(out.raw)
        finally:
            lib.BCryptDestroyHash(hhash)
    finally:
        lib.BCryptCloseAlgorithmProvider(halg, 0)


def hmac_sha384(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA384 via the validated provider (HMAC-flagged hash provider)."""
    lib = _lib()
    halg = _open_hash_alg(hmac=True)
    try:
        cbobj = DW(0)
        cbr = DW(0)
        _check(lib.BCryptGetProperty(halg, "ObjectLength", ctypes.byref(cbobj),
                                     4, ctypes.byref(cbr), 0), "hmac object length")
        hhash = LP()
        obj = ctypes.create_string_buffer(cbobj.value)
        _check(lib.BCryptCreateHash(halg, ctypes.byref(hhash), obj,
                                    cbobj.value, key, len(key), 0),
               "create hmac")
        try:
            _check(lib.BCryptHashData(hhash, data, len(data), 0), "hmac data")
            out = ctypes.create_string_buffer(48)
            _check(lib.BCryptFinishHash(hhash, out, 48, 0), "finish hmac")
            return bytes(out.raw)
        finally:
            lib.BCryptDestroyHash(hhash)
    finally:
        lib.BCryptCloseAlgorithmProvider(halg, 0)


class _BCryptBuffer(ctypes.Structure):
    _fields_ = [("cbBuffer", DW), ("BufferType", DW), ("pvBuffer", LP)]


class _BCryptBufferDesc(ctypes.Structure):
    _fields_ = [("ulVersion", DW), ("cBuffers", DW), ("pBuffers", LP)]


_KDF_HKDF_INFO = 20  # verified live: only type yielding OpenSSL-identical output


def hkdf_sha384(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA384 extract+expand via the validated provider.

    Flow per BCryptKeyDerivation docs: GenerateSymmetricKey on the HKDF
    algorithm with IKM -> SetProperty HkdfHashAlgorithm=SHA384 ->
    SetProperty HkdfSaltAndFinalize=salt -> KeyDerivation with
    KDF_HKDF_INFO. Bit-equality with OpenSSL is asserted by tests.
    """
    if not 1 <= length <= 255 * 48:
        raise CngError("HKDF length violation")
    lib = _lib()
    halg = LP()
    _check(lib.BCryptOpenAlgorithmProvider(ctypes.byref(halg), "HKDF", None, 0),
           "open HKDF")
    try:
        hkdf = LP()
        _check(lib.BCryptGenerateSymmetricKey(
            halg, ctypes.byref(hkdf), None, 0, ikm, len(ikm), 0), "HKDF key")
        try:
            hv, _ = _wsz("SHA384")
            _check(lib.BCryptSetProperty(hkdf, "HkdfHashAlgorithm", hv, 16, 0),
                   "HKDF hash alg")
            _check(lib.BCryptSetProperty(hkdf, "HkdfSaltAndFinalize",
                                         salt, len(salt), 0), "HKDF salt")
            ibuf = ctypes.create_string_buffer(bytes(info))
            bb = _BCryptBuffer(len(info), _KDF_HKDF_INFO, ctypes.addressof(ibuf))
            desc = _BCryptBufferDesc(0, 1, ctypes.addressof(bb))
            out = ctypes.create_string_buffer(length)
            cbr = DW(0)
            _check(lib.BCryptKeyDerivation(hkdf, ctypes.byref(desc), out,
                                            length, ctypes.byref(cbr), 0),
                   "HKDF derive")
            if cbr.value != length:
                raise CngError("HKDF short derive")
            return bytes(out.raw)
        finally:
            lib.BCryptDestroyKey(hkdf)
    finally:
        lib.BCryptCloseAlgorithmProvider(halg, 0)


# P-384 ECDH public blob: BCRYPT_ECCKEY_BLOB{dwMagic, cbKey} + X + Y (BE).
_ECDH_P384_PUBLIC_MAGIC = 0x334B4345


def _ecdh_p384_keypair(lib):
    halg = LP()
    _check(lib.BCryptOpenAlgorithmProvider(ctypes.byref(halg), "ECDH_P384",
                                           None, 0), "open ECDH_P384")
    try:
        hkey = LP()
        _check(lib.BCryptGenerateKeyPair(halg, ctypes.byref(hkey), 384, 0),
               "ECDH keygen")
        _check(lib.BCryptFinalizeKeyPair(hkey, 0), "ECDH finalize")
        return halg, hkey
    except CngError:
        lib.BCryptCloseAlgorithmProvider(halg, 0)
        raise


def _ecdh_export_pub(lib, hkey) -> Tuple[bytes, bytes]:
    cb = DW(0)
    cbr = DW(0)
    _check(lib.BCryptExportKey(hkey, None, "ECCPUBLICBLOB", None, 0,
                               ctypes.byref(cb), 0), "ECDH pub size")
    blob = ctypes.create_string_buffer(cb.value)
    _check(lib.BCryptExportKey(hkey, None, "ECCPUBLICBLOB", blob, cb.value,
                               ctypes.byref(cbr), 0), "ECDH pub export")
    raw = bytes(blob.raw[:cbr.value])
    magic, cbkey = struct.unpack("<II", raw[:8])  # BCRYPT_ECCKEY_BLOB: LE ULONGs
    if magic != _ECDH_P384_PUBLIC_MAGIC or cbkey != 48 or len(raw) != 8 + 96:
        raise CngError("ECDH pub blob violation")
    return raw[8:8 + 48], raw[8 + 48:8 + 96]


def _ecdh_import_pub(lib, halg, x: bytes, y: bytes):
    if len(x) != 48 or len(y) != 48:
        raise CngError("ECDH peer share violation")
    blob = struct.pack("<II", _ECDH_P384_PUBLIC_MAGIC, 48) + bytes(x) + bytes(y)
    hpub = LP()
    _check(lib.BCryptImportKeyPair(halg, None, "ECCPUBLICBLOB",
                                   ctypes.byref(hpub), blob, len(blob), 0),
           "ECDH pub import")
    return hpub


def ecdh_p384_raw(peer_x: bytes, peer_y: bytes) -> Tuple[bytes, bytes, bytes]:
    """Ephemeral P-384 ECDH via the validated provider.

    Returns (x, y, raw_shared_secret_48B). The raw secret comes from
    BCRYPT_KDF_RAW_SECRET (L"TRUNCATE"), which CNG documents as
    LITTLE-endian — byte-flipped here to the big-endian x-coordinate
    the combiner (and OpenSSL) uses. Bit-equality asserted by tests.
    """
    import struct as _st
    lib = _lib()
    halg, hpriv = _ecdh_p384_keypair(lib)
    try:
        x, y = _ecdh_export_pub(lib, hpriv)
        hpub = _ecdh_import_pub(lib, halg, peer_x, peer_y)
        try:
            hsec = LP()
            _check(lib.BCryptSecretAgreement(hpriv, hpub, ctypes.byref(hsec), 0),
                   "ECDH agree")
            try:
                out = ctypes.create_string_buffer(48)
                cbr = DW(0)
                _check(lib.BCryptDeriveKey(hsec, "TRUNCATE", None, out, 48,
                                            ctypes.byref(cbr), 0),
                       "ECDH raw derive")
                if cbr.value != 48:
                    raise CngError("ECDH raw size violation")
                raw_le = bytes(out.raw)
            finally:
                lib.BCryptDestroySecret(hsec)
        finally:
            lib.BCryptDestroyKey(hpub)
        return x, y, raw_le[::-1]
    finally:
        lib.BCryptDestroyKey(hpriv)
        lib.BCryptCloseAlgorithmProvider(halg, 0)


# ---------------------------------------------------------------------------
# ML-KEM-1024 via CNG (FIPS 203, Windows 11 24H2+). Interop with liboqs
# (FIPS 203 ctypes) is asserted both directions by tests: CNG-encaps ->
# liboqs-decaps and liboqs-encaps -> CNG-decaps must agree.
# ---------------------------------------------------------------------------

_MLKEM_PUBLIC_MAGIC = 0x504B4C4D
_MLKEM1024_EK = 1568
_MLKEM1024_CT = 1568
_MLKEM1024_SS = 32


def _wsz_nul(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


def _mlkem_keygen_1024(lib):
    halg = LP()
    _check(lib.BCryptOpenAlgorithmProvider(ctypes.byref(halg), "ML-KEM",
                                           None, 0), "open ML-KEM")
    try:
        hkey = LP()
        _check(lib.BCryptGenerateKeyPair(halg, ctypes.byref(hkey), 0, 0),
               "ML-KEM keygen")
        try:
            _check(lib.BCryptSetProperty(
                hkey, "ParameterSetName", _wsz_nul("1024"),
                len(_wsz_nul("1024")), 0), "ML-KEM param 1024")
            _check(lib.BCryptFinalizeKeyPair(hkey, 0), "ML-KEM finalize")
        except CngError:
            lib.BCryptDestroyKey(hkey)
            raise
        return halg, hkey
    except CngError:
        lib.BCryptCloseAlgorithmProvider(halg, 0)
        raise


def _mlkem_export_ek(lib, hkey) -> bytes:
    """Export encapsulation key; returns RAW 1568B FIPS 203 ek."""
    cb = DW(0)
    cbr = DW(0)
    _check(lib.BCryptExportKey(hkey, None, "MLKEMPUBLICBLOB", None, 0,
                               ctypes.byref(cb), 0), "ML-KEM ek size")
    blob = ctypes.create_string_buffer(cb.value)
    _check(lib.BCryptExportKey(hkey, None, "MLKEMPUBLICBLOB", blob,
                               cb.value, ctypes.byref(cbr), 0),
           "ML-KEM ek export")
    raw = bytes(blob.raw[:cbr.value])
    magic, cb_ps, cb_key = struct.unpack("<III", raw[:12])
    if magic != _MLKEM_PUBLIC_MAGIC or len(raw) != 12 + cb_ps + cb_key:
        raise CngError("ML-KEM ek blob violation")
    if cb_key != _MLKEM1024_EK:
        raise CngError("ML-KEM ek size violation (want 1024)")
    return raw[12 + cb_ps:12 + cb_ps + cb_key]


def _mlkem_import_ek(lib, halg, ek: bytes):
    if len(ek) != _MLKEM1024_EK:
        raise CngError("ML-KEM ek size violation")
    ps = _wsz_nul("1024")
    blob = (struct.pack("<III", _MLKEM_PUBLIC_MAGIC, len(ps), len(ek))
            + ps + bytes(ek))
    hkey = LP()
    _check(lib.BCryptImportKeyPair(halg, None, "MLKEMPUBLICBLOB",
                                   ctypes.byref(hkey), blob, len(blob), 0),
           "ML-KEM ek import")
    return hkey


def _mlkem_lengths(lib, hkey) -> Tuple[int, int]:
    cb = DW(0)
    cbr = DW(0)
    _check(lib.BCryptGetProperty(hkey, "KEMSharedSecretLength",
                                 ctypes.byref(cb), 4, ctypes.byref(cbr), 0),
           "ML-KEM ss len")
    ss_len = int(cb.value)
    _check(lib.BCryptGetProperty(hkey, "KEMCiphertextLength",
                                 ctypes.byref(cb), 4, ctypes.byref(cbr), 0),
           "ML-KEM ct len")
    return ss_len, int(cb.value)


def mlkem1024_keygen() -> Tuple[bytes, object]:
    """Generate ML-KEM-1024 in CNG. Returns (raw_ek_1568, opaque_key)."""
    lib = _lib()
    halg, hkey = _mlkem_keygen_1024(lib)
    try:
        return _mlkem_export_ek(lib, hkey), _CngKemKey(lib, halg, hkey)
    except CngError:
        lib.BCryptDestroyKey(hkey)
        lib.BCryptCloseAlgorithmProvider(halg, 0)
        raise


class _CngKemKey:
    """RAII holder for a CNG ML-KEM key + provider (explicit close)."""

    def __init__(self, lib, halg, hkey):
        self._lib = lib
        self._halg = halg
        self._hkey = hkey
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            try:
                self._lib.BCryptDestroyKey(self._hkey)
            finally:
                self._lib.BCryptCloseAlgorithmProvider(self._halg, 0)
            self._closed = True

    def __del__(self):  # best effort; close() is authoritative
        try:
            self.close()
        except Exception:
            pass


def mlkem1024_encaps(ek: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate to a raw 1568B ek via CNG. Returns (ct, ss)."""
    lib = _lib()
    halg = LP()
    _check(lib.BCryptOpenAlgorithmProvider(ctypes.byref(halg), "ML-KEM",
                                           None, 0), "open ML-KEM")
    try:
        hkey = _mlkem_import_ek(lib, halg, ek)
        try:
            ss_len, ct_len = _mlkem_lengths(lib, hkey)
            if ss_len != _MLKEM1024_SS or ct_len != _MLKEM1024_CT:
                raise CngError("ML-KEM-1024 length violation")
            ss = ctypes.create_string_buffer(ss_len)
            ct = ctypes.create_string_buffer(ct_len)
            css = DW(0)
            cct = DW(0)
            _check(lib.BCryptEncapsulate(hkey, ss, ss_len, ctypes.byref(css),
                                          ct, ct_len, ctypes.byref(cct), 0),
                   "ML-KEM encaps")
            return bytes(ct.raw[:cct.value]), bytes(ss.raw[:css.value])
        finally:
            lib.BCryptDestroyKey(hkey)
    finally:
        lib.BCryptCloseAlgorithmProvider(halg, 0)


def mlkem1024_decaps(handle: _CngKemKey, ct: bytes) -> bytes:
    """Decapsulate with a CNG-held ML-KEM-1024 key. Returns 32B ss."""
    if len(ct) != _MLKEM1024_CT:
        raise CngError("ML-KEM ct size violation")
    if handle._closed:
        raise CngError("ML-KEM key already closed")
    lib = handle._lib
    ss = ctypes.create_string_buffer(_MLKEM1024_SS)
    css = DW(0)
    _check(lib.BCryptDecapsulate(handle._hkey, ct, len(ct), ss,
                                 _MLKEM1024_SS, ctypes.byref(css), 0),
           "ML-KEM decaps")
    if css.value != _MLKEM1024_SS:
        raise CngError("ML-KEM ss size violation")
    return bytes(ss.raw)
