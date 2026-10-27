#!/usr/bin/env python3
"""Offline dual-officer key-fill import (KMI fill-device equivalent in software).

Air-gapped key injection without a network: the ceremony side seals key
material so that it takes BOTH officers' passphrases to open (2-of-2; a
single compromised passphrase is useless), and every fill is ML-DSA-87
signed by the ceremony key (no TOFU on import). Transport is any removable
media (USB/SD) -- this module only ever reads a local file.

Security properties:
- 2-of-2: random DEK sealed per fill; DEK wrapped once per officer
  (scrypt N=131072 + AES-256-GCM). Both wraps must open.
- Authenticity: canonical fill doc ML-DSA-87 signed; trust anchor is a
  caller-supplied ceremony public key (pinned, never discovered).
- Freshness/single-use: expires_utc enforced; fill_id recorded in a
  0600 import registry -- re-import of the same fill fails closed.
- Fail-closed parsing: strict schema, 64KB size cap, no legacy formats.

This is the software half of physical fill (DS-101/DS-102 SKL hardware
remains the accredited path for classified use).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

FILL_MAGIC = "KMI-FILL-V1"
FILL_VERSION = 1
MAX_FILL_BYTES = 64 * 1024
_SCRYPT_N = 131072
_SCRYPT_R = 8
_SCRYPT_P = 1


class KeyFillError(Exception):
    """Raised when a key fill is invalid, untrusted, expired, or unopenable."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as e:
        raise KeyFillError(f"malformed base64 field: {e}") from e


def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _scrypt_kek(passphrase: str, salt: bytes) -> bytearray:
    """Scrypt KEK in a WIPEABLE bytearray (callers zeroize in finally)."""
    return bytearray(hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                                    n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                                    maxmem=256 * 1024 * 1024, dklen=32))


def _aes_seal(key: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), aad)


def _aes_open(key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        return AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ct), aad)
    except Exception as e:
        raise KeyFillError(f"authenticated decryption failed: {e}") from e


def create_key_fill(*, fill_id: str, payload: Dict[str, Any],
                    officer_ids: Sequence[str],
                    officer_passphrases: Sequence[str],
                    signing_key: bytes,
                    issuer_kid: str = "ceremony-root-1",
                    expires_hours: float = 72.0) -> Dict[str, Any]:
    """Seal a key-fill for two officers (ceremony side). Fail-closed."""
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(fill_id or "")):
        raise KeyFillError("bad fill_id")
    officers = [str(o or "") for o in officer_ids]
    passphrases = [str(p or "") for p in officer_passphrases]
    if len(officers) != 2 or len(passphrases) != 2:
        raise KeyFillError("exactly two officers and two passphrases required")
    if officers[0] == officers[1]:
        raise KeyFillError("officers must be distinct (dual custody)")
    for oid in officers:
        if not _re.fullmatch(r"[A-Za-z0-9_-]{1,64}", oid):
            raise KeyFillError(f"bad officer id {oid!r}")
    try:
        expiry_h = float(expires_hours)
    except (TypeError, ValueError) as e:
        raise KeyFillError(f"bad expires_hours: {e}") from e
    import math as _math
    if not _math.isfinite(expiry_h) or expiry_h <= 0:
        raise KeyFillError("expires_hours must be finite and positive")
    if any(len(p) < 8 for p in passphrases):
        raise KeyFillError("officer passphrases must be >= 8 chars")
    if not isinstance(payload, dict) or not payload:
        raise KeyFillError("payload must be a non-empty object")
    if not isinstance(signing_key, (bytes, bytearray)) or len(signing_key) != 4896:
        raise KeyFillError("signing_key must be a 4896-byte ML-DSA-87 private key")

    now = time.time()
    dek = bytearray(secrets.token_bytes(32))
    try:
        payload_blob = _canonical(payload)
        if len(payload_blob) > 32 * 1024:
            raise KeyFillError("payload too large (32KB cap)")
        enc_nonce, enc_ct = _aes_seal(
            dek, payload_blob, f"{FILL_MAGIC}:payload:{fill_id}".encode("utf-8"))
        wraps = []
        for oid, pw in zip(officers, passphrases):
            salt = secrets.token_bytes(32)
            kek = _scrypt_kek(pw, salt)
            try:
                w_nonce, w_ct = _aes_seal(
                    kek, dek, f"{FILL_MAGIC}:wrap:{fill_id}:{oid}".encode("utf-8"))
            finally:
                for i in range(len(kek)):
                    kek[i] = 0
            wraps.append({"officer_id": oid, "salt": _b64e(salt),
                          "nonce": _b64e(w_nonce), "ct": _b64e(w_ct)})
        doc = {
            "v": FILL_VERSION,
            "magic": FILL_MAGIC,
            "fill_id": fill_id,
            "created_utc": now,
            "expires_utc": now + expiry_h * 3600.0,
            "issuer_kid": str(issuer_kid),
            "payload_sha3_256": hashlib.sha3_256(payload_blob).hexdigest(),
            "officers": officers,
            "enc": {"nonce": _b64e(enc_nonce), "ct": _b64e(enc_ct)},
            "wraps": wraps,
        }
        from liboqs_wrapper import LibOQS_MLDSA_87
        sig = LibOQS_MLDSA_87().sign(bytes(signing_key), _canonical(doc))
        doc["sig"] = _b64e(bytes(sig))
        return doc
    finally:
        for i in range(len(dek)):
            dek[i] = 0


def _load_registry(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        raise KeyFillError(f"import registry unreadable: {e}") from e


def _save_registry(path: str, reg: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2, sort_keys=True)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


class _RegistryLock:
    """Exclusive cross-process lock for the single-use registry.

    check-then-record without locking admits a double-import race between
    two concurrent importer processes. os.open(O_CREAT|O_EXCL) is atomic
    on both Windows and POSIX; stale locks (>120s) are broken (crash-safe).
    """

    def __init__(self, registry_path: str, timeout_s: float = 30.0):
        self._lock_path = str(registry_path) + ".lock"
        self._timeout_s = float(timeout_s)
        self._fd: Optional[int] = None

    def __enter__(self) -> "_RegistryLock":
        import time as _time
        deadline = _time.time() + self._timeout_s
        while True:
            try:
                self._fd = os.open(self._lock_path,
                                   os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                try:
                    os.chmod(self._lock_path, 0o600)
                except OSError:
                    pass
                return self
            except FileExistsError:
                try:
                    age = _time.time() - os.path.getmtime(self._lock_path)
                except OSError:
                    age = 0.0
                if age > 120.0:
                    try:
                        os.unlink(self._lock_path)
                    except OSError:
                        pass
                    continue
                if _time.time() >= deadline:
                    raise KeyFillError(
                        "import registry busy (concurrent import?)")
                _time.sleep(0.05)

    def __exit__(self, *exc) -> None:
        try:
            if self._fd is not None:
                os.close(self._fd)
        except OSError:
            pass
        finally:
            self._fd = None
            try:
                os.unlink(self._lock_path)
            except OSError:
                pass


def import_key_fill(*, fill_path: Optional[str] = None,
                    fill_bytes: Optional[bytes] = None,
                    officer_ids: Sequence[str],
                    officer_passphrases: Sequence[str],
                    verify_key: bytes,
                    registry_path: str) -> Dict[str, Any]:
    """Open + verify + single-use-record a key fill (field side). Fail-closed.

    Returns {"fill_id", "payload", "imported_at"}. The payload is returned,
    never written, by this function -- the caller persists it under its own
    storage policy. Raises KeyFillError on any problem.
    """
    if (fill_path is None) == (fill_bytes is None):
        raise KeyFillError("provide exactly one of fill_path / fill_bytes")
    raw = fill_bytes if fill_bytes is not None else open(fill_path, "rb").read()
    if len(raw) > MAX_FILL_BYTES:
        raise KeyFillError("fill exceeds 64KB cap")
    try:
        doc = json.loads(bytes(raw).decode("utf-8"))
    except Exception as e:
        raise KeyFillError(f"fill is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise KeyFillError("fill must be a JSON object")
    for field in ("v", "magic", "fill_id", "created_utc", "expires_utc",
                  "issuer_kid", "payload_sha3_256", "officers", "enc",
                  "wraps", "sig"):
        if field not in doc:
            raise KeyFillError(f"fill missing required field: {field}")
    if doc["v"] != FILL_VERSION or doc["magic"] != FILL_MAGIC:
        raise KeyFillError("unsupported fill version/magic (no legacy formats)")
    if not isinstance(verify_key, (bytes, bytearray)) or len(verify_key) != 2592:
        raise KeyFillError("verify_key must be a 2592-byte ML-DSA-87 public key")
    try:
        _expires = float(doc["expires_utc"])
    except (TypeError, ValueError) as e:
        raise KeyFillError(f"bad expires_utc: {e}") from e
    if time.time() > _expires:
        raise KeyFillError("fill expired")
    officers = [str(o or "") for o in officer_ids]
    passphrases = [str(p or "") for p in officer_passphrases]
    if len(officers) != 2 or len(passphrases) != 2 or officers[0] == officers[1]:
        raise KeyFillError("exactly two distinct officers required")
    if set(officers) != set(str(o or "") for o in doc["officers"]):
        raise KeyFillError("officer set does not match fill ceremony set")

    # 1. Authenticity first (never open attacker bytes).
    sig = _b64d(str(doc["sig"]))
    body = {k: v for k, v in doc.items() if k != "sig"}
    from liboqs_wrapper import LibOQS_MLDSA_87
    try:
        sig_ok = bool(LibOQS_MLDSA_87().verify(bytes(verify_key), _canonical(body), bytes(sig)))
    except Exception:
        sig_ok = False
    if not sig_ok:
        raise KeyFillError("fill signature invalid (untrusted ceremony key?)")

    # 2-4 run under the registry lock so two concurrent importers cannot
    # both pass the single-use check for the same fill_id.
    with _RegistryLock(registry_path):
        # 2. Single-use registry (replay/rotation hygiene).
        fill_id = str(doc["fill_id"])
        reg = _load_registry(registry_path)
        if fill_id in reg:
            raise KeyFillError(f"fill {fill_id!r} already imported (replay refused)")

        # 3. Open both wraps -> DEK (2-of-2, either order).
        wraps = {w.get("officer_id"): w for w in doc["wraps"]
                 if isinstance(w, dict)}
        dek = None
        for oid, pw in zip(officers, passphrases):
            w = wraps.get(oid)
            if not isinstance(w, dict):
                raise KeyFillError(f"no wrap for officer {oid!r}")
            kek = _scrypt_kek(pw, _b64d(str(w["salt"])))
            try:
                dek = bytearray(_aes_open(
                    kek, _b64d(str(w["nonce"])), _b64d(str(w["ct"])),
                    f"{FILL_MAGIC}:wrap:{fill_id}:{oid}".encode("utf-8")))
            finally:
                for i in range(len(kek)):
                    kek[i] = 0
        if dek is None or len(dek) != 32:
            raise KeyFillError("DEK recovery failed")

        # 4. Unseal payload + integrity pin.
        try:
            enc = doc["enc"]
            payload_blob = _aes_open(
                dek, _b64d(str(enc["nonce"])), _b64d(str(enc["ct"])),
                f"{FILL_MAGIC}:payload:{fill_id}".encode("utf-8"))
        finally:
            for i in range(len(dek)):
                dek[i] = 0
        if hashlib.sha3_256(payload_blob).hexdigest() != str(doc["payload_sha3_256"]):
            raise KeyFillError("payload integrity mismatch")
        try:
            payload = json.loads(payload_blob.decode("utf-8"))
        except Exception as e:
            raise KeyFillError(f"payload is not valid JSON: {e}") from e
        if not isinstance(payload, dict):
            raise KeyFillError("payload must be a JSON object")

        reg[fill_id] = {"imported_at": time.time(),
                        "sha3_256": hashlib.sha3_256(payload_blob).hexdigest(),
                        "issuer_kid": str(doc["issuer_kid"])}
        _save_registry(registry_path, reg)
        return {"fill_id": fill_id, "payload": payload,
                "imported_at": reg[fill_id]["imported_at"]}


def verify_fill_signature(doc: Dict[str, Any], verify_key: bytes) -> bool:
    """Standalone signature check (auditors). Never raises."""
    try:
        if not isinstance(doc, dict) or "sig" not in doc:
            return False
        sig = _b64d(str(doc["sig"]))
        body = {k: v for k, v in doc.items() if k != "sig"}
        from liboqs_wrapper import LibOQS_MLDSA_87
        return bool(LibOQS_MLDSA_87().verify(bytes(verify_key), _canonical(body), bytes(sig)))
    except Exception:
        return False
