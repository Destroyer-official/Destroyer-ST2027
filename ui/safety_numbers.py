#!/usr/bin/env python3
"""TOFU safety numbers + persistent pin store (Phase 0, no prod behavior change).

Both peers compute identical grouped numbers from the SAME inputs:
  SHA3-512(ML-DSA-87 identity public key) || SHA3-512(ECDH public key)
Verify once over an independent channel (in person / verified voice call).
On later sessions the stored pin is compared automatically; any change
refuses the connection until re-verified out-of-band (MITM guard:
see OPEN_INTERNET_HARDENING_PLAN.md T1).

Nothing here alters handshake behavior yet -- display + store only.
Enforcement wiring is Phase 0 item D0.3.
"""

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List

PIN_STORE = Path.home() / ".secure_p2p" / "pins.json"
GROUP = 4  # digits per group
# 12 groups x 4 decimal digits = 48 digits ~= 159 bits of the 512-bit digest
# shown for human comparison. Decimal truncation bias here is ~2^-353:
# cryptographically negligible; comparison security rests on the full
# SHA3-512 pin stored via check_pin/store_pin, not on the shown digits.
GROUPS = 12

# Optional HMAC key for pin entries. When P2P_PIN_KEK (or the storage
# passphrase) is configured, new pins are MACed and tampered entries are
# treated as CHANGED (fail-closed). Without it, pins rely on OS file ACLs
# (0600, created atomically). A KEK kept next to the store only raises the
# bar against offline file tampering, not against full-account compromise.
_PIN_KEK = (os.environ.get("P2P_PIN_KEK") or os.environ.get("P2P_STORAGE_PASSPHRASE") or "").encode('utf-8')


def fingerprint_bundle(bundle: dict) -> str:
    """Canonical 7-field SHA3-512 identity fingerprint for key continuity.
    Covers all stable identity keys across classical and post-quantum layers:
    - identity
    - static_key
    - signing_key
    - signed_prekey
    - prekey_signature
    - kem_public_key
    - falcon_public_key
    Fresh per-handshake fields (ephemeral keys, nonces, timestamps) and bundle
    signatures are excluded so the resulting pin is deterministic and stable.
    """
    if not isinstance(bundle, dict):
        return ""
    fp_fields = {
        k: str(bundle.get(k, ''))
        for k in ('identity', 'static_key', 'signing_key',
                  'signed_prekey', 'prekey_signature',
                  'kem_public_key', 'falcon_public_key')
    }
    fp_src = json.dumps(fp_fields, sort_keys=True).encode('utf-8')
    return hashlib.sha3_512(fp_src).hexdigest()


def safety_numbers(key_a: bytes, key_b: bytes) -> str:
    """Grouped decimal safety number over identity keys (SHA3-512).
    Canonically sorts both key inputs to guarantee symmetric agreement:
    safety_numbers(A, B) == safety_numbers(B, A).
    """
    first_pk, second_pk = sorted([key_a, key_b])
    digest = hashlib.sha3_512(first_pk + b"||" + second_pk).digest()
    value = int.from_bytes(digest, "big")
    digits = str(value).zfill(GROUP * GROUPS)[-GROUP * GROUPS:]
    return " ".join(digits[i:i + GROUP] for i in range(0, len(digits), GROUP))


_INVALID_PIN_HOSTS = {  # nosec B104 - detection allowlist, never bound; identifies unpinnable targets to REJECT pinning
    "::", "0.0.0.0", "127.0.0.1", "::1", "localhost", "*", "0", "",
    "cert_tofu_::", "cert_tofu_0.0.0.0", "cert_tofu_127.0.0.1",
    "cert_tofu_::1", "cert_tofu_localhost", "cert_tofu_", "cert_tofu_*"
}


def is_unpinnable_target(target: str) -> bool:
    """Return True if target is a wildcard, loopback, or invalid host that should not be pinned to disk."""
    if not target or target.strip() in _INVALID_PIN_HOSTS:
        return True
    clean = target.strip().lower()
    if clean in _INVALID_PIN_HOSTS:
        return True
    if clean.startswith("cert_tofu_"):
        host_part = clean[10:].split("%")[0]
        if host_part in _INVALID_PIN_HOSTS:
            return True
        try:
            import ipaddress
            ip = ipaddress.ip_address(host_part)
            if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
                return True
        except ValueError:
            pass
    return False


_PINENC_MAGIC = b"PINENC_V1:"


def _pins_envelope_key() -> Optional[bytes]:
    pw = _PIN_KEK
    if not pw:
        return None
    return hashlib.scrypt(pw,
                          salt=b"PinsStore::Envelope::v1",
                          n=32768, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def load_pins() -> dict:
    if not PIN_STORE.exists():
        return {}
    raw = PIN_STORE.read_bytes()
    if raw.startswith(_PINENC_MAGIC):
        key = _pins_envelope_key()
        if key is None:
            raise ValueError("pins.json is sealed but P2P_PIN_KEK / P2P_STORAGE_PASSPHRASE is not set (fail-closed)")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = raw[len(_PINENC_MAGIC):len(_PINENC_MAGIC) + 12]
        ct = raw[len(_PINENC_MAGIC) + 12:]
        decrypted = AESGCM(key).decrypt(nonce, ct, b"PinsStore::v1")
        return json.loads(decrypted.decode('utf-8'))
    try:
        return json.loads(raw.decode('utf-8'))
    except Exception:
        return {}


def _mac_entry(peer_id: str, fingerprint: str) -> str:
    return hmac.new(_PIN_KEK, f"{peer_id}||{fingerprint}".encode('utf-8'),
                    hashlib.sha512).hexdigest()


def _entry_matches(peer_id: str, fingerprint: str, stored) -> bool:
    """Compare a stored pin entry. Plain strings compare directly (legacy);
    dict entries require a valid HMAC when a KEK is configured."""
    if isinstance(stored, dict):
        fp = stored.get("fp", "")
        mac = stored.get("mac", "")
        if _PIN_KEK:
            if not mac or not hmac.compare_digest(
                    mac, _mac_entry(peer_id, fp)):
                return False  # tampered entry: never 'match'
        return hmac.compare_digest(str(fp), str(fingerprint))
    return hmac.compare_digest(str(stored), str(fingerprint))


def check_pin(peer_id: str, fingerprint: str) -> str:
    """Return 'new' | 'match' | 'CHANGED' | 'unpinnable' (caller decides enforcement)."""
    if is_unpinnable_target(peer_id):
        return "unpinnable"
    pins = load_pins()
    if peer_id not in pins:
        return "new"
    return "match" if _entry_matches(peer_id, fingerprint, pins[peer_id]) else "CHANGED"


def store_pin(peer_id: str, fingerprint: str) -> None:
    if is_unpinnable_target(peer_id):
        return
    pins = load_pins()
    if _PIN_KEK:
        pins[peer_id] = {"fp": fingerprint, "mac": _mac_entry(peer_id, fingerprint)}
    else:
        pins[peer_id] = fingerprint
    _atomic_write_json(PIN_STORE, pins)


def revoke_pin(peer_id: str) -> bool:
    """Explicitly delete and revoke a peer's pinned identity fingerprint from the store."""
    if not PIN_STORE.exists():
        return False
    pins = load_pins()
    if peer_id in pins:
        del pins[peer_id]
        _atomic_write_json(PIN_STORE, pins)
        return True
    return False


def _atomic_write_json(path: Path, data: dict) -> None:
    """Write JSON atomically (tmp + fsync + replace) with 0600 from creation, encrypted if KEK set."""
    path.parent.mkdir(parents=True, exist_ok=True)
    key = _pins_envelope_key()
    if key is not None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)
        payload = json.dumps(data, indent=2).encode('utf-8')
        ct = AESGCM(key).encrypt(nonce, payload, b"PinsStore::v1")
        sealed_bytes = _PINENC_MAGIC + nonce + ct
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".pins-")
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(sealed_bytes)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            raise
    else:
        # 2028 hardening: plaintext pins rely on 0600 ACL only -- tamper is
        # undetected without KEK MAC. Fail-closed in production (sticky prod);
        # lab keeps ACL-only write with an explicit warning.
        _prod = os.environ.get("SECURE_P2P_PRODUCTION", "0") == "1" or os.environ.get("P2P_PRODUCTION", "0").lower() in ("1", "true")
        if _prod:
            raise ValueError("FAIL-CLOSED: refusing plaintext pins.json write in production (set P2P_PIN_KEK or P2P_STORAGE_PASSPHRASE to seal TOFU trust anchors)")
        import logging as _logging
        _logging.getLogger(__name__).warning("pins.json stored WITHOUT sealing/MAC (set P2P_PIN_KEK or P2P_STORAGE_PASSPHRASE); TOFU trust relies on 0600 ACL only")
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".pins-")
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            raise


