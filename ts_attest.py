#!/usr/bin/env python3
"""
ts_attest.py — RATS-role platform attestation: TPM-bound Evidence on the
endpoint, policy appraisal on the verifier (component #2, RT-3 depth).

Architecture (IETF RATS RFC 9334 roles, enforced in code):
  ATTESTER (this endpoint): collects live platform posture
    (ts_runtime.read_platform_posture: Secure Boot, VBS/HVCI, DMA
    capability, measured-boot log, UMCI activity, native core version),
    binds it to verifier-supplied nonce entropy, and signs the canonical
    encoding with the TPM-bound ECDSA-P256 device key (cng_platform:
    non-migratable, non-exportable — proven live).
  VERIFIER (operator peer/service): checks envelope shape, freshness
    (300 s), nonce equality (constant-time), and the TPM signature with
    an independent library (`cryptography`, raw R||S over Prehashed
    SHA-256), then evaluates policy. Returns a signed-or-plain
    AttestationResult: healthy + reasons. An unhealthy box yields a
    VALIDLY SIGNED unhealthy verdict — the signature proves origin, the
    policy proves posture. Those are separate claims and stay separate.

What this is NOT: the device key is ECDSA-P256 (not post-quantum) and is
used EXCLUSIVELY for device-identity evidence in the TPM-AIK tradition.
It never covers data, digests of data, or session keys (those stay
ML-KEM-1024 + ML-DSA-87 per CNSA 2.0). Tamper orders stay ML-DSA-87.
Full TPM-quote appraisal (PCR/IMA whitelist, Keylime pattern) remains an
operator-verifier duty — TBS is absent on Win11 build 26200, so no local
quote path is claimed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("ts_attest")

EVIDENCE_VERSION = 1
EVIDENCE_DOMAIN = b"TS-ATTEST-v1"
ATTEST_FRESHNESS_S = 300.0
DEVICE_KEY_NAME = "TS-DEVICE-IDENTITY"

# BCRYPT ECCPUBLICBLOB magic for P-256 public keys (little-endian u32).
_ECDSA_P256_PUB_MAGIC = 0x31534345
_ECDH_P256_PUB_MAGIC = 0x314B4345
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class AttestError(Exception):
    """Fail-closed attestation failure."""


@dataclass
class AttestationResult:
    healthy: bool
    reasons: List[str] = field(default_factory=list)
    kid: str = ""
    evidence_ts: float = 0.0


def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def produce_evidence(nonce: bytes, key_name: str = DEVICE_KEY_NAME) -> Dict[str, Any]:
    """ATTESTER: collect posture, bind nonce, TPM-sign. Returns envelope dict.

    The TPM device key is opened or created (persisted, non-migratable).
    Key creation is an explicit ceremony side effect, documented as such.
    """
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 32:
        raise AttestError("attestation nonce must be 32 bytes")
    if not isinstance(key_name, str) or not key_name or len(key_name) > 64:
        raise AttestError("device key name violation")
    import cng_platform
    import ts_runtime
    posture = ts_runtime.read_platform_posture()
    try:
        native = ts_runtime.native_version()
    except Exception:
        native = None  # recorded as-is; policy fails it (no silent omission)
    body = {"v": EVIDENCE_VERSION, "nonce": bytes(nonce).hex(),
            "ts": time.time(), "posture": posture, "native": native}
    digest = hashlib.sha256(_canonical(body)).digest()
    provider = cng_platform.open_platform_provider()
    try:
        key, _created = cng_platform.get_or_create_device_key(provider, key_name)
        try:
            sig = cng_platform.sign_digest(key, digest)
            pub = cng_platform.export_pubkey_blob(key)
        finally:
            cng_platform.close_handle(key)
    finally:
        cng_platform.close_handle(provider)
    return {**body, "kid": key_name, "sig": sig.hex(), "pub": pub.hex()}


def _parse_pubkey_blob(blob: bytes) -> Tuple[int, int]:
    """Parse ECCPUBLICBLOB -> (x, y) with strict validation."""
    if len(blob) != 72:
        raise AttestError("device pubkey size violation")
    magic, cbkey = struct.unpack("<II", blob[:8])
    if magic not in (_ECDSA_P256_PUB_MAGIC, _ECDH_P256_PUB_MAGIC):
        raise AttestError("device pubkey algorithm refused (P-256 only)")
    if cbkey != 32:
        raise AttestError("device pubkey coordinate size violation")
    x = int.from_bytes(blob[8:40], "big")
    y = int.from_bytes(blob[40:72], "big")
    if not 1 <= x < _P256_ORDER or not 1 <= y < _P256_ORDER:
        raise AttestError("device pubkey coordinate range violation")
    return x, y


def _verify_tpm_sig(pub_blob: bytes, digest: bytes, sig: bytes) -> None:
    """Verify TPM ECDSA-P256 over Prehashed SHA-256 (independent lib).

    CNG emits raw IEEE-1363 R||S; the `cryptography` verifier consumes DER,
    so the signature is converted (not re-signed, not reinterpreted).
    """
    if len(sig) != 64:
        raise AttestError("device signature size violation")
    x, y = _parse_pubkey_blob(pub_blob)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDSA, SECP256R1, EllipticCurvePublicNumbers)
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed, encode_dss_signature)
        from cryptography.hazmat.primitives.hashes import SHA256
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        if not 1 <= r < _P256_ORDER or not 1 <= s < _P256_ORDER:
            raise AttestError("device signature range violation")
        pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
        pub.verify(encode_dss_signature(r, s), bytes(digest), ECDSA(Prehashed(SHA256())))
    except AttestError:
        raise
    except InvalidSignature:
        raise AttestError("device signature invalid")
    except Exception as e:
        raise AttestError(f"device signature verification failed: {e}")


def evaluate_policy(posture: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Pure policy appraisal over a posture dict (no I/O, fully testable)."""
    if not isinstance(posture, dict):
        return False, ["posture-shape"]
    reasons: List[str] = []
    if posture.get("secure_boot") is not True:
        reasons.append("secure-boot-off-or-unknown")
    if posture.get("vbs_status") != 2:
        reasons.append("vbs-not-enforced")
    if posture.get("hvci_running") is not True:
        reasons.append("hvci-not-running")
    if posture.get("measured_boot_log") is not True:
        reasons.append("measured-boot-unverified")
    if not posture.get("native"):
        reasons.append("no-deterministic-native-core")
    return (not reasons), reasons


def is_lab_mode() -> bool:
    """True ONLY when explicit lab/testing override is set.

    Production and unconfigured environments run in strict fail-closed mode
    by default (RFC 9334 RATS verifier policy: identity trust is independent
    of the evidence itself).
    """
    return os.environ.get("P2P_LAB_MODE", "").strip().lower() in ("1", "true", "yes", "on")


def is_strict_attest() -> bool:
    """True by default (fail-closed).

    Refuses unanchored self-supplied device keys unless P2P_LAB_MODE=1
    is explicitly set.
    """
    if is_lab_mode():
        return False
    return True


def appraise_evidence(env: Dict[str, Any], expected_nonce: bytes,
                       now: Optional[float] = None,
                       trusted_keys: Optional[Dict[str, str]] = None) -> AttestationResult:
    """VERIFIER: validate envelope, freshness, nonce, TPM signature, policy.

    HARDENING (audit Finding 4 — self-supplied-key substitution):
    the ``pub`` field inside ``env`` is ATTACKER-CONTROLLED and MUST NOT be
    trusted by itself. A valid signature under a self-supplied key only
    proves "holder of this private key signed this envelope", NOT "this
    came from the enrolled device". Callers making trust decisions MUST
    pass ``trusted_keys`` — a map of enrolled ``kid -> expected pub hex``
    (ECCPUBLICBLOB, 72 bytes) established out-of-band at enrollment
    (IETF RATS RFC 9334 verifier role: identity trust is independent of
    the evidence itself).

    Fail-closed rules:
      * default (strict mode): ``trusted_keys`` is REQUIRED and ``kid`` must
        be enrolled; the supplied ``pub`` must match the enrolled value with
        ``hmac.compare_digest``. Any mismatch or missing enrollment raises
        AttestError.
      * lab mode (explicit P2P_LAB_MODE=1) with ``trusted_keys``: same checks
        enforced.
      * lab mode (explicit P2P_LAB_MODE=1) without ``trusted_keys``: legacy
        TOFU path allowed for local unit diagnostics only, with an explicit
        warning log (never use for authorization).
    """
    if not isinstance(env, dict):
        raise AttestError("evidence shape violation")
    try:
        if env.get("v") != EVIDENCE_VERSION:
            raise AttestError("evidence version refused")
        nonce = bytes.fromhex(env["nonce"])
        ts = float(env["ts"])
        kid = str(env["kid"])
        sig = bytes.fromhex(env["sig"])
        pub = bytes.fromhex(env["pub"])
        posture = env["posture"]
        if not kid or len(kid) > 64:
            raise AttestError("evidence kid violation")
    except (KeyError, ValueError, TypeError) as e:
        raise AttestError(f"evidence envelope corrupt: {e}")
    if len(nonce) != 32 or not hmac.compare_digest(nonce, bytes(expected_nonce)):
        raise AttestError("evidence nonce mismatch")
    now = time.time() if now is None else now
    if abs(now - ts) > ATTEST_FRESHNESS_S:
        raise AttestError("stale evidence")
    # --- Enrollment binding (fail-closed): never trust self-supplied pub alone.
    if trusted_keys is not None:
        try:
            expected_pub_hex = trusted_keys.get(kid)
        except AttributeError:
            raise AttestError("trusted_keys shape violation")
        if not isinstance(expected_pub_hex, str):
            raise AttestError("unknown device identity (kid not enrolled)")
        try:
            expected_pub = bytes.fromhex(expected_pub_hex)
        except ValueError:
            raise AttestError("enrolled device key corrupt")
        if len(expected_pub) != 72 or not hmac.compare_digest(expected_pub, bytes(pub)):
            raise AttestError("device key mismatch (not the enrolled device)")
    elif is_strict_attest():
        raise AttestError(
            "device identity unanchored: trusted_keys enrollment required "
            "by default (self-supplied pub refused; set P2P_LAB_MODE=1 for lab testing)")
    else:
        log.warning(
            "ts_attest TOFU: appraising self-supplied device key without "
            "enrollment (kid=%s); lab only — never use for authorization", kid)
    body = {"v": env["v"], "nonce": env["nonce"], "ts": env["ts"],
            "posture": posture, "native": env.get("native")}
    _verify_tpm_sig(pub, hashlib.sha256(_canonical(body)).digest(), sig)
    healthy, reasons = evaluate_policy(posture)
    return AttestationResult(healthy=healthy, reasons=reasons,
                             kid=kid, evidence_ts=ts)
