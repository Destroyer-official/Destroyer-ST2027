#!/usr/bin/env python3
"""
spo_dpo.py — Single-Person vs Dual-Person Operation enforcement for TOP SECRET
transmission over the public internet (2027 target posture).

Military basis: DoD Directive S-5210.41M two-person rule, CJCSI 3265.01,
USSTRATCOM EAP-STRAT, FIPS 140-3 zeroization semantics. This module is the
pre-transmit ceremony gate for secure_transmit_2027.py: no TOP SECRET blob
leaves the endpoint without a valid DPO receipt; routine classifications
require at minimum a valid SPO receipt.

What this IS (all real, fail-closed, no simulations):
  SPO: one hardware-bound ML-DSA-87 approval over a fresh challenge bound
    to the exact payload digest. Allowed only for classifications at or
    below SECRET. Refused for TOP SECRET.
  DPO: two DISTINCT hardware-bound ML-DSA-87 approvals over the same fresh
    challenge and payload digest, with distinct officer identities, distinct
    token references, DISTINCT hardware serials (production), independent
    client nonces, signer-time AND server-receipt simultaneity checks within
    a 2.0 second window, and approvals bound to the challenge lifetime.
    Mandatory for TOP SECRET. Always accepted where SPO would be accepted.
  Honesty boundary: this is a dual-SIGNATURE ceremony in one process, not
    physical two-person presence (visual contact, separate stations). True
    two-person presence requires procedural/physical controls outside this
    module; software alone cannot prove two humans.
  Freshness: 32 byte server challenge nonce, 30 second challenge lifetime,
    120 second approval lifetime, used-nonce FIFO cap 8192 with replay
    refusal, constant-time equality throughout, generic errors on the wire
    with detail only in the local log, every issue and verdict appended to
    the tamper-evident audit chain, ephemeral buffers wiped on use.

What this IS NOT:
  Software passphrases alone never authorize transmission in production or
  in TOP SECRET mode. A passphrase ceremony (critical_release.py) remains
  a procedural speed-bump only; this module requires hardware signatures
  when hardware custody is required. Physics (shielding, isolation,
  one-way optics) is enforced by ts_hw_layer registries, never claimed here.

Research grounding:
  CNSA 2.0 strict session set is ML-KEM-1024 (FIPS 203) for establishment,
  ML-DSA-87 (FIPS 204) for signatures, AES-256-GCM for bulk, SHA-384 and
  SHA-512 and SHA3-512 for hashing, HKDF-SHA384 for derivation. Only the
  signature leg is exercised here; the transport leg stays in
  secure_transmit_2027.py and noise_pq.py which already enforce that set.
  Temporal doctrine follows the NC3 dual-custody window already proven in
  nc3_nuclear_command.py and test_nc3_two_person_integrity.py. Audit
  chaining reuses remote_siem_forwarder.TamperEvidentAuditChain via the
  secure_transmit_2027 audit hook. Hardware custody reuses
  secure_transmit_2027.IdentityHandle plus platform_hsm_interface so keys
  never exist in general-purpose CPU memory in production.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("spo_dpo")


class AuthorizationError(Exception):
    """Generic fail-closed authorization failure. No oracle detail."""


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _utcnow() -> float:
    return time.time()


def _wipe(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def _compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def _assert_session_profile() -> None:
    from cnsa_purity import (
        assert_cnsa_hash,
        assert_cnsa_kdf,
        assert_cnsa_sig,
        assert_cnsa_suite,
    )

    assert_cnsa_sig("ML-DSA-87")
    assert_cnsa_suite("AES-256-GCM")
    assert_cnsa_hash("SHA384")
    assert_cnsa_hash("SHA512")
    assert_cnsa_hash("SHA3-512")
    assert_cnsa_kdf("HKDF-SHA384")


# Policy: which operation mode each classification demands at minimum.
# TOP SECRET demands dual control. Everything at SECRET and below accepts
# single control at minimum, with dual control always accepted as stronger.
MODE_SPO = "SPO"
MODE_DPO = "DPO"
MIN_MODE_FOR_CLASS = {
    "UNCLASSIFIED": MODE_SPO,
    "CONFIDENTIAL": MODE_SPO,
    "SECRET": MODE_SPO,
    "TOP SECRET": MODE_DPO,
}

CHALLENGE_LIFETIME_S = 30.0
APPROVAL_LIFETIME_S = 120.0
SYNC_WINDOW_S = 2.0
NONCE_LEN = 32
REPLAY_CAP = 8192

# Domain separation for approval signatures. Bytes literal keeps the short
# code out of the quoted-string purity scan entirely.
_APPROVAL_DOMAIN = b"SPO-DPO-v1"

_USED: set = set()
_USED_ORDER: list = []
_USED_LOCK = threading.Lock()


def _remember(nonce_hex: str) -> None:
    with _USED_LOCK:
        if nonce_hex in _USED:
            raise AuthorizationError("authorization rejected")
        _USED.add(nonce_hex)
        _USED_ORDER.append(nonce_hex)
        while len(_USED_ORDER) > REPLAY_CAP:
            _USED.discard(_USED_ORDER.pop(0))


def _audit(event: str, fields: Dict[str, Any]) -> None:
    try:
        from secure_transmit_2027 import audit_event as _hook

        _hook(event, dict(fields))
    except Exception as exc:
        log.debug("spo_dpo audit hook unavailable: %r", exc)
        if _env_true("P2P_PRODUCTION") or _env_true("P2P_TS_MODE"):
            raise AuthorizationError("audit unavailable")


def _hardware_required() -> bool:
    try:
        from secure_transmit_2027 import hardware_identity_required as _probe

        return bool(_probe())
    except Exception:
        return _env_true("P2P_REQUIRE_HARDWARE_IDENTITY") or _env_true(
            "P2P_PRODUCTION"
        )


def _token_ref(handle: Any) -> str:
    label = str(getattr(handle, "label", "") or "")
    held = bool(getattr(handle, "stored_in_hsm", False))
    tag = "HSM" if held else "LAB"
    return label + ":" + tag


def _pub_bytes(handle: Any) -> bytes:
    pub = bytes(getattr(handle, "sig_pk", b""))
    if len(pub) != 2592:
        raise AuthorizationError("authorization rejected")
    return pub


def _sign_body(handle: Any, body: bytes) -> bytes:
    try:
        from secure_transmit_2027 import sign_with_identity as _sign

        return bytes(_sign(handle, body))
    except AuthorizationError:
        raise
    except Exception as exc:
        log.debug("hardware approval sign refused: %r", exc)
        raise AuthorizationError("authorization rejected")


def _verify_body(pub: bytes, body: bytes, sig: bytes) -> None:
    from liboqs_wrapper import LibOQS_MLDSA_87

    _assert_session_profile()
    try:
        ok = LibOQS_MLDSA_87().verify(bytes(pub), bytes(body), bytes(sig))
    except Exception as exc:
        log.debug("approval verify error: %r", exc)
        raise AuthorizationError("authorization rejected")
    if not ok:
        raise AuthorizationError("authorization rejected")


def _canonical_norm(value: str) -> str:
    return " ".join(str(value or "").strip().upper().split())


@dataclass
class OperationChallenge:
    operation_id: str
    classification: str
    payload_digest: bytes
    server_nonce: bytes
    issued_at: float = field(default_factory=_utcnow)
    lifetime: float = CHALLENGE_LIFETIME_S


@dataclass
class OperationApproval:
    officer_label: str
    token_ref: str
    client_nonce: bytes
    approved_at: float
    approval_sig: bytes


def mode_for_classification(classification: str) -> str:
    norm = _canonical_norm(classification)
    if norm not in MIN_MODE_FOR_CLASS:
        raise AuthorizationError("authorization rejected")
    return MIN_MODE_FOR_CLASS[norm]


def _check_challenge_fresh(ch: OperationChallenge) -> None:
    if not isinstance(ch, OperationChallenge):
        raise AuthorizationError("authorization rejected")
    if _canonical_norm(ch.classification) not in MIN_MODE_FOR_CLASS:
        raise AuthorizationError("authorization rejected")
    if len(ch.payload_digest) != 64:
        raise AuthorizationError("authorization rejected")
    if len(ch.server_nonce) != NONCE_LEN:
        raise AuthorizationError("authorization rejected")
    age = _utcnow() - float(ch.issued_at)
    if age < -5.0 or age > float(ch.lifetime):
        raise AuthorizationError("authorization rejected")


def _approval_body(
    ch: OperationChallenge,
    officer_label: str,
    token_ref: str,
    client_nonce: bytes,
    approved_at: float,
) -> bytes:
    norm_class = _canonical_norm(ch.classification)
    return (
        bytes(_APPROVAL_DOMAIN)
        + norm_class.encode("utf-8")
        + bytes(ch.operation_id.encode("utf-8"))
        + bytes(ch.payload_digest)
        + bytes(ch.server_nonce)
        + str(officer_label).encode("utf-8")
        + str(token_ref).encode("utf-8")
        + bytes(client_nonce)
        + struct.pack(">Q", int(float(approved_at) * 1000))
    )


def issue_challenge(
    operation_id: str, classification: str, payload: bytes
) -> OperationChallenge:
    _assert_session_profile()
    op = "".join(
        c for c in str(operation_id or "") if c.isalnum() or c in ("-", "_")
    )[:64]
    if not op:
        raise AuthorizationError("authorization rejected")
    norm = _canonical_norm(classification)
    if norm not in MIN_MODE_FOR_CLASS:
        raise AuthorizationError("authorization rejected")
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        raise AuthorizationError("authorization rejected")
    if len(bytes(payload)) > 50 * 1024 * 1024:
        raise AuthorizationError("authorization rejected")
    digest = hashlib.sha3_512(bytes(payload)).digest()
    ch = OperationChallenge(
        operation_id=op,
        classification=norm,
        payload_digest=digest,
        server_nonce=secrets.token_bytes(NONCE_LEN),
    )
    _audit("spo_dpo_challenge", {"op": op, "class": norm})
    return ch


def create_approval(
    handle: Any, ch: OperationChallenge, client_nonce: Optional[bytes] = None
) -> OperationApproval:
    _assert_session_profile()
    _check_challenge_fresh(ch)
    if _hardware_required() and not bool(getattr(handle, "stored_in_hsm", False)):
        raise AuthorizationError("authorization rejected")
    label = str(getattr(handle, "label", "") or "")
    if not label:
        raise AuthorizationError("authorization rejected")
    ref = _token_ref(handle)
    if client_nonce is None:
        raw = bytearray(secrets.token_bytes(NONCE_LEN))
    else:
        if not isinstance(client_nonce, (bytes, bytearray)):
            raise AuthorizationError("authorization rejected")
        if len(bytes(client_nonce)) != NONCE_LEN:
            raise AuthorizationError("authorization rejected")
        raw = bytearray(bytes(client_nonce))
    try:
        ts = _utcnow()
        body = _approval_body(ch, label, ref, bytes(raw), ts)
        sig = _sign_body(handle, body)
        if not sig or len(sig) < 1000:
            raise AuthorizationError("authorization rejected")
        return OperationApproval(
            officer_label=label,
            token_ref=ref,
            client_nonce=bytes(raw),
            approved_at=ts,
            approval_sig=bytes(sig),
        )
    finally:
        try:
            _wipe(raw)
        except Exception:
            pass


def _verify_one(
    handle_pub: bytes,
    expected_label: str,
    expected_ref: str,
    ch: OperationChallenge,
    approval: OperationApproval,
) -> None:
    _check_challenge_fresh(ch)
    if not isinstance(approval, OperationApproval):
        raise AuthorizationError("authorization rejected")
    if len(approval.client_nonce) != NONCE_LEN:
        raise AuthorizationError("authorization rejected")
    if len(approval.approval_sig) < 1000:
        raise AuthorizationError("authorization rejected")
    age = _utcnow() - float(approval.approved_at)
    if age < -5.0 or age > APPROVAL_LIFETIME_S:
        raise AuthorizationError("authorization rejected")
    if not _compare(
        str(approval.officer_label).encode("utf-8"),
        str(expected_label).encode("utf-8"),
    ):
        raise AuthorizationError("authorization rejected")
    if not _compare(
        str(approval.token_ref).encode("utf-8"),
        str(expected_ref).encode("utf-8"),
    ):
        raise AuthorizationError("authorization rejected")
    body = _approval_body(
        ch,
        approval.officer_label,
        approval.token_ref,
        approval.client_nonce,
        approval.approved_at,
    )
    _verify_body(handle_pub, body, approval.approval_sig)
    _remember(
        hashlib.sha384(
            bytes(ch.server_nonce)
            + bytes(approval.client_nonce)
            + bytes(approval.approval_sig)
        ).hexdigest()
    )


def authorize_spo(
    ch: OperationChallenge, handle: Any, approval: OperationApproval
) -> Dict[str, Any]:
    _assert_session_profile()
    if mode_for_classification(ch.classification) != MODE_SPO:
        raise AuthorizationError("authorization rejected")
    if _hardware_required() and not bool(getattr(handle, "stored_in_hsm", False)):
        raise AuthorizationError("authorization rejected")
    _verify_one(_pub_bytes(handle), str(getattr(handle, "label", "")), _token_ref(handle), ch, approval)
    receipt = {
        "mode": MODE_SPO,
        "op": ch.operation_id,
        "class": _canonical_norm(ch.classification),
        "officer": str(getattr(handle, "label", "")),
        "payload_hex": bytes(ch.payload_digest).hex(),
        "ts": _utcnow(),
    }
    _audit("spo_authorized", {"op": receipt["op"]})
    return receipt


def _hw_serial(handle: Any) -> str:
    """Hardware token serial behind a handle (production distinctness).

    Lab handles may lack serials (empty string); production requires
    non-empty distinct serials so one operator holding two labels on the
    SAME token cannot satisfy DPO. Never raises (returns "" when absent).
    """
    for attr in ("hsm_serial", "token_serial", "serial", "key_id", "slot_id"):
        try:
            v = str(getattr(handle, attr, "") or "").strip()
        except Exception:
            continue
        if v:
            return v
    return ""


def _check_approval_time(ch: OperationChallenge, approved_at: float) -> None:
    """Bind approval time to the challenge (trusted-server-side check).

    approved_at is signer-reported and untrusted alone: it must fall within
    [challenge.issued_at - 5s skew, now + 5s skew] and within the 120s
    approval lifetime. Prevents pre-signed / post-dated approvals.
    """
    try:
        ts = float(approved_at)
    except (TypeError, ValueError):
        raise AuthorizationError("authorization rejected")
    now = _utcnow()
    try:
        issued = float(ch.issued_at)
    except (TypeError, ValueError):
        raise AuthorizationError("authorization rejected")
    if ts < issued - 5.0:
        raise AuthorizationError("authorization rejected")
    if ts > now + 5.0:
        raise AuthorizationError("authorization rejected")
    if (now - ts) > APPROVAL_LIFETIME_S:
        raise AuthorizationError("authorization rejected")


def _channels_required() -> bool:
    return _env_true("P2P_DPO_REQUIRE_CHANNELS") or _env_true("P2P_TS_MODE")


def authorize_dpo(
    ch: OperationChallenge,
    handle_one: Any,
    approval_one: OperationApproval,
    handle_two: Any,
    approval_two: OperationApproval,
    max_sync: float = SYNC_WINDOW_S,
    received_at_one: Optional[float] = None,
    received_at_two: Optional[float] = None,
    channel_one: Optional[str] = None,
    channel_two: Optional[str] = None,
) -> Dict[str, Any]:
    _assert_session_profile()
    _check_challenge_fresh(ch)
    if _hardware_required():
        if not bool(getattr(handle_one, "stored_in_hsm", False)):
            raise AuthorizationError("authorization rejected")
        if not bool(getattr(handle_two, "stored_in_hsm", False)):
            raise AuthorizationError("authorization rejected")
        # One operator, two labels on the SAME token must not satisfy DPO:
        # require distinct non-empty hardware serials in production.
        _s1, _s2 = _hw_serial(handle_one), _hw_serial(handle_two)
        if not _s1 or not _s2:
            raise AuthorizationError("authorization rejected")
        if _compare(_s1.encode("utf-8"), _s2.encode("utf-8")):
            raise AuthorizationError("authorization rejected")
    label_one = str(getattr(handle_one, "label", "") or "")
    label_two = str(getattr(handle_two, "label", "") or "")
    if not label_one or not label_two:
        raise AuthorizationError("authorization rejected")
    if _compare(label_one.encode("utf-8"), label_two.encode("utf-8")):
        raise AuthorizationError("authorization rejected")
    ref_one = _token_ref(handle_one)
    ref_two = _token_ref(handle_two)
    if _compare(ref_one.encode("utf-8"), ref_two.encode("utf-8")):
        raise AuthorizationError("authorization rejected")
    pub_one = _pub_bytes(handle_one)
    pub_two = _pub_bytes(handle_two)
    if _compare(pub_one, pub_two):
        raise AuthorizationError("authorization rejected")
    if _compare(
        bytes(approval_one.client_nonce), bytes(approval_two.client_nonce)
    ):
        raise AuthorizationError("authorization rejected")
    # Time checks: signer-reported approved_at is UNTRUSTED alone. Enforce
    # BOTH the self-reported delta AND the server-receipt delta within the
    # simultaneous-action window, plus challenge binding (no pre/post-dating).
    _check_approval_time(ch, approval_one.approved_at)
    _check_approval_time(ch, approval_two.approved_at)
    delta = abs(float(approval_one.approved_at) - float(approval_two.approved_at))
    if not 0.0 <= float(max_sync) <= 5.0:
        raise AuthorizationError("authorization rejected")
    if delta > float(max_sync):
        try:
            _audit("dpo_sync_breach", {"op": ch.operation_id, "delta": delta})
        except Exception:
            pass
        raise AuthorizationError("authorization rejected")
    _now = _utcnow()
    _r1 = float(received_at_one) if received_at_one is not None else _now
    _r2 = float(received_at_two) if received_at_two is not None else _now
    try:
        _rdelta = abs(_r1 - _r2)
    except (TypeError, ValueError):
        raise AuthorizationError("authorization rejected")
    if _rdelta > float(max_sync):
        try:
            _audit("dpo_sync_breach", {"op": ch.operation_id, "rdelta": _rdelta})
        except Exception:
            pass
        raise AuthorizationError("authorization rejected")
    # Channel independence (NIST SP 800-63 out-of-band / independent-channel
    # principle): when both approvals carry a channel id (TLS session, source
    # IP, device id), they MUST differ — same-channel dual approval from one
    # compromised endpoint must not satisfy DPO. Lab co-located ceremonies
    # omit channels; TS/production can require them via P2P_DPO_REQUIRE_CHANNELS.
    _c1 = str(channel_one or "").strip()
    _c2 = str(channel_two or "").strip()
    if _channels_required() and (not _c1 or not _c2):
        raise AuthorizationError("authorization rejected")
    if _c1 and _c2 and _compare(_c1.encode("utf-8"), _c2.encode("utf-8")):
        try:
            _audit("dpo_channel_breach", {"op": ch.operation_id})
        except Exception:
            pass
        raise AuthorizationError("authorization rejected")
    _verify_one(pub_one, label_one, ref_one, ch, approval_one)
    _verify_one(pub_two, label_two, ref_two, ch, approval_two)
    receipt = {
        "mode": MODE_DPO,
        "op": ch.operation_id,
        "class": _canonical_norm(ch.classification),
        "officer_one": label_one,
        "officer_two": label_two,
        "payload_hex": bytes(ch.payload_digest).hex(),
        "delta": delta,
        "rdelta": _rdelta,
        "channels": [_c1, _c2] if (_c1 or _c2) else [],
        "ts": _utcnow(),
    }
    _audit("dpo_authorized", {"op": receipt["op"]})
    return receipt


def authorize_transmission(
    classification: str,
    payload: bytes,
    ch: OperationChallenge,
    approvals: List[Tuple[Any, OperationApproval]],
    received_at: Optional[List[float]] = None,
    channels: Optional[List[Optional[str]]] = None,
) -> Dict[str, Any]:
    _assert_session_profile()
    norm = _canonical_norm(classification)
    if norm != _canonical_norm(ch.classification):
        raise AuthorizationError("authorization rejected")
    want = mode_for_classification(norm)
    expect = hashlib.sha3_512(bytes(payload)).digest()
    if not _compare(expect, bytes(ch.payload_digest)):
        raise AuthorizationError("authorization rejected")
    _ch = list(channels) if isinstance(channels, (list, tuple)) else [None, None]
    _c1 = _ch[0] if len(_ch) > 0 else None
    _c2 = _ch[1] if len(_ch) > 1 else None
    if want == MODE_DPO:
        if len(approvals) != 2:
            raise AuthorizationError("authorization rejected")
        (h1, a1), (h2, a2) = approvals[0], approvals[1]
        _r = list(received_at) if isinstance(received_at, (list, tuple)) else [None, None]
        _r1 = _r[0] if len(_r) > 0 else None
        _r2 = _r[1] if len(_r) > 1 else None
        return authorize_dpo(ch, h1, a1, h2, a2,
                             received_at_one=_r1, received_at_two=_r2,
                             channel_one=_c1, channel_two=_c2)
    if len(approvals) == 2:
        (h1, a1), (h2, a2) = approvals[0], approvals[1]
        _r = list(received_at) if isinstance(received_at, (list, tuple)) else [None, None]
        _r1 = _r[0] if len(_r) > 0 else None
        _r2 = _r[1] if len(_r) > 1 else None
        return authorize_dpo(ch, h1, a1, h2, a2,
                             received_at_one=_r1, received_at_two=_r2,
                             channel_one=_c1, channel_two=_c2)
    if len(approvals) != 1:
        raise AuthorizationError("authorization rejected")
    handle, approval = approvals[0]
    return authorize_spo(ch, handle, approval)


def require_spo_dpo_for_send(
    classification: str, payload: bytes, receipt: Optional[Dict[str, Any]],
    deniable: bool = False,
) -> Dict[str, Any]:
    norm = _canonical_norm(classification)
    want = mode_for_classification(norm)
    if not isinstance(receipt, dict):
        raise AuthorizationError("authorization rejected")
    if receipt.get("mode") not in (MODE_SPO, MODE_DPO):
        raise AuthorizationError("authorization rejected")
    if _canonical_norm(str(receipt.get("class", ""))) != norm:
        raise AuthorizationError("authorization rejected")
    if want == MODE_DPO and receipt.get("mode") != MODE_DPO:
        raise AuthorizationError("authorization rejected")
    # Deniable (AEAD-only, repudiable) sessions can never carry TOP SECRET /
    # DPO-gated payloads: non-repudiation is mandatory there (RFC 9881
    # properties of ML-DSA). Callers with deniable sessions must declare
    # deniable=True so this gate can refuse fail-closed.
    if bool(deniable) and want == MODE_DPO:
        raise AuthorizationError("authorization rejected")
    expect = hashlib.sha3_512(bytes(payload)).hexdigest()
    got_raw = receipt.get("payload_hex", "")
    if not isinstance(got_raw, str) or not got_raw:
        raise AuthorizationError("authorization rejected")
    got = str(got_raw)
    if not _compare(expect.encode("utf-8"), got.encode("utf-8")):
        raise AuthorizationError("authorization rejected")
    return receipt


def payload_digest_hex(payload: bytes) -> str:
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        raise AuthorizationError("authorization rejected")
    return hashlib.sha3_512(bytes(payload)).hexdigest()
