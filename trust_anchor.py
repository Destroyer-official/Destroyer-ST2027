#!/usr/bin/env python3
"""
trust_anchor.py — Trust infrastructure and operational key management for
TOP SECRET transmission (2027 target posture, item #5).

What this IS (all real, fail-closed, no simulations):

  PKI: offline 3-of-5 threshold hardware CA for ML-DSA-87 identities.
    Each of 5 custodians holds an ML-DSA-87 signing key in hardware
    (HSM IdentityHandle) or sealed lab software. A certificate is valid
    only with >=3 distinct authorized custodian signatures over the
    canonical TBS. In strict mode (TOP SECRET or production) there is no
    TOFU fallback: an unknown peer without a valid threshold certificate
    is refused. Lab retains TOFU via the existing pin store.

  REVOCATION: threshold-signed compromise broadcast with sequence and
    freshness. Revoking also needs quorum, so no single rogue custodian
    can deny service. Every handshake and every send verifies the peer
    certificate chain plus the in-memory revocation cache. Entries carry
    monotonically increasing per-serial sequence numbers; replays and
    stale broadcasts are refused. Transport of entries reuses the
    constant-rate uniform cells (length-prefixed frames), so revocation
    flow is itself unobservable.

  EPHEMERAL: zero-plaintext-disk profile for the TOP SECRET path. When
    required, identity pins live in memory only, revocation state lives
    in memory only, secrets live in OS-locked native buffers or hardware,
    and any attempt to persist plaintext secrets, pins, or ledgers to
    disk fails closed. Legacy SQLite and log-file modules are never
    initialized on this path.

What this IS NOT:
  Software cannot teleport an offline vault, witness five humans, or
  erase a solid-state drive with certainty (wear leveling, SSD
  over-provisioning, and swap remain facility duties per Tails/Whonix
  amnesia doctrine). What is enforced here: no TOP SECRET-path write of
  plaintext secrets, pins, or ledgers reaches disk while ephemeral is
  required, and any such attempt aborts the session loudly.

Research grounding (live-fetched Sept 2026):
  [RFC9881] Oct 2025 ML-DSA in X.509 PKIX certificates and CRLs, pure
    variant only, ML-DSA-44/65/87. TBS discipline here mirrors that
    profile (algorithm agility refused: ML-DSA-87 joins only).
  [KSK] IANA Root Zone KSK ceremonies: 3-of-7 HSM activation, dual
    occupancy, witnessed scripts, quarterly cycles. This module follows
    that shape at 3-of-5 with the same dual-control spirit as the SPO/DPO
    and NC3 doctrines already in the repo.
  [REV] Industry 2025 retreat from OCSP (privacy exposure, CVE-2026-35188
    stapling double-free, CVE-2026-58062 unbound staples) toward CRLs and
    short-lived certificates. Revocation here is CRL-style hash-bound
    plus short validity windows, never plain OCSP callbacks.
  [AMN] Tails amnesia (RAM only, no disk, memory poisoning at shutdown,
    no swap) and Whonix live mode. Ephemeral here applies that doctrine
    to the session path: locked native memory, explicit wipe, no disk.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("trust_anchor")


class TrustError(Exception):
    """Generic fail-closed trust failure. No oracle detail."""


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def _assert_profile() -> None:
    from cnsa_purity import assert_cnsa_hash, assert_cnsa_sig

    assert_cnsa_sig("ML-DSA-87")
    assert_cnsa_hash("SHA384")
    assert_cnsa_hash("SHA512")
    assert_cnsa_hash("SHA3-512")


def pki_required() -> bool:
    return (_env_true("P2P_REQUIRE_PKI") or _env_true("P2P_TS_MODE")
            or _env_true("P2P_PRODUCTION"))


def ephemeral_required() -> bool:
    return (_env_true("P2P_EPHEMERAL") or _env_true("P2P_TS_MODE")
            or _env_true("P2P_PRODUCTION"))


_QUORUM = 3
_TOTAL = 5
_MAX_LIFETIME = 48 * 3600
# RFC 9881 (Oct 2025) ML-DSA PKIX OIDs. Pure variant only; parameters MUST
# be absent; HashML-DSA MUST NOT appear in certificates (our signatures are
# pure ML-DSA-87 via liboqs, and cnsa2_policy_engine refuses HASHML-DSA).
_SIG_OID_87 = "2.16.840.1.101.3.4.3.19"
_ALLOW_SIG_OID = {_SIG_OID_87}  # CNSA-strict session set: 87 only
_CERT_DOMAIN = b"CA-CERT-v1"
_REVOKE_DOMAIN = b"CA-REVOKE-v1"
_MAX_SKEW_FUTURE = 5.0


def _norm_ident(value: str) -> str:
    return "".join(
        c for c in str(value or "") if c.isalnum() or c in ("-", "_"))[:64]


@dataclass
class Custodian:
    label: str
    mldsa_pk: bytes


@dataclass
class CertTBS:
    serial: bytes  # 16
    subject: str
    subject_pk: bytes  # 2592 ML-DSA-87
    not_before: int
    not_after: int
    issuer: str = "OFFLINE-ROOT-3OF5"


@dataclass
class CertSig:
    custodian: str
    sig: bytes


@dataclass
class Certificate:
    tbs: CertTBS
    sigs: List[CertSig] = field(default_factory=list)


@dataclass
class Revocation:
    serial: bytes  # 16
    reason: str
    ts: float
    seq: int
    sigs: List[CertSig] = field(default_factory=list)


def tbs_bytes(tbs: CertTBS) -> bytes:
    if len(bytes(tbs.serial)) != 16 or len(bytes(tbs.subject_pk)) != 2592:
        raise TrustError("trust rejected")
    subject = _norm_ident(tbs.subject)
    if not subject:
        raise TrustError("trust rejected")
    return (bytes(_CERT_DOMAIN) + bytes(tbs.serial) + subject.encode()
            + bytes(tbs.subject_pk)
            + struct.pack(">Q", int(tbs.not_before))
            + struct.pack(">Q", int(tbs.not_after)))


def revoke_bytes(rev: Revocation) -> bytes:
    if len(bytes(rev.serial)) != 16 or not 0 <= int(rev.seq) < (1 << 64):
        raise TrustError("trust rejected")
    reason = "".join(c for c in str(rev.reason or "")
                     if c.isalnum() or c in ("-", "_"))[:32]
    if not reason:
        raise TrustError("trust rejected")
    return (bytes(_REVOKE_DOMAIN) + bytes(rev.serial) + reason.encode()
            + struct.pack(">Q", int(float(rev.ts) * 1000))
            + struct.pack(">Q", int(rev.seq)))


def _verify_mldsa(pub: bytes, msg: bytes, sig: bytes) -> None:
    from liboqs_wrapper import LibOQS_MLDSA_87

    _assert_profile()
    try:
        ok = LibOQS_MLDSA_87().verify(bytes(pub), bytes(msg), bytes(sig))
    except Exception as exc:
        log.debug("threshold verify error: %r", exc)
        raise TrustError("trust rejected")
    if not ok:
        raise TrustError("trust rejected")


def _sign_with_custodian(handle: Any, msg: bytes) -> bytes:
    try:
        from secure_transmit_2027 import sign_with_identity as _sign

        return bytes(_sign(handle, msg))
    except TrustError:
        raise
    except Exception as exc:
        log.debug("custodian sign refused: %r", exc)
        raise TrustError("trust rejected")


def issue_certificate(tbs: CertTBS, signers: List[Any],
                      authorized: Optional[List[Custodian]] = None
                      ) -> Certificate:
    _assert_profile()
    if len(signers) < _QUORUM:
        raise TrustError("trust rejected")
    span = int(tbs.not_after) - int(tbs.not_before)
    if not 0 < span <= _MAX_LIFETIME:
        raise TrustError("trust rejected")
    allowed = None
    if authorized is not None:
        if len(authorized) != _TOTAL:
            raise TrustError("trust rejected")
        allowed = {_norm_ident(c.label) for c in authorized}
        if len(allowed) != _TOTAL:
            raise TrustError("trust rejected")
    body = tbs_bytes(tbs)
    seen: set = set()
    sigs: List[CertSig] = []
    for handle in signers:
        label = str(getattr(handle, "label", "") or "")
        if not label or label in seen:
            raise TrustError("trust rejected")
        if allowed is not None and _norm_ident(label) not in allowed:
            raise TrustError("trust rejected")
        seen.add(label)
        sigs.append(CertSig(custodian=label,
                            sig=_sign_with_custodian(handle, body)))
    if len(sigs) < _QUORUM:
        raise TrustError("trust rejected")
    return Certificate(tbs=tbs, sigs=sigs)


def verify_certificate(cert: Certificate, custodians: List[Custodian],
                       now: Optional[float] = None) -> CertTBS:
    _assert_profile()
    at = float(now) if now is not None else time.time()
    body = tbs_bytes(cert.tbs)
    span = int(cert.tbs.not_after) - int(cert.tbs.not_before)
    if not 0 < span <= _MAX_LIFETIME:
        raise TrustError("trust rejected")
    if not (float(cert.tbs.not_before) - _MAX_SKEW_FUTURE
            <= at <= float(cert.tbs.not_after)):
        raise TrustError("trust rejected")
    by_label = {c.label: c.mldsa_pk for c in custodians}
    if len(by_label) != _TOTAL:
        raise TrustError("trust rejected")
    seen: set = set()
    valid = 0
    for entry in cert.sigs:
        if entry.custodian in seen:
            raise TrustError("trust rejected")
        seen.add(entry.custodian)
        pub = by_label.get(entry.custodian)
        if pub is None or len(bytes(pub)) != 2592:
            raise TrustError("trust rejected")
        _verify_mldsa(bytes(pub), body, bytes(entry.sig))
        valid += 1
    if valid < _QUORUM:
        raise TrustError("trust rejected")
    return cert.tbs


def sign_revocation(rev: Revocation, signers: List[Any],
                    authorized: Optional[List[Custodian]] = None
                    ) -> Revocation:
    _assert_profile()
    if len(signers) < _QUORUM:
        raise TrustError("trust rejected")
    allowed = None
    if authorized is not None:
        if len(authorized) != _TOTAL:
            raise TrustError("trust rejected")
        allowed = {_norm_ident(c.label) for c in authorized}
    body = revoke_bytes(rev)
    seen: set = set()
    sigs: List[CertSig] = []
    for handle in signers:
        label = str(getattr(handle, "label", "") or "")
        if not label or label in seen:
            raise TrustError("trust rejected")
        if allowed is not None and _norm_ident(label) not in allowed:
            raise TrustError("trust rejected")
        seen.add(label)
        sigs.append(CertSig(custodian=label,
                            sig=_sign_with_custodian(handle, body)))
    rev.sigs = sigs
    return rev


def verify_revocation(rev: Revocation, custodians: List[Custodian]) -> None:
    _assert_profile()
    body = revoke_bytes(rev)
    # Revocation persists: only the future skew is bounded (clock), the past
    # is unbounded so an old compromise stays revoked. Replay across
    # sequence numbers is refused by the cache, not by expiry here.
    if float(rev.ts) - time.time() > _MAX_SKEW_FUTURE:
        raise TrustError("trust rejected")
    if float(rev.ts) <= 0:
        raise TrustError("trust rejected")
    by_label = {c.label: c.mldsa_pk for c in custodians}
    seen: set = set()
    valid = 0
    for entry in rev.sigs:
        if entry.custodian in seen:
            raise TrustError("trust rejected")
        seen.add(entry.custodian)
        pub = by_label.get(entry.custodian)
        if pub is None:
            raise TrustError("trust rejected")
        _verify_mldsa(bytes(pub), body, bytes(entry.sig))
        valid += 1
    if valid < _QUORUM:
        raise TrustError("trust rejected")


class RevocationCache:
    """Memory-only revocation state. No disk, thread-safe, fail-closed."""

    def __init__(self, custodians: List[Custodian]) -> None:
        self._custodians = list(custodians)
        self._lock = threading.Lock()
        self._entries: Dict[bytes, Revocation] = {}
        self.hits = 0
        self.rejects = 0

    def add(self, rev: Revocation) -> None:
        verify_revocation(rev, self._custodians)
        key = bytes(rev.serial)
        with self._lock:
            prior = self._entries.get(key)
            if prior is not None and int(rev.seq) <= int(prior.seq):
                self.rejects += 1
                raise TrustError("trust rejected")
            self._entries[key] = rev

    def is_revoked(self, serial: bytes) -> bool:
        with self._lock:
            hit = bytes(serial) in self._entries
        if hit:
            self.hits += 1
        return hit

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


_PIN_MEMORY: Dict[str, str] = {}
_PIN_LOCK = threading.Lock()

_REGISTRY: List[Custodian] = []
_CERTS: Dict[str, Certificate] = {}
_CACHE: Optional[RevocationCache] = None
_REG_LOCK = threading.Lock()


def configure(custodians: List[Custodian],
              cache: Optional[RevocationCache] = None) -> None:
    global _REGISTRY, _CACHE
    if len(custodians) != _TOTAL or any(
            len(bytes(c.mldsa_pk)) != 2592 or not _norm_ident(c.label)
            for c in custodians):
        raise TrustError("trust rejected")
    labels = [_norm_ident(c.label) for c in custodians]
    if len(set(labels)) != _TOTAL:
        raise TrustError("trust rejected")
    with _REG_LOCK:
        _REGISTRY = list(custodians)
        _CACHE = cache


def register_certificate(cert: Certificate) -> None:
    with _REG_LOCK:
        custodians = list(_REGISTRY)
    if len(custodians) != _TOTAL:
        raise TrustError("trust rejected")
    verify_certificate(cert, custodians)
    with _REG_LOCK:
        for prior in _CERTS.values():
            if (_compare(bytes(prior.tbs.serial), bytes(cert.tbs.serial))
                    and (not _compare(bytes(prior.tbs.subject_pk),
                                      bytes(cert.tbs.subject_pk))
                         or _norm_ident(prior.tbs.subject)
                         != _norm_ident(cert.tbs.subject))):
                raise TrustError("trust rejected")
        _CERTS[_norm_ident(cert.tbs.subject)] = cert


def peer_certificate_for(peer_id: str) -> Optional[Certificate]:
    with _REG_LOCK:
        return _CERTS.get(_norm_ident(peer_id))


def active_custodians() -> List[Custodian]:
    with _REG_LOCK:
        return list(_REGISTRY)


def active_cache() -> Optional[RevocationCache]:
    with _REG_LOCK:
        return _CACHE


def clear_registry() -> None:
    with _REG_LOCK:
        global _REGISTRY, _CACHE
        _REGISTRY = []
        _CERTS.clear()
        _CACHE = None
    with _PIN_LOCK:
        _PIN_MEMORY.clear()


def load_custodians_from_env() -> List[Custodian]:
    raw = (os.environ.get("P2P_CA_CUSTODIANS", "").strip()
           or os.environ.get("P2P_CA_FILE", "").strip())
    if not raw:
        raise TrustError("trust rejected")
    try:
        if raw.startswith("["):
            items = json.loads(raw)
        else:
            items = json.loads(Path(raw).read_text(encoding="utf-8"))
    except Exception as exc:
        raise TrustError(f"trust rejected: {exc}")
    out: List[Custodian] = []
    if not isinstance(items, list):
        raise TrustError("trust rejected")
    for entry in items:
        try:
            out.append(Custodian(label=_norm_ident(entry["label"]),
                                 mldsa_pk=bytes.fromhex(entry["mldsa_pk"])))
        except (KeyError, ValueError, TypeError):
            raise TrustError("trust rejected")
    return out


def ensure_configured() -> Tuple[List[Custodian], Optional[RevocationCache]]:
    global _REGISTRY, _CACHE
    with _REG_LOCK:
        custodians = list(_REGISTRY)
        cache = _CACHE
    if len(custodians) != _TOTAL:
        loaded = load_custodians_from_env()
        with _REG_LOCK:
            if not _REGISTRY:
                _REGISTRY.extend(loaded)
                if _CACHE is None:
                    _CACHE = RevocationCache(list(loaded))
            custodians = list(_REGISTRY)
            cache = _CACHE
    if len(custodians) != _TOTAL:
        raise TrustError("trust rejected")
    return custodians, cache


def require_cert_for_remote(remote_pk: bytes, peer_cert_json: Optional[str],
                             expected_subject: str) -> Certificate:
    want = _norm_ident(expected_subject)
    if not want:
        raise TrustError("trust rejected")
    custodians, cache = ensure_configured()
    if not peer_cert_json:
        raise TrustError("trust rejected")
    cert = cert_from_json(peer_cert_json)
    verify_certificate(cert, custodians)
    if cache is not None and cache.is_revoked(bytes(cert.tbs.serial)):
        raise TrustError("trust rejected")
    if _norm_ident(cert.tbs.subject) != want:
        raise TrustError("trust rejected")
    if not _compare(bytes(cert.tbs.subject_pk), bytes(remote_pk)):
        raise TrustError("trust rejected")
    _audit("pki_remote_ok", {"peer": want})
    return cert


def verify_peer_identity(peer_id: str, local_pk: bytes, remote_pk: bytes,
                         certificate: Optional[Certificate] = None,
                         custodians: Optional[List[Custodian]] = None,
                         revoked: Optional[RevocationCache] = None) -> None:
    """Strict PKI binding or lab TOFU. Revocation always checked when known."""
    from secure_transmit_2027 import identity_pin

    if len(bytes(local_pk)) != 2592 or len(bytes(remote_pk)) != 2592:
        raise TrustError("trust rejected")
    if revoked is not None and certificate is not None:
        if revoked.is_revoked(bytes(certificate.tbs.serial)):
            raise TrustError("trust rejected")
    if pki_required():
        if certificate is None or custodians is None:
            raise TrustError("trust rejected")
        tbs = verify_certificate(certificate, custodians)
        if _norm_ident(tbs.subject) != _norm_ident(peer_id):
            raise TrustError("trust rejected")
        if not _compare(bytes(tbs.subject_pk), bytes(remote_pk)):
            raise TrustError("trust rejected")
        _audit("pki_bind_ok", {"peer": _norm_ident(peer_id)})
        return
    # Lab TOFU path. Ephemeral mode keeps pins in memory only. The key is
    # the session label alone so a changed remote pair aborts like the
    # file-backed TOFU it replaces (keying by remote hash would silently
    # treat every new remote as a fresh pin).
    safety = identity_pin(bytes(local_pk), bytes(remote_pk))
    if ephemeral_required():
        key = _norm_ident(peer_id)
        if not key:
            raise TrustError("trust rejected")
        with _PIN_LOCK:
            prior = _PIN_MEMORY.get(key)
            if prior is None:
                _PIN_MEMORY[key] = safety
                _audit("tofu_pin_memory", {"peer": key})
                return
            if not _compare(prior.encode(), safety.encode()):
                raise TrustError("trust rejected")
        return
    from secure_transmit_2027 import check_pin as _tofu

    try:
        _tofu(peer_id, safety)
    except Exception as exc:
        log.debug("tofu refused: %r", exc)
        raise TrustError("trust rejected")


def _audit(event: str, fields: Dict[str, Any]) -> None:
    try:
        from secure_transmit_2027 import audit_event as _hook

        _hook(event, dict(fields))
    except Exception as exc:
        log.debug("trust audit unavailable: %r", exc)
        if ephemeral_required():
            raise TrustError("trust rejected")


def forbid_plaintext_disk(path: Path) -> None:
    """Fail closed if ephemeral mode would leave plaintext on disk."""
    if not ephemeral_required():
        return
    text = str(path)
    if text in ("", ".", ":memory:"):
        return
    raise TrustError("trust rejected")


def cert_to_json(cert: Certificate) -> str:
    return json.dumps({
        "serial": bytes(cert.tbs.serial).hex(),
        "subject": cert.tbs.subject,
        "subject_pk": bytes(cert.tbs.subject_pk).hex(),
        "not_before": int(cert.tbs.not_before),
        "not_after": int(cert.tbs.not_after),
        "issuer": cert.tbs.issuer,
        "sigs": [{"custodian": s.custodian, "sig": bytes(s.sig).hex()}
                 for s in cert.sigs],
    }, sort_keys=True)


def cert_from_json(text: str) -> Certificate:
    try:
        raw = json.loads(text)
        tbs = CertTBS(serial=bytes.fromhex(raw["serial"]),
                      subject=str(raw["subject"]),
                      subject_pk=bytes.fromhex(raw["subject_pk"]),
                      not_before=int(raw["not_before"]),
                      not_after=int(raw["not_after"]),
                      issuer=str(raw.get("issuer", "OFFLINE-ROOT-3OF5")))
        sigs = [CertSig(custodian=str(s["custodian"]),
                        sig=bytes.fromhex(s["sig"])) for s in raw["sigs"]]
    except (KeyError, ValueError, TypeError) as exc:
        raise TrustError(f"trust rejected: {exc}")
    if len(tbs.serial) != 16 or len(tbs.subject_pk) != 2592 or not sigs:
        raise TrustError("trust rejected")
    return Certificate(tbs=tbs, sigs=sigs)


def revocation_to_json(rev: Revocation) -> str:
    return json.dumps({
        "serial": bytes(rev.serial).hex(),
        "reason": str(rev.reason),
        "ts": float(rev.ts),
        "seq": int(rev.seq),
        "sigs": [{"custodian": s.custodian, "sig": bytes(s.sig).hex()}
                 for s in rev.sigs],
    }, sort_keys=True)


def revocation_from_json(text: str) -> Revocation:
    try:
        raw = json.loads(text)
        rev = Revocation(serial=bytes.fromhex(raw["serial"]),
                         reason=str(raw["reason"]),
                         ts=float(raw["ts"]), seq=int(raw["seq"]),
                         sigs=[CertSig(custodian=str(s["custodian"]),
                                       sig=bytes.fromhex(s["sig"]))
                               for s in raw["sigs"]])
    except (KeyError, ValueError, TypeError) as exc:
        raise TrustError(f"trust rejected: {exc}")
    revoke_bytes(rev)
    return rev
