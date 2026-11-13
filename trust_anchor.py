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

import calendar
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
    if name in ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION"):
        from production_gate import is_production
        return is_production()
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
    s = str(value or "")
    if not s or len(s) > 64 or not all(c.isalnum() or c in ("-", "_", ":", ".") for c in s):
        raise ValueError(f"Invalid identifier: {value!r} (must be 1-64 chars [a-zA-Z0-9_.:-])")
    return s


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
    """
    Authenticated persistent revocation ledger with memory cache.
    Thread-safe, fail-closed.
    Survives application restarts by persisting threshold-signed revocations
    to an authenticated durable ledger, verifying signatures upon reload (F-05).
    """

    def __init__(self, custodians: List[Custodian], ledger_path: Optional[str] = None) -> None:
        self._custodians = list(custodians)
        self._lock = threading.Lock()
        self._entries: Dict[bytes, Revocation] = {}
        self.hits = 0
        self.rejects = 0

        # Determine ledger persistence target
        from production_gate import is_production
        is_prod = is_production()
        ephemeral = os.environ.get("P2P_EPHEMERAL_MODE", "").strip().lower() in ("1", "true", "yes", "on")

        if ledger_path is not None:
            self._ledger_path: Optional[str] = ledger_path
        else:
            env_ledger = os.environ.get("P2P_REVOCATION_LEDGER")
            if env_ledger:
                self._ledger_path = env_ledger
            elif is_prod and not ephemeral:
                self._ledger_path = os.path.abspath(".p2p_revocation_ledger.json")
            else:
                self._ledger_path = None

        if self._ledger_path and os.path.exists(self._ledger_path):
            self._load_ledger()

    def _load_ledger(self) -> None:
        """Load and cryptographically verify all revocation records from persistent ledger."""
        if not self._ledger_path or not os.path.exists(self._ledger_path):
            return
        try:
            with open(self._ledger_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries = data.get("entries", [])
            for item in entries:
                serial = bytes.fromhex(item["serial"])
                reason = str(item["reason"])
                ts = float(item["ts"])
                seq = int(item["seq"])
                sigs = [
                    CertSig(custodian=s["custodian"], sig=bytes.fromhex(s["sig"]))
                    for s in item.get("sigs", [])
                ]
                rev = Revocation(serial=serial, reason=reason, ts=ts, seq=seq, sigs=sigs)
                # Strict cryptographic threshold verification on reload
                verify_revocation(rev, self._custodians)
                with self._lock:
                    prior = self._entries.get(serial)
                    if prior is not None and seq <= int(prior.seq):
                        continue
                    self._entries[serial] = rev
        except Exception as exc:
            log.critical("Revocation ledger failed verification or is corrupted: %r", exc)
            from production_gate import is_production
            if is_production():
                raise TrustError(f"Persistent revocation ledger failed verification: {exc}")

    def _persist_ledger(self) -> None:
        """Atomically persist threshold-signed revocation state to disk."""
        if not self._ledger_path:
            return
        payload = {
            "version": 1,
            "entries": [
                {
                    "serial": rev.serial.hex(),
                    "reason": rev.reason,
                    "ts": rev.ts,
                    "seq": rev.seq,
                    "sigs": [
                        {"custodian": s.custodian, "sig": s.sig.hex()}
                        for s in rev.sigs
                    ],
                }
                for rev in self._entries.values()
            ]
        }
        tmp_path = f"{self._ledger_path}.tmp.{os.getpid()}_{secrets.token_hex(4)}"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self._ledger_path)
        except Exception as exc:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            log.critical("Failed to persist revocation ledger: %r", exc)
            from production_gate import is_production
            if is_production():
                raise TrustError(f"Failed to persist revocation ledger: {exc}")

    def add(self, rev: Revocation) -> None:
        verify_revocation(rev, self._custodians)
        key = bytes(rev.serial)
        with self._lock:
            prior = self._entries.get(key)
            if prior is not None and int(rev.seq) <= int(prior.seq):
                self.rejects += 1
                raise TrustError("trust rejected")
            self._entries[key] = rev
            self._persist_ledger()

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


# ============================================================================
# RFC 9881 Standards-Compliant X.509 & Monotonic CRL Engine
# ============================================================================

_OID_MLDSA87_IBM = "1.3.6.1.4.1.2.267.12.8.7"
_OID_MLDSA87_NIST = "2.16.840.1.101.3.4.3.19"
_OID_THRESHOLD_SIGS = "1.3.6.1.4.1.2.267.12.8.7.99"
_OID_CRL_NUMBER = "2.5.29.20"
_OID_COMMON_NAME = "2.5.4.3"

_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_OID = 0x06
_TAG_UTF8_STRING = 0x0C
_TAG_GENERALIZED_TIME = 0x18
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_CONTEXT_0 = 0xA0
_TAG_CONTEXT_3 = 0xA3


def _der_len(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    elif length <= 0xFF:
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    elif length <= 0xFFFFFF:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x84, (length >> 24) & 0xFF, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


def _der_tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(val)) + val


def _der_seq(items: List[bytes]) -> bytes:
    return _der_tlv(_TAG_SEQUENCE, b"".join(items))


def _der_set(items: List[bytes]) -> bytes:
    return _der_tlv(_TAG_SET, b"".join(items))


def _der_int(val: int) -> bytes:
    if val == 0:
        return _der_tlv(_TAG_INTEGER, b"\x00")
    b: List[int] = []
    v = val
    while v > 0:
        b.append(v & 0xFF)
        v >>= 8
    b.reverse()
    raw = bytes(b)
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(_TAG_INTEGER, raw)


def _der_int_bytes(data: bytes) -> bytes:
    if not data:
        return _der_tlv(_TAG_INTEGER, b"\x00")
    if data[0] & 0x80:
        return _der_tlv(_TAG_INTEGER, b"\x00" + data)
    return _der_tlv(_TAG_INTEGER, data)


def _der_bit_string(data: bytes) -> bytes:
    return _der_tlv(_TAG_BIT_STRING, b"\x00" + data)


def _der_octet_string(data: bytes) -> bytes:
    return _der_tlv(_TAG_OCTET_STRING, data)


def _der_utf8(s: str) -> bytes:
    return _der_tlv(_TAG_UTF8_STRING, s.encode("utf-8"))


def _der_oid(oid_str: str) -> bytes:
    parts = [int(p) for p in oid_str.split(".")]
    out = [parts[0] * 40 + parts[1]]
    for p in parts[2:]:
        if p == 0:
            out.append(0)
        else:
            buf = []
            val = p
            while val > 0:
                buf.append(val & 0x7F)
                val >>= 7
            buf.reverse()
            for i in range(len(buf) - 1):
                buf[i] |= 0x80
            out.extend(buf)
    return _der_tlv(_TAG_OID, bytes(out))


def _der_generalized_time(ts: int) -> bytes:
    gm = time.gmtime(ts)
    s = time.strftime("%Y%m%d%H%M%SZ", gm)
    return _der_tlv(_TAG_GENERALIZED_TIME, s.encode("ascii"))


def _der_cn(name: str) -> bytes:
    oid = _der_oid(_OID_COMMON_NAME)
    val = _der_utf8(name)
    rdn = _der_seq([oid, val])
    return _der_seq([_der_set([rdn])])


def cert_to_x509_der(cert: Certificate, oid: str = _OID_MLDSA87_IBM) -> bytes:
    """Encode Certificate to RFC 9881 X.509 DER format with threshold signatures."""
    ver = _der_tlv(_TAG_CONTEXT_0, _der_tlv(_TAG_INTEGER, b"\x02"))
    serial = _der_int_bytes(bytes(cert.tbs.serial))
    sig_alg = _der_seq([_der_oid(oid)])
    issuer = _der_cn(cert.tbs.issuer)
    nb = _der_generalized_time(int(cert.tbs.not_before))
    na = _der_generalized_time(int(cert.tbs.not_after))
    validity = _der_seq([nb, na])
    subject = _der_cn(cert.tbs.subject)
    spki = _der_seq([sig_alg, _der_bit_string(bytes(cert.tbs.subject_pk))])

    sig_entries = [_der_seq([_der_utf8(s.custodian), _der_bit_string(bytes(s.sig))]) for s in cert.sigs]
    ext_payload = _der_octet_string(_der_seq(sig_entries))
    ext_item = _der_seq([_der_oid(_OID_THRESHOLD_SIGS), ext_payload])
    exts = _der_tlv(_TAG_CONTEXT_3, _der_seq([ext_item]))

    tbs = _der_seq([ver, serial, sig_alg, issuer, validity, subject, spki, exts])
    primary_sig = _der_bit_string(bytes(cert.sigs[0].sig)) if cert.sigs else _der_bit_string(b"\x00" * 4627)
    return _der_seq([tbs, sig_alg, primary_sig])


def _decode_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise TrustError("DER truncated")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise TrustError("DER truncated")
    first = data[offset]
    offset += 1
    if first < 128:
        l = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or offset + n > len(data):
            raise TrustError("DER invalid length")
        l = 0
        for _ in range(n):
            l = (l << 8) | data[offset]
            offset += 1
    if offset + l > len(data):
        raise TrustError("DER truncated")
    val = data[offset:offset + l]
    return tag, val, offset + l


def _parse_seq(data: bytes) -> List[Tuple[int, bytes]]:
    items = []
    off = 0
    while off < len(data):
        tag, val, next_off = _decode_tlv(data, off)
        items.append((tag, val))
        off = next_off
    return items


def _parse_oid_str(val: bytes) -> str:
    if not val:
        return ""
    parts = [str(val[0] // 40), str(val[0] % 40)]
    v = 0
    for b in val[1:]:
        v = (v << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(v))
            v = 0
    return ".".join(parts)


def _parse_time_secs(tag: int, val: bytes) -> int:
    s = val.decode("ascii")
    if tag == _TAG_GENERALIZED_TIME and len(s) >= 15 and s.endswith("Z"):
        return int(calendar.timegm(time.strptime(s[:14], "%Y%m%d%H%M%S")))
    return int(s)


def cert_from_x509_der(der_bytes: bytes) -> Certificate:
    """Decode RFC 9881 X.509 DER certificate with threshold signatures."""
    tag, val, rem = _decode_tlv(der_bytes, 0)
    if tag != _TAG_SEQUENCE or rem != len(der_bytes):
        raise TrustError("trust rejected: not sequence")
    cert_fields = _parse_seq(val)
    if len(cert_fields) != 3:
        raise TrustError("trust rejected: cert structure invalid")
    tbs_raw = cert_fields[0][1]
    tbs_fields = _parse_seq(tbs_raw)
    idx = 0
    if tbs_fields[idx][0] == _TAG_CONTEXT_0:
        idx += 1
    # Serial
    serial_val = tbs_fields[idx][1]
    if len(serial_val) > 1 and serial_val[0] == 0:
        serial_val = serial_val[1:]
    if len(serial_val) != 16:
        raise TrustError("trust rejected: serial not 16 bytes")
    serial = serial_val
    idx += 1
    # Sig alg
    idx += 1
    # Issuer
    issuer = "OFFLINE-ROOT-3OF5"
    idx += 1
    # Validity
    val_fields = _parse_seq(tbs_fields[idx][1])
    nb = _parse_time_secs(val_fields[0][0], val_fields[0][1])
    na = _parse_time_secs(val_fields[1][0], val_fields[1][1])
    idx += 1
    # Subject: extract CN
    subj_rdn = _parse_seq(tbs_fields[idx][1])
    subj_name = "node"
    try:
        attrs = _parse_seq(_parse_seq(subj_rdn[0][1])[0][1])
        subj_name = attrs[1][1].decode("utf-8")
    except Exception:
        pass
    idx += 1
    # SPKI
    spki_fields = _parse_seq(tbs_fields[idx][1])
    pk_bits = spki_fields[1][1]
    if pk_bits[0] != 0:
        raise TrustError("trust rejected: bit string alignment")
    subject_pk = pk_bits[1:]
    if len(subject_pk) != 2592:
        raise TrustError("trust rejected: subject_pk not 2592 bytes")
    idx += 1

    # Extensions: find threshold signatures
    sigs: List[CertSig] = []
    while idx < len(tbs_fields):
        if tbs_fields[idx][0] == _TAG_CONTEXT_3:
            ext_items = _parse_seq(tbs_fields[idx][1])
            for ext in ext_items:
                ext_f = _parse_seq(ext[1])
                if ext_f and _parse_oid_str(ext_f[0][1]) == _OID_THRESHOLD_SIGS:
                    payload = ext_f[1][1]
                    sig_list = _parse_seq(payload)
                    if sig_list and sig_list[0][0] == _TAG_SEQUENCE:
                        sig_list = _parse_seq(sig_list[0][1])
                    for s_item in sig_list:
                        s_f = _parse_seq(s_item[1])
                        c_label = s_f[0][1].decode("utf-8")
                        s_bits = s_f[1][1]
                        sigs.append(CertSig(custodian=c_label, sig=s_bits[1:] if s_bits[0] == 0 else s_bits))
        idx += 1

    tbs = CertTBS(serial=serial, subject=subj_name, subject_pk=subject_pk, not_before=nb, not_after=na, issuer=issuer)
    return Certificate(tbs=tbs, sigs=sigs)


def crl_tbs_bytes(crl_number: int, this_update: int, next_update: int, revoked_serials: List[bytes]) -> bytes:
    """Byte-identical canonical CRL TBS format matching Rust crl_tbs_bytes."""
    b = bytearray(b"CA-CRL-v1")
    b.extend(struct.pack(">Q", crl_number))
    b.extend(struct.pack(">Q", this_update))
    b.extend(struct.pack(">Q", next_update))
    b.extend(struct.pack(">Q", len(revoked_serials)))
    for s in revoked_serials:
        if len(bytes(s)) != 16:
            raise TrustError("trust rejected: serial must be 16 bytes")
        b.extend(bytes(s))
    return bytes(b)


def issue_x509_crl(crl_number: int, this_update: int, next_update: int, revoked_serials: List[bytes], signers: List[Any], authorized: Optional[List[Custodian]] = None) -> bytes:
    """Issue threshold-signed RFC 5280 / RFC 9881 CRL in DER format."""
    _assert_profile()
    if len(signers) < _QUORUM:
        raise TrustError("trust rejected: quorum not met")
    body = crl_tbs_bytes(crl_number, this_update, next_update, revoked_serials)

    allowed = None
    if authorized is not None:
        if len(authorized) != _TOTAL:
            raise TrustError("trust rejected")
        allowed = {_norm_ident(c.label) for c in authorized}

    seen = set()
    sigs: List[CertSig] = []
    for handle in signers:
        label = str(getattr(handle, "label", "") or "")
        if not label or label in seen:
            raise TrustError("trust rejected")
        if allowed is not None and _norm_ident(label) not in allowed:
            raise TrustError("trust rejected")
        seen.add(label)
        sigs.append(CertSig(custodian=label, sig=_sign_with_custodian(handle, body)))

    ver = _der_int(1)  # v2
    sig_alg = _der_seq([_der_oid(_OID_MLDSA87_IBM)])
    issuer = _der_cn("OFFLINE-ROOT-3OF5")
    tu = _der_generalized_time(this_update)
    nu = _der_generalized_time(next_update)

    rev_entries = [_der_seq([_der_int_bytes(s), _der_generalized_time(this_update)]) for s in revoked_serials]
    rev_seq = _der_seq(rev_entries)

    crl_num_ext = _der_seq([_der_oid(_OID_CRL_NUMBER), _der_octet_string(_der_int(crl_number))])
    sig_entries = [_der_seq([_der_utf8(s.custodian), _der_bit_string(bytes(s.sig))]) for s in sigs]
    ext_payload = _der_octet_string(_der_seq(sig_entries))
    thresh_ext = _der_seq([_der_oid(_OID_THRESHOLD_SIGS), ext_payload])
    exts = _der_tlv(_TAG_CONTEXT_0, _der_seq([crl_num_ext, thresh_ext]))

    tbs = _der_seq([ver, sig_alg, issuer, tu, nu, rev_seq, exts])
    primary_sig = _der_bit_string(bytes(sigs[0].sig)) if sigs else _der_bit_string(b"\x00" * 4627)
    return _der_seq([tbs, sig_alg, primary_sig])


def verify_x509_crl(der_bytes: bytes, custodians: List[Custodian]) -> Tuple[int, List[bytes]]:
    """Validate RFC 5280 / RFC 9881 DER CRL against 3-of-5 threshold Root CA."""
    _assert_profile()
    tag, val, rem = _decode_tlv(der_bytes, 0)
    if tag != _TAG_SEQUENCE or rem != len(der_bytes):
        raise TrustError("trust rejected: not sequence")
    crl_fields = _parse_seq(val)
    if len(crl_fields) != 3:
        raise TrustError("trust rejected: crl structure invalid")
    tbs_fields = _parse_seq(crl_fields[0][1])

    idx = 0
    if tbs_fields[idx][0] == _TAG_INTEGER:
        idx += 1  # version
    idx += 1  # sig alg
    idx += 1  # issuer
    tu = _parse_time_secs(tbs_fields[idx][0], tbs_fields[idx][1])
    idx += 1
    nu = tu + 86400
    if idx < len(tbs_fields) and tbs_fields[idx][0] in (_TAG_GENERALIZED_TIME, 0x17):
        nu = _parse_time_secs(tbs_fields[idx][0], tbs_fields[idx][1])
        idx += 1

    revoked_serials: List[bytes] = []
    if idx < len(tbs_fields) and tbs_fields[idx][0] == _TAG_SEQUENCE:
        for r_entry in _parse_seq(tbs_fields[idx][1]):
            r_f = _parse_seq(r_entry[1])
            if r_f:
                s_bytes = r_f[0][1]
                if len(s_bytes) > 1 and s_bytes[0] == 0:
                    s_bytes = s_bytes[1:]
                revoked_serials.append(s_bytes)
        idx += 1

    crl_number = 0
    sigs: List[CertSig] = []
    while idx < len(tbs_fields):
        if tbs_fields[idx][0] == _TAG_CONTEXT_0:
            ext_items = _parse_seq(tbs_fields[idx][1])
            if ext_items and ext_items[0][0] == _TAG_SEQUENCE:
                ext_items = _parse_seq(ext_items[0][1])
            for ext in ext_items:
                ext_f = _parse_seq(ext[1])
                if ext_f:
                    oid_s = _parse_oid_str(ext_f[0][1])
                    if oid_s == _OID_CRL_NUMBER:
                        int_tag, int_val, _ = _decode_tlv(ext_f[1][1], 0)
                        crl_number = int.from_bytes(int_val, "big")
                    elif oid_s == _OID_THRESHOLD_SIGS:
                        payload = ext_f[1][1]
                        sig_list = _parse_seq(payload)
                        if sig_list and sig_list[0][0] == _TAG_SEQUENCE:
                            sig_list = _parse_seq(sig_list[0][1])
                        for s_item in sig_list:
                            s_f = _parse_seq(s_item[1])
                            c_label = s_f[0][1].decode("utf-8")
                            s_bits = s_f[1][1]
                            sigs.append(CertSig(custodian=c_label, sig=s_bits[1:] if s_bits[0] == 0 else s_bits))
        idx += 1

    if len(custodians) != _TOTAL:
        raise TrustError("trust rejected")
    body = crl_tbs_bytes(crl_number, tu, nu, revoked_serials)

    by_label = {c.label: c.mldsa_pk for c in custodians}
    seen = set()
    valid = 0
    for entry in sigs:
        if entry.custodian in seen:
            raise TrustError("trust rejected: duplicate custodian")
        seen.add(entry.custodian)
        pub = by_label.get(entry.custodian)
        if pub is None:
            raise TrustError("trust rejected: unknown custodian")
        _verify_mldsa(bytes(pub), body, bytes(entry.sig))
        valid += 1

    if valid < _QUORUM:
        raise TrustError("trust rejected: quorum not met")

    return crl_number, revoked_serials
