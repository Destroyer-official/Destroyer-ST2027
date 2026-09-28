#!/usr/bin/env python3
"""
group_key_manager.py

Pairwise-distributed group key manager skeleton with epoch rotation.

Design (additive only, 1:1 paths untouched):
- Each group holds ONE symmetric group key (``bytearray``) + a monotonic
  ``epoch`` counter + an explicit member list + a ratchet-tree mirror.
- The group key is distributed to members over the EXISTING pairwise
  (1:1) channels. This module performs pure key bookkeeping only and
  performs NO network I/O itself; callers fan out the per-member
  envelopes over whatever pairwise transport they already use.
- Membership change (add/remove) triggers an immediate rekey: fresh
  secret entropy is mixed with the previous key through the chained
  schedule (RFC 9420 §8 shape) and ``epoch`` is incremented by exactly
  one. Rekey failures are fail-closed (group is locked, encryption
  refuses, caller must abort/retry).
- ``encrypt_for_group`` returns ``{"group_id", "epoch", "envelopes"}``
  where ``envelopes`` maps each member -> ciphertext bytes. When the
  orchestrator exposes a pairwise ``_encrypt_message`` hook it is
  preferred per member; otherwise a local AES-GCM envelope under the
  group key is used as an explicit fallback that strict mode
  (``P2P_GROUP_REQUIRE_PAIRWISE=1``, automatic in production) refuses
  fail-closed -- see _pairwise_wrap and the Limitations section below.

Limitations vs MLS (RFC 9420) -- this is NOT MLS and NOT wire interop:
- Tree STRUCTURE is integrated (mirrored roster, blanking, cover sets,
  tree-hash agreement channel, welcome tree-hash check) but there is no
  HPKE update path yet: per-member envelopes still fan out O(n) over
  pairwise channels. Suitable for enclave-size groups (squads), not
  thousands. No RFC wire byte-compatibility is claimed anywhere.
- Epoch keys chain (schedule: HKDF over prev + fresh + transcript +
  suite context): FS via one-wayness + wipe, PCS via fresh envelope-only
  entropy. There is no per-message forward secrecy at the group layer
  (pairwise channels may still provide their own).
- The PQ ciphersuite is pinned at group creation (default pure-PQ
  ML-KEM-1024 + ML-DSA-87 per draft-ietf-mls-pq-ciphersuites-06) and
  bound into every commit transcript; downgrade attempts are rejected.
  Only the pure-PQ suite has a local implementation -- hybrids are
  refused honestly, never negotiated into weakness.
- KeyPackage advertisements carry a validity window (RFC 9420 §10 /
  §7.2 lifetime analogue) and live in a per-group directory registry
  (roster AND outsiders: presence is NOT membership). Receivers check
  liveness at USE time from the explicit argument first, the registry
  second. UPDATE proposals (RFC 9420 §12.1.2 analogue) refresh one
  member's keys as a PCS step without roster churn and bind the new
  advertisement into the registry; REMOVE drops clearance AND package.
- New members join via ``build_welcome`` / ``join_from_welcome``
  (RFC 9420 §12.4.3 analogue): the public sync bundle carries NO key
  material (the epoch key still rides the pairwise envelope); join-time
  suite pinning refuses downgrades; joiners start clearance-less.
- Subsidiary keys derive via ``export_subkey`` (RFC 9420 §8.5 exporter
  analogue): HKDF-SHA3-512 over (epoch key, transcript salt,
  suite/group/epoch/label context), current-epoch-only.
- Commits MAY carry a commit-level ML-DSA-87 signature over the
  canonical encoding (verified in all modes when supplied); per-proposal
  signatures remain mandatory in strict mode.
- Group agreement exists via the epoch transcript chain + monotonic
  epochs (forks detectable, jumps rejected); membership changes arriving
  over pairwise channels are applied via apply_remote_commit(), which
  enforces member-only committers, transcript continuity, suite pinning,
  and (in strict mode) per-proposal ML-DSA-87 signatures. Research basis:
  ETK (2026) external-operations rule; SUF-CMA signatures required.
- No protection against a malicious distributor: whoever holds the
  group key can read all epochs they hold keys for. Removed members
  MUST NOT receive the post-removal epoch key (caller enforces fan-out
  exclusion); added members MUST NOT receive pre-join epoch keys
  (no key history is retained here by design).
- Requires working pairwise (1:1) channels for key distribution.
  Without them there is no secure group channel.

Concurrency: thread-safe via a single re-entrant lock.
Memory hygiene: group keys are held as ``bytearray`` so rekey/destroy
  can zero the old material. Best effort only (no mlock/mprotect).
"""

from __future__ import annotations

import hashlib
import inspect
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from utils.helpers import is_env_true
from treekem import RatchetTree, TreeError
from mls_framing import (
    TRANSCRIPT_INIT,
    DEFAULT_SUITE,
    SUPPORTED_SUITES,
    KNOWN_SUITES,
    Proposal,
    Commit,
    KeyPackage,
    KIND_ADD,
    KIND_REMOVE,
    KIND_UPDATE,
    transcript_update,
    verify_proposal_sig,
)

logger = logging.getLogger(__name__)

GROUP_KEY_SIZE = 32  # 256-bit group keys (AES-256-GCM envelopes).
GROUP_ID_MAX_LEN = 128
MEMBER_ID_MAX_LEN = 256
MAX_MEMBERS_PER_GROUP = 256

# Classification lattice for labeled group traffic (need-to-know).
CLASSIFICATION_LEVELS = {
    "UNCLASSIFIED": 0,
    "CONFIDENTIAL": 1,
    # AUDITED (B105): false positive / test fixture, verified individually 2026-09
    "SECRET": 2,  # nosec: B105
    "TOP SECRET": 3,
}
_MAX_COMPARTMENTS = 16

# Tree occupancy marker (T3-K): a leaf this node knows as a roster member
# but holds no advertised key for yet. Non-empty (blank == unoccupied in
# treekem semantics), explicitly NOT a key -- never used as key material.
_STRUCTURE_MARKER = b"GKM-TREE-STRUCTURE-V1"


def _schedule_context(suite_id: str, group_id: str, epoch: int) -> bytes:
    """Domain-separated context for the epoch key schedule (length-framed)."""
    import struct as _struct
    sid = suite_id.encode("utf-8")
    gid = group_id.encode("utf-8")
    return (b"GKM-SCHEDULE-V1:" + _struct.pack(">I", len(sid)) + sid
            + _struct.pack(">I", len(gid)) + gid
            + epoch.to_bytes(8, "big"))


def _schedule_epoch_key(prev_key: Optional[bytes], fresh: bytes,
                        transcript: bytes, suite_id: str, group_id: str,
                        epoch: int, key_size: int) -> bytes:
    """Chained epoch-key derivation, RFC 9420 §8 key-schedule shape (T3-K).

    ``new = HKDF-SHA3-512(salt=transcript, ikm=prev||fresh, info=ctx)``;
    genesis (no prev key) uses ``ikm=fresh``. Properties: forward secrecy
    (HKDF one-way: the new key reveals nothing about the wiped prev key)
    and PCS (an attacker holding the prev key but missing the fresh
    secret -- which only ever travels inside per-member envelopes --
    cannot derive the new key). History binds via the transcript salt.
    """
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # type: ignore
        from cryptography.hazmat.primitives import hashes as _hashes  # type: ignore
    except Exception as exc:
        raise GroupRekeyError(
            "cryptography package required for epoch schedule") from exc
    if not isinstance(fresh, (bytes, bytearray)) or len(fresh) != key_size:
        raise GroupRekeyError("schedule fresh entropy must be key-sized")
    ikm = (bytes(prev_key) if prev_key else b"") + bytes(fresh)
    if prev_key is not None and len(prev_key) != key_size:
        raise GroupRekeyError("schedule prev key has wrong size")
    hkdf = HKDF(algorithm=_hashes.SHA3_512(), length=key_size,
                salt=bytes(transcript),
                info=_schedule_context(suite_id, group_id, epoch))
    return hkdf.derive(ikm)


def _label_context(group_id: str, epoch: int, classification: str,
                   compartments: list) -> bytes:
    """Canonical bytes bound by the label MAC (length-framed, sorted)."""
    import struct as _struct
    gid = group_id.encode("utf-8")
    out = (b"GROUP-LABEL-V1:" + _struct.pack(">I", len(gid)) + gid
           + epoch.to_bytes(8, "big"))
    cname = classification.encode("utf-8")
    out += _struct.pack(">I", len(cname)) + cname
    out += _struct.pack(">H", len(compartments))
    for c in compartments:
        cb = str(c).encode("utf-8")
        out += _struct.pack(">I", len(cb)) + cb
    return out


class GroupKeyError(Exception):
    """Base error for group-key operations."""


class GroupExistsError(GroupKeyError):
    """Group already exists."""


class GroupNotFoundError(GroupKeyError):
    """Unknown group_id."""


class GroupLockedError(GroupKeyError):
    """Group is locked after a failed rekey (fail-closed)."""


class GroupRekeyError(GroupKeyError):
    """Rekey failed; group has been locked fail-closed."""


class GroupMembershipError(GroupKeyError):
    """Invalid membership operation."""


class GroupAccessDenied(GroupKeyError):
    """Clearance/label check refused an operation (fail-closed)."""


def _zero(buf: bytearray) -> None:
    """Best-effort wipe of a mutable buffer.

    Prefers the native wipe in :mod:`native_secure_buffer` (``sodium_memzero``
    / ``ctypes.memset`` with read-back verification — a foreign call the C
    optimizer cannot elide) over the pure-Python loop. Never raises.
    """
    try:
        from native_secure_buffer import wipe_native
        wipe_native(buf)
        return
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    try:
        for i in range(len(buf)):
            buf[i] = 0
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass


def _validate_group_id(group_id: str) -> str:
    if not isinstance(group_id, str) or not group_id:
        raise GroupMembershipError("group_id must be a non-empty str")
    if len(group_id) > GROUP_ID_MAX_LEN:
        raise GroupMembershipError("group_id too long")
    return group_id


def _validate_member_id(member_id: str) -> str:
    if not isinstance(member_id, str) or not member_id:
        raise GroupMembershipError("member_id must be a non-empty str")
    if len(member_id) > MEMBER_ID_MAX_LEN:
        raise GroupMembershipError("member_id too long")
    return member_id


def _strict_pairwise_required() -> bool:
    """True when per-member pairwise wrap is mandatory (no local fallback).

    Explicit ``P2P_GROUP_REQUIRE_PAIRWISE=1``, or automatic in production
    (``P2P_PRODUCTION``/``SECURE_P2P_PRODUCTION``). Explicit ``=0`` opts out
    in lab only; it is ignored with a CRITICAL log in production.
    """
    import os as _os
    _prod = is_env_true("SECURE_P2P_PRODUCTION") or is_env_true("P2P_PRODUCTION")
    _explicit = _os.environ.get("P2P_GROUP_REQUIRE_PAIRWISE", "")
    if _prod:
        if _explicit == "0":
            logger.critical("P2P_GROUP_REQUIRE_PAIRWISE=0 ignored in production (pairwise wrap enforced)")
        return True
    return is_env_true("P2P_GROUP_REQUIRE_PAIRWISE")


def _strict_group_auth_required() -> bool:
    """True when remote commits/proposals must carry ML-DSA-87 signatures.

    Explicit ``P2P_GROUP_REQUIRE_SIGNED_COMMITS=1``, or automatic in
    production. Research basis: ETK/EUROCRYPT-2026 shows unauthenticated
    and externally-injected group operations weaken PCS; RFC 9420 mandates
    SUF-CMA signatures on handshake messages. Lab default is permissive
    (warn) so unsigned local flows keep working in tests.
    """
    import os as _os
    _prod = is_env_true("SECURE_P2P_PRODUCTION") or is_env_true("P2P_PRODUCTION")
    _explicit = _os.environ.get("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "")
    if _prod:
        if _explicit == "0":
            logger.critical("P2P_GROUP_REQUIRE_SIGNED_COMMITS=0 ignored in production (signed commits enforced)")
        return True
    return is_env_true("P2P_GROUP_REQUIRE_SIGNED_COMMITS")


@dataclass
class _GroupState:
    group_id: str
    members: List[str] = field(default_factory=list)
    group_key: bytearray = field(default_factory=lambda: bytearray(GROUP_KEY_SIZE))
    epoch: int = 0
    created_at: float = field(default_factory=time.time)
    locked: bool = False  # Set on rekey failure (fail-closed).
    transcript_hash: bytes = field(default_factory=lambda: TRANSCRIPT_INIT)
    # Pinned PQ ciphersuite (Tier-3/T3-A): negotiated at creation, bound
    # into every commit transcript; downgrade attempts are rejected.
    suite_id: str = DEFAULT_SUITE
    # KeyPackage registry (T3-G, RFC 9420 §10 directory analogue): latest
    # advertisement per member_id, roster members AND outsiders (a
    # pre-join directory cache -- presence here is NOT membership).
    # Liveness is enforced at USE time (ADD/UPDATE validation), never
    # trusted from storage alone.
    key_packages: Dict[str, Any] = field(default_factory=dict)
    # Ratchet-tree mirror (T3-K, RFC 9420 §4/§7 shape): structural
    # agreement channel alongside the transcript. Leaves hold registry
    # kem_pub bytes when known, else _STRUCTURE_MARKER (occupancy
    # without key claims -- never key material).
    tree: Any = None
    # Clearance registry: member_id -> (level_int, frozenset(compartments)).
    # Members WITHOUT an entry are denied LABELED traffic (fail-closed)
    # but may still use unlabeled envelopes (backward compatible).
    clearances: Dict[str, tuple] = field(default_factory=dict)


class GroupKeyManager:
    """Pairwise-distributed group key store with epoch rotation.

    Args:
        orchestrator: Optional object exposing a pairwise encryption hook
            (e.g. ``_encrypt_message`` / ``encrypt_for_member``). Only
            probed opportunistically; never required.
        key_size: Group key length in bytes (default 32).
    """

    def __init__(self, orchestrator: Optional[Any] = None, key_size: int = GROUP_KEY_SIZE) -> None:
        if key_size not in (16, 24, 32):
            raise ValueError("key_size must be 16, 24, or 32 for AES-GCM envelopes")
        self._orchestrator = orchestrator
        self._key_size = key_size
        self._lock = threading.RLock()
        self._groups: Dict[str, _GroupState] = {}

    # ------------------------------------------------------------------
    # internal helpers (no network I/O)
    # ------------------------------------------------------------------

    def _get(self, group_id: str) -> _GroupState:
        try:
            return self._groups[group_id]
        except KeyError:
            raise GroupNotFoundError(f"unknown group: {group_id!r}")

    def _check_unlocked(self, state: _GroupState) -> None:
        if state.locked:
            raise GroupLockedError(
                f"group {state.group_id!r} is locked after a rekey failure "
                "(fail-closed: destroy and recreate the group)"
            )

    def _leaf_pub_locked(self, state: _GroupState, member_id: str) -> bytes:
        """Best-known leaf key for the tree mirror: registry kem_pub, else
        the structure marker (occupancy without key claims)."""
        kp = state.key_packages.get(member_id)
        try:
            kem = bytes(kp.kem_pub) if kp is not None else b""
        except Exception:
            kem = b""
        return kem or _STRUCTURE_MARKER

    def _mirror_tree_locked(self, state: _GroupState,
                            initial: bool = False) -> None:
        """(Re)build the tree mirror from roster + registry (T3-K).

        Caller must hold ``self._lock``. TreeErrors surface as
        GroupKeyError (fail-closed: never run with a diverged mirror).
        """
        try:
            width = 1
            while width < max(1, len(state.members)):
                width *= 2
            tree = RatchetTree(width=width)
            for m in sorted(state.members):
                tree.add(m, self._leaf_pub_locked(state, m))
            state.tree = tree
        except TreeError as exc:
            raise GroupKeyError(f"tree mirror failed: {exc}") from exc

    def _tree_locked(self, state: _GroupState) -> RatchetTree:
        t = getattr(state, "tree", None)
        if not isinstance(t, RatchetTree):
            self._mirror_tree_locked(state)
            t = state.tree
        return t

    def tree_hash_of(self, group_id: str) -> bytes:
        """Current ratchet-tree hash (structural agreement channel, T3-K)."""
        with self._lock:
            return bytes(self._tree_locked(self._get(_validate_group_id(group_id))).tree_hash())

    def tree_cover_of(self, group_id: str) -> List[int]:
        """Minimal encryption-target set (cover) for the group tree.

        Informational in v1 (fan-out still rides pairwise envelopes);
        the target set a future HPKE update path encrypts to.
        """
        with self._lock:
            return list(self._tree_locked(self._get(_validate_group_id(group_id))).cover())

    def get_pq_treekem(self, group_id: str, local_member_id: str,
                       local_secret_key: Optional[bytes] = None) -> Any:
        """Return the PERSISTENT PQTreeKEM engine for this group (RFC 9420 / FIPS 203).

        One engine per group, pinned to a single local identity: TreeKEM
        path secrets accumulate across updates, so a fresh engine per call
        could never decapsulate past the first epoch (no-demo rule: the
        stateless version was unusable for receivers). First build
        REQUIRES the local member's ML-KEM secret (3168 bytes); later
        calls re-supply it (rotation-safe replace) or omit it.

        Fail-closed: EVERY roster member must have a valid 1568-byte
        ML-KEM kem_pub in the directory registry. There is deliberately
        NO deterministic fallback key: RFC 9420 requires a real HPKE key
        to encrypt to a member, and encapsulating to a synthesized
        placeholder would mint ciphertexts nobody can open (silent
        desync/DoS). Missing advertisements mean "not ready", never
        "make something up".
        """
        from pq_treekem import PQTreeKEM, TreeError
        group_id = _validate_group_id(group_id)
        local_member_id = _validate_member_id(local_member_id)
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            engine = getattr(state, "pq_engine", None)
            owner = getattr(state, "pq_engine_owner", None)
            if engine is not None:
                if owner != local_member_id:
                    raise GroupKeyError(
                        f"PQ engine for group {group_id!r} is pinned to "
                        f"{owner!r}, not {local_member_id!r} (one local "
                        "identity per manager)")
                if local_secret_key is not None:
                    self._register_pq_local_secret(state, engine, local_member_id,
                                                   local_secret_key)
                return engine
            if local_secret_key is None:
                raise GroupKeyError(
                    f"PQ engine for group {group_id!r} needs "
                    f"{local_member_id!r}'s ML-KEM secret on first build "
                    "(receivers cannot decapsulate without it)")
            width = 1
            while width < max(1, len(state.members)):
                width *= 2
            try:
                engine = PQTreeKEM(group_id=group_id, width=width,
                                   local_member_id=local_member_id)
            except TreeError as exc:
                raise GroupKeyError(f"PQ engine build failed: {exc}") from exc
            engine.epoch_secret = bytes(state.group_key)
            engine.current_epoch = state.epoch
            missing = []
            import time as _time
            _now = _time.time()
            _strict_kp = _strict_group_auth_required()
            for m in sorted(state.members):
                pkg = state.key_packages.get(m)
                kem_pk = getattr(pkg, 'kem_pub', None)
                if not kem_pk or len(kem_pk) != 1568:
                    missing.append(m)
                    continue
                try:
                    _live = bool(pkg.is_live(_now))
                except Exception:
                    _live = False
                if not _live:
                    if _strict_kp:
                        raise GroupMembershipError(
                            f"stale/expired KeyPackage for {m!r}: PQ engine "
                            "refused in strict mode")
                    logger.warning(
                        "group %r: PQ engine built on non-live KeyPackage "
                        "for %r (lab only)", group_id, m)
                try:
                    engine.add_member(m, bytes(kem_pk))
                except TreeError as exc:
                    raise GroupKeyError(f"PQ roster build failed for {m!r}: {exc}") from exc
            if missing:
                raise GroupKeyError(
                    f"PQ-TreeKEM not ready for group {group_id!r}: no live "
                    f"ML-KEM KeyPackage for {missing} (publish_key_package "
                    "first; placeholders are never synthesized)")
            self._register_pq_local_secret(state, engine, local_member_id,
                                           local_secret_key)
            state.pq_engine = engine
            state.pq_engine_owner = local_member_id
            return engine

    @staticmethod
    def _register_pq_local_secret(state: _GroupState, engine: Any,
                                  local_member_id: str,
                                  local_secret_key: bytes) -> None:
        """Register (or rotate) the local leaf secret on a PQ engine."""
        from pq_treekem import TreeError
        if not isinstance(local_secret_key, (bytes, bytearray)) or \
                len(local_secret_key) != 3168:
            raise GroupKeyError(
                "local ML-KEM secret must be 3168 bytes (ML-KEM-1024)")
        try:
            leaf_idx = engine.tree.members()[local_member_id]
        except KeyError:
            raise GroupKeyError(
                f"local member {local_member_id!r} not on the PQ roster") from None
        try:
            pub = bytes(engine._node_keys[2 * leaf_idx].public_key)
            engine.set_local_leaf_credentials(leaf_idx, pub, bytes(local_secret_key))
        except (TreeError, KeyError, AttributeError) as exc:
            raise GroupKeyError(f"local PQ credential registration failed: {exc}") from exc

    def create_pq_update(self, group_id: str, local_member_id: str,
                         local_secret_key: Optional[bytes] = None) -> Tuple[Any, bytes]:
        """Create a PQ update as the committer AND advance local state.

        Why both: the committer's engine ratchets on create; if local
        state (epoch key, epoch, transcript, tree mirror) did not advance
        with it, committer and receivers would permanently diverge. The
        returned (update_path, new_epoch_secret) is what the caller fans
        out over pairwise channels; receivers apply it via
        apply_pq_update_path. Committer authenticity toward peers rests
        on that fan-out (same trust as empty commits); callers MAY attach
        a commit_sig (canonical: _pq_commit_canonical) with their ML-DSA
        key for strict-mode receivers.
        """
        from pq_treekem import PQTreeKEMError
        group_id = _validate_group_id(group_id)
        local_member_id = _validate_member_id(local_member_id)
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if local_member_id not in state.members:
                raise GroupMembershipError(
                    f"PQ update by non-member {local_member_id!r} refused")
            if state.suite_id not in SUPPORTED_SUITES:
                raise GroupKeyError(
                    f"PQ update refused under non-PQ suite {state.suite_id!r}")
            tree_kem = self.get_pq_treekem(group_id, local_member_id,
                                           local_secret_key=local_secret_key)
            try:
                leaf_idx = tree_kem.tree.members()[local_member_id]
            except KeyError:
                raise GroupKeyError(
                    f"local member {local_member_id!r} not on the PQ roster") from None
            # Pre-update tree hash: the transcript step MUST bind the same
            # bytes receivers verify (their checked claim), not the
            # post-update tree, or creator/receiver transcripts diverge.
            tx_before = bytes(tree_kem.tree.tree_hash())
            try:
                update_path, _ = tree_kem.create_update_path(leaf_idx)
            except PQTreeKEMError as exc:
                raise GroupKeyError(f"PQ update creation failed: {exc}") from exc
            if tree_kem.current_epoch != state.epoch + 1:
                raise GroupKeyError("PQ engine did not advance exactly one epoch")
            _zero(state.group_key)
            state.group_key = bytearray(bytes(tree_kem.epoch_secret)[:self._key_size])
            state.epoch = tree_kem.current_epoch
            import hashlib as _hashlib
            import struct as _struct
            h = _hashlib.sha3_512()
            h.update(bytes(state.transcript_hash))
            h.update(b"PQ-UPDATE-V1:")
            h.update(state.epoch.to_bytes(8, "big"))
            cid = local_member_id.encode("utf-8")
            h.update(_struct.pack(">I", len(cid)) + cid)
            h.update(tx_before)
            state.transcript_hash = h.digest()
            self._mirror_tree_locked(state)
            logger.info("group %r created PQ update to epoch %d as %r",
                        group_id, state.epoch, local_member_id)
            return update_path, bytes(tree_kem.epoch_secret)

    def apply_pq_update_path(self, group_id: str, updater_leaf: int, update_path: Any, local_member_id: str,
                             committer_id: str, committer_pub: Optional[bytes] = None,
                             verify_cb: Optional[Callable[[bytes, bytes, bytes], bool]] = None,
                             local_secret_key: Optional[bytes] = None) -> int:
        """Apply a received PQUpdatePath, synchronizing the group epoch and secret.

        Enforcement mirrors apply_remote_commit (same threat model):
        1. Committer MUST be a current roster member; the
           (committer_id, committer_pub) binding is CALLER-ATTESTED over
           the authenticated pairwise channel, and must equal the path's
           self-claimed updater_id.
        2. Suite MUST be locally enforceable (pure-PQ pin; hybrids refused
           honestly as elsewhere).
        3. Commit-level ML-DSA-87 signature over the canonical path
           bytes (group, updater, leaf, epoch, tree hash): REQUIRED in
           strict mode, warn-accepted in lab (T3-F policy shape).
        4. The PQ engine itself enforces epoch==current+1 (no rollback)
           and tree-hash continuity (no cross-fork application).
        5. The epoch advance is transcript-bound (domain-separated step),
           so transcript agreement tracks PQ epochs too.
        6. Receiver decapsulation needs the LOCAL member's ML-KEM secret
           (``local_secret_key``, 3168 bytes): path secrets accumulate in
           the persistent engine, so a stateless engine could never
           decapsulate past genesis. Absent secret on first use fails
           closed; the manager never stores it outside the engine.
        Node ciphertexts ride inside the path; their integrity is proven
        by successful decapsulation, and transport authenticity rests on
        the pairwise channel exactly as for every other group path.
        Fail-closed throughout; the local key changes only after ALL
        checks pass.
        """
        from pq_treekem import PQTreeKEMError
        group_id = _validate_group_id(group_id)
        committer_id = _validate_member_id(committer_id)
        local_member_id = _validate_member_id(local_member_id)
        if update_path is None:
            raise GroupKeyError("update_path must be provided")
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if committer_id not in state.members:
                raise GroupMembershipError(
                    f"external PQ update refused: {committer_id!r} is not a roster member")
            updater_claim = getattr(update_path, "updater_id", None)
            if updater_claim != committer_id:
                raise GroupKeyError(
                    f"PQ updater self-claim {updater_claim!r} != attested committer {committer_id!r}")
            if state.suite_id not in SUPPORTED_SUITES:
                raise GroupKeyError(
                    f"PQ update refused under non-PQ suite {state.suite_id!r}")
            strict = _strict_group_auth_required()
            commit_sig = getattr(update_path, "commit_sig", None)
            if commit_sig is not None:
                # Present-but-invalid is never silent-stripped (both modes).
                if committer_pub is None or verify_cb is None:
                    raise GroupKeyError(
                        "PQ commit signature supplied without committer key "
                        "and verify callback (nothing to verify against)")
                try:
                    sig_ok = bool(verify_cb(bytes(committer_pub),
                                            self._pq_commit_canonical(group_id, update_path),
                                            bytes(commit_sig)))
                except Exception:
                    sig_ok = False
                if not sig_ok:
                    raise GroupKeyError(
                        f"PQ commit-level signature invalid for {committer_id!r} (rejected in all modes)")
            elif strict:
                raise GroupKeyError(
                    f"unsigned PQ update from {committer_id!r} refused in "
                    "strict mode (attach commit_sig via _pq_commit_canonical)")
            else:
                logger.warning(
                    "group %r: applying UNSIGNED PQ update from %r "
                    "(lab only -- enable strict signed commits)", group_id, committer_id)
            tree_kem = self.get_pq_treekem(group_id, local_member_id,
                                                local_secret_key=local_secret_key)
            try:
                new_epoch_secret = tree_kem.apply_update_path(updater_leaf, update_path)
            except PQTreeKEMError as exc:
                raise GroupKeyError(f"PQ update rejected by tree engine: {exc}") from exc
            if tree_kem.current_epoch != state.epoch + 1:
                raise GroupKeyError("PQ update did not advance exactly one epoch")
            _zero(state.group_key)
            state.group_key = bytearray(bytes(new_epoch_secret)[:self._key_size])
            state.epoch = tree_kem.current_epoch
            import hashlib as _hashlib
            import struct as _struct
            h = _hashlib.sha3_512()
            h.update(bytes(state.transcript_hash))
            h.update(b"PQ-UPDATE-V1:")
            h.update(state.epoch.to_bytes(8, "big"))
            cid = committer_id.encode("utf-8")
            h.update(_struct.pack(">I", len(cid)) + cid)
            claimed_tx = getattr(update_path, "tree_hash_before", b"")
            if isinstance(claimed_tx, str):
                claimed_tx = bytes.fromhex(claimed_tx)
            h.update(bytes(claimed_tx))
            state.transcript_hash = h.digest()
            self._mirror_tree_locked(state)
            logger.info("group %r applied PQ update to epoch %d from %r",
                        group_id, state.epoch, committer_id)
            return state.epoch

    @staticmethod
    def _pq_commit_canonical(group_id: str, update_path: Any) -> bytes:
        """Canonical bytes a PQ commit signature covers (deterministic)."""
        import struct as _struct
        gid = group_id.encode("utf-8")
        uid = str(getattr(update_path, "updater_id", "")).encode("utf-8")
        out = (b"PQ-COMMIT-V1:" + _struct.pack(">I", len(gid)) + gid
               + _struct.pack(">I", len(uid)) + uid
               + _struct.pack(">I", int(getattr(update_path, "updater_leaf", 0)))
               + _struct.pack(">Q", int(getattr(update_path, "epoch_id", 0))))
        claimed_tx = getattr(update_path, "tree_hash_before", b"")
        if isinstance(claimed_tx, str):
            claimed_tx = bytes.fromhex(claimed_tx)
        return out + bytes(claimed_tx)

    def _rekey_locked(self, state: _GroupState, proposals: Optional[List[Proposal]] = None) -> int:
        """Chained epoch rotation (T3-K schedule), wipe old, bump epoch, chain transcript.

        ``new = schedule(prev, fresh, transcript, suite)`` -- FS via HKDF
        one-way + wipe, PCS via fresh secret entropy. Caller must hold
        ``self._lock``. Fail-closed: on any failure the old key material
        is wiped, the group is locked, and :class:`GroupRekeyError` is
        raised.
        """
        old = state.group_key
        try:
            fresh = secrets.token_bytes(self._key_size)
            if len(fresh) != self._key_size:
                raise GroupRekeyError("RNG returned short key material")
            new_epoch = state.epoch + 1
            commit = Commit(
                epoch=new_epoch,
                prev_tx=state.transcript_hash,
                proposals=proposals or [],
                suite_id=state.suite_id,
            )
            new_tx = commit.new_transcript()
            new_key = bytearray(_schedule_epoch_key(
                bytes(old), bytes(fresh), new_tx, state.suite_id,
                state.group_id, new_epoch, self._key_size))
            _zero(old)
            state.group_key = new_key
            # Monotonic epoch: exactly +1 per successful rekey, never reset.
            state.epoch = new_epoch
            state.transcript_hash = new_tx
            # Every mutation path funnels through here: refresh the tree
            # mirror so structure and roster never diverge. Mirror failure
            # locks the group via the fail-closed handlers below.
            self._mirror_tree_locked(state)
            state.locked = False
            logger.info("group %r rekeyed to epoch %d (tx=%s)", state.group_id, state.epoch, state.transcript_hash[:8].hex())
            return state.epoch
        except GroupRekeyError:
            _zero(old)
            state.group_key = bytearray(self._key_size)
            state.locked = True
            raise
        except Exception as exc:  # fail-closed on RNG / memory errors
            try:
                _zero(old)
            finally:
                state.group_key = bytearray(self._key_size)
                state.locked = True
            raise GroupRekeyError(f"rekey failed for {state.group_id!r}: {exc}") from exc

    def _pairwise_wrap(self, member_id: str, plaintext: bytes) -> bytes:
        """Wrap ``plaintext`` for one member via the pairwise hook if usable.

        Preferred path: ``orchestrator._encrypt_message`` (or
        ``encrypt_for_member`` / ``encrypt_for_peer``) when present and
        synchronously callable. Async hooks cannot be awaited from this
        synchronous skeleton, so they are skipped with a debug log.

        Fallback path: local AES-256-GCM envelope under the *group* key,
        bound to (group_id, epoch, member_id) as associated data
        (``GKM-V2`` length-framed). The fallback exists for lab/skeleton use
        only: strict mode (``P2P_GROUP_REQUIRE_PAIRWISE=1``, automatic in
        production) refuses it fail-closed, because a group-key compromise
        alone would expose the distribution envelope.
        """
        hook: Optional[Callable[..., Any]] = None
        orch = self._orchestrator
        if orch is not None:
            for name in ("encrypt_for_member", "encrypt_for_peer", "_encrypt_message"):
                cand = getattr(orch, name, None)
                if callable(cand):
                    hook = cand
                    hook_name = name
                    break
        if hook is not None:
            try:
                if inspect.iscoroutinefunction(hook):
                    logger.debug(
                        "pairwise hook %s is async; using AES-GCM placeholder for %r",
                        hook_name, member_id,
                    )
                else:
                    try:
                        result = hook(member_id, plaintext)  # type: ignore[operator]
                    except TypeError:
                        # Most 1:1 hooks take a single message arg bound to
                        # the current peer (e.g. _encrypt_message(message)).
                        result = hook(plaintext)  # type: ignore[operator]
                    if isinstance(result, (bytes, bytearray)) and len(result) > 0:
                        return bytes(result)
                    logger.debug("pairwise hook returned empty; using placeholder for %r", member_id)
            except Exception as exc:
                logger.warning("pairwise wrap for %r failed, using placeholder: %s", member_id, exc)
        # Explicit placeholder fallback (pure logic, no I/O).
        raise _NeedPlaceholderFallback()

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def create_group(self, group_id: str, members: List[str],
                     suite_id: str = DEFAULT_SUITE) -> Dict[str, Any]:
        """Create a group at epoch 0 with fresh random key material and transcript genesis (RFC 9420 §8.2).

        ``suite_id`` pins the PQ ciphersuite for the group lifetime
        (Tier-3/T3-A downgrade defense; research basis:
        draft-ietf-mls-pq-ciphersuites-06). Only locally-enforced suites
        are accepted -- known-but-unimplemented hybrids are refused
        honestly rather than negotiated into weakness.
        """
        group_id = _validate_group_id(group_id)
        clean = sorted({_validate_member_id(m) for m in (members or [])})
        if len(clean) != len(list(members or [])):
            raise GroupMembershipError("duplicate member ids")
        if len(clean) > MAX_MEMBERS_PER_GROUP:
            raise GroupMembershipError("too many members")
        if suite_id not in SUPPORTED_SUITES:
            if suite_id in KNOWN_SUITES:
                raise GroupMembershipError(
                    f"PQ suite {suite_id!r} is known but has no local "
                    "implementation (no hybrid HPKE combiner here); refusing")
            raise GroupMembershipError(f"unknown PQ suite {suite_id!r}")
        with self._lock:
            if group_id in self._groups:
                raise GroupExistsError(f"group already exists: {group_id!r}")
            try:
                fresh = secrets.token_bytes(self._key_size)
            except Exception as exc:
                raise GroupRekeyError(f"group creation failed (RNG): {exc}") from exc
            props = [Proposal(kind=KIND_ADD, member_id=m) for m in clean]
            initial_tx = transcript_update(TRANSCRIPT_INIT, props, 0)
            # Genesis goes through the same schedule (prev=None): every
            # epoch key, including epoch 0, is schedule-derived and bound
            # to (transcript, suite, group, epoch).
            key = bytearray(_schedule_epoch_key(
                None, fresh, initial_tx, suite_id, group_id, 0,
                self._key_size))
            state = _GroupState(
                group_id=group_id,
                members=clean,
                group_key=key,
                epoch=0,
                transcript_hash=initial_tx,
                suite_id=suite_id,
            )
            self._mirror_tree_locked(state, initial=True)
            self._groups[group_id] = state
            logger.info("group %r created with %d members at epoch 0 (suite=%s tx=%s)", group_id, len(clean), suite_id, initial_tx[:8].hex())
            return {"group_id": group_id, "epoch": 0, "members": list(clean), "transcript_hash": initial_tx, "suite_id": suite_id}

    def add_member(self, group_id: str, member_id: str) -> int:
        """Add a member, then rekey (epoch +1). Fail-closed on rekey error."""
        group_id = _validate_group_id(group_id)
        member_id = _validate_member_id(member_id)
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if member_id in state.members:
                raise GroupMembershipError(f"member already in group: {member_id!r}")
            if len(state.members) >= MAX_MEMBERS_PER_GROUP:
                raise GroupMembershipError("group is full")
            state.members.append(member_id)
            state.members.sort()
            # New member must not read prior epochs: rekey immediately and
            # only distribute the NEW epoch key to the full roster.
            proposal = Proposal(kind=KIND_ADD, member_id=member_id)
            return self._rekey_locked(state, [proposal])

    def remove_member(self, group_id: str, member_id: str) -> int:
        """Remove a member, then rekey (epoch +1). Fail-closed on rekey error."""
        group_id = _validate_group_id(group_id)
        member_id = _validate_member_id(member_id)
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if member_id not in state.members:
                raise GroupMembershipError(f"member not in group: {member_id!r}")
            state.members = [m for m in state.members if m != member_id]
            # Removed member must not receive the new epoch: rekey now;
            # caller MUST exclude them from fan-out of the new envelopes.
            # Their clearance AND cached advertisement die with membership
            # (no inheritance on re-add).
            state.clearances.pop(member_id, None)
            state.key_packages.pop(member_id, None)
            proposal = Proposal(kind=KIND_REMOVE, member_id=member_id)
            return self._rekey_locked(state, [proposal])

    def rotate(self, group_id: str) -> int:
        """Manual epoch rotation without membership change (epoch +1)."""
        group_id = _validate_group_id(group_id)
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            return self._rekey_locked(state, [])

    def refresh_member_keys(self, group_id: str, member_id: str,
                            new_package: Optional[KeyPackage] = None) -> int:
        """PCS refresh for one member (RFC 9420 §12.1.2 Update analogue).

        Emits an UPDATE proposal and rekeys (epoch +1). When
        ``new_package`` is supplied it becomes the member's registered
        advertisement (member_id must match, keys non-empty, window live)
        so peers validating the commit can bind the rotation to fresh
        keys. Fail-closed on rekey error like every other mutation path.
        """
        group_id = _validate_group_id(group_id)
        member_id = _validate_member_id(member_id)
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if member_id not in state.members:
                raise GroupMembershipError(f"refresh of non-member: {member_id!r}")
            if new_package is not None:
                self._store_package_locked(state, new_package, member_id)
            proposal = Proposal(kind=KIND_UPDATE, member_id=member_id)
            return self._rekey_locked(state, [proposal])

    def publish_key_package(self, group_id: str, package: KeyPackage) -> None:
        """Cache a KeyPackage advertisement (RFC 9420 §10 directory analogue).

        Accepts roster members AND outsiders (pre-join directory cache).
        Shape enforced now (keys non-empty, window well-formed); LIVENESS
        is enforced at use time, never trusted from storage alone. A
        non-live package is stored with a warning (lab visibility) so
        strict-mode USE still refuses it -- storage is not acceptance.
        """
        group_id = _validate_group_id(group_id)
        if not isinstance(package, KeyPackage):
            raise GroupMembershipError("package must be a KeyPackage")
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            self._store_package_locked(state, package, None)

    def _store_package_locked(self, state: _GroupState,
                              package: KeyPackage,
                              expect_member: Optional[str]) -> None:
        """Validate + store an advertisement. Caller must hold the lock."""
        mid = _validate_member_id(package.member_id)
        if expect_member is not None and mid != expect_member:
            raise GroupMembershipError(
                f"package member {mid!r} does not match {expect_member!r}")
        if not package.ml_dsa_pub or not package.kem_pub:
            raise GroupMembershipError(
                f"package for {mid!r} advertises empty keys (useless)")
        import time as _time
        if not package.is_live(_time.time()):
            logger.warning(
                "group %r: caching non-live KeyPackage for %r "
                "(stored, NOT accepted for strict use)", state.group_id, mid)
        state.key_packages[mid] = package

    def key_packages_of(self, group_id: str) -> Dict[str, KeyPackage]:
        """Latest cached KeyPackage per member_id (copy; presence != membership)."""
        with self._lock:
            return dict(self._get(_validate_group_id(group_id)).key_packages)

    def build_welcome(self, group_id: str, new_member_id: str) -> Dict[str, Any]:
        """Build the public sync bundle for a roster member (RFC 9420 §12.4.3
        Welcome analogue, T3-H).

        Carries NO key material: the epoch key reaches the joiner over
        their pairwise channel (same trust as the fan-out path); this
        bundle carries the public state needed to initialize (roster,
        epoch, transcript, pinned suite, tree hash). Refused for
        non-members (external joins stay refused by policy) and for
        locked groups (never onboard onto fail-closed state).
        """
        group_id = _validate_group_id(group_id)
        new_member_id = _validate_member_id(new_member_id)
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if new_member_id not in state.members:
                raise GroupMembershipError(
                    f"welcome refused for non-member {new_member_id!r} "
                    "(external joins refused by policy)")
            # Structure-only tree hash (T3-K): a marker-normalized rebuild
            # at the SAME width, so all sides agree deterministically even
            # when registries differ (key agreement rides the KeyPackage
            # liveness path, not this hash). Verifies roster+positions.
            marker_tree = RatchetTree(width=self._tree_locked(state).width)
            for m in sorted(state.members):
                marker_tree.add(m, _STRUCTURE_MARKER)
            return {
                "v": 2,
                "group_id": group_id,
                "epoch": state.epoch,
                "transcript_hash": bytes(state.transcript_hash).hex(),
                "suite_id": state.suite_id,
                "members": list(state.members),
                "tree_width": marker_tree.width,
                "tree_hash": marker_tree.tree_hash().hex(),
            }

    def join_from_welcome(self, welcome: Dict[str, Any], member_id: str,
                          epoch_key: bytes) -> Dict[str, Any]:
        """Install group state from a Welcome bundle (joiner side, T3-H).

        ``epoch_key`` is the caller's pairwise-decrypted epoch key (same
        trust as ``apply_remote_commit``). Fail-closed: malformed bundles,
        unknown/unsupported suites (downgrade defense at join), joiner not
        on the roster, wrong key length, tree-hash mismatch (roster
        tampering), or an already-known group_id all raise. The joiner
        starts with NO clearances and an empty package registry (labeled
        traffic denied until explicitly granted).
        """
        if not isinstance(welcome, dict):
            raise GroupKeyError("welcome must be a dict")
        if welcome.get("v") != 2:
            raise GroupKeyError("unsupported welcome version (expected v2)")
        group_id = _validate_group_id(welcome.get("group_id", ""))
        member_id = _validate_member_id(member_id)
        epoch = welcome.get("epoch", -1)
        if not isinstance(epoch, int) or epoch < 0:
            raise GroupKeyError("welcome epoch must be a non-negative int")
        try:
            transcript = bytes.fromhex(welcome.get("transcript_hash", ""))
        except (ValueError, TypeError) as exc:
            raise GroupKeyError(f"welcome transcript malformed: {exc}") from exc
        if len(transcript) != 64:
            raise GroupKeyError("welcome transcript must be 64 bytes (SHA3-512)")
        suite_id = welcome.get("suite_id", "")
        if suite_id not in SUPPORTED_SUITES:
            raise GroupKeyError(
                f"welcome suite {suite_id!r} refused (downgrade defense: "
                f"only {sorted(SUPPORTED_SUITES)} enforceable locally)")
        members = welcome.get("members", [])
        if (not isinstance(members, list) or not members
                or any(not isinstance(m, str) for m in members)):
            raise GroupKeyError("welcome roster malformed")
        if member_id not in members:
            raise GroupMembershipError(
                f"joiner {member_id!r} not on the welcome roster")
        if len(set(members)) != len(members) or len(members) > MAX_MEMBERS_PER_GROUP:
            raise GroupKeyError("welcome roster malformed (dupes/oversize)")
        if not isinstance(epoch_key, (bytes, bytearray)) or \
                len(epoch_key) != self._key_size:
            raise GroupKeyError(
                f"welcome epoch key must be {self._key_size} bytes from the "
                "caller's pairwise envelope")
        with self._lock:
            if group_id in self._groups:
                raise GroupExistsError(
                    f"join refused: group {group_id!r} already known "
                    "(welcomes never overwrite live state)")
            state = _GroupState(
                group_id=group_id,
                members=sorted(set(members)),
                group_key=bytearray(bytes(epoch_key)),
                epoch=epoch,
                transcript_hash=transcript,
                suite_id=suite_id,
            )
            self._mirror_tree_locked(state)
            # Tree-hash verification (T3-K): rebuild the marker-normalized
            # structure at the welcomed width and compare. Markers (not
            # registry keys) are compared so sides with different package
            # caches still agree; key agreement rides the KeyPackage path.
            # Legacy welcomes without a hash: lab warn-accept, strict refuse
            # (same policy shape as suite-less commits).
            claimed = welcome.get("tree_hash")
            if claimed is not None:
                try:
                    claimed_b = bytes.fromhex(claimed)
                except (ValueError, TypeError) as exc:
                    raise GroupKeyError(
                        f"welcome tree_hash malformed: {exc}") from exc
                width = welcome.get("tree_width", 0)
                if not isinstance(width, int) or width < 1 or width > 256 \
                        or (width & (width - 1)):
                    raise GroupKeyError("welcome tree_width malformed")
                try:
                    marker_tree = RatchetTree(width=width)
                    for m in sorted(set(members)):
                        marker_tree.add(m, _STRUCTURE_MARKER)
                except TreeError as exc:
                    raise GroupKeyError(
                        f"welcome roster does not fit tree: {exc}") from exc
                if not secrets.compare_digest(marker_tree.tree_hash(),
                                              claimed_b):
                    raise GroupKeyError(
                        "welcome tree_hash mismatch (roster tampered?)")
            elif _strict_group_auth_required():
                raise GroupKeyError(
                    "hash-less welcome refused in strict mode "
                    "(P2P_GROUP_REQUIRE_SIGNED_COMMITS=1)")
            else:
                logger.warning(
                    "group %r: joining from hash-less welcome (lab only)",
                    group_id)
            self._groups[group_id] = state
            logger.info("group %r joined from welcome at epoch %d as %r",
                        group_id, epoch, member_id)
            return {"group_id": group_id, "epoch": epoch,
                    "members": sorted(set(members)), "suite_id": suite_id}

    def apply_remote_commit(
        self,
        group_id: str,
        commit_bytes: bytes,
        committer_id: str,
        new_epoch_key: bytes,
        committer_pub: Optional[bytes] = None,
        verify_cb: Optional[Callable[[bytes, bytes, bytes], bool]] = None,
        key_packages: Optional[Dict[str, KeyPackage]] = None,
        commit_sig: Optional[bytes] = None,
    ) -> int:
        """Apply a committer-signed Commit received over an authenticated
        pairwise channel (the v1 group receive path).

        Research basis (ETK/EUROCRYPT-2026, RFC 9420 §6.1 content
        authentication, §12.2 proposal-list validation, §12.4 commits,
        §16.6 FS/PCS, draft-ietf-mls-pq-ciphersuites-06): unauthenticated
        and externally-injected group operations weaken PCS, handshake
        signatures must be SUF-CMA (ML-DSA-87 qualifies), proposal lists
        must be internally consistent, and the PQ ciphersuite must be
        pinned against downgrade.

        Enforcement:

        1. Committer MUST be a current roster member (external commits --
           including DS-injected ones -- are refused outright).
        2. ``(committer_id, committer_pub)`` binding is CALLER-ATTESTED: the
           caller must have authenticated the peer on the pairwise channel
           BEFORE invoking (same trust as the envelope fan-out path).
        3. Epoch MUST equal current+1 exactly (no jumps, no replays;
           concurrent commits resolve first-writer-wins; no fork-resolution
           protocol exists in v1 -- see module header).
        4. ``commit.prev_tx`` MUST equal the local transcript (fork detect).
        5. Suite gate (T3-A): unknown suite ids are rejected; a suite
           differing from the pinned group suite is rejected as a
           downgrade attempt (both modes); legacy suite-less commits are
           refused in strict/production mode and warn-accepted in lab
           (same policy shape as unsigned proposals).
        6. EVERY proposal MUST carry a valid ML-DSA-87 signature under the
           committer key in strict/production mode. Present-but-invalid
           signatures ALWAYS fail (no silent strip); unsigned proposals are
           refused in strict mode, warn-accepted in lab. Empty commits
           (pure rotation signal) are allowed: committer authenticity then
           rests on the pairwise channel + transcript continuity.
        7. Proposal semantics: ADD targets must be non-members, REMOVE and
           UPDATE targets must be current members (UPDATE = key refresh,
           RFC 9420 §12.1.2 analogue; applied as a PCS rekey step).
           Proposal-LIST consistency (T3-I, RFC 9420 §12.2 shape): one
           member, at most one proposal per commit -- duplicates and
           contradictions (ADD+REMOVE, UPDATE+REMOVE, double ADD) are
           refused before any state changes; oversize lists are refused
           as abusive.
        8. KeyPackage liveness (T3-C, RFC 9420 §10/§7.2 lifetime analogue):
           when the caller supplies ``key_packages`` for ADD targets,
           expired/not-yet-valid advertisements are rejected (strict) or
           warn-accepted (lab). Without supplied packages no lifetime
           claim is checked (nothing to check against).
        9. The new epoch key comes from the caller's pairwise-decrypted
           envelope (v1 has no TreeKEM: keys fan out O(n), never derived
           from commits -- deriving from commits would let removed members
           ratchet forward and break PCS on removal).
        10. Commit-level authentication (T3-F, defense in depth): when the
           caller supplies ``commit_sig`` (ML-DSA-87 over the canonical
           ``Commit.encode()`` bytes, which include the suite annotation),
           it MUST verify under ``committer_pub``/``verify_cb`` in BOTH
           modes -- present-but-invalid is never silent-stripped. Absent,
           existing rules apply (per-proposal sigs in strict mode, pairwise
           channel authentication otherwise). The signature travels
           BESIDE the commit (e.g. in the pairwise envelope), so no
           framing version bump is needed; full MLS signs every
           FramedContent, which v1 reaches when a DS/wire path exists.

        Returns the new epoch. Fail-closed throughout (GroupKeyError /
        GroupMembershipError); the local key is replaced only after ALL
        checks pass, old material wiped.
        """
        group_id = _validate_group_id(group_id)
        committer_id = _validate_member_id(committer_id)
        if not isinstance(commit_bytes, (bytes, bytearray)) or not commit_bytes:
            raise GroupKeyError("commit must be non-empty bytes")
        if not isinstance(new_epoch_key, (bytes, bytearray)) or \
                len(new_epoch_key) != self._key_size:
            raise GroupKeyError(
                f"new epoch key must be {self._key_size} bytes from the "
                "caller's pairwise envelope")
        try:
            commit = Commit.decode(bytes(commit_bytes))
        except ValueError as exc:
            raise GroupKeyError(f"malformed Commit frame: {exc}") from exc
        if commit_sig is not None:
            # 10. Commit-level signature: verified before any state is
            # touched; covers the canonical encoding (suite annotation
            # included), so downgrade tampering breaks the signature too.
            if committer_pub is None or verify_cb is None:
                raise GroupKeyError(
                    "commit signature supplied without committer key and "
                    "verify callback (nothing to verify against)")
            try:
                sig_ok = bool(verify_cb(bytes(committer_pub),
                                        commit.encode(),
                                        bytes(commit_sig)))
            except Exception:
                sig_ok = False
            if not sig_ok:
                raise GroupKeyError(
                    f"commit-level signature invalid for commit by "
                    f"{committer_id!r} (rejected in all modes)")
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if committer_id not in state.members:
                raise GroupMembershipError(
                    f"external commit refused: {committer_id!r} is not a "
                    f"roster member (ETK external-operations rule)")
            if commit.epoch != state.epoch + 1:
                raise GroupKeyError(
                    f"commit epoch {commit.epoch} != current+1 "
                    f"({state.epoch + 1}); stale or forked")
            if not secrets.compare_digest(
                    bytes(commit.prev_tx), bytes(state.transcript_hash)):
                raise GroupKeyError(
                    "commit transcript mismatch (fork detected)")
            strict = _strict_group_auth_required()
            # 5. Suite gate (downgrade defense).
            if commit.suite_id and commit.suite_id not in KNOWN_SUITES:
                raise GroupKeyError(
                    f"commit advertises unknown PQ suite {commit.suite_id!r}")
            if commit.suite_id and commit.suite_id != state.suite_id:
                raise GroupKeyError(
                    f"suite downgrade/mismatch refused: commit "
                    f"{commit.suite_id!r} != pinned {state.suite_id!r}")
            if not commit.suite_id and strict:
                raise GroupKeyError(
                    "suite-less commit refused in strict mode: group "
                    f"{group_id!r} pins {state.suite_id!r} "
                    "(P2P_GROUP_REQUIRE_SIGNED_COMMITS=1)")
            if not commit.suite_id:
                logger.warning(
                    "group %r: applying suite-less commit (lab only -- "
                    "strict mode requires suite-pinned commits)", group_id)
            if verify_cb is None and strict and commit.proposals:
                raise GroupKeyError(
                    "signed commits required in strict mode: no verify "
                    "callback supplied (P2P_GROUP_REQUIRE_SIGNED_COMMITS=1)")
            # 5b. Proposal-list consistency (T3-I, RFC 9420 §12.2 shape):
            # one member, one proposal per commit. Duplicate or
            # contradictory mentions (ADD+REMOVE, UPDATE+REMOVE, double
            # ADD, ...) are refused before any per-proposal check, so a
            # commit can never add-then-strip or refresh-then-evict in a
            # single ambiguous step. Oversize lists are refused as abusive
            # (a commit can touch at most every member once).
            if len(commit.proposals) > 2 * MAX_MEMBERS_PER_GROUP:
                raise GroupKeyError(
                    f"commit carries {len(commit.proposals)} proposals "
                    "(abusive; bounded at twice max roster)")
            _seen_targets: Dict[str, int] = {}
            for prop in commit.proposals:
                prev = _seen_targets.get(prop.member_id)
                if prev is not None:
                    raise GroupMembershipError(
                        f"contradictory/duplicate proposals for "
                        f"{prop.member_id!r} in one commit (kinds "
                        f"{prev} then {prop.kind})")
                _seen_targets[prop.member_id] = prop.kind
            for prop in commit.proposals:
                if prop.kind == KIND_ADD:
                    if prop.member_id in state.members:
                        raise GroupMembershipError(
                            f"add of existing member {prop.member_id!r}")
                elif prop.kind == KIND_REMOVE:
                    if prop.member_id not in state.members:
                        raise GroupMembershipError(
                            f"remove of non-member {prop.member_id!r}")
                elif prop.kind == KIND_UPDATE:
                    if prop.member_id not in state.members:
                        raise GroupMembershipError(
                            f"update of non-member {prop.member_id!r}")
                else:  # pragma: no cover - framing already rejects kinds
                    raise GroupMembershipError("unknown proposal kind")
                if prop.sig:
                    if committer_pub is None:
                        raise GroupKeyError(
                            "signed proposal but no committer key supplied")
                    if not verify_proposal_sig(prop, bytes(committer_pub),
                                               verify_cb):
                        raise GroupKeyError(
                            f"proposal signature invalid for {prop.member_id!r}")
                elif strict:
                    raise GroupKeyError(
                        f"unsigned proposal for {prop.member_id!r} refused "
                        "in strict mode")
                else:
                    logger.warning(
                        "group %r: applying UNSIGNED proposal for %r "
                        "(lab only -- enable strict signed commits)",
                        group_id, prop.member_id)
            # 8. KeyPackage liveness for ADD targets + key binding for
            # UPDATE targets (T3-C/T3-G, RFC 9420 §10/§7.2). Package source:
            # explicit caller arg first, local registry (directory cache)
            # second. Absent entirely: nothing to check, proceed (keys ride
            # the pairwise envelope as before).
            if True:
                import time as _time
                now = _time.time()
                for prop in commit.proposals:
                    if prop.kind == KIND_ADD:
                        kp = None
                        if key_packages and prop.member_id in key_packages:
                            kp = key_packages[prop.member_id]
                        elif prop.member_id in state.key_packages:
                            kp = state.key_packages[prop.member_id]
                        if kp is None:
                            continue  # nothing supplied: nothing to check
                        if not isinstance(kp, KeyPackage) or not kp.is_live(now):
                            if strict:
                                raise GroupMembershipError(
                                    f"stale/expired KeyPackage for "
                                    f"{prop.member_id!r} refused in strict mode")
                            logger.warning(
                                "group %r: ADD with non-live KeyPackage for %r "
                                "(lab only)", group_id, prop.member_id)
                    elif prop.kind == KIND_UPDATE:
                        kp = None
                        if key_packages and prop.member_id in key_packages:
                            kp = key_packages[prop.member_id]
                        elif prop.member_id in state.key_packages:
                            kp = state.key_packages[prop.member_id]
                        if kp is None:
                            continue  # rotation recorded via rekey alone
                        if not isinstance(kp, KeyPackage):
                            raise GroupMembershipError(
                                f"malformed KeyPackage for {prop.member_id!r}")
                        if kp.member_id != prop.member_id:
                            raise GroupMembershipError(
                                f"UPDATE package binding mismatch: package "
                                f"{kp.member_id!r} != target {prop.member_id!r}")
                        if not kp.is_live(now):
                            if strict:
                                raise GroupMembershipError(
                                    f"stale/expired UPDATE KeyPackage for "
                                    f"{prop.member_id!r} refused in strict mode")
                            logger.warning(
                                "group %r: UPDATE with non-live KeyPackage "
                                "for %r (lab only)", group_id, prop.member_id)
                        # Bind the rotation: registered keys move forward.
                        state.key_packages[prop.member_id] = kp
            # All checks passed: apply membership, install fanned-out key.
            for prop in commit.proposals:
                if prop.kind == KIND_ADD:
                    state.members.append(prop.member_id)
                elif prop.kind == KIND_REMOVE:
                    state.members = [m for m in state.members
                                     if m != prop.member_id]
                    state.clearances.pop(prop.member_id, None)
                    state.key_packages.pop(prop.member_id, None)
                elif prop.kind == KIND_UPDATE:
                    pass  # roster unchanged: PCS rekey step only
                else:  # pragma: no cover - validated above
                    raise GroupMembershipError("unknown proposal kind")
            state.members.sort()
            # Mirror the tree BEFORE installing key material: a diverged
            # mirror raises GroupKeyError and nothing is installed.
            self._mirror_tree_locked(state)
            _zero(state.group_key)
            state.group_key = bytearray(bytes(new_epoch_key))
            state.epoch = commit.epoch
            state.transcript_hash = commit.new_transcript()
            logger.info("group %r applied remote commit to epoch %d from %r",
                        group_id, state.epoch, committer_id)
            return state.epoch

    def encrypt_for_group(self, group_id: str, plaintext: bytes | str) -> Dict[str, Any]:
        """Encrypt for the group -> ``{"group_id", "epoch", "envelopes"}``.

        ``envelopes`` maps each current member -> ciphertext bytes. Each
        envelope uses the pairwise hook when available, else the AES-GCM
        placeholder under the current epoch key.
        """
        group_id = _validate_group_id(group_id)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes or str")
        if len(plaintext) == 0:
            raise ValueError("plaintext must be non-empty")
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if not state.members:
                raise GroupMembershipError("group has no members")
            epoch = state.epoch
            key_snapshot = bytes(state.group_key)
            members = list(state.members)
        aad = None  # computed per member below (V2 member-bound)
        envelopes: Dict[str, bytes] = {}
        strict_pairwise = _strict_pairwise_required()
        for member in members:
            try:
                envelopes[member] = self._pairwise_wrap(member, bytes(plaintext))
            except _NeedPlaceholderFallback:
                if strict_pairwise:
                    # Production: a group-key compromise must not expose the
                    # distribution envelope — refuse rather than seal locally.
                    raise GroupKeyError(
                        f"pairwise 1:1 channel to {member!r} unavailable "
                        "(P2P_GROUP_REQUIRE_PAIRWISE=1: refusing local-envelope fallback)"
                    )
                logger.warning(
                    "group %r epoch %d: no pairwise channel to %r; using "
                    "local AES-GCM envelope bound to (group, epoch, member) "
                    "(lab only — set P2P_GROUP_REQUIRE_PAIRWISE=1 to refuse)",
                    group_id, epoch, member,
                )
                envelopes[member] = _aead_seal(
                    key_snapshot, _envelope_aad(group_id, epoch, member), bytes(plaintext))
            except Exception as exc:
                raise GroupKeyError(f"per-member wrap failed for {member!r}: {exc}") from exc
        return {"group_id": group_id, "epoch": epoch, "envelopes": envelopes}

    def decrypt_from_group(self, group_id: str, data: bytes | Dict[str, Any], epoch: int,
                           member_id: Optional[str] = None) -> bytes:
        """Decrypt a placeholder AES-GCM envelope from ``encrypt_for_group``.

        Accepts raw envelope bytes or ``{"ct": ...}``. Verifies the epoch
        matches the current epoch (stale epochs are rejected: no key
        history is retained). Pairwise-hook envelopes must be unwrapped
        by the caller's 1:1 stack first, not here.

        ``member_id`` selects the V2 member-bound AAD. When omitted, the
        legacy V1 group-only AAD is tried (pre-upgrade envelopes): allowed
        in lab with a warning, refused in strict/production mode.
        """
        group_id = _validate_group_id(group_id)
        if member_id is not None:
            member_id = _validate_member_id(member_id)
        if isinstance(data, dict):
            data = data.get("ct", data.get("envelope", b""))
        if not isinstance(data, (bytes, bytearray)) or not data:
            raise TypeError("data must be non-empty bytes or {'ct': bytes}")
        if not isinstance(epoch, int) or epoch < 0:
            raise ValueError("epoch must be a non-negative int")
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if epoch != state.epoch:
                raise GroupKeyError(
                    f"stale epoch {epoch} (current {state.epoch}); no key history retained"
                )
            key_snapshot = bytes(state.group_key)
        if member_id is not None:
            return _aead_open(key_snapshot, _envelope_aad(group_id, epoch, member_id), bytes(data))
        if _strict_pairwise_required():
            raise GroupKeyError(
                "member-bound (V2) envelope required in strict mode: "
                "pass member_id (P2P_GROUP_REQUIRE_PAIRWISE=1)"
            )
        logger.warning(
            "group %r: decrypting legacy V1 group-only envelope without "
            "member binding (lab only — pass member_id)", group_id,
        )
        return _aead_open(key_snapshot, _envelope_aad(group_id, epoch), bytes(data))

    # -- read-only accessors (no key material leaves except via envelopes) --

    # -- classification & compartments (Tier-3 need-to-know) ---------------
    # Labels ride OUTSIDE the message envelopes with their own MAC under the
    # current epoch key, so stripping/forging a label fails closed even
    # though the label itself is visible (markings must be visible to be
    # useful). Enforcement is dominance: member_level >= label_level AND
    # member_compartments ⊇ label_compartments. Members WITHOUT a
    # registered clearance are denied LABELED traffic (fail-closed) but may
    # still use unlabeled envelopes (backward compatible).

    def set_clearance(self, group_id: str, member_id: str,
                      classification: str,
                      compartments: tuple | list = ()) -> None:
        """Register a member's clearance (need-to-know basis)."""
        import re as _re
        group_id = _validate_group_id(group_id)
        member_id = _validate_member_id(member_id)
        level = CLASSIFICATION_LEVELS.get(str(classification or "").upper())
        if level is None:
            raise GroupMembershipError(
                f"unknown classification {classification!r} "
                f"(want one of {sorted(CLASSIFICATION_LEVELS)})")
        comps = tuple(compartments or ())
        if len(comps) > _MAX_COMPARTMENTS:
            raise GroupMembershipError("too many compartments")
        for c in comps:
            if not isinstance(c, str) or not _re.fullmatch(r"[A-Za-z0-9_-]{1,32}", c):
                raise GroupMembershipError(f"bad compartment {c!r}")
        with self._lock:
            state = self._get(group_id)
            if member_id not in state.members:
                raise GroupMembershipError(
                    f"cannot clear non-member {member_id!r}")
            state.clearances[member_id] = (level, frozenset(comps))

    def seal_labeled(self, group_id: str, plaintext: bytes | str,
                     classification: str, compartments: tuple | list = ()
                     ) -> Dict[str, Any]:
        """Seal a message with a MAC-bound classification label.

        Returns ``{"group_id", "epoch", "label", "label_mac", "inner"}``
        where ``inner`` is the standard ``encrypt_for_group`` result and
        ``label_mac`` is HMAC-SHA384(epoch_key, label-context) hex.
        """
        import hmac as _hmac_mod
        import re as _re
        group_id = _validate_group_id(group_id)
        level = CLASSIFICATION_LEVELS.get(str(classification or "").upper())
        if level is None:
            raise GroupMembershipError(
                f"unknown classification {classification!r}")
        comps = sorted({c for c in (compartments or ())
                        if isinstance(c, str) and _re.fullmatch(r"[A-Za-z0-9_-]{1,32}", c)})
        if len(comps) != len(list(compartments or ())):
            raise GroupMembershipError("invalid compartment token in label")
        if len(comps) > _MAX_COMPARTMENTS:
            raise GroupMembershipError("too many compartments")
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            epoch = state.epoch
            key_snapshot = bytes(state.group_key)
        label = {"classification": str(classification).upper(),
                 "compartments": comps}
        mac = _hmac_mod.new(
            key_snapshot,
            _label_context(group_id, epoch, str(classification).upper(), comps),
            hashlib.sha384).hexdigest()
        inner = self.encrypt_for_group(group_id, plaintext)
        if inner["epoch"] != epoch:
            raise GroupKeyError("epoch moved during labeled seal; retry")
        return {"group_id": group_id, "epoch": epoch, "label": label,
                "label_mac": mac, "inner": inner}

    def open_labeled(self, group_id: str, sealed: Dict[str, Any],
                     member_id: str,
                     clearance: Optional[tuple] = None) -> bytes:
        """Open a labeled envelope iff the member dominates its label.

        ``clearance`` optionally overrides ``(level_int, compartments)``;
        otherwise the registered clearance applies. Missing clearance,
        MAC mismatch, stale epoch, or non-dominance all fail closed
        (GroupAccessDenied) BEFORE any decryption (no oracle).
        """
        import hmac as _hmac_mod
        group_id = _validate_group_id(group_id)
        member_id = _validate_member_id(member_id)
        if not isinstance(sealed, dict):
            raise GroupKeyError("labeled envelope must be a dict")
        try:
            epoch = sealed["epoch"]
            label = sealed["label"]
            mac = sealed["label_mac"]
            inner = sealed["inner"]
            cls_name = str(label["classification"]).upper()
            label_comps = [str(c) for c in label["compartments"]]
        except (KeyError, TypeError, AttributeError) as exc:
            raise GroupKeyError(f"malformed labeled envelope: {exc}") from exc
        if not isinstance(epoch, int) or epoch < 0:
            raise GroupKeyError("bad envelope epoch")
        level = CLASSIFICATION_LEVELS.get(cls_name)
        if level is None:
            raise GroupKeyError(f"unknown label classification {cls_name!r}")
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            if member_id not in state.members:
                raise GroupAccessDenied(f"{member_id!r} is not a group member")
            if clearance is None:
                clearance = state.clearances.get(member_id)
            if clearance is None:
                raise GroupAccessDenied(
                    f"{member_id!r} has no registered clearance (labeled "
                    "traffic denied fail-closed)")
            try:
                mem_level, mem_comps = int(clearance[0]), frozenset(clearance[1])
            except (TypeError, ValueError, IndexError) as exc:
                raise GroupAccessDenied(f"malformed clearance: {exc}") from exc
            cur_epoch = state.epoch
            key_snapshot = bytes(state.group_key)
        if epoch != cur_epoch:
            raise GroupKeyError(
                f"stale labeled epoch {epoch} (current {cur_epoch})")
        expect = _hmac_mod.new(
            key_snapshot,
            _label_context(group_id, epoch, cls_name, sorted(label_comps)),
            hashlib.sha384).hexdigest()
        if not secrets.compare_digest(str(mac).lower(), expect.lower()):
            raise GroupAccessDenied("label MAC mismatch (forged/stripped label?)")
        if not (mem_level >= level and set(label_comps) <= set(mem_comps)):
            raise GroupAccessDenied(
                f"{member_id!r} clearance does not dominate label "
                f"{cls_name}/{sorted(label_comps)}")
        try:
            ct = inner["envelopes"][member_id]
        except (KeyError, TypeError) as exc:
            raise GroupAccessDenied(f"no envelope for {member_id!r}: {exc}") from exc
        return self.decrypt_from_group(group_id, ct, epoch, member_id=member_id)

    def epoch_of(self, group_id: str) -> int:
        with self._lock:
            state = self._get(_validate_group_id(group_id))
            return state.epoch

    def members_of(self, group_id: str) -> List[str]:
        with self._lock:
            return list(self._get(_validate_group_id(group_id)).members)

    def list_groups(self) -> List[str]:
        with self._lock:
            return sorted(self._groups)

    def destroy_group(self, group_id: str) -> bool:
        """Wipe key material and forget the group. Returns True if removed."""
        with self._lock:
            state = self._groups.pop(_validate_group_id(group_id), None)
            if state is None:
                return False
            _zero(state.group_key)
            state.members = []
            state.locked = True
            return True

    def key_fingerprint(self, group_id: str) -> str:
        """SHA-256 fingerprint of (group_id, epoch, key) for debugging."""
        with self._lock:
            state = self._get(_validate_group_id(group_id))
            digest = hashlib.sha256(
                state.group_id.encode("utf-8")
                + state.epoch.to_bytes(8, "big")
                + bytes(state.group_key)
            ).hexdigest()
            return digest

    def transcript_of(self, group_id: str) -> bytes:
        """Current transcript hash of the group (RFC 9420 §8.2 shape, SHA3-512)."""
        with self._lock:
            state = self._get(_validate_group_id(group_id))
            return bytes(state.transcript_hash)

    def export_subkey(self, group_id: str, label: str, length: int = 32,
                      epoch: Optional[int] = None) -> bytes:
        """Derive a purpose-bound subkey (MLS exporter analogue, T3-E).

        Research basis: RFC 9420 §8.5 exporter secret — subsidiary keys
        (compartment crypts, file-transfer keys, audit-MAC keys) derive
        from the epoch secret so members agree without new round trips.

        ``HKDF-SHA3-512(ikm=epoch_key, salt=transcript, info=context)``
        where ``context`` binds ``GKM-EXPORT-V1 || suite || group ||
        epoch || label``. Properties: same (key, transcript, epoch,
        suite, label) => same subkey on every member (agreement);
        different epoch/label => unrelated output; a removed member
        holding only a STALE epoch key cannot derive the current
        epoch's subkeys (PCS-aligned); outputs reveal nothing about
        the epoch key (HKDF one-way).

        Only the CURRENT epoch may be exported: old keys are wiped at
        rekey, so historical export is refused fail-closed (never
        silently derived from the wrong epoch). Returned ``bytes`` are
        immutable -- callers needing wipeable handling must copy into a
        ``bytearray`` and wipe it themselves.
        """
        group_id = _validate_group_id(group_id)
        if not isinstance(label, str) or not label or len(label) > 128:
            raise GroupKeyError("export label must be a non-empty str (<=128 chars)")
        if not isinstance(length, int) or not 16 <= length <= 256:
            raise GroupKeyError("export length must be 16..256 bytes")
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # type: ignore
            from cryptography.hazmat.primitives import hashes as _hashes  # type: ignore
        except Exception as exc:
            raise GroupKeyError(
                "cryptography package required for exporter KDF") from exc
        with self._lock:
            state = self._get(group_id)
            self._check_unlocked(state)
            cur = state.epoch
            if epoch is None:
                epoch = cur
            if epoch != cur:
                raise GroupKeyError(
                    f"exporter refused for stale epoch {epoch} "
                    f"(current {cur}): old keys are wiped, derivation "
                    "from the wrong epoch is never silent")
            import struct as _struct
            gid = group_id.encode("utf-8")
            sid = state.suite_id.encode("utf-8")
            lab = label.encode("utf-8")
            info = (b"GKM-EXPORT-V1:" + _struct.pack(">I", len(sid)) + sid
                    + _struct.pack(">I", len(gid)) + gid
                    + epoch.to_bytes(8, "big")
                    + _struct.pack(">I", len(lab)) + lab)
            hkdf = HKDF(algorithm=_hashes.SHA3_512(), length=length,
                        salt=bytes(state.transcript_hash),
                        info=info)
            return hkdf.derive(bytes(state.group_key))


class _NeedPlaceholderFallback(Exception):
    """Internal control-flow: pairwise hook unavailable, use AES-GCM stub."""


# ----------------------------------------------------------------------
# AES-GCM placeholder envelopes (pure logic; lazy crypto import)
# ----------------------------------------------------------------------

def _envelope_aad(group_id: str, epoch: int, member_id: Optional[str] = None) -> bytes:
    """Associated data binding the envelope to its context (length-framed).

    V2 (member-bound): ``GKM-V2:`` + u32len(group_id) + group_id +
    u64be(epoch) + u32len(member_id) + member_id. Length framing (not ``:``
    delimiters: IDs may contain ``:``) so distinct triples never collide.
    V1 (legacy, group-only): ``GKM-V1:`` + group_id + ``:`` + u64be(epoch),
    accepted on decrypt only for pre-upgrade envelopes (lab warn / prod
    refused unless the envelope also verifies under V2).
    """
    gid = group_id.encode("utf-8")
    if member_id is None:
        return b"GKM-V1:" + gid + b":" + epoch.to_bytes(8, "big")
    mid = member_id.encode("utf-8")
    import struct as _struct
    return (b"GKM-V2:" + _struct.pack(">I", len(gid)) + gid
            + epoch.to_bytes(8, "big")
            + _struct.pack(">I", len(mid)) + mid)


def _aead_seal(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """Seal with AES-GCM: nonce(12) || ct+tag. Lazy import, no I/O."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    except Exception as exc:
        raise GroupKeyError(
            "cryptography package required for placeholder envelopes"
        ) from exc
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), aad)


def _aead_open(key: bytes, aad: bytes, envelope: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    except Exception as exc:
        raise GroupKeyError(
            "cryptography package required for placeholder envelopes"
        ) from exc
    if len(envelope) < 12 + 16:
        raise GroupKeyError("envelope too short")
    nonce, ct = envelope[:12], envelope[12:]
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ct, aad)
    except Exception as exc:
        raise GroupKeyError(f"envelope authentication failed: {exc}") from exc

