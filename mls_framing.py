#!/usr/bin/env python3
"""mls_framing.py — MLS-inspired group framing skeleton (RFC 9420 shape, v2).

What this IS: versioned, length-prefixed binary framing for group
operations (KeyPackage publish, Add/Remove/Update proposals, Commit)
with an epoch transcript hash chain. Every Commit binds
(prev_transcript || proposals || suite_annotation || epoch), giving the
group-agreement primitive the pairwise skeleton lacks: members who
process the same Commit sequence derive the same transcript; forks are
detectable by comparing transcript hashes.

v2 changes (Tier-3 increment; v1 frames are REJECTED with a clear
error, no silent cross-version acceptance):
- Proposal kind 3 = UPDATE (RFC 9420 §12.1.2 Update path analogue): a member
  refreshes its own advertised keys. Applied as a PCS step: the epoch
  rekeys and the updater's new KeyPackage replaces the old one.
- KeyPackage carries a validity window (not_before/not_after unix
  seconds, RFC 9420 §10/§7.2 lifetime analogue). Receivers enforce liveness
  to bound replay of stale advertisements.
- Commit binds a PQ ciphersuite annotation (research basis:
  draft-ietf-mls-pq-ciphersuites-06, July 2026). The annotation rides in
  the previously-reserved ``new_tx_input`` blob as ``b"suite=" + id``
  and is hashed into the transcript, so a suite-downgrade fork is a
  transcript fork (detectable). Empty annotation = legacy/unspecified;
  strict receivers refuse it (same policy shape as unsigned proposals).

What this IS NOT (honest limits, cf. group_key_manager.py header):
- NOT a TreeKEM ratchet tree: key distribution still fans out O(n)
  per-member envelopes via GroupKeyManager (pairwise channels).
- NOT full MLS: no tree resolution/blanking, no PSK/resumption,
  no federated Delivery Service, no HPKE. Proposals carry an optional
  ML-DSA-87 signature slot verified by the caller-supplied callback;
  without a verify callback, membership authentication MUST happen
  over the pairwise channels before applying proposals.
- Suite registry documents the draft's names; only the pure-PQ
  ML-KEM-1024 + ML-DSA-87 suite is locally enforced (claiming more
  would be dishonest: no hybrid HPKE combiner is implemented here).
- All crypto is classical-HKDF/AES-GCM envelope binding here; PQ
  strength comes from the GroupKeyManager epoch keys (ML-KEM-derived
  in production).

Wire format v2 (all integers big-endian, all blobs u32len-prefixed):
  KeyPackage:  b"MLSF1" || u16(version=2) || u32len(member_id) || member_id
               || u32len(ml_dsa_pub) || ml_dsa_pub || u32len(kem_pub) || kem_pub
               || u64be(not_before) || u64be(not_after)
  Proposal:    b"MLSP1" || u16(2) || u8(kind:1=add,2=remove,3=update)
               || u32len(member) || member || u32len(sig) || sig
               (sig may be empty when unsigned)
  Commit:      b"MLSC1" || u16(2) || u64be(epoch) || u32len(prev_tx) || prev_tx
               || u16(n_proposals) || proposals... || u32len(new_tx_input)
               new_tx_input = b"" (legacy) or b"suite=" + suite_id bytes
Transcript update: new_tx = SHA3-512(prev_tx || canonical(proposals)
                   || new_tx_input || epoch_be64).
                   (h.update(b"") is digest-neutral, so legacy empty
                   commits hash exactly as under v1 code.)
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass, field
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)

VERSION = 2
MAGIC_KEYPACKAGE = b"MLSF1"
MAGIC_PROPOSAL = b"MLSP1"
MAGIC_COMMIT = b"MLSC1"

KIND_ADD = 1
KIND_REMOVE = 2
KIND_UPDATE = 3  # v2: member key refresh (RFC 9420 §12.1.2 Update analogue).

TRANSCRIPT_INIT = b"MLS-TRANSCRIPT-GENESIS-V1"

# PQ ciphersuite registry (names per draft-ietf-mls-pq-ciphersuites-06).
# Only SUITE_PQ_PURE_1024 is locally enforceable (ML-KEM-1024 KEM,
# ML-DSA-87 signatures, SHAKE256 KDF at 192-bit): the hybrids are
# documented for negotiation honesty but raise "unsupported suite"
# until a hybrid HPKE combiner exists here.
SUITE_PQ_PURE_1024 = "ML-KEM-1024+ML-DSA-87/pure-PQ"
SUITE_HYBRID_X25519_768 = "ML-KEM-768+X25519/hybrid"      # documented, unsupported
SUITE_HYBRID_P256_768 = "ML-KEM-768+P-256/hybrid"         # documented, unsupported
SUITE_HYBRID_P384_1024 = "ML-KEM-1024+P-384/hybrid"       # documented, unsupported
SUPPORTED_SUITES = frozenset({SUITE_PQ_PURE_1024})
KNOWN_SUITES = frozenset({SUITE_PQ_PURE_1024, SUITE_HYBRID_X25519_768,
                          SUITE_HYBRID_P256_768, SUITE_HYBRID_P384_1024})
DEFAULT_SUITE = SUITE_PQ_PURE_1024
_SUITE_WIRE_PREFIX = b"suite="
SUITE_ID_MAX_LEN = 128
# KeyPackage lifetime bounds (RFC 9420 §10/§7.2 lifetime analogue).
KP_LIFETIME_MAX_SKEW = 300  # 5 min clock-skew tolerance on not_before.
KP_LIFETIME_MAX_SPAN = 30 * 24 * 3600  # 30 days max advertisement span.


def _pack_blob(data: bytes) -> bytes:
    if len(data) > 0xFFFFFFFF:
        raise ValueError("blob too large")
    return struct.pack(">I", len(data)) + bytes(data)


def _unpack_blob(buf: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(buf):
        raise ValueError("truncated length prefix")
    (n,) = struct.unpack_from(">I", buf, offset)
    offset += 4
    if offset + n > len(buf):
        raise ValueError("truncated blob body")
    return buf[offset:offset + n], offset + n


#: Maximum member_id size on the wire (matches the group layer; bounds
#: memory allocation on decode -- a multi-GB identity blob is a DoS
#: vector, not an identity).
MEMBER_ID_MAX_LEN = 256


def _pack_member_id(member_id: str) -> bytes:
    """Encode a member_id with wire bounds enforced (both directions)."""
    if not isinstance(member_id, str) or not member_id:
        raise ValueError("member_id must be a non-empty str")
    raw = member_id.encode("utf-8")
    if len(raw) > MEMBER_ID_MAX_LEN:
        raise ValueError(f"member_id exceeds {MEMBER_ID_MAX_LEN} bytes")
    return _pack_blob(raw)


def _unpack_member_id(raw: bytes) -> str:
    """Decode a member_id blob with wire bounds enforced."""
    if len(raw) > MEMBER_ID_MAX_LEN:
        raise ValueError(f"member_id exceeds {MEMBER_ID_MAX_LEN} bytes")
    try:
        mid = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("member_id not utf-8") from exc
    if not mid:
        raise ValueError("empty member_id")
    return mid


@dataclass
class KeyPackage:
    """A member's advertised keys with a validity window (v2).

    ``not_before``/``not_after`` are unix seconds (RFC 9420 §10 KeyPackage /
    §7.2 LeafNode lifetime analogue). ``is_live(now)`` enforces the window with a small skew
    tolerance; over-long spans are rejected at construction.
    """
    member_id: str
    ml_dsa_pub: bytes = b""
    kem_pub: bytes = b""
    not_before: int = 0
    not_after: int = 0

    def __post_init__(self):
        for attr in ("not_before", "not_after"):
            val = getattr(self, attr)
            if not isinstance(val, int) or val < 0 or val > 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"{attr} must be a u64 unix time")
        if self.not_after and self.not_after <= self.not_before:
            raise ValueError("KeyPackage lifetime must satisfy not_after > not_before")
        if self.not_after and (self.not_after - self.not_before) > KP_LIFETIME_MAX_SPAN:
            raise ValueError("KeyPackage lifetime span exceeds 30 days")

    def is_live(self, now: Optional[float] = None) -> bool:
        """True when the advertisement window covers ``now`` (skew-tolerant)."""
        import time as _time
        t = int(now if now is not None else _time.time())
        if not self.not_after:
            return False  # zero window = never live (fail-closed)
        return (self.not_before - KP_LIFETIME_MAX_SKEW) <= t <= self.not_after

    def encode(self) -> bytes:
        return (MAGIC_KEYPACKAGE + struct.pack(">H", VERSION)
                + _pack_member_id(self.member_id)
                + _pack_blob(bytes(self.ml_dsa_pub))
                + _pack_blob(bytes(self.kem_pub))
                + struct.pack(">Q", self.not_before)
                + struct.pack(">Q", self.not_after))

    @classmethod
    def decode(cls, buf: bytes) -> "KeyPackage":
        try:
            return cls._decode_inner(bytes(buf))
        except struct.error as exc:
            raise ValueError(f"truncated KeyPackage: {exc}") from exc

    @classmethod
    def _decode_inner(cls, buf: bytes) -> "KeyPackage":
        if buf[:5] != MAGIC_KEYPACKAGE:
            raise ValueError("bad KeyPackage magic")
        (ver,) = struct.unpack_from(">H", buf, 5)
        if ver != VERSION:
            raise ValueError(f"unsupported KeyPackage version {ver}")
        off = 7
        raw_mid, off = _unpack_blob(buf, off)
        mldsa, off = _unpack_blob(buf, off)
        kem, off = _unpack_blob(buf, off)
        if off + 16 > len(buf):
            raise ValueError("truncated KeyPackage lifetime")
        (nb, na) = struct.unpack_from(">QQ", buf, off)
        off += 16
        if off != len(buf):
            raise ValueError("trailing bytes in KeyPackage")
        mid = _unpack_member_id(raw_mid)
        return cls(member_id=mid, ml_dsa_pub=mldsa, kem_pub=kem,
                   not_before=nb, not_after=na)


@dataclass
class Proposal:
    """Add/Remove/Update proposal (v2). `sig` covers the unsigned encoding."""
    kind: int
    member_id: str
    sig: bytes = b""

    def encode_unsigned(self) -> bytes:
        if self.kind not in (KIND_ADD, KIND_REMOVE, KIND_UPDATE):
            raise ValueError("unknown proposal kind")
        return (MAGIC_PROPOSAL + struct.pack(">H", VERSION)
                + struct.pack("B", self.kind)
                + _pack_member_id(self.member_id))

    def encode(self) -> bytes:
        return self.encode_unsigned() + _pack_blob(bytes(self.sig))

    @classmethod
    def decode(cls, buf: bytes) -> "Proposal":
        try:
            return cls._decode_inner(bytes(buf))
        except struct.error as exc:
            raise ValueError(f"truncated Proposal: {exc}") from exc

    @classmethod
    def _decode_inner(cls, buf: bytes) -> "Proposal":
        if buf[:5] != MAGIC_PROPOSAL:
            raise ValueError("bad Proposal magic")
        (ver,) = struct.unpack_from(">H", buf, 5)
        if ver != VERSION:
            raise ValueError(f"unsupported Proposal version {ver}")
        # B101-hardening (fuzz-found 2026-09-23): direct buf[7] indexing
        # raised bare IndexError on truncated input; length-gate first so
        # decoders fail ONLY with ValueError, unconditionally.
        if len(buf) < 8:
            raise ValueError("truncated Proposal kind byte")
        kind = buf[7]
        if kind not in (KIND_ADD, KIND_REMOVE, KIND_UPDATE):
            raise ValueError("unknown proposal kind")
        raw_mid, off = _unpack_blob(buf, 8)
        sig, off = _unpack_blob(buf, off)
        if off != len(buf):
            raise ValueError("trailing bytes in Proposal")
        mid = _unpack_member_id(raw_mid)
        return cls(kind=kind, member_id=mid, sig=sig)


def transcript_update(prev_tx: bytes, proposals: List[Proposal], epoch: int,
                      extra: bytes = b"") -> bytes:
    """Chain the epoch transcript: SHA3-512(prev || canonical || extra || epoch).

    ``extra`` carries the Commit's suite annotation (v2); ``h.update(b"")``
    is digest-neutral, so legacy empty commits hash exactly as before.
    """
    if not isinstance(prev_tx, (bytes, bytearray)) or not prev_tx:
        raise ValueError("prev transcript must be non-empty bytes")
    if not isinstance(epoch, int) or epoch < 0:
        raise ValueError("epoch must be a non-negative int")
    if not isinstance(extra, (bytes, bytearray)):
        raise TypeError("extra must be bytes")
    h = hashlib.sha3_512()
    h.update(bytes(prev_tx))
    for p in proposals:
        if not isinstance(p, Proposal):
            raise TypeError("proposals must be Proposal")
        h.update(p.encode())
    h.update(bytes(extra))
    h.update(epoch.to_bytes(8, "big"))
    return h.digest()


def encode_suite_annotation(suite_id: str) -> bytes:
    """Encode a suite id into the Commit new_tx_input blob (v2)."""
    if not suite_id:
        return b""
    raw = suite_id.encode("utf-8")
    if len(raw) > SUITE_ID_MAX_LEN:
        raise ValueError("suite id too long")
    if suite_id not in KNOWN_SUITES:
        raise ValueError(f"unknown PQ suite {suite_id!r}")
    return _SUITE_WIRE_PREFIX + raw


def decode_suite_annotation(blob: bytes) -> str:
    """Parse the Commit new_tx_input blob back to a suite id ("" = legacy)."""
    if not blob:
        return ""
    if not blob.startswith(_SUITE_WIRE_PREFIX):
        raise ValueError("unrecognized Commit new_tx_input annotation")
    suite_id = bytes(blob[len(_SUITE_WIRE_PREFIX):]).decode("utf-8")
    if suite_id not in KNOWN_SUITES:
        raise ValueError(f"unknown PQ suite {suite_id!r}")
    return suite_id


@dataclass
class Commit:
    """Commit binding proposals + suite annotation + epoch to the transcript (v2).

    ``suite_id`` is the PQ ciphersuite annotation ("" = legacy/unspecified).
    ``new_tx_input`` on the wire is the encoded annotation; the transcript
    binds it, so a suite-downgrade fork is a transcript fork.
    """
    epoch: int
    prev_tx: bytes = b""
    proposals: List[Proposal] = field(default_factory=list)
    suite_id: str = ""

    def encode(self) -> bytes:
        if not isinstance(self.epoch, int) or self.epoch < 0:
            raise ValueError("epoch must be a non-negative int")
        annotation = encode_suite_annotation(self.suite_id)
        out = (MAGIC_COMMIT + struct.pack(">H", VERSION)
               + struct.pack(">Q", self.epoch)
               + _pack_blob(bytes(self.prev_tx)))
        if len(self.proposals) > 0xFFFF:
            raise ValueError("too many proposals")
        out += struct.pack(">H", len(self.proposals))
        for p in self.proposals:
            out += _pack_blob(p.encode())
        out += _pack_blob(annotation)
        return out

    @classmethod
    def decode(cls, buf: bytes) -> "Commit":
        try:
            return cls._decode_inner(bytes(buf))
        except struct.error as exc:
            raise ValueError(f"truncated Commit: {exc}") from exc

    @classmethod
    def _decode_inner(cls, buf: bytes) -> "Commit":
        if buf[:5] != MAGIC_COMMIT:
            raise ValueError("bad Commit magic")
        (ver,) = struct.unpack_from(">H", buf, 5)
        if ver != VERSION:
            raise ValueError(f"unsupported Commit version {ver}")
        (epoch,) = struct.unpack_from(">Q", buf, 7)
        prev_tx, off = _unpack_blob(buf, 15)
        (n,) = struct.unpack_from(">H", buf, off)
        off += 2
        props: List[Proposal] = []
        for _ in range(n):
            raw, off = _unpack_blob(buf, off)
            props.append(Proposal.decode(raw))
        annotation, off = _unpack_blob(buf, off)
        if off != len(buf):
            raise ValueError("trailing bytes in Commit")
        return cls(epoch=epoch, prev_tx=prev_tx, proposals=props,
                   suite_id=decode_suite_annotation(bytes(annotation)))

    def new_transcript(self) -> bytes:
        """Transcript after applying this commit (binds suite annotation)."""
        return transcript_update(self.prev_tx, self.proposals, self.epoch,
                                 encode_suite_annotation(self.suite_id))


def verify_proposal_sig(proposal: Proposal, ml_dsa_pub: bytes,
                        verify_cb: Optional[Callable[[bytes, bytes, bytes], bool]] = None) -> bool:
    """Verify a proposal's ML-DSA signature.

    Without ``verify_cb`` returns False for signed proposals (fail-closed:
    callers must authenticate membership over pairwise channels instead)
    and False for unsigned ones alike — i.e. no signature, no trust.
    ``verify_cb`` receives (pub, unsigned_bytes, sig) and must be a
    constant-time-safe verifier (e.g. liboqs ML-DSA-87).
    """
    if not proposal.sig:
        return False
    if verify_cb is None or not ml_dsa_pub:
        return False
    try:
        return bool(verify_cb(bytes(ml_dsa_pub), proposal.encode_unsigned(), bytes(proposal.sig)))
    except Exception:
        return False
