#!/usr/bin/env python3
"""
secure_transmit_2027.py — Most-secure practical transmission over the public internet (2027).

Architecture (finalized from 2026 research, no demos/simulation — all primitives real):

  Outer:  TLS 1.3 ONLY, mutual auth, single suite TLS_AES_256_GCM_SHA384 (CNSA 2.0 profile).
  Inner:  Hybrid PQ key exchange SecP384r1 + ML-KEM-1024 per RFC 10024 (Aug 2026),
          HKDF-SHA384 combiner per SP 800-56Cr2 / SP 800-227, ML-DSA-87
          transcript signatures per FIPS 204, AES-256-GCM records, fresh
          ephemeral rekey (HNDL quantum-cost axis), anti-replay bitmap,
          fixed padding quanta, TOFU safety numbers.

Research grounding (verified Sept 2026 via live fetch):
  [FIPS203/204/205] NIST finalized ML-KEM / ML-DSA / SLH-DSA 13 Aug 2024.
  [CNSA2.0] NSA CNSA Suite 2.0: ML-KEM-1024 + ML-DSA-87 + AES-256 + SHA-384/512;
    NIAP PL-33: CNSA 1.0 mandatory 2027-01-01, CNSA 2.0 mandatory 2028-01-01;
    new NSS acquisitions support CNSA 2.0 from 2027-01-01.
  [RFC10024] Aug 2026: X25519MLKEM768 (0x11EC), SecP256r1MLKEM768 (0x11EB),
    SecP384r1MLKEM1024 (0x11ED); concatenation combiner; for SecP384r1MLKEM1024
    secret = ECDHE(48B) || ML-KEM(32B) = 80B; X25519MLKEM768 secret =
    ML-KEM(32B) || X25519(32B) = 64B (order frozen for FIPS reasons).
  [OpenSSL3.5] Defaults to hybrid X25519MLKEM768; supports ML-KEM/ML-DSA/SLH-DSA.
  [CNSA-TLS] draft-becker-cnsa2-tls-profile: TLS 1.3 only, 0x1302 first/only,
    ML-KEM-1024, ML-DSA-87, SHA-384 HKDF, mutual cert auth, psk_dhe_ke only.
  [RFC9849] ECH (Mar 2026) + draft-ietf-uta-pqc-app: ECH/HPKE MUST use pure-PQ or
    PQ/T hybrid KEM to resist HNDL; deploy with encrypted DNS.
  [HNDL-econ] arXiv 2603.01091 (Mar 2026): storage is trivial; defense axes are
    (a) ECH triage degradation, (b) quantum-workload inflation via frequent
    fresh-entropy rekey (E = ceil(bytes/rekey_interval)) and larger KEX params;
    TLS 1.3 KeyUpdate is deterministic (E=1) — real FS needs fresh ephemeral
    exchange or PSK-DHE resumption; deprecate RSA/0-RTT/non-FS modes.
  [MLS-PQ] draft-ietf-mls-pq-ciphersuites (Jul 2026): ML-KEM hybrid suites at
    192/256-bit use AES-256-GCM + HKDF-SHA384; full-PQ needs ML-DSA too.

Threat model addressed: HNDL bulk harvest, active MITM (classical + future CRQC),
downgrade/strip, replay/reorder, traffic analysis, memory disclosure, supply chain.

Fail-closed everywhere: any length/signature/tag/transcript/timestamp failure
aborts with SecurityError, no weaker retry, no oracle strings.

All crypto is REAL: liboqs (oqs.dll, Ed25519-verified at import) for ML-KEM-1024
(FIPS 203) + ML-DSA-87 (FIPS 204); `cryptography` (OpenSSL 3.5.7) for P-384,
X25519, AES-256-GCM, HKDF-SHA384; os.urandom/secrets for entropy.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

log = logging.getLogger("secure_transmit_2027")

# ---------------------------------------------------------------------------
# Fail-closed errors (generic messages on the wire; detail only in local log)
# ---------------------------------------------------------------------------

class SecurityError(Exception):
    """Generic fail-closed security failure. Never leaks which check failed."""


# ---------------------------------------------------------------------------
# Strict policy constants (CNSA 2.0 / RFC 10024 L5 path)
# ---------------------------------------------------------------------------

PROTOCOL_VERSION: bytes = b"ST2027V1"
TLS_MIN = ssl.TLSVersion.TLSv1_3
TLS_MAX = ssl.TLSVersion.TLSv1_3
# IANA 0x1302 — the ONLY allowed outer suite (CNSA profile).
ALLOWED_CIPHER = "TLS_AES_256_GCM_SHA384"
HASH_ALG = "SHA384"          # HKDF + transcript hash family
SYMMETRIC = "AES-256-GCM"    # 256-bit keys only (PQ margin: Grover halves)
KEM_NAME = "SecP384r1MLKEM1024"  # RFC 10024 L5 path (NOT X25519MLKEM768/Cat-3)
SIG_NAME = "ML-DSA-87"       # CNSA-required identity (FIPS 204)

# FIPS 203 sizes (pinned — never negotiated).
MLKEM1024_PK = 1568
MLKEM1024_CT = 1568
MLKEM1024_SS = 32
P384_SHARE = 97              # uncompressed 0x04 || X(48) || Y(48)
P384_SS = 48                 # x-coordinate octet string
HYBRID_SS = P384_SS + MLKEM1024_SS  # 80 bytes, ECDHE FIRST per RFC 10024 s5
CLIENT_SHARE_LEN = P384_SHARE + MLKEM1024_PK   # 1665
SERVER_SHARE_LEN = P384_SHARE + MLKEM1024_CT   # 1665

HANDSHAKE_MAX_AGE_S = 60     # replay window for handshake timestamps
SESSION_REKEY_BYTES = 1 << 20       # 1 MiB — fresh ephemeral KEX (HNDL E-axis)
SESSION_REKEY_SECONDS = 15 * 60     # 15 min cap even if idle-ish
MAX_RECORD_PLAINTEXT = 16 * 1024    # 16 KiB cap per record (DoS bound)
# Total-wire quanta (header 13B + tag 16B included) — always <= 1280 IPv6 MTU.
PAD_QUANTA = (256, 512, 1232)
FRAME_MAGIC = b"\x53\x54"    # "ST" — typed frame, no comparable plaintext strs
FRAME_TYPE_DATA = 0x01
FRAME_TYPE_REKEY = 0x02
FRAME_TYPE_CHAFF = 0xFF      # heartbeat-as-chaff (indistinguishable-ish)
REPLAY_WINDOW = 64
PIN_DIR = Path.home() / ".secure_p2p" / "pins_2027"


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def _zero(b: bytearray) -> None:
    for i in range(len(b)):
        b[i] = 0


def _compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def _ct_is_zero(buf: bytes) -> bool:
    """Constant-time all-zero check (no early exit on first nonzero byte).

    Rationale: any() short-circuits, leaking the position of the first
    nonzero byte through timing. Padding validity must not leak, so the
    comparison always walks the full buffer. hmac.compare_digest is the
    stdlib constant-time primitive; interpreter-level limits are
    documented (native ts_rt owns comparisons going forward).
    """
    return hmac.compare_digest(bytes(buf), b"\x00" * len(buf))


def _now() -> int:
    return int(time.time())


def _hkdf_sha384(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    # Pinned combiner use: 80B hybrid secret in, 16..64B out (32 = record keys).
    if len(ikm) != HYBRID_SS or not 16 <= length <= 64:
        raise SecurityError("KDF parameter violation")
    hkdf = HKDF(algorithm=hashes.SHA384(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def _transcript(*parts: bytes) -> bytes:
    h = hashlib.sha384()
    h.update(PROTOCOL_VERSION)
    for p in parts:
        h.update(struct.pack(">I", len(p)))
        h.update(p)
    return h.digest()


def _pad_len(n: int) -> int:
    for q in PAD_QUANTA:
        if n <= q:
            return q
    raise SecurityError("record too large")


def identity_pin(local_sig_pk: bytes, remote_sig_pk: bytes) -> str:
    """TOFU identity pin: SHA3-512 over both ML-DSA-87 identity keys, grouped.

    Display out-of-band on first contact; pin; abort on silent change.
    SHA-384/SHA3-512 only (policy forbids 128-bit hashes for identity).
    Ephemeral KEM material is deliberately NOT pinned — it rotates every
    session; identity continuity is what detects MITM.
    """
    if not local_sig_pk or not remote_sig_pk:
        raise SecurityError("identity pin violation")
    d = hashlib.sha3_512(
        b"ST2027-IDENTITY-v1" + local_sig_pk + remote_sig_pk
    ).hexdigest().upper()
    return " ".join(d[i:i + 4] for i in range(0, 64, 4))


def safety_number(local_sig_pk: bytes, remote_sig_pk: bytes,
                  local_kem_pk: bytes = b"", remote_kem_pk: bytes = b"") -> str:
    """Back-compat alias: v1 pins identities only; KEM args must be empty."""
    if local_kem_pk or remote_kem_pk:
        raise SecurityError("kem pinning removed — identities only in v1")
    return identity_pin(local_sig_pk, remote_sig_pk)


def _pin_path(peer_id: str) -> Path:
    safe = "".join(c for c in peer_id if c.isalnum() or c in ("-", "_"))[:64]
    if not safe:
        raise SecurityError("peer id violation")
    return PIN_DIR / (safe + ".pin")


def check_pin(peer_id: str, safety: str) -> None:
    """TOFU pin check. First contact stores; later mismatch aborts (OOB re-verify)."""
    PIN_DIR.mkdir(parents=True, exist_ok=True)
    p = _pin_path(peer_id)
    if not p.exists():
        p.write_text(safety, encoding="ascii")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        log.warning("TOFU: pinned new peer %s — VERIFY OOB: %s", peer_id, safety)
        return
    pinned = p.read_text(encoding="ascii").strip()
    if not _compare(pinned.encode(), safety.encode()):
        raise SecurityError("peer identity changed — abort; re-verify out-of-band")


# ---------------------------------------------------------------------------
# Real hybrid KEX: P-384 (cryptography/OpenSSL) + ML-KEM-1024 (liboqs)
# ---------------------------------------------------------------------------

@dataclass
class HybridKeyPair:
    p384_private: object          # ec.EllipticCurvePrivateKey (opaque handle)
    p384_public_bytes: bytes      # 97B uncompressed
    mlkem_pk: bytes               # 1568B
    mlkem_sk: bytes               # 3168B (liboqs)
    sig_pk: bytes                 # ML-DSA-87 pk (identity, long-term)
    sig_sk: bytes                 # ML-DSA-87 sk


def generate_hybrid_keypair(sig_pk: bytes = b"", sig_sk: bytes = b"") -> HybridKeyPair:
    from cryptography.hazmat.primitives.asymmetric import ec
    from liboqs_wrapper import LibOQS_MLKEM_1024
    priv = ec.generate_private_key(ec.SECP384R1())
    pub = priv.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.X962,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.UncompressedPoint,
    )
    if len(pub) != P384_SHARE:
        raise SecurityError("P-384 encoding violation")
    kem = LibOQS_MLKEM_1024()
    ml_pk, ml_sk = kem.keygen()
    if len(ml_pk) != MLKEM1024_PK:
        raise SecurityError("ML-KEM-1024 size violation")
    return HybridKeyPair(priv, pub, ml_pk, ml_sk, sig_pk, sig_sk)


def generate_identity() -> Tuple[bytes, bytes]:
    """Long-term ML-DSA-87 identity (FIPS 204, CNSA-required). Store in HSM/TPM."""
    from liboqs_wrapper import LibOQS_MLDSA_87
    pk, sk = LibOQS_MLDSA_87().keygen()
    return pk, sk


def hybrid_combine(ecdhe_secret: bytes, mlkem_secret: bytes) -> bytes:
    """RFC 10024 SecP384r1MLKEM1024 combiner: ECDHE(48B) || ML-KEM(32B) = 80B.

    Order is load-bearing for FIPS (SP 800-56Cr2: first secret must come from
    the certified implementation — here P-384). Both orders are equally secure
    cryptographically; the wire/combiner order is frozen by deployment.

    This concatenation is the INPUT to the dual-PRF stage, not the session
    key itself: HKDF-Extract(salt = SHA-384(transcripts incl. ML-KEM ek/ct,
    P-384 shares, sigs, timestamps), IKM = this 80B) then HKDF-Expand(info).
    That matches the dualPRF[KEM1,KEM2] shape of Bindel et al. (PQCrypto'19:
    dPRF = extract, PRF = expand with CIPHERTEXTS bound in the label — here
    via the transcript salt), whose robustness needs a dual-PRF. HKDF-as-
    dual-PRF is an ASSUMPTION shared with TLS 1.3/MLS/Noise-PQ (not a
    theorem: eprint 2022/065; sufficient fixed-length-input conditions in
    the HMAC dual-PRF analysis). Stated as assumption, not fact.
    """
    if len(ecdhe_secret) != P384_SS or len(mlkem_secret) != MLKEM1024_SS:
        raise SecurityError("combiner size violation")
    out = ecdhe_secret + mlkem_secret
    if len(out) != HYBRID_SS:
        raise SecurityError("combiner violation")
    return out


def sign_transcript(sig_sk: bytes, transcript: bytes) -> bytes:
    from liboqs_wrapper import LibOQS_MLDSA_87
    return LibOQS_MLDSA_87().sign(sig_sk, transcript)


def verify_transcript(sig_pk: bytes, transcript: bytes, sig: bytes) -> None:
    from liboqs_wrapper import LibOQS_MLDSA_87
    ok = LibOQS_MLDSA_87().verify(sig_pk, transcript, sig)
    if not ok:
        raise SecurityError("handshake authentication failed")


# ---------------------------------------------------------------------------
# Handshake messages (verify-before-decaps, timestamps, transcript binding)
# ---------------------------------------------------------------------------

@dataclass
class HandshakeState:
    role: str
    peer_id: str
    session_salt: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    _secure: Optional[SecureBytes] = field(default=None, repr=False)
    created: int = field(default_factory=_now)
    bytes_under_key: int = 0

    def key(self) -> bytes:
        # Short-lived copy, used inside the AEAD call only; never retained.
        if self._secure is None:
            raise SecurityError("no session")
        return self._secure.use()

    def destroy(self) -> None:
        if self._secure is not None:
            self._secure.destroy()
            self._secure = None


@dataclass
class ClientEphemeral:
    """Per-handshake ephemeral secrets. Destroy after client_finish."""
    p384_priv: object
    mlkem_sk: bytearray
    mlkem_pk: bytes

    def destroy(self) -> None:
        try:
            _zero(self.mlkem_sk)
        except Exception:
            pass
        self.mlkem_sk = bytearray()


def _sign_for(kp: HybridKeyPair | IdentityHandle, transcript: bytes) -> Tuple[bytes, bytes]:
    """Return (sig_pk, sig) for a software keypair or hardware IdentityHandle.

    This is what actually routes handshake authentication through the HSM
    path when the identity is held in hardware (H1); raw sig_sk material is
    never extracted from the handle.
    """
    if isinstance(kp, HybridKeyPair):
        return kp.sig_pk, sign_transcript(kp.sig_sk, transcript)
    return kp.sig_pk, sign_with_identity(kp, transcript)


def _assert_session_profile() -> None:
    """Runtime CNSA 2.0 policy: the negotiated profile names must be in the
    strict allow sets. Guards against future edits silently widening the
    profile (the static scanner guards the code; this guards the values)."""
    from cnsa_purity import (assert_cnsa_group, assert_cnsa_hash,
                             assert_cnsa_kdf, assert_cnsa_sig, assert_cnsa_suite)
    assert_cnsa_group(KEM_NAME)        # SecP384r1MLKEM1024 (RFC 10024 L5)
    assert_cnsa_sig(SIG_NAME)          # ML-DSA-87 (FIPS 204)
    assert_cnsa_suite(ALLOWED_CIPHER)  # TLS_AES_256_GCM_SHA384
    assert_cnsa_suite(SYMMETRIC)       # AES-256-GCM
    assert_cnsa_hash(HASH_ALG)         # SHA384
    assert_cnsa_kdf("HKDF-SHA384")


def build_client_hello(kp: HybridKeyPair | IdentityHandle, peer_id: str) -> Tuple[bytes, bytes, ClientEphemeral, int]:
    """Returns (wire_msg, transcript_pre, ephemeral, t). Server verifies BEFORE decaps.

    v1 forward secrecy: BOTH components are ephemeral — fresh P-384 AND fresh
    ML-KEM-1024 ek per handshake. Long-term kp.mlkem_* is NOT used on the wire
    (reserved for future KEM-auth); identity is kp.sig_* (ML-DSA-87).
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from liboqs_wrapper import LibOQS_MLKEM_1024
    _assert_session_profile()
    eph = ec.generate_private_key(ec.SECP384R1())
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    eph_ml_pk, eph_ml_sk_raw = LibOQS_MLKEM_1024().keygen()
    # liboqs returns immutable bytes (one unavoidable copy); move into a
    # mutable bytearray immediately and drop the reference so only the
    # wipeable copy survives. The original is GC-collected (see H6 limits).
    eph_ml_sk = bytearray(eph_ml_sk_raw)
    del eph_ml_sk_raw
    if len(eph_pub) != P384_SHARE or len(eph_ml_pk) != MLKEM1024_PK:
        raise SecurityError("ephemeral encoding violation")
    t = _now()
    # wire: ver(8) || t(8) || eph_p384(97) || eph_ml_ek(1568) || sig_pk(len+val) || sig(len+val)
    tr = _transcript(b"CH", eph_pub, eph_ml_pk, struct.pack(">Q", t), peer_id.encode())
    sig_pk, sig = _sign_for(kp, tr)
    msg = (PROTOCOL_VERSION + struct.pack(">Q", t) + eph_pub + eph_ml_pk
           + struct.pack(">H", len(sig_pk)) + sig_pk
           + struct.pack(">H", len(sig)) + sig)
    return msg, tr, ClientEphemeral(eph, eph_ml_sk, eph_ml_pk), t


def server_accept(msg: bytes, server_kp: HybridKeyPair | IdentityHandle, peer_id: str,
                  peer_cert: Optional[str] = None,
                  peer_subject: Optional[str] = None) -> Tuple[bytes, HandshakeState]:
    """Verify client hello (sig+timestamp+transcript) BEFORE decaps. Silent abort."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from liboqs_wrapper import LibOQS_MLKEM_1024
    _assert_session_profile()
    try:
        off = 0
        if msg[off:off + 8] != PROTOCOL_VERSION:
            raise SecurityError("version")
        off += 8
        (t,) = struct.unpack(">Q", msg[off:off + 8]); off += 8
        if abs(_now() - t) > HANDSHAKE_MAX_AGE_S:
            raise SecurityError("stale")
        eph_cli = msg[off:off + P384_SHARE]; off += P384_SHARE
        ml_ek_cli = msg[off:off + MLKEM1024_PK]; off += MLKEM1024_PK
        (lpk,) = struct.unpack(">H", msg[off:off + 2]); off += 2
        if lpk == 0 or lpk > 5000 or len(msg) < off + lpk + 2:
            raise SecurityError("size")
        cli_sig_pk = msg[off:off + lpk]; off += lpk
        (lsig,) = struct.unpack(">H", msg[off:off + 2]); off += 2
        cli_sig = msg[off:off + lsig]; off += lsig
        if off != len(msg):
            raise SecurityError("trailing")
        tr = _transcript(b"CH", eph_cli, ml_ek_cli, struct.pack(">Q", t), peer_id.encode())
        verify_transcript(cli_sig_pk, tr, cli_sig)   # <-- verify BEFORE decaps
        if len(ml_ek_cli) != MLKEM1024_PK or len(eph_cli) != P384_SHARE:
            raise SecurityError("peer share violation")
        # Fresh server ephemeral P-384 for this session (not the long-term kp key).
        eph_srv = ec.generate_private_key(ec.SECP384R1())
        eph_srv_pub = eph_srv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), eph_cli)
        ecdhe = eph_srv.exchange(ec.ECDH(), peer_pub)
        ml_ct, ml_ss = LibOQS_MLKEM_1024().encaps(ml_ek_cli)
        hybrid = hybrid_combine(ecdhe, ml_ss)
        ts = _now()
        tr2 = _transcript(b"SH", tr, eph_srv_pub, ml_ct, struct.pack(">Q", ts))
        srv_sig_pk, sig2 = _sign_for(server_kp, tr2)
        st = HandshakeState(role="server", peer_id=peer_id)
        salt = hashlib.sha384(PROTOCOL_VERSION + b"v1-hkdf" + tr + tr2).digest()[:32]
        okm = _hkdf_sha384(hybrid, salt, b"ST2027-record-v1", 32)
        st._secure = SecureBytes(okm)
        st.created = ts
        # Identity continuity: strict PKI binding (no TOFU) when required,
        # memory TOFU when ephemeral, file TOFU in the lab only. Ephemeral
        # KEM material always rotates and is never pinned.
        try:
            from trust_anchor import ephemeral_required as _eph_req
            from trust_anchor import pki_required as _pki_req
            _need_pki = bool(_pki_req())
            _need_eph = bool(_eph_req())
        except Exception:
            _need_pki, _need_eph = False, False
        if _need_pki:
            from trust_anchor import require_cert_for_remote as _cert_gate
            _cert_gate(cli_sig_pk, peer_cert,
                       peer_subject if peer_subject else peer_id)
        elif _need_eph:
            from trust_anchor import verify_peer_identity as _vpi

            _vpi("srv:" + peer_id, srv_sig_pk, cli_sig_pk)
        else:
            check_pin("srv:" + peer_id, identity_pin(srv_sig_pk, cli_sig_pk))
        resp = (PROTOCOL_VERSION + struct.pack(">Q", ts) + eph_srv_pub + ml_ct
                + struct.pack(">H", len(srv_sig_pk)) + srv_sig_pk
                + struct.pack(">H", len(sig2)) + sig2)
        audit_event("handshake_server_ok", {"peer": peer_id})
        return resp, st
    except SecurityError:
        try:
            audit_event("handshake_server_reject", {"peer": peer_id})
        except Exception:
            pass
        raise
    except Exception as e:  # fail closed, no oracle
        log.debug("handshake reject: %r", e)
        try:
            audit_event("handshake_server_reject", {"peer": peer_id})
        except Exception:
            pass
        raise SecurityError("handshake rejected")


def client_finish(resp: bytes, cli_eph: ClientEphemeral, cli_kp: HybridKeyPair | IdentityHandle, tr_cli: bytes,
                  peer_id: str, t_cli: int, peer_cert: Optional[str] = None,
                  peer_subject: Optional[str] = None) -> HandshakeState:
    from cryptography.hazmat.primitives.asymmetric import ec
    from liboqs_wrapper import LibOQS_MLKEM_1024
    try:
        off = 0
        if resp[off:off + 8] != PROTOCOL_VERSION:
            raise SecurityError("version")
        off += 8
        (ts,) = struct.unpack(">Q", resp[off:off + 8]); off += 8
        if abs(_now() - ts) > HANDSHAKE_MAX_AGE_S:
            raise SecurityError("stale")
        eph_srv = resp[off:off + P384_SHARE]; off += P384_SHARE
        if len(eph_srv) != P384_SHARE:
            raise SecurityError("peer share violation")
        ml_ct = resp[off:off + MLKEM1024_CT]; off += MLKEM1024_CT
        (lpk,) = struct.unpack(">H", resp[off:off + 2]); off += 2
        if lpk == 0 or lpk > 5000 or len(resp) < off + lpk + 2:
            raise SecurityError("size")
        srv_sig_pk = resp[off:off + lpk]; off += lpk
        (lsig,) = struct.unpack(">H", resp[off:off + 2]); off += 2
        srv_sig = resp[off:off + lsig]; off += lsig
        if off != len(resp):
            raise SecurityError("trailing")
        tr2 = _transcript(b"SH", tr_cli, eph_srv, ml_ct, struct.pack(">Q", ts))
        verify_transcript(srv_sig_pk, tr2, srv_sig)  # verify BEFORE decaps/use
        peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), eph_srv)
        ecdhe = cli_eph.p384_priv.exchange(ec.ECDH(), peer_pub)
        ml_ss = LibOQS_MLKEM_1024().decaps(bytes(cli_eph.mlkem_sk), ml_ct)
        hybrid = hybrid_combine(ecdhe, ml_ss)
        st = HandshakeState(role="client", peer_id=peer_id)
        salt = hashlib.sha384(PROTOCOL_VERSION + b"v1-hkdf" + tr_cli + tr2).digest()[:32]
        okm = _hkdf_sha384(hybrid, salt, b"ST2027-record-v1", 32)
        st._secure = SecureBytes(okm)
        # TOFU pins long-term ML-DSA-87 identities (ephemeral KEM rotates always).
        cli_sig_pk = cli_kp.sig_pk  # same attribute on HybridKeyPair and IdentityHandle
        try:
            from trust_anchor import ephemeral_required as _eph_req_c
            from trust_anchor import pki_required as _pki_req_c
            _need_pki_c = bool(_pki_req_c())
            _need_eph_c = bool(_eph_req_c())
        except Exception:
            _need_pki_c, _need_eph_c = False, False
        if _need_pki_c:
            from trust_anchor import require_cert_for_remote as _cert_gate_c
            _cert_gate_c(srv_sig_pk, peer_cert,
                         peer_subject if peer_subject else peer_id)
        elif _need_eph_c:
            from trust_anchor import verify_peer_identity as _vpi_c

            _vpi_c("cli:" + peer_id, cli_sig_pk, srv_sig_pk)
        else:
            check_pin("cli:" + peer_id, identity_pin(cli_sig_pk, srv_sig_pk))
        _ = t_cli
        audit_event("handshake_client_ok", {"peer": peer_id})
        return st
    except SecurityError:
        try:
            audit_event("handshake_client_reject", {"peer": peer_id})
        except Exception:
            pass
        raise
    except Exception as e:
        log.debug("handshake finish reject: %r", e)
        try:
            audit_event("handshake_client_reject", {"peer": peer_id})
        except Exception:
            pass
        raise SecurityError("handshake rejected")
    finally:
        try:
            cli_eph.destroy()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Record layer: AES-256-GCM, seq bitmap replay, quanta padding, rekey flag
# ---------------------------------------------------------------------------

class ReplayWindow:
    def __init__(self) -> None:
        self.base: int = 0
        self.bitmap: int = 0  # bit i = seen(base+i), 64-bit window
        self.started = False

    def check_and_mark(self, seq: int) -> None:
        if seq < 0 or seq >= (1 << 64):
            raise SecurityError("sequence violation")
        if not self.started:
            self.base = seq
            self.bitmap = 1
            self.started = True
            return
        if seq < self.base:
            raise SecurityError("replay rejected")
        off = seq - self.base
        if off < REPLAY_WINDOW:
            if (self.bitmap >> off) & 1:
                raise SecurityError("replay rejected")
            self.bitmap |= (1 << off)
            return
        # slide window
        shift = off - (REPLAY_WINDOW - 1)
        if shift >= REPLAY_WINDOW:
            self.bitmap = 0
        else:
            self.bitmap >>= shift
        self.base += shift
        self.bitmap |= (1 << (REPLAY_WINDOW - 1))


@dataclass
class Channel:
    state: HandshakeState
    send_seq: int = field(default_factory=lambda: secrets.randbits(64))
    recv_win: ReplayWindow = field(default_factory=ReplayWindow)
    direction_out: int = 0xA5
    direction_in: int = 0x5A

    def needs_rekey(self) -> bool:
        age = _now() - self.state.created
        return (self.state.bytes_under_key >= SESSION_REKEY_BYTES
                or age >= SESSION_REKEY_SECONDS)

    def _nonce(self, seq: int, direction: int) -> bytes:
        # 12B GCM nonce = seq(8BE) || dir(1) || zero(3); monotonic, never reuse
        # under same key (seq random-start + strictly increasing).
        return struct.pack(">Q", seq) + bytes([direction]) + b"\x00\x00\x00"

    def seal(self, plaintext: bytes, ftype: int = FRAME_TYPE_DATA) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if len(plaintext) > MAX_RECORD_PLAINTEXT:
            raise SecurityError("record too large")
        if ftype not in (FRAME_TYPE_DATA, FRAME_TYPE_REKEY, FRAME_TYPE_CHAFF):
            raise SecurityError("frame type violation")
        seq = (self.send_seq + 1) % (1 << 64)
        self.send_seq = seq
        body = bytes([ftype]) + plaintext
        wire_len = 2 + 8 + 2 + len(body) + 16  # magic+seq+len+body+tag
        total = _pad_len(wire_len)
        pad = total - wire_len
        frame = FRAME_MAGIC + struct.pack(">Q", seq) + struct.pack(">H", len(body) + pad) + body + b"\x00" * pad
        aad = frame[:12]  # magic||seq||len bound into tag (header auth)
        ct = AESGCM(self.state.key()).encrypt(self._nonce(seq, self.direction_out), frame[12:], aad)
        self.state.bytes_under_key += len(ct)
        return frame[:12] + ct

    def open(self, wire: bytes) -> Tuple[int, bytes]:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if len(wire) < 12 + 1 + 16 or len(wire) not in PAD_QUANTA:
            raise SecurityError("framing violation")
        if wire[:2] != FRAME_MAGIC:
            raise SecurityError("framing violation")
        seq = struct.unpack(">Q", wire[2:10])[0]
        (hlen,) = struct.unpack(">H", wire[10:12])
        # header len must equal encrypted payload length (body+pad); binds
        # padding length into AAD so truncation/extension fails closed.
        if hlen != len(wire) - 12 - 16:
            raise SecurityError("framing violation")
        self.recv_win.check_and_mark(seq)  # silent replay drop (no oracle)
        aad = wire[:12]
        try:
            pt = AESGCM(self.state.key()).decrypt(
                self._nonce(seq, self.direction_in), wire[12:], aad)
        except Exception:
            raise SecurityError("authentication failed")
        # pt == body + zero-pad, where body == ftype(1) || plaintext
        if len(pt) < 1 or len(pt) != hlen:
            raise SecurityError("framing violation")
        ftype = pt[0]
        payload = pt[1:]
        # DATA frames carry a 2B inner length prefix so trailing-zero
        # ambiguity is impossible: msg = payload[2:2+mlen], tail must be zero.
        if ftype == FRAME_TYPE_DATA:
            if len(payload) < 2:
                raise SecurityError("framing violation")
            (mlen,) = struct.unpack(">H", payload[:2])
            msg = payload[2:2 + mlen]
            tail = payload[2 + mlen:]
            if len(msg) != mlen or not _ct_is_zero(tail):
                raise SecurityError("framing violation")
            return ftype, msg
        if ftype in (FRAME_TYPE_REKEY, FRAME_TYPE_CHAFF):
            # control frames: remainder after ftype must be all zero pad
            if not _ct_is_zero(payload):
                raise SecurityError("framing violation")
            return ftype, b""
        raise SecurityError("frame type violation")

    def seal_data(self, msg: bytes) -> bytes:
        if len(msg) + 2 > MAX_RECORD_PLAINTEXT:
            raise SecurityError("record too large")
        return self.seal(struct.pack(">H", len(msg)) + msg, FRAME_TYPE_DATA)

    def seal_chaff(self) -> bytes:
        return self.seal(b"", FRAME_TYPE_CHAFF)


# ---------------------------------------------------------------------------
# Outer TLS 1.3 (mutual, CNSA profile) — double envelope: TLS || inner AEAD
# ---------------------------------------------------------------------------

def _pin_tls_suite(ctx: ssl.SSLContext) -> None:
    """Pin the outer TLS 1.3 suite to TLS_AES_256_GCM_SHA384 (CNSA profile).

    Preferred: SSLContext.set_ciphersuites (TLS 1.3 offer list). Some builds
    (incl. this Win64 CPython 3.14) lack it — then the offer cannot be
    constrained and the pin is enforced post-handshake by
    assert_outer_is_pinned() on EVERY connection (fail-closed there: abort +
    close on any mismatch). Refusing to run at all would brick the tool on
    such builds; negotiating-then-verifying keeps the security property
    (no non-pinned session ever carries data) while staying honest about
    the weaker offer ordering — see log warning.
    """
    set_cs = getattr(ctx, "set_ciphersuites", None)
    if callable(set_cs):
        try:
            set_cs(ALLOWED_CIPHER)
            return
        except Exception as e:
            raise SecurityError(f"TLS suite pinning failed: {e}")
    log.warning("set_ciphersuites unavailable — suite pin enforced post-handshake")
    try:
        # Restrict the TLS<=1.2 list as well; harmless for a TLS-1.3-only ctx.
        ctx.set_ciphers("AES256-GCM-SHA384")
    except Exception as e:
        raise SecurityError(f"TLS cipher pinning failed: {e}")


def make_server_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = TLS_MIN
    ctx.maximum_version = TLS_MAX
    _pin_tls_suite(ctx)
    # Prefer hybrid PQC KEM groups; L5 first. Names depend on OpenSSL 3.5.
    for grp in ("SecP384r1MLKEM1024", "X25519MLKEM768", "secp384r1"):
        try:
            ctx.set_ecdh_curve(grp)  # type: ignore[attr-defined]
            break
        except Exception:
            continue
    ctx.load_cert_chain(certfile, keyfile)
    ctx.load_verify_locations(cafile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False
    # No tickets that bypass fresh PQ KEX across resumptions without DHE:
    ctx.options |= getattr(ssl, "OP_NO_TICKET", 0)
    return ctx


def make_client_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = TLS_MIN
    ctx.maximum_version = TLS_MAX
    _pin_tls_suite(ctx)
    for grp in ("SecP384r1MLKEM1024", "X25519MLKEM768", "secp384r1"):
        try:
            ctx.set_ecdh_curve(grp)  # type: ignore[attr-defined]
            break
        except Exception:
            continue
    ctx.load_cert_chain(certfile, keyfile)
    ctx.load_verify_locations(cafile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False
    ctx.options |= getattr(ssl, "OP_NO_TICKET", 0)
    return ctx


def assert_outer_is_pinned(sock: ssl.SSLSocket) -> None:
    ver = sock.version()
    suite = (sock.cipher() or ("?",))[0]
    if ver != "TLSv1.3" or suite != ALLOWED_CIPHER:
        try:
            sock.close()
        finally:
            raise SecurityError(f"outer TLS pin violated: {ver}/{suite}")


# ---------------------------------------------------------------------------
# Minimal framed TCP transport helpers (length-prefixed, strictly bounded)
# ---------------------------------------------------------------------------

_HDR = struct.Struct(">I")
# Handshake messages carry ML-DSA-87 identity keys (2592B) + signatures
# (~4.6KB): worst case 16 + 97 + 1568 + 2 + 2592 + 2 + 4627 = 8904B.
# Cap 16384 bounds DoS while fitting the largest legitimate hello.
HANDSHAKE_CAP = 16384

def _send_msg(s: socket.socket, b: bytes) -> None:
    if len(b) > 65535:
        raise SecurityError("message too large")
    s.sendall(_HDR.pack(len(b)) + b)


def _recv_msg(s: socket.socket, cap: int = 65535, timeout: float = 10.0) -> bytes:
    s.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            raise SecurityError("peer closed")
        hdr += chunk
    (n,) = _HDR.unpack(hdr)
    if n == 0 or n > cap:
        raise SecurityError("framing violation")
    out = bytearray()
    while len(out) < n:
        chunk = s.recv(min(n - len(out), 16384))
        if not chunk:
            raise SecurityError("peer closed")
        out += chunk
    return bytes(out)


# ---------------------------------------------------------------------------
# High-level API: send_bytes / recv_bytes over double envelope + rekey
# ---------------------------------------------------------------------------

def _peer_in_allowlist(peer_ip: str) -> bool:
    """True iff peer_ip is covered by P2P_PEER_PREFIX (production gate)."""
    import ipaddress
    try:
        return ipaddress.ip_address(peer_ip.strip().strip("[]")) in \
            ipaddress.ip_network(require_peer_prefix(), strict=False)
    except (ValueError, SecurityError):
        return False


def server_once(lsock: socket.socket, tls_ctx: ssl.SSLContext,
                server_kp: HybridKeyPair | IdentityHandle, peer_id: str,
                out_path: Optional[Path] = None,
                peer_cert: Optional[str] = None,
                peer_subject: Optional[str] = None) -> Path:
    """Accept one connection, handshake, receive one blob. Returns file path.

    Stream integrity: every chunk is AES-256-GCM authenticated, order is bound
    by the replay window, and a SHA-384 digest trailer (eof=2 frame) defeats
    truncation attacks — the file is written only after the digest verifies.
    """
    try:
        port = lsock.getsockname()[1]
    except OSError:
        raise SecurityError("listener not bound")
    verify_vendored_binaries()
    check_listener_scope(lsock, port)
    conn, peer_addr = lsock.accept()
    try:
        peer_ip = peer_addr[0] if peer_addr else ""
    except (IndexError, TypeError):
        peer_ip = ""
    if (_env_true("P2P_PRODUCTION") or _env_true("P2P_TS_MODE")) \
            and not _peer_in_allowlist(peer_ip):
        try:
            audit_event("peer_prefix_reject", {"peer_ip": peer_ip})
        except Exception:
            pass
        try:
            conn.close()
        except OSError:
            pass
        raise SecurityError("peer not in allow-list")
    st: Optional[HandshakeState] = None
    try:
        with tls_ctx.wrap_socket(conn, server_side=True) as tls:
            assert_outer_is_pinned(tls)
            hello = _recv_msg(tls, cap=HANDSHAKE_CAP)
            resp, st = server_accept(hello, server_kp, peer_id,
                                     peer_cert=peer_cert,
                                     peer_subject=peer_subject)
            _send_msg(tls, resp)
            ch = Channel(st, direction_out=0x5A, direction_in=0xA5)
            chunks: list[bytes] = []
            total = 0
            seen_eof = False
            digest: Optional[bytes] = None
            while True:
                wire = _recv_msg(tls, cap=2048)
                ftype, payload = ch.open(wire)
                if ftype == FRAME_TYPE_CHAFF:
                    continue
                if ftype == FRAME_TYPE_REKEY:
                    # Peer rotated to fresh ephemeral keys; rotate with it.
                    ch = rehandshake(ch, tls, server_kp, peer_id, is_server=True,
                                     peer_cert=peer_cert,
                                     peer_subject=peer_subject)
                    continue
                if ftype == FRAME_TYPE_DATA:
                    # payload = seq(8BE) || eof(1) || chunk|digest
                    if len(payload) < 9:
                        raise SecurityError("payload violation")
                    eof = payload[8]
                    body = payload[9:]
                    if eof == 0:
                        if seen_eof:
                            raise SecurityError("payload violation")
                        total += len(body)
                        if total > 50 * 1024 * 1024:
                            raise SecurityError("transfer too large")
                        chunks.append(body)
                        continue
                    if eof == 1:
                        if seen_eof:
                            raise SecurityError("payload violation")
                        seen_eof = True
                        total += len(body)
                        if total > 50 * 1024 * 1024:
                            raise SecurityError("transfer too large")
                        chunks.append(body)
                        continue
                    if eof == 2:
                        if not seen_eof or digest is not None or len(body) != 48:
                            raise SecurityError("digest violation")
                        digest = body
                        break
                    raise SecurityError("payload violation")
                raise SecurityError("unexpected frame")
            blob = b"".join(chunks)
            if digest is None or not _compare(digest, hashlib.sha384(blob).digest()):
                raise SecurityError("transfer integrity failed")
            dest = out_path or Path(f"received_{_now()}.bin")
            tmp = dest.with_suffix(dest.suffix + ".tmp")
            tmp.write_bytes(blob)
            os.replace(tmp, dest)
            audit_event("transfer_recv_ok", {"peer": peer_id, "bytes": total})
            return dest
    finally:
        try:
            conn.close()
        except OSError:
            pass
        if st is not None:
            st.destroy()


def client_send(host: str, port: int, tls_ctx: ssl.SSLContext,
                cli_kp: HybridKeyPair | IdentityHandle, peer_id: str, data: bytes,
                server_hostname: str = "peer",
                peer_cert: Optional[str] = None,
                peer_subject: Optional[str] = None) -> None:
    """Send one blob with per-chunk AEAD, mid-stream rekey, digest trailer."""
    if len(data) > 50 * 1024 * 1024:
        raise SecurityError("transfer too large")
    lit = _production_preflight(host, server_hostname, port, peer_id)
    st: Optional[HandshakeState] = None
    with socket.create_connection((lit, port), timeout=10) as raw:
        with tls_ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
            assert_outer_is_pinned(tls)
            hello, tr, eph, t = build_client_hello(cli_kp, peer_id)
            _send_msg(tls, hello)
            resp = _recv_msg(tls, cap=HANDSHAKE_CAP)
            st = client_finish(resp, eph, cli_kp, tr, peer_id, t,
                                 peer_cert=peer_cert,
                                 peer_subject=peer_subject)
            ch = Channel(st, direction_out=0xA5, direction_in=0x5A)
            seq_no = 0
            for off in range(0, len(data) or 1, 1024):
                chunk = data[off:off + 1024]
                eof = 1 if off + 1024 >= len(data) else 0
                payload = struct.pack(">Q", seq_no) + bytes([eof]) + chunk
                seq_no += 1
                _send_msg(tls, ch.seal_data(payload))
                if ch.needs_rekey():
                    # Fresh ephemeral hybrid exchange INSIDE the live outer
                    # TLS (HNDL quantum-cost axis E>1); peer mirrors it on
                    # seeing the REKEY frame. Never downgrade to KeyUpdate.
                    _send_msg(tls, ch.seal(b"", FRAME_TYPE_REKEY))
                    ch = rehandshake(ch, tls, cli_kp, peer_id, is_server=False,
                                     peer_cert=peer_cert,
                                     peer_subject=peer_subject)
            digest_frame = struct.pack(">Q", seq_no) + b"\x02" + hashlib.sha384(data).digest()
            _send_msg(tls, ch.seal_data(digest_frame))
            # trailing chaff so size/timing leaks less (caller may add jitter)
            _send_msg(tls, ch.seal_chaff())
            audit_event("transfer_send_ok", {"peer": peer_id, "bytes": len(data)})
    if st is not None:
        st.destroy()


def rehandshake(ch: Channel, tls_sock: socket.socket,
                kp: HybridKeyPair | IdentityHandle, peer_id: str, is_server: bool,
                peer_cert: Optional[str] = None,
                peer_subject: Optional[str] = None) -> Channel:
    """Fresh ephemeral hybrid exchange inside live outer TLS (HNDL E>1)."""
    if is_server:
        hello = _recv_msg(tls_sock, cap=HANDSHAKE_CAP)
        resp, st = server_accept(hello, kp, peer_id + "/r",
                                 peer_cert=peer_cert,
                                 peer_subject=peer_subject)
        _send_msg(tls_sock, resp)
    else:
        hello, tr, eph, t = build_client_hello(kp, peer_id + "/r")
        _send_msg(tls_sock, hello)
        resp = _recv_msg(tls_sock, cap=HANDSHAKE_CAP)
        st = client_finish(resp, eph, kp, tr, peer_id + "/r", t,
                           peer_cert=peer_cert,
                           peer_subject=peer_subject)
    old = ch.state
    new = Channel(st, direction_out=ch.direction_out, direction_in=ch.direction_in)
    new.send_seq = secrets.randbits(64)
    old.destroy()
    audit_event("rehandshake", {"peer": peer_id, "server": is_server})
    return new


# ---------------------------------------------------------------------------
# H1 — Hardware custody for long-term ML-DSA-87 identities (fix residual #1)
# ---------------------------------------------------------------------------
# Policy: production MUST keep sig_sk in HSM/TPM (PKCS#11 / Windows CNG) and
# sign via the hardware path. Software keys are lab-only and fail closed when
# P2P_REQUIRE_HARDWARE_IDENTITY=1 or P2P_PRODUCTION=1.
# Reuses verified implementation: platform_hsm_interface.generate_mldsa_keypair
# + sign_with_mldsa (PKCS#11 CKA_EXTRACTABLE=False / CNG+TPM sealed).

def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def hardware_identity_required() -> bool:
    return _env_true("P2P_REQUIRE_HARDWARE_IDENTITY") or _env_true("P2P_PRODUCTION")


@dataclass
class IdentityHandle:
    """Long-term ML-DSA-87 identity. sig_sk is None when held in hardware."""
    sig_pk: bytes
    sig_sk: Optional[bytes]  # None => non-exportable hardware key
    key_data: Optional[dict]  # opaque HSM reference (key_id/key_name)
    stored_in_hsm: bool
    label: str


def generate_identity_hsm(label: str) -> IdentityHandle:
    """Generate ML-DSA-87 identity preferring hardware custody. Fail-closed.

    Returns IdentityHandle with stored_in_hsm=True on success via
    platform_hsm_interface; falls back to software liboqs ONLY when hardware
    is not required (lab). Production with no hardware raises SecurityError.
    """
    safe = "".join(c for c in label if c.isalnum() or c in ("-", "_"))[:48]
    if not safe:
        raise SecurityError("identity label violation")
    try:
        from platform_hsm_interface import generate_mldsa_keypair
        kd = generate_mldsa_keypair(safe, "87")
    except Exception as e:
        log.debug("hsm mldsa keygen unavailable: %r", e)
        kd = None
    if kd:
        if kd.get("stored_in_hsm"):
            audit_event("identity_hsm_keygen", {"label": safe})
            return IdentityHandle(
                sig_pk=kd["public_key"], sig_sk=None,
                key_data=kd, stored_in_hsm=True, label=safe)
        # HSM path returned software key material (hardware inactive).
        if hardware_identity_required():
            raise SecurityError("hardware identity required — no HSM/TPM active")
        return IdentityHandle(
            sig_pk=kd["public_key"], sig_sk=kd["private_key"],
            key_data=kd, stored_in_hsm=False, label=safe)
    if hardware_identity_required():
        raise SecurityError("hardware identity required — no HSM/TPM active")
    pk, sk = generate_identity()  # lab-only software path (liboqs, real FIPS 204)
    audit_event("identity_software_keygen", {"label": safe})
    return IdentityHandle(sig_pk=pk, sig_sk=sk, key_data=None,
                          stored_in_hsm=False, label=safe)


def sign_with_identity(handle: IdentityHandle, message: bytes) -> bytes:
    """Sign via hardware when held there; otherwise software (lab only)."""
    if len(message) > 8 * 1024 * 1024:
        raise SecurityError("sign message too large")
    if handle.stored_in_hsm:
        try:
            from platform_hsm_interface import sign_with_mldsa
            sig = sign_with_mldsa(handle.key_data, message)
        except Exception as e:
            log.debug("hsm sign failed: %r", e)
            sig = None
        if not sig:
            raise SecurityError("hardware sign failed")
        return sig
    if handle.sig_sk is None:
        raise SecurityError("no signing key available")
    if hardware_identity_required():
        # Should be unreachable: software handle must never exist in prod.
        raise SecurityError("hardware identity required — software key refused")
    return sign_transcript(handle.sig_sk, message)


# ---------------------------------------------------------------------------
# H2 — Encrypted DNS + ECH/anonymity prerequisites (fix residual #2)
# ---------------------------------------------------------------------------
# Python stdlib ssl has no ECH sender yet; the production-grade fix is
# enforcement, not custom crypto: (a) never leak a sensitive hostname in
# cleartext SNI/DNS — require literal IP or DoH-resolved mapping; (b) pin a
# generic outer SNI; (c) require CDN/anycast coalescence for anonymity sets
# per RFC 9849 deployment guidance; (d) refuse to start when ECH-capable
# transport is required but absent (P2P_REQUIRE_ECH=1).

def resolve_peer_literal(host: str) -> str:
    """Return literal IP for peer; refuse plaintext-DNS hostnames in prod.

    Set P2P_PEER_IP to the peer's literal IPv6/IPv4 address, or
    P2P_DOH_MAPPING to '<host>=<ip>' entries resolved over DoH out-of-band.
    Hostnames without a mapping fail closed when P2P_PRODUCTION=1.
    """
    import ipaddress
    host = host.strip().strip("[]")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    mapping = os.environ.get("P2P_DOH_MAPPING", "")
    for item in mapping.split(","):
        if "=" in item:
            name, ip = item.split("=", 1)
            if name.strip().lower() == host.lower():
                try:
                    ipaddress.ip_address(ip.strip().strip("[]"))
                    return ip.strip().strip("[]")
                except ValueError:
                    break
    if _env_true("P2P_PRODUCTION") and not _env_true("P2P_ALLOW_PLAINTEXT_DNS"):
        raise SecurityError("peer hostname requires DoH mapping (P2P_DOH_MAPPING)")
    return host  # lab only


def enforce_ech_prerequisites(peer_host: str, outer_sni: str, peer_id: str = "") -> None:
    """Fail closed if SNI/DNS would leak identity or ECH is required+absent.

    - outer_sni must be a generic infrastructural name: it must not equal the
      peer host and must not embed the peer_id (no identity in cleartext SNI).
    - peer_host should be a literal IP (or DoH-mapped); sensitive hostnames
      in cleartext SNI are refused in production.
    - if P2P_REQUIRE_ECH=1, require an ECH-capable stack (ssl HAS_ECH marker
      or P2P_ECH_CONFIG present); CPython has no ECH sender yet so this
      correctly blocks claiming ECH protection that isn't there.
    """
    import ipaddress
    sni = (outer_sni or "").strip().lower()
    if not sni or len(sni) > 253 or any(c in sni for c in ("_", " ", "/")):
        raise SecurityError("outer SNI violation")
    pid = (peer_id or "").strip().lower()
    if pid and len(pid) >= 3 and pid in sni:
        raise SecurityError("outer SNI must not embed peer identity")
    if sni == peer_host.strip().strip("[]").lower():
        raise SecurityError("outer SNI must be generic, not the peer host")
    try:
        ipaddress.ip_address(peer_host.strip().strip("[]"))
        is_literal = True
    except ValueError:
        is_literal = False
    if _env_true("P2P_PRODUCTION") and not is_literal \
            and not _env_true("P2P_ALLOW_PLAINTEXT_DNS"):
        raise SecurityError("peer must be literal IP or DoH-mapped in production")
    if _env_true("P2P_REQUIRE_ECH"):
        has_ech = hasattr(ssl, "HAS_ECH") or bool(os.environ.get("P2P_ECH_CONFIG"))
        try:
            from ssl import SSLContext  # noqa: F401 — capability probe only
            has_ech = has_ech and hasattr(ssl.SSLContext, "set_ech_config")
        except Exception:
            has_ech = False
        if not has_ech:
            raise SecurityError("ECH required but stack has no ECH sender")


# ---------------------------------------------------------------------------
# H3 — IPv6 firewall allow-list enforcement (fix residual #3)
# ---------------------------------------------------------------------------
# Reuses docs/FIREWALL_IPV6.md policy as code: single-port [::] bind, peer /64
# ACCEPT + DROP tail, silent-drop (no RST/ICMP). Enforcement is a preflight
# gate: production refuses to listen without P2P_PEER_PREFIX set to a valid
# IPv6 /64 (or wider-mask rejected), and helpers emit exact rules to apply.

def require_peer_prefix() -> str:
    prefix = os.environ.get("P2P_PEER_PREFIX", "").strip()
    if not prefix:
        if _env_true("P2P_PRODUCTION") or _env_true("P2P_TS_MODE"):
            raise SecurityError("P2P_PEER_PREFIX required in production/TS mode")
        return ""
    import ipaddress
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        raise SecurityError("peer prefix violation")
    if net.version != 6 or net.prefixlen > 64:
        raise SecurityError("peer prefix must be IPv6 /64 or shorter")
    return str(net)


def generate_ip6tables_rules(port: int, peer_prefix: str) -> list:
    if not 1 <= port <= 65535:
        raise SecurityError("port violation")
    import ipaddress
    cand = peer_prefix.strip() if peer_prefix else require_peer_prefix()
    try:
        net = ipaddress.ip_network(cand, strict=False)
    except ValueError:
        raise SecurityError("peer prefix violation")
    if net.version != 6 or net.prefixlen > 64:
        raise SecurityError("peer prefix must be IPv6 /64 or shorter")
    net_s = str(net)
    return [
        f"ip6tables -A INPUT -p tcp --dport {port} -s {net_s} -j ACCEPT",
        f"ip6tables -A INPUT -p tcp --dport {port} -j DROP",
    ]


def check_listener_scope(lsock: socket.socket, port: int) -> None:
    """Listener must be single-port; production must have peer prefix pinned."""
    try:
        bound_port = lsock.getsockname()[1]
    except OSError:
        raise SecurityError("listener not bound")
    if bound_port != port:
        raise SecurityError("listener port violation")
    if _env_true("P2P_PRODUCTION") or _env_true("P2P_TS_MODE"):
        require_peer_prefix()  # fail closed: no silent open-listener


# ---------------------------------------------------------------------------
# H4 — WORM/SIEM tamper-evident audit (fix residual #4)
# ---------------------------------------------------------------------------
# Reuses remote_siem_forwarder.TamperEvidentAuditChain (HMAC-SHA384 forward
# chaining, head anchoring). Every handshake/rekey/verify failure is appended;
# chain verification is exposed for monitors. Ledger path honors P2P_SIEM_LEDGER.

_audit_chain = None

def _get_audit_chain():
    global _audit_chain
    if _audit_chain is None:
        from pathlib import Path as _P
        from remote_siem_forwarder import TamperEvidentAuditChain
        ledger = os.environ.get("P2P_SIEM_LEDGER")
        if ledger:
            _audit_chain = TamperEvidentAuditChain(ledger_path=_P(ledger))
        else:
            _audit_chain = TamperEvidentAuditChain()
    return _audit_chain


def audit_event(event: str, fields: dict | None = None) -> None:
    try:
        chain = _get_audit_chain()
        chain.append_event(event_type=f"st2027:{event}", severity="INFO",
                           payload=dict(fields or {}))
    except Exception as e:
        log.debug("audit append failed: %r", e)
        if _env_true("P2P_PRODUCTION"):
            raise SecurityError("audit unavailable")


def verify_audit_chain() -> bool:
    return bool(_get_audit_chain().verify_ledger()[0])


# ---------------------------------------------------------------------------
# H5 — Supply-chain gate for vendored PQC providers (fix residual #5)
# ---------------------------------------------------------------------------
# oqs.dll + libsodium.dll ship with Ed25519 sidecars (.sig/.pub) verified at
# import by dependency_security_verifier. This gate runs the FULL verifier
# before any session starts (production fail-closed), plus an optional Rekor
# bundle check via generate_production_sbom.verify_rekor_bundle when
# P2P_REKOR_BUNDLE + P2P_REKOR_PUB are configured (Sigstore migration path).

_supply_verified = False

def verify_vendored_binaries() -> None:
    global _supply_verified
    try:
        from dependency_security_verifier import verify_all_dependencies
        ok = verify_all_dependencies()
    except Exception as e:
        log.debug("supply verifier error: %r", e)
        ok = False
    if not ok:
        raise SecurityError("vendored binary verification failed")
    bundle = os.environ.get("P2P_REKOR_BUNDLE", "").strip()
    pubhex = os.environ.get("P2P_REKOR_PUB", "").strip()
    if bundle and pubhex:
        try:
            from pathlib import Path as _P
            from generate_production_sbom import verify_rekor_bundle
            if not verify_rekor_bundle(_P(bundle), bytes.fromhex(pubhex)):
                raise SecurityError("rekor bundle verification failed")
        except SecurityError:
            raise
        except Exception as e:
            log.debug("rekor verify error: %r", e)
            raise SecurityError("rekor bundle verification failed")
    _supply_verified = True
    audit_event("supply_chain_verified", {})


# ---------------------------------------------------------------------------
# H6 — Secure-memory discipline for Python key copies (fix residual #6)
# ---------------------------------------------------------------------------
# CPython bytes are immutable copies that cannot be reliably wiped; OpenSSL /
# liboqs buffers are outside our control. The production-grade mitigation:
# (a) session keys live in SecureBytes (bytearray + explicit destroy + best-
# effort mlock via platform_hsm_interface.lock_memory); (b) key() access is
# audited and copies are short-lived (used inside AESGCM call only);
# (c) no secret is ever logged; (d) destroy() is called on every exit path.

class SecureBytes:
    """Mutable, explicitly-destroyed secret container (bytearray-backed)."""

    def __init__(self, data: bytes) -> None:
        if not data:
            raise SecurityError("empty secret refused")
        self._buf = bytearray(data)
        self._locked = False
        try:
            from platform_hsm_interface import lock_memory
            import ctypes as _ct
            addr = _ct.addressof((_ct.c_char * len(self._buf)).from_buffer(self._buf))
            self._locked = bool(lock_memory(addr, len(self._buf)))
        except Exception:
            self._locked = False
        self._destroyed = False

    def use(self) -> bytes:
        if self._destroyed:
            raise SecurityError("secret already destroyed")
        return bytes(self._buf)  # short-lived copy; caller must not retain

    def destroy(self) -> None:
        if not self._destroyed:
            _zero(self._buf)
            self._destroyed = True
            try:
                from platform_hsm_interface import unlock_memory
                import ctypes as _ct
                addr = _ct.addressof((_ct.c_char * len(self._buf)).from_buffer(self._buf))
                unlock_memory(addr, len(self._buf))
            except Exception:
                pass

    def __del__(self):  # best effort; explicit destroy() is authoritative
        try:
            self.destroy()
        except Exception:
            pass


def _production_preflight(peer_host: str, outer_sni: str, port: int, peer_id: str = "") -> str:
    """Run all fail-closed gates before any session. Returns literal peer IP."""
    # Component #3, row 1+3: power-up self-tests (cached per process) and
    # CNSA 2.0 purity (cached static scan) gate EVERY session path —
    # lab and production alike, because broken primitives help no one.
    from crypto_selftest import ensure_selftests
    ensure_selftests()
    from cnsa_purity import ensure_purity_cached
    ensure_purity_cached()
    verify_vendored_binaries()
    lit = resolve_peer_literal(peer_host)
    enforce_ech_prerequisites(lit, outer_sni, peer_id)
    if _env_true("P2P_PRODUCTION"):
        # Listener/peer allow-list must be pinned; hardware custody of the
        # caller's own identity is enforced at keygen/sign time (fail-closed
        # there), so there is no separate probe flag to check here.
        require_peer_prefix()
    if _env_true("P2P_TS_MODE"):
        # TOP SECRET: full hardware-layer preflight (FIPS provider, hardware
        # custody, RED/BLACK, TEMPEST approval, diode, armed mesh). Lazy
        # import keeps the base path dependency-free.
        from ts_hw_layer import require_ts_layer
        require_ts_layer(audit_cb=lambda e, f: audit_event(e, f))
        # TOP SECRET: OS & execution-runtime preflight (component #2:
        # deterministic native core, verified platform, boot chain, anti-DMA).
        from ts_runtime import require_ts_runtime
        require_ts_runtime(audit_cb=lambda e, f: audit_event(e, f))
        # TOP SECRET ephemeral profile (#5): no plaintext secrets, pins, or
        # ledgers may rest on disk. The session path keeps them in locked
        # native memory or hardware; SQLite and log files are never opened
        # here. Refuse a misconfigured host loudly instead of writing.
        from trust_anchor import ephemeral_required as _eph_req
        from trust_anchor import forbid_plaintext_disk as _forbid
        if _eph_req():
            for candidate in (os.environ.get("P2P_SIEM_LEDGER", ""),
                              os.environ.get("P2P_SQLITE_PATH", ""),
                              os.environ.get("P2P_LOG_FILE", "")):
                if candidate.strip():
                    _forbid(Path(candidate))
    audit_event("preflight_ok", {"peer": lit, "port": port})
    return lit


# ---------------------------------------------------------------------------
# CLI: keygen / send / recv (operational entry point)
# ---------------------------------------------------------------------------

def _load_identity(label: str, priv_path: Optional[Path]) -> IdentityHandle:
    """Load the caller's ML-DSA-87 identity: HSM first, lab file fallback.

    Production refuses file-backed software keys outright — hardware custody
    is mandatory there (generate_identity_hsm raises when no HSM is active).
    In the lab, a stable file identity avoids re-pinning TOFU every run.
    """
    if hardware_identity_required():
        # Fail closed: no file fallback, no software minting in production.
        return generate_identity_hsm(label)
    if priv_path is not None and priv_path.exists():
        sk = priv_path.read_bytes()
        from liboqs_wrapper import LibOQS_MLDSA_87
        if len(sk) != LibOQS_MLDSA_87().sk_size:
            raise SecurityError("identity file size violation")
        pub_path = priv_path.with_suffix(".pub")
        if not pub_path.exists():
            raise SecurityError("identity pub file missing")
        return IdentityHandle(sig_pk=pub_path.read_bytes(), sig_sk=sk,
                              key_data=None, stored_in_hsm=False, label=label)
    handle = generate_identity_hsm(label)  # HSM if active, else fresh lab key
    if not handle.stored_in_hsm and priv_path is not None and handle.sig_sk:
        priv_path.write_bytes(handle.sig_sk)
        priv_path.with_suffix(".pub").write_bytes(handle.sig_pk)
        try:
            os.chmod(priv_path, 0o600)
        except OSError:
            pass
        log.warning("Lab software identity persisted at %s — use HSM in production", priv_path)
    return handle


def _enforce_transmit_authorization(
    classification: Optional[str], receipt_path: Optional[str],
    payload: bytes, is_sender: bool) -> None:
    """Dual-control gate for TOP SECRET movement (SPO/DPO, zero compromise).

    TS and production postures handle TOP SECRET only and demand a valid
    dual-person receipt bound to the exact payload digest. Lab without a
    receipt is allowed for testing convenience only; any provided receipt
    is still verified. Fail-closed with generic errors, detail in local log.
    """
    import json as _json

    ts_mode = _env_true("P2P_TS_MODE")
    prod_mode = _env_true("P2P_PRODUCTION")
    want = (classification or ("TOP SECRET" if (ts_mode or prod_mode) else "SECRET"))
    norm = " ".join(str(want).strip().upper().split())
    if ts_mode and norm != "TOP SECRET":
        raise SecurityError("TS mode handles TOP SECRET only")
    if norm not in ("SECRET", "TOP SECRET"):
        raise SecurityError("classification refused")
    path_str = (receipt_path or os.environ.get("P2P_DPO_RECEIPT", "")).strip()
    if ts_mode or (prod_mode and norm == "TOP SECRET"):
        if not path_str:
            raise SecurityError("dual-control receipt required")
        try:
            receipt = _json.loads(Path(path_str).read_text(encoding="utf-8"))
        except Exception as exc:
            log.debug("receipt load refused: %r", exc)
            raise SecurityError("dual-control receipt required")
        try:
            from spo_dpo import require_spo_dpo_for_send as _gate
            _gate(norm, bytes(payload), receipt)
        except Exception as exc:
            log.debug("transmit authorization refused: %r", exc)
            raise SecurityError("transmit authorization refused")
        audit_event("transmit_authorized",
                    {"class": norm, "sender": bool(is_sender)})
        return
    if path_str:
        try:
            receipt = _json.loads(Path(path_str).read_text(encoding="utf-8"))
            from spo_dpo import require_spo_dpo_for_send as _gate_lab
            _gate_lab(norm, bytes(payload), receipt)
        except Exception as exc:
            log.debug("lab receipt refused: %r", exc)
            raise SecurityError("transmit authorization refused")


def _gate_hw_admin(a) -> None:
    """Hardware readiness messaging + administrator elevation for send/recv.

    Policy (deliberate, test-safe):
    - Lab path (no TS env, no --require-admin): immediate return, zero
      behavior/output change.
    - TS mode: print the HAVE/MISSING advisory table so the operator sees
      exactly which hardware is absent. Enforcement stays with the
      ts_hw_layer require_* gates (fail-closed); this gate never adds a new
      refusal on its own, so unequipped CI/lab TS runs keep working.
    - --require-admin: elevation is demanded; a skipped/declined prompt or
      failed relaunch refuses the transmission (SecurityError).
    - TS mode on an interactive terminal without --no-elevate: ask once
      (consent + UAC/sudo relaunch with exit-code propagation). A declined
      prompt continues with a loud warning; existing gates still enforce.
      Non-interactive shells never prompt (log + continue).
    SystemExit from a successful elevated relaunch propagates (the parent
    must not continue twice).
    """
    import hw_readiness as _hw

    want_admin = bool(getattr(a, "require_admin", False))
    no_elevate = bool(getattr(a, "no_elevate", False))
    ts_mode = _env_true("P2P_TS_MODE")
    if not want_admin and not ts_mode:
        return
    if ts_mode:
        for _v in _hw.collect():
            print(_v.headline())
    if want_admin or (ts_mode and not no_elevate):
        result = _hw.ensure_admin(no_elevate=no_elevate)
        if want_admin and result in ("skipped", "declined"):
            raise SecurityError("administrator rights required")
        if result in ("skipped", "declined"):
            log.warning("continuing without elevation; admin-gated "
                        "hardware checks report UNKNOWN")


def _resolve_peer_cert(value: Optional[str]) -> Optional[str]:
    """Accept a certificate file path or inline JSON. Fail-closed either way.

    Operators provision files; tests and automation may pass inline JSON.
    A path that names nothing readable is refused, never treated as JSON.
    """
    if value is None:
        return None
    text = str(value)
    if not text.strip():
        return None
    candidate = Path(text.strip())
    try:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    except OSError as exc:
        log.debug("peer cert file refused: %r", exc)
        raise SecurityError("peer certificate refused")
    if text.strip().startswith("{"):
        return text
    raise SecurityError("peer certificate refused")


def main(argv: Optional[list] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="secure_transmit_2027",
                                 description="PQ-hybrid secure file transfer (TLS 1.3 + SecP384r1MLKEM1024 + ML-DSA-87)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="mint ML-DSA-87 identity (HSM preferred)")
    kg.add_argument("--label", required=True)
    kg.add_argument("--sig-priv", default=None, help="lab file fallback path")

    snd = sub.add_parser("send", help="send a file")
    snd.add_argument("--host", required=True)
    snd.add_argument("--port", type=int, required=True)
    snd.add_argument("--cert", required=True)
    snd.add_argument("--key", required=True)
    snd.add_argument("--ca", required=True)
    snd.add_argument("--peer-id", required=True)
    snd.add_argument("--file", required=True)
    snd.add_argument("--sni", default="cdn-front.example.net")
    snd.add_argument("--label", default="sender")
    snd.add_argument("--sig-priv", default=None)
    snd.add_argument("--class", dest="classification", default=None,
                     help="SECRET or TOP SECRET (TS mode defaults to TOP SECRET)")
    snd.add_argument("--dpo-receipt", default=None,
                     help="JSON dual-control receipt for TOP SECRET sends")
    snd.add_argument("--anonymity", action="store_true",
                     help="route via overlay plus constant-rate uniform cells (#4)")
    snd.add_argument("--peer-cert", default=None,
                     help="threshold CA certificate JSON for the remote peer (strict, no TOFU)")
    snd.add_argument("--peer-subject", default=None,
                     help="certified subject label expected for the remote peer")
    snd.add_argument("--require-admin", action="store_true",
                     help="demand Administrator rights (consent + UAC/sudo "
                          "relaunch); refuse when declined or impossible")
    snd.add_argument("--no-elevate", action="store_true",
                     help="never relaunch elevated; accept reduced posture "
                          "explicitly (fail-closed gates still enforce)")

    rcv = sub.add_parser("recv", help="receive one file")
    rcv.add_argument("--port", type=int, required=True)
    rcv.add_argument("--cert", required=True)
    rcv.add_argument("--key", required=True)
    rcv.add_argument("--ca", required=True)
    rcv.add_argument("--peer-id", required=True)
    rcv.add_argument("--out", required=True)
    rcv.add_argument("--label", default="receiver")
    rcv.add_argument("--sig-priv", default=None)
    rcv.add_argument("--class", dest="classification", default=None,
                     help="SECRET or TOP SECRET (TS mode defaults to TOP SECRET)")
    rcv.add_argument("--dpo-receipt", default=None,
                     help="JSON dual-control receipt for TOP SECRET receives")
    rcv.add_argument("--anonymity", action="store_true",
                     help="route via overlay plus constant-rate uniform cells (#4)")
    rcv.add_argument("--peer-cert", default=None,
                     help="threshold CA certificate JSON for the remote peer (strict, no TOFU)")
    rcv.add_argument("--peer-subject", default=None,
                     help="certified subject label expected for the remote peer")
    rcv.add_argument("--require-admin", action="store_true",
                     help="demand Administrator rights (consent + UAC/sudo "
                          "relaunch); refuse when declined or impossible")
    rcv.add_argument("--no-elevate", action="store_true",
                     help="never relaunch elevated; accept reduced posture "
                          "explicitly (fail-closed gates still enforce)")

    hw = sub.add_parser("check-hw",
                        help="hardware readiness checklist (HAVE/MISSING per "
                             "item) + optional admin elevation")
    hw.add_argument("--strict", action="store_true",
                    help="exit 1 unless every TS-required item reports HAVE")
    hw.add_argument("--json", action="store_true",
                    help="machine-readable report on stdout")
    hw.add_argument("--require-admin", action="store_true",
                    help="demand Administrator rights first (consent + "
                         "UAC/sudo relaunch); refuse when declined")
    hw.add_argument("--no-elevate", action="store_true",
                    help="never relaunch elevated")
    hw.add_argument("--assume-yes", action="store_true",
                    help="answer yes to the elevation consent prompt")

    a = ap.parse_args(argv)
    if getattr(a, "peer_cert", None) is not None:
        # Operators provision certificate files; fail closed on unreadable
        # paths instead of silently treating them as (invalid) inline JSON.
        a.peer_cert = _resolve_peer_cert(getattr(a, "peer_cert", None))
    if a.cmd == "check-hw":
        import hw_readiness as _hw_cli

        if getattr(a, "require_admin", False):
            _hw_cli.ensure_admin(
                assume_yes=False,
                no_elevate=bool(getattr(a, "no_elevate", False)))
        fwd = []
        if getattr(a, "strict", False):
            fwd.append("--strict")
        if getattr(a, "json", False):
            fwd.append("--json")
        if getattr(a, "no_elevate", False):
            fwd.append("--no-elevate")
        if getattr(a, "assume_yes", False):
            fwd.append("--assume-yes")
        return _hw_cli.main(fwd)
    if a.cmd in ("send", "recv"):
        _gate_hw_admin(a)
    if a.cmd == "keygen":
        h = _load_identity(a.label, Path(a.sig_priv) if a.sig_priv else None)
        print(f"identity: label={h.label} hsm={h.stored_in_hsm} sig_pk={len(h.sig_pk)}B")
        print(f"pin (verify OOB): {identity_pin(h.sig_pk, h.sig_pk)}")
        return 0
    if a.cmd == "send":
        import json as _json_anon

        h = _load_identity(a.label, Path(a.sig_priv) if a.sig_priv else None)
        ctx = make_client_context(a.cert, a.key, a.ca)
        data = Path(a.file).read_bytes()
        want_anon = bool(getattr(a, "anonymity", False))
        if _env_true("P2P_TS_MODE"):
            # TOP SECRET over public internet mandates the anonymity
            # transport: overlay plus constant-rate uniform cells.
            want_anon = True
            try:
                from transport_anonymity import require_overlay as _ovl

                _ovl(a.host, a.port)
            except Exception as exc:
                log.debug("send overlay refused: %r", exc)
                raise SecurityError("overlay required")
        _enforce_transmit_authorization(
            getattr(a, "classification", None),
            getattr(a, "dpo_receipt", None),
            data, is_sender=True)
        if want_anon:
            receipt = None
            receipt_path = (getattr(a, "dpo_receipt", None)
                            or os.environ.get("P2P_DPO_RECEIPT", "")).strip()
            if receipt_path:
                receipt = _json_anon.loads(Path(receipt_path).read_text(
                    encoding="utf-8"))
            from transport_anonymity import anonymous_send as _anon_send

            _anon_send(a.host, a.port, ctx, h, a.peer_id, data,
                       classification=(getattr(a, "classification", None)
                                       or "TOP SECRET"),
                       receipt=receipt, server_hostname=a.sni,
                       peer_cert=getattr(a, "peer_cert", None),
                       peer_subject=getattr(a, "peer_subject", None))
            print(f"sent {len(data)} bytes to {a.host}:{a.port} via anonymity")
            return 0
        client_send(a.host, a.port, ctx, h, a.peer_id, data, server_hostname=a.sni,
                    peer_cert=getattr(a, "peer_cert", None),
                    peer_subject=getattr(a, "peer_subject", None))
        print(f"sent {len(data)} bytes to {a.host}:{a.port}")
        return 0
    if a.cmd == "recv":
        h = _load_identity(a.label, Path(a.sig_priv) if a.sig_priv else None)
        ctx = make_server_context(a.cert, a.key, a.ca)
        if _env_true("P2P_TS_MODE"):
            # TOP SECRET: no wildcard listener — bind the attested BLACK
            # interface address only (RED/BLACK row, TS-2).
            from ts_hw_layer import enforce_bind as _ts_bind
            black = _ts_bind("BLACK", os.environ.get("P2P_BLACK_BIND", ""))
            fam = socket.AF_INET6 if ":" in black else socket.AF_INET
            lsock = socket.socket(fam, socket.SOCK_STREAM)
            lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            lsock.bind((black, a.port))
        else:
            lsock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            lsock.bind(("::", a.port))
        lsock.listen(1)
        want_anon = bool(getattr(a, "anonymity", False))
        if _env_true("P2P_TS_MODE"):
            want_anon = True
        if want_anon:
            import json as _json_anon_rx

            receipt = None
            receipt_path = (getattr(a, "dpo_receipt", None)
                            or os.environ.get("P2P_DPO_RECEIPT", "")).strip()
            if receipt_path:
                receipt = _json_anon_rx.loads(Path(receipt_path).read_text(
                    encoding="utf-8"))
            from transport_anonymity import anonymous_recv as _anon_recv

            try:
                dest = _anon_recv(
                    lsock, ctx, h, a.peer_id, Path(a.out),
                    classification=(getattr(a, "classification", None)
                                    or "TOP SECRET"),
                    receipt=receipt,
                    peer_cert=getattr(a, "peer_cert", None),
                    peer_subject=getattr(a, "peer_subject", None))
            finally:
                lsock.close()
            print(f"received -> {dest} via anonymity")
            return 0
        try:
            dest = server_once(lsock, ctx, h, a.peer_id, out_path=Path(a.out),
                               peer_cert=getattr(a, "peer_cert", None),
                               peer_subject=getattr(a, "peer_subject", None))
        finally:
            lsock.close()
        _enforce_transmit_authorization(
            getattr(a, "classification", None),
            getattr(a, "dpo_receipt", None),
            Path(dest).read_bytes(), is_sender=False)
        print(f"received -> {dest}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
