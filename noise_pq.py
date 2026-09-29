#!/usr/bin/env python3
"""
noise_pq.py — Noise_XXhfs-style post-quantum handshake with ML-KEM-1024.

Skeleton follows the Noise `hfs` (hybrid forward secrecy) extension:
Perrin, "KEM-based Hybrid Forward Secrecy for Noise",
github.com/noiseprotocol/noise_hfs_spec (noise_hfs.md, rev 1,
2018-11-17, status unofficial/unstable — a draft extension, NOT a
peer-reviewed result and NOT part of the Noise spec rev 34). Its tokens
are `e1` (send KEM ek) and `ekem1` (send KEM ct, MixKey(ss)); its XXhfs
pattern is:
  XXhfs:  -> e, e1
          <- e, ee, ekem1, s, es
          -> s, se
with KEM function mapping per spec sections 3-4 (GENERATE_KEM_KEYPAIR /
GENERATE_KEM_CIPHERTEXT / KEM decaps; MixKey(kem_output)). The spec
names NO concrete KEM (section 6 explicitly lists none) and contains
NO security proofs — any claim that "the extension proves" this
profile hybrid is FALSE. Peer-reviewed KEM-Noise results (PQNoise,
Angel et al., CCS 2022, ePrint 2022/539) cover KEM-replacement Noise
patterns generally, not this profile.

Instantiation (profile Noise_XXhfs+sig_P384+MLKEM1024_AES256GCM_SHA384):
  DH function ... P-384 ECDH (CNSA L5 hedge; spec-era examples use 25519/448).
  hfs function .. ML-KEM-1024 (FIPS 203): initiator GENERATE_KEM_KEYPAIR,
    send ek (1568); responder GENERATE_KEM_CIPHERTEXT, send ct (1568);
    MixKey(ss) with ss 32 bytes. M1/M2 ek/ct travel in clear exactly as
    the spec's M1/M2 placement (no key exists yet to encrypt them under).
  HASH .......... SHA-384. CIPHER ...... AES-256-GCM.
  Static auth ... CUSTOM SUBSTITUTION (not in the hfs extension): Noise DH
    statics cannot express signing keys, so es/se tokens are REPLACED by
    ML-DSA-87 signatures over the handshake hash (+sig profile suffix),
    verify-before-derive, SIGMA-style. Session keys still mix ee+ss_kem
    only. This substitution is UNPROVEN (no reduction to the hfs draft,
    which has no proofs, nor to PQNoise, which keeps DH/KEM auth) and is
    stated as an assumption; what IS proven by test is structural
    agreement with the XXhfs message skeleton plus fail-closed
    verify-before-derive on both sides.
  Combiner ...... HKDF-SHA384 over (ck, ikm) per Noise MixKey (dual-PRF
    combiner per Bindel et al. PQCrypto'19: dPRF = HKDF-Extract, PRF =
    HKDF-Expand with ciphertexts bound — here every transmitted blob is
    MixHashed into h, and Split/transport keys derive from ck chained
    through those hashes. Dual-PRF-ness of HKDF is an ASSUMPTION shared
    with TLS 1.3/MLS/Noise-PQ (eprint 2022/065 shows it was never proven
    in general; fixed-length-input sufficient conditions exist) — stated
    as assumption. The ProVerif model abstracts kdf as one-way (stronger
    than dual-PRF), which is standard practice and documented there.

Message flow (all lengths fixed; any deviation aborts):
  M1 I->R: e_pub(97) || ml_ek(1568)
  M2 R->I: e_pub(97) || ml_ct(1568) || enc(sig_r_pk 2592) || enc(sig_r)
  M3 I->R: enc(sig_i_pk 2592) || enc(sig_i)
  Split -> (k_ir, k_ri) + transcript hash h (channel binding export).

Transport: AES-256-GCM, 12B nonce seq(8BE)||dir(1)||zero(3), strict replay
window (shared semantics with secure_transmit_2027.Channel).

All primitives REAL: liboqs ML-KEM-1024/ML-DSA-87, OpenSSL P-384/AES-GCM/
HKDF-SHA384. No simulations.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
from dataclasses import dataclass, field
from typing import Optional, Tuple

PROTOCOL_NAME = b"Noise_XXhfs+sig_P384+MLKEM1024_AES256GCM_SHA384"
HASHLEN = 48
MLKEM_EK = 1568
MLKEM_CT = 1568
MLKEM_SS = 32
P384_PUB = 97
P384_SS = 48


class NoiseError(Exception):
    """Fail-closed Noise handshake/transport failure."""


def _noise_hkdf(ck: bytes, ikm: bytes, n_out: int) -> Tuple[bytes, ...]:
    """Noise-spec HKDF(ck, ikm): temp_key=HMAC(ck,ikm); out_i=HMAC(temp_key,prev||i)."""
    if len(ck) != HASHLEN or not 1 <= n_out <= 3:
        raise NoiseError("HKDF parameter violation")
    temp_key = hmac.new(ck, ikm, hashlib.sha384).digest()
    outs = []
    prev = b""
    for i in range(1, n_out + 1):
        prev = hmac.new(temp_key, prev + bytes([i]), hashlib.sha384).digest()
        outs.append(prev)
    return tuple(outs)


class SymmetricState:
    """Noise SymmetricState with SHA-384 / AES-256-GCM (spec section 5)."""

    def __init__(self, protocol_name: bytes = PROTOCOL_NAME) -> None:
        if len(protocol_name) <= HASHLEN:
            self.h = protocol_name + b"\x00" * (HASHLEN - len(protocol_name))
        else:
            self.h = hashlib.sha384(protocol_name).digest()
        self.ck = self.h
        self._key: Optional[bytes] = None
        self._n = 0

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.sha384(self.h + data).digest()

    def mix_key(self, ikm: bytes) -> None:
        ck, temp_k = _noise_hkdf(self.ck, ikm, 2)
        self.ck = ck
        # CNSA cipher keys are 256-bit; temp_k is 48B (SHA-384 output).
        # Truncating HKDF output preserves PRF security (prefix of a PRF).
        self._key = temp_k[:32]
        self._n = 0

    def mix_key_and_hash(self, ikm: bytes) -> None:
        ck, temp_h, temp_k = _noise_hkdf(self.ck, ikm, 3)
        self.ck = ck
        self.mix_hash(temp_h)
        self._key = temp_k[:32]
        self._n = 0

    def _nonce(self) -> bytes:
        if self._n >= (1 << 64) - 1:
            raise NoiseError("cipher nonce exhausted")
        return struct.pack(">Q", self._n) + b"\x00\x00\x00\x00"

    def encrypt_and_hash(self, pt: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if self._key is None:
            out = pt
        else:
            out = AESGCM(self._key).encrypt(self._nonce(), pt, self.h)
            self._n += 1
        self.mix_hash(out)
        return out

    def decrypt_and_hash(self, ct: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if self._key is None:
            out = ct
        else:
            try:
                out = AESGCM(self._key).decrypt(self._nonce(), ct, self.h)
            except Exception:
                raise NoiseError("handshake authentication failed")
            self._n += 1
        # MixHash(ciphertext) — NOT the plaintext. Both parties must absorb
        # the identical wire bytes or the transcript forks (caught live:
        # mixing `out` here broke every second payload).
        self.mix_hash(ct)
        return out

    def split(self) -> Tuple[Tuple[bytes, bytes], bytes]:
        k1, k2 = _noise_hkdf(self.ck, b"\x00" * HASHLEN, 2)
        return ((k1[:32], k2[:32])), self.h

    def destroy(self) -> None:
        # Only _key-derived bytearray material is truly wiped; immutable
        # `bytes` outputs from HKDF cannot be scrubbed — references are
        # dropped so refcount release frees them immediately (CPython, no
        # cycles). Same documented H6 limitation as secure_transmit_2027.
        self._key = None


def _p384_keygen() -> Tuple[object, bytes]:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    priv = ec.generate_private_key(ec.SECP384R1())
    pub = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if len(pub) != P384_PUB:
        raise NoiseError("P-384 encoding violation")
    return priv, pub


def _p384_dh(priv, pub_bytes: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec
    if len(pub_bytes) != P384_PUB:
        raise NoiseError("P-384 share violation")
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), pub_bytes)
    ss = priv.exchange(ec.ECDH(), peer)
    if len(ss) != P384_SS:
        raise NoiseError("ECDH violation")
    return ss


def _mlkem_keygen() -> Tuple[bytes, bytes]:
    from liboqs_wrapper import LibOQS_MLKEM_1024
    pk, sk = LibOQS_MLKEM_1024().keygen()
    if len(pk) != MLKEM_EK:
        raise NoiseError("ML-KEM-1024 size violation")
    return pk, bytearray(sk)  # wipeable


def _mlkem_encaps(ek: bytes):
    from liboqs_wrapper import LibOQS_MLKEM_1024
    if len(ek) != MLKEM_EK:
        raise NoiseError("ML-KEM ek violation")
    return LibOQS_MLKEM_1024().encaps(ek)  # (ct, ss)


def _mlkem_decaps(sk: bytearray, ct: bytes) -> bytes:
    from liboqs_wrapper import LibOQS_MLKEM_1024
    if len(ct) != MLKEM_CT:
        raise NoiseError("ML-KEM ct violation")
    return LibOQS_MLKEM_1024().decaps(bytes(sk), ct)


def _sign(sk: bytes, msg: bytes) -> bytes:
    from liboqs_wrapper import LibOQS_MLDSA_87
    return LibOQS_MLDSA_87().sign(sk, msg)


def _verify(pk: bytes, msg: bytes, sig: bytes) -> None:
    from liboqs_wrapper import LibOQS_MLDSA_87
    if not LibOQS_MLDSA_87().verify(pk, msg, sig):
        raise NoiseError("identity signature invalid")


@dataclass
class NoiseSession:
    is_initiator: bool
    sig_pk: bytes
    sig_sk: bytes
    sym: SymmetricState = field(default_factory=SymmetricState)
    _e_priv: Optional[object] = field(default=None, repr=False)
    _e_pub: Optional[bytes] = field(default=None, repr=False)
    _f_sk: Optional[bytearray] = field(default=None, repr=False)  # ML-KEM dk (initiator)
    _f_ss: Optional[bytes] = field(default=None, repr=False)      # KEM ss (responder)
    _peer_sig_pk: Optional[bytes] = field(default=None, repr=False)
    _k_send: Optional[bytes] = field(default=None, repr=False)
    _k_recv: Optional[bytes] = field(default=None, repr=False)
    _send_n: int = 0
    _m3_done: bool = False  # M3 emitted (initiator) / processed (responder)
    _recv_win_base: int = 0
    _recv_win_bits: int = 0
    _recv_started: bool = False
    handshake_hash: Optional[bytes] = None

    def destroy(self) -> None:
        # Truly wiped: _f_sk (mutable bytearray). Immutable bytes (_f_ss,
        # _k_send/_k_recv, sym key): references dropped for immediate
        # refcount release — cannot be scrubbed, documented H6 limitation.
        if self._f_sk is not None:
            for i in range(len(self._f_sk)):
                self._f_sk[i] = 0
            self._f_sk = None
        self._f_ss = self._k_send = self._k_recv = None
        self.sym.destroy()


def _take_ephemeral(sess: NoiseSession) -> bytes:
    priv, pub = _p384_keygen()
    sess._e_priv = priv
    sess._e_pub = pub
    sess.sym.mix_hash(pub)
    return pub


def initiator_hello(sess: NoiseSession) -> bytes:
    """M1: -> e, e1. Preconditions: initiator, fresh session."""
    if not sess.is_initiator or sess._e_pub is not None:
        raise NoiseError("handshake state violation")
    e_pub = _take_ephemeral(sess)
    ml_ek, ml_dk = _mlkem_keygen()
    sess._f_sk = ml_dk
    sess.sym.mix_hash(ml_ek)
    return e_pub + ml_ek


def responder_reply(sess: NoiseSession, m1: bytes, signer=None) -> bytes:
    """M2: <- e, ee, ekem1, s, es(sig). Verify nothing yet (nothing signed).

    signer: optional callable(msg)->sig for HSM-held identities. When None,
    the session's software sig_sk signs (lab path).
    """
    if sess.is_initiator or sess._e_pub is not None:
        raise NoiseError("handshake state violation")
    if len(m1) != P384_PUB + MLKEM_EK:
        raise NoiseError("M1 size violation")
    e_cli, ek_cli = m1[:P384_PUB], m1[P384_PUB:]
    # Noise processing order: mix RECEIVED values first (e_cli, ek_cli) in
    # send order, then generate own ephemeral material. Any other order
    # forks the transcript hash h between the parties (caught live).
    sess.sym.mix_hash(e_cli)
    sess.sym.mix_hash(ek_cli)
    e_pub = _take_ephemeral(sess)  # mixes e_pub exactly once (see helper)
    ml_ct, ml_ss = _mlkem_encaps(ek_cli)
    sess._f_ss = ml_ss
    sess.sym.mix_hash(ml_ct)
    sess.sym.mix_key(_p384_dh(sess._e_priv, e_cli))   # ee
    sess.sym.mix_key(ml_ss)                            # ff
    enc_pk = sess.sym.encrypt_and_hash(sess.sig_pk)    # s (encrypted)
    h_for_sig = bytes(sess.sym.h)
    sig = signer(h_for_sig) if signer is not None else _sign(sess.sig_sk, h_for_sig)  # es->sig over h
    enc_sig = sess.sym.encrypt_and_hash(sig)
    return e_pub + ml_ct + enc_pk + enc_sig


def initiator_finish(sess: NoiseSession, m2: bytes) -> None:
    """Process M2: complete ee/ff, decrypt s, VERIFY sig_r BEFORE derive."""
    if not sess.is_initiator or sess._f_sk is None or sess.handshake_hash is not None:
        raise NoiseError("handshake state violation")
    if len(m2) < P384_PUB + MLKEM_CT:
        raise NoiseError("M2 size violation")
    e_srv, rest = m2[:P384_PUB], m2[P384_PUB:]
    ml_ct, rest = rest[:MLKEM_CT], rest[MLKEM_CT:]
    sess.sym.mix_hash(e_srv)
    sess.sym.mix_hash(ml_ct)
    sess.sym.mix_key(_p384_dh(sess._e_priv, e_srv))    # ee
    ml_ss = _mlkem_decaps(sess._f_sk, ml_ct)           # ff
    sess.sym.mix_key(ml_ss)
    # Split enc_pk (2592 + 16 tag) from enc_sig (rest).
    from liboqs_wrapper import LibOQS_MLDSA_87  # noqa: F401 (sizes below)
    enc_pk, enc_sig = rest[:2592 + 16], rest[2592 + 16:]
    srv_pk = sess.sym.decrypt_and_hash(enc_pk)
    h_for_verify = sess.sym.h  # transcript THROUGH the signed message's
    srv_sig = sess.sym.decrypt_and_hash(enc_sig)
    _verify(srv_pk, h_for_verify, srv_sig)   # verify-before-derive
    sess._peer_sig_pk = srv_pk


def initiator_complete(sess: NoiseSession, signer=None) -> bytes:
    """M3: -> s, se(sig). Returns message; transport keys NOT yet split.

    signer: optional callable(msg)->sig for HSM-held identities.
    Exactly one M3 per session (handshake-cipher nonce reuse = forgery).
    """
    if not sess.is_initiator or sess._peer_sig_pk is None \
            or sess._m3_done or sess.handshake_hash is not None:
        raise NoiseError("handshake state violation")
    enc_pk = sess.sym.encrypt_and_hash(sess.sig_pk)
    h_for_sig = bytes(sess.sym.h)
    sig = signer(h_for_sig) if signer is not None else _sign(sess.sig_sk, h_for_sig)
    out = enc_pk + sess.sym.encrypt_and_hash(sig)
    sess._m3_done = True  # exactly one M3 per session (nonce reuse = forgery)
    return out


def responder_complete(sess: NoiseSession, m3: bytes) -> None:
    """Process M3: decrypt s, VERIFY sig_i BEFORE Split."""
    if sess.is_initiator or sess._f_ss is None or sess._m3_done \
            or sess.handshake_hash is not None:
        raise NoiseError("handshake state violation")
    enc_pk, enc_sig = m3[:2592 + 16], m3[2592 + 16:]
    if len(enc_sig) == 0:
        raise NoiseError("M3 size violation")
    cli_pk = sess.sym.decrypt_and_hash(enc_pk)
    h_for_verify = sess.sym.h  # transcript through the signed message
    cli_sig = sess.sym.decrypt_and_hash(enc_sig)
    _verify(cli_pk, h_for_verify, cli_sig)   # verify-before-derive
    sess._peer_sig_pk = cli_pk
    sess._m3_done = True


def split_session(sess: NoiseSession) -> Tuple[bytes, bytes, bytes]:
    """Split() -> (k_send, k_recv, handshake_hash h). Wipes handshake state."""
    if sess._peer_sig_pk is None or sess.handshake_hash is not None:
        raise NoiseError("handshake incomplete or already split")
    (k1, k2), h = sess.sym.split()
    sess.handshake_hash = h
    k_send, k_recv = (k1, k2) if sess.is_initiator else (k2, k1)
    sess.destroy()  # wipes ephemerals, KEM ss, and handshake cipher state
    sess._k_send, sess._k_recv = k_send, k_recv  # transport keys only survive
    return k_send, k_recv, h


def _transport_nonce(seq: int, direction: int) -> bytes:
    return struct.pack(">Q", seq) + bytes([direction]) + b"\x00\x00\x00"


def transport_send(sess: NoiseSession, pt: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if sess._k_send is None or len(pt) > 16384:
        raise NoiseError("transport state violation")
    if sess._send_n >= (1 << 64) - 1:
        raise NoiseError("transport sequence exhausted (re-handshake required)")
    seq = sess._send_n + 1
    sess._send_n = seq
    direction = 0xA5 if sess.is_initiator else 0x5A
    ct = AESGCM(sess._k_send).encrypt(_transport_nonce(seq, direction), pt, b"NPQ1")
    return struct.pack(">Q", seq) + ct


def _recv_check(sess: NoiseSession, seq: int) -> None:
    """Read-only replay test. Safe on unauthenticated input; no mutation.

    Mirrors secure_transmit_2027.Channel semantics (RFC 6479: advance
    only on validated S; WireGuard: check only after verified tag).
    """
    if seq < 0 or seq >= (1 << 64):
        raise NoiseError("sequence violation")
    if not sess._recv_started:
        return
    if seq < sess._recv_win_base:
        raise NoiseError("replay rejected")
    off = seq - sess._recv_win_base
    if off < 64 and ((sess._recv_win_bits >> off) & 1):
        raise NoiseError("replay rejected")


def _recv_mark(sess: NoiseSession, seq: int) -> None:
    """Advance replay window. Call ONLY after the AEAD tag verified."""
    if not sess._recv_started:
        sess._recv_win_base, sess._recv_win_bits, sess._recv_started = seq, 1, True
        return
    if seq < sess._recv_win_base:
        return  # validated by _recv_check; nothing to record
    off = seq - sess._recv_win_base
    if off < 64:
        sess._recv_win_bits |= (1 << off)
    else:
        shift = off - 63
        sess._recv_win_bits = 0 if shift >= 64 else (sess._recv_win_bits >> shift)
        sess._recv_win_base += shift
        sess._recv_win_bits |= (1 << 63)


def transport_recv(sess: NoiseSession, wire: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if sess._k_recv is None or len(wire) < 8 + 1 + 16:
        raise NoiseError("transport framing violation")
    seq = struct.unpack(">Q", wire[:8])[0]
    direction = 0x5A if sess.is_initiator else 0xA5
    _recv_check(sess, seq)  # Step 1: read-only (forged seq cannot shift)
    try:
        pt = AESGCM(sess._k_recv).decrypt(
            _transport_nonce(seq, direction), wire[8:], b"NPQ1")
    except Exception:
        raise NoiseError("transport authentication failed")
    _recv_mark(sess, seq)  # Step 3: mutate ONLY on authentication success
    return pt
