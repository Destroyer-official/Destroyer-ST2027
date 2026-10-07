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

Instantiation (profile Noise_XXhfs_P384_MLKEM1024_MLDSA87_AES256GCM_SHA384):
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
    only. Signatures use strictly separated domain strings for responder
    (DOMAIN_SEP_SIG_RESP) and initiator (DOMAIN_SEP_SIG_INIT) to prevent
    cross-role reflection attacks. This substitution is UNPROVEN (no reduction
    to the hfs draft, which has no proofs, nor to PQNoise, which keeps DH/KEM auth)
    and is stated as an assumption; what IS proven by test is structural
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

RATCHET & POST-COMPROMISE SECURITY (PCS):
  This file defines the initial session handshake and produces a single
  pair of transport keys (k_ir, k_ri). Continuous post-compromise security
  (PCS) is NOT provided by this file alone; PCS requires continuous key
  rotation, which lives in `double_ratchet.py` (PQ double ratchet) and
  `secure_transmit_2027.py::rehandshake` (Continuous Epoch Ratchet).

MEMORY WIPING LIMITATIONS (Python runtime vs Rust data plane):
  Memory wiping in Python (`_zero(bytearray)`) is container sanitization
  only. CPython immutable `bytes` objects (returned by ECDH exchange,
  liboqs decaps, and slice operations) and OpenSSL/ctypes internal heap
  buffers cannot be guaranteed zeroized or pinned in physical RAM.
  Hardware-enforced memory locking (`VirtualLock`/`mlock`) and verified
  non-swappable zeroization exist strictly in the Rust data plane
  (`rust_data_plane/src/memlock.rs`, `LockedKey32`, `ZeroizeOnDrop`).

ANTI-DOS / AMPLIFICATION BOUNDS:
  M1 is 1,665 bytes; M2 is 8,916 bytes (a 5.35x reflection amplification
  factor). Processing an unauthenticated M1 requires P-384 keygen, ML-KEM
  encapsulation, and ML-DSA signing. Consequently, this handshake MUST NOT
  be exposed over unauthenticated connectionless UDP without an outer
  stateless cookie / address return-routability gate (e.g. QUIC retry token,
  WireGuard cookie). In Destroyer ST2027, the handshake runs over connection-
  oriented TCP / TLS 1.3 outer envelope where the 3-way handshake prevents
  IP address spoofing.

All primitives REAL: liboqs ML-KEM-1024/ML-DSA-87, OpenSSL P-384/AES-GCM/
HKDF-SHA384. No simulations.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

PROTOCOL_NAME = b"Noise_XXhfs_P384_MLKEM1024_MLDSA87_AES256GCM_SHA384"
PROTOCOL_NAME_PSK2 = b"Noise_XXhfs_psk2_P384_MLKEM1024_MLDSA87_AES256GCM_SHA384"
PSK_LEN = 32
HASHLEN = 48
MLKEM_EK = 1568
MLKEM_CT = 1568
MLKEM_SS = 32
P384_PUB = 97
P384_SS = 48
MLDSA87_PK = 2592
MLDSA87_SIG = 4627
AEAD_TAG_LEN = 16

EXPECTED_M1_LEN = P384_PUB + MLKEM_EK
EXPECTED_M2_LEN = P384_PUB + MLKEM_CT + (MLDSA87_PK + AEAD_TAG_LEN) + (MLDSA87_SIG + AEAD_TAG_LEN)
EXPECTED_M3_LEN = (MLDSA87_PK + AEAD_TAG_LEN) + (MLDSA87_SIG + AEAD_TAG_LEN)

# Domain separation context strings for handshake authentication signatures.
# Roles are strictly separated to prevent cross-role reflection / signature substitution attacks.
# Note: liboqs C API does not expose the FIPS 204 context (ctx) parameter in OQS_SIG_sign,
# so unambiguous length-delimited prefix domain separation is applied directly to the message.
DOMAIN_SEP_SIG_RESP = b"ST2027-Noise-XXhfs-MLDSA87-v1-Responder\x00"
DOMAIN_SEP_SIG_INIT = b"ST2027-Noise-XXhfs-MLDSA87-v1-Initiator\x00"
# Backward-compatibility alias
DOMAIN_SEP_SIG = DOMAIN_SEP_SIG_RESP

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


def _zero(b: bytearray) -> None:
    """Explicitly zeroizes a mutable bytearray buffer in-place."""
    if b is not None and isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0


def _lock_buffer(buf: bytearray) -> bool:
    """Best-effort page lock (VirtualLock/mlock) to prevent secret swapping."""
    if not buf or not isinstance(buf, (bytearray, memoryview)):
        return False
    try:
        import ctypes as _ct
        import sys as _sys
        addr = _ct.addressof((_ct.c_char * len(buf)).from_buffer(buf))
        if _sys.platform == "win32":
            return bool(_ct.windll.kernel32.VirtualLock(_ct.c_void_p(addr), _ct.c_size_t(len(buf))))
        else:
            libc = _ct.CDLL(None)
            return bool(libc.mlock(_ct.c_void_p(addr), _ct.c_size_t(len(buf))) == 0)
    except Exception:
        return False


def _unlock_buffer(buf: bytearray) -> None:
    """Best-effort unlock before wipe."""
    if not buf or not isinstance(buf, (bytearray, memoryview)):
        return
    try:
        import ctypes as _ct
        import sys as _sys
        addr = _ct.addressof((_ct.c_char * len(buf)).from_buffer(buf))
        if _sys.platform == "win32":
            _ct.windll.kernel32.VirtualUnlock(_ct.c_void_p(addr), _ct.c_size_t(len(buf)))
        else:
            libc = _ct.CDLL(None)
            libc.munlock(_ct.c_void_p(addr), _ct.c_size_t(len(buf)))
    except Exception:
        pass



class SymmetricState:
    """Noise SymmetricState with SHA-384 / AES-256-GCM (spec section 5)."""

    def __init__(self, protocol_name: bytes = PROTOCOL_NAME) -> None:
        if len(protocol_name) <= HASHLEN:
            self.h = protocol_name + b"\x00" * (HASHLEN - len(protocol_name))
        else:
            self.h = hashlib.sha384(protocol_name).digest()
        self.ck = self.h
        self._key: Optional[bytearray] = None
        self._n = 0

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.sha384(self.h + data).digest()

    def mix_key(self, ikm: bytes) -> None:
        ck, temp_k = _noise_hkdf(self.ck, ikm, 2)
        self.ck = ck
        # CNSA cipher keys are 256-bit; temp_k is 48B (SHA-384 output).
        # Store as mutable bytearray so destroy() can wipe it in place.
        if self._key is not None:
            _unlock_buffer(self._key)
            _zero(self._key)
        self._key = bytearray(temp_k[:32])
        _lock_buffer(self._key)
        self._n = 0

    def mix_key_and_hash(self, ikm: bytes) -> None:
        ck, temp_h, temp_k = _noise_hkdf(self.ck, ikm, 3)
        self.ck = ck
        self.mix_hash(temp_h)
        if self._key is not None:
            _unlock_buffer(self._key)
            _zero(self._key)
        self._key = bytearray(temp_k[:32])
        _lock_buffer(self._key)
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
        # Noise spec section 5.2: (temp_k1, temp_k2) = HKDF(ck, zerolen, 2)
        k1, k2 = _noise_hkdf(self.ck, b"", 2)
        return ((k1[:32], k2[:32])), self.h

    def destroy(self) -> None:
        # In-place memory scrubbing of mutable cipher key buffer
        if self._key is not None:
            _unlock_buffer(self._key)
            _zero(self._key)
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
    try:
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), pub_bytes)
        ss = priv.exchange(ec.ECDH(), peer)
    except Exception as exc:
        raise NoiseError(f"P-384 curve point validation failure: {exc}") from exc
    if len(ss) != P384_SS:
        raise NoiseError("ECDH violation")
    return ss


def _mlkem_keygen() -> Tuple[bytes, bytes]:
    from liboqs_wrapper import LibOQS_MLKEM_1024
    pk, sk = LibOQS_MLKEM_1024().keygen()
    if len(pk) != MLKEM_EK:
        raise NoiseError("ML-KEM-1024 size violation")
    sk_buf = bytearray(sk)
    _lock_buffer(sk_buf)
    return pk, sk_buf


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


def _sign(sk: bytes, msg: bytes, *, is_initiator: bool = False) -> bytes:
    from liboqs_wrapper import LibOQS_MLDSA_87
    domain = DOMAIN_SEP_SIG_INIT if is_initiator else DOMAIN_SEP_SIG_RESP
    return LibOQS_MLDSA_87().sign(sk, domain + msg)


def _verify(pk: bytes, msg: bytes, sig: bytes, *, is_initiator: bool = False) -> None:
    from liboqs_wrapper import LibOQS_MLDSA_87
    domain = DOMAIN_SEP_SIG_INIT if is_initiator else DOMAIN_SEP_SIG_RESP
    if not LibOQS_MLDSA_87().verify(pk, domain + msg, sig):
        raise NoiseError("identity signature invalid")


@dataclass
class NoiseSession:
    is_initiator: bool
    sig_pk: bytes
    sig_sk: bytes
    psk: Optional[bytes] = None
    sym: Optional[SymmetricState] = field(default=None)
    _e_priv: Optional[object] = field(default=None, repr=False)
    _e_pub: Optional[bytes] = field(default=None, repr=False)
    _f_sk: Optional[bytearray] = field(default=None, repr=False)  # ML-KEM dk (initiator)
    _f_ss: Optional[bytearray] = field(default=None, repr=False)  # KEM ss (responder)
    _peer_sig_pk: Optional[bytes] = field(default=None, repr=False)
    _k_send: Optional[bytearray] = field(default=None, repr=False)
    _k_recv: Optional[bytearray] = field(default=None, repr=False)
    _send_n: int = 0
    _m3_done: bool = False  # M3 emitted (initiator) / processed (responder)
    _recv_win_base: int = 0
    _recv_win_bits: int = 0
    _recv_started: bool = False
    handshake_hash: Optional[bytes] = None

    def __post_init__(self) -> None:
        if self.psk is not None:
            if not isinstance(self.psk, (bytes, bytearray)) or len(self.psk) != PSK_LEN:
                raise NoiseError(f"PSK parameter violation: expected exactly {PSK_LEN} bytes, got {len(self.psk) if hasattr(self.psk, '__len__') else type(self.psk)}")
            if self.sym is None:
                self.sym = SymmetricState(PROTOCOL_NAME_PSK2)
        else:
            if self.sym is None:
                self.sym = SymmetricState(PROTOCOL_NAME)

    def destroy(self) -> None:
        # Best-effort container sanitization for mutable bytearrays and page-locked buffers.
        if self._f_sk is not None:
            _unlock_buffer(self._f_sk)
            _zero(self._f_sk)
            self._f_sk = None
        if self._f_ss is not None:
            _unlock_buffer(self._f_ss)
            _zero(self._f_ss)
            self._f_ss = None
        if self._k_send is not None:
            _unlock_buffer(self._k_send)
            _zero(self._k_send)
            self._k_send = None
        if self._k_recv is not None:
            _unlock_buffer(self._k_recv)
            _zero(self._k_recv)
            self._k_recv = None
        if self.psk is not None:
            if isinstance(self.psk, bytearray):
                _unlock_buffer(self.psk)
                _zero(self.psk)
            self.psk = None
        if self.sym is not None:
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
    the session's software sig_sk signs (lab path). Responder role binds DOMAIN_SEP_SIG_RESP.
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
    ml_ct, ml_ss_raw = _mlkem_encaps(ek_cli)
    ml_ss = bytearray(ml_ss_raw)
    sess._f_ss = ml_ss
    sess.sym.mix_hash(ml_ct)
    dh_secret = bytearray(_p384_dh(sess._e_priv, e_cli))
    sess.sym.mix_key(dh_secret)                        # ee
    _zero(dh_secret)
    sess.sym.mix_key(ml_ss)                            # ff
    enc_pk = sess.sym.encrypt_and_hash(sess.sig_pk)    # s (encrypted)
    h_for_sig = bytes(sess.sym.h)
    sig = signer(h_for_sig) if signer is not None else _sign(sess.sig_sk, h_for_sig, is_initiator=False)  # es->sig over h
    enc_sig = sess.sym.encrypt_and_hash(sig)
    if sess.psk is not None:
        sess.sym.mix_key_and_hash(bytes(sess.psk))
    return e_pub + ml_ct + enc_pk + enc_sig


def initiator_finish(
    sess: NoiseSession,
    m2: bytes,
    expected_peer_pk: Optional[bytes] = None,
    *,
    allow_unpinned: bool = False,
) -> None:
    """Process M2: complete ee/ff, decrypt s, VERIFY sig_r BEFORE derive.

    Fail-closed identity pinning: expected_peer_pk is required by default.
    To connect to an arbitrary unpinned peer, allow_unpinned=True must be explicitly set.
    """
    if expected_peer_pk is None and not allow_unpinned:
        raise NoiseError("unpinned peer identity rejected: expected_peer_pk required (or set allow_unpinned=True)")
    if not sess.is_initiator or sess._f_sk is None or sess.handshake_hash is not None:
        raise NoiseError("handshake state violation")
    if len(m2) != EXPECTED_M2_LEN:
        raise NoiseError(f"M2 exact length violation: expected {EXPECTED_M2_LEN}, got {len(m2)}")
    e_srv, rest = m2[:P384_PUB], m2[P384_PUB:]
    ml_ct, rest = rest[:MLKEM_CT], rest[MLKEM_CT:]
    sess.sym.mix_hash(e_srv)
    sess.sym.mix_hash(ml_ct)
    dh_secret = bytearray(_p384_dh(sess._e_priv, e_srv))
    sess.sym.mix_key(dh_secret)                         # ee
    _zero(dh_secret)
    ml_ss = bytearray(_mlkem_decaps(sess._f_sk, ml_ct)) # ff
    _unlock_buffer(sess._f_sk)
    _zero(sess._f_sk)
    sess._f_sk = None
    sess.sym.mix_key(ml_ss)
    _zero(ml_ss)
    # Split enc_pk (2592 + 16 tag) from enc_sig (rest).
    from liboqs_wrapper import LibOQS_MLDSA_87  # noqa: F401 (sizes below)
    enc_pk, enc_sig = rest[:2592 + 16], rest[2592 + 16:]
    srv_pk = sess.sym.decrypt_and_hash(enc_pk)
    h_for_verify = sess.sym.h  # transcript THROUGH the signed message's
    srv_sig = sess.sym.decrypt_and_hash(enc_sig)
    _verify(srv_pk, h_for_verify, srv_sig, is_initiator=False)   # verify-before-derive (responder role)
    if expected_peer_pk is not None and srv_pk != expected_peer_pk:
        raise NoiseError("peer identity mismatch (pinned ML-DSA-87 key rejected)")
    sess._peer_sig_pk = srv_pk
    if sess.psk is not None:
        sess.sym.mix_key_and_hash(bytes(sess.psk))


def initiator_complete(sess: NoiseSession, signer=None) -> bytes:
    """M3: -> s, se(sig). Returns message; transport keys NOT yet split.

    signer: optional callable(msg)->sig for HSM-held identities.
    Exactly one M3 per session (handshake-cipher nonce reuse = forgery).
    Initiator role binds DOMAIN_SEP_SIG_INIT.
    """
    if not sess.is_initiator or sess._peer_sig_pk is None \
            or sess._m3_done or sess.handshake_hash is not None:
        raise NoiseError("handshake state violation")
    enc_pk = sess.sym.encrypt_and_hash(sess.sig_pk)
    h_for_sig = bytes(sess.sym.h)
    sig = signer(h_for_sig) if signer is not None else _sign(sess.sig_sk, h_for_sig, is_initiator=True)
    out = enc_pk + sess.sym.encrypt_and_hash(sig)
    sess._m3_done = True  # exactly one M3 per session (nonce reuse = forgery)
    return out


def responder_complete(
    sess: NoiseSession,
    m3: bytes,
    expected_peer_pk: Optional[bytes] = None,
    *,
    allow_unpinned: bool = False,
) -> None:
    """Process M3: decrypt s, VERIFY sig_i BEFORE Split.

    Fail-closed identity pinning: expected_peer_pk is required by default.
    To accept an arbitrary unpinned peer, allow_unpinned=True must be explicitly set.
    """
    if expected_peer_pk is None and not allow_unpinned:
        raise NoiseError("unpinned peer identity rejected: expected_peer_pk required (or set allow_unpinned=True)")
    if sess.is_initiator or sess._f_ss is None or sess._m3_done \
            or sess.handshake_hash is not None:
        raise NoiseError("handshake state violation")
    if len(m3) != EXPECTED_M3_LEN:
        raise NoiseError(f"M3 exact length violation: expected {EXPECTED_M3_LEN}, got {len(m3)}")
    enc_pk, enc_sig = m3[:2592 + 16], m3[2592 + 16:]
    cli_pk = sess.sym.decrypt_and_hash(enc_pk)
    h_for_verify = sess.sym.h  # transcript through the signed message
    cli_sig = sess.sym.decrypt_and_hash(enc_sig)
    _verify(cli_pk, h_for_verify, cli_sig, is_initiator=True)   # verify-before-derive (initiator role)
    if expected_peer_pk is not None and cli_pk != expected_peer_pk:
        raise NoiseError("peer identity mismatch (pinned ML-DSA-87 key rejected)")
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
    sess._k_send, sess._k_recv = bytearray(k_send), bytearray(k_recv)  # transport keys only survive
    _lock_buffer(sess._k_send)
    _lock_buffer(sess._k_recv)
    return k_send, k_recv, h


def derive_shared_frame_key(sess: NoiseSession) -> bytes:
    """Derive unified 32-byte shared frame key for DestroyerNode / rust_data_plane.

    Both initiator and responder derive the bit-identical frame key bound to the
    cryptographic transcript hash `h` and crossed session keys.
    """
    if sess.handshake_hash is None or sess._k_send is None or sess._k_recv is None:
        raise NoiseError("session must be split before deriving frame key")
    k1 = bytes(sess._k_send) if sess.is_initiator else bytes(sess._k_recv)
    k2 = bytes(sess._k_recv) if sess.is_initiator else bytes(sess._k_send)
    frame_key = hmac.new(sess.handshake_hash, k1 + k2 + b"ST2027-Rust-DataPlane-SharedFrameKey", hashlib.sha384).digest()[:32]
    return frame_key


def derive_double_ratchet_root(sess: NoiseSession) -> Tuple[bytes, bytes]:
    """Derive (root_key, transcript_h) to initialize DoubleRatchet root key.

    Returns:
        root_key: 32-byte symmetric root key for Double Ratchet initialization
        h: 48-byte transcript hash for channel binding / authentication
    """
    if sess.handshake_hash is None or sess._k_send is None or sess._k_recv is None:
        raise NoiseError("session must be split before deriving DoubleRatchet root")
    k1 = bytes(sess._k_send) if sess.is_initiator else bytes(sess._k_recv)
    k2 = bytes(sess._k_recv) if sess.is_initiator else bytes(sess._k_send)
    root_key = hmac.new(sess.handshake_hash, k1 + k2 + b"ST2027-DoubleRatchet-RootKey", hashlib.sha384).digest()[:32]
    return root_key, sess.handshake_hash


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


class StatelessCookieGate:
    """
    Stateless Anti-Amplification & Anti-DoS Cookie Gate (RFC 9000 / WireGuard style).

    Protects Noise_XXhfs responders from CPU exhaustion and reflection attacks:
    1. M1 is 1,665 bytes while M2 is 8,916 bytes (a 5.35x amplification factor).
    2. Generating M2 requires P-384 ECDH keygen, ML-KEM encapsulation, and ML-DSA-87 signature (~4-5ms CPU).
    3. StatelessCookieGate validates sender address return-routability before any asymmetric crypto is computed.
    4. Optional micro-Proof-of-Work (PoW) challenge dynamically scales under high ingress load.
    """
    MAGIC = b"NPQC1\x00"
    ROTATION_INTERVAL = 120  # Epoch interval in seconds

    def __init__(self, rotation_interval: int = ROTATION_INTERVAL, max_cached_solutions: int = 8192) -> None:
        self.rotation_interval = max(10, rotation_interval)
        self._curr_secret: bytes = secrets.token_bytes(32)
        self._prev_secret: bytes = self._curr_secret
        self._last_rotation: float = time.monotonic()
        self._seen_solutions: collections.OrderedDict[bytes, float] = collections.OrderedDict()
        self.max_cached_solutions = max_cached_solutions

    def _maybe_rotate(self) -> None:
        now = time.monotonic()
        if now - self._last_rotation >= self.rotation_interval:
            self._prev_secret = self._curr_secret
            self._curr_secret = secrets.token_bytes(32)
            self._last_rotation = now
            # Prune solutions older than 2 * rotation_interval to prevent memory growth
            cutoff = now - (2 * self.rotation_interval)
            expired = [k for k, t in self._seen_solutions.items() if t < cutoff]
            for k in expired:
                del self._seen_solutions[k]

    def _epoch(self) -> int:
        return int(time.time()) // self.rotation_interval

    def _compute_mac(self, secret: bytes, client_ip: str, client_port: int, m1_prefix: bytes, epoch: int) -> bytes:
        data = (
            client_ip.encode("ascii", "replace")
            + struct.pack(">H", client_port & 0xFFFF)
            + m1_prefix[:64]
            + struct.pack(">Q", epoch)
        )
        return hmac.new(secret, data, hashlib.sha384).digest()[:24]

    def create_cookie(self, client_ip: str, client_port: int, m1_prefix: bytes) -> bytes:
        """Create a stateless 38-byte cookie encoding address and M1 binding."""
        self._maybe_rotate()
        epoch = self._epoch()
        mac = self._compute_mac(self._curr_secret, client_ip, client_port, m1_prefix, epoch)
        return self.MAGIC + struct.pack(">Q", epoch) + mac

    def verify_cookie(self, cookie: bytes, client_ip: str, client_port: int, m1_prefix: bytes) -> bool:
        """Verify an address-bound cookie against active epoch keys."""
        expected_len = len(self.MAGIC) + 8 + 24
        if not cookie or len(cookie) != expected_len:
            return False
        if not hmac.compare_digest(cookie[:len(self.MAGIC)], self.MAGIC):
            return False
        epoch = struct.unpack(">Q", cookie[len(self.MAGIC):len(self.MAGIC) + 8])[0]
        mac = cookie[len(self.MAGIC) + 8:]
        curr_epoch = self._epoch()
        if abs(epoch - curr_epoch) > 1:
            return False
        self._maybe_rotate()
        for secret in (self._curr_secret, self._prev_secret):
            expected = self._compute_mac(secret, client_ip, client_port, m1_prefix, epoch)
            if hmac.compare_digest(mac, expected):
                return True
        return False

    def create_challenge(self, client_ip: str, client_port: int, m1_prefix: bytes, difficulty_bits: int = 0) -> bytes:
        """Create a cookie challenge packet (optionally requesting micro-PoW)."""
        diff = max(0, min(difficulty_bits, 32))
        cookie = self.create_cookie(client_ip, client_port, m1_prefix)
        return b"NPQ_CHALLENGE\x00" + bytes([diff]) + cookie

    def verify_response(
        self,
        response: bytes,
        client_ip: str,
        client_port: int,
        m1_prefix: bytes,
        difficulty_bits: int = 0,
    ) -> bool:
        """Verify client challenge response containing cookie + 8-byte PoW nonce."""
        # Single-use enforcement: check for solution replay
        if response in self._seen_solutions:
            return False

        cookie_len = len(self.MAGIC) + 8 + 24
        if len(response) != cookie_len + 8:
            return False
        cookie, nonce_bytes = response[:cookie_len], response[cookie_len:]
        if not self.verify_cookie(cookie, client_ip, client_port, m1_prefix):
            return False
        if difficulty_bits > 0:
            h = hashlib.sha256(cookie + nonce_bytes).digest()
            val = int.from_bytes(h, "big")
            target = 1 << (256 - difficulty_bits)
            if val >= target:
                return False

        # Mark solution as consumed (one-time-use)
        self._seen_solutions[response] = time.monotonic()
        if len(self._seen_solutions) > self.max_cached_solutions:
            self._seen_solutions.popitem(last=False)
        return True

    def reset_replay_cache(self) -> None:
        """Clear single-use challenge solution cache (testing / maintenance)."""
        self._seen_solutions.clear()

    @staticmethod
    def solve_challenge(challenge_payload: bytes, max_iterations: int = 2_000_000) -> Optional[bytes]:
        """Client-side solver for cookie + micro-PoW challenge."""
        prefix = b"NPQ_CHALLENGE\x00"
        if not challenge_payload.startswith(prefix) or len(challenge_payload) < len(prefix) + 1:
            return None
        difficulty_bits = challenge_payload[len(prefix)]
        cookie = challenge_payload[len(prefix) + 1:]
        if difficulty_bits == 0:
            return cookie + struct.pack(">Q", 0)
        target = 1 << (256 - difficulty_bits)
        for nonce in range(max_iterations):
            nb = struct.pack(">Q", nonce)
            h = hashlib.sha256(cookie + nb).digest()
            if int.from_bytes(h, "big") < target:
                return cookie + nb
        return None

    def process_incoming_m1(
        self,
        wire: bytes,
        client_ip: str,
        client_port: int,
        require_cookie: bool = False,
        difficulty_bits: int = 0,
    ) -> Tuple[str, bytes]:
        """
        Ingress filter for incoming M1 frames over connectionless transport.
        Returns:
            ("ACCEPT", m1_bytes) — proceed to responder_reply
            ("CHALLENGE", challenge_packet) — transmit challenge back to client
            ("DROP", b"") — invalid, oversize, or spoofed; drop silently
        """
        solution, m1 = unpack_cookie_m1(wire)
        if len(m1) != EXPECTED_M1_LEN:
            return ("DROP", b"")
        if not require_cookie and solution is None:
            return ("ACCEPT", m1)
        if solution is None:
            challenge = self.create_challenge(client_ip, client_port, m1[:64], difficulty_bits)
            return ("CHALLENGE", challenge)
        if self.verify_response(solution, client_ip, client_port, m1[:64], difficulty_bits):
            return ("ACCEPT", m1)
        return ("DROP", b"")

    @staticmethod
    def client_handle_challenge(challenge_wire: bytes, m1: bytes) -> Optional[bytes]:
        """
        Client-side response to an incoming challenge packet: solves challenge
        and returns the cookie-wrapped M1 frame ready for retransmission.
        """
        solution = StatelessCookieGate.solve_challenge(challenge_wire)
        if solution is None:
            return None
        return pack_cookie_m1(solution, m1)


COOKIE_M1_PREFIX = b"NPQK1\x00"


def pack_cookie_m1(cookie_solution: bytes, m1: bytes) -> bytes:
    """Pack an address-verified cookie solution prefix onto an M1 handshake frame."""
    return COOKIE_M1_PREFIX + struct.pack(">H", len(cookie_solution)) + cookie_solution + m1


def unpack_cookie_m1(wire: bytes) -> Tuple[Optional[bytes], bytes]:
    """Unpack wire payload into (cookie_solution_or_None, m1_bytes)."""
    if wire.startswith(COOKIE_M1_PREFIX) and len(wire) > len(COOKIE_M1_PREFIX) + 2:
        off = len(COOKIE_M1_PREFIX)
        clen = struct.unpack(">H", wire[off:off+2])[0]
        off += 2
        if len(wire) >= off + clen:
            solution = wire[off:off+clen]
            m1 = wire[off+clen:]
            return solution, m1
    return None, wire


