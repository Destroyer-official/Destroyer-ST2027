#!/usr/bin/env python3
"""
crypto_selftest.py — FIPS 140-3-style power-up self-tests + conditional
tests + entropy-source policy for the TOP SECRET session path.

What this IS (all real, executed, fail-closed):
  POWER-UP KATs (FIPS 140-3 section 10 / ISO 19790 7.10 analogue):
    - AES-256-GCM: OpenSSL (cryptography) vs pycryptodome (independent
      codebases) — encrypt equality, tag verify, tamper rejection.
    - HKDF-SHA384: OpenSSL vs pycryptodome equality (32B record-key use).
    - SHA-384 / HMAC-SHA384: cross-implementation equality.
    - X25519: RFC 7748 Section 5.2 + Section 6.1 vectors (fetched live
      from rfc-editor.org during implementation; pinned below).
    - P-384 ECDH: OpenSSL vs pycryptodome shared-secret equality.
  CONDITIONAL TESTS (run per keygen/encaps at session start):
    - ML-KEM-1024 PCT: encaps -> decaps equality (real liboqs).
    - ML-DSA-87 PCT: sign -> verify true, tampered -> false.
  ENTROPY POLICY: session randomness must come from os.urandom/secrets
    (Windows: BCryptGenRandom CNG). check_no_weak_rng() statically refuses
    `random` module use in the TS session files; failure blocks sessions.

What this IS NOT: a CMVP certificate. Lab validation of the module build
(OpenSSL FIPS Provider #4985 family) stays an operator duty enforced by
ts_hw_layer.require_fips_module(). These self-tests are the software-
enforceable half: they prove the linked primitives behave correctly on
THIS host before any session key is derived. Any failure enters the error
state (SelfTestError) and no session may start.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("crypto_selftest")

REPO_ROOT = Path(__file__).resolve().parent


class SelfTestError(Exception):
    """Power-up or conditional self-test failure (error state, fail-closed)."""


_FAILED = False
_PASSED: Optional[Dict[str, str]] = None

# RFC 7748 Section 5.2 vector 1 + Section 6.1 DH test (pinned, verified).
X25519_VEC1_SCALAR = bytes.fromhex(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
X25519_VEC1_U = bytes.fromhex(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
X25519_VEC1_OUT = bytes.fromhex(
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
X25519_ALICE_PRIV = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
X25519_ALICE_PUB = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
X25519_BOB_PRIV = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
X25519_BOB_PUB = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
X25519_SHARED = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

# Fixed (non-secret) KAT material for the cross-implementation checks.
KAT_AES_KEY = bytes(range(32))
KAT_AES_NONCE = bytes(range(12))
KAT_AES_AAD = b"ST2027-KAT-AAD"
KAT_AES_PT = b"TOP-SECRET-KAT-RECORD-0123456789"
KAT_HKDF_IKM = bytes(range(80))          # 80B hybrid-secret shape
KAT_HKDF_SALT = bytes(range(32))
KAT_HKDF_INFO = b"ST2027-record-v1"


def _openssl_aesgcm_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ct = AESGCM(key).encrypt(nonce, pt, aad)
    return ct[:-16], ct[-16:]


def _pycryptodome_aesgcm_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes):
    from Crypto.Cipher import AES  # nosec B413 - pycryptodome vetted cross-check oracle
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    c.update(aad)
    return c.encrypt(pt), c.digest()


def _openssl_hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(algorithm=hashes.SHA384(), length=length,
                salt=salt, info=info).derive(ikm)


def _pycryptodome_hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    from Crypto.Protocol.KDF import HKDF  # nosec B413 - pycryptodome vetted cross-check oracle
    from Crypto.Hash import SHA384  # nosec B413 - pycryptodome vetted cross-check oracle
    return HKDF(ikm, length, salt, SHA384, 1, context=info)


def _kat_aes_gcm() -> str:
    ct1, tag1 = _openssl_aesgcm_encrypt(KAT_AES_KEY, KAT_AES_NONCE, KAT_AES_AAD, KAT_AES_PT)
    ct2, tag2 = _pycryptodome_aesgcm_encrypt(KAT_AES_KEY, KAT_AES_NONCE, KAT_AES_AAD, KAT_AES_PT)
    # Independent implementations must agree bit-for-bit (deterministic GCM).
    if not hmac.compare_digest(ct1, ct2) or not hmac.compare_digest(tag1, tag2):
        raise SelfTestError("AES-256-GCM cross-implementation mismatch")
    # Valid-path decrypt agrees on both (not just rejection agreement).
    if _openssl_aesgcm_decrypt(KAT_AES_KEY, KAT_AES_NONCE, KAT_AES_AAD, ct1, tag1) != KAT_AES_PT \
            or _pycryptodome_aesgcm_decrypt(KAT_AES_KEY, KAT_AES_NONCE, KAT_AES_AAD, ct2, tag2) != KAT_AES_PT:
        raise SelfTestError("AES-256-GCM valid-decrypt mismatch")
    # Tamper must fail closed on both.
    bad = bytearray(ct1)
    bad[0] ^= 0x01
    for fn in (_openssl_aesgcm_decrypt, _pycryptodome_aesgcm_decrypt):
        try:
            fn(KAT_AES_KEY, KAT_AES_NONCE, KAT_AES_AAD, bytes(bad), tag1)
            raise SelfTestError("AES-256-GCM accepted tampered ciphertext")
        except SelfTestError:
            raise
        except Exception:
            pass
    return f"aes256gcm-ok tag={tag1.hex()[:16]}.."


def _openssl_aesgcm_decrypt(key: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        return AESGCM(key).decrypt(nonce, ct + tag, aad)
    except Exception as e:
        raise ValueError(str(e))


def _pycryptodome_aesgcm_decrypt(key: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes:
    from Crypto.Cipher import AES  # nosec B413 - pycryptodome vetted cross-check oracle
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    c.update(aad)
    return c.decrypt_and_verify(ct, tag)


def _kat_hkdf_sha384() -> str:
    o1 = _openssl_hkdf(KAT_HKDF_IKM, KAT_HKDF_SALT, KAT_HKDF_INFO, 32)
    o2 = _pycryptodome_hkdf(KAT_HKDF_IKM, KAT_HKDF_SALT, KAT_HKDF_INFO, 32)
    if not hmac.compare_digest(o1, o2) or len(o1) != 32:
        raise SelfTestError("HKDF-SHA384 cross-implementation mismatch")
    # Domain separation: different info MUST differ.
    o3 = _openssl_hkdf(KAT_HKDF_IKM, KAT_HKDF_SALT, b"other-info", 32)
    if hmac.compare_digest(o1, o3):
        raise SelfTestError("HKDF-SHA384 domain separation failure")
    return f"hkdf384-ok {o1.hex()[:16]}.."


def _kat_hashes() -> str:
    from Crypto.Hash import SHA384 as P_SHA384, HMAC as P_HMAC  # nosec B413 - pycryptodome vetted cross-check oracle
    msg = b"ST2027-HASH-KAT" * 64
    if hashlib.sha384(msg).digest() != P_SHA384.new(msg).digest():
        raise SelfTestError("SHA-384 cross-implementation mismatch")
    if hmac.new(b"key", msg, hashlib.sha384).digest() != \
            P_HMAC.new(b"key", msg, digestmod=P_SHA384).digest():
        raise SelfTestError("HMAC-SHA384 cross-implementation mismatch")
    return "sha384-hmac-ok"


def _kat_x25519_rfc7748() -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives import serialization
    got = X25519PrivateKey.from_private_bytes(X25519_VEC1_SCALAR).exchange(
        X25519PublicKey.from_public_bytes(X25519_VEC1_U))
    if not hmac.compare_digest(got, X25519_VEC1_OUT):
        raise SelfTestError("X25519 RFC 7748 5.2 vector mismatch")
    alice = X25519PrivateKey.from_private_bytes(X25519_ALICE_PRIV)
    bob = X25519PrivateKey.from_private_bytes(X25519_BOB_PRIV)
    alice_pub = alice.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    bob_pub = bob.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not hmac.compare_digest(alice_pub, X25519_ALICE_PUB) or \
            not hmac.compare_digest(bob_pub, X25519_BOB_PUB):
        raise SelfTestError("X25519 RFC 7748 6.1 public-key mismatch")
    s1 = alice.exchange(X25519PublicKey.from_public_bytes(X25519_BOB_PUB))
    s2 = bob.exchange(X25519PublicKey.from_public_bytes(X25519_ALICE_PUB))
    if not hmac.compare_digest(s1, X25519_SHARED) or not hmac.compare_digest(s1, s2):
        raise SelfTestError("X25519 RFC 7748 6.1 shared-secret mismatch")
    return "x25519-rfc7748-ok"


def _kat_p384_ecdh() -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    from Crypto.PublicKey import ECC  # nosec B413 - pycryptodome vetted cross-check oracle
    a_priv = int.from_bytes(secrets.token_bytes(48), "big")
    b_priv = int.from_bytes(secrets.token_bytes(48), "big")
    a_ossl = ec.derive_private_key(a_priv, ec.SECP384R1())
    b_ossl = ec.derive_private_key(b_priv, ec.SECP384R1())
    s_ossl = a_ossl.exchange(ec.ECDH(), b_ossl.public_key())
    a_py = ECC.construct(curve="P-384", d=a_priv)
    b_py = ECC.construct(curve="P-384", d=b_priv)
    # Cross-check 1: public-key encodings agree on identical scalars.
    if a_py.public_key().pointQ.x != a_ossl.public_key().public_numbers().x \
            or a_py.public_key().pointQ.y != a_ossl.public_key().public_numbers().y:
        raise SelfTestError("P-384 public-key encoding mismatch")
    # Cross-check 2: the SHARED SECRET agrees bit-for-bit (the actual KAT).
    s_py = int((a_priv * b_py.public_key().pointQ).x).to_bytes(48, "big")
    if len(s_ossl) != 48 or not hmac.compare_digest(s_ossl, s_py):
        raise SelfTestError("P-384 ECDH cross-implementation mismatch")
    return "p384-ecdh-ok"


def _pct_mlkem() -> str:
    from liboqs_wrapper import LibOQS_MLKEM_1024
    kem = LibOQS_MLKEM_1024()
    pk, sk = kem.keygen()
    ct, ss1 = kem.encaps(pk)
    ss2 = kem.decaps(sk, ct)
    if not hmac.compare_digest(ss1, ss2) or len(ss1) != 32:
        raise SelfTestError("ML-KEM-1024 PCT failure")
    # Implicit rejection (FIPS 203 §7.3): decapsulating a forged
    # ciphertext must NOT return the real shared secret (it returns a
    # pseudorandom implicit-rejection value instead of erroring).
    bad = bytearray(ct)
    bad[0] ^= 0x01
    ss3 = kem.decaps(sk, bytes(bad))
    if hmac.compare_digest(ss1, ss3):
        raise SelfTestError("ML-KEM-1024 implicit rejection failure")
    return "mlkem1024-pct-ok"


def _pct_mldsa() -> str:
    from liboqs_wrapper import LibOQS_MLDSA_87
    sig = LibOQS_MLDSA_87()
    pk, sk = sig.keygen()
    msg = b"ST2027-PCT-" + secrets.token_bytes(32)
    s = sig.sign(sk, msg)
    if not sig.verify(pk, msg, s):
        raise SelfTestError("ML-DSA-87 PCT failure")
    bad = bytearray(s)
    bad[0] ^= 0x01
    if sig.verify(pk, msg, bytes(bad)):
        raise SelfTestError("ML-DSA-87 accepted forged signature")
    return "mldsa87-pct-ok"


# Files whose session path must never touch weak RNG or non-CNSA primitives.
TS_SESSION_FILES = ("secure_transmit_2027.py", "ts_hw_layer.py", "ts_runtime.py",
                    "ts_attest.py", "cng_platform.py", "noise_pq.py",
                    "crypto_selftest.py", "cnsa_purity.py")


def check_no_weak_rng(files: Optional[List[str]] = None) -> List[str]:
    """Static gate: `random` module MUST NOT appear in TS session files.

    secrets/os.urandom (Windows: BCryptGenRandom via CNG) is the only
    approved entropy interface. Returns checked files; raises on violation.
    """
    offenders = []
    for name in (files or list(TS_SESSION_FILES)):
        p = REPO_ROOT / name
        if not p.exists():
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            if re.search(r"(^|\W)(import\s+random|from\s+random\s+import|random\.)", code):
                offenders.append(f"{name}:{i}")
    if offenders:
        raise SelfTestError(f"weak RNG use in TS path: {offenders}")
    return list(files or list(TS_SESSION_FILES))


def check_entropy_source() -> str:
    """Runtime gate: os.urandom works, is non-repeating, and secrets rides it."""
    a = os.urandom(32)
    b = os.urandom(32)
    if a == b or len(set(a)) < 8:
        raise SelfTestError("os.urandom degenerate output")
    if secrets.token_bytes(32) == secrets.token_bytes(32):
        raise SelfTestError("secrets degenerate output")
    return "entropy-ok"


def run_powerup_selftests() -> Dict[str, str]:
    """Run the full power-up suite. Raises SelfTestError (error state)."""
    global _FAILED, _PASSED
    results = {
        "aes_gcm": _kat_aes_gcm(),
        "hkdf_sha384": _kat_hkdf_sha384(),
        "hashes": _kat_hashes(),
        "x25519": _kat_x25519_rfc7748(),
        "p384": _kat_p384_ecdh(),
        "mlkem_pct": _pct_mlkem(),
        "mldsa_pct": _pct_mldsa(),
        "entropy": check_entropy_source(),
    }
    check_no_weak_rng()
    results["weak_rng_scan"] = "clean"
    _FAILED = False
    _PASSED = results
    log.info("crypto self-tests green: %s", sorted(results))
    return results


def ensure_selftests() -> Dict[str, str]:
    """Cached gate for session preflight: run once per process, then reuse."""
    global _FAILED, _PASSED
    if _FAILED:
        raise SelfTestError("crypto module in error state (self-test failed)")
    if _PASSED is not None:
        return _PASSED
    try:
        return run_powerup_selftests()
    except SelfTestError:
        _FAILED = True
        raise
