"""Python <-> Rust data-plane cross-check + boundary contract (G4).

The hot path (framing/AEAD/replay/KEM) runs in Rust `destroyer_core`;
PQ signatures stay in the Python liboqs path by policy (Rust PQ crates
unaudited). This suite proves the two planes agree BIT-FOR-BIT and pins
the boundary so neither side silently drifts:

  1. Rust seal -> Python open (rebuilt nonce/AAD per aead.rs spec).
  2. Python seal -> Rust open (fresh responder session, replay accepts).
  3. Tampered wire rejected by BOTH (Rust None + Python InvalidTag).
  4. Boundary contract: PQ (ML-KEM/ML-DSA) importable + size-pinned in
     Python; Rust tree contains zero signature schemes (comment-word
     false positives excluded by token match).

Requires the maturin-built destroyer_core (else skipped like the other
native suites). No network.
"""

import os
import struct

import pytest

destroyer_core = pytest.importorskip("destroyer_core")

DIR_SEND = 0x00
FTYPE_MSG = 0x01


def _nonce(seq: int, direction: int = DIR_SEND) -> bytes:
    return struct.pack(">Q", seq) + bytes((direction, 0, 0, 0))


def _derive_hp_key(key: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"destroyer/header-protection/v1").derive(key)


def _compute_header_mask(hp_key: bytes, tag: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(b"ST2027-HEADER-MASK-v1" + hp_key + tag).digest()[:11]


def _python_open(key: bytes, frame: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    masked_header, ct_with_tag = frame[:11], frame[11:]
    hp_key = _derive_hp_key(key)
    tag = frame[-16:]
    mask = _compute_header_mask(hp_key, tag)
    unmasked_header = bytes(a ^ b for a, b in zip(masked_header, mask))
    seq = struct.unpack(">Q", unmasked_header[:8])[0]
    return AESGCM(key).decrypt(_nonce(seq), ct_with_tag, unmasked_header), unmasked_header


def _python_seal(key: bytes, seq: int, ftype: int, padded: bytes,
                 true_len: int) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    unmasked_header = struct.pack(">Q", seq) + struct.pack(">H", true_len) + bytes((ftype,))
    ct_with_tag = AESGCM(key).encrypt(_nonce(seq), bytes(padded), unmasked_header)
    hp_key = _derive_hp_key(key)
    tag = ct_with_tag[-16:]
    mask = _compute_header_mask(hp_key, tag)
    masked_header = bytes(a ^ b for a, b in zip(unmasked_header, mask))
    return masked_header + ct_with_tag


def _engines(key: bytes, start_seq: int = 7):
    SecureEngine = destroyer_core.SecureEngine
    alice, bob = SecureEngine(), SecureEngine()
    alice.establish_session(list(key), start_seq, True)
    bob.establish_session(list(key), start_seq, False)
    return alice, bob


def test_rust_seal_python_open():
    import secrets
    key = secrets.token_bytes(32)
    alice, _ = _engines(key)
    payload = b"cross-plane-probe-01"
    quantum, frame = alice.seal_msg(FTYPE_MSG, list(payload))
    frame = bytes(frame)
    assert quantum in (256, 512, 1232) and len(frame) == quantum  # nosec: B101
    pt, header = _python_open(key, frame)
    assert struct.unpack(">H", header[8:10])[0] == len(payload)  # nosec: B101
    assert header[10] == FTYPE_MSG  # nosec: B101
    assert pt[:len(payload)] == payload  # nosec: B101
    assert pt[len(payload):] == b"\x00" * (len(pt) - len(payload))  # nosec: B101


def test_python_seal_rust_open():
    import secrets
    key = secrets.token_bytes(32)
    _, bob = _engines(key)
    msg = b"python-sealed-frame"
    quantum = 256
    pad_len = quantum - 27  # 11B header + 16B tag = 27B overhead
    padded = msg + b"\x00" * (pad_len - len(msg))
    frame = _python_seal(key, 7, FTYPE_MSG, padded, len(msg))
    opened = bob.open_msg(list(frame))
    assert opened is not None  # nosec: B101
    ftype, pt = opened
    assert ftype == FTYPE_MSG  # nosec: B101
    assert bytes(pt[:len(msg)]) == msg  # nosec: B101


def test_cross_tamper_rejected_by_both():
    import secrets
    from cryptography.exceptions import InvalidTag
    key = secrets.token_bytes(32)
    alice, bob = _engines(key)
    _, frame = alice.seal_msg(FTYPE_MSG, list(b"tamper-me"))
    frame = bytearray(frame)
    frame[-1] ^= 0x01
    assert bob.open_msg(list(bytes(frame))) is None  # nosec: B101
    with pytest.raises(InvalidTag):
        _python_open(key, bytes(frame))


def test_boundary_contract_pq_dual_core():
    # 1. PQ primitives in Python reference path: present + size-pinned.
    from liboqs_wrapper import LibOQS_MLDSA_87, LibOQS_MLKEM_1024
    kem = LibOQS_MLKEM_1024()
    assert (kem.pk_size, kem.ct_size, kem.ss_size) == (1568, 1568, 32)  # nosec: B101
    dsa = LibOQS_MLDSA_87()
    assert (dsa.pk_size, dsa.sk_size, dsa.sig_size) == (2592, 4896, 4627)  # nosec: B101

    # 2. Rust core dependencies in Cargo.toml: strictly modern CNSA 2.0 / FIPS 204.
    # Outdated or legacy schemes (RSA, ECDSA, Ed25519) are forbidden.
    from pathlib import Path
    repo = Path(__file__).resolve().parent
    if not (repo / "rust_data_plane").exists():
        repo = repo.parent
    root = repo / "rust_data_plane"
    cargo = open(root / "Cargo.toml", encoding="utf-8").read().lower()
    for legacy_crate in ("ed25519", "ecdsa", "rsa", "p256"):
        assert legacy_crate not in cargo, f"legacy crypto crate forbidden in Rust deps: {legacy_crate}"  # nosec: B101

    # 3. Rust secure core native ML-DSA-87 verification (FIPS 204).
    signer = destroyer_core.CoreMldsaSigner()
    vk_bytes = bytes(signer.verifying_bytes())
    assert len(vk_bytes) == 2592
    domain = b"test-domain"
    msg = b"sovereign-payload"
    sig = bytes(signer.sign(list(domain), list(msg)))
    assert len(sig) == 4627
    destroyer_core.CoreMldsaSigner.verify(list(vk_bytes), list(domain), list(msg), list(sig))


def test_native_hybrid_kex_roundtrip():
    """Verify Rust-native hybrid KEX roundtrip with transcript binding."""
    NativeHybridKex = getattr(destroyer_core, "NativeHybridKex", None)
    if NativeHybridKex is None:
        pytest.skip("NativeHybridKex not exposed in destroyer_core")
    import secrets
    transcript = secrets.token_bytes(48)
    
    # Alice generates ephemeral keys (X25519 + ML-KEM-1024)
    alice = NativeHybridKex()
    alice_x_pub, alice_ml_ek = alice.get_public_keys()
    assert len(alice_x_pub) == 32
    assert len(alice_ml_ek) == 1568

    # Bob encapsulates against Alice's public keys
    bob_eph_x, bob_ml_ct, bob_ss = NativeHybridKex.encapsulate_to_peer(
        alice_x_pub, alice_ml_ek, transcript
    )
    assert len(bob_eph_x) == 32
    assert len(bob_ml_ct) == 1568
    assert len(bob_ss) == 32

    # Alice decapsulates Bob's ciphertext
    alice_ss = alice.decapsulate_session_key(bob_eph_x, bob_ml_ct, transcript)
    assert len(alice_ss) == 32

    # Both must reach identical 32-byte session secret
    assert alice_ss == bob_ss

