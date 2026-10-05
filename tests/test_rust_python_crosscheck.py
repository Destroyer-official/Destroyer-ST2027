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


def _python_open(key: bytes, frame: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    header, ct = frame[:11], frame[11:]
    seq = struct.unpack(">Q", header[:8])[0]
    return AESGCM(key).decrypt(_nonce(seq), ct, header), header


def _python_seal(key: bytes, seq: int, ftype: int, padded: bytes,
                 true_len: int) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    header = struct.pack(">Q", seq) + struct.pack(">H", true_len) + bytes((ftype,))
    ct = AESGCM(key).encrypt(_nonce(seq), bytes(padded), header)
    return header + ct


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
    padded = msg + b"\x00" * (64 - len(msg))
    frame = _python_seal(key, 5, FTYPE_MSG, padded, len(msg))
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


def test_boundary_contract_pq_stays_python():
    # PQ primitives: present + size-pinned in the Python liboqs path.
    from liboqs_wrapper import LibOQS_MLDSA_87, LibOQS_MLKEM_1024
    kem = LibOQS_MLKEM_1024()
    assert (kem.pk_size, kem.ct_size, kem.ss_size) == (1568, 1568, 32)  # nosec: B101
    dsa = LibOQS_MLDSA_87()
    assert (dsa.pk_size, dsa.sk_size, dsa.sig_size) == (2592, 4896, 4627)  # nosec: B101
    from pathlib import Path
    repo = Path(__file__).resolve().parent
    if not (repo / "rust_data_plane").exists():
        repo = repo.parent
    root = repo / "rust_data_plane"
    cargo = open(root / "Cargo.toml", encoding="utf-8").read()
    for crate in ("ml-dsa", "dilithium", "falcon", "slh", "sphincs",
                  "ed25519", "ecdsa", "rsa", "p256", "p384"):
        assert crate not in cargo.lower(), f"sig crate in Rust deps: {crate}"  # nosec: B101
    import re
    token_re = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    hits = []
    for dirpath, _, files in os.walk(root / "src"):
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            tokens = set(token_re.findall(
                open(os.path.join(dirpath, fn), encoding="utf-8").read().lower()))
            bad = tokens & {"dilithium", "mldsa", "falcon", "sphincs",
                            "ed25519", "ecdsa"}
            if bad:
                hits.append((fn, sorted(bad)))
    assert not hits, f"signature symbols in Rust tree: {hits}"  # nosec: B101


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

