"""PQXDH combiner v2 Known-Answer / property tests (pure function, no network).

Covers crypto.kem.hybrid_combine_v2:
  - determinism: identical inputs -> identical 32-byte output
  - tamper sensitivity: single flipped byte in the CT portion of the
    transcript -> different derived key
  - tamper sensitivity: single flipped byte in a DH share -> different key
  - input framing: ambiguous splits without length-prefixing would collide;
    here distinct splits must give distinct keys

Run: pytest test_pqxdh_combiner_v2_kat.py -v  (or: python test_pqxdh_combiner_v2_kat.py)
"""

import os
import sys

import pytest

try:
    from crypto.kem import hybrid_combine_v2  # repo-root layout
except ImportError:  # fallback: load crypto/kem.py directly by path
    import importlib.util as _ilu

    _HERE = os.path.dirname(os.path.abspath(__file__))
    _CANDIDATES = [
        os.path.join(_HERE, "crypto", "kem.py"),
        os.path.join(_HERE, "secure_p2p_core", "crypto", "kem.py"),
    ]
    hybrid_combine_v2 = None
    for _p in _CANDIDATES:
        if os.path.exists(_p):
            _spec = _ilu.spec_from_file_location("securep2p_crypto_kem_kat", _p)
            _mod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            hybrid_combine_v2 = _mod.hybrid_combine_v2
            break
    if hybrid_combine_v2 is None:
        raise


def _fixed_inputs():
    """Deterministic synthetic vectors (NOT real key material, no network)."""
    dh1 = bytes([0x11]) * 32
    dh2 = bytes([0x22]) * 32
    dh3 = bytes([0x33]) * 32
    dh4 = bytes([0x44]) * 32
    ss_hybrid = bytes([0x55]) * 48  # matches liboqs_wrapper 48B hybrid ss
    ct = bytes(range(64))  # synthetic ciphertext bytes (tamper target)
    transcript = (
        b"initiator-alice" + b"responder-bob" + b"initiator-first"
        + b"\x00" + ct + b"opk-flag-test"
    )
    return [dh1, dh2, dh3, dh4], ss_hybrid, transcript, ct


def test_v2_determinism_and_length():
    dh_list, ss_hybrid, transcript, _ct = _fixed_inputs()
    sk1 = hybrid_combine_v2(dh_list, ss_hybrid, transcript)
    sk2 = hybrid_combine_v2(list(dh_list), bytes(ss_hybrid), bytes(transcript))
    assert isinstance(sk1, bytes) and isinstance(sk2, bytes)  # nosec: B101
    assert len(sk1) == 32  # nosec: B101
    assert sk1 == sk2  # pure function: same inputs -> same key  # nosec: B101


def test_v2_ct_byte_flip_changes_key():
    """Flip one byte of the CT inside the transcript -> different SK."""
    dh_list, ss_hybrid, transcript, ct = _fixed_inputs()
    sk_good = hybrid_combine_v2(dh_list, ss_hybrid, transcript)
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0x01
    tampered_transcript = transcript.replace(bytes(ct), bytes(tampered_ct))
    assert tampered_transcript != transcript  # nosec: B101
    sk_bad = hybrid_combine_v2(dh_list, ss_hybrid, tampered_transcript)
    assert len(sk_bad) == 32  # nosec: B101
    assert sk_bad != sk_good  # nosec: B101


def test_v2_dh_byte_flip_changes_key():
    dh_list, ss_hybrid, transcript, _ct = _fixed_inputs()
    sk_good = hybrid_combine_v2(dh_list, ss_hybrid, transcript)
    bad_dh = bytearray(dh_list[0])
    bad_dh[-1] ^= 0xFF
    sk_bad = hybrid_combine_v2([bytes(bad_dh)] + dh_list[1:], ss_hybrid, transcript)
    assert sk_bad != sk_good  # nosec: B101


def test_v2_framing_split_sensitivity():
    """Length-prefixing must distinguish ('ab','c') from ('a','bc')."""
    t = b"fixed-transcript"
    sk1 = hybrid_combine_v2([b"ab", b"c", b"d", b"e"], b"ss", t)
    sk2 = hybrid_combine_v2([b"a", b"bc", b"d", b"e"], b"ss", t)
    assert sk1 != sk2  # nosec: B101


def test_v2_rejects_bad_inputs():
    dh_list, ss_hybrid, transcript, _ct = _fixed_inputs()
    with pytest.raises(ValueError):
        hybrid_combine_v2(dh_list[:3], ss_hybrid, transcript)  # not 4 DHs
    with pytest.raises(ValueError):
        hybrid_combine_v2(dh_list, b"", transcript)  # empty ss
    with pytest.raises(ValueError):
        hybrid_combine_v2(dh_list, ss_hybrid, b"")  # empty transcript
    with pytest.raises(TypeError):
        hybrid_combine_v2(dh_list, ss_hybrid, "not-bytes")  # type error


if __name__ == "__main__":
    _dh, _ss, _t, _ct = _fixed_inputs()
    _a = hybrid_combine_v2(_dh, _ss, _t)
    _b = hybrid_combine_v2(list(_dh), bytes(_ss), bytes(_t))
    assert _a == _b and len(_a) == 32, "determinism check failed"  # nosec: B101
    _tampered = _t.replace(bytes(_ct), bytes(bytearray([_ct[0] ^ 0x01]) + _ct[1:]))
    _c = hybrid_combine_v2(_dh, _ss, _tampered)
    assert _c != _a, "tamper check failed (ct flip must change SK)"  # nosec: B101
    print(f"PQXDH v2 KAT self-check OK: sk={_a.hex()[:32]}... tamper_diverges=True")

