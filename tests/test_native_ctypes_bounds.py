"""Native FFI input bounds (audit 6.2 / ctypes hardening).

Every buffer crossing into liboqs via ctypes is length-pinned BEFORE
from_buffer_copy: fixed sizes for keys/ciphertexts/signatures, an upper
bound on signatures (empty/oversize rejected pre-FFI), and an 8MB message
ceiling against native-side memory-exhaustion DoS.

Covers (ML-DSA-87, Falcon-1024, SLH-DSA-256f):
  1. Empty signature rejected (ValueError, no native call).
  2. Oversize signature (> sig_size) rejected pre-FFI.
  3. Oversize message (> 8MB) rejected pre-FFI in sign and verify.
  4. Wrong-size garbage signature returns False (verify path), not raise.
  5. Positive roundtrips still work (KAT guard against over-blocking).
"""

import pytest

from liboqs_wrapper import (
    LibOQS_Falcon_1024,
    LibOQS_MLDSA_87,
    LibOQS_SLH_DSA_256f,
    _NATIVE_MAX_MESSAGE_BYTES,
)

SIG_IMPLS = {
    "mldsa87": LibOQS_MLDSA_87,
    "falcon1024": LibOQS_Falcon_1024,
    "slhdsa256f": LibOQS_SLH_DSA_256f,
}


@pytest.mark.parametrize("name,cls", list(SIG_IMPLS.items()))
def test_empty_signature_rejected(name, cls):
    impl = cls()
    pk, _ = impl.keygen()
    with pytest.raises(ValueError):
        impl.verify(pk, b"msg", b"")


@pytest.mark.parametrize("name,cls", list(SIG_IMPLS.items()))
def test_oversize_signature_rejected_prefi(name, cls):
    impl = cls()
    pk, _ = impl.keygen()
    with pytest.raises(ValueError):
        impl.verify(pk, b"msg", b"\x00" * (impl.sig_size + 1))


@pytest.mark.parametrize("name,cls", list(SIG_IMPLS.items()))
def test_oversize_message_rejected_sign_and_verify(name, cls):
    impl = cls()
    pk, sk = impl.keygen()
    big = b"\x00" * (_NATIVE_MAX_MESSAGE_BYTES + 1)
    with pytest.raises(ValueError):
        impl.sign(sk, big)
    with pytest.raises(ValueError):
        impl.verify(pk, big, b"\x00" * 64)


@pytest.mark.parametrize("name,cls", list(SIG_IMPLS.items()))
def test_wrong_size_garbage_returns_false(name, cls):
    impl = cls()
    pk, _ = impl.keygen()
    # Right-sized garbage must fail verification (False), not raise.
    assert impl.verify(pk, b"message", b"\x00" * impl.sig_size) is False  # nosec: B101


@pytest.mark.parametrize("name,cls", list(SIG_IMPLS.items()))
def test_positive_roundtrip(name, cls):
    impl = cls()
    pk, sk = impl.keygen()
    msg = b"ctypes-bounds-kat-probe"
    sig = impl.sign(sk, msg)
    assert 1 <= len(sig) <= impl.sig_size  # nosec: B101
    assert impl.verify(pk, msg, sig) is True  # nosec: B101
    assert impl.verify(pk, msg + b"x", sig) is False  # nosec: B101

