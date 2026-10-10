#!/usr/bin/env python3
"""Live cross-implementation interop: Python reference <-> Rust secure core.

This is the strongest verification in the repo: real randomness on both
sides, proving byte-identity of the Noise_XXhfs handshake, transport
framing, key schedule, ML-DSA signatures, and threshold-TBS encodings
across two independent implementations (OpenSSL/liboqs vs pure-Rust
p384/ml-kem/ml-dsa/aes-gcm).

Skipped when the compiled extension is absent (lab without `maturin build`)
or when liboqs is unavailable. NO existing module was modified for this file.

Proven here (both directions, initiator<->responder swapped):
  1. M1/M2/M3 lengths exact (1665/8916/7251) across implementations.
  2. Split keys agree crossed (Python k_send == Rust k_recv and vice versa).
  3. Transcript hashes agree bit-for-bit (KEM-binding coverage identical).
  4. Frame keys + ratchet roots agree (HKDF/HMAC schedules identical).
  5. Transport wires decrypt cross-implementation (AES-GCM nonce/AAD/keys).
  6. ML-DSA signatures verify cross-implementation BOTH ways
     (liboqs <-> ml-dsa crate) with role-separated domains.
  7. Threshold TBS/revocation encodings byte-identical; Rust-signed quorum
     verifies under Python `trust_anchor.verify_certificate`.
"""

import os
import time

import pytest

import rust_backend
from rust_backend import M1_LEN, M2_LEN, M3_LEN

native = pytest.importorskip(
    "destroyer_core._native", reason="Rust extension absent (maturin build required)")
liboqs = pytest.importorskip(
    "liboqs_wrapper", reason="liboqs unavailable on this runner")


def _mldsa_keypair():
    pk, sk = liboqs.LibOQS_MLDSA_87().keygen()
    assert len(pk) == 2592
    return pk, sk


def _run_handshake(py_initiator: bool):
    """One full handshake, Python on one side, Rust on the other."""
    import noise_pq

    pk_py, sk_py = _mldsa_keypair()
    if py_initiator:
        py = noise_pq.NoiseSession(True, pk_py, sk_py)
        ru = native.CoreHsResponder()
        m1 = noise_pq.initiator_hello(py)
        assert len(m1) == M1_LEN and m1[0] == 0x04
        m2 = ru.reply(bytes(m1))
        assert len(m2) == M2_LEN
        noise_pq.initiator_finish(py, bytes(m2), expected_peer_pk=bytes(ru.identity()))
        m3 = noise_pq.initiator_complete(py)
        assert len(m3) == M3_LEN
        ru.complete(bytes(m3), pk_py)
        rk_s, rk_r, rh = ru.split()
        ik_s, ik_r, ih = noise_pq.split_session(py)
    else:
        py = noise_pq.NoiseSession(False, pk_py, sk_py)
        ru = native.CoreHsInitiator()
        m1 = ru.hello()
        assert len(m1) == M1_LEN and m1[0] == 0x04
        m2 = noise_pq.responder_reply(py, bytes(m1))
        assert len(m2) == M2_LEN
        ru.finish(bytes(m2), pk_py)
        m3 = ru.complete()
        assert len(m3) == M3_LEN
        noise_pq.responder_complete(py, bytes(m3), expected_peer_pk=bytes(ru.identity()))
        rk_s, rk_r, rh = ru.split()
        ik_s, ik_r, ih = noise_pq.split_session(py)
    # Crossed agreement (initiator k_send == responder k_recv).
    if py_initiator:
        assert bytes(ik_s) == bytes(rk_r) and bytes(ik_r) == bytes(rk_s)
    else:
        assert bytes(ik_r) == bytes(rk_s) and bytes(ik_s) == bytes(rk_r)
    assert bytes(ih) == bytes(rh)
    return py, bytes(ik_s), bytes(ik_r), bytes(ih), bytes(rk_s), bytes(rk_r), bytes(rh)


def test_constants_match_rust_policy():
    assert (M1_LEN, M2_LEN, M3_LEN) == (1665, 8916, 7251)
    assert rust_backend.MLDSA87_PK == 2592 and rust_backend.TRANSCRIPT_LEN == 48


def test_handshake_py_initiator_rust_responder():
    py, ik_s, ik_r, ih, rk_s, rk_r, rh = _run_handshake(py_initiator=True)
    # Frame keys + ratchet roots agree across implementations.
    import noise_pq
    assert noise_pq.derive_shared_frame_key(py) == bytes(
        native.derive_frame_key(rk_s, rk_r, rh, False))
    assert noise_pq.derive_double_ratchet_root(py)[0] == bytes(
        native.derive_ratchet_root(rk_s, rk_r, rh, False)[0])


def test_handshake_rust_initiator_py_responder():
    py, ik_s, ik_r, ih, rk_s, rk_r, rh = _run_handshake(py_initiator=False)
    import noise_pq
    assert noise_pq.derive_shared_frame_key(py) == bytes(
        native.derive_frame_key(rk_s, rk_r, rh, True))
    assert noise_pq.derive_double_ratchet_root(py)[0] == bytes(
        native.derive_ratchet_root(rk_s, rk_r, rh, True)[0])


def test_transport_cross_decrypts_both_directions():
    import noise_pq

    py, ik_s, ik_r, ih, rk_s, rk_r, rh = _run_handshake(py_initiator=True)
    # Python -> Rust: Python seals with its k_send; Rust opens as responder.
    wire = noise_pq.transport_send(py, b"python-to-rust-probe")
    assert wire[:8] == (1).to_bytes(8, "big")  # seq starts at 1, both sides
    ru_rx = native.CoreTransport(rk_s, rk_r, False)
    assert bytes(ru_rx.recv(bytes(wire))) == b"python-to-rust-probe"
    # Rust -> Python: Rust seals AS RESPONDER (dir 0x5A, key rk_s == ik_r);
    # Python opens as initiator. Same-side sealing would be a reflection.
    ru_tx = native.CoreTransport(rk_s, rk_r, False)
    wire2 = bytes(ru_tx.send(b"rust-to-python-probe"))
    assert noise_pq.transport_recv(py, wire2) == b"rust-to-python-probe"
    # Tampered wire refused cross-implementation (tag gate, then replay
    # window unshifted: the next honest message still opens).
    bad = bytearray(ru_tx.send(b"tamper-me"))
    bad[-1] ^= 1
    with pytest.raises(Exception):
        noise_pq.transport_recv(py, bytes(bad))
    assert noise_pq.transport_recv(py, bytes(ru_tx.send(b"after-tamper"))) == b"after-tamper"


def test_threshold_tbs_interop_rust_signs_python_verifies():
    import trust_anchor
    from trust_anchor import CertTBS, Certificate, CertSig, Custodian

    labels = [f"custodian-{i}" for i in range(5)]
    signers = [native.CoreMldsaSigner() for _ in range(5)]
    vks = [bytes(s.verifying_bytes()) for s in signers]
    custodians = [Custodian(label=l, mldsa_pk=v) for l, v in zip(labels, vks)]
    subj = bytes(native.CoreMldsaSigner().verifying_bytes())
    serial = os.urandom(16)
    tbs = CertTBS(serial=serial, subject="node-interop",
                  subject_pk=subj, not_before=1_700_000_000,
                  not_after=1_700_000_000 + 3600)
    body_py = trust_anchor.tbs_bytes(tbs)
    body_rs = bytes(native.pki_tbs_bytes(serial, "node-interop", subj,
                                          1_700_000_000, 1_700_000_000 + 3600))
    assert body_py == body_rs  # canonical encoding byte-identical
    sigs = [CertSig(custodian=labels[i],
                    sig=bytes(signers[i].sign(b"", body_py))) for i in range(3)]
    cert = Certificate(tbs=tbs, sigs=sigs)
    back = trust_anchor.verify_certificate(cert, custodians, now=1_700_000_100.0)
    assert trust_anchor.tbs_bytes(back) == body_py
    # Revocation encoding byte-identical; Python-side verify accepts it.
    rev = trust_anchor.Revocation(serial=serial, reason="compromise",
                                  ts=1_700_000_200.0, seq=7)
    assert bytes(native.pki_revoke_bytes(serial, "compromise", 1_700_000_200.0, 7)) == \
        trust_anchor.revoke_bytes(rev)
    rev.sigs = [CertSig(custodian=labels[i],
                        sig=bytes(signers[i].sign(
                            b"", trust_anchor.revoke_bytes(rev)))) for i in range(3)]
    trust_anchor.verify_revocation(rev, custodians)
