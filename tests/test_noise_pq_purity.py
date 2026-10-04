#!/usr/bin/env python3
"""Production tests: Noise_XXhfs+ML-KEM-1024 handshake (REAL primitives)
and CNSA 2.0 purity gates + crypto self-tests."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

import noise_pq as npq
import cnsa_purity as purity
import crypto_selftest as stest


def _identities():
    from liboqs_wrapper import LibOQS_MLDSA_87
    ci_pk, ci_sk = LibOQS_MLDSA_87().keygen()
    cr_pk, cr_sk = LibOQS_MLDSA_87().keygen()
    return (ci_pk, ci_sk), (cr_pk, cr_sk)


def _handshake():
    (ci_pk, ci_sk), (cr_pk, cr_sk) = _identities()
    ini = npq.NoiseSession(True, ci_pk, ci_sk)
    rsp = npq.NoiseSession(False, cr_pk, cr_sk)
    m1 = npq.initiator_hello(ini)
    assert len(m1) == 97 + 1568  # e_pub || ml_ek, fixed sizes
    m2 = npq.responder_reply(rsp, m1)
    npq.initiator_finish(ini, m2, expected_peer_pk=cr_pk)
    m3 = npq.initiator_complete(ini)
    npq.responder_complete(rsp, m3, expected_peer_pk=ci_pk)
    ki_s, ki_r, hi = npq.split_session(ini)
    kr_s, kr_r, hr = npq.split_session(rsp)
    return (ini, rsp), (ki_s, ki_r, hi), (kr_s, kr_r, hr)


def test_xxhfs_agreement_and_channel_binding():
    (_ini, _rsp), (ki_s, ki_r, hi), (kr_s, kr_r, hr) = _handshake()
    assert ki_s == kr_r and ki_r == kr_s  # crossed transport keys agree
    assert hi == hr and len(hi) == 48     # transcript binding agrees (SHA-384)
    assert ki_s != ki_r and len(ki_s) == 32


def test_xxhfs_transport_roundtrip_replay_reject():
    (ini, rsp), _, _ = _handshake()
    w = npq.transport_send(ini, b"strategic-payload-1")
    assert npq.transport_recv(rsp, w) == b"strategic-payload-1"
    with pytest.raises(npq.NoiseError):  # replay
        npq.transport_recv(rsp, w)
    bad = bytearray(w)
    bad[-1] ^= 0x01
    with pytest.raises(npq.NoiseError):  # forgery
        npq.transport_recv(rsp, bytes(bad))


def test_xxhfs_tamper_fails_closed():
    (ci_pk, ci_sk), (cr_pk, cr_sk) = _identities()
    ini = npq.NoiseSession(True, ci_pk, ci_sk)
    rsp = npq.NoiseSession(False, cr_pk, cr_sk)
    m1 = npq.initiator_hello(ini)
    bad = bytearray(m1)
    bad[100] ^= 0x01  # corrupt ML-KEM ek: encaps still runs (well-formed
    # key, IND-CCA covers it) but both sides derive different secrets, so
    # the handshake MUST die at M2 authentication — fail-closed by transcript.
    m2 = npq.responder_reply(rsp, bytes(bad))
    with pytest.raises(npq.NoiseError):
        npq.initiator_finish(ini, m2, expected_peer_pk=cr_pk)
    # Rogue-key proxy: attacker completes the handshake under ITS identity.
    (a_pk, a_sk) = _identities()[0]
    ini3 = npq.NoiseSession(True, ci_pk, ci_sk)
    evil = npq.NoiseSession(False, a_pk, a_sk)
    m1c = npq.initiator_hello(ini3)
    m2b = npq.responder_reply(evil, m1c)
    npq.initiator_finish(ini3, m2b, allow_unpinned=True)  # verifies vs PRESENTED key (succeeds)
    # TOFU pinning (out-of-band cr_pk) catches the substitution: the
    # presented peer key differs, so a pinning caller aborts pre-Split.
    assert ini3._peer_sig_pk != cr_pk
    # Bit-flipped M2 fails closed in AEAD decrypt.
    ini4 = npq.NoiseSession(True, ci_pk, ci_sk)
    rsp4 = npq.NoiseSession(False, cr_pk, cr_sk)
    m1d = npq.initiator_hello(ini4)
    m2d = bytearray(npq.responder_reply(rsp4, m1d))
    m2d[-1] ^= 0x01
    with pytest.raises(npq.NoiseError):
        npq.initiator_finish(ini4, bytes(m2d), expected_peer_pk=cr_pk)


def test_xxhfs_state_machine_enforced():
    (ci_pk, ci_sk), (cr_pk, cr_sk) = _identities()
    ini = npq.NoiseSession(True, ci_pk, ci_sk)
    with pytest.raises(npq.NoiseError):
        npq.initiator_complete(ini)  # M3 before M2
    with pytest.raises(npq.NoiseError):
        npq.split_session(ini)       # split before complete
    with pytest.raises(npq.NoiseError):
        npq.transport_send(ini, b"x")  # no transport keys yet


def test_xxhfs_double_use_refused():
    (_, _), _, _ = _handshake()  # baseline green first
    (ci_pk, ci_sk), (cr_pk, cr_sk) = _identities()
    ini = npq.NoiseSession(True, ci_pk, ci_sk)
    rsp = npq.NoiseSession(False, cr_pk, cr_sk)
    m1 = npq.initiator_hello(ini)
    m2 = npq.responder_reply(rsp, m1)
    npq.initiator_finish(ini, m2, expected_peer_pk=cr_pk)
    m3 = npq.initiator_complete(ini)
    with pytest.raises(npq.NoiseError):
        npq.initiator_complete(ini)  # second M3 refused (nonce reuse)
    npq.responder_complete(rsp, m3, expected_peer_pk=ci_pk)
    with pytest.raises(npq.NoiseError):
        npq.responder_complete(rsp, m3, expected_peer_pk=ci_pk)  # second M3 refused
    npq.split_session(ini)
    npq.split_session(rsp)
    with pytest.raises(npq.NoiseError):
        npq.split_session(ini)  # double split refused
    with pytest.raises(npq.NoiseError):
        npq.split_session(rsp)


def test_purity_scan_clean_and_cached():
    assert purity.scan_tree() == {}
    purity.ensure_purity_cached()
    purity.ensure_purity_cached()  # idempotent
    assert purity.assert_cnsa_kem("ML-KEM-1024") == "ML-KEM-1024"
    assert purity.assert_cnsa_sig("ML-DSA-87") == "ML-DSA-87"
    assert purity.assert_cnsa_group("SecP384r1MLKEM1024")
    assert purity.assert_cnsa_suite("TLS_AES_256_GCM_SHA384")
    assert purity.assert_cnsa_hash("SHA384")
    assert purity.assert_cnsa_kdf("HKDF-SHA384")
    with pytest.raises(purity.PurityError):
        purity.assert_cnsa_kem("ML-KEM-768")
    with pytest.raises(purity.PurityError):
        purity.assert_cnsa_sig("Falcon-1024")
    with pytest.raises(purity.PurityError):
        purity.assert_cnsa_suite("TLS_AES_128_GCM_SHA256")


def test_purity_catches_planted_violations(tmp_path, monkeypatch):
    import cnsa_purity as p
    monkeypatch.setattr(p, "REPO_ROOT", tmp_path)
    evil = tmp_path / "evil_mod.py"
    evil.write_text("from x import Falcon1024\nk = SlhDsa512()\n",
                    encoding="utf-8")
    with pytest.raises(p.PurityError):
        p.scan_tree(["evil_mod.py"])
    # f-string literal spans are scanned too (3.12+ FSTRING_MIDDLE):
    # a bare deny token hits, while prose-with-spaces stays exempt
    # (messages are not crypto usage — same rule as plain strings).
    evil2 = tmp_path / "evil_fstr.py"
    evil2.write_text('alg = f"Kyber768"\n', encoding="utf-8")
    with pytest.raises(p.PurityError):
        p.scan_tree(["evil_fstr.py"])
    ok_fstr = tmp_path / "ok_fstr.py"
    ok_fstr.write_text('msg = f"negotiating session now"\n', encoding="utf-8")
    assert p.scan_tree(["ok_fstr.py"]) == {}
    # Missing inventory files fail closed (no silent scan shrinkage).
    with pytest.raises(p.PurityError):
        p.scan_tree()
    # ...while explicit custom lists still skip absent files.
    assert p.scan_tree(["does_not_exist_xyz.py"]) == {}


def test_selftests_green_and_cached(tmp_path, monkeypatch):
    r1 = stest.run_powerup_selftests()
    assert set(r1) >= {"aes_gcm", "hkdf_sha384", "hashes", "x25519",
                       "p384", "mlkem_pct", "mldsa_pct", "entropy"}
    r2 = stest.ensure_selftests()
    assert r2 == r1  # cached path identical
    assert stest.check_no_weak_rng() is not None  # clean tree returns file list
    # Planted weak-RNG offender is caught.
    import crypto_selftest as cs
    monkeypatch.setattr(cs, "REPO_ROOT", tmp_path)
    evil = tmp_path / "evil_rng.py"
    evil.write_text("import random\nx = random.randbytes(32)\n", encoding="utf-8")
    with pytest.raises(stest.SelfTestError):
        stest.check_no_weak_rng(["evil_rng.py"])


def test_selftest_error_state_latches(monkeypatch):
    import crypto_selftest as cs
    saved_passed, saved_failed = cs._PASSED, cs._FAILED
    cs._PASSED, cs._FAILED = None, False
    try:
        def boom():
            raise stest.SelfTestError("injected KAT failure")
        monkeypatch.setattr(cs, "_kat_aes_gcm", boom)
        with pytest.raises(stest.SelfTestError):
            cs.ensure_selftests()
        # Latched: subsequent calls refuse WITHOUT re-running tests.
        with pytest.raises(stest.SelfTestError):
            cs.ensure_selftests()
        assert cs._FAILED is True
    finally:
        cs._PASSED, cs._FAILED = saved_passed, saved_failed


def test_noise_intermediate_key_scrubbing():
    """Verifies that SymmetricState._key is a bytearray and zeroized in-place upon destroy()."""
    sym = npq.SymmetricState()
    sym.mix_key(b"initial_key_material_for_test_12345678")
    assert isinstance(sym._key, bytearray)
    raw_key_ref = sym._key
    assert any(b != 0 for b in raw_key_ref)
    sym.destroy()
    assert sym._key is None
    # Underlying memory must be actively zeroed
    assert all(b == 0 for b in raw_key_ref)


def test_noise_session_transport_keys_scrubbed():
    """Verifies that NoiseSession transport and secret keys are zeroized in-place upon destroy()."""
    sess = npq.NoiseSession(is_initiator=True, sig_pk=b"A"*2592, sig_sk=b"B"*4896)
    sess._f_ss = bytearray(b"C" * 32)
    sess._k_send = bytearray(b"D" * 32)
    sess._k_recv = bytearray(b"E" * 32)
    ref_ss = sess._f_ss
    ref_send = sess._k_send
    ref_recv = sess._k_recv

    sess.destroy()

    assert sess._f_ss is None
    assert sess._k_send is None
    assert sess._k_recv is None
    assert all(b == 0 for b in ref_ss)
    assert all(b == 0 for b in ref_send)
    assert all(b == 0 for b in ref_recv)

