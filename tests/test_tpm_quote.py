#!/usr/bin/env python3
"""Tests for tpm_quote.py skeleton (additive only, runtime <30s)."""

from __future__ import annotations

import os
import secrets
import time

import tpm_quote
from tpm_quote import attach_quote_to_handshake, sign_quote, verify_quote


def _fresh_keypair():
    pub, sk = tpm_quote.generate_ak_stub()
    return bytes(pub), bytes(sk)


def _sample_pcr():
    return {0: "00" * 32, 7: "ab" * 32}


def test_sign_verify_roundtrip():
    pub, sk = _fresh_keypair()
    nonce = secrets.token_bytes(32)
    env = sign_quote(_sample_pcr(), nonce, "ak-test-1", sk)
    assert env["v"] == 1  # nosec: B101
    assert env["alg"] == "ML-DSA-87"  # nosec: B101
    assert verify_quote(env, nonce, trusted_pubs=[pub]) is True  # nosec: B101


def test_wrong_nonce_false():
    pub, sk = _fresh_keypair()
    env = sign_quote(_sample_pcr(), secrets.token_bytes(32), "ak-test-1", sk)
    assert verify_quote(env, secrets.token_bytes(32), trusted_pubs=[pub]) is False  # nosec: B101


def test_stale_ts_false():
    pub, sk = _fresh_keypair()
    nonce = secrets.token_bytes(32)
    stale_ts = time.time() - 3600.0
    env = sign_quote(_sample_pcr(), nonce, "ak-test-1", sk, ts=stale_ts)
    assert verify_quote(env, nonce, max_skew_s=60, trusted_pubs=[pub]) is False  # nosec: B101


def test_empty_trust_list_false():
    _pub, sk = _fresh_keypair()
    nonce = secrets.token_bytes(32)
    env = sign_quote(_sample_pcr(), nonce, "ak-test-1", sk)
    assert verify_quote(env, nonce, trusted_pubs=[]) is False  # nosec: B101
    assert verify_quote(env, nonce, trusted_pubs=None) is False  # nosec: B101


def test_tampered_pcr_false():
    pub, sk = _fresh_keypair()
    nonce = secrets.token_bytes(32)
    env = sign_quote(_sample_pcr(), nonce, "ak-test-1", sk)
    bad = dict(env)
    bad_pcr = dict(env["pcr"])
    bad_pcr[0] = "ff" * 32
    bad["pcr"] = bad_pcr
    assert verify_quote(bad, nonce, trusted_pubs=[pub]) is False  # nosec: B101


def test_attach_returns_none_by_default():
    old_quote = os.environ.get("P2P_TPM_QUOTE")
    old_native = os.environ.get("P2P_ALLOW_TPM_NATIVE")
    try:
        os.environ.pop("P2P_TPM_QUOTE", None)
        os.environ.pop("P2P_ALLOW_TPM_NATIVE", None)
        assert attach_quote_to_handshake("peer-default-gate") is None  # nosec: B101
        os.environ["P2P_TPM_QUOTE"] = "1"
        os.environ["P2P_ALLOW_TPM_NATIVE"] = "0"
        assert attach_quote_to_handshake("peer-native-off") is None  # nosec: B101
    finally:
        if old_quote is None:
            os.environ.pop("P2P_TPM_QUOTE", None)
        else:
            os.environ["P2P_TPM_QUOTE"] = old_quote
        if old_native is None:
            os.environ.pop("P2P_ALLOW_TPM_NATIVE", None)
        else:
            os.environ["P2P_ALLOW_TPM_NATIVE"] = old_native


def test_generate_tpm_quote_degraded_verifies():
    from tpm_quote import generate_tpm_quote
    import warnings
    nonce = secrets.token_bytes(32)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        env = generate_tpm_quote(_sample_pcr(), nonce, "ak-test-2")
    assert "error" not in env, env.get("error")  # nosec: B101
    assert env.get("degraded") is True  # nosec: B101
    assert env.get("ak_pub")  # nosec: B101
    assert verify_quote(env, nonce, trusted_pubs=[env["ak_pub"]]) is True  # nosec: B101


def test_generate_tpm_quote_bad_ek_chain_fails_closed():
    from tpm_quote import generate_tpm_quote
    import warnings
    nonce = secrets.token_bytes(32)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        env = generate_tpm_quote(_sample_pcr(), nonce, "ak-test-3",
                                 ek_cert_chain=[b"\x00" * 10])
    assert env.get("error") == "EK certificate chain validation failed"  # nosec: B101


def test_generate_tpm_quote_empty_nonce_rejected():
    from tpm_quote import generate_tpm_quote
    import pytest
    with pytest.raises((TypeError, ValueError)):
        generate_tpm_quote(_sample_pcr(), b"", "ak-test-4")

