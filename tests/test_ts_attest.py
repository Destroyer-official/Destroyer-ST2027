#!/usr/bin/env python3
"""Production tests for ts_attest — REAL TPM signatures, REAL verification.

The RATS split is honored throughout: the ATTESTER signs with the live
TPM-bound key; the VERIFIER checks with the independent `cryptography`
library. No mocks of crypto anywhere.
"""

import os
import time

import pytest

import ts_attest as ta


def _cng_or_skip():
    try:
        import cng_platform
        h = cng_platform.open_platform_provider()
        cng_platform.close_handle(h)
        return cng_platform
    except Exception:
        pytest.skip("no CNG platform provider on this host")


def _unique_key():
    return f"TS-TEST-{os.getpid()}-AT"


def test_live_roundtrip_signed_unhealthy_verdict(monkeypatch, tmp_path):
    cng = _cng_or_skip()
    for v in ("P2P_TS_MODE", "P2P_PRODUCTION"):
        monkeypatch.delenv(v, raising=False)
    key_name = _unique_key()
    nonce = os.urandom(32)
    try:
        env = ta.produce_evidence(nonce, key_name)
        assert env["v"] == 1 and env["kid"] == key_name
        assert len(bytes.fromhex(env["sig"])) == 64
        assert len(bytes.fromhex(env["pub"])) == 72
        res = ta.appraise_evidence(env, nonce)
        # This dev box is unenforced: the verdict must be VALIDLY SIGNED
        # but UNHEALTHY, with exact reasons — origin and posture separated.
        assert res.healthy is False
        assert res.reasons, "unhealthy verdict must enumerate reasons"
        assert any("secure-boot" in r for r in res.reasons)
    finally:
        try:
            h = cng.open_platform_provider()
            try:
                if cng.device_key_exists(h, key_name):
                    k = cng.open_device_key(h, key_name)
                    cng.delete_key(k)
            finally:
                cng.close_handle(h)
        except Exception:
            pass


def test_tampered_evidence_rejected(monkeypatch):
    cng = _cng_or_skip()
    for v in ("P2P_TS_MODE", "P2P_PRODUCTION"):
        monkeypatch.delenv(v, raising=False)
    key_name = _unique_key()
    nonce = os.urandom(32)
    try:
        env = ta.produce_evidence(nonce, key_name)
        env["posture"] = dict(env["posture"], secure_boot=True)  # forgery attempt
        with pytest.raises(ta.AttestError):
            ta.appraise_evidence(env, nonce)
        with pytest.raises(ta.AttestError):  # wrong challenge nonce
            ta.appraise_evidence(ta.produce_evidence(nonce, key_name), os.urandom(32))
    finally:
        try:
            h = cng.open_platform_provider()
            try:
                if cng.device_key_exists(h, key_name):
                    k = cng.open_device_key(h, key_name)
                    cng.delete_key(k)
            finally:
                cng.close_handle(h)
        except Exception:
            pass


def test_stale_evidence_rejected(monkeypatch):
    cng = _cng_or_skip()
    for v in ("P2P_TS_MODE", "P2P_PRODUCTION"):
        monkeypatch.delenv(v, raising=False)
    key_name = _unique_key()
    nonce = os.urandom(32)
    try:
        env = ta.produce_evidence(nonce, key_name)
        with pytest.raises(ta.AttestError):
            ta.appraise_evidence(env, nonce, now=env["ts"] + 3600.0)
        ok = ta.appraise_evidence(env, nonce, now=env["ts"] + 10.0)
        assert ok.healthy is False  # fresh but unenforced box
    finally:
        try:
            h = cng.open_platform_provider()
            try:
                if cng.device_key_exists(h, key_name):
                    k = cng.open_device_key(h, key_name)
                    cng.delete_key(k)
            finally:
                cng.close_handle(h)
        except Exception:
            pass


def test_evaluate_policy_pure_both_directions():
    good = {"secure_boot": True, "vbs_status": 2, "hvci_running": True,
            "measured_boot_log": True, "native": "ts_rt 1.0.0 [rustc x]"}
    healthy, reasons = ta.evaluate_policy(good)
    assert healthy is True and reasons == []
    for bad_key, bad_val in (("secure_boot", False), ("vbs_status", 0),
                             ("hvci_running", None), ("measured_boot_log", False),
                             ("native", None)):
        bad = dict(good)
        bad[bad_key] = bad_val
        healthy, reasons = ta.evaluate_policy(bad)
        assert healthy is False and reasons
    healthy, reasons = ta.evaluate_policy("not-a-dict")
    assert healthy is False


def test_pubkey_and_envelope_validation():
    with pytest.raises(ta.AttestError):
        ta._parse_pubkey_blob(b"\x00" * 71)
    with pytest.raises(ta.AttestError):
        ta._parse_pubkey_blob(b"\xFF" * 72)  # bad magic
    with pytest.raises(ta.AttestError):
        ta._verify_tpm_sig(b"\x00" * 72, b"\x00" * 32, b"\x00" * 64)
    with pytest.raises(ta.AttestError):
        ta._verify_tpm_sig(b"\x00" * 72, b"\x00" * 32, b"short")
    with pytest.raises(ta.AttestError):
        ta.appraise_evidence({"v": 999}, b"\x00" * 32)
    with pytest.raises(ta.AttestError):
        ta.produce_evidence(b"short-nonce")
