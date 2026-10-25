"""Behavioral tests for Neon PostgreSQL security and HMAC authentication.

Tests:
1. Dynamic loading via importlib.
2. HMAC authentication with secret key vs rejected pubkey-as-secret.
3. Secret key minimum length enforcement (>= 32 chars).
4. Nonce replay protection (second attempt rejected).
5. Rate limit fail-closed enforcement when limit exceeded.
"""

import base64
import hashlib
import hmac
import importlib.util
from pathlib import Path
import time
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SECURITY_PY = REPO_ROOT / "notupload" / "fastapi-neon-ano" / "Neon_PostgreSQL" / "core" / "security.py"


def _load_security_module():
    spec = importlib.util.spec_from_file_location("neon_core_security", str(SECURITY_PY))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sec_mod():
    assert SECURITY_PY.exists(), f"security.py not found at {SECURITY_PY}"
    return _load_security_module()


def test_hmac_secret_length_enforcement(sec_mod):
    """HMAC secret key must be at least 32 characters long."""
    short_secret = "too-short-secret"
    with pytest.raises(Exception):
        sec_mod.SecurityManager(
            hmac_secret_key=short_secret,
            rate_limits={"register": 10, "query": 10},
        )


def test_hmac_verification_secret_vs_pubkey(sec_mod):
    """Verify that HMAC succeeds with configured secret, and FAILS if signed with pubkey."""
    secret = "a" * 32
    mgr = sec_mod.SecurityManager(
        hmac_secret_key=secret,
        rate_limits={"register": 10, "query": 10},
    )
    pubkey = "b" * 64
    request_data = "GET|/users|{}|1234567890|nonce123456789012"

    # 1. Sign using the real HMAC secret
    valid_sig = hmac.new(secret.encode(), request_data.encode(), hashlib.sha256).digest()
    valid_b64 = base64.b64encode(valid_sig).decode()
    assert mgr.verify_hmac_signature(request_data, valid_b64, pubkey) is True

    # 2. Sign using pubkey as key (the legacy flaw) -> must FAIL
    bad_sig = hmac.new(pubkey.encode(), request_data.encode(), hashlib.sha256).digest()
    bad_b64 = base64.b64encode(bad_sig).decode()
    assert mgr.verify_hmac_signature(request_data, bad_b64, pubkey) is False

    # 3. Tampered request data -> must FAIL
    assert mgr.verify_hmac_signature(request_data + "tamper", valid_b64, pubkey) is False


def test_nonce_replay_protection(sec_mod):
    """Identical nonce must be rejected on replay."""
    secret = "s" * 32
    mgr = sec_mod.SecurityManager(
        hmac_secret_key=secret,
        rate_limits={"register": 10, "query": 10},
    )
    pubkey = "c" * 64
    nonce = "testnonce_1234567890123456"
    now_ts = str(time.time())

    class DummyURL:
        path = "/test/endpoint"

    class DummyRequest:
        method = "POST"
        url = DummyURL()
        headers = {
            "X-Pubkey": pubkey,
            "X-Timestamp": now_ts,
            "X-Nonce": nonce,
            "X-Signature": "",
        }

    body = '{"hello":"world"}'
    raw_req_data = mgr.extract_request_data(DummyRequest(), body, nonce)
    sig = hmac.new(secret.encode(), raw_req_data.encode(), hashlib.sha256).digest()
    DummyRequest.headers["X-Signature"] = base64.b64encode(sig).decode()

    # First request must succeed
    res1 = mgr.authenticate_request(DummyRequest(), body)
    assert res1.success is True

    # Replay request with same nonce must be rejected
    res2 = mgr.authenticate_request(DummyRequest(), body)
    assert res2.success is False
    assert "Replay detected" in res2.error_message


def test_rate_limiting_fail_closed(sec_mod):
    """When requests exceed limit, rate limiter must deny further requests."""
    secret = "r" * 32
    mgr = sec_mod.SecurityManager(
        hmac_secret_key=secret,
        rate_limits={"query": 2},
        rate_limit_window=60,
    )
    ip = "192.168.1.100"

    res1 = mgr.check_rate_limit(ip, "query")
    assert res1.allowed is True
    res2 = mgr.check_rate_limit(ip, "query")
    assert res2.allowed is True

    # Third request exceeds limit (2)
    res3 = mgr.check_rate_limit(ip, "query")
    assert res3.allowed is False
    assert res3.remaining == 0
    assert "Rate limit exceeded" in res3.error_message
