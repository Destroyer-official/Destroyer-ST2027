# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""Regression tests for the audit nonce-management finding (2026-10-14).

Pre-fix behavior (all under a LIVE key, RFC 8439 Sec 2.8 violations):
  * CounterBasedNonceManager re-randomized its 4-byte salt every 5 minutes
    (birthday collision on the 32-bit salt space in ~227 days of uptime)
    and silently reset at the 1% counter threshold.
  * tls_channel_manager.NonceManager auto-reset (prefix re-roll) at the
    usage threshold AND every time its collision-cache window overflowed
    (~1024 nonces), restarting the counter under the same key.
  * utils/helpers + secure_p2p_core NonceManager silently re-rolled the
    4-byte prefix at max_nonce_uses despite documenting RuntimeError.

Post-fix: salt/prefix fixed per key instance, counter strictly monotonic,
exhaustion FAILS CLOSED with RuntimeError; explicit reset() exists only
for use alongside key rotation.
"""

import time

import pytest


def test_counter_based_salt_stable_across_time(monkeypatch):
    """No time-based re-salt: salt must survive a >5-minute clock jump."""
    from tls_channel_manager import CounterBasedNonceManager

    mgr = CounterBasedNonceManager()
    salt0 = mgr.get_salt()
    n1 = mgr.generate_nonce()

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 10_000)
    n2 = mgr.generate_nonce()
    n3 = mgr.generate_nonce()

    assert mgr.get_salt() == salt0, "salt must never re-randomize under a live key"
    assert n1 == salt0 + (0).to_bytes(8, "big")
    assert n2 == salt0 + (1).to_bytes(8, "big")
    assert n3 == salt0 + (2).to_bytes(8, "big")
    assert len({n1, n2, n3}) == 3


def test_counter_based_never_repeats_nonce():
    from tls_channel_manager import CounterBasedNonceManager

    mgr = CounterBasedNonceManager()
    seen = {mgr.generate_nonce() for _ in range(5000)}
    assert len(seen) == 5000


def test_counter_based_exhaustion_fails_closed():
    """Small counter space must RAISE, never silently re-salt and continue."""
    from tls_channel_manager import CounterBasedNonceManager

    mgr = CounterBasedNonceManager(counter_size=1, salt_size=11, nonce_size=12)
    salt0 = mgr.get_salt()
    # threshold = (2^8 - 1) // 100 = 2 -> counters 0,1,2 OK, then raise
    mgr.generate_nonce()
    mgr.generate_nonce()
    mgr.generate_nonce()
    with pytest.raises(RuntimeError, match="NONCE SPACE EXHAUSTED"):
        mgr.generate_nonce()
    assert mgr.get_salt() == salt0, "exhaustion must NOT re-salt under the same key"


def test_counter_based_is_rotation_needed_signal():
    from tls_channel_manager import CounterBasedNonceManager

    mgr = CounterBasedNonceManager(counter_size=1, salt_size=11, nonce_size=12)
    assert mgr.is_rotation_needed() is False
    for _ in range(3):
        mgr.generate_nonce()
    assert mgr.is_rotation_needed() is True, "record layer relies on this signal"


def test_tls_nonce_manager_window_flush_keeps_prefix():
    """Window overflow must flush the cache only — never re-roll the prefix."""
    from tls_channel_manager import NonceManager

    mgr = NonceManager(12, max_nonce_uses=2**24)
    prefix0 = mgr.nonce_prefix
    nonces = [mgr.generate_nonce() for _ in range(1100)]
    assert len(set(nonces)) == 1100
    assert mgr.nonce_prefix == prefix0, "prefix must not change on window flush"
    assert all(n.startswith(prefix0) for n in nonces)
    assert mgr.counter == 1100, "counter must stay monotonic across flushes"


def test_tls_nonce_manager_exhaustion_fails_closed():
    from tls_channel_manager import NonceManager

    mgr = NonceManager(12, max_nonce_uses=5, rotation_threshold=0.99)
    prefix0 = mgr.nonce_prefix
    for _ in range(4):  # counters 1..4 under threshold/max
        mgr.generate_nonce()
    with pytest.raises(RuntimeError, match="NONCE SPACE EXHAUSTED"):
        mgr.generate_nonce()
    assert mgr.nonce_prefix == prefix0


def test_helpers_nonce_manager_exhaustion_fails_closed():
    from utils.helpers import NonceManager

    mgr = NonceManager(nonce_size=12, max_nonce_uses=5, max_history=5)
    prefix0 = mgr.nonce_prefix
    for _ in range(5):
        mgr.generate_nonce()
    with pytest.raises(RuntimeError, match="NONCE SPACE EXHAUSTED"):
        mgr.generate_nonce()
    assert mgr.nonce_prefix == prefix0, "exhaustion must NOT re-roll the prefix"


def test_core_helpers_nonce_manager_exhaustion_fails_closed():
    from secure_p2p_core.utils.helpers import NonceManager

    mgr = NonceManager(nonce_size=12, max_nonce_uses=5, max_history=5)
    prefix0 = mgr.nonce_prefix
    for _ in range(5):
        mgr.generate_nonce()
    with pytest.raises(RuntimeError, match="NONCE SPACE EXHAUSTED"):
        mgr.generate_nonce()
    assert mgr.nonce_prefix == prefix0


def test_explicit_reset_still_redraws_salt_for_key_rotation():
    """reset() remains available for the rotate_key() pattern (salt changes)."""
    from tls_channel_manager import CounterBasedNonceManager

    mgr = CounterBasedNonceManager()
    salt0 = mgr.get_salt()
    mgr.reset()
    salt1 = mgr.get_salt()
    assert salt0 != salt1
    assert mgr.get_counter() == 0
    assert mgr.generate_nonce() == salt1 + (0).to_bytes(8, "big")
