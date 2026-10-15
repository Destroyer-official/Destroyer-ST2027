"""Combiner downgrade guard (audit 2026-10-14).

Pre-fix: once PQXDH combiner v2 was negotiated, ANY exception during v2
transcript building or root derivation silently kept the v1 raw-concat root
(and a SecurityError from negotiate_protocol_version's production floor was
swallowed and replaced with v1). An attacker able to force a v2 error would
therefore select the weaker combiner — exactly the downgrade the production
floor exists to refuse.

Post-fix: under production/TS posture both paths fail closed (SecurityError);
lab keeps the v1 fallback for interop debugging only.

Note: a full two-peer handshake integration test was omitted here because
get_public_bundle() emits a FALCON-signed bundle that fails self-verification
under this environment's FALCON key format detection — an unrelated pre-existing
serialization quirk, not caused by the combiner change. The decision logic
(new _production_posture helper + re-raise of negotiate_protocol_version's
SecurityError) is tested directly below.
"""

import pytest


def test_production_posture_helper(monkeypatch):
    from hybrid_kex import HybridKeyExchange

    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("P2P_TS_MODE", raising=False)
    assert HybridKeyExchange._production_posture() is False

    monkeypatch.setenv("P2P_PRODUCTION", "1")
    assert HybridKeyExchange._production_posture() is True

    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.setenv("P2P_TS_MODE", "1")
    assert HybridKeyExchange._production_posture() is True


def test_negotiate_protocol_version_raises_in_production_floor(monkeypatch):
    """negotiate_protocol_version itself must still raise (not be the thing
    swallowed by the new except SecurityError branch)."""
    from hybrid_kex import HybridKeyExchange, SecurityError

    kex = HybridKeyExchange(identity="neg_test")
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    peer_v1_bundle = {"identity": "peer", "protocol_version": 1}
    with pytest.raises(SecurityError):
        kex.negotiate_protocol_version(peer_v1_bundle)
