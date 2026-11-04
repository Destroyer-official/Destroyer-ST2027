import hashlib
import json
import os
import pytest
from hybrid_kex_legacy import HybridKeyExchange
import ui.safety_numbers as safety_numbers
from ui.safety_numbers import check_pin, revoke_pin


def _compute_bundle_fingerprint(bundle: dict) -> str:
    fp_fields = {k: str(bundle.get(k, '')) for k in (
        'identity', 'static_key', 'signing_key', 'signed_prekey',
        'prekey_signature', 'kem_public_key', 'falcon_public_key')}
    return hashlib.sha3_512(json.dumps(fp_fields, sort_keys=True).encode('utf-8')).hexdigest()


def test_f01_unauthorized_first_contact_rejected_in_production(monkeypatch):
    """F-01: In production/strict mode, an unknown peer without whitelist authorization MUST fail closed."""
    peer_id = "test_f01_unauth_peer"
    revoke_pin(peer_id)

    # Generate genuine bundle for peer
    peer_kex = HybridKeyExchange(identity=peer_id, ephemeral=True, in_memory_only=True)
    bundle = peer_kex.get_public_bundle()

    local_kex = HybridKeyExchange(identity="local_operator", ephemeral=True, in_memory_only=True)
    assert local_kex.authorized_peer_fingerprints is None

    # Under strict/production policy, unanchored bundle must be rejected
    monkeypatch.setenv("P2P_STRICT_SECURITY", "1")
    assert local_kex.verify_public_bundle(bundle) is False


def test_f01_authorized_first_contact_accepted_and_pinned_in_memory(monkeypatch):
    """F-01: In in-memory mode, enrolled peer bundle verifies and pins to instance memory."""
    peer_id = "test_f01_auth_peer_mem"

    peer_kex = HybridKeyExchange(identity=peer_id, ephemeral=True, in_memory_only=True)
    bundle = peer_kex.get_public_bundle()
    fp = _compute_bundle_fingerprint(bundle)

    # Pre-enroll the peer fingerprint
    local_kex = HybridKeyExchange(
        identity="local_operator",
        ephemeral=True,
        in_memory_only=True,
        authorized_peer_fingerprints=[fp]
    )
    assert local_kex.authorized_peer_fingerprints == {fp.lower()}

    monkeypatch.setenv("P2P_STRICT_SECURITY", "1")
    assert local_kex.verify_public_bundle(bundle) is True

    # In-memory pin must now be established
    assert local_kex._in_memory_pins.get(peer_id) == fp

    # Subsequent verification succeeds via in-memory pinned match
    assert local_kex.verify_public_bundle(bundle) is True

    # Tampered identity key must be rejected by in-memory pin continuity
    tampered = dict(bundle)
    tampered["static_key"] = "AAAA" + bundle["static_key"][4:]
    assert local_kex.verify_public_bundle(tampered) is False


def test_f01_authorized_first_contact_accepted_and_pinned_persistently(monkeypatch, tmp_path):
    """F-01: In persistent mode, enrolled peer bundle verifies and commits to disk pin store."""
    peer_id = "test_f01_auth_peer_disk"
    test_pins = tmp_path / "pins.json"
    monkeypatch.setattr(safety_numbers, "PIN_STORE", test_pins)

    peer_kex = HybridKeyExchange(identity=peer_id, ephemeral=True, in_memory_only=True)
    bundle = peer_kex.get_public_bundle()
    fp = _compute_bundle_fingerprint(bundle)

    local_kex = HybridKeyExchange(
        identity="local_operator",
        keys_dir=str(tmp_path / "keys"),
        ephemeral=True,
        in_memory_only=False,
        authorized_peer_fingerprints=[fp]
    )

    monkeypatch.setenv("P2P_STRICT_SECURITY", "1")
    assert local_kex.verify_public_bundle(bundle) is True

    # Persistent pin must now be stored on disk
    assert safety_numbers.check_pin(peer_id, fp) == "match"

    # Subsequent verification succeeds via disk pin store
    assert local_kex.verify_public_bundle(bundle) is True

    # Tampered identity key must be rejected by disk pin continuity
    tampered = dict(bundle)
    tampered["static_key"] = "AAAA" + bundle["static_key"][4:]
    assert local_kex.verify_public_bundle(tampered) is False


def test_f01_session_manager_configured_fingerprints(monkeypatch):
    """F-01: SessionManager propagates authorized fingerprints to its HybridKeyExchange instances."""
    from network.session_manager import SessionManager
    
    peer_id = "test_f01_sm_peer"
    revoke_pin(peer_id)
    peer_kex = HybridKeyExchange(identity=peer_id, ephemeral=True, in_memory_only=True)
    bundle = peer_kex.get_public_bundle()
    fp = _compute_bundle_fingerprint(bundle)

    # 1. Without authorized fingerprint in strict mode -> fails closed
    monkeypatch.setenv("P2P_STRICT_SECURITY", "1")
    sm_unauth = SessionManager()
    kex_unauth = HybridKeyExchange(
        identity=f"session_{peer_id}",
        ephemeral=True,
        in_memory_only=True,
        authorized_peer_fingerprints=sm_unauth.authorized_peer_fingerprints
    )
    assert kex_unauth.verify_public_bundle(bundle) is False

    # 2. With enrolled fingerprint in strict mode -> verifies and anchors
    sm_auth = SessionManager(authorized_peer_fingerprints=[fp])
    kex_auth = HybridKeyExchange(
        identity=f"session_{peer_id}",
        ephemeral=True,
        in_memory_only=True,
        authorized_peer_fingerprints=sm_auth.authorized_peer_fingerprints
    )
    assert kex_auth.verify_public_bundle(bundle) is True

