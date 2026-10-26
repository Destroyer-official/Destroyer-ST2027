# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""DHT PoW production floor (A-13, 2026-10-16 audit).

Pre-fix: production could run the S/Kademlia admission proof-of-work at
difficulty 2 (16-bit) — verify_deployment only warned — while docs treat 3
as the high-threat floor. Fix: _pow_difficulty() is the single difficulty
authority (generation, admission, verification all resolve through it) and
auto-raises sub-floor configurations to PRODUCTION_POW_FLOOR_BYTES=3 under
production posture. Lab keeps the matched default of 2 for availability.

production_gate is sticky for the process lifetime, so every test here
disarms it in teardown to avoid poisoning sibling suites (see the F-06
pollution lesson).
"""

import hashlib
import secrets

import pytest


@pytest.fixture(autouse=True)
def _disarm_production_gate():
    yield
    try:
        import production_gate
        production_gate.reset_for_tests()
    except Exception:
        pass


def _clear_posture(monkeypatch):
    for var in ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION", "P2P_TS_MODE"):
        monkeypatch.delenv(var, raising=False)


def test_lab_default_is_two(monkeypatch):
    _clear_posture(monkeypatch)
    monkeypatch.delenv("P2P_DHT_POW_DIFFICULTY_BYTES", raising=False)
    import decentralized_architecture as da

    assert da._pow_difficulty() == 2  # nosec: B101


def test_production_floor_raises_env_two(monkeypatch):
    import decentralized_architecture as da

    monkeypatch.setenv("P2P_PRODUCTION", "1")
    monkeypatch.setenv("P2P_DHT_POW_DIFFICULTY_BYTES", "2")
    assert da._pow_difficulty() == 3  # nosec: B101


def test_production_floor_respects_higher_env(monkeypatch):
    import decentralized_architecture as da

    monkeypatch.setenv("P2P_PRODUCTION", "1")
    monkeypatch.setenv("P2P_DHT_POW_DIFFICULTY_BYTES", "4")
    assert da._pow_difficulty() == 4  # nosec: B101


def test_floor_governs_generation_and_verification_alike(monkeypatch):
    """The same authority serves mining and admission: no gen/verify split."""
    import decentralized_architecture as da

    _clear_posture(monkeypatch)
    monkeypatch.setenv("P2P_DHT_POW_DIFFICULTY_BYTES", "1")

    pubkey = secrets.token_bytes(32)
    nonce = None
    node_id = None
    for n in range(10000):
        d = hashlib.sha3_256(pubkey + n.to_bytes(4, "big")).digest()
        if d[0] == 0:
            nonce, node_id = n, d
            break
    assert nonce is not None  # nosec: B101

    node = da.DHTNodeInfo(node_id=node_id, address="10.0.0.1", port=5001,
                          public_key=pubkey, pow_nonce=nonce)
    assert node.verify_pow_and_identity() is True  # nosec: B101 (lab: floor 1)

    # Same node/difficulty under production posture: the default-arg path now
    # resolves the floor (3), so a 1-byte-preimage identity no longer passes.
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    assert da._pow_difficulty() == 3  # nosec: B101
    assert node.verify_pow_and_identity() is False  # nosec: B101
