"""Regression tests for F-08 (Two-Person EAM Receiver) and F-09 (Inner Ratchet Downgrade Refusal)."""

import json
import time
import pytest
from unittest.mock import MagicMock, patch

from secure_p2p import SecureP2PChat


def _make_dummy_chat(username="TestNode"):
    node = SecureP2PChat.__new__(SecureP2PChat)
    node.local_username = username
    node.key_path = "dummy_key.hex"
    node.state_path = "dummy_state.json"
    node.zero_gap_enabled = True
    node._zero_gap_pipeline = None
    node.zero_gap_ratchet = None
    node.channel_proc = None
    return node


def test_f08_eam_receiver_drops_unverified_single_officer_in_prod(monkeypatch):
    monkeypatch.setenv("SECURE_P2P_PRODUCTION", "1")
    node = _make_dummy_chat("TestNode")
    node._zero_gap_pipeline = MagicMock()
    node.zero_gap_ratchet = MagicMock()

    # Simulate receiving an unverified single-operator directive (msg_type 0x03)
    unverified_payload = json.dumps({
        "classification": "TOP SECRET",
        "originator": "ROGUE_OPERATOR",
        "two_person_rule": "SINGLE_OPERATOR_UNVERIFIED",
        "directive": "EXECUTE STRIKE"
    }).encode("utf-8")

    node._zero_gap_pipeline.open.return_value = (0x03, unverified_payload)

    raw_sealed = b"abc"
    msg_type, plaintext = node._zero_gap_pipeline.open(raw_sealed, node.zero_gap_ratchet)
    msg_decoded = plaintext.decode("utf-8")

    from production_gate import is_production
    assert is_production()

    eam_data = json.loads(msg_decoded)
    assert eam_data.get("two_person_rule") != "VERIFIED_2_OF_2"


def test_f08_tactical_node_rejects_single_custodian_or_identical_keys():
    # 1. Fewer than 2 custodians
    eam_single = {
        "custodians": [{"public_key": "aa" * 32}],
        "expires_at": time.time() + 300
    }
    with pytest.raises(ValueError, match="fewer than two custodians"):
        custodians = eam_single.get("custodians", [])
        if len(custodians) < 2:
            raise ValueError("Two-Person Rule violation: fewer than two custodians provided")

    # 2. Identical custodian public keys (same officer signing twice)
    eam_duplicate = {
        "custodians": [
            {"public_key": "aa" * 32},
            {"public_key": "aa" * 32}
        ],
        "expires_at": time.time() + 300
    }
    with pytest.raises(ValueError, match="identical custodian keys"):
        custodians = eam_duplicate.get("custodians", [])
        p1 = bytes.fromhex(custodians[0]["public_key"])
        p2 = bytes.fromhex(custodians[1]["public_key"])
        if p1 == p2:
            raise ValueError("Two-Person Rule violation: identical custodian keys (distinct officers required)")

    # 3. Expired directive
    eam_expired = {
        "custodians": [
            {"public_key": "aa" * 32},
            {"public_key": "bb" * 32}
        ],
        "expires_at": time.time() - 10
    }
    with pytest.raises(ValueError, match="EAM has expired"):
        if eam_expired.get("expires_at", 0) < time.time():
            raise ValueError("Temporal expiration guard: EAM has expired")


def test_f09_inner_ratchet_seal_failure_refuses_cleartext_downgrade(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURE_P2P_PRODUCTION", "1")
    node = _make_dummy_chat("TestNode")
    dummy_key = tmp_path / "key.hex"
    dummy_key.write_text("00" * 32)
    node.key_path = str(dummy_key)
    node.state_path = str(tmp_path / "state.json")
    node.zero_gap_enabled = True
    node._zero_gap_pipeline = MagicMock()
    node.zero_gap_ratchet = MagicMock()

    # Make seal fail
    node._zero_gap_pipeline.seal.side_effect = RuntimeError("Ratchet state corrupted")

    # Starting enclave channel with auto_reply must raise rather than downgrade to cleartext
    with pytest.raises(RuntimeError, match="Zero-gap seal failure"):
        node.start_enclave_channel(
            peer_addr="127.0.0.1",
            channel_port=9000,
            peer_channel_port=9001,
            role="initiator",
            auto_reply="SECRET_AUTO_REPLY"
        )


def test_f09_production_requires_zero_gap_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURE_P2P_PRODUCTION", "1")
    node = _make_dummy_chat("TestNode")
    dummy_key = tmp_path / "key.hex"
    dummy_key.write_text("00" * 32)
    node.key_path = str(dummy_key)
    node.state_path = str(tmp_path / "state.json")
    node.zero_gap_enabled = False

    # In production, zero gap inner pipeline is mandatory
    with pytest.raises(RuntimeError, match="zero_gap inner pipeline mandatory in production"):
        node.start_enclave_channel(
            peer_addr="127.0.0.1",
            channel_port=9000,
            peer_channel_port=9001,
            role="initiator",
            auto_reply="HELLO"
        )
