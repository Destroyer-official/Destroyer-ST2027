"""Behavioral tests for tactical message anti-replay protection.

Tests TacticalConsoleStation._claim_tactical_message instantiated via __new__
to verify that identical tactical packets are rejected on second presentation,
preventing replay attacks against battlefield operator consoles.
"""

import threading
import time
from tactical_operator_console import TacticalConsoleStation


def _make_uninitialized_station():
    station = TacticalConsoleStation.__new__(TacticalConsoleStation)
    station._tactical_replay_lock = threading.Lock()
    station._seen_tactical_messages = {}
    station._max_tactical_replays = 1000
    station._tactical_replay_ttl = 300.0
    return station


def test_tactical_replay_rejects_second_presentation():
    """Calling _claim_tactical_message twice with identical arguments rejects second."""
    station = _make_uninitialized_station()
    kind = "COT_EVENT"
    signer = "TACTICAL_NODE_ALPHA"
    signed_bytes = b"<event version='2.0' uid='strike-01'/>"

    # First presentation must succeed
    claimed_first = station._claim_tactical_message(kind, signer, signed_bytes)
    assert claimed_first is True

    # Replayed presentation must fail
    claimed_second = station._claim_tactical_message(kind, signer, signed_bytes)
    assert claimed_second is False


def test_tactical_replay_distinguishes_signers_and_payloads():
    """Different signer or different bytes must not be blocked by prior claims."""
    station = _make_uninitialized_station()
    payload = b"ORDER: ADVANCE"

    # Alpha sends
    assert station._claim_tactical_message("TACTICAL_MSG", "OFFICER_ALPHA", payload) is True
    # Alpha sends again -> rejected
    assert station._claim_tactical_message("TACTICAL_MSG", "OFFICER_ALPHA", payload) is False

    # Bravo sends same payload -> accepted (different signer)
    assert station._claim_tactical_message("TACTICAL_MSG", "OFFICER_BRAVO", payload) is True

    # Alpha sends different payload -> accepted
    assert station._claim_tactical_message("TACTICAL_MSG", "OFFICER_ALPHA", b"ORDER: HOLD") is True


def test_tactical_replay_capacity_cap():
    """When cache exceeds max_tactical_replays, new messages fail closed."""
    station = _make_uninitialized_station()
    station._max_tactical_replays = 2

    assert station._claim_tactical_message("MSG", "NODE", b"1") is True
    assert station._claim_tactical_message("MSG", "NODE", b"2") is True

    # 3rd message exceeds capacity (2) -> must fail closed
    assert station._claim_tactical_message("MSG", "NODE", b"3") is False


def test_tactical_replay_ttl_expiry():
    """Expired messages should be purged and re-accepted after TTL."""
    station = _make_uninitialized_station()
    station._tactical_replay_ttl = 0.05  # 50ms TTL for testing

    assert station._claim_tactical_message("PTT_VOICE", "RADIO_01", b"AUDIO_FRAME_01") is True
    assert station._claim_tactical_message("PTT_VOICE", "RADIO_01", b"AUDIO_FRAME_01") is False

    time.sleep(0.08)

    # After expiry, cleanup purges the expired entry and accepts
    assert station._claim_tactical_message("PTT_VOICE", "RADIO_01", b"AUDIO_FRAME_01") is True
