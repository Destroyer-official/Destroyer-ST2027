"""Heartbeat ACK flood throttle (audit 4.5 / roadmap must-pass).

The handler answers at most 1 HEARTBEAT_ACK per 5s window and reflects a
txid only when short + alnum. Proves: 100 inbound HEARTBEAT/s -> <= 1 ACK
(no ACK amplification loop), malformed txids dropped, HEARTBEAT_ACK itself
never triggers a send.

Fast, no network: fake orchestrator captures sends.
"""

import asyncio
import logging
import time

import pytest

from messaging.handler import MessageHandler


class _FakeP2P:
    def __init__(self):
        self.sent = 0

    async def send_framed(self, sock, data):
        self.sent += 1
        return True


class _FakeOrchestrator:
    MAX_USERNAME_LENGTH = 64

    def __init__(self):
        self.acks = []
        self.p2p = _FakeP2P()
        self.tcp_socket = object()
        self._last_hb_ack_time = 0.0
        self.last_heartbeat_received = 0.0

    async def _encrypt_message(self, msg):
        self.acks.append(msg)
        return b"enc:" + msg.encode("utf-8", errors="ignore")


def _handler():
    h = MessageHandler.__new__(MessageHandler)
    h.orchestrator = _FakeOrchestrator()
    h.logger = logging.getLogger("test_heartbeat_throttle")
    return h


def test_heartbeat_flood_yields_single_ack():
    h = _handler()
    for _ in range(100):
        asyncio.run(
            h.handle_message("HEARTBEAT:floodtx"))
    assert (  # nosec: B101
        len(h.orchestrator.acks) <= 1
    ), f"ACK amplification: {len(h.orchestrator.acks)} ACKs for 100 heartbeats"
    assert h.orchestrator.p2p.sent <= 1  # nosec: B101


def test_malformed_txid_dropped_no_ack():
    h = _handler()
    h.orchestrator._last_hb_ack_time = 0.0  # outside throttle window
    asyncio.run(
        h.handle_message("HEARTBEAT:" + "x" * 200))
    assert h.orchestrator.acks == []  # nosec: B101
    asyncio.run(
        h.handle_message("HEARTBEAT:bad;txid!"))
    assert h.orchestrator.acks == []  # nosec: B101


def test_heartbeat_ack_never_answered():
    h = _handler()
    asyncio.run(
        h.handle_message("HEARTBEAT_ACK:whatever"))
    assert h.orchestrator.acks == []  # nosec: B101
    assert h.orchestrator.p2p.sent == 0  # nosec: B101


def test_throttle_window_releases():
    h = _handler()
    asyncio.run(h.handle_message("HEARTBEAT:a"))
    assert len(h.orchestrator.acks) == 1  # nosec: B101
    # Inside window: suppressed.
    asyncio.run(h.handle_message("HEARTBEAT:b"))
    assert len(h.orchestrator.acks) == 1  # nosec: B101
    # After window: answered again.
    h.orchestrator._last_hb_ack_time = time.time() - 6.0
    asyncio.run(h.handle_message("HEARTBEAT:c"))
    assert len(h.orchestrator.acks) == 2  # nosec: B101

