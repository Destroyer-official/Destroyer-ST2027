#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""test_simple_chat.py

Verify simple_chat_implementation initialization, active_connections registration,
and DoubleRatchet loopback messaging.
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import simple_chat_implementation as sci
from network.session_manager import SessionContext


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def test_ddil_queue_does_not_fabricate_outer_aead_tag():
    class _Mesh:
        def __init__(self):
            self.calls = []

        def enqueue_bundle(self, **kwargs):
            self.calls.append(kwargs)
            return kwargs

    mesh = _Mesh()
    sci._enqueue_ddil_ciphertext(
        mesh, "peer-1", 123, b"double-ratchet-message", sci.BundlePriority.STANDARD
    )

    assert mesh.calls[0]["auth_tag"] == b""  # nosec: B101
    assert mesh.calls[0]["ciphertext_bytes"] == b"double-ratchet-message"  # nosec: B101


@pytest.mark.anyio
async def test_simple_chat_loopback_session():
    # Create an in-memory loopback pipe using asyncio.open_connection
    server_session = None

    async def _on_client_connected(reader, writer):
        nonlocal server_session
        server_session = await sci.initialize_session(
            peer_id="127.0.0.1:server",
            reader=reader,
            writer=writer,
            is_initiator=False,
        )

    server = await asyncio.start_server(_on_client_connected, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)

    client_session = await sci.initialize_session(
        peer_id=f"127.0.0.1:{port}",
        reader=client_reader,
        writer=client_writer,
        is_initiator=True,
    )

    # Wait for server session establishment
    for _ in range(200):
        if server_session is not None:
            break
        await asyncio.sleep(0.05)

    assert isinstance(client_session, SessionContext)  # nosec: B101
    assert isinstance(server_session, SessionContext)  # nosec: B101
    assert f"127.0.0.1:{port}" in sci.active_connections  # nosec: B101

    # Verify Double Ratchet encryption across client and server
    ct = client_session.double_ratchet.encrypt(b"Tactical EAM Vector")
    pt = server_session.double_ratchet.decrypt(ct)
    assert pt == b"Tactical EAM Vector"  # nosec: B101

    # Verify reverse direction (responder -> initiator)
    ct2 = server_session.double_ratchet.encrypt(b"EAM Acknowledged by HQ")
    pt2 = client_session.double_ratchet.decrypt(ct2)
    assert pt2 == b"EAM Acknowledged by HQ"  # nosec: B101

    client_writer.close()
    await client_writer.wait_closed()
    if server_session and server_session.writer:
        server_session.writer.close()
        await server_session.writer.wait_closed()
    server.close()
    await server.wait_closed()

