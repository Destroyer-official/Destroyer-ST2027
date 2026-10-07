#!/usr/bin/env python3
"""
test_cli_key_fill_and_diode.py

Automated testing for CLI commands:
- /key-fill-import: Offline KMI key-fill import under dual custody
- /diode-tx: Unidirectional transmission across simplex diode boundary (Cauchy Reed-Solomon MDS FEC)
- /diode-rx: Simplex payload reconstruction without ACK
"""

import os
import sys
import json
import time
import pytest
import tempfile
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock

import key_fill_import as kfi
from tactical_data_diode import DiodeTransmitter, DiodeReceiver
from liboqs_wrapper import LibOQS_MLDSA_87


@pytest.fixture(scope="module")
def ceremony_keys():
    pk, sk = LibOQS_MLDSA_87().keygen()
    return bytes(pk), bytes(sk)


@pytest.fixture()
def workdir():
    d = tempfile.mkdtemp(prefix="cli_keyfill_diode_")
    yield Path(d)
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def test_cli_key_fill_import_success(ceremony_keys, workdir, monkeypatch):
    """Test /key-fill-import successfully authenticates and unseals payload into session."""
    async def _run():
        try:
            from secure_p2p import SecureP2PChat
        except ImportError:
            from archive.legacy_prototype.secure_p2p import SecureP2PChat

        pk, sk = ceremony_keys
        ceremony_pub_path = str(workdir / "ceremony.pub")
        with open(ceremony_pub_path, "wb") as f:
            f.write(pk)

        fill_doc = kfi.create_key_fill(
            fill_id="KMI-FILL-TEST-001",
            payload={
                "kind": "tactical-war-order-keys",
                "war_order_key": "aa" * 32,
                "pre_shared_key": "bb" * 32,
            },
            officer_ids=["GEN_ALPHA", "ADM_BRAVO"],
            officer_passphrases=["alpha-pass-123", "bravo-pass-456"],
            signing_key=sk,
        )
        fill_path = str(workdir / "fill.json")
        with open(fill_path, "w", encoding="utf-8") as f:
            json.dump(fill_doc, f)

        # Setup chat instance in workdir
        chat = SecureP2PChat(identity="node_alpha")
        chat.base_dir = str(workdir)

        monkeypatch.setenv("P2P_KEY_FILL_OFFICER1", "GEN_ALPHA")
        monkeypatch.setenv("P2P_KEY_FILL_PW1", "alpha-pass-123")
        monkeypatch.setenv("P2P_KEY_FILL_OFFICER2", "ADM_BRAVO")
        monkeypatch.setenv("P2P_KEY_FILL_PW2", "bravo-pass-456")

        cmd = f"/key-fill-import {fill_path} {ceremony_pub_path}"
        await chat._handle_command(cmd)

        assert hasattr(chat, "imported_key_fill")  # nosec: B101
        assert chat.imported_key_fill["fill_id"] == "KMI-FILL-TEST-001"  # nosec: B101
        assert chat._nc3_war_key == bytes.fromhex("aa" * 32)  # nosec: B101
        assert chat.pre_shared_key == bytes.fromhex("bb" * 32)  # nosec: B101

    asyncio.run(_run())


def test_cli_key_fill_import_replay_fails_closed(ceremony_keys, workdir, monkeypatch):
    """Test re-importing the same fill fails closed due to registry locking."""
    async def _run():
        try:
            from secure_p2p import SecureP2PChat
        except ImportError:
            from archive.legacy_prototype.secure_p2p import SecureP2PChat

        pk, sk = ceremony_keys
        ceremony_pub_path = str(workdir / "ceremony.pub")
        with open(ceremony_pub_path, "wb") as f:
            f.write(pk)

        fill_doc = kfi.create_key_fill(
            fill_id="KMI-FILL-TEST-REPLAY",
            payload={"kind": "psk", "war_order_key": "11" * 32},
            officer_ids=["GEN_ALPHA", "ADM_BRAVO"],
            officer_passphrases=["passphrase-1-alpha", "passphrase-2-bravo"],
            signing_key=sk,
        )
        fill_path = str(workdir / "fill_replay.json")
        with open(fill_path, "w", encoding="utf-8") as f:
            json.dump(fill_doc, f)

        chat = SecureP2PChat(identity="node_alpha")
        chat.base_dir = str(workdir)

        monkeypatch.setenv("P2P_KEY_FILL_OFFICER1", "GEN_ALPHA")
        monkeypatch.setenv("P2P_KEY_FILL_PW1", "passphrase-1-alpha")
        monkeypatch.setenv("P2P_KEY_FILL_OFFICER2", "ADM_BRAVO")
        monkeypatch.setenv("P2P_KEY_FILL_PW2", "passphrase-2-bravo")

        # First import: success
        cmd = f"/key-fill-import {fill_path} {ceremony_pub_path}"
        await chat._handle_command(cmd)
        assert chat.imported_key_fill["fill_id"] == "KMI-FILL-TEST-REPLAY"  # nosec: B101

        # Reset attribute to test second import
        chat.imported_key_fill = None

        # Second import: must fail closed and NOT set imported_key_fill
        await chat._handle_command(cmd)
        assert chat.imported_key_fill is None  # nosec: B101

    asyncio.run(_run())


def test_cli_diode_tx_and_rx_roundtrip():
    """Test /diode-tx and /diode-rx command handlers roundtrip across loopback socket."""
    async def _run():
        try:
            from secure_p2p import SecureP2PChat
        except ImportError:
            from archive.legacy_prototype.secure_p2p import SecureP2PChat

        chat_sender = SecureP2PChat(identity="diode_tx_node")
        chat_receiver = SecureP2PChat(identity="diode_rx_node")

        port = 57199
        msg_text = "STRATCOM-FLASH-DEFCON-1-AUTHORIZATION"

        async def _run_rx():
            await chat_receiver._handle_command(f"/diode-rx 127.0.0.1 {port} 4.0")

        rx_task = asyncio.create_task(_run_rx())
        await asyncio.sleep(0.3)  # Give receiver socket time to bind

        # Dispatch transmission command
        await chat_sender._handle_command(f"/diode-tx 127.0.0.1 {port} {msg_text}")

        await rx_task

    asyncio.run(_run())


