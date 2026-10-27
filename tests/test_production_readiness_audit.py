#!/usr/bin/env python3
"""
test_production_readiness_audit.py

Automated verification of the comprehensive production-readiness hardening:
1. Zero-Trust File Message Gate: file messages from unverified peers rejected fail-closed.
2. RBAC File Permission Gate: unprivileged peers rejected fail-closed.
3. RBAC File Permission Allowed: verified operator peers with SEND_FILE permitted.
4. Rust Data Plane Bytearray Zeroization: DestroyerNode receives mutable bytearray and wipes.
5. Strict Session Manager TPM Production Gate: fails closed without simulation fallback.
6. Witnessed Key Ceremony Production Hardware Gate: fails closed without simulation fallback.
7. MLS Framing Transcript Chaining: commits chain SHA3-512 transcript hashes across operations.
8. Twin Parity: 100% functional line-by-line parity between secure_p2.py and secure_p2p.py.
"""

import os
import sys
import base64
import asyncio
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from pathlib import Path

from data_models import SecurityRole, SecurityPermission
from zero_trust_engine import RBACPolicyEngine
from group_key_manager import GroupKeyManager, TRANSCRIPT_INIT
from file_transfer import FileMessage, FileMessageType


def test_zero_trust_file_message_rejected_for_unverified_peer():
    """Unverified peers (e.g. PENDING_OOB_VERIFICATION) must be rejected fail-closed on file transfer."""
    async def _run():
        try:
            from secure_p2p import SecureP2PChat
        except ImportError:
            from archive.legacy_prototype.secure_p2p import SecureP2PChat

        chat = SecureP2PChat(identity="test_alice")
        chat.peer_username = "bob"
        chat.peer_verification_status = "PENDING_OOB_VERIFICATION"

        msg = FileMessage(
            message_type=FileMessageType.FILE_ACCEPT,
            file_id="test-file-123",
        )
        raw_b64 = base64.b64encode(msg.to_bytes()).decode('ascii')
        payload = f"FILE:{raw_b64}"

        with patch.object(chat, '_handle_file_accept', new_callable=AsyncMock) as mock_accept:
            await chat._handle_file_message(payload)
            mock_accept.assert_not_called()

        chat.cleanup()

    asyncio.run(_run())


def test_rbac_file_message_rejected_without_send_file_permission():
    """Authenticated peers without SEND_FILE (e.g. ANONYMOUS) must be rejected fail-closed."""
    async def _run():
        try:
            from secure_p2p import SecureP2PChat
        except ImportError:
            from archive.legacy_prototype.secure_p2p import SecureP2PChat

        chat = SecureP2PChat(identity="test_alice")
        chat.peer_username = "bob"
        chat.peer_verification_status = "VERIFIED_MATCH"
        chat.rbac.assign_role("bob", SecurityRole.ANONYMOUS)

        msg = FileMessage(
            message_type=FileMessageType.FILE_ACCEPT,
            file_id="test-file-123",
        )
        raw_b64 = base64.b64encode(msg.to_bytes()).decode('ascii')
        payload = f"FILE:{raw_b64}"

        with patch.object(chat, '_handle_file_accept', new_callable=AsyncMock) as mock_accept:
            await chat._handle_file_message(payload)
            mock_accept.assert_not_called()

        chat.cleanup()

    asyncio.run(_run())


def test_file_message_accepted_for_verified_operator():
    """Verified operator peer with SEND_FILE is permitted through to handler."""
    async def _run():
        try:
            from secure_p2p import SecureP2PChat
        except ImportError:
            from archive.legacy_prototype.secure_p2p import SecureP2PChat

        chat = SecureP2PChat(identity="test_alice")
        chat.peer_username = "bob"
        chat.peer_verification_status = "VERIFIED_MATCH"
        chat.rbac.assign_role("bob", SecurityRole.OPERATOR)

        msg = FileMessage(
            message_type=FileMessageType.FILE_ACCEPT,
            file_id="test-file-123",
        )
        raw_b64 = base64.b64encode(msg.to_bytes()).decode('ascii')
        payload = f"FILE:{raw_b64}"

        with patch.object(chat, '_handle_file_accept', new_callable=AsyncMock) as mock_accept:
            await chat._handle_file_message(payload)
            mock_accept.assert_called_once()

        chat.cleanup()

    asyncio.run(_run())


def test_rust_data_plane_bytearray_zeroization():
    """Verify that DestroyerNode.establish receives a bytearray and zeroizes memory."""
    from destroyer_node import DestroyerNode, DataPlaneUnavailable

    try:
        node = DestroyerNode()
    except DataPlaneUnavailable:
        node = DestroyerNode.__new__(DestroyerNode)
        node.engine = MagicMock()

    secret = bytearray(b"A" * 32)
    assert any(b != 0 for b in secret)  # nosec: B101

    node.establish(secret, is_initiator=True)
    # DestroyerNode zeroizes mutable bytearrays
    assert all(b == 0 for b in secret), "Expected secret bytearray to be zeroized in-place"  # nosec: B101


def test_session_manager_tpm_production_gate_fail_closed():
    """In production mode, session manager TPM quote generation fails closed if hardware unavailable."""
    async def _run():
        from network.session_manager import SessionManager, SecurityError

        sm = SessionManager()
        mock_kex = MagicMock()
        mock_kex.get_public_bundle.return_value = {"identity": "test_local"}

        mock_reader = AsyncMock()
        mock_writer = MagicMock()

        with patch.dict(os.environ, {"P2P_PRODUCTION": "1", "P2P_TPM_QUOTE": "1"}):
            with patch("tpm_quote.attach_quote_to_handshake", side_effect=RuntimeError("Hardware TPM absent")):
                with pytest.raises(SecurityError, match="MILITARY FATAL: TPM attestation quote generation failed"):
                    await sm._perform_handshake(
                        hybrid_kex=mock_kex,
                        peer_id="test_peer",
                        reader=mock_reader,
                        writer=mock_writer,
                        is_initiator=True
                    )

    asyncio.run(_run())


def test_witnessed_key_ceremony_hardware_production_gate_fail_closed():
    """In production mode, witnessed key ceremony raises RuntimeError if hardware TPM is absent."""
    from scripts.witnessed_key_ceremony import WitnessedKeyCeremony

    ceremony = WitnessedKeyCeremony()
    with patch.dict(os.environ, {"P2P_PRODUCTION": "1"}):
        with patch("scripts.witnessed_key_ceremony.is_tpm_available", return_value=False):
            with pytest.raises(RuntimeError, match="MILITARY FATAL: Physical hardware root-of-trust"):
                ceremony.check_hardware_root_of_trust()


def test_mls_framing_transcript_hash_chain():
    """GroupKeyManager chains RFC 9420-style SHA3-512 transcript hash across epochs."""
    gkm = GroupKeyManager(key_size=32)
    group_id = "battle-group-alpha"

    # 1. Create group
    info = gkm.create_group(group_id, ["officer1", "officer2"])
    assert info["epoch"] == 0  # nosec: B101
    tx0 = gkm.transcript_of(group_id)
    assert tx0 != TRANSCRIPT_INIT  # nosec: B101
    assert len(tx0) == 64  # SHA3-512 digest length  # nosec: B101

    # 2. Add member
    epoch1 = gkm.add_member(group_id, "officer3")
    assert epoch1 == 1  # nosec: B101
    tx1 = gkm.transcript_of(group_id)
    assert tx1 != tx0  # nosec: B101
    assert len(tx1) == 64  # nosec: B101

    # 3. Rotate key
    epoch2 = gkm.rotate(group_id)
    assert epoch2 == 2  # nosec: B101
    tx2 = gkm.transcript_of(group_id)
    assert tx2 != tx1  # nosec: B101
    assert len(tx2) == 64  # nosec: B101

    # 4. Remove member
    epoch3 = gkm.remove_member(group_id, "officer2")
    assert epoch3 == 3  # nosec: B101
    tx3 = gkm.transcript_of(group_id)
    assert tx3 != tx2  # nosec: B101
    assert len(tx3) == 64  # nosec: B101


def test_twin_parity_between_secure_p2_and_secure_p2p():
    """Verify 100% line-by-line parity between secure_p2.py and secure_p2p.py."""
    root = Path(__file__).resolve().parent.parent
    p2_path = root / "archive" / "legacy_prototype" / "secure_p2.py"
    p2p_path = root / "archive" / "legacy_prototype" / "secure_p2p.py"
    if not p2_path.exists() or not p2p_path.exists():
        pytest.skip("legacy prototype twins not present in archive")
    lines_p2 = [ln.rstrip() for ln in p2_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    lines_p2p = [ln.rstrip() for ln in p2p_path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    assert len(lines_p2) == len(lines_p2p), f"Drift in normalized line count: {len(lines_p2)} vs {len(lines_p2p)}"  # nosec: B101
    for idx, (l1, l2) in enumerate(zip(lines_p2, lines_p2p)):
        assert l1 == l2, f"Discrepancy at normalized line {idx+1}:\n  p2:  {l1}\n  p2p: {l2}"  # nosec: B101

