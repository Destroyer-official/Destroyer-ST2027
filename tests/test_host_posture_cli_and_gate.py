#!/usr/bin/env python3
"""
test_host_posture_cli_and_gate.py

Automated testing for:
1. /host-posture and /host_posture chat command handling in SecureP2PChat
2. SessionManager handshake host posture gate under P2P_REQUIRE_HOST_POSTURE=1
"""

import os
import sys
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

try:
    from secure_p2p import SecureP2PChat
except ImportError:
    from archive.legacy_prototype.secure_p2p import SecureP2PChat
from network.session_manager import SessionManager, SecurityError


# Import scripts directory for verify_host_hardening
_here = os.path.dirname(os.path.abspath(__file__))
_root = _here if os.path.isdir(os.path.join(_here, "scripts")) else os.path.dirname(_here)
scripts_dir = os.path.join(_root, "scripts")
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)
import verify_host_hardening


def test_cli_host_posture_command():
    """Verify /host-posture command runs verifier and populates last_host_posture_report."""
    async def _run():
        chat = SecureP2PChat(identity="test_posture_node")
        await chat._handle_command("/host-posture")

        assert hasattr(chat, "last_host_posture_report")  # nosec: B101
        report = chat.last_host_posture_report
        assert "readiness_score" in report  # nosec: B101
        assert "overall_passed" in report  # nosec: B101
        assert "checks" in report  # nosec: B101

    asyncio.run(_run())


def test_cli_host_posture_strict_flag():
    """Verify /host-posture --strict enables strict evaluation."""
    async def _run():
        chat = SecureP2PChat(identity="test_posture_node")
        with patch("verify_host_hardening.HostHardeningVerifier") as mock_cls:
            mock_inst = MagicMock()
            mock_inst.run_all_checks.return_value = {
                "overall_passed": True,
                "readiness_score": 100.0,
                "summary": {"passed": 5, "warned": 0, "failed": 0},
                "checks": {},
            }
            mock_cls.return_value = mock_inst

            await chat._handle_command("/host-posture --strict")
            mock_cls.assert_called_with(strict=True)

    asyncio.run(_run())


def test_session_manager_host_posture_gate_fails_closed(monkeypatch):
    """Verify handshake aborts with SecurityError when P2P_REQUIRE_HOST_POSTURE=1 and posture check fails."""
    async def _run():
        monkeypatch.setenv("P2P_REQUIRE_HOST_POSTURE", "1")
        sm = SessionManager()

        reader = AsyncMock()
        writer = AsyncMock()
        hybrid_kex = MagicMock()
        hybrid_kex.get_public_bundle.return_value = {"bundle": "test"}

        with patch("scripts.verify_host_hardening.HostHardeningVerifier") as mock_cls:
            mock_inst = MagicMock()
            mock_inst.run_all_checks.return_value = {
                "overall_passed": False,
                "readiness_score": 40.0,
                "checks": {"secure_boot": {"status": "FAIL"}},
            }
            mock_cls.return_value = mock_inst

            with pytest.raises(SecurityError) as exc:
                await sm._perform_handshake(hybrid_kex, "node_b", reader, writer, is_initiator=True)

            assert "MILITARY FATAL: Host posture non-compliant" in str(exc.value)  # nosec: B101

    asyncio.run(_run())


def test_session_manager_host_posture_gate_passes_when_compliant(monkeypatch):
    """Verify handshake proceeds when P2P_REQUIRE_HOST_POSTURE=1 and posture check is compliant."""
    async def _run():
        monkeypatch.setenv("P2P_REQUIRE_HOST_POSTURE", "1")
        sm = SessionManager()

        reader = AsyncMock()
        writer = AsyncMock()
        hybrid_kex = MagicMock()
        hybrid_kex.get_public_bundle.return_value = {"bundle": "test"}
        hybrid_kex.verify_public_bundle.return_value = True
        hybrid_kex.initiate_handshake.return_value = ("handshake_msg", b"\x00" * 32)

        reader_recv = AsyncMock(side_effect=[
            {"type": "BUNDLE_OFFER", "bundle": {"bundle": "peer"}},
            {"type": "HANDSHAKE_CONFIRM", "success": True}
        ])

        with patch("scripts.verify_host_hardening.HostHardeningVerifier") as mock_cls, \
             patch("network.session_manager._send_frame", new=AsyncMock()), \
             patch("network.session_manager._recv_frame", new=reader_recv):
            mock_inst = MagicMock()
            mock_inst.run_all_checks.return_value = {
                "overall_passed": True,
                "readiness_score": 100.0,
                "checks": {"secure_boot": {"status": "PASS"}},
            }
            mock_cls.return_value = mock_inst

            secret = await sm._perform_handshake(hybrid_kex, "node_b", reader, writer, is_initiator=True)
            assert secret == b"\x00" * 32  # nosec: B101

    asyncio.run(_run())

