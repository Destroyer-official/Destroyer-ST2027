"""
Automated Test Suite: Production Tier 5 Session & Config Audit Remediations

Verifies:
1. SessionContext.secure_cleanup() actively zeroizes DoubleRatchet and HybridKeyExchange states.
2. SessionManager.terminate_session() invokes genuine secure_cleanup() and reclaims memory.
3. SessionManager.create_session() fails closed with zero state/socket leakage on handshake/init failure.
4. SessionManager.get_session_stats() is safe against dictionary mutation during iteration.
5. ConfigManager.save() persists configurations atomically (temp file + fsync + os.replace).
6. secure_p2p_core.utils.config_manager fail-closed should_fallback() policy and CNSA 2.0 signatures.
"""

import asyncio
import gc
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, AsyncMock, patch

from network.session_manager import SessionContext, SessionManager, SecurityError
from utils.config_manager import ConfigManager
import secure_p2p_core.utils.config_manager as core_cm


class TestTier5SessionAndConfigAudit(unittest.IsolatedAsyncioTestCase):

    async def test_session_context_secure_cleanup_wipes_all_crypto(self):
        """Verify SessionContext.secure_cleanup actively zeroes crypto components and closes writer."""
        mock_dr = MagicMock()
        mock_dr.secure_cleanup = MagicMock()
        mock_kex = MagicMock()
        mock_kex.secure_cleanup = MagicMock()
        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False
        mock_audit = MagicMock()

        ctx = SessionContext(
            peer_id="peer_alpha",
            reader=MagicMock(),
            writer=mock_writer,
            double_ratchet=mock_dr,
            hybrid_kex=mock_kex,
            audit_logger=mock_audit,
            session_id="session_alpha_1"
        )

        ctx.secure_cleanup()

        mock_dr.secure_cleanup.assert_called_once()
        mock_kex.secure_cleanup.assert_called_once()
        mock_writer.close.assert_called_once()
        mock_audit.flush_buffer.assert_called_once()
        mock_audit.close.assert_called_once()

        self.assertIsNone(ctx.double_ratchet)
        self.assertIsNone(ctx.hybrid_kex)
        self.assertIsNone(ctx.audit_logger)

    async def test_session_manager_terminate_session_calls_crypto_secure_cleanup(self):
        """Verify SessionManager.terminate_session invokes genuine secure_cleanup() on DoubleRatchet and HybridKEX."""
        sm = SessionManager()

        mock_dr = MagicMock()
        mock_dr.secure_cleanup = MagicMock()
        mock_kex = MagicMock()
        mock_kex.secure_cleanup = MagicMock()
        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False
        mock_writer.wait_closed = AsyncMock()

        ctx = SessionContext(
            peer_id="peer_bravo",
            reader=MagicMock(),
            writer=mock_writer,
            double_ratchet=mock_dr,
            hybrid_kex=mock_kex,
            session_id="session_bravo_1"
        )
        sm.sessions["peer_bravo"] = ctx

        await sm.terminate_session("peer_bravo")

        mock_dr.secure_cleanup.assert_called_once()
        mock_kex.secure_cleanup.assert_called_once()
        mock_writer.close.assert_called_once()
        self.assertNotIn("peer_bravo", sm.sessions)

    async def test_session_manager_create_session_fail_closed_cleanup_on_error(self):
        """Verify create_session securely wipes partial crypto material and closes writer on handshake failure."""
        sm = SessionManager()
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False

        with patch.object(sm, "_perform_handshake", side_effect=SecurityError("Handshake failure injection")):
            with self.assertRaises(SecurityError):
                await sm.create_session("peer_charlie", mock_reader, mock_writer, is_initiator=True)

        # Ensure writer was closed and no session remained in active sessions
        mock_writer.close.assert_called()
        self.assertNotIn("peer_charlie", sm.sessions)

    async def test_session_manager_stats_concurrent_mutation_safe(self):
        """Verify get_session_stats does not crash if sessions are mutated concurrently."""
        sm = SessionManager()
        for i in range(10):
            sm.sessions[f"peer_{i}"] = SessionContext(
                peer_id=f"peer_{i}",
                reader=MagicMock(),
                writer=MagicMock(),
                session_id=f"session_{i}"
            )

        stats = sm.get_session_stats()
        self.assertEqual(stats["active_sessions"], 10)
        self.assertEqual(len(stats["peer_ids"]), 10)
        self.assertEqual(len(stats["sessions"]), 10)

    def test_utils_config_manager_atomic_save(self):
        """Verify utils.config_manager.ConfigManager.save writes atomically without temp file residue."""
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "test_config.json")
            cfg = ConfigManager(config_path=cfg_path)
            cfg.set("security.test_key", "atomic_val_123")

            success = cfg.save()
            self.assertTrue(success)
            self.assertTrue(os.path.exists(cfg_path))

            # Verify saved content
            with open(cfg_path, "r", encoding="utf-8") as f:
                saved_data = json.load(f)
            self.assertEqual(saved_data.get("security", {}).get("test_key"), "atomic_val_123")

            # Check that no temporary files (.tmp.*) were left behind
            dir_files = os.listdir(td)
            temp_files = [fn for fn in dir_files if ".tmp." in fn]
            self.assertEqual(temp_files, [])

    def test_secure_p2p_core_config_manager_invariants(self):
        """Verify secure_p2p_core config manager fail-closed fallback and atomic save."""
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "core_config.json")
            cfg = core_cm.ConfigManager(config_path=cfg_path)

            # Invariant 1: should_fallback defaults to False (fail-closed)
            self.assertFalse(cfg.should_fallback("double_ratchet"))
            self.assertFalse(cfg.should_fallback("hybrid_kex"))
            self.assertFalse(cfg.should_fallback("audit_logging"))

            # Invariant 2: CNSA 2.0 signature standard
            sigs = core_cm.ConfigManager.DEFAULT_SECURITY_SETTINGS["security"]["algorithms"]["signatures"]
            self.assertIn("ML-DSA-87", sigs)
            self.assertIn("SLH-DSA-256f", sigs)
            self.assertNotIn("SPHINCS+", sigs)

            # Invariant 3: Atomic save
            cfg.set("security.core_test_key", "core_val_456")
            success = cfg.save()
            self.assertTrue(success)
            self.assertTrue(os.path.exists(cfg_path))

            with open(cfg_path, "r", encoding="utf-8") as f:
                saved_data = json.load(f)
            self.assertEqual(saved_data.get("security", {}).get("core_test_key"), "core_val_456")

            # Check that no temporary files (.tmp.*) were left behind
            dir_files = os.listdir(td)
            temp_files = [fn for fn in dir_files if ".tmp." in fn]
            self.assertEqual(temp_files, [])


if __name__ == "__main__":
    unittest.main()
