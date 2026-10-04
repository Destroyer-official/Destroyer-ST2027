#!/usr/bin/env python3
"""
test_production_tier4_tactical_commands.py
Comprehensive test suite for Tier 4 tactical slash commands, Active Cyber Defense operator
controls, fail-closed ephemeral deletion, and thread-safe nonce generation.
"""

import os
import sys
import time
import unittest
import threading
import secrets
from unittest.mock import MagicMock, AsyncMock, patch

import ui.safety_numbers as safety_numbers
from active_cyber_defense import (
    ActiveCyberDefenseEngine,
    get_active_cyber_defense_engine,
    DefensivePlaybook,
)
from tactical_cloaking_router import tactical_cloak_enabled
from messaging.commands import CommandProcessor
from utils.helpers import NonceManager, constant_time_compare
from ephemeral_messaging import (
    EphemeralMessageManager,
    EphemeralMessage,
    MessageType,
    DeletionStatus,
    SecureWiper,
)


class TestTier4TacticalCommands(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.orchestrator = MagicMock()
        self.orchestrator.local_username = "AlphaStation"
        self.orchestrator.peer_username = "BravoStation"
        self.orchestrator.peer_id = "bravo_station_1"
        self.orchestrator.peer_ip = "192.168.1.50"
        self.orchestrator.peer_port = 50007
        self.orchestrator.is_connected = True
        self.orchestrator.use_ephemeral_identity = True
        self.orchestrator.security_verified = {"cert_exchange": True}
        self.orchestrator.message_queue = MagicMock()
        self.orchestrator.message_queue.qsize.return_value = 0
        self.orchestrator.active_file_transfers = {}
        self.orchestrator.security.validation.validate_command.return_value = True

        # Hybrid KEX mock
        self.mock_kex = MagicMock()
        self.mock_kex.identity = "alpha_ephemeral_id_12345"
        self.mock_kex.next_rotation_time = time.time() + 3600
        self.mock_kex.static_key = b"X" * 32
        self.mock_bundle = {
            "identity": "AlphaStation",
            "static_key": "c3RhdGljX2tleV9hbHBoYQ==",
            "signing_key": "c2lnbmluZ19rZXlfYWxwaGE=",
            "signed_prekey": "c2lnbmVkX3ByZWtleQ==",
            "prekey_signature": "cHJla2V5X3NpZ25hdHVyZQ==",
            "kem_public_key": "a2VtX3B1YmxpY19rZXk=",
            "falcon_public_key": "ZmFsY29uX3Br",
        }
        self.mock_kex.get_public_bundle.return_value = self.mock_bundle
        self.orchestrator.hybrid_kex = self.mock_kex
        self.orchestrator.my_hybrid_bundle = self.mock_bundle

        # Peer bundle mock
        self.peer_bundle = {
            "identity": "BravoStation",
            "static_key": "c3RhdGljX2tleV9icmF2bw==",
            "signing_key": "c2lnbmluZ19rZXlfYnJhdm8=",
            "signed_prekey": "c2lnbmVkX3ByZWtleV9icmF2bw==",
            "prekey_signature": "cHJla2V5X3NpZ19icmF2bw==",
            "kem_public_key": "a2VtX3BrX2JyYXZv",
            "falcon_public_key": "ZmFsY29uX3BrX2JyYXZv",
        }
        self.orchestrator.last_peer_bundle = self.peer_bundle
        self.orchestrator.peer_fingerprint = safety_numbers.fingerprint_bundle(self.peer_bundle)
        self.orchestrator.peer_verification_states = {"BravoStation": "VERIFIED_MATCH"}
        self.orchestrator.peer_verification_status = "VERIFIED_MATCH"

        self.cmd_processor = CommandProcessor(self.orchestrator)

    def test_safety_numbers_generation_and_symmetry(self):
        """Test that canonical TOFU safety numbers generate valid 48-digit strings symmetrically."""
        fp_alpha = safety_numbers.fingerprint_bundle(self.mock_bundle).encode("utf-8")
        fp_bravo = safety_numbers.fingerprint_bundle(self.peer_bundle).encode("utf-8")

        num_ab = safety_numbers.safety_numbers(fp_alpha, fp_bravo)
        num_ba = safety_numbers.safety_numbers(fp_bravo, fp_alpha)

        # 1. Exact symmetry
        self.assertEqual(num_ab, num_ba)

        # 2. 12 groups of 4 decimal digits = 48 digits + 11 spaces = 59 characters
        self.assertEqual(len(num_ab), 59)
        groups = num_ab.split(" ")
        self.assertEqual(len(groups), 12)
        for g in groups:
            self.assertEqual(len(g), 4)
            self.assertTrue(g.isdigit())

    def test_show_safety_numbers_command(self):
        """Test /safety-number command execution under CommandProcessor."""
        # Execute /safety-number with connected peer
        self.cmd_processor._show_safety_numbers(["/safety-number"])

        # Execute /safety-number with explicit peer argument
        target = "bravo_remote_test"
        stored_fp = "0123456789abcdef" * 8
        safety_numbers.store_pin(target, stored_fp)
        try:
            self.cmd_processor._show_safety_numbers(["/safety-number", target])
        finally:
            safety_numbers.revoke_pin(target)

    async def test_quarantine_operator_command(self):
        """Test /quarantine command execution severs session and updates ACD state."""
        acd = get_active_cyber_defense_engine()
        test_peer = "adversarial_station_99"

        # Ensure not quarantined initially
        acd.unquarantine_peer(test_peer)
        self.assertFalse(acd.is_peer_quarantined(test_peer))

        # Run /quarantine on test peer
        await self.cmd_processor._handle_quarantine(["/quarantine", test_peer])
        self.assertTrue(acd.is_peer_quarantined(test_peer))

        # Quarantine active connected peer triggers connection teardown
        self.orchestrator._close_connection = AsyncMock()
        await self.cmd_processor._handle_quarantine(["/quarantine", "BravoStation"])
        self.orchestrator._close_connection.assert_awaited_once_with(attempt_reconnect=False)

        # Lift quarantine
        acd.unquarantine_peer(test_peer)
        acd.unquarantine_peer("BravoStation")
        self.assertFalse(acd.is_peer_quarantined(test_peer))

    def test_tactical_cloak_toggle(self):
        """Test /silence and /cloak toggle P2P_TACTICAL_CLOAK correctly."""
        orig = os.environ.get("P2P_TACTICAL_CLOAK")
        try:
            os.environ["P2P_TACTICAL_CLOAK"] = "0"
            self.assertFalse(tactical_cloak_enabled())

            self.cmd_processor._toggle_tactical_cloak()
            self.assertTrue(tactical_cloak_enabled())

            self.cmd_processor._toggle_tactical_cloak()
            self.assertFalse(tactical_cloak_enabled())
        finally:
            if orig is not None:
                os.environ["P2P_TACTICAL_CLOAK"] = orig
            else:
                os.environ.pop("P2P_TACTICAL_CLOAK", None)

    async def test_rekey_command(self):
        """Test /rekey forces ratchet rotation when connected and ephemeral rotation when idle."""
        # 1. Connected with Double Ratchet
        mock_ratchet = MagicMock()
        mock_ratchet.force_ratchet_rotation.return_value = b"R" * 32
        self.orchestrator.ratchet = mock_ratchet
        self.orchestrator.is_connected = True

        await self.cmd_processor._handle_rekey()
        mock_ratchet.force_ratchet_rotation.assert_called_once()

        # 2. Disconnected ephemeral mode
        self.orchestrator.is_connected = False
        self.orchestrator.ratchet = None
        await self.cmd_processor._handle_rekey()
        self.mock_kex.rotate_keys.assert_called_once()

    def test_defense_telemetry_command(self):
        """Test /defense displays active cyber defense report without errors."""
        acd = get_active_cyber_defense_engine()
        acd.ingest_event("test_telemetry_probe", peer_id="probe_node")
        self.cmd_processor._show_defense_status()

    def test_ephemeral_fail_closed_deletion(self):
        """Verify DoD 5220.22-M secure deletion zeroizes memory and evicts fail-closed."""
        mgr = EphemeralMessageManager()
        msg = mgr.create_message(
            content=b"TOP_SECRET_MILITARY_PAYLOAD_DO_NOT_LEAK",
            sender_id="alpha",
            recipient_id="bravo",
            ttl_seconds=300,
            message_type=MessageType.STANDARD
        )
        msg_id = msg.message_id
        self.assertEqual(mgr.get_message_count(), 1)

        # 1. Normal secure deletion
        success = mgr.delete_message(msg_id, reason="mission_complete")
        self.assertTrue(success)
        self.assertEqual(mgr.get_message_count(), 0)
        self.assertIsNone(mgr.get_message(msg_id))
        self.assertTrue(all(b == 0 for b in msg.content))

        # 2. Fail-closed deletion under corrupted wipe or exception
        corrupt_msg = mgr.create_message(
            content=b"HIGH_SENSITIVITY_TACTICAL_INTEL",
            sender_id="charlie",
            recipient_id="delta",
            ttl_seconds=300
        )
        c_id = corrupt_msg.message_id
        with patch.object(SecureWiper, "verify_wipe", return_value=False):
            deleted = mgr.delete_message(c_id, reason="tamper_test")
            self.assertFalse(deleted)
            # Must be evicted from active messages despite verification failure
            self.assertEqual(mgr.get_message_count(), 0)
            self.assertIsNone(mgr.get_message(c_id))
            # Emergency zeroize pass must have cleared the content
            self.assertTrue(all(b == 0 for b in corrupt_msg.content))

    def test_nonce_manager_thread_safety(self):
        """Verify NonceManager generates unique nonces under multi-threaded concurrency."""
        nm = NonceManager(max_nonce_uses=100000)
        generated_nonces = []
        lock = threading.Lock()

        def worker():
            local_nonces = [nm.generate_nonce() for _ in range(500)]
            with lock:
                generated_nonces.extend(local_nonces)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(generated_nonces), 5000)
        # All 5000 nonces generated across 10 threads must be strictly distinct
        self.assertEqual(len(set(generated_nonces)), 5000)

    async def test_eam_nuclear_command_dispatch(self):
        """Test /eam and /nuclear command formatting and dispatch."""
        # 1. Without directive
        await self.cmd_processor.execute_command("/eam", ["/eam"])

        # 2. With directive
        directive = "DEFCON-1 AUTHORIZE STRATCOM STRIKE PACKAGE BRAVO"
        await self.cmd_processor.execute_command("/eam", ["/eam", directive])

    def test_zgdp_and_tpm_telemetry_commands(self):
        """Test /zgdp and /attest command outputs."""
        self.cmd_processor._show_zgdp_status(["/zgdp"])
        self.cmd_processor._show_tpm_attestation()

    async def test_cot_command_dispatch(self):
        """Test /cot command dispatch."""
        await self.cmd_processor.execute_command("/cot", ["/cot", "38.8719 -77.0563 PENTAGON_RECON"])


if __name__ == "__main__":
    unittest.main()
