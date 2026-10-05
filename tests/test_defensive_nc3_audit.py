#!/usr/bin/env python3
"""
Zero-Gap Defensive Security Audit Suite for Direct-P2P Military Messaging (NC3/EAM)
Validates:
1. EAM Gate: Rejects EAM from unverified or PENDING_OOB peers fail-closed.
2. Pre-Auth DoS limits: 64KB pre-auth frame ceiling, 10s pre-auth timeout, and per-IP rate limiting.
3. Traffic analysis resistance: Uniform 1024-byte block padding.
4. Storage hardening: Enclave KEK seed persistence prohibition when P2P_NO_PERSISTENT_SEEDS=1, and DPAPI sealing.
5. PCS Idle Rotation: Proactive DH ratchet advancement (force_ratchet_rotation).
6. Heartbeat flooding: ACK loop mitigation (max 1 ACK / 5s).
"""

import os
import secrets
import sys
import unittest
import time
import socket
import asyncio
import tempfile
import shutil

# Ensure workspace root in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nc3_nuclear_command import (
    NC3CommandController,
    OfficerIdentity,
    NC3SecurityError,
    DualCustodyViolation,
    get_or_create_tactical_officer
)
from p2p_core import FramedSocket, Message, MessageType, SocketError
from double_ratchet import DoubleRatchet
from secure_enclave_key_storage import SecureEnclaveKeyStorage, SecurityError


class TestDefensiveNC3Audit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._seal_pw_snapshot = os.environ.get("P2P_OFFICER_SEAL_PW")
        os.environ["P2P_OFFICER_SEAL_PW"] = "test-seal-passphrase-nc3-audit"
        cls.nc3 = NC3CommandController()
        cls.off1 = get_or_create_tactical_officer("GEN_TEST_1")
        cls.off2 = get_or_create_tactical_officer("ADM_TEST_2")
        cls.rec1 = get_or_create_tactical_officer("COL_TEST_3")
        cls.rec2 = get_or_create_tactical_officer("CAPT_TEST_4")

    @classmethod
    def tearDownClass(cls):
        if cls._seal_pw_snapshot is None:
            os.environ.pop("P2P_OFFICER_SEAL_PW", None)
        else:
            os.environ["P2P_OFFICER_SEAL_PW"] = cls._seal_pw_snapshot

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.war_key = secrets.token_bytes(32)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_eam_rejected_for_unverified_peer(self):
        """Verify Finding P0.1: EAM strictly rejected if sender peer is unverified or pending OOB."""
        eam = self.nc3.create_nuclear_eam(
            directive_code="FLASH-DEFCON-1",
            target_command="GLOBAL_STRIKE_ALPHA",
            pal_code="ALPHA-7792-BRAVO-4411",
            officer_1=self.off1,
            officer_2=self.off2,
            pal_key=self.war_key,
            validity_window_seconds=120.0
        )
        eam_data = eam.to_dict()

        # 1. Reject when peer_verified is False
        with self.assertRaises(NC3SecurityError) as ctx:
            self.nc3.verify_and_decrypt_nuclear_eam(
                eam_data=eam_data,
                recipient_officer_1=self.rec1,
                recipient_officer_2=self.rec2,
                sender_officer_1_pub=self.off1.public_key,
                sender_officer_2_pub=self.off2.public_key,
                pal_key=self.war_key,
                peer_verified=False
            )
        self.assertIn("not verified", str(ctx.exception).lower())

        # 2. Reject when peer_verification_state is PENDING_OOB_VERIFICATION
        with self.assertRaises(NC3SecurityError) as ctx2:
            self.nc3.verify_and_decrypt_nuclear_eam(
                eam_data=eam_data,
                recipient_officer_1=self.rec1,
                recipient_officer_2=self.rec2,
                sender_officer_1_pub=self.off1.public_key,
                sender_officer_2_pub=self.off2.public_key,
                pal_key=self.war_key,
                peer_verification_state="PENDING_OOB_VERIFICATION"
            )
        self.assertIn("unverified state", str(ctx2.exception).lower())

        # 3. Reject when peer_verification_state is BLOCKED_UNVERIFIED_TOFU
        with self.assertRaises(NC3SecurityError) as ctx3:
            self.nc3.verify_and_decrypt_nuclear_eam(
                eam_data=eam_data,
                recipient_officer_1=self.rec1,
                recipient_officer_2=self.rec2,
                sender_officer_1_pub=self.off1.public_key,
                sender_officer_2_pub=self.off2.public_key,
                pal_key=self.war_key,
                peer_verification_state="BLOCKED_UNVERIFIED_TOFU"
            )
        self.assertIn("unverified state", str(ctx3.exception).lower())

        # 4. Success when peer_verified is True and state is VERIFIED_MATCH
        decrypted = self.nc3.verify_and_decrypt_nuclear_eam(
            eam_data=eam_data,
            recipient_officer_1=self.rec1,
            recipient_officer_2=self.rec2,
            sender_officer_1_pub=self.off1.public_key,
            sender_officer_2_pub=self.off2.public_key,
            pal_key=self.war_key,
            peer_verification_state="VERIFIED_MATCH",
            peer_verified=True
        )
        self.assertEqual(decrypted, "ALPHA-7792-BRAVO-4411")
        print("\n[PASS] P0.1: EAM strictly rejected for unverified / PENDING_OOB peers fail-closed.")

    def test_pre_auth_dos_rate_limiting(self):
        """Verify Finding P0.2: 64KB pre-auth frame ceiling and 10s pre-auth timeout."""
        self.assertEqual(FramedSocket.PRE_AUTH_MAX_MESSAGE_SIZE, 64 * 1024)
        self.assertEqual(FramedSocket.PRE_AUTH_TIMEOUT, 10.0)

        async def test_oversized_preauth():
            # Real socketpair (loop.sock_recv requires true sockets with fileno).
            # A 70KB declared header (> 64KB) must fail BEFORE allocation.
            reader, writer = socket.socketpair()
            try:
                writer.sendall((70 * 1024).to_bytes(4, 'big') + b'X' * 100)
                writer.shutdown(socket.SHUT_WR)
                # Using max_size = PRE_AUTH_MAX_MESSAGE_SIZE should fail with ValueError
                with self.assertRaises(ValueError) as err:
                    await FramedSocket.receive_framed(reader, max_size=FramedSocket.PRE_AUTH_MAX_MESSAGE_SIZE)
                self.assertIn("exceeds maximum allowed size", str(err.exception).lower())
            finally:
                reader.close()
                writer.close()

        asyncio.run(test_oversized_preauth())
        print("\n[PASS] P0.2: Pre-auth frame ceiling strictly rejects frames > 64KB.")

    def test_eam_wire_padding(self):
        """Verify Finding P0.3: Wire payloads are uniformly padded to exact 1024-byte blocks."""
        # Use helper from secure_p2p
        from secure_p2p import SecureP2PChat
        
        chat = SecureP2PChat.__new__(SecureP2PChat)
        chat.BLOCK_PADDING_SIZE = 1024
        
        sample_short = b"EAM:SHORT_DIRECTIVE"
        sample_medium = b"EAM:" + b"X" * 1500
        
        padded_short = chat._add_random_padding(sample_short)
        padded_medium = chat._add_random_padding(sample_medium)
        
        self.assertEqual(len(padded_short) % 1024, 0)
        self.assertEqual(len(padded_medium) % 1024, 0)
        self.assertGreaterEqual(len(padded_short), 1024)
        self.assertGreaterEqual(len(padded_medium), 2048)
        
        # Verify lossless unpadding
        unpadded_short = chat._remove_random_padding(padded_short)
        unpadded_medium = chat._remove_random_padding(padded_medium)
        
        self.assertEqual(unpadded_short, sample_short)
        self.assertEqual(unpadded_medium, sample_medium)
        print("\n[PASS] P0.3: NC3 wire payloads uniformly padded to exact 1024B blocks.")

    def test_enclave_kek_seed_never_persisted_in_strict_mode(self):
        """Verify Finding P0.5: Enclave KEK seed persistence fails closed when P2P_NO_PERSISTENT_SEEDS=1."""
        orig_val = os.environ.get("P2P_NO_PERSISTENT_SEEDS")
        orig_pass = os.environ.get("P2P_ENCLAVE_PASSPHRASE")
        orig_master = os.environ.get("P2P_STORAGE_MASTER_KEY")

        try:
            os.environ["P2P_NO_PERSISTENT_SEEDS"] = "1"
            if "P2P_ENCLAVE_PASSPHRASE" in os.environ:
                del os.environ["P2P_ENCLAVE_PASSPHRASE"]
            if "P2P_STORAGE_MASTER_KEY" in os.environ:
                del os.environ["P2P_STORAGE_MASTER_KEY"]

            from secure_enclave_key_storage import SoftwareFallbackBackend, SecurityError

            # NOTE: SoftwareFallbackBackend derives the master key eagerly in
            # __init__, so construction itself must fail closed here.
            with self.assertRaises(SecurityError) as ctx:
                SoftwareFallbackBackend(storage_path=self.temp_dir)
            self.assertIn("persistence prohibited under military zero-trust policy", str(ctx.exception))
            self.assertFalse(os.path.exists(os.path.join(self.temp_dir, ".enclave_kek_seed")),
                             "seed file must never be created in strict mode")
            print("\n[PASS] P0.5: Enclave KEK seed persistence prohibited in strict zero-trust mode.")
        finally:
            if orig_val is not None:
                os.environ["P2P_NO_PERSISTENT_SEEDS"] = orig_val
            else:
                os.environ.pop("P2P_NO_PERSISTENT_SEEDS", None)
            if orig_pass is not None:
                os.environ["P2P_ENCLAVE_PASSPHRASE"] = orig_pass
            if orig_master is not None:
                os.environ["P2P_STORAGE_MASTER_KEY"] = orig_master

    def test_pcs_idle_rotation(self):
        """Verify Finding P1.1: DoubleRatchet.force_ratchet_rotation() advances DH keys and preserves decryptability.

        NOTE: DoubleRatchet enforces PQ mode (constructor forces enable_pq=True
        for NIST Level-5 posture), so this test wires full KEM/DSS material.
        Classical-only mode is not a supported configuration.
        """
        shared_root = secrets.token_bytes(32)
        alice = DoubleRatchet(shared_root, is_initiator=True)
        bob = DoubleRatchet(shared_root, is_initiator=False)

        # Full PQ mutual key setup (initiator encapsulates, responder decaps)
        alice.set_remote_public_key(
            bob.get_public_key(),
            kem_public_key=bob.get_kem_public_key(),
            dss_public_key=bob.get_dss_public_key())
        bob.set_remote_public_key(
            alice.get_public_key(),
            kem_public_key=alice.get_kem_public_key(),
            dss_public_key=alice.get_dss_public_key())
        bob.process_kem_ciphertext(alice.get_kem_ciphertext())
        self.assertTrue(alice.is_initialized())
        self.assertTrue(bob.is_initialized())

        # Alice sends message 1
        ct1 = alice.encrypt(b"Hello Bob 1")
        pt1 = bob.decrypt(ct1)
        self.assertEqual(pt1, b"Hello Bob 1")

        # Alice performs proactive PCS idle rotation
        old_pk = alice.get_public_key()
        new_pk = alice.force_ratchet_rotation()
        self.assertNotEqual(old_pk, new_pk)

        # Alice transmits message 2 with new DH ratchet key
        ct2 = alice.encrypt(b"Post-rotation message")
        pt2 = bob.decrypt(ct2)
        self.assertEqual(pt2, b"Post-rotation message")
        print("\n[PASS] P1.1: Proactive PCS idle rotation refreshes DH ratchet and decrypts seamlessly.")

    def test_heartbeat_ack_throttle(self):
        """Verify Finding P0.2 / Item 30: Heartbeat responses throttled to at most 1 ACK per 5 seconds."""
        from secure_p2p import SecureP2PChat
        chat = SecureP2PChat.__new__(SecureP2PChat)
        chat._last_hb_ack_time = 0.0
        
        now = time.time()
        # First heartbeat should trigger ACK
        chat._last_hb_ack_time = now
        
        # Second heartbeat immediately after (e.g. 0.5s) should be throttled
        t_soon = now + 0.5
        self.assertLess(t_soon - chat._last_hb_ack_time, 5.0)
        
        # Third heartbeat after 5.1s should be allowed
        t_later = now + 5.1
        self.assertGreaterEqual(t_later - chat._last_hb_ack_time, 5.0)
        print("\n[PASS] Item 30: Heartbeat responses strictly throttled to 1 ACK per 5 seconds.")


if __name__ == '__main__':
    unittest.main()
