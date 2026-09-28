#!/usr/bin/env python3
"""
Test Suite: NC3 / PAL Two-Person Integrity (TPI) & Dual-Custody Hardware Protocol
================================================================================
DoD Directive S-5210.41M, CJCSI 3265.01, USSTRATCOM EAP-STRAT Compliance Validation

Validates:
1. Verifiable Secret Sharing (VSS): 2-of-2 split, cryptographic commitments, fail-closed anti-tamper.
2. Hardware Challenge-Response: Sovereign ML-DSA-87 signatures, unique physical token enforcement.
3. Physical Temporal Synchronization Window: Strict 2.0-second simultaneous action ceiling.
4. Autonomous Emergency Zeroization: Immediate DoD 5220.22-M 7-pass wiping on failure and completion.
"""

import os
import sys
import time
import secrets
import unittest
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from nc3_nuclear_command import (
    NC3CommandController,
    OfficerIdentity,
    VerifiableKeyShare,
    VerifiableSecretSharing2of2,
    HardwareChallenge,
    HardwareTokenResponse,
    DualCustodyViolation,
    DualCustodySynchronizationError,
    VSSChecksumMismatchError,
    HardwareTokenAuthenticationError,
    EAMExpiredError,
    EAMReplayError,
    NC3SecurityError,
    autonomous_emergency_zeroize
)
from secure_memory_wiper import secure_wipe_dod_7pass, secure_wipe_dod


class TestNC3TwoPersonIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controller = NC3CommandController()
        # Strategic Officers (NIST FIPS 204 ML-DSA-87)
        cls.gen_alpha = cls.controller.generate_officer_credentials(
            officer_id="OF-GEN-01-NORAD",
            rank="General",
            duty_title="Commander, North American Aerospace Defense Command"
        )
        cls.adm_bravo = cls.controller.generate_officer_credentials(
            officer_id="OF-ADM-02-STRAT",
            rank="Admiral",
            duty_title="Commander, United States Strategic Command"
        )
        cls.col_charlie = cls.controller.generate_officer_credentials(
            officer_id="OF-COL-03-NMCC",
            rank="Colonel",
            duty_title="Operations Director, National Military Command Center"
        )
        cls.capt_delta = cls.controller.generate_officer_credentials(
            officer_id="OF-CAPT-04-WING9",
            rank="Captain",
            duty_title="Combat Crew Commander, 90th Missile Wing"
        )

    # =========================================================================
    # 1. VERIFIABLE SECRET SHARING (VSS) TESTS
    # =========================================================================

    def test_01_vss_split_and_combine_success(self):
        """Verify 2-of-2 VSS splits a 32-byte PAL key and combines back perfectly."""
        original_key = secrets.token_bytes(32)
        s1, s2 = VerifiableSecretSharing2of2.split(original_key)

        self.assertEqual(s1.share_index, 1)
        self.assertEqual(s2.share_index, 2)
        self.assertEqual(len(s1.share_bytes), 32)
        self.assertEqual(len(s2.share_bytes), 32)
        # Individual shares must differ from the original key
        self.assertNotEqual(s1.share_bytes, original_key)
        self.assertNotEqual(s2.share_bytes, original_key)

        # Commitments must be valid
        self.assertTrue(VerifiableSecretSharing2of2.verify_share(s1))
        self.assertTrue(VerifiableSecretSharing2of2.verify_share(s2))

        # Reconstructed secret must match exactly
        reconstructed = VerifiableSecretSharing2of2.combine(s1, s2)
        self.assertEqual(reconstructed, original_key)

        # Reversed argument order must also work
        reconstructed_reversed = VerifiableSecretSharing2of2.combine(s2, s1)
        self.assertEqual(reconstructed_reversed, original_key)

    def test_02_vss_tampered_share_rejection(self):
        """Verify that altering even a single bit in a VSS share raises VSSChecksumMismatchError."""
        original_key = secrets.token_bytes(32)
        s1, s2 = VerifiableSecretSharing2of2.split(original_key)

        # Tamper with share 1
        tampered_bytes = bytearray(s1.share_bytes)
        tampered_bytes[0] ^= 0x01
        corrupted_s1 = VerifiableKeyShare(
            share_index=s1.share_index,
            share_bytes=bytes(tampered_bytes),
            share_commitment=s1.share_commitment,
            secret_commitment=s1.secret_commitment,
            salt=s1.salt,
            created_at=s1.created_at
        )

        self.assertFalse(VerifiableSecretSharing2of2.verify_share(corrupted_s1))
        with self.assertRaises(VSSChecksumMismatchError):
            VerifiableSecretSharing2of2.combine(corrupted_s1, s2)

    def test_03_vss_mismatched_ceremony_shares_rejection(self):
        """Verify that combining shares from two different ceremonies fails closed."""
        key_a = secrets.token_bytes(32)
        key_b = secrets.token_bytes(32)

        s1_a, _ = VerifiableSecretSharing2of2.split(key_a)
        _, s2_b = VerifiableSecretSharing2of2.split(key_b)

        with self.assertRaises(VSSChecksumMismatchError):
            VerifiableSecretSharing2of2.combine(s1_a, s2_b)

    def test_04_vss_invalid_share_indices(self):
        """Verify that providing duplicate shares (e.g. s1 and s1) fails."""
        original_key = secrets.token_bytes(32)
        s1, _ = VerifiableSecretSharing2of2.split(original_key)

        with self.assertRaises(DualCustodyViolation):
            VerifiableSecretSharing2of2.combine(s1, s1)

    # =========================================================================
    # 2. HARDWARE CHALLENGE-RESPONSE AUTHENTICATION TESTS
    # =========================================================================

    def test_05_hardware_challenge_issuance_and_response(self):
        """Verify hardware challenge generation and valid ML-DSA-87 token response."""
        challenge = self.controller.issue_hardware_challenge()
        self.assertEqual(len(challenge.server_nonce), 32)
        self.assertTrue(challenge.challenge_id)

        resp = self.controller.create_hardware_token_response(
            officer=self.gen_alpha,
            challenge=challenge,
            token_id="YUBIKEY-5-FIPS-SN-772819"  # nosec: B106
        )
        self.assertEqual(resp.officer_id, "OF-GEN-01-NORAD")
        self.assertEqual(resp.token_id, "YUBIKEY-5-FIPS-SN-772819")
        self.assertEqual(len(resp.client_nonce), 32)
        self.assertTrue(len(resp.auth_signature) > 0)

    def test_06_dual_hardware_token_distinct_physical_token_invariant(self):
        """DoD S-5210.41M: Both authorizations cannot come from the same physical token."""
        challenge = self.controller.issue_hardware_challenge()
        t = time.time()

        # Both officers erroneously authenticate with the SAME hardware token serial
        resp_1 = self.controller.create_hardware_token_response(
            officer=self.gen_alpha,
            challenge=challenge,
            token_id="SHARED-ROGUE-TOKEN-9999",  # nosec: B106
            timestamp_utc=t
        )
        resp_2 = self.controller.create_hardware_token_response(
            officer=self.adm_bravo,
            challenge=challenge,
            token_id="SHARED-ROGUE-TOKEN-9999",  # nosec: B106
            timestamp_utc=t + 0.1
        )

        with self.assertRaises(DualCustodyViolation) as ctx:
            self.controller.verify_dual_hardware_responses(
                challenge=challenge,
                resp_1=resp_1,
                resp_2=resp_2,
                officer_1_pub=self.gen_alpha.public_key,
                officer_2_pub=self.adm_bravo.public_key
            )
        self.assertIn("Both officers submitted the same physical token", str(ctx.exception))

    def test_07_dual_hardware_token_same_officer_rejection(self):
        """Verify that a single officer cannot dual-sign using two different tokens."""
        challenge = self.controller.issue_hardware_challenge()
        t = time.time()

        resp_1 = self.controller.create_hardware_token_response(
            officer=self.gen_alpha,
            challenge=challenge,
            token_id="TOKEN-A",  # nosec: B106
            timestamp_utc=t
        )
        resp_2 = self.controller.create_hardware_token_response(
            officer=self.gen_alpha,  # Same officer!
            challenge=challenge,
            token_id="TOKEN-B",  # nosec: B106
            timestamp_utc=t + 0.1
        )

        with self.assertRaises(DualCustodyViolation) as ctx:
            self.controller.verify_dual_hardware_responses(
                challenge=challenge,
                resp_1=resp_1,
                resp_2=resp_2,
                officer_1_pub=self.gen_alpha.public_key,
                officer_2_pub=self.gen_alpha.public_key
            )
        self.assertIn("distinct officers", str(ctx.exception).lower())

    def test_08_hardware_challenge_expired_rejection(self):
        """Verify that an expired hardware challenge fails closed."""
        challenge = HardwareChallenge(
            challenge_id=secrets.token_hex(16),
            server_nonce=secrets.token_bytes(32),
            timestamp_utc=time.time() - 45.0,  # 45 seconds ago
            expiry_seconds=30.0                # 30s ceiling
        )
        t = time.time()
        resp_1 = self.controller.create_hardware_token_response(self.gen_alpha, challenge, "TOKEN-1", timestamp_utc=t)
        resp_2 = self.controller.create_hardware_token_response(self.adm_bravo, challenge, "TOKEN-2", timestamp_utc=t + 0.1)

        with self.assertRaises(HardwareTokenAuthenticationError) as ctx:
            self.controller.verify_dual_hardware_responses(
                challenge=challenge,
                resp_1=resp_1,
                resp_2=resp_2,
                officer_1_pub=self.gen_alpha.public_key,
                officer_2_pub=self.adm_bravo.public_key
            )
        self.assertIn("expired", str(ctx.exception).lower())

    # =========================================================================
    # 3. PHYSICAL TEMPORAL SYNCHRONIZATION WINDOW TESTS
    # =========================================================================

    def test_09_temporal_synchronization_within_window_success(self):
        """Verify authorizations within the 2.0s simultaneous window succeed."""
        challenge = self.controller.issue_hardware_challenge()
        t1 = time.time()
        t2 = t1 + 1.2  # 1.2s difference <= 2.0s ceiling

        resp_1 = self.controller.create_hardware_token_response(self.gen_alpha, challenge, "HSM-NORAD-01", timestamp_utc=t1)
        resp_2 = self.controller.create_hardware_token_response(self.adm_bravo, challenge, "HSM-STRAT-02", timestamp_utc=t2)

        verified = self.controller.verify_dual_hardware_responses(
            challenge=challenge,
            resp_1=resp_1,
            resp_2=resp_2,
            officer_1_pub=self.gen_alpha.public_key,
            officer_2_pub=self.adm_bravo.public_key,
            max_sync_window_seconds=2.0
        )
        self.assertTrue(verified)

    def test_10_temporal_synchronization_breach_fails_closed(self):
        """
        Verify authorizations exceeding 2.0s ceiling (e.g. 3.2s) raise
        DualCustodySynchronizationError to prevent single-operator serial execution.
        """
        challenge = self.controller.issue_hardware_challenge()
        t1 = time.time()
        t2 = t1 + 3.2  # 3.2s difference > 2.0s ceiling

        resp_1 = self.controller.create_hardware_token_response(self.gen_alpha, challenge, "HSM-NORAD-01", timestamp_utc=t1)
        resp_2 = self.controller.create_hardware_token_response(self.adm_bravo, challenge, "HSM-STRAT-02", timestamp_utc=t2)

        with self.assertRaises(DualCustodySynchronizationError) as ctx:
            self.controller.verify_dual_hardware_responses(
                challenge=challenge,
                resp_1=resp_1,
                resp_2=resp_2,
                officer_1_pub=self.gen_alpha.public_key,
                officer_2_pub=self.adm_bravo.public_key,
                max_sync_window_seconds=2.0
            )
        self.assertIn("Temporal synchronization violation", str(ctx.exception))
        self.assertIn("3.200s apart", str(ctx.exception))

    # =========================================================================
    # 4. END-TO-END NC3 EAM WITH VSS AND DUAL HARDWARE TOKENS
    # =========================================================================

    def test_11_full_eam_with_vss_and_hardware_tokens(self):
        """Verify full operational lifecycle: EAM creation, signing, transfer, and unsealing with VSS & HW tokens."""
        pal_code = "WAR-ORDER-BRAVO-TARGET-GRID-7719-EXECUTE"
        directive_code = "FLASH-DEFCON-1-TITAN-STRIKE"
        target_command = "NMCC-PENTAGON-STRAT-WING"

        # 1. Generate 32-byte war-order key and split into VSS shares
        master_war_key = secrets.token_bytes(32)
        share_1, share_2 = VerifiableSecretSharing2of2.split(master_war_key)

        # 2. Issue hardware challenge and gather dual hardware responses
        challenge = self.controller.issue_hardware_challenge()
        now = time.time()
        resp_1 = self.controller.create_hardware_token_response(
            officer=self.gen_alpha,
            challenge=challenge,
            token_id="YUBIKEY-BIO-GEN-ALPHA-01",  # nosec: B106
            timestamp_utc=now
        )
        resp_2 = self.controller.create_hardware_token_response(
            officer=self.adm_bravo,
            challenge=challenge,
            token_id="YUBIKEY-BIO-ADM-BRAVO-02",  # nosec: B106
            timestamp_utc=now + 0.4  # 400ms delta (well within 2.0s window)
        )

        # 3. Create Nuclear EAM using VSS shares and hardware responses
        eam = self.controller.create_nuclear_eam(
            directive_code=directive_code,
            target_command=target_command,
            pal_code=pal_code,
            officer_1=self.gen_alpha,
            officer_2=self.adm_bravo,
            hw_challenge=challenge,
            hw_responses=(resp_1, resp_2),
            vss_shares=(share_1, share_2),
            max_sync_window_seconds=2.0
        )

        self.assertIsNotNone(eam)
        self.assertTrue(eam.hw_auth_digest)
        self.assertTrue(eam.vss_commitment)
        self.assertEqual(len(eam.hw_custodians), 2)

        # 4. Recipient verification and unsealing using VSS shares & verified hardware
        decrypted_pal = self.controller.verify_and_decrypt_nuclear_eam(
            eam_data=eam.to_dict(),
            recipient_officer_1=self.col_charlie,
            recipient_officer_2=self.capt_delta,
            sender_officer_1_pub=self.gen_alpha.public_key,
            sender_officer_2_pub=self.adm_bravo.public_key,
            vss_shares=(share_1, share_2),
            hw_challenge=challenge,
            hw_responses=(resp_1, resp_2),
            max_sync_window_seconds=2.0
        )

        self.assertEqual(decrypted_pal, pal_code)

    def test_12_eam_with_tampered_vss_fails_closed(self):
        """Verify that presenting corrupted VSS shares to verify_and_decrypt fails closed."""
        pal_code = "ALPHA-OMEGA-LAUNCH-9911"
        master_war_key = secrets.token_bytes(32)
        share_1, share_2 = VerifiableSecretSharing2of2.split(master_war_key)

        eam = self.controller.create_nuclear_eam(
            directive_code="DIR-TEST",
            target_command="CMD-TEST",
            pal_code=pal_code,
            officer_1=self.gen_alpha,
            officer_2=self.adm_bravo,
            vss_shares=(share_1, share_2)
        )

        # Corrupt share 2
        bad_bytes = bytearray(share_2.share_bytes)
        bad_bytes[5] ^= 0xFF
        bad_share_2 = VerifiableKeyShare(
            share_index=2,
            share_bytes=bytes(bad_bytes),
            share_commitment=share_2.share_commitment,
            secret_commitment=share_2.secret_commitment,
            salt=share_2.salt,
            created_at=share_2.created_at
        )

        with self.assertRaises(VSSChecksumMismatchError):
            self.controller.verify_and_decrypt_nuclear_eam(
                eam_data=eam.to_dict(),
                recipient_officer_1=self.col_charlie,
                recipient_officer_2=self.capt_delta,
                sender_officer_1_pub=self.gen_alpha.public_key,
                sender_officer_2_pub=self.adm_bravo.public_key,
                vss_shares=(share_1, bad_share_2)
            )

    # =========================================================================
    # 5. DOD 5220.22-M 7-PASS AUTONOMOUS ZEROIZATION TESTS
    # =========================================================================

    def test_13_autonomous_emergency_zeroize_7pass(self):
        """Verify DoD 5220.22-M 7-pass zeroization purges buffers with verification."""
        secret_buffer = bytearray(b"HIGHLY-CONFIDENTIAL-PAL-KEY-MATERIAL-1234567890")
        buf_len = len(secret_buffer)

        # Run 7-pass autonomous zeroization
        autonomous_emergency_zeroize(secret_buffer)

        # Verify every byte has been overwritten to 0x00
        self.assertTrue(all(b == 0 for b in secret_buffer))
        self.assertEqual(len(secret_buffer), buf_len)

    def test_14_secure_wipe_dod_7pass_direct(self):
        """Direct verification of secure_wipe_dod_7pass performing 7 full passes."""
        buf = bytearray(secrets.token_bytes(64))
        result = secure_wipe_dod_7pass(buf)

        self.assertTrue(result.success)
        self.assertTrue(result.verification_passed)
        self.assertEqual(result.passes_completed, 7)
        self.assertTrue(all(b == 0 for b in buf))


if __name__ == "__main__":
    unittest.main()

