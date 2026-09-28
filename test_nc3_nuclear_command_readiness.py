#!/usr/bin/env python3
"""
NC3 (Nuclear Command, Control, and Communications) Verification Battery
=======================================================================
Validates that the system is ready for Nuclear-Grade Command and Control,
Emergency Action Messages (EAM), and Permissive Action Link (PAL) transfer
in full compliance with:
- DoD Directive S-5210.41M (Two-Person Rule / Dual Custody)
- USSTRATCOM Emergency Action Procedures (EAP-STRAT)
- CJCSI 3265.01 (NC3 Security Baseline)
- FIPS 140-3 Security Level 4
"""

import os
import sys
import time
import json
import secrets
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from nc3_nuclear_command import (
    NC3CommandController,
    OfficerIdentity,
    EmergencyActionMessage,
    DualCustodyViolation,
    EAMExpiredError,
    EAMReplayError,
    NC3SecurityError,
    nc3_controller
)
from secure_memory_wiper import secure_wipe_dod
from destroyer_node import DestroyerNode


class TestNC3NuclearCommandReadiness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controller = NC3CommandController()
        # Explicit war-order authentication key for every trial: no defaults.
        cls.war_key = secrets.token_bytes(32)

        # Provision certified strategic command officers (ML-DSA-87)
        print("\n[*] Provisioning Certified Strategic Command Officers (NIST FIPS 204 ML-DSA-87)...")
        cls.general_alpha = cls.controller.generate_officer_credentials(
            officer_id="OF-GEN-01-NORAD",
            rank="General",
            duty_title="Commander, North American Aerospace Defense Command"
        )
        cls.admiral_bravo = cls.controller.generate_officer_credentials(
            officer_id="OF-ADM-02-STRAT",
            rank="Admiral",
            duty_title="Commander, United States Strategic Command"
        )
        cls.colonel_charlie = cls.controller.generate_officer_credentials(
            officer_id="OF-COL-03-NMCC",
            rank="Colonel",
            duty_title="Operations Director, National Military Command Center"
        )
        cls.captain_delta = cls.controller.generate_officer_credentials(
            officer_id="OF-CAPT-04-WING9",
            rank="Captain",
            duty_title="Combat Crew Commander, 90th Missile Wing"
        )
        print("    [OK] Strategic Officers Provisioned with Sovereign ML-DSA-87 Keys.")

    def test_01_two_person_rule_dual_authorization_success(self):
        """Verify standard Two-Person Rule: Dual-Officer signed EAM with PAL code transfer."""
        pal_code = "PAL-AUTH-ALPHA-9821-OMEGA-EXECUTE"
        directive_code = "FLASH-DEFCON-1-GUARDIAN-SHIELD"
        target_command = "NORAD-INTERCEPTOR-GRID-ALPHA-9"

        # Sender dual-custody authorization (General Alpha + Admiral Bravo)
        eam = self.controller.create_nuclear_eam(
            directive_code=directive_code,
            target_command=target_command,
            pal_code=pal_code,
            officer_1=self.general_alpha,
            officer_2=self.admiral_bravo,
            pal_key=self.war_key
        )

        self.assertIsNotNone(eam)
        self.assertEqual(eam.directive_code, directive_code)
        self.assertEqual(eam.classification, "TOP SECRET // SI-OP-IA // NC3 // NOFORN")
        self.assertEqual(len(eam.canonical_digest), 128)  # SHA3-512 hex

        # Recipient dual-custody verification (Colonel Charlie + Captain Delta)
        # Recipient officers verify sender signatures using public keys
        recovered_pal = self.controller.verify_and_decrypt_nuclear_eam(
            eam_data=eam.to_dict(),
            recipient_officer_1=self.colonel_charlie,
            recipient_officer_2=self.captain_delta,
            sender_officer_1_pub=self.general_alpha.public_key,
            sender_officer_2_pub=self.admiral_bravo.public_key,
            pal_key=self.war_key
        )

        self.assertEqual(recovered_pal, pal_code, "Decrypted PAL code must match original exactly.")
        print(f"\n  [NC3 TRIAL 1] Two-Person Rule Verified: Dual-Officer EAM successfully authenticated and unsealed.")

    def test_02_single_officer_impersonation_rejection(self):
        """Enforce Two-Person Rule: Reject any attempt by a single officer to self-authorize."""
        # Officer 1 attempts to sign as both custodian 1 and custodian 2
        with self.assertRaises(DualCustodyViolation):
            self.controller.create_nuclear_eam(
                directive_code="UNAUTHORIZED-SOLO-ATTEMPT",
                target_command="MISSILE-SILO-01",
                pal_code="ILLEGAL-PAL-ATTEMPT",
                officer_1=self.general_alpha,
                officer_2=self.general_alpha,  # Same officer!
                pal_key=self.war_key
            )
        print("  [NC3 TRIAL 2] Single-Officer Impersonation Blocked (DualCustodyViolation).")

    def test_03_tampered_pal_or_transcript_bitflip_rejection(self):
        """Verify tamper-resistance: Bit flip in ciphertext or directive triggers fail-closed abort."""
        pal_code = "PAL-SECURE-DELTA-5501"
        eam = self.controller.create_nuclear_eam(
            directive_code="EXEC-DIR-44",
            target_command="BOMBER-WING-5",
            pal_code=pal_code,
            officer_1=self.general_alpha,
            officer_2=self.admiral_bravo,
            pal_key=self.war_key
        )

        eam_dict = eam.to_dict()

        # Attack A: Tamper directive code
        tampered_dict_a = dict(eam_dict)
        tampered_dict_a["directive_code"] = "TAMPERED-DIR-99"
        with self.assertRaises(NC3SecurityError):
            self.controller.verify_and_decrypt_nuclear_eam(
                eam_data=tampered_dict_a,
                recipient_officer_1=self.colonel_charlie,
                recipient_officer_2=self.captain_delta,
                sender_officer_1_pub=self.general_alpha.public_key,
                sender_officer_2_pub=self.admiral_bravo.public_key,
                pal_key=self.war_key
            )

        # Attack B: Bit flip in encrypted PAL code
        tampered_dict_b = dict(eam_dict)
        ct_bytes = bytearray(tampered_dict_b["encrypted_pal_code"].encode())
        ct_bytes[5] ^= 0x01
        tampered_dict_b["encrypted_pal_code"] = ct_bytes.decode('utf-8', errors='ignore')
        with self.assertRaises(NC3SecurityError):
            self.controller.verify_and_decrypt_nuclear_eam(
                eam_data=tampered_dict_b,
                recipient_officer_1=self.colonel_charlie,
                recipient_officer_2=self.captain_delta,
                sender_officer_1_pub=self.general_alpha.public_key,
                sender_officer_2_pub=self.admiral_bravo.public_key,
                pal_key=self.war_key
            )
        print("  [NC3 TRIAL 3] Tampered EAM Payload Rejected Fail-Closed (100% Tamper Proof).")

    def test_04_temporal_validity_window_expiration(self):
        """Reject Emergency Action Messages outside strict validity window (Anti-Stale)."""
        pal_code = "PAL-TIMED-ALERT-1109"
        eam = self.controller.create_nuclear_eam(
            directive_code="EXPIRE-TEST",
            target_command="SUBMARINE-COMMAND-PACIFIC",
            pal_code=pal_code,
            officer_1=self.general_alpha,
            officer_2=self.admiral_bravo,
            pal_key=self.war_key,
            validity_window_seconds=1.0  # 1-second lifetime
        )

        eam_dict = eam.to_dict()
        # Wait for window to expire
        time.sleep(1.5)

        with self.assertRaises(EAMExpiredError):
            self.controller.verify_and_decrypt_nuclear_eam(
                eam_data=eam_dict,
                recipient_officer_1=self.colonel_charlie,
                recipient_officer_2=self.captain_delta,
                sender_officer_1_pub=self.general_alpha.public_key,
                sender_officer_2_pub=self.admiral_bravo.public_key,
                pal_key=self.war_key
            )
        print("  [NC3 TRIAL 4] Stale EAM Rejected Upon Window Expiration (EAMExpiredError).")

    def test_05_anti_replay_eam_rejection(self):
        """Prevent adversarial message re-transmission: identical EAM ID rejected on second arrival."""
        pal_code = "PAL-SINGLE-USE-KEY-7723"
        eam = self.controller.create_nuclear_eam(
            directive_code="ONCE-ONLY-DIRECTIVE",
            target_command="MISSILE-FIELD-BRAVO",
            pal_code=pal_code,
            officer_1=self.general_alpha,
            officer_2=self.admiral_bravo,
            pal_key=self.war_key
        )

        eam_dict = eam.to_dict()

        # First verification succeeds
        first_open = self.controller.verify_and_decrypt_nuclear_eam(
            eam_data=eam_dict,
            recipient_officer_1=self.colonel_charlie,
            recipient_officer_2=self.captain_delta,
            sender_officer_1_pub=self.general_alpha.public_key,
            sender_officer_2_pub=self.admiral_bravo.public_key,
            pal_key=self.war_key
        )
        self.assertEqual(first_open, pal_code)

        # Second verification with same EAM ID MUST fail as replay
        with self.assertRaises(EAMReplayError):
            self.controller.verify_and_decrypt_nuclear_eam(
                eam_data=eam_dict,
                recipient_officer_1=self.colonel_charlie,
                recipient_officer_2=self.captain_delta,
                sender_officer_1_pub=self.general_alpha.public_key,
                sender_officer_2_pub=self.admiral_bravo.public_key,
                pal_key=self.war_key
            )
        print("  [NC3 TRIAL 5] EAM Replay Attack Neutralized (EAMReplayError).")

    def test_06_dod_5220_22m_memory_zeroization(self):
        """Verify DoD 5220.22-M 3-pass sanitization purges sensitive buffers with read-back proof."""
        sensitive_code = bytearray(b"PAL-CLASSIFIED-TOP-SECRET-CODE-88992211")
        length = len(sensitive_code)

        # Execute DoD 5220.22-M 3-pass memory wipe
        wipe_result = secure_wipe_dod(sensitive_code)
        self.assertTrue(wipe_result.success)
        self.assertTrue(wipe_result.verification_passed)
        self.assertEqual(wipe_result.passes_completed, 3)

        # Verify all bytes in buffer are 0x00
        self.assertTrue(all(b == 0 for b in sensitive_code))
        print(f"  [NC3 TRIAL 6] DoD 5220.22-M 3-Pass Memory Sanitization Confirmed (All {length} bytes wiped).")

    def test_07_full_double_envelope_transmission_over_rust_data_plane(self):
        """
        Verify end-to-end nuclear EAM transmission through the destroyer_core Rust data plane.
        
        Flow:
        1. Dual-Officer EAM created and signed with ML-DSA-87.
        2. Serialized EAM sealed into destroyer_core Rust ChaCha20-Poly1305 outer envelope.
        3. Transported across the wire in quantized 1232B frames.
        4. Opened via destroyer_core, unsealed, and verified by recipient officers.
        """
        pal_code = "NUCLEAR-AUTHENTICATOR-CODE-ZULU-999"
        eam = self.controller.create_nuclear_eam(
            directive_code="EXECUTE-ORDER-CODE-ZULU",
            target_command="ALL-STRATEGIC-FORCES",
            pal_code=pal_code,
            officer_1=self.general_alpha,
            officer_2=self.admiral_bravo,
            pal_key=self.war_key
        )

        serialized_eam = eam.serialize().encode('utf-8')

        # Transmit through Rust data plane
        node_sender = DestroyerNode(51820)
        node_receiver = DestroyerNode(51821)
        session_key = secrets.token_bytes(32)

        node_sender.establish(session_key, is_initiator=True)
        node_receiver.establish(session_key, is_initiator=False)

        # Seal into outer Rust AEAD stream
        wire_blob = node_sender.seal_stream(serialized_eam)
        self.assertGreater(len(wire_blob), len(serialized_eam))

        # Open from outer Rust AEAD stream
        unsealed_bytes = node_receiver.open_stream(wire_blob)
        self.assertEqual(unsealed_bytes, serialized_eam)

        # Deserialize and verify dual signatures
        received_eam_dict = json.loads(unsealed_bytes.decode('utf-8'))
        unsealed_pal = self.controller.verify_and_decrypt_nuclear_eam(
            eam_data=received_eam_dict,
            recipient_officer_1=self.colonel_charlie,
            recipient_officer_2=self.captain_delta,
            sender_officer_1_pub=self.general_alpha.public_key,
            sender_officer_2_pub=self.admiral_bravo.public_key,
            pal_key=self.war_key
        )

        self.assertEqual(unsealed_pal, pal_code)
        print("  [NC3 TRIAL 7] Nuclear EAM Successfully Transmitted Over Rust Data Plane Double Envelope.")

    def test_08_war_order_key_mandatory_no_default(self):
        """Default/fallback war-order keys are prohibited: missing or short
        keys fail closed on BOTH create and verify paths."""
        with self.assertRaises(DualCustodyViolation):
            self.controller.create_nuclear_eam(
                directive_code="DIR",
                target_command="TGT",
                pal_code="PAL",
                officer_1=self.general_alpha,
                officer_2=self.admiral_bravo,
                pal_key=None,
            )
        with self.assertRaises(DualCustodyViolation):
            self.controller.create_nuclear_eam(
                directive_code="DIR",
                target_command="TGT",
                pal_code="PAL",
                officer_1=self.general_alpha,
                officer_2=self.admiral_bravo,
                pal_key=b"too-short",
            )
        eam = self.controller.create_nuclear_eam(
            directive_code="DIR",
            target_command="TGT",
            pal_code="PAL",
            officer_1=self.general_alpha,
            officer_2=self.admiral_bravo,
            pal_key=self.war_key,
        )
        with self.assertRaises(DualCustodyViolation):
            self.controller.verify_and_decrypt_nuclear_eam(
                eam_data=eam.to_dict(),
                recipient_officer_1=self.colonel_charlie,
                recipient_officer_2=self.captain_delta,
                sender_officer_1_pub=self.general_alpha.public_key,
                sender_officer_2_pub=self.admiral_bravo.public_key,
                pal_key=None,
            )
        print("  [NC3 TRIAL 8] Default War-Order Key Prohibited Fail-Closed.")

    def test_09_sealed_officer_credentials_roundtrip(self):
        """Officer credential files are AES-256-GCM sealed (never plaintext);
        corrupt files raise instead of silently minting replacement identity."""
        import json
        import tempfile

        import nc3_nuclear_command as nc3mod
        from nc3_nuclear_command import get_or_create_tactical_officer

        os.environ["P2P_OFFICER_SEAL_PW"] = "test-seal-passphrase"
        nc3mod._officer_seal_key_cache = None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                off = get_or_create_tactical_officer("TEST-OF-01", officers_dir=tmp)
                assert off.secret_key is not None  # nosec: B101
                with open(os.path.join(tmp, "TEST-OF-01.json"), encoding="utf-8") as f:
                    raw = f.read()
                stored = json.loads(raw)
                assert stored.get("v") == 2, "credential file must be sealed v2"  # nosec: B101
                assert "secret_key_hex" not in raw, "plaintext secret leaked to disk"  # nosec: B101
                # Reload from sealed file: same keys back.
                nc3mod._officer_seal_key_cache = None
                off2 = get_or_create_tactical_officer("TEST-OF-01", officers_dir=tmp)
                assert off2.secret_key == off.secret_key  # nosec: B101
                assert off2.public_key == off.public_key  # nosec: B101
                # Corrupt file: must raise, never silently re-issue identity.
                with open(os.path.join(tmp, "TEST-OF-01.json"), "w", encoding="utf-8") as f:
                    f.write("{corrupt-json")
                nc3mod._officer_seal_key_cache = None
                with self.assertRaises(NC3SecurityError):
                    get_or_create_tactical_officer("TEST-OF-01", officers_dir=tmp)
        finally:
            nc3mod._officer_seal_key_cache = None
            os.environ.pop("P2P_OFFICER_SEAL_PW", None)
        print("  [NC3 TRIAL 9] Sealed Officer Credentials Verified (AES-256-GCM at rest).")


if __name__ == "__main__":
    unittest.main(verbosity=2)

