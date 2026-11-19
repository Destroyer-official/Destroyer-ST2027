"""
Unit and Integration Tests for Phase J: Blinded Homomorphic Cross-Domain Guard
Verifies Bell-LaPadula MLS clearance dominance and dirty-word filtering on blinded ciphertexts.
"""

import os
import sys
import unittest

from cjadc2_blinded_guard import (
    IS_NATIVE,
    BlindedCrossDomainGuard,
    BlindedClearanceToken,
    SecurityLevel,
    COMPARTMENT_TK,
    COMPARTMENT_SI,
    COMPARTMENT_NOFORN,
    ClearanceDominanceError,
    DirtyWordViolationError,
)


class TestBlindedCrossDomainGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.filter_key = b"\x42" * 32
        cls.guard = BlindedCrossDomainGuard(guard_id="GUARD-ALPHA", filter_key=cls.filter_key)
        cls.guard.add_prohibited_pattern("LAUNCH_CODE")
        cls.guard.add_prohibited_pattern("TOP SECRET")
        cls.guard.add_prohibited_pattern("TARGET_COORDINATES")

    def test_01_bell_lapadula_dominance_matrix(self):
        """Verify strict Bell-LaPadula dominance: No Read Up, No Write Down."""
        unclass = BlindedClearanceToken(SecurityLevel.UNCLASSIFIED)
        secret = BlindedClearanceToken(SecurityLevel.SECRET)
        ts = BlindedClearanceToken(SecurityLevel.TOP_SECRET)

        clean_text = "Standard tactical reconnaissance status report nominal."
        tokens = self.guard.tokenize_and_blind(clean_text)
        ciphertext = b"CIPHERTEXT-ENCRYPTED-FOR-DESTINATION"

        # 1. Secret -> TS (Up-transfer: TS dominates Secret): Allowed
        attestation = self.guard.evaluate_egress(
            source_enclave="ENCLAVE-SECRET",
            target_enclave="ENCLAVE-TOPSECRET",
            source_label=secret,
            target_clearance=ts,
            blinded_tokens=tokens,
            payload_ciphertext=ciphertext,
        )
        self.assertIsNotNone(attestation)

        # 2. TS -> Secret (Down-transfer: Secret does NOT dominate TS): Rejected
        with self.assertRaises(ClearanceDominanceError):
            self.guard.evaluate_egress(
                source_enclave="ENCLAVE-TOPSECRET",
                target_enclave="ENCLAVE-SECRET",
                source_label=ts,
                target_clearance=secret,
                blinded_tokens=tokens,
                payload_ciphertext=ciphertext,
            )

        # 3. Secret -> Unclassified: Rejected
        with self.assertRaises(ClearanceDominanceError):
            self.guard.evaluate_egress(
                source_enclave="ENCLAVE-SECRET",
                target_enclave="ENCLAVE-UNCLASS",
                source_label=secret,
                target_clearance=unclass,
                blinded_tokens=tokens,
                payload_ciphertext=ciphertext,
            )

    def test_02_compartment_dominance_enforcement(self):
        """Verify compartment subset checks under Bell-LaPadula."""
        src_label = BlindedClearanceToken(SecurityLevel.TOP_SECRET, COMPARTMENT_TK | COMPARTMENT_SI)
        tgt_all_comp = BlindedClearanceToken(
            SecurityLevel.TOP_SECRET, COMPARTMENT_TK | COMPARTMENT_SI | COMPARTMENT_NOFORN
        )
        tgt_missing_si = BlindedClearanceToken(SecurityLevel.TOP_SECRET, COMPARTMENT_TK)

        tokens = self.guard.tokenize_and_blind("Compartmented SITREP")
        ciphertext = b"CIPHERTEXT-COMPARTMENTED-PAYLOAD"

        # Target holds all required compartments: Allowed
        attestation = self.guard.evaluate_egress(
            source_enclave="SCIF-ALPHA",
            target_enclave="SCIF-BETA",
            source_label=src_label,
            target_clearance=tgt_all_comp,
            blinded_tokens=tokens,
            payload_ciphertext=ciphertext,
        )
        self.assertTrue(len(attestation) > 0)

        # Target missing SI compartment: Refused fail-closed
        with self.assertRaises(ClearanceDominanceError):
            self.guard.evaluate_egress(
                source_enclave="SCIF-ALPHA",
                target_enclave="SCIF-BETA",
                source_label=src_label,
                target_clearance=tgt_missing_si,
                blinded_tokens=tokens,
                payload_ciphertext=ciphertext,
            )

    def test_03_blinded_clean_payload_egress_and_attestation(self):
        """Verify clean payload generates cryptographically verifiable attestation."""
        label = BlindedClearanceToken(SecurityLevel.CONFIDENTIAL)
        clearance = BlindedClearanceToken(SecurityLevel.SECRET)

        clean_text = "Logistics supply convoy arrives at depot at 0600Z."
        tokens = self.guard.tokenize_and_blind(clean_text)
        ciphertext = b"\xDE\xAD\xBE\xEF" * 16

        attestation = self.guard.evaluate_egress(
            source_enclave="LOG-DEPOT-1",
            target_enclave="TAC-HQ",
            source_label=label,
            target_clearance=clearance,
            blinded_tokens=tokens,
            payload_ciphertext=ciphertext,
        )

        # Verify attestation at destination
        valid = self.guard.verify_egress_attestation(attestation, ciphertext)
        self.assertTrue(valid)

    def test_04_tampered_ciphertext_attestation_refusal(self):
        """Verify tampered ciphertext fails attestation verification."""
        label = BlindedClearanceToken(SecurityLevel.SECRET)
        clearance = BlindedClearanceToken(SecurityLevel.SECRET)

        clean_text = "Routine maintenance cycle completed."
        tokens = self.guard.tokenize_and_blind(clean_text)
        ciphertext = b"SECURE-PAYLOAD-ORIGINAL-DATA"

        attestation = self.guard.evaluate_egress(
            source_enclave="NODE-A",
            target_enclave="NODE-B",
            source_label=label,
            target_clearance=clearance,
            blinded_tokens=tokens,
            payload_ciphertext=ciphertext,
        )

        # Tampered ciphertext
        tampered_ciphertext = b"SECURE-PAYLOAD-TAMPERED-DATA"
        self.assertFalse(self.guard.verify_egress_attestation(attestation, tampered_ciphertext))

    def test_05_dirty_word_detection_refusal_fail_closed(self):
        """Verify prohibited dirty words in blinded stream cause immediate rejection."""
        label = BlindedClearanceToken(SecurityLevel.CONFIDENTIAL)
        clearance = BlindedClearanceToken(SecurityLevel.SECRET)

        dirty_text = "The secret LAUNCH_CODE must never be leaked across guard."
        dirty_tokens = self.guard.tokenize_and_blind(dirty_text)
        ciphertext = b"BLINDED-EXFILTRATION-CIPHERTEXT"

        with self.assertRaises(DirtyWordViolationError):
            self.guard.evaluate_egress(
                source_enclave="ENCLAVE-COMPROMISED",
                target_enclave="EXTERNAL-SINK",
                source_label=label,
                target_clearance=clearance,
                blinded_tokens=dirty_tokens,
                payload_ciphertext=ciphertext,
            )

    def test_06_dirty_bigram_detection(self):
        """Verify multi-word compound classifications are detected blindly."""
        label = BlindedClearanceToken(SecurityLevel.SECRET)
        clearance = BlindedClearanceToken(SecurityLevel.TOP_SECRET)

        dirty_text = "Document marked as TOP SECRET // NOFORN directive."
        dirty_tokens = self.guard.tokenize_and_blind(dirty_text)
        ciphertext = b"BLINDED-EXFILTRATION-CIPHERTEXT-2"

        with self.assertRaises(DirtyWordViolationError):
            self.guard.evaluate_egress(
                source_enclave="ENCLAVE-SRC",
                target_enclave="ENCLAVE-DST",
                source_label=label,
                target_clearance=clearance,
                blinded_tokens=dirty_tokens,
                payload_ciphertext=ciphertext,
            )

    def test_07_native_rust_fast_path(self):
        """Verify native Rust CoreBlindedCds is bound and active."""
        self.assertTrue(IS_NATIVE)
        self.assertIsNotNone(self.guard._core)


if __name__ == "__main__":
    unittest.main()
