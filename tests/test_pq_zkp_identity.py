#!/usr/bin/env python3
"""
tests/test_pq_zkp_identity.py
=============================
Verification suite for Phase H: Post-Quantum Zero-Knowledge Identity Attestation (PQ-ZKP).
Validates anonymous membership, clearance monotonicity, nullifier anti-replay, and SIGINT defeat.
"""

import os
import sys
import secrets
import unittest
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from identity.pq_zkp_verifier import (
    ClearanceLevel,
    TacticalIdentity,
    StratcomIdentityAccumulator,
    PqZkpIdentityProver,
    PqZkpIdentityVerifier,
    InsufficientClearanceError,
    DoubleAttestationError,
    ForgedProofError,
)
from destroyer_core import CorePqZkp, IS_NATIVE


class TestPqZkpIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup tactical test identities with distinct clearance tiers
        cls.ssbn_sub = TacticalIdentity(
            callsign="TITAN-SSBN-773",
            serial_number="USN-SSBN-2026-9901",
            clearance_level=ClearanceLevel.TOP_SECRET_SCI_NC3,
            public_key_fingerprint=secrets.token_bytes(32),
        )

        cls.icbm_silo = TacticalIdentity(
            callsign="MINUTEMAN-SILO-08",
            serial_number="USAF-NC3-4410",
            clearance_level=ClearanceLevel.TOP_SECRET,
            public_key_fingerprint=secrets.token_bytes(32),
        )

        cls.tactical_uav = TacticalIdentity(
            callsign="REAPER-UAV-14",
            serial_number="USAF-UAV-8812",
            clearance_level=ClearanceLevel.SECRET,
            public_key_fingerprint=secrets.token_bytes(32),
        )

        cls.patrol_boat = TacticalIdentity(
            callsign="DEFENDER-PB-02",
            serial_number="USCG-PB-1102",
            clearance_level=ClearanceLevel.CONFIDENTIAL,
            public_key_fingerprint=secrets.token_bytes(32),
        )

        # Build STRATCOM Merkle accumulator
        cls.accumulator = StratcomIdentityAccumulator([
            cls.ssbn_sub,
            cls.icbm_silo,
            cls.tactical_uav,
            cls.patrol_boat,
        ])

        cls.verifier = PqZkpIdentityVerifier(cls.accumulator.root)

    # =========================================================================
    # 1. Anonymous Attestation & Zero-Knowledge Privacy Tests
    # =========================================================================

    def test_01_anonymous_identity_attestation_success(self):
        """Verify that a valid tactical unit generates an attestation proof that verifies cleanly."""
        prover = PqZkpIdentityProver(self.ssbn_sub, self.accumulator, leaf_index=0)
        epoch_id = secrets.token_bytes(16)
        nonce = secrets.token_bytes(32)

        proof_wire = prover.generate_attestation_proof(
            claimed_min_clearance=ClearanceLevel.TOP_SECRET,
            epoch_id=epoch_id,
            session_nonce=nonce,
        )

        self.assertTrue(len(proof_wire) > 200)

        # Verifier checks proof
        valid, verified_lvl, nullifier = self.verifier.verify_attestation(
            proof_wire=proof_wire,
            expected_session_nonce=nonce,
            expected_min_clearance=ClearanceLevel.TOP_SECRET,
            epoch_id=epoch_id,
        )

        self.assertTrue(valid)
        self.assertEqual(verified_lvl, ClearanceLevel.TOP_SECRET)
        self.assertEqual(len(nullifier), 64)  # 32 bytes hex

    def test_02_zero_knowledge_privacy_no_callsign_leak(self):
        """Verify that the wire proof package contains zero occurrences of callsign, serial, or plaintext metadata."""
        prover = PqZkpIdentityProver(self.ssbn_sub, self.accumulator, leaf_index=0)
        proof_wire = prover.generate_attestation_proof(
            claimed_min_clearance=ClearanceLevel.SECRET,
            epoch_id=secrets.token_bytes(16),
            session_nonce=secrets.token_bytes(32),
        )

        # Search for raw string bytes
        self.assertNotIn(b"TITAN", proof_wire)
        self.assertNotIn(b"SSBN", proof_wire)
        self.assertNotIn(b"773", proof_wire)
        self.assertNotIn(b"USN-SSBN", proof_wire)
        self.assertNotIn(b"2026-9901", proof_wire)

    def test_03_clearance_monotonicity_top_secret_attests_to_secret(self):
        """Verify a TOP_SECRET_SCI_NC3 (Level 5) node can attest to SECRET (Level 3) without disclosing Level 5."""
        prover = PqZkpIdentityProver(self.ssbn_sub, self.accumulator, leaf_index=0)
        epoch_id = secrets.token_bytes(16)
        nonce = secrets.token_bytes(32)

        # Attest to Level 3
        proof_wire = prover.generate_attestation_proof(
            claimed_min_clearance=ClearanceLevel.SECRET,
            epoch_id=epoch_id,
            session_nonce=nonce,
        )

        # Gateway requiring SECRET accepts
        valid, verified_lvl, _ = self.verifier.verify_attestation(
            proof_wire=proof_wire,
            expected_session_nonce=nonce,
            expected_min_clearance=ClearanceLevel.SECRET,
            epoch_id=epoch_id,
        )

        self.assertTrue(valid)
        self.assertEqual(verified_lvl, ClearanceLevel.SECRET)

    # =========================================================================
    # 2. Clearance Boundary Enforcement Tests
    # =========================================================================

    def test_04_insufficient_clearance_refused_at_prover(self):
        """Verify a node with CONFIDENTIAL cannot generate a proof claiming TOP_SECRET."""
        prover = PqZkpIdentityProver(self.patrol_boat, self.accumulator, leaf_index=3)

        with self.assertRaises(InsufficientClearanceError):
            prover.generate_attestation_proof(
                claimed_min_clearance=ClearanceLevel.TOP_SECRET,
                epoch_id=secrets.token_bytes(16),
                session_nonce=secrets.token_bytes(32),
            )

    def test_05_insufficient_clearance_refused_at_verifier(self):
        """Verify that if a node proves SECRET, but the verifier requires TOP_SECRET, it is refused."""
        prover = PqZkpIdentityProver(self.tactical_uav, self.accumulator, leaf_index=2)
        epoch_id = secrets.token_bytes(16)
        nonce = secrets.token_bytes(32)

        proof_wire = prover.generate_attestation_proof(
            claimed_min_clearance=ClearanceLevel.SECRET,
            epoch_id=epoch_id,
            session_nonce=nonce,
        )

        with self.assertRaises(InsufficientClearanceError):
            self.verifier.verify_attestation(
                proof_wire=proof_wire,
                expected_session_nonce=nonce,
                expected_min_clearance=ClearanceLevel.TOP_SECRET,  # Demands higher clearance
                epoch_id=epoch_id,
            )

    # =========================================================================
    # 3. Anti-Replay & Sybil Nullifier Tests
    # =========================================================================

    def test_06_double_attestation_same_epoch_rejected_via_nullifier(self):
        """Verify that repeating an attestation in the same epoch is rejected as sybil reuse."""
        prover = PqZkpIdentityProver(self.icbm_silo, self.accumulator, leaf_index=1)
        epoch_id = secrets.token_bytes(16)
        nonce_1 = secrets.token_bytes(32)

        proof_wire_1 = prover.generate_attestation_proof(
            claimed_min_clearance=ClearanceLevel.TOP_SECRET,
            epoch_id=epoch_id,
            session_nonce=nonce_1,
        )

        # First attestation succeeds
        valid, _, _ = self.verifier.verify_attestation(
            proof_wire=proof_wire_1,
            expected_session_nonce=nonce_1,
            expected_min_clearance=ClearanceLevel.TOP_SECRET,
            epoch_id=epoch_id,
        )
        self.assertTrue(valid)

        # Second attestation in SAME epoch with different session nonce must fail closed
        nonce_2 = secrets.token_bytes(32)
        proof_wire_2 = prover.generate_attestation_proof(
            claimed_min_clearance=ClearanceLevel.TOP_SECRET,
            epoch_id=epoch_id,
            session_nonce=nonce_2,
        )

        with self.assertRaises(DoubleAttestationError):
            self.verifier.verify_attestation(
                proof_wire=proof_wire_2,
                expected_session_nonce=nonce_2,
                expected_min_clearance=ClearanceLevel.TOP_SECRET,
                epoch_id=epoch_id,
            )

    def test_07_different_epoch_fresh_nullifier_allowed(self):
        """Verify that across different operational epochs, fresh nullifiers allow unlinkable attestations."""
        prover = PqZkpIdentityProver(self.icbm_silo, self.accumulator, leaf_index=1)
        epoch_alpha = secrets.token_bytes(16)
        epoch_bravo = secrets.token_bytes(16)

        nonce_a = secrets.token_bytes(32)
        nonce_b = secrets.token_bytes(32)

        proof_a = prover.generate_attestation_proof(ClearanceLevel.SECRET, epoch_alpha, nonce_a)
        proof_b = prover.generate_attestation_proof(ClearanceLevel.SECRET, epoch_bravo, nonce_b)

        # Epoch Alpha
        valid_a, _, null_a = self.verifier.verify_attestation(proof_a, nonce_a, ClearanceLevel.SECRET, epoch_alpha)
        # Epoch Bravo
        valid_b, _, null_b = self.verifier.verify_attestation(proof_b, nonce_b, ClearanceLevel.SECRET, epoch_bravo)

        self.assertTrue(valid_a)
        self.assertTrue(valid_b)
        self.assertNotEqual(null_a, null_b)  # Unlinkable across epochs

    # =========================================================================
    # 4. Anti-Tamper & Security Boundary Tests
    # =========================================================================

    def test_08_tampered_merkle_root_fails_closed(self):
        """Verify that verifying against a rogue accumulator root fails closed."""
        prover = PqZkpIdentityProver(self.ssbn_sub, self.accumulator, leaf_index=0)
        nonce = secrets.token_bytes(32)
        proof = prover.generate_attestation_proof(ClearanceLevel.SECRET, secrets.token_bytes(16), nonce)

        rogue_root = secrets.token_bytes(32)
        rogue_verifier = PqZkpIdentityVerifier(rogue_root)

        with self.assertRaises(ForgedProofError):
            rogue_verifier.verify_attestation(proof, nonce, ClearanceLevel.SECRET)

    def test_09_mismatched_session_nonce_fails_closed(self):
        """Verify that returning a proof with a mismatched nonce fails closed."""
        prover = PqZkpIdentityProver(self.ssbn_sub, self.accumulator, leaf_index=0)
        nonce_issued = secrets.token_bytes(32)
        nonce_different = secrets.token_bytes(32)

        proof = prover.generate_attestation_proof(ClearanceLevel.SECRET, secrets.token_bytes(16), nonce_issued)

        with self.assertRaises(ForgedProofError):
            self.verifier.verify_attestation(proof, expected_session_nonce=nonce_different, expected_min_clearance=ClearanceLevel.SECRET)

    def test_10_tampered_proof_wire_fails_closed(self):
        """Verify bit-flipping any byte of the proof response fails closed."""
        prover = PqZkpIdentityProver(self.ssbn_sub, self.accumulator, leaf_index=0)
        nonce = secrets.token_bytes(32)
        epoch = secrets.token_bytes(16)
        proof = bytearray(prover.generate_attestation_proof(ClearanceLevel.SECRET, epoch, nonce))

        # Tamper challenge response byte
        proof[120] ^= 0x55

        with self.assertRaises(ForgedProofError):
            self.verifier.verify_attestation(bytes(proof), nonce, ClearanceLevel.SECRET, epoch_id=epoch)

    def test_11_non_member_cannot_forge_proof(self):
        """Verify an adversarial non-cleared node cannot forge a membership proof."""
        adversary = TacticalIdentity(
            callsign="ENEMY-SIGINT-STATION",
            serial_number="UNKNOWN-999",
            clearance_level=ClearanceLevel.TOP_SECRET_SCI_NC3,
            public_key_fingerprint=secrets.token_bytes(32),
        )
        # Adversary not enrolled in self.accumulator
        # Even if adversary tries index 0 with adversary identity:
        with self.assertRaises(ForgedProofError):
            prover_adv = PqZkpIdentityProver(adversary, self.accumulator, leaf_index=0)
            nonce = secrets.token_bytes(32)
            proof = prover_adv.generate_attestation_proof(ClearanceLevel.SECRET, secrets.token_bytes(16), nonce)
            self.verifier.verify_attestation(proof, nonce, ClearanceLevel.SECRET)

    def test_12_rust_core_pq_zkp_fast_path_direct(self):
        """Verify native Rust CorePqZkp methods directly."""
        self.assertTrue(IS_NATIVE)

        fp = secrets.token_bytes(32)
        leaf_hash = CorePqZkp.compute_leaf_hash(
            "TEST-UNIT", "SERIAL-1", 4, fp
        )
        self.assertEqual(len(leaf_hash), 32)

        root, leaves = CorePqZkp.build_merkle_accumulator([leaf_hash])
        self.assertEqual(len(root), 32)
        self.assertEqual(len(leaves), 256)


if __name__ == "__main__":
    unittest.main()
