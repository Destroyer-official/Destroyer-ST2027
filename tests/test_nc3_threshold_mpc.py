#!/usr/bin/env python3
"""
Test Suite: Decentralized t-of-n Threshold Post-Quantum Signatures (MPC NC3)
=============================================================================
DoD Directive S-5210.41M, FIPS 204 ML-DSA-87, CNSA 2.0 Compliance Validation

Validates:
1. NC3ThresholdKeyGenerator: t-of-n Shamir/Feldman VSS with SHA-384 public commitments.
2. OperatorSiloNode: sovereign ML-DSA-87 signing, DoD S-5210.41M payload verification,
   anti-replay, and temporal freshness enforcement.
3. NC3ThresholdAggregator: Combining t valid partial shares into full threshold signature
   verifying against master public key.
4. Security Invariant: Master strategic authorization key is never reconstructed on any
   single machine.
5. Security Invariant: Strict 2.0-second simultaneous co-signing window (DoD S-5210.41M).
6. Quorum enforcement: < t shares fail, duplicate silos fail, distinct t-of-n succeeds.
7. Anti-tamper: tampered shares, forged signatures, altered payloads fail closed.
8. Wire format: binary serialization and deserialization roundtrip.
"""

import os
import sys
import time
import json
import secrets
import tempfile
import unittest
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from nc3_threshold_mpc import (
    NC3ThresholdKeyGenerator,
    OperatorSiloNode,
    NC3ThresholdAggregator,
    ThresholdShare,
    FeldmanCommitments,
    PartialSignature,
    ThresholdSignature,
    create_eam_payload,
    verify_threshold_signature,
    NC3SecurityError,
    DualCustodyViolation,
    DualCustodySynchronizationError,
    VSSChecksumMismatchError,
    EAMExpiredError,
    EAMReplayError,
    EAM_PREAMBLE,
    EAM_CLASSIFICATION,
    MAX_CO_SIGNING_WINDOW_SECONDS,
)


class TestNC3ThresholdMPC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generator = NC3ThresholdKeyGenerator()
        # Pre-generate standard 2-of-3 threshold ceremony fixtures
        cls.master_pk_2of3, cls.shares_2of3, cls.commitments_2of3 = cls.generator.generate_threshold_key(
            threshold=2,
            total_shares=3,
            silo_ids=["SILO-ALPHA-01", "SILO-BRAVO-02", "SILO-CHARLIE-03"]
        )

        # Pre-generate 3-of-5 threshold ceremony fixtures
        cls.master_pk_3of5, cls.shares_3of5, cls.commitments_3of5 = cls.generator.generate_threshold_key(
            threshold=3,
            total_shares=5,
            silo_ids=[f"STRAT-SILO-{i:02d}" for i in range(1, 6)]
        )

    # =========================================================================
    # 1. KEY GENERATOR & FELDMAN COMMITMENT TESTS
    # =========================================================================

    def test_01_key_generation_2of3_shares_and_commitments(self):
        """Verify 2-of-3 threshold key generation produces valid Feldman commitments."""
        self.assertEqual(len(self.shares_2of3), 3)
        self.assertEqual(self.commitments_2of3.threshold, 2)
        self.assertEqual(self.commitments_2of3.total_shares, 3)
        self.assertEqual(len(self.commitments_2of3.coeff_commitments), 2)
        self.assertEqual(len(self.commitments_2of3.share_commitments), 3)
        self.assertEqual(len(self.master_pk_2of3), 2592)  # ML-DSA-87 public key size

        # Each share must individually satisfy Feldman commitment
        for share in self.shares_2of3:
            self.assertTrue(self.commitments_2of3.verify_share(share))

    def test_02_key_generation_3of5_shares_and_commitments(self):
        """Verify 3-of-5 threshold key generation produces valid Feldman commitments."""
        self.assertEqual(len(self.shares_3of5), 5)
        self.assertEqual(self.commitments_3of5.threshold, 3)
        self.assertEqual(self.commitments_3of5.total_shares, 5)
        self.assertEqual(len(self.commitments_3of5.coeff_commitments), 3)
        self.assertEqual(len(self.commitments_3of5.share_commitments), 5)

        for share in self.shares_3of5:
            self.assertTrue(self.commitments_3of5.verify_share(share))

    def test_03_key_generation_invalid_parameters_refused(self):
        """Verify key generator enforces t >= 2 and n >= t."""
        # Threshold < 2 must fail
        with self.assertRaises(DualCustodyViolation):
            self.generator.generate_threshold_key(threshold=1, total_shares=3)

        # Total shares < threshold must fail
        with self.assertRaises(DualCustodyViolation):
            self.generator.generate_threshold_key(threshold=4, total_shares=3)

        # Duplicate silo IDs must fail
        with self.assertRaises(DualCustodyViolation):
            self.generator.generate_threshold_key(
                threshold=2, total_shares=2, silo_ids=["SILO-01", "SILO-01"]
            )

    def test_04_tampered_share_fails_feldman_commitment(self):
        """Verify that altering a share value fails Feldman commitment verification."""
        share = self.shares_2of3[0]
        # Create tampered share copy with corrupted share_value
        tampered = ThresholdShare(
            share_index=share.share_index,
            share_value=(share.share_value ^ 0x01),
            share_bytes=share.share_bytes,
            share_commitment=share.share_commitment,
            master_commitment=share.master_commitment,
            salt=share.salt,
            created_at=share.created_at,
            silo_id=share.silo_id,
        )
        self.assertFalse(self.commitments_2of3.verify_share(tampered))

    def test_05_tampered_salt_fails_feldman_commitment(self):
        """Verify that altering the ceremony salt fails Feldman commitment verification."""
        share = self.shares_2of3[0]
        tampered_salt = bytearray(share.salt)
        tampered_salt[0] ^= 0xff
        tampered = ThresholdShare(
            share_index=share.share_index,
            share_value=share.share_value,
            share_bytes=share.share_bytes,
            share_commitment=share.share_commitment,
            master_commitment=share.master_commitment,
            salt=bytes(tampered_salt),
            created_at=share.created_at,
            silo_id=share.silo_id,
        )
        self.assertFalse(self.commitments_2of3.verify_share(tampered))

    # =========================================================================
    # 2. OPERATOR SILO NODE & DOD S-5210.41M VALIDATION
    # =========================================================================

    def test_06_operator_silo_initialization_with_corrupt_share_raises(self):
        """Verify OperatorSiloNode rejects invalid share on initialization."""
        share = self.shares_2of3[0]
        corrupt_share = ThresholdShare(
            share_index=share.share_index,
            share_value=(share.share_value + 1),
            share_bytes=share.share_bytes,
            share_commitment=share.share_commitment,
            master_commitment=share.master_commitment,
            salt=share.salt,
            created_at=share.created_at,
            silo_id=share.silo_id,
        )
        with self.assertRaises(VSSChecksumMismatchError):
            OperatorSiloNode("SILO-BAD", corrupt_share, self.commitments_2of3)

    def test_07_silo_computes_partial_signature_on_valid_payload(self):
        """Verify silo computes valid partial signature on DoD S-5210.41M payload."""
        silo = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        payload = create_eam_payload(
            directive_code="DEFCON-1-AUTH-ALPHA",
            target_command="USSTRATCOM-OFFUTT"
        )
        partial_sig = silo.compute_partial_signature(payload)

        self.assertEqual(partial_sig.silo_id, "SILO-ALPHA-01")
        self.assertEqual(partial_sig.share_index, 1)
        self.assertEqual(len(partial_sig.payload_digest), 48)
        self.assertEqual(len(partial_sig.partial_signature_bytes), 48)
        self.assertEqual(len(partial_sig.silo_public_key), 2592)
        self.assertEqual(len(partial_sig.silo_mldsa_sig), 4627)

    def test_08_silo_rejects_expired_payload(self):
        """Verify silo rejects EAM payload outside validity freshness window."""
        silo = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        payload = create_eam_payload(
            directive_code="DEFCON-1-STRIKE",
            target_command="USSTRATCOM-OFFUTT"
        )
        # Artificially age timestamp by 125 seconds (> 120s validity window)
        payload["timestamp_utc"] = time.time() - 125.0

        with self.assertRaises(EAMExpiredError):
            silo.compute_partial_signature(payload)

    def test_09_silo_rejects_unauthorized_classification(self):
        """Verify silo rejects payload with unauthorized or downgraded classification."""
        silo = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        payload = create_eam_payload(
            directive_code="DEFCON-1-STRIKE",
            target_command="USSTRATCOM-OFFUTT"
        )
        payload["classification"] = "SECRET // NOFORN"

        with self.assertRaises(DualCustodyViolation):
            silo.compute_partial_signature(payload)

    def test_10_silo_rejects_invalid_preamble(self):
        """Verify silo rejects payload missing valid NC3 preamble."""
        silo = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        payload = create_eam_payload(
            directive_code="DEFCON-1-STRIKE",
            target_command="USSTRATCOM-OFFUTT"
        )
        payload["preamble"] = "[ROUTINE-CHAT]"

        with self.assertRaises(DualCustodyViolation):
            silo.compute_partial_signature(payload)

    def test_11_silo_anti_replay_enforcement(self):
        """Verify silo refuses to sign the same eam_id twice (anti-replay)."""
        silo = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        payload = create_eam_payload(
            directive_code="DEFCON-1-STRIKE",
            target_command="USSTRATCOM-OFFUTT",
            eam_id="EAM-REPLAY-TEST-001"
        )
        # First signing attempt succeeds
        sig1 = silo.compute_partial_signature(payload)
        self.assertIsNotNone(sig1)

        # Second signing attempt with same eam_id must raise EAMReplayError
        with self.assertRaises(EAMReplayError):
            silo.compute_partial_signature(payload)

    # =========================================================================
    # 3. THRESHOLD AGGREGATOR & SIMULTANEOUS CO-SIGNING (DoD S-5210.41M)
    # =========================================================================

    def test_12_aggregator_2of3_success(self):
        """Verify any 2 of 3 silos can successfully produce an aggregated signature."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)
        silo3 = OperatorSiloNode("SILO-CHARLIE-03", self.shares_2of3[2], self.commitments_2of3)

        payload = create_eam_payload("STRAT-RELEASE-DELTA", "USSTRATCOM-OFFUTT")

        # Test pair (1, 2)
        sig1 = silo1.compute_partial_signature(payload)
        sig2 = silo2.compute_partial_signature(payload)
        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        full_sig_12 = aggregator.aggregate_signatures(payload, [sig1, sig2])
        self.assertTrue(aggregator.verify(self.master_pk_2of3, payload, full_sig_12))

        # Test pair (2, 3) on fresh payload
        payload_23 = create_eam_payload("STRAT-RELEASE-ECHO", "USSTRATCOM-OFFUTT")
        sig2_b = silo2.compute_partial_signature(payload_23)
        sig3_b = silo3.compute_partial_signature(payload_23)
        full_sig_23 = aggregator.aggregate_signatures(payload_23, [sig2_b, sig3_b])
        self.assertTrue(aggregator.verify(self.master_pk_2of3, payload_23, full_sig_23))

        # Test pair (1, 3) on fresh payload
        payload_13 = create_eam_payload("STRAT-RELEASE-FOXTROT", "USSTRATCOM-OFFUTT")
        sig1_c = silo1.compute_partial_signature(payload_13)
        sig3_c = silo3.compute_partial_signature(payload_13)
        full_sig_13 = aggregator.aggregate_signatures(payload_13, [sig1_c, sig3_c])
        self.assertTrue(aggregator.verify(self.master_pk_2of3, payload_13, full_sig_13))

    def test_13_aggregator_3of5_success(self):
        """Verify any 3 of 5 silos can successfully produce an aggregated signature."""
        silos = [
            OperatorSiloNode(f"STRAT-SILO-{i:02d}", self.shares_3of5[i - 1], self.commitments_3of5)
            for i in range(1, 6)
        ]
        payload = create_eam_payload("STRAT-STRIKE-PENTAGON", "NMCC-PENTAGON")

        # Choose arbitrary 3 silos: indices 1, 3, 5 (silos 0, 2, 4)
        chosen = [silos[0], silos[2], silos[4]]
        partial_sigs = [s.compute_partial_signature(payload) for s in chosen]

        aggregator = NC3ThresholdAggregator(self.master_pk_3of5, self.commitments_3of5)
        full_sig = aggregator.aggregate_signatures(payload, partial_sigs)

        self.assertEqual(len(full_sig.signer_indices), 3)
        self.assertEqual(full_sig.signer_indices, [1, 3, 5])
        self.assertTrue(aggregator.verify(self.master_pk_3of5, payload, full_sig))

    def test_14_strict_2s_simultaneous_window_enforcement_pass(self):
        """Verify co-signing with timestamp skew <= 2.0s succeeds (DoD S-5210.41M)."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)

        payload = create_eam_payload("STRAT-STRIKE-SYNC-PASS", "USSTRATCOM-OFFUTT")
        base_t = time.time()

        # Skew of exactly 1.85 seconds (within 2.0s limit)
        sig1 = silo1.compute_partial_signature(payload, simulated_timestamp=base_t)
        sig2 = silo2.compute_partial_signature(payload, simulated_timestamp=base_t + 1.85)

        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        full_sig = aggregator.aggregate_signatures(payload, [sig1, sig2])
        self.assertAlmostEqual(full_sig.sync_skew_seconds, 1.85, places=3)
        self.assertTrue(aggregator.verify(self.master_pk_2of3, payload, full_sig))

    def test_15_strict_2s_simultaneous_window_enforcement_fail(self):
        """Verify co-signing with timestamp skew > 2.0s strictly raises DualCustodySynchronizationError."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)

        payload = create_eam_payload("STRAT-STRIKE-SYNC-FAIL", "USSTRATCOM-OFFUTT")
        base_t = time.time()

        # Skew of 2.05 seconds (> 2.0s limit)
        sig1 = silo1.compute_partial_signature(payload, simulated_timestamp=base_t)
        sig2 = silo2.compute_partial_signature(payload, simulated_timestamp=base_t + 2.05)

        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        with self.assertRaises(DualCustodySynchronizationError):
            aggregator.aggregate_signatures(payload, [sig1, sig2])

    def test_16_quorum_failure_insufficient_shares(self):
        """Verify aggregator raises DualCustodyViolation when shares < threshold."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        payload = create_eam_payload("STRAT-UNDER-QUORUM", "USSTRATCOM-OFFUTT")

        sig1 = silo1.compute_partial_signature(payload)
        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)

        # Only 1 share provided for threshold 2
        with self.assertRaises(DualCustodyViolation):
            aggregator.aggregate_signatures(payload, [sig1])

    def test_17_duplicate_silo_signature_rejection(self):
        """Verify aggregator raises DualCustodyViolation when duplicate signatures from same silo are submitted."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        payload = create_eam_payload("STRAT-DUP-QUORUM", "USSTRATCOM-OFFUTT")

        sig1 = silo1.compute_partial_signature(payload)
        # Attempt to pass sig1 twice to satisfy threshold 2
        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        with self.assertRaises(DualCustodyViolation):
            aggregator.aggregate_signatures(payload, [sig1, sig1])

    # =========================================================================
    # 4. ANTI-TAMPER & FAIL-CLOSED INTEGRITY CHECKS
    # =========================================================================

    def test_18_tampered_partial_signature_scalar_rejected(self):
        """Verify altering partial signature scalar w_i raises VSSChecksumMismatchError."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)
        payload = create_eam_payload("STRAT-TAMPER-SCALAR", "USSTRATCOM-OFFUTT")

        sig1 = silo1.compute_partial_signature(payload)
        sig2 = silo2.compute_partial_signature(payload)

        # Corrupt 1 byte in partial_signature_bytes
        corrupt_bytes = bytearray(sig2.partial_signature_bytes)
        corrupt_bytes[-1] ^= 0x01
        tampered_sig2 = PartialSignature(
            silo_id=sig2.silo_id,
            share_index=sig2.share_index,
            timestamp_utc=sig2.timestamp_utc,
            payload_digest=sig2.payload_digest,
            partial_signature_bytes=bytes(corrupt_bytes),
            share_commitment=sig2.share_commitment,
            silo_public_key=sig2.silo_public_key,
            silo_mldsa_sig=sig2.silo_mldsa_sig,
        )

        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        with self.assertRaises(VSSChecksumMismatchError):
            aggregator.aggregate_signatures(payload, [sig1, tampered_sig2])

    def test_19_forged_silo_mldsa_signature_rejected(self):
        """Verify altering sovereign ML-DSA-87 node signature raises VSSChecksumMismatchError."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)
        payload = create_eam_payload("STRAT-FORGED-MLDSA", "USSTRATCOM-OFFUTT")

        sig1 = silo1.compute_partial_signature(payload)
        sig2 = silo2.compute_partial_signature(payload)

        # Corrupt ML-DSA-87 signature
        corrupt_mldsa = bytearray(sig2.silo_mldsa_sig)
        corrupt_mldsa[0] ^= 0x55
        tampered_sig2 = PartialSignature(
            silo_id=sig2.silo_id,
            share_index=sig2.share_index,
            timestamp_utc=sig2.timestamp_utc,
            payload_digest=sig2.payload_digest,
            partial_signature_bytes=sig2.partial_signature_bytes,
            share_commitment=sig2.share_commitment,
            silo_public_key=sig2.silo_public_key,
            silo_mldsa_sig=bytes(corrupt_mldsa),
        )

        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        with self.assertRaises(VSSChecksumMismatchError):
            aggregator.aggregate_signatures(payload, [sig1, tampered_sig2])

    def test_20_tampered_payload_verification_fails(self):
        """Verify that altering even a single character in the payload invalidates the signature."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)
        payload = create_eam_payload("STRAT-AUTH-ALPHA", "USSTRATCOM-OFFUTT")

        sig1 = silo1.compute_partial_signature(payload)
        sig2 = silo2.compute_partial_signature(payload)

        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        full_sig = aggregator.aggregate_signatures(payload, [sig1, sig2])

        # Verification against original payload succeeds
        self.assertTrue(aggregator.verify(self.master_pk_2of3, payload, full_sig))

        # Verification against altered payload must fail
        tampered_payload = dict(payload)
        tampered_payload["directive_code"] = "STRAT-AUTH-BETA"
        self.assertFalse(aggregator.verify(self.master_pk_2of3, tampered_payload, full_sig))

    # =========================================================================
    # 5. SECURITY INVARIANT: MASTER KEY NEVER RECONSTRUCTED
    # =========================================================================

    def test_21_master_secret_never_reconstructed_on_aggregator(self):
        """
        SECURITY INVARIANT VALIDATION:
        The master strategic authorization secret key is NEVER reconstructed
        on the aggregator or any single machine during or after signing.
        """
        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)

        # 1. Inspect aggregator object attributes: no private keys stored
        self.assertFalse(hasattr(aggregator, "master_secret"))
        self.assertFalse(hasattr(aggregator, "master_secret_key"))
        self.assertFalse(hasattr(aggregator, "_master_sk"))
        self.assertFalse(hasattr(aggregator, "sk"))

        # 2. Inspect silo nodes: each holds ONLY its single share
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        self.assertEqual(silo1._share.share_index, 1)
        self.assertFalse(hasattr(silo1, "master_secret"))

        # 3. Complete aggregation ceremony
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)
        payload = create_eam_payload("STRAT-INVARIANT-CHECK", "USSTRATCOM-OFFUTT")
        sig1 = silo1.compute_partial_signature(payload)
        sig2 = silo2.compute_partial_signature(payload)
        full_sig = aggregator.aggregate_signatures(payload, [sig1, sig2])

        # 4. Re-verify aggregator state post-aggregation
        self.assertFalse(hasattr(aggregator, "master_secret"))
        self.assertFalse(hasattr(aggregator, "master_secret_key"))
        self.assertTrue(aggregator.verify(self.master_pk_2of3, payload, full_sig))

    # =========================================================================
    # 6. WIRE SERIALIZATION & DESERIALIZATION ROUNDTRIP
    # =========================================================================

    def test_22_threshold_signature_wire_roundtrip(self):
        """Verify binary wire serialization and deserialization preserves all fields and validity."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)
        payload = create_eam_payload("STRAT-WIRE-TEST", "USSTRATCOM-OFFUTT")

        sig1 = silo1.compute_partial_signature(payload)
        sig2 = silo2.compute_partial_signature(payload)

        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        full_sig = aggregator.aggregate_signatures(payload, [sig1, sig2])

        # Serialize to binary wire format
        wire_bytes = full_sig.to_bytes()
        self.assertTrue(wire_bytes.startswith(b"NC3-MPC-T1"))

        # Deserialize from binary wire format
        deserialized_sig = ThresholdSignature.from_bytes(wire_bytes)
        self.assertEqual(deserialized_sig.threshold, full_sig.threshold)
        self.assertEqual(deserialized_sig.signer_indices, full_sig.signer_indices)
        self.assertEqual(deserialized_sig.signer_silos, full_sig.signer_silos)
        self.assertEqual(deserialized_sig.payload_digest, full_sig.payload_digest)
        self.assertEqual(deserialized_sig.aggregated_signature, full_sig.aggregated_signature)
        self.assertEqual(deserialized_sig.master_public_key, full_sig.master_public_key)

        # Verification using deserialized signature must pass
        self.assertTrue(aggregator.verify(self.master_pk_2of3, payload, deserialized_sig))
        self.assertTrue(aggregator.verify(self.master_pk_2of3, payload, wire_bytes))

    def test_23_wire_deserialization_tampered_magic_rejected(self):
        """Verify wire deserialization rejects corrupted magic header."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)
        payload = create_eam_payload("STRAT-WIRE-TAMPER", "USSTRATCOM-OFFUTT")

        sig1 = silo1.compute_partial_signature(payload)
        sig2 = silo2.compute_partial_signature(payload)
        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        full_sig = aggregator.aggregate_signatures(payload, [sig1, sig2])

        wire_bytes = bytearray(full_sig.to_bytes())
        wire_bytes[0] = 0x00  # Corrupt magic byte

        with self.assertRaises(NC3SecurityError):
            ThresholdSignature.from_bytes(bytes(wire_bytes))

    def test_24_dict_serialization_roundtrips(self):
        """Verify dictionary serialization for shares, commitments, and partial signatures."""
        share = self.shares_2of3[0]
        share_dict = share.to_dict(include_secret=True)
        share_restored = ThresholdShare.from_dict(share_dict)
        self.assertEqual(share.share_index, share_restored.share_index)
        self.assertEqual(share.share_value, share_restored.share_value)
        self.assertEqual(share.share_commitment, share_restored.share_commitment)

        comm_dict = self.commitments_2of3.to_dict()
        comm_restored = FeldmanCommitments.from_dict(comm_dict)
        self.assertEqual(self.commitments_2of3.threshold, comm_restored.threshold)
        self.assertEqual(self.commitments_2of3.master_commitment, comm_restored.master_commitment)

        silo = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        payload = create_eam_payload("STRAT-DICT-TEST", "USSTRATCOM-OFFUTT")
        partial_sig = silo.compute_partial_signature(payload)
        partial_dict = partial_sig.to_dict()
        partial_restored = PartialSignature.from_dict(partial_dict)
        self.assertEqual(partial_sig.silo_id, partial_restored.silo_id)
        self.assertEqual(partial_sig.payload_digest, partial_restored.payload_digest)
        self.assertEqual(partial_sig.partial_signature_bytes, partial_restored.partial_signature_bytes)

    def test_25_convenience_verifier_function(self):
        """Verify the module-level verify_threshold_signature function."""
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)
        payload = create_eam_payload("STRAT-CONVENIENCE-TEST", "USSTRATCOM-OFFUTT")

        sig1 = silo1.compute_partial_signature(payload)
        sig2 = silo2.compute_partial_signature(payload)
        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        full_sig = aggregator.aggregate_signatures(payload, [sig1, sig2])

        self.assertTrue(
            verify_threshold_signature(
                self.master_pk_2of3, payload, full_sig, self.commitments_2of3
            )
        )

    def test_26_sealed_share_persistence_roundtrip_and_tamper_rejection(self):
        """Verify PBKDF2/AES-GCM sealed share persistence and tamper rejection."""
        from nc3_threshold_mpc import seal_share_to_file, load_sealed_share_from_file
        share = self.shares_2of3[0]
        passphrase = b"TOP-SECRET-CUSTODIAN-PASSPHRASE-2027"

        with tempfile.TemporaryDirectory() as tmp_dir:
            seal_path = os.path.join(tmp_dir, "silo_01.sealed.json")

            # 1. Seal share
            seal_share_to_file(share, seal_path, passphrase=passphrase)
            self.assertTrue(os.path.exists(seal_path))

            # 2. Unseal and verify exact recovery
            restored = load_sealed_share_from_file(seal_path, passphrase=passphrase)
            self.assertEqual(restored.share_index, share.share_index)
            self.assertEqual(restored.share_value, share.share_value)
            self.assertEqual(restored.share_commitment, share.share_commitment)
            self.assertEqual(restored.master_commitment, share.master_commitment)
            self.assertEqual(restored.salt, share.salt)
            self.assertEqual(restored.silo_id, share.silo_id)

            # 3. Wrong passphrase fails fail-closed
            with self.assertRaises(NC3SecurityError):
                load_sealed_share_from_file(seal_path, passphrase=b"WRONG-PASSPHRASE")

            # 4. Tampered ciphertext fails fail-closed
            with open(seal_path, "r", encoding="utf-8") as f:
                tampered_pkg = json.load(f)
            ct_bytes = bytearray(bytes.fromhex(tampered_pkg["ciphertext_hex"]))
            ct_bytes[0] ^= 0xFF
            tampered_pkg["ciphertext_hex"] = ct_bytes.hex()
            tamper_path = os.path.join(tmp_dir, "silo_tampered.sealed.json")
            with open(tamper_path, "w", encoding="utf-8") as f:
                json.dump(tampered_pkg, f)

            with self.assertRaises(NC3SecurityError):
                load_sealed_share_from_file(tamper_path, passphrase=passphrase)

    def test_27_production_posture_secret_export_prohibited(self):
        """Verify production mode strictly prohibits unsealed share secret export."""
        share = self.shares_2of3[0]
        old_env = os.environ.get("P2P_PRODUCTION")
        try:
            os.environ["P2P_PRODUCTION"] = "1"
            with self.assertRaises(NC3SecurityError):
                share.to_dict(include_secret=True)
        finally:
            if old_env is None:
                os.environ.pop("P2P_PRODUCTION", None)
            else:
                os.environ["P2P_PRODUCTION"] = old_env

    def test_28_nc3_command_controller_create_and_verify_threshold_eam(self):
        """Verify end-to-end threshold MPC EAM lifecycle with NC3CommandController."""
        from nc3_nuclear_command import NC3CommandController, serialize_eam_wire, deserialize_eam_wire

        controller = NC3CommandController()
        silo1 = OperatorSiloNode("SILO-NORAD-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-STRATCOM-02", self.shares_2of3[1], self.commitments_2of3)

        war_key = secrets.token_bytes(32)
        pal_code = "STRAT-WAR-ORDER-BRAVO-ZULU-44"

        # Construct candidate payload to sign with unique eam_id
        now_ts = time.time()
        unique_eam_id = f"EAM-MPC-E2E-{secrets.token_hex(6)}"
        payload = {
            "eam_id": unique_eam_id,
            "preamble": "[NC3/EAM-AUTH-DEFCON-1]",
            "classification": "TOP SECRET // SI-OP-IA // NC3 // NOFORN",
            "timestamp_utc": now_ts,
            "validity_window_seconds": 120.0,
            "directive_code": "EXEC-RETALIATION-ALPHA",
            "target_command": "STRATCOM-TASKFORCE",
            "encrypted_pal_code": "PENDING-PAL-ENCRYPTION",
        }

        # Co-sign within valid synchronized window
        sig1 = silo1.compute_partial_signature(payload, simulated_timestamp=now_ts)
        sig2 = silo2.compute_partial_signature(payload, simulated_timestamp=now_ts + 0.05)

        eam = controller.create_threshold_mpc_eam(
            directive_code="EXEC-RETALIATION-ALPHA",
            target_command="STRATCOM-TASKFORCE",
            pal_code=pal_code,
            war_key=war_key,
            partial_signatures=[sig1, sig2],
            commitments=self.commitments_2of3,
            master_public_key=self.master_pk_2of3,
            validity_window_seconds=120.0,
            eam_id=unique_eam_id,
        )
        self.assertIsNotNone(eam.threshold_mpc_signature)

        # Wire serialization roundtrip
        wire_envelope = serialize_eam_wire(eam.to_dict())
        self.assertEqual(len(wire_envelope) % 1024, 0)  # 1024-byte uniform block padding
        deserialized_eam = deserialize_eam_wire(wire_envelope)

        # Recipient officers verify and decrypt
        rec1 = controller.generate_officer_credentials("REC-GEN-01", "General", "NORAD")
        rec2 = controller.generate_officer_credentials("REC-ADM-02", "Admiral", "STRATCOM")

        decrypted_pal = controller.verify_and_decrypt_nuclear_eam(
            eam_data=deserialized_eam,
            recipient_officer_1=rec1,
            recipient_officer_2=rec2,
            sender_officer_1_pub=self.master_pk_2of3,
            sender_officer_2_pub=self.master_pk_2of3,
            pal_key=war_key,
            mpc_commitments=self.commitments_2of3,
        )
        self.assertEqual(decrypted_pal, pal_code)

    def test_29_nc3_command_controller_threshold_eam_skew_breach_fails(self):
        """Verify that EAM verification fails if silo synchronization skew exceeds 2.0s."""
        from nc3_nuclear_command import NC3CommandController, DualCustodySynchronizationError

        controller = NC3CommandController()
        silo1 = OperatorSiloNode("SILO-NORAD-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-STRATCOM-02", self.shares_2of3[1], self.commitments_2of3)

        war_key = secrets.token_bytes(32)
        pal_code = "STRAT-SKEW-TEST-PAL"
        now_ts = time.time()
        skew_id_1 = f"EAM-SKEW-1-{secrets.token_hex(6)}"
        payload1 = create_eam_payload("SKEW-TEST", "USSTRATCOM", eam_id=skew_id_1)

        # 1. Co-signing with 2.5s skew (> 2.0s window) must be rejected on creation fail-closed
        sig1 = silo1.compute_partial_signature(payload1, simulated_timestamp=now_ts)
        sig2 = silo2.compute_partial_signature(payload1, simulated_timestamp=now_ts + 2.5)

        with self.assertRaises(DualCustodySynchronizationError):
            controller.create_threshold_mpc_eam(
                directive_code="SKEW-TEST",
                target_command="USSTRATCOM",
                pal_code=pal_code,
                war_key=war_key,
                partial_signatures=[sig1, sig2],
                commitments=self.commitments_2of3,
                master_public_key=self.master_pk_2of3,
                eam_id=skew_id_1,
            )

        # 2. Wire/in-flight message with tampered sync skew > 2.0s must also be rejected on verification
        skew_id_2 = f"EAM-SKEW-2-{secrets.token_hex(6)}"
        payload2 = create_eam_payload("SKEW-TEST", "USSTRATCOM", eam_id=skew_id_2)
        valid_sig1 = silo1.compute_partial_signature(payload2, simulated_timestamp=now_ts)
        valid_sig2 = silo2.compute_partial_signature(payload2, simulated_timestamp=now_ts + 0.1)
        valid_eam = controller.create_threshold_mpc_eam(
            directive_code="SKEW-TEST",
            target_command="USSTRATCOM",
            pal_code=pal_code,
            war_key=war_key,
            partial_signatures=[valid_sig1, valid_sig2],
            commitments=self.commitments_2of3,
            master_public_key=self.master_pk_2of3,
            eam_id=skew_id_2,
        )
        tampered_dict = valid_eam.to_dict()
        tampered_dict["threshold_mpc_signature"]["sync_skew_seconds"] = 3.5

        rec1 = controller.generate_officer_credentials("REC-GEN-01", "General", "NORAD")
        rec2 = controller.generate_officer_credentials("REC-ADM-02", "Admiral", "STRATCOM")

        with self.assertRaises(DualCustodySynchronizationError):
            controller.verify_and_decrypt_nuclear_eam(
                eam_data=tampered_dict,
                recipient_officer_1=rec1,
                recipient_officer_2=rec2,
                sender_officer_1_pub=self.master_pk_2of3,
                sender_officer_2_pub=self.master_pk_2of3,
                pal_key=war_key,
                mpc_commitments=self.commitments_2of3,
            )

    def test_30_rust_data_plane_fast_path_integration(self):
        """Verify Rust destroyer_core data plane threshold MPC verification methods."""
        from destroyer_core import CoreNc3
        from nc3_threshold_mpc import verify_threshold_signature_wire

        # 1. Temporal window validation
        skew = CoreNc3.verify_temporal_window([1000, 1500, 2200])
        self.assertEqual(skew, 1200)

        with self.assertRaises(Exception):
            CoreNc3.verify_temporal_window([1000, 3500])  # Skew 2500ms > 2000ms

        # 2. Silo quorum validation
        CoreNc3.verify_silo_quorum([1, 2, 3], 3)
        with self.assertRaises(Exception):
            CoreNc3.verify_silo_quorum([1, 2], 3)  # Insufficient quorum
        with self.assertRaises(Exception):
            CoreNc3.verify_silo_quorum([1, 1, 2], 2)  # Duplicate indices

        # 3. Wire format verification fast path
        silo1 = OperatorSiloNode("SILO-ALPHA-01", self.shares_2of3[0], self.commitments_2of3)
        silo2 = OperatorSiloNode("SILO-BRAVO-02", self.shares_2of3[1], self.commitments_2of3)
        payload = create_eam_payload("FAST-PATH-EAM", "PENTAGON-NMCC")

        sig1 = silo1.compute_partial_signature(payload)
        sig2 = silo2.compute_partial_signature(payload)
        aggregator = NC3ThresholdAggregator(self.master_pk_2of3, self.commitments_2of3)
        full_sig = aggregator.aggregate_signatures(payload, [sig1, sig2])

        wire_bytes = full_sig.to_bytes()
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

        # Fast path verification must succeed
        self.assertTrue(
            verify_threshold_signature_wire(wire_bytes, payload_bytes, self.master_pk_2of3)
        )


if __name__ == "__main__":
    unittest.main()
