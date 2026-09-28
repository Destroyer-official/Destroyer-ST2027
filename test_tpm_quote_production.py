#!/usr/bin/env python3
"""
Test Suite: Production-Grade TPM 2.0 Hardware Attestation, Sealed Storage & Identity Binding.
Validates:
1. Physical/Simulated PCR register reads.
2. TCG-compliant PCR composite digest determinism and sensitivity.
3. Hardware-locked PCR sealed storage (AES-256-GCM + HKDF-SHA3-512) and tamper fail-closed rejection.
4. Cryptographic attestation-to-identity binding (ML-DSA-87) preventing identity spoofing.
5. Strict fail-closed policy enforcement.
"""

import os
import secrets
import unittest

import tpm_quote
from tpm_quote import (
    PCRMismatchError,
    AttestationVerificationError,
    read_hardware_pcrs,
    compute_pcr_composite,
    seal_secret_to_pcrs,
    unseal_secret_from_pcrs,
    bind_attestation_to_identity,
    verify_identity_attestation_binding,
    sign_quote,
    verify_quote,
    generate_ak_stub,
)


class TestTPMQuoteProduction(unittest.TestCase):
    """Test suite for production TPM 2.0 hardware attestation features."""

    @classmethod
    def setUpClass(cls):
        cls.ak_pub, cls.ak_sk = generate_ak_stub()
        cls.id_pub, cls.id_sk = generate_ak_stub()  # ML-DSA-87 identity keypair

    def test_01_read_hardware_pcrs_format(self):
        """read_hardware_pcrs returns valid hex digests for specified registers."""
        pcrs = read_hardware_pcrs([0, 1, 2, 7])
        self.assertIsInstance(pcrs, dict)
        for idx in [0, 1, 2, 7]:
            self.assertIn(idx, pcrs)
            self.assertEqual(len(pcrs[idx]), 64)  # 32-byte SHA-256 in hex
            bytes.fromhex(pcrs[idx])  # validate valid hex

    def test_02_pcr_composite_determinism_and_sensitivity(self):
        """PCR composite is deterministic and sensitive to single-bit changes."""
        pcrs1 = {0: "aa" * 32, 7: "bb" * 32}
        pcrs2 = {0: "aa" * 32, 7: "bb" * 32}
        pcrs_tampered = {0: "aa" * 32, 7: "ba" * 32}

        c1 = compute_pcr_composite(pcrs1)
        c2 = compute_pcr_composite(pcrs2)
        c3 = compute_pcr_composite(pcrs_tampered)

        self.assertEqual(c1, c2)
        self.assertNotEqual(c1, c3)
        self.assertEqual(len(c1), 64)  # SHA3-512 is 64 bytes

    def test_03_seal_and_unseal_roundtrip(self):
        """Secret sealed to PCRs can be successfully unsealed with identical PCRs."""
        target_pcrs = {0: "11" * 32, 1: "22" * 32, 7: "77" * 32}
        secret = b"TOP_SECRET_MILITARY_LAUNCH_KEYING_MATERIAL_2028"
        passphrase = "CeremonyPassphrase998!"  # nosec: B105

        envelope = seal_secret_to_pcrs(
            secret_bytes=secret,
            target_pcrs=target_pcrs,
            auth_passphrase=passphrase
        )

        self.assertEqual(envelope["v"], 1)
        self.assertEqual(envelope["type"], "PCR_SEALED_STORAGE_V1")
        self.assertEqual(envelope["pcr_indices"], [0, 1, 7])

        # Unseal with identical PCRs
        unsealed = unseal_secret_from_pcrs(
            envelope=envelope,
            current_pcrs=target_pcrs,
            auth_passphrase=passphrase
        )
        self.assertEqual(unsealed, secret)

    def test_04_tampered_pcr_unseal_fails_closed(self):
        """Unsealing with modified PCR state raises PCRMismatchError fail-closed."""
        target_pcrs = {0: "11" * 32, 7: "77" * 32}
        secret = b"CLASSIFIED_EAM_PAYLOAD"

        envelope = seal_secret_to_pcrs(
            secret_bytes=secret,
            target_pcrs=target_pcrs
        )

        # Attacker tampered with Secure Boot (PCR 7 altered)
        altered_pcrs = {0: "11" * 32, 7: "78" * 32}
        with self.assertRaises(PCRMismatchError):
            unseal_secret_from_pcrs(envelope, altered_pcrs)

    def test_05_wrong_passphrase_unseal_fails(self):
        """Unsealing with wrong authorization passphrase fails closed."""
        target_pcrs = {0: "11" * 32, 7: "77" * 32}
        secret = b"INTELLIGENCE_DISPATCH"

        envelope = seal_secret_to_pcrs(
            secret_bytes=secret,
            target_pcrs=target_pcrs,
            auth_passphrase="CorrectPassword"  # nosec: B106
        )

        with self.assertRaises(PCRMismatchError):
            unseal_secret_from_pcrs(envelope, target_pcrs, auth_passphrase="WrongPassword")  # nosec: B106

    def test_06_attestation_to_identity_binding(self):
        """TPM quote is cryptographically bound to operator ML-DSA-87 identity key."""
        pcrs = {0: "00" * 32, 7: "ab" * 32}
        nonce = secrets.token_bytes(32)

        # 1. Hardware produces quote
        quote = sign_quote(pcrs, nonce, "ak-charlie", bytes(self.ak_sk))

        # 2. Operator binds quote to long-term identity key
        bound_quote = bind_attestation_to_identity(
            quote_envelope=quote,
            identity_pub=bytes(self.id_pub),
            identity_sk=bytes(self.id_sk)
        )

        self.assertIn("identity_binding", bound_quote)
        self.assertEqual(bound_quote["identity_binding"]["bound_identity_pub"], bytes(self.id_pub).hex())

        # 3. Verifier validates both quote and identity binding
        ok = verify_identity_attestation_binding(
            quote_envelope=bound_quote,
            expected_identity_pub=bytes(self.id_pub),
            expected_nonce=nonce,
            trusted_ak_pubs=[bytes(self.ak_pub)]
        )
        self.assertTrue(ok)

    def test_07_forged_identity_binding_rejected(self):
        """Binding verification rejects spoofed identity key or tampered quote."""
        pcrs = {0: "00" * 32, 7: "ab" * 32}
        nonce = secrets.token_bytes(32)

        quote = sign_quote(pcrs, nonce, "ak-charlie", bytes(self.ak_sk))
        bound_quote = bind_attestation_to_identity(
            quote_envelope=quote,
            identity_pub=bytes(self.id_pub),
            identity_sk=bytes(self.id_sk)
        )

        # Adversary attempts to substitute legitimate identity with impostor key
        impostor_pub, _ = generate_ak_stub()
        ok_impostor = verify_identity_attestation_binding(
            quote_envelope=bound_quote,
            expected_identity_pub=bytes(impostor_pub),
            expected_nonce=nonce,
            trusted_ak_pubs=[bytes(self.ak_pub)]
        )
        self.assertFalse(ok_impostor)

        # Adversary tampers with quote signature inside bound quote
        tampered_quote = dict(bound_quote)
        tampered_quote["sig"] = "ff" * len(bytes.fromhex(bound_quote["sig"]))
        ok_tampered = verify_identity_attestation_binding(
            quote_envelope=tampered_quote,
            expected_identity_pub=bytes(self.id_pub),
            expected_nonce=nonce,
            trusted_ak_pubs=[bytes(self.ak_pub)]
        )
        self.assertFalse(ok_tampered)


if __name__ == "__main__":
    unittest.main()

