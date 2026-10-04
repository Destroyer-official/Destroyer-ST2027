#!/usr/bin/env python3
"""
test_production_tier123_hardening.py

Regression & Verification Suite for Tier 1, 2, & 3 Production-Grade Hardening.
Validates zero-simulation and fail-closed policies across:
- Tier 1: Tactical DDIL BPsec AEAD enforcement (zero XOR fallback).
- Tier 2: Zero Trust Hardware Attestation (Intel SGX, ARM TrustZone, AMD SEV) & TPM EK roots.
- Tier 2: Host hardening honesty (zero fake True returns in CFI/CET stubs).
- Tier 3: Zero-knowledge inner challenge verification.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
import unittest
from unittest.mock import patch, MagicMock

import dep_impl
import tee_manager
from tee_manager import (
    AttestationReport,
    AttestationStatus,
    IntelSGXBackend,
    ARMTrustZoneBackend,
    AMDSEVBackend,
    TEEManager,
    TEERequiredError,
    TEEType,
)
import tpm_quote
from tpm_quote import _verify_ek_chain
import zk_authenticator
from zk_authenticator import ZKAuthenticator, ZKProof, GroupMembershipProof


class TestProductionTier123Hardening(unittest.TestCase):
    """Test suite for Tier 1, 2, 3 fail-closed hardening and zero-simulation enforcement."""

    def test_ddil_bpsec_refuses_without_aesgcm(self):
        """Tier 1: without AES-256-GCM both BPsec directions refuse (a
        previous revision silently used an XOR 'cipher' that downstream
        code believed was AES-GCM)."""
        import tactical_mesh_ddil as ddil
        from liboqs_wrapper import LibOQS_MLDSA_87
        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()
        sym = secrets.token_bytes(32)
        # Real bundle first (signature must verify to reach the AEAD branch).
        bundle = ddil.create_bpsec_bundle(
            sender_id="A", recipient_id="B", seq=1,
            payload_plaintext=b"plaintext must never ride XOR",
            sender_sk=sk, sender_pk=pk, symmetric_key=sym)
        with patch.object(ddil, "AESGCM", None):
            with self.assertRaises(RuntimeError):
                ddil.create_bpsec_bundle(
                    sender_id="A", recipient_id="B", seq=2,
                    payload_plaintext=b"must refuse, not degrade",
                    sender_sk=sk, sender_pk=pk, symmetric_key=sym)
            with self.assertRaises(RuntimeError):
                ddil.decrypt_bpsec_bundle(bundle, sym)

    def test_sgx_attestation_fails_closed_in_production(self):
        """Intel SGX attestation must fail closed in production without real IAS/DCAP verification."""
        enclave = IntelSGXBackend()
        nonce = secrets.token_bytes(32)
        quote_data = b"SGX_QUOTE_HEADER_" + nonce[:20] + b"_MEASUREMENT_DATA_0000000000000000"
        sig = hashlib.sha384(quote_data).digest()

        report = AttestationReport(
            tee_type=TEEType.INTEL_SGX,
            status=AttestationStatus.PENDING,
            timestamp=time.time(),
            nonce=nonce,
            quote_data=quote_data,
            signature=sig,
        )

        # In production mode: unverified SGX quotes MUST fail closed
        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "true"}):
            ok = enclave.verify_attestation(report)
            self.assertFalse(ok)
            self.assertEqual(report.status, AttestationStatus.FAILED)
            self.assertIn("fail-closed", report.error_message.lower())

        # In non-production lab mode: valid quote structure verifies for test harnesses
        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "0", "P2P_PRODUCTION": "0"}):
            ok = enclave.verify_attestation(report)
            self.assertTrue(ok)
            self.assertEqual(report.status, AttestationStatus.VERIFIED)

    def test_trustzone_static_key_rejected_in_production(self):
        """ARM TrustZone must reject static simulation key in production mode."""
        enclave = ARMTrustZoneBackend()
        nonce = secrets.token_bytes(32)
        quote_data = b"TZAT" + nonce + b"_ENCLAVE_MEASUREMENT_DATA"
        sim_key = hashlib.sha512(b"trustzone_device_key").digest()
        sim_sig = hmac.new(sim_key, quote_data, hashlib.sha512).digest()

        report = AttestationReport(
            tee_type=TEEType.ARM_TRUSTZONE,
            status=AttestationStatus.PENDING,
            timestamp=time.time(),
            nonce=nonce,
            quote_data=quote_data,
            signature=sim_sig,
        )

        # In production without provisioned key: rejects static simulation key
        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "true", "P2P_TRUSTZONE_DEVICE_KEY": ""}):
            ok = enclave.verify_attestation(report)
            self.assertFalse(ok)
            self.assertEqual(report.status, AttestationStatus.FAILED)
            self.assertIn("static simulation key rejected", report.error_message.lower())

        # In production with provisioned device key: verifies with authentic key
        real_device_key = "PROD_SECRET_HW_KEY_ARM_TZ_88492"
        real_key_digest = hashlib.sha512(real_device_key.encode("utf-8")).digest()
        real_sig = hmac.new(real_key_digest, quote_data, hashlib.sha512).digest()
        report.signature = real_sig

        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "true", "P2P_TRUSTZONE_DEVICE_KEY": real_device_key}):
            ok = enclave.verify_attestation(report)
            self.assertTrue(ok)
            self.assertEqual(report.status, AttestationStatus.VERIFIED)

    def test_sev_static_key_rejected_in_production(self):
        """AMD SEV must reject static simulation key in production mode."""
        enclave = AMDSEVBackend()
        nonce = secrets.token_bytes(32)
        quote_data = b"SEV_REPORT_DATA_" + nonce + (b"X" * 80)
        sim_key = hashlib.sha512(b"sev_vcek").digest()
        sim_sig = hmac.new(sim_key, quote_data, hashlib.sha512).digest()

        report = AttestationReport(
            tee_type=TEEType.AMD_SEV,
            status=AttestationStatus.PENDING,
            timestamp=time.time(),
            nonce=nonce,
            quote_data=quote_data,
            signature=sim_sig,
        )

        # In production without provisioned VCEK: rejects static simulation key
        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "true", "P2P_SEV_VCEK": ""}):
            ok = enclave.verify_attestation(report)
            self.assertFalse(ok)
            self.assertEqual(report.status, AttestationStatus.FAILED)
            self.assertIn("static simulation key rejected", report.error_message.lower())

        # In production with provisioned VCEK: verifies with authentic key
        real_vcek = "PROD_VCEK_CERTIFICATE_KEY_AMD_MILITARY_99"
        real_vcek_digest = hashlib.sha512(real_vcek.encode("utf-8")).digest()
        real_sig = hmac.new(real_vcek_digest, quote_data, hashlib.sha512).digest()
        report.signature = real_sig

        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "true", "P2P_SEV_VCEK": real_vcek}):
            ok = enclave.verify_attestation(report)
            self.assertTrue(ok)
            self.assertEqual(report.status, AttestationStatus.VERIFIED)

    def test_tee_manager_execute_requires_tee_in_production(self):
        """TEEManager.execute_in_enclave must raise TEERequiredError when no backend is available in production."""
        manager = TEEManager(tee_required=False)
        # Force active backend to None to simulate environment without detected hardware TEE
        manager._active_backend = None

        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "true"}):
            with self.assertRaises(TEERequiredError):
                manager.execute_in_enclave(lambda: "sensitive_output")

    def test_pq_crypto_constructs_without_hqc(self):
        """PostQuantumCrypto must build on hosts whose oqs.dll lacks HQC-256
        (a previous revision crashed ALL of TLS construction), and cleanup()
        must never AttributeError on allocated_memory. Absent members
        degrade to explicit None with fail-closed KEM paths (never silent)."""
        from tls_channel_manager import PostQuantumCrypto
        pqc = PostQuantumCrypto()  # must not raise
        self.assertTrue(hasattr(pqc, "allocated_memory"))
        pqc.cleanup()  # must not raise or log-cleanup-error path
        # HQC either works or is explicit None (this host: absent from DLL).
        self.assertTrue(pqc.hqc is None or hasattr(pqc.hqc, "keygen"))
        if pqc.hybrid_kex is None:
            # Degraded combiner: KEM entry points fail closed, loudly.
            with self.assertRaises(RuntimeError):
                pqc.kem_encapsulate(b"\x00" * 1568)
            with self.assertRaises(RuntimeError):
                pqc.kem_decapsulate(b"HYBRIDSK" + b"\x00" * 32, b"\x00" * 32)
        else:
            self.assertTrue(hasattr(pqc.hybrid_kex, "keygen"))

    def test_falcon_quarantine_strict_refuses_primary(self):
        """Strict/production: Falcon keygen/sign raise, verify returns False
        (quarantine: Falcon is not primary). Lab keeps legacy roundtrip."""
        from tls_channel_manager import PostQuantumCrypto
        from cnsa2_policy_engine import SecurityPolicyViolation
        pqc = PostQuantumCrypto()
        msg = b"quarantine-probe"
        # Lab default: real Falcon roundtrip works.
        with patch.dict(os.environ, {"CNSA_2027_STRICT": "0",
                                     "P2P_PRODUCTION": "0",
                                     "SECURE_P2P_PRODUCTION": "0"}):
            pk, sk = pqc.generate_signature_keypair()
            self.assertEqual((len(pk), len(sk)), (1793, 2305))
            sig = pqc.sign(sk, msg)
            self.assertTrue(pqc.verify(pk, msg, sig))
            self.assertFalse(pqc.verify(pk, b"tampered", sig))
        # Strict: issuance refuses, trust refused (False, never raises).
        with patch.dict(os.environ, {"CNSA_2027_STRICT": "1",
                                     "P2P_PRODUCTION": "0",
                                     "SECURE_P2P_PRODUCTION": "0"}):
            with self.assertRaises(SecurityPolicyViolation):
                pqc.generate_signature_keypair()
            with self.assertRaises(SecurityPolicyViolation):
                pqc.sign(b"\x00" * 2305, msg)
            self.assertFalse(pqc.verify(pk, msg, sig))

    def test_dss_keypair_is_mldsa87_and_roundtrips(self):
        """generate_dss_keypair mints ML-DSA-87 (was missing: silent
        require_authentication downgrade). sign_mldsa/verify_mldsa agree."""
        from tls_channel_manager import PostQuantumCrypto
        pqc = PostQuantumCrypto()
        dpk, dsk = pqc.generate_dss_keypair()
        self.assertEqual((len(dpk), len(dsk)), (2592, 4896))
        sig = pqc.sign_mldsa(dsk, b"channel-binding-proof")
        self.assertTrue(pqc.verify_mldsa(dpk, b"channel-binding-proof", sig))
        self.assertFalse(pqc.verify_mldsa(dpk, b"forged", sig))
        with self.assertRaises(ValueError):
            pqc.sign_mldsa(b"short", b"x")

    def test_initialize_crypto_never_raises_and_stays_coherent(self):
        """_initialize_crypto degrades explicitly (never raises); default
        construction still carries no half-initialized PQ attributes."""
        from tls_channel_manager import TLSSecureChannel
        ch = TLSSecureChannel()
        ch._initialize_crypto()  # must not raise on any host
        self.assertIsInstance(ch.enable_pq_kem, bool)
        if ch.dss_public_key is not None:
            self.assertEqual(len(ch.dss_public_key), 2592)
            self.assertEqual(len(ch.dss_private_key), 4896)

    def test_ocsp_unreadable_status_fails_closed(self):
        """OCSP staple whose certificate_status cannot be read must verify
        False (a previous revision swallowed the error and fell through to
        freshness checks that could return True)."""
        import datetime
        import tls_channel_manager as tcm
        now = datetime.datetime.now(datetime.timezone.utc)

        class _StatusBoom:
            response_status = tcm.ocsp.OCSPResponseStatus.SUCCESSFUL

            @property
            def certificate_status(self):
                raise RuntimeError("simulated status-decode failure")

            this_update_utc = now - datetime.timedelta(hours=1)
            next_update_utc = now + datetime.timedelta(hours=1)

        with patch.object(tcm.ocsp, "load_der_ocsp_response",
                          return_value=_StatusBoom()):
            self.assertFalse(tcm._tls_verify_ocsp_der_local(b"der-bytes"))

    def test_tpm_ek_chain_placeholder_rejected_in_production(self):
        """TPM EK chain verification rejects placeholder roots in production fail-closed."""
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding

        # 1. Generate Root CA
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_subject = root_issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test TPM Vendor Root CA")
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_issuer)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(root_key, hashes.SHA256())
        )
        root_der = root_cert.public_bytes(Encoding.DER)
        root_fp = root_cert.fingerprint(hashes.SHA256()).hex().lower()

        # 2. Generate Device EK certificate signed by Root CA with keyAgreement usage
        ek_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ek_subject = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test Device EK")
        ])
        ek_cert = (
            x509.CertificateBuilder()
            .subject_name(ek_subject)
            .issuer_name(root_subject)
            .public_key(ek_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(root_key, hashes.SHA256())
        )
        ek_der = ek_cert.public_bytes(Encoding.DER)
        chain = [ek_der, root_der]

        # In production: with only placeholder roots in _EK_VENDOR_ROOTS, chain MUST fail closed
        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "true", "P2P_TPM_EK_ROOTS": ""}):
            result = _verify_ek_chain(chain, vendor="amd")
            self.assertFalse(result)

        # In production: when root_fp is pinned in P2P_TPM_EK_ROOTS, verification passes
        valid_roots_config = json.dumps({"amd": [root_fp]})
        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "true", "P2P_TPM_EK_ROOTS": valid_roots_config}):
            result = _verify_ek_chain(chain, vendor="amd")
            self.assertTrue(result)

    def test_dep_impl_placeholders_report_honestly(self):
        """EnhancedDEP placeholder stub methods must return False (honest reporting, no demo)."""
        dep = dep_impl.EnhancedDEP()
        placeholder_methods = [
            dep._implement_linux_cfi,
            dep._implement_intel_cet,
            dep._implement_arm_pointer_auth,
            dep._implement_macos_cfi,
            dep._implement_arm64_pac,
            dep._implement_universal_cfi,
            dep._implement_software_cfi,
            dep._implement_runtime_call_validation,
            dep._implement_memory_protection_hardening,
            dep._implement_exception_based_protection,
        ]
        for meth in placeholder_methods:
            ret = meth()
            self.assertFalse(ret, f"{meth.__name__} must return False instead of placeholder True")

    def test_zk_group_membership_inner_challenge_enforced(self):
        """Group membership proof verification must reject tampered inner ZK challenge."""
        with patch.dict(os.environ, {"P2P_ENABLE_EXPERIMENTAL": "1"}):
            authenticator = ZKAuthenticator(allow_unaudited=True)
            member_secret = secrets.token_bytes(32)
            member_int = authenticator._bytes_to_int(member_secret)
            member_pub = authenticator._int_to_bytes(
                authenticator._mod_exp(authenticator.g, member_int, authenticator.PRIME)
            )

            group_key = b"COMMAND_GROUP_ALPHA_001"
            other_pub1 = secrets.token_bytes(32)
            other_pub2 = secrets.token_bytes(32)
            group_members = [other_pub1, member_pub, other_pub2]

            proof = authenticator.prove_group_membership(
                member_secret=member_secret,
                group_key=group_key,
                member_public_keys=group_members
            )

            # Untampered proof verifies
            self.assertTrue(authenticator.verify_group_membership(proof, group_members))

            # Tampered inner ZK challenge fails verification
            tampered_inner_proof = ZKProof(
                commitment=proof.proof.commitment,
                challenge=secrets.token_bytes(32),  # Corrupted challenge
                response=proof.proof.response,
                proof_type=proof.proof.proof_type
            )
            tampered_membership_proof = GroupMembershipProof(
                group_id=proof.group_id,
                proof=tampered_inner_proof,
                ring_signature=proof.ring_signature
            )
            self.assertFalse(authenticator.verify_group_membership(tampered_membership_proof, group_members))

    def test_pqc_factory_degrades_per_member(self):
        """get_default_pqc_algorithms never raises: absent host members
        (e.g. HQC-256, draft-pending) are skipped loudly, never assembled
        silently and never crashing the factory. ML-KEM-1024 + ML-DSA-87
        must always be present (mandatory pair)."""
        from pqc_algorithms import get_default_pqc_algorithms
        impls = get_default_pqc_algorithms()
        self.assertIn("mlkem", impls)
        self.assertIn("mldsa", impls)
        # Mandatory pair is functional (roundtrip), whatever sizes the
        # hybrid wrappers use on this host.
        pk, sk = impls["mlkem"].keygen()
        self.assertTrue(pk and sk)
        ct, ss1 = impls["mlkem"].encaps(pk)
        ss2 = impls["mlkem"].decaps(sk, ct)
        self.assertEqual(ss1, ss2)
        dpk, dsk = impls["mldsa"].keygen()
        self.assertEqual((len(dpk), len(dsk)), (2592, 4896))


if __name__ == "__main__":
    unittest.main()
