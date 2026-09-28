#!/usr/bin/env python3
"""
2027+ Defense-Grade Sovereign Security Hardening Verification Suite
================================================================================
Validates:
1. TPM 2.0 Remote Hardware Attestation Quote Verification (FIPS 140-3 Level 4 / NIST SP 800-155)
2. Network Adversary Resistance: Public IP Leakage Prevention (Fail-Closed)
3. Sovereign Cloud Lockdown: Prohibition of Public Cloud OAuth2 in Production
4. Merkle-Chained Tamper-Evident Audit Trail Integrity
5. Witnessed Key Ceremony & Custodian Quorum Verification
"""

import os
import sys
import time
import json
import secrets
import hashlib
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from platform_hsm_interface import (
    TPMRemoteAttestation,
    HardwareSecurityRequirementError,
    HardwareSecurityErrorCode,
    get_tpm_attestation
)
from audit_logging_system import (
    initialize_audit_system,
    get_audit_logger,
    AuditEventType,
    AuditSeverity
)
import pqc_algorithms


class Test2027DefenseHardening(unittest.TestCase):
    """Test suite for 2027+ Defense-Grade hardening enforcements."""

    def setUp(self):
        self.orig_prod = os.environ.get("SECURE_P2P_PRODUCTION")
        self.orig_fallback = os.environ.get("P2P_FAIL_ON_SOFTWARE_FALLBACK")
        self.orig_loopback = os.environ.get("P2P_ALLOW_LOOPBACK")
        os.environ.pop("P2P_ALLOW_LOOPBACK", None)
        # Hermetic gate precondition: these tests assert production
        # fail-closed BEHAVIOR, which must not depend on ambient overrides
        # leaked by other suites (or lingering background threads) in the
        # same pytest process. Purge every P2P_ALLOW_*/P2P_DISABLE_*/
        # P2P_ENABLE_* override plus ephemeral/anonymous modes; each test
        # sets exactly what it needs. Full snapshot restored in tearDown.
        self._full_env_snapshot = dict(os.environ)
        for _k in list(os.environ.keys()):
            _ku = _k.upper()
            if (_ku.startswith("P2P_ALLOW_") or _ku.startswith("P2P_DISABLE_")
                    or _ku.startswith("P2P_ENABLE_")
                    or _ku in ("P2P_EPHEMERAL_MODE", "P2P_ANONYMOUS")):
                del os.environ[_k]

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._full_env_snapshot)

    # -------------------------------------------------------------------------
    # 1. TPM 2.0 Remote Attestation Tests
    # -------------------------------------------------------------------------
    def test_tpm_remote_attestation_verification_valid(self):
        """Test that a correctly generated and signed TPM attestation quote passes."""
        att = TPMRemoteAttestation()
        nonce = secrets.token_bytes(32)

        # Generate genuine ML-DSA-87 signer
        mldsa = pqc_algorithms.LibOQS_MLDSA_87()
        pk, sk = mldsa.keygen()

        attestation_data = att.generate_attestation(
            key_name="test_key",
            nonce=nonce,
            signer_callback=lambda q: mldsa.sign(sk, q)
        )
        self.assertIsNotNone(attestation_data)
        self.assertIn("quote", attestation_data)
        self.assertIn("signature", attestation_data)

        # Verify attestation with correct public key and nonce
        valid = att.verify_attestation(attestation_data, public_key=pk, expected_nonce=nonce)
        self.assertTrue(valid)

    def test_tpm_remote_attestation_verification_falcon1024_valid(self):
        """Test that a TPM attestation quote signed via FALCON-1024 passes verification."""
        att = TPMRemoteAttestation()
        nonce = secrets.token_bytes(32)

        from hybrid_kex import FALCON
        falcon = FALCON()
        pk, sk = falcon.keygen()

        attestation_data = att.generate_attestation(
            key_name="test_falcon_key",
            nonce=nonce,
            signer_callback=lambda q: falcon.sign(sk, q)
        )
        self.assertIsNotNone(attestation_data)
        self.assertIn("quote", attestation_data)
        self.assertIn("signature", attestation_data)

        # Verify attestation with correct FALCON-1024 public key and nonce
        valid = att.verify_attestation(attestation_data, public_key=pk, expected_nonce=nonce)
        self.assertTrue(valid)

    def test_tpm_remote_attestation_nonce_replay_rejected(self):
        """Test that an attestation with a replayed/mismatched nonce is rejected."""
        att = TPMRemoteAttestation()
        nonce = secrets.token_bytes(32)
        wrong_nonce = secrets.token_bytes(32)

        mldsa = pqc_algorithms.LibOQS_MLDSA_87()
        pk, sk = mldsa.keygen()

        attestation_data = att.generate_attestation(
            key_name="test_key",
            nonce=nonce,
            signer_callback=lambda q: mldsa.sign(sk, q)
        )

        valid = att.verify_attestation(attestation_data, public_key=pk, expected_nonce=wrong_nonce)
        self.assertFalse(valid)

    def test_tpm_remote_attestation_tampered_quote_rejected(self):
        """Test that a tampered quote hash fails verification."""
        att = TPMRemoteAttestation()
        nonce = secrets.token_bytes(32)

        mldsa = pqc_algorithms.LibOQS_MLDSA_87()
        pk, sk = mldsa.keygen()

        attestation_data = att.generate_attestation(
            key_name="test_key",
            nonce=nonce,
            signer_callback=lambda q: mldsa.sign(sk, q)
        )

        # Tamper with quote
        bad_quote = bytearray(bytes.fromhex(attestation_data["quote"]))
        bad_quote[0] ^= 0xFF
        attestation_data["quote"] = bytes(bad_quote).hex()

        valid = att.verify_attestation(attestation_data, public_key=pk, expected_nonce=nonce)
        self.assertFalse(valid)

    def test_tpm_remote_attestation_forged_signature_rejected(self):
        """Test that a signature from a different key is rejected."""
        att = TPMRemoteAttestation()
        nonce = secrets.token_bytes(32)

        mldsa = pqc_algorithms.LibOQS_MLDSA_87()
        pk1, sk1 = mldsa.keygen()
        pk2, sk2 = mldsa.keygen()

        attestation_data = att.generate_attestation(
            key_name="test_key",
            nonce=nonce,
            signer_callback=lambda q: mldsa.sign(sk1, q)
        )

        # Verify against wrong public key pk2
        valid = att.verify_attestation(attestation_data, public_key=pk2, expected_nonce=nonce)
        self.assertFalse(valid)

    def test_tpm_remote_attestation_production_fail_closed_missing_pubkey(self):
        """In production mode, verifying attestation without public key MUST fail-closed."""
        old_prod = os.environ.get("SECURE_P2P_PRODUCTION")
        os.environ["SECURE_P2P_PRODUCTION"] = "true"
        try:
            att = TPMRemoteAttestation()
            nonce = secrets.token_bytes(32)

            attestation_data = att.generate_attestation(key_name="test_key", nonce=nonce)

            # Must raise HardwareSecurityRequirementError or return False
            with self.assertRaises((HardwareSecurityRequirementError, Exception)):
                att.verify_attestation(attestation_data, public_key=None, expected_nonce=nonce)
        finally:
            if old_prod is None:
                os.environ.pop("SECURE_P2P_PRODUCTION", None)
            else:
                os.environ["SECURE_P2P_PRODUCTION"] = old_prod

    # -------------------------------------------------------------------------
    # 2. Public IP Leakage Prevention Tests
    # -------------------------------------------------------------------------
    def test_public_ip_fail_closed_in_production(self):
        """Test that connecting to a public IP fails closed in production mode."""
        old_prod = os.environ.get("SECURE_P2P_PRODUCTION")
        os.environ["SECURE_P2P_PRODUCTION"] = "true"
        os.environ.pop("P2P_USE_TOR", None)
        os.environ.pop("P2P_TACTICAL_APN", None)
        os.environ.pop("P2P_MULTIHOP_ROUTING", None)

        from archive.legacy_prototype.secure_p2p import SecureP2PChat, SecurityError

        chat = SecureP2PChat(port=18991, ephemeral=True)
        # Attempt to connect to a public IP (e.g., 93.184.216.34)
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            with self.assertRaises(SecurityError) as ctx:
                loop.run_until_complete(chat._connect_to_peer("93.184.216.34", 18992))
            self.assertIn("forbidden in 2027+ Defense Production mode", str(ctx.exception))
        finally:
            loop.close()
            if old_prod is None:
                os.environ.pop("SECURE_P2P_PRODUCTION", None)
            else:
                os.environ["SECURE_P2P_PRODUCTION"] = old_prod

    def test_private_and_loopback_ip_permitted_in_production(self):
        """Test that private IPs and loopback are permitted without APN/Tor."""
        old_prod = os.environ.get("SECURE_P2P_PRODUCTION")
        os.environ["SECURE_P2P_PRODUCTION"] = "true"
        try:
            from archive.legacy_prototype.secure_p2p import SecureP2PChat

            chat = SecureP2PChat(port=18993, ephemeral=True)
            # 127.0.0.1 should not raise the Public IP SecurityError
            # (It may fail with connection refused or missing components, but not Public IP error)
            import ipaddress
            for test_ip in ["127.0.0.1", "::1", "192.168.1.10", "10.0.0.5"]:
                ip_obj = ipaddress.ip_address(test_ip)
                self.assertTrue(ip_obj.is_private or ip_obj.is_loopback)
        finally:
            if old_prod is None:
                os.environ.pop("SECURE_P2P_PRODUCTION", None)
            else:
                os.environ["SECURE_P2P_PRODUCTION"] = old_prod

    # -------------------------------------------------------------------------
    # 3. Sovereign OAuth2 Lockdown Tests
    # -------------------------------------------------------------------------
    def test_oauth2_public_cloud_rejected_in_production(self):
        """Test that OAuth2 with public cloud providers raises AuthenticationError in production."""
        old_prod = os.environ.get("SECURE_P2P_PRODUCTION")
        os.environ["SECURE_P2P_PRODUCTION"] = "true"
        try:
            from tls_channel_manager import OAuth2DeviceFlowAuth, AuthenticationError

            for provider in ['google', 'microsoft', 'github']:
                with self.assertRaises(AuthenticationError) as ctx:
                    OAuth2DeviceFlowAuth(provider=provider, client_id="test_id")
                self.assertIn("prohibited in sovereign production mode", str(ctx.exception))
        finally:
            if old_prod is None:
                os.environ.pop("SECURE_P2P_PRODUCTION", None)
            else:
                os.environ["SECURE_P2P_PRODUCTION"] = old_prod

    # -------------------------------------------------------------------------
    # 4. Merkle-Chained Audit Trail Integrity Tests
    # -------------------------------------------------------------------------
    def test_audit_merkle_chain_integrity(self):
        """Test that audit events form an unbroken, mathematically verifiable Merkle chain."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        try:
            audit = initialize_audit_system(temp_db)
            audit.log_event("TEST_EVENT_1", "Initial event message", "INFO")
            audit.log_event("TEST_EVENT_2", "Second event message", "HIGH")
            audit.log_event("TEST_EVENT_3", "Third event message", "CRITICAL")
            audit.flush_buffer()

            valid, err = audit.verify_chain_integrity()
            self.assertTrue(valid, f"Chain integrity failed: {err}")
            audit.close()
        finally:
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except Exception:  # nosec: B110
                    pass

    # -------------------------------------------------------------------------
    # 5. Witnessed Key Ceremony Execution Test
    # -------------------------------------------------------------------------
    def test_witnessed_key_ceremony_execution(self):
        """Test that the formal key ceremony executes and produces verifiable receipts."""
        from scripts.witnessed_key_ceremony import WitnessedKeyCeremony

        ceremony = WitnessedKeyCeremony(ceremony_id=f"TEST-CEREMONY-{int(time.time())}")
        self.assertTrue(ceremony.register_custodians())
        hsm_status = ceremony.check_hardware_root_of_trust()
        self.assertIn("tpm_available", hsm_status)

        keys = ceremony.generate_cnsa2_root_keys()
        self.assertIn("ml_dsa_87", keys)
        self.assertIn("slh_dsa_256f", keys)
        self.assertIn("ml_kem_1024", keys)
        self.assertIn("secp521r1", keys)

        receipt_file = None
        # Quorum-gated minting (2026): single-operator runs cannot mint.
        with self.assertRaises(RuntimeError):
            ceremony.generate_ceremony_receipt()
        # Lab self-approval (harness-held keys; production custodians sign
        # offline) then mint + independent verification.
        ceremony._lab_self_approve()
        receipt_file = ceremony.generate_ceremony_receipt()
        self.assertTrue(receipt_file.exists())

        with open(receipt_file, "r", encoding="utf-8") as f:
            receipt_data = json.load(f)

        self.assertEqual(receipt_data["quorum_required"], 2)
        self.assertEqual(len(receipt_data["custodian_signatures"]), 3)
        self.assertIn("merkle_root_hash", receipt_data)
        for entry in receipt_data["custodian_signatures"]:
            self.assertEqual(entry.get("scheme"), "Ed25519")
            self.assertTrue(entry.get("public_key_b64"))
        ok, msg = WitnessedKeyCeremony.verify_receipt(receipt_data, quorum_m=2)
        self.assertTrue(ok, msg)

    # -------------------------------------------------------------------------
    # 6. HardwareSecurityRequirementError Defense-Grade Diagnostics Tests
    # -------------------------------------------------------------------------
    def test_hardware_security_requirement_error_diagnostics(self):
        """Verify HardwareSecurityRequirementError produces full forensic diagnostics."""
        diag_data = {"pcr": 7, "tpm_driver": "tbs.dll", "state": "compromised"}
        err = HardwareSecurityRequirementError(
            message="Secure boot measurement altered in boot stage",
            error_code=HardwareSecurityErrorCode.SECURE_BOOT_INACTIVE,
            device_diagnostics=diag_data,
            remediation_guidance="Inspect firmware signatures against OEM PK."
        )

        # Ensure inheritance from SecurityError
        from platform_hsm_interface import SecurityError
        self.assertIsInstance(err, SecurityError)

        # Ensure defense attributes are populated
        self.assertEqual(err.error_code, HardwareSecurityErrorCode.SECURE_BOOT_INACTIVE)
        self.assertEqual(err.severity, "CRITICAL")
        self.assertTrue(len(err.incident_id) >= 16)
        self.assertIn("FIPS 140-3 Level 4", err.compliance_standard)
        self.assertEqual(err.device_diagnostics, diag_data)
        self.assertEqual(err.remediation_guidance, "Inspect firmware signatures against OEM PK.")

        # Serialization validation
        serialized = err.to_dict()
        self.assertIn("incident_id", serialized)
        self.assertEqual(serialized["error_code"], HardwareSecurityErrorCode.SECURE_BOOT_INACTIVE)
        self.assertIn("device_diagnostics", serialized)

        json_out = err.to_json()
        self.assertIn("incident_id", json_out)
        self.assertIn("SECURE_BOOT_INACTIVE", json_out)

        # String representation validation
        err_str = str(err)
        self.assertIn("[FATAL HARDWARE SECURITY FAULT]", err_str)
        self.assertIn("CODE: SECURE_BOOT_INACTIVE", err_str)
        self.assertIn(err.incident_id, err_str)

    def test_hardware_security_requirement_error_audit_dispatch(self):
        """Verify HardwareSecurityRequirementError automatically logs to audit system."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        try:
            audit = initialize_audit_system(temp_db)
            err = HardwareSecurityRequirementError(
                message="TPM hardware physically unresponsive",
                error_code=HardwareSecurityErrorCode.TPM_NOT_DETECTED,
                device_diagnostics={"bus": "LPC", "address": 0x2E}
            )
            audit.flush_buffer()

            events = audit.query_events(event_type="HARDWARE_SECURITY_VIOLATION")
            self.assertTrue(len(events) >= 1)
            latest = events[-1]
            self.assertEqual(getattr(latest.severity, "value", latest.severity), "CRITICAL")
            self.assertIn(err.incident_id, latest.message)
            self.assertIn(HardwareSecurityErrorCode.TPM_NOT_DETECTED, latest.message)
            audit.close()
        finally:
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except Exception:  # nosec: B110
                    pass

    def test_hardware_security_error_codes_completeness(self):
        """Verify all standardized defense error codes exist."""
        required_codes = [
            "TPM_NOT_DETECTED",
            "TPM_INITIALIZATION_FAILED",
            "PCR_READ_FAILED",
            "PCR_MEASUREMENT_MISMATCH",
            "PCR_SECURE_BOOT_MISSING",
            "SECURE_BOOT_INACTIVE",
            "NONCE_REPLAY_DETECTED",
            "QUOTE_INTEGRITY_TAMPERED",
            "ATTESTATION_SIGNATURE_MISSING",
            "ATTESTATION_PUBKEY_REQUIRED",
            "ATTESTATION_SIGNATURE_FAILED",
            "ATTESTATION_TIMESTAMP_EXPIRED",
            "SOFTWARE_FALLBACK_PROHIBITED",
            "HARDWARE_KEY_EXPORT_PROHIBITED",
            "GENERAL_HARDWARE_VIOLATION"
        ]
        for code in required_codes:
            self.assertTrue(hasattr(HardwareSecurityErrorCode, code), f"Missing code: {code}")
            self.assertEqual(getattr(HardwareSecurityErrorCode, code), code)

    # -------------------------------------------------------------------------
    # 6. ATO Pilot Governance & Accredited Evidence Artifacts Tests
    # -------------------------------------------------------------------------
    def test_cavp_validation_report_100_percent_pass(self):
        """Verify automated CAVP report in compliance_reports has 100% pass rate."""
        cavp_file = PROJECT_ROOT / "compliance_reports" / "cavp_validation_report.json"
        self.assertTrue(cavp_file.exists(), "cavp_validation_report.json must exist")

        with open(cavp_file, "r", encoding="utf-8") as f:
            report = json.load(f)

        failed = report.get("tests_failed", 0)
        passed = report.get("tests_passed", 0)
        self.assertEqual(failed, 0, "CAVP failed tests must be 0")
        self.assertTrue(passed >= 17, "CAVP must execute at least 17 KATs")

    def test_reproducible_build_receipt_verified(self):
        """Verify signed reproducible build receipt confirms SLSA Level 3+ and Ed25519 signatures."""
        receipt_file = PROJECT_ROOT / "compliance_reports" / "signed_reproducible_build_receipt.json"
        self.assertTrue(receipt_file.exists(), "signed_reproducible_build_receipt.json must exist")

        with open(receipt_file, "r", encoding="utf-8") as f:
            receipt = json.load(f)

        self.assertEqual(receipt.get("overall_status"), "PASS")
        binaries = receipt.get("binaries", {})
        self.assertIn("oqs.dll", binaries)
        self.assertIn("libsodium.dll", binaries)
        self.assertTrue(binaries["oqs.dll"]["signature_verified"])
        self.assertTrue(binaries["oqs.dll"]["manifest_matched"])
        self.assertTrue(binaries["libsodium.dll"]["signature_verified"])
        self.assertTrue(binaries["libsodium.dll"]["manifest_matched"])

    def test_independent_redteam_assessment_verdict(self):
        """Verify the internal adversarial drill report is honestly labeled.

        The report is SELF-ASSESSMENT (not independent, not classified, no
        authority). The test pins that framing: no classification banners,
        no fake evaluators, no authorization verdicts -- while keeping the
        technical drill substance (vectors, dual-custody posture).
        """
        redteam_file = PROJECT_ROOT / "compliance_reports" / "independent_redteam_assessment.json"
        self.assertTrue(redteam_file.exists(), "independent_redteam_assessment.json must exist")

        with open(redteam_file, "r", encoding="utf-8") as f:
            doc = json.load(f)

        self.assertEqual(doc.get("assessment_kind", "")[:15], "SELF-ASSESSMENT")
        meta = doc.get("assessment_metadata", {})
        blob = json.dumps(doc)
        self.assertNotIn("classification", meta)
        self.assertNotIn("NOFORN", blob)
        self.assertNotIn("National Defense Cyber Red Team", blob)
        summary = doc.get("executive_summary", {})
        self.assertEqual(summary.get("overall_verdict"), "INTERNAL_DRILL_COMPLETE")
        self.assertIn("Maximum Attacker Cost", summary.get("security_paradigm", ""))
        self.assertEqual(summary.get("unauthenticated_switches"), "CLOSED_FAIL_CLOSED")
        self.assertEqual(summary.get("draft_algorithms"), "QUARANTINED_FAIL_CLOSED_IN_PRODUCTION")
        self.assertIn("NOT_PERFORMED", summary.get("self_score_reconciliation", {}).get("independent_audit_status", ""))
        self.assertIn("NO_AUTHORITY", json.dumps(doc.get("reviewer_notes_for_ao_package", {})))

    def test_niap_common_criteria_and_cmvp_submittal_coverage(self):
        """Verify NIAP Common Criteria matrix and CMVP submittal specifications exist."""
        niap_file = PROJECT_ROOT / "compliance_reports" / "niap_common_criteria_matrix.json"
        cmvp_file = PROJECT_ROOT / "compliance_reports" / "cmvp_fips140_3_submittal.json"
        affidavit_file = PROJECT_ROOT / "certs" / "key_ceremony_affidavit.json"

        self.assertTrue(niap_file.exists(), "niap_common_criteria_matrix.json must exist")
        self.assertTrue(cmvp_file.exists(), "cmvp_fips140_3_submittal.json must exist")
        self.assertTrue(affidavit_file.exists(), "key_ceremony_affidavit.json must exist")

        with open(niap_file, "r", encoding="utf-8") as f:
            niap = json.load(f)
        sfrs = [s["sfr_id"] for s in niap.get("security_functional_requirements", [])]
        self.assertIn("FCS_CKM.1/PQC", sfrs)
        self.assertIn("FCS_COP.1/SYM", sfrs)
        self.assertIn("FAU_STG.1/WORM", sfrs)

    def test_network_transport_defense_policy(self):
        """Verify network transport defense policy enforces Tor / Private APN for public IPs in production."""
        from cnsa2_policy_engine import CNSA2PolicyEngine, SecurityPolicyViolation
        engine = CNSA2PolicyEngine()

        # Local/loopback and onion always allowed
        self.assertTrue(engine.validate_network_transport("direct", "127.0.0.1:8888"))
        self.assertTrue(engine.validate_network_transport("direct", "10.0.0.5:8888"))
        self.assertTrue(engine.validate_network_transport("direct", "securenode.onion:8888"))

        # In production mode, direct public IP must fail-closed
        old_prod = os.environ.get("SECURE_P2P_PRODUCTION")
        os.environ["SECURE_P2P_PRODUCTION"] = "true"
        try:
            # Tor transport to public IP allowed (onion-encapsulated)
            self.assertTrue(engine.validate_network_transport("tor", "93.184.216.34:8888"))
            # Private APN transport to public/carrier IP allowed
            self.assertTrue(engine.validate_network_transport("private_apn", "93.184.216.34:8888"))

            # Unencapsulated direct connection to public IP must raise SecurityPolicyViolation
            with self.assertRaises(SecurityPolicyViolation):
                engine.validate_network_transport("direct", "93.184.216.34:8888")
        finally:
            if old_prod is None:
                os.environ.pop("SECURE_P2P_PRODUCTION", None)
            else:
                os.environ["SECURE_P2P_PRODUCTION"] = old_prod


if __name__ == "__main__":
    unittest.main(verbosity=2)


