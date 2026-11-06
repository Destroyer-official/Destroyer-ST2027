#!/usr/bin/env python3
"""
tests/test_cmt_laboratory_submittal_packet.py
================================================================================
Comprehensive Verification Battery for Cryptographic Module Testing (CMT)
Laboratory Evaluation Dossier and Authorizing Official (AO) Submittal Package.

Validates:
1. Master manifest schema, artifact coverage (14/14), and ML-DSA-87 signature.
2. Sealed tar.gz submittal archive structure and member file integrity.
3. Cryptographic Module Security Policy (CMSP) 12-section ISO/IEC 19790 completeness.
4. Tamper detection: single-bit payload or signature alterations fail-closed.
5. Absolute regulatory truthfulness: no false or unearned CMVP / ATO claims.
================================================================================
"""

import json
import os
import sys
import tarfile
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from liboqs_wrapper import LibOQS_MLDSA_87
from scripts.package_cmt_laboratory_submittal import (
    CMTLaboratorySubmittalPackager,
    SUBMITTAL_ARTIFACT_DEFS,
    compute_hashes,
    verify_mldsa87_signature,
)

COMPLIANCE_DIR = REPO_ROOT / "compliance_reports"


class TestCMTLaboratorySubmittalPacket:
    """Test suite validating the formal CMT Laboratory and AO submission dossier."""

    def test_master_submittal_manifest_exists_and_signed(self):
        """Verify master manifest exists and ML-DSA-87 signature verifies."""
        manifest_file = COMPLIANCE_DIR / "cmt_laboratory_submission_manifest.json"
        sig_file = COMPLIANCE_DIR / "cmt_laboratory_submission_manifest.json.mldsa87.sig"
        pub_file = COMPLIANCE_DIR / "cmt_laboratory_submission_manifest.json.mldsa87.pub"

        assert manifest_file.exists(), "Master manifest must exist"
        assert sig_file.exists(), "Manifest ML-DSA-87 signature must exist"
        assert pub_file.exists(), "Manifest public key must exist"

        manifest_bytes = manifest_file.read_bytes()
        sig_bytes = sig_file.read_bytes()
        pub_bytes = pub_file.read_bytes()

        assert len(sig_bytes) == 4627, "ML-DSA-87 signature size must be 4,627 bytes"
        assert len(pub_bytes) == 2592, "ML-DSA-87 public key size must be 2,592 bytes"

        # Verify signature
        valid = verify_mldsa87_signature(manifest_bytes, sig_bytes, pub_bytes)
        assert valid is True, "Master manifest ML-DSA-87 signature must be cryptographically valid"

    def test_master_manifest_schema_and_artifact_count(self):
        """Verify master manifest schema adheres to 2027 submittal standard."""
        manifest_file = COMPLIANCE_DIR / "cmt_laboratory_submission_manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "cmt_laboratory_submittal_manifest" in data
        body = data["cmt_laboratory_submittal_manifest"]

        assert body["schema_version"] == "2027.1.0-CNSA2-MIL"
        assert "manifest_id" in body
        assert "published_utc" in body
        assert "applicable_standards" in body

        # Check artifact inventory
        artifacts = body.get("artifacts", [])
        assert len(artifacts) == len(SUBMITTAL_ARTIFACT_DEFS), f"Must catalog all {len(SUBMITTAL_ARTIFACT_DEFS)} artifacts"

        # Ensure all cataloged artifacts exist on disk and hashes match
        for a in artifacts:
            rel = a["relative_path"]
            fpath = REPO_ROOT / rel
            assert fpath.exists(), f"Artifact {rel} must exist on disk"
            content = fpath.read_bytes()
            h384, h512 = compute_hashes(content)
            assert h384 == a["sha384"], f"SHA-384 must match for {rel}"
            assert h512 == a["sha512"], f"SHA-512 must match for {rel}"

    def test_submittal_tarball_archive_integrity(self):
        """Verify sealed tar.gz submittal bundle contains all required files."""
        tar_path = COMPLIANCE_DIR / "cmt_lab_submission_packet.tar.gz"
        assert tar_path.exists(), "Submittal tarball must exist"
        assert tar_path.stat().st_size > 10000, "Tarball must not be empty"

        with tarfile.open(tar_path, "r:gz") as tar:
            members = tar.getnames()

            # Master manifest and sidecars must be present in archive
            assert "cmt_laboratory_submission_manifest.json" in members
            assert "cmt_laboratory_submission_manifest.json.mldsa87.sig" in members
            assert "cmt_laboratory_submission_manifest.json.mldsa87.pub" in members

            # Check every artifact is included
            for item in SUBMITTAL_ARTIFACT_DEFS:
                rel = item["relative_path"].replace("\\", "/")
                assert rel in members, f"Tarball must include {rel}"
                if item["has_sig"]:
                    sig_rel = rel + ".mldsa87.sig"
                    assert sig_rel in members, f"Tarball must include signature {sig_rel}"

    def test_cmsp_fips140_3_security_policy_completeness(self):
        """Verify docs/FIPS_140_3_SECURITY_POLICY.md contains all 12 required sections."""
        policy_path = REPO_ROOT / "docs" / "FIPS_140_3_SECURITY_POLICY.md"
        assert policy_path.exists(), "FIPS 140-3 Security Policy must exist"

        text = policy_path.read_text(encoding="utf-8")

        # Verify all 12 ISO/IEC 19790 / SP 800-140B sections are represented
        required_sections = [
            "1. Module Overview & Cryptographic Boundary",
            "2. FIPS 140-3 Target Security Levels by Section",
            "3. Approved Cryptographic Algorithms",
            "4. Cryptographic Module Interfaces & Ports",
            "5. Roles, Services, and Authentication",
            "6. Software & Firmware Security",
            "7. Operational Environment",
            "8. Physical Security",
            "9. Non-Invasive Security & Side-Channel Defenses",
            "10. Sensitive Parameter Management & Zeroization",
            "11. Self-Tests",
            "12. Electromagnetic Compatibility & Mitigation of Other Attacks",
            "13. Cryptographic Module Testing (CMT) Laboratory Submission Artifact Map",
        ]
        for sec in required_sections:
            assert sec in text, f"Security Policy must include section: {sec}"

        # Verify CNSA 2.0 mandatory algorithms are detailed
        assert "ML-KEM-1024" in text
        assert "ML-DSA-87" in text
        assert "SLH-DSA-256f" in text
        assert "AES-256-GCM" in text
        assert "FIPS PUB 203" in text
        assert "FIPS PUB 204" in text
        assert "FIPS PUB 205" in text

        # Verify Zeroization procedure is explicitly specified
        assert "sodium_memzero" in text
        assert "ZeroizeOnDrop" in text

    def test_tamper_detection_fail_closed(self):
        """Verify that altering even 1 byte in a submittal artifact or signature fails verification."""
        manifest_file = COMPLIANCE_DIR / "cmt_laboratory_submission_manifest.json"
        sig_file = COMPLIANCE_DIR / "cmt_laboratory_submission_manifest.json.mldsa87.sig"
        pub_file = COMPLIANCE_DIR / "cmt_laboratory_submission_manifest.json.mldsa87.pub"

        manifest_bytes = manifest_file.read_bytes()
        sig_bytes = sig_file.read_bytes()
        pub_bytes = pub_file.read_bytes()

        # 1. Tamper payload: flip first byte
        tampered_manifest = bytes([manifest_bytes[0] ^ 0xFF]) + manifest_bytes[1:]
        assert verify_mldsa87_signature(tampered_manifest, sig_bytes, pub_bytes) is False, (
            "Tampered manifest must fail ML-DSA-87 verification"
        )

        # 2. Tamper signature: flip first byte
        tampered_sig = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
        assert verify_mldsa87_signature(manifest_bytes, tampered_sig, pub_bytes) is False, (
            "Tampered signature must fail ML-DSA-87 verification"
        )

    def test_absolute_regulatory_truthfulness_no_false_claims(self):
        """Verify all submittal documents explicitly state pre-evaluation status and non-claims."""
        manifest_file = COMPLIANCE_DIR / "cmt_laboratory_submission_manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        disclosure = data["cmt_laboratory_submittal_manifest"]["regulatory_and_accreditation_pathway"]["truthful_compliance_disclosure"]
        assert "MANDATORY DISCLOSURE" in disclosure
        assert "not undergone formal testing" in disclosure
        assert "does not possess a government Authority to Operate (ATO)" in disclosure

        policy_file = REPO_ROOT / "docs" / "FIPS_140_3_SECURITY_POLICY.md"
        policy_text = policy_file.read_text(encoding="utf-8")
        assert "PRE-EVALUATION VENDOR SUBMISSION SPECIFICATION" in policy_text
        assert ("NOT yet been formally validated" in policy_text or "**NOT** yet been formally validated" in policy_text)
        assert "TARGET LEVELS" in policy_text

    def test_packager_verify_submittal_packet_method(self):
        """Execute CMTLaboratorySubmittalPackager.verify_submittal_packet() and assert True."""
        packager = CMTLaboratorySubmittalPackager(verbose=False)
        assert packager.verify_submittal_packet() is True
