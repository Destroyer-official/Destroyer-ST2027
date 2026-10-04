"""
test_phase3_acvp_cbom_udp.py
Comprehensive Phase 3 Test Suite:
1. NIST ACVP / CAVP Known Answer Tests & Automated Validation (FIPS 203, 204, 205, AES-GCM, SHA)
2. CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) Generation, Cataloging & Post-Quantum ML-DSA-87 Signatures
3. WireGuard-Style Rust UDP Data Plane Cutover, Token-Bucket Rate Limiter, Fixed Quantum & Anti-Replay
4. Twin Parity Validation (secure_p2p.py == secure_p2.py byte-for-byte)
"""

import json
import os
import secrets
import socket
import time
from pathlib import Path
import pytest

from acvp_validation_harness import (
    ACVPValidationHarness,
    run_acvp_validation_suite,
)
from generate_production_cbom import (
    generate_cbom_data,
    sign_and_export_cbom,
    verify_cbom_signature,
)
from destroyer_node import (
    DestroyerNode,
    udp_data_plane_enabled,
    FTYPE_MSG,
    FTYPE_CHAFF,
)


class TestNistAcvpValidation:
    """NIST ACVP / CAVP Known Answer Test Harness Validation Suite."""

    def test_full_acvp_suite_execution(self):
        """Execute all ACVP/CAVP vectors and assert zero failures."""
        report = run_acvp_validation_suite()
        assert report["summary"]["total_tests"] >= 12  # nosec: B101
        assert report["summary"]["failed"] == 0  # nosec: B101
        assert report["metadata"]["overall_status"] == "COMPLIANT"  # nosec: B101
        assert report["summary"]["passed"] == report["summary"]["total_tests"]  # nosec: B101

    def test_acvp_report_artifact_structure(self):
        """Verify the generated JSON report conforms to compliance reporting schema."""
        report_path = Path("compliance_reports/acvp_cavp_validation_report.json")
        assert report_path.exists(), "ACVP report file must exist"  # nosec: B101

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "metadata" in data  # nosec: B101
        assert data["metadata"]["target_profile"] == "NSA-CNSA-2.0-STRICT"  # nosec: B101
        assert data["metadata"]["overall_status"] == "COMPLIANT"  # nosec: B101
        assert len(data["results"]) >= 12  # nosec: B101

        # Verify specific critical algorithms are present and passed
        algorithms = {item["algorithm"] for item in data["results"]}
        assert "ML-KEM-1024" in algorithms  # nosec: B101
        assert "ML-DSA-87" in algorithms  # nosec: B101
        assert "SLH-DSA-256f" in algorithms  # nosec: B101
        assert "AES-256-GCM" in algorithms  # nosec: B101
        assert "ChaCha20-Poly1305" in algorithms  # nosec: B101
        assert any("SHA" in a for a in algorithms)  # nosec: B101

        for item in data["results"]:
            assert item["status"] == "PASS", f"Algorithm {item['algorithm']} failed validation"  # nosec: B101

    def test_individual_acvp_vectors(self):
        """Individually run harness methods to test edge validations."""
        harness = ACVPValidationHarness(verbose=False)
        assert harness.validate_fips203_ml_kem_1024() is True  # nosec: B101
        assert harness.validate_fips204_ml_dsa_87() is True  # nosec: B101
        assert harness.validate_fips205_slh_dsa_256f() is True  # nosec: B101
        assert harness.validate_aes_256_gcm_cavp() is True  # nosec: B101
        assert harness.validate_chacha20_poly1305() is True  # nosec: B101
        assert harness.validate_hashes_and_xof() is True  # nosec: B101


class TestCycloneDxCbom:
    """CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) Generation and Verification Suite."""

    def test_cbom_structure_and_components(self):
        """Validate CycloneDX 1.6 schema compliance and cryptographic asset depth."""
        cbom = generate_cbom_data()
        assert cbom["bomFormat"] == "CycloneDX"  # nosec: B101
        assert cbom["specVersion"] == "1.6"  # nosec: B101
        assert cbom["serialNumber"].startswith("urn:uuid:")  # nosec: B101
        assert "metadata" in cbom  # nosec: B101
        assert "components" in cbom  # nosec: B101
        assert len(cbom["components"]) >= 10  # nosec: B101

        # Verify cryptographic-asset components
        for comp in cbom["components"]:
            assert comp["type"] == "cryptographic-asset"  # nosec: B101
            assert "cryptoProperties" in comp  # nosec: B101
            crypto_prop = comp["cryptoProperties"]
            assert "assetType" in crypto_prop  # nosec: B101
            assert "algorithmProperties" in crypto_prop  # nosec: B101
            algo_prop = crypto_prop["algorithmProperties"]
            assert isinstance(algo_prop, dict)  # nosec: B101
            assert len(algo_prop) > 0  # nosec: B101

    def test_cbom_signing_and_verification(self, tmp_path):
        """Verify CBOM can be signed with ML-DSA-87 and verified cleanly."""
        cbom_path, sig_path, pub_path = sign_and_export_cbom(output_dir=tmp_path)
        assert cbom_path.exists()  # nosec: B101
        assert sig_path.exists()  # nosec: B101
        assert pub_path.exists()  # nosec: B101

        # Verify valid signatures
        valid = verify_cbom_signature(cbom_path, sig_path, pub_path)
        assert valid is True  # nosec: B101

    def test_cbom_tamper_detection(self, tmp_path):
        """Ensure modifying even a single byte of CBOM triggers verification failure."""
        cbom_path, sig_path, pub_path = sign_and_export_cbom(output_dir=tmp_path)

        # Tamper with the CBOM JSON content
        raw = cbom_path.read_bytes()
        tampered = raw.replace(b"CycloneDX", b"TamperedDX")
        cbom_path.write_bytes(tampered)

        valid = verify_cbom_signature(cbom_path, sig_path, pub_path)
        assert valid is False  # nosec: B101


class TestRustUdpDataPlane:
    """WireGuard-Style Rust UDP Data Plane and Rate Limiting Suite."""

    def test_token_bucket_rate_limiter(self):
        """Test DestroyerNode token-bucket per-source rate limiting."""
        node = DestroyerNode()
        ip = "192.0.2.100"
        # 64 burst requests allowed
        for i in range(64):
            assert node._check_rate_limit(ip) is True, f"Request {i+1} should be within burst allowance"  # nosec: B101
        # 65th immediate request must be dropped (exhausted)
        assert node._check_rate_limit(ip) is False, "Request over burst limit must be dropped"  # nosec: B101

    def test_udp_data_plane_env_flag(self, monkeypatch):
        """Verify udp_data_plane_enabled recognizes rust_udp and udp."""
        monkeypatch.setenv("P2P_DATA_PLANE", "rust_udp")
        assert udp_data_plane_enabled() is True  # nosec: B101
        monkeypatch.setenv("P2P_DATA_PLANE", "udp")
        assert udp_data_plane_enabled() is True  # nosec: B101
        monkeypatch.setenv("P2P_DATA_PLANE", "rust")
        assert udp_data_plane_enabled() is False  # nosec: B101
        monkeypatch.setenv("P2P_DATA_PLANE", "python")
        assert udp_data_plane_enabled() is False  # nosec: B101

    def test_destroyer_node_udp_loopback_bidirectional(self):
        """Test DestroyerNode UDP roundtrip with fixed quantum wire framing."""
        shared_key = secrets.token_bytes(32)

        node_a = DestroyerNode()
        node_b = DestroyerNode()

        node_a.establish(shared_key, is_initiator=True)
        node_b.establish(shared_key, is_initiator=False)

        host_a, port_a = node_a.bind_udp("127.0.0.1", 0)
        host_b, port_b = node_b.bind_udp("127.0.0.1", 0)

        assert port_a > 0  # nosec: B101
        assert port_b > 0  # nosec: B101

        try:
            msg_ab = b"CLASSIFIED DEFENSE PAYLOAD: MIL-SPEC 2026 ALPHA"
            sent_len = node_a.send_udp_msg(msg_ab, (host_b, port_b))
            assert sent_len == 256, f"Wire length {sent_len} must be 256 bytes (WIRE_QUANTUM_SMALL)"  # nosec: B101

            res_b = node_b.recv_udp_msg(timeout=2.0)
            assert res_b is not None  # nosec: B101
            payload_b, sender_b = res_b
            assert payload_b == msg_ab  # nosec: B101
            assert sender_b[1] == port_a  # nosec: B101

            # Node B -> Node A response
            msg_ba = b"ACK RECEIVED OVER RUST UDP: READY FOR MISSION"
            sent_ba = node_b.send_udp_msg(msg_ba, (host_a, port_a))
            assert sent_ba == 256  # nosec: B101

            res_a = node_a.recv_udp_msg(timeout=2.0)
            assert res_a is not None  # nosec: B101
            payload_a, sender_a = res_a
            assert payload_a == msg_ba  # nosec: B101
            assert sender_a[1] == port_b  # nosec: B101

        finally:
            node_a.close_udp()
            node_b.close_udp()

    def test_destroyer_node_chaff_absorption(self):
        """Ensure chaff packets (traffic analysis resistance) are absorbed silently."""
        shared_key = secrets.token_bytes(32)
        node_a = DestroyerNode()
        node_b = DestroyerNode()

        node_a.establish(shared_key, is_initiator=True)
        node_b.establish(shared_key, is_initiator=False)

        host_a, port_a = node_a.bind_udp("127.0.0.1", 0)
        host_b, port_b = node_b.bind_udp("127.0.0.1", 0)

        try:
            node_a.send_udp_msg(b"dummy chaff noise data", (host_b, port_b), chaff=True)
            chaff_res = node_b.recv_udp_msg(timeout=0.5)
            assert chaff_res is None, "Chaff packets must be absorbed silently"  # nosec: B101
        finally:
            node_a.close_udp()
            node_b.close_udp()

    def test_destroyer_node_oversized_silent_drop(self):
        """Ensure packets exceeding MTU (1280B) are silently dropped."""
        node = DestroyerNode()
        host, port = node.bind_udp("127.0.0.1", 0)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            giant_datagram = b"\xaa" * 1500
            sock.sendto(giant_datagram, (host, port))
            sock.close()

            res = node.recv_udp_msg(timeout=0.5)
            assert res is None, "Oversized datagram must be silently dropped without crash"  # nosec: B101
        finally:
            node.close_udp()

    def test_destroyer_node_anti_replay_drop(self):
        """Ensure replayed packets are detected and rejected by the sliding window bitmap."""
        shared_key = secrets.token_bytes(32)
        node_a = DestroyerNode()
        node_b = DestroyerNode()

        node_a.establish(shared_key, is_initiator=True)
        node_b.establish(shared_key, is_initiator=False)

        host_a, port_a = node_a.bind_udp("127.0.0.1", 0)
        host_b, port_b = node_b.bind_udp("127.0.0.1", 0)

        try:
            frame = node_a.transmit(b"REPLAY TEST TARGET")

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            raw_sock.sendto(frame, (host_b, port_b))

            first_recv = node_b.recv_udp_msg(timeout=2.0)
            assert first_recv is not None  # nosec: B101
            assert first_recv[0] == b"REPLAY TEST TARGET"  # nosec: B101

            # Replay the identical frame to B's UDP socket
            raw_sock.sendto(frame, (host_b, port_b))
            raw_sock.close()

            second_recv = node_b.recv_udp_msg(timeout=0.5)
            assert second_recv is None, "Replayed datagram must be rejected by anti-replay bitmap"  # nosec: B101

        finally:
            node_a.close_udp()
            node_b.close_udp()


class TestFips140_3AndNiapCommonCriteria:
    """FIPS 140-3 CMSP & NIAP Common Criteria Security Target Suite."""

    def test_acvp_report_signature_verification(self):
        """Verify the ACVP report is cryptographically signed with ML-DSA-87."""
        from acvp_validation_harness import verify_acvp_report_signature
        rep = Path("compliance_reports/acvp_cavp_validation_report.json")
        sig = Path("compliance_reports/acvp_cavp_validation_report.json.mldsa87.sig")
        pub = Path("compliance_reports/acvp_cavp_validation_report.json.mldsa87.pub")

        assert rep.exists() and sig.exists() and pub.exists()  # nosec: B101
        assert verify_acvp_report_signature(rep, sig, pub) is True  # nosec: B101

    def test_fips140_3_cmsp_policy_and_submittal(self):
        """Verify FIPS 140-3 CMSP documentation and signed NVLAP/CMVP submittal package."""
        from liboqs_wrapper import LibOQS_MLDSA_87
        doc_path = Path("docs/FIPS_140_3_SECURITY_POLICY.md")
        submittal_path = Path("compliance_reports/cmvp_fips140_3_submittal.json")
        sig_path = Path("compliance_reports/cmvp_fips140_3_submittal.json.mldsa87.sig")
        pub_path = Path("compliance_reports/cmvp_fips140_3_submittal.json.mldsa87.pub")

        assert doc_path.exists()  # nosec: B101
        assert submittal_path.exists() and sig_path.exists() and pub_path.exists()  # nosec: B101

        dsa = LibOQS_MLDSA_87()
        assert dsa.verify(pub_path.read_bytes(), submittal_path.read_bytes(), sig_path.read_bytes()) is True  # nosec: B101

    def test_niap_common_criteria_security_target(self):
        """Verify NIAP NDcPP v3.0 Common Criteria Security Target and signed matrix."""
        from liboqs_wrapper import LibOQS_MLDSA_87
        doc_path = Path("docs/NIAP_COMMON_CRITERIA_SECURITY_TARGET.md")
        matrix_path = Path("compliance_reports/niap_common_criteria_matrix.json")
        sig_path = Path("compliance_reports/niap_common_criteria_matrix.json.mldsa87.sig")
        pub_path = Path("compliance_reports/niap_common_criteria_matrix.json.mldsa87.pub")

        assert doc_path.exists()  # nosec: B101
        assert matrix_path.exists() and sig_path.exists() and pub_path.exists()  # nosec: B101

        dsa = LibOQS_MLDSA_87()
        assert dsa.verify(pub_path.read_bytes(), matrix_path.read_bytes(), sig_path.read_bytes()) is True  # nosec: B101

    def test_witnessed_key_ceremony_receipt(self):
        """Verify that a witnessed key ceremony receipt exists and has Merkle root chaining."""
        receipts = list(Path("compliance_reports").glob("ceremony_receipt_*.json"))
        assert len(receipts) > 0, "At least one witnessed key ceremony receipt must exist"  # nosec: B101
        with open(receipts[-1], "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "ceremony_id" in data  # nosec: B101
        assert "merkle_root_hash" in data  # nosec: B101
        assert "generated_root_credentials" in data  # nosec: B101
        assert "ML-DSA-87" in str(data)  # nosec: B101

    def test_intercontinental_10mb_streaming(self):
        """Verify 10MB bulk UDP data plane stream integrity with SHA3-512 bit-for-bit parity."""
        from verify_intercontinental_udp_stream import IntercontinentalUdpStreamVerifier
        verifier = IntercontinentalUdpStreamVerifier(verbose=False)
        rep = verifier.run_all()
        assert rep["all_passed"] is True  # nosec: B101


class TestTwinFileParity:
    """Twin Parity Validation: secure_p2p.py and secure_p2.py must match byte-for-byte."""

    def test_byte_for_byte_twin_identity(self):
        path_p2p = Path("archive/legacy_prototype/secure_p2p.py")
        path_p2 = Path("archive/legacy_prototype/secure_p2.py")

        assert path_p2p.exists(), "secure_p2p.py must exist"  # nosec: B101
        assert path_p2.exists(), "secure_p2.py must exist"  # nosec: B101

        bytes_p2p = path_p2p.read_bytes()
        bytes_p2 = path_p2.read_bytes()

        assert len(bytes_p2p) == len(bytes_p2), (  # nosec: B101
            f"Size mismatch: secure_p2p.py is {len(bytes_p2p)} bytes, "
            f"secure_p2.py is {len(bytes_p2)} bytes"
        )
        assert bytes_p2p == bytes_p2, "secure_p2p.py and secure_p2.py are not 100% byte-for-byte identical!"  # nosec: B101


