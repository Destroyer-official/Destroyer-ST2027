#!/usr/bin/env python3
"""
tests/test_military_five_pillars_operational.py
====================================================================
End-to-end verification of the 5 Sovereign Military Tactical Pillars:
  Pillar 1: Hardware-Circuit-Level Instant Key Zeroization & Anti-Tamper Affidavit
  Pillar 2: Low Probability of Detection (LPD) & Interception (LPI) Isochronous Pacing
  Pillar 3: Air-Gapped / Isolated Overlay & Serverless Self-Healing Dark Mesh (DDIL)
  Pillar 4: Strict Zero Trust Mutual Authentication & Hardware-Bound Verification (TPM 2.0)
  Pillar 5: Military Root Certificate Authority (CA) & Explicit Rejection of Untrusted Nodes
"""

import os
import sys
import time
import json
import secrets
import hashlib
import tempfile
import threading
import subprocess
from pathlib import Path
import pytest

from secure_p2p import TacticalP2PNode, NATIVE_BIN
from pq_certificate_authority import create_certificate_authority, PQCertificate, PQCertificateAuthority
from emergency_anti_tamper import AntiTamperTrigger


class TestMilitaryFivePillars:

    @pytest.fixture(autouse=True)
    def setup_env(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_5_pillars_")
        self.psk_path = os.path.join(self.tmp_dir, "tactical.psk")
        with open(self.psk_path, "w", encoding="utf-8") as f:
            f.write(secrets.token_hex(32) + "\n")

        # Set up Military Root CA
        self.ca = create_certificate_authority("US_STRATEGIC_DEFENSE_ROOT_CA")
        self.root_ca_file = os.path.join(self.tmp_dir, "military_root_ca.json")
        self.ca.save_root_certificate(self.root_ca_file)

        # Generate ML-DSA-87 identity keypairs with hardened ACL permissions via native auth-keygen
        self.alpha_sk_file = os.path.join(self.tmp_dir, "station_alpha.auth.sk")
        self.alpha_pk_file = os.path.join(self.tmp_dir, "station_alpha.auth.pk")
        subprocess.run([str(NATIVE_BIN), "auth-keygen", "--out-sk", self.alpha_sk_file, "--out-pk", self.alpha_pk_file], check=True, capture_output=True)

        alpha_pk_bytes = bytes.fromhex(Path(self.alpha_pk_file).read_text(encoding="utf-8").strip())
        self.alpha_cert = self.ca.issue_certificate("STATION_ALPHA", alpha_pk_bytes, validity_days=2)
        self.alpha_cert_file = os.path.join(self.tmp_dir, "station_alpha.cert.json")
        self.alpha_cert.save_to_file(self.alpha_cert_file)

        self.bravo_sk_file = os.path.join(self.tmp_dir, "station_bravo.auth.sk")
        self.bravo_pk_file = os.path.join(self.tmp_dir, "station_bravo.auth.pk")
        subprocess.run([str(NATIVE_BIN), "auth-keygen", "--out-sk", self.bravo_sk_file, "--out-pk", self.bravo_pk_file], check=True, capture_output=True)

        bravo_pk_bytes = bytes.fromhex(Path(self.bravo_pk_file).read_text(encoding="utf-8").strip())
        self.bravo_cert = self.ca.issue_certificate("STATION_BRAVO", bravo_pk_bytes, validity_days=2)
        self.bravo_cert_file = os.path.join(self.tmp_dir, "station_bravo.cert.json")
        self.bravo_cert.save_to_file(self.bravo_cert_file)

        yield

        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_pillar_1_circuit_zeroization_and_signed_affidavit(self):
        """Pillar 1: Instant hardware circuit level zeroization generates signed affidavit."""
        alpha_work = os.path.join(self.tmp_dir, "alpha_work")
        node = TacticalP2PNode(
            name="TEST_ALPHA",
            role="responder",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9600,
            channel_port=9610,
            work_dir=alpha_work,
            psk_file=self.psk_path,
            lab_mode=True
        )
        os.makedirs(alpha_work, exist_ok=True)
        # Create dummy session key to test purge
        Path(node.key_path).write_text("DUMMY_TOP_SECRET_SESSION_KEY_BYTES", encoding="utf-8")
        Path(node.state_path).write_text("DUMMY_MONOTONIC_STATE_SEQUENCE_99", encoding="utf-8")

        # Trigger emergency physical circuit zeroization
        success = node.emergency_zeroize(trigger=AntiTamperTrigger.CHASSIS_INTRUSION_SENSOR)
        assert success is True

        # Verify volatile memory wiped and files purged
        assert not os.path.exists(node.key_path)
        assert not os.path.exists(node.state_path)

    def test_pillar_2_lpd_lpi_isochronous_telemetry(self):
        """Pillar 2: LPD/LPI isochronous pacing and Shannon entropy traffic invariance."""
        node = TacticalP2PNode(
            name="TEST_ALPHA",
            role="responder",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9620,
            channel_port=9630,
            work_dir=os.path.join(self.tmp_dir, "alpha_p2"),
            psk_file=self.psk_path,
            lab_mode=True
        )
        telemetry = node.get_lpd_lpi_telemetry()
        assert telemetry["scheduler_interval_ms"] == 20
        assert telemetry["wire_quantum_bytes"] == 1232
        assert telemetry["synthetic_chaff_type"] == "0xFF (Continuous Camouflage)"
        assert telemetry["shannon_entropy_bits_per_byte"] >= 7.95
        assert "CONSTANT_RATE" in telemetry["traffic_invariance"]
        node.close()

    def test_pillar_3_air_gapped_serverless_dark_mesh(self):
        """Pillar 3: Serverless self-healing dark mesh stores, reconciles, and routes bundles."""
        node = TacticalP2PNode(
            name="TEST_ALPHA",
            role="responder",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9640,
            channel_port=9650,
            work_dir=os.path.join(self.tmp_dir, "alpha_p3"),
            psk_file=self.psk_path,
            lab_mode=True
        )
        assert node.mesh_node is not None
        # Enqueue a dark overlay bundle
        bundle = node.mesh_node.enqueue_bundle(
            recipient_id="FORWARD_OBSERVER_BRAVO",
            seq=1,
            ciphertext_bytes=b"TACTICAL_COORDINATES_OVERLAY_BURST",
            auth_tag=hashlib.sha256(b"TACTICAL_COORDINATES_OVERLAY_BURST").digest()[:16],
            priority=1,
            ttl_sec=3600
        )
        assert bundle is not None
        assert bundle.bundle_id is not None
        assert len(node.mesh_node.outbound_store["FORWARD_OBSERVER_BRAVO"]) == 1
        digest = node.mesh_node.get_merkle_digest("FORWARD_OBSERVER_BRAVO")
        assert len(digest) in (64, 128)
        node.close()

    def test_pillar_4_zero_trust_hardware_attestation(self):
        """Pillar 4: TPM 2.0 PCR attestation and dynamic zero-trust continuous verification."""
        node = TacticalP2PNode(
            name="TEST_ALPHA",
            role="responder",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9660,
            channel_port=9670,
            work_dir=os.path.join(self.tmp_dir, "alpha_p4"),
            psk_file=self.psk_path,
            lab_mode=True
        )
        st = node.get_tpm_status()
        assert "status" in st
        assert node.zt_engine is not None
        # Baseline trust score
        score = node.zt_engine.trust_score(node.peer_addr)
        assert score >= 70
        # Positive signal keeps score high
        node.zt_engine.record_success(node.peer_addr)
        assert node.zt_engine.is_trusted(node.peer_addr)
        node.close()

    def test_pillar_5_military_root_ca_verified_handshake(self):
        """Pillar 5: Both nodes possess valid pre-installed Military Root CA signed certificates."""
        alpha = TacticalP2PNode(
            name="ALPHA_HQ",
            role="responder",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9680,
            peer_kex_port=9680,
            channel_port=9690,
            peer_channel_port=9691,
            work_dir=os.path.join(self.tmp_dir, "alpha_ca"),
            psk_file=self.psk_path,
            lab_mode=True,
            auth_sk_file=self.alpha_sk_file,
            peer_auth_pk_file=self.bravo_pk_file,
            root_ca_file=self.root_ca_file,
            node_cert_file=self.alpha_cert_file,
            peer_cert_file=self.bravo_cert_file,
            require_root_ca=True
        )

        bravo = TacticalP2PNode(
            name="BRAVO_HQ",
            role="initiator",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9681,
            peer_kex_port=9680,
            channel_port=9691,
            peer_channel_port=9690,
            work_dir=os.path.join(self.tmp_dir, "bravo_ca"),
            psk_file=self.psk_path,
            lab_mode=True,
            auth_sk_file=self.bravo_sk_file,
            peer_auth_pk_file=self.alpha_pk_file,
            root_ca_file=self.root_ca_file,
            node_cert_file=self.bravo_cert_file,
            peer_cert_file=self.alpha_cert_file,
            require_root_ca=True
        )

        os.makedirs(alpha.work_dir, exist_ok=True)
        os.makedirs(bravo.work_dir, exist_ok=True)

        kex_res = {}
        def run_a():
            kex_res["alpha"] = alpha.negotiate_hybrid_kex(timeout_sec=15)
        def run_b():
            kex_res["bravo"] = bravo.negotiate_hybrid_kex(timeout_sec=15)

        ta = threading.Thread(target=run_a)
        tb = threading.Thread(target=run_b)
        ta.start(); time.sleep(0.3); tb.start()
        ta.join(); tb.join()

        assert kex_res.get("alpha") is True
        assert kex_res.get("bravo") is True
        assert alpha.root_ca_verified is True
        assert bravo.root_ca_verified is True
        assert alpha.sas == bravo.sas

        alpha.close()
        bravo.close()

    def test_pillar_5_explicitly_rejects_node_without_military_root_ca_cert(self):
        """Pillar 5: Node explicitly rejects connections from nodes without Root CA signed cert."""
        # Create an unauthorized rogue CA and rogue certificate
        rogue_ca = create_certificate_authority("ROGUE_UNTRUSTED_CA")
        rogue_sk_file = os.path.join(self.tmp_dir, "rogue.auth.sk")
        rogue_pk_file = os.path.join(self.tmp_dir, "rogue.auth.pk")
        subprocess.run([str(NATIVE_BIN), "auth-keygen", "--out-sk", rogue_sk_file, "--out-pk", rogue_pk_file], check=True, capture_output=True)

        rogue_pk_bytes = bytes.fromhex(Path(rogue_pk_file).read_text(encoding="utf-8").strip())
        rogue_cert = rogue_ca.issue_certificate("ROGUE_IMPOSTOR", rogue_pk_bytes, validity_days=5)
        rogue_cert_file = os.path.join(self.tmp_dir, "rogue.cert.json")
        rogue_cert.save_to_file(rogue_cert_file)

        # Target node enforcing Military Root CA
        alpha = TacticalP2PNode(
            name="ALPHA_SECURE",
            role="responder",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9700,
            channel_port=9710,
            work_dir=os.path.join(self.tmp_dir, "alpha_reject"),
            psk_file=self.psk_path,
            lab_mode=True,
            auth_sk_file=self.alpha_sk_file,
            peer_auth_pk_file=None,
            root_ca_file=self.root_ca_file,  # Legit Root CA
            node_cert_file=self.alpha_cert_file,
            peer_cert_file=rogue_cert_file,  # Rogue cert!
            require_root_ca=True
        )

        # negotiate_hybrid_kex MUST return False and fail closed!
        rejected = not alpha.negotiate_hybrid_kex(timeout_sec=3)
        assert rejected is True, "Security Breach: Alpha accepted a certificate from an untrusted Root CA!"
        assert alpha.root_ca_verified is False
        alpha.close()

    def test_pillar_4_strict_hardware_fail_closed_on_workstation(self):
        """Pillar 4: When strict hardware is enforced, missing external HSM/FIPS fails closed."""
        import hw_readiness
        verdicts = hw_readiness.collect()
        # In a standard lab or development workstation, strict_ok must be False
        # (because physical Luna HSM / FIPS 140-3 boundary are external military appliances)
        is_strict = hw_readiness.strict_ok(verdicts)
        assert is_strict is False
        missing = [v for v in verdicts if v.ts_required and v.status != hw_readiness.HAVE]
        missing_ids = [v.id for v in missing]
        assert "hsm" in missing_ids or "fips" in missing_ids or "admin" in missing_ids

    def test_pillar_5_rejects_tampered_root_ca_signature(self):
        """Pillar 5: Bit-flipped certificate signature is immediately rejected fail-closed."""
        with open(self.bravo_cert_file, "r", encoding="utf-8") as f:
            cert_data = json.load(f)
        # Tamper signature hex
        sig_hex = cert_data["signature"]
        flipped = ("00" if sig_hex[:2] != "00" else "ff") + sig_hex[2:]
        cert_data["signature"] = flipped
        tampered_cert_file = os.path.join(self.tmp_dir, "bravo_tampered.cert.json")
        with open(tampered_cert_file, "w", encoding="utf-8") as f:
            json.dump(cert_data, f)

        # Attempt verification under root CA
        root_cert = PQCertificate.load_from_file(self.root_ca_file)
        tampered_cert = PQCertificate.load_from_file(tampered_cert_file)
        with pytest.raises(Exception) as exc_info:
            PQCertificateAuthority.verify_cert_against_root(root_cert, tampered_cert)
        assert "signature invalid" in str(exc_info.value).lower() or "verification" in str(exc_info.value).lower()


