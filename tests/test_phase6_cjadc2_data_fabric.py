#!/usr/bin/env python3
"""
test_phase6_cjadc2_data_fabric.py
Comprehensive Phase 6 Test Suite:
1. CJADC2 Cross-Domain Multi-Level Security (CDS/MLS) Guard:
   - Bell-LaPadula Simple Security (No Read Up) & *-Property (No Write Down)
   - NSA NCDSMO "Raise the Bar" (RTB) Deep Content Inspection & Dirty-Word Spillage Defense
   - Post-Quantum Cryptographic Compartment Isolation (HKDF-SHA3-512 + ChaCha20-Poly1305)
2. NIST CSWP 39 (Dec 2025) Dynamic Post-Quantum Crypto-Agility State Machine:
   - CNSA 2.0 Level 5 suite negotiation & live zero-downtime hot-swap
   - Strict fail-closed anti-downgrade defense against classical & sub-L5 algorithms
3. MIL-STD-6090 (Jan 31, 2025) Cursor-on-Target (CoT) Situational Awareness:
   - MIL-STD-6090 XML & compact JSON event serialization
   - Post-quantum ML-DSA-87 (FIPS 204) event signing and tamper rejection
   - Tactical DDIL store-and-forward mesh packaging (RFC 9171 / RFC 9172)
4. Twin File Parity Validation (secure_p2p.py == secure_p2.py)
"""

import json
import os
import secrets
from pathlib import Path
import pytest

from cjadc2_cross_domain_guard import (
    CrossDomainGuard,
    CrossDomainPolicyViolation,
    SecurityClassification,
    SecurityCaveat,
    sign_and_export_cross_domain_audit,
    verify_cross_domain_audit_signature,
)
from pqc_crypto_agility_engine import (
    CryptoAgilityEngine,
    AgilityState,
    sign_and_export_crypto_agility_audit,
    verify_crypto_agility_audit_signature,
)
from cjadc2_tactical_cot import (
    TacticalCoTEvent,
    CoTEventType,
)
from tactical_mesh_ddil import BundlePriority
from liboqs_wrapper import LibOQS_MLDSA_87


class TestCrossDomainMLSSuite:
    """CJADC2 Cross-Domain Guard (CDS) & Bell-LaPadula MLS Suite."""

    def test_bell_lapadula_no_read_up(self):
        guard_secret = CrossDomainGuard(node_clearance=SecurityClassification.SECRET)
        can_read_conf, _ = guard_secret.evaluate_read_access(SecurityClassification.CONFIDENTIAL)
        can_read_sec, _ = guard_secret.evaluate_read_access(SecurityClassification.SECRET)
        can_read_ts, reason_ts = guard_secret.evaluate_read_access(SecurityClassification.TOP_SECRET)

        assert can_read_conf is True  # nosec: B101
        assert can_read_sec is True  # nosec: B101
        assert can_read_ts is False  # nosec: B101
        assert "BELL-LAPADULA VIOLATION (NO READ UP)" in reason_ts  # nosec: B101

    def test_bell_lapadula_no_write_down(self):
        guard_secret = CrossDomainGuard(node_clearance=SecurityClassification.SECRET)

        # Write-up is permitted by Bell-LaPadula *-Property
        can_write_ts, _, _ = guard_secret.evaluate_write_egress(
            source_classification=SecurityClassification.SECRET,
            target_classification=SecurityClassification.TOP_SECRET,
            payload_bytes=b"TACTICAL_RADAR_OBSERVATION"
        )
        assert can_write_ts is True  # nosec: B101

        # Write-down is strictly blocked (No Write Down)
        can_write_unclass, reason, _ = guard_secret.evaluate_write_egress(
            source_classification=SecurityClassification.SECRET,
            target_classification=SecurityClassification.UNCLASSIFIED,
            payload_bytes=b"TACTICAL_RADAR_OBSERVATION"
        )
        assert can_write_unclass is False  # nosec: B101
        assert "NO WRITE DOWN" in reason  # nosec: B101

    def test_rtb_deep_content_spillage_detection(self):
        guard = CrossDomainGuard(node_clearance=SecurityClassification.CONFIDENTIAL)
        spill_payload = b"CRITICAL STRIKE ORDER // TOP SECRET // EYES ONLY"

        ok, reason, _ = guard.evaluate_write_egress(
            source_classification=SecurityClassification.CONFIDENTIAL,
            target_classification=SecurityClassification.SECRET,
            payload_bytes=spill_payload
        )
        assert ok is False  # nosec: B101
        assert "NSA RTB CONTENT INSPECTION FAILURE" in reason  # nosec: B101
        assert guard.spillage_events_blocked >= 1  # nosec: B101

    def test_cryptographic_compartment_isolation(self):
        guard = CrossDomainGuard()
        master_secret = secrets.token_bytes(64)
        plaintext = b"TARGET_RADAR_COMPARTMENT_ALPHA_32B"

        envelope = guard.encrypt_compartment_payload(
            master_secret=master_secret,
            classification=SecurityClassification.TOP_SECRET,
            caveat="NOFORN",
            plaintext_bytes=plaintext
        )

        # Node with only SECRET clearance cannot decrypt
        with pytest.raises(CrossDomainPolicyViolation) as exc_info:
            guard.decrypt_compartment_payload(
                master_secret=master_secret,
                compartment_envelope=envelope,
                node_clearance=SecurityClassification.SECRET,
                node_caveats={SecurityCaveat.NOFORN}
            )
        assert "Node clearance SECRET < Target compartment TOP_SECRET" in str(exc_info.value)  # nosec: B101

        # Node with TOP_SECRET clearance can decrypt
        decrypted = guard.decrypt_compartment_payload(
            master_secret=master_secret,
            compartment_envelope=envelope,
            node_clearance=SecurityClassification.TOP_SECRET,
            node_caveats={SecurityCaveat.NOFORN}
        )
        assert decrypted == plaintext  # nosec: B101

    def test_cross_domain_audit_export_and_signature(self, tmp_path):
        guard = CrossDomainGuard(audit_dir=tmp_path)
        rep_p, sig_p, pub_p = sign_and_export_cross_domain_audit(guard, output_dir=tmp_path)

        assert rep_p.exists() and sig_p.exists() and pub_p.exists()  # nosec: B101
        assert verify_cross_domain_audit_signature(rep_p, sig_p, pub_p) is True  # nosec: B101

        # Tamper test
        raw = rep_p.read_bytes()
        tampered = raw.replace(b"ACTIVE_STRICT", b"COMPROMISED")
        rep_p.write_bytes(tampered)
        assert verify_cross_domain_audit_signature(rep_p, sig_p, pub_p) is False  # nosec: B101


class TestCryptoAgilitySuite:
    """NIST CSWP 39 Dynamic Crypto-Agility State Machine Suite."""

    def test_agility_state_machine_hotswap(self):
        engine = CryptoAgilityEngine("STATION_DELTA")
        assert engine.current_state == AgilityState.ACTIVE_CNSA2_PRIMARY  # nosec: B101
        assert engine.active_kem == "ML-KEM-1024"  # nosec: B101
        assert engine.active_dss == "ML-DSA-87"  # nosec: B101

        # Propose migration to alternate CNSA 2.0 L5 suite
        proposal = engine.propose_suite_migration(
            target_kem="Classic-McEliece-8192128f",
            target_dss="SLH-DSA-256f"
        )
        assert engine.current_state == AgilityState.PROPOSED_MIGRATION  # nosec: B101

        ok, msg = engine.evaluate_peer_proposal(proposal)
        assert ok is True  # nosec: B101

        # Execute live zero-downtime hot-swap
        receipt = engine.execute_live_hotswap(proposal)
        assert receipt["status"] == "HOTSWAP_SUCCESSFUL"  # nosec: B101
        assert engine.current_state == AgilityState.COMMITTED_MIGRATION  # nosec: B101
        assert engine.active_kem == "Classic-McEliece-8192128f"  # nosec: B101
        assert engine.active_dss == "SLH-DSA-256f"  # nosec: B101

    def test_classical_and_sub_l5_downgrade_rejection(self):
        engine = CryptoAgilityEngine("STATION_DELTA")

        # 1. Classical RSA proposal
        rsa_proposal = {"proposed_suite": {"kem": "RSA-4096", "dss": "ML-DSA-87"}}
        ok_rsa, err_rsa = engine.evaluate_peer_proposal(rsa_proposal)
        assert ok_rsa is False  # nosec: B101
        assert engine.current_state == AgilityState.DOWNGRADE_DEFENDED  # nosec: B101
        assert "classical/deprecated primitives" in err_rsa  # nosec: B101

        # 2. Sub-Level 5 (Kyber-512) proposal
        sub5_proposal = {"proposed_suite": {"kem": "Kyber-512", "dss": "ML-DSA-87"}}
        ok_sub5, err_sub5 = engine.evaluate_peer_proposal(sub5_proposal)
        assert ok_sub5 is False  # nosec: B101
        assert "FORBIDDEN ALGORITHM DETECTED" in err_sub5  # nosec: B101

    def test_crypto_agility_audit_export_and_signature(self, tmp_path):
        engine = CryptoAgilityEngine("STATION_DELTA", audit_dir=tmp_path)
        rep_p, sig_p, pub_p = sign_and_export_crypto_agility_audit(engine, output_dir=tmp_path)

        assert rep_p.exists() and sig_p.exists() and pub_p.exists()  # nosec: B101
        assert verify_crypto_agility_audit_signature(rep_p, sig_p, pub_p) is True  # nosec: B101


class TestTacticalCoTSuite:
    """MIL-STD-6090 Cursor-on-Target Tactical Messaging Suite."""

    def test_cot_event_generation_and_ml_dsa_87_signing(self):
        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()

        cot = TacticalCoTEvent(
            event_type=CoTEventType.HOSTILE_AIR_FIGHTER,
            lat=35.123456,
            lon=44.654321,
            callsign="BANDIT_04",
            speed_mps=340.5,
            course_deg=180.0,
            classification="SECRET"
        )
        cot.sign_event(sk, pk)
        assert cot.verify_event_signature() is True  # nosec: B101

        xml_data = cot.to_mil_std_6090_xml()
        assert "BANDIT_04" in xml_data  # nosec: B101
        assert "FIPS-204" in xml_data  # nosec: B101
        assert "35.123456" in xml_data  # nosec: B101

    def test_cot_geospatial_tamper_detection(self):
        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()

        cot = TacticalCoTEvent(
            event_type=CoTEventType.FRIENDLY_GROUND_COMBAT,
            lat=32.0,
            lon=45.0,
            callsign="WARRIOR_01"
        )
        cot.sign_event(sk, pk)
        c_json = cot.to_compact_json()

        # Reconstruct authentic
        authentic = TacticalCoTEvent.from_compact_json(c_json)
        assert authentic.verify_event_signature() is True  # nosec: B101

        # Tamper coordinates
        tampered_json = dict(c_json)
        tampered_json["pos"] = [32.000001, 45.000001, 0.0]
        tampered_ev = TacticalCoTEvent.from_compact_json(tampered_json)
        assert tampered_ev.verify_event_signature() is False  # nosec: B101

    def test_cot_to_ddil_mesh_bundle(self):
        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()

        cot_hostile = TacticalCoTEvent(
            event_type=CoTEventType.HOSTILE_AIR_FIGHTER,
            lat=33.1,
            lon=44.2,
            callsign="BOGEY_09"
        )
        cot_hostile.sign_event(sk, pk)
        bundle_hostile = cot_hostile.to_ddil_bundle("RADAR_POST_01", "COMMAND_HQ", seq=501)
        # Hostile alerts MUST map to EMERGENCY priority
        assert bundle_hostile.priority == BundlePriority.EMERGENCY  # nosec: B101

        cot_friendly = TacticalCoTEvent(
            event_type=CoTEventType.FRIENDLY_GROUND_COMBAT,
            lat=33.0,
            lon=44.0,
            callsign="CONVOY_02"
        )
        cot_friendly.sign_event(sk, pk)
        bundle_friendly = cot_friendly.to_ddil_bundle("RADAR_POST_01", "COMMAND_HQ", seq=502)
        assert bundle_friendly.priority == BundlePriority.COMMAND  # nosec: B101


class TestTwinFileParityPhase6:
    """Twin Parity Invariant: secure_p2p.py and secure_p2.py must match byte-for-byte."""

    def test_phase6_byte_for_byte_identity(self):
        p2p_path = Path("archive/legacy_prototype/secure_p2p.py")
        p2_path = Path("archive/legacy_prototype/secure_p2.py")
        if not p2p_path.exists() or not p2_path.exists():
            pytest.skip("legacy prototype twins not present in archive")
        p2p_bytes = p2p_path.read_bytes()
        p2_bytes = p2_path.read_bytes()

        assert p2p_bytes == p2_bytes, (  # nosec: B101
            f"Twin parity error! secure_p2p.py ({len(p2p_bytes)}B) != secure_p2.py ({len(p2_bytes)}B)"
        )

