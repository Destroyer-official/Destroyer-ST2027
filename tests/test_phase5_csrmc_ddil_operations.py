#!/usr/bin/env python3
"""
test_phase5_csrmc_ddil_operations.py
Comprehensive Phase 5 Test Suite:
1. DoD CSRMC Phase 5 Operations Telemetry Streaming, Mission Readiness & ML-DSA-87 Signatures
2. Tactical DDIL Mesh Partition Resilience, Store-and-Forward & Merkle-DAG Delta Reconciliation
3. Emergency Anti-Tamper & Scorched-Earth Cryptographic Zeroization (DoD 5220.22-M / NIST SP 800-88)
4. Multi-Node Byzantine Fault Tolerant (BFT) Quorum Consensus for Critical Tactical Commands
5. Twin File Parity Validation (secure_p2p.py == secure_p2.py)
"""

import json
import os
import secrets
import time
from pathlib import Path
import pytest

from csrmc_operations_monitor import (
    CSRMCOperationsMonitor,
    sign_and_export_csrmc_report,
    verify_csrmc_report_signature,
)
from tactical_mesh_ddil import (
    DDILNodeMesh,
    DDILBundle,
    BundlePriority,
    create_bpsec_bundle,
    decrypt_bpsec_bundle,
    TacticalAuthorityLevel,
    TacticalIdentityCache,
    AuthorityDecayEngine,
    GovernanceEnvelope,
    get_tactical_keyring,
)
from emergency_anti_tamper import (
    EmergencyZeroizationEngine,
    AntiTamperTrigger,
)
from byzantine_mesh_consensus import (
    ByzantineQuorumEngine,
    CriticalCommandType,
    sign_and_export_byzantine_receipt,
    verify_byzantine_receipt_signature,
)
from liboqs_wrapper import LibOQS_MLDSA_87


class TestCSRMCOperationsSuite:
    """DoD CSRMC Phase 5 Operations Telemetry & Readiness Suite."""

    def test_csrmc_telemetry_computation(self):
        monitor = CSRMCOperationsMonitor()
        telemetry = monitor.compute_operations_telemetry()

        assert "csrmc_operations_phase_telemetry" in telemetry  # nosec: B101
        data = telemetry["csrmc_operations_phase_telemetry"]

        assert data["lifecycle_phase"] == "Phase 5: Operations Phase"  # nosec: B101
        assert data["evaluation_mode"] == "CONTINUOUS_DATA_STREAMING"  # nosec: B101

        assurance = data["mission_assurance"]
        assert assurance["operational_status"] == "MISSION_CAPABLE_MAX"  # nosec: B101
        assert assurance["mission_readiness_score_pct"] == 100.0  # nosec: B101
        assert assurance["mean_time_to_remediate_ms"] < 50.0  # nosec: B101
        assert assurance["network_availability_pct"] >= 99.9  # nosec: B101

        crypto = data["cryptographic_runtime_health"]
        assert crypto["fallback_status"] == "ZERO_FALLBACKS_PERMITTED"  # nosec: B101

        # Verify research-backed Phase 5 telemetry components
        assert "tactical_ddil_mesh_readiness" in data  # nosec: B101
        assert "anti_tamper_and_zeroization_readiness" in data  # nosec: B101
        assert "byzantine_quorum_governance" in data  # nosec: B101

        ddil = data["tactical_ddil_mesh_readiness"]
        assert "RFC 9171 / RFC 9172" in ddil["mesh_architecture"]  # nosec: B101
        assert ddil["key_compression_profile"] == "TETA_32B_KEY_ID_BINDING_ACTIVE"  # nosec: B101

        tamper = data["anti_tamper_and_zeroization_readiness"]
        assert "NIST SP 800-88 Rev 2" in tamper["standard"]  # nosec: B101
        assert tamper["cold_boot_mitigation"] == "NON_PAGEABLE_MEMORY_PINNED"  # nosec: B101

    def test_csrmc_report_signing_and_tamper_rejection(self, tmp_path):
        rep_p, sig_p, pub_p = sign_and_export_csrmc_report(output_dir=tmp_path)

        assert rep_p.exists() and sig_p.exists() and pub_p.exists()  # nosec: B101
        assert verify_csrmc_report_signature(rep_p, sig_p, pub_p) is True  # nosec: B101

        # Tamper test
        raw = rep_p.read_bytes()
        tampered = raw.replace(b"MISSION_CAPABLE_MAX", b"COMPROMISED_FAILED")
        rep_p.write_bytes(tampered)

        assert verify_csrmc_report_signature(rep_p, sig_p, pub_p) is False  # nosec: B101


class TestTacticalMeshDDILSuite:
    """Tactical DDIL Mesh Store-and-Forward & Merkle Delta Reconciliation Suite."""

    def test_ddil_mesh_partition_and_reconciliation(self):
        node_a = DDILNodeMesh("HQ_STATION")
        node_b = DDILNodeMesh("FORWARD_PATROL")

        # 1. Sever link
        node_a.set_peer_connectivity("FORWARD_PATROL", False)
        node_b.set_peer_connectivity("HQ_STATION", False)

        assert node_a.is_peer_connected("FORWARD_PATROL") is False  # nosec: B101

        # 2. Queue encrypted bundles while disconnected
        for i in range(4):
            node_a.enqueue_bundle(
                recipient_id="FORWARD_PATROL",
                seq=i + 1,
                ciphertext_bytes=secrets.token_bytes(128),
                auth_tag=secrets.token_bytes(16),
            )

        assert len(node_a.outbound_store["FORWARD_PATROL"]) == 4  # nosec: B101

        # 3. Restore connectivity
        node_a.set_peer_connectivity("FORWARD_PATROL", True)
        node_b.set_peer_connectivity("HQ_STATION", True)

        # 4. Merkle delta reconciliation
        known_by_b = set(node_b.delivered_bundles.keys())
        delta = node_a.reconcile_with_peer("FORWARD_PATROL", remote_known_bundle_ids=known_by_b)
        assert len(delta) == 4  # nosec: B101

        for b in delta:
            accepted = node_b.receive_reconciled_bundle(b)
            assert accepted is True  # nosec: B101

        # 5. Subsequent reconciliation should yield 0 duplicates
        known_after = set(node_b.delivered_bundles.keys())
        delta_none = node_a.reconcile_with_peer("FORWARD_PATROL", remote_known_bundle_ids=known_after)
        assert len(delta_none) == 0  # nosec: B101

    def test_bundle_priority_preemption_and_rfc9172_compression(self):
        from tactical_mesh_ddil import BundlePriority, create_bpsec_bundle, decrypt_bpsec_bundle

        mesh = DDILNodeMesh("COMMAND_BASE")
        mesh.set_peer_connectivity("REMOTE_POST", True)

        # Queue 3 standard bundles
        for i in range(3):
            mesh.enqueue_bundle("REMOTE_POST", seq=i + 1, ciphertext_bytes=b"STD", auth_tag=b"TAG", priority=BundlePriority.STANDARD)

        # Queue 1 emergency flash bundle afterwards
        mesh.enqueue_bundle("REMOTE_POST", seq=999, ciphertext_bytes=b"FLASH", auth_tag=b"TAG", priority=BundlePriority.EMERGENCY)

        reconciled = mesh.reconcile_with_peer("REMOTE_POST", set())
        assert len(reconciled) == 4  # nosec: B101
        # First reconciled bundle MUST be EMERGENCY priority
        assert reconciled[0].priority == BundlePriority.EMERGENCY  # nosec: B101
        assert reconciled[0].seq == 999  # nosec: B101

        # Test RFC 9172 BPsec blocks and Key-ID compression
        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()
        sym_key = secrets.token_bytes(32)
        plaintext = b"TOP_SECRET_FLASH_ORDER_DATA_2028"

        bundle = create_bpsec_bundle(
            sender_id="COMMAND_BASE",
            recipient_id="REMOTE_POST",
            seq=101,
            payload_plaintext=plaintext,
            sender_sk=sk,
            sender_pk=pk,
            symmetric_key=sym_key,
            priority=BundlePriority.EMERGENCY,
            compress_key=True,
        )

        assert bundle.sender_pubkey is None  # nosec: B101
        assert bundle.sender_key_id is not None  # nosec: B101
        assert bundle.priority == BundlePriority.EMERGENCY  # nosec: B101

        sec_blocks = bundle.get_rfc9172_security_blocks()
        assert sec_blocks["rfc9172_bib"]["block_type"] == "BLOCK_INTEGRITY_BLOCK"  # nosec: B101
        assert sec_blocks["rfc9172_bcb"]["block_type"] == "BLOCK_CONFIDENTIALITY_BLOCK"  # nosec: B101

        decrypted = decrypt_bpsec_bundle(bundle, sym_key)
        assert decrypted == plaintext  # nosec: B101

    def test_teta_authority_decay_progression(self):
        engine = AuthorityDecayEngine()
        assert engine.get_current_authority_level() == TacticalAuthorityLevel.FULL_OPERATIONAL  # nosec: B101
        ok, msg = engine.can_execute_action("REKEY_NETWORK")
        assert ok is True  # nosec: B101

        # Simulate 2 hours offline -> DEGRADED_TACTICAL
        engine.set_simulated_elapsed_offline(7200.0)
        assert engine.get_current_authority_level() == TacticalAuthorityLevel.DEGRADED_TACTICAL  # nosec: B101
        ok, msg = engine.can_execute_action("FORWARD_DATA")
        assert ok is True  # nosec: B101
        ok, msg = engine.can_execute_action("REKEY_NETWORK")
        assert ok is False  # nosec: B101

        # Simulate 6 hours offline -> READ_ONLY_BEACON
        engine.set_simulated_elapsed_offline(21600.0)
        assert engine.get_current_authority_level() == TacticalAuthorityLevel.READ_ONLY_BEACON  # nosec: B101
        ok, msg = engine.can_execute_action("BEACON_TELEMETRY")
        assert ok is True  # nosec: B101
        ok, msg = engine.can_execute_action("SEND_COMMAND")
        assert ok is False  # nosec: B101

        # Simulate 15 hours offline -> QUARANTINED_DECAYED
        engine.set_simulated_elapsed_offline(54000.0)
        assert engine.get_current_authority_level() == TacticalAuthorityLevel.QUARANTINED_DECAYED  # nosec: B101
        ok, msg = engine.can_execute_action("SEND_COMMAND")
        assert ok is False  # nosec: B101
        # Emergency zeroization is always allowed even when decayed
        ok, msg = engine.can_execute_action("EMERGENCY_ZEROIZE")
        assert ok is True  # nosec: B101

        # Refresh attestation returns to FULL_OPERATIONAL
        engine.refresh_attestation()
        assert engine.get_current_authority_level() == TacticalAuthorityLevel.FULL_OPERATIONAL  # nosec: B101

    # NOTE: the no-XOR-fallback gate lives in
    # test_production_tier123_hardening.py
    # (test_ddil_bpsec_refuses_without_aesgcm), the suite whose header
    # contract promises Tier-1 XOR coverage -- kept in exactly one place.

    def test_teta_pre_mission_governance_envelopes(self):
        signer = LibOQS_MLDSA_87()
        kr = get_tactical_keyring()

        pk_cmd1, sk_cmd1 = signer.keygen()
        pk_cmd2, sk_cmd2 = signer.keygen()
        kr.register_peer_key("COMMANDER_1", pk_cmd1)
        kr.register_peer_key("COMMANDER_2", pk_cmd2)

        envelope = GovernanceEnvelope(
            envelope_id="TETA-ENV-001",
            authorized_action="REKEY_NETWORK",
            target_parameters={"target_epoch": "SPECIAL_FORCES_09"},
            valid_until_utc=time.time() + 86400.0,
            required_signatures=2,
        )

        # 1 signature is insufficient
        envelope.sign("COMMANDER_1", sk_cmd1, signer)
        assert envelope.verify(kr) is False  # nosec: B101

        # 2 signatures satisfies threshold
        envelope.sign("COMMANDER_2", sk_cmd2, signer)
        assert envelope.verify(kr) is True  # nosec: B101

        # Node mesh can execute authorized action via pre-mission envelope even in degraded state
        mesh = DDILNodeMesh("OUTPOST_01")
        assert mesh.load_governance_envelope(envelope) is True  # nosec: B101

        mesh.authority_decay.set_simulated_elapsed_offline(7200.0)  # DEGRADED_TACTICAL
        ok, msg = mesh.can_execute("REKEY_NETWORK")
        assert ok is True  # nosec: B101
        assert "Pre-Mission Governance Envelope" in msg  # nosec: B101


class TestEmergencyAntiTamperSuite:
    """Emergency Anti-Tamper & Scorched-Earth Zeroization Suite."""

    def test_memory_shredding_and_audit_generation(self, tmp_path):
        engine = EmergencyZeroizationEngine(audit_dir=tmp_path)

        secret_buffer = bytearray(b"SENSITIVE_MILITARY_TACTICAL_DATA_KEY_2028")
        engine.register_sensitive_buffer(secret_buffer)

        callback_invoked = False
        def mock_callback():
            nonlocal callback_invoked
            callback_invoked = True

        engine.register_cleanup_callback(mock_callback)

        # Execute emergency zeroization
        incident = engine.execute_scorched_earth_zeroization(
            trigger=AntiTamperTrigger.CHASSIS_INTRUSION_SENSOR,
            operator_id="TACTICAL_OFFICER_01",
            terminate_process=False,
        )

        assert engine.zeroized is True  # nosec: B101
        assert callback_invoked is True  # nosec: B101
        assert all(b == 0 for b in secret_buffer), "Buffer was not shredded!"  # nosec: B101

        audit_file = tmp_path / "emergency_zeroization_audit.json"
        sig_file = tmp_path / "emergency_zeroization_audit.json.mldsa87.sig"
        pub_file = tmp_path / "emergency_zeroization_audit.json.mldsa87.pub"

        assert audit_file.exists()  # nosec: B101
        assert sig_file.exists()  # nosec: B101
        assert pub_file.exists()  # nosec: B101

    def test_cold_boot_voltage_drop_trigger(self, tmp_path):
        engine = EmergencyZeroizationEngine(audit_dir=tmp_path)
        secret_ram = bytearray(b"CRYOGENIC_SPRAY_TEST_KEY_TOP_SECRET")
        engine.register_sensitive_buffer(secret_ram)

        incident = engine.execute_scorched_earth_zeroization(
            trigger=AntiTamperTrigger.COLD_BOOT_VOLTAGE_DROP,
            operator_id="WATCHDOG_SENSOR",
            terminate_process=False,
        )

        audit = incident["emergency_zeroization_audit"]
        assert audit["trigger_type"] == "COLD_BOOT_VOLTAGE_DROP"  # nosec: B101
        assert "NIST SP 800-88 Rev 2" in audit["standard"]  # nosec: B101
        assert audit["cold_boot_mitigation"] == "NON_PAGEABLE_LOCKED_MEMORY_PURGED"  # nosec: B101
        assert all(b == 0 for b in secret_ram)  # nosec: B101


class TestByzantineQuorumSuite:
    """Multi-Node Byzantine Fault Tolerant (BFT) Consensus Suite."""

    def test_byzantine_m_of_n_consensus(self, tmp_path):
        engine = ByzantineQuorumEngine(required_quorum_m=2, total_authorized_nodes_n=3)
        signer = LibOQS_MLDSA_87()

        keys = {}
        for name in ["NODE_1", "NODE_2", "NODE_3"]:
            pk, sk = signer.keygen()
            keys[name] = (pk, sk)
            engine.register_command_node(name, pk)

        # Test Rogue Injection (insufficient/unauthorized signers)
        rogue_pk, rogue_sk = signer.keygen()
        payload = {"quarantine": "SUSPICIOUS_NODE_X"}
        canonical_rogue = json.dumps(
            {"command": CriticalCommandType.NETWORK_WIDE_QUARANTINE, "proposer": "ROGUE", "target": payload},
            sort_keys=True,
        ).encode("utf-8")
        rogue_sig = signer.sign(rogue_sk, canonical_rogue)

        approved, msg, rec = engine.evaluate_proposal(
            command_type=CriticalCommandType.NETWORK_WIDE_QUARANTINE,
            target_payload=payload,
            proposed_by="ROGUE",
            signatures={"ROGUE": rogue_sig},
        )
        assert approved is False  # nosec: B101
        assert rec["quorum_satisfied"] is False  # nosec: B101

        # Test Valid 2-of-3 Quorum
        canonical_valid = json.dumps(
            {"command": CriticalCommandType.NETWORK_WIDE_QUARANTINE, "proposer": "NODE_1", "target": payload},
            sort_keys=True,
        ).encode("utf-8")
        sig_1 = signer.sign(keys["NODE_1"][1], canonical_valid)
        sig_2 = signer.sign(keys["NODE_2"][1], canonical_valid)

        approved, msg, rec = engine.evaluate_proposal(
            command_type=CriticalCommandType.NETWORK_WIDE_QUARANTINE,
            target_payload=payload,
            proposed_by="NODE_1",
            signatures={"NODE_1": sig_1, "NODE_2": sig_2},
        )
        assert approved is True  # nosec: B101
        assert rec["quorum_satisfied"] is True  # nosec: B101
        assert rec["valid_signatures_collected"] == 2  # nosec: B101

        # Export and verify receipt signature
        rep_p, sig_p, pub_p = sign_and_export_byzantine_receipt(rec, output_dir=tmp_path)
        assert verify_byzantine_receipt_signature(rep_p, sig_p, pub_p) is True  # nosec: B101

    def test_byzantine_anti_replay_and_expiration(self):
        engine = ByzantineQuorumEngine(required_quorum_m=2, total_authorized_nodes_n=3)
        signer = LibOQS_MLDSA_87()

        keys = {}
        for name in ["CMD_A", "CMD_B", "CMD_C"]:
            pk, sk = signer.keygen()
            keys[name] = (pk, sk)
            engine.register_command_node(name, pk)

        payload = {"revoke": "ROGUE_DRONE_07"}
        canonical = engine.build_canonical_payload(
            command_type=CriticalCommandType.REVOKE_NODE_CREDENTIAL,
            target_payload=payload,
            proposed_by="CMD_A",
            proposal_seq=42,
            epoch_id="TACTICAL_EPOCH_99",
        )

        sig_a = signer.sign(keys["CMD_A"][1], canonical)
        sig_b = signer.sign(keys["CMD_B"][1], canonical)

        # 1. First execution -> Approved
        approved, msg, rec = engine.evaluate_proposal(
            command_type=CriticalCommandType.REVOKE_NODE_CREDENTIAL,
            target_payload=payload,
            proposed_by="CMD_A",
            signatures={"CMD_A": sig_a, "CMD_B": sig_b},
            proposal_seq=42,
            epoch_id="TACTICAL_EPOCH_99",
        )
        assert approved is True  # nosec: B101

        # 2. Replay attempt -> Rejected fail-closed
        replayed, r_msg, r_rec = engine.evaluate_proposal(
            command_type=CriticalCommandType.REVOKE_NODE_CREDENTIAL,
            target_payload=payload,
            proposed_by="CMD_A",
            signatures={"CMD_A": sig_a, "CMD_B": sig_b},
            proposal_seq=42,
            epoch_id="TACTICAL_EPOCH_99",
        )
        assert replayed is False  # nosec: B101
        assert r_rec["status"] == "REPLAY_DETECTED_REJECTED"  # nosec: B101

        # 3. Expiration attempt -> Rejected fail-closed
        expired, e_msg, e_rec = engine.evaluate_proposal(
            command_type=CriticalCommandType.EMERGENCY_SILENCE,
            target_payload={"grid": "ALPHA"},
            proposed_by="CMD_A",
            signatures={"CMD_A": sig_a, "CMD_B": sig_b},
            valid_until_utc=100.0,
        )
        assert expired is False  # nosec: B101
        assert e_rec["status"] == "EXPIRED_REJECTED"  # nosec: B101


class TestTwinFileParityPhase5:
    """Twin Parity Validation: secure_p2p.py and secure_p2.py must match byte-for-byte."""

    def test_phase5_byte_for_byte_identity(self):
        p2p_path = Path("archive/legacy_prototype/secure_p2p.py")
        p2_path = Path("archive/legacy_prototype/secure_p2.py")
        if not p2p_path.exists() or not p2_path.exists():
            pytest.skip("legacy prototype twins not present in archive")
        p2p_bytes = p2p_path.read_bytes()
        p2_bytes = p2_path.read_bytes()

        assert p2p_bytes == p2_bytes, (  # nosec: B101
            f"Twin parity error! secure_p2p.py ({len(p2p_bytes)}B) != secure_p2.py ({len(p2_bytes)}B)"
        )


class TestPhase5MissionDrillAndChat:
    """End-to-end Master Phase 5 Operations Mission Drill & Chat Integration."""

    def test_phase5_operations_mission_drill_execution(self):
        from run_phase5_csrmc_operations_drill import Phase5OperationsMissionDrill, verify_phase5_drill_report

        drill = Phase5OperationsMissionDrill(drill_id="TEST-MISSION-DRILL-001")
        report = drill.run_full_drill()

        assert report["overall_status"] == "PASS"  # nosec: B101
        assert report["summary"]["total_probes"] == 5  # nosec: B101
        assert report["summary"]["probes_passed"] == 5  # nosec: B101
        assert report["summary"]["operational_verdict"] == "CSRMC_PHASE5_OPERATIONAL_AUTHORIZATION_ACTIVE"  # nosec: B101

        assert verify_phase5_drill_report() is True  # nosec: B101

    def test_interactive_chat_ddil_and_display_integration(self, capsys):
        import simple_chat_implementation
        from ui.display import DisplayManager

        # Test DDIL peer connectivity hooks
        mesh = simple_chat_implementation.get_ddil_node_mesh()
        mesh.set_peer_connectivity("TEST-REMOTE-PEER", True)
        assert mesh.is_peer_connected("TEST-REMOTE-PEER") is True  # nosec: B101

        mesh.set_peer_connectivity("TEST-REMOTE-PEER", False)
        assert mesh.is_peer_connected("TEST-REMOTE-PEER") is False  # nosec: B101

        # Test Section 8 in UI Display
        dm = DisplayManager(None)
        dm._display_csrmc_phase5_status()
        captured = capsys.readouterr().out
        assert "DoD Cybersecurity Risk Management Construct" in captured  # nosec: B101
        assert "CONTINUOUS_DATA_STREAMING" in captured  # nosec: B101
        assert "ZERO_FALLBACKS_PERMITTED" in captured  # nosec: B101


class TestCJADC2AlliedGateway:
    """CJADC2 Allied Coalition Gateway and Cross-Domain Redaction tests."""

    def test_allied_coalition_release_success(self):
        from cjadc2_allied_gateway import AlliedCoalitionGateway, CoalitionAlliance, SecurityViolationException

        gw = AlliedCoalitionGateway("USA-COALITION-NODE")
        payload = {
            "track_id": "TARGET-ALPHA",
            "coordinates": {"lat": 34.55, "lon": 45.12},
            "source_intel": "EYES ONLY // REL TO FVEY",
            "payload_data": "Unclassified radar telemetry"
        }

        packet = gw.prepare_outbound_transfer(
            recipient_country="GBR",
            alliance=CoalitionAlliance.FVEY,
            raw_payload=payload,
            classification_header="// SECRET // REL TO FVEY //",
            is_noforn=False
        )

        assert packet["release_status"] == "AUTHORIZED_COALITION_RELEASE"  # nosec: B101
        assert packet["recipient_country"] == "GBR"  # nosec: B101
        assert gw.verify_incoming_transfer(packet) is True  # nosec: B101

    def test_noforn_fail_closed_enforcement(self):
        import pytest
        from cjadc2_allied_gateway import AlliedCoalitionGateway, CoalitionAlliance, SecurityViolationException

        gw = AlliedCoalitionGateway("USA-COALITION-NODE")
        with pytest.raises(SecurityViolationException, match="COALITION TRANSFER REJECTED: Content marked NOFORN"):
            gw.prepare_outbound_transfer(
                recipient_country="AUS",
                alliance=CoalitionAlliance.FVEY,
                raw_payload={"secret_data": "classified_us_only"},  # nosec: B105
                classification_header="// TOP SECRET // NOFORN //",
                is_noforn=True
            )

    def test_coalition_membership_validation(self):
        import pytest
        from cjadc2_allied_gateway import AlliedCoalitionGateway, CoalitionAlliance, SecurityViolationException

        gw = AlliedCoalitionGateway("USA-COALITION-NODE")
        # JPN is not in NATO
        with pytest.raises(SecurityViolationException, match="not an authorized member of coalition"):
            gw.prepare_outbound_transfer(
                recipient_country="JPN",
                alliance=CoalitionAlliance.NATO,
                raw_payload={"radar": "123"},
                classification_header="// SECRET //",
                is_noforn=False
            )

    def test_gateway_report_generation_and_verification(self):
        from cjadc2_allied_gateway import generate_cjadc2_report, verify_cjadc2_report

        report_p, sig_p, pub_p = generate_cjadc2_report()
        assert report_p.exists()  # nosec: B101
        assert sig_p.exists()  # nosec: B101
        assert pub_p.exists()  # nosec: B101
        assert verify_cjadc2_report() is True  # nosec: B101



