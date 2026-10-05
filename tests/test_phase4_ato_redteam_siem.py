"""
test_phase4_ato_redteam_siem.py
Comprehensive Phase 4 Test Suite:
1. NIST OSCAL v1.1.0 System Security Plan (SSP) & SCTM Generation, Schema & ML-DSA-87 Signatures
2. Tamper-Evident Remote SIEM Forwarder with HMAC-SHA384 Cryptographic Chaining & Tail Anchoring
3. Automated Red-Team Adversarial Penetration Drill across 5 Threat Vectors
4. Tactical Network Cloaking Router (Direct Public Socket Prevention)
5. Programmatic Authorizing Official (AO) Decision Engine & Full ATO Verification
6. Twin File Parity Validation (secure_p2p.py == secure_p2.py)
"""

import json
import os
import secrets
from pathlib import Path
import pytest

from generate_oscal_ssp import (
    generate_oscal_ssp_data,
    sign_and_export_oscal_ssp,
    verify_oscal_ssp_signature,
)
from remote_siem_forwarder import (
    TamperEvidentAuditChain,
    verify_audit_log_chain,
    emit_siem_event,
)
from red_team_adversarial_drill import RedTeamDrillHarness
from tactical_cloaking_router import (
    tactical_cloak_enabled,
    validate_outbound_destination,
    TacticalCloakViolation,
)
from verify_ato_deployment_package import AODecisionEngine


class TestOscalSspAndSctm:
    """NIST OSCAL v1.1.0 System Security Plan (SSP) & SCTM Verification Suite."""

    def test_oscal_ssp_schema_and_nist_control_mappings(self):
        """Validate OSCAL v1.1.0 schema compliance and NIST SP 800-53 Rev 5 control coverage."""
        ssp = generate_oscal_ssp_data()
        assert "system-security-plan" in ssp  # nosec: B101
        plan = ssp["system-security-plan"]

        # Metadata validation
        metadata = plan["metadata"]
        assert metadata["oscal-version"] == "1.1.0"  # nosec: B101
        assert "roles" in metadata  # nosec: B101
        assert "parties" in metadata  # nosec: B101

        # Security categorization
        system_chars = plan["system-characteristics"]
        impact = system_chars["security-impact-level"]
        assert impact["security-objective-confidentiality"] == "fips-199-high"  # nosec: B101
        assert impact["security-objective-integrity"] == "fips-199-high"  # nosec: B101
        assert impact["security-objective-availability"] == "fips-199-high"  # nosec: B101

        # Control implementation mapping
        control_impl = plan["control-implementation"]
        implemented = control_impl["implemented-requirements"]
        assert len(implemented) >= 10  # nosec: B101

        control_ids = {item["control-id"].lower() for item in implemented}
        mandatory_controls = {
            "ac-3", "ac-4", "au-2", "au-9", "au-10",
            "ia-2", "ia-5", "sc-8", "sc-12", "sc-13", "si-4", "si-7"
        }
        missing = mandatory_controls - control_ids
        assert not missing, f"Missing mandatory NIST SP 800-53 controls: {missing}"  # nosec: B101

    def test_oscal_ssp_signing_and_tamper_detection(self, tmp_path):
        """Verify OSCAL SSP can be signed with ML-DSA-87 and tampered bytes trigger rejection."""
        ssp_path, sig_path, pub_path = sign_and_export_oscal_ssp(output_dir=tmp_path)
        assert ssp_path.exists()  # nosec: B101
        assert sig_path.exists()  # nosec: B101
        assert pub_path.exists()  # nosec: B101

        # Authentic signature verification
        assert verify_oscal_ssp_signature(ssp_path, sig_path, pub_path) is True  # nosec: B101

        # Tamper test
        raw = ssp_path.read_bytes()
        tampered = raw.replace(b"fips-199-high", b"fips-199-loww")
        ssp_path.write_bytes(tampered)

        assert verify_oscal_ssp_signature(ssp_path, sig_path, pub_path) is False  # nosec: B101


class TestTamperEvidentSiemForwarder:
    """Tamper-Evident SIEM Audit Chaining and Verification Suite."""

    def test_audit_chain_sequential_integrity(self, tmp_path):
        """Verify HMAC-SHA384 forward chaining under normal event streaming."""
        ledger = tmp_path / "test_audit.jsonl"
        anchor = tmp_path / "test_head.anchor.json"
        key = secrets.token_bytes(32)

        chain = TamperEvidentAuditChain(ledger_path=ledger, anchor_path=anchor, hmac_key=key)

        for i in range(10):
            chain.append_event(
                event_type="AUTH_TEST",
                severity="INFO",
                payload={"index": i, "data": secrets.token_hex(16)},
            )

        valid, count, msg = chain.verify_ledger()
        assert valid is True  # nosec: B101
        assert count == 10  # nosec: B101

    def test_audit_chain_tamper_detection_in_middle(self, tmp_path):
        """Ensure modifying a single character in an audit record invalidates subsequent chain."""
        ledger = tmp_path / "test_audit_tamper.jsonl"
        anchor = tmp_path / "test_head.anchor.json"
        key = secrets.token_bytes(32)

        chain = TamperEvidentAuditChain(ledger_path=ledger, anchor_path=anchor, hmac_key=key)

        for i in range(5):
            chain.append_event(
                event_type="AUTH_TRANSACTION",
                severity="LOW",
                payload={"account": f"user_{i}", "action": "LOGIN"},
            )

        # Tamper line 3
        lines = ledger.read_text(encoding="utf-8").splitlines()
        entry_3 = json.loads(lines[2])
        entry_3["payload"]["action"] = "ADMIN_ESCALATION"
        lines[2] = json.dumps(entry_3)
        ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, count, msg = chain.verify_ledger()
        assert valid is False  # nosec: B101
        assert "TAMPER DETECTED at line 3" in msg  # nosec: B101

    def test_audit_chain_deletion_detection(self, tmp_path):
        """Ensure deleting a record in the middle is detected as a sequence gap."""
        ledger = tmp_path / "test_audit_deletion.jsonl"
        anchor = tmp_path / "test_head.anchor.json"
        key = secrets.token_bytes(32)

        chain = TamperEvidentAuditChain(ledger_path=ledger, anchor_path=anchor, hmac_key=key)

        for i in range(5):
            chain.append_event(event_type="EVENT", severity="LOW", payload={"idx": i})

        # Remove line 3
        lines = ledger.read_text(encoding="utf-8").splitlines()
        del lines[2]
        ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, count, msg = chain.verify_ledger()
        assert valid is False  # nosec: B101
        assert "Sequence gap" in msg  # nosec: B101

    def test_audit_chain_head_anchoring(self, tmp_path):
        """Verify export_head_anchor records the correct head HMAC and sequence."""
        ledger = tmp_path / "test_anchor.jsonl"
        anchor = tmp_path / "head.anchor.json"
        key = secrets.token_bytes(32)

        chain = TamperEvidentAuditChain(ledger_path=ledger, anchor_path=anchor, hmac_key=key)
        chain.append_event("BOOT", "HIGH", {"status": "INITIALIZED"})
        head_data = chain.export_head_anchor()

        assert anchor.exists()  # nosec: B101
        assert head_data["seq"] == 1  # nosec: B101
        assert head_data["head_hmac"] == chain.last_hmac  # nosec: B101


class TestRedTeamAdversarialDrill:
    """Automated Red-Team Penetration Drill Verification Suite."""

    def test_red_team_full_drill_execution(self):
        """Execute all 5 red-team assault vectors and assert 100% defense."""
        harness = RedTeamDrillHarness(verbose=False)
        report = harness.run_full_drill()

        summary = report["summary"]
        assert summary["total_vectors"] == 5  # nosec: B101
        assert summary["failed"] == 0  # nosec: B101
        assert summary["passed"] == 5  # nosec: B101
        assert summary["all_passed"] is True  # nosec: B101
        assert report["metadata"]["overall_status"] == "DEFENDED"  # nosec: B101


class TestTacticalCloakingRouter:
    """Tactical Network Cloaking & Overlay Routing Suite."""

    def test_tactical_cloaking_blocking_public_destination(self, monkeypatch):
        """Ensure direct public socket destinations are rejected under tactical cloak."""
        monkeypatch.setenv("P2P_TACTICAL_CLOAK", "1")
        monkeypatch.setenv("P2P_OVERLAY_ACTIVE", "0")

        assert tactical_cloak_enabled() is True  # nosec: B101

        # Loopback / Private allowed
        assert validate_outbound_destination("127.0.0.1", 50007) is True  # nosec: B101
        assert validate_outbound_destination("10.1.2.3", 50007) is True  # nosec: B101

        # Public IP blocked
        with pytest.raises(TacticalCloakViolation):
            validate_outbound_destination("8.8.8.8", 50007)

    def test_tactical_cloaking_overlay_allowed(self, monkeypatch):
        """Ensure destinations with active overlay or disabled cloak are permitted."""
        monkeypatch.setenv("P2P_TACTICAL_CLOAK", "1")
        monkeypatch.setenv("P2P_OVERLAY_ACTIVE", "1")

        # Public destination permitted when encapsulated through tactical overlay
        assert validate_outbound_destination("8.8.8.8", 50007) is True  # nosec: B101


class TestConopsAndKeyManagementPlan:
    """Concept of Operations (CONOPS) & Key Management Plan (KMP) Suite."""

    def test_conops_schema_and_operational_environments(self):
        conops_file = Path("compliance_reports/conops_operational_profile.json")
        assert conops_file.exists()  # nosec: B101
        with open(conops_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["conops_metadata"]["classification"] == (  # nosec: B101
            "UNCLASSIFIED (self-marked work product; no distribution "
            "limitation asserted by any authority; FOUO retired 2019 -- not used)"
        )
        envs = {e["env_id"]: e for e in data["operational_environments"]}
        assert "ENV-AIRGAP" in envs  # nosec: B101
        assert "ENV-EDGE" in envs  # nosec: B101
        assert "ENV-DDIL" in envs  # nosec: B101
        modes = data["operational_modes"]
        assert "tactical_cloak_mode" in modes  # nosec: B101
        assert "emergency_zeroize_mode" in modes  # nosec: B101

    def test_key_management_plan_sp800_57_cnsa2(self):
        kmp_file = Path("compliance_reports/key_management_plan.json")
        assert kmp_file.exists()  # nosec: B101
        with open(kmp_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        standards = data["kmp_metadata"]["standards_compliance"]
        assert any("NIST SP 800-57" in s for s in standards)  # nosec: B101
        assert any("CNSA 2.0" in s for s in standards)  # nosec: B101
        keys = {k["key_type"]: k for k in data["key_inventory"]}
        assert "ROOT_IDENTITY_SIGNATURE" in keys  # nosec: B101
        assert "EPHEMERAL_SESSION_KEM" in keys  # nosec: B101
        assert "DOUBLE_RATCHET_MESSAGE_KEY" in keys  # nosec: B101
        assert keys["DOUBLE_RATCHET_MESSAGE_KEY"]["cryptoperiod_frames"] == 1  # nosec: B101


class TestCanaryPilotSuite:
    """Canary Pilot Deployment & NIST SP 800-137 Continuous Telemetry Suite."""

    def test_canary_pilot_telemetry_execution(self):
        from deploy_canary_pilot import CanaryPilotDeployer
        deployer = CanaryPilotDeployer()
        telemetry = deployer.run_pilot_evaluation()

        assert telemetry["overall_status"] == "OPERATIONAL"  # nosec: B101
        summary = telemetry["summary"]
        assert summary["total_probes"] == 5  # nosec: B101
        assert summary["probes_passed"] == 5  # nosec: B101
        assert summary["all_probes_passed"] is True  # nosec: B101

        probe_ids = [p["probe_id"] for p in telemetry["probes"]]
        assert "ISCM-P1" in probe_ids  # nosec: B101
        assert "ISCM-P2" in probe_ids  # nosec: B101
        assert "ISCM-P3" in probe_ids  # nosec: B101
        assert "ISCM-P4" in probe_ids  # nosec: B101
        assert "ISCM-P5" in probe_ids  # nosec: B101


class TestActiveCyberDefenseSuite:
    """DoD cATO Pillar 2: Active Cyber Defense (ACD) Autonomous Response Suite."""

    def test_acd_playbook_execution_and_thresholds(self, tmp_path):
        from active_cyber_defense import ActiveCyberDefenseEngine, DefensivePlaybook

        q_file = tmp_path / "test_acd_q.json"
        engine = ActiveCyberDefenseEngine(
            replay_threshold=3,
            replay_window_sec=5.0,
            auth_fail_threshold=3,
            auth_fail_window_sec=5.0,
            quarantine_duration_sec=30.0,
            quarantine_file=q_file,
        )

        # Replay flood trigger test
        for _ in range(2):
            res = engine.ingest_event("replay_rejection", peer_id="peer_gamma")
            assert len(res) == 0  # nosec: B101
        res = engine.ingest_event("replay_rejection", peer_id="peer_gamma")
        assert len(res) == 1  # nosec: B101
        assert res[0]["playbook"] == DefensivePlaybook.QUARANTINE_PEER  # nosec: B101
        assert engine.is_peer_quarantined("peer_gamma") is True  # nosec: B101

        # Tamper trigger test
        res = engine.ingest_event("corrupt_frame_mac_invalid", peer_id="peer_delta", session_id="sess_test_1")
        assert len(res) == 1  # nosec: B101
        assert res[0]["playbook"] == DefensivePlaybook.SEVER_SESSION_AND_ISOLATE  # nosec: B101
        assert engine.is_session_severed("sess_test_1") is True  # nosec: B101

        # Auth fail flood test
        for _ in range(2):
            res = engine.ingest_event("cert_reject", source_ip="203.0.113.50")
            assert len(res) == 0  # nosec: B101
        res = engine.ingest_event("cert_reject", source_ip="203.0.113.50")
        assert len(res) == 1  # nosec: B101
        assert res[0]["playbook"] == DefensivePlaybook.BLOCK_SOURCE_AND_REKEY  # nosec: B101
        assert engine.is_source_blocked("203.0.113.50") is True  # nosec: B101

    def test_acd_report_signing_and_verification(self, tmp_path):
        from active_cyber_defense import (
            ActiveCyberDefenseEngine,
            sign_and_export_acd_report,
            verify_acd_report_signature,
        )

        engine = ActiveCyberDefenseEngine(quarantine_file=tmp_path / "q.json")
        rep_p, sig_p, pub_p = sign_and_export_acd_report(engine, output_dir=tmp_path)

        assert rep_p.exists() and sig_p.exists() and pub_p.exists()  # nosec: B101
        assert verify_acd_report_signature(rep_p, sig_p, pub_p) is True  # nosec: B101

        # Tamper detection
        raw = rep_p.read_bytes()
        tampered = raw.replace(b"OPERATIONAL", b"COMPROMISED")
        rep_p.write_bytes(tampered)
        assert verify_acd_report_signature(rep_p, sig_p, pub_p) is False  # nosec: B101


class TestDoDZeroTrustSuite:
    """DoD Zero Trust Architecture (ZTA 2.0) 2027 Target Level Evaluation Suite."""

    def test_zero_trust_7_pillar_scoring(self):
        from zero_trust_assessment import DoDZeroTrustEvaluator

        evaluator = DoDZeroTrustEvaluator()
        assessment = evaluator.perform_full_assessment()["dod_zero_trust_assessment"]

        assert assessment["overall_score_percentage"] >= 95.0  # nosec: B101
        assert assessment["target_level_achieved"] is True  # nosec: B101
        assert assessment["status"] == "TARGET_LEVEL_ACHIEVED"  # nosec: B101

        pillars = assessment["pillars"]
        assert len(pillars) == 7  # nosec: B101
        for p in pillars:
            assert p["score_percentage"] >= 90.0  # nosec: B101
            assert p["status"] == "COMPLIANT"  # nosec: B101

    def test_zero_trust_report_signing_and_verification(self, tmp_path):
        from zero_trust_assessment import (
            sign_and_export_zero_trust_assessment,
            verify_zero_trust_assessment_signature,
        )

        r_path, s_path, p_path = sign_and_export_zero_trust_assessment(output_dir=tmp_path)
        assert r_path.exists() and s_path.exists() and p_path.exists()  # nosec: B101
        assert verify_zero_trust_assessment_signature(r_path, s_path, p_path) is True  # nosec: B101


class TestOscalSarSuite:
    """NIST OSCAL v1.1.0 SAR & POA&M Verification Suite."""

    def test_oscal_sar_schema_and_findings(self):
        from generate_oscal_sar import generate_oscal_sar_data

        sar = generate_oscal_sar_data()
        assert "assessment-results" in sar  # nosec: B101
        results = sar["assessment-results"]
        assert results["metadata"]["oscal-version"] == "1.1.0"  # nosec: B101

        poam = results["plan-of-action-and-milestones"]
        assert poam["open-critical-vulnerabilities"] == 0  # nosec: B101
        assert poam["open-high-vulnerabilities"] == 0  # nosec: B101
        assert len(poam["poam-items"]) >= 2  # nosec: B101

    def test_oscal_sar_signing_and_verification(self, tmp_path):
        from generate_oscal_sar import (
            sign_and_export_oscal_sar,
            verify_oscal_sar_signature,
        )

        r_path, s_path, p_path = sign_and_export_oscal_sar(output_dir=tmp_path)
        assert r_path.exists() and s_path.exists() and p_path.exists()  # nosec: B101
        assert verify_oscal_sar_signature(r_path, s_path, p_path) is True  # nosec: B101


class TestAoDecisionEngineAndAto:
    """Self-assessment evidence pack suite (NOT an Authorizing Official).

    Asserts the pack assembles with all 10 evidence gates passing and that
    its decision record is explicitly self-assessment (never GRANTED).
    """

    def test_ao_evaluation_and_evidence_pack_complete(self):
        """Evaluate all 10 gates and assert the evidence pack is complete."""
        engine = AODecisionEngine(verbose=False)
        decision = engine.evaluate_all_and_package_evidence()

        assert decision["assessment_kind"].startswith("SELF-ASSESSMENT")  # nosec: B101
        summary = decision["evaluation_summary"]
        assert summary["total_gates"] == 10  # nosec: B101
        assert summary["passed_gates"] == 10  # nosec: B101
        assert summary["all_gates_passed"] is True  # nosec: B101

        auth = decision["authorization_decision"]
        assert auth["status"] == "SELF-ASSESS-PASS"  # nosec: B101
        assert auth["authorization_type"] == "SELF-ASSESSMENT EVIDENCE PACK FOR AO REVIEW"  # nosec: B101
        assert "GRANTED" not in auth["status"]  # nosec: B101
        assert auth["valid_through_utc"] is None  # nosec: B101


class TestTwinFileParityPhase4:
    """Twin Parity Validation: secure_p2p.py and secure_p2.py must match byte-for-byte."""

    def test_phase4_byte_for_byte_identity(self):
        path_p2p = Path("archive/legacy_prototype/secure_p2p.py")
        path_p2 = Path("archive/legacy_prototype/secure_p2.py")

        if not path_p2p.exists() or not path_p2.exists():
            pytest.skip("legacy prototype twins not present in archive")

        p2p_bytes = path_p2p.read_bytes()
        p2_bytes = path_p2.read_bytes()

        assert p2p_bytes == p2_bytes, (  # nosec: B101
            f"Twin parity error! secure_p2p.py ({len(p2p_bytes)}B) != secure_p2.py ({len(p2_bytes)}B)"
        )

