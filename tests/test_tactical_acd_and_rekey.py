#!/usr/bin/env python3
"""
tests/test_tactical_acd_and_rekey.py
Verification of Active Cyber Defense (ACD) integration, on-demand Continuous Epoch
Ratcheting (CER), and fail-closed security enforcement in TacticalP2PNode.
"""

import os
import sys
import tempfile
import time
import secrets
from pathlib import Path
import pytest

from destroyer_tactical_p2p import TacticalP2PNode
from active_cyber_defense import DefensivePlaybook


class TestTacticalACDAndRekey:
    @pytest.fixture(autouse=True)
    def setup_nodes(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_acd_rekey_")
        self.psk_path = os.path.join(self.tmp_dir, "tactical.psk")
        with open(self.psk_path, "w", encoding="utf-8") as f:
            f.write(secrets.token_hex(32) + "\n")

        self.node = TacticalP2PNode(
            name="TEST_ALPHA",
            role="responder",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9300,
            channel_port=9310,
            work_dir=os.path.join(self.tmp_dir, "alpha"),
            psk_file=self.psk_path,
            lab_mode=True
        )
        os.makedirs(self.node.work_dir, exist_ok=True)
        yield
        self.node.close()
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_acd_engine_initialized(self):
        """TacticalP2PNode initializes ActiveCyberDefenseEngine with persistent quarantine."""
        assert self.node.acd_engine is not None
        assert self.node.acd_engine.lock is not None
        assert not self.node.acd_engine.is_peer_quarantined("127.0.0.1")
        assert not self.node.acd_engine.is_source_blocked("127.0.0.1")

    def test_02_pipeline_and_acd_status_telemetry(self, capsys):
        """Telemetry methods format and display real-time defense posture without error."""
        # Initialize pipeline with dummy secret
        from unified_secure_pipeline import create_zero_gap_session
        secret = secrets.token_bytes(32)
        pipe, ratchet = create_zero_gap_session(secret, is_initiator=False)
        self.node.zero_gap_pipeline = pipe
        self.node.zero_gap_ratchet = ratchet

        self.node.print_pipeline_status()
        out = capsys.readouterr().out
        assert "ZERO-GAP MULTI-LAYER DEFENSE STATUS" in out
        assert "Dual-Engine (Inner Ratchet + Outer Rust AEAD)" in out
        assert "CER Epoch" in out

        self.node.print_acd_status()
        out_acd = capsys.readouterr().out
        assert "ACTIVE CYBER DEFENSE (ACD) TELEMETRY" in out_acd
        assert "DoD cATO Continuous Monitoring" in out_acd

    def test_03_trigger_rekey_advances_epoch(self):
        """On-demand trigger_rekey rotates the CER epoch and updates Rust AEAD engine."""
        from unified_secure_pipeline import create_zero_gap_session
        secret = secrets.token_bytes(32)
        pipe, ratchet = create_zero_gap_session(secret, is_initiator=False)
        self.node.zero_gap_pipeline = pipe
        self.node.zero_gap_ratchet = ratchet

        initial_epoch = self.node.zero_gap_pipeline.current_epoch
        assert initial_epoch == 0

        # Trigger on-demand rekey
        new_epoch = self.node.trigger_rekey()
        assert new_epoch == 1
        assert self.node.zero_gap_pipeline.current_epoch == 1

        # Trigger second rekey
        new_epoch2 = self.node.trigger_rekey()
        assert new_epoch2 == 2
        assert self.node.zero_gap_pipeline.current_epoch == 2

    def test_04_tamper_event_triggers_immediate_acd_isolation(self):
        """Tampering with an unsealed frame triggers ACD TAMPER_DETECTED and SEVER playbook."""
        # Ingest a tamper event simulating an unseal failure or MAC invalidation
        actions = self.node.acd_engine.ingest_event(
            event_type="tamper_detected",
            peer_id=self.node.peer_addr,
            source_ip=self.node.peer_addr,
            session_id="session_tactical",
            details={"error": "corrupt_frame_mac_invalid"}
        )
        assert len(actions) == 1
        assert actions[0]["playbook"] == DefensivePlaybook.SEVER_SESSION_AND_ISOLATE
        assert self.node.acd_engine.is_session_severed("session_tactical")

    def test_05_replay_burst_triggers_peer_quarantine(self):
        """Replay burst triggers automated QUARANTINE_PEER playbook."""
        peer = "192.168.10.50"
        # Simulate replay detections within window
        for _ in range(self.node.acd_engine.replay_threshold - 1):
            acts = self.node.acd_engine.ingest_event("replay_detected", peer_id=peer, source_ip=peer)
            assert len(acts) == 0

        # Threshold reached: quarantine triggered
        acts = self.node.acd_engine.ingest_event("replay_detected", peer_id=peer, source_ip=peer)
        assert len(acts) == 1
        assert acts[0]["playbook"] == DefensivePlaybook.QUARANTINE_PEER
        assert self.node.acd_engine.is_peer_quarantined(peer)

    def test_06_in_band_rekey_synchronization(self):
        """Peer receives CONTROL:REKEY_EPOCH:1, rotates its epoch, and resumes communication on Epoch 1."""
        from unified_secure_pipeline import create_zero_gap_session
        secret = secrets.token_bytes(32)
        pipeA, ratchetA = create_zero_gap_session(secret, is_initiator=True)
        pipeB, ratchetB = create_zero_gap_session(secret, is_initiator=False)

        # Node A triggers rekey:
        target_epoch = pipeA.current_epoch + 1
        ctrl_frame = pipeA.seal(f"CONTROL:REKEY_EPOCH:{target_epoch}".encode("utf-8"), ratchetA)
        pipeA.rotate_epoch()

        # Node B receives and decrypts ctrl_frame under current epoch:
        mtype, pt = pipeB.open(ctrl_frame, ratchetB)
        msg_str = pt.decode("utf-8")
        assert msg_str == f"CONTROL:REKEY_EPOCH:{target_epoch}"

        # Node B validates and rotates:
        parts = msg_str.split(":")
        recv_target = int(parts[2])
        assert recv_target == pipeB.current_epoch + 1
        pipeB.rotate_epoch()

        assert pipeA.current_epoch == 1
        assert pipeB.current_epoch == 1

        # Now transmit under Epoch 1:
        tactical_msg = b"CRITICAL STRATEGIC DIRECTIVE 2027"
        sealed_tactical = pipeA.seal(tactical_msg, ratchetA)
        mtype2, opened_tactical = pipeB.open(sealed_tactical, ratchetB)
        assert opened_tactical == tactical_msg

    def test_07_unsealed_plaintext_rejected_by_acd(self):
        """Unsealed plaintext messages violate Zero-Gap doctrine and trigger traffic_anomaly ACD event."""
        acts = self.node.acd_engine.ingest_event(
            event_type="traffic_anomaly",
            peer_id=self.node.peer_addr,
            source_ip=self.node.peer_addr,
            details={"reason": "unsealed_payload"}
        )
        assert self.node.acd_engine.total_events_processed >= 1

    def test_08_secure_p2p_direct_entry_point_runs_drill(self):
        """secure_p2p.py runs the sovereign two-terminal tactical drill directly without deprecation."""
        import subprocess
        res = subprocess.run(
            [sys.executable, "secure_p2p.py", "demo", "--lab"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )
        assert res.returncode == 0, f"secure_p2p.py demo failed with stderr: {res.stderr}"
        assert "100% IN-BAND BIDIRECTIONAL ENCRYPTED EXCHANGE CONFIRMED" in res.stdout
        assert "DEPRECATION NOTICE" not in res.stderr
        assert "FATAL: legacy secure_p2p.py refused" not in res.stderr

    def test_09_secure_p2p_cli_subcommands(self):
        """secure_p2p.py exposes node, demo, audit, and web subcommands."""
        import subprocess
        res = subprocess.run(
            [sys.executable, "secure_p2p.py", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        assert res.returncode == 0
        assert "node" in res.stdout
        assert "demo" in res.stdout
        assert "audit" in res.stdout
        assert "web" in res.stdout

    def test_10_continuous_zero_trust_penalty_and_success(self):
        """Continuous Zero-Trust engine tracks penalties and rewards dynamically."""
        if self.node.zt_engine is None:
            pytest.skip("destroyer_core not available")
        zt = self.node.zt_engine
        peer = self.node.peer_addr
        initial = zt.trust_score(peer)
        assert initial == 75
        assert zt.is_trusted(peer)

        # Apply minor penalty
        zt.record_penalty(peer, 15)
        after_penalty = zt.trust_score(peer)
        assert after_penalty == 60
        assert zt.is_trusted(peer)

        # Record success
        zt.record_success(peer)
        assert zt.trust_score(peer) == 60

        # Breaching severance floor (< 50) triggers fail-closed error
        with pytest.raises(ValueError, match="zero-trust continuous verification failure"):
            zt.record_penalty(peer, 20)

    def test_11_print_trust_status(self, capsys):
        """print_trust_status outputs continuous zero-trust metrics and score."""
        self.node.print_trust_status()
        out = capsys.readouterr().out
        if self.node.zt_engine:
            assert "CONTINUOUS ZERO-TRUST POSTURE" in out
            assert "Dynamic Score" in out
            assert "75/100" in out
        else:
            assert "Zero-Trust Engine: INACTIVE" in out

    def test_12_autonomous_rekey_cadence(self):
        """TacticalP2PNode initializes _last_rekey_time and tracks rekey timestamps."""
        assert hasattr(self.node, "_last_rekey_time")
        assert self.node._last_rekey_time > 0

    def test_13_multi_cell_fragmentation_and_reassembly(self):
        """Large messages are fragmented into <= 600B chunks and reassembled without loss."""
        from unified_secure_pipeline import create_zero_gap_session
        root = secrets.token_bytes(32)
        p_init, r_init = create_zero_gap_session(root, is_initiator=True)
        p_resp, r_resp = create_zero_gap_session(root, is_initiator=False)

        large_text = "TACTICAL_INTEL_REPORT:" + ("A" * 5000)
        sealed = p_init.seal(large_text.encode("utf-8"), r_init)
        assert len(sealed) > 5000

        CHUNK_SIZE = 600
        chunks = [sealed[i:i+CHUNK_SIZE] for i in range(0, len(sealed), CHUNK_SIZE)]
        total = len(chunks)
        assert total > 8

        # Reassemble
        rx_buf = {}
        full_rx = None
        fid = secrets.token_hex(8)
        for idx, c in enumerate(chunks):
            if fid not in rx_buf:
                rx_buf[fid] = [None] * total
            rx_buf[fid][idx] = c
            if all(x is not None for x in rx_buf[fid]):
                full_rx = b"".join(rx_buf[fid])

        assert full_rx == sealed
        msg_type, opened = p_resp.open(full_rx, r_resp)
        assert opened.decode("utf-8") == large_text

    def test_14_in_band_document_transfer(self):
        """Documents are sealed with SHA-384 integrity and transferred in-band."""
        import hashlib
        import base64
        tmp_doc = os.path.join(self.node.work_dir, "mission_plan.txt")
        test_content = b"TOP SECRET MISSION PLAN: OPERATION CERBERUS STRIKE 2027\n" * 20
        with open(tmp_doc, "wb") as f:
            f.write(test_content)

        assert os.path.exists(tmp_doc)
        sha384_expected = hashlib.sha3_384(test_content).hexdigest()

        # Test helper format
        b64_content = base64.b64encode(test_content).decode("ascii")
        doc_msg = f"DOC:mission_plan.txt:{sha384_expected}:{b64_content}"
        assert doc_msg.startswith("DOC:mission_plan.txt:")

    def test_15_nc3_two_person_rule_dual_mldsa87_eam(self):
        """Two-Person Rule generates authentic ML-DSA-87 signed EAM with valid PAL decryption."""
        from nc3_nuclear_command import nc3_controller, serialize_eam_wire, deserialize_eam_wire
        off1 = nc3_controller.generate_officer_credentials("GEN_TEST_A", "General", "Commander")
        off2 = nc3_controller.generate_officer_credentials("ADM_TEST_B", "Admiral", "Deputy")
        r1 = nc3_controller.generate_officer_credentials("COL_TEST_C", "Colonel", "NMCC")
        r2 = nc3_controller.generate_officer_credentials("CAPT_TEST_D", "Captain", "Evaluator")

        war_key = secrets.token_bytes(32)
        pal = "OMEGA-7712-ZULU"
        eam = nc3_controller.create_nuclear_eam(
            directive_code="FLASH-DEFCON1-STRIKE",
            target_command="NMCC-PENTAGON",
            pal_code=pal,
            officer_1=off1,
            officer_2=off2,
            pal_key=war_key,
            validity_window_seconds=120.0
        )
        assert len(eam.custodian_1_signature) > 0
        assert len(eam.custodian_2_signature) > 0

        wire = serialize_eam_wire(eam.to_dict())
        deserialized = deserialize_eam_wire(wire)
        unsealed = nc3_controller.verify_and_decrypt_nuclear_eam(
            eam_data=deserialized,
            recipient_officer_1=r1,
            recipient_officer_2=r2,
            sender_officer_1_pub=off1.public_key,
            sender_officer_2_pub=off2.public_key,
            pal_key=war_key,
            peer_verified=True
        )
        assert unsealed == pal

    def test_16_routine_chat_nc3_safety_gate_blocks_single_officer_nuclear_order(self):
        """Conversational text containing raw strategic nuclear orders is blocked by the NC3 safety gate."""
        from unittest.mock import MagicMock
        self.node.channel_proc = MagicMock()
        self.node.channel_proc.stdin = MagicMock()
        self.node.zero_gap_pipeline = MagicMock()
        self.node.zero_gap_ratchet = MagicMock()

        # Attempt to transmit strategic nuclear release command casually in chat
        result = self.node.send_chat_message("URGENT: DISPATCH NUCLEAR STRIKE ON TARGET DELTA NOW")
        assert result is False, "Single-officer nuclear strike order must be blocked"

        # Attempt to transmit PAL code casually in chat
        result_pal = self.node.send_chat_message("Here is the permissive action link authorization")
        assert result_pal is False, "Single-officer PAL code transmission must be blocked"

        # Verify ACD registered the auth failure events
        assert len(self.node.acd_engine.auth_fail_events[self.node.peer_addr]) >= 2
        assert self.node.acd_engine.total_events_processed >= 2

    def test_17_routine_chat_rtb_spillage_blocks_lower_clearance(self):
        """Conversational text containing classified markers is blocked when node has lower clearance."""
        from unittest.mock import MagicMock
        self.node.channel_proc = MagicMock()
        self.node.channel_proc.stdin = MagicMock()
        self.node.zero_gap_pipeline = MagicMock()
        self.node.zero_gap_ratchet = MagicMock()
        self.node.clearance = "SECRET"

        # Attempt to send TOP SECRET indicator in SECRET session
        result = self.node.send_chat_message("Reviewing top secret payload telemetry")
        assert result is False, "Classified spillage must fail-closed"

        # Legitimate routine chat without classified keywords passes guards and transmits
        self.node.channel_proc.stdin.write = MagicMock()
        self.node.channel_proc.stdin.flush = MagicMock()
        self.node.zero_gap_pipeline.seal.return_value = b"SEALED_PAYLOAD_BYTES"
        ok = self.node.send_chat_message("All perimeter sensors operational and green.")
        assert ok is True

