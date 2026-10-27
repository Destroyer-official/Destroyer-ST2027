#!/usr/bin/env python3
"""
test_production_tier4_cjadc2_and_consensus.py

Comprehensive test suite verifying Tier 4 Strategic Defense & BFT Quorum Consensus:
- DoD cATO Pillar 2: Active Cyber Defense Ingress Gate & Event Ingestion in SessionManager
- Cryptographic Tamper Alerting & Immediate Session Isolation
- Multi-Node Byzantine Fault Tolerant (BFT) Quorum Actuator Execution:
  * NETWORK_WIDE_QUARANTINE
  * TACTICAL_REKEY_ALL
  * REVOKE_NODE_CREDENTIAL
  * EMERGENCY_SILENCE
- Secure File Sharing Chunk Size & Staged Memory Bounds
- Secure Key Manager Production Mode Plaintext Key Rejection
- CJADC2 Allied Tactical Gateway Content Disarm & Reconstruction (CDR) and NOFORN Guard
"""

import asyncio
import datetime
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Ensure repository root is in python path
REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__file__).resolve().parent.parent
import sys
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from active_cyber_defense import (
    ActiveCyberDefenseEngine,
    DefensivePlaybook,
    get_active_cyber_defense_engine,
)
from byzantine_mesh_consensus import (
    ByzantineQuorumEngine,
    CriticalCommandType,
)
from cjadc2_allied_gateway import (
    AlliedCoalitionGateway,
    CoalitionAlliance,
    CoalitionRedactionError,
)
from cjadc2_cross_domain_guard import SecurityClassification
from liboqs_wrapper import LibOQS_MLDSA_87
from network.session_manager import SessionContext, SessionManager, SecurityError
from secure_file_sharing import FileChunk, FileMetadata, SecureFileTransferManager
from secure_key_manager import SecureKeyManager, SecurityPolicyViolationError
import ui.safety_numbers as safety_numbers


class TestProductionTier4AndConsensus(unittest.TestCase):
    """Test suite validating Tier 4 Strategic Defense, BFT Consensus, and Audit Fixes."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="tier4_test_")
        self.acd = get_active_cyber_defense_engine()
        # Reset ACD state for clean test run
        with self.acd.lock:
            self.acd.quarantined_peers.clear()
            self.acd.blocked_sources.clear()
            self.acd.severed_sessions.clear()
            self.acd.executed_playbooks.clear()
            self.acd.replay_events.clear()
            self.acd.auth_fail_events.clear()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        os.environ.pop("P2P_PRODUCTION", None)
        os.environ.pop("SECURE_P2P_PRODUCTION", None)
        os.environ.pop("P2P_FAIL_ON_SOFTWARE_FALLBACK", None)
        os.environ.pop("P2P_TACTICAL_CLOAK", None)
        os.environ.pop("P2P_ALLOW_LEGACY_KEY_MIGRATION", None)

    def test_session_manager_acd_quarantine_ingress_gate(self):
        """Verify that quarantined peers and blocked source IPs are rejected fail-closed at ingress."""
        async def _run():
            sm = SessionManager()
            bad_peer = "adversary_recon_node_99"
            self.acd._execute_quarantine(bad_peer, reason="Test quarantine")

            # 1. create_session should reject quarantined peer fail-closed
            dummy_reader = asyncio.StreamReader()
            class DummyWriter:
                def is_closing(self): return False
                def close(self): pass
                def get_extra_info(self, name): return ("10.0.0.50", 12345)

            with self.assertRaises(SecurityError) as ctx:
                await sm.create_session(bad_peer, dummy_reader, DummyWriter())
            self.assertIn("quarantined", str(ctx.exception).lower())

            # 2. _perform_handshake should reject quarantined peer
            from hybrid_kex import HybridKeyExchange
            kex = HybridKeyExchange(identity="local_node", ephemeral=True, in_memory_only=True)
            with self.assertRaises(SecurityError) as ctx2:
                await sm._perform_handshake(kex, bad_peer, dummy_reader, DummyWriter(), is_initiator=True)
            self.assertIn("quarantined", str(ctx2.exception).lower())

            # 3. Source IP block check
            blocked_ip = "203.0.113.88"
            self.acd._execute_block_and_rekey(blocked_ip, reason="Test IP block")
            class BlockedWriter:
                def is_closing(self): return False
                def close(self): pass
                def get_extra_info(self, name): return (blocked_ip, 54321)

            with self.assertRaises(SecurityError) as ctx3:
                await sm._perform_handshake(kex, "new_peer_unquarantined", dummy_reader, BlockedWriter(), is_initiator=True)
            self.assertIn("blocked", str(ctx3.exception).lower())

        asyncio.run(_run())

    def test_session_manager_tamper_sever_and_isolate(self):
        """Verify that handle_tamper_detected triggers SEVER_SESSION_AND_ISOLATE and terminates session."""
        async def _run():
            sm = SessionManager()
            dummy_reader = asyncio.StreamReader()
            class DummyWriter:
                def is_closing(self): return False
                def close(self): pass
                def get_extra_info(self, name): return None

            peer_id = "test_tampered_peer_12"
            session = SessionContext(
                peer_id=peer_id,
                reader=dummy_reader,
                writer=DummyWriter(),
                session_id="session_tamper_uuid_101",
            )
            sm.sessions[peer_id] = session

            # Verify initial health
            self.assertTrue(session.is_healthy())

            # Trigger tamper detection
            await sm.handle_tamper_detected(peer_id, session_id="session_tamper_uuid_101", details={"mac_failed": True})

            # Peer must be removed from active sessions
            self.assertNotIn(peer_id, sm.sessions)

            # Session must be marked severed in ACD
            self.assertTrue(self.acd.is_session_severed("session_tamper_uuid_101"))
            self.assertTrue(self.acd.is_peer_quarantined(peer_id))

            # Session is_healthy must now evaluate to False
            self.assertFalse(session.is_healthy())

        asyncio.run(_run())

    def test_byzantine_consensus_actuator_approved(self):
        """Verify that ByzantineQuorumEngine.execute_approved_command autonomously executes strategic actions."""
        engine = ByzantineQuorumEngine(required_quorum_m=2, total_authorized_nodes_n=3)
        signer = LibOQS_MLDSA_87()

        # Register 2 authorized commanders
        pk_alpha, sk_alpha = signer.keygen()
        pk_bravo, sk_bravo = signer.keygen()
        engine.register_command_node("CMD_ALPHA", pk_alpha)
        engine.register_command_node("CMD_BRAVO", pk_bravo)

        # 1. NETWORK_WIDE_QUARANTINE
        target_q = {"peer_id": "ROGUE_TACTICAL_NODE_77"}
        canonical_q = engine.build_canonical_payload(
            command_type=CriticalCommandType.NETWORK_WIDE_QUARANTINE,
            target_payload=target_q,
            proposed_by="CMD_ALPHA",
            proposal_seq=1,
            epoch_id="EPOCH_2026_09",
        )
        sigs_q = {
            "CMD_ALPHA": signer.sign(sk_alpha, canonical_q),
            "CMD_BRAVO": signer.sign(sk_bravo, canonical_q),
        }
        ok, msg, record_q = engine.evaluate_proposal(
            command_type=CriticalCommandType.NETWORK_WIDE_QUARANTINE,
            target_payload=target_q,
            proposed_by="CMD_ALPHA",
            signatures=sigs_q,
            proposal_seq=1,
            epoch_id="EPOCH_2026_09",
        )
        self.assertTrue(ok)
        self.assertTrue(engine.execute_approved_command(record_q))
        self.assertTrue(self.acd.is_peer_quarantined("ROGUE_TACTICAL_NODE_77"))

        # 2. REVOKE_NODE_CREDENTIAL
        # Store a safety number pin first
        target_peer = "COMPROMISED_STATION_42"
        safety_numbers.store_pin(target_peer, "0123456789abcdef" * 8)
        self.assertEqual(safety_numbers.check_pin(target_peer, "0123456789abcdef" * 8), "match")

        target_r = {"revoke_node": target_peer}
        canonical_r = engine.build_canonical_payload(
            command_type=CriticalCommandType.REVOKE_NODE_CREDENTIAL,
            target_payload=target_r,
            proposed_by="CMD_ALPHA",
            proposal_seq=2,
            epoch_id="EPOCH_2026_09",
        )
        sigs_r = {
            "CMD_ALPHA": signer.sign(sk_alpha, canonical_r),
            "CMD_BRAVO": signer.sign(sk_bravo, canonical_r),
        }
        ok, msg, record_r = engine.evaluate_proposal(
            command_type=CriticalCommandType.REVOKE_NODE_CREDENTIAL,
            target_payload=target_r,
            proposed_by="CMD_ALPHA",
            signatures=sigs_r,
            proposal_seq=2,
            epoch_id="EPOCH_2026_09",
        )
        self.assertTrue(ok)
        self.assertTrue(engine.execute_approved_command(record_r))
        # Pin must be revoked (now 'new' because entry deleted)
        self.assertEqual(safety_numbers.check_pin(target_peer, "0123456789abcdef" * 8), "new")
        self.assertTrue(self.acd.is_peer_quarantined(target_peer))

        # 3. EMERGENCY_SILENCE
        target_s = {"mode": "FULL_RADIO_SILENCE"}
        canonical_s = engine.build_canonical_payload(
            command_type=CriticalCommandType.EMERGENCY_SILENCE,
            target_payload=target_s,
            proposed_by="CMD_ALPHA",
            proposal_seq=3,
            epoch_id="EPOCH_2026_09",
        )
        sigs_s = {
            "CMD_ALPHA": signer.sign(sk_alpha, canonical_s),
            "CMD_BRAVO": signer.sign(sk_bravo, canonical_s),
        }
        ok, msg, record_s = engine.evaluate_proposal(
            command_type=CriticalCommandType.EMERGENCY_SILENCE,
            target_payload=target_s,
            proposed_by="CMD_ALPHA",
            signatures=sigs_s,
            proposal_seq=3,
            epoch_id="EPOCH_2026_09",
        )
        self.assertTrue(ok)
        self.assertTrue(engine.execute_approved_command(record_s))
        self.assertEqual(os.environ.get("P2P_TACTICAL_CLOAK"), "1")

        # 4. TACTICAL_REKEY_ALL
        target_k = {"scope": "GLOBAL_FORWARD_SECRECY"}
        canonical_k = engine.build_canonical_payload(
            command_type=CriticalCommandType.TACTICAL_REKEY_ALL,
            target_payload=target_k,
            proposed_by="CMD_ALPHA",
            proposal_seq=4,
            epoch_id="EPOCH_2026_09",
        )
        sigs_k = {
            "CMD_ALPHA": signer.sign(sk_alpha, canonical_k),
            "CMD_BRAVO": signer.sign(sk_bravo, canonical_k),
        }
        ok, msg, record_k = engine.evaluate_proposal(
            command_type=CriticalCommandType.TACTICAL_REKEY_ALL,
            target_payload=target_k,
            proposed_by="CMD_ALPHA",
            signatures=sigs_k,
            proposal_seq=4,
            epoch_id="EPOCH_2026_09",
        )
        self.assertTrue(ok)
        self.assertTrue(engine.execute_approved_command(record_k))

    def test_byzantine_consensus_actuator_rejected_fail_closed(self):
        """Verify that execute_approved_command rejects unapproved or deficit records fail-closed."""
        engine = ByzantineQuorumEngine(required_quorum_m=2, total_authorized_nodes_n=3)
        fake_record = {
            "command_type": CriticalCommandType.NETWORK_WIDE_QUARANTINE,
            "target_payload": {"peer_id": "INNOCENT_NODE"},
            "status": "QUORUM_DEFICIT_REJECTED",
            "quorum_satisfied": False,
        }
        # Refuses execution fail-closed
        self.assertFalse(engine.execute_approved_command(fake_record))
        self.assertFalse(self.acd.is_peer_quarantined("INNOCENT_NODE"))

    def test_secure_file_sharing_chunk_bounds(self):
        """Verify store_file_chunk strictly bounds chunk size and staged memory bytes."""
        mgr = SecureFileTransferManager(temp_storage_dir=Path(self.tmpdir) / "file_sharing")
        file_id = "a" * 32
        chunk_size = 8 * 1024  # 8KB
        file_size = 16 * 1024  # 16KB total (2 chunks)
        metadata = FileMetadata(
            file_id=file_id,
            filename="recon_report.bin",
            file_size=file_size,
            file_type="application/octet-stream",
            checksum="0" * 64,
            chunk_size=chunk_size,
            total_chunks=2,
            created_at=datetime.datetime.now(),
            sender_id="sender_station_01",
        )
        mgr.active_downloads[file_id] = {
            "output_path": str(Path(self.tmpdir) / "recon_report.bin"),
            "expected_metadata": metadata,
            "status": "initialized",
            "created_at": datetime.datetime.now(),
            "received_chunks": {},
            "chunks_received": 0,
            "staged_bytes": 0,
            "auth_key": b"0" * 32,
        }

        # 1. Chunk exceeding declared chunk_size must be rejected fail-closed
        oversized_data = b"X" * (chunk_size + 1024)
        c_tag = FileChunk.compute_chunk_tag(
            b"0" * 32, file_id, 0, False,
            hashlib.sha3_256(oversized_data).hexdigest(), oversized_data
        )
        bad_chunk = FileChunk(
            file_id=file_id,
            chunk_number=0,
            chunk_data=oversized_data,
            chunk_checksum=hashlib.sha3_256(oversized_data).hexdigest(),
            is_final=False,
            auth_tag=c_tag,
        )
        ok, err = asyncio.run(mgr.store_file_chunk(file_id, bad_chunk))
        self.assertFalse(ok)
        self.assertIn("exceeds expected chunk size", err)

        # 2. Cumulative staged bytes exceeding file_size + chunk_size limit must be rejected
        mgr.active_downloads[file_id]["staged_bytes"] = file_size + chunk_size
        legit_data = b"Y" * 1024
        l_tag = FileChunk.compute_chunk_tag(
            b"0" * 32, file_id, 0, False,
            hashlib.sha3_256(legit_data).hexdigest(), legit_data
        )
        flood_chunk = FileChunk(
            file_id=file_id,
            chunk_number=0,
            chunk_data=legit_data,
            chunk_checksum=hashlib.sha3_256(legit_data).hexdigest(),
            is_final=False,
            auth_tag=l_tag,
        )
        ok2, err2 = asyncio.run(mgr.store_file_chunk(file_id, flood_chunk))
        self.assertFalse(ok2)
        self.assertIn("Cumulative staged bytes exceed file size limit", err2)

    def test_secure_key_manager_production_plaintext_rejection(self):
        """Verify that SecureKeyManager rejects unencrypted legacy keys with SecurityPolicyViolationError in production."""
        os.environ["P2P_PRODUCTION"] = "1"
        km = SecureKeyManager(secure_dir=self.tmpdir)
        legacy_key_file = Path(self.tmpdir) / "legacy_secret_key.key"
        # Write unencrypted plaintext key
        legacy_key_file.write_bytes(b"SUPER_SECRET_PLAINTEXT_KEY_MATERIAL")

        with self.assertRaises(SecurityPolicyViolationError) as ctx:
            km.retrieve_key("legacy_secret_key")
        self.assertIn("Unencrypted legacy key", str(ctx.exception))
        self.assertIn("production mode", str(ctx.exception))

    def test_cjadc2_allied_gateway_cdr_and_noforn(self):
        """Verify Content Disarm & Reconstruction and NOFORN redaction in AlliedCoalitionGateway."""
        gw = AlliedCoalitionGateway()

        # 1. Partner clearance verification
        self.assertTrue(gw.is_partner_cleared("GBR", CoalitionAlliance.FVEY))
        self.assertTrue(gw.is_partner_cleared("AUS", CoalitionAlliance.AUKUS))
        self.assertFalse(gw.is_partner_cleared("RUS", CoalitionAlliance.NATO))

        # 2. Content Disarm & Reconstruction (strips scripts and macros)
        dirty_payload = json.dumps({
            "target": "COORDINATE_GRID_32",
            "metadata": "<script>alert('xss');</script>javascript:eval(dangerous_code)",
            "classification": "SECRET",
        }).encode("utf-8")
        clean_payload, hostile = gw.execute_content_disarm_and_reconstruction(dirty_payload)
        self.assertTrue(hostile)  # active hostile content was actually stripped
        self.assertNotIn(b"<script>", clean_payload)
        self.assertNotIn(b"javascript:", clean_payload)

        # 3. NOFORN Hard Block: Releasing NOFORN to foreign partner raises CoalitionRedactionError
        with self.assertRaises(CoalitionRedactionError):
            gw.redact_and_package_for_coalition(
                payload_bytes=b"High value target tracking",
                source_classification=SecurityClassification.SECRET,
                target_alliance=CoalitionAlliance.FVEY,
                target_partner_nation="GBR",
                active_caveats={"NOFORN", "HCS-P"},
            )

        # 4. Valid Coalition Release with ML-DSA-87 token
        package = gw.redact_and_package_for_coalition(
            payload_bytes=b"Allied sector perimeter clear with HCS-P intelligence",
            source_classification=SecurityClassification.SECRET,
            target_alliance=CoalitionAlliance.FVEY,
            target_partner_nation="GBR",
            active_caveats={"HCS-P"},
        )
        self.assertEqual(package.get("status"), "AUTHORIZED_COALITION_RELEASE")
        self.assertTrue(gw.verify_coalition_release(package))


class TestByzantineTier4V1(unittest.TestCase):
    """Tier-4 v1 BFT hardening (research basis: HotStuff-2 QC shape,
    n>=3f+1 quorum theory, 2024-26 accountability literature).

    - T4-A: insecure quorum shapes fail fast; roster can never exceed N.
    - T4-C: double-signing the same (epoch, seq) refuses the proposal,
      emits forensics, and flags the signer (uniform, all modes).
    - T4-D: approvals export as offline-verifiable quorum certificates.
    """

    def _engine3(self):
        from liboqs_wrapper import LibOQS_MLDSA_87
        eng = ByzantineQuorumEngine(required_quorum_m=2,
                                   total_authorized_nodes_n=3)
        dsa = LibOQS_MLDSA_87()
        keys = {}
        for n in ("N1", "N2", "N3"):
            pk, sk = dsa.keygen()
            keys[n] = (bytes(pk), bytes(sk))
            eng.register_command_node(n, keys[n][0])
        return eng, dsa, keys

    def _sigs(self, eng, dsa, keys, signers, **kw):
        canon = eng.build_canonical_payload(**kw)
        return {s: bytes(dsa.sign(keys[s][1], canon)) for s in signers}, canon

    def test_quorum_bounds_fail_fast(self):
        # 2-of-5 lets any 2 (possibly both Byzantine) approve: refused.
        with self.assertRaises(ValueError):
            ByzantineQuorumEngine(required_quorum_m=2,
                                 total_authorized_nodes_n=5)
        # Dictatorships, over-quorums, singletons: all refused.
        for m, n in ((1, 3), (4, 3), (2, 1), (0, 3)):
            with self.assertRaises(ValueError):
                ByzantineQuorumEngine(required_quorum_m=m,
                                     total_authorized_nodes_n=n)
        # Valid shapes construct with the right fault budget.
        eng = ByzantineQuorumEngine(required_quorum_m=4,
                                   total_authorized_nodes_n=5)
        self.assertEqual(eng.max_faults, 1)
        eng234 = ByzantineQuorumEngine(required_quorum_m=2,
                                      total_authorized_nodes_n=3)
        self.assertEqual(eng234.max_faults, 0)

    def test_roster_capped_and_reregistration_guarded(self):
        eng, _, keys = self._engine3()
        # Fourth node on N=3 refused (would weaken the bound).
        from liboqs_wrapper import LibOQS_MLDSA_87
        pk4, _ = LibOQS_MLDSA_87().keygen()
        with self.assertRaises(ValueError):
            eng.register_command_node("N4", bytes(pk4))
        # Same-key re-registration idempotent; key-swap refused.
        eng.register_command_node("N1", keys["N1"][0])
        with self.assertRaises(ValueError):
            eng.register_command_node("N1", bytes(pk4))
        with self.assertRaises(ValueError):
            eng.register_command_node("N1", b"")

    def test_equivocation_refused_with_forensics(self):
        eng, dsa, keys = self._engine3()
        kw = dict(command_type=CriticalCommandType.TACTICAL_REKEY_ALL,
                  target_payload={"epoch": 7}, proposed_by="N1",
                  proposal_seq=11, epoch_id="E9")
        sigs_a, _ = self._sigs(eng, dsa, keys, ("N1", "N2"), **kw)
        ok, _, rec = eng.evaluate_proposal(signatures=sigs_a, **kw)
        self.assertTrue(ok)
        # N1 now signs a CONFLICTING payload for the same (epoch, seq).
        kw2 = dict(kw)
        kw2["target_payload"] = {"epoch": 999}
        sigs_b, _ = self._sigs(eng, dsa, keys, ("N1", "N3"), **kw2)
        ok2, msg2, rec2 = eng.evaluate_proposal(signatures=sigs_b, **kw2)
        self.assertFalse(ok2)
        self.assertEqual(rec2["status"], "EQUIVOCATION_REJECTED")
        self.assertIn("N1", eng.flagged_signers)
        self.assertEqual(len(eng.forensic_records), 1)
        fr = eng.forensic_records[0]
        self.assertEqual(fr["signer"], "N1")
        self.assertNotEqual(fr["first_digest"], fr["second_digest"])
        # Same-signer re-vote for the IDENTICAL digest is not equivocation.
        sigs_c, _ = self._sigs(eng, dsa, keys, ("N2", "N3"), **kw)
        ok3, _, rec3 = eng.evaluate_proposal(signatures=sigs_c, **kw)
        self.assertFalse(ok3)  # replay (already executed), not equivocation
        self.assertEqual(rec3["status"], "REPLAY_DETECTED_REJECTED")

    def test_quorum_certificate_offline_verification(self):
        eng, dsa, keys = self._engine3()
        kw = dict(command_type=CriticalCommandType.NETWORK_WIDE_QUARANTINE,
                  target_payload={"peer_id": "ROGUE_X"},
                  proposed_by="N1", proposal_seq=3, epoch_id="E10")
        sigs, _ = self._sigs(eng, dsa, keys, ("N1", "N2"), **kw)
        ok, _, rec = eng.evaluate_proposal(signatures=sigs, **kw)
        self.assertTrue(ok)
        qc = eng.build_quorum_certificate(rec, sigs)
        self.assertEqual(qc["threshold_m"], 2)
        # Offline: no engine needed.
        vok, vmsg = ByzantineQuorumEngine.verify_quorum_certificate(qc)
        self.assertTrue(vok, vmsg)
        # Tampered payload digest fails.
        import copy
        evil = copy.deepcopy(qc)
        evil["target_payload"] = {"peer_id": "ALLY_Y"}
        vok, _ = ByzantineQuorumEngine.verify_quorum_certificate(evil)
        self.assertFalse(vok)
        # Swapped signature fails.
        evil2 = copy.deepcopy(qc)
        evil2["signatures"]["N1"] = evil2["signatures"]["N2"]
        vok, _ = ByzantineQuorumEngine.verify_quorum_certificate(evil2)
        self.assertFalse(vok)
        # Sub-threshold (one sig stripped) fails.
        evil3 = copy.deepcopy(qc)
        del evil3["signatures"]["N2"]
        evil3["signers"] = ["N1"]
        vok, _ = ByzantineQuorumEngine.verify_quorum_certificate(evil3)
        self.assertFalse(vok)
        # Unknown extra signer not counted, valid pair still verifies.
        okqc = copy.deepcopy(qc)
        okqc["signatures"]["GHOST"] = "00" * 64
        vok, _ = ByzantineQuorumEngine.verify_quorum_certificate(okqc)
        self.assertTrue(vok)
        # Malformed envelopes never raise.
        for bad in ({}, {"v": 99}, {"v": 1, "algorithm": "X"},
                    {"v": 1, "algorithm": "ML-DSA-87"}):
            vok, _ = ByzantineQuorumEngine.verify_quorum_certificate(bad)
            self.assertFalse(vok)


class TestGatewayTier4V1(unittest.TestCase):
    """Tier-4 v1 gateway hardening (research basis: CDS transfer doctrine,
    Data Guard permit/block/quarantine taxonomy, AU-2 decision audit).

    - T4-E: hostile-stripped content quarantines in strict (no token
      issued); lab warns + releases. Human review approves (signed
      release) or denies; double-review/unknown/empty-reviewer refuse.
    - Token redaction lists reflect compartments actually found.
    - Every terminal decision is audit-logged.
    """

    def _gw(self):
        return AlliedCoalitionGateway()

    def _hostile(self):
        return json.dumps({
            "target": "GRID_7",
            "metadata": "<script>alert('xss');</script>",
            "classification": "SECRET",
        }).encode("utf-8")

    def _kw(self, payload):
        return dict(payload_bytes=payload,
                    source_classification=SecurityClassification.SECRET,
                    target_alliance=CoalitionAlliance.FVEY,
                    target_partner_nation="GBR",
                    active_caveats=set())

    def test_quarantine_strict_review_approve(self):
        import os
        os.environ["P2P_GATEWAY_QUARANTINE_HOSTILE"] = "1"
        try:
            gw = self._gw()
            res = gw.redact_and_package_for_coalition(**self._kw(self._hostile()))
            self.assertEqual(res["status"], "QUARANTINED_FOR_REVIEW")
            self.assertIsNone(res["sanitized_payload"])  # nothing releasable
            self.assertNotIn("release_token", res)
            qid = res["quarantine_id"]
            self.assertIn(qid, gw.quarantine_hold)
            # Approve: full signed release from held bytes.
            pkg = gw.review_quarantined(qid, True, "REVIEWER_JONES", "manual CDR verification")
            self.assertEqual(pkg["status"], "AUTHORIZED_COALITION_RELEASE")
            self.assertEqual(pkg["reviewed_by"], "REVIEWER_JONES")
            self.assertTrue(gw.verify_coalition_release(pkg))
            self.assertNotIn(qid, gw.quarantine_hold)  # consumed
            # Double-review refused (consumed hold).
            with self.assertRaises(CoalitionRedactionError):
                gw.review_quarantined(qid, True, "REVIEWER_JONES")
            # Audit trail covers hold + approval.
            kinds = [d["decision"] for d in gw.transfer_decisions()]
            self.assertIn("QUARANTINED_FOR_REVIEW", kinds)
            self.assertIn("REVIEW_APPROVED", kinds)
        finally:
            os.environ.pop("P2P_GATEWAY_QUARANTINE_HOSTILE", None)

    def test_quarantine_review_deny_and_refusals(self):
        import os
        os.environ["P2P_GATEWAY_QUARANTINE_HOSTILE"] = "1"
        try:
            gw = self._gw()
            res = gw.redact_and_package_for_coalition(**self._kw(self._hostile()))
            qid = res["quarantine_id"]
            denied = gw.review_quarantined(qid, False, "REVIEWER_JONES", "unacceptable risk")
            self.assertEqual(denied["status"], "REVIEW_DENIED")
            self.assertNotIn(qid, gw.quarantine_hold)
            self.assertIn("REVIEW_DENIED",
                          [d["decision"] for d in gw.transfer_decisions()])
            with self.assertRaises(CoalitionRedactionError):
                gw.review_quarantined("Q-NOPE", True, "REVIEWER_JONES")
            with self.assertRaises(CoalitionRedactionError):
                gw.review_quarantined(qid, True, "")
        finally:
            os.environ.pop("P2P_GATEWAY_QUARANTINE_HOSTILE", None)

    def test_lab_releases_benign_and_warns_hostile(self):
        import os
        for var in ("P2P_GATEWAY_QUARANTINE_HOSTILE", "P2P_PRODUCTION",
                    "SECURE_P2P_PRODUCTION"):
            os.environ.pop(var, None)
        gw = self._gw()
        # Benign: releases, no quarantine.
        pkg = gw.redact_and_package_for_coalition(
            **self._kw(b"Allied sector perimeter clear"))
        self.assertEqual(pkg["status"], "AUTHORIZED_COALITION_RELEASE")
        self.assertTrue(gw.verify_coalition_release(pkg))
        # Hostile in lab: releases with warning (strict would hold).
        pkg2 = gw.redact_and_package_for_coalition(
            **self._kw(self._hostile()))
        self.assertEqual(pkg2["status"], "AUTHORIZED_COALITION_RELEASE")
        self.assertTrue(pkg2["release_token"]["cdr_hostile_stripped"])

    def test_redaction_list_is_actual_not_static(self):
        import os
        for var in ("P2P_GATEWAY_QUARANTINE_HOSTILE", "P2P_PRODUCTION",
                    "SECURE_P2P_PRODUCTION"):
            os.environ.pop(var, None)
        gw = self._gw()
        pkg = gw.redact_and_package_for_coalition(
            payload_bytes=b"sector clear with HCS-P intelligence",
            source_classification=SecurityClassification.SECRET,
            target_alliance=CoalitionAlliance.FVEY,
            target_partner_nation="GBR",
            active_caveats={"HCS-P"},
        )
        self.assertEqual(pkg["release_token"]["redacted_compartments"], ["HCS-P"])
        self.assertNotIn(b"HCS-P", pkg["sanitized_payload"].encode("utf-8"))


class TestACDIngestTier4V1(unittest.TestCase):
    """Tier-4 v1 ACD ingest hardening (T4-F): exact-match dispatch.

    A previous revision routed playbooks by SUBSTRING, so SIEM-forwarded
    arbitrary event names containing fragments ("replay", "tamper",
    "auth_fail") could fire quarantine/block. Dispatch is now exact on
    registered names (case-sensitive tokens); unknown names warn +
    count, never fire -- including case variants and superstrings.
    """

    def _engine(self):
        from active_cyber_defense import ActiveCyberDefenseEngine
        import tempfile
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tmp.close()
        eng = ActiveCyberDefenseEngine(
            replay_threshold=3, replay_window_sec=60.0,
            auth_fail_threshold=3, auth_fail_window_sec=60.0,
            quarantine_duration_sec=60.0,
            quarantine_file=__import__("pathlib").Path(tmp.name),
        )
        return eng

    def test_adversarial_names_never_fire(self):
        eng = self._engine()
        hostile_names = [
            "replay_protection_verified_ok",   # contains 'replay'
            "RESOLVED_auth_failure_ticket",    # contains 'auth_fail'
            "tamper_free_attestation_report",  # contains 'tamper'
            "myreplay", "REPLAY_BURST", "Replay_Rejection",
            "handshake_failure_resolved", "cert_rejection_appeal",
            "traffic_anomaly_cleared", "key_leak_risk_dismissed",
            "", "replay", "tamper",
        ]
        for name in hostile_names:
            for _ in range(5):  # above every threshold: still nothing
                actions = eng.ingest_event(name, peer_id="victim_1",
                                           source_ip="198.51.100.9",
                                           session_id="sess_1")
                self.assertEqual(actions, [], f"{name!r} fired a playbook")
        self.assertFalse(eng.is_peer_quarantined("victim_1"))
        self.assertFalse(eng.is_source_blocked("198.51.100.9"))
        self.assertFalse(eng.is_session_severed("sess_1"))
        self.assertGreaterEqual(len(eng.unknown_event_types), len(hostile_names))

    def test_exact_names_still_fire(self):
        eng = self._engine()
        for _ in range(3):
            actions = eng.ingest_event("replay_rejection", peer_id="p1")
        self.assertEqual(len(actions), 1)
        self.assertTrue(eng.is_peer_quarantined("p1"))
        actions = eng.ingest_event("tamper_detected", peer_id="p2",
                                   session_id="s2")
        self.assertEqual(len(actions), 1)
        self.assertTrue(eng.is_session_severed("s2"))
        for _ in range(3):
            actions = eng.ingest_event("handshake_fail", peer_id="p3",
                                       source_ip="203.0.113.7")
        self.assertEqual(len(actions), 1)
        self.assertTrue(eng.is_source_blocked("203.0.113.7"))


class TestBallotTier4V1(unittest.TestCase):
    """Tier-4 v1 multi-round ballots (T4-G; Rûm-2025 round direction).

    Votes trickle in across DDIL rounds; the ballot decides the moment
    M valid rostered votes exist. Same canonical bytes, thresholds,
    replay index, and equivocation forensics as single-shot; unknown
    or closed ballots, expired deadlines, over-max rounds, duplicate
    opens, and double tallies all fail closed.
    """

    def _eng3(self):
        from liboqs_wrapper import LibOQS_MLDSA_87
        from byzantine_mesh_consensus import ByzantineQuorumEngine
        eng = ByzantineQuorumEngine(required_quorum_m=2,
                                   total_authorized_nodes_n=3)
        dsa = LibOQS_MLDSA_87()
        keys = {}
        for n in ("N1", "N2", "N3"):
            pk, sk = dsa.keygen()
            keys[n] = (bytes(pk), bytes(sk))
            eng.register_command_node(n, keys[n][0])
        return eng, dsa, keys

    def _open(self, eng, seq=41, epoch="EB3"):
        from byzantine_mesh_consensus import CriticalCommandType
        return eng.open_ballot(
            command_type=CriticalCommandType.TACTICAL_REKEY_ALL,
            target_payload={"epoch": 33}, proposed_by="N1",
            proposal_seq=seq, epoch_id=epoch)

    def _sign(self, eng, dsa, keys, signer, seq=41, epoch="EB3",
              valid_until=None):
        canon = eng.build_canonical_payload(
            command_type="TACTICAL_REKEY_ALL",
            target_payload={"epoch": 33}, proposed_by="N1",
            proposal_seq=seq, epoch_id=epoch,
            valid_until_utc=valid_until)
        return bytes(dsa.sign(keys[signer][1], canon))

    def test_ballot_collects_across_rounds_and_tallies(self):
        eng, dsa, keys = self._eng3()
        bal = self._open(eng)
        counted, _ = eng.cast_ballot_vote(bal, "N1", self._sign(eng, dsa, keys, "N1"), round_num=1)
        self.assertTrue(counted)
        counted, msg = eng.cast_ballot_vote(bal, "N2", self._sign(eng, dsa, keys, "N2"), round_num=3)
        self.assertTrue(counted)
        self.assertIn("quorum reached", msg)
        ok, _, rec = eng.tally_ballot(bal)
        self.assertTrue(ok)
        self.assertEqual(rec["status"], "APPROVED")
        self.assertEqual(rec["rounds_seen"], 3)
        self.assertEqual(rec["vote_rounds"], {"N1": 1, "N2": 3})
        # QC builds from the tally record + banked votes.
        qc = eng.build_quorum_certificate(
            rec, {s: eng._ballots[bal]["votes"][s] for s in ("N1", "N2")})
        vok, _ = eng.verify_quorum_certificate(qc)
        self.assertTrue(vok)
        # Double tally refused (replay-safe).
        ok2, _, rec2 = eng.tally_ballot(bal)
        self.assertFalse(ok2)
        self.assertEqual(rec2["status"], "UNKNOWN_BALLOT_REJECTED")

    def test_ballot_refusals_fail_closed(self):
        eng, dsa, keys = self._eng3()
        bal = self._open(eng)
        # Unknown ballot / closed ballot / bad round / outsider / bad sig.
        counted, _ = eng.cast_ballot_vote("BAL:nope", "N1",
                                          self._sign(eng, dsa, keys, "N1"))
        self.assertFalse(counted)
        counted, _ = eng.cast_ballot_vote(bal, "GHOST",
                                          self._sign(eng, dsa, keys, "N1"))
        self.assertFalse(counted)
        counted, _ = eng.cast_ballot_vote(bal, "N1",
                                          self._sign(eng, dsa, keys, "N1"),
                                          round_num=0)
        self.assertFalse(counted)
        counted, _ = eng.cast_ballot_vote(bal, "N1", b"junk-sig")
        self.assertFalse(counted)
        # Duplicate identical vote ignored (banked once); tally short.
        # NOTE: ML-DSA signatures are randomized, so "identical" means
        # resubmitting the SAME bytes (re-signing yields a distinct valid
        # signature, which is correctly treated as equivocation).
        s1 = self._sign(eng, dsa, keys, "N1")
        counted, _ = eng.cast_ballot_vote(bal, "N1", s1)
        self.assertTrue(counted)
        counted, _ = eng.cast_ballot_vote(bal, "N1", s1)
        self.assertTrue(counted)  # idempotent re-cast
        ok, _, rec = eng.tally_ballot(bal)
        self.assertFalse(ok)
        self.assertEqual(rec["status"], "QUORUM_DEFICIT_REJECTED")
        # Duplicate open refused; close works on a FRESH open ballot
        # (the tallied one above is already closed); closed tally refused.
        with self.assertRaises(ValueError):
            self._open(eng)
        bal2 = eng.open_ballot(
            command_type=CriticalCommandType.TACTICAL_REKEY_ALL,
            target_payload={"epoch": 34}, proposed_by="N1",
            proposal_seq=99, epoch_id="EB9")
        self.assertTrue(eng.close_ballot(bal2))
        self.assertFalse(eng.close_ballot(bal2))
        ok, _, _ = eng.tally_ballot(bal2)
        self.assertFalse(ok)

    def test_ballot_equivocating_voter_refused_flagged_ballot_lives(self):
        eng, dsa, keys = self._eng3()
        bal = self._open(eng)
        s1 = self._sign(eng, dsa, keys, "N1")
        counted, _ = eng.cast_ballot_vote(bal, "N1", s1)
        self.assertTrue(counted)
        # Same node, same ballot bytes, DIFFERENT signature bytes: craft by
        # re-signing (ML-DSA randomized -> distinct valid sig over same msg).
        s1b = self._sign(eng, dsa, keys, "N1")
        self.assertNotEqual(s1, s1b)
        counted, msg = eng.cast_ballot_vote(bal, "N1", s1b)
        self.assertFalse(counted)
        self.assertIn("Equivocation", msg)
        self.assertIn("N1", eng.flagged_signers)
        self.assertEqual(len(eng.forensic_records), 1)
        # Ballot completes on honest votes; the equivocator's banked
        # first vote is STRIPPED at tally (flagged signers decide nothing).
        eng.cast_ballot_vote(bal, "N2", self._sign(eng, dsa, keys, "N2"))
        eng.cast_ballot_vote(bal, "N3", self._sign(eng, dsa, keys, "N3"))
        ok, _, rec = eng.tally_ballot(bal)
        self.assertTrue(ok)
        self.assertNotIn("N1", rec["authorized_signers"])
        self.assertIn("N1", rec["excluded_flagged_signers"])

    def test_ballot_expiry_and_max_rounds(self):
        import time
        eng, dsa, keys = self._eng3()
        past = time.time() - 1.0
        bal = eng.open_ballot(
            command_type="TACTICAL_REKEY_ALL",
            target_payload={"epoch": 33}, proposed_by="N1",
            proposal_seq=42, epoch_id="EB3",
            valid_until_utc=past, max_rounds=2)
        counted, _ = eng.cast_ballot_vote(bal, "N1",
                                          self._sign(eng, dsa, keys, "N1",
                                                     seq=42,
                                                     valid_until=past),
                                          round_num=1)
        self.assertTrue(counted)
        counted, msg = eng.cast_ballot_vote(
            bal, "N2", self._sign(eng, dsa, keys, "N2", seq=42,
                                  valid_until=past), round_num=3)
        self.assertFalse(counted)
        self.assertIn("max", msg)
        ok, _, rec = eng.tally_ballot(bal)
        self.assertFalse(ok)  # expired + short
        self.assertEqual(rec["status"], "EXPIRED_REJECTED")


if __name__ == "__main__":
    unittest.main()
