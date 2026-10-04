#!/usr/bin/env python3
"""
test_tier4_spqr_and_rum_bft.py

Dedicated test suite verifying Tier 4 Advanced Research implementations:
1. Sparse Post-Quantum Ratchet (SPQR) on-demand and event-driven rekeying.
2. SPQR cadence diagnostics and stats reporting.
3. Leaderless Rûm (2025) round-based consensus vote aggregation and Quorum Certificate (QC) validation.
4. Rûm BFT failure closed on insufficient votes or Byzantine equivocation.
5. Content Disarm & Reconstruction (CDR) neutralization of XXE, path traversal, and malicious scripts.
6. Clean tactical payload preservation through CDR.
7. Twin parity verification between secure_p2p.py and secure_p2.py.
"""

import hashlib
import json
import os
import secrets
import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from double_ratchet import DoubleRatchet
from byzantine_mesh_consensus import (
    ByzantineQuorumEngine,
    CriticalCommandType,
)
from cjadc2_allied_gateway import (
    AlliedCoalitionGateway,
    CoalitionAlliance,
    SecurityClassification,
)
from liboqs_wrapper import LibOQS_MLDSA_87


def _make_ratchet_pair(protocol_version=2):
    root = secrets.token_bytes(32)
    alice = DoubleRatchet(root_key=root, is_initiator=True,
                          protocol_version=protocol_version)
    bob = DoubleRatchet(root_key=root, is_initiator=False,
                        protocol_version=protocol_version)
    alice.negotiate_pq_ratchet_version(protocol_version)
    bob.negotiate_pq_ratchet_version(protocol_version)
    alice.set_remote_public_key(bob.get_public_key(), bob.get_kem_public_key(),
                                bob.get_dss_public_key())
    bob.set_remote_public_key(alice.get_public_key(), alice.get_kem_public_key(),
                              alice.get_dss_public_key())
    bob.process_kem_ciphertext(alice.get_kem_ciphertext())
    assert alice.is_initialized() and bob.is_initialized()  # nosec: B101
    return alice, bob


class TestTier4SPQRAndRumBFT(unittest.TestCase):
    """Test suite for Tier 4 research-backed implementations."""

    def test_01_spqr_force_refresh_accelerates_pcs(self):
        """Verify force_spqr_refresh rotates DH and KEM state on v2 sessions."""
        alice, bob = _make_ratchet_pair(protocol_version=2)

        # Baseline message round-trip
        msg1 = alice.encrypt(b"Alpha to Bravo: SITREP 01")
        dec1 = bob.decrypt(msg1)
        self.assertEqual(dec1, b"Alpha to Bravo: SITREP 01")

        # Capture pre-refresh stats
        stats_pre = alice.get_spqr_stats()
        self.assertEqual(stats_pre["pq_ratchet_version"], 2)

        # Force on-demand SPQR refresh (accelerating post-compromise security recovery)
        refreshed = alice.force_spqr_refresh(reason="EAM_FLASH_EVENT")
        self.assertTrue(refreshed)

        stats_post = alice.get_spqr_stats()
        self.assertEqual(stats_post["msg_counter"], 0)

        # Encrypt with the refreshed state (attaches fresh KEM CT extension)
        msg_eam = alice.encrypt(b"FLASH PRIORITY: EXECUTE STRATEGIC OPTION")
        dec_eam = bob.decrypt(msg_eam)
        self.assertEqual(dec_eam, b"FLASH PRIORITY: EXECUTE STRATEGIC OPTION")

    def test_02_spqr_diagnostics_and_stats(self):
        """Verify SPQR stats structure and cadence policy."""
        alice, _ = _make_ratchet_pair(protocol_version=2)
        stats = alice.get_spqr_stats()
        self.assertIn("msg_counter", stats)
        self.assertIn("msg_interval", stats)
        self.assertIn("max_age_seconds", stats)
        self.assertIn("pq_ratchet_version", stats)
        self.assertEqual(stats["pq_ratchet_version"], 2)

    def test_03_leaderless_rum_round_voting_achieves_qc(self):
        """Verify Rûm leaderless round voting achieves 2-of-3 threshold and builds valid QC."""
        engine = ByzantineQuorumEngine(required_quorum_m=2, total_authorized_nodes_n=3)
        signer = LibOQS_MLDSA_87()

        # Generate credentials for 3 nodes
        nodes = {}
        for nid in ["NODE_ALPHA", "NODE_BRAVO", "NODE_CHARLIE"]:
            pk, sk = signer.keygen()
            engine.register_command_node(nid, pk)
            nodes[nid] = (pk, sk)

        proposal_id = "RUM_ROUND_1_PROP_001"
        cmd = CriticalCommandType.NETWORK_WIDE_QUARANTINE
        target = {"reason": "Hostile reconnaissance detected across tactical mesh", "target_zone": "SECTOR_7"}

        # Build canonical payload bytes
        canonical = engine.build_canonical_payload(
            command_type=cmd,
            target_payload=target,
            proposed_by=proposal_id,
            proposal_seq=1,
            epoch_id="1",
        )

        # Node Alpha and Node Bravo vote in Round 1
        votes = {
            "NODE_ALPHA": signer.sign(nodes["NODE_ALPHA"][1], canonical),
            "NODE_BRAVO": signer.sign(nodes["NODE_BRAVO"][1], canonical),
        }

        # Aggregate round votes
        result = engine.collect_rum_round_votes(
            round_num=1,
            proposal_id=proposal_id,
            command_type=cmd,
            target_payload=target,
            votes=votes,
            epoch=1,
        )

        self.assertTrue(result["success"])
        self.assertIsNotNone(result["quorum_certificate"])

        # Verify the Quorum Certificate independently
        qc = result["quorum_certificate"]
        valid, reason = ByzantineQuorumEngine.verify_quorum_certificate(qc)
        self.assertTrue(valid, f"QC failed verification: {reason}")
        self.assertEqual(qc["threshold_m"], 2)
        self.assertEqual(qc["roster_n"], 3)

    def test_04_leaderless_rum_insufficient_votes_fails_closed(self):
        """Verify Rûm round voting with minority vote fails closed without issuing QC."""
        engine = ByzantineQuorumEngine(required_quorum_m=2, total_authorized_nodes_n=3)
        signer = LibOQS_MLDSA_87()

        nodes = {}
        for nid in ["NODE_1", "NODE_2", "NODE_3"]:
            pk, sk = signer.keygen()
            engine.register_command_node(nid, pk)
            nodes[nid] = (pk, sk)

        proposal_id = "RUM_ROUND_1_PROP_FAIL"
        cmd = CriticalCommandType.TACTICAL_REKEY_ALL
        target = {"scope": "GLOBAL"}
        canonical = engine.build_canonical_payload(
            command_type=cmd,
            target_payload=target,
            proposed_by=proposal_id,
            proposal_seq=1,
            epoch_id="1",
        )

        # Only 1 vote provided (minority)
        votes = {
            "NODE_1": signer.sign(nodes["NODE_1"][1], canonical),
        }

        result = engine.collect_rum_round_votes(
            round_num=1,
            proposal_id=proposal_id,
            command_type=cmd,
            target_payload=target,
            votes=votes,
            epoch=1,
        )

        self.assertFalse(result["success"])
        self.assertIsNone(result["quorum_certificate"])
        self.assertIn("Quorum failure", result["status_message"])

    def test_05_cjadc2_cdr_disarms_xxe_and_path_traversal(self):
        """Verify Content Disarm & Reconstruction sanitizes XXE, path traversal, and script vectors."""
        gw = AlliedCoalitionGateway()

        dirty_xxe_payload = json.dumps({
            "operation": "TACTICAL_ASSET_MOVE",
            "xxe_attack": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "path_traversal": "../../windows/system32/cmd.exe",
            "embedded_script": "<script>alert('pwn')</script>",
            "null_byte": "clean\x00corrupt",
        }).encode("utf-8")

        cleaned_bytes, hostile_stripped = gw.execute_content_disarm_and_reconstruction(dirty_xxe_payload)

        self.assertTrue(hostile_stripped)
        self.assertNotIn(b"<script>", cleaned_bytes)
        self.assertNotIn(b"SYSTEM", cleaned_bytes)
        self.assertNotIn(b"\x00", cleaned_bytes)
        self.assertNotIn(b"../../", cleaned_bytes)

        # Cleaned payload must parse as valid canonical JSON
        cleaned_dict = json.loads(cleaned_bytes.decode("utf-8"))
        self.assertIn("operation", cleaned_dict)
        self.assertEqual(cleaned_dict["operation"], "TACTICAL_ASSET_MOVE")

    def test_06_cjadc2_cdr_preserves_clean_payloads(self):
        """Verify clean operational payload passes CDR intact without hostile flag."""
        gw = AlliedCoalitionGateway()

        clean_payload = json.dumps({
            "unit": "1st_BATTALION",
            "lat": 34.0522,
            "lon": -118.2437,
            "status": "OPERATIONAL",
            "classification": "SECRET",
        }, sort_keys=True).encode("utf-8")

        cleaned_bytes, hostile_stripped = gw.execute_content_disarm_and_reconstruction(clean_payload)
        self.assertFalse(hostile_stripped)
        self.assertEqual(json.loads(cleaned_bytes.decode("utf-8")), json.loads(clean_payload.decode("utf-8")))

    def test_07_twin_parity_sha256_invariant(self):
        """Verify 100% exact byte-for-byte SHA256 parity between secure_p2p.py and secure_p2.py."""
        p2p_path = REPO_ROOT / "archive/legacy_prototype/secure_p2p.py"
        p2_path = REPO_ROOT / "archive/legacy_prototype/secure_p2.py"

        with open(p2p_path, "rb") as f:
            h_p2p = hashlib.sha256(f.read()).hexdigest()
        with open(p2_path, "rb") as f:
            h_p2 = hashlib.sha256(f.read()).hexdigest()

        self.assertEqual(h_p2p, h_p2, "secure_p2p.py and secure_p2.py MUST have identical SHA256 hashes")


if __name__ == "__main__":
    unittest.main()
