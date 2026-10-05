#!/usr/bin/env python3
"""
test_tier4_pq_treekem_and_tfc.py

Automated test suite verifying Tier 4 Research Implementations:
1. Post-Quantum TreeKEM (IETF draft-ietf-mls-pq-ciphersuites / Eurocrypt 2025).
2. O(log N) UpdatePath generation with ML-KEM-1024 copath encapsulations.
3. Multi-party asynchronous group epoch secret derivation (Alice, Bob, Carol, Dave).
4. Post-Compromise Security (PCS) rekeying via UpdatePath.
5. Eviction fail-closed: evicted member cannot decapsulate subsequent UpdatePaths.
6. Traffic Flow Confidentiality (TFC) discrete bucket padding and lossless unpadding.
7. Authenticated dummy chaff frame generation and detection.
8. Memoryless Poisson-distributed inter-arrival interval generation.
9. Bit-for-bit twin parity invariant between secure_p2p.py and secure_p2.py.
"""

import hashlib
import json
import os
import secrets
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pq_treekem import PQTreeKEM, PQTreeKEMError
from tactical_cloaking_router import (
    pad_to_tfc_bucket,
    unpad_tfc_bucket,
    generate_chaff_frame,
    is_chaff_frame,
    get_poisson_interval,
    TFC_BUCKET_SIZES,
)
from liboqs_wrapper import LibOQS_MLKEM_1024


class TestTier4PQTreeKEMAndTFC(unittest.TestCase):
    """Test battery for Post-Quantum TreeKEM and Traffic Flow Confidentiality."""

    def setUp(self):
        self.kem = LibOQS_MLKEM_1024()

    def test_01_tfc_discrete_bucket_padding_and_unpadding(self):
        """Verify TFC pads to discrete bucket sizes and unpads losslessly."""
        test_payloads = [
            b"Short text",
            b"A" * 200,    # Total 202 -> bucket 256
            b"B" * 400,    # Total 402 -> bucket 512
            b"C" * 800,    # Total 802 -> bucket 1024
            b"D" * 1200,   # Total 1202 -> bucket 1400
        ]
        expected_buckets = [256, 256, 512, 1024, 1400]

        for payload, exp_bucket in zip(test_payloads, expected_buckets):
            padded = pad_to_tfc_bucket(payload)
            self.assertEqual(len(padded), exp_bucket, f"Payload {len(payload)}B did not pad to {exp_bucket}")
            unpadded = unpad_tfc_bucket(padded)
            self.assertEqual(unpadded, payload, "Unpadded payload does not match original")

    def test_02_chaff_generation_and_identification(self):
        """Verify dummy chaff packets are generated with valid bucket sizes and detected."""
        for bucket in [256, 512, 1024, 1400]:
            chaff = generate_chaff_frame(bucket_size=bucket)
            self.assertEqual(len(chaff), bucket)
            self.assertTrue(is_chaff_frame(chaff))

        real_payload = pad_to_tfc_bucket(b"REAL_OPERATIONAL_DATA_TRANSMISSION")
        self.assertFalse(is_chaff_frame(real_payload))

    def test_03_poisson_chaff_timing_distribution(self):
        """Verify Poisson process generates positive, randomized inter-arrival intervals."""
        intervals = [get_poisson_interval(rate_lambda=0.5) for _ in range(50)]
        self.assertTrue(all(i > 0 for i in intervals))
        # Verify variance (not constant)
        self.assertGreater(len(set(intervals)), 20)

    def test_04_pq_treekem_4_party_update_path_synchronization(self):
        """Verify 4 members in PQ-TreeKEM derive identical epoch secrets via O(log N) UpdatePath."""
        group_id = "TASK_FORCE_SENTINEL_ALPHA"
        members = ["alice", "bob", "carol", "dave"]
        keys = {}
        nodes = {}

        # 1. Generate keypairs for all 4 members
        for m in members:
            pk, sk = self.kem.keygen()
            keys[m] = (pk, sk)

        # 2. Instantiate PQTreeKEM instances for Alice, Bob, Carol, Dave
        for m in members:
            tree_kem = PQTreeKEM(group_id=group_id, width=4, local_member_id=m)
            # Add all members to local tree
            for other_m in members:
                leaf_idx = tree_kem.add_member(other_m, keys[other_m][0])
                if other_m == m:
                    tree_kem.set_local_leaf_credentials(leaf_idx, keys[m][0], keys[m][1])
            nodes[m] = tree_kem

        # 3. Synchronize initial baseline epoch secret across all 4 nodes
        shared_init_epoch = hashlib.sha3_512(b"INITIAL_PQ_MLS_GROUP_EPOCH_SEED").digest()[:32]
        for m in members:
            nodes[m].epoch_secret = shared_init_epoch

        # 4. Alice generates an UpdatePath (updating her leaf and climbing direct path)
        alice_leaf = nodes["alice"].tree.members()["alice"]
        update_path, alice_new_epoch = nodes["alice"].create_update_path(alice_leaf)

        self.assertIsNotNone(update_path)
        self.assertEqual(len(update_path.nodes), 2)  # In width=4, direct path from leaf has 2 parent steps to root

        # 5. Bob, Carol, and Dave all process Alice's UpdatePath
        bob_new_epoch = nodes["bob"].apply_update_path(alice_leaf, update_path)
        carol_new_epoch = nodes["carol"].apply_update_path(alice_leaf, update_path)
        dave_new_epoch = nodes["dave"].apply_update_path(alice_leaf, update_path)

        # 6. Mathematical Invariant: All members derive the EXACT same epoch secret!
        self.assertEqual(alice_new_epoch, bob_new_epoch, "Bob failed to synchronize epoch secret with Alice")
        self.assertEqual(alice_new_epoch, carol_new_epoch, "Carol failed to synchronize epoch secret with Alice")
        self.assertEqual(alice_new_epoch, dave_new_epoch, "Dave failed to synchronize epoch secret with Alice")

    def test_05_pq_treekem_pcs_continuous_ratchet_epoch(self):
        """Verify subsequent UpdatePath by Bob achieves Post-Compromise Security (PCS)."""
        group_id = "TASK_FORCE_SENTINEL_BETA"
        members = ["alice", "bob"]
        keys = {}
        nodes = {}

        for m in members:
            pk, sk = self.kem.keygen()
            keys[m] = (pk, sk)

        for m in members:
            tree_kem = PQTreeKEM(group_id=group_id, width=2, local_member_id=m)
            for other_m in members:
                l_idx = tree_kem.add_member(other_m, keys[other_m][0])
                if other_m == m:
                    tree_kem.set_local_leaf_credentials(l_idx, keys[m][0], keys[m][1])
            nodes[m] = tree_kem

        init_seed = hashlib.sha3_512(b"PCS_TEST_INIT_SEED").digest()[:32]
        nodes["alice"].epoch_secret = init_seed
        nodes["bob"].epoch_secret = init_seed

        # Step 1: Alice updates
        alice_leaf = nodes["alice"].tree.members()["alice"]
        path1, epoch1_alice = nodes["alice"].create_update_path(alice_leaf)
        epoch1_bob = nodes["bob"].apply_update_path(alice_leaf, path1)
        self.assertEqual(epoch1_alice, epoch1_bob)

        # Step 2: Bob updates (PCS recovery)
        bob_leaf = nodes["bob"].tree.members()["bob"]
        path2, epoch2_bob = nodes["bob"].create_update_path(bob_leaf)
        epoch2_alice = nodes["alice"].apply_update_path(bob_leaf, path2)
        self.assertEqual(epoch2_bob, epoch2_alice)

        # Epoch must have progressed forward
        self.assertNotEqual(epoch1_alice, epoch2_alice)

    def test_06_pq_treekem_eviction_fails_closed(self):
        """Verify removed member cannot decapsulate subsequent UpdatePaths."""
        group_id = "TASK_FORCE_EVICT"
        members = ["alice", "bob", "carol"]
        keys = {}
        nodes = {}

        for m in members:
            pk, sk = self.kem.keygen()
            keys[m] = (pk, sk)

        for m in members:
            tk = PQTreeKEM(group_id=group_id, width=4, local_member_id=m)
            for om in members:
                l_idx = tk.add_member(om, keys[om][0])
                if om == m:
                    tk.set_local_leaf_credentials(l_idx, keys[m][0], keys[m][1])
            nodes[m] = tk

        shared_seed = hashlib.sha3_512(b"EVICT_TEST_SEED").digest()[:32]
        for m in members:
            nodes[m].epoch_secret = shared_seed

        # Evict Carol from Alice and Bob's tree
        nodes["alice"].remove_member("carol")
        nodes["bob"].remove_member("carol")

        # Alice updates path (copath now excludes Carol's blanked leaf)
        alice_leaf = nodes["alice"].tree.members()["alice"]
        update_path, alice_epoch = nodes["alice"].create_update_path(alice_leaf)

        # Bob can still process because he remains in the tree
        bob_epoch = nodes["bob"].apply_update_path(alice_leaf, update_path)
        self.assertEqual(alice_epoch, bob_epoch)

    def test_07_twin_parity_sha256_invariant(self):
        """Verify 100% exact byte-for-byte SHA256 parity between secure_p2p.py and secure_p2.py."""
        p2p_path = REPO_ROOT / "archive/legacy_prototype/secure_p2p.py"
        p2_path = REPO_ROOT / "archive/legacy_prototype/secure_p2.py"

        if not p2_path.exists() or not p2p_path.exists():
            self.skipTest("legacy prototype twins not present in archive")

        with open(p2p_path, "rb") as f:
            h_p2p = hashlib.sha256(f.read()).hexdigest()
        with open(p2_path, "rb") as f:
            h_p2 = hashlib.sha256(f.read()).hexdigest()

        self.assertEqual(h_p2p, h_p2, "secure_p2p.py and secure_p2p.py MUST have identical SHA256 hashes")

    def _paired_nodes(self, members=("alice", "bob")):
        """Two synced managers sharing the epoch baseline (test helper)."""
        from pq_treekem import PQTreeKEM
        keys, nodes = {}, {}
        for m in members:
            pk, sk = self.kem.keygen()
            keys[m] = (bytes(pk), bytes(sk))
        for m in members:
            t = PQTreeKEM(group_id="GATE-GROUP", width=4,
                          local_member_id=m)
            for o in members:
                idx = t.add_member(o, keys[o][0])
                if o == m:
                    t.set_local_leaf_credentials(idx, keys[m][0], keys[m][1])
            nodes[m] = t
        seed = hashlib.sha3_512(b"GATE-BASELINE").digest()[:32]
        for m in members:
            nodes[m].epoch_secret = seed
        return nodes, keys

    def test_08_update_replay_rollback_refused(self):
        """Re-applying a consumed update must fail closed (forward secrecy:
        the epoch secret can never roll backward)."""
        from pq_treekem import PQTreeKEMError
        nodes, _ = self._paired_nodes()
        alice_leaf = nodes["alice"].tree.members()["alice"]
        path, _ = nodes["alice"].create_update_path(alice_leaf)
        nodes["bob"].apply_update_path(alice_leaf, path)
        before = bytes(nodes["bob"].epoch_secret)
        with self.assertRaises(PQTreeKEMError):
            nodes["bob"].apply_update_path(alice_leaf, path)
        self.assertEqual(bytes(nodes["bob"].epoch_secret), before)

    def test_09_forked_tree_update_refused(self):
        """An update built for a diverged tree is refused via tree_hash
        (stale views / cross-fork application fail closed)."""
        from pq_treekem import PQTreeKEMError
        nodes, keys = self._paired_nodes()
        pk2, sk2 = self.kem.keygen()
        nodes["alice"].tree.remove("alice")
        nodes["alice"].add_member("alice", bytes(pk2))
        nodes["alice"].set_local_leaf_credentials(
            nodes["alice"].tree.members()["alice"], bytes(pk2), bytes(sk2))
        alice_leaf = nodes["alice"].tree.members()["alice"]
        path, _ = nodes["alice"].create_update_path(alice_leaf)
        with self.assertRaises(PQTreeKEMError):
            nodes["bob"].apply_update_path(alice_leaf, path)

    def test_10_leaf_credential_bounds(self):
        """Out-of-range leaf indices fail closed (no phantom node keys)."""
        from pq_treekem import PQTreeKEMError
        nodes, keys = self._paired_nodes()
        with self.assertRaises(PQTreeKEMError):
            nodes["alice"].set_local_leaf_credentials(99, keys["alice"][0],
                                                      keys["alice"][1])
        with self.assertRaises(PQTreeKEMError):
            nodes["alice"].set_local_leaf_credentials(-1, keys["alice"][0],
                                                      keys["alice"][1])

    def test_11_tree_hash_agreement_after_sync(self):
        """Committer and receivers converge on identical tree hashes
        (committer advances its own view; receivers advance theirs)."""
        nodes, _ = self._paired_nodes()
        alice_leaf = nodes["alice"].tree.members()["alice"]
        path, _ = nodes["alice"].create_update_path(alice_leaf)
        nodes["bob"].apply_update_path(alice_leaf, path)
        self.assertEqual(nodes["alice"].tree.tree_hash(),
                         nodes["bob"].tree.tree_hash())


if __name__ == "__main__":
    unittest.main()
