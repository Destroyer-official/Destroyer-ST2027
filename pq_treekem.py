#!/usr/bin/env python3
"""
pq_treekem.py — Post-Quantum TreeKEM Implementation with ML-KEM-1024 (FIPS 203).

Research Basis:
- IETF Draft draft-ietf-mls-pq-ciphersuites (2025/2026): Pure-PQ & Hybrid Group Ratchets.
- RFC 9420 (Messaging Layer Security) §4, §7.6-§7.8 (Ratchet Trees & UpdatePaths).
- Eurocrypt 2025: TreeKEM in a Post-Quantum World: Efficiency and Asynchronous Security.

Architecture:
- Combines left-grown binary ratchet trees from treekem.py with NIST Level-5 ML-KEM-1024.
- Generates O(log N) UpdatePath envelopes containing copath encapsulations.
- Provides asynchronous group epoch rekeying and provable Post-Compromise Security (PCS).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import struct
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from treekem import RatchetTree, TreeError
from liboqs_wrapper import LibOQS_MLKEM_1024, LibOQS_MLDSA_87

logger = logging.getLogger("PQTreeKEM")


class PQTreeKEMError(Exception):
    """Base exception for Post-Quantum TreeKEM operations (fail-closed)."""
    pass


def _hkdf_expand_sha3_512(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand using SHA3-512 for NIST Level-5 cryptographic domain separation."""
    if len(prk) < 32:
        raise PQTreeKEMError("HKDF PRK must be at least 32 bytes")
    
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        msg = t + info + bytes([counter])
        t = hmac.new(prk, msg, hashlib.sha3_512).digest()
        okm += t
        counter += 1
    return okm[:length]


@dataclass
class PQNodeKey:
    """ML-KEM-1024 cryptographic key material for a single ratchet tree node."""
    public_key: bytes
    secret_key: Optional[bytes] = None  # None for unmerged or remote nodes
    path_secret: Optional[bytes] = None


@dataclass
class PQUpdatePathNode:
    """A single node along an updater's direct path within an UpdatePath transmission."""
    node_index: int
    public_key: bytes
    # Map of copath node index -> ML-KEM-1024 ciphertext encrypting the parent path secret
    copath_ciphertexts: Dict[int, bytes] = field(default_factory=dict)


@dataclass
class PQUpdatePath:
    """Complete MLS-compliant Post-Quantum UpdatePath for group rekeying."""
    updater_leaf: int
    updater_id: str
    nodes: List[PQUpdatePathNode]
    epoch_id: int
    tree_hash_before: str
    # Optional commit-level ML-DSA-87 signature over the distributor's
    # canonical bytes (see GroupKeyManager._pq_commit_canonical). Attached
    # by the distributing caller (who holds keys); verified by receivers
    # in strict mode. Absent by default: lab-only unsigned operation.
    commit_sig: Optional[bytes] = None


class PQTreeKEM:
    """
    Post-Quantum TreeKEM Engine implementing O(log N) group key agreement
    using ML-KEM-1024 (FIPS 203) and RFC 9420 ratchet tree topology.
    """

    def __init__(self, group_id: str, width: int = 4, local_member_id: str = "") -> None:
        self.group_id = group_id
        self.local_member_id = local_member_id
        self._lock = threading.RLock()
        self.kem = LibOQS_MLKEM_1024()
        self.tree = RatchetTree(width=width)
        
        # Local node key store: node_index -> PQNodeKey
        self._node_keys: Dict[int, PQNodeKey] = {}
        self.current_epoch: int = 1
        self.epoch_secret: bytes = secrets.token_bytes(32)

    def add_member(self, member_id: str, kem_public_key: bytes) -> int:
        """
        Add a member with their advertised ML-KEM-1024 public key.
        Returns the assigned leaf index (0 <= leaf < width).
        """
        with self._lock:
            if len(kem_public_key) != self.kem.pk_size:
                raise PQTreeKEMError(
                    f"Invalid ML-KEM-1024 PK size: {len(kem_public_key)} bytes (expected {self.kem.pk_size})"
                )
            leaf_idx = self.tree.add(member_id, kem_public_key)
            node_idx = 2 * leaf_idx  # Leaf n is at array index 2n per RFC 9420 App C
            self._node_keys[node_idx] = PQNodeKey(public_key=kem_public_key)
            return leaf_idx

    def set_local_leaf_credentials(self, leaf_idx: int, public_key: bytes, secret_key: bytes) -> None:
        """Register the local member's private ML-KEM-1024 key for their own leaf node."""
        with self._lock:
            if not isinstance(leaf_idx, int) or not 0 <= leaf_idx < self.tree.width:
                raise PQTreeKEMError(f"leaf index {leaf_idx!r} out of range (width {self.tree.width})")
            if len(secret_key) != self.kem.sk_size:
                raise PQTreeKEMError(f"Invalid ML-KEM-1024 SK size: {len(secret_key)} bytes")
            node_idx = 2 * leaf_idx
            self._node_keys[node_idx] = PQNodeKey(public_key=public_key, secret_key=secret_key)

    def remove_member(self, member_id: str) -> None:
        """Evict a member and blank their leaf and ancestor nodes in the ratchet tree."""
        with self._lock:
            leaf_idx = self.tree.members().get(member_id)
            if leaf_idx is None:
                raise PQTreeKEMError(f"Member '{member_id}' not found in group '{self.group_id}'")
            for node_idx in self.tree.direct_path(leaf_idx):
                self._node_keys.pop(node_idx, None)
            self.tree.remove(member_id)

    def create_update_path(self, updater_leaf: int) -> Tuple[PQUpdatePath, bytes]:
        """
        Generate an MLS Post-Quantum UpdatePath for the updater leaf.
        
        1. Generates fresh leaf path secret S_0.
        2. Climbs the direct path, deriving parent secrets S_{i+1} = HKDF(S_i).
        3. Generates fresh ML-KEM-1024 keypairs for each direct path node.
        4. Encapsulates parent secrets to every copath node in the copath resolution.
        5. Computes the new epoch root secret.
        
        Returns:
            Tuple[PQUpdatePath, new_epoch_secret]
        """
        with self._lock:
            tree_hash_before = self.tree.tree_hash()
            direct_path = self.tree.direct_path(updater_leaf)
            copath = self.tree.copath(updater_leaf)

            if len(direct_path) == 0:
                raise PQTreeKEMError("Empty direct path")

            # 1. Generate fresh leaf secret (PCS healing step)
            current_secret = secrets.token_bytes(32)
            path_nodes: List[PQUpdatePathNode] = []

            # We climb direct_path[1:] (ancestor parent nodes up to root)
            for step_idx, node_idx in enumerate(direct_path[1:]):
                # Derive next path secret up the tree
                step_info = f"PQ_TREEKEM_PATH_STEP_{step_idx}_{node_idx}".encode("utf-8")
                parent_secret = _hkdf_expand_sha3_512(current_secret, step_info, 32)

                # Generate fresh ML-KEM-1024 keypair for this direct-path node
                pk, sk = self.kem.keygen()
                self._node_keys[node_idx] = PQNodeKey(public_key=pk, secret_key=sk, path_secret=parent_secret)
                # Advance our OWN tree view (committer applies immediately,
                # RFC 9420 shape): receivers apply the same pubs, so all
                # sides' tree hashes stay identical for agreement checks.
                self.tree.set_node_pub(node_idx, pk)

                # Resolve the copath node at this height
                copath_ciphertexts: Dict[int, bytes] = {}
                if step_idx < len(copath):
                    copath_node_idx = copath[step_idx]
                    resolution = self.tree.resolution_of(copath_node_idx)
                    for target_node in resolution:
                        target_key = self._node_keys.get(target_node)
                        if target_key and target_key.public_key:
                            # Encapsulate the parent secret to the copath target node
                            ct, ss = self.kem.encaps(target_key.public_key)
                            # Mask parent_secret with shared secret using SHA3-512
                            mask = hashlib.sha3_512(ss + b"::PQ_TREEKEM_SECRET_MASK::").digest()[:32]
                            masked_secret = bytes(a ^ b for a, b in zip(parent_secret, mask))
                            # Package CT || masked_secret
                            copath_ciphertexts[target_node] = ct + masked_secret

                path_nodes.append(
                    PQUpdatePathNode(
                        node_index=node_idx,
                        public_key=pk,
                        copath_ciphertexts=copath_ciphertexts,
                    )
                )
                current_secret = parent_secret

            # Root path secret mixes into the new epoch secret
            root_secret = current_secret
            new_epoch_secret = _hkdf_expand_sha3_512(
                self.epoch_secret,
                b"PQ_MLS_EPOCH_UPDATE::" + root_secret,
                32
            )
            self.epoch_secret = new_epoch_secret
            self.current_epoch += 1

            update_path = PQUpdatePath(
                updater_leaf=updater_leaf,
                updater_id=self.local_member_id,
                nodes=path_nodes,
                epoch_id=self.current_epoch,
                tree_hash_before=tree_hash_before,
            )
            return update_path, new_epoch_secret

    def apply_update_path(self, updater_leaf: int, update_path: PQUpdatePath) -> bytes:
        """
        Process an incoming PQUpdatePath from another group member.

        1. Finds the copath node where local member intersects the updater's direct path.
        2. Decapsulates the parent secret with local secret key.
        3. Climbs remaining steps up to the root, deriving the exact same root secret.
        4. Updates local tree public keys along updater's direct path.

        Fail-closed gates (evaluated BEFORE any state mutation):
        - Epoch MUST equal current+1 exactly. Skipped epochs cannot be
          processed (their fresh entropy is unknown), and replayed old
          updates MUST NOT roll the epoch secret backward (forward
          secrecy depends on monotonicity).
        - tree_hash_before MUST match the local tree (stale/forked views
          refused; prevents cross-fork application).
        - Caller MUST have authenticated the updater out-of-band: this
          method verifies structure and cryptography, not authorship.

        Returns:
            bytes: The synchronized new_epoch_secret.
        """
        with self._lock:
            local_leaf = self.tree.members().get(self.local_member_id)
            if local_leaf is None:
                raise PQTreeKEMError(f"Local member '{self.local_member_id}' not in tree")

            if local_leaf == updater_leaf:
                # Local member was updater: epoch already updated
                return self.epoch_secret

            if update_path.epoch_id != self.current_epoch + 1:
                raise PQTreeKEMError(
                    f"stale/future update epoch {update_path.epoch_id} "
                    f"(current {self.current_epoch}; exactly +1 required)")
            if update_path.tree_hash_before != self.tree.tree_hash():
                raise PQTreeKEMError(
                    "update tree hash mismatch (stale view or forked tree)")

            updater_direct_path = self.tree.direct_path(updater_leaf)
            local_direct_path = set(self.tree.direct_path(local_leaf))

            # Find the intersection node where local path meets updater direct path
            intersection_node: Optional[int] = None
            for n in updater_direct_path:
                if n in local_direct_path:
                    intersection_node = n
                    break

            if intersection_node is None:
                raise PQTreeKEMError("No intersection found between local member and updater path")

            # Locate the update path node corresponding to intersection
            target_update_node: Optional[PQUpdatePathNode] = None
            for pnode in update_path.nodes:
                if pnode.node_index == intersection_node:
                    target_update_node = pnode
                    break

            if target_update_node is None:
                raise PQTreeKEMError(f"UpdatePath missing intersection node {intersection_node}")

            # Identify which local node key can decrypt from the copath ciphertexts
            decapsulated_secret: Optional[bytes] = None
            for copath_target, payload in target_update_node.copath_ciphertexts.items():
                local_key = self._node_keys.get(copath_target)
                if local_key and local_key.secret_key:
                    # Parse CT (1568 bytes) + masked_secret (32 bytes)
                    ct = payload[:self.kem.ct_size]
                    masked = payload[self.kem.ct_size:]
                    ss = self.kem.decaps(local_key.secret_key, ct)
                    mask = hashlib.sha3_512(ss + b"::PQ_TREEKEM_SECRET_MASK::").digest()[:32]
                    decapsulated_secret = bytes(a ^ b for a, b in zip(masked, mask))
                    break

            if decapsulated_secret is None:
                raise PQTreeKEMError("Failed to decapsulate parent secret: no matching copath private key")

            # Climb from intersection node up to the root
            current_secret = decapsulated_secret
            remaining_nodes = updater_direct_path[updater_direct_path.index(intersection_node) + 1:]
            
            # Update public keys and derive remaining path secrets.
            # Tree pubs advance on BOTH sides (committer in create,
            # receiver here) so tree hashes stay identical everywhere.
            self._node_keys[intersection_node] = PQNodeKey(
                public_key=target_update_node.public_key,
                path_secret=current_secret
            )
            self.tree.set_node_pub(intersection_node, target_update_node.public_key)

            for step_idx, node_idx in enumerate(remaining_nodes):
                step_info = f"PQ_TREEKEM_PATH_STEP_{updater_direct_path.index(node_idx) - 1}_{node_idx}".encode("utf-8")
                current_secret = _hkdf_expand_sha3_512(current_secret, step_info, 32)
                # Find matching update node public key
                for pnode in update_path.nodes:
                    if pnode.node_index == node_idx:
                        self._node_keys[node_idx] = PQNodeKey(
                            public_key=pnode.public_key,
                            path_secret=current_secret
                        )
                        self.tree.set_node_pub(node_idx, pnode.public_key)
                        break

            # Derive identical epoch secret
            root_secret = current_secret
            new_epoch_secret = _hkdf_expand_sha3_512(
                self.epoch_secret,
                b"PQ_MLS_EPOCH_UPDATE::" + root_secret,
                32
            )
            self.epoch_secret = new_epoch_secret
            self.current_epoch = update_path.epoch_id
            return new_epoch_secret
