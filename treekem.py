#!/usr/bin/env python3
"""treekem.py — ratchet-tree STRUCTURE skeleton (TreeKEM foundation, T3-J).

Research basis: RFC 9420 §4 (ratchet-tree concepts), §7.6-§7.8
(update paths / add-remove / tree hashes), Appendix C (array indexing).

What this IS: a left-grown binary tree with RFC-shaped blanking,
resolution, direct path / copath / filtered direct path, cover sets,
and a recursive tree hash. Widths are powers of two (extra leaves are
first-class BLANK leaves, as in the RFC); capacity matches the group
layer (256 members max).

What this IS NOT (honest limits):
- NOT an integrated TreeKEM yet: node values are OPAQUE key bytes
  supplied by the caller; there is no HPKE, no UpdatePath secret
  derivation, no key schedule. Group encryption still fans out via
  GroupKeyManager pairwise envelopes. The integration point is
  ``cover()``: the resolution of the root is the minimal set of nodes
  whose keys collectively reach every occupied leaf -- the target set
  a future HPKE update path will encrypt to (O(log n) instead of O(n)).
- The tree-hash encoding is LOCAL and canonical (length-framed,
  SHA3-512, ``TK*`` domain labels), NOT RFC TLS-serialization
  byte-exact. It binds the same properties (occupancy, keys bound to
  positions, blank structure) for fork detection between two nodes
  running THIS code -- never presented as RFC wire interop.
- No Delivery Service, no concurrency beyond a single RLock.

Index model (RFC App C): leaf *n* lives at array index 2*n;
parent=01x has left=00x, right=10x. The implementation keeps a
recursive object tree and flattens to array order only for
introspection (``to_array``); all operations are structural.
"""

from __future__ import annotations

import hashlib
import struct
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

MAX_TREE_LEAVES = 256  # matches GroupKeyManager.MAX_MEMBERS_PER_GROUP.


class TreeError(Exception):
    """Base error for ratchet-tree operations (fail-closed throughout)."""


def _pack_blob(data: bytes) -> bytes:
    if len(data) > 0xFFFFFF:
        raise TreeError("blob too large")
    return struct.pack(">I", len(data)) + bytes(data)


@dataclass
class TreeNode:
    """One tree node. ``pub`` None == BLANK (RFC §4.1.1)."""
    leaf_index: Optional[int] = None  # set for leaves only
    member_id: str = ""               # leaves only; "" == unassigned
    pub: Optional[bytes] = None       # opaque node key; None == blank
    left: Optional["TreeNode"] = None
    right: Optional["TreeNode"] = None
    unmerged: List[int] = field(default_factory=list)  # leaf indices (parents)

    @property
    def is_leaf(self) -> bool:
        return self.left is None and self.right is None

    @property
    def blank(self) -> bool:
        return self.pub is None


class RatchetTree:
    """Left-grown binary ratchet tree (structure only)."""

    def __init__(self, width: int = 1) -> None:
        if width < 1 or width > MAX_TREE_LEAVES or (width & (width - 1)):
            raise TreeError("width must be a power of two in 1..256")
        self._lock = threading.RLock()
        self._width = width
        self._root = self._build_full(0, width)
        self._members: Dict[str, int] = {}  # member_id -> leaf index

    # -- construction -------------------------------------------------
    @staticmethod
    def _build_full(start: int, count: int) -> TreeNode:
        if count == 1:
            return TreeNode(leaf_index=start)
        half = count // 2
        return TreeNode(
            left=RatchetTree._build_full(start, half),
            right=RatchetTree._build_full(start + half, half),
        )

    # -- navigation ---------------------------------------------------
    def _leaf(self, index: int) -> TreeNode:
        node = self._root
        lo, hi = 0, self._width
        while not node.is_leaf:
            mid = (lo + hi) // 2
            if index < mid:
                node, hi = node.left, mid
            else:
                node, lo = node.right, mid
        if node.leaf_index != index:  # explicit: no asserts in library code
            raise TreeError("tree navigation invariant violated")
        return node

    def _path_nodes(self, index: int) -> List[TreeNode]:
        """Direct path LEAF -> ROOT inclusive (leaf first)."""
        nodes = [self._leaf(index)]
        node = self._root
        lo, hi = 0, self._width
        stack = [node]
        while not node.is_leaf:
            mid = (lo + hi) // 2
            if index < mid:
                node, hi = node.left, mid
            else:
                node, lo = node.right, mid
            stack.append(node)
        # stack is ROOT..LEAF; reverse to LEAF..ROOT, dedupe leaf.
        nodes.extend(reversed(stack[:-1]))
        return nodes

    def _sibling(self, node: TreeNode, parent: TreeNode) -> TreeNode:
        return parent.right if parent.left is node else parent.left

    def direct_path(self, index: int) -> List[int]:
        """Array indices on the leaf->root path (leaf first, RFC §4.1.2)."""
        return [self._array_index(n) for n in self._path_nodes(index)]

    def copath(self, index: int) -> List[int]:
        """Siblings along the direct path, leaf level first (RFC §4.1.2)."""
        path = self._path_nodes(index)
        out: List[int] = []
        for child, parent in zip(path[:-1], path[1:]):
            out.append(self._array_index(self._sibling(child, parent)))
        return out

    def filtered_direct_path(self, index: int) -> List[int]:
        """Direct path minus parents whose copath child resolves empty."""
        path = self._path_nodes(index)
        out: List[int] = []
        for child, parent in zip(path[:-1], path[1:]):
            sib = self._sibling(child, parent)
            if self._resolution(sib):
                out.append(self._array_index(parent))
        return out

    # -- resolution / cover (RFC §4.1.1) -------------------------------
    def _resolution(self, node: TreeNode) -> List[TreeNode]:
        if not node.blank:
            return [node] + [self._leaf(i) for i in node.unmerged]
        if node.is_leaf:
            return []
        return self._resolution(node.left) + self._resolution(node.right)

    def resolution_of(self, array_index: int) -> List[int]:
        """Array indices resolving a node (depth-first, left-first)."""
        return [self._array_index(n) for n in self._resolution(self._by_array(array_index))]

    def cover(self) -> List[int]:
        """Resolution of the root: minimal encryption-target set.

        Fully populated tree -> [root] (one target). With blanks, the
        targets fan out only over occupied subtrees -- the shape a
        future HPKE update path encrypts to.
        """
        with self._lock:
            return [self._array_index(n) for n in self._resolution(self._root)]

    def set_node_pub(self, array_index: int, pub: bytes) -> None:
        """Install a fresh public key on a direct-path node (committer
        view update, RFC 9420 §7.6 shape).

        Used by update-path creators to advance their OWN tree view so
        committer and receiver trees stay structurally identical (a
        precondition for tree-hash agreement checks). Only non-leaf
        nodes may be set (leaf identity keys rotate via remove/add);
        blank leaves are never filled this way. Empty pubs rejected.
        """
        if not isinstance(pub, (bytes, bytearray)) or not pub:
            raise TreeError("node pub must be non-empty bytes")
        with self._lock:
            node = self._by_array(array_index)
            if node.is_leaf:
                raise TreeError("leaf keys rotate via remove/add, not set_node_pub")
            node.pub = bytes(pub)
            node.unmerged = []

    # -- array view (RFC App C) ----------------------------------------
    def _array_index(self, node: TreeNode) -> int:
        if node.is_leaf:
            return 2 * node.leaf_index
        # parent: find via structural walk (widths are tiny; clarity first).
        for idx in range(1, 2 * self._width - 1, 2):
            if self._by_array(idx) is node:
                return idx
        raise TreeError("node not in tree")

    def _by_array(self, idx: int) -> TreeNode:
        if idx % 2 == 0:
            leaf = idx // 2
            if leaf >= self._width:
                raise TreeError("array index out of range")
            return self._leaf(leaf)
        # odd: walk parents.
        found: List[TreeNode] = []

        def _walk(n: TreeNode, my_idx: int) -> None:
            if my_idx == idx:
                found.append(n)
                return
            if not n.is_leaf:
                size = self._subtree_leaves(n) // 2
                _walk(n.left, my_idx - size)
                _walk(n.right, my_idx + size)

        _walk(self._root, self._width - 1)
        if not found:
            raise TreeError("array index out of range")
        return found[0]

    @staticmethod
    def _subtree_leaves(node: TreeNode) -> int:
        if node.is_leaf:
            return 1
        return (RatchetTree._subtree_leaves(node.left)
                + RatchetTree._subtree_leaves(node.right))

    def to_array(self) -> List[Tuple[int, Optional[str]]]:
        """Array-order snapshot: (index, member_id|None). Blanks -> None."""
        out: List[Tuple[int, Optional[str]]] = []
        for idx in range(2 * self._width - 1):
            n = self._by_array(idx)
            out.append((idx, n.member_id if n.is_leaf and n.member_id else None))
        return out

    # -- membership ----------------------------------------------------
    @property
    def width(self) -> int:
        return self._width

    def members(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._members)

    def _blank_path(self, index: int) -> None:
        """Blank leaf + every node on its direct path (T3-J).

        A removed/rotated leaf's keys are dead: path secrets MUST be
        refreshed before the nodes carry keys again. Blanking (not
        deleting) preserves positions so transcripts stay comparable.
        """
        for node in self._path_nodes(index):
            node.pub = None
            node.unmerged = []
            if node.is_leaf:
                node.member_id = ""

    def add(self, member_id: str, leaf_pub: bytes, parent_pub: Optional[bytes] = None) -> int:
        """Occupy the leftmost blank leaf (growing the tree if full).

        Returns the leaf index. New parents created by growth start
        BLANK (their secrets arrive via the committer's update path).
        """
        # Fuzz-found (2026-09-23): non-str ids (int/bytes/None) slipped
        # past truthiness into member maps and exploded later with
        # AttributeError. Boundary enforces str-only, fail-closed.
        if not isinstance(member_id, str) or not member_id or len(member_id) > 256:
            raise TreeError("member_id must be a non-empty str (<=256)")
        if not isinstance(leaf_pub, (bytes, bytearray)) or not leaf_pub:
            raise TreeError("leaf_pub must be non-empty bytes")
        with self._lock:
            if member_id in self._members:
                raise TreeError(f"member already in tree: {member_id!r}")
            target = None
            for idx in range(self._width):
                leaf = self._leaf(idx)
                if leaf.blank and not leaf.member_id:
                    target = idx
                    break
            if target is None:
                self._grow()
                target = self._width // 2  # first leaf of the new right half
            leaf = self._leaf(target)
            leaf.pub = bytes(leaf_pub)
            leaf.member_id = member_id
            if parent_pub is not None:
                for node in self._path_nodes(target)[1:]:
                    if node.blank:
                        node.pub = bytes(parent_pub)
                        break
            self._members[member_id] = target
            return target

    def _grow(self) -> None:
        if self._width * 2 > MAX_TREE_LEAVES:
            raise TreeError("tree at maximum width (256 leaves)")
        new_width = self._width * 2
        new_root = TreeNode(left=self._root,
                            right=self._build_full(self._width, self._width))
        self._root = new_root
        self._width = new_width

    def remove(self, member_id: str) -> int:
        """Blank a member's leaf + direct path. Returns the freed index."""
        with self._lock:
            if member_id not in self._members:
                raise TreeError(f"member not in tree: {member_id!r}")
            idx = self._members.pop(member_id)
            self._blank_path(idx)
            return idx

    def rotate(self, member_id: str, new_pub: bytes) -> int:
        """Self-update marker (RFC §7.6 shape, structure only): re-key the
        leaf and blank the direct path above it (fresh path secrets must
        arrive via the committer's update path)."""
        if not isinstance(new_pub, (bytes, bytearray)) or not new_pub:
            raise TreeError("new_pub must be non-empty bytes")
        with self._lock:
            if member_id not in self._members:
                raise TreeError(f"member not in tree: {member_id!r}")
            idx = self._members[member_id]
            path = self._path_nodes(idx)
            path[0].pub = bytes(new_pub)
            for node in path[1:]:
                node.pub = None
                node.unmerged = []
            return idx

    # -- tree hash (local canonical, SHA3-512) ---------------------------
    def _hash_node(self, node: TreeNode) -> bytes:
        h = hashlib.sha3_512()
        if node.is_leaf:
            if node.blank:
                h.update(b"TKLEAF-BLANK:")
                h.update(struct.pack(">I", node.leaf_index))
            else:
                h.update(b"TKLEAF:")
                h.update(struct.pack(">I", node.leaf_index))
                h.update(_pack_blob(node.member_id.encode("utf-8")))
                h.update(_pack_blob(bytes(node.pub)))
        else:
            left_h = self._hash_node(node.left)
            right_h = self._hash_node(node.right)
            if node.blank:
                h.update(b"TKPARENT-BLANK:")
            else:
                h.update(b"TKPARENT:")
                h.update(_pack_blob(bytes(node.pub)))
            h.update(left_h)
            h.update(right_h)
        return h.digest()

    def tree_hash(self) -> bytes:
        """Recursive tree hash of the root (fork detection between peers
        running THIS code; NOT RFC wire byte-exact -- see header)."""
        with self._lock:
            return self._hash_node(self._root)
