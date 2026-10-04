#!/usr/bin/env python3
"""Gates for treekem.py: structure, blanking, resolution, paths, tree hash.

Fast, no network, no hardware. Research basis: RFC 9420 §4.1 (nodes,
resolution, paths), §7.7-§7.8 (add/remove, tree hashes), App C (array
indexing: leaf n at 2n).
"""
import pytest

from treekem import MAX_TREE_LEAVES, RatchetTree, TreeError


def _tree4():
    t = RatchetTree(width=4)
    for i, m in enumerate(("alice", "bob", "carol", "dave")):
        t.add(m, bytes([i + 1]) * 32)
    return t


def test_leaf_array_indexing_app_c():
    t = RatchetTree(width=8)
    assert [i for i, _ in t.to_array()] == list(range(15))  # nosec: B101
    # Leaf n at array index 2n.
    for n in range(8):
        assert t.direct_path(n)[0] == 2 * n  # nosec: B101
    # 8-leaf root at array index 7.
    assert t.direct_path(0)[-1] == 7  # nosec: B101


def test_singleton_and_empty_shapes():
    t = RatchetTree()
    assert t.cover() == []  # blank root resolves empty  # nosec: B101
    assert t.tree_hash() == RatchetTree().tree_hash()  # deterministic  # nosec: B101
    t.add("solo", b"\x01" * 32)
    assert t.cover() == [0]  # only leaf  # nosec: B101
    assert t.direct_path(0) == [0]  # nosec: B101
    assert t.copath(0) == []  # nosec: B101


def test_full_tree_cover_is_single_root():
    # Blank parents (no update path yet): cover fans out to occupied leaves.
    t = _tree4()
    assert t.cover() == [0, 2, 4, 6]  # nosec: B101
    # Populated root (update-path keys arrived): single cover target.
    t2 = RatchetTree(width=4)
    for i, m in enumerate(("alice", "bob", "carol", "dave")):
        t2.add(m, bytes([i + 1]) * 32, parent_pub=b"P" * 32)
    assert t2.cover() == [3]  # width-4 root at array index 3  # nosec: B101
    assert t2.resolution_of(3) == [3]  # nosec: B101


def test_remove_blanks_path_and_excludes_cover():
    t = _tree4()
    h0 = t.tree_hash()
    freed = t.remove("bob")
    assert freed == 1  # nosec: B101
    assert t.tree_hash() != h0  # removal is hash-visible  # nosec: B101
    cover = t.cover()
    assert 2 not in cover  # bob's leaf (array 2) no longer a target  # nosec: B101
    assert t.members() == {"alice": 0, "carol": 2, "dave": 3}  # nosec: B101
    # Re-add fills the freed (leftmost blank) leaf.
    assert t.add("erin", b"\x09" * 32) == 1  # nosec: B101
    assert t.members()["erin"] == 1  # nosec: B101


def test_copath_and_filtered_path_shapes():
    t = _tree4()
    # Leaf 0 (array 0): path 0 -> 1 -> 3; copath [2, 5].
    assert t.direct_path(0) == [0, 1, 3]  # nosec: B101
    assert t.copath(0) == [2, 5]  # nosec: B101
    # Fully populated: filtered path keeps every parent.
    assert t.filtered_direct_path(0) == [1, 3]  # nosec: B101


def test_rotate_blanks_path_keeps_leaf():
    t = _tree4()
    h0 = t.tree_hash()
    t.rotate("alice", b"\xaa" * 32)
    assert t.members()["alice"] == 0  # still occupies the leaf  # nosec: B101
    assert t.tree_hash() != h0  # nosec: B101
    # Path above the leaf is blank: root no longer directly resolvable.
    assert t.cover() != [3]  # nosec: B101


def test_growth_doubles_and_preserves():
    t = RatchetTree(width=2)
    t.add("a", b"\x01" * 32)
    t.add("b", b"\x02" * 32)
    h_full = t.tree_hash()
    assert t.add("c", b"\x03" * 32) == 2  # first leaf of grown half  # nosec: B101
    assert t.width == 4  # nosec: B101
    assert t.members() == {"a": 0, "b": 1, "c": 2}  # nosec: B101
    assert t.tree_hash() != h_full  # nosec: B101


def test_validation_fail_closed():
    t = _tree4()
    with pytest.raises(TreeError):
        t.add("alice", b"\x01" * 32)  # duplicate
    with pytest.raises(TreeError):
        t.remove("ghost")  # unknown
    with pytest.raises(TreeError):
        t.rotate("ghost", b"\x01" * 32)
    with pytest.raises(TreeError):
        t.add("", b"\x01" * 32)
    with pytest.raises(TreeError):
        t.add("x", b"")
    with pytest.raises(TreeError):
        RatchetTree(width=3)  # not a power of two
    with pytest.raises(TreeError):
        RatchetTree(width=2 * MAX_TREE_LEAVES + 2)


def test_tree_hash_binds_keys_and_positions():
    t1, t2 = _tree4(), _tree4()
    assert t1.tree_hash() == t2.tree_hash()  # same ops, same hash  # nosec: B101
    t2.remove("dave")
    t2.add("dave", b"\xff" * 32)  # same position, different key
    assert t1.tree_hash() != t2.tree_hash()  # key change is hash-visible  # nosec: B101

