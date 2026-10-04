"""Tier-3 group receive path + compartment enforcement (G3/MLS research).

Research basis: RFC 9420 (TreeKEM/epochs/transcript), ETK/EUROCRYPT-2026
(external commits weaken PCS -- refused here; SUF-CMA signatures required
-- ML-DSA-87 qualifies).

Covers:
  T3.1 apply_remote_commit:
  1. Symmetric sync: two managers applying the same signed commit agree
     on members/epoch/transcript AND interoperate on envelopes.
  2. External committer (non-member) refused.
  3. Stale epoch replay refused; epoch jump refused.
  4. Forked prev_tx refused.
  5. Unsigned proposals: lab warns+applies; strict refuses.
  6. Present-but-invalid signature always refused (even lab).
  7. Remove path rotates + drops target.
  T3.2 compartments:
  8. Clearance validation (bad level/compartment/non-member).
  9. Dominance matrix (level/compartment allow + deny cases).
  10. Label strip/tamper fails MAC; stale-epoch label fails.
  11. No-clearance member denied labeled, allowed unlabeled traffic.
  12. Removal drops clearance (no inheritance on re-add).

Fast, deterministic, no network. Requires native liboqs (oqs.dll).
"""

import pytest

from group_key_manager import (
    GroupAccessDenied,
    GroupExistsError,
    GroupKeyError,
    GroupKeyManager,
    GroupLockedError,
    GroupMembershipError,
    KIND_ADD,
    KIND_REMOVE,
)
from mls_framing import Commit, KeyPackage, Proposal


@pytest.fixture(scope="module")
def dsa():
    from liboqs_wrapper import LibOQS_MLDSA_87
    return LibOQS_MLDSA_87()


@pytest.fixture(scope="module")
def alice_keys(dsa):
    pk, sk = dsa.keygen()
    return bytes(pk), bytes(sk)


def _verify_cb(dsa):
    def _cb(pub, msg, sig):
        return bool(dsa.verify(bytes(pub), bytes(msg), bytes(sig)))
    return _cb


def _pair(alice_keys):
    """Two managers with identical epoch-0 state (deterministic genesis)."""
    apk, _ = alice_keys
    a, b = GroupKeyManager(), GroupKeyManager()
    for mgr in (a, b):
        mgr.create_group("g", ["alice", "bob"])
    return a, b, apk


def _signed_add(dsa, sk, member):
    prop = Proposal(kind=KIND_ADD, member_id=member)
    prop.sig = bytes(dsa.sign(sk, prop.encode_unsigned()))
    return prop


def _commit_for(tx0, epoch, proposals):
    return Commit(epoch=epoch, prev_tx=bytes(tx0),
                  proposals=list(proposals)).encode()


def test_symmetric_sync_and_interop(dsa, alice_keys):
    apk, ask = alice_keys
    a, b, _ = _pair(alice_keys)
    tx0 = a.transcript_of("g")
    prop = _signed_add(dsa, ask, "carol")
    wire = _commit_for(tx0, 1, [prop])
    key1 = b"K" * 32
    assert a.apply_remote_commit("g", wire, "alice", key1, apk,  # nosec: B101
                                 _verify_cb(dsa)) == 1
    assert b.apply_remote_commit("g", wire, "alice", key1, apk,  # nosec: B101
                                 _verify_cb(dsa)) == 1
    assert a.members_of("g") == b.members_of("g") == ["alice", "bob", "carol"]  # nosec: B101
    assert a.transcript_of("g") == b.transcript_of("g")  # nosec: B101
    # Cross-manager envelope interop on the agreed epoch key.
    sealed = a.encrypt_for_group("g", b"enclave-wide")
    ct = sealed["envelopes"]["bob"]
    assert b.decrypt_from_group("g", ct, 1, member_id="bob") == b"enclave-wide"  # nosec: B101


def test_external_committer_refused(dsa, alice_keys):
    apk, ask = alice_keys
    a, _, _ = _pair(alice_keys)
    tx0 = a.transcript_of("g")
    prop = _signed_add(dsa, ask, "mallory")
    wire = _commit_for(tx0, 1, [prop])
    with pytest.raises(GroupMembershipError):
        a.apply_remote_commit("g", wire, "mallory", b"K" * 32, apk,
                              _verify_cb(dsa))


def test_stale_jump_and_fork_rejected(dsa, alice_keys):
    apk, ask = alice_keys
    a, _, _ = _pair(alice_keys)
    tx0 = a.transcript_of("g")
    prop = _signed_add(dsa, ask, "carol")
    wire = _commit_for(tx0, 1, [prop])
    a.apply_remote_commit("g", wire, "alice", b"K" * 32, apk, _verify_cb(dsa))
    # Replay same commit (stale epoch).
    with pytest.raises(GroupKeyError):
        a.apply_remote_commit("g", wire, "alice", b"K" * 32, apk,
                              _verify_cb(dsa))
    # Epoch jump (current+2).
    prop2 = _signed_add(dsa, ask, "dave")
    with pytest.raises(GroupKeyError):
        a.apply_remote_commit("g", _commit_for(tx0, 3, [prop2]), "alice",
                              b"K" * 32, apk, _verify_cb(dsa))
    # Forked transcript.
    prop3 = _signed_add(dsa, ask, "erin")
    with pytest.raises(GroupKeyError):
        a.apply_remote_commit("g", _commit_for(b"\x00" * 64, 2, [prop3]),
                              "alice", b"K" * 32, apk, _verify_cb(dsa))


def test_unsigned_policy_lab_vs_strict(dsa, alice_keys, monkeypatch):
    apk, ask = alice_keys
    a, _, _ = _pair(alice_keys)
    tx0 = a.transcript_of("g")
    bare = Proposal(kind=KIND_ADD, member_id="carol")  # no sig
    wire = _commit_for(tx0, 1, [bare])
    # Lab default: warn + apply.
    monkeypatch.delenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", raising=False)
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    assert a.apply_remote_commit("g", wire, "alice", b"K" * 32, apk,  # nosec: B101
                                 _verify_cb(dsa)) == 1
    # Strict: unsigned refused even with a verify callback present.
    b, _, _ = _pair(alice_keys)
    monkeypatch.setenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "1")
    with pytest.raises(GroupKeyError):
        b.apply_remote_commit("g", wire, "alice", b"K" * 32, apk,
                              _verify_cb(dsa))


def test_invalid_sig_always_refused(dsa, alice_keys, monkeypatch):
    apk, ask = alice_keys
    a, _, _ = _pair(alice_keys)
    tx0 = a.transcript_of("g")
    prop = _signed_add(dsa, ask, "carol")
    bad = bytearray(prop.sig)
    bad[0] ^= 0x01
    prop.sig = bytes(bad)
    wire = _commit_for(tx0, 1, [prop])
    monkeypatch.delenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", raising=False)
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    with pytest.raises(GroupKeyError):
        a.apply_remote_commit("g", wire, "alice", b"K" * 32, apk,
                              _verify_cb(dsa))


def test_remove_rotates_and_drops_target(dsa, alice_keys):
    apk, ask = alice_keys
    a, b, _ = _pair(alice_keys)
    a.set_clearance("g", "bob", "SECRET", ("SIERRA",))
    tx0 = a.transcript_of("g")
    prop = Proposal(kind=KIND_REMOVE, member_id="bob")
    prop.sig = bytes(dsa.sign(ask, prop.encode_unsigned()))
    wire = _commit_for(tx0, 1, [prop])
    key1 = b"R" * 32
    for mgr in (a, b):
        assert mgr.apply_remote_commit("g", wire, "alice", key1, apk,  # nosec: B101
                                       _verify_cb(dsa)) == 1
        assert mgr.members_of("g") == ["alice"]  # nosec: B101
    # Bob's clearance died with membership on both sides.
    with pytest.raises(GroupAccessDenied):
        b.open_labeled("g", {"group_id": "g", "epoch": 1,
                             "label": {"classification": "UNCLASSIFIED",
                                       "compartments": []},
                             "label_mac": "00" * 48, "inner": {}},
                       "bob")


def test_clearance_validation():
    mgr = GroupKeyManager()
    mgr.create_group("g", ["alice"])
    with pytest.raises(GroupMembershipError):
        mgr.set_clearance("g", "alice", "ULTRA-SECRET", ())
    with pytest.raises(GroupMembershipError):
        mgr.set_clearance("g", "alice", "SECRET", ("bad compartment!",))
    with pytest.raises(GroupMembershipError):
        mgr.set_clearance("g", "ghost", "SECRET", ())
    mgr.set_clearance("g", "alice", "TOP SECRET", ("SIERRA", "FOXTROT"))


def test_dominance_matrix():
    mgr = GroupKeyManager()
    mgr.create_group("g", ["alice", "bob"])
    mgr.set_clearance("g", "alice", "TOP SECRET", ("SIERRA", "FOXTROT"))
    mgr.set_clearance("g", "bob", "SECRET", ("SIERRA",))
    top = mgr.seal_labeled("g", b"eyes-only", "TOP SECRET", ("SIERRA",))
    assert mgr.open_labeled("g", top, "alice") == b"eyes-only"  # nosec: B101
    with pytest.raises(GroupAccessDenied):  # level too low
        mgr.open_labeled("g", top, "bob")
    sec = mgr.seal_labeled("g", b"wide", "SECRET", ("SIERRA",))
    assert mgr.open_labeled("g", sec, "bob") == b"wide"  # nosec: B101
    foxtrot = mgr.seal_labeled("g", b"fox", "SECRET", ("FOXTROT",))
    with pytest.raises(GroupAccessDenied):  # missing compartment
        mgr.open_labeled("g", foxtrot, "bob")
    assert mgr.open_labeled("g", foxtrot, "alice") == b"fox"  # nosec: B101


def test_label_strip_and_stale_epoch_fail():
    import copy
    mgr = GroupKeyManager()
    mgr.create_group("g", ["alice"])
    mgr.set_clearance("g", "alice", "TOP SECRET", ("SIERRA",))
    sealed = mgr.seal_labeled("g", b"data", "TOP SECRET", ("SIERRA",))
    stripped = copy.deepcopy(sealed)
    stripped["label"] = {"classification": "UNCLASSIFIED", "compartments": []}
    with pytest.raises(GroupAccessDenied):
        mgr.open_labeled("g", stripped, "alice")
    mgr.rotate("g")  # epoch moves on; old label bound to old epoch
    with pytest.raises(GroupKeyError):
        mgr.open_labeled("g", sealed, "alice")


def test_unlabeled_compat_and_no_clearance_deny():
    mgr = GroupKeyManager()
    mgr.create_group("g", ["alice", "bob"])
    # No clearances registered: unlabeled traffic flows as before.
    sealed = mgr.encrypt_for_group("g", b"plain")
    assert mgr.decrypt_from_group("g", sealed["envelopes"]["alice"], 0,  # nosec: B101
                                  member_id="alice") == b"plain"
    # ...but labeled traffic is denied without clearance.
    mgr.set_clearance("g", "alice", "SECRET", ())
    lab = mgr.seal_labeled("g", b"s", "SECRET", ())
    with pytest.raises(GroupAccessDenied):
        mgr.open_labeled("g", lab, "bob")


# ------------------------------------------------------------------
# Tier-3 v2f: tree integration + chained schedule (T3-K)
# ------------------------------------------------------------------

def test_tree_mirror_agreement_and_fork(dsa, alice_keys):
    apk, ask = alice_keys
    a, b, _ = _pair(alice_keys)
    # Genesis mirrors agree structurally.
    assert a.tree_hash_of("g") == b.tree_hash_of("g")  # nosec: B101
    assert len(a.tree_hash_of("g")) == 64  # nosec: B101
    # Same commits -> same tree on both sides (agreement channel).
    prop = _signed_prop(dsa, ask, KIND_ADD, "carol")
    wire = _commit_for(a.transcript_of("g"), 1, [prop])
    for mgr in (a, b):
        assert mgr.apply_remote_commit("g", wire, "alice", b"K" * 32, apk,  # nosec: B101
                                       _verify_cb(dsa)) == 1
    assert a.tree_hash_of("g") == b.tree_hash_of("g")  # nosec: B101
    # Divergent roster -> divergent tree hash (fork visible structurally).
    a.remove_member("g", "carol")
    assert a.tree_hash_of("g") != b.tree_hash_of("g")  # nosec: B101
    # Cover set exposed for the HPKE future (informational in v1).
    assert isinstance(b.tree_cover_of("g"), list)  # nosec: B101
    assert len(b.tree_cover_of("g")) >= 1  # nosec: B101


def test_schedule_chains_deterministically(monkeypatch):
    """White-box: with fixed fresh entropy the epoch key is exactly the
    schedule output (proves chaining, not independent randomness)."""
    from group_key_manager import _schedule_epoch_key
    from mls_framing import Commit as _C, DEFAULT_SUITE as _SUITE
    monkeypatch.setattr("secrets.token_bytes", lambda n=32: b"F" * n)
    mgr = GroupKeyManager()
    mgr.create_group("g", ["alice", "bob"])
    prev = bytes(mgr._groups["g"].group_key)
    tx0 = mgr.transcript_of("g")
    assert mgr.rotate("g") == 1  # nosec: B101
    # Predict: rotate emits an empty-proposal suite-pinned commit.
    new_tx = _C(epoch=1, prev_tx=bytes(tx0), proposals=[],
                suite_id=_SUITE).new_transcript()
    expected = _schedule_epoch_key(prev, b"F" * 32, new_tx, _SUITE,
                                   "g", 1, 32)
    assert bytes(mgr._groups["g"].group_key) == expected  # nosec: B101
    assert mgr.transcript_of("g") == new_tx  # nosec: B101


def test_schedule_fs_pcs_properties():
    """Adversarial-key-compromise simulation (white-box key reads)."""
    from group_key_manager import _envelope_aad, _aead_open
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    mgr = GroupKeyManager()
    mgr.create_group("g", ["alice", "bob"])
    sealed0 = mgr.encrypt_for_group("g", b"epoch-zero-secret")
    ct0 = sealed0["envelopes"]["alice"]
    epoch0_key = bytes(mgr._groups["g"].group_key)
    tx0 = mgr.transcript_of("g")
    assert mgr.rotate("g") == 1  # nosec: B101
    epoch1_key = bytes(mgr._groups["g"].group_key)
    assert epoch1_key != epoch0_key  # nosec: B101
    # FS layer 1 (API): stale-epoch envelopes rejected, no history.
    with pytest.raises(GroupKeyError):
        mgr.decrypt_from_group("g", ct0, 0, member_id="alice")
    # FS layer 2 (crypto): epoch-1 ciphertext does not open under the
    # epoch-2 key even with the epoch-1 AAD (keys are unrelated outputs).
    with pytest.raises(GroupKeyError):
        _aead_open(epoch1_key, _envelope_aad("g", 0, "alice"), ct0)
    # PCS: attacker holding the epoch-0 key + all PUBLIC context cannot
    # derive the epoch-1 key (fresh envelope-only entropy is missing).
    from group_key_manager import _schedule_context
    ctx = _schedule_context(mgr._groups["g"].suite_id, "g", 1)
    tx1 = mgr.transcript_of("g")
    candidates = [epoch0_key]
    for ikm in (epoch0_key, epoch0_key + tx1, epoch0_key + tx0,
                epoch0_key + b""):
        for salt in (tx1, b""):
            candidates.append(HKDF(algorithm=hashes.SHA3_512(), length=32,
                                   salt=salt, info=ctx).derive(ikm))
    assert all(c != epoch1_key for c in candidates)  # nosec: B101
    # ...and the stolen epoch-0 key opens nothing current.
    sealed1 = mgr.encrypt_for_group("g", b"epoch-one-secret")
    with pytest.raises(GroupKeyError):
        _aead_open(epoch0_key, _envelope_aad("g", 1, "alice"),
                   sealed1["envelopes"]["alice"])


def test_welcome_tree_hash_enforced(dsa, alice_keys, monkeypatch):
    import copy
    apk, ask = alice_keys
    a, _, _ = _pair(alice_keys)
    prop = _signed_prop(dsa, ask, KIND_ADD, "carol")
    wire = _commit_for(a.transcript_of("g"), 1, [prop])
    assert a.apply_remote_commit("g", wire, "alice", b"K" * 32, apk,  # nosec: B101
                                 _verify_cb(dsa)) == 1
    welcome = a.build_welcome("g", "carol")
    assert "tree_hash" in welcome and "tree_width" in welcome  # nosec: B101
    # Roster tampering against a fixed hash: refused (structure mismatch).
    evil = copy.deepcopy(welcome)
    evil["members"] = ["alice", "bob", "carol", "mallory"]
    with pytest.raises(GroupKeyError):
        GroupKeyManager().join_from_welcome(evil, "carol", b"K" * 32)
    # Hash-less legacy welcome: lab warn-accepts...
    for var in ("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "P2P_PRODUCTION",
                "SECURE_P2P_PRODUCTION"):
        monkeypatch.delenv(var, raising=False)
    legacy = copy.deepcopy(welcome)
    del legacy["tree_hash"]
    j = GroupKeyManager()
    assert j.join_from_welcome(legacy, "carol", b"K" * 32)["epoch"] == 1  # nosec: B101
    # ...strict refuses.
    monkeypatch.setenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "1")
    with pytest.raises(GroupKeyError):
        GroupKeyManager().join_from_welcome(legacy, "carol", b"K" * 32)

def test_contradictory_proposal_lists_refused(dsa, alice_keys):
    from mls_framing import KIND_UPDATE, KIND_REMOVE
    apk, ask = alice_keys
    a, _, _ = _pair(alice_keys)
    tx0 = a.transcript_of("g")
    # ADD + REMOVE for the same member in one commit: refused.
    add = _signed_prop(dsa, ask, KIND_ADD, "carol")
    rem = _signed_prop(dsa, ask, KIND_REMOVE, "carol")
    with pytest.raises(GroupMembershipError):
        a.apply_remote_commit("g", _commit_for(tx0, 1, [add, rem]), "alice",
                              b"K" * 32, apk, _verify_cb(dsa))
    # Double ADD for the same member: refused.
    add2 = _signed_prop(dsa, ask, KIND_ADD, "carol")
    with pytest.raises(GroupMembershipError):
        a.apply_remote_commit("g", _commit_for(tx0, 1, [add, add2]), "alice",
                              b"K" * 32, apk, _verify_cb(dsa))
    # UPDATE + REMOVE for the same member: refused (no refresh-then-evict).
    upd = _signed_prop(dsa, ask, KIND_UPDATE, "bob")
    rem_bob = _signed_prop(dsa, ask, KIND_REMOVE, "bob")
    with pytest.raises(GroupMembershipError):
        a.apply_remote_commit("g", _commit_for(tx0, 1, [upd, rem_bob]),
                              "alice", b"K" * 32, apk, _verify_cb(dsa))
    # State untouched by all three rejections: roster + epoch + transcript.
    assert a.members_of("g") == ["alice", "bob"]  # nosec: B101
    assert a.epoch_of("g") == 0  # nosec: B101
    assert a.transcript_of("g") == tx0  # nosec: B101
    # Distinct members in one commit still apply cleanly.
    add_c = _signed_prop(dsa, ask, KIND_ADD, "carol")
    upd_b = _signed_prop(dsa, ask, KIND_UPDATE, "bob")
    assert a.apply_remote_commit("g", _commit_for(tx0, 1, [add_c, upd_b]),  # nosec: B101
                                 "alice", b"K" * 32, apk,
                                 _verify_cb(dsa)) == 1
    assert sorted(a.members_of("g")) == ["alice", "bob", "carol"]  # nosec: B101


# ------------------------------------------------------------------
# Tier-3 v2d: Welcome / join-from-welcome (T3-H, RFC 9420 §12.4.3 analogue)
# ------------------------------------------------------------------

def test_welcome_join_roundtrip_and_interop(dsa, alice_keys):
    apk, ask = alice_keys
    a, _, _ = _pair(alice_keys)
    # Alice adds carol on her side; carol joins from a welcome + envelope key.
    prop = _signed_prop(dsa, ask, KIND_ADD, "carol")
    wire = _commit_for(a.transcript_of("g"), 1, [prop])
    key1 = b"W" * 32
    assert a.apply_remote_commit("g", wire, "alice", key1, apk,  # nosec: B101
                                 _verify_cb(dsa)) == 1
    welcome = a.build_welcome("g", "carol")
    assert "transcript_hash" in welcome and len(bytes.fromhex(welcome["transcript_hash"])) == 64  # nosec: B101
    assert set(welcome) >= {"v", "group_id", "epoch", "suite_id", "members",  # nosec: B101
                            "tree_width", "tree_hash"}
    assert "ciphertext" not in str(welcome) and "key" not in [k.lower() for k in welcome]  # nosec: B101
    carol = GroupKeyManager()
    res = carol.join_from_welcome(welcome, "carol", key1)
    assert res["epoch"] == 1 and res["members"] == ["alice", "bob", "carol"]  # nosec: B101
    # Joined state agrees: transcript, suite, and live interop.
    assert carol.transcript_of("g") == a.transcript_of("g")  # nosec: B101
    sealed = a.encrypt_for_group("g", b"welcome-to-the-enclave")
    assert carol.decrypt_from_group("g", sealed["envelopes"]["carol"], 1,  # nosec: B101
                                    member_id="carol") == b"welcome-to-the-enclave"
    # Joiner starts clearance-less (labeled traffic denied until granted).
    with pytest.raises(GroupAccessDenied):
        carol.open_labeled("g", {"group_id": "g", "epoch": 1,
                                 "label": {"classification": "UNCLASSIFIED",
                                           "compartments": []},
                                 "label_mac": "00" * 48, "inner": {}},
                           "carol")


def test_welcome_refusals_fail_closed(dsa, alice_keys):
    import copy
    apk, ask = alice_keys
    a, _, _ = _pair(alice_keys)
    # Outsider welcome refused (external joins stay refused).
    with pytest.raises(GroupMembershipError):
        a.build_welcome("g", "mallory")
    welcome = a.build_welcome("g", "alice")
    carol = GroupKeyManager()
    # Unknown/unsupported suite refused at join (downgrade defense).
    evil = copy.deepcopy(welcome)
    evil["suite_id"] = "ML-KEM-768+X25519/hybrid"
    with pytest.raises(GroupKeyError):
        carol.join_from_welcome(evil, "alice", b"K" * 32)
    bogus = copy.deepcopy(welcome)
    bogus["suite_id"] = "nothing/pqc"
    with pytest.raises(GroupKeyError):
        carol.join_from_welcome(bogus, "alice", b"K" * 32)
    # Joiner off-roster, bad key length, malformed transcript refused.
    with pytest.raises(GroupMembershipError):
        carol.join_from_welcome(welcome, "mallory", b"K" * 32)
    with pytest.raises(GroupKeyError):
        carol.join_from_welcome(welcome, "alice", b"short")
    bad_tx = copy.deepcopy(welcome)
    bad_tx["transcript_hash"] = "zz"
    with pytest.raises(GroupKeyError):
        carol.join_from_welcome(bad_tx, "alice", b"K" * 32)
    # Welcome never overwrites live state.
    assert carol.join_from_welcome(welcome, "alice", b"K" * 32)["epoch"] == 0  # nosec: B101
    with pytest.raises(GroupExistsError):
        carol.join_from_welcome(welcome, "alice", b"K" * 32)
    # Locked group refuses to issue welcomes.
    a._groups["g"].locked = True
    try:
        with pytest.raises(GroupLockedError):
            a.build_welcome("g", "alice")
    finally:
        a._groups["g"].locked = False

def _live_kp(member, kem_byte=b"\x03"):
    import time
    from mls_framing import KeyPackage as _KP
    now = int(time.time())
    return _KP(member_id=member, ml_dsa_pub=b"\x01" * 32,
               kem_pub=kem_byte * 16,
               not_before=now - 60, not_after=now + 3600)


def _stale_kp(member):
    import time
    from mls_framing import KeyPackage as _KP
    now = int(time.time())
    return _KP(member_id=member, ml_dsa_pub=b"\x01" * 32,
               kem_pub=b"\x03" * 16,
               not_before=now - 7200, not_after=now - 3600)


def test_publish_registry_shape_and_outsiders():
    from mls_framing import KeyPackage as _KP
    mgr = GroupKeyManager()
    mgr.create_group("g", ["alice", "bob"])
    # Member + outsider (pre-join directory cache) both storable.
    mgr.publish_key_package("g", _live_kp("alice"))
    mgr.publish_key_package("g", _live_kp("carol"))
    reg = mgr.key_packages_of("g")
    assert set(reg) == {"alice", "carol"}  # nosec: B101
    # Presence is NOT membership.
    assert mgr.members_of("g") == ["alice", "bob"]  # nosec: B101
    # Empty keys / non-package rejected (fail-closed advertisement).
    with pytest.raises(GroupMembershipError):
        mgr.publish_key_package("g", _KP(member_id="dave"))
    with pytest.raises(GroupMembershipError):
        mgr.publish_key_package("g", {"member_id": "dave"})
    # Stale package: stored with warning, NOT accepted for strict use
    # (proven by the strict-registry test below).
    mgr.publish_key_package("g", _stale_kp("erin"))
    assert "erin" in mgr.key_packages_of("g")  # nosec: B101


def test_strict_add_enforced_from_registry(dsa, alice_keys, monkeypatch):
    from mls_framing import DEFAULT_SUITE as _SUITE
    apk, ask = alice_keys
    monkeypatch.setenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "1")
    # Stale registry advertisement refuses the ADD in strict mode...
    s, _, _ = _pair(alice_keys)
    s.publish_key_package("g", _stale_kp("carol"))
    prop = _signed_prop(dsa, ask, KIND_ADD, "carol")
    with pytest.raises(GroupMembershipError):
        s.apply_remote_commit(
            "g", _suite_commit_for(s.transcript_of("g"), 1, [prop], _SUITE),
            "alice", b"K" * 32, apk, _verify_cb(dsa))
    # ...while a live one admits it (no explicit arg needed).
    s2, _, _ = _pair(alice_keys)
    s2.publish_key_package("g", _live_kp("carol"))
    prop2 = _signed_prop(dsa, ask, KIND_ADD, "carol")
    assert s2.apply_remote_commit(  # nosec: B101
        "g", _suite_commit_for(s2.transcript_of("g"), 1, [prop2], _SUITE),
        "alice", b"K" * 32, apk, _verify_cb(dsa)) == 1
    assert "carol" in s2.members_of("g")  # nosec: B101


def test_update_binds_new_keys_and_remove_drops_package(dsa, alice_keys):
    from mls_framing import KIND_UPDATE, KIND_REMOVE
    apk, ask = alice_keys
    a, b, _ = _pair(alice_keys)
    a.publish_key_package("g", _live_kp("bob", b"\x03"))
    # Local refresh with a fresh package rotates the registry entry.
    assert a.refresh_member_keys("g", "bob", _live_kp("bob", b"\x04")) == 1  # nosec: B101
    assert a.key_packages_of("g")["bob"].kem_pub == b"\x04" * 16  # nosec: B101
    # Mismatched package binding refused.
    with pytest.raises(GroupMembershipError):
        a.refresh_member_keys("g", "bob", _live_kp("mallory", b"\x05"))
    # Remote UPDATE binds the supplied rotation into the peer registry.
    tx0 = b.transcript_of("g")
    upd = _signed_prop(dsa, ask, KIND_UPDATE, "bob")
    new_pkg = _live_kp("bob", b"\x06")
    assert b.apply_remote_commit(  # nosec: B101
        "g", _commit_for(tx0, 1, [upd]), "alice", b"U" * 32, apk,
        _verify_cb(dsa), key_packages={"bob": new_pkg}) == 1
    assert b.key_packages_of("g")["bob"].kem_pub == b"\x06" * 16  # nosec: B101
    # Bound to the WRONG target: refused.
    tx1 = b.transcript_of("g")
    upd2 = _signed_prop(dsa, ask, KIND_UPDATE, "bob")
    with pytest.raises(GroupMembershipError):
        b.apply_remote_commit(
            "g", _commit_for(tx1, 2, [upd2]), "alice", b"U" * 32, apk,
            _verify_cb(dsa), key_packages={"bob": _live_kp("mallory")})
    # REMOVE drops the advertisement locally and remotely.
    assert a.remove_member("g", "bob") == 2  # nosec: B101
    assert "bob" not in a.key_packages_of("g")  # nosec: B101
    prop = _signed_prop(dsa, ask, KIND_REMOVE, "bob")
    c, _, _ = _pair(alice_keys)
    c.publish_key_package("g", _live_kp("bob"))
    assert c.apply_remote_commit(  # nosec: B101
        "g", _commit_for(c.transcript_of("g"), 1, [prop]), "alice",
        b"R" * 32, apk, _verify_cb(dsa)) == 1
    assert "bob" not in c.key_packages_of("g")  # nosec: B101
    assert "bob" not in c.members_of("g")  # nosec: B101

def test_exporter_agreement_separation_and_epoch_binding(dsa, alice_keys):
    apk, ask = alice_keys
    a, b, _ = _pair(alice_keys)
    # Sync both onto one epoch key (pairwise fan-out analogue), then agree.
    prop = _signed_prop(dsa, ask, KIND_ADD, "carol")
    wire = _commit_for(a.transcript_of("g"), 1, [prop])
    for mgr in (a, b):
        assert mgr.apply_remote_commit("g", wire, "alice", b"K" * 32, apk,  # nosec: B101
                                       _verify_cb(dsa)) == 1
    # Agreement: synced managers derive identical subkeys.
    assert a.export_subkey("g", "audit-mac") == b.export_subkey("g", "audit-mac")  # nosec: B101
    # Label separation + length honored.
    assert a.export_subkey("g", "audit-mac") != a.export_subkey("g", "file-crypt")  # nosec: B101
    assert len(a.export_subkey("g", "x", length=64)) == 64  # nosec: B101
    # Epoch binding: rotation re-binds every label.
    before = a.export_subkey("g", "audit-mac")
    a.rotate("g")
    after = a.export_subkey("g", "audit-mac")
    assert before != after  # nosec: B101
    # Fail-closed inputs: unknown group, stale epoch, bad label/length.
    with pytest.raises(GroupKeyError):
        a.export_subkey("nope", "audit-mac")
    with pytest.raises(GroupKeyError):
        a.export_subkey("g", "audit-mac", epoch=0)
    with pytest.raises(GroupKeyError):
        a.export_subkey("g", "")
    with pytest.raises(GroupKeyError):
        a.export_subkey("g", "audit-mac", length=8)


def test_exporter_pcs_isolation_for_removed_member(dsa, alice_keys):
    apk, ask = alice_keys
    a, b, _ = _pair(alice_keys)
    old_sub = b.export_subkey("g", "compartment/SIERRA")
    # Alice removes bob; both move to epoch 1 with a fresh key.
    prop = _signed_prop(dsa, ask, KIND_REMOVE, "bob")
    wire = _commit_for(a.transcript_of("g"), 1, [prop])
    key1 = b"R" * 32
    for mgr in (a, b):
        assert mgr.apply_remote_commit("g", wire, "alice", key1, apk,  # nosec: B101
                                       _verify_cb(dsa)) == 1
    new_sub = a.export_subkey("g", "compartment/SIERRA")
    assert new_sub != old_sub  # stale-epoch keys derive nothing current  # nosec: B101


def test_commit_signature_verified_when_supplied(dsa, alice_keys, monkeypatch):
    from mls_framing import Commit as _C, DEFAULT_SUITE as _SUITE
    apk, ask = alice_keys
    for var in ("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "P2P_PRODUCTION",
                "SECURE_P2P_PRODUCTION"):
        monkeypatch.delenv(var, raising=False)
    for strict_on in (False, True):
        if strict_on:
            monkeypatch.setenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "1")
        else:
            monkeypatch.delenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", raising=False)
        m, _, _ = _pair(alice_keys)
        tx0 = m.transcript_of("g")
        prop = _signed_prop(dsa, ask, KIND_ADD, "carol")
        commit = _C(epoch=1, prev_tx=bytes(tx0), proposals=[prop],
                    suite_id=_SUITE if strict_on else "")
        good_sig = bytes(dsa.sign(ask, commit.encode()))
        # Valid commit-level signature accepted.
        assert m.apply_remote_commit(  # nosec: B101
            "g", commit.encode(), "alice", b"K" * 32, apk,
            _verify_cb(dsa), commit_sig=good_sig) == 1
        # Tampered signature rejected in BOTH modes (never stripped).
        m2, _, _ = _pair(alice_keys)
        bad = bytearray(good_sig)
        bad[0] ^= 0x01
        with pytest.raises(GroupKeyError):
            m2.apply_remote_commit(
                "g", commit.encode(), "alice", b"K" * 32, apk,
                _verify_cb(dsa), commit_sig=bytes(bad))
        # Supplied without key/callback: refused, not skipped.
        m3, _, _ = _pair(alice_keys)
        with pytest.raises(GroupKeyError):
            m3.apply_remote_commit("g", commit.encode(), "alice", b"K" * 32,
                                   None, None, commit_sig=good_sig)

def _signed_prop(dsa, sk, kind, member):
    from mls_framing import Proposal as _P
    prop = _P(kind=kind, member_id=member)
    prop.sig = bytes(dsa.sign(sk, prop.encode_unsigned()))
    return prop


def _suite_commit_for(tx0, epoch, proposals, suite_id):
    from mls_framing import Commit as _C
    return _C(epoch=epoch, prev_tx=bytes(tx0), proposals=list(proposals),
              suite_id=suite_id).encode()


def test_create_group_rejects_unsupported_suite():
    from mls_framing import SUITE_HYBRID_X25519_768, DEFAULT_SUITE
    mgr = GroupKeyManager()
    # Known-but-unimplemented hybrid: refused honestly, never negotiated down.
    with pytest.raises(GroupMembershipError):
        mgr.create_group("g-hybrid", ["alice"], SUITE_HYBRID_X25519_768)
    # Unknown suite: refused.
    with pytest.raises(GroupMembershipError):
        mgr.create_group("g-bogus", ["alice"], "ML-KEM-512+Ed25519/homebrew")
    # Default pure-PQ suite pins cleanly.
    res = mgr.create_group("g", ["alice", "bob"])
    assert res["suite_id"] == DEFAULT_SUITE  # nosec: B101


def test_suite_downgrade_refused_and_strict_binds(dsa, alice_keys, monkeypatch):
    from mls_framing import (DEFAULT_SUITE, SUITE_HYBRID_P384_1024,
                             KIND_ADD)
    apk, ask = alice_keys
    for var in ("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "P2P_PRODUCTION",
                "SECURE_P2P_PRODUCTION"):
        monkeypatch.delenv(var, raising=False)
    a, _, _ = _pair(alice_keys)
    tx0 = a.transcript_of("g")
    # Downgrade attempt (known hybrid vs pinned pure-PQ): refused in lab too.
    evil = _signed_prop(dsa, ask, KIND_ADD, "mallory")
    with pytest.raises(GroupKeyError):
        a.apply_remote_commit(
            "g", _suite_commit_for(tx0, 1, [evil], SUITE_HYBRID_P384_1024),
            "alice", b"K" * 32, apk, _verify_cb(dsa))
    # Pinned-suite commit applies and binds the transcript.
    good = _signed_prop(dsa, ask, KIND_ADD, "carol")
    assert a.apply_remote_commit(  # nosec: B101
        "g", _suite_commit_for(tx0, 1, [good], DEFAULT_SUITE),
        "alice", b"K" * 32, apk, _verify_cb(dsa)) == 1
    assert a.members_of("g") == ["alice", "bob", "carol"]  # nosec: B101
    # Strict mode: legacy suite-less commits refused outright.
    b, _, _ = _pair(alice_keys)
    monkeypatch.setenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "1")
    with pytest.raises(GroupKeyError):
        b.apply_remote_commit("g", _commit_for(b.transcript_of("g"), 1, [good]),
                              "alice", b"K" * 32, apk, _verify_cb(dsa))


def test_update_refresh_rekeys_without_roster_churn(dsa, alice_keys):
    from mls_framing import KIND_UPDATE
    apk, ask = alice_keys
    a, b, _ = _pair(alice_keys)
    # Local refresh path: epoch +1, roster untouched.
    assert a.refresh_member_keys("g", "alice") == 1  # nosec: B101
    assert a.members_of("g") == ["alice", "bob"]  # nosec: B101
    with pytest.raises(GroupMembershipError):
        a.refresh_member_keys("g", "ghost")
    # Remote update commit applies as a PCS rekey step (member NOT removed --
    # regression gate for the old add/else-remove dispatch).
    tx0 = b.transcript_of("g")
    upd = _signed_prop(dsa, ask, KIND_UPDATE, "bob")
    assert b.apply_remote_commit("g", _commit_for(tx0, 1, [upd]), "alice",  # nosec: B101
                                 b"U" * 32, apk, _verify_cb(dsa)) == 1
    assert sorted(b.members_of("g")) == ["alice", "bob"]  # nosec: B101
    # Update of a non-member is refused.
    tx1 = b.transcript_of("g")
    upd_ghost = _signed_prop(dsa, ask, KIND_UPDATE, "ghost")
    with pytest.raises(GroupMembershipError):
        b.apply_remote_commit("g", _commit_for(tx1, 2, [upd_ghost]), "alice",
                              b"U" * 32, apk, _verify_cb(dsa))


def test_keypackage_lifetime_validated(dsa, alice_keys, monkeypatch):
    import time
    from mls_framing import (KeyPackage as _KP, KIND_ADD,
                             DEFAULT_SUITE as _SUITE)
    apk, ask = alice_keys
    for var in ("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "P2P_PRODUCTION",
                "SECURE_P2P_PRODUCTION"):
        monkeypatch.delenv(var, raising=False)
    now = int(time.time())
    live_kp = _KP(member_id="carol", ml_dsa_pub=apk, kem_pub=b"\x03" * 16,
                  not_before=now - 60, not_after=now + 3600)
    stale_kp = _KP(member_id="carol", ml_dsa_pub=apk, kem_pub=b"\x03" * 16,
                   not_before=now - 7200, not_after=now - 3600)
    # Strict: live KP accepted, stale KP refused (suite-pinned commits,
    # as strict mode requires both signatures and suite binding).
    monkeypatch.setenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "1")
    s, _, _ = _pair(alice_keys)
    prop = _signed_prop(dsa, ask, KIND_ADD, "carol")
    assert s.apply_remote_commit(  # nosec: B101
        "g", _suite_commit_for(s.transcript_of("g"), 1, [prop], _SUITE),
        "alice", b"K" * 32, apk, _verify_cb(dsa),
        key_packages={"carol": live_kp}) == 1
    s2, _, _ = _pair(alice_keys)
    prop2 = _signed_prop(dsa, ask, KIND_ADD, "carol")
    with pytest.raises(GroupMembershipError):
        s2.apply_remote_commit(
            "g", _suite_commit_for(s2.transcript_of("g"), 1, [prop2], _SUITE),
            "alice", b"K" * 32, apk, _verify_cb(dsa),
            key_packages={"carol": stale_kp})
    # Lab: stale KP warn-applies (no strict gate).
    monkeypatch.delenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", raising=False)
    s3, _, _ = _pair(alice_keys)
    prop3 = _signed_prop(dsa, ask, KIND_ADD, "carol")
    assert s3.apply_remote_commit(  # nosec: B101
        "g", _commit_for(s3.transcript_of("g"), 1, [prop3]), "alice",
        b"K" * 32, apk, _verify_cb(dsa),
        key_packages={"carol": stale_kp}) == 1


# ------------------------------------------------------------------
# Tier-3 PQ integration: manager-driven TreeKEM create/apply (T3-L).
# Real ML-KEM keys, real decapsulation, real agreement -- no markers,
# no bypasses. commit_sig uses ML-DSA-87 over _pq_commit_canonical.
# ------------------------------------------------------------------

def _pqkem():
    from liboqs_wrapper import LibOQS_MLKEM_1024
    return LibOQS_MLKEM_1024()


def _pq_pair(dsa, alice_keys, monkeypatch):
    """Two managers, live KPs for both members, synced epoch-0 key."""
    import time
    from group_key_manager import GroupKeyManager
    kem = _pqkem()
    apk, ask = alice_keys
    _, bsk_dsa = dsa.keygen()
    now = int(time.time())
    pubs, privs, dsas = {}, {}, {}
    for m in ("alice", "bob"):
        kpk, ksk = kem.keygen()
        pubs[m], privs[m] = bytes(kpk), bytes(ksk)
    dsas["alice"] = (apk, ask)
    bpk, bsk = dsa.keygen()
    dsas["bob"] = (bytes(bpk), bytes(bsk))
    mgrs = []
    for mgr in (GroupKeyManager(), GroupKeyManager()):
        mgr.create_group("g", ["alice", "bob"])
        for m in ("alice", "bob"):
            dpk = dsas[m][0]
            mgr.publish_key_package(
                "g", KeyPackage(member_id=m, ml_dsa_pub=dpk,
                               kem_pub=pubs[m],
                               not_before=now - 60, not_after=now + 3600))
        mgrs.append(mgr)
    a, b = mgrs
    # Fan-out simulation: identical epoch-0 key on both sides.
    b._groups["g"].group_key = bytearray(bytes(a._groups["g"].group_key))
    for var in ("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "P2P_PRODUCTION",
                "SECURE_P2P_PRODUCTION"):
        monkeypatch.delenv(var, raising=False)
    return a, b, pubs, privs, dsas


def _pq_sign(dsa, sk, mgr, group_id, path):
    return bytes(dsa.sign(sk, mgr._pq_commit_canonical(group_id, path)))


def test_pq_update_end_to_end_agreement(dsa, alice_keys, monkeypatch):
    a, b, pubs, privs, dsas = _pq_pair(dsa, alice_keys, monkeypatch)
    apk, ask = dsas["alice"]
    leaf_a = a.get_pq_treekem("g", "alice",
                              local_secret_key=privs["alice"]).tree.members()["alice"]
    path, new_a = a.create_pq_update("g", "alice",
                                     local_secret_key=privs["alice"])
    sig = _pq_sign(dsa, ask, a, "g", path)
    path.commit_sig = sig
    leaf_b = leaf_a  # same roster positions on both mirrors
    ep = b.apply_pq_update_path("g", leaf_b, path, "bob",
                                committer_id="alice",
                                committer_pub=apk,
                                verify_cb=_verify_cb(dsa),
                                local_secret_key=privs["bob"])
    assert ep == 1  # nosec: B101
    assert bytes(a._groups["g"].group_key) == bytes(b._groups["g"].group_key)  # nosec: B101
    assert a.epoch_of("g") == b.epoch_of("g") == 1  # nosec: B101
    assert a.transcript_of("g") == b.transcript_of("g")  # nosec: B101
    assert a.tree_hash_of("g") == b.tree_hash_of("g")  # nosec: B101
    # Interop on the agreed PQ epoch key.
    sealed = a.encrypt_for_group("g", b"pq-agreed")
    ct = sealed["envelopes"]["bob"]
    assert b.decrypt_from_group("g", ct, 1, member_id="bob") == b"pq-agreed"  # nosec: B101


def test_pq_update_refusals(dsa, alice_keys, monkeypatch):
    a, b, pubs, privs, dsas = _pq_pair(dsa, alice_keys, monkeypatch)
    apk, ask = dsas["alice"]
    leaf_a = a.get_pq_treekem("g", "alice",
                              local_secret_key=privs["alice"]).tree.members()["alice"]
    path, _ = a.create_pq_update("g", "alice",
                                 local_secret_key=privs["alice"])
    # External committer refused.
    with pytest.raises(GroupMembershipError):
        b.apply_pq_update_path("g", leaf_a, path, "bob",
                               committer_id="mallory",
                               local_secret_key=privs["bob"])
    # Updater-claim mismatch refused.
    with pytest.raises(GroupKeyError):
        b.apply_pq_update_path("g", leaf_a, path, "bob",
                               committer_id="bob",
                               local_secret_key=privs["bob"])
    # Tampered signature refused in lab AND strict.
    sig = _pq_sign(dsa, ask, a, "g", path)
    bad = bytearray(sig)
    bad[0] ^= 0x01
    path.commit_sig = bytes(bad)
    with pytest.raises(GroupKeyError):
        b.apply_pq_update_path("g", leaf_a, path, "bob",
                               committer_id="alice", committer_pub=apk,
                               verify_cb=_verify_cb(dsa),
                               local_secret_key=privs["bob"])
    monkeypatch.setenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "1")
    with pytest.raises(GroupKeyError):
        b.apply_pq_update_path("g", leaf_a, path, "bob",
                               committer_id="alice", committer_pub=apk,
                               verify_cb=_verify_cb(dsa),
                               local_secret_key=privs["bob"])
    # Valid signature applies under strict.
    path.commit_sig = sig
    assert b.apply_pq_update_path(  # nosec: B101
        "g", leaf_a, path, "bob", committer_id="alice",
        committer_pub=apk, verify_cb=_verify_cb(dsa),
        local_secret_key=privs["bob"]) == 1
    # Replay refused (epoch gate).
    with pytest.raises(GroupKeyError):
        b.apply_pq_update_path("g", leaf_a, path, "bob",
                               committer_id="alice", committer_pub=apk,
                               verify_cb=_verify_cb(dsa),
                               local_secret_key=privs["bob"])


def test_pq_update_strict_unsigned_refused(dsa, alice_keys, monkeypatch):
    a, b, pubs, privs, dsas = _pq_pair(dsa, alice_keys, monkeypatch)
    monkeypatch.setenv("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "1")
    path, _ = a.create_pq_update("g", "alice",
                                 local_secret_key=privs["alice"])
    with pytest.raises(GroupKeyError):
        b.apply_pq_update_path("g", 0, path, "bob",
                               committer_id="alice",
                               local_secret_key=privs["bob"])


def test_pq_engine_needs_real_packages(dsa, alice_keys, monkeypatch):
    from group_key_manager import GroupKeyManager
    for var in ("P2P_GROUP_REQUIRE_SIGNED_COMMITS", "P2P_PRODUCTION",
                "SECURE_P2P_PRODUCTION"):
        monkeypatch.delenv(var, raising=False)
    mgr = GroupKeyManager()
    mgr.create_group("g", ["alice", "bob"])
    # No KeyPackages published: engine build refuses (no markers).
    with pytest.raises(GroupKeyError):
        mgr.get_pq_treekem("g", "alice", local_secret_key=b"K" * 32)
    # Wrong-size secret refused.
    import time
    kem = _pqkem()
    kpk, ksk = kem.keygen()
    mgr.publish_key_package(
        "g", KeyPackage(member_id="alice", ml_dsa_pub=b"\x01" * 32,
                       kem_pub=bytes(kpk),
                       not_before=int(time.time()) - 60,
                       not_after=int(time.time()) + 3600))
    mgr.publish_key_package(
        "g", KeyPackage(member_id="bob", ml_dsa_pub=b"\x01" * 32,
                       kem_pub=bytes(kpk),
                       not_before=int(time.time()) - 60,
                       not_after=int(time.time()) + 3600))
    with pytest.raises(GroupKeyError):
        mgr.get_pq_treekem("g", "alice", local_secret_key=b"short")

