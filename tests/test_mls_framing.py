#!/usr/bin/env python3
"""Gates for mls_framing.py: roundtrips, transcript chain, tamper rejection.

Fast (<60s), no network, no TPM/COM.
"""
import pytest

from mls_framing import (
    KIND_ADD,
    KIND_REMOVE,
    KIND_UPDATE,
    TRANSCRIPT_INIT,
    Commit,
    KeyPackage,
    Proposal,
    decode_suite_annotation,
    encode_suite_annotation,
    transcript_update,
    verify_proposal_sig,
)


def test_keypackage_roundtrip():
    kp = KeyPackage(member_id="alice", ml_dsa_pub=b"\x01" * 32, kem_pub=b"\x02" * 16)
    assert KeyPackage.decode(kp.encode()) == kp  # nosec: B101


def test_keypackage_rejects_tamper():
    kp = KeyPackage(member_id="alice").encode()
    with pytest.raises(ValueError):
        KeyPackage.decode(b"BAD!" + kp[4:])
    with pytest.raises(ValueError):
        KeyPackage.decode(kp + b"\x00")  # trailing bytes
    with pytest.raises(ValueError):
        KeyPackage.decode(kp[:10])  # truncated


def test_proposal_roundtrip_and_kinds():
    for kind in (KIND_ADD, KIND_REMOVE, KIND_UPDATE):
        p = Proposal(kind=kind, member_id="bob", sig=b"\xab" * 8)
        assert Proposal.decode(p.encode()) == p  # nosec: B101
    # Unknown kind byte rejected on decode (v2 version bytes).
    raw = (b"MLSP1\x00\x02" + bytes([99])
           + b"\x00\x00\x00\x01x" + b"\x00\x00\x00\x00")
    with pytest.raises(ValueError):
        Proposal.decode(raw)
    # v1 frames rejected outright (no silent cross-version acceptance).
    v1 = (b"MLSP1\x00\x01" + bytes([KIND_ADD])
          + b"\x00\x00\x00\x01x" + b"\x00\x00\x00\x00")
    with pytest.raises(ValueError):
        Proposal.decode(v1)


def test_commit_transcript_chains_and_binds():
    p1 = Proposal(kind=KIND_ADD, member_id="alice")
    c1 = Commit(epoch=1, prev_tx=TRANSCRIPT_INIT, proposals=[p1])
    t1 = c1.new_transcript()
    c2 = Commit(epoch=2, prev_tx=t1, proposals=[])
    t2 = c2.new_transcript()
    assert t1 != t2 and t1 != TRANSCRIPT_INIT  # nosec: B101
    # Fork detection: same epoch, different proposals -> different transcript.
    c1b = Commit(epoch=1, prev_tx=TRANSCRIPT_INIT,
                 proposals=[Proposal(kind=KIND_ADD, member_id="mallory")])
    assert c1b.new_transcript() != t1  # nosec: B101
    # Epoch binds: same proposals, different epoch -> different transcript.
    c1c = Commit(epoch=2, prev_tx=TRANSCRIPT_INIT, proposals=[p1])
    assert c1c.new_transcript() != t1  # nosec: B101
    # Roundtrip through the wire form.
    assert Commit.decode(c1.encode()).new_transcript() == t1  # nosec: B101


def test_commit_rejects_tamper():
    c = Commit(epoch=1, prev_tx=TRANSCRIPT_INIT, proposals=[]).encode()
    with pytest.raises(ValueError):
        Commit.decode(b"XXXXX" + c[5:])
    with pytest.raises(ValueError):
        Commit.decode(c + b"\x00")
    with pytest.raises(ValueError):
        Commit.decode(c[:12])


def test_verify_proposal_sig_fail_closed_without_callback():
    p = Proposal(kind=KIND_ADD, member_id="alice", sig=b"\x01" * 64)
    assert verify_proposal_sig(p, b"\x02" * 32) is False  # nosec: B101
    assert verify_proposal_sig(Proposal(kind=KIND_ADD, member_id="a"), b"\x02" * 32) is False  # nosec: B101


def test_verify_proposal_sig_with_callback():
    def fake_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
        return pub == b"\x02" * 32 and sig == b"\x01" * 64 and len(msg) > 0

    p = Proposal(kind=KIND_ADD, member_id="alice", sig=b"\x01" * 64)
    assert verify_proposal_sig(p, b"\x02" * 32, fake_verify) is True  # nosec: B101
    assert verify_proposal_sig(p, b"\x03" * 32, fake_verify) is False  # nosec: B101


def test_transcript_update_validates_inputs():
    with pytest.raises(ValueError):
        transcript_update(b"", [], 1)
    with pytest.raises(ValueError):
        transcript_update(TRANSCRIPT_INIT, [], -1)
    with pytest.raises(TypeError):
        transcript_update(TRANSCRIPT_INIT, ["not-a-proposal"], 1)


def test_keypackage_lifetime_enforced():
    import time
    now = int(time.time())
    kp = KeyPackage(member_id="alice", ml_dsa_pub=b"\x01" * 32,
                    kem_pub=b"\x02" * 16,
                    not_before=now - 60, not_after=now + 3600)
    assert KeyPackage.decode(kp.encode()) == kp  # nosec: B101
    assert kp.is_live(now) is True  # nosec: B101
    assert kp.is_live(now + 7200) is False  # expired  # nosec: B101
    assert kp.is_live(now - 3600) is False  # not yet valid  # nosec: B101
    # Zero window = never live (fail-closed).
    assert KeyPackage(member_id="a").is_live(now) is False  # nosec: B101
    # Inverted / over-long windows rejected at construction.
    with pytest.raises(ValueError):
        KeyPackage(member_id="a", not_before=now + 10, not_after=now)
    with pytest.raises(ValueError):
        KeyPackage(member_id="a", not_before=now, not_after=now + 31 * 24 * 3600)


def test_suite_annotation_bound_to_transcript():
    from mls_framing import DEFAULT_SUITE
    p = Proposal(kind=KIND_ADD, member_id="alice")
    plain = Commit(epoch=1, prev_tx=TRANSCRIPT_INIT, proposals=[p])
    pinned = Commit(epoch=1, prev_tx=TRANSCRIPT_INIT, proposals=[p],
                    suite_id=DEFAULT_SUITE)
    # Suite annotation changes the transcript (downgrade fork = transcript fork).
    assert pinned.new_transcript() != plain.new_transcript()  # nosec: B101
    # Legacy empty annotation hashes exactly as before (digest-neutral extra).
    assert plain.new_transcript() == transcript_update(TRANSCRIPT_INIT, [p], 1)  # nosec: B101
    # Roundtrip through the wire form.
    assert Commit.decode(pinned.encode()).suite_id == DEFAULT_SUITE  # nosec: B101
    assert Commit.decode(plain.encode()).suite_id == ""  # nosec: B101
    # Unknown suites never encode/decode.
    with pytest.raises(ValueError):
        encode_suite_annotation("ML-KEM-512+Ed25519/homebrew")
    with pytest.raises(ValueError):
        decode_suite_annotation(b"suite=ML-KEM-512+Ed25519/homebrew")
    with pytest.raises(ValueError):
        decode_suite_annotation(b"mystery-prefix")


def test_group_key_manager_transcript_chain():
    from group_key_manager import GroupKeyManager
    mgr = GroupKeyManager()
    res = mgr.create_group("g-tx", ["alice", "bob"])
    t0 = mgr.transcript_of("g-tx")
    assert t0 == res["transcript_hash"]  # nosec: B101
    assert len(t0) == 64  # SHA3-512 digest length  # nosec: B101

    mgr.add_member("g-tx", "charlie")
    t1 = mgr.transcript_of("g-tx")
    assert t1 != t0 and len(t1) == 64  # nosec: B101

    mgr.remove_member("g-tx", "bob")
    t2 = mgr.transcript_of("g-tx")
    assert t2 != t1 and len(t2) == 64  # nosec: B101

    mgr.rotate("g-tx")
    t3 = mgr.transcript_of("g-tx")
    assert t3 != t2 and len(t3) == 64  # nosec: B101

