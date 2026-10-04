#!/usr/bin/env python3
"""Layer-1 hardening gates: native buffers + V2 member-bound group envelopes.

Fast (<60s), no network, no TPM/COM.
"""
import os
import secrets

import pytest

from native_secure_buffer import NativeSecureBuffer, wipe_native
from group_key_manager import (
    GroupKeyError,
    GroupKeyManager,
    _envelope_aad,
)


# -- native buffers ----------------------------------------------------

def test_wipe_native_rejects_immutable():
    with pytest.raises(TypeError):
        wipe_native(b"immutable")


def test_wipe_native_zeroes_and_verifies():
    buf = bytearray(b"secret-16-bytes!")
    method = wipe_native(buf)
    assert bytes(buf) == b"\x00" * len(buf)  # nosec: B101
    assert isinstance(method, str) and method  # nosec: B101


def test_buffer_context_wipes_on_exit():
    with NativeSecureBuffer(16) as buf:
        assert len(buf) == 16  # nosec: B101
        buf.fill(secrets.token_bytes(16))
        assert isinstance(buf.is_pinned, bool)  # nosec: B101
    assert buf.wiped  # nosec: B101
    assert bytes(buf) == b"\x00" * 16  # nosec: B101


def test_buffer_from_immutable_documents_source():
    buf = NativeSecureBuffer(b"x" * 32)
    assert "immutable" in buf._source_wiped_note  # nosec: B101
    assert buf.export_bytes() == b"x" * 32  # nosec: B101
    buf.wipe()
    assert buf.wiped  # nosec: B101


def test_require_pinned_lab_pass_prod_gate():
    buf = NativeSecureBuffer(16)
    buf.require_pinned()  # lab default: no enforcement
    buf.wipe()


# -- group V2 envelopes --------------------------------------------------

def test_v2_aad_differs_per_member_and_from_v1():
    a = _envelope_aad("g", 3, "alice")
    b = _envelope_aad("g", 3, "bob")
    v1 = _envelope_aad("g", 3)
    assert a != b and a != v1 and a.startswith(b"GKM-V2:")  # nosec: B101
    # delimiter ambiguity: ':' inside IDs must not collide
    assert _envelope_aad("a:b", 1, "c") != _envelope_aad("a", 1, "b:c")  # nosec: B101


def test_group_roundtrip_member_bound():
    mgr = GroupKeyManager()
    mgr.create_group("g1", ["alice", "bob"])
    out = mgr.encrypt_for_group("g1", b"hello-group")
    assert set(out["envelopes"]) == {"alice", "bob"}  # nosec: B101
    assert mgr.decrypt_from_group("g1", out["envelopes"]["alice"], out["epoch"], "alice") == b"hello-group"  # nosec: B101
    # cross-member use fails closed (AAD mismatch)
    with pytest.raises(GroupKeyError):
        mgr.decrypt_from_group("g1", out["envelopes"]["alice"], out["epoch"], "bob")


def test_group_strict_refuses_local_fallback(monkeypatch):
    monkeypatch.setenv("P2P_GROUP_REQUIRE_PAIRWISE", "1")
    mgr = GroupKeyManager()  # no orchestrator -> no pairwise hook
    mgr.create_group("g2", ["alice"])
    with pytest.raises(GroupKeyError):
        mgr.encrypt_for_group("g2", b"nope")
    # decrypt without member binding refused in strict mode
    monkeypatch.delenv("P2P_GROUP_REQUIRE_PAIRWISE")
    out = mgr.encrypt_for_group("g2", b"lab-only")
    monkeypatch.setenv("P2P_GROUP_REQUIRE_PAIRWISE", "1")
    with pytest.raises(GroupKeyError):
        mgr.decrypt_from_group("g2", out["envelopes"]["alice"], out["epoch"])

