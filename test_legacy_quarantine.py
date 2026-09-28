#!/usr/bin/env python3
"""Legacy prototype quarantine: TS/PROD must refuse, lab import unaffected."""

import gc
import os
import sys

import pytest


@pytest.fixture(scope="module", autouse=True)
def _contain_legacy_stderr_hijack():
    """The legacy twins replace global sys.stderr at import
    (secure_p2p.py:174 COMExceptionFilter). Without containment that
    hijack outlives the session and crashes interpreter teardown with
    "lost sys.stderr" even when every test passes. Save, restore, and
    force collection while the real stream is still open."""
    saved = sys.stderr
    yield
    sys.stderr = saved
    gc.collect()


def _import_twins(monkeypatch):
    # The twins hijack global sys.stderr at import on win32
    # (secure_p2p.py:174 COMExceptionFilter), which corrupts interpreter
    # teardown for the whole session. Neutralize by importing under a
    # non-win32 platform mask: the guard under test checks env flags only,
    # so production/TS refusal behavior is identical either way.
    # Pre-warm the platform-sensitive dependency chain FIRST under the true
    # platform: enhanced_secure_memory.py:46 selects libc vs kernel32 at
    # import from sys.platform, and the POSIX branch cannot load libc on a
    # real Windows host (find_library('c') -> None -> TypeError). Warming
    # caches it in sys.modules so the mask below affects only the twins'
    # own import-time guards, never the shared chain.
    import protocol_manager  # noqa: F401
    monkeypatch.setattr(sys, "platform", "linux")
    from archive.legacy_prototype.secure_p2p import SecureP2PChat as ChatA
    from archive.legacy_prototype.secure_p2 import SecureP2PChat as ChatB
    return ChatA, ChatB


def test_legacy_monoliths_refuse_ts_mode(monkeypatch):
    monkeypatch.setenv("P2P_TS_MODE", "1")
    ChatA, ChatB = _import_twins(monkeypatch)
    with pytest.raises(RuntimeError):
        ChatA()
    with pytest.raises(RuntimeError):
        ChatB()


def test_legacy_monoliths_refuse_production(monkeypatch):
    monkeypatch.delenv("P2P_TS_MODE", raising=False)
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    ChatA, ChatB = _import_twins(monkeypatch)
    with pytest.raises(RuntimeError):
        ChatA()
    with pytest.raises(RuntimeError):
        ChatB()


def test_twins_quarantined_out_of_root():
    """Task-3: no operator-confusable prototype at repo root.

    secure_p2.py / secure_p2p.py must live ONLY in
    archive/legacy_prototype/ (byte-identical), importable solely via the
    archive.legacy_prototype.* path. A root copy is a deployment-confusion
    regression and fails here.
    """
    import hashlib
    import pathlib

    root = pathlib.Path(__file__).resolve().parent
    assert not (root / "secure_p2.py").exists()
    assert not (root / "secure_p2p.py").exists()
    leg = root / "archive" / "legacy_prototype"
    a = (leg / "secure_p2.py").read_bytes()
    b = (leg / "secure_p2p.py").read_bytes()
    assert (hashlib.sha256(a).hexdigest()
            == hashlib.sha256(b).hexdigest()), "twin identity broken by move"
    assert (leg / "__init__.py").exists()
    assert (root / "archive" / "__init__.py").exists()


def test_twins_importable_only_via_archive(monkeypatch):
    """The archive package path is the single import route."""
    import sys

    monkeypatch.setattr(sys, "platform", "linux")
    import protocol_manager  # noqa: F401  (pre-warm, see _import_twins)
    from archive.legacy_prototype.secure_p2p import SecureP2PChat as A
    from archive.legacy_prototype.secure_p2 import SecureP2PChat as B
    assert A is not B
    assert A.__module__ == "archive.legacy_prototype.secure_p2p"
    assert B.__module__ == "archive.legacy_prototype.secure_p2"


def test_twins_write_no_runtime_state_to_root():
    """Quarantined runs must not re-pollute the repo root.

    The twins' audit DB (and certs/keys/logs dirs) resolve from __file__,
    never the process CWD: after ANY twin construction, repo root must
    contain no secure_p2p_audit.db*. Static guard (fast); live proof is
    the 2-terminal suites, whose runs leave root clean.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent
    assert not list(root.glob("secure_p2p_audit.db*")), \
        "root audit-DB debris present — twin runs must anchor state to archive/"
    leg = root / "archive" / "legacy_prototype"
    for twin in ("secure_p2.py", "secure_p2p.py"):
        src = (leg / twin).read_text(encoding="utf-8", errors="replace")
        assert 'initialize_audit_system("secure_p2p_audit.db")' not in src, \
            f"{twin}: cwd-relative audit DB regressed"
        m = re.search(r"initialize_audit_system\(([^)]*)\)", src)
        assert m and "__file__" in m.group(1), \
            f"{twin}: audit DB path must derive from __file__"
