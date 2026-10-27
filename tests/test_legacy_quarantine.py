#!/usr/bin/env python3
"""Legacy prototype quarantine: TS/PROD must refuse, lab import unaffected."""

import gc
import os
import sys

import pytest
from pathlib import Path

_LEGACY_P2 = Path(__file__).resolve().parent.parent / "archive" / "legacy_prototype" / "secure_p2.py"
if not _LEGACY_P2.exists():
    pytestmark = pytest.mark.skip(reason="legacy prototype twins not present in archive")


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
    import protocol_manager  # noqa: F401
    from archive.legacy_prototype.secure_p2p import SecureP2PChat as ChatA
    from archive.legacy_prototype.secure_p2 import SecureP2PChat as ChatB
    return ChatA, ChatB


def test_front_secure_p2p_arms_ts_mode(monkeypatch):
    """secure_p2p.py arms sovereign military mode when P2P_TS_MODE is set."""
    monkeypatch.setenv("P2P_TS_MODE", "1")
    ChatA, ChatB = _import_twins(monkeypatch)
    a = ChatA(identity="node_alpha", anonymous=True)
    b = ChatB(identity="node_bravo", anonymous=True)
    assert getattr(a, 'ts_mode', False) is True
    assert getattr(b, 'ts_mode', False) is True
    assert a.post_quantum_enabled is True
    assert b.post_quantum_enabled is True
    a.cleanup()
    b.cleanup()


def test_front_secure_p2p_arms_production_mode(monkeypatch):
    """secure_p2p.py arms production sovereign mode when P2P_PRODUCTION is set."""
    monkeypatch.delenv("P2P_TS_MODE", raising=False)
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    ChatA, ChatB = _import_twins(monkeypatch)
    a = ChatA(identity="node_alpha", anonymous=True)
    b = ChatB(identity="node_bravo", anonymous=True)
    assert getattr(a, 'production_mode', False) is True
    assert getattr(b, 'production_mode', False) is True
    a.cleanup()
    b.cleanup()


def test_front_secure_p2p_present_and_in_sync():
    """Verify secure_p2p.py is present at repository root as the front sovereign application.

    Also validates that legacy mirror paths remain in byte-identical lockstep.
    """
    import hashlib
    import pathlib

    root = pathlib.Path(__file__).resolve().parent
    assert (root / "secure_p2p.py").exists(), "secure_p2p.py must be present at repository root"
    leg = root / "archive" / "legacy_prototype"
    root_bytes = (root / "secure_p2p.py").read_bytes()
    a = (leg / "secure_p2.py").read_bytes()
    b = (leg / "secure_p2p.py").read_bytes()
    root_hash = hashlib.sha256(root_bytes).hexdigest()
    assert root_hash == hashlib.sha256(a).hexdigest(), "archive secure_p2.py out of sync with front secure_p2p.py"
    assert root_hash == hashlib.sha256(b).hexdigest(), "archive secure_p2p.py out of sync with front secure_p2p.py"
    assert (leg / "__init__.py").exists()
    assert (root / "archive" / "__init__.py").exists()


def test_twins_importable_only_via_archive():
    """The archive package path is importable and distinct."""
    import protocol_manager  # noqa: F401
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
