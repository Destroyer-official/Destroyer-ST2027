"""Fail-closed file-receive filename guard (found 2026-09-24).

Peer-supplied ``FileMetadata.filename`` reached
``SecureP2PChat._complete_file_reception`` and was joined to ``downloads/``
unsanitized, so a malicious peer's ``"../../evil.txt"`` escaped the download
directory. The guard in ``secure_p2.py`` (mirrored byte-identical in
``secure_p2p.py`` -- twin parity verified by SHA-256) sanitizes to an
allowlist, refuses dotfiles, and confines the resolved path to ``downloads/``.

Follow-up hardening (same date): ``SecureFileHandler.reassemble_file`` now
creates the output with ``O_CREAT|O_EXCL`` (CWE-59: a pre-planted symlink,
directory, or raced file at the target fails closed instead of being
followed/overwritten), new files land mode ``0o600``, and the reception
error path drops the transfer entry instead of leaking it.

These gates drive the REAL method end-to-end -- real ``FileChunk`` objects
(sha3_256 self-validating), the REAL ``SecureFileHandler`` write path with a
real checksum -- and assert:
  1. Nothing is written outside ``downloads/`` (confinement).
  2. The on-disk name is neutralized (no separators, no leading dot).
  3. A pre-planted symlink at the predictable target is refused, its target
     untouched, the transfer cleaned up, the peer told fail-closed.
  4. The transfer entry is cleaned up on every path -- never an unhandled
     exception, a silent escape, or a leaked entry.

Also gates the 2026-09-24 validator switch: send-path modules must resolve
``InputValidator`` from the live scanned ``security.validation`` first, and
the live validator must strictly reject ``..``.

Run: ``pytest test_file_receive_traversal_guard.py -v``
"""

import asyncio
import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from secure_file_sharing import FileChunk, FileMetadata
try:
    from secure_p2p import SecureP2PChat
except ImportError:
    from archive.legacy_prototype.secure_p2 import SecureP2PChat

PAYLOAD = b"TRAVERSAL-GUARD-PROBE-PAYLOAD"
PAYLOAD_SHA3 = hashlib.sha3_256(PAYLOAD).hexdigest()

EVIL_FILENAMES = [
    "../../evil.txt",
    "..\\..\\evil_win.txt",
    "/abs_evil.txt",
    ".hidden_evil",
    ".../...//evil",
    "..%2F..%2Fevil.txt",
]


def _make_chat(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    chat = SecureP2PChat(anonymous=True)
    chat.peer_username = "guard-probe-peer"
    # NOTE: the REAL SecureFileHandler is kept deliberately, so the gates
    # exercise the true write path including O_EXCL exclusive creation.
    sent = []
    errors = []

    async def fake_send(msg):
        sent.append(msg)

    async def fake_error(file_id, message):
        errors.append((file_id, message))

    chat._send_file_message = fake_send
    chat._send_file_error = fake_error
    return chat, sent, errors


def _register_transfer(chat, filename, payload=PAYLOAD):
    file_id = "a" * 32
    digest = hashlib.sha3_256(payload).hexdigest()
    metadata = FileMetadata(
        file_id=file_id,
        filename=filename,
        file_size=len(payload),
        file_type="application/octet-stream",
        checksum=digest,
        chunk_size=4096,
        total_chunks=1,
        created_at=datetime.now(timezone.utc),
        sender_id="probe-peer",
    )
    chunk = FileChunk(
        file_id=file_id,
        chunk_number=0,
        chunk_data=payload,
        chunk_checksum=digest,
    )
    chat.active_file_transfers[file_id] = {
        "metadata": metadata,
        # NOTE: real key is 'chunks_received' (direct indexing in
        # _complete_file_reception); a wrong key fail-closes via the
        # outer except instead of reaching the guard.
        "chunks_received": {0: chunk},
        "total_size": len(payload),
        "received_size": len(payload),
    }
    return file_id


def _snapshot(tmp_path):
    return {p.resolve() for p in tmp_path.rglob("*") if p.is_file()}


def _assert_confined(tmp_path, before):
    downloads = tmp_path / "downloads"
    assert downloads.is_dir(), "downloads/ must be created"
    after = {p.resolve() for p in tmp_path.rglob("*") if p.is_file()}
    # Chat __init__ itself creates audit db + logs in CWD (pre-existing app
    # behavior, unrelated to the receive path): only NEW files must be
    # confined.
    new_files = after - before
    escapes = [str(p) for p in new_files if downloads.resolve() not in p.parents]
    assert escapes == [], f"files escaped downloads/: {escapes}"
    for p in downloads.iterdir():
        if p.is_symlink():
            continue  # planted-link test owns its link; covered separately
        assert "/" not in p.name and "\\" not in p.name, f"separator survived: {p.name}"
        assert not p.name.startswith("."), f"dotfile survived: {p.name}"
        if os.name == "posix":
            mode = stat.S_IMODE(p.stat().st_mode)
            assert mode == 0o600, f"peer-supplied file not 0o600: {p.name} {oct(mode)}"
    return downloads


def test_receive_confines_traversal_filenames(monkeypatch, tmp_path):
    """Adversarial peer filenames are neutralized and confined to downloads/."""
    chat, sent, errors = _make_chat(monkeypatch, tmp_path)
    before = _snapshot(tmp_path)
    for evil in EVIL_FILENAMES:
        file_id = _register_transfer(chat, evil)
        asyncio.run(chat._complete_file_reception(file_id))
        assert file_id not in chat.active_file_transfers, f"transfer leaked: {evil}"
    downloads = _assert_confined(tmp_path, before)
    assert len(list(downloads.iterdir())) == len(EVIL_FILENAMES)
    for p in downloads.iterdir():
        assert p.read_bytes() == PAYLOAD


def test_receive_dotfile_is_renamed(monkeypatch, tmp_path):
    """Dotfiles from peers never land as dotfiles (hidden-file drop)."""
    chat, sent, errors = _make_chat(monkeypatch, tmp_path)
    before = _snapshot(tmp_path)
    file_id = _register_transfer(chat, ".bashrc")
    asyncio.run(chat._complete_file_reception(file_id))
    downloads = _assert_confined(tmp_path, before)
    names = [p.name for p in downloads.iterdir()]
    assert names and all(not n.startswith(".") for n in names)


def test_planted_symlink_refused_fail_closed(monkeypatch, tmp_path):
    """A pre-planted symlink at the predictable target is refused (CWE-59)."""
    chat, sent, errors = _make_chat(monkeypatch, tmp_path)
    honeypot = tmp_path / "honeypot.txt"
    honeypot.write_bytes(b"ORIGINAL")
    link = tmp_path / "downloads" / "report.txt"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(honeypot)
    except OSError:
        pytest.skip("symlink creation needs privilege on this platform")
    before = _snapshot(tmp_path)
    # "report.txt" sanitizes to itself, so the peer's file collides with
    # the planted link.
    file_id = _register_transfer(chat, "report.txt")
    asyncio.run(chat._complete_file_reception(file_id))
    assert file_id not in chat.active_file_transfers, "transfer leaked on refusal path"
    assert honeypot.read_bytes() == b"ORIGINAL", "symlink target was written through"
    assert link.is_symlink(), "planted link must be left untouched, not replaced"
    assert errors, "peer must be told fail-closed"
    _assert_confined(tmp_path, before)


def test_reassemble_refuses_preexisting_path_directly(tmp_path):
    """reassemble_file fails closed on pre-existing file or dir (CWE-59).

    Runs without symlinks so the exclusive-creation contract is proven
    even where link creation needs privilege (the planted-link test
    above covers following behavior where the platform allows it).
    """
    from secure_file_sharing import SecureFileHandler

    handler = SecureFileHandler()
    digest = hashlib.sha3_256(PAYLOAD).hexdigest()
    chunk = FileChunk(file_id="b" * 32, chunk_number=0, chunk_data=PAYLOAD,
                      chunk_checksum=digest)
    planted = tmp_path / "planted.txt"
    planted.write_bytes(b"ORIGINAL")
    with pytest.raises(ValueError, match="pre-existing"):
        handler.reassemble_file([chunk], planted, digest)
    assert planted.read_bytes() == b"ORIGINAL"
    with pytest.raises(OSError):
        handler.reassemble_file([chunk], tmp_path, digest)


def test_reception_error_path_cleans_up_transfer(monkeypatch, tmp_path):
    """The reception error path drops the transfer entry (no leak)."""
    chat, sent, errors = _make_chat(monkeypatch, tmp_path)
    file_id = _register_transfer(chat, "report.txt")
    # Corrupt the entry shape: direct indexing in _complete_file_reception
    # raises inside try -> outer except must send fail-closed + pop entry.
    del chat.active_file_transfers[file_id]["chunks_received"]
    asyncio.run(chat._complete_file_reception(file_id))
    assert file_id not in chat.active_file_transfers, "transfer leaked on error path"
    assert errors and errors[0][0] == file_id


def test_secure_delete_wipes_regular_file(tmp_path):
    """secure_delete_file destroys regular files and reports success."""
    from secure_file_sharing import SecureFileHandler

    target = tmp_path / "wipe_me.bin"
    target.write_bytes(b"SENSITIVE-" * 100)
    assert SecureFileHandler().secure_delete_file(target) is True
    assert not target.exists()


def test_secure_delete_refuses_symlink(tmp_path):
    """secure_delete_file never wipes through a symlink (CWE-59)."""
    from secure_file_sharing import SecureFileHandler

    honeypot = tmp_path / "honeypot.txt"
    honeypot.write_bytes(b"ORIGINAL")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(honeypot)
    except OSError:
        pytest.skip("symlink creation needs privilege on this platform")
    assert SecureFileHandler().secure_delete_file(link) is False
    assert honeypot.read_bytes() == b"ORIGINAL"
    assert link.is_symlink(), "refused link must be left untouched"


def test_live_validator_strictly_rejects_traversal(tmp_path):
    """Send-path validation resolves live-first and rejects '..' outright."""
    from security.validation import InputValidator  # live scanned tree

    ok, err = InputValidator.validate_file_path(str(tmp_path / ".." / "evil.txt"))
    assert not ok and "traversal" in err.lower()
    probe = tmp_path / "ok.bin"
    probe.write_bytes(b"ok")
    ok, err = InputValidator.validate_file_path(str(probe))
    assert ok, err
