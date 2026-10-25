"""Behavioral tests for archive hardening and extract_archive defenses.

Tests libsodium_manager.extract_archive against:
1. Path traversal attacks in ZIP archives.
2. Path traversal attacks in TAR.GZ archives.
3. Symlink extraction attacks in ZIP archives.
4. Symlink extraction attacks in TAR.GZ archives.
5. Decompression bombs / size limit exhaustion in ZIP archives.
6. Valid, benign archive extraction.
"""

import io
import os
import tarfile
import zipfile
from pathlib import Path
import pytest
from libsodium_manager import extract_archive


def test_extract_archive_benign_zip(tmp_path):
    """Benign zip extraction must succeed and return True."""
    archive_path = tmp_path / "valid.zip"
    extract_dir = tmp_path / "out_valid_zip"
    extract_dir.mkdir()

    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("hello.txt", b"Hello Secure World")

    res = extract_archive(str(archive_path), str(extract_dir))
    assert res is True
    assert (extract_dir / "hello.txt").read_bytes() == b"Hello Secure World"


def test_extract_archive_benign_tar(tmp_path):
    """Benign tar.gz extraction must succeed and return True."""
    archive_path = tmp_path / "valid.tar.gz"
    extract_dir = tmp_path / "out_valid_tar"
    extract_dir.mkdir()

    with tarfile.open(archive_path, "w:gz") as tf:
        data = b"Hello Tar World"
        ti = tarfile.TarInfo(name="greeting.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))

    res = extract_archive(str(archive_path), str(extract_dir))
    assert res is True
    assert (extract_dir / "greeting.txt").read_bytes() == b"Hello Tar World"


def test_extract_archive_rejects_zip_traversal(tmp_path):
    """Zip containing relative path traversal (../) must be rejected and return False."""
    archive_path = tmp_path / "traversal.zip"
    extract_dir = tmp_path / "out_traversal_zip"
    extract_dir.mkdir()

    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("../escaped.txt", b"evil traversal payload")

    res = extract_archive(str(archive_path), str(extract_dir))
    assert res is False
    assert not (tmp_path / "escaped.txt").exists()


def test_extract_archive_rejects_tar_traversal(tmp_path):
    """Tar containing relative path traversal (../../) must be rejected and return False."""
    archive_path = tmp_path / "traversal.tar.gz"
    extract_dir = tmp_path / "out_traversal_tar"
    extract_dir.mkdir()

    with tarfile.open(archive_path, "w:gz") as tf:
        data = b"evil traversal"
        ti = tarfile.TarInfo(name="../../traversal_out.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))

    res = extract_archive(str(archive_path), str(extract_dir))
    assert res is False
    assert not (tmp_path / "traversal_out.txt").exists()


def test_extract_archive_rejects_zip_symlink(tmp_path):
    """Zip containing symlink attribute (0o120000) must be rejected and return False."""
    archive_path = tmp_path / "symlink.zip"
    extract_dir = tmp_path / "out_symlink_zip"
    extract_dir.mkdir()

    with zipfile.ZipFile(archive_path, "w") as zf:
        zi = zipfile.ZipInfo("link_target")
        # Set Unix symlink mode
        zi.external_attr = 0o120777 << 16
        zf.writestr(zi, "/etc/passwd")

    res = extract_archive(str(archive_path), str(extract_dir))
    assert res is False


def test_extract_archive_rejects_tar_symlink(tmp_path):
    """Tar containing symlink entry must be rejected and return False."""
    archive_path = tmp_path / "symlink.tar.gz"
    extract_dir = tmp_path / "out_symlink_tar"
    extract_dir.mkdir()

    with tarfile.open(archive_path, "w:gz") as tf:
        ti = tarfile.TarInfo(name="evil_link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/shadow"
        tf.addfile(ti)

    res = extract_archive(str(archive_path), str(extract_dir))
    assert res is False


def test_extract_archive_rejects_size_bomb(tmp_path, monkeypatch):
    """Archive exceeding uncompressed size budget must be rejected and return False."""
    archive_path = tmp_path / "bomb.zip"
    extract_dir = tmp_path / "out_bomb"
    extract_dir.mkdir()

    # Enforce small 1KB threshold
    monkeypatch.setenv("P2P_ARCHIVE_MAX_BYTES", "1024")

    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("large.dat", b"A" * 2048)

    res = extract_archive(str(archive_path), str(extract_dir))
    assert res is False
