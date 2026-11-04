"""Regression tests for F-06: Atomic Non-Symlink File Write in secure_transmit_2027.py."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from secure_transmit_2027 import _secure_atomic_write, SecurityError


def test_atomic_write_normal():
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "output.bin"
        data = b"TOP SECRET MISSION PAYLOAD 2027"
        written = _secure_atomic_write(dest, data)
        assert written == dest
        assert dest.exists()
        assert dest.read_bytes() == data


def test_atomic_write_overwrite_regular_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "output.bin"
        dest.write_bytes(b"OLD DATA")
        new_data = b"NEW AUTHENTICATED PAYLOAD"
        _secure_atomic_write(dest, new_data)
        assert dest.read_bytes() == new_data


def test_atomic_write_refuses_symlink_mocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "output.bin"
        with patch.object(Path, "is_symlink", return_value=True):
            with pytest.raises(SecurityError, match="symlink target refused"):
                _secure_atomic_write(dest, b"MALICIOUS")


def test_atomic_write_refuses_symlink_destination():
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "sensitive_target.txt"
        target.write_bytes(b"CRITICAL CONFIG DO NOT OVERWRITE")
        symlink_dest = Path(tmpdir) / "symlink_dest.bin"
        try:
            os.symlink(target, symlink_dest)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not permitted/supported on this platform without privileges")

        # Attempt to write to symlink destination must fail
        with pytest.raises(SecurityError, match="symlink target refused"):
            _secure_atomic_write(symlink_dest, b"MALICIOUS OVERWRITE")

        # Verify target was NOT modified
        assert target.read_bytes() == b"CRITICAL CONFIG DO NOT OVERWRITE"


def test_atomic_write_refuses_symlink_parent():
    with tempfile.TemporaryDirectory() as tmpdir:
        real_dir = Path(tmpdir) / "real_dir"
        real_dir.mkdir()
        symlink_dir = Path(tmpdir) / "symlink_dir"
        try:
            os.symlink(real_dir, symlink_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not permitted/supported on this platform without privileges")

        dest = symlink_dir / "target.bin"
        with pytest.raises(SecurityError, match="symlink target refused"):
            _secure_atomic_write(dest, b"MALICIOUS OVERWRITE")
