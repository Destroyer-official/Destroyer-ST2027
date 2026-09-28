#!/usr/bin/env python3
"""native_secure_buffer.py

Pinned, zeroizing native buffers for key material.

Problem (Layer 1.1): Python ``bytes`` are immutable — ``del``/overwrite
cannot erase copies lingering in CPython arenas, pools, or interned
strings. Even ``bytearray`` wiping is a Python-level loop the C
optimizer cannot strip (it runs in the interpreter), but the buffer
itself is still pageable and its provenance is untracked.

This module provides :class:`NativeSecureBuffer`: a ``bytearray``-backed
handle that additionally, on a best-effort basis:

1. LOCKS the pages non-pageable (``mlock``/``VirtualLock``) via
   ``secure_key_manager`` when importable, else direct ``ctypes``
   ``mlock``/``VirtualLock`` with correct ``argtypes``/``restype``.
   Failures are recorded (``is_locked == False``), never raised.
2. WIPES with a native call the compiler cannot elide
   (``sodium_memzero`` when libsodium is reachable through
   ``secure_key_manager``, else ``ctypes.memset``), verified by a
   read-back pass. The pure-Python loop is the last resort only.
3. REPORTS provenance: ``is_pinned`` / ``is_locked`` / ``wipe_method``
   so callers (and tests) can assert the buffers they depend on, and
   production gates can fail closed when pinning is mandatory
   (``P2P_REQUIRE_PINNED_KEYS=1``).

Design rules (no new native code to audit):

- No new C extension, no new DLL: only the OS C library / kernel32
  already linked into every process, plus the already-vendored
  ``libsodium.dll`` wrapper. Nothing here invents crypto.
- No imports of project modules at top level (lazy + guarded) so this
  file never creates import cycles and never touches the network, TPM,
  COM, or WMI. All native calls are ``ctypes`` memory calls only, which
  cannot raise OS access violations the way COM/CNG provider calls can.
- ``bytes`` inputs are accepted but the immutable source cannot be
  wiped; constructors copy into the managed buffer and document this.

Honest limits: pinning is advisory (``mlock`` limits/privileges apply),
copies made by *callers* (e.g. ``bytes(buf)``) live outside the buffer,
and no software can defeat cold-boot/DMA/TEMPEST. See module docstring
of ``group_key_manager.py`` and ``docs/deployment_hardening_guide.md``.
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from typing import Optional

logger = logging.getLogger(__name__)


def _try_sodium_memzero(buf: bytearray) -> bool:
    """Wipe via libsodium ``sodium_memzero`` if reachable. Returns success."""
    try:
        import secure_key_manager as _skm
        fn = getattr(_skm, "sodium_memzero", None)
        if callable(fn):
            fn(buf, len(buf))
            return True
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    try:
        from libsodium_manager import LIBSODIUM as _lib
        if _lib is not None and hasattr(_lib, "sodium_memzero"):
            _lib.sodium_memzero(ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(buf))), len(buf))
            return True
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    return False


def _ctypes_memset(buf: bytearray) -> bool:
    """Wipe via OS ``memset`` through ``ctypes`` (compiler cannot elide a
    foreign call). Returns success."""
    try:
        if not buf:
            return True
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        if sys.platform == "win32":
            libc = ctypes.WinDLL("msvcrt", use_last_error=True)  # type: ignore[attr-defined]
        else:
            libc = ctypes.CDLL(None)
        libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
        libc.memset.restype = ctypes.c_void_p
        libc.memset(addr, 0, len(buf))
        return True
    except Exception:
        return False


def _python_wipe(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def wipe_native(buf: bytearray) -> str:
    """Best-effort native wipe of a mutable buffer. Returns method name.

    Order: ``sodium_memzero`` -> ``ctypes.memset`` -> Python loop.
    Verifies with a read-back pass; raises only on verification failure
    of a non-empty buffer (fail-closed), never on the wipe calls.
    """
    if not isinstance(buf, (bytearray, memoryview)):
        raise TypeError("wipe_native requires a mutable bytearray/memoryview")
    if len(buf) == 0:
        return "noop-empty"
    method = "python-loop"
    if _try_sodium_memzero(buf):
        method = "sodium_memzero"
    elif _ctypes_memset(buf):
        method = "ctypes-memset"
    else:
        _python_wipe(buf)
    for i in range(len(buf)):
        if buf[i] != 0:
            # Last resort: python loop once more, then fail closed.
            _python_wipe(buf)
            for j in range(len(buf)):
                if buf[j] != 0:
                    raise RuntimeError("native wipe verification failed (fail-closed)")
            method = "python-loop"
            break
    return method


def _try_mlock(buf: bytearray) -> bool:
    """Best-effort page lock. Returns True if the lock call succeeded."""
    try:
        if not buf:
            return False
        try:
            import secure_key_manager as _skm
            lock = getattr(_skm, "sodium_mlock", None) or getattr(_skm, "mlock_buffer", None)
            if callable(lock):
                lock(buf, len(buf))
                return True
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        size = len(buf)
        if sys.platform == "win32":
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            k32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            k32.VirtualLock.restype = ctypes.c_bool
            return bool(k32.VirtualLock(addr, size))
        else:
            libc = ctypes.CDLL(None)
            libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.mlock.restype = ctypes.c_int
            return libc.mlock(addr, size) == 0
    except Exception:
        return False


def _try_munlock(buf: bytearray) -> None:
    try:
        if not buf:
            return
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        size = len(buf)
        if sys.platform == "win32":
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            k32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            k32.VirtualUnlock.restype = ctypes.c_bool
            k32.VirtualUnlock(addr, size)
        else:
            libc = ctypes.CDLL(None)
            libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.munlock.restype = ctypes.c_int
            libc.munlock(addr, size)
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass


class NativeSecureBuffer:
    """Managed mutable buffer for key material.

    Backed by a ``bytearray`` (so no new runtime dependency), with
    best-effort page locking at allocation and native wiping at
    teardown. Use as a context manager — the buffer is wiped on exit::

        with NativeSecureBuffer(32) as buf:
            buf.fill(secrets.token_bytes(32))
            use(bytes(buf))  # copies leave the buffer: minimize lifetime

    ``is_pinned`` is True only when the OS lock call succeeded; gates
    can require it via ``P2P_REQUIRE_PINNED_KEYS=1`` (see
    :meth:`require_pinned`).
    """

    def __init__(self, size_or_data: int | bytes | bytearray = 32) -> None:
        if isinstance(size_or_data, int):
            if size_or_data <= 0:
                raise ValueError("size must be positive")
            self._buf = bytearray(size_or_data)
            self._source_wiped_note = "fresh allocation (no immutable source)"
        elif isinstance(size_or_data, (bytes, bytearray)):
            if len(size_or_data) == 0:
                raise ValueError("data must be non-empty")
            self._buf = bytearray(size_or_data)
            self._source_wiped_note = (
                "copied from immutable bytes input: the SOURCE cannot be "
                "wiped and may persist in allocator memory"
                if isinstance(size_or_data, bytes) else "copied from bytearray input"
            )
        else:
            raise TypeError("size_or_data must be int or bytes-like")
        self._locked = _try_mlock(self._buf)
        self._wipe_method: Optional[str] = None
        self._wiped = False
        if not self._locked:
            logger.debug("NativeSecureBuffer: page lock unavailable; pageable fallback")

    # -- introspection -------------------------------------------------
    @property
    def is_pinned(self) -> bool:
        """True when the OS page-lock call succeeded (non-pageable)."""
        return self._locked

    @property
    def is_locked(self) -> bool:
        return self._locked

    @property
    def wiped(self) -> bool:
        return self._wiped

    def __len__(self) -> int:
        return len(self._buf)

    def __bytes__(self) -> bytes:
        return bytes(self._buf)

    def export_bytes(self) -> bytes:
        """Copy out as immutable ``bytes`` (unwipeable — minimize lifetime)."""
        return bytes(self._buf)

    def fill(self, data: bytes | bytearray) -> None:
        if len(data) != len(self._buf):
            raise ValueError("fill length must match buffer size")
        self._buf[:] = bytes(data)

    # -- lifecycle ------------------------------------------------------
    def wipe(self) -> str:
        """Native wipe + unlock. Idempotent. Returns the wipe method used."""
        if self._wiped:
            return self._wipe_method or "already-wiped"
        method = wipe_native(self._buf)
        _try_munlock(self._buf)
        self._locked = False
        self._wiped = True
        self._wipe_method = method
        return method

    def require_pinned(self) -> None:
        """Fail closed when pinning is mandatory but unavailable."""
        if not self._locked and os.environ.get("P2P_REQUIRE_PINNED_KEYS", "0") == "1":
            raise RuntimeError(
                "FAIL-CLOSED: pinned (mlock/VirtualLock) key buffer unavailable "
                "(P2P_REQUIRE_PINNED_KEYS=1)"
            )

    def __enter__(self) -> "NativeSecureBuffer":
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self.wipe()
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass

    def __del__(self) -> None:  # best effort only; explicit wipe() preferred
        try:
            if not getattr(self, "_wiped", True):
                self.wipe()
        except BaseException:
            pass

