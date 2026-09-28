#!/usr/bin/env python3
"""DestroyerNode — Rust data-plane wrapper (opt-in, staging integration).

Uses `destroyer_core.SecureEngine` for framing/AEAD/replay while session keys
keep coming from the audited Python PQ handshake (ML-KEM-1024 decapsulated
secret via HKDF). Activated only with ``P2P_DATA_PLANE=rust``; default path is
unchanged Python.

Wire format per frame: fixed quantum (256/512/1232B), header
``seq:u64 | len:u16 | type:u8`` + ChaCha20-Poly1305 (16B tag).
Types: 0x01 message, 0xFF chaff (absorbed, never returned).
"""

import os
import time
import secrets

FTYPE_MSG = 0x01
FTYPE_CHAFF = 0xFF


class DataPlaneUnavailable(RuntimeError):
    """Raised when the Rust plane is requested but not built."""


class DestroyerNode:
    """Thin session wrapper over the native SecureEngine."""

    def __init__(self, port: int = 51820):
        self.port = port
        try:
            from destroyer_core import SecureEngine
        except ImportError as e:
            import sys
            import traceback

            raise DataPlaneUnavailable(
                "destroyer_core native module not built. "
                "Run `maturin develop -r` in rust_data_plane/ first. "
                f"cause={e!r} exe={sys.executable} "
                f"path0={sys.path[0] if sys.path else None} "
                f"trace={traceback.format_exc(limit=3)}"
            ) from e
        self.engine = SecureEngine()
        self.udp_sock = None
        self.udp_addr = None
        self._buckets = {}
        self._udp_drops = 0
        self._udp_admitted = 0

    # Upper bound for chunked streams (H24): seal_stream/transmit_large
    # refuse absurd totals instead of building unbounded frame lists.
    MAX_STREAM_BYTES = 16 * 1024 * 1024

    def establish(
        self,
        frame_key: bytes,
        start_seq: int | None = None,
        *,
        is_initiator: bool,
    ) -> None:
        """Bind a 32-byte frame key (from the PQ handshake KDF).

        The caller should wipe its copy after this returns; Rust holds the
        only remaining copy (ZeroizeOnDrop). If a MUTABLE bytearray is
        passed, it is wiped here after the handoff. `is_initiator` MUST be
        true on exactly one side — it separates the two directions into
        distinct nonce domains, so simultaneous traffic can never reuse a nonce.
        """
        if len(frame_key) != 32:
            raise ValueError("frame_key must be 32 bytes")
        if start_seq is None:
            # 32-bit random offset: obscures session sequence position on wire
            # while leaving >18 quintillion packets headroom before 64-bit wrap.
            start_seq = secrets.randbelow(2**32)
        try:
            self.engine.establish_session(bytes(frame_key), start_seq, is_initiator)
        finally:
            if isinstance(frame_key, bytearray):
                for i in range(len(frame_key)):
                    frame_key[i] = 0

    def transmit(self, message: bytes, chaff: bool = False) -> bytes:
        """Seal one message into a fixed-quantum wire frame."""
        ftype = FTYPE_CHAFF if chaff else FTYPE_MSG
        _quantum, frame = self.engine.seal_msg(ftype, bytes(message))
        return frame

    def transmit_large(self, message: bytes) -> list:
        """Seal an arbitrarily large message into ordered 1232B-max frames.

        Split at 1205B boundaries; the receiver reassembles frames in
        sequence order (see :meth:`receive_many`). Every wire frame keeps
        the fixed-quantum shape — size classes leak nothing about total.
        """
        if len(message) > self.MAX_STREAM_BYTES:
            raise ValueError(
                f"Refusing to seal {len(message)} bytes (cap {self.MAX_STREAM_BYTES})")
        out = []
        for i in range(0, max(len(message), 1), 1205):
            chunk = message[i : i + 1205] or b""
            _quantum, frame = self.engine.seal_msg(FTYPE_MSG, bytes(chunk))
            out.append(frame)
            if not message:
                break
        return out

    def receive_many(self, frames) -> bytes:
        """Open an ordered frame list back into one message (inverse of
        :meth:`transmit_large`). Any dropped frame aborts loudly — callers
        must treat partial file receipt as failure, never as data."""
        parts = []
        for frame in frames:
            opened = self.receive(frame)
            if opened is None:
                raise ValueError("chunk failed authentication/replay — abort")
            ftype, payload = opened
            if ftype != FTYPE_MSG:
                raise ValueError("chaff frame inside file stream — abort")
            parts.append(payload)
        return b"".join(parts)

    def seal_stream(self, data: bytes) -> bytes:
        """Seal arbitrary bytes into a self-delimiting stream of wire frames.

        Each frame is length-prefixed (4B big-endian) so one transport write
        carries the whole stream. Used as an OUTER envelope over ratchet
        ciphertext when ``P2P_DATA_PLANE=rust``.
        """
        import struct

        if len(data) > self.MAX_STREAM_BYTES:
            raise ValueError(
                f"Refusing to seal {len(data)} bytes (cap {self.MAX_STREAM_BYTES})")
        out = bytearray()
        for i in range(0, max(len(data), 1), 1205):
            chunk = data[i : i + 1205] or b""
            _quantum, frame = self.engine.seal_msg(FTYPE_MSG, bytes(chunk))
            out += struct.pack(">I", len(frame))
            out += frame
            if not data:
                break
        return bytes(out)

    def open_stream(self, blob: bytes):
        """Inverse of :meth:`seal_stream`. Returns bytes or None (drop silently;
        any single bad frame poisons the whole stream — fail closed)."""
        import struct

        parts = []
        off = 0
        total = 0
        if not blob:
            return None
        while off < len(blob):
            if off + 4 > len(blob):
                return None
            (n,) = struct.unpack_from(">I", blob, off)
            off += 4
            if n == 0 or off + n > len(blob) or n > 1232:
                return None
            opened = self.receive(bytes(blob[off : off + n]))
            if opened is None:
                return None
            ftype, payload = opened
            if ftype != FTYPE_MSG:
                return None
            total += len(payload)
            if total > self.MAX_STREAM_BYTES:
                return None
            parts.append(payload)
            off += n
        return b"".join(parts)

    def receive(self, frame: bytes):
        """Open one wire frame.

        Returns ``(ftype, payload)`` or ``None`` when the frame must be
        dropped silently (bad tag / replay / behind-window). Chaff frames
        report ``(0xFF, b'')`` so the caller can absorb them without logs
        above debug level. NEVER signal the peer on None.
        """
        opened = self.engine.open_msg(bytes(frame))
        if opened is None:
            return None
        ftype, payload = opened
        return (ftype, bytes(payload))

    @property
    def drops(self) -> int:
        return self.engine.drop_count() + self._udp_drops

    # -------------------------------------------------------------------------
    # Phase 3 WireGuard-Style UDP Transport Cutover
    # -------------------------------------------------------------------------
    MAX_DATAGRAM = 1280  # IPv6 minimum MTU (RFC 8200) without fragmentation

    def _check_rate_limit(self, ip: str) -> bool:
        """Token bucket per-source rate limiting: 64 burst capacity, 16 refill/sec."""
        now = time.monotonic()
        if ip not in self._buckets:
            if len(self._buckets) >= 4096:
                # Evict stalest bucket to prevent memory exhaustion
                oldest_ip = min(self._buckets.keys(), key=lambda k: self._buckets[k][1])
                del self._buckets[oldest_ip]
            self._buckets[ip] = [64.0, now]

        tokens, last = self._buckets[ip]
        dt = now - last
        tokens = min(64.0, tokens + dt * 16.0)
        self._buckets[ip] = [tokens, now]

        if tokens >= 1.0:
            self._buckets[ip][0] = tokens - 1.0
            return True
        return False

    def bind_udp(self, host: str = "127.0.0.1", port: int = 0) -> tuple[str, int]:
        """Bind local UDP socket for silent-drop data plane traffic."""
        import socket
        if self.udp_sock is not None:
            self.close_udp()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        sock.settimeout(0.5)
        self.udp_sock = sock
        self.udp_addr = sock.getsockname()
        return self.udp_addr

    def send_udp_msg(self, message: bytes, dest: tuple[str, int], chaff: bool = False) -> int:
        """Seal message into fixed quantum wire frame and send via UDP."""
        if self.udp_sock is None:
            raise RuntimeError("UDP socket not bound: call bind_udp first")
        frame = self.transmit(message, chaff=chaff)
        if len(frame) > self.MAX_DATAGRAM:
            raise ValueError(f"Frame exceeds MAX_DATAGRAM ({len(frame)} > {self.MAX_DATAGRAM})")
        return self.udp_sock.sendto(frame, dest)

    def recv_udp_msg(self, timeout: float = 0.5) -> tuple[bytes, tuple[str, int]] | None:
        """Receive one UDP datagram with black-hole silent drop discipline."""
        if self.udp_sock is None:
            raise RuntimeError("UDP socket not bound: call bind_udp first")
        import socket
        self.udp_sock.settimeout(timeout)
        try:
            raw, from_addr = self.udp_sock.recvfrom(self.MAX_DATAGRAM + 1)
        except (socket.timeout, TimeoutError):
            return None
        except Exception:
            self._udp_drops += 1
            return None

        # Silent drop if oversized (would be fragmented on wire)
        if len(raw) > self.MAX_DATAGRAM:
            self._udp_drops += 1
            return None

        # Silent drop if over rate limit budget
        if not self._check_rate_limit(from_addr[0]):
            self._udp_drops += 1
            return None

        self._udp_admitted += 1
        opened = self.receive(raw)
        if opened is None:
            self._udp_drops += 1
            return None

        ftype, payload = opened
        if ftype == FTYPE_CHAFF:
            return None  # Chaff absorbed silently

        return payload, from_addr

    def close_udp(self) -> None:
        """Close UDP socket and flush rate buckets."""
        if self.udp_sock is not None:
            try:
                self.udp_sock.close()
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            self.udp_sock = None
            self.udp_addr = None
        self._buckets.clear()


def data_plane_mode() -> str:
    """Return active data plane mode: 'rust_udp', 'rust', or 'python'."""
    val = os.environ.get("P2P_DATA_PLANE", "python").strip().lower()
    if val in ("rust_udp", "udp"):
        return "rust_udp"
    if val in ("rust", "rust_stream"):
        return "rust"
    return "python"


def data_plane_enabled() -> bool:
    """Operator opt-in flag (true if rust stream or rust_udp is active)."""
    return data_plane_mode() in ("rust", "rust_udp")


def udp_data_plane_enabled() -> bool:
    """Operator opt-in flag strictly for WireGuard-style UDP cutover."""
    return data_plane_mode() == "rust_udp"


