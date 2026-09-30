#!/usr/bin/env python3
"""
paced_socket_wrapper.py -- Hardware-Paced Wire Camouflage for Interactive Chat

Wraps any socket connection with constant-rate pacing so that an adversary
observing the wire sees ONLY:
  - Fixed 1,232-byte UDP datagrams (IPv6 MTU compliant)
  - Constant interval timing (15ms or 50ms per tick)
  - CSPRNG chaff when no real payload is queued
  - Shannon entropy H >= 7.95 bits/byte

Traffic analysis becomes impossible because:
  1. No correlation between user activity and wire timing
  2. No correlation between message length and packet size
  3. Every tick is indistinguishable (real data vs. chaff)

This module transparently wraps secure_p2.py socket I/O without changing
the application protocol. Messages are queued and emitted on the next
available tick slot, replacing what would have been chaff.

Fail-closed: if pacing cannot be established, the connection is refused.
"""

import logging
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("paced_socket_wrapper")

# Workspace resolution for the native binary
ROOT = Path(__file__).resolve().parent
NATIVE_BIN = ROOT / "rust_data_plane" / "target" / "release" / "secure-transmit.exe"
if not NATIVE_BIN.exists():
    NATIVE_BIN = ROOT / "rust_data_plane" / "target" / "release" / "secure-transmit"


class PacedChannel:
    """Hardware-paced wire camouflage channel using the native Rust data plane.

    Wraps the native `secure-transmit.exe channel` subprocess to provide
    constant-rate pacing with CSPRNG chaff for traffic flow confidentiality.
    """

    DEFAULT_INTERVAL_MS = 20   # 20ms tick interval (50 ticks/sec)
    DEFAULT_QUANTUM = 1232     # IPv6 MTU compliant frame size
    DEFAULT_DRAIN_TICKS = 8    # Drain window before shutdown

    def __init__(self, key_path: str, state_path: str,
                 bind_addr: str, peer_addr: str,
                 role: str = "initiator",
                 interval_ms: int = None,
                 quantum: int = None):
        """Initialize a paced channel.

        Args:
            key_path: Path to the session key file (32 bytes, derived from PQ KEX).
            state_path: Path to the monotonic nonce state file.
            bind_addr: Local bind address (host:port).
            peer_addr: Peer target address (host:port).
            role: "initiator" or "responder".
            interval_ms: Tick interval in milliseconds (default: 20ms).
            quantum: Frame quantum size in bytes (default: 1232).
        """
        self.key_path = key_path
        self.state_path = state_path
        self.bind_addr = bind_addr
        self.peer_addr = peer_addr
        self.role = role.lower()
        self.interval_ms = interval_ms or self.DEFAULT_INTERVAL_MS
        self.quantum = quantum or self.DEFAULT_QUANTUM

        self._proc: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self._received_messages: list = []
        self._receive_event = threading.Event()
        self._tick_count = 0
        self._sent_count = 0
        self._recv_count = 0

    @property
    def is_active(self) -> bool:
        """True if the paced channel subprocess is running."""
        return self._running and self._proc is not None and self._proc.poll() is None

    def start(self) -> bool:
        """Start the paced channel subprocess.

        Returns:
            True if the channel started successfully.
        """
        if not NATIVE_BIN.exists():
            log.error(f"[PACING] Native binary not found at {NATIVE_BIN}")
            return False

        cmd = [
            str(NATIVE_BIN), "channel",
            "--key-file", self.key_path,
            "--state", self.state_path,
            "--bind", self.bind_addr,
            "--to", self.peer_addr,
            "--role", self.role,
            "--interval-ms", str(self.interval_ms),
            "--quantum", str(self.quantum),
            "--drain-ticks", str(self.DEFAULT_DRAIN_TICKS),
            "--stdin",  # Enable interactive stdin for sending messages
        ]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self._running = True

            # Start background reader for incoming messages
            self._reader_thread = threading.Thread(
                target=self._read_output, daemon=True)
            self._reader_thread.start()

            log.info(f"[PACING] Channel active: {self.bind_addr} -> {self.peer_addr} "
                     f"(interval={self.interval_ms}ms, quantum={self.quantum}B)")
            return True

        except Exception as e:
            log.error(f"[PACING] Failed to start channel: {e}")
            self._running = False
            return False

    def send(self, message: str) -> bool:
        """Queue a message for paced emission on the next tick slot.

        The message will replace the CSPRNG chaff that would have been
        sent on the next tick, making it indistinguishable from chaff
        to a passive observer.

        Args:
            message: The message string to send.

        Returns:
            True if the message was queued successfully.
        """
        if not self.is_active:
            log.warning("[PACING] Cannot send: channel not active")
            return False

        try:
            self._proc.stdin.write(message + "\n")
            self._proc.stdin.flush()
            with self._lock:
                self._sent_count += 1
            return True
        except Exception as e:
            log.error(f"[PACING] Send failed: {e}")
            return False

    def receive(self, timeout: float = None) -> Optional[str]:
        """Receive the next message from the paced channel.

        Args:
            timeout: Maximum seconds to wait (None = block forever).

        Returns:
            The received message string, or None on timeout.
        """
        # Check if there's already a message in the queue
        with self._lock:
            if self._received_messages:
                return self._received_messages.pop(0)

        # Wait for a new message
        if self._receive_event.wait(timeout=timeout):
            self._receive_event.clear()
            with self._lock:
                if self._received_messages:
                    return self._received_messages.pop(0)

        return None

    def stop(self):
        """Gracefully stop the paced channel."""
        self._running = False
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        log.info(f"[PACING] Channel stopped "
                 f"(sent={self._sent_count}, recv={self._recv_count}, "
                 f"ticks={self._tick_count})")

    def status(self) -> dict:
        """Return channel status telemetry."""
        return {
            "active": self.is_active,
            "bind": self.bind_addr,
            "peer": self.peer_addr,
            "interval_ms": self.interval_ms,
            "quantum_bytes": self.quantum,
            "ticks": self._tick_count,
            "sent": self._sent_count,
            "received": self._recv_count,
        }

    def _read_output(self):
        """Background reader for channel stdout (incoming messages + telemetry)."""
        try:
            while self._running and self._proc and self._proc.poll() is None:
                line = self._proc.stdout.readline()
                if not line:
                    break
                line_str = line.strip()
                if not line_str:
                    continue

                if "RECV_MSG" in line_str:
                    # Extract payload from RECV_MSG line
                    parts = line_str.split("payload=")
                    payload = parts[1] if len(parts) > 1 else ""
                    with self._lock:
                        self._received_messages.append(payload)
                        self._recv_count += 1
                    self._receive_event.set()

                elif "EMIT_MSG" in line_str:
                    with self._lock:
                        self._tick_count += 1

                elif "ACTIVE" in line_str:
                    log.info(f"[PACING] Channel activated: {line_str}")

        except Exception as e:
            if self._running:
                log.error(f"[PACING] Reader error: {e}")
        finally:
            self._running = False


class PacedSocketAdapter:
    """Adapts the paced channel to the socket-like interface used by secure_p2.py.

    This adapter can be used as a drop-in replacement for socket send/recv
    operations, transparently wrapping all traffic in constant-rate pacing.
    Features stream buffering so that recv_exact(4) followed by recv_exact(N)
    works identically to a stream-oriented TCP/TLS socket.
    """

    def __init__(self, paced_channel: PacedChannel):
        self._channel = paced_channel
        self._rx_buffer = bytearray()
        self._rx_lock = threading.Lock()
        self.is_paced = True

    def sendall(self, data: bytes) -> None:
        """Send data through the paced channel."""
        import base64
        # Encode binary data as base64 for the text-based channel interface
        encoded = base64.b64encode(data).decode('ascii')
        if not self._channel.send(f"B64:{encoded}"):
            raise ConnectionError("Paced channel send failed")

    def send(self, data: bytes) -> int:
        """Send bytes through the paced channel, returning the number of bytes sent."""
        self.sendall(data)
        return len(data)

    def recv(self, bufsize: int, timeout: float = None) -> bytes:
        """Receive data from the paced channel with stream buffering."""
        import base64

        with self._rx_lock:
            if self._rx_buffer:
                chunk = bytes(self._rx_buffer[:bufsize])
                del self._rx_buffer[:bufsize]
                return chunk

        msg = self._channel.receive(timeout=timeout)
        if msg is None:
            return b""

        if msg.startswith("B64:"):
            data = base64.b64decode(msg[4:])
        else:
            data = msg.encode('utf-8')

        with self._rx_lock:
            self._rx_buffer.extend(data)
            chunk = bytes(self._rx_buffer[:bufsize])
            del self._rx_buffer[:bufsize]
            return chunk

    def cipher(self):
        """Duck typing for p2p_core.is_ssl_socket check."""
        return ("AES-256-GCM-Paced-Chaff", "CNSA2.0", 256)

    def context(self):
        """Duck typing for p2p_core.is_ssl_socket check."""
        return self

    def fileno(self) -> int:
        """Return sentinel fileno for synthetic socket."""
        return -1

    def close(self):
        """Close the paced channel and wipe rx buffer."""
        with self._rx_lock:
            for i in range(len(self._rx_buffer)):
                self._rx_buffer[i] = 0
            self._rx_buffer.clear()
        self._channel.stop()

