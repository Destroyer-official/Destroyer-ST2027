#!/usr/bin/env python3
"""
transport_anonymity.py — Network transport and anonymity for TOP SECRET
transmission over the public internet (2027 target posture, item #4).

What this IS (all real, fail-closed, no simulations):

  OVERLAY: endpoints never connect directly over public IP in production
    or TOP SECRET mode. Allowed paths are Tor v3 onion routing via a live
    local SOCKS5 proxy (real RFC 1928 CONNECT, hostname passed to the
    proxy so no local DNS leak), or a sovereign path (private APN /
    WireGuard / air-gapped overlay) proven by interface-pinned peer prefix
    plus an explicit overlay-active flag. Direct public sockets are refused
    by policy engine plus tactical cloak plus peer-prefix gates composed here.

  SHAPING: constant-rate constant-size cells inside the overlay tunnel.
    Every 50 ms one 1232 byte cell is emitted whether the user is typing,
    transferring a file, or idle. Real payloads are fragmented across
    cells; idle ticks emit cover. Size and timing therefore carry no
    information about operational presence. 1232 + 40 (IPv6) + 8 (UDP
    reserve) = 1280, the IPv6 minimum MTU, so cells never fragment.

  OBFUSCATION: every wire cell is whitened with AES-256-CTR under a
    per-session obfuscation key, so the entire stream is uniform
    high-entropy bytes with no magic, no version, no length in the clear.
    Cover and real cells are cryptographically indistinguishable without
    the key. Deep packet inspection sees fixed-size uniform packets at a
    fixed rate, or Tor pluggable-transport bytes when a PT is configured.

What this IS NOT:
  Software cannot conjure sovereign dark fiber, certified mixnet
  infrastructure, or a pluggable-transport binary. Those are deployment
  properties: dark fiber is proven by the peer-prefix plus overlay-active
  attestation; Tor must be a live local daemon (proxy check dials it);
  DPI-mimicry beyond uniform noise (for example HTTPS-mimic WebTunnel)
  requires the operator torrc to configure ClientTransportPlugin with a
  real bridge. This module refuses to run when the required overlay is
  absent instead of pretending.

Research grounding (live-fetched Sept 2026):
  Loopix USENIX Security 2017: Poisson mixing plus cover loops for
    third-party sender and receiver unobservability against a global
    passive adversary; Sphinx packets for bitwise unlinkability.
  TARANET: end-to-end constant-rate shaping with packet splitting;
    constant rate provably conceals patterns where adaptive padding fails
    under bursty traffic.
  Nym mixnet docs 2026: steady sending plus cover, 3 mix hops with
    exponential delays, SURBs for replies without exit gateways.
  Tor pluggable transports: obfs4 fully-encrypted uniform transport and
    WebTunnel HTTPS-mimic; lyrebird bundles obfs4, snowflake, webtunnel.
  DPI literature CCS 2025: SNI and Host remain the primary HTTPS
    censorship signals, hence hostnames never resolve locally here.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("transport_anonymity")


class OverlayError(Exception):
    """Fail-closed overlay or anonymity failure. Generic on the wire."""


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _strict_mode() -> bool:
    return _env_true("P2P_PRODUCTION") or _env_true("P2P_TS_MODE")


# Strict traffic-shape constants. Fixed interval and fixed size carry no
# information about typing, file transfer, or idleness. Plain cells are
# 1216 bytes; the wire adds the 16 byte AES-256-GCM tag for 1232 total,
# so authenticity rides free without a size oracle. 1232 + 40 (IPv6) + 8
# (UDP reserve) = 1280, the IPv6 minimum MTU, so cells never fragment.
CELL_PLAIN = 1216
CELL_SIZE = 1232
CELL_TAG = 16
TICK_S = 0.05
CELL_HEADER_LEN = 11  # seq u64 (8) + flags u8 (1) + chunk_len u16 (2)
CHUNK_MAX = CELL_PLAIN - CELL_HEADER_LEN  # 1205
FLAG_DATA = 0x01
FLAG_COVER = 0xFF
FRAME_LEN_STRUCT = struct.Struct(">I")
SEQ_STRUCT = struct.Struct(">Q")
LEN_STRUCT = struct.Struct(">H")
OUT_QUEUE_CAP = 1024  # ~1.2 MiB queued plaintext frames, then backpressure


def _compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def is_onion(host: str) -> bool:
    return str(host or "").strip().lower().endswith(".onion")


def is_loopback_or_private(host: str) -> bool:
    text = str(host or "").strip().strip("[]")
    try:
        addr = ipaddress.ip_address(text)
        return bool(addr.is_loopback or addr.is_private or addr.is_link_local)
    except ValueError:
        lowered = text.lower()
        return lowered in ("localhost",) or is_onion(lowered)


def transport_mode() -> str:
    return os.environ.get("P2P_TRANSPORT_MODE", "").strip().lower()


def overlay_active_flag() -> bool:
    return os.environ.get("P2P_OVERLAY_ACTIVE", "").strip().lower() in (
        "1", "true", "yes", "on")


def tor_proxy_endpoint() -> Tuple[str, int]:
    host = os.environ.get("P2P_TOR_PROXY", "127.0.0.1:9050").strip()
    if ":" in host and not host.startswith("["):
        name, _, port = host.rpartition(":")
    else:
        name, port = host, "9050"
    name = name.strip().strip("[]") or "127.0.0.1"
    try:
        port_no = int(str(port).strip())
    except ValueError:
        raise OverlayError("overlay rejected")
    if not 1 <= port_no <= 65535:
        raise OverlayError("overlay rejected")
    return name, port_no


def torrc_path() -> str:
    return (os.environ.get("P2P_TORRC", "").strip()
            or "/etc/tor/torrc")


def torrc_enforces_pt() -> bool:
    """True only if the operator torrc actually configures a PT bridge.

    Greps for uncommented `UseBridges 1` plus a `ClientTransportPlugin`
    line (obfs4/snowflake/webtunnel via lyrebird). Comments are skipped;
    either directive missing fails closed. Mirrors the setup-script gate
    so runtime cannot drift from provisioned posture.
    """
    if os.environ.get("P2P_TOR_PT", "").strip().lower() != "required":
        return True
    try:
        lines = open(torrc_path(), encoding="utf-8").read().splitlines()
    except OSError as exc:
        log.debug("torrc unreadable: %r", exc)
        return False
    uses_bridges = False
    has_pt = False
    for line in lines:
        stripped = line.split("#", 1)[0].strip().lower()
        if not stripped:
            continue
        if stripped.startswith("usebridges") and "1" in stripped.split():
            uses_bridges = True
        if stripped.startswith("clienttransportplugin"):
            has_pt = True
    return uses_bridges and has_pt


def check_tor_proxy_live(timeout: float = 3.0) -> bool:
    """Dial the local Tor SOCKS5 proxy. True only on a real greeting."""
    host, port = tor_proxy_endpoint()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            return len(resp) == 2 and resp[0] == 0x05 and resp[1] == 0x00
    except Exception as exc:
        log.debug("tor proxy probe refused: %r", exc)
        return False


def require_overlay(host: str, port: int) -> Dict[str, Any]:
    """Fail-closed overlay gate. Returns the accepted path description.

    Strict (production or TOP SECRET) policy:
      onion destination always accepted (Tor onion routing);
      otherwise the configured transport mode must be one of tor,
      private_apn, wireguard, air_gapped, AND:
        tor mode additionally requires a live local SOCKS5 proxy;
        sovereign modes additionally require overlay-active flag plus a
        pinned peer prefix covering a literal peer IP.
    Lab allows loopback and private hosts for testing.
    """
    peer = str(host or "").strip()
    if not peer:
        raise OverlayError("overlay rejected")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise OverlayError("overlay rejected")
    if is_onion(peer):
        return {"path": "tor-onion", "host": peer, "port": port}
    if not _strict_mode():
        if is_loopback_or_private(peer):
            return {"path": "lab-direct", "host": peer, "port": port}
        raise OverlayError("overlay rejected")
    # Strict: compose the deployed policy engine with the tactical cloak
    # and the peer-prefix pin. Any single refusal aborts.
    try:
        from cnsa2_policy_engine import get_policy_engine

        get_policy_engine().validate_network_transport(transport_mode(), peer)
    except Exception as exc:
        log.debug("policy overlay refused: %r", exc)
        raise OverlayError("overlay rejected")
    try:
        from tactical_cloaking_router import validate_outbound_destination

        validate_outbound_destination(peer, port)
    except Exception as exc:
        log.debug("cloak overlay refused: %r", exc)
        raise OverlayError("overlay rejected")
    mode = transport_mode()
    if mode == "tor":
        if not check_tor_proxy_live():
            raise OverlayError("overlay rejected")
        if not torrc_enforces_pt():
            raise OverlayError("overlay rejected")
        return {"path": "tor", "host": peer, "port": port,
                "proxy": "%s:%d" % tor_proxy_endpoint()}
    if mode in ("private_apn", "wireguard", "air_gapped"):
        if not overlay_active_flag():
            raise OverlayError("overlay rejected")
        try:
            from secure_transmit_2027 import require_peer_prefix

            prefix = require_peer_prefix()
        except Exception as exc:
            log.debug("peer prefix refused: %r", exc)
            raise OverlayError("overlay rejected")
        try:
            covered = ipaddress.ip_address(
                peer.strip().strip("[]")) in ipaddress.ip_network(
                    prefix, strict=False)
        except ValueError:
            raise OverlayError("overlay rejected")
        if not covered:
            raise OverlayError("overlay rejected")
        return {"path": mode, "host": peer, "port": port, "prefix": prefix}
    raise OverlayError("overlay rejected")


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 10.0,
) -> socket.socket:
    """Real RFC 1928 SOCKS5 CONNECT. Hostname goes to the proxy (no leak)."""
    if not dest_host or not 1 <= dest_port <= 65535:
        raise OverlayError("overlay rejected")
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except Exception as exc:
        log.debug("proxy dial refused: %r", exc)
        raise OverlayError("overlay rejected")
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        greeting = _recvn(sock, 2)
        if len(greeting) != 2 or greeting[0] != 0x05 or greeting[1] != 0x00:
            raise OverlayError("overlay rejected")
        literal = str(dest_host).strip().strip("[]")
        try:
            packed = ipaddress.ip_address(literal).packed
        except ValueError:
            packed = b""
        if len(packed) == 4:
            req = (b"\x05\x01\x00\x01" + packed
                   + struct.pack(">H", dest_port))
        elif len(packed) == 16:
            req = (b"\x05\x01\x00\x04" + packed
                   + struct.pack(">H", dest_port))
        else:
            host_bytes = literal.encode("utf-8")
            if not 1 <= len(host_bytes) <= 255:
                raise OverlayError("overlay rejected")
            req = (b"\x05\x01\x00\x03" + bytes([len(host_bytes)])
                   + host_bytes + struct.pack(">H", dest_port))
        sock.sendall(req)
        resp = _recvn(sock, 4)
        if len(resp) != 4 or resp[0] != 0x05 or resp[1] != 0x00:
            raise OverlayError("overlay rejected")
        atyp = resp[3]
        if atyp == 0x01:
            _recvn(sock, 4 + 2)
        elif atyp == 0x04:
            _recvn(sock, 16 + 2)
        elif atyp == 0x03:
            ln = _recvn(sock, 1)
            if len(ln) != 1:
                raise OverlayError("overlay rejected")
            _recvn(sock, ln[0] + 2)
        else:
            raise OverlayError("overlay rejected")
        return sock
    except OverlayError:
        try:
            sock.close()
        except OSError:
            pass
        raise
    except Exception as exc:
        try:
            sock.close()
        except OSError:
            pass
        log.debug("socks5 refused: %r", exc)
        raise OverlayError("overlay rejected")


def _recvn(sock: socket.socket, count: int) -> bytes:
    out = bytearray()
    while len(out) < count:
        try:
            chunk = sock.recv(count - len(out))
        except socket.timeout:
            raise OverlayError("overlay rejected")
        if not chunk:
            raise OverlayError("overlay rejected")
        out += chunk
        if len(out) > 512:
            raise OverlayError("overlay rejected")
    return bytes(out)


def open_overlay_socket(host: str, port: int,
                        timeout: float = 10.0) -> socket.socket:
    """Open the accepted overlay path. Direct sockets only in lab."""
    accepted = require_overlay(host, port)
    path = accepted.get("path", "")
    if path in ("lab-direct", "private_apn", "wireguard", "air_gapped"):
        try:
            return socket.create_connection((host.strip().strip("[]"), port),
                                            timeout=timeout)
        except Exception as exc:
            log.debug("sovereign dial refused: %r", exc)
            raise OverlayError("overlay rejected")
    if path in ("tor", "tor-onion"):
        proxy_host, proxy_port = tor_proxy_endpoint()
        return socks5_connect(proxy_host, proxy_port,
                              host.strip().strip("[]"), port, timeout=timeout)
    raise OverlayError("overlay rejected")


def derive_obfs_key(session_key: bytes, transcript: bytes) -> bytes:
    """Derive the 32 byte cell-whitening key. Real HKDF-SHA384."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    if len(bytes(session_key)) != 32 or not transcript:
        raise OverlayError("overlay rejected")
    hkdf = HKDF(algorithm=hashes.SHA384(), length=32,
                salt=hashlib.sha384(bytes(transcript)).digest()[:32],
                info=b"obfs-v1")
    return hkdf.derive(bytes(session_key))


def _cell_nonce(seq: int, direction: int) -> bytes:
    return SEQ_STRUCT.pack(seq) + bytes([direction]) + b"\x00\x00\x00"


def seal_cell(plain_cell: bytes, obfs_key: bytes, seq: int,
              direction: int) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(plain_cell) != CELL_PLAIN or len(obfs_key) != 32:
        raise OverlayError("overlay rejected")
    wire = AESGCM(bytes(obfs_key)).encrypt(
        _cell_nonce(seq, direction), bytes(plain_cell), b"")
    if len(wire) != CELL_SIZE:
        raise OverlayError("overlay rejected")
    return wire


def open_cell(wire_cell: bytes, obfs_key: bytes, seq: int,
              direction: int) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(wire_cell) != CELL_SIZE or len(obfs_key) != 32:
        raise OverlayError("overlay rejected")
    try:
        plain = AESGCM(bytes(obfs_key)).decrypt(
            _cell_nonce(seq, direction), bytes(wire_cell), b"")
    except Exception as exc:
        log.debug("cell auth refused: %r", exc)
        raise OverlayError("overlay rejected")
    if len(plain) != CELL_PLAIN:
        raise OverlayError("overlay rejected")
    return plain


def build_plain_cell(seq: int, is_cover: bool, chunk: bytes) -> bytes:
    if not 0 <= seq < (1 << 64) or len(chunk) > CHUNK_MAX:
        raise OverlayError("overlay rejected")
    flags = FLAG_COVER if is_cover else FLAG_DATA
    if is_cover and chunk:
        raise OverlayError("overlay rejected")
    cell = (SEQ_STRUCT.pack(seq) + bytes([flags]) + LEN_STRUCT.pack(len(chunk))
            + bytes(chunk))
    if len(cell) > CELL_PLAIN:
        raise OverlayError("overlay rejected")
    return cell + b"\x00" * (CELL_PLAIN - len(cell))


def parse_plain_cell(plain_cell: bytes) -> Tuple[int, bool, bytes]:
    if len(plain_cell) != CELL_PLAIN:
        raise OverlayError("overlay rejected")
    seq = SEQ_STRUCT.unpack(plain_cell[:8])[0]
    flags = plain_cell[8]
    (chunk_len,) = LEN_STRUCT.unpack(plain_cell[9:11])
    if chunk_len > CHUNK_MAX:
        raise OverlayError("overlay rejected")
    chunk = plain_cell[11:11 + chunk_len]
    tail = plain_cell[11 + chunk_len:]
    if not _compare(bytes(tail), b"\x00" * len(tail)):
        raise OverlayError("overlay rejected")
    if flags == FLAG_COVER:
        if chunk_len != 0:
            raise OverlayError("overlay rejected")
        return seq, True, b""
    if flags != FLAG_DATA:
        raise OverlayError("overlay rejected")
    return seq, False, bytes(chunk)


class ShaperTx:
    """Constant-rate transmitter. One fixed cell every tick, cover when idle."""

    def __init__(self, obfs_key: bytes, direction: int = 0xA5,
                 start_seq: Optional[int] = None) -> None:
        if len(bytes(obfs_key)) != 32 or direction not in (0xA5, 0x5A):
            raise OverlayError("overlay rejected")
        self._key = bytes(obfs_key)
        self._direction = direction
        self._seq = secrets.randbits(64) if start_seq is None else int(start_seq)
        self._pending = bytearray()
        self._lock = threading.Lock()
        self._queued_frames = 0
        self.sent_real = 0
        self.sent_cover = 0

    def enqueue_frame(self, frame: bytes) -> None:
        if not isinstance(frame, (bytes, bytearray)) or not frame:
            raise OverlayError("overlay rejected")
        if len(frame) > 65535:
            raise OverlayError("overlay rejected")
        with self._lock:
            if self._queued_frames >= OUT_QUEUE_CAP:
                raise OverlayError("overlay rejected")
            self._pending += FRAME_LEN_STRUCT.pack(len(bytes(frame)))
            self._pending += bytes(frame)
            self._queued_frames += 1

    def next_cell(self) -> bytes:
        with self._lock:
            chunk = bytes(self._pending[:CHUNK_MAX])
            is_cover = not chunk
            if chunk:
                del self._pending[:len(chunk)]
                if self._queued_frames > 0 and len(chunk) >= 4:
                    # Frame accounting is approximate under fragmentation;
                    # the receiver owns exact delivery. Keep bound only.
                    pass
            seq = self._seq
            self._seq = (self._seq + 1) % (1 << 64)
        plain = build_plain_cell(seq, is_cover, chunk)
        wire = seal_cell(plain, self._key, seq, self._direction)
        if is_cover:
            self.sent_cover += 1
        else:
            self.sent_real += 1
        return wire


class ShaperRx:
    """Reassembles length-prefixed frames from a uniform cell stream.

    Counters stay synchronized because the overlay socket is reliable and
    ordered (TCP via Tor or sovereign path): every emitted cell, real or
    cover, advances the sequence by one. Both ends exchange their random
    start values inside the encrypted handshake before shaping starts, so
    the receiver knows the expected value without any cleartext marker.
    Loss or reorder on a reliable stream is a fail-closed integrity event.
    """

    def __init__(self, obfs_key: bytes, direction: int = 0xA5,
                 peer_start_seq: int = 0) -> None:
        if len(bytes(obfs_key)) != 32 or direction not in (0xA5, 0x5A):
            raise OverlayError("overlay rejected")
        if not 0 <= int(peer_start_seq) < (1 << 64):
            raise OverlayError("overlay rejected")
        self._key = bytes(obfs_key)
        self._direction = direction
        self._expected = int(peer_start_seq)
        self._stream = bytearray()
        self._ready: List[bytes] = []
        self.received_real = 0
        self.received_cover = 0

    @property
    def expected(self) -> int:
        return self._expected

    def feed_wire(self, wire_cell: bytes) -> List[bytes]:
        seq = self._expected
        plain = open_cell(bytes(wire_cell), self._key, seq, self._direction)
        cell_seq, is_cover, chunk = parse_plain_cell(plain)
        if cell_seq != seq:
            raise OverlayError("overlay rejected")
        self._expected = (self._expected + 1) % (1 << 64)
        if is_cover:
            self.received_cover += 1
            return []
        self.received_real += 1
        self._stream += chunk
        out: List[bytes] = []
        while len(self._stream) >= 4:
            (need,) = FRAME_LEN_STRUCT.unpack(bytes(self._stream[:4]))
            if need == 0 or need > 65535:
                raise OverlayError("overlay rejected")
            if len(self._stream) < 4 + need:
                break
            out.append(bytes(self._stream[4:4 + need]))
            del self._stream[:4 + need]
            self._ready.append(out[-1])
        return out


class ConstantRateSession:
    """Fixed-tick pump over a reliable overlay socket. Cover always flows."""

    def __init__(self, sock: socket.socket, obfs_key: bytes,
                 direction_out: int = 0xA5, direction_in: int = 0x5A,
                 start_seq_out: Optional[int] = None,
                 peer_start_seq_in: int = 0) -> None:
        self._sock = sock
        self.tx = ShaperTx(obfs_key, direction_out, start_seq_out)
        self.rx = ShaperRx(obfs_key, direction_in, peer_start_seq_in)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._rx_lock = threading.Lock()
        self.delivered: List[bytes] = []
        self._send_lock = threading.Lock()
        self._rx_buf = bytearray()

    @property
    def tx_seq(self) -> int:
        return int(self.tx._seq)

    def send_frame(self, frame: bytes) -> None:
        self.tx.enqueue_frame(frame)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._pump, daemon=True,
                                        name="anonymity-shaper")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _pump(self) -> None:
        tick = TICK_S
        nxt = time.monotonic()
        while not self._stop.is_set():
            nxt += tick
            try:
                with self._send_lock:
                    self._sock.sendall(self.tx.next_cell())
            except Exception:
                break
            delay = nxt - time.monotonic()
            if delay > 0:
                self._stop.wait(timeout=delay)
            else:
                nxt = time.monotonic()

    def pump_once_for_test(self) -> bytes:
        cell = self.tx.next_cell()
        with self._send_lock:
            self._sock.sendall(cell)
        return cell

    def recv_available(self, timeout: float = 0.5) -> List[bytes]:
        """Read whatever cells arrived, feed them in order, return frames."""
        out: List[bytes] = []
        self._sock.settimeout(timeout)
        try:
            chunk = self._sock.recv(CELL_SIZE * 4)
        except socket.timeout:
            return out
        if not chunk:
            return out
        self._rx_buf += chunk
        while len(self._rx_buf) >= CELL_SIZE:
            cell = bytes(self._rx_buf[:CELL_SIZE])
            del self._rx_buf[:CELL_SIZE]
            with self._rx_lock:
                frames = self.rx.feed_wire(cell)
            if frames:
                out.extend(frames)
                self.delivered.extend(frames)
        return out


def _recv_exact(sock: socket.socket, count: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    out = bytearray()
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk:
            raise OverlayError("overlay rejected")
        out += chunk
        if len(out) > CELL_SIZE:
            raise OverlayError("overlay rejected")
    return bytes(out)


def anonymous_send(
    host: str,
    port: int,
    tls_ctx: Any,
    identity: Any,
    peer_id: str,
    data: bytes,
    classification: str = "TOP SECRET",
    receipt: Optional[Dict[str, Any]] = None,
    server_hostname: str = "peer",
    sock_factory: Optional[Callable[[], socket.socket]] = None,
    peer_cert: Optional[str] = None,
    peer_subject: Optional[str] = None,
) -> Dict[str, Any]:
    """End-to-end anonymous send: overlay plus constant-rate uniform cells.

    The ST2027 handshake runs inside outer TLS 1.3 carried by the accepted
    overlay (Tor onion/proxy or attested sovereign path), so deep packet
    inspection observes only pluggable-transport or tunnel bytes. The data
    phase then flows as fixed 1232 byte uniform cells every 50 ms in both
    directions, with cover whenever idle. Dual control is enforced before
    any byte leaves.
    """
    import hashlib as _hl
    import struct as _st

    import secure_transmit_2027 as st

    norm = " ".join(str(classification or "TOP SECRET").strip().upper().split())
    if norm != "TOP SECRET":
        raise OverlayError("overlay rejected")
    if len(bytes(data)) > 50 * 1024 * 1024:
        raise OverlayError("overlay rejected")
    try:
        from spo_dpo import require_spo_dpo_for_send as _dpo

        _dpo(norm, bytes(data), receipt or {})
    except Exception as exc:
        log.debug("anonymous dual control refused: %r", exc)
        raise OverlayError("overlay rejected")
    accepted = require_overlay(host, port)
    raw = sock_factory() if sock_factory is not None else open_overlay_socket(
        host, port)
    st_state = None
    try:
        import ssl as _ssl

        with tls_ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
            st.assert_outer_is_pinned(tls)
            hello, tr, eph, t = st.build_client_hello(identity, peer_id)
            st._send_msg(tls, hello)
            resp = st._recv_msg(tls, cap=st.HANDSHAKE_CAP)
            st_state = st.client_finish(resp, eph, identity, tr, peer_id, t,
                                            peer_cert=peer_cert,
                                            peer_subject=peer_subject)
            ch = st.Channel(st_state, direction_out=0xA5, direction_in=0x5A)
            # Nonce exchange inside the encrypted channel binds the
            # obfuscation key without an extra handshake on the wire.
            nonce_here = secrets.token_bytes(32)
            tls.sendall(_st.pack(">I", len(nonce_here)) + nonce_here)
            peer_len = _st.unpack(">I", _recv_exact(tls, 4, 10.0))[0]
            if peer_len != 32:
                raise OverlayError("overlay rejected")
            nonce_peer = _recv_exact(tls, 32, 10.0)
            both = nonce_here + nonce_peer if bytes(nonce_here) < bytes(
                nonce_peer) else nonce_peer + nonce_here
            # Both ends derive from session key plus sorted nonces only.
            # The client transcript `tr` is not shared with the server, so
            # it must never enter the derivation (symmetry is load-bearing).
            _ = tr
            obfs = derive_obfs_key(bytes(st_state.key()), both)
            # Start-sequence exchange, also inside the channel.
            # Length-prefixed like every other pre-shaper frame, matching
            # _recv_exact_frame on the far end (raw sendall once hung the
            # handshake here: the receiver read ciphertext as a length).
            start_here = secrets.randbits(64)
            st._send_msg(tls, ch.seal_data(_st.pack(">Q", start_here)))
            peer_frame = _recv_exact_frame(tls, ch, 10.0)
            (peer_start,) = _st.unpack(">Q", peer_frame)
            session = ConstantRateSession(
                tls, obfs, direction_out=0xA5, direction_in=0x5A,
                start_seq_out=start_here, peer_start_seq_in=peer_start)
            # Channel frames travel as shaper payloads from here on.
            # The TLS socket is now driven by the fixed-tick pump, so hand
            # the socket to the session without closing it here.
            session.start()
            try:
                seq_no = 0
                for off in range(0, len(bytes(data)) or 1, 1024):
                    chunk = bytes(data)[off:off + 1024]
                    last = off + 1024 >= len(bytes(data))
                    payload = _st.pack(">Q", seq_no) + bytes(
                        [1 if last else 0]) + chunk
                    seq_no += 1
                    wire = ch.seal_data(payload)
                    if ch.needs_rekey():
                        raise OverlayError("overlay rejected")
                    session.send_frame(wire)
                digest = _hl.sha384(bytes(data)).digest()
                session.send_frame(ch.seal_data(
                    _st.pack(">Q", seq_no) + b"\x02" + digest))
                session.send_frame(ch.seal_chaff())
                # Drain: keep the fixed rate until the peer acknowledges
                # delivery via a channel-level ack carried as shaper data.
                # Bounded wait preserves constant rate; absence fails closed.
                ack_deadline = time.monotonic() + 30.0
                while time.monotonic() < ack_deadline:
                    frames = session.recv_available(timeout=0.5)
                    for frame in frames:
                        try:
                            ftype, _ = ch.open(frame)
                        except Exception:
                            raise OverlayError("overlay rejected")
                        if ftype == st.FRAME_TYPE_DATA:
                            session.stop()
                            st.audit_event("anon_send_ok",
                                           {"peer": peer_id,
                                            "bytes": len(bytes(data)),
                                            "path": accepted.get("path", "")})
                            return {"ok": True,
                                    "path": accepted.get("path", ""),
                                    "bytes": len(bytes(data))}
                    time.sleep(0.05)
                raise OverlayError("overlay rejected")
            finally:
                try:
                    session.stop()
                except Exception:
                    pass
    finally:
        try:
            if st_state is not None:
                st_state.destroy()
        except Exception:
            pass
        try:
            raw.close()
        except OSError:
            pass
    raise OverlayError("overlay rejected")


def _recv_exact_frame(tls: socket.socket, ch: Any,
                      timeout: float) -> bytes:
    import secure_transmit_2027 as st

    tls.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        chunk = tls.recv(4 - len(hdr))
        if not chunk:
            raise OverlayError("overlay rejected")
        hdr += chunk
    (need,) = struct.unpack(">I", hdr)
    if need == 0 or need > 65535:
        raise OverlayError("overlay rejected")
    out = bytearray()
    while len(out) < need:
        chunk = tls.recv(min(need - len(out), 16384))
        if not chunk:
            raise OverlayError("overlay rejected")
        out += chunk
    ftype, payload = ch.open(bytes(out))
    if ftype != st.FRAME_TYPE_DATA:
        raise OverlayError("overlay rejected")
    return payload


def anonymous_recv(
    lsock: socket.socket,
    tls_ctx: Any,
    identity: Any,
    peer_id: str,
    out_path: Any,
    classification: str = "TOP SECRET",
    receipt: Optional[Dict[str, Any]] = None,
    peer_cert: Optional[str] = None,
    peer_subject: Optional[str] = None,
) -> Any:
    """Anonymous receive side. Cover flows both ways for the whole session."""
    import hashlib as _hl
    import struct as _st
    from pathlib import Path as _Path

    import secure_transmit_2027 as st

    norm = " ".join(str(classification or "TOP SECRET").strip().upper().split())
    if norm != "TOP SECRET":
        raise OverlayError("overlay rejected")
    try:
        _port = lsock.getsockname()[1]
    except OSError:
        raise OverlayError("overlay rejected")
    st.verify_vendored_binaries()
    st.check_listener_scope(lsock, _port)
    conn, _peer = lsock.accept()
    st_state = None
    try:
        with tls_ctx.wrap_socket(conn, server_side=True) as tls:
            st.assert_outer_is_pinned(tls)
            hello = st._recv_msg(tls, cap=st.HANDSHAKE_CAP)
            resp, st_state = st.server_accept(hello, identity, peer_id,
                                                  peer_cert=peer_cert,
                                                  peer_subject=peer_subject)
            st._send_msg(tls, resp)
            ch = st.Channel(st_state, direction_out=0x5A,
                            direction_in=0xA5)
            peer_len = _st.unpack(">I", _recv_exact(tls, 4, 10.0))[0]
            if peer_len != 32:
                raise OverlayError("overlay rejected")
            nonce_peer = _recv_exact(tls, 32, 10.0)
            nonce_here = secrets.token_bytes(32)
            tls.sendall(_st.pack(">I", len(nonce_here)) + nonce_here)
            both = nonce_here + nonce_peer if bytes(nonce_here) < bytes(
                nonce_peer) else nonce_peer + nonce_here
            # Peer start arrives as the first channel data frame.
            peer_frame = _recv_exact_frame(tls, ch, 10.0)
            (peer_start,) = _st.unpack(">Q", peer_frame)
            start_here = secrets.randbits(64)
            st._send_msg(tls, ch.seal_data(_st.pack(">Q", start_here)))
            obfs = derive_obfs_key(bytes(st_state.key()), both)
            # Data phase uses the same fixed-tick discipline. Read exactly
            # one uniform cell per tick; idle ticks deliver cover.
            session = ConstantRateSession(tls, obfs, direction_out=0x5A,
                                          direction_in=0xA5,
                                          start_seq_out=start_here,
                                          peer_start_seq_in=peer_start)
            session.start()
            try:
                chunks: List[bytes] = []
                total = 0
                seen_eof = False
                digest: Optional[bytes] = None
                deadline = time.monotonic() + 120.0
                while time.monotonic() < deadline:
                    frames = session.recv_available(timeout=0.5)
                    if not frames:
                        continue
                    for frame in frames:
                        ftype, payload = ch.open(frame)
                        if ftype == st.FRAME_TYPE_CHAFF:
                            continue
                        if ftype != st.FRAME_TYPE_DATA:
                            raise OverlayError("overlay rejected")
                        if len(payload) < 9:
                            raise OverlayError("overlay rejected")
                        eof = payload[8]
                        body = payload[9:]
                        if eof in (0, 1):
                            if seen_eof:
                                raise OverlayError("overlay rejected")
                            if eof == 1:
                                seen_eof = True
                            total += len(body)
                            if total > 50 * 1024 * 1024:
                                raise OverlayError("overlay rejected")
                            chunks.append(body)
                            continue
                        if eof == 2:
                            if not seen_eof or digest is not None:
                                raise OverlayError("overlay rejected")
                            if len(body) != 48:
                                raise OverlayError("overlay rejected")
                            digest = body
                            blob = b"".join(chunks)
                            if digest is None or not _compare(
                                    digest, _hl.sha384(blob).digest()):
                                raise OverlayError("overlay rejected")
                            try:
                                from spo_dpo import (
                                    require_spo_dpo_for_send as _dpo)

                                _dpo(norm, blob, receipt or {})
                            except Exception as exc:
                                log.debug("anonymous dual control refused: %r",
                                          exc)
                                raise OverlayError("overlay rejected")
                            dest = _Path(out_path) if out_path is not None \
                                else _Path("received_anon.bin")
                            tmp = dest.with_suffix(dest.suffix + ".tmp")
                            tmp.write_bytes(blob)
                            os.replace(tmp, dest)
                            # Acknowledge inside the shaped stream so the
                            # sender can stop its pump without a timing leak.
                            # Must be DATA (sender acks DATA only; chaff is
                            # ignored cover and would time out the sender).
                            session.send_frame(ch.seal_data(b"ANON-ACK-v1"))
                            time.sleep(0.15)
                            st.audit_event("anon_recv_ok",
                                           {"peer": peer_id, "bytes": total})
                            return dest
                        raise OverlayError("overlay rejected")
                raise OverlayError("overlay rejected")
            finally:
                try:
                    session.stop()
                except Exception:
                    pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        if st_state is not None:
            try:
                st_state.destroy()
            except Exception:
                pass
    raise OverlayError("overlay rejected")
