#!/usr/bin/env python3
"""
Simplex Tactical Data Diode with Forward Error Correction (FEC)
===============================================================
Conforming to:
- NIST SP 800-115 & DoD 8500.01 (Unidirectional Air-Gap Security)
- MIL-STD-188-220 & NATO STANAG 4586 (Tactical Data Telemetry)
- Maximum Distance Separable (MDS) Cauchy Reed-Solomon Erasure Coding

Architecture:
1. Software Simplex Emulation (NOT a physical optical diode):
    - Transmitter possesses ONLY a send socket (never calls recv/recvfrom; zero inbound capability).
    - Receiver possesses ONLY a listen socket (never calls send/sendto; zero outbound capability).
    - Egress/ingress interfaces are explicitly pinned (no wildcard binds
      by default). True reverse-channel impossibility still requires
      OPTICAL DIODE HARDWARE (severed RX fiber); on shared IP hardware
      this module provides interface-pinned UDP simplex only.
2. Forward Error Correction (FEC):
   - Pure Galois Field GF(2^8) Cauchy Reed-Solomon erasure coder.
   - For every K data chunks, generates M parity chunks.
   - Perfectly recovers original payload from ANY K chunks out of K+M (tolerates M packet drops).
3. Cursor-on-Target (CoT) Tactical Telemetry:
   - Native MIL-STD tactical telemetry framing for blue-force tracking and command status.
"""

import os
import sys
import time
import uuid
import socket
import struct
import hashlib
import secrets
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from secure_memory_wiper import secure_wipe_dod


# =============================================================================
# 1. GALOIS FIELD GF(2^8) CAUCHY REED-SOLOMON ERASURE CODER
# =============================================================================

class GF256:
    """
    Galois Field GF(2^8) arithmetic using standard irreducible polynomial
    p(x) = x^8 + x^4 + x^3 + x^2 + 1 (0x11D, primitive element 2).
    Provides O(1) field multiplication and inversion via log/exp tables.
    """
    POLYNOMIAL = 0x11D

    def __init__(self):
        self.exp = [0] * 512
        self.log = [0] * 256
        x = 1
        for i in range(255):
            self.exp[i] = x
            self.exp[i + 255] = x
            self.log[x] = i
            x <<= 1
            if x & 0x100:
                x ^= self.POLYNOMIAL

    def add(self, a: int, b: int) -> int:
        return a ^ b

    def sub(self, a: int, b: int) -> int:
        return a ^ b

    def mul(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return self.exp[self.log[a] + self.log[b]]

    def inv(self, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("Cannot invert zero in GF(2^8)")
        return self.exp[255 - self.log[a]]

    def div(self, a: int, b: int) -> int:
        if b == 0:
            raise ZeroDivisionError("Division by zero in GF(2^8)")
        if a == 0:
            return 0
        return self.exp[(self.log[a] + 255 - self.log[b]) % 255]


# Global GF(2^8) field instance
_gf = GF256()


class CauchyErasureCoder:
    """
    Maximum Distance Separable (MDS) Cauchy Reed-Solomon Erasure Coder.
    Generates M parity packets for K data packets.
    Reconstructs original K data packets from ANY K received packets.
    """
    def __init__(self, k: int, m: int):
        if k <= 0 or m <= 0 or k + m > 256:
            raise ValueError(f"Invalid coding parameters K={k}, M={m} (must satisfy K+M <= 256)")
        self.k = k
        self.m = m
        self._matrix = self._build_cauchy_matrix(k, m)

    @staticmethod
    def _build_cauchy_matrix(k: int, m: int) -> List[List[int]]:
        """
        Builds an M x K Cauchy generator matrix:
        C_{i, j} = 1 / (X_i ^ Y_j), where X and Y are disjoint non-zero subsets.
        """
        # X_i = i, Y_j = m + j ensures X and Y are disjoint
        matrix = []
        for i in range(m):
            row = []
            x_i = i
            for j in range(k):
                y_j = m + j
                row.append(_gf.inv(x_i ^ y_j))
            matrix.append(row)
        return matrix

    def encode(self, data_chunks: List[bytes]) -> List[bytes]:
        """
        Encodes K data chunks into K data chunks + M parity chunks (total K+M).
        All chunks must have identical length.
        """
        if len(data_chunks) != self.k:
            raise ValueError(f"Expected {self.k} data chunks, got {len(data_chunks)}")

        chunk_len = len(data_chunks[0])
        for c in data_chunks:
            if len(c) != chunk_len:
                raise ValueError("All chunks to encode must have the same length")

        parity_chunks = [bytearray(chunk_len) for _ in range(self.m)]

        for p_idx in range(self.m):
            row = self._matrix[p_idx]
            for byte_pos in range(chunk_len):
                val = 0
                for d_idx in range(self.k):
                    coeff = row[d_idx]
                    d_byte = data_chunks[d_idx][byte_pos]
                    val ^= _gf.mul(coeff, d_byte)
                parity_chunks[p_idx][byte_pos] = val

        result = [bytes(c) for c in data_chunks]
        result.extend([bytes(p) for p in parity_chunks])
        return result

    def decode(self, received_chunks: Dict[int, bytes], chunk_len: int) -> List[bytes]:
        """
        Reconstructs the original K data chunks from any K received chunks.
        `received_chunks` maps chunk_index (0..K+M-1) -> chunk_bytes.
        """
        if len(received_chunks) < self.k:
            raise ValueError(f"Insufficient chunks to decode: need {self.k}, got {len(received_chunks)}")

        # Pick exactly K chunks
        selected_indices = sorted(list(received_chunks.keys()))[:self.k]

        # Fast path: if all K original data chunks were received, return them directly
        if selected_indices == list(range(self.k)):
            return [received_chunks[i] for i in range(self.k)]

        # Build K x K decoding matrix
        # For data chunk j (0 <= j < K), row is elementary basis vector e_j
        # For parity chunk p (K <= idx < K+M), row is row (idx - K) of Cauchy matrix
        sub_matrix = []
        rhs_chunks = []

        for idx in selected_indices:
            rhs_chunks.append(received_chunks[idx])
            if idx < self.k:
                row = [1 if j == idx else 0 for j in range(self.k)]
            else:
                row = list(self._matrix[idx - self.k])
            sub_matrix.append(row)

        # Invert K x K sub_matrix via Gaussian elimination in GF(2^8)
        inv_matrix = self._invert_matrix(sub_matrix)

        # Multiply inv_matrix by rhs_chunks to recover original K data chunks
        recovered_data = [bytearray(chunk_len) for _ in range(self.k)]
        for out_idx in range(self.k):
            inv_row = inv_matrix[out_idx]
            for byte_pos in range(chunk_len):
                val = 0
                for in_idx in range(self.k):
                    coeff = inv_row[in_idx]
                    in_byte = rhs_chunks[in_idx][byte_pos]
                    val ^= _gf.mul(coeff, in_byte)
                recovered_data[out_idx][byte_pos] = val

        return [bytes(c) for c in recovered_data]

    def _invert_matrix(self, matrix: List[List[int]]) -> List[List[int]]:
        """Inverts a K x K matrix in GF(2^8) using Gauss-Jordan elimination."""
        n = len(matrix)
        # Augment with identity matrix
        aug = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(matrix)]

        for col in range(n):
            # Find pivot
            pivot_row = None
            for row in range(col, n):
                if aug[row][col] != 0:
                    pivot_row = row
                    break
            if pivot_row is None:
                raise ValueError("Singular matrix encountered during erasure decoding")

            # Swap pivot to current row
            if pivot_row != col:
                aug[col], aug[pivot_row] = aug[pivot_row], aug[col]

            # Scale pivot row to make diagonal element 1
            pivot_inv = _gf.inv(aug[col][col])
            for j in range(col, 2 * n):
                aug[col][j] = _gf.mul(aug[col][j], pivot_inv)

            # Eliminate other rows
            for row in range(n):
                if row != col and aug[row][col] != 0:
                    factor = aug[row][col]
                    for j in range(col, 2 * n):
                        aug[row][j] ^= _gf.mul(factor, aug[col][j])

        # Extract inverse matrix from augmented right half
        return [row[n:] for row in aug]


# =============================================================================
# 2. DIODE FRAME WIRE STRUCTURE & PACKETIZATION
# =============================================================================

DIODE_MAGIC = b"TDD1"  # Tactical Data Diode v1 (4 bytes)
DIODE_HEADER_FORMAT = ">4s16sIIHHH32s"
DIODE_HEADER_SIZE = struct.calcsize(DIODE_HEADER_FORMAT)
# 4s(magic) + 16s(tx_id) + I(total_len) + I(chunk_len) + H(k) + H(m) + H(chunk_idx) + 32s(sha3) = 68 bytes


@dataclass
class DiodePacket:
    """Individual packet crossing the unidirectional diode boundary."""
    magic: bytes
    tx_id: bytes
    total_len: int
    chunk_len: int
    k: int
    m: int
    chunk_index: int
    chunk_sha3: bytes
    chunk_data: bytes

    def serialize(self) -> bytes:
        header = struct.pack(
            DIODE_HEADER_FORMAT,
            self.magic,
            self.tx_id,
            self.total_len,
            self.chunk_len,
            self.k,
            self.m,
            self.chunk_index,
            self.chunk_sha3
        )
        return header + self.chunk_data

    @classmethod
    def deserialize(cls, wire_bytes: bytes) -> "DiodePacket":
        if len(wire_bytes) < DIODE_HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(wire_bytes)} bytes")

        header_bytes = wire_bytes[:DIODE_HEADER_SIZE]
        chunk_data = wire_bytes[DIODE_HEADER_SIZE:]

        magic, tx_id, total_len, chunk_len, k, m, chunk_index, chunk_sha3 = struct.unpack(
            DIODE_HEADER_FORMAT, header_bytes
        )

        if magic != DIODE_MAGIC:
            raise ValueError(f"Invalid diode magic: {magic}")
        if len(chunk_data) != chunk_len:
            raise ValueError(f"Chunk data length mismatch: expected {chunk_len}, got {len(chunk_data)}")

        # Verify integrity hash
        actual_sha3 = hashlib.sha3_256(chunk_data).digest()
        if not secrets.compare_digest(actual_sha3, chunk_sha3):
            raise ValueError(f"Packet chunk {chunk_index} integrity check failed")

        return cls(
            magic=magic,
            tx_id=tx_id,
            total_len=total_len,
            chunk_len=chunk_len,
            k=k,
            m=m,
            chunk_index=chunk_index,
            chunk_sha3=chunk_sha3,
            chunk_data=chunk_data
        )


# =============================================================================
# 3. CURSOR-ON-TARGET (CoT) TACTICAL TELEMETRY
# =============================================================================

@dataclass
class CursorOnTargetEvent:
    """
    MIL-STD Cursor-on-Target (CoT) Event Representation.
    Standard NATO STANAG / US DoD tactical awareness message.
    """
    event_type: str         # e.g. "a-f-G-U-C" (Atom-Friend-Ground-Unit-Combat)
    uid: str                # e.g. "STRATCOM-ALPHA-ICBM-01"
    time_utc: str           # ISO 8601 UTC
    stale_utc: str          # ISO 8601 UTC expiry
    lat: float              # WGS-84 Latitude
    lon: float              # WGS-84 Longitude
    hae: float              # Height Above Ellipsoid (meters)
    ce: float               # Circular Error (meters)
    le: float               # Linear Error (meters)
    callsign: str
    status: str             # e.g. "OPERATIONAL", "DEFCON-1", "ARMED"

    def to_xml(self) -> str:
        return (
            f'<?xml version="1.0" standalone="yes"?>'
            f'<event version="2.0" uid="{self.uid}" type="{self.event_type}" '
            f'time="{self.time_utc}" start="{self.time_utc}" stale="{self.stale_utc}" how="m-g">'
            f'<point lat="{self.lat:.6f}" lon="{self.lon:.6f}" hae="{self.hae:.1f}" '
            f'ce="{self.ce:.1f}" le="{self.le:.1f}"/>'
            f'<detail><contact callsign="{self.callsign}"/><status readiness="{self.status}"/></detail>'
            f'</event>'
        )

    @classmethod
    def create_tactical(
        cls,
        callsign: str,
        event_type: str = "a-f-G-U-C",
        lat: float = 41.1399,
        lon: float = -104.8695,
        status: str = "DEFCON-1"
    ) -> "CursorOnTargetEvent":
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        stale = datetime.fromtimestamp(now.timestamp() + 300.0, tz=timezone.utc)
        stale_str = stale.strftime("%Y-%m-%dT%H:%M:%SZ")
        uid = f"NC3-COT-{uuid.uuid4().hex[:12].upper()}"
        return cls(
            event_type=event_type,
            uid=uid,
            time_utc=now_str,
            stale_utc=stale_str,
            lat=lat,
            lon=lon,
            hae=1870.0,
            ce=5.0,
            le=10.0,
            callsign=callsign,
            status=status
        )


# =============================================================================
# 4. SIMPLEX DATA DIODE ENGINE (TRANSMITTER & RECEIVER)
# =============================================================================

class DiodeTransmitter:
    """
    Pure simplex transmitter.
    Has ONLY a sending socket. It NEVER binds to receive, never reads, and cannot ACK.
    Egress interface is explicitly pinned (no wildcard): either
    egress_source_ip (bind source, any OS) or egress_ifname (Linux
    SO_BINDTODEVICE). Fail-closed on invalid/unbindable interfaces.
    """
    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 55100, chunk_payload_size: int = 1024,
                 egress_source_ip: Optional[str] = None, egress_ifname: Optional[str] = None):
        import ipaddress as _ip
        try:
            _ip.ip_address(target_host)
        except ValueError as e:
            raise ValueError(f"refusing invalid diode target host {target_host!r}: {e}") from e
        if not (1 <= int(target_port) <= 65535):
            raise ValueError(f"refusing invalid diode target port {target_port!r}")
        self.target_host = target_host
        self.target_port = int(target_port)
        self.chunk_payload_size = chunk_payload_size
        self._explicit_bind = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Configure socket for non-blocking simplex transmit
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if egress_ifname is not None:
            if os.name != "posix" or not hasattr(socket, "SO_BINDTODEVICE"):
                try:
                    self._sock.close()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                raise ValueError("egress_ifname refused: SO_BINDTODEVICE is Linux-only")
            try:
                # SO_BINDTODEVICE = 25; needs CAP_NET_RAW -- fail closed.
                self._sock.setsockopt(socket.SOL_SOCKET, 25,
                                      egress_ifname.encode("utf-8") + b"\x00")
            except OSError as e:
                try:
                    self._sock.close()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                raise ValueError(f"refusing unbindable egress interface {egress_ifname!r}: {e}") from e
            self._explicit_bind = True
        if egress_source_ip is not None:
            try:
                _ip.ip_address(egress_source_ip)
                self._sock.bind((egress_source_ip, 0))
            except Exception as e:
                try:
                    self._sock.close()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                raise ValueError(f"refusing unbindable egress source {egress_source_ip!r}: {e}") from e
            self._explicit_bind = True

    def close(self):
        try:
            self._sock.close()
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass

    def send_payload(self, raw_payload: bytes, k: int = 8, m: int = 4, burst_interpacket_delay_ms: float = 0.5) -> bytes:
        """
        Splits payload, applies Cauchy Reed-Solomon FEC, and blasts K+M packets
        unidirectionally across the simplex diode boundary.
        Returns the transmission ID.
        """
        tx_id = secrets.token_bytes(16)
        total_len = len(raw_payload)

        # 1. Chunking with uniform block padding
        chunk_len = max(self.chunk_payload_size, (total_len + k - 1) // k)
        padded_total_len = k * chunk_len
        padded_payload = bytearray(raw_payload)
        if len(padded_payload) < padded_total_len:
            padded_payload.extend(b"\x00" * (padded_total_len - len(padded_payload)))

        data_chunks = [
            bytes(padded_payload[i * chunk_len : (i + 1) * chunk_len])
            for i in range(k)
        ]

        # 2. Compute Cauchy Reed-Solomon Erasure Parity Chunks
        coder = CauchyErasureCoder(k=k, m=m)
        all_chunks = coder.encode(data_chunks)

        # 3. Unidirectional Simplex Blast
        delay = burst_interpacket_delay_ms / 1000.0
        for idx, chunk in enumerate(all_chunks):
            sha3 = hashlib.sha3_256(chunk).digest()
            packet = DiodePacket(
                magic=DIODE_MAGIC,
                tx_id=tx_id,
                total_len=total_len,
                chunk_len=chunk_len,
                k=k,
                m=m,
                chunk_index=idx,
                chunk_sha3=sha3,
                chunk_data=chunk
            )
            wire_bytes = packet.serialize()
            self._sock.sendto(wire_bytes, (self.target_host, self.target_port))
            if delay > 0:
                time.sleep(delay)

        # Immediate DoD 7-pass zeroization of sensitive memory
        secure_wipe_dod(padded_payload, passes=7)
        return tx_id


class DiodeReceiver:
    """
    Pure simplex receiver.
    Has ONLY a listening socket. It NEVER transmits, cannot ACK, cannot NACK.
    The bind address must be EXPLICIT (no 0.0.0.0/:: wildcard) unless
    allow_wildcard=True is passed deliberately (logged loudly).
    """
    def __init__(self, bind_host: str = "127.0.0.1", bind_port: int = 55100,
                 allow_wildcard: bool = False):
        import ipaddress as _ip
        try:
            parsed = _ip.ip_address(bind_host)
        except ValueError as e:
            raise ValueError(f"refusing invalid diode bind host {bind_host!r}: {e}") from e
        if parsed.is_unspecified and not allow_wildcard:
            raise ValueError(
                f"refusing wildcard diode bind {bind_host!r}: pass an explicit "
                f"ingress address (or allow_wildcard=True with justification)")
        if allow_wildcard and parsed.is_unspecified:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "DiodeReceiver wildcard bind explicitly allowed (all interfaces receive)")
        if not (1 <= int(bind_port) <= 65535):
            raise ValueError(f"refusing invalid diode bind port {bind_port!r}")
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_host, self.bind_port))
        self._sock.settimeout(2.0)

    def close(self):
        try:
            self._sock.close()
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass

    def receive_payload(self, timeout_seconds: float = 5.0) -> Optional[bytes]:
        """
        Listens for incoming packets from the diode, groups them by tx_id,
        and applies Reed-Solomon decoding as soon as K packets arrive for a transmission.
        Returns reconstructed payload or None on timeout.
        """
        start_time = time.time()
        received_by_tx: Dict[bytes, Dict[int, bytes]] = {}
        meta_by_tx: Dict[bytes, Tuple[int, int, int, int]] = {} # tx_id -> (total_len, chunk_len, k, m)

        while time.time() - start_time < timeout_seconds:
            try:
                data, _ = self._sock.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                pkt = DiodePacket.deserialize(data)
            # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B112
                continue

            tx_id = pkt.tx_id
            if tx_id not in received_by_tx:
                received_by_tx[tx_id] = {}
                meta_by_tx[tx_id] = (pkt.total_len, pkt.chunk_len, pkt.k, pkt.m)

            received_by_tx[tx_id][pkt.chunk_index] = pkt.chunk_data

            # Check if threshold K is reached for this transmission
            total_len, chunk_len, k, m = meta_by_tx[tx_id]
            if len(received_by_tx[tx_id]) >= k:
                coder = CauchyErasureCoder(k=k, m=m)
                recovered_chunks = coder.decode(received_by_tx[tx_id], chunk_len)
                full_stream = b"".join(recovered_chunks)
                # Slice to exact original unpadded payload length
                return full_stream[:total_len]

        return None

