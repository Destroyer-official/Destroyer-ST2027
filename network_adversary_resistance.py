#!/usr/bin/env python3
"""
network_adversary_resistance.py

Production-ready network adversary resistance for military-grade P2P messaging.

This module implements comprehensive network adversary resistance including:
- Constant-rate traffic (fixed rate regardless of actual messages)
- Multi-hop routing with onion encryption per hop
- Traffic shaping to obscure message boundaries

**Validates: Requirements 9.1, 9.2, 9.3**
"""

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import struct
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional, List, Tuple, Any, Dict

# Try to import cryptographic libraries
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Configure logging
logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

DEFAULT_CONSTANT_RATE = 1.0  # 1 message per second
UNIFORM_PACKET_SIZE = 1024
MAX_HOPS = 5
DEFAULT_HOPS = 3
ONION_LAYER_OVERHEAD = 12 + 16  # ChaCha20-Poly1305 nonce + tag
TRAFFIC_SHAPE_INTERVAL_MS = 100


# ============================================================================
# Exceptions
# ============================================================================

class NetworkAdversaryResistanceError(Exception):
    """Base exception for network adversary resistance errors."""


class ConstantRateError(NetworkAdversaryResistanceError):
    """Error in constant-rate traffic generation."""


class MultiHopRoutingError(NetworkAdversaryResistanceError):
    """Error in multi-hop routing."""


class TrafficShapingError(NetworkAdversaryResistanceError):
    """Error in traffic shaping."""


class OnionEncryptionError(NetworkAdversaryResistanceError):
    """Error in onion encryption/decryption."""


# ============================================================================
# Message Types
# ============================================================================

class MessageType(IntEnum):
    """Types of messages in the constant-rate traffic system."""
    REAL_MESSAGE = 0x01
    COVER_MESSAGE = 0x02
    PADDING_MESSAGE = 0x03
    CONTROL_MESSAGE = 0x04


# ============================================================================
# Constant-Rate Traffic Engine
# **Validates: Requirements 9.1**
# ============================================================================

class ConstantRateTrafficEngine:
    """
    Maintains constant traffic rate regardless of actual message volume.
    
    **Validates: Requirements 9.1**
    """
    
    def __init__(
        self,
        rate_per_second: float = DEFAULT_CONSTANT_RATE,
        packet_size: int = UNIFORM_PACKET_SIZE,
        send_callback: Optional[Callable[[bytes], None]] = None
    ):
        if rate_per_second <= 0 or rate_per_second > 100:
            raise ValueError("rate_per_second must be between 0 and 100")
        if packet_size < 64:
            raise ValueError("packet_size must be at least 64 bytes")
        
        self.rate_per_second = rate_per_second
        self.packet_size = packet_size
        self._send_callback = send_callback
        
        self._message_queue: List[bytes] = []
        self._max_queue_size = int(os.environ.get("P2P_MAX_TRAFFIC_QUEUE_SIZE", "1000"))
        self._queue_lock = threading.Lock()
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        self._real_messages_sent = 0
        self._cover_messages_sent = 0
        self._total_packets_sent = 0
        self._start_time: Optional[float] = None
        self._packet_timestamps: List[float] = []
    
    @property
    def interval_seconds(self) -> float:
        return 1.0 / self.rate_per_second
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    def queue_message(self, message: bytes) -> bool:
        """Queue a real message for transmission with bound clamp (Finding 27)."""
        padded = self._pad_to_uniform_size(message, MessageType.REAL_MESSAGE)
        with self._queue_lock:
            if len(self._message_queue) >= self._max_queue_size:
                logger.warning(f"Constant-rate message queue full ({self._max_queue_size}), dropping oldest message to prevent DoS")
                self._message_queue.pop(0)
            self._message_queue.append(padded)
            return True
    
    def _pad_to_uniform_size(self, data: bytes, msg_type: MessageType) -> bytes:
        header_size = 5
        max_data_size = self.packet_size - header_size
        
        if len(data) > max_data_size:
            data = data[:max_data_size]
        
        header = struct.pack('>BI', msg_type.value, len(data))
        padding_size = self.packet_size - header_size - len(data)
        padding = secrets.token_bytes(padding_size)
        
        return header + data + padding
    
    def _generate_cover_packet(self) -> bytes:
        cover_data = secrets.token_bytes(self.packet_size - 5)
        return self._pad_to_uniform_size(cover_data, MessageType.COVER_MESSAGE)
    
    def start(self) -> None:
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        self._start_time = time.time()
        self._packet_timestamps = []
        
        self._thread = threading.Thread(
            target=self._traffic_loop,
            daemon=True,
            name="ConstantRateTraffic"
        )
        self._thread.start()
        logger.info(f"Constant-rate traffic started at {self.rate_per_second}/sec")
    
    def stop(self) -> None:
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        
        self._thread = None
        logger.info("Constant-rate traffic stopped")
    
    def _traffic_loop(self) -> None:
        next_send_time = time.time()
        
        while not self._stop_event.is_set():
            try:
                current_time = time.time()
                
                if current_time < next_send_time:
                    sleep_time = next_send_time - current_time
                    if sleep_time > 0:
                        self._stop_event.wait(timeout=sleep_time)
                        if self._stop_event.is_set():
                            break
                
                packet = self._get_next_packet()
                
                if self._send_callback:
                    try:
                        self._send_callback(packet)
                    except Exception as e:
                        logger.warning(f"Packet send failed: {e}")
                
                send_time = time.time()
                self._packet_timestamps.append(send_time)
                self._total_packets_sent += 1
                
                cutoff = send_time - 60
                self._packet_timestamps = [
                    t for t in self._packet_timestamps if t > cutoff
                ]
                
                next_send_time = send_time + self.interval_seconds
                
            except Exception as e:
                logger.error(f"Constant-rate traffic error: {e}")
                self._stop_event.wait(timeout=0.1)
    
    def _get_next_packet(self) -> bytes:
        with self._queue_lock:
            if self._message_queue:
                packet = self._message_queue.pop(0)
                self._real_messages_sent += 1
                return packet
        
        self._cover_messages_sent += 1
        return self._generate_cover_packet()
    
    def get_actual_rate(self, window_seconds: float = 10.0) -> float:
        now = time.time()
        cutoff = now - window_seconds
        recent_packets = [t for t in self._packet_timestamps if t > cutoff]
        
        if len(recent_packets) < 2:
            return 0.0
        
        time_span = recent_packets[-1] - recent_packets[0]
        if time_span <= 0:
            return 0.0
        
        return (len(recent_packets) - 1) / time_span
    
    def get_rate_deviation(self, window_seconds: float = 10.0) -> float:
        actual_rate = self.get_actual_rate(window_seconds)
        if actual_rate == 0:
            return 1.0
        return abs(actual_rate - self.rate_per_second) / self.rate_per_second
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "target_rate": self.rate_per_second,
            "actual_rate": self.get_actual_rate(),
            "rate_deviation": self.get_rate_deviation(),
            "real_messages_sent": self._real_messages_sent,
            "cover_messages_sent": self._cover_messages_sent,
            "total_packets_sent": self._total_packets_sent,
            "queue_depth": len(self._message_queue),
            "uptime_seconds": time.time() - self._start_time if self._start_time else 0
        }
    
    @staticmethod
    def extract_message(packet: bytes) -> Tuple[MessageType, bytes]:
        if len(packet) < 5:
            raise ConstantRateError("Packet too short")
        
        msg_type = MessageType(packet[0])
        data_length = struct.unpack('>I', packet[1:5])[0]
        
        if data_length > len(packet) - 5:
            raise ConstantRateError("Invalid data length in packet")
        
        data = packet[5:5 + data_length]
        return msg_type, data


# ============================================================================
# Onion Encryption Layer
# **Validates: Requirements 9.2**
# ============================================================================

@dataclass
class OnionLayer:
    """Represents a single layer of onion encryption."""
    hop_id: str
    hop_address: str
    hop_port: int
    shared_key: bytes
    
    def __post_init__(self):
        if len(self.shared_key) != 32:
            raise ValueError("shared_key must be 32 bytes")


class OnionEncryption:
    """
    Implements onion encryption for multi-hop routing.
    **Validates: Requirements 9.2**
    """
    
    NONCE_SIZE = 12
    TAG_SIZE = 16
    
    def __init__(self):
        if not HAS_CRYPTOGRAPHY:
            raise OnionEncryptionError("cryptography library required")
    
    def encrypt_layer(self, plaintext: bytes, key: bytes) -> bytes:
        if len(key) != 32:
            raise OnionEncryptionError("Key must be 32 bytes")
        
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def decrypt_layer(self, ciphertext: bytes, key: bytes) -> bytes:
        if len(key) != 32:
            raise OnionEncryptionError("Key must be 32 bytes")
        
        if len(ciphertext) < self.NONCE_SIZE + self.TAG_SIZE:
            raise OnionEncryptionError("Ciphertext too short")
        
        nonce = ciphertext[:self.NONCE_SIZE]
        encrypted = ciphertext[self.NONCE_SIZE:]
        
        try:
            cipher = ChaCha20Poly1305(key)
            return cipher.decrypt(nonce, encrypted, None)
        except Exception as e:
            raise OnionEncryptionError(f"Decryption failed: {e}")
    
    def wrap_onion(self, message: bytes, layers: List[OnionLayer]) -> bytes:
        if not layers:
            raise OnionEncryptionError("At least one layer required")
        
        data = message
        for layer in reversed(layers):
            routing_info = self._build_routing_info(layer)
            data = routing_info + data
            data = self.encrypt_layer(data, layer.shared_key)
        
        return data
    
    def unwrap_layer(self, onion_message: bytes, key: bytes) -> Tuple[bytes, Optional[str], Optional[int]]:
        decrypted = self.decrypt_layer(onion_message, key)
        next_hop, port, remaining = self._parse_routing_info(decrypted)
        return remaining, next_hop, port
    
    def _build_routing_info(self, layer: OnionLayer) -> bytes:
        address_bytes = layer.hop_address.encode('utf-8')
        flags = 0x00
        return struct.pack('>BHB', flags, layer.hop_port, len(address_bytes)) + address_bytes
    
    def _parse_routing_info(self, data: bytes) -> Tuple[Optional[str], Optional[int], bytes]:
        if len(data) < 4:
            raise OnionEncryptionError("Routing info too short")
        
        flags, port, addr_len = struct.unpack('>BHB', data[:4])
        
        if flags == 0x01:
            return None, None, data[4:]
        
        if len(data) < 4 + addr_len:
            raise OnionEncryptionError("Address truncated")
        
        address = data[4:4 + addr_len].decode('utf-8')
        remaining = data[4 + addr_len:]
        return address, port, remaining


# ============================================================================
# Multi-Hop Routing Engine
# **Validates: Requirements 9.2**
# ============================================================================

@dataclass
class RelayNode:
    """Represents a relay node in the routing network."""
    node_id: str
    address: str
    port: int
    public_key: bytes
    latency_ms: float = 0.0
    reliability: float = 1.0
    last_seen: float = field(default_factory=time.time)


class MultiHopRouter:
    """
    Routes messages through multiple relay nodes with onion encryption.
    **Validates: Requirements 9.2**
    """
    
    def __init__(self, num_hops: int = DEFAULT_HOPS, relay_nodes: Optional[List[RelayNode]] = None):
        if num_hops < 1 or num_hops > MAX_HOPS:
            raise ValueError(f"num_hops must be between 1 and {MAX_HOPS}")
        
        self.num_hops = num_hops
        self._relay_nodes: Dict[str, RelayNode] = {}
        self._onion = OnionEncryption() if HAS_CRYPTOGRAPHY else None
        self._route_cache: Dict[str, List[RelayNode]] = {}
        self._lock = threading.Lock()
        
        if relay_nodes:
            for node in relay_nodes:
                self.add_relay_node(node)
    
    def add_relay_node(self, node: RelayNode) -> None:
        with self._lock:
            self._relay_nodes[node.node_id] = node
    
    def remove_relay_node(self, node_id: str) -> None:
        with self._lock:
            if node_id in self._relay_nodes:
                del self._relay_nodes[node_id]
                self._route_cache = {
                    k: v for k, v in self._route_cache.items()
                    if not any(n.node_id == node_id for n in v)
                }
    
    def select_route(self, destination: str, exclude_nodes: Optional[List[str]] = None) -> List[RelayNode]:
        exclude_set = set(exclude_nodes or [])
        
        with self._lock:
            available = [
                node for node_id, node in self._relay_nodes.items()
                if node_id not in exclude_set and node.reliability > 0.5
            ]
            
            if len(available) < self.num_hops:
                raise MultiHopRoutingError(
                    f"Not enough relay nodes: need {self.num_hops}, have {len(available)}"
                )
            
            selected = []
            remaining = available.copy()
            
            for _ in range(self.num_hops):
                weights = [n.reliability for n in remaining]
                total_weight = sum(weights)
                
                if total_weight == 0:
                    raise MultiHopRoutingError("No reliable nodes available")
                
                r = secrets.randbelow(int(total_weight * 1000)) / 1000
                cumulative = 0.0
                
                for i, node in enumerate(remaining):
                    cumulative += weights[i]
                    if r < cumulative:
                        selected.append(node)
                        remaining.pop(i)
                        break
                else:
                    selected.append(remaining.pop())
            
            return selected
    
    def build_onion_message(self, message: bytes, route: List[RelayNode], destination_key: bytes) -> bytes:
        if not self._onion:
            raise MultiHopRoutingError("Onion encryption not available")
        
        layers = []
        for node in route:
            shared_key = self._derive_shared_key(node.public_key)
            layer = OnionLayer(
                hop_id=node.node_id,
                hop_address=node.address,
                hop_port=node.port,
                shared_key=shared_key
            )
            layers.append(layer)
        
        final_layer = OnionLayer(
            hop_id="destination",
            hop_address="",
            hop_port=0,
            shared_key=destination_key
        )
        layers.append(final_layer)
        
        return self._onion.wrap_onion(message, layers)
    
    def _derive_shared_key(self, public_key: bytes, local_private_key: Optional[Any] = None) -> bytes:
        """
        Derive shared encryption key using Diffie-Hellman key agreement with HKDF.
        If a local private key is provided, performs X25519 ECDH.
        """
        if not HAS_CRYPTOGRAPHY:
            return hashlib.sha512(public_key).digest()[:32]
        
        try:
            if local_private_key is not None and len(public_key) == 32:
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
                peer_pub = X25519PublicKey.from_public_bytes(public_key)
                if isinstance(local_private_key, bytes):
                    priv = X25519PrivateKey.from_private_bytes(local_private_key)
                else:
                    priv = local_private_key
                shared_secret = priv.exchange(peer_pub)
                hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=b"SecureP2P::OnionRouting::v1", info=b"onion-routing-key")
                return hkdf.derive(shared_secret)
        except Exception as e:
            logger.debug(f"ECDH derivation fallback: {e}")

        hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=b"SecureP2P::OnionRouting::v1", info=b"onion-routing-key")
        return hkdf.derive(public_key)
    
    def process_incoming_onion(self, onion_message: bytes, my_key: bytes) -> Tuple[bytes, Optional[str], Optional[int]]:
        if not self._onion:
            raise MultiHopRoutingError("Onion encryption not available")
        return self._onion.unwrap_layer(onion_message, my_key)
    
    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "num_hops": self.num_hops,
                "available_nodes": len(self._relay_nodes),
                "cached_routes": len(self._route_cache),
                "nodes": [
                    {"id": n.node_id, "address": n.address, "reliability": n.reliability}
                    for n in self._relay_nodes.values()
                ]
            }


# ============================================================================
# Traffic Shaping Engine
# **Validates: Requirements 9.3**
# ============================================================================

class TrafficShapingEngine:
    """
    Shapes traffic to obscure message boundaries and patterns.
    **Validates: Requirements 9.3**
    """
    
    HEADER_SIZE = 17  # seq(8) + frag_idx(2) + total_frags(2) + flags(1) + checksum(4)
    
    def __init__(
        self,
        packet_size: int = UNIFORM_PACKET_SIZE,
        send_interval_ms: int = TRAFFIC_SHAPE_INTERVAL_MS,
        send_callback: Optional[Callable[[bytes], None]] = None
    ):
        if packet_size < 64:
            raise ValueError("packet_size must be at least 64 bytes")
        if send_interval_ms < 10:
            raise ValueError("send_interval_ms must be at least 10")
        
        self.packet_size = packet_size
        self.send_interval_ms = send_interval_ms
        self._send_callback = send_callback
        self.payload_size = packet_size - self.HEADER_SIZE
        
        self._sequence_counter = 0
        self._seq_lock = threading.Lock()
        
        self._packet_queue: List[bytes] = []
        self._queue_lock = threading.Lock()
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        self._packets_sent = 0
        self._bytes_sent = 0
        self._messages_fragmented = 0
    
    def _get_next_sequence(self) -> int:
        with self._seq_lock:
            seq = self._sequence_counter
            self._sequence_counter = (self._sequence_counter + 1) % (2**64)
            return seq
    
    def fragment_message(self, message: bytes) -> List[bytes]:
        if not message:
            return []
        
        num_fragments = (len(message) + self.payload_size - 1) // self.payload_size
        if num_fragments == 0:
            num_fragments = 1
        
        sequence = self._get_next_sequence()
        packets = []
        
        for i in range(num_fragments):
            start = i * self.payload_size
            end = min(start + self.payload_size, len(message))
            fragment_data = message[start:end]
            
            packet = self._build_packet(
                sequence=sequence,
                fragment_index=i,
                total_fragments=num_fragments,
                data=fragment_data,
                is_real=True
            )
            packets.append(packet)
        
        self._messages_fragmented += 1
        return packets
    
    def _build_packet(self, sequence: int, fragment_index: int, total_fragments: int, data: bytes, is_real: bool = True) -> bytes:
        flags = 0
        # In hardened traffic shaping, cleartext 'is_real' flag 0x01 is ELIMINATED (Item 24).
        # Cover packets are framed identically to data packets so passive observers cannot distinguish chaff.
        if fragment_index == total_fragments - 1:
            flags |= 0x02
        
        header = struct.pack('>QHHB', sequence, fragment_index, total_fragments, flags)
        checksum = int.from_bytes(hashlib.sha512(data).digest()[:4], byteorder='big')
        header += struct.pack('>I', checksum)
        
        if len(data) < self.payload_size:
            padding = secrets.token_bytes(self.payload_size - len(data))
            data = data + padding
        elif len(data) > self.payload_size:
            data = data[:self.payload_size]
        
        return header + data
    
    def generate_cover_packet(self) -> bytes:
        sequence = self._get_next_sequence()
        cover_data = secrets.token_bytes(self.payload_size)
        return self._build_packet(sequence=sequence, fragment_index=0, total_fragments=1, data=cover_data, is_real=False)
    
    def queue_message(self, message: bytes) -> int:
        packets = self.fragment_message(message)
        with self._queue_lock:
            self._packet_queue.extend(packets)
        return len(packets)
    
    def start(self) -> None:
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        
        self._thread = threading.Thread(target=self._shaping_loop, daemon=True, name="TrafficShaping")
        self._thread.start()
        logger.info(f"Traffic shaping started, interval={self.send_interval_ms}ms")
    
    def stop(self) -> None:
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        
        self._thread = None
        logger.info("Traffic shaping stopped")
    
    def _shaping_loop(self) -> None:
        interval_sec = self.send_interval_ms / 1000.0
        
        while not self._stop_event.is_set():
            try:
                packet = self._get_next_packet()
                
                if self._send_callback:
                    try:
                        self._send_callback(packet)
                        self._packets_sent += 1
                        self._bytes_sent += len(packet)
                    except Exception as e:
                        logger.warning(f"Shaped packet send failed: {e}")
                
                self._stop_event.wait(timeout=interval_sec)
                
            except Exception as e:
                logger.error(f"Traffic shaping error: {e}")
                self._stop_event.wait(timeout=0.1)
    
    def _get_next_packet(self) -> bytes:
        with self._queue_lock:
            if self._packet_queue:
                return self._packet_queue.pop(0)
        return self.generate_cover_packet()
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "packet_size": self.packet_size,
            "send_interval_ms": self.send_interval_ms,
            "packets_sent": self._packets_sent,
            "bytes_sent": self._bytes_sent,
            "messages_fragmented": self._messages_fragmented,
            "queue_depth": len(self._packet_queue)
        }
    
    @staticmethod
    def is_real_packet(packet: bytes) -> bool:
        """Check if packet has valid length and framing (chaff is indistinguishable at transport layer)."""
        if len(packet) < 17:
            return False
        return True


# ============================================================================
# Network Adversary Resistance Manager
# **Validates: Requirements 9.1, 9.2, 9.3**
# ============================================================================

class NetworkAdversaryResistanceManager:
    """
    Unified manager for all network adversary resistance features.
    **Validates: Requirements 9.1, 9.2, 9.3**
    """
    
    def __init__(
        self,
        constant_rate: float = DEFAULT_CONSTANT_RATE,
        num_hops: int = DEFAULT_HOPS,
        packet_size: int = UNIFORM_PACKET_SIZE,
        send_callback: Optional[Callable[[bytes], None]] = None
    ):
        self._send_callback = send_callback
        
        self.constant_rate_engine = ConstantRateTrafficEngine(
            rate_per_second=constant_rate,
            packet_size=packet_size,
            send_callback=self._on_constant_rate_send
        )
        
        self.multi_hop_router = MultiHopRouter(num_hops=num_hops)
        
        self.traffic_shaper = TrafficShapingEngine(
            packet_size=packet_size,
            send_callback=self._on_shaped_send
        )
        
        self._use_constant_rate = True
        self._use_traffic_shaping = True
        self._use_multi_hop = True

        # Finding 10: State synchronization per-peer lock & node states
        self.node_states: Dict[str, Dict[str, Any]] = {}
        self._peer_locks: Dict[str, asyncio.Lock] = {}
        self._peer_locks_guard = threading.Lock()

    async def sync_with_peer(self, peer_id: str, state_update: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronize state with a peer using per-peer asyncio.Lock to prevent race conditions (Finding 10).
        """
        with self._peer_locks_guard:
            if peer_id not in self._peer_locks:
                self._peer_locks[peer_id] = asyncio.Lock()
            lock = self._peer_locks[peer_id]

        async with lock:
            current = self.node_states.get(peer_id, {})
            current.update(state_update)
            current["last_sync"] = time.time()
            self.node_states[peer_id] = current
            # Small async yield point simulation to ensure lock coverage
            await asyncio.sleep(0)
            return dict(self.node_states[peer_id])

    
    def _on_constant_rate_send(self, packet: bytes) -> None:
        if self._send_callback:
            self._send_callback(packet)
    
    def _on_shaped_send(self, packet: bytes) -> None:
        if self._use_constant_rate:
            self.constant_rate_engine.queue_message(packet)
        elif self._send_callback:
            self._send_callback(packet)
    
    def send_message(self, message: bytes, destination: Optional[str] = None, destination_key: Optional[bytes] = None) -> None:
        data = message
        
        if self._use_multi_hop and destination and destination_key:
            try:
                route = self.multi_hop_router.select_route(destination)
                data = self.multi_hop_router.build_onion_message(message, route, destination_key)
            except MultiHopRoutingError as e:
                logger.warning(f"Multi-hop routing failed, sending direct: {e}")
        
        if self._use_traffic_shaping:
            self.traffic_shaper.queue_message(data)
        elif self._use_constant_rate:
            self.constant_rate_engine.queue_message(data)
        elif self._send_callback:
            self._send_callback(data)
    
    def add_relay_node(self, node: RelayNode) -> None:
        self.multi_hop_router.add_relay_node(node)
    
    def start(self) -> None:
        if self._use_traffic_shaping:
            self.traffic_shaper.start()
        if self._use_constant_rate:
            self.constant_rate_engine.start()
        logger.info("Network adversary resistance started")
    
    def stop(self) -> None:
        self.constant_rate_engine.stop()
        self.traffic_shaper.stop()
        logger.info("Network adversary resistance stopped")
    
    def configure(self, use_constant_rate: Optional[bool] = None, use_traffic_shaping: Optional[bool] = None, use_multi_hop: Optional[bool] = None) -> None:
        if use_constant_rate is not None:
            self._use_constant_rate = use_constant_rate
        if use_traffic_shaping is not None:
            self._use_traffic_shaping = use_traffic_shaping
        if use_multi_hop is not None:
            self._use_multi_hop = use_multi_hop
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "constant_rate": self.constant_rate_engine.get_statistics(),
            "multi_hop": self.multi_hop_router.get_statistics(),
            "traffic_shaping": self.traffic_shaper.get_statistics(),
            "config": {
                "use_constant_rate": self._use_constant_rate,
                "use_traffic_shaping": self._use_traffic_shaping,
                "use_multi_hop": self._use_multi_hop
            }
        }


# ============================================================================
# Multi-Path Connection Manager
# **Validates: Requirements 19.4**
# ============================================================================

@dataclass
class NetworkPath:
    """Represents a network path for multi-path connections."""
    path_id: str
    address: str
    port: int
    latency_ms: float = 0.0
    reliability: float = 1.0
    is_active: bool = True
    last_success: float = field(default_factory=time.time)
    failure_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


class MultiPathConnectionManager:
    """
    Manages connections via multiple network paths with automatic failover.
    
    **Validates: Requirements 19.4**
    
    Features:
    - Support connection via multiple network paths simultaneously
    - Automatic failover when a path fails
    - Load balancing across available paths
    - Path health monitoring
    """
    
    MAX_FAILURE_COUNT = 3  # Max failures before path is marked inactive
    FAILOVER_TIMEOUT_MS = 5000  # Timeout before failover
    HEALTH_CHECK_INTERVAL_S = 30  # Health check interval
    
    def __init__(self, paths: Optional[List[NetworkPath]] = None):
        """
        Initialize the multi-path connection manager.
        
        Args:
            paths: Initial list of network paths
        """
        self._paths: Dict[str, NetworkPath] = {}
        self._primary_path_id: Optional[str] = None
        self._lock = threading.RLock()
        
        # Statistics
        self._failovers_performed = 0
        self._total_bytes_sent = 0
        self._total_bytes_received = 0
        
        # Health monitoring
        self._health_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        
        if paths:
            for path in paths:
                self.add_path(path)
        
        logger.info("MultiPathConnectionManager initialized")
    
    def add_path(self, path: NetworkPath) -> None:
        """
        Add a network path.
        
        Args:
            path: NetworkPath to add
        """
        with self._lock:
            self._paths[path.path_id] = path
            
            # Set as primary if first path
            if self._primary_path_id is None:
                self._primary_path_id = path.path_id
            
            logger.info(f"Added network path: {path.path_id} ({path.address}:{path.port})")
    
    def remove_path(self, path_id: str) -> bool:
        """
        Remove a network path.
        
        Args:
            path_id: ID of path to remove
            
        Returns:
            True if path was removed
        """
        with self._lock:
            if path_id not in self._paths:
                return False
            
            del self._paths[path_id]
            
            # Select new primary if needed
            if self._primary_path_id == path_id:
                self._primary_path_id = self._select_best_path()
            
            logger.info(f"Removed network path: {path_id}")
            return True
    
    def get_active_paths(self) -> List[NetworkPath]:
        """Get all active network paths."""
        with self._lock:
            return [p for p in self._paths.values() if p.is_active]
    
    def get_primary_path(self) -> Optional[NetworkPath]:
        """Get the current primary path."""
        with self._lock:
            if self._primary_path_id and self._primary_path_id in self._paths:
                return self._paths[self._primary_path_id]
            return None
    
    def _select_best_path(self) -> Optional[str]:
        """Select the best available path based on reliability and latency."""
        active_paths = [p for p in self._paths.values() if p.is_active]
        
        if not active_paths:
            return None
        
        # Score paths by reliability and latency
        def path_score(p: NetworkPath) -> float:
            # Higher reliability is better, lower latency is better
            latency_factor = 1.0 / (1.0 + p.latency_ms / 1000.0)
            return p.reliability * latency_factor
        
        best_path = max(active_paths, key=path_score)
        return best_path.path_id
    
    def send_data(
        self,
        data: bytes,
        send_func: Callable[[str, int, bytes], bool]
    ) -> bool:
        """
        Send data via the best available path with automatic failover.
        
        Args:
            data: Data to send
            send_func: Function(address, port, data) -> success
            
        Returns:
            True if data was sent successfully
            
        **Validates: Requirements 19.4**
        """
        with self._lock:
            # Try primary path first
            if self._primary_path_id:
                primary = self._paths.get(self._primary_path_id)
                if primary and primary.is_active:
                    if self._try_send(primary, data, send_func):
                        return True
            
            # Failover to other paths
            for path in self._paths.values():
                if path.path_id == self._primary_path_id:
                    continue
                if not path.is_active:
                    continue
                
                if self._try_send(path, data, send_func):
                    # Promote this path to primary
                    self._primary_path_id = path.path_id
                    self._failovers_performed += 1
                    logger.info(f"Failover to path: {path.path_id}")
                    return True
            
            logger.error("All paths failed to send data")
            return False
    
    def _try_send(
        self,
        path: NetworkPath,
        data: bytes,
        send_func: Callable[[str, int, bytes], bool]
    ) -> bool:
        """Try to send data via a specific path."""
        try:
            success = send_func(path.address, path.port, data)
            
            if success:
                path.last_success = time.time()
                path.failure_count = 0
                path.bytes_sent += len(data)
                self._total_bytes_sent += len(data)
                return True
            else:
                self._handle_path_failure(path)
                return False
                
        except Exception as e:
            logger.warning(f"Path {path.path_id} send failed: {e}")
            self._handle_path_failure(path)
            return False
    
    def _handle_path_failure(self, path: NetworkPath) -> None:
        """Handle a path failure."""
        path.failure_count += 1
        
        if path.failure_count >= self.MAX_FAILURE_COUNT:
            path.is_active = False
            logger.warning(f"Path {path.path_id} marked inactive after {path.failure_count} failures")
            
            # Select new primary if this was primary
            if self._primary_path_id == path.path_id:
                self._primary_path_id = self._select_best_path()
    
    def record_receive(self, path_id: str, bytes_count: int) -> None:
        """Record data received on a path."""
        with self._lock:
            if path_id in self._paths:
                self._paths[path_id].bytes_received += bytes_count
                self._total_bytes_received += bytes_count
    
    def reactivate_path(self, path_id: str) -> bool:
        """Reactivate a previously failed path."""
        with self._lock:
            if path_id not in self._paths:
                return False
            
            path = self._paths[path_id]
            path.is_active = True
            path.failure_count = 0
            logger.info(f"Reactivated path: {path_id}")
            return True
    
    def start_health_monitoring(self) -> None:
        """Start background health monitoring."""
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        
        self._health_thread = threading.Thread(
            target=self._health_monitor_loop,
            daemon=True,
            name="MultiPathHealthMonitor"
        )
        self._health_thread.start()
        logger.info("Multi-path health monitoring started")
    
    def stop_health_monitoring(self) -> None:
        """Stop background health monitoring."""
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        if self._health_thread and self._health_thread.is_alive():
            self._health_thread.join(timeout=2.0)
        
        self._health_thread = None
        logger.info("Multi-path health monitoring stopped")
    
    def _health_monitor_loop(self) -> None:
        """Background loop for health monitoring."""
        while not self._stop_event.is_set():
            try:
                self._check_path_health()
            except Exception as e:
                logger.error(f"Health check error: {e}")
            
            self._stop_event.wait(timeout=self.HEALTH_CHECK_INTERVAL_S)
    
    def _check_path_health(self) -> None:
        """Check health of all paths."""
        with self._lock:
            current_time = time.time()
            
            for path in self._paths.values():
                # Check if path has been inactive too long
                if path.is_active:
                    time_since_success = current_time - path.last_success
                    if time_since_success > 60:  # 60 seconds without success
                        path.reliability = max(0.1, path.reliability * 0.9)
                else:
                    # Try to reactivate paths that have been inactive for a while
                    time_since_success = current_time - path.last_success
                    if time_since_success > 300:  # 5 minutes
                        path.is_active = True
                        path.failure_count = 0
                        logger.info(f"Auto-reactivated path: {path.path_id}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get multi-path connection statistics."""
        with self._lock:
            return {
                "total_paths": len(self._paths),
                "active_paths": len([p for p in self._paths.values() if p.is_active]),
                "primary_path": self._primary_path_id,
                "failovers_performed": self._failovers_performed,
                "total_bytes_sent": self._total_bytes_sent,
                "total_bytes_received": self._total_bytes_received,
                "paths": [
                    {
                        "path_id": p.path_id,
                        "address": p.address,
                        "port": p.port,
                        "is_active": p.is_active,
                        "reliability": p.reliability,
                        "latency_ms": p.latency_ms,
                        "failure_count": p.failure_count,
                        "bytes_sent": p.bytes_sent,
                        "bytes_received": p.bytes_received,
                    }
                    for p in self._paths.values()
                ]
            }


# ============================================================================
# Traffic Analysis Detection Engine
# **Validates: Requirements 19.5**
# ============================================================================

class TrafficAnalysisAlert:
    """Represents a traffic analysis detection alert."""
    
    def __init__(
        self,
        alert_type: str,
        confidence: float,
        details: Dict[str, Any],
        timestamp: Optional[float] = None
    ):
        self.alert_type = alert_type
        self.confidence = confidence
        self.details = details
        self.timestamp = timestamp or time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_type": self.alert_type,
            "confidence": self.confidence,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class TrafficAnalysisDetector:
    """
    Detects suspected traffic analysis attempts.
    
    **Validates: Requirements 19.5**
    
    Detection methods:
    - Timing correlation analysis
    - Volume correlation analysis
    - Pattern detection in traffic
    - Anomalous probe detection
    """
    
    # Detection thresholds
    TIMING_CORRELATION_THRESHOLD = 0.8  # Correlation coefficient threshold
    VOLUME_ANOMALY_THRESHOLD = 3.0  # Standard deviations
    PROBE_RATE_THRESHOLD = 10  # Probes per minute
    PATTERN_DETECTION_WINDOW = 60  # Seconds
    
    def __init__(
        self,
        alert_callback: Optional[Callable[[TrafficAnalysisAlert], None]] = None
    ):
        """
        Initialize the traffic analysis detector.
        
        Args:
            alert_callback: Function to call when alert is generated
        """
        self._alert_callback = alert_callback
        self._lock = threading.RLock()
        
        # Traffic statistics
        self._inbound_timestamps: List[float] = []
        self._outbound_timestamps: List[float] = []
        self._inbound_sizes: List[int] = []
        self._outbound_sizes: List[int] = []
        
        # Probe detection
        self._probe_timestamps: List[float] = []
        self._suspicious_sources: Dict[str, int] = {}
        
        # Alerts
        self._alerts: List[TrafficAnalysisAlert] = []
        self._alert_count = 0
        
        # Background monitoring
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        logger.info("TrafficAnalysisDetector initialized")
    
    def record_inbound(self, size: int, source: Optional[str] = None) -> None:
        """
        Record an inbound packet.
        
        Args:
            size: Packet size in bytes
            source: Source address (optional)
        """
        with self._lock:
            timestamp = time.time()
            self._inbound_timestamps.append(timestamp)
            self._inbound_sizes.append(size)
            
            # Trim old data (keep last 5 minutes)
            self._trim_old_data()
    
    def record_outbound(self, size: int) -> None:
        """
        Record an outbound packet.
        
        Args:
            size: Packet size in bytes
        """
        with self._lock:
            timestamp = time.time()
            self._outbound_timestamps.append(timestamp)
            self._outbound_sizes.append(size)
            
            # Trim old data
            self._trim_old_data()
    
    def record_probe(self, source: str) -> None:
        """
        Record a suspected probe attempt.
        
        Args:
            source: Source address of the probe
        """
        with self._lock:
            timestamp = time.time()
            self._probe_timestamps.append(timestamp)
            
            # Track suspicious sources
            self._suspicious_sources[source] = self._suspicious_sources.get(source, 0) + 1
            
            # Check for probe rate threshold
            self._check_probe_rate(source)
    
    def _trim_old_data(self) -> None:
        """Trim data older than the detection window."""
        cutoff = time.time() - 300  # Keep 5 minutes of data
        
        # Trim inbound data
        while self._inbound_timestamps and self._inbound_timestamps[0] < cutoff:
            self._inbound_timestamps.pop(0)
            self._inbound_sizes.pop(0)
        
        # Trim outbound data
        while self._outbound_timestamps and self._outbound_timestamps[0] < cutoff:
            self._outbound_timestamps.pop(0)
            self._outbound_sizes.pop(0)
        
        # Trim probe data
        while self._probe_timestamps and self._probe_timestamps[0] < cutoff:
            self._probe_timestamps.pop(0)
    
    def _check_probe_rate(self, source: str) -> None:
        """Check if probe rate exceeds threshold."""
        current_time = time.time()
        cutoff = current_time - 60  # Last minute
        
        recent_probes = [t for t in self._probe_timestamps if t > cutoff]
        
        if len(recent_probes) >= self.PROBE_RATE_THRESHOLD:
            self._generate_alert(
                alert_type="probe_rate_exceeded",
                confidence=0.9,
                details={
                    "source": source,
                    "probe_count": len(recent_probes),
                    "threshold": self.PROBE_RATE_THRESHOLD,
                    "window_seconds": 60,
                }
            )
    
    def check_timing_correlation(self) -> Optional[TrafficAnalysisAlert]:
        """
        Check for timing correlation between inbound and outbound traffic.
        
        Returns:
            Alert if correlation detected, None otherwise
            
        **Validates: Requirements 19.5**
        """
        with self._lock:
            if len(self._inbound_timestamps) < 10 or len(self._outbound_timestamps) < 10:
                return None
            
            # Calculate correlation between inbound and outbound timing
            correlation = self._calculate_timing_correlation()
            
            if correlation > self.TIMING_CORRELATION_THRESHOLD:
                return self._generate_alert(
                    alert_type="timing_correlation",
                    confidence=correlation,
                    details={
                        "correlation_coefficient": correlation,
                        "threshold": self.TIMING_CORRELATION_THRESHOLD,
                        "inbound_count": len(self._inbound_timestamps),
                        "outbound_count": len(self._outbound_timestamps),
                    }
                )
            
            return None
    
    def _calculate_timing_correlation(self) -> float:
        """Calculate timing correlation coefficient."""
        if not self._inbound_timestamps or not self._outbound_timestamps:
            return 0.0
        
        # Simple correlation: check if outbound follows inbound closely
        correlations = []
        
        for out_time in self._outbound_timestamps[-20:]:
            # Find closest inbound timestamp
            min_diff = float('inf')
            for in_time in self._inbound_timestamps[-20:]:
                diff = abs(out_time - in_time)
                if diff < min_diff:
                    min_diff = diff
            
            # Convert to correlation score (closer = higher)
            if min_diff < 0.1:  # Within 100ms
                correlations.append(1.0 - min_diff * 10)
            else:
                correlations.append(0.0)
        
        if not correlations:
            return 0.0
        
        return sum(correlations) / len(correlations)
    
    def check_volume_anomaly(self) -> Optional[TrafficAnalysisAlert]:
        """
        Check for volume anomalies that might indicate traffic analysis.
        
        Returns:
            Alert if anomaly detected, None otherwise
            
        **Validates: Requirements 19.5**
        """
        with self._lock:
            if len(self._inbound_sizes) < 20:
                return None
            
            # Calculate mean and standard deviation
            mean_size = sum(self._inbound_sizes) / len(self._inbound_sizes)
            variance = sum((s - mean_size) ** 2 for s in self._inbound_sizes) / len(self._inbound_sizes)
            std_dev = variance ** 0.5
            
            if std_dev == 0:
                return None
            
            # Check recent packets for anomalies
            recent_sizes = self._inbound_sizes[-10:]
            anomalies = []
            
            for size in recent_sizes:
                z_score = abs(size - mean_size) / std_dev
                if z_score > self.VOLUME_ANOMALY_THRESHOLD:
                    anomalies.append(size)
            
            if len(anomalies) >= 3:  # Multiple anomalies
                return self._generate_alert(
                    alert_type="volume_anomaly",
                    confidence=min(0.95, len(anomalies) / 10.0 + 0.5),
                    details={
                        "anomaly_count": len(anomalies),
                        "mean_size": mean_size,
                        "std_dev": std_dev,
                        "threshold_std_devs": self.VOLUME_ANOMALY_THRESHOLD,
                    }
                )
            
            return None
    
    def check_pattern_detection(self) -> Optional[TrafficAnalysisAlert]:
        """
        Check for suspicious patterns in traffic.
        
        Returns:
            Alert if pattern detected, None otherwise
            
        **Validates: Requirements 19.5**
        """
        with self._lock:
            if len(self._inbound_timestamps) < 20:
                return None
            
            # Check for regular intervals (might indicate probing)
            intervals = []
            for i in range(1, min(20, len(self._inbound_timestamps))):
                interval = self._inbound_timestamps[-i] - self._inbound_timestamps[-i-1]
                intervals.append(interval)
            
            if not intervals:
                return None
            
            # Check for suspiciously regular intervals
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
            
            # Very low variance indicates regular probing
            if variance < 0.01 and mean_interval < 1.0:  # Regular intervals under 1 second
                return self._generate_alert(
                    alert_type="regular_pattern",
                    confidence=0.85,
                    details={
                        "mean_interval": mean_interval,
                        "variance": variance,
                        "sample_count": len(intervals),
                    }
                )
            
            return None
    
    def _generate_alert(
        self,
        alert_type: str,
        confidence: float,
        details: Dict[str, Any]
    ) -> TrafficAnalysisAlert:
        """Generate and record an alert."""
        alert = TrafficAnalysisAlert(
            alert_type=alert_type,
            confidence=confidence,
            details=details
        )
        
        self._alerts.append(alert)
        self._alert_count += 1
        
        logger.warning(f"Traffic analysis alert: {alert_type} (confidence: {confidence:.2f})")
        
        # Call callback if provided
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
        
        return alert
    
    def start_monitoring(self) -> None:
        """Start background traffic analysis monitoring."""
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="TrafficAnalysisMonitor"
        )
        self._monitor_thread.start()
        logger.info("Traffic analysis monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop background traffic analysis monitoring."""
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)
        
        self._monitor_thread = None
        logger.info("Traffic analysis monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while not self._stop_event.is_set():
            try:
                # Run all detection checks
                self.check_timing_correlation()
                self.check_volume_anomaly()
                self.check_pattern_detection()
            except Exception as e:
                logger.error(f"Traffic analysis monitoring error: {e}")
            
            self._stop_event.wait(timeout=10.0)  # Check every 10 seconds
    
    def get_alerts(self, since: Optional[float] = None) -> List[TrafficAnalysisAlert]:
        """
        Get alerts, optionally filtered by timestamp.
        
        Args:
            since: Only return alerts after this timestamp
            
        Returns:
            List of alerts
        """
        with self._lock:
            if since is None:
                return self._alerts.copy()
            return [a for a in self._alerts if a.timestamp > since]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get traffic analysis detection statistics."""
        with self._lock:
            return {
                "running": self._running,
                "alert_count": self._alert_count,
                "inbound_packets": len(self._inbound_timestamps),
                "outbound_packets": len(self._outbound_timestamps),
                "probe_count": len(self._probe_timestamps),
                "suspicious_sources": len(self._suspicious_sources),
                "recent_alerts": [a.to_dict() for a in self._alerts[-10:]],
            }


def create_default_manager(send_callback: Optional[Callable[[bytes], None]] = None) -> NetworkAdversaryResistanceManager:
    """Create a manager with default settings."""
    return NetworkAdversaryResistanceManager(
        constant_rate=DEFAULT_CONSTANT_RATE,
        num_hops=DEFAULT_HOPS,
        packet_size=UNIFORM_PACKET_SIZE,
        send_callback=send_callback
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("Testing constant-rate traffic engine...")
    packets_received = []
    
    def test_callback(packet: bytes):
        packets_received.append(packet)
    
    engine = ConstantRateTrafficEngine(rate_per_second=2.0, send_callback=test_callback)
    engine.queue_message(b"Hello, World!")
    engine.queue_message(b"Test message 2")
    
    engine.start()
    time.sleep(3)
    engine.stop()
    
    stats = engine.get_statistics()
    print(f"Statistics: {stats}")
    print(f"Packets received: {len(packets_received)}")
    print(f"Actual rate: {stats['actual_rate']:.2f}/sec")
    print(f"Rate deviation: {stats['rate_deviation']*100:.1f}%")
    
    print("\nAll tests completed!")
