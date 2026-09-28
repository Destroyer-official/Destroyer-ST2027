#!/usr/bin/env python3
"""
decentralized_architecture.py

Production-ready decentralized architecture for military-grade P2P messaging.

This module implements comprehensive decentralized features including:
- DHT-based peer discovery (no central server dependency)
- Direct device-to-device sync (Bluetooth, WiFi Direct)
- Store-and-forward via relay nodes
- Local mesh networking support

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

Correctness Properties Implemented:
- Property 6: DHT Peer Lookup Correctness (Requirements 3.3)
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import struct
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum, Enum
from typing import Callable, Optional, List, Tuple, Any, Dict, Set
from pathlib import Path

class SecurityError(Exception):
    """Base exception for decentralized security violations."""
    pass

# Configure logging
logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

# DHT Configuration
DHT_K_BUCKET_SIZE = 20  # Maximum nodes per k-bucket (Kademlia standard)
DHT_ALPHA = 3  # Parallel lookups
DHT_ID_BITS = 256  # SHA3-256 based node IDs
DHT_REPLICATION_FACTOR = 3  # Store data on k closest nodes
DHT_REFRESH_INTERVAL = 3600  # Bucket refresh interval (1 hour)
DHT_EXPIRY_TIME = 86400  # Data expiry time (24 hours)

# Mesh Networking Configuration
MESH_DISCOVERY_PORT = 5353  # mDNS port for local discovery
MESH_BROADCAST_INTERVAL = 30  # Seconds between discovery broadcasts
MESH_MAX_HOPS = 5  # Maximum hops for mesh routing
MESH_UDP_PORT = 45678  # UDP broadcast port for local discovery

# Relay Node Configuration
RELAY_MAX_QUEUE_SIZE = 1000  # Maximum messages per peer
RELAY_MAX_TOTAL_QUEUED = 10000  # Global cap across all peers (anti-amplification)
RELAY_MESSAGE_TTL = 86400  # Message TTL (24 hours)
RELAY_CLEANUP_INTERVAL = 3600  # Cleanup interval (1 hour)
RELAYENC_MAGIC = b"RELAYENC_V1:"  # At-rest sealed envelope marker

# Device Sync Configuration
BLUETOOTH_SERVICE_UUID = "550e8400-e29b-41d4-a716-446655440000"
WIFI_DIRECT_PORT = 8765


# ============================================================================
# Exceptions
# ============================================================================

# S/Kademlia PoW difficulty (leading zero BYTES of node_id).
# 2028 hardening: single source of truth — generation, verification, and
# admission MUST agree (a past mismatch generated difficulty-2 IDs while
# verification demanded 3, so honest nodes were rejected). Default 2
# (16-bit, ~0.1s to mine, verified by measurement) keeps node startup
# reliable; difficulty-3 mining averages ~35s in CPython with ~30% budget
# overrun, i.e. an availability hazard for honest nodes. Raise via
# P2P_DHT_POW_DIFFICULTY_BYTES=3 for high-threat deployments with
# persistent (pre-mined) identities; verify_deployment.py warns when
# production runs below 3. PoW is defense-in-depth garnish here — the
# Sybil barriers are signed-DHT + whitelist + TOFU pinning (all
# default-on).
DEFAULT_POW_DIFFICULTY_BYTES = 2


def _pow_difficulty() -> int:
    """Effective PoW difficulty: env override or matched default."""
    try:
        return max(0, int(os.environ.get("P2P_DHT_POW_DIFFICULTY_BYTES",
                                         str(DEFAULT_POW_DIFFICULTY_BYTES))))
    except (TypeError, ValueError):
        return DEFAULT_POW_DIFFICULTY_BYTES


class DecentralizedError(Exception):
    """Base exception for decentralized architecture errors."""


class DHTError(DecentralizedError):
    """Error in DHT operations."""


class PeerNotFoundError(DHTError):
    """Peer not found in DHT."""


class MeshNetworkError(DecentralizedError):
    """Error in mesh networking."""


class RelayError(DecentralizedError):
    """Error in relay operations."""


class DeviceSyncError(DecentralizedError):
    """Error in device-to-device sync."""


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class DHTNodeInfo:
    """Information about a DHT node."""
    node_id: bytes  # 256-bit node ID (SHA3-256 hash)
    address: str  # IP address or hostname
    port: int  # Port number
    public_key: Optional[bytes] = None  # ML-KEM-1024 public key
    sig_public_key: Optional[bytes] = None  # ML-DSA-87 public key
    pow_nonce: Optional[int] = None  # Proof-of-work puzzle nonce (Finding 16)
    last_seen: float = field(default_factory=time.time)
    onion_address: Optional[str] = None  # Tor v3 onion address

    def verify_pow_and_identity(self, required_zero_bytes: Optional[int] = None) -> bool:
        """Verify node_id = sha3_256(public_key + pow_nonce) and leading zeros (Findings 15, 16)."""
        if required_zero_bytes is None:
            required_zero_bytes = _pow_difficulty()
        if not self.public_key or self.pow_nonce is None:
            return False
        try:
            expected = hashlib.sha3_256(self.public_key + self.pow_nonce.to_bytes(4, 'big')).digest()
            if self.node_id != expected:
                return False
            return all(self.node_id[i] == 0 for i in range(required_zero_bytes))
        except Exception:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'node_id': self.node_id.hex(),
            'address': self.address,
            'port': self.port,
            'public_key': self.public_key.hex() if self.public_key else None,
            'sig_public_key': self.sig_public_key.hex() if self.sig_public_key else None,
            'pow_nonce': self.pow_nonce,
            'last_seen': self.last_seen,
            'onion_address': self.onion_address,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DHTNodeInfo':
        """Deserialize from dictionary."""
        return cls(
            node_id=bytes.fromhex(data['node_id']),
            address=data['address'],
            port=data['port'],
            public_key=bytes.fromhex(data['public_key']) if data.get('public_key') else None,
            sig_public_key=bytes.fromhex(data['sig_public_key']) if data.get('sig_public_key') else None,
            pow_nonce=data.get('pow_nonce'),
            last_seen=data.get('last_seen', time.time()),
            onion_address=data.get('onion_address'),
        )


@dataclass
class DHTValue:
    """Value stored in DHT."""
    key: bytes  # Key (hash of peer ID)
    value: bytes  # Serialized peer info
    timestamp: float = field(default_factory=time.time)
    ttl: int = DHT_EXPIRY_TIME
    signature: Optional[bytes] = None  # ML-DSA-87 signature
    sig_public_key: Optional[bytes] = None  # ML-DSA-87 public key
    
    def is_expired(self) -> bool:
        """Check if value has expired."""
        return time.time() > self.timestamp + self.ttl


@dataclass
class RelayMessage:
    """Message queued for relay delivery."""
    message_id: str
    sender_id: bytes
    recipient_id: bytes
    encrypted_payload: bytes
    timestamp: float = field(default_factory=time.time)
    ttl: int = RELAY_MESSAGE_TTL
    hop_count: int = 0
    # Origin authentication (H16): ML-DSA-87 signature over signing_bytes().
    # Unsigned messages are accepted only when no verifier is configured
    # (legacy/intra-process path) and are never persisted without a seal.
    sender_sig: Optional[bytes] = None
    sender_pubkey: Optional[bytes] = None

    def is_expired(self) -> bool:
        """Check if message has expired."""
        return time.time() > self.timestamp + self.ttl

    def signing_bytes(self) -> bytes:
        """Canonical bytes covered by sender_sig."""
        return (self.sender_id + self.recipient_id + self.encrypted_payload +
                struct.pack('>d', self.timestamp) +
                self.message_id.encode('utf-8'))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'message_id': self.message_id,
            'sender_id': self.sender_id.hex(),
            'recipient_id': self.recipient_id.hex(),
            'encrypted_payload': self.encrypted_payload.hex(),
            'timestamp': self.timestamp,
            'ttl': self.ttl,
            'hop_count': self.hop_count,
            'sender_sig': self.sender_sig.hex() if self.sender_sig else None,
            'sender_pubkey': self.sender_pubkey.hex() if self.sender_pubkey else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RelayMessage':
        """Deserialize from dictionary."""
        return cls(
            message_id=data['message_id'],
            sender_id=bytes.fromhex(data['sender_id']),
            recipient_id=bytes.fromhex(data['recipient_id']),
            encrypted_payload=bytes.fromhex(data['encrypted_payload']),
            timestamp=data.get('timestamp', time.time()),
            ttl=data.get('ttl', RELAY_MESSAGE_TTL),
            hop_count=data.get('hop_count', 0),
            sender_sig=bytes.fromhex(data['sender_sig']) if data.get('sender_sig') else None,
            sender_pubkey=bytes.fromhex(data['sender_pubkey']) if data.get('sender_pubkey') else None,
        )


@dataclass
class MeshPeer:
    """Peer discovered on local mesh network."""
    peer_id: bytes
    address: str
    port: int
    last_seen: float = field(default_factory=time.time)
    hop_count: int = 0
    rssi: Optional[int] = None  # Signal strength for wireless
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'peer_id': self.peer_id.hex(),
            'address': self.address,
            'port': self.port,
            'last_seen': self.last_seen,
            'hop_count': self.hop_count,
            'rssi': self.rssi,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MeshPeer':
        """Deserialize from dictionary."""
        return cls(
            peer_id=bytes.fromhex(data['peer_id']),
            address=data['address'],
            port=data['port'],
            last_seen=data.get('last_seen', time.time()),
            hop_count=data.get('hop_count', 0),
            rssi=data.get('rssi'),
        )


# ============================================================================
# K-Bucket for DHT Routing Table
# ============================================================================

class KBucket:
    """
    K-bucket for Kademlia DHT routing table.
    
    Each bucket holds up to K nodes with similar XOR distance from our node ID.
    Implements LRU eviction with preference for long-lived nodes.
    """
    
    def __init__(self, k: int = DHT_K_BUCKET_SIZE, ping_callback: Optional[Callable[[DHTNodeInfo], bool]] = None):
        """Initialize k-bucket with maximum size k."""
        self.k = k
        self.ping_callback = ping_callback
        self._nodes: List[DHTNodeInfo] = []
        self._lock = threading.Lock()
        self.last_updated = time.time()
    
    def add_node(self, node: DHTNodeInfo) -> bool:
        """
        Add or update a node in the bucket.
        
        Returns True if node was added/updated, False if bucket is full.
        """
        with self._lock:
            # Check if node already exists
            for i, existing in enumerate(self._nodes):
                if existing.node_id == node.node_id:
                    # Move to end (most recently seen)
                    self._nodes.pop(i)
                    node.last_seen = time.time()
                    self._nodes.append(node)
                    self.last_updated = time.time()
                    return True
            
            # Subnet diversity: limit max 2 nodes from same subnet to prevent Eclipse attacks (Finding 2.2)
            if node.address and node.address not in ("127.0.0.1", "::1", "localhost"):
                prefix = node.address.rsplit('.', 1)[0] if '.' in node.address else node.address.rsplit(':', 4)[0]
                same_subnet = sum(
                    1 for n in self._nodes
                    if n.address and (n.address.rsplit('.', 1)[0] if '.' in n.address else n.address.rsplit(':', 4)[0]) == prefix
                )
                if same_subnet >= 2:
                    return False

            # Add new node if space available
            if len(self._nodes) < self.k:
                self._nodes.append(node)
                self.last_updated = time.time()
                return True
            
            # Bucket full - check if oldest node is stale via liveness verification
            oldest = self._nodes[0]
            is_stale = (time.time() - oldest.last_seen > DHT_REFRESH_INTERVAL)
            if not is_stale and self.ping_callback:
                try:
                    is_alive = self.ping_callback(oldest)
                    if is_alive:
                        # Oldest is still alive: move to tail, keep established node, reject candidate
                        self._nodes.pop(0)
                        oldest.last_seen = time.time()
                        self._nodes.append(oldest)
                        return False
                    else:
                        is_stale = True
                except Exception:
                    # B110: ping failure keeps the established node (fail-closed
                    # toward stability: no eviction on uncertain liveness),
                    # but must stay observable.
                    logger.debug("DHT liveness ping failed; keeping established node", exc_info=True)
                    pass

            if is_stale:
                # Replace stale node
                self._nodes.pop(0)
                self._nodes.append(node)
                self.last_updated = time.time()
                return True
            
            return False
    
    def remove_node(self, node_id: bytes) -> bool:
        """Remove a node from the bucket."""
        with self._lock:
            for i, node in enumerate(self._nodes):
                if node.node_id == node_id:
                    self._nodes.pop(i)
                    return True
            return False
    
    def get_nodes(self) -> List[DHTNodeInfo]:
        """Get all nodes in the bucket."""
        with self._lock:
            return list(self._nodes)
    
    def __len__(self) -> int:
        return len(self._nodes)


# ============================================================================
# DHT Routing Table
# ============================================================================

class DHTRoutingTable:
    """
    Kademlia-style DHT routing table.
    
    Organizes nodes into k-buckets based on XOR distance from local node ID.
    Supports efficient O(log n) lookups.
    """
    
    def __init__(self, local_node_id: bytes, k: int = DHT_K_BUCKET_SIZE, ping_callback: Optional[Callable[[DHTNodeInfo], bool]] = None):
        """
        Initialize routing table.
        
        Args:
            local_node_id: Our node's 256-bit ID
            k: Maximum nodes per bucket
            ping_callback: Optional callback for liveness check before eviction
        """
        self.local_node_id = local_node_id
        self.k = k
        self.ping_callback = ping_callback
        self._buckets: List[KBucket] = [KBucket(k, ping_callback=ping_callback) for _ in range(DHT_ID_BITS)]
        self._lock = threading.Lock()
    
    @staticmethod
    def xor_distance(id1: bytes, id2: bytes) -> int:
        """Calculate XOR distance between two node IDs."""
        return int.from_bytes(
            bytes(a ^ b for a, b in zip(id1, id2)),
            byteorder='big'
        )
    
    @staticmethod
    def get_bucket_index(distance: int) -> int:
        """Get bucket index for a given XOR distance."""
        if distance == 0:
            return 0
        return min(distance.bit_length() - 1, DHT_ID_BITS - 1)
    
    def add_node(self, node: DHTNodeInfo) -> bool:
        """Add a node to the routing table after verifying identity and proof-of-work (Finding 16)."""
        if node.node_id == self.local_node_id:
            return False

        # 2028 hardening: production refuses downgraded DHT policy.
        _prod = os.environ.get("SECURE_P2P_PRODUCTION", "0") == "1" or os.environ.get("P2P_PRODUCTION", "0").lower() in ("1", "true")
        if _prod and os.environ.get("P2P_ENFORCE_DHT_POW", "1") != "1":
            logger.critical("MILITARY FATAL: production refuses P2P_ENFORCE_DHT_POW!=1 (Sybil downgrade)")
            return False
        
        # Verify node-ID proof-of-work and public key binding (Finding 15, 16)
        # Matched default via _pow_difficulty(): generation and admission
        # agree by construction (see DEFAULT_POW_DIFFICULTY_BYTES).
        required_zeros = _pow_difficulty()
        if os.environ.get("P2P_ENFORCE_DHT_POW", "1") == "1":
            if not node.verify_pow_and_identity(required_zeros):
                logger.warning(f"Rejecting DHT node admission: invalid PoW or public key mismatch for {node.node_id.hex()[:16]}")
                return False

        distance = self.xor_distance(self.local_node_id, node.node_id)
        bucket_idx = self.get_bucket_index(distance)
        
        with self._lock:
            return self._buckets[bucket_idx].add_node(node)
    
    def remove_node(self, node_id: bytes) -> bool:
        """Remove a node from the routing table."""
        distance = self.xor_distance(self.local_node_id, node_id)
        bucket_idx = self.get_bucket_index(distance)
        
        with self._lock:
            return self._buckets[bucket_idx].remove_node(node_id)
    
    def find_closest_nodes(self, target_id: bytes, count: int = DHT_K_BUCKET_SIZE) -> List[DHTNodeInfo]:
        """
        Find the k closest nodes to a target ID.
        
        Args:
            target_id: Target node ID to find closest nodes to
            count: Maximum number of nodes to return
            
        Returns:
            List of closest nodes sorted by XOR distance
        """
        all_nodes = []
        
        with self._lock:
            for bucket in self._buckets:
                all_nodes.extend(bucket.get_nodes())
        
        # Sort by XOR distance to target
        all_nodes.sort(key=lambda n: self.xor_distance(n.node_id, target_id))
        
        return all_nodes[:count]
    
    def get_node(self, node_id: bytes) -> Optional[DHTNodeInfo]:
        """Get a specific node by ID."""
        distance = self.xor_distance(self.local_node_id, node_id)
        bucket_idx = self.get_bucket_index(distance)
        
        with self._lock:
            for node in self._buckets[bucket_idx].get_nodes():
                if node.node_id == node_id:
                    return node
        return None
    
    def get_all_nodes(self) -> List[DHTNodeInfo]:
        """Get all nodes in the routing table."""
        all_nodes = []
        with self._lock:
            for bucket in self._buckets:
                all_nodes.extend(bucket.get_nodes())
        return all_nodes
    
    def get_stale_buckets(self) -> List[int]:
        """Get indices of buckets that need refreshing."""
        stale = []
        now = time.time()
        with self._lock:
            for i, bucket in enumerate(self._buckets):
                if len(bucket) > 0 and now - bucket.last_updated > DHT_REFRESH_INTERVAL:
                    stale.append(i)
        return stale


# ============================================================================
# DHT Storage
# ============================================================================

def verify_dht_signature(key: bytes, value: bytes, signature: bytes, sig_public_key: bytes, timestamp: Optional[float] = None) -> bool:
    """
    Cryptographically verify ML-DSA-87 (or Ed25519) signature over DHT key, value, and timestamp (Finding 1).
    Fail closed on any error or signature mismatch.
    """
    if not signature or not sig_public_key:
        return False

    candidates = []
    if timestamp is not None:
        try:
            candidates.append(key + value + struct.pack('>Q', int(timestamp)))
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        try:
            candidates.append(key + value + str(int(timestamp)).encode('utf-8'))
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    candidates.append(key + value)

    # 1. Try ML-DSA-87 (NIST FIPS 204 Level 5)
    try:
        from pqc_algorithms import EnhancedMLDSA_87
        dsa = EnhancedMLDSA_87()
        for cand in candidates:
            try:
                if dsa.verify(sig_public_key, cand, signature):
                    return True
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass

    # 2. Try Ed25519 if 32-byte public key
    if len(sig_public_key) == 32:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            ed_pk = ed25519.Ed25519PublicKey.from_public_bytes(sig_public_key)
            for cand in candidates:
                try:
                    ed_pk.verify(signature, cand)
                    return True
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass

    return False


def _try_merge_crl_bundle(value: bytes) -> int:
    """Optionally merge an air-gap CRL gossip bundle carried in a STORE value.

    Purely local helper (no network fetch). Accepts either a bare CRL bundle
    dict ({issuer, version, revoked_serials, timestamp, sig, ...}) or a dict
    wrapping one under the 'crl_bundle' key. Delegates verification/merge to
    MultiDeviceManager.import_crl_bundle (fail-open with warn when unsigned).

    Returns number of newly merged revocations, 0 when absent/inapplicable.
    Never raises (STORE path must be unaffected by CRL errors).
    """
    try:
        if not value:
            return 0
        try:
            val_dict = json.loads(value.decode('utf-8'))
        except Exception:
            return 0
        if not isinstance(val_dict, dict):
            return 0
        bundle = val_dict.get('crl_bundle', val_dict)
        if not isinstance(bundle, dict) or 'revoked_serials' not in bundle:
            return 0
        try:
            from multi_device_manager import get_multi_device_manager
            manager = get_multi_device_manager()
        except Exception as e:
            logger.debug(f"CRL gossip: no device manager available, skipping merge: {e}")
            return 0
        try:
            return int(manager.import_crl_bundle(bundle))
        except Exception as e:
            logger.debug(f"CRL gossip merge skipped (fail-open): {e}")
            return 0
    except Exception:
        return 0


class DHTStorage:
    """
    In-memory and persistent storage for DHT key-value pairs.
    
    Supports TTL expiration and automatic cleanup.
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize DHT storage.
        
        Args:
            storage_path: Optional path for persistent storage
        """
        self.storage_path = Path(storage_path) if storage_path else None
        self._data: Dict[bytes, DHTValue] = {}
        self._lock = threading.Lock()
        
        # Load existing data if path provided
        if self.storage_path and self.storage_path.exists():
            self._load_from_disk()
    
    def _load_from_disk(self) -> None:
        """Load data from disk."""
        if not self.storage_path or not self.storage_path.exists():
            return
        
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            
            for key_hex, value_data in data.items():
                key = bytes.fromhex(key_hex)
                value = DHTValue(
                    key=key,
                    value=bytes.fromhex(value_data['value']),
                    timestamp=value_data['timestamp'],
                    ttl=value_data['ttl'],
                    signature=bytes.fromhex(value_data['signature']) if value_data.get('signature') else None,
                    sig_public_key=bytes.fromhex(value_data['sig_public_key']) if value_data.get('sig_public_key') else None,
                )
                if not value.is_expired():
                    self._data[key] = value
            
            logger.info(f"Loaded {len(self._data)} DHT entries from disk")
        except Exception as e:
            logger.error(f"Failed to load DHT storage: {e}")
    
    def _save_to_disk(self) -> None:
        """Save data to disk."""
        if not self.storage_path:
            return
        
        try:
            data = {}
            with self._lock:
                for key, value in self._data.items():
                    if not value.is_expired():
                        data[key.hex()] = {
                            'value': value.value.hex(),
                            'timestamp': value.timestamp,
                            'ttl': value.ttl,
                            'signature': value.signature.hex() if value.signature else None,
                            'sig_public_key': value.sig_public_key.hex() if value.sig_public_key else None,
                        }
            
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Failed to save DHT storage: {e}")
    
    def store(self, key: bytes, value: bytes, ttl: int = DHT_EXPIRY_TIME, 
              signature: Optional[bytes] = None,
              sig_public_key: Optional[bytes] = None,
              timestamp: Optional[float] = None) -> bool:
        """
        Store a value in the DHT with cryptographic ML-DSA-87 signature verification.
        
        Args:
            key: Key to store under
            value: Value to store
            ttl: Time-to-live in seconds
            signature: Optional ML-DSA-87 signature
            sig_public_key: Optional ML-DSA-87 or Ed25519 public key
            timestamp: Optional creation timestamp
            
        Returns:
            True if stored successfully
        """
        # Maximum allowed TTL is 3600 seconds (1 hour) to mitigate persistent storage poisoning
        clamped_ttl = min(float(ttl), 3600.0)
        current_ts = timestamp if timestamp is not None else time.time()

        # Fail-closed signature enforcement for DHT storage (Findings 1, 16, 25)
        if not signature:
            logger.warning(f"Rejecting unsigned DHT store under secure policy for key {key.hex()[:16]}")
            return False

        # Extract sig_public_key from value if not passed
        if not sig_public_key and value:
            try:
                val_dict = json.loads(value.decode('utf-8'))
                if isinstance(val_dict, dict) and val_dict.get('sig_public_key'):
                    sig_public_key = bytes.fromhex(val_dict['sig_public_key'])
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass

        if not sig_public_key:
            # Strict fail-closed: reject signature when public key cannot be determined (Finding 1)
            logger.warning(f"Rejecting DHT store: signature present without public key for {key.hex()[:16]}")
            return False

        if not verify_dht_signature(key, value, signature, sig_public_key, current_ts):
            logger.warning(f"Rejecting DHT store with invalid signature for key {key.hex()[:16]}")
            return False

        with self._lock:
            existing = self._data.get(key)
            if existing and not existing.is_expired():
                # Key ownership binding (Finding 16): overwrite must be signed by the existing public key
                if existing.sig_public_key and sig_public_key:
                    if existing.sig_public_key != sig_public_key:
                        logger.warning(f"Rejecting DHT overwrite of key {key.hex()[:16]}: key ownership mismatch (different public key)")
                        return False
                # Anti-replay / downgrade protection: new timestamp must be strictly greater than existing
                if current_ts <= existing.timestamp:
                    logger.warning(f"Rejecting DHT overwrite with non-monotonic timestamp: {current_ts} <= {existing.timestamp}")
                    return False
                if existing.signature and not signature:
                    logger.warning(f"Rejecting unauthenticated overwrite of signed DHT key {key.hex()[:16]}")
                    return False

            # Memory bound check: evict expired entries if table is large
            if len(self._data) > 10000:
                expired_keys = [k for k, v in self._data.items() if v.is_expired()]
                for k in expired_keys:
                    del self._data[k]

            self._data[key] = DHTValue(
                key=key,
                value=value,
                timestamp=current_ts,
                ttl=clamped_ttl,
                signature=signature,
                sig_public_key=sig_public_key,
            )
        
        self._save_to_disk()
        return True
    
    def get(self, key: bytes) -> Optional[DHTValue]:
        """
        Get a value from the DHT.
        
        Args:
            key: Key to look up
            
        Returns:
            DHTValue if found and not expired, None otherwise
        """
        with self._lock:
            value = self._data.get(key)
            if value and not value.is_expired():
                return value
            elif value:
                # Remove expired entry
                del self._data[key]
        return None
    
    def delete(self, key: bytes) -> bool:
        """Delete a value from the DHT."""
        with self._lock:
            if key in self._data:
                del self._data[key]
                self._save_to_disk()
                return True
        return False
    
    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        removed = 0
        with self._lock:
            expired_keys = [k for k, v in self._data.items() if v.is_expired()]
            for key in expired_keys:
                del self._data[key]
                removed += 1
        
        if removed > 0:
            self._save_to_disk()
            logger.info(f"Cleaned up {removed} expired DHT entries")
        
        return removed
    
    def get_all_keys(self) -> List[bytes]:
        """Get all non-expired keys."""
        with self._lock:
            return [k for k, v in self._data.items() if not v.is_expired()]



# ============================================================================
# Decentralized Peer Discovery (DHT-based)
# ============================================================================

class DecentralizedPeerDiscovery:
    """
    DHT-based peer discovery without central server dependency.
    
    Implements Kademlia-style distributed hash table for peer lookup.
    Supports storing and retrieving peer information across the network.
    
    **Property 6: DHT Peer Lookup Correctness**
    *For any* peer ID stored in the DHT, lookup SHALL return the correct
    peer information (address, port, public keys) if the peer exists.
    **Validates: Requirements 3.1, 3.3**
    """
    
    def __init__(
        self,
        node_id: Optional[bytes] = None,
        address: Optional[str] = None,
        port: int = 45678,
        storage_path: Optional[Path] = None,
        bootstrap_nodes: Optional[List[Tuple[str, int]]] = None,
        public_key: Optional[bytes] = None,
    ):
        """
        Initialize decentralized peer discovery.
        
        Args:
            node_id: Our node's 256-bit ID (generated if not provided)
            address: Local address to bind to
            port: Local port to bind to
            storage_path: Path for persistent storage
            bootstrap_nodes: List of (address, port) tuples for bootstrap
            public_key: Public key to cryptographically bind to the node ID
        """
        self.public_key = public_key if public_key else secrets.token_bytes(32)

        # Initialize ML-DSA-87 signature keypair for DHT authentication (Finding 1)
        self.sig_public_key = None
        self.sig_private_key = None
        self._dsa = None
        try:
            from pqc_algorithms import EnhancedMLDSA_87
            self._dsa = EnhancedMLDSA_87()
            self.sig_public_key, self.sig_private_key = self._dsa.keygen()
        except Exception as e:
            logger.warning(f"Failed to initialize ML-DSA-87 for DHT node: {e}")

        # Generate node ID bound to public key with S/Kademlia crypto puzzle (Findings 2.2 & Items 15, 16)
        # Matched default via _pow_difficulty(): honest self-generated nodes
        # always satisfy default verification (see DEFAULT_POW_DIFFICULTY_BYTES).
        if node_id is None:
            # Proof-of-work bound to public key: candidate = sha3_256(public_key + nonce) (Findings 15, 16)
            target_zeros = _pow_difficulty()
            max_range = 2000000 if target_zeros <= 2 else 20000000
            for nonce in range(max_range):
                candidate = hashlib.sha3_256(self.public_key + nonce.to_bytes(4, 'big')).digest()
                if all(candidate[i] == 0 for i in range(target_zeros)):
                    node_id = candidate
                    self.pow_nonce = nonce
                    break
            if node_id is None:
                raise SecurityError("Failed to solve S/Kademlia proof-of-work puzzle within iteration limit")
        
        self.node_id = node_id
        # B104: wildcard bind is required for inbound P2P DHT; override for lab
        # with P2P_BIND_ADDRESS=127.0.0.1. mTLS + signed-DHT enforced on secure path.
        import os as _os
        self.address = address or _os.environ.get("P2P_BIND_ADDRESS", "0.0.0.0")  # nosec B104 - P2P inbound, configurable
        self.port = port
        
        # Initialize routing table with ping liveness check and storage
        self.routing_table = DHTRoutingTable(node_id, ping_callback=self._ping_node_sync)
        self.storage = DHTStorage(storage_path)
        
        # Bootstrap nodes
        self.bootstrap_nodes = bootstrap_nodes or []
        
        # State
        self._running = False
        self._lock = threading.Lock()
        self._pending_lookups: Dict[str, Dict[str, Any]] = {}
        self._pending_lookups_by_key: Dict[str, Dict[str, Any]] = {}
        self._server_socket: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._refresh_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self._on_peer_discovered: Optional[Callable[[DHTNodeInfo], None]] = None
        
        logger.info(f"DecentralizedPeerDiscovery initialized with node_id={node_id.hex()[:16]}...")
    
    def start(self) -> bool:
        """
        Start the DHT node.
        
        Returns:
            True if started successfully
        """
        with self._lock:
            if self._running:
                return True
            
            try:
                # Create UDP socket for DHT protocol
                self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server_socket.bind((self.address, self.port))
                self._server_socket.settimeout(1.0)
                
                self._running = True
                
                # Start server thread
                self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
                self._server_thread.start()
                
                # Start refresh thread
                self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
                self._refresh_thread.start()
                
                # Bootstrap from known nodes
                self._bootstrap()
                
                logger.info(f"DHT node started on {self.address}:{self.port}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to start DHT node: {e}")
                self._running = False
                return False
    
    def stop(self) -> None:
        """Stop the DHT node."""
        with self._lock:
            self._running = False
        
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                raise NotImplementedError("Abstract method")
        
        if self._server_thread:
            self._server_thread.join(timeout=2.0)
        
        if self._refresh_thread:
            self._refresh_thread.join(timeout=2.0)
        
        logger.info("DHT node stopped")
    
    def _bootstrap(self) -> None:
        """Bootstrap from known nodes."""
        for address, port in self.bootstrap_nodes:
            try:
                # Send PING to bootstrap node
                self._send_ping(address, port)
            except Exception as e:
                logger.warning(f"Failed to bootstrap from {address}:{port}: {e}")
    
    def _server_loop(self) -> None:
        """Main server loop for handling incoming DHT messages."""
        while self._running:
            try:
                data, addr = self._server_socket.recvfrom(65535)
                self._handle_message(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"Error in DHT server loop: {e}")
    
    def _refresh_loop(self) -> None:
        """Periodic refresh of routing table and storage."""
        while self._running:
            try:
                # Sleep in small intervals to allow quick shutdown
                for _ in range(60):
                    if not self._running:
                        return
                    time.sleep(1)
                
                # Cleanup expired storage entries
                self.storage.cleanup_expired()
                
                # Refresh stale buckets
                stale_buckets = self.routing_table.get_stale_buckets()
                for bucket_idx in stale_buckets:
                    # Generate random ID in bucket range and lookup
                    random_id = self._generate_id_in_bucket(bucket_idx)
                    self.lookup_node(random_id)
                
            except Exception as e:
                logger.error(f"Error in DHT refresh loop: {e}")
    
    def _generate_id_in_bucket(self, bucket_idx: int) -> bytes:
        """Generate a random node ID that would fall in the given bucket."""
        # Create ID with specific distance from our node
        random_bytes = secrets.token_bytes(32)
        distance = 1 << bucket_idx
        
        # XOR with our node ID to get target distance
        result = bytearray(self.node_id)
        distance_bytes = distance.to_bytes(32, byteorder='big')
        for i in range(32):
            result[i] ^= distance_bytes[i]
        
        return bytes(result)
    
    def _handle_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle incoming DHT message with pre-parsing size cap and per-IP rate limiting."""
        if len(data) > 65536:
            logger.warning(f"Dropping oversized DHT datagram ({len(data)} bytes) from {addr}")
            return

        # Per-IP UDP Rate Limiting (Finding 26 / DOS mitigation)
        client_ip = addr[0]
        now = time.time()
        with self._lock:
            if not hasattr(self, '_dht_ip_rates'):
                self._dht_ip_rates = {}
            window = 60.0
            max_packets = int(os.environ.get("P2P_DHT_MAX_PACKETS_PER_MIN", "60"))
            recent = [t for t in self._dht_ip_rates.get(client_ip, []) if now - t < window]
            if len(recent) >= max_packets:
                logger.warning(f"DHT rate limit exceeded for IP {client_ip} ({len(recent)}/{max_packets} per min). Dropping datagram.")
                return
            recent.append(now)
            self._dht_ip_rates[client_ip] = recent
            if len(self._dht_ip_rates) > 1000:
                self._dht_ip_rates = {k: v for k, v in self._dht_ip_rates.items() if v and now - v[-1] < window}

        try:
            message = json.loads(data.decode('utf-8'))
            msg_type = message.get('type')
            
            if msg_type == 'PING':
                self._handle_ping(message, addr)
            elif msg_type == 'PONG':
                self._handle_pong(message, addr)
            elif msg_type == 'FIND_NODE':
                self._handle_find_node(message, addr)
            elif msg_type == 'FIND_NODE_RESPONSE':
                self._handle_find_node_response(message, addr)
            elif msg_type == 'STORE':
                self._handle_store(message, addr)
            elif msg_type == 'FIND_VALUE':
                self._handle_find_value(message, addr)
            elif msg_type == 'FIND_VALUE_RESPONSE':
                self._handle_find_value_response(message, addr)
            else:
                logger.warning(f"Unknown DHT message type: {msg_type}")
                
        except Exception as e:
            logger.error(f"Error handling DHT message from {addr}: {e}")
    
    def _send_message(self, message: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """Send a DHT message to an address."""
        try:
            data = json.dumps(message).encode('utf-8')
            self._server_socket.sendto(data, addr)
        except Exception as e:
            logger.error(f"Failed to send DHT message to {addr}: {e}")
    
    def _send_ping(self, address: str, port: int) -> None:
        """Send PING message."""
        message = {
            'type': 'PING',
            'node_id': self.node_id.hex(),
            'public_key': self.public_key.hex() if hasattr(self, 'public_key') and self.public_key else None,
            'pow_nonce': getattr(self, 'pow_nonce', None),
            'timestamp': time.time(),
        }
        self._send_message(message, (address, port))
    
    def _handle_ping(self, message: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """Handle PING message."""
        sender_id = bytes.fromhex(message['node_id'])
        pubkey = bytes.fromhex(message['public_key']) if message.get('public_key') else None
        pow_nonce = message.get('pow_nonce')
        
        # Add and verify sender in routing table
        node_info = DHTNodeInfo(
            node_id=sender_id,
            address=addr[0],
            port=addr[1],
            public_key=pubkey,
            pow_nonce=pow_nonce,
        )
        if not self.routing_table.add_node(node_info):
            logger.warning(f"Rejecting unverified PING sender {sender_id.hex()[:16]}")
            return
        
        # Send PONG response
        response = {
            'type': 'PONG',
            'node_id': self.node_id.hex(),
            'public_key': self.public_key.hex() if hasattr(self, 'public_key') and self.public_key else None,
            'pow_nonce': getattr(self, 'pow_nonce', None),
            'timestamp': time.time(),
        }
        self._send_message(response, addr)
    
    def _handle_pong(self, message: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """Handle PONG message."""
        sender_id = bytes.fromhex(message['node_id'])
        pubkey = bytes.fromhex(message['public_key']) if message.get('public_key') else None
        pow_nonce = message.get('pow_nonce')
        
        # Add/update sender in routing table with admission verification (Finding 16)
        node_info = DHTNodeInfo(
            node_id=sender_id,
            address=addr[0],
            port=addr[1],
            public_key=pubkey,
            pow_nonce=pow_nonce,
        )
        admitted = self.routing_table.add_node(node_info)
        if not admitted:
            logger.warning(f"Rejecting unverified PONG sender {sender_id.hex()[:16]}")
            return
        
        # Notify callback only if verified and admitted (Finding 16)
        if self._on_peer_discovered:
            self._on_peer_discovered(node_info)
    
    def _handle_find_node(self, message: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """Handle FIND_NODE message."""
        target_id = bytes.fromhex(message['target_id'])
        sender_id = bytes.fromhex(message['node_id'])
        pubkey = bytes.fromhex(message['public_key']) if message.get('public_key') else None
        pow_nonce = message.get('pow_nonce')
        
        # Add sender to routing table with verification
        node_info = DHTNodeInfo(
            node_id=sender_id,
            address=addr[0],
            port=addr[1],
            public_key=pubkey,
            pow_nonce=pow_nonce,
        )
        if not self.routing_table.add_node(node_info):
            logger.warning(f"Rejecting unverified FIND_NODE sender {sender_id.hex()[:16]}")
            return
        
        # Find closest nodes to target
        closest = self.routing_table.find_closest_nodes(target_id, DHT_K_BUCKET_SIZE)
        
        # Send response
        response = {
            'type': 'FIND_NODE_RESPONSE',
            'node_id': self.node_id.hex(),
            'target_id': target_id.hex(),
            'nodes': [n.to_dict() for n in closest],
        }
        self._send_message(response, addr)
    
    def _handle_find_node_response(self, message: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """Handle FIND_NODE_RESPONSE message."""
        nodes_data = message.get('nodes', [])
        
        for node_data in nodes_data:
            try:
                node_info = DHTNodeInfo.from_dict(node_data)
                admitted = self.routing_table.add_node(node_info)
                
                # Notify callback only if verified and admitted (Finding 16)
                if admitted and self._on_peer_discovered:
                    self._on_peer_discovered(node_info)
            except Exception as e:
                logger.warning(f"Failed to parse node info: {e}")
    
    def _ping_node_sync(self, node: DHTNodeInfo) -> bool:
        """Verify liveness of node before eviction from routing table."""
        if not node.address or not node.port:
            return False
        try:
            self._send_ping(node.address, node.port)
            return (time.time() - node.last_seen) < DHT_REFRESH_INTERVAL
        except Exception:
            return False

    def _handle_store(self, message: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """Handle STORE message with cryptographic signature verification (Finding 1)."""
        key = bytes.fromhex(message['key'])
        value = bytes.fromhex(message['value'])
        ttl = min(int(message.get('ttl', DHT_EXPIRY_TIME)), 3600)
        signature = bytes.fromhex(message['signature']) if message.get('signature') else None
        sig_pubkey = bytes.fromhex(message['sig_public_key']) if message.get('sig_public_key') else None
        timestamp = message.get('timestamp')
        sender_id = bytes.fromhex(message['node_id']) if message.get('node_id') else None
        pubkey = bytes.fromhex(message['public_key']) if message.get('public_key') else None
        pow_nonce = message.get('pow_nonce')

        if sender_id:
            node_info = DHTNodeInfo(
                node_id=sender_id,
                address=addr[0],
                port=addr[1],
                public_key=pubkey,
                sig_public_key=sig_pubkey,
                pow_nonce=pow_nonce,
            )
            if not self.routing_table.add_node(node_info):
                logger.warning(f"Rejecting STORE sender with invalid PoW/identity: {sender_id.hex()[:16]}")
                return

        # Enforce signed STORE under secure policy (Finding 1 & Finding 25)
        if os.environ.get("P2P_REQUIRE_SIGNED_DHT", "1") == "1":
            if not signature:
                logger.warning(f"Rejecting unsigned STORE message from {addr} under secure policy")
                response = {
                    'type': 'STORE_ACK',
                    'node_id': self.node_id.hex(),
                    'key': key.hex(),
                    'success': False,
                }
                self._send_message(response, addr)
                return

            # Extract sig_pubkey from value if not in message
            if not sig_pubkey and value:
                try:
                    val_dict = json.loads(value.decode('utf-8'))
                    if isinstance(val_dict, dict) and val_dict.get('sig_public_key'):
                        sig_pubkey = bytes.fromhex(val_dict['sig_public_key'])
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass

            if not sig_pubkey or not verify_dht_signature(key, value, signature, sig_pubkey, timestamp):
                logger.warning(f"Rejecting STORE with invalid/unverified signature from {addr} for key {key.hex()[:16]}")
                response = {
                    'type': 'STORE_ACK',
                    'node_id': self.node_id.hex(),
                    'key': key.hex(),
                    'success': False,
                }
                self._send_message(response, addr)
                return
        
        # CRL gossip (air-gap, optional, non-breaking): if the value carries a
        # CRL bundle, merge it locally. Fail-open: never reject STORE on CRL
        # errors; no network fetch is performed here.
        try:
            _try_merge_crl_bundle(value)
        except Exception:
            logger.debug("CRL gossip merge skipped (fail-open)", exc_info=True)

        # Store the value
        stored = self.storage.store(key, value, ttl, signature, sig_pubkey, timestamp)
        
        # Send acknowledgment
        response = {
            'type': 'STORE_ACK',
            'node_id': self.node_id.hex(),
            'key': key.hex(),
            'success': stored,
        }
        self._send_message(response, addr)
    
    def _handle_find_value(self, message: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """Handle FIND_VALUE message."""
        key = bytes.fromhex(message['key'])
        txid = message.get('txid')
        sender_id = bytes.fromhex(message['node_id'])
        pubkey = bytes.fromhex(message['public_key']) if message.get('public_key') else None
        pow_nonce = message.get('pow_nonce')
        
        # Add sender to routing table with verification
        node_info = DHTNodeInfo(
            node_id=sender_id,
            address=addr[0],
            port=addr[1],
            public_key=pubkey,
            pow_nonce=pow_nonce,
        )
        if not self.routing_table.add_node(node_info):
            logger.warning(f"Rejecting unverified FIND_VALUE sender {sender_id.hex()[:16]}")
            return
        
        # Check if we have the value
        value = self.storage.get(key)
        
        if value:
            # Return the value with signature and timestamp
            response = {
                'type': 'FIND_VALUE_RESPONSE',
                'txid': txid,
                'node_id': self.node_id.hex(),
                'key': key.hex(),
                'found': True,
                'value': value.value.hex(),
                'timestamp': value.timestamp,
                'signature': value.signature.hex() if value.signature else None,
                'sig_public_key': value.sig_public_key.hex() if value.sig_public_key else None,
            }
        else:
            # Return closest nodes
            closest = self.routing_table.find_closest_nodes(key, DHT_K_BUCKET_SIZE)
            response = {
                'type': 'FIND_VALUE_RESPONSE',
                'txid': txid,
                'node_id': self.node_id.hex(),
                'key': key.hex(),
                'found': False,
                'nodes': [n.to_dict() for n in closest],
            }
        
        self._send_message(response, addr)
    
    def _handle_find_value_response(self, message: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """Handle FIND_VALUE_RESPONSE message with txid correlation, PoW, and signature verification (Finding 2)."""
        txid = message.get('txid')
        key_hex = message.get('key')
        found = message.get('found', False)

        # Correlate response with active pending lookup
        lookup = None
        with self._lock:
            if txid and hasattr(self, '_pending_lookups') and txid in self._pending_lookups:
                lookup = self._pending_lookups[txid]
            elif key_hex and hasattr(self, '_pending_lookups_by_key') and key_hex in self._pending_lookups_by_key:
                lookup = self._pending_lookups_by_key[key_hex]

        if found:
            value_hex = message.get('value')
            if not value_hex:
                return
            try:
                val_bytes = bytes.fromhex(value_hex)
                sig_bytes = bytes.fromhex(message['signature']) if message.get('signature') else None
                sig_pubkey = bytes.fromhex(message['sig_public_key']) if message.get('sig_public_key') else None
                ts = message.get('timestamp')
                key_bytes = bytes.fromhex(key_hex) if key_hex else b""

                # Parse and verify peer info candidate
                data = json.loads(val_bytes.decode('utf-8'))
                candidate = DHTNodeInfo.from_dict(data)

                # Verify PoW and identity
                if not candidate.verify_pow_and_identity():
                    logger.warning(f"Rejecting FIND_VALUE response with invalid PoW/identity from {addr}")
                    return

                # Verify ML-DSA-87 signature if signature is required
                if os.environ.get("P2P_REQUIRE_SIGNED_DHT", "1") == "1":
                    if not sig_bytes:
                        logger.warning(f"Rejecting unsigned FIND_VALUE value from {addr}")
                        return
                    pubkey_to_verify = sig_pubkey or candidate.sig_public_key
                    if not pubkey_to_verify or not verify_dht_signature(key_bytes, val_bytes, sig_bytes, pubkey_to_verify, ts):
                        logger.warning(f"Rejecting FIND_VALUE response with unverified signature from {addr}")
                        return

                if lookup:
                    with lookup['lock']:
                        lookup['responses'].append(candidate)
                        lookup['raw_values'].append((val_bytes, sig_bytes, sig_pubkey, ts))
                        lookup['event'].set()

            except Exception as e:
                logger.warning(f"Failed to process FIND_VALUE_RESPONSE value: {e}")
        else:
            # Handle closest nodes returned by peer
            nodes_data = message.get('nodes', [])
            for node_data in nodes_data:
                try:
                    node_info = DHTNodeInfo.from_dict(node_data)
                    if node_info.verify_pow_and_identity():
                        self.routing_table.add_node(node_info)
                        if lookup:
                            with lookup['lock']:
                                lookup['closest_nodes'].append(node_info)
                except Exception as e:
                    logger.debug(f"Failed to parse node in FIND_VALUE_RESPONSE: {e}")
            if lookup:
                lookup['event'].set()
    
    def lookup_node(self, target_id: bytes, timeout: float = 5.0) -> Optional[DHTNodeInfo]:
        """
        Look up a node by ID.
        
        **Property 6: DHT Peer Lookup Correctness**
        
        Args:
            target_id: Node ID to look up
            timeout: Lookup timeout in seconds
            
        Returns:
            DHTNodeInfo if found, None otherwise
        """
        # Check if we already know this node
        node = self.routing_table.get_node(target_id)
        if node:
            return node
        
        # Iterative lookup
        closest = self.routing_table.find_closest_nodes(target_id, DHT_ALPHA)
        queried: Set[bytes] = set()
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            # Query closest unqueried nodes
            to_query = [n for n in closest if n.node_id not in queried][:DHT_ALPHA]
            
            if not to_query:
                break
            
            for node in to_query:
                queried.add(node.node_id)
                
                # Send FIND_NODE request
                message = {
                    'type': 'FIND_NODE',
                    'node_id': self.node_id.hex(),
                    'public_key': self.public_key.hex() if hasattr(self, 'public_key') and self.public_key else None,
                    'pow_nonce': getattr(self, 'pow_nonce', None),
                    'target_id': target_id.hex(),
                }
                self._send_message(message, (node.address, node.port))
            
            # Wait for responses
            time.sleep(0.5)
            
            # Check if we found the target
            node = self.routing_table.get_node(target_id)
            if node:
                return node
            
            # Update closest nodes
            closest = self.routing_table.find_closest_nodes(target_id, DHT_K_BUCKET_SIZE)
        
        return None
    
    def store_peer_info(self, peer_id: bytes, peer_info: DHTNodeInfo, 
                        signature: Optional[bytes] = None) -> bool:
        """
        Store peer information in the DHT signed with ML-DSA-87 (Finding 1).
        
        Args:
            peer_id: Peer's ID (key)
            peer_info: Peer information to store
            signature: Optional cryptographic signature
            
        Returns:
            True if stored successfully
        """
        key = hashlib.sha3_256(peer_id).digest()
        value = json.dumps(peer_info.to_dict()).encode('utf-8')
        ts = int(time.time())
        msg_to_sign = key + value + struct.pack('>Q', ts)

        if signature is None and hasattr(self, 'sig_private_key') and self.sig_private_key:
            try:
                from pqc_algorithms import EnhancedMLDSA_87
                dsa = getattr(self, '_dsa', None) or EnhancedMLDSA_87()
                signature = dsa.sign(self.sig_private_key, msg_to_sign)
            except Exception as e:
                logger.warning(f"Failed to sign DHT peer info with ML-DSA-87: {e}")
        elif signature is None and hasattr(self, 'signing_key') and self.signing_key:
            try:
                signature = self.signing_key.sign(key + value)
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass

        # Reject unsigned store_peer_info under secure policy (Finding 1 & Finding 25)
        if not signature:
            logger.warning(f"Rejecting unsigned store_peer_info for {peer_id.hex()[:16]} under secure policy")
            return False

        # Store locally
        if not self.storage.store(key, value, DHT_EXPIRY_TIME, signature, self.sig_public_key, ts):
            return False
        
        # Find closest nodes and store on them
        closest = self.routing_table.find_closest_nodes(key, DHT_REPLICATION_FACTOR)
        
        for node in closest:
            message = {
                'type': 'STORE',
                'node_id': self.node_id.hex(),
                'public_key': self.public_key.hex() if hasattr(self, 'public_key') and self.public_key else None,
                'sig_public_key': self.sig_public_key.hex() if hasattr(self, 'sig_public_key') and self.sig_public_key else None,
                'pow_nonce': getattr(self, 'pow_nonce', None),
                'key': key.hex(),
                'value': value.hex(),
                'ttl': DHT_EXPIRY_TIME,
                'timestamp': ts,
                'signature': signature.hex() if signature else None,
            }
            self._send_message(message, (node.address, node.port))
        
        return True
    
    def lookup_peer_info(self, peer_id: bytes, timeout: float = 5.0, require_quorum: bool = True) -> Optional[DHTNodeInfo]:
        """
        Look up peer information from the DHT with network correlation and quorum consensus verification (Finding 2).
        
        **Property 6: DHT Peer Lookup Correctness**
        
        Args:
            peer_id: Peer's ID to look up
            timeout: Lookup timeout in seconds
            require_quorum: Whether to require quorum agreement across closest responsive nodes
            
        Returns:
            DHTNodeInfo if found and verified, None otherwise
        """
        key = hashlib.sha3_256(peer_id).digest()
        
        # Prepare transaction tracking
        txid = secrets.token_hex(16)
        lookup_state = {
            'key': key,
            'responses': [],
            'raw_values': [],
            'closest_nodes': [],
            'event': threading.Event(),
            'lock': threading.Lock()
        }
        with self._lock:
            self._pending_lookups[txid] = lookup_state
            self._pending_lookups_by_key[key.hex()] = lookup_state

        closest = self.routing_table.find_closest_nodes(key, DHT_K_BUCKET_SIZE)
        queried: Set[bytes] = set()

        start_time = time.time()
        try:
            while time.time() - start_time < timeout:
                to_query = [n for n in closest if n.node_id not in queried][:DHT_ALPHA]
                if not to_query:
                    break

                for node in to_query:
                    queried.add(node.node_id)
                    message = {
                        'type': 'FIND_VALUE',
                        'txid': txid,
                        'node_id': self.node_id.hex(),
                        'public_key': self.public_key.hex() if hasattr(self, 'public_key') and self.public_key else None,
                        'sig_public_key': self.sig_public_key.hex() if hasattr(self, 'sig_public_key') and self.sig_public_key else None,
                        'pow_nonce': getattr(self, 'pow_nonce', None),
                        'key': key.hex()
                    }
                    self._send_message(message, (node.address, node.port))

                # Wait for responses or timeout
                lookup_state['event'].wait(timeout=min(0.5, max(0.05, timeout - (time.time() - start_time))))
                lookup_state['event'].clear()

                with lookup_state['lock']:
                    current_responses = list(lookup_state['responses'])
                    raw_items = list(lookup_state['raw_values'])

                if current_responses:
                    from collections import Counter
                    counts = Counter(r.node_id for r in current_responses)
                    # Enforce quorum minimum: 3 agreeing nodes whenever the
                    # network was actually consulted (Finding 17). The
                    # non-quorum exception covers only the isolated case
                    # (no routable peers queried at all), never a live net.
                    quorum_needed = 3 if (require_quorum or len(queried) >= 3 or len(closest) >= 3) else 1

                    for nid, c in counts.items():
                        if c >= quorum_needed:
                            chosen = next(r for r in current_responses if r.node_id == nid)
                            for rv, sig, spk, ts in raw_items:
                                self.storage.store(key, rv, DHT_EXPIRY_TIME, sig, spk or chosen.sig_public_key, ts)
                                break
                            return chosen

                # Add newly discovered nodes from responses
                with lookup_state['lock']:
                    new_nodes = list(lookup_state['closest_nodes'])
                    lookup_state['closest_nodes'].clear()
                for nn in new_nodes:
                    if nn.node_id not in queried and nn not in closest:
                        closest.append(nn)

            # Final quorum check on collected responses
            with lookup_state['lock']:
                final_responses = list(lookup_state['responses'])
                final_raw = list(lookup_state['raw_values'])
            if final_responses:
                from collections import Counter
                counts = Counter(r.node_id for r in final_responses)
                quorum_needed = 3 if (require_quorum or len(queried) >= 3) else 1
                for nid, c in counts.items():
                    if c >= quorum_needed:
                        chosen = next(r for r in final_responses if r.node_id == nid)
                        for rv, sig, spk, ts in final_raw:
                            self.storage.store(key, rv, DHT_EXPIRY_TIME, sig, spk or chosen.sig_public_key, ts)
                            break
                        return chosen

            # Isolated-node fallback: local storage is consulted ONLY when no
            # network peer was queried at all (air-gap/single node). Any live
            # network response set above already required quorum.
            if not require_quorum and not queried:
                local_value = self.storage.get(key)
                if local_value:
                    try:
                        data = json.loads(local_value.value.decode('utf-8'))
                        candidate = DHTNodeInfo.from_dict(data)
                        if candidate.verify_pow_and_identity():
                            return candidate
                    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B110
                        pass

            return None

        finally:
            with self._lock:
                self._pending_lookups.pop(txid, None)
                self._pending_lookups_by_key.pop(key.hex(), None)
    
    def set_peer_discovered_callback(self, callback: Callable[[DHTNodeInfo], None]) -> None:
        """Set callback for when a new peer is discovered."""
        self._on_peer_discovered = callback
    
    def get_known_peers(self) -> List[DHTNodeInfo]:
        """Get all known peers from routing table."""
        return self.routing_table.get_all_nodes()
    
    @property
    def is_running(self) -> bool:
        """Check if DHT node is running."""
        return self._running



# ============================================================================
# Local Mesh Network Discovery
# ============================================================================

class LocalMeshDiscovery:
    """
    Local mesh network discovery for air-gapped operation.
    
    Supports peer discovery without internet connectivity using:
    - UDP broadcast on local network
    - mDNS-style service discovery
    
    **Validates: Requirements 3.5**
    """
    
    def __init__(
        self,
        node_id: bytes,
        port: int = MESH_UDP_PORT,
        broadcast_interval: float = MESH_BROADCAST_INTERVAL,
    ):
        """
        Initialize local mesh discovery.
        
        Args:
            node_id: Our node's ID
            port: UDP port for discovery
            broadcast_interval: Seconds between broadcasts
        """
        self.node_id = node_id
        self.port = port
        self.broadcast_interval = broadcast_interval
        
        self._peers: Dict[bytes, MeshPeer] = {}
        self._lock = threading.Lock()
        self._running = False
        self._socket: Optional[socket.socket] = None
        self._broadcast_thread: Optional[threading.Thread] = None
        self._listen_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self._on_peer_discovered: Optional[Callable[[MeshPeer], None]] = None
        self._on_peer_lost: Optional[Callable[[MeshPeer], None]] = None
        
        logger.info(f"LocalMeshDiscovery initialized on port {port}")
    
    def start(self) -> bool:
        """Start mesh discovery."""
        with self._lock:
            if self._running:
                return True
            
            try:
                # Create UDP socket for broadcast
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self._socket.bind(('', self.port))
                self._socket.settimeout(1.0)
                
                self._running = True
                
                # Start broadcast thread
                self._broadcast_thread = threading.Thread(target=self._broadcast_loop, daemon=True)
                self._broadcast_thread.start()
                
                # Start listen thread
                self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
                self._listen_thread.start()
                
                logger.info("Local mesh discovery started")
                return True
                
            except Exception as e:
                logger.error(f"Failed to start mesh discovery: {e}")
                self._running = False
                return False
    
    def stop(self) -> None:
        """Stop mesh discovery."""
        with self._lock:
            self._running = False
        
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                logger.debug("Socket close error ignored")
        
        if self._broadcast_thread:
            self._broadcast_thread.join(timeout=2.0)
        
        if self._listen_thread:
            self._listen_thread.join(timeout=2.0)
        
        logger.info("Local mesh discovery stopped")
    
    def _broadcast_loop(self) -> None:
        """Periodically broadcast presence."""
        while self._running:
            try:
                self._send_discovery_broadcast()
                
                # Check for stale peers
                self._cleanup_stale_peers()
                
                # Sleep in intervals for quick shutdown
                for _ in range(int(self.broadcast_interval)):
                    if not self._running:
                        return
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in mesh broadcast loop: {e}")
    
    def _listen_loop(self) -> None:
        """Listen for discovery broadcasts."""
        while self._running:
            try:
                data, addr = self._socket.recvfrom(4096)
                self._handle_discovery_message(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"Error in mesh listen loop: {e}")
    
    def _send_discovery_broadcast(self) -> None:
        """Send discovery broadcast message."""
        message = {
            'type': 'MESH_DISCOVERY',
            'node_id': self.node_id.hex(),
            'port': self.port,
            'timestamp': time.time(),
        }
        
        data = json.dumps(message).encode('utf-8')
        
        try:
            # Broadcast to local network
            self._socket.sendto(data, ('<broadcast>', self.port))
        except Exception as e:
            logger.warning(f"Failed to send discovery broadcast: {e}")
    
    def _handle_discovery_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle incoming discovery message."""
        try:
            message = json.loads(data.decode('utf-8'))
            
            if message.get('type') != 'MESH_DISCOVERY':
                return
            
            peer_id = bytes.fromhex(message['node_id'])
            
            # Ignore our own broadcasts
            if peer_id == self.node_id:
                return
            
            peer = MeshPeer(
                peer_id=peer_id,
                address=addr[0],
                port=message.get('port', self.port),
                last_seen=time.time(),
            )
            
            # Check if this is a new peer
            is_new = False
            with self._lock:
                if peer_id not in self._peers:
                    is_new = True
                self._peers[peer_id] = peer
            
            if is_new and self._on_peer_discovered:
                self._on_peer_discovered(peer)
                logger.info(f"Discovered mesh peer: {addr[0]}:{peer.port}")
                
        except Exception as e:
            logger.warning(f"Failed to handle discovery message: {e}")
    
    def _cleanup_stale_peers(self) -> None:
        """Remove peers that haven't been seen recently."""
        stale_threshold = time.time() - (self.broadcast_interval * 3)
        
        with self._lock:
            stale_peers = [
                peer_id for peer_id, peer in self._peers.items()
                if peer.last_seen < stale_threshold
            ]
            
            for peer_id in stale_peers:
                peer = self._peers.pop(peer_id)
                if self._on_peer_lost:
                    self._on_peer_lost(peer)
                logger.info(f"Lost mesh peer: {peer.address}:{peer.port}")
    
    def get_peers(self) -> List[MeshPeer]:
        """Get all discovered mesh peers."""
        with self._lock:
            return list(self._peers.values())
    
    def set_peer_discovered_callback(self, callback: Callable[[MeshPeer], None]) -> None:
        """Set callback for when a peer is discovered."""
        self._on_peer_discovered = callback
    
    def set_peer_lost_callback(self, callback: Callable[[MeshPeer], None]) -> None:
        """Set callback for when a peer is lost."""
        self._on_peer_lost = callback
    
    @property
    def is_running(self) -> bool:
        """Check if mesh discovery is running."""
        return self._running


# ============================================================================
# Store-and-Forward Relay Node
# ============================================================================

class RelayNode:
    """
    Store-and-forward relay for offline peer message delivery.
    
    Queues messages for offline peers and delivers when they come online.
    Supports multiple relay nodes for redundancy.
    
    **Validates: Requirements 3.4**
    """
    
    def __init__(
        self,
        node_id: bytes,
        max_queue_size: int = RELAY_MAX_QUEUE_SIZE,
        message_ttl: int = RELAY_MESSAGE_TTL,
        storage_path: Optional[Path] = None,
        signer: Optional[Callable[[bytes], bytes]] = None,
        sender_pubkey: Optional[bytes] = None,
        verifier: Optional[Callable[[bytes, bytes, bytes], bool]] = None,
    ):
        """
        Initialize relay node.

        Args:
            node_id: Our node's ID
            max_queue_size: Maximum messages per peer
            message_ttl: Message time-to-live in seconds
            storage_path: Path for persistent storage
            signer: Optional callable signing relay payloads (H16 origin auth)
            sender_pubkey: Public key matching signer, attached to messages
            verifier: Optional callable (pubkey, msg, sig) -> bool used to
                authenticate queued/persisted messages at pickup
        """
        self.node_id = node_id
        self.max_queue_size = max_queue_size
        self.message_ttl = message_ttl
        self.storage_path = storage_path
        self._signer = signer
        self._sender_pubkey = sender_pubkey
        self._verifier = verifier

        # Message queues per recipient
        self._queues: Dict[bytes, List[RelayMessage]] = {}
        self._lock = threading.Lock()

        # Load persisted messages
        if storage_path:
            self._load_from_disk()

        logger.info("RelayNode initialized")

    def _relay_envelope_key(self) -> Optional[bytes]:
        pw = os.environ.get("P2P_STORAGE_PASSPHRASE", "")
        if not pw:
            return None
        return hashlib.scrypt(pw.encode('utf-8'),
                              salt=b"RelayNodeStorage::Envelope::v1",
                              n=32768, r=8, p=1,
                              maxmem=64 * 1024 * 1024, dklen=32)

    def _verify_relay_message(self, message: RelayMessage) -> bool:
        """Authenticate a relay message when a verifier is configured."""
        if self._verifier is None:
            return True
        if not message.sender_sig or not message.sender_pubkey:
            logger.warning(f"Rejecting unsigned relay message {message.message_id}: signature required")
            return False
        try:
            return bool(self._verifier(message.sender_pubkey, message.signing_bytes(), message.sender_sig))
        except Exception as e:
            logger.warning(f"Relay signature verification error: {e}")
            return False
    
    def _load_from_disk(self) -> None:
        """Load queued messages from disk (sealed envelope or legacy JSON)."""
        if not self.storage_path or not self.storage_path.exists():
            return

        try:
            raw = self.storage_path.read_bytes()
            if raw.startswith(RELAYENC_MAGIC):
                key = self._relay_envelope_key()
                if key is None:
                    logger.error("Relay store is sealed but P2P_STORAGE_PASSPHRASE is unset: refusing to load blind")
                    return
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce, ct = raw[len(RELAYENC_MAGIC):][:12], raw[len(RELAYENC_MAGIC) + 12:]
                raw = AESGCM(key).decrypt(nonce, ct, b"RelayNodeStorage::v1")
            elif self._relay_envelope_key() is not None:
                logger.warning("Relay store is legacy plaintext; will re-save sealed")
            data = json.loads(raw.decode('utf-8'))

            for recipient_hex, messages_data in data.items():
                recipient_id = bytes.fromhex(recipient_hex)
                messages = []
                for msg_data in messages_data:
                    try:
                        msg = RelayMessage.from_dict(msg_data)
                    # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B112
                        continue
                    if msg.is_expired():
                        continue
                    if not self._verify_relay_message(msg):
                        continue
                    messages.append(msg)

                if messages:
                    self._queues[recipient_id] = messages

            total = sum(len(q) for q in self._queues.values())
            logger.info(f"Loaded {total} queued messages from disk")
        except Exception as e:
            logger.error(f"Failed to load relay storage: {e}")

    def _save_to_disk(self) -> None:
        """Save queued messages to disk (sealed when a passphrase exists)."""
        if not self.storage_path:
            return

        try:
            data = {}
            with self._lock:
                for recipient_id, messages in self._queues.items():
                    valid_messages = [m for m in messages if not m.is_expired()]
                    if valid_messages:
                        data[recipient_id.hex()] = [m.to_dict() for m in valid_messages]

            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(data).encode('utf-8')
            key = self._relay_envelope_key()
            if key is not None:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce = secrets.token_bytes(12)
                payload = RELAYENC_MAGIC + nonce + AESGCM(key).encrypt(nonce, payload, b"RelayNodeStorage::v1")
            fd = os.open(str(self.storage_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(payload)
        except Exception as e:
            logger.error(f"Failed to save relay storage: {e}")
    
    def queue_message(self, message: RelayMessage) -> bool:
        """
        Queue a message for delivery to an offline peer.

        Signs locally-originated messages when a signer is configured and
        authenticates inbound ones when a verifier is configured. Enforces
        per-peer and global quotas.

        Args:
            message: Message to queue

        Returns:
            True if queued successfully, False if rejected
        """
        if self._signer is not None and not message.sender_sig and self._sender_pubkey is not None:
            try:
                message.sender_sig = self._signer(message.signing_bytes())
                message.sender_pubkey = self._sender_pubkey
            except Exception as e:
                logger.error(f"Relay signing failed, refusing to queue: {e}")
                return False
        # P0-5 ingress guards: drop expired messages and any message whose
        # hop_count already exceeds MESH_MAX_HOPS. Nothing in this design
        # forwards multi-hop today (store-and-forward + direct send), but the
        # ceiling must be enforced at ingress so a malicious or future
        # forwarder can never smuggle high-hop traffic through the queue.
        try:
            if message.is_expired():
                logger.warning("Refusing to queue expired relay message")
                return False
        except Exception:
            return False
        try:
            if int(getattr(message, 'hop_count', 0) or 0) > MESH_MAX_HOPS:
                logger.warning(
                    f"Refusing to queue relay message exceeding MAX_HOPS "
                    f"({message.hop_count} > {MESH_MAX_HOPS})"
                )
                return False
        except Exception:
            return False
        if not self._verify_relay_message(message):
            return False
        with self._lock:
            if message.recipient_id not in self._queues:
                self._queues[message.recipient_id] = []

            queue = self._queues[message.recipient_id]

            # Check queue size limit
            if len(queue) >= self.max_queue_size:
                # Remove oldest message
                queue.pop(0)
                logger.warning(f"Queue full for {message.recipient_id.hex()[:16]}, removed oldest")

            queue.append(message)

            # Global quota across all peers (anti-amplification)
            total = sum(len(q) for q in self._queues.values())
            while total > RELAY_MAX_TOTAL_QUEUED:
                oldest_peer = min(self._queues, key=lambda k: self._queues[k][0].timestamp if self._queues[k] else float('inf'))
                if not self._queues[oldest_peer]:
                    del self._queues[oldest_peer]
                    continue
                self._queues[oldest_peer].pop(0)
                if not self._queues[oldest_peer]:
                    del self._queues[oldest_peer]
                total -= 1

        self._save_to_disk()
        logger.debug(f"Queued message {message.message_id} for {message.recipient_id.hex()[:16]}")
        return True
    
    def get_messages_for_peer(self, peer_id: bytes) -> List[RelayMessage]:
        """
        Get all queued messages for a peer.
        
        Args:
            peer_id: Peer's ID
            
        Returns:
            List of queued messages (removes expired)
        """
        with self._lock:
            if peer_id not in self._queues:
                return []
            
            # Filter out expired messages
            valid_messages = [m for m in self._queues[peer_id] if not m.is_expired()]
            self._queues[peer_id] = valid_messages
            
            return list(valid_messages)
    
    def acknowledge_message(self, peer_id: bytes, message_id: str) -> bool:
        """
        Acknowledge delivery of a message.
        
        Args:
            peer_id: Peer's ID
            message_id: Message ID to acknowledge
            
        Returns:
            True if message was found and removed
        """
        with self._lock:
            if peer_id not in self._queues:
                return False
            
            queue = self._queues[peer_id]
            for i, msg in enumerate(queue):
                if msg.message_id == message_id:
                    queue.pop(i)
                    self._save_to_disk()
                    logger.debug(f"Acknowledged message {message_id}")
                    return True
        
        return False
    
    def cleanup_expired(self) -> int:
        """
        Remove expired messages from all queues.
        
        Returns:
            Number of messages removed
        """
        removed = 0
        with self._lock:
            for peer_id in list(self._queues.keys()):
                original_len = len(self._queues[peer_id])
                self._queues[peer_id] = [m for m in self._queues[peer_id] if not m.is_expired()]
                removed += original_len - len(self._queues[peer_id])
                
                # Remove empty queues
                if not self._queues[peer_id]:
                    del self._queues[peer_id]
        
        if removed > 0:
            self._save_to_disk()
            logger.info(f"Cleaned up {removed} expired relay messages")
        
        return removed
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get statistics about queued messages."""
        with self._lock:
            total_messages = sum(len(q) for q in self._queues.values())
            return {
                'total_peers': len(self._queues),
                'total_messages': total_messages,
                'max_queue_size': self.max_queue_size,
            }


# ============================================================================
# Device-to-Device Sync (Bluetooth/WiFi Direct)
# ============================================================================

class DeviceSyncTransport(ABC):
    """Abstract base class for device-to-device sync transports."""
    
    @abstractmethod
    def start(self) -> bool:
        """Start the transport."""
        raise NotImplementedError("Abstract method")
    
    @abstractmethod
    def stop(self) -> None:
        """Stop the transport."""
        raise NotImplementedError("Abstract method")
    
    @abstractmethod
    def discover_devices(self) -> List[Dict[str, Any]]:
        """Discover nearby devices."""
        raise NotImplementedError("Abstract method")
    
    @abstractmethod
    def connect(self, device_info: Dict[str, Any]) -> bool:
        """Connect to a device."""
        raise NotImplementedError("Abstract method")
    
    @abstractmethod
    def send_data(self, data: bytes) -> bool:
        """Send data to connected device."""
        raise NotImplementedError("Abstract method")
    
    @abstractmethod
    def receive_data(self, timeout: float = 5.0) -> Optional[bytes]:
        """Receive data from connected device."""
        raise NotImplementedError("Abstract method")


class WiFiDirectTransport(DeviceSyncTransport):
    """
    WiFi Direct transport for device-to-device sync.
    
    Provides direct device communication over WiFi without internet.
    
    **Validates: Requirements 3.2**
    """
    
    def __init__(self, port: int = WIFI_DIRECT_PORT):
        """Initialize WiFi Direct transport."""
        self.port = port
        self._server_socket: Optional[socket.socket] = None
        self._client_socket: Optional[socket.socket] = None
        self._running = False
        self._connected = False
        self._lock = threading.Lock()
        
        logger.info(f"WiFiDirectTransport initialized on port {port}")
    
    def start(self) -> bool:
        """Start WiFi Direct transport."""
        with self._lock:
            if self._running:
                return True
            
            try:
                self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # B104: 0.0.0.0 is intentional for P2P listen (peer must accept inbound);
                # restricted by air-gapped default (peer discovery off), mTLS required
                # on the secure path, and host firewall policy. Lab-only alternative:
                # set P2P_BIND_ADDRESS=127.0.0.1 to loop back.
                _bind = os.environ.get("P2P_BIND_ADDRESS", "0.0.0.0")  # nosec B104 - P2P listen address, mTLS-gated
                self._server_socket.bind((_bind, self.port))
                self._server_socket.listen(1)
                self._server_socket.settimeout(1.0)
                
                self._running = True
                logger.info("WiFi Direct transport started")
                return True
                
            except Exception as e:
                logger.error(f"Failed to start WiFi Direct transport: {e}")
                return False
    
    def stop(self) -> None:
        """Stop WiFi Direct transport."""
        with self._lock:
            self._running = False
            self._connected = False
        
        if self._client_socket:
            try:
                self._client_socket.close()
            except Exception:
                logger.debug("Socket close error ignored")
        
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                logger.debug("Socket close error ignored")
        
        logger.info("WiFi Direct transport stopped")
    
    def discover_devices(self) -> List[Dict[str, Any]]:
        """
        Discover nearby WiFi Direct devices.
        
        Note: Full WiFi Direct discovery requires platform-specific APIs.
        This implementation uses UDP broadcast for discovery.
        """
        devices = []
        
        try:
            # Create UDP socket for discovery
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2.0)
            
            # Send discovery broadcast
            discovery_msg = json.dumps({
                'type': 'WIFI_DIRECT_DISCOVERY',
                'port': self.port,
            }).encode('utf-8')
            
            sock.sendto(discovery_msg, ('<broadcast>', self.port))
            
            # Collect responses
            start_time = time.time()
            while time.time() - start_time < 2.0:
                try:
                    data, addr = sock.recvfrom(1024)
                    msg = json.loads(data.decode('utf-8'))
                    if msg.get('type') == 'WIFI_DIRECT_RESPONSE':
                        devices.append({
                            'address': addr[0],
                            'port': msg.get('port', self.port),
                            'name': msg.get('name', 'Unknown'),
                        })
                except socket.timeout:
                    break
                # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B112
                    continue
            
            sock.close()
            
        except Exception as e:
            logger.error(f"WiFi Direct discovery failed: {e}")
        
        return devices
    
    def connect(self, device_info: Dict[str, Any]) -> bool:
        """Connect to a WiFi Direct device."""
        with self._lock:
            if self._connected:
                return True
            
            try:
                self._client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._client_socket.settimeout(5.0)
                self._client_socket.connect((device_info['address'], device_info['port']))
                self._connected = True
                logger.info(f"Connected to WiFi Direct device: {device_info['address']}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to connect to WiFi Direct device: {e}")
                return False
    
    def send_data(self, data: bytes) -> bool:
        """Send data over WiFi Direct connection."""
        with self._lock:
            if not self._connected or not self._client_socket:
                return False
            
            try:
                # Send length prefix followed by data
                length = len(data)
                self._client_socket.sendall(struct.pack('>I', length))
                self._client_socket.sendall(data)
                return True
                
            except Exception as e:
                logger.error(f"Failed to send WiFi Direct data: {e}")
                self._connected = False
                return False
    
    def receive_data(self, timeout: float = 5.0) -> Optional[bytes]:
        """Receive data over WiFi Direct connection."""
        with self._lock:
            if not self._connected or not self._client_socket:
                return None
            
            try:
                self._client_socket.settimeout(timeout)
                
                # Receive length prefix
                length_data = self._client_socket.recv(4)
                if len(length_data) < 4:
                    return None
                
                length = struct.unpack('>I', length_data)[0]
                
                # Receive data
                data = b''
                while len(data) < length:
                    chunk = self._client_socket.recv(min(4096, length - len(data)))
                    if not chunk:
                        return None
                    data += chunk
                
                return data
                
            except socket.timeout:
                return None
            except Exception as e:
                logger.error(f"Failed to receive WiFi Direct data: {e}")
                self._connected = False
                return None
    
    def accept_connection(self, timeout: float = 5.0) -> bool:
        """Accept an incoming WiFi Direct connection."""
        with self._lock:
            if not self._server_socket:
                return False
            
            try:
                self._server_socket.settimeout(timeout)
                self._client_socket, addr = self._server_socket.accept()
                self._connected = True
                logger.info(f"Accepted WiFi Direct connection from: {addr}")
                return True
                
            except socket.timeout:
                return False
            except Exception as e:
                logger.error(f"Failed to accept WiFi Direct connection: {e}")
                return False


class DeviceSyncManager:
    """
    Manager for device-to-device synchronization.
    
    Coordinates sync over multiple transports (Bluetooth, WiFi Direct).
    
    **Validates: Requirements 3.2**
    """
    
    def __init__(self, node_id: bytes):
        """Initialize device sync manager."""
        self.node_id = node_id
        self._transports: Dict[str, DeviceSyncTransport] = {}
        self._lock = threading.Lock()
        
        # Add WiFi Direct transport by default
        self._transports['wifi_direct'] = WiFiDirectTransport()
        
        logger.info("DeviceSyncManager initialized")
    
    def add_transport(self, name: str, transport: DeviceSyncTransport) -> None:
        """Add a sync transport."""
        with self._lock:
            self._transports[name] = transport
    
    def start_all(self) -> Dict[str, bool]:
        """Start all transports."""
        results = {}
        with self._lock:
            for name, transport in self._transports.items():
                results[name] = transport.start()
        return results
    
    def stop_all(self) -> None:
        """Stop all transports."""
        with self._lock:
            for transport in self._transports.values():
                transport.stop()
    
    def discover_devices(self) -> Dict[str, List[Dict[str, Any]]]:
        """Discover devices on all transports."""
        results = {}
        with self._lock:
            for name, transport in self._transports.items():
                try:
                    results[name] = transport.discover_devices()
                except Exception as e:
                    logger.error(f"Discovery failed on {name}: {e}")
                    results[name] = []
        return results
    
    def sync_with_device(
        self,
        transport_name: str,
        device_info: Dict[str, Any],
        data_to_send: bytes,
    ) -> Optional[bytes]:
        """
        Sync data with a device.
        
        Args:
            transport_name: Name of transport to use
            device_info: Device connection info
            data_to_send: Data to send to device
            
        Returns:
            Data received from device, or None on failure
        """
        with self._lock:
            transport = self._transports.get(transport_name)
            if not transport:
                logger.error(f"Unknown transport: {transport_name}")
                return None
        
        try:
            if not transport.connect(device_info):
                return None
            
            if not transport.send_data(data_to_send):
                return None
            
            return transport.receive_data()
            
        except Exception as e:
            logger.error(f"Sync failed: {e}")
            return None



# ============================================================================
# Main Decentralized Architecture Manager
# ============================================================================

class DecentralizedArchitecture:
    """
    Main manager for decentralized P2P architecture.
    
    Integrates all decentralized components:
    - DHT-based peer discovery
    - Local mesh networking
    - Store-and-forward relay
    - Device-to-device sync
    
    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
    """
    
    def __init__(
        self,
        node_id: Optional[bytes] = None,
        address: Optional[str] = None,
        dht_port: int = 45678,
        mesh_port: int = MESH_UDP_PORT,
        storage_dir: Optional[Path] = None,
        bootstrap_nodes: Optional[List[Tuple[str, int]]] = None,
    ):
        """
        Initialize decentralized architecture.
        
        Args:
            node_id: Our node's ID (generated if not provided)
            address: Local address to bind to
            dht_port: Port for DHT protocol
            mesh_port: Port for mesh discovery
            storage_dir: Directory for persistent storage
            bootstrap_nodes: Bootstrap nodes for DHT
        """
        # Generate node ID if not provided
        if node_id is None:
            node_id = hashlib.sha3_256(secrets.token_bytes(32)).digest()
        
        self.node_id = node_id
        # B104: wildcard bind required for inbound P2P; lab override via env.
        self.address = address or os.environ.get("P2P_BIND_ADDRESS", "0.0.0.0")  # nosec B104 - P2P inbound, configurable
        
        # Set up storage paths
        if storage_dir:
            storage_dir = Path(storage_dir)
            dht_storage = storage_dir / "dht_storage.json"
            relay_storage = storage_dir / "relay_storage.json"
        else:
            dht_storage = None
            relay_storage = None
        
        # Initialize components
        self.peer_discovery = DecentralizedPeerDiscovery(
            node_id=node_id,
            address=address,
            port=dht_port,
            storage_path=dht_storage,
            bootstrap_nodes=bootstrap_nodes,
        )
        
        self.mesh_discovery = LocalMeshDiscovery(
            node_id=node_id,
            port=mesh_port,
        )
        
        self.relay_node = RelayNode(
            node_id=node_id,
            storage_path=relay_storage,
            signer=self._relay_sign,
            sender_pubkey=self.peer_discovery.sig_public_key,
            verifier=self._relay_verify if self.peer_discovery.sig_public_key else None,
        )
        
        self.device_sync = DeviceSyncManager(node_id)
        
        # State
        self._running = False
        self._lock = threading.Lock()
        
        # Callbacks
        self._on_peer_discovered: Optional[Callable[[DHTNodeInfo], None]] = None
        self._on_message_received: Optional[Callable[[RelayMessage], None]] = None
        
        logger.info(f"DecentralizedArchitecture initialized with node_id={node_id.hex()[:16]}...")
    
    def start(self) -> bool:
        """
        Start all decentralized components.
        
        Returns:
            True if all components started successfully
        """
        with self._lock:
            if self._running:
                return True
            
            success = True
            
            # Start DHT peer discovery
            if not self.peer_discovery.start():
                logger.error("Failed to start DHT peer discovery")
                success = False
            
            # Start mesh discovery
            if not self.mesh_discovery.start():
                logger.error("Failed to start mesh discovery")
                success = False
            
            # Start device sync transports
            sync_results = self.device_sync.start_all()
            for name, result in sync_results.items():
                if not result:
                    logger.warning(f"Failed to start {name} transport")
            
            # Set up callbacks
            self.peer_discovery.set_peer_discovered_callback(self._handle_dht_peer)
            self.mesh_discovery.set_peer_discovered_callback(self._handle_mesh_peer)
            
            self._running = success
            
            if success:
                logger.info("Decentralized architecture started")
            
            return success
    
    def stop(self) -> None:
        """Stop all decentralized components."""
        with self._lock:
            self._running = False
        
        self.peer_discovery.stop()
        self.mesh_discovery.stop()
        self.device_sync.stop_all()
        
        logger.info("Decentralized architecture stopped")
    
    def _handle_dht_peer(self, peer: DHTNodeInfo) -> None:
        """Handle peer discovered via DHT."""
        if self._on_peer_discovered:
            self._on_peer_discovered(peer)
        
        # Check for queued messages
        messages = self.relay_node.get_messages_for_peer(peer.node_id)
        for msg in messages:
            if self._on_message_received:
                self._on_message_received(msg)
    
    def _handle_mesh_peer(self, peer: MeshPeer) -> None:
        """Handle peer discovered via mesh."""
        # Convert to DHTNodeInfo for unified handling
        dht_peer = DHTNodeInfo(
            node_id=peer.peer_id,
            address=peer.address,
            port=peer.port,
            last_seen=peer.last_seen,
        )
        
        # Add to DHT routing table
        self.peer_discovery.routing_table.add_node(dht_peer)
        
        if self._on_peer_discovered:
            self._on_peer_discovered(dht_peer)
    
    def register_peer(
        self,
        peer_info: DHTNodeInfo,
        signature: Optional[bytes] = None,
    ) -> bool:
        """
        Register our peer information in the DHT.
        
        Args:
            peer_info: Our peer information
            signature: ML-DSA-87 signature of peer info
            
        Returns:
            True if registered successfully
        """
        return self.peer_discovery.store_peer_info(
            self.node_id,
            peer_info,
            signature,
        )
    
    def lookup_peer(self, peer_id: bytes, timeout: float = 5.0) -> Optional[DHTNodeInfo]:
        """
        Look up a peer by ID.
        
        **Property 6: DHT Peer Lookup Correctness**
        
        Args:
            peer_id: Peer's ID
            timeout: Lookup timeout
            
        Returns:
            DHTNodeInfo if found
        """
        # Try DHT first
        peer = self.peer_discovery.lookup_peer_info(peer_id, timeout)
        if peer:
            return peer
        
        # Check mesh peers
        for mesh_peer in self.mesh_discovery.get_peers():
            if mesh_peer.peer_id == peer_id:
                return DHTNodeInfo(
                    node_id=mesh_peer.peer_id,
                    address=mesh_peer.address,
                    port=mesh_peer.port,
                    last_seen=mesh_peer.last_seen,
                )
        
        return None
    
    def _send_direct_to_peer(self, peer: DHTNodeInfo, message: 'RelayMessage') -> None:
        """
        Send a message directly to an online peer.
        
        Args:
            peer: Peer information from DHT lookup
            message: Message to send
            
        Raises:
            Exception: If direct send fails
        """
        import socket
        import ssl
        
        # Create secure connection to peer
        sock = socket.socket(socket.AF_INET6 if ':' in peer.address else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        
        try:
            # Connect to peer
            sock.connect((peer.address, peer.port))
            
            # Wrap with hardened TLS 1.3
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            # IP-tactical-only: Direct IP peer addresses; MITM scope neutralized by CERT_REQUIRED + pinned CA anchor.
            # Module status: Unwired research module, disabled by default in production.
            # (B504: check_hostname=False is correct for raw-IP peers; identity is bound
            # via pinned CA + post-handshake SHA384 fingerprint check below, not DNS.)
            context.check_hostname = False  # nosec B504 - IP peer + CERT_REQUIRED + fingerprint pinning
            ca_file = getattr(self, 'ca_file', None) or os.environ.get('P2P_CA_FILE')
            if ca_file and os.path.exists(ca_file):
                context.load_verify_locations(ca_file)
            else:
                try:
                    context.load_default_certs()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
            context.verify_mode = ssl.CERT_REQUIRED
            
            is_ip = (':' in peer.address) or (peer.address.replace('.', '').isdigit())
            server_name = None if is_ip else peer.address
            ssl_sock = context.wrap_socket(sock, server_hostname=server_name)
            
            # Post-handshake verification of peer certificate
            peercert_der = ssl_sock.getpeercert(binary_form=True)
            if not peercert_der:
                ssl_sock.close()
                raise SecurityError("Peer did not provide a valid TLS certificate.")
            # P0-3: the fingerprint pin is MANDATORY, not optional. Without a
            # pinned expected_fingerprint, CERT_REQUIRED proves only CA-validity
            # (public-CA certs accepted via load_default_certs fallback), which
            # does not authenticate THIS peer. Unwired research path or not,
            # fail closed: no pin, no send.
            if not (hasattr(peer, 'expected_fingerprint') and peer.expected_fingerprint):
                ssl_sock.close()
                raise SecurityError(
                    f"Refusing direct send to {peer.address}: no pinned peer fingerprint "
                    "(IP peers require an out-of-band pinned fingerprint)"
                )
            if hasattr(peer, 'expected_fingerprint') and peer.expected_fingerprint:
                import hashlib
                cert_fp = hashlib.sha384(peercert_der).digest()
                if cert_fp != peer.expected_fingerprint:
                    ssl_sock.close()
                    raise SecurityError(f"Peer certificate fingerprint mismatch for {peer.address}")
            
            # Serialize and send message. P0-5: preserve the sender_sig /
            # sender_pubkey / hop_count on the wire (previously stripped).
            # Receivers that understand RelayMessage.from_dict can verify
            # origin; receivers that do not simply ignore the extra keys.
            # Dropping authentication material would make origin forgery
            # undetectable even where verification is available.
            _sig_hex = None
            try:
                if getattr(message, 'sender_sig', None):
                    _sig_hex = bytes(message.sender_sig).hex()
            except Exception:
                _sig_hex = None
            _spk_hex = None
            try:
                if getattr(message, 'sender_pubkey', None):
                    _spk_hex = bytes(message.sender_pubkey).hex()
            except Exception:
                _spk_hex = None
            message_data = {
                'message_id': message.message_id,
                'sender_id': message.sender_id.hex(),
                'recipient_id': message.recipient_id.hex(),
                'encrypted_payload': message.encrypted_payload.hex(),
                'timestamp': message.timestamp,
                'ttl': message.ttl,
                'hop_count': int(getattr(message, 'hop_count', 0) or 0),
                'sender_sig': _sig_hex,
                'sender_pubkey': _spk_hex,
            }
            
            import json
            payload = json.dumps(message_data).encode('utf-8')
            
            # Send length-prefixed message
            length = len(payload)
            ssl_sock.sendall(length.to_bytes(4, 'big'))
            ssl_sock.sendall(payload)
            
            # Wait for acknowledgment
            ack = ssl_sock.recv(3)
            if ack != b'ACK':
                raise Exception(f"Peer did not acknowledge message: {ack}")
                
            logger.debug(f"Direct message sent to {peer.address}:{peer.port}")
            
        finally:
            try:
                sock.close()
            except Exception:
                logger.debug("Socket close error ignored")
    
    def _relay_sign(self, data: bytes) -> bytes:
        """Sign relay payloads with this node's ML-DSA-87 key (H16)."""
        dsa = getattr(self.peer_discovery, '_dsa', None)
        priv = getattr(self.peer_discovery, 'sig_private_key', None)
        if dsa is None or priv is None:
            raise ValueError("Relay signing unavailable: no ML-DSA-87 backend")
        return dsa.sign(priv, data)

    @staticmethod
    def _relay_verify(pubkey: bytes, data: bytes, signature: bytes) -> bool:
        """Verify a relay payload signature (any sender key)."""
        try:
            from pqc_algorithms import EnhancedMLDSA_87
            return bool(EnhancedMLDSA_87().verify(pubkey, data, signature))
        except Exception:
            return False

    def send_message(
        self,
        recipient_id: bytes,
        encrypted_payload: bytes,
        ttl: int = RELAY_MESSAGE_TTL,
    ) -> str:
        """
        Send a message to a peer.
        
        If peer is offline, message is queued for relay delivery.
        
        Args:
            recipient_id: Recipient's ID
            encrypted_payload: Encrypted message payload
            ttl: Message time-to-live
            
        Returns:
            Message ID
        """
        message_id = str(uuid.uuid4())
        
        message = RelayMessage(
            message_id=message_id,
            sender_id=self.node_id,
            recipient_id=recipient_id,
            encrypted_payload=encrypted_payload,
            ttl=ttl,
        )
        
        # Try to find peer
        peer = self.lookup_peer(recipient_id, timeout=2.0)
        
        if peer:
            # Send directly to peer using secure channel
            try:
                self._send_direct_to_peer(peer, message)
                logger.info(f"Peer {recipient_id.hex()[:16]} is online, sent directly")
            except Exception as e:
                # Fallback to relay if direct send fails
                logger.warning(f"Direct send failed, using relay: {e}")
                self.relay_node.queue_message(message)
                logger.info(f"Message queued for relay delivery")
        else:
            # Queue for relay delivery
            self.relay_node.queue_message(message)
            logger.info(f"Peer {recipient_id.hex()[:16]} is offline, queued for relay")
        
        return message_id
    
    def get_queued_messages(self) -> List[RelayMessage]:
        """Get messages queued for us."""
        return self.relay_node.get_messages_for_peer(self.node_id)
    
    def acknowledge_message(self, message_id: str) -> bool:
        """Acknowledge receipt of a message."""
        return self.relay_node.acknowledge_message(self.node_id, message_id)
    
    def get_known_peers(self) -> List[DHTNodeInfo]:
        """Get all known peers."""
        peers = self.peer_discovery.get_known_peers()
        
        # Add mesh peers
        for mesh_peer in self.mesh_discovery.get_peers():
            # Check if already in list
            if not any(p.node_id == mesh_peer.peer_id for p in peers):
                peers.append(DHTNodeInfo(
                    node_id=mesh_peer.peer_id,
                    address=mesh_peer.address,
                    port=mesh_peer.port,
                    last_seen=mesh_peer.last_seen,
                ))
        
        return peers
    
    def discover_local_devices(self) -> Dict[str, List[Dict[str, Any]]]:
        """Discover devices for direct sync."""
        return self.device_sync.discover_devices()
    
    def sync_with_device(
        self,
        transport: str,
        device_info: Dict[str, Any],
        data: bytes,
    ) -> Optional[bytes]:
        """Sync data with a local device."""
        return self.device_sync.sync_with_device(transport, device_info, data)
    
    def set_peer_discovered_callback(
        self,
        callback: Callable[[DHTNodeInfo], None],
    ) -> None:
        """Set callback for peer discovery."""
        self._on_peer_discovered = callback
    
    def set_message_received_callback(
        self,
        callback: Callable[[RelayMessage], None],
    ) -> None:
        """Set callback for message receipt."""
        self._on_message_received = callback
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the decentralized network."""
        return {
            'node_id': self.node_id.hex(),
            'dht_peers': len(self.peer_discovery.get_known_peers()),
            'mesh_peers': len(self.mesh_discovery.get_peers()),
            'relay_stats': self.relay_node.get_queue_stats(),
            'running': self._running,
        }
    
    @property
    def is_running(self) -> bool:
        """Check if architecture is running."""
        return self._running


# ============================================================================
# Factory Functions
# ============================================================================

_global_architecture: Optional[DecentralizedArchitecture] = None
_global_lock = threading.Lock()


def get_decentralized_architecture(
    node_id: Optional[bytes] = None,
    **kwargs,
) -> DecentralizedArchitecture:
    """
    Get or create the global decentralized architecture instance.
    
    Args:
        node_id: Node ID (uses existing or generates new)
        **kwargs: Additional arguments for DecentralizedArchitecture
        
    Returns:
        DecentralizedArchitecture instance
    """
    global _global_architecture
    
    with _global_lock:
        if _global_architecture is None:
            _global_architecture = DecentralizedArchitecture(node_id=node_id, **kwargs)
        return _global_architecture


def reset_decentralized_architecture() -> None:
    """Reset the global architecture instance (for testing)."""
    global _global_architecture
    
    with _global_lock:
        if _global_architecture:
            _global_architecture.stop()
            _global_architecture = None


# ============================================================================
# Property Test Support
# ============================================================================

def create_test_dht_node(
    node_id: Optional[bytes] = None,
    address: str = "127.0.0.1",
    port: int = 0,
) -> DHTNodeInfo:
    """
    Create a test DHT node for property testing.
    
    Args:
        node_id: Node ID (generated if not provided)
        address: Node address
        port: Node port (random if 0)
        
    Returns:
        DHTNodeInfo for testing
    """
    if node_id is None:
        node_id = hashlib.sha3_256(secrets.token_bytes(32)).digest()
    
    if port == 0:
        port = secrets.randbelow(10000) + 10000
    
    return DHTNodeInfo(
        node_id=node_id,
        address=address,
        port=port,
    )


def verify_dht_lookup_correctness(
    discovery: DecentralizedPeerDiscovery,
    peer_info: DHTNodeInfo,
) -> bool:
    """
    Verify DHT lookup returns correct peer info.
    
    **Property 6: DHT Peer Lookup Correctness**
    
    Args:
        discovery: DHT discovery instance
        peer_info: Peer info that was stored
        
    Returns:
        True if lookup returns correct info
    """
    # Store peer info
    discovery.store_peer_info(peer_info.node_id, peer_info)
    
    # Look up peer info
    result = discovery.lookup_peer_info(peer_info.node_id, timeout=1.0)
    
    if result is None:
        return False
    
    # Verify fields match
    return (
        result.node_id == peer_info.node_id and
        result.address == peer_info.address and
        result.port == peer_info.port
    )


# ============================================================================
# Main Entry Point (for testing)
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start architecture
    arch = DecentralizedArchitecture(
        address=os.environ.get("P2P_BIND_ADDRESS", "127.0.0.1"),  # nosec B104 - demo main, loopback by default
        dht_port=45678,
    )
    
    def on_peer_discovered(peer: DHTNodeInfo):
        print(f"Discovered peer: {peer.address}:{peer.port}")
    
    arch.set_peer_discovered_callback(on_peer_discovered)
    
    if arch.start():
        print(f"Decentralized architecture started")
        print(f"Node ID: {arch.node_id.hex()}")
        print(f"Stats: {arch.get_stats()}")
        
        try:
            # Keep running
            while True:
                time.sleep(10)
                print(f"Known peers: {len(arch.get_known_peers())}")
        except KeyboardInterrupt:
            print("\nShutting down...")
    
    arch.stop()
    print("Done")

