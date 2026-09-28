"""
Enhanced Peer Management System

This module provides comprehensive peer management capabilities for the secure P2P chat system,
including peer organization, search, groups, favorites, connection history, and statistics.

Features:
- Enhanced peer organization with groups and favorites
- Advanced search and filtering capabilities
- Connection history and statistics tracking
- Improved error handling and status feedback
- Better P2P Discovery Service integration with caching and offline support
- Connection quality monitoring and analytics

Author: Secure Communications Team
License: MIT
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import secrets
import os

from air_gapped_operation import (
    ENC_STORAGE_MAGIC,
    encrypt_storage_payload,
    decrypt_storage_payload,
    set_secure_file_permissions,
)

# Import existing database integration
try:
    from core import (
        initialize_secure_system,
        get_user_endpoint_by_user_id,
        get_user_endpoint_by_display_name,
        shutdown_secure_system,
    )
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False
    # Stub functions for offline mode
    async def initialize_secure_system():
        raise RuntimeError('Database integration required. Mock offline mode forbidden.')
    
    async def get_user_endpoint_by_user_id(user_id: str):
        raise RuntimeError('Database integration required. Mock offline mode forbidden.')
    
    async def get_user_endpoint_by_display_name(display_name: str):
        raise RuntimeError('Database integration required. Mock offline mode forbidden.')
    
    async def shutdown_secure_system():
        raise RuntimeError('Database integration required. Mock offline mode forbidden.')

# Setup logging
logger = logging.getLogger(__name__)

class ConnectionStatus(Enum):
    """Connection status enumeration."""
    NEVER_CONNECTED = "never_connected"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    FAILED = "failed"
    BLOCKED = "blocked"

class PeerGroup(Enum):
    """Predefined peer groups."""
    FAVORITES = "favorites"
    WORK = "work"
    FRIENDS = "friends"
    FAMILY = "family"
    BLOCKED = "blocked"
    RECENT = "recent"
    CUSTOM = "custom"

@dataclass
class ConnectionStats:
    """Connection statistics for a peer."""
    total_connections: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    total_messages_sent: int = 0
    total_messages_received: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    average_response_time: float = 0.0
    last_response_time: float = 0.0
    connection_quality_score: float = 0.0
    uptime_percentage: float = 0.0

@dataclass
class PeerInfo:
    """Enhanced peer information structure."""
    username: str
    display_name: str
    ipv6_address: str
    port: int
    user_id: Optional[str] = None
    
    # Connection information
    status: ConnectionStatus = ConnectionStatus.NEVER_CONNECTED
    last_connected: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    first_connected: Optional[datetime] = None
    
    # Organization
    groups: Set[str] = None
    is_favorite: bool = False
    is_blocked: bool = False
    custom_tags: Set[str] = None
    notes: str = ""
    
    # Statistics
    stats: ConnectionStats = None
    
    # Caching and discovery
    source: str = "local"  # local, discovery_service, manual
    cache_timestamp: Optional[datetime] = None
    discovery_attempts: int = 0
    last_discovery_attempt: Optional[datetime] = None
    
    # Security
    public_key: Optional[str] = None
    key_fingerprint: Optional[str] = None
    trust_level: str = "unknown"  # unknown, low, medium, high, verified
    
    def __post_init__(self):
        """Initialize default values after dataclass creation."""
        if self.groups is None:
            self.groups = set()
        if self.custom_tags is None:
            self.custom_tags = set()
        if self.stats is None:
            self.stats = ConnectionStats()
        if self.first_connected is None and self.last_connected:
            self.first_connected = self.last_connected

class EnhancedPeerManager:
    """
    Enhanced peer management system with advanced features.
    
    This class provides comprehensive peer management capabilities including:
    - Peer organization with groups and favorites
    - Advanced search and filtering
    - Connection history and statistics
    - Improved error handling and status feedback
    - Better P2P Discovery Service integration
    - Offline support with intelligent caching
    """
    
    def __init__(self, data_dir: str = "."):
        """Initialize the enhanced peer manager."""
        self.data_dir = Path(data_dir)
        self.peers_file = self.data_dir / "enhanced_peer_connections.json"
        self.cache_file = self.data_dir / "peer_discovery_cache.json"
        self.stats_file = self.data_dir / "peer_statistics.json"
        
        # In-memory storage
        self.peers: Dict[str, PeerInfo] = {}
        self.discovery_cache: Dict[str, Dict] = {}
        self.groups: Dict[str, Set[str]] = {}
        
        # Discovery service state
        self.discovery_initialized = False
        self.discovery_available = DATABASE_AVAILABLE
        
        # Configuration
        self.cache_ttl = timedelta(hours=24)  # Cache TTL for discovery results
        self.max_discovery_attempts = 3
        self.discovery_retry_delay = timedelta(minutes=5)
        
        # Load existing data
        self.load_all_data()
        
        # Initialize default groups
        self._initialize_default_groups()
    
    def _initialize_default_groups(self):
        """Initialize default peer groups."""
        for group in PeerGroup:
            if group.value not in self.groups:
                self.groups[group.value] = set()
    
    def load_all_data(self):
        """Load all peer data from storage files."""
        self._load_peers()
        self._load_discovery_cache()
        self._load_groups()
    
    def _load_peers(self):
        """Load peer connections from storage with AES-256-GCM decryption (Finding 6)."""
        if self.peers_file.exists():
            if os.environ.get("P2P_IN_MEMORY_STORAGE", "0") == "1":
                return
            try:
                with open(self.peers_file, 'rb') as f:
                    payload = f.read()

                data = decrypt_storage_payload(payload)
                
                # Convert old format to new format if needed
                for username, peer_data in data.items():
                    if isinstance(peer_data, dict):
                        # Handle old format
                        if 'stats' not in peer_data:
                            peer_data['stats'] = asdict(ConnectionStats())
                        if 'groups' not in peer_data:
                            peer_data['groups'] = []
                        if 'custom_tags' not in peer_data:
                            peer_data['custom_tags'] = []
                        
                        # Convert datetime strings
                        for date_field in ['last_connected', 'last_seen', 'first_connected', 'cache_timestamp', 'last_discovery_attempt']:
                            if date_field in peer_data and peer_data[date_field]:
                                try:
                                    peer_data[date_field] = datetime.fromisoformat(peer_data[date_field])
                                except (ValueError, TypeError):
                                    peer_data[date_field] = None
                        
                        # Convert sets
                        peer_data['groups'] = set(peer_data.get('groups', []))
                        peer_data['custom_tags'] = set(peer_data.get('custom_tags', []))
                        
                        # Convert stats
                        stats_data = peer_data.get('stats', {})
                        peer_data['stats'] = ConnectionStats(**stats_data)
                        
                        # Convert status
                        status_str = peer_data.get('status', 'never_connected')
                        try:
                            peer_data['status'] = ConnectionStatus(status_str)
                        except ValueError:
                            peer_data['status'] = ConnectionStatus.NEVER_CONNECTED
                        
                        # Create PeerInfo object
                        self.peers[username] = PeerInfo(**peer_data)
                
                logger.info(f"Loaded {len(self.peers)} peers from storage")

                # Re-encrypt if loaded from legacy plaintext
                if not payload.startswith(ENC_STORAGE_MAGIC):
                    self._save_peers()

            except Exception as e:
                logger.error(f"Error loading peers: {e}")
                self.peers = {}
    
    def _load_discovery_cache(self):
        """Load discovery service cache with AES-256-GCM decryption (Finding 6)."""
        if self.cache_file.exists():
            if os.environ.get("P2P_IN_MEMORY_STORAGE", "0") == "1":
                return
            try:
                with open(self.cache_file, 'rb') as f:
                    payload = f.read()

                self.discovery_cache = decrypt_storage_payload(payload)
                logger.info(f"Loaded {len(self.discovery_cache)} cached discovery entries")

                if not payload.startswith(ENC_STORAGE_MAGIC):
                    self._save_discovery_cache()

            except Exception as e:
                logger.error(f"Error loading discovery cache: {e}")
                self.discovery_cache = {}
    
    def _load_groups(self):
        """Load peer groups from peer data."""
        self.groups = {group.value: set() for group in PeerGroup}
        
        for username, peer in self.peers.items():
            for group in peer.groups:
                if group not in self.groups:
                    self.groups[group] = set()
                self.groups[group].add(username)
            
            # Add to special groups
            if peer.is_favorite:
                self.groups[PeerGroup.FAVORITES.value].add(username)
            if peer.is_blocked:
                self.groups[PeerGroup.BLOCKED.value].add(username)
    
    def save_all_data(self):
        """Save all peer data to storage files."""
        self._save_peers()
        self._save_discovery_cache()
    
    def _save_peers(self):
        """Save peer connections to storage encrypted with AES-256-GCM (Finding 6)."""
        if os.environ.get("P2P_IN_MEMORY_STORAGE", "0") == "1":
            return
        try:
            # Ensure data directory exists
            self.data_dir.mkdir(parents=True, exist_ok=True)
            
            # Convert PeerInfo objects to serializable format
            data = {}
            for username, peer in self.peers.items():
                peer_dict = asdict(peer)
                
                # Convert datetime objects to ISO strings
                for date_field in ['last_connected', 'last_seen', 'first_connected', 'cache_timestamp', 'last_discovery_attempt']:
                    if peer_dict[date_field]:
                        peer_dict[date_field] = peer_dict[date_field].isoformat()
                
                # Convert sets to lists
                peer_dict['groups'] = list(peer_dict['groups'])
                peer_dict['custom_tags'] = list(peer_dict['custom_tags'])
                
                # Convert enum to string
                peer_dict['status'] = peer_dict['status'].value
                
                data[username] = peer_dict
            
            encrypted_payload = encrypt_storage_payload(data)
            with open(self.peers_file, 'wb') as f:
                f.write(encrypted_payload)
            
            set_secure_file_permissions(self.peers_file)
            logger.debug(f"Saved {len(self.peers)} peers to storage")
        except Exception as e:
            logger.error(f"Error saving peers: {e}")
    
    def _save_discovery_cache(self):
        """Save discovery service cache encrypted with AES-256-GCM (Finding 6)."""
        if os.environ.get("P2P_IN_MEMORY_STORAGE", "0") == "1":
            return
        try:
            # Ensure data directory exists
            self.data_dir.mkdir(parents=True, exist_ok=True)
            
            encrypted_payload = encrypt_storage_payload(self.discovery_cache)
            with open(self.cache_file, 'wb') as f:
                f.write(encrypted_payload)

            set_secure_file_permissions(self.cache_file)
            logger.debug(f"Saved {len(self.discovery_cache)} cached discovery entries")
        except Exception as e:
            logger.error(f"Error saving discovery cache: {e}")
    
    async def ensure_discovery_service(self) -> bool:
        """Ensure P2P Discovery Service is properly initialized."""
        if not self.discovery_available:
            return False
        
        if not self.discovery_initialized:
            try:
                result = await initialize_secure_system()
                
                # Handle both bool and dict return types
                if isinstance(result, bool):
                    success = result
                else:
                    success = result.get('success', False)
                
                if success:
                    self.discovery_initialized = True
                    logger.info("P2P Discovery Service initialized successfully")
                else:
                    error_msg = result.get('message', 'Unknown error') if isinstance(result, dict) else 'Initialization failed'
                    logger.warning(f"P2P Discovery Service initialization failed: {error_msg}")
                    return False
            except Exception as e:
                logger.error(f"P2P Discovery Service initialization error: {e}")
                return False
        
        return self.discovery_initialized
    
    async def lookup_peer_by_username(self, username: str, force_refresh: bool = False) -> Optional[PeerInfo]:
        """
        Enhanced peer lookup with caching and improved error handling.
        
        Args:
            username: Username to lookup
            force_refresh: Force refresh from discovery service
            
        Returns:
            PeerInfo object if found, None otherwise
        """
        # Check local cache first (unless force refresh)
        if not force_refresh and username in self.peers:
            peer = self.peers[username]
            # Check if cache is still valid
            if (peer.cache_timestamp and 
                datetime.now() - peer.cache_timestamp < self.cache_ttl):
                logger.debug(f"Using cached peer data for '{username}'")
                return peer
        
        # Try discovery service lookup
        discovery_result = await self._lookup_from_discovery_service(username)
        if discovery_result:
            return discovery_result
        
        # Fallback to local storage
        return self.peers.get(username)
    
    async def _lookup_from_discovery_service(self, username: str) -> Optional[PeerInfo]:
        """Lookup peer from P2P Discovery Service with enhanced error handling."""
        if not await self.ensure_discovery_service():
            logger.debug("Discovery service not available for peer lookup")
            return None
        
        # Check if we should attempt discovery (rate limiting)
        if username in self.peers:
            peer = self.peers[username]
            if (peer.discovery_attempts >= self.max_discovery_attempts and
                peer.last_discovery_attempt and
                datetime.now() - peer.last_discovery_attempt < self.discovery_retry_delay):
                logger.debug(f"Rate limiting discovery attempts for '{username}'")
                return None
        
        try:
            logger.info(f"Looking up peer '{username}' in P2P Discovery Service...")
            
            # Direct lookup by exact display_name (case variations removed to prevent spoofing)
            result = await get_user_endpoint_by_display_name(username)
            if result.get('success'):
                peer_info = self._create_peer_from_discovery_result(username, result)
                if peer_info and self._update_peer_from_discovery(peer_info):
                    logger.info(f"Found peer '{username}' at [{peer_info.ipv6_address}]:{peer_info.port}")
                    return peer_info
            
            # Try lookup by user_id if available locally
            if username in self.peers and self.peers[username].user_id:
                user_id = self.peers[username].user_id
                logger.debug(f"Trying lookup by user_id: {user_id}")
                result = await get_user_endpoint_by_user_id(user_id)
                if result.get('success'):
                    peer_info = self._create_peer_from_discovery_result(username, result)
                    if peer_info and self._update_peer_from_discovery(peer_info):
                        logger.info(f"Found peer '{username}' via user_id at [{peer_info.ipv6_address}]:{peer_info.port}")
                        return peer_info
            
            # Update discovery attempt tracking
            self._update_discovery_attempt(username, False)
            logger.info(f"Peer '{username}' not found in P2P Discovery Service")
            return None
            
        except Exception as e:
            logger.error(f"P2P Discovery Service lookup error for '{username}': {e}")
            self._update_discovery_attempt(username, False)
            return None
    
    def _check_peer_key_continuity(self, username: str, new_fingerprint: Optional[str]) -> bool:
        """
        Verify key continuity (TOFU protection).
        If peer is known and has a recorded fingerprint, the new fingerprint MUST match.
        Supports matching full SHA3-512 hex (128 chars) as well as legacy SHA3-256 (64 chars) or UI truncated pins.
        """
        if not new_fingerprint or username not in self.peers:
            return True
        existing_peer = self.peers[username]
        if existing_peer.key_fingerprint:
            stored = existing_peer.key_fingerprint.lower()
            incoming = new_fingerprint.lower()
            is_match = (
                stored == incoming
                or (len(stored) < len(incoming) and incoming.startswith(stored))
                or (len(incoming) < len(stored) and stored.startswith(incoming))
            )
            if not is_match:
                logger.critical(
                    f"SECURITY ALERT: Key continuity violation for peer '{username}'! "
                    f"Stored: {existing_peer.key_fingerprint}, Received: {new_fingerprint}. "
                    "Possible MITM/impersonation attack."
                )
                return False
        return True

    def _create_peer_from_discovery_result(self, username: str, result: Dict) -> Optional[PeerInfo]:
        """Create PeerInfo object from discovery service result after cryptographic validation."""
        # Cryptographic bundle signature verification (fail-closed)
        bundle = result.get('bundle')
        if not bundle or not isinstance(bundle, dict):
            logger.critical(f"SECURITY ALERT: Missing or malformed public key bundle for discovered peer '{username}'! Rejecting unauthenticated peer.")
            return None

        try:
            from anonymous_identity_manager import AnonymousIdentity
            if not AnonymousIdentity.verify_public_bundle(bundle):
                logger.critical(f"SECURITY ALERT: Discovery bundle signature verification failed for '{username}'! Rejecting unauthenticated peer.")
                return None
        except Exception as e:
            logger.error(f"Bundle signature verification error for '{username}': {e}")
            return None

        existing_peer = self.peers.get(username)
        
        raw_pk = result.get('public_key')
        if isinstance(raw_pk, str):
            pk_bytes = raw_pk.encode('utf-8')
        else:
            pk_bytes = raw_pk

        fp = result.get('key_fingerprint')
        if not fp and pk_bytes:
            fp = hashlib.sha3_512(pk_bytes).hexdigest()

        peer_info = PeerInfo(
            username=username,
            display_name=result.get('display_name', username),
            ipv6_address=result.get('public_ip'),
            port=result.get('port'),
            user_id=result.get('user_id'),
            public_key=pk_bytes,
            key_fingerprint=fp,
            source='discovery_service',
            cache_timestamp=datetime.now(),
            last_seen=datetime.now() if result.get('online') else None
        )
        
        # Preserve existing data if available
        if existing_peer:
            peer_info.groups = existing_peer.groups
            peer_info.is_favorite = existing_peer.is_favorite
            peer_info.is_blocked = existing_peer.is_blocked
            peer_info.custom_tags = existing_peer.custom_tags
            peer_info.notes = existing_peer.notes
            peer_info.stats = existing_peer.stats
            peer_info.first_connected = existing_peer.first_connected
            peer_info.public_key = peer_info.public_key or existing_peer.public_key
            peer_info.key_fingerprint = peer_info.key_fingerprint or existing_peer.key_fingerprint
            peer_info.trust_level = existing_peer.trust_level
            
            if existing_peer.last_connected:
                peer_info.last_connected = existing_peer.last_connected
        
        return peer_info
    
    def _update_peer_from_discovery(self, peer_info: Optional[PeerInfo]) -> bool:
        """Update peer in storage after successful discovery with TOFU key continuity check."""
        if not peer_info:
            return False
        if not self._check_peer_key_continuity(peer_info.username, peer_info.key_fingerprint):
            logger.error(f"Refusing to update peer '{peer_info.username}' from discovery due to key mismatch.")
            return False

        self.peers[peer_info.username] = peer_info
        self._update_discovery_attempt(peer_info.username, True)
        self.save_all_data()
        return True
    
    def _update_discovery_attempt(self, username: str, success: bool):
        """Update discovery attempt tracking."""
        if username not in self.peers:
            return
        
        peer = self.peers[username]
        peer.last_discovery_attempt = datetime.now()
        
        if success:
            peer.discovery_attempts = 0
        else:
            peer.discovery_attempts += 1
    
    def add_peer(self, username: str, display_name: str, ipv6: str, port: int, 
                 user_id: str = None, source: str = "manual",
                 public_key: Optional[bytes] = None,
                 key_fingerprint: Optional[str] = None) -> PeerInfo:
        """Add or update peer with enhanced information and cryptographic continuity."""
        if public_key and not key_fingerprint:
            key_fingerprint = hashlib.sha3_512(public_key).hexdigest()

        if not self._check_peer_key_continuity(username, key_fingerprint):
            raise ValueError(f"Key continuity violation for peer '{username}'")

        existing_peer = self.peers.get(username)
        
        if existing_peer:
            # Update existing peer
            existing_peer.display_name = display_name
            existing_peer.ipv6_address = ipv6
            existing_peer.port = port
            if user_id:
                existing_peer.user_id = user_id
            if public_key:
                existing_peer.public_key = public_key
            if key_fingerprint:
                existing_peer.key_fingerprint = key_fingerprint
            existing_peer.source = source
            existing_peer.cache_timestamp = datetime.now()
            peer_info = existing_peer
        else:
            # Create new peer
            peer_info = PeerInfo(
                username=username,
                display_name=display_name,
                ipv6_address=ipv6,
                port=port,
                user_id=user_id,
                public_key=public_key,
                key_fingerprint=key_fingerprint,
                source=source,
                cache_timestamp=datetime.now()
            )
            self.peers[username] = peer_info
        
        self.save_all_data()
        logger.info(f"Added/updated peer '{username}' ({display_name}) at [{ipv6}]:{port}")
        return peer_info
    
    def get_peer(self, username: str) -> Optional[PeerInfo]:
        """Get peer information."""
        return self.peers.get(username)
    
    def remove_peer(self, username: str) -> bool:
        """Remove peer from storage."""
        if username in self.peers:
            # Remove from groups
            for group_peers in self.groups.values():
                group_peers.discard(username)
            
            del self.peers[username]
            self.save_all_data()
            logger.info(f"Removed peer '{username}'")
            return True
        return False
    
    def update_peer_connection(self, username: str, success: bool = True, 
                             response_time: float = None, bytes_sent: int = 0, 
                             bytes_received: int = 0):
        """Update peer connection statistics."""
        if username not in self.peers:
            return
        
        peer = self.peers[username]
        now = datetime.now()
        
        # Update connection info
        if success:
            peer.status = ConnectionStatus.CONNECTED
            peer.last_connected = now
            peer.last_seen = now
            if not peer.first_connected:
                peer.first_connected = now
        else:
            peer.status = ConnectionStatus.FAILED
        
        # Update statistics
        stats = peer.stats
        stats.total_connections += 1
        if success:
            stats.successful_connections += 1
        else:
            stats.failed_connections += 1
        
        if bytes_sent > 0:
            stats.total_bytes_sent += bytes_sent
        if bytes_received > 0:
            stats.total_bytes_received += bytes_received
        
        if response_time is not None:
            stats.last_response_time = response_time
            # Update average response time (simple moving average)
            if stats.average_response_time == 0:
                stats.average_response_time = response_time
            else:
                stats.average_response_time = (stats.average_response_time * 0.8 + response_time * 0.2)
        
        # Calculate connection quality score
        if stats.total_connections > 0:
            success_rate = stats.successful_connections / stats.total_connections
            response_score = max(0, 1 - (stats.average_response_time / 5000))  # 5 second baseline
            stats.connection_quality_score = (success_rate * 0.7 + response_score * 0.3) * 100
        
        # Add to recent group if successful
        if success:
            self.add_peer_to_group(username, PeerGroup.RECENT.value)
        
        self.save_all_data()
    
    def update_message_stats(self, username: str, sent: int = 0, received: int = 0):
        """Update message statistics for a peer."""
        if username not in self.peers:
            return
        
        stats = self.peers[username].stats
        stats.total_messages_sent += sent
        stats.total_messages_received += received
        
        self.save_all_data()
    
    def search_peers(self, query: str, filters: Dict[str, Any] = None) -> List[PeerInfo]:
        """
        Advanced peer search with filtering.
        
        Args:
            query: Search query (searches username, display_name, notes, tags)
            filters: Additional filters (group, status, trust_level, etc.)
            
        Returns:
            List of matching PeerInfo objects
        """
        results = []
        query_lower = query.lower() if query else ""
        
        for peer in self.peers.values():
            # Text search
            if query:
                searchable_text = f"{peer.username} {peer.display_name} {peer.notes}".lower()
                searchable_text += " " + " ".join(peer.custom_tags).lower()
                
                if query_lower not in searchable_text:
                    continue
            
            # Apply filters
            if filters:
                if 'group' in filters and filters['group'] not in peer.groups:
                    continue
                if 'status' in filters and peer.status != filters['status']:
                    continue
                if 'trust_level' in filters and peer.trust_level != filters['trust_level']:
                    continue
                if 'is_favorite' in filters and peer.is_favorite != filters['is_favorite']:
                    continue
                if 'is_blocked' in filters and peer.is_blocked != filters['is_blocked']:
                    continue
                if 'min_quality' in filters and peer.stats.connection_quality_score < filters['min_quality']:
                    continue
            
            results.append(peer)
        
        # Sort by relevance (favorites first, then by connection quality, then by last seen)
        results.sort(key=lambda p: (
            not p.is_favorite,  # Favorites first
            -p.stats.connection_quality_score,  # Higher quality first
            -(p.last_seen.timestamp() if p.last_seen else 0)  # More recent first
        ))
        
        return results
    
    def list_peers(self, sort_by: str = "last_connected", reverse: bool = True) -> List[Tuple[str, PeerInfo]]:
        """List all peers with sorting options."""
        items = list(self.peers.items())
        
        # Define sort key functions
        sort_keys = {
            "last_connected": lambda x: x[1].last_connected.timestamp() if x[1].last_connected else 0,
            "username": lambda x: x[0].lower(),
            "display_name": lambda x: x[1].display_name.lower(),
            "connection_count": lambda x: x[1].stats.total_connections,
            "quality_score": lambda x: x[1].stats.connection_quality_score,
            "last_seen": lambda x: x[1].last_seen.timestamp() if x[1].last_seen else 0,
        }
        
        if sort_by in sort_keys:
            items.sort(key=sort_keys[sort_by], reverse=reverse)
        
        return items
    
    def add_peer_to_group(self, username: str, group: str):
        """Add peer to a group."""
        if username not in self.peers:
            return False
        
        peer = self.peers[username]
        peer.groups.add(group)
        
        if group not in self.groups:
            self.groups[group] = set()
        self.groups[group].add(username)
        
        # Handle special groups
        if group == PeerGroup.FAVORITES.value:
            peer.is_favorite = True
        elif group == PeerGroup.BLOCKED.value:
            peer.is_blocked = True
        
        self.save_all_data()
        return True
    
    def remove_peer_from_group(self, username: str, group: str):
        """Remove peer from a group."""
        if username not in self.peers:
            return False
        
        peer = self.peers[username]
        peer.groups.discard(group)
        
        if group in self.groups:
            self.groups[group].discard(username)
        
        # Handle special groups
        if group == PeerGroup.FAVORITES.value:
            peer.is_favorite = False
        elif group == PeerGroup.BLOCKED.value:
            peer.is_blocked = False
        
        self.save_all_data()
        return True
    
    def get_peers_in_group(self, group: str) -> List[PeerInfo]:
        """Get all peers in a specific group."""
        if group not in self.groups:
            return []
        
        return [self.peers[username] for username in self.groups[group] 
                if username in self.peers]
    
    def get_peer_groups(self, username: str) -> Set[str]:
        """Get all groups a peer belongs to."""
        if username not in self.peers:
            return set()
        return self.peers[username].groups.copy()
    
    def add_custom_tag(self, username: str, tag: str):
        """Add custom tag to peer."""
        if username not in self.peers:
            return False
        
        self.peers[username].custom_tags.add(tag)
        self.save_all_data()
        return True
    
    def remove_custom_tag(self, username: str, tag: str):
        """Remove custom tag from peer."""
        if username not in self.peers:
            return False
        
        self.peers[username].custom_tags.discard(tag)
        self.save_all_data()
        return True
    
    def update_peer_notes(self, username: str, notes: str):
        """Update peer notes."""
        if username not in self.peers:
            return False
        
        self.peers[username].notes = notes
        self.save_all_data()
        return True
    
    def update_peer_trust_level(self, username: str, trust_level: str):
        """Update peer trust level."""
        if username not in self.peers:
            return False
        
        valid_levels = ["unknown", "low", "medium", "high", "verified"]
        if trust_level not in valid_levels:
            return False
        
        self.peers[username].trust_level = trust_level
        self.save_all_data()
        return True
    
    def get_connection_statistics(self) -> Dict[str, Any]:
        """Get overall connection statistics."""
        total_peers = len(self.peers)
        connected_peers = sum(1 for p in self.peers.values() if p.status == ConnectionStatus.CONNECTED)
        favorite_peers = sum(1 for p in self.peers.values() if p.is_favorite)
        blocked_peers = sum(1 for p in self.peers.values() if p.is_blocked)
        
        total_connections = sum(p.stats.total_connections for p in self.peers.values())
        successful_connections = sum(p.stats.successful_connections for p in self.peers.values())
        
        avg_quality = sum(p.stats.connection_quality_score for p in self.peers.values()) / total_peers if total_peers > 0 else 0
        
        return {
            "total_peers": total_peers,
            "connected_peers": connected_peers,
            "favorite_peers": favorite_peers,
            "blocked_peers": blocked_peers,
            "total_connections": total_connections,
            "successful_connections": successful_connections,
            "success_rate": (successful_connections / total_connections * 100) if total_connections > 0 else 0,
            "average_quality_score": avg_quality,
            "groups": {group: len(peers) for group, peers in self.groups.items()},
            "discovery_service_available": self.discovery_available,
            "discovery_service_initialized": self.discovery_initialized
        }
    
    def cleanup_stale_cache(self, max_age: timedelta = None):
        """Clean up stale cache entries."""
        if max_age is None:
            max_age = self.cache_ttl
        
        now = datetime.now()
        stale_peers = []
        
        for username, peer in self.peers.items():
            if (peer.cache_timestamp and 
                now - peer.cache_timestamp > max_age and
                peer.source == 'discovery_service'):
                stale_peers.append(username)
        
        for username in stale_peers:
            logger.debug(f"Removing stale cache entry for '{username}'")
            # Don't remove the peer, just mark cache as stale
            self.peers[username].cache_timestamp = None
        
        if stale_peers:
            self.save_all_data()
        
        return len(stale_peers)
    
    def export_peers(self, format: str = "json") -> str:
        """Export peer data in specified format."""
        if format == "json":
            data = {}
            for username, peer in self.peers.items():
                peer_dict = asdict(peer)
                # Convert datetime objects to ISO strings
                for date_field in ['last_connected', 'last_seen', 'first_connected', 'cache_timestamp', 'last_discovery_attempt']:
                    if peer_dict[date_field]:
                        peer_dict[date_field] = peer_dict[date_field].isoformat()
                # Convert sets to lists
                peer_dict['groups'] = list(peer_dict['groups'])
                peer_dict['custom_tags'] = list(peer_dict['custom_tags'])
                # Convert enum to string
                peer_dict['status'] = peer_dict['status'].value
                data[username] = peer_dict
            
            return json.dumps(data, indent=2, ensure_ascii=False)
        
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'username', 'display_name', 'ipv6_address', 'port', 'user_id',
                'status', 'last_connected', 'is_favorite', 'is_blocked',
                'groups', 'custom_tags', 'notes', 'trust_level',
                'total_connections', 'successful_connections', 'connection_quality_score'
            ])
            
            # Write data
            for username, peer in self.peers.items():
                writer.writerow([
                    peer.username, peer.display_name, peer.ipv6_address, peer.port, peer.user_id,
                    peer.status.value, peer.last_connected.isoformat() if peer.last_connected else '',
                    peer.is_favorite, peer.is_blocked,
                    ';'.join(peer.groups), ';'.join(peer.custom_tags), peer.notes, peer.trust_level,
                    peer.stats.total_connections, peer.stats.successful_connections, peer.stats.connection_quality_score
                ])
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    async def shutdown(self):
        """Shutdown the peer manager and cleanup resources."""
        logger.info("Shutting down Enhanced Peer Manager")
        self.save_all_data()
        
        if self.discovery_initialized:
            try:
                await shutdown_secure_system()
                logger.info("P2P Discovery Service shutdown complete")
            except Exception as e:
                logger.error(f"Error shutting down discovery service: {e}")