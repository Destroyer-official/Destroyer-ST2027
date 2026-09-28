"""
Peer management operations.

Provides peer lookup, addition, and connection management with enhanced capabilities
including groups, favorites, connection history, and statistics.
"""

import logging
from typing import Dict, List, Optional, Tuple

try:
    from ..base import BaseModule, UserManagementError
except (ImportError, ValueError):
    from base import BaseModule, UserManagementError

# Import the new enhanced peer manager
try:
    from enhanced_peer_manager import (
        EnhancedPeerManager as NewEnhancedPeerManager,
        PeerInfo,
        ConnectionStatus
    )
    ENHANCED_PEER_MANAGER_AVAILABLE = True
except ImportError:
    ENHANCED_PEER_MANAGER_AVAILABLE = False
    NewEnhancedPeerManager = None
    PeerInfo = None
    ConnectionStatus = None


class EnhancedPeerManager(BaseModule):
    """
    Enhanced peer management with advanced features.
    
    This class provides a compatibility wrapper for the new enhanced peer manager
    while maintaining backward compatibility with the existing API.
    
    Features:
    - Peer organization with groups and favorites
    - Advanced search and filtering
    - Connection history and statistics
    - P2P Discovery Service integration
    - Offline support with intelligent caching
    """
    
    def __init__(self, orchestrator=None):
        """Initialize the enhanced peer manager."""
        super().__init__(orchestrator)
        
        if ENHANCED_PEER_MANAGER_AVAILABLE:
            self.manager = NewEnhancedPeerManager()
            if hasattr(self, 'log'):
                self.log.info("Enhanced peer manager initialized")
        else:
            self.manager = None
            if hasattr(self, 'log'):
                self.log.warning("Enhanced peer manager not available, using fallback")
            # Fallback to simple in-memory storage
            self._peers = {}

    async def lookup_peer_by_username(self, username: str) -> Optional[Dict]:
        """
        Lookup peer by username with enhanced capabilities.
        
        Args:
            username: Username to lookup
            
        Returns:
            Peer information dictionary or None if not found
        """
        try:
            if self.manager:
                peer_info = await self.manager.lookup_peer_by_username(username)
                if peer_info:
                    # Convert PeerInfo to dict for backward compatibility
                    return {
                        'display_name': peer_info.display_name,
                        'ipv6_address': peer_info.ipv6_address,
                        'port': peer_info.port,
                        'user_id': peer_info.user_id,
                        'last_seen': peer_info.last_seen.isoformat() if peer_info.last_seen else None,
                        'source': peer_info.source,
                        'connection_count': peer_info.stats.total_connections,
                        'last_connected': peer_info.last_connected.isoformat() if peer_info.last_connected else None
                    }
            else:
                # Fallback implementation
                return self._peers.get(username)
            
            return None
            
        except Exception as e:
            if hasattr(self, 'log'):
                self.log.error(f"Peer lookup failed for '{username}': {e}", exc_info=True)
            raise UserManagementError(
                f"Peer lookup failed: {e}",
                severity="MEDIUM",
                module="data.peer_mgmt",
                function="lookup_peer_by_username"
            )

    def add_peer(self, username: str, display_name: str, ipv6: str, port: int):
        """
        Add peer to the peer list.
        
        Args:
            username: Username
            display_name: Display name
            ipv6: IPv6 address
            port: Port number
        """
        try:
            if self.manager:
                self.manager.add_peer(username, display_name, ipv6, port)
                if hasattr(self, 'log'):
                    self.log.info(f"Peer added: {username} ({display_name})")
            else:
                # Fallback implementation
                self._peers[username] = {
                    'display_name': display_name,
                    'ipv6_address': ipv6,
                    'port': port,
                    'user_id': None,
                    'last_seen': None,
                    'source': 'manual',
                    'connection_count': 0,
                    'last_connected': None
                }
                if hasattr(self, 'log'):
                    self.log.info(f"Peer added (fallback): {username}")
                
        except Exception as e:
            if hasattr(self, 'log'):
                self.log.error(f"Failed to add peer '{username}': {e}", exc_info=True)
            raise UserManagementError(
                f"Failed to add peer: {e}",
                severity="MEDIUM",
                module="data.peer_mgmt",
                function="add_peer"
            )

    def get_peer(self, username: str) -> Optional[Dict]:
        """
        Get peer information from local storage.
        
        Args:
            username: Username to get
            
        Returns:
            Peer information dictionary or None if not found
        """
        try:
            if self.manager:
                peer_info = self.manager.get_peer(username)
                if peer_info:
                    # Convert PeerInfo to dict for backward compatibility
                    return {
                        'display_name': peer_info.display_name,
                        'ipv6_address': peer_info.ipv6_address,
                        'port': peer_info.port,
                        'user_id': peer_info.user_id,
                        'last_seen': peer_info.last_seen.isoformat() if peer_info.last_seen else None,
                        'source': peer_info.source,
                        'connection_count': peer_info.stats.total_connections,
                        'last_connected': peer_info.last_connected.isoformat() if peer_info.last_connected else None
                    }
            else:
                # Fallback implementation
                return self._peers.get(username)
            
            return None
            
        except Exception as e:
            if hasattr(self, 'log'):
                self.log.error(f"Failed to get peer '{username}': {e}", exc_info=True)
            raise UserManagementError(
                f"Failed to get peer: {e}",
                severity="LOW",
                module="data.peer_mgmt",
                function="get_peer"
            )

    def list_peers(self) -> List[Tuple[str, Dict]]:
        """
        List all peers.
        
        Returns:
            List of tuples (username, peer_dict)
        """
        try:
            if self.manager:
                peer_items = self.manager.list_peers()
                result = []

                for username, peer_info in peer_items:
                    peer_dict = {
                        'display_name': peer_info.display_name,
                        'ipv6_address': peer_info.ipv6_address,
                        'port': peer_info.port,
                        'user_id': peer_info.user_id,
                        'last_seen': peer_info.last_seen.isoformat() if peer_info.last_seen else None,
                        'source': peer_info.source,
                        'connection_count': peer_info.stats.total_connections,
                        'last_connected': peer_info.last_connected.isoformat() if peer_info.last_connected else None
                    }
                    result.append((username, peer_dict))

                return result
            else:
                # Fallback implementation
                return [(username, peer_dict) for username, peer_dict in self._peers.items()]
                
        except Exception as e:
            if hasattr(self, 'log'):
                self.log.error(f"Failed to list peers: {e}", exc_info=True)
            raise UserManagementError(
                f"Failed to list peers: {e}",
                severity="LOW",
                module="data.peer_mgmt",
                function="list_peers"
            )

    def update_peer_connection(self, username: str, success: bool = True):
        """
        Update peer connection status and statistics.
        
        Args:
            username: Username
            success: Whether connection was successful
        """
        try:
            if self.manager:
                self.manager.update_peer_connection(username, success)
                if hasattr(self, 'log'):
                    self.log.info(f"Peer connection updated: {username} (success={success})")
            else:
                # Fallback implementation
                if username in self._peers:
                    self._peers[username]['connection_count'] = self._peers[username].get('connection_count', 0) + 1
                    if success:
                        from datetime import datetime
                        self._peers[username]['last_connected'] = datetime.now().isoformat()
                    if hasattr(self, 'log'):
                        self.log.info(f"Peer connection updated (fallback): {username}")
                    
        except Exception as e:
            if hasattr(self, 'log'):
                self.log.error(f"Failed to update peer connection for '{username}': {e}", exc_info=True)
            raise UserManagementError(
                f"Failed to update peer connection: {e}",
                severity="LOW",
                module="data.peer_mgmt",
                function="update_peer_connection"
            )

    def cleanup(self):
        """Cleanup method for compatibility."""
        try:
            if self.manager:
                # The new manager handles cleanup automatically
                self.manager.save_all_data()
                if hasattr(self, 'log'):
                    self.log.info("Peer manager cleanup completed")
            else:
                # Fallback cleanup
                self._peers.clear()
                if hasattr(self, 'log'):
                    self.log.info("Peer manager cleanup completed (fallback)")
                
        except Exception as e:
            if hasattr(self, 'log'):
                self.log.error(f"Cleanup failed: {e}", exc_info=True)
