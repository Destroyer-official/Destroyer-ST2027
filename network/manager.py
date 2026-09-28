"""
Network operations coordinator.

Coordinates all network operations through sub-modules.
"""

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule


class NetworkManager(BaseModule):
    """Coordinator for all network operations."""
    
    def __init__(self, orchestrator):
        """Initialize network manager."""
        super().__init__(orchestrator)
        self._handshake = None
        self._io = None
        self._monitoring = None
        self._connection = None
    
    @property
    def handshake(self):
        """Lazy load handshake module."""
        if self._handshake is None:
            from .handshake import HandshakeManager
            self._handshake = HandshakeManager(self.orchestrator)
        return self._handshake
    
    @property
    def io(self):
        """Lazy load I/O module."""
        if self._io is None:
            from .io import NetworkIO
            self._io = NetworkIO(self.orchestrator)
        return self._io
    
    @property
    def monitoring(self):
        """Lazy load monitoring module."""
        if self._monitoring is None:
            from .monitoring import ConnectionMonitoring
            self._monitoring = ConnectionMonitoring(self.orchestrator)
        return self._monitoring
    
    @property
    def connection(self):
        """Lazy load connection module."""
        if self._connection is None:
            from .connection import ConnectionManager
            self._connection = ConnectionManager(self.orchestrator)
        return self._connection
