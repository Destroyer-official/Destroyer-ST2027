"""
Data management coordinator.

Coordinates all data management operations through sub-modules.
"""

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule


class DataManager(BaseModule):
    """Coordinator for all data management operations."""
    
    def __init__(self, orchestrator):
        """Initialize data manager."""
        super().__init__(orchestrator)
        self._user_mgmt = None
        self._peer_mgmt = None
        self._file_transfer = None
    
    @property
    def user_mgmt(self):
        """Lazy load user management module."""
        if self._user_mgmt is None:
            from .user_mgmt import EnhancedUserManager
            self._user_mgmt = EnhancedUserManager(self.orchestrator)
        return self._user_mgmt
    
    @property
    def peer_mgmt(self):
        """Lazy load peer management module."""
        if self._peer_mgmt is None:
            from .peer_mgmt import EnhancedPeerManager
            self._peer_mgmt = EnhancedPeerManager(self.orchestrator)
        return self._peer_mgmt
    
    @property
    def file_transfer(self):
        """Lazy load file transfer module."""
        if self._file_transfer is None:
            from .file_transfer import FileTransferManager
            self._file_transfer = FileTransferManager(self.orchestrator)
        return self._file_transfer
