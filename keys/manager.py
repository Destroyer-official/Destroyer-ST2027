"""
Key management coordinator.

Coordinates all key management operations through sub-modules.
"""

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule


class KeysManager(BaseModule):
    """Coordinator for all key management operations."""
    
    def __init__(self, orchestrator):
        """Initialize keys manager."""
        super().__init__(orchestrator)
        self._storage = None
        self._rotation = None
        self._generation = None
        self._hsm = None
    
    @property
    def storage(self):
        """Lazy load storage module."""
        if self._storage is None:
            from .storage import KeyStorage
            self._storage = KeyStorage(self.orchestrator)
        return self._storage
    
    @property
    def rotation(self):
        """Lazy load rotation module."""
        if self._rotation is None:
            from .rotation import KeyRotation
            self._rotation = KeyRotation(self.orchestrator)
        return self._rotation
    
    @property
    def generation(self):
        """Lazy load generation module."""
        if self._generation is None:
            from .generation import KeyGeneration
            self._generation = KeyGeneration(self.orchestrator)
        return self._generation
    
    @property
    def hsm(self):
        """Lazy load HSM integration module."""
        if self._hsm is None:
            from .hsm_integration import HSMIntegration
            self._hsm = HSMIntegration(self.orchestrator)
        return self._hsm
