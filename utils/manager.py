"""
Utils operations coordinator.

Coordinates all utility operations through sub-modules.
"""

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule


class UtilsManager(BaseModule):
    """Coordinator for all utility operations."""
    
    def __init__(self, orchestrator):
        """Initialize utils manager."""
        super().__init__(orchestrator)
        self._initialization = None
        self._cleanup = None
        self._memory = None
        self._helpers = None
    
    @property
    def initialization(self):
        """Lazy load initialization module."""
        if self._initialization is None:
            from .initialization import Initialization
            self._initialization = Initialization(self.orchestrator)
        return self._initialization
    
    @property
    def cleanup(self):
        """Lazy load cleanup module."""
        if self._cleanup is None:
            from .cleanup import Cleanup
            self._cleanup = Cleanup(self.orchestrator)
        return self._cleanup
    
    @property
    def memory(self):
        """Lazy load memory module."""
        if self._memory is None:
            from .memory import MemoryManager
            self._memory = MemoryManager(self.orchestrator)
        return self._memory
    
    @property
    def helpers(self):
        """Lazy load helpers module."""
        if self._helpers is None:
            from .helpers import Helpers
            self._helpers = Helpers(self.orchestrator)
        return self._helpers
