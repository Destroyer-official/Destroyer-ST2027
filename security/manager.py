"""
Security operations coordinator.

Coordinates all security operations through sub-modules.
"""

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule


class SecurityManager(BaseModule):
    """Coordinator for all security operations."""
    
    def __init__(self, orchestrator):
        """Initialize security manager."""
        super().__init__(orchestrator)
        self._hardening = None
        self._integrity = None
        self._monitor = None
        self._validation = None
    
    @property
    def hardening(self):
        """Lazy load hardening module."""
        if self._hardening is None:
            from .hardening import SecurityHardening
            self._hardening = SecurityHardening(self.orchestrator)
        return self._hardening
    
    @property
    def integrity(self):
        """Lazy load integrity module."""
        if self._integrity is None:
            from .integrity import IntegrityChecks
            self._integrity = IntegrityChecks(self.orchestrator)
        return self._integrity
    
    @property
    def monitor(self):
        """Lazy load monitoring module."""
        if self._monitor is None:
            from .monitor import SecurityMonitor
            self._monitor = SecurityMonitor(self.orchestrator)
        return self._monitor
    
    @property
    def validation(self):
        """Lazy load validation module."""
        if self._validation is None:
            from .validation import InputValidator
            self._validation = InputValidator(self.orchestrator)
        return self._validation
