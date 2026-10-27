"""
Crypto operations coordinator.

Coordinates all cryptographic operations through sub-modules.
"""

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule


class CryptoOperations(BaseModule):
    """Coordinator for all cryptographic operations."""
    
    def __init__(self, orchestrator):
        """Initialize crypto operations."""
        super().__init__(orchestrator)
        self._padding = None
        self._signatures = None
        self._kem = None
        self._auth_tags = None
    
    @property
    def padding(self):
        """Lazy load padding module."""
        if self._padding is None:
            from .padding import PaddingOperations
            self._padding = PaddingOperations(self.orchestrator)
        return self._padding
    
    @property
    def signatures(self):
        """Lazy load signatures module."""
        if self._signatures is None:
            from .signatures import SignatureOperations
            self._signatures = SignatureOperations(self.orchestrator)
        return self._signatures
    
    @property
    def kem(self):
        """Lazy load KEM module."""
        if self._kem is None:
            from .kem import KEMOperations
            self._kem = KEMOperations(self.orchestrator)
        return self._kem
    
    @property
    def auth_tags(self):
        """Lazy load auth tags module."""
        if self._auth_tags is None:
            from .auth_tags import AuthTagOperations
            self._auth_tags = AuthTagOperations(self.orchestrator)
        return self._auth_tags
