"""
Crypto operations coordinator.

Coordinates all cryptographic operations through sub-modules.
"""

from ..base import BaseModule


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

    def encrypt(self, *args, **kwargs):
        """Encrypt message or data."""
        if hasattr(self.orchestrator, 'messaging') and hasattr(self.orchestrator.messaging, 'encryption'):
            return self.orchestrator.messaging.encryption.encrypt_message(*args, **kwargs)
        raise NotImplementedError("Encryption not available")

    def decrypt(self, *args, **kwargs):
        """Decrypt message or data."""
        if hasattr(self.orchestrator, 'messaging') and hasattr(self.orchestrator.messaging, 'encryption'):
            return self.orchestrator.messaging.encryption.decrypt_message(*args, **kwargs)
        raise NotImplementedError("Decryption not available")

    def sign(self, message: bytes, private_key: bytes, algorithm: str = "falcon") -> bytes:
        """Sign message."""
        return self.signatures.sign_with_falcon_1024(message, private_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes, algorithm: str = "falcon") -> bool:
        """Verify signature."""
        return self.signatures.verify_falcon_1024_signature(message, signature, public_key)

    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes, algorithm: str = "falcon") -> bool:
        """Verify signature alias."""
        return self.verify(message, signature, public_key, algorithm)
