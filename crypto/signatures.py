"""
Signature operations (ML-DSA-87, SLH-DSA-256f).

Provides quantum-resistant signature generation and verification using
NIST-standardized post-quantum algorithms.
"""

try:
    from ..base import BaseModule, CryptoError
except (ImportError, ValueError):
    from base import BaseModule, CryptoError


class SignatureOperations(BaseModule):
    """Quantum-resistant signature operations."""
    
    def __init__(self, orchestrator):
        """Initialize signature operations."""
        super().__init__(orchestrator)
        self._ml_dsa_87 = None
        self._slh_dsa_256f = None
    
    @property
    def ml_dsa_87(self):
        """Lazy load ML-DSA-87 implementation."""
        if self._ml_dsa_87 is None:
            try:
                from pqc_algorithms import EnhancedMLDSA_87
                self._ml_dsa_87 = EnhancedMLDSA_87()
            except ImportError as e:
                self.logger.error(f"Failed to import ML-DSA-87: {e}", exc_info=True)
                raise CryptoError(
                    f"Failed to load ML-DSA-87 implementation: {e}",
                    module="crypto.signatures",
                    function="ml_dsa_87",
                    severity="CRITICAL"
                )
        return self._ml_dsa_87
    
    @property
    def slh_dsa_256f(self):
        """Lazy load SLH-DSA-256f implementation."""
        if self._slh_dsa_256f is None:
            try:
                from pqc_algorithms import EnhancedSPHINCS_256s
                self._slh_dsa_256f = EnhancedSPHINCS_256s()
            except ImportError as e:
                self.logger.error(f"Failed to import SLH-DSA-256f: {e}", exc_info=True)
                raise CryptoError(
                    f"Failed to load SLH-DSA-256f implementation: {e}",
                    module="crypto.signatures",
                    function="slh_dsa_256f",
                    severity="CRITICAL"
                )
        return self._slh_dsa_256f
    
    def sign_with_ml_dsa_87(self, message: bytes, private_key: bytes) -> bytes:
        """
        Sign with ML-DSA-87 (NIST FIPS 204).
        
        ML-DSA-87 provides NIST Level 5 (256-bit) post-quantum security
        using lattice-based cryptography.
        
        Args:
            message: Message to sign (bytes)
            private_key: ML-DSA-87 private key (bytes)
            
        Returns:
            ML-DSA-87 signature (bytes)
            
        Raises:
            CryptoError: If signing fails
        """
        try:
            if not isinstance(message, bytes):
                raise TypeError("Message must be bytes")
            if not isinstance(private_key, bytes):
                raise TypeError("Private key must be bytes")
            
            self.logger.debug(f"Signing message with ML-DSA-87 (message_len={len(message)}, key_len={len(private_key)})")
            
            signature = self.ml_dsa_87.sign(private_key, message)
            
            if not isinstance(signature, bytes):
                raise ValueError("Signature must be bytes")
            
            self.logger.debug(f"ML-DSA-87 signature generated (sig_len={len(signature)})")
            return signature
            
        except TypeError as e:
            self.logger.error(f"Type error in ML-DSA-87 signing: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for ML-DSA-87 signing: {e}",
                module="crypto.signatures",
                function="sign_with_ml_dsa_87",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"ML-DSA-87 signing failed: {e}", exc_info=True)
            raise CryptoError(
                f"ML-DSA-87 signing failed: {e}",
                module="crypto.signatures",
                function="sign_with_ml_dsa_87",
                severity="HIGH"
            )
    
    def verify_ml_dsa_87_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify ML-DSA-87 signature (NIST FIPS 204).
        
        Args:
            message: Original message (bytes)
            signature: ML-DSA-87 signature (bytes)
            public_key: ML-DSA-87 public key (bytes)
            
        Returns:
            True if signature is valid, False otherwise
            
        Raises:
            CryptoError: If verification fails
        """
        try:
            if not isinstance(message, bytes):
                raise TypeError("Message must be bytes")
            if not isinstance(signature, bytes):
                raise TypeError("Signature must be bytes")
            if not isinstance(public_key, bytes):
                raise TypeError("Public key must be bytes")
            
            self.logger.debug(f"Verifying ML-DSA-87 signature (message_len={len(message)}, sig_len={len(signature)}, key_len={len(public_key)})")
            
            is_valid = self.ml_dsa_87.verify(public_key, message, signature)
            
            if not isinstance(is_valid, bool):
                raise ValueError("Verification result must be boolean")
            
            self.logger.debug(f"ML-DSA-87 signature verification result: {is_valid}")
            return is_valid
            
        except TypeError as e:
            self.logger.error(f"Type error in ML-DSA-87 verification: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for ML-DSA-87 verification: {e}",
                module="crypto.signatures",
                function="verify_ml_dsa_87_signature",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"ML-DSA-87 verification failed: {e}", exc_info=True)
            raise CryptoError(
                f"ML-DSA-87 verification failed: {e}",
                module="crypto.signatures",
                function="verify_ml_dsa_87_signature",
                severity="HIGH"
            )
    
    def sign_with_slh_dsa_256f(self, message: bytes, private_key: bytes) -> bytes:
        """
        Sign with SLH-DSA-256f (NIST FIPS 205).
        
        SLH-DSA-256f provides NIST Level 5 (256-bit) post-quantum security
        using hash-based cryptography with stateless operation.
        
        Args:
            message: Message to sign (bytes)
            private_key: SLH-DSA-256f private key (bytes)
            
        Returns:
            SLH-DSA-256f signature (bytes)
            
        Raises:
            CryptoError: If signing fails
        """
        try:
            if not isinstance(message, bytes):
                raise TypeError("Message must be bytes")
            if not isinstance(private_key, bytes):
                raise TypeError("Private key must be bytes")
            
            self.logger.debug(f"Signing message with SLH-DSA-256f (message_len={len(message)}, key_len={len(private_key)})")
            
            signature = self.slh_dsa_256f.sign(private_key, message)
            
            if not isinstance(signature, bytes):
                raise ValueError("Signature must be bytes")
            
            self.logger.debug(f"SLH-DSA-256f signature generated (sig_len={len(signature)})")
            return signature
            
        except TypeError as e:
            self.logger.error(f"Type error in SLH-DSA-256f signing: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for SLH-DSA-256f signing: {e}",
                module="crypto.signatures",
                function="sign_with_slh_dsa_256f",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"SLH-DSA-256f signing failed: {e}", exc_info=True)
            raise CryptoError(
                f"SLH-DSA-256f signing failed: {e}",
                module="crypto.signatures",
                function="sign_with_slh_dsa_256f",
                severity="HIGH"
            )
    
    def verify_slh_dsa_256f_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify SLH-DSA-256f signature (NIST FIPS 205).
        
        Args:
            message: Original message (bytes)
            signature: SLH-DSA-256f signature (bytes)
            public_key: SLH-DSA-256f public key (bytes)
            
        Returns:
            True if signature is valid, False otherwise
            
        Raises:
            CryptoError: If verification fails
        """
        try:
            if not isinstance(message, bytes):
                raise TypeError("Message must be bytes")
            if not isinstance(signature, bytes):
                raise TypeError("Signature must be bytes")
            if not isinstance(public_key, bytes):
                raise TypeError("Public key must be bytes")
            
            self.logger.debug(f"Verifying SLH-DSA-256f signature (message_len={len(message)}, sig_len={len(signature)}, key_len={len(public_key)})")
            
            is_valid = self.slh_dsa_256f.verify(public_key, message, signature)
            
            if not isinstance(is_valid, bool):
                raise ValueError("Verification result must be boolean")
            
            self.logger.debug(f"SLH-DSA-256f signature verification result: {is_valid}")
            return is_valid
            
        except TypeError as e:
            self.logger.error(f"Type error in SLH-DSA-256f verification: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for SLH-DSA-256f verification: {e}",
                module="crypto.signatures",
                function="verify_slh_dsa_256f_signature",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"SLH-DSA-256f verification failed: {e}", exc_info=True)
            raise CryptoError(
                f"SLH-DSA-256f verification failed: {e}",
                module="crypto.signatures",
                function="verify_slh_dsa_256f_signature",
                severity="HIGH"
            )
