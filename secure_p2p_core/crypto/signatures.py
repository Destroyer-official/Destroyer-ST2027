"""
Signature operations (ML-DSA-87, SLH-DSA-256f).

Provides quantum-resistant signature generation and verification using
NIST-standardized post-quantum algorithms.
"""

from typing import Optional, Tuple
import hmac
import hashlib
from ..base import BaseModule, CryptoError

MilitarySecurityError = CryptoError


class AwaitableBytes(bytes):
    def __await__(self):
        async def _coro():
            return bytes(self)
        return _coro().__await__()

class AwaitableBool:
    def __init__(self, val: bool):
        self._val = bool(val)
    def __bool__(self):
        return self._val
    def __eq__(self, other):
        return self._val == bool(other)
    def __ne__(self, other):
        return self._val != bool(other)
    def __repr__(self):
        return repr(self._val)
    def __await__(self):
        async def _coro():
            return self._val
        return _coro().__await__()


class SignatureOperations(BaseModule):
    """Quantum-resistant signature operations."""
    
    def __init__(self, orchestrator=None):
        """Initialize signature operations."""
        super().__init__(orchestrator)
        self._ml_dsa_87 = None
        self._slh_dsa_256f = None
        self._ml_dsa_87_signer = None
        self._slh_dsa_256f_signer = None
        self.hybrid_session_key = None
        self._peer_ml_dsa_87_public_key = None
        self._peer_slh_dsa_256f_public_key = None
        self._ml_dsa_87_public_key = None
        self._slh_dsa_256f_public_key = None

    def set_hybrid_session_key(self, session_key: bytes) -> None:
        """Set hybrid session key."""
        self.hybrid_session_key = session_key

    def set_peer_public_keys(self, ml_dsa_key: bytes, slh_dsa_key: bytes) -> None:
        """Set peer public keys."""
        self._peer_ml_dsa_87_public_key = ml_dsa_key
        self._peer_slh_dsa_256f_public_key = slh_dsa_key

    def get_public_keys(self) -> Tuple[Optional[bytes], Optional[bytes]]:
        """Get own public keys."""
        return (self._ml_dsa_87_public_key, self._slh_dsa_256f_public_key)



    def generate_military_auth_tag(self, key_or_ciphertext: bytes, data_or_hash: bytes) -> Any:
        """Generate military authentication tag."""
        key = self.hybrid_session_key if self.hybrid_session_key is not None else key_or_ciphertext
        data = (key_or_ciphertext + data_or_hash) if self.hybrid_session_key is not None else data_or_hash
        tag = hmac.new(key, data, hashlib.sha3_512).digest()
        return AwaitableBytes(tag)

    def verify_military_auth_tag(self, key_or_ciphertext: bytes, data_or_hash: bytes, auth_tag: bytes = None) -> Any:
        """Verify military authentication tag."""
        if auth_tag is None:
            if not self.hybrid_session_key:
                return AwaitableBool(False)
            expected_tag = hmac.new(self.hybrid_session_key, key_or_ciphertext, hashlib.sha3_512).digest()
            return AwaitableBool(hmac.compare_digest(expected_tag, data_or_hash))
        if self.hybrid_session_key is not None:
            expected_tag = hmac.new(self.hybrid_session_key, key_or_ciphertext + data_or_hash, hashlib.sha3_512).digest()
        else:
            expected_tag = hmac.new(key_or_ciphertext, data_or_hash, hashlib.sha3_512).digest()
        return AwaitableBool(hmac.compare_digest(expected_tag, auth_tag))
    
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
                from liboqs_wrapper import LibOQS_SLH_DSA_256f
                self._slh_dsa_256f = LibOQS_SLH_DSA_256f()
            except Exception as e:
                self.logger.error(f"Failed to load SLH-DSA-256f: {e}", exc_info=True)
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
            if not isinstance(message, bytes) or not isinstance(private_key, bytes):
                raise TypeError("Message and private key must be bytes")

            if len(private_key) != 128:
                raise CryptoError("Invalid private key size for SLH-DSA-256f: expected 128 bytes",
                                  module="crypto.signatures", function="sign_with_slh_dsa_256f")
            
            self.logger.debug(f"Signing message with SLH-DSA-256f (message_len={len(message)}, key_len={len(private_key)})")
            
            signature = self.slh_dsa_256f.sign(private_key, message)
            
            if not isinstance(signature, bytes):
                raise ValueError("Signature must be bytes")
            
            self.logger.debug(f"SLH-DSA-256f signature generated (sig_len={len(signature)})")
            return signature
            
        except (TypeError, CryptoError):
            raise
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
            if not isinstance(message, bytes) or not isinstance(signature, bytes) or not isinstance(public_key, bytes):
                raise TypeError("Inputs must be bytes")

            if len(public_key) != 64:
                raise CryptoError("Invalid public key size for SLH-DSA-256f: expected 64 bytes",
                                  module="crypto.signatures", function="verify_slh_dsa_256f_signature")
            
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
