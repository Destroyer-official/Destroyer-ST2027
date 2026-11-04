"""
Authentication tag operations.

Provides secure authentication tag generation and verification
using HMAC-SHA3-512 for message authentication and integrity protection.
"""

import hmac
import hashlib
from ..base import BaseModule, CryptoError


class AuthTagOperations(BaseModule):
    """secure authentication tag operations."""
    
    # HMAC algorithm configuration
    HMAC_ALGORITHM = hashlib.sha3_512
    HMAC_DIGEST_SIZE = 64  # SHA3-512 produces 64-byte digest
    
    def generate_military_auth_tag(self, ciphertext: bytes, message_hash: bytes) -> bytes:
        """
        Generate secure authentication tag.
        
        Creates an HMAC-SHA3-512 authentication tag over the ciphertext
        and message hash to provide authenticated encryption with
        integrity protection.
        
        Args:
            ciphertext: Encrypted message (bytes)
            message_hash: Hash of original message (bytes)
            
        Returns:
            Authentication tag (bytes)
            
        Raises:
            CryptoError: If tag generation fails
        """
        try:
            if not isinstance(ciphertext, bytes):
                raise TypeError("Ciphertext must be bytes")
            if not isinstance(message_hash, bytes):
                raise TypeError("Message hash must be bytes")
            
            self.logger.debug(f"Generating military auth tag (ct_len={len(ciphertext)}, hash_len={len(message_hash)})")
            
            # Combine ciphertext and message hash for authentication
            auth_input = ciphertext + message_hash
            
            # Generate HMAC-SHA3-512 authentication tag
            # Use message_hash as the key for HMAC (provides key derivation)
            h = hmac.new(message_hash, auth_input, self.HMAC_ALGORITHM)
            auth_tag = h.digest()
            
            if not isinstance(auth_tag, bytes):
                raise ValueError("Authentication tag must be bytes")
            
            if len(auth_tag) != self.HMAC_DIGEST_SIZE:
                raise ValueError(f"Authentication tag size mismatch: expected {self.HMAC_DIGEST_SIZE}, got {len(auth_tag)}")
            
            self.logger.debug(f"Military auth tag generated (tag_len={len(auth_tag)})")
            return auth_tag
            
        except TypeError as e:
            self.logger.error(f"Type error in auth tag generation: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for auth tag generation: {e}",
                module="crypto.auth_tags",
                function="generate_military_auth_tag",
                severity="HIGH"
            )
        except ValueError as e:
            self.logger.error(f"Value error in auth tag generation: {e}", exc_info=True)
            raise CryptoError(
                f"Auth tag generation validation failed: {e}",
                module="crypto.auth_tags",
                function="generate_military_auth_tag",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"Auth tag generation failed: {e}", exc_info=True)
            raise CryptoError(
                f"Auth tag generation failed: {e}",
                module="crypto.auth_tags",
                function="generate_military_auth_tag",
                severity="HIGH"
            )
    
    def verify_military_auth_tag(self, ciphertext: bytes, message_hash: bytes, auth_tag: bytes) -> bool:
        """
        Verify secure authentication tag.
        
        Verifies an HMAC-SHA3-512 authentication tag using constant-time
        comparison to prevent timing attacks.
        
        Args:
            ciphertext: Encrypted message (bytes)
            message_hash: Hash of original message (bytes)
            auth_tag: Authentication tag to verify (bytes)
            
        Returns:
            True if tag is valid, False otherwise
            
        Raises:
            CryptoError: If verification fails
        """
        try:
            if not isinstance(ciphertext, bytes):
                raise TypeError("Ciphertext must be bytes")
            if not isinstance(message_hash, bytes):
                raise TypeError("Message hash must be bytes")
            if not isinstance(auth_tag, bytes):
                raise TypeError("Authentication tag must be bytes")
            
            self.logger.debug(f"Verifying military auth tag (ct_len={len(ciphertext)}, hash_len={len(message_hash)}, tag_len={len(auth_tag)})")
            
            # Validate tag size
            if len(auth_tag) != self.HMAC_DIGEST_SIZE:
                self.logger.warning(f"Invalid auth tag size: expected {self.HMAC_DIGEST_SIZE}, got {len(auth_tag)}")
                return False
            
            # Combine ciphertext and message hash for verification
            auth_input = ciphertext + message_hash
            
            # Recompute HMAC-SHA3-512 authentication tag
            h = hmac.new(message_hash, auth_input, self.HMAC_ALGORITHM)
            expected_tag = h.digest()
            
            # Use constant-time comparison to prevent timing attacks
            is_valid = hmac.compare_digest(auth_tag, expected_tag)
            
            if not isinstance(is_valid, bool):
                raise ValueError("Verification result must be boolean")
            
            self.logger.debug(f"Military auth tag verification result: {is_valid}")
            return is_valid
            
        except TypeError as e:
            self.logger.error(f"Type error in auth tag verification: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for auth tag verification: {e}",
                module="crypto.auth_tags",
                function="verify_military_auth_tag",
                severity="HIGH"
            )
        except ValueError as e:
            self.logger.error(f"Value error in auth tag verification: {e}", exc_info=True)
            raise CryptoError(
                f"Auth tag verification validation failed: {e}",
                module="crypto.auth_tags",
                function="verify_military_auth_tag",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"Auth tag verification failed: {e}", exc_info=True)
            raise CryptoError(
                f"Auth tag verification failed: {e}",
                module="crypto.auth_tags",
                function="verify_military_auth_tag",
                severity="HIGH"
            )
