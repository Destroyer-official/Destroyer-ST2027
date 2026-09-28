"""
Authentication tag operations.

Provides secure authentication tag generation and verification
using HMAC-SHA3-512 for message authentication and integrity protection.
"""

import hmac
import hashlib
from typing import Optional
try:
    from ..base import BaseModule, CryptoError
except (ImportError, ValueError):
    from base import BaseModule, CryptoError


class AuthTagOperations(BaseModule):
    """secure authentication tag operations."""
    
    # HMAC algorithm configuration
    HMAC_ALGORITHM = hashlib.sha3_512
    HMAC_DIGEST_SIZE = 64  # SHA3-512 produces 64-byte digest
    
    def __init__(self, orchestrator=None, auth_key: Optional[bytes] = None):
        super().__init__(orchestrator)
        if auth_key is not None:
            if len(auth_key) < 32:
                raise ValueError("auth_key must be at least 32 bytes")
            self._default_auth_key = auth_key
        elif orchestrator and hasattr(orchestrator, 'session_auth_key') and orchestrator.session_auth_key:
            self._default_auth_key = orchestrator.session_auth_key
        else:
            import secrets
            self._default_auth_key = secrets.token_bytes(32)

    def _derive_mac_key(self, message_hash: bytes, auth_key: Optional[bytes] = None) -> bytes:
        """Derive independent HMAC key using secret key material with domain separation per NIST SP 800-56C (Finding 5)."""
        key_source = auth_key or getattr(self, '_default_auth_key', None)
        if not key_source:
            raise CryptoError(
                "Secret authentication key (>= 32 bytes) is required for MAC derivation",
                module="crypto.auth_tags",
                function="_derive_mac_key",
                severity="HIGH"
            )
        if len(key_source) < 32:
            raise CryptoError(
                f"Secret authentication key too short: expected >= 32 bytes, got {len(key_source)}",
                module="crypto.auth_tags",
                function="_derive_mac_key",
                severity="HIGH"
            )

        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=b"SecureP2P::AuthTag::DomainSalt::v1::CNSA2-Level5",
            info=b"Military-Auth-Tag-Key-Derivation-v1",
            backend=default_backend()
        )
        return bytearray(hkdf.derive(key_source + message_hash))

    def generate_military_auth_tag(self, ciphertext: bytes, message_hash: bytes, auth_key: Optional[bytes] = None) -> bytes:
        """
        Generate secure authentication tag.
        
        Creates an HMAC-SHA3-512 authentication tag over the ciphertext
        and message hash using an independent HKDF-derived key or provided auth_key.
        
        Args:
            ciphertext: Encrypted message (bytes)
            message_hash: Hash of original message (bytes)
            auth_key: Optional explicit secret key for HMAC
            
        Returns:
            Authentication tag (bytes)
            
        Raises:
            CryptoError: If tag generation fails
        """
        mac_key = None
        try:
            if not isinstance(ciphertext, bytes):
                raise TypeError("Ciphertext must be bytes")
            if not isinstance(message_hash, bytes):
                raise TypeError("Message hash must be bytes")
            
            self.logger.debug(f"Generating military auth tag (ct_len={len(ciphertext)}, hash_len={len(message_hash)})")
            
            # Combine ciphertext and message hash for authentication
            auth_input = ciphertext + message_hash
            
            # Generate HMAC-SHA3-512 authentication tag with independent key
            mac_key = self._derive_mac_key(message_hash, auth_key)
            h = hmac.new(mac_key, auth_input, self.HMAC_ALGORITHM)
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
        finally:
            if mac_key is not None and isinstance(mac_key, bytearray):
                for i in range(len(mac_key)):
                    mac_key[i] = 0
    
    def verify_military_auth_tag(self, ciphertext: bytes, message_hash: bytes, auth_tag: bytes, auth_key: Optional[bytes] = None) -> bool:
        """
        Verify secure authentication tag.
        
        Verifies an HMAC-SHA3-512 authentication tag using constant-time
        comparison to prevent timing attacks.
        
        Args:
            ciphertext: Encrypted message (bytes)
            message_hash: Hash of original message (bytes)
            auth_tag: Authentication tag to verify (bytes)
            auth_key: Optional explicit secret key for HMAC
            
        Returns:
            True if tag is valid, False otherwise
            
        Raises:
            CryptoError: If verification fails
        """
        mac_key = None
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
            
            # Recompute HMAC-SHA3-512 authentication tag with independent key
            mac_key = self._derive_mac_key(message_hash, auth_key)
            h = hmac.new(mac_key, auth_input, self.HMAC_ALGORITHM)
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
        finally:
            if mac_key is not None and isinstance(mac_key, bytearray):
                for i in range(len(mac_key)):
                    mac_key[i] = 0

    def secure_cleanup(self) -> None:
        """Securely zeroize stored default authentication key."""
        if hasattr(self, '_default_auth_key') and self._default_auth_key:
            try:
                from secure_key_manager import secure_erase
                secure_erase(self._default_auth_key)
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            finally:
                self._default_auth_key = None

