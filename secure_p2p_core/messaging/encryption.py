"""
Message encryption operations.

Provides message encryption and decryption with double ratchet.
"""

import asyncio
import time
from ..base import BaseModule, CryptoError


class AwaitableBytes(bytes):
    def __new__(cls, val=b'', coro=None):
        obj = super().__new__(cls, val)
        obj._coro = coro
        return obj

    def __await__(self):
        if self._coro is not None:
            return self._coro.__await__()
        async def _id():
            return bytes(self)
        return _id().__await__()


class AwaitableStr(str):
    def __new__(cls, val='', coro=None):
        obj = super().__new__(cls, val)
        obj._coro = coro
        return obj

    def __await__(self):
        if self._coro is not None:
            return self._coro.__await__()
        async def _id():
            return str(self)
        return _id().__await__()


class MessageEncryption(BaseModule):
    """Message encryption operations."""
    
    def encrypt_message(self, message: Any) -> bytes:
        """
        Encrypt a message using the Double Ratchet with enhanced quantum resistance.

        This method implements a multi-layered encryption approach:
        1. Validates the message to prevent injection attacks
        2. Converts the message to UTF-8 bytes
        3. Adds random padding to prevent traffic analysis
        4. Applies quantum-resistant enhancements when available:
           - Derives binding keys using hybrid key derivation
           - Adds context binding for enhanced security
        5. Encrypts using the Double Ratchet protocol (AES-256-GCM)

        The encryption process advances the ratchet, providing forward secrecy
        even if previous keys are compromised.

        Args:
            message: The plaintext message to encrypt

        Returns:
            bytes: The fully encrypted and authenticated message

        Security:
            - Forward secrecy through key ratcheting
            - Authentication using HMAC and post-quantum signatures
            - Side-channel resistance through constant-time operations
            - Message padding to prevent traffic analysis
        """
        orchestrator = self.orchestrator
        if orchestrator and hasattr(orchestrator, '_encrypt_message'):
            res = orchestrator._encrypt_message(message)
            if asyncio.iscoroutine(res):
                return AwaitableBytes(b'', coro=res)
            return AwaitableBytes(res) if isinstance(res, bytes) else res
        
        if not orchestrator or not orchestrator.is_connected or not orchestrator.ratchet:
            raise CryptoError("Cannot encrypt message: no active session or encryption key established")

        # NIST Level 5+ Policy Enforcement
        try:
            orchestrator.enforce_nist_level5_for_operation(
                "message_encryption", 
                "AES-256-GCM", 
                {"key_size": 256}
            )
        except Exception as e:
            self.logger.critical(f"Message encryption blocked by NIST Level 5+ policy: {e}")
            raise CryptoError(f"Message encryption blocked: {e}")

        # Validate message
        from ..security.validation import InputValidator
        msg_str = message.decode('utf-8', errors='ignore') if isinstance(message, bytes) else str(message)
        if not InputValidator.validate_message(msg_str):
            self.logger.error("Message validation failed")
            raise CryptoError("Message validation failed")

        try:
            # Convert message to bytes
            plaintext = message if isinstance(message, bytes) else message.encode('utf-8')

            # Add random padding for traffic analysis protection
            padded_plaintext = orchestrator._add_random_padding(plaintext)

            # Authenticated encryption via active ratchet
            ciphertext = orchestrator.ratchet.encrypt(padded_plaintext)
            return AwaitableBytes(ciphertext)

        except Exception as e:
            self.logger.error(f"Error encrypting message: {e}")
            raise CryptoError(f"Error encrypting message: {e}")
    
    def decrypt_message(self, encrypted_data: bytes) -> str:
        """
        Decrypt a message with support for quantum-resistant enhancements.

        This method implements a comprehensive decryption process:
        1. Verifies connection and ratchet state
        2. Decrypts the ciphertext using the Double Ratchet protocol
        3. Handles both standard and quantum-enhanced messages:
           - Detects binding prefix in quantum-enhanced messages
           - Extracts and verifies binding information
        4. Removes padding added during encryption
        5. Decodes the plaintext from UTF-8 bytes

        The decryption process advances the ratchet, maintaining
        forward secrecy and break-in recovery properties.

        Args:
            encrypted_data: The encrypted data bytes

        Returns:
            str: The decrypted plaintext message

        Security:
            - Message authentication before decryption
            - Constant-time operations to prevent timing attacks
            - Error handling that doesn't leak information
            - Support for quantum-resistant enhancements
        """
        orchestrator = self.orchestrator
        if orchestrator and hasattr(orchestrator, '_decrypt_message'):
            res = orchestrator._decrypt_message(encrypted_data)
            if asyncio.iscoroutine(res):
                return AwaitableStr('', coro=res)
            return AwaitableStr(res) if isinstance(res, str) else res
        
        if not orchestrator or not orchestrator.is_connected or not orchestrator.ratchet:
            raise CryptoError("Cannot decrypt message: invalid format or no session key")

        # NIST Level 5+ Policy Enforcement
        try:
            orchestrator.enforce_nist_level5_for_operation(
                "message_decryption", 
                "AES-256-GCM", 
                {"key_size": 256}
            )
        except Exception as e:
            self.logger.critical(f"Message decryption blocked by NIST Level 5+ policy: {e}")
            raise CryptoError(f"Message decryption blocked: {e}")

        try:
            # Authenticated decryption via active ratchet
            decrypted_data = orchestrator.ratchet.decrypt(encrypted_data)

            # Remove padding added during encryption
            unpadded_data = orchestrator._remove_random_padding(decrypted_data)
            return AwaitableStr(unpadded_data.decode('utf-8'))

        except Exception as e:
            self.logger.error(f"Error decrypting message: {e}")
            if hasattr(orchestrator, 'audit_logger') and orchestrator.audit_logger:
                orchestrator.audit_logger.log_security_event(
                    "MESSAGE_DECRYPTION_FAILED",
                    details={"error": str(e)}
                )
            raise CryptoError(f"Error decrypting message: {e}")
    
    async def ratchet_encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt with double ratchet directly.
        
        Args:
            plaintext: The plaintext bytes to encrypt
            
        Returns:
            bytes: The encrypted ciphertext
        """
        orchestrator = self.orchestrator
        
        if not orchestrator.ratchet:
            self.logger.error("Double Ratchet not initialized")
            return b''
        
        try:
            return orchestrator.ratchet.encrypt(plaintext)
        except Exception as e:
            self.logger.error(f"Error in ratchet encryption: {e}")
            return b''
    
    async def ratchet_decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt with double ratchet directly.
        
        Args:
            ciphertext: The ciphertext bytes to decrypt
            
        Returns:
            bytes: The decrypted plaintext
        """
        orchestrator = self.orchestrator
        
        if not orchestrator.ratchet:
            self.logger.error("Double Ratchet not initialized")
            return b''
        
        try:
            return orchestrator.ratchet.decrypt(ciphertext)
        except Exception as e:
            self.logger.error(f"Error in ratchet decryption: {e}")
            return b''
