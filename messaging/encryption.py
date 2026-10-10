"""
Message encryption operations.

Provides message encryption and decryption with double ratchet.
"""

import time
import struct
import hmac
try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule


class CryptographicOperationError(Exception):
    """Raised when an encryption or decryption operation fails (Item 39 / Finding 6.1)."""
    pass


class MessageEncryption(BaseModule):
    """Message encryption operations."""
    
    async def encrypt_message(self, message: str) -> bytes:
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

        Raises:
            CryptographicOperationError: If encryption fails or policy is violated
        """
        orchestrator = self.orchestrator
        
        # NIST Level 5+ Policy Enforcement
        try:
            orchestrator.enforce_nist_level5_for_operation(
                "message_encryption", 
                "AES-256-GCM", 
                {"key_size": 256}
            )
        except Exception as e:
            self.logger.critical(f"Message encryption blocked by NIST Level 5+ policy: {e}")
            raise CryptographicOperationError(f"NIST Level 5+ policy violation: {e}") from e

        # Validate message
        try:
            from ..security.validation import InputValidator
        except (ImportError, ValueError):
            try:
                from security.validation import InputValidator
            except ImportError:
                InputValidator = None

        if InputValidator and not InputValidator.validate_message(message):
            self.logger.error("Message validation failed")
            raise CryptographicOperationError("Message content validation failed")

        if not orchestrator.is_connected:
            self.logger.warning("Cannot encrypt message: not connected")
            raise CryptographicOperationError("Cannot encrypt message: not connected to peer")

        if not orchestrator.ratchet:
            self.logger.error("Double Ratchet not initialized")
            raise CryptographicOperationError("Cannot encrypt message: Double Ratchet not initialized")

        try:
            # Convert message to bytes
            plaintext = message.encode('utf-8')

            # Add random padding for traffic analysis protection
            padded_plaintext = orchestrator._add_random_padding(plaintext)

            # Use quantum resistance enhancement if available
            if (hasattr(orchestrator, 'quantum_resistance') and 
                orchestrator.security_verified.get('quantum_resistance', False)):
                try:
                    # Deterministic context binding derived from shared hybrid root key and canonical length
                    raw_len = len(plaintext)
                    context = f"ST2027::quantum_binding::v2::{raw_len}".encode('utf-8')
                    binding_key = orchestrator.quantum_resistance.hybrid_key_derivation(
                        orchestrator.hybrid_root_key, 
                        context
                    )

                    # Canonical binding header: Magic b"STQB" (4B) || Length raw_len (4B BE) || Tag (8B)
                    binding_tag = binding_key[:8]
                    header = b"STQB" + struct.pack(">I", raw_len) + binding_tag
                    enhanced_plaintext = header + padded_plaintext

                    # Encrypt with enhanced quantum resistance
                    ciphertext = orchestrator.ratchet.encrypt(enhanced_plaintext)
                    return ciphertext
                except Exception as e:
                    self.logger.critical(
                        f"Quantum resistance encryption enhancement failed: {e}. "
                        "Refusing silent classical downgrade."
                    )
                    raise CryptographicOperationError(f"Quantum resistance enhancement failed: {e}") from e

            # Standard encryption
            return orchestrator.ratchet.encrypt(padded_plaintext)

        except Exception as e:
            self.logger.error(f"Error encrypting message: {e}")
            if isinstance(e, CryptographicOperationError):
                raise
            raise CryptographicOperationError(f"Encryption failed: {e}") from e
    
    async def decrypt_message(self, encrypted_data: bytes) -> str:
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

        Args:
            encrypted_data: The encrypted data bytes

        Returns:
            str: The decrypted plaintext message

        Raises:
            CryptographicOperationError: If decryption fails
        """
        orchestrator = self.orchestrator
        
        # NIST Level 5+ Policy Enforcement
        try:
            orchestrator.enforce_nist_level5_for_operation(
                "message_decryption", 
                "AES-256-GCM", 
                {"key_size": 256}
            )
        except Exception as e:
            self.logger.critical(f"Message decryption blocked by NIST Level 5+ policy: {e}")
            raise CryptographicOperationError(f"NIST Level 5+ policy violation: {e}") from e

        if not orchestrator.is_connected:
            self.logger.warning("Cannot decrypt message: not connected")
            raise CryptographicOperationError("Cannot decrypt message: not connected to peer")

        if not orchestrator.ratchet:
            self.logger.error("Double Ratchet not initialized")
            raise CryptographicOperationError("Cannot decrypt message: Double Ratchet not initialized")

        try:
            # Decrypt the data
            decrypted_data = orchestrator.ratchet.decrypt(encrypted_data)

            # Check if this is a quantum-enhanced message (has verified binding header)
            if (hasattr(orchestrator, 'quantum_resistance') and 
                orchestrator.security_verified.get('quantum_resistance', False)):
                if decrypted_data.startswith(b"STQB") and len(decrypted_data) >= 16:
                    raw_len = struct.unpack(">I", decrypted_data[4:8])[0]
                    received_tag = decrypted_data[8:16]
                    padded_payload = decrypted_data[16:]

                    context = f"ST2027::quantum_binding::v2::{raw_len}".encode('utf-8')
                    expected_key = orchestrator.quantum_resistance.hybrid_key_derivation(
                        orchestrator.hybrid_root_key,
                        context
                    )
                    expected_tag = expected_key[:8]

                    if not hmac.compare_digest(received_tag, expected_tag):
                        self.logger.critical("Quantum-resistant message binding verification failed: tag mismatch")
                        raise CryptographicOperationError("Quantum-resistant message binding verification failed: tag mismatch")

                    unpadded_data = orchestrator._remove_random_padding(padded_payload)
                    if len(unpadded_data) != raw_len:
                        self.logger.critical(f"Plaintext length {len(unpadded_data)} does not match bound length {raw_len}")
                        raise CryptographicOperationError("Plaintext length mismatch with bound quantum envelope")

                    return unpadded_data.decode('utf-8')

            # Standard decryption path
            unpadded_data = orchestrator._remove_random_padding(decrypted_data)
            return unpadded_data.decode('utf-8')

        except Exception as e:
            self.logger.error(f"Error decrypting message: {e}")
            if hasattr(orchestrator, 'audit_logger'):
                orchestrator.audit_logger.log_security_event(
                    "MESSAGE_DECRYPTION_FAILED",
                    severity="HIGH",
                    details={"error": str(e)}
                )
            raise CryptographicOperationError(f"Decryption failed: {e}") from e
    
    async def ratchet_encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt with double ratchet directly.
        
        Args:
            plaintext: The plaintext bytes to encrypt
            
        Returns:
            bytes: The encrypted ciphertext

        Raises:
            CryptographicOperationError: If ratchet is not initialized or encryption fails
        """
        orchestrator = self.orchestrator
        
        if not orchestrator.ratchet:
            self.logger.error("Double Ratchet not initialized")
            raise CryptographicOperationError("Double Ratchet not initialized")
        
        try:
            return orchestrator.ratchet.encrypt(plaintext)
        except Exception as e:
            self.logger.error(f"Error in ratchet encryption: {e}")
            raise CryptographicOperationError(f"Ratchet encryption failed: {e}") from e
    
    async def ratchet_decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt with double ratchet directly.
        
        Args:
            ciphertext: The ciphertext bytes to decrypt
            
        Returns:
            bytes: The decrypted plaintext

        Raises:
            CryptographicOperationError: If ratchet is not initialized or decryption fails
        """
        orchestrator = self.orchestrator
        
        if not orchestrator.ratchet:
            self.logger.error("Double Ratchet not initialized")
            raise CryptographicOperationError("Double Ratchet not initialized")
        
        try:
            return orchestrator.ratchet.decrypt(ciphertext)
        except Exception as e:
            self.logger.error(f"Error in ratchet decryption: {e}")
            raise CryptographicOperationError(f"Ratchet decryption failed: {e}") from e
