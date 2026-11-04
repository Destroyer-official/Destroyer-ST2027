"""
secure padding operations.

Provides padding and unpadding functionality for cryptographic operations.
Implements random padding with length encoding for enhanced security.
"""

import secrets
from ..base import BaseModule, CryptoError

MilitarySecurityError = CryptoError


class PaddingOperations(BaseModule):
    """secure padding operations."""
    
    # Maximum random padding bytes (1-32 bytes)
    MAX_RANDOM_PADDING_BYTES = 32
    
    def add_military_grade_padding(self, data: bytes) -> bytes:
        """
        Add secure padding to data.
        
        This is an alias for add_random_padding for backward compatibility.
        
        Args:
            data: Data to pad (bytes)
            
        Returns:
            Padded data with random padding
            
        Raises:
            CryptoError: If padding fails
        """
        try:
            return self.add_random_padding(data)
        except CryptoError:
            raise
        except Exception as e:
            self.logger.error(f"secure padding failed: {e}", exc_info=True)
            raise CryptoError(
                f"secure padding failed: {e}",
                module="crypto.padding",
                function="add_military_grade_padding",
                severity="HIGH"
            )
    
    def remove_military_grade_padding(self, padded_data: bytes) -> bytes:
        """
        Remove secure padding from data.
        
        This is an alias for remove_random_padding for backward compatibility.
        
        Args:
            padded_data: Padded data (bytes)
            
        Returns:
            Original unpadded data
            
        Raises:
            CryptoError: If unpadding fails
        """
        try:
            return self.remove_random_padding(padded_data)
        except CryptoError:
            raise
        except Exception as e:
            self.logger.error(f"secure padding removal failed: {e}", exc_info=True)
            raise CryptoError(
                f"secure padding removal failed: {e}",
                module="crypto.padding",
                function="remove_military_grade_padding",
                severity="HIGH"
            )
    
    def add_random_padding(self, data: bytes) -> bytes:
        """
        Add random padding to plaintext before encryption.
        
        Structure: [ Plaintext | Random Padding Bytes | Length of Random Padding Bytes (1 byte) ]
        Padding length is 1 to MAX_RANDOM_PADDING_BYTES (inclusive).
        
        Args:
            data: Data to pad (bytes)
            
        Returns:
            Padded data with random padding
            
        Raises:
            CryptoError: If padding fails
        """
        try:
            if not isinstance(data, bytes):
                raise TypeError("Input to padding must be bytes.")
            
            # Generate 1 to MAX_RANDOM_PADDING_BYTES of random padding
            num_random_bytes = secrets.randbelow(self.MAX_RANDOM_PADDING_BYTES) + 1
            random_padding = secrets.token_bytes(num_random_bytes)
            len_byte = num_random_bytes.to_bytes(1, 'big')
            
            self.logger.debug(f"Added {num_random_bytes} random padding bytes + 1 length byte.")
            return data + random_padding + len_byte
            
        except TypeError as e:
            self.logger.error(f"Type error in padding: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for padding: {e}",
                module="crypto.padding",
                function="add_random_padding",
                severity="HIGH"
            )
        except CryptoError:
            raise
        except Exception as e:
            self.logger.error(f"Random padding failed: {e}", exc_info=True)
            raise CryptoError(
                f"Random padding failed: {e}",
                module="crypto.padding",
                function="add_random_padding",
                severity="HIGH"
            )
    
    def remove_random_padding(self, padded_data: bytes) -> bytes:
        """
        Remove random padding from decrypted plaintext.
        
        Reverses the add_random_padding operation by reading the length byte
        and removing the specified amount of padding.
        
        Args:
            padded_data: Padded data (bytes)
            
        Returns:
            Original unpadded data
            
        Raises:
            CryptoError: If unpadding fails
        """
        try:
            if not padded_data:
                self.logger.warning("Attempted to unpad an empty message.")
                raise ValueError("Cannot unpad empty message: too short")
            
            if len(padded_data) < 2:
                self.logger.error("Padded message too short to contain padding length byte.")
                raise ValueError("Padded message too short to contain padding length byte")
            
            num_random_bytes = padded_data[-1]  # Last byte is the length of *random* padding
            
            if num_random_bytes < 1 or num_random_bytes > self.MAX_RANDOM_PADDING_BYTES:
                self.logger.error(f"Invalid padding length byte: {num_random_bytes}")
                raise ValueError(f"Invalid padding length: {num_random_bytes} (must be 1-{self.MAX_RANDOM_PADDING_BYTES})")
            
            # Total padding length is num_random_bytes + 1 (for the length byte itself)
            total_padding_length = num_random_bytes + 1
            
            if total_padding_length > len(padded_data):
                self.logger.error(
                    f"Invalid padding: indicated padding length {total_padding_length} "
                    f"(random: {num_random_bytes}) is greater than message length {len(padded_data)}."
                )
                raise ValueError(
                    f"Invalid padding: indicated padding ({total_padding_length} bytes) "
                    f"exceeds message length ({len(padded_data)})"
                )
            
            original_plaintext_end_index = len(padded_data) - total_padding_length
            
            self.logger.debug(f"Removed {num_random_bytes} random padding bytes + 1 length byte.")
            return padded_data[:original_plaintext_end_index]
            
        except ValueError as e:
            self.logger.error(f"Padding validation error: {e}", exc_info=True)
            raise CryptoError(
                f"Padding validation failed: {e}",
                module="crypto.padding",
                function="remove_random_padding",
                severity="HIGH"
            )
        except CryptoError:
            raise
        except Exception as e:
            self.logger.error(f"Random padding removal failed: {e}", exc_info=True)
            raise CryptoError(
                f"Random padding removal failed: {e}",
                module="crypto.padding",
                function="remove_random_padding",
                severity="HIGH"
            )
