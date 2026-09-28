"""
secure padding operations.

Provides padding and unpadding functionality for cryptographic operations.
Implements random padding with length encoding for enhanced security.
"""

import secrets
try:
    from ..base import BaseModule, CryptoError
except (ImportError, ValueError):
    from base import BaseModule, CryptoError


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
            # secrets.randbelow(N) returns 0 to N-1. So randbelow(MAX_RANDOM_PADDING_BYTES) gives 0 to 31.
            # Adding 1 makes it 1 to 32.
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
                raise ValueError("Cannot unpad empty message")
            
            if len(padded_data) < 1:
                self.logger.error("Padded message too short to contain padding length byte.")
                raise ValueError("Padded message too short to contain padding info")
            
            num_random_bytes = padded_data[-1]  # Last byte is the length of *random* padding
            
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
        except Exception as e:
            self.logger.error(f"Random padding removal failed: {e}", exc_info=True)
            raise CryptoError(
                f"Random padding removal failed: {e}",
                module="crypto.padding",
                function="remove_random_padding",
                severity="HIGH"
            )
