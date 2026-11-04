"""
Unit tests for messaging/encryption.py module
"""

import pytest
from unittest.mock import Mock, AsyncMock
from secure_p2p_core.messaging.encryption import MessageEncryption


class TestMessageEncryption:
    """Test suite for MessageEncryption class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.message_encryption = MessageEncryption(self.mock_parent)
    
    def test_initialization(self):
        """Test MessageEncryption initialization"""
        assert self.message_encryption is not None
        assert self.message_encryption.parent == self.mock_parent
    
    @pytest.mark.asyncio
    async def test_encrypt_message(self):
        """Test encrypting message"""
        plaintext = b"Test message"
        expected_ciphertext = b"encrypted_data"
        
        self.mock_parent._encrypt_message = AsyncMock(return_value=expected_ciphertext)
        
        ciphertext = await self.message_encryption.encrypt_message(plaintext)
        
        assert ciphertext == expected_ciphertext
        assert self.mock_parent._encrypt_message.called
    
    @pytest.mark.asyncio
    async def test_decrypt_message(self):
        """Test decrypting message"""
        ciphertext = b"encrypted_data"
        expected_plaintext = b"Test message"
        
        self.mock_parent._decrypt_message = AsyncMock(return_value=expected_plaintext)
        
        plaintext = await self.message_encryption.decrypt_message(ciphertext)
        
        assert plaintext == expected_plaintext
        assert self.mock_parent._decrypt_message.called
