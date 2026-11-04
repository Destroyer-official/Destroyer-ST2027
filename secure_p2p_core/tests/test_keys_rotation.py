"""
Unit tests for keys/rotation.py module
"""

import pytest
from unittest.mock import Mock, AsyncMock
from secure_p2p_core.keys.rotation import KeyRotation


class TestKeyRotation:
    """Test suite for KeyRotation class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.key_rotation = KeyRotation(self.mock_parent)
    
    def test_initialization(self):
        """Test KeyRotation initialization"""
        assert self.key_rotation is not None
        assert self.key_rotation.parent == self.mock_parent
    
    @pytest.mark.asyncio
    async def test_rotate_keys_success(self):
        """Test successful key rotation"""
        self.mock_parent._rotate_keys = AsyncMock(return_value=True)
        
        result = await self.key_rotation.rotate_keys()
        
        assert result is True
        assert self.mock_parent._rotate_keys.called
    
    @pytest.mark.asyncio
    async def test_derive_auth_key(self):
        """Test deriving authentication key"""
        shared_secret = b'\x00' * 32
        
        self.mock_parent._derive_auth_key = Mock(return_value=b'\x01' * 32)
        
        auth_key = self.key_rotation.derive_auth_key(shared_secret)
        
        assert auth_key == b'\x01' * 32
        assert self.mock_parent._derive_auth_key.called
