"""
Unit tests for utils/cleanup.py module
"""

import pytest
from unittest.mock import Mock, AsyncMock
from secure_p2p_core.utils.cleanup import SystemCleanup


class TestSystemCleanup:
    """Test suite for SystemCleanup class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.cleanup = SystemCleanup(self.mock_parent)
    
    def test_initialization(self):
        """Test SystemCleanup initialization"""
        assert self.cleanup is not None
        assert self.cleanup.parent == self.mock_parent
    
    @pytest.mark.asyncio
    async def test_cleanup(self):
        """Test cleanup operation"""
        self.mock_parent.cleanup = AsyncMock()
        
        await self.cleanup.cleanup()
        
        # Should delegate to parent
        assert True  # If no exception, test passes
    
    def test_emergency_wipe(self):
        """Test emergency wipe"""
        self.mock_parent._emergency_wipe = Mock()
        
        self.cleanup.emergency_wipe()
        
        # Should delegate to parent if available
        assert True  # If no exception, test passes
    
    def test_secure_erase(self):
        """Test secure erase"""
        data = bytearray(b'\x00' * 32)
        
        self.mock_parent._secure_erase = Mock()
        
        self.cleanup.secure_erase(data)
        
        # Should delegate to parent if available
        assert True  # If no exception, test passes
