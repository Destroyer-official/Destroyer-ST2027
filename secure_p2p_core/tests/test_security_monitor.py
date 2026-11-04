"""
Unit tests for security/monitor.py module
"""

import pytest
from unittest.mock import Mock, AsyncMock
from secure_p2p_core.security.monitor import SecurityMonitor


class TestSecurityMonitor:
    """Test suite for SecurityMonitor class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.security_monitor = SecurityMonitor(self.mock_parent)
    
    def test_initialization(self):
        """Test SecurityMonitor initialization"""
        assert self.security_monitor is not None
        assert self.security_monitor.parent == self.mock_parent
    
    @pytest.mark.asyncio
    async def test_start_monitoring(self):
        """Test starting security monitoring"""
        await self.security_monitor.start_monitoring()
        
        assert self.security_monitor._is_monitoring is True
        
        # Cleanup
        await self.security_monitor.stop_monitoring()
    
    @pytest.mark.asyncio
    async def test_stop_monitoring(self):
        """Test stopping security monitoring"""
        await self.security_monitor.start_monitoring()
        await self.security_monitor.stop_monitoring()
        
        assert self.security_monitor._is_monitoring is False
    
    @pytest.mark.asyncio
    async def test_canary_check(self):
        """Test canary check"""
        result = await self.security_monitor.canary_check()
        
        # Should return boolean
        assert isinstance(result, bool)
    
    @pytest.mark.asyncio
    async def test_runtime_integrity_check(self):
        """Test runtime integrity check"""
        result = await self.security_monitor.runtime_integrity_check()
        
        # Should return boolean
        assert isinstance(result, bool)
