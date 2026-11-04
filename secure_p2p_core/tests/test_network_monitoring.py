"""
Unit tests for network/monitoring.py module
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from secure_p2p_core.network.monitoring import ConnectionMonitor, ConnectionMetrics


class TestConnectionMetrics:
    """Test suite for ConnectionMetrics dataclass"""
    
    def test_initialization(self):
        """Test ConnectionMetrics initialization"""
        metrics = ConnectionMetrics()
        assert metrics.last_heartbeat_sent == 0.0
        assert metrics.last_heartbeat_received == 0.0
        assert metrics.missed_heartbeats == 0
        assert metrics.connection_quality == 1.0
        assert metrics.total_heartbeats_sent == 0


class TestConnectionMonitor:
    """Test suite for ConnectionMonitor class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.HEARTBEAT_INTERVAL = 30.0
        self.mock_parent.audit_logger = None
        self.monitor = ConnectionMonitor(self.mock_parent)
    
    def test_initialization(self):
        """Test ConnectionMonitor initialization"""
        assert self.monitor is not None
        assert self.monitor.parent == self.mock_parent
        assert self.monitor.heartbeat_interval == 30.0
        assert self.monitor.max_missed_heartbeats == 3
        assert isinstance(self.monitor.metrics, ConnectionMetrics)
    
    @pytest.mark.asyncio
    async def test_start_monitoring(self):
        """Test starting connection monitoring"""
        await self.monitor.start_monitoring()
        
        assert self.monitor._is_monitoring is True
        assert self.monitor._monitoring_task is not None
        assert self.monitor._heartbeat_task is not None
        
        # Cleanup
        await self.monitor.stop_monitoring()
    
    @pytest.mark.asyncio
    async def test_stop_monitoring(self):
        """Test stopping connection monitoring"""
        await self.monitor.start_monitoring()
        await self.monitor.stop_monitoring()
        
        assert self.monitor._is_monitoring is False
    
    @pytest.mark.asyncio
    async def test_start_monitoring_already_started(self):
        """Test starting monitoring when already started"""
        await self.monitor.start_monitoring()
        
        # Try to start again
        await self.monitor.start_monitoring()
        
        assert self.monitor._is_monitoring is True
        
        # Cleanup
        await self.monitor.stop_monitoring()
    
    @pytest.mark.asyncio
    async def test_handle_heartbeat_response(self):
        """Test handling heartbeat response"""
        heartbeat_data = {'timestamp': 1000.0}
        
        await self.monitor.handle_heartbeat_response(heartbeat_data)
        
        assert self.monitor.metrics.total_heartbeats_received == 1
        assert self.monitor.metrics.missed_heartbeats == 0
        assert self.monitor.metrics.last_heartbeat_received > 0
    
    @pytest.mark.asyncio
    async def test_handle_connection_failure(self):
        """Test handling connection failure"""
        await self.monitor.handle_connection_failure()
        
        assert self.monitor.metrics.connection_failures == 1
        assert self.monitor.metrics.last_failure_time > 0
    
    @pytest.mark.asyncio
    async def test_assess_connection_quality_perfect(self):
        """Test connection quality assessment with perfect connection"""
        quality = await self.monitor._assess_connection_quality()
        
        # Perfect connection should have quality 1.0
        assert quality == 1.0
        assert self.monitor.metrics.connection_quality == 1.0
    
    @pytest.mark.asyncio
    async def test_assess_connection_quality_with_missed_heartbeats(self):
        """Test connection quality assessment with missed heartbeats"""
        self.monitor.metrics.missed_heartbeats = 2
        
        quality = await self.monitor._assess_connection_quality()
        
        # Quality should be reduced due to missed heartbeats
        assert quality < 1.0
        assert quality >= 0.0
    
    def test_get_metrics(self):
        """Test getting connection metrics"""
        metrics = self.monitor.get_metrics()
        
        assert isinstance(metrics, ConnectionMetrics)
        assert metrics == self.monitor.metrics
    
    def test_reset_metrics(self):
        """Test resetting connection metrics"""
        # Modify metrics
        self.monitor.metrics.missed_heartbeats = 5
        self.monitor.metrics.connection_failures = 3
        
        # Reset
        self.monitor.reset_metrics()
        
        # Verify reset
        assert self.monitor.metrics.missed_heartbeats == 0
        assert self.monitor.metrics.connection_failures == 0
        assert self.monitor.metrics.connection_quality == 1.0
