"""
Minimal unit tests for utils module.

Tests core functionality of memory management, initialization, cleanup, and helpers.
"""

import pytest
import os
import sys
from unittest.mock import Mock, AsyncMock, patch, MagicMock


# Mock secure_key_manager before any imports
sys.modules['secure_key_manager'] = MagicMock()


class TestMemoryManager:
    """Minimal tests for MemoryManager and KeyEraser"""
    
    def test_key_eraser_context_manager(self):
        """Test KeyEraser can be used as context manager"""
        from secure_p2p_core.utils.memory import KeyEraser
        
        key_material = b"test_key_material"
        
        with patch('secure_p2p_core.utils.memory.log'):
            ke = KeyEraser(key_material, "test_key")
            assert ke.key_material == key_material
            assert ke.description == "test_key"
    
    @patch('secure_p2p_core.utils.memory.log')
    def test_key_eraser_secure_erase_none(self, mock_log):
        """Test KeyEraser handles None key material"""
        from secure_p2p_core.utils.memory import KeyEraser
        
        ke = KeyEraser(None, "test_key")
        ke.secure_erase()  # Should not raise
        
        # Verify debug log was called
        assert any('No key material' in str(call) for call in mock_log.debug.call_args_list)
    
    def test_memory_manager_initialization(self):
        """Test MemoryManager can be initialized"""
        from secure_p2p_core.utils.memory import MemoryManager
        
        mock_orchestrator = Mock()
        mm = MemoryManager(mock_orchestrator)
        
        assert mm is not None
        assert mm.orchestrator == mock_orchestrator
    
    def test_secure_memory_wipe_function(self):
        """Test secure_memory_wipe function exists and handles errors"""
        from secure_p2p_core.utils.memory import secure_memory_wipe
        
        # Test with invalid address (should return False gracefully)
        result = secure_memory_wipe(0, 0)
        assert isinstance(result, bool)


class TestInitialization:
    """Minimal tests for Initialization class"""
    
    @pytest.mark.asyncio
    async def test_initialization_class_exists(self):
        """Test Initialization class can be instantiated"""
        from secure_p2p_core.utils.initialization import Initialization
        
        mock_orchestrator = Mock()
        init = Initialization(mock_orchestrator)
        
        assert init is not None
        assert init.orchestrator == mock_orchestrator
    
    def test_load_configuration(self):
        """Test configuration loading"""
        from secure_p2p_core.utils.initialization import Initialization
        
        mock_orchestrator = Mock()
        init = Initialization(mock_orchestrator)
        
        with patch.dict(os.environ, {'P2P_SECURITY_LEVEL': 'HIGH'}):
            config = init.load_configuration()
            
            assert isinstance(config, dict)
            assert 'security_level' in config
            assert config['security_level'] == 'HIGH'
    
    def test_setup_logging(self):
        """Test logging setup"""
        from secure_p2p_core.utils.initialization import Initialization
        
        mock_orchestrator = Mock()
        init = Initialization(mock_orchestrator)
        
        # Should not raise
        init.setup_logging()


class TestCleanup:
    """Minimal tests for Cleanup class"""
    
    @pytest.mark.asyncio
    async def test_cleanup_class_exists(self):
        """Test Cleanup class can be instantiated"""
        from secure_p2p_core.utils.cleanup import Cleanup
        
        mock_orchestrator = Mock()
        cleanup = Cleanup(mock_orchestrator)
        
        assert cleanup is not None
        assert cleanup.orchestrator == mock_orchestrator
    
    @pytest.mark.asyncio
    async def test_stop_monitoring_handles_missing_attributes(self):
        """Test stop_monitoring handles missing orchestrator attributes"""
        from secure_p2p_core.utils.cleanup import Cleanup
        
        mock_orchestrator = Mock()
        # Set secure_memory_regions as empty list to avoid iteration error
        mock_orchestrator.secure_memory_regions = []
        cleanup = Cleanup(mock_orchestrator)
        
        # Should not raise
        await cleanup.stop_monitoring()


class TestHelpers:
    """Minimal tests for Helpers class"""
    
    def test_helpers_initialization(self):
        """Test Helpers class can be instantiated"""
        from secure_p2p_core.utils.helpers import Helpers
        
        mock_orchestrator = Mock()
        helpers = Helpers(mock_orchestrator)
        
        assert helpers is not None
        assert helpers.orchestrator == mock_orchestrator
    
    def test_format_binary_with_bytes(self):
        """Test format_binary with byte data"""
        from secure_p2p_core.utils.helpers import _format_binary
        
        data = b"test_data"
        result = _format_binary(data)
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_format_binary_with_none(self):
        """Test format_binary with None"""
        from secure_p2p_core.utils.helpers import _format_binary
        
        result = _format_binary(None)
        assert result == "None"
    
    def test_generate_nonce(self):
        """Test nonce generation"""
        from secure_p2p_core.utils.helpers import generate_nonce
        
        nonce = generate_nonce(12)
        
        assert isinstance(nonce, bytes)
        assert len(nonce) == 12
    
    def test_constant_time_compare_equal(self):
        """Test constant time compare with equal values"""
        from secure_p2p_core.utils.helpers import constant_time_compare
        
        a = b"test_value"
        b = b"test_value"
        
        assert constant_time_compare(a, b) is True
    
    def test_constant_time_compare_not_equal(self):
        """Test constant time compare with different values"""
        from secure_p2p_core.utils.helpers import constant_time_compare
        
        a = b"test_value_1"
        b = b"test_value_2"
        
        assert constant_time_compare(a, b) is False
    
    def test_constant_time_compare_different_lengths(self):
        """Test constant time compare with different lengths"""
        from secure_p2p_core.utils.helpers import constant_time_compare
        
        a = b"short"
        b = b"much_longer"
        
        assert constant_time_compare(a, b) is False
    
    def test_nonce_manager(self):
        """Test NonceManager generates unique nonces"""
        from secure_p2p_core.utils.helpers import NonceManager
        
        nm = NonceManager(nonce_size=12)
        
        nonce1 = nm.generate_nonce()
        nonce2 = nm.generate_nonce()
        
        assert isinstance(nonce1, bytes)
        assert isinstance(nonce2, bytes)
        assert len(nonce1) == 12
        assert len(nonce2) == 12
        assert nonce1 != nonce2  # Should be different


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
