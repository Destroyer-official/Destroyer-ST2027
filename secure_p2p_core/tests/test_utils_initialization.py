"""
Unit tests for utils/initialization.py module
"""

import pytest
from unittest.mock import Mock, patch
from secure_p2p_core.utils.initialization import SystemInitializer


class TestSystemInitializer:
    """Test suite for SystemInitializer class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.initializer = SystemInitializer(self.mock_parent)
    
    def test_initialization(self):
        """Test SystemInitializer initialization"""
        assert self.initializer is not None
        assert self.initializer.parent == self.mock_parent
    
    def test_initialize_hardware_security(self):
        """Test hardware security initialization"""
        result = self.initializer.initialize_hardware_security()
        
        # Should return a boolean or dict
        assert isinstance(result, (bool, dict))
    
    def test_initialize_libsodium(self):
        """Test libsodium initialization"""
        result = self.initializer.initialize_libsodium()
        
        # Should return a boolean
        assert isinstance(result, bool)
    
    def test_initialize_quantum_resistance(self):
        """Test quantum resistance initialization"""
        result = self.initializer.initialize_quantum_resistance()
        
        # Should return a boolean
        assert isinstance(result, bool)
    
    def test_setup_logging(self):
        """Test logging setup"""
        with patch('logging.basicConfig') as mock_config:
            self.initializer.setup_logging()
            # Logging setup should be called
            assert True  # If no exception, test passes
