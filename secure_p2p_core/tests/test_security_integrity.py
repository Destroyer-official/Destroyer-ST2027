"""
Unit tests for security/integrity.py module
"""

import pytest
from unittest.mock import Mock
from secure_p2p_core.security.integrity import IntegrityChecker


class TestIntegrityChecker:
    """Test suite for IntegrityChecker class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.integrity_checker = IntegrityChecker(self.mock_parent)
    
    def test_initialization(self):
        """Test IntegrityChecker initialization"""
        assert self.integrity_checker is not None
        assert self.integrity_checker.parent == self.mock_parent
    
    def test_check_code_integrity(self):
        """Test code integrity check"""
        result = self.integrity_checker.check_code_integrity()
        
        # Should return boolean
        assert isinstance(result, bool)
    
    def test_check_config_integrity(self):
        """Test config integrity check"""
        result = self.integrity_checker.check_config_integrity()
        
        # Should return boolean
        assert isinstance(result, bool)
    
    def test_check_memory_integrity(self):
        """Test memory integrity check"""
        result = self.integrity_checker.check_memory_integrity()
        
        # Should return boolean
        assert isinstance(result, bool)
    
    def test_detect_memory_corruption(self):
        """Test memory corruption detection"""
        result = self.integrity_checker.detect_memory_corruption()
        
        # Should return boolean
        assert isinstance(result, bool)
