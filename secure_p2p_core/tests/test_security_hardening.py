"""
Unit tests for security/hardening.py module
"""

import pytest
from unittest.mock import Mock
from secure_p2p_core.security.hardening import SecurityHardening


class TestSecurityHardening:
    """Test suite for SecurityHardening class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.security_hardening = SecurityHardening(self.mock_parent)
    
    def test_initialization(self):
        """Test SecurityHardening initialization"""
        assert self.security_hardening is not None
        assert self.security_hardening.parent == self.mock_parent
    
    def test_initialize_security_hardening(self):
        """Test security hardening initialization"""
        result = self.security_hardening.initialize_security_hardening()
        
        # Should return boolean
        assert isinstance(result, bool)
    
    def test_enforce_maximum_security(self):
        """Test enforcing maximum security"""
        result = self.security_hardening.enforce_maximum_security()
        
        # Should return boolean
        assert isinstance(result, bool)
    
    def test_enable_anti_debugging(self):
        """Test enabling anti-debugging"""
        result = self.security_hardening.enable_anti_debugging()
        
        # Should return boolean
        assert isinstance(result, bool)
