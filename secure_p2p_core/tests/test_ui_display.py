"""
Unit tests for ui/display.py module
"""

import pytest
from unittest.mock import Mock, patch
from secure_p2p_core.ui.display import UIDisplay


class TestUIDisplay:
    """Test suite for UIDisplay class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.ui_display = UIDisplay(self.mock_parent)
    
    def test_initialization(self):
        """Test UIDisplay initialization"""
        assert self.ui_display is not None
        assert self.ui_display.parent == self.mock_parent
    
    def test_print_banner(self):
        """Test printing banner"""
        with patch('builtins.print') as mock_print:
            self.ui_display.print_banner()
            assert mock_print.called
    
    def test_print_security_summary(self):
        """Test printing security summary"""
        with patch('builtins.print') as mock_print:
            self.ui_display.print_security_summary()
            assert mock_print.called
    
    def test_display_security_recommendations(self):
        """Test displaying security recommendations"""
        with patch('builtins.print') as mock_print:
            self.ui_display.display_security_recommendations()
            assert mock_print.called
    
    def test_get_hw_security_status(self):
        """Test getting hardware security status"""
        status = self.ui_display.get_hw_security_status()
        
        assert isinstance(status, dict)
        assert "hsm_available" in status or "tpm_available" in status or "status" in status
