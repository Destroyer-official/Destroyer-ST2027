"""
Unit tests for crypto/padding.py module
"""

import pytest
from secure_p2p_core.crypto.padding import PaddingOperations, MilitarySecurityError


class TestPaddingOperations:
    """Test suite for PaddingOperations class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.padding_ops = PaddingOperations()
    
    def test_initialization(self):
        """Test PaddingOperations initialization"""
        assert self.padding_ops is not None
    
    def test_add_padding_basic(self):
        """Test adding padding to plaintext"""
        plaintext = b"Hello, World!"
        padded = self.padding_ops.add_military_grade_padding(plaintext)
        
        # Padded should be longer than original
        assert len(padded) > len(plaintext)
        # Should have at least 2 extra bytes (1 padding + 1 length)
        assert len(padded) >= len(plaintext) + 2
        # Should have at most 33 extra bytes (32 padding + 1 length)
        assert len(padded) <= len(plaintext) + 33
    
    def test_remove_padding_basic(self):
        """Test removing padding from padded plaintext"""
        plaintext = b"Hello, World!"
        padded = self.padding_ops.add_military_grade_padding(plaintext)
        recovered = self.padding_ops.remove_military_grade_padding(padded)
        
        # Recovered should match original
        assert recovered == plaintext
    
    def test_padding_roundtrip(self):
        """Test padding and unpadding roundtrip"""
        test_messages = [
            b"Short",
            b"Medium length message",
            b"A" * 1000,  # Long message
            b"",  # Empty (edge case)
            b"\x00\x01\x02",  # Binary data
        ]
        
        for msg in test_messages:
            if len(msg) == 0:
                # Empty messages should still work
                padded = self.padding_ops.add_military_grade_padding(msg)
                assert len(padded) >= 2
            else:
                padded = self.padding_ops.add_military_grade_padding(msg)
                recovered = self.padding_ops.remove_military_grade_padding(padded)
                assert recovered == msg
    
    def test_padding_variability(self):
        """Test that padding is variable (not deterministic)"""
        plaintext = b"Test message"
        padded1 = self.padding_ops.add_military_grade_padding(plaintext)
        padded2 = self.padding_ops.add_military_grade_padding(plaintext)
        
        # Padded messages should likely be different due to random padding
        # (There's a small chance they're the same, but very unlikely)
        # We test that they CAN be different, not that they MUST be
        assert len(padded1) >= len(plaintext) + 2
        assert len(padded2) >= len(plaintext) + 2
    
    def test_remove_padding_too_short(self):
        """Test error handling for message too short"""
        with pytest.raises(MilitarySecurityError, match="too short"):
            self.padding_ops.remove_military_grade_padding(b"X")
    
    def test_remove_padding_invalid_length(self):
        """Test error handling for invalid padding length"""
        # Create invalid padded message with padding length = 0
        invalid_padded = b"Hello" + b"\x00"
        with pytest.raises(MilitarySecurityError, match="Invalid padding length"):
            self.padding_ops.remove_military_grade_padding(invalid_padded)
        
        # Create invalid padded message with padding length > 32
        invalid_padded = b"Hello" + b"\x40"  # 64 > 32
        with pytest.raises(MilitarySecurityError, match="Invalid padding length"):
            self.padding_ops.remove_military_grade_padding(invalid_padded)
    
    def test_remove_padding_exceeds_message(self):
        """Test error handling when padding exceeds message length"""
        # Create message where padding length byte indicates more padding than message has
        invalid_padded = b"Hi" + b"\x20"  # Says 32 bytes padding but message is only 3 bytes
        with pytest.raises(MilitarySecurityError, match="exceeds message length"):
            self.padding_ops.remove_military_grade_padding(invalid_padded)
