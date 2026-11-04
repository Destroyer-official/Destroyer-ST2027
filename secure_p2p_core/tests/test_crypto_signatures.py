"""
Unit tests for crypto/signatures.py module
"""

import pytest
import hashlib
from secure_p2p_core.crypto.signatures import SignatureOperations, MilitarySecurityError


class TestSignatureOperations:
    """Test suite for SignatureOperations class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.sig_ops = SignatureOperations()
    
    def test_initialization(self):
        """Test SignatureOperations initialization"""
        assert self.sig_ops is not None
        assert self.sig_ops._ml_dsa_87_signer is None
        assert self.sig_ops._slh_dsa_256f_signer is None
        assert self.sig_ops.hybrid_session_key is None
    
    def test_set_hybrid_session_key(self):
        """Test setting hybrid session key"""
        session_key = b'\x00' * 32
        self.sig_ops.set_hybrid_session_key(session_key)
        assert self.sig_ops.hybrid_session_key == session_key
    
    def test_set_peer_public_keys(self):
        """Test setting peer public keys"""
        ml_dsa_key = b'\x01' * 100
        slh_dsa_key = b'\x02' * 100
        
        self.sig_ops.set_peer_public_keys(ml_dsa_key, slh_dsa_key)
        assert self.sig_ops._peer_ml_dsa_87_public_key == ml_dsa_key
        assert self.sig_ops._peer_slh_dsa_256f_public_key == slh_dsa_key
    
    def test_get_public_keys(self):
        """Test getting own public keys"""
        ml_dsa_key, slh_dsa_key = self.sig_ops.get_public_keys()
        # Initially should be None
        assert ml_dsa_key is None
        assert slh_dsa_key is None
    
    @pytest.mark.asyncio
    async def test_generate_military_auth_tag(self):
        """Test generating military authentication tag"""
        # Set session key
        session_key = b'\x00' * 32
        self.sig_ops.set_hybrid_session_key(session_key)
        
        # Generate auth tag
        ciphertext = b"encrypted_data"
        message_hash = hashlib.sha3_512(b"original_message").digest()
        
        auth_tag = await self.sig_ops.generate_military_auth_tag(ciphertext, message_hash)
        
        # Auth tag should be 64 bytes (SHA3-512 output)
        assert len(auth_tag) == 64
        assert isinstance(auth_tag, bytes)
    
    @pytest.mark.asyncio
    async def test_verify_military_auth_tag(self):
        """Test verifying military authentication tag"""
        # Set session key
        session_key = b'\x00' * 32
        self.sig_ops.set_hybrid_session_key(session_key)
        
        # Generate auth tag
        ciphertext = b"encrypted_data"
        message_hash = hashlib.sha3_512(b"original_message").digest()
        auth_tag = await self.sig_ops.generate_military_auth_tag(ciphertext, message_hash)
        
        # Verify auth tag
        is_valid = await self.sig_ops.verify_military_auth_tag(ciphertext, message_hash, auth_tag)
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_verify_military_auth_tag_invalid(self):
        """Test verifying invalid military authentication tag"""
        # Set session key
        session_key = b'\x00' * 32
        self.sig_ops.set_hybrid_session_key(session_key)
        
        # Generate auth tag
        ciphertext = b"encrypted_data"
        message_hash = hashlib.sha3_512(b"original_message").digest()
        auth_tag = await self.sig_ops.generate_military_auth_tag(ciphertext, message_hash)
        
        # Tamper with auth tag
        tampered_tag = bytes([b ^ 0xFF for b in auth_tag])
        
        # Verify tampered tag
        is_valid = await self.sig_ops.verify_military_auth_tag(ciphertext, message_hash, tampered_tag)
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_verify_military_auth_tag_no_session_key(self):
        """Test verifying auth tag without session key"""
        ciphertext = b"encrypted_data"
        message_hash = hashlib.sha3_512(b"original_message").digest()
        auth_tag = b'\x00' * 64
        
        # Should return False when no session key is set
        is_valid = await self.sig_ops.verify_military_auth_tag(ciphertext, message_hash, auth_tag)
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_auth_tag_different_for_different_data(self):
        """Test that auth tags are different for different data"""
        session_key = b'\x00' * 32
        self.sig_ops.set_hybrid_session_key(session_key)
        
        ciphertext1 = b"encrypted_data_1"
        ciphertext2 = b"encrypted_data_2"
        message_hash = hashlib.sha3_512(b"original_message").digest()
        
        auth_tag1 = await self.sig_ops.generate_military_auth_tag(ciphertext1, message_hash)
        auth_tag2 = await self.sig_ops.generate_military_auth_tag(ciphertext2, message_hash)
        
        # Auth tags should be different for different ciphertexts
        assert auth_tag1 != auth_tag2
