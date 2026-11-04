"""
Unit tests for network/handshake.py module
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, MagicMock
from secure_p2p_core.network.handshake import (
    HandshakeManager, HandshakeState, HandshakeContext
)


class TestHandshakeContext:
    """Test suite for HandshakeContext dataclass"""
    
    def test_initialization(self):
        """Test HandshakeContext initialization"""
        context = HandshakeContext(peer_id="test_peer")
        assert context.peer_id == "test_peer"
        assert context.state == HandshakeState.INIT
        assert context.shared_secret is None
        assert context.retry_count == 0
    
    def test_transition_to(self):
        """Test state transition"""
        context = HandshakeContext(peer_id="test_peer")
        context.transition_to(HandshakeState.CLIENT_HELLO_SENT, "test_function")
        
        assert context.state == HandshakeState.CLIENT_HELLO_SENT
        assert context.function == "test_function"
    
    def test_mark_failed(self):
        """Test marking handshake as failed"""
        context = HandshakeContext(peer_id="test_peer")
        context.mark_failed("Test error", "test_function")
        
        assert context.state == HandshakeState.FAILED
        assert context.error_message == "Test error"
        assert context.function == "test_function"


class TestHandshakeManager:
    """Test suite for HandshakeManager class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.mock_parent.hybrid_kex = Mock()
        self.handshake_mgr = HandshakeManager(self.mock_parent)
    
    def test_initialization(self):
        """Test HandshakeManager initialization"""
        assert self.handshake_mgr is not None
        assert self.handshake_mgr.parent == self.mock_parent
        assert self.handshake_mgr.handshake_timeout == 30.0
        assert self.handshake_mgr.max_retry_count == 3
    
    def test_create_handshake_context(self):
        """Test creating handshake context"""
        context = self.handshake_mgr._create_handshake_context("peer1")
        
        assert context.peer_id == "peer1"
        assert context.state == HandshakeState.INIT
        assert "peer1" in self.handshake_mgr._handshake_contexts
    
    def test_get_handshake_context(self):
        """Test retrieving handshake context"""
        context = self.handshake_mgr._create_handshake_context("peer1")
        retrieved = self.handshake_mgr._get_handshake_context("peer1")
        
        assert retrieved == context
        assert retrieved.peer_id == "peer1"
    
    def test_get_nonexistent_context(self):
        """Test retrieving non-existent context"""
        retrieved = self.handshake_mgr._get_handshake_context("nonexistent")
        assert retrieved is None
    
    def test_cleanup_handshake_context(self):
        """Test cleaning up handshake context"""
        context = self.handshake_mgr._create_handshake_context("peer1")
        context.shared_secret = b'\x00' * 32
        
        self.handshake_mgr._cleanup_handshake_context("peer1")
        
        assert "peer1" not in self.handshake_mgr._handshake_contexts
    
    @pytest.mark.asyncio
    async def test_initiate_handshake_success(self):
        """Test successful handshake initiation"""
        peer_bundle = {
            'identity': 'test_peer',
            'static_key': b'\x00' * 32,
            'kem_public_key': b'\x01' * 100
        }
        
        # Mock hybrid_kex.initiate_handshake
        self.mock_parent.hybrid_kex.initiate_handshake = Mock(
            return_value=({'handshake': 'data'}, b'\x00' * 32)
        )
        
        handshake_msg, root_key = await self.handshake_mgr.initiate_military_hybrid_kem_handshake(peer_bundle)
        
        assert handshake_msg == {'handshake': 'data'}
        assert root_key == b'\x00' * 32
        assert self.mock_parent.hybrid_kex.initiate_handshake.called
    
    @pytest.mark.asyncio
    async def test_initiate_handshake_no_hybrid_kex(self):
        """Test handshake initiation without hybrid_kex"""
        peer_bundle = {'identity': 'test_peer'}
        
        # Remove hybrid_kex
        delattr(self.mock_parent, 'hybrid_kex')
        
        with pytest.raises(Exception):  # Should raise SecurityError
            await self.handshake_mgr.initiate_military_hybrid_kem_handshake(peer_bundle)
    
    @pytest.mark.asyncio
    async def test_handle_handshake_missing_ciphertext(self):
        """Test handling handshake with missing ciphertext"""
        handshake_message = {'identity': 'test_peer'}
        
        with pytest.raises(Exception):  # Should raise SecurityError
            await self.handshake_mgr.handle_military_hybrid_kem_handshake(handshake_message)
    
    @pytest.mark.asyncio
    async def test_exchange_keys_client_no_context(self):
        """Test client key exchange creates context if missing"""
        self.mock_parent.peer_username = 'test_peer'
        self.mock_parent._exchange_hybrid_keys_client = AsyncMock(return_value=True)
        
        result = await self.handshake_mgr.exchange_hybrid_keys_client()
        
        assert result is True
        assert self.mock_parent._exchange_hybrid_keys_client.called
    
    @pytest.mark.asyncio
    async def test_exchange_keys_server_success(self):
        """Test successful server key exchange"""
        self.mock_parent.peer_username = 'test_peer'
        self.mock_parent._exchange_hybrid_keys_server = AsyncMock(return_value=True)
        
        result = await self.handshake_mgr.exchange_hybrid_keys_server()
        
        assert result is True
        assert self.mock_parent._exchange_hybrid_keys_server.called
    
    @pytest.mark.asyncio
    async def test_exchange_keys_server_timeout(self):
        """Test server key exchange timeout"""
        self.mock_parent.peer_username = 'test_peer'
        
        # Mock a slow operation that times out
        async def slow_exchange():
            await asyncio.sleep(100)
            return True
        
        self.mock_parent._exchange_hybrid_keys_server = slow_exchange
        self.handshake_mgr.key_exchange_timeout = 0.1  # Very short timeout
        
        with pytest.raises(Exception):  # Should raise SecurityError
            await self.handshake_mgr.exchange_hybrid_keys_server()
