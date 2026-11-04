"""
Test for handshake error fix - "Failed to synchronize with server"

This test verifies that the handshake synchronization error has been resolved
through better module organization and enhanced logging.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from secure_p2p_core.network.handshake import HandshakeManager, HandshakeState


class TestHandshakeFix:
    """Test suite for verifying handshake error fix"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.mock_parent.hybrid_kex = Mock()
        self.handshake_mgr = HandshakeManager(self.mock_parent)
    
    @pytest.mark.asyncio
    async def test_handshake_state_tracking(self):
        """Test that handshake states are properly tracked"""
        peer_id = "test_peer"
        context = self.handshake_mgr._create_handshake_context(peer_id)
        
        # Verify initial state
        assert context.state == HandshakeState.INIT
        
        # Test state transitions
        context.transition_to(HandshakeState.CLIENT_HELLO_SENT, "test_function")
        assert context.state == HandshakeState.CLIENT_HELLO_SENT
        
        context.transition_to(HandshakeState.KEY_EXCHANGE_SENT, "test_function")
        assert context.state == HandshakeState.KEY_EXCHANGE_SENT
        
        context.transition_to(HandshakeState.COMPLETE, "test_function")
        assert context.state == HandshakeState.COMPLETE
    
    @pytest.mark.asyncio
    async def test_handshake_error_logging(self):
        """Test that handshake errors are logged with proper context"""
        peer_id = "test_peer"
        context = self.handshake_mgr._create_handshake_context(peer_id)
        
        # Mark as failed
        error_msg = "Test synchronization error"
        context.mark_failed(error_msg, "test_function")
        
        # Verify error state
        assert context.state == HandshakeState.FAILED
        assert context.error_message == error_msg
        assert context.function == "test_function"
    
    @pytest.mark.asyncio
    async def test_handshake_timeout_handling(self):
        """Test that handshake timeouts are properly handled"""
        self.mock_parent.peer_username = 'test_peer'
        
        # Mock a slow operation that times out
        async def slow_exchange():
            await asyncio.sleep(100)
            return True
        
        self.mock_parent._exchange_hybrid_keys_server = slow_exchange
        self.handshake_mgr.key_exchange_timeout = 0.1  # Very short timeout
        
        # Should raise exception on timeout
        with pytest.raises(Exception):
            await self.handshake_mgr.exchange_hybrid_keys_server()
        
        # Verify context shows failure
        context = self.handshake_mgr._get_handshake_context('test_peer')
        if context:
            assert context.state == HandshakeState.FAILED
    
    @pytest.mark.asyncio
    async def test_handshake_retry_logic(self):
        """Test that handshake retry logic works correctly"""
        self.mock_parent.peer_username = 'test_peer'
        
        # Mock a function that fails first time, succeeds second time
        call_count = 0
        async def flaky_exchange():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("First attempt fails")
            return True
        
        self.mock_parent._exchange_hybrid_keys_client = flaky_exchange
        
        # Should succeed after retry
        result = await self.handshake_mgr.exchange_hybrid_keys_client()
        
        assert result is True
        assert call_count == 2  # Should have retried once
    
    @pytest.mark.asyncio
    async def test_handshake_context_cleanup(self):
        """Test that handshake context is properly cleaned up"""
        peer_id = "test_peer"
        context = self.handshake_mgr._create_handshake_context(peer_id)
        context.shared_secret = b'\x00' * 32
        
        # Verify context exists
        assert peer_id in self.handshake_mgr._handshake_contexts
        
        # Cleanup
        self.handshake_mgr._cleanup_handshake_context(peer_id)
        
        # Verify context is removed
        assert peer_id not in self.handshake_mgr._handshake_contexts
    
    @pytest.mark.asyncio
    async def test_enhanced_logging_context(self):
        """Test that enhanced logging includes module/function/state context"""
        peer_bundle = {
            'identity': 'test_peer',
            'static_key': b'\x00' * 32,
            'kem_public_key': b'\x01' * 100
        }
        
        # Mock hybrid_kex.initiate_handshake
        self.mock_parent.hybrid_kex.initiate_handshake = Mock(
            return_value=({'handshake': 'data'}, b'\x00' * 32)
        )
        
        # Initiate handshake
        handshake_msg, root_key = await self.handshake_mgr.initiate_military_hybrid_kem_handshake(peer_bundle)
        
        # Verify context was created and tracked
        context = self.handshake_mgr._get_handshake_context('test_peer')
        assert context is not None
        assert context.module == "network.handshake"
        assert context.state == HandshakeState.KEY_EXCHANGE_SENT
    
    def test_handshake_configuration(self):
        """Test that handshake configuration parameters are properly set"""
        assert self.handshake_mgr.handshake_timeout == 30.0
        assert self.handshake_mgr.key_exchange_timeout == 60.0
        assert self.handshake_mgr.ack_timeout == 30.0
        assert self.handshake_mgr.max_retry_count == 3
        assert self.handshake_mgr.retry_backoff_base == 2.0
    
    @pytest.mark.asyncio
    async def test_synchronization_acknowledgment(self):
        """Test that synchronization acknowledgment is properly handled"""
        # This test verifies that the handshake manager properly tracks
        # acknowledgment states to prevent synchronization errors
        
        peer_id = "test_peer"
        context = self.handshake_mgr._create_handshake_context(peer_id)
        
        # Simulate handshake progression
        context.transition_to(HandshakeState.CLIENT_HELLO_SENT, "test")
        context.transition_to(HandshakeState.KEY_EXCHANGE_SENT, "test")
        context.transition_to(HandshakeState.VERIFY_SENT, "test")
        context.transition_to(HandshakeState.ACK_RECEIVED, "test")
        context.transition_to(HandshakeState.COMPLETE, "test")
        
        # Verify final state
        assert context.state == HandshakeState.COMPLETE
        assert context.error_message is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
