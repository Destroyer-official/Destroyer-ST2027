"""
Unit tests for network/io.py module
"""

import pytest
import socket
from unittest.mock import Mock, AsyncMock, patch
from secure_p2p_core.network.io import NetworkIO


class TestNetworkIO:
    """Test suite for NetworkIO class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.CONNECTION_TIMEOUT = 90
        self.network_io = NetworkIO(self.mock_parent)
    
    def test_initialization(self):
        """Test NetworkIO initialization"""
        assert self.network_io is not None
        assert self.network_io.parent == self.mock_parent
        assert self.network_io.connection_timeout == 90
        assert self.network_io.socket_buffer_size == 65536
    
    @pytest.mark.asyncio
    async def test_connect_to_peer_success(self):
        """Test successful peer connection"""
        self.mock_parent._connect_to_peer = AsyncMock(return_value=True)
        
        result = await self.network_io.connect_to_peer("127.0.0.1", 8000)
        
        assert result is True
        assert self.mock_parent._connect_to_peer.called
    
    @pytest.mark.asyncio
    async def test_connect_to_peer_failure(self):
        """Test failed peer connection"""
        self.mock_parent._connect_to_peer = AsyncMock(return_value=False)
        
        result = await self.network_io.connect_to_peer("127.0.0.1", 8000)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_connect_to_peer_exception(self):
        """Test peer connection with exception"""
        self.mock_parent._connect_to_peer = AsyncMock(side_effect=Exception("Connection error"))
        
        result = await self.network_io.connect_to_peer("127.0.0.1", 8000)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_handle_incoming_connection_success(self):
        """Test successful incoming connection handling"""
        mock_socket = Mock(spec=socket.socket)
        client_address = ("127.0.0.1", 12345)
        
        self.mock_parent._handle_incoming_connection = AsyncMock()
        
        await self.network_io.handle_incoming_connection(mock_socket, client_address, 8000)
        
        assert self.mock_parent._handle_incoming_connection.called
    
    @pytest.mark.asyncio
    async def test_handle_incoming_connection_exception(self):
        """Test incoming connection handling with exception"""
        mock_socket = Mock(spec=socket.socket)
        client_address = ("127.0.0.1", 12345)
        
        self.mock_parent._handle_incoming_connection = AsyncMock(
            side_effect=Exception("Handling error")
        )
        
        with pytest.raises(Exception):
            await self.network_io.handle_incoming_connection(mock_socket, client_address, 8000)
    
    @pytest.mark.asyncio
    async def test_send_message_with_parent_method(self):
        """Test sending message using parent's method"""
        mock_socket = Mock(spec=socket.socket)
        message = b"Test message"
        
        self.mock_parent._send_message = AsyncMock(return_value=True)
        
        result = await self.network_io.send_message(mock_socket, message)
        
        assert result is True
        assert self.mock_parent._send_message.called
    
    @pytest.mark.asyncio
    async def test_receive_message_with_parent_method(self):
        """Test receiving message using parent's method"""
        mock_socket = Mock(spec=socket.socket)
        expected_data = b"Received data"
        
        self.mock_parent._receive_message = AsyncMock(return_value=expected_data)
        
        result = await self.network_io.receive_message(mock_socket)
        
        assert result == expected_data
        assert self.mock_parent._receive_message.called
    
    def test_configure_socket(self):
        """Test socket configuration"""
        mock_socket = Mock(spec=socket.socket)
        
        self.network_io.configure_socket(mock_socket)
        
        # Verify socket configuration methods were called
        assert mock_socket.setblocking.called
        assert mock_socket.setsockopt.called
    
    def test_create_ssl_context(self):
        """Test SSL context creation"""
        with patch('ssl.create_default_context') as mock_create_context:
            mock_context = Mock()
            mock_create_context.return_value = mock_context
            
            context = self.network_io.create_ssl_context(
                cert_file="cert.pem",
                key_file="key.pem"
            )
            
            assert context == mock_context
            assert mock_context.load_cert_chain.called
