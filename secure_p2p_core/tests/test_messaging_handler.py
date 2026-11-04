"""
Unit tests for messaging/handler.py module
"""

import pytest
from unittest.mock import Mock, AsyncMock
from secure_p2p_core.messaging.handler import MessageHandler


class TestMessageHandler:
    """Test suite for MessageHandler class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_parent = Mock()
        self.mock_parent.audit_logger = None
        self.message_handler = MessageHandler(self.mock_parent)
    
    def test_initialization(self):
        """Test MessageHandler initialization"""
        assert self.message_handler is not None
        assert self.message_handler.parent == self.mock_parent
    
    @pytest.mark.asyncio
    async def test_receive_messages(self):
        """Test receiving messages"""
        self.mock_parent._receive_messages = AsyncMock()
        
        await self.message_handler.receive_messages()
        
        assert self.mock_parent._receive_messages.called
    
    @pytest.mark.asyncio
    async def test_handle_command(self):
        """Test handling command"""
        command = "/help"
        
        self.mock_parent._handle_command = AsyncMock()
        
        await self.message_handler.handle_command(command)
        
        assert self.mock_parent._handle_command.called
