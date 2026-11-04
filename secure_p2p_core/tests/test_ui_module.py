"""
Unit tests for UI module (display, prompts, menus)
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from secure_p2p_core.ui.display import DisplayManager
from secure_p2p_core.ui.prompts import PromptManager
from secure_p2p_core.ui.menus import MenuManager


class TestDisplayManager:
    """Test suite for DisplayManager class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_orchestrator = Mock()
        self.display_manager = DisplayManager(self.mock_orchestrator)
    
    def test_initialization(self):
        """Test DisplayManager initialization"""
        assert self.display_manager is not None
        assert self.display_manager.orchestrator == self.mock_orchestrator
    
    def test_display_banner(self):
        """Test displaying banner"""
        with patch('builtins.print') as mock_print:
            self.display_manager.display_banner()
            assert mock_print.called
    
    def test_print_security_summary(self):
        """Test printing security summary"""
        with patch('builtins.print') as mock_print:
            self.display_manager.print_security_summary()
            # Should log to security_summary_logger, not print
            # Just verify no exceptions
    
    def test_get_hw_security_status(self):
        """Test getting hardware security status"""
        status = self.display_manager.get_hw_security_status()
        assert isinstance(status, str)
        assert status in ["[OK] Windows TPM", "[--] Software Only", "[??] Unknown"] or status.startswith("[OK]")
    
    def test_get_memory_protection_status(self):
        """Test getting memory protection status"""
        status = self.display_manager.get_memory_protection_status()
        assert isinstance(status, str)
        assert "[OK]" in status or "[??]" in status
    
    def test_display_message(self):
        """Test displaying a message"""
        with patch('builtins.print') as mock_print:
            self.display_manager.display_message("TestUser", "Hello", 1234567890.0)
            assert mock_print.called
    
    def test_display_menu(self):
        """Test displaying a menu"""
        with patch('builtins.print') as mock_print:
            options = ["Option 1", "Option 2", "Option 3"]
            self.display_manager.display_menu(options)
            assert mock_print.called
    
    def test_display_status(self):
        """Test displaying status"""
        with patch('builtins.print') as mock_print:
            status = {"connected": True, "peers": 2}
            self.display_manager.display_status(status)
            assert mock_print.called


class TestPromptManager:
    """Test suite for PromptManager class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_orchestrator = Mock()
        self.prompt_manager = PromptManager(self.mock_orchestrator)
    
    def test_initialization(self):
        """Test PromptManager initialization"""
        assert self.prompt_manager is not None
        assert self.prompt_manager.orchestrator == self.mock_orchestrator
    
    @pytest.mark.asyncio
    async def test_async_input(self):
        """Test async input"""
        with patch('builtins.input', return_value="test input"):
            result = await self.prompt_manager.async_input("Enter something: ")
            assert result == "test input"
    
    @pytest.mark.asyncio
    async def test_async_input_eof(self):
        """Test async input with EOF"""
        with patch('builtins.input', side_effect=EOFError):
            result = await self.prompt_manager.async_input("Enter something: ")
            assert result == "exit"
    
    def test_prompt_user(self):
        """Test prompt user"""
        with patch('builtins.input', return_value="test"):
            result = self.prompt_manager.prompt_user("Enter: ")
            assert result == "test"
    
    def test_get_user_input_no_validator(self):
        """Test get user input without validator"""
        with patch('builtins.input', return_value="test"):
            result = self.prompt_manager.get_user_input("Enter: ")
            assert result == "test"
    
    def test_get_user_input_with_validator(self):
        """Test get user input with validator"""
        validator = lambda x: len(x) > 3
        with patch('builtins.input', side_effect=["ab", "abcd"]):
            result = self.prompt_manager.get_user_input("Enter: ", validator)
            assert result == "abcd"
    
    def test_confirm_action_yes(self):
        """Test confirm action with yes"""
        with patch('builtins.input', return_value="yes"):
            result = self.prompt_manager.confirm_action("Confirm?")
            assert result is True
    
    def test_confirm_action_no(self):
        """Test confirm action with no"""
        with patch('builtins.input', return_value="no"):
            result = self.prompt_manager.confirm_action("Confirm?")
            assert result is False
    
    def test_get_secure_input(self):
        """Test get secure input"""
        with patch('getpass.getpass', return_value="secret"):
            result = self.prompt_manager.get_secure_input("Password: ")
            assert result == "secret"


class TestMenuManager:
    """Test suite for MenuManager class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_orchestrator = Mock()
        self.mock_orchestrator.ui = Mock()
        self.mock_orchestrator.ui.prompts = Mock()
        self.mock_orchestrator.data = Mock()
        self.mock_orchestrator.data.peer_mgmt = Mock()
        self.mock_orchestrator.data.user_mgmt = Mock()
        self.mock_orchestrator.network = Mock()
        self.mock_orchestrator.network.connection = Mock()
        self.menu_manager = MenuManager(self.mock_orchestrator)
    
    def test_initialization(self):
        """Test MenuManager initialization"""
        assert self.menu_manager is not None
        assert self.menu_manager.orchestrator == self.mock_orchestrator
    
    @pytest.mark.asyncio
    async def test_handle_connections_not_implemented(self):
        """Test handle_connections raises NotImplementedError"""
        with pytest.raises(NotImplementedError):
            await self.menu_manager.handle_connections()
    
    def test_show_stored_peers_empty(self):
        """Test show stored peers with empty list"""
        self.mock_orchestrator.data.peer_mgmt.list_peers.return_value = []
        with patch('builtins.print') as mock_print:
            self.menu_manager.show_stored_peers()
            assert mock_print.called
    
    def test_show_stored_peers_with_data(self):
        """Test show stored peers with data"""
        peers = [
            {
                'username': 'user1',
                'display_name': 'User One',
                'ipv6': '::1',
                'port': 50007,
                'last_seen': 'Recently',
                'connection_status': 'Online'
            }
        ]
        self.mock_orchestrator.data.peer_mgmt.list_peers.return_value = peers
        with patch('builtins.print') as mock_print:
            self.menu_manager.show_stored_peers()
            assert mock_print.called
