"""
Minimal unit tests for keys module.

Tests core functionality of key storage, rotation, generation, and HSM integration.
"""

import pytest
import os
import sys
from unittest.mock import Mock, AsyncMock, patch, MagicMock


# Mock secure_key_manager before any imports to avoid initialization issues
sys.modules['secure_key_manager'] = MagicMock()


class TestKeysStorage:
    """Minimal tests for KeyStorage class"""
    
    @patch('secure_p2p_core.keys.storage.SECURE_KEY_MANAGER_AVAILABLE', True)
    @patch('secure_p2p_core.keys.storage.secure_key_manager')
    def test_storage_initialization(self, mock_skm):
        """Test KeyStorage can be initialized"""
        from secure_p2p_core.keys.storage import KeyStorage
        
        mock_orchestrator = Mock()
        mock_orchestrator.in_memory_only = True
        storage = KeyStorage(mock_orchestrator)
        
        assert storage is not None
        assert storage.orchestrator == mock_orchestrator
    
    @patch('secure_p2p_core.keys.storage.SECURE_KEY_MANAGER_AVAILABLE', True)
    @patch('secure_p2p_core.keys.storage.secure_key_manager')
    def test_store_and_retrieve_key(self, mock_skm):
        """Test basic key storage and retrieval"""
        from secure_p2p_core.keys.storage import KeyStorage
        
        mock_orchestrator = Mock()
        mock_orchestrator.in_memory_only = True
        storage = KeyStorage(mock_orchestrator)
        
        # Mock secure_key_manager responses
        mock_skm.store_key.return_value = "test_key_id"
        mock_skm.retrieve_key.return_value = b"test_key_material"
        
        # Test store
        key_id = storage.store_key(b"test_key_material", "test_key")
        assert key_id == "test_key_id"
        
        # Test retrieve
        retrieved = storage.retrieve_key("test_key")
        assert retrieved == b"test_key_material"


class TestKeysRotation:
    """Minimal tests for KeyRotation class"""
    
    def test_rotation_initialization(self):
        """Test KeyRotation can be initialized"""
        from secure_p2p_core.keys.rotation import KeyRotation
        
        mock_orchestrator = Mock()
        rotation = KeyRotation(mock_orchestrator)
        
        assert rotation is not None
        assert rotation.orchestrator == mock_orchestrator
    
    @pytest.mark.asyncio
    async def test_rotate_keys(self):
        """Test key rotation delegates to hybrid_kex"""
        from secure_p2p_core.keys.rotation import KeyRotation
        
        mock_orchestrator = Mock()
        mock_orchestrator.hybrid_kex = Mock()
        mock_orchestrator.hybrid_kex.rotate_keys = Mock(return_value=True)
        
        rotation = KeyRotation(mock_orchestrator)
        result = await rotation.rotate_keys()
        
        assert result is True
        assert mock_orchestrator.hybrid_kex.rotate_keys.called


class TestKeysGeneration:
    """Minimal tests for KeyGeneration class"""
    
    def test_generation_initialization(self):
        """Test KeyGeneration can be initialized"""
        from secure_p2p_core.keys.generation import KeyGeneration
        
        mock_orchestrator = Mock()
        generation = KeyGeneration(mock_orchestrator)
        
        assert generation is not None
        assert generation.orchestrator == mock_orchestrator
    
    def test_derive_auth_key(self):
        """Test authentication key derivation"""
        from secure_p2p_core.keys.generation import KeyGeneration
        
        mock_orchestrator = Mock()
        generation = KeyGeneration(mock_orchestrator)
        
        root_key = os.urandom(32)
        auth_key = generation._derive_auth_key(root_key)
        
        assert auth_key is not None
        assert len(auth_key) == 64  # SHA3-512 produces 64 bytes
        assert isinstance(auth_key, bytes)


class TestHSMIntegration:
    """Minimal tests for HSMIntegration class"""
    
    def test_hsm_initialization(self):
        """Test HSMIntegration can be initialized"""
        from secure_p2p_core.keys.hsm_integration import HSMIntegration
        
        mock_orchestrator = Mock()
        hsm = HSMIntegration(mock_orchestrator)
        
        assert hsm is not None
        assert hsm.orchestrator == mock_orchestrator
        assert hsm._hsm_initialized is False
    
    def test_hsm_availability_check(self):
        """Test HSM availability check"""
        from secure_p2p_core.keys.hsm_integration import HSMIntegration
        
        mock_orchestrator = Mock()
        hsm = HSMIntegration(mock_orchestrator)
        
        # Should return False when not initialized
        assert hsm.is_hsm_available() is False
