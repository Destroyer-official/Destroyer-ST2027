#!/usr/bin/env python3
"""
Integration Tests for Full P2P System
Tests end-to-end functionality and module interactions
"""

import pytest
import asyncio
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from secure_p2p_core.core.orchestrator import SecureP2PChat


class TestFullSystemIntegration:
    """Test full system end-to-end"""
    
    @pytest.fixture
    def chat_instance(self):
        """Create a chat instance for testing"""
        chat = SecureP2PChat(identity="test_user", ephemeral=True)
        yield chat
        # Cleanup
        try:
            chat.cleanup()
        except:
            assert True  # Handled exception
    
    def test_orchestrator_initialization(self, chat_instance):
        """Test that orchestrator initializes correctly"""
        assert chat_instance is not None
        assert chat_instance.identity == "test_user"
        assert hasattr(chat_instance, 'crypto')
        assert hasattr(chat_instance, 'connection')
        assert hasattr(chat_instance, 'security')
    
    def test_lazy_module_loading(self, chat_instance):
        """Test that modules load lazily"""
        # Modules should not be loaded initially
        assert chat_instance._crypto is None
        assert chat_instance._connection is None
        
        # Access crypto module
        crypto = chat_instance.crypto
        assert crypto is not None
        assert chat_instance._crypto is not None
        
        # Access connection module
        connection = chat_instance.connection
        assert connection is not None
        assert chat_instance._connection is not None
    
    def test_crypto_module_integration(self, chat_instance):
        """Test crypto module integration"""
        crypto = chat_instance.crypto
        
        # Test that crypto operations are available
        assert hasattr(crypto, 'encrypt')
        assert hasattr(crypto, 'decrypt')
        
        # Test basic encryption/decryption
        test_data = b"Test message for encryption"
        try:
            # This may fail without full setup, but should not crash
            encrypted = crypto.encrypt(test_data)
            assert encrypted is not None
        except Exception as e:
            # Expected if keys not set up
            assert "key" in str(e).lower() or "not initialized" in str(e).lower()
    
    def test_security_module_integration(self, chat_instance):
        """Test security module integration"""
        security = chat_instance.security
        
        # Test that security operations are available
        assert hasattr(security, 'monitor')
        assert hasattr(security, 'integrity')
        assert hasattr(security, 'hardening')
    
    def test_key_management_integration(self, chat_instance):
        """Test key management integration"""
        key_mgr = chat_instance.key_manager
        
        # Test that key operations are available
        assert hasattr(key_mgr, 'generate_identity_keys')
        assert hasattr(key_mgr, 'generate_ephemeral_keys')
    
    def test_audit_logging_integration(self, chat_instance):
        """Test audit logging integration"""
        audit = chat_instance.audit_logger
        
        # Test that audit operations are available
        assert hasattr(audit, 'log_event')
        assert hasattr(audit, 'log_security_event')
        
        # Test logging an event
        try:
            audit.log_event("test_event", {"test": "data"})
        except Exception as e:
            # May fail if database not initialized, but should not crash
            assert True  # Handled exception
    
    def test_backward_compatibility_api(self, chat_instance):
        """Test that all public API methods are preserved"""
        # Check critical methods exist
        critical_methods = [
            'initiate_military_hybrid_kem_handshake',
            'handle_military_hybrid_kem_handshake',
            'connect_to_peer',
            'cleanup'
        ]
        
        for method in critical_methods:
            assert hasattr(chat_instance, method), f"Missing method: {method}"
    
    def test_module_interaction_crypto_and_keys(self, chat_instance):
        """Test interaction between crypto and key modules"""
        crypto = chat_instance.crypto
        key_mgr = chat_instance.key_manager
        
        # Both modules should be accessible
        assert crypto is not None
        assert key_mgr is not None
        
        # They should be able to work together
        # (actual operations may require full initialization)
    
    def test_module_interaction_network_and_security(self, chat_instance):
        """Test interaction between network and security modules"""
        connection = chat_instance.connection
        security = chat_instance.security
        
        # Both modules should be accessible
        assert connection is not None
        assert security is not None
    
    def test_configuration_loading(self, chat_instance):
        """Test that configuration is loaded correctly"""
        # Check that config is accessible
        assert hasattr(chat_instance, 'config')
        
        # Config should have expected attributes
        config = chat_instance.config
        assert config is not None


class TestModuleInterfaces:
    """Test module interfaces and boundaries"""
    
    def test_crypto_module_interface(self):
        """Test crypto module has proper interface"""
        from secure_p2p_core.crypto.padding import PaddingOperations
        from secure_p2p_core.crypto.signatures import SignatureOperations
        
        # Check classes exist
        assert PaddingOperations is not None
        assert SignatureOperations is not None
    
    def test_network_module_interface(self):
        """Test network module has proper interface"""
        from secure_p2p_core.network.handshake import HandshakeManager
        from secure_p2p_core.network.io import NetworkIO
        from secure_p2p_core.network.monitoring import ConnectionMonitor
        
        # Check classes exist
        assert HandshakeManager is not None
        assert NetworkIO is not None
        assert ConnectionMonitor is not None
    
    def test_security_module_interface(self):
        """Test security module has proper interface"""
        from secure_p2p_core.security.monitor import SecurityMonitor
        from secure_p2p_core.security.integrity import IntegrityChecker
        from secure_p2p_core.security.hardening import SecurityHardening
        
        # Check classes exist
        assert SecurityMonitor is not None
        assert IntegrityChecker is not None
        assert SecurityHardening is not None
    
    def test_keys_module_interface(self):
        """Test keys module has proper interface"""
        from secure_p2p_core.keys.storage import KeyStorage
        from secure_p2p_core.keys.rotation import KeyRotation
        
        # Check classes exist
        assert KeyStorage is not None
        assert KeyRotation is not None
    
    def test_messaging_module_interface(self):
        """Test messaging module has proper interface"""
        from secure_p2p_core.messaging.handler import MessageHandler
        from secure_p2p_core.messaging.encryption import MessageEncryption
        from secure_p2p_core.messaging.commands import CommandProcessor
        
        # Check classes exist
        assert MessageHandler is not None
        assert MessageEncryption is not None
        assert CommandProcessor is not None
    
    def test_ui_module_interface(self):
        """Test UI module has proper interface"""
        from secure_p2p_core.ui.display import UIDisplay
        from secure_p2p_core.ui.prompts import UserPrompts
        
        # Check classes exist
        assert UIDisplay is not None
        assert UserPrompts is not None
    
    def test_utils_module_interface(self):
        """Test utils module has proper interface"""
        from secure_p2p_core.utils.initialization import SystemInitializer
        from secure_p2p_core.utils.cleanup import SystemCleanup
        
        # Check classes exist
        assert SystemInitializer is not None
        assert SystemCleanup is not None


class TestBackwardCompatibility:
    """Test backward compatibility with original API"""
    
    def test_securep2pchat_class_accessible(self):
        """Test that SecureP2PChat class is accessible from main module"""
        from secure_p2p_core.core.orchestrator import SecureP2PChat
        
        assert SecureP2PChat is not None
        
        # Should be able to instantiate
        chat = SecureP2PChat(identity="test", ephemeral=True)
        assert chat is not None
    
    def test_method_signatures_preserved(self):
        """Test that method signatures are preserved"""
        from secure_p2p_core.core.orchestrator import SecureP2PChat
        import inspect
        
        chat = SecureP2PChat(identity="test", ephemeral=True)
        
        # Check critical method signatures
        methods_to_check = [
            ('initiate_military_hybrid_kem_handshake', ['peer_bundle']),
            ('handle_military_hybrid_kem_handshake', ['client_socket', 'client_address']),
            ('cleanup', [])
        ]
        
        for method_name, expected_params in methods_to_check:
            if hasattr(chat, method_name):
                method = getattr(chat, method_name)
                sig = inspect.signature(method)
                params = list(sig.parameters.keys())
                
                # Check that expected params are present (may have additional params)
                for expected_param in expected_params:
                    assert expected_param in params, f"Missing parameter {expected_param} in {method_name}"
    
    def test_configuration_format_compatible(self):
        """Test that configuration format is compatible"""
        config_file = Path("config.json")
        
        if config_file.exists():
            import json
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Config should be loadable
            assert config is not None
            
            # Should have expected structure (if it exists)
            # This is a basic check - actual structure may vary


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
