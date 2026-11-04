"""
Performance metrics test for modularization

This test documents performance metrics before and after modularization.
"""

import pytest
import time
from unittest.mock import Mock


class TestPerformanceMetrics:
    """Test suite for documenting performance metrics"""
    
    def test_module_import_time(self):
        """Test that module imports are reasonably fast"""
        start_time = time.time()
        
        # Import key modules
        from secure_p2p_core.crypto import padding, signatures
        from secure_p2p_core.network import handshake, io, monitoring
        from secure_p2p_core.keys import storage, rotation
        
        end_time = time.time()
        import_time = end_time - start_time
        
        # Should import in less than 5 seconds
        assert import_time < 5.0, f"Module imports took {import_time:.2f}s"
        
        print(f"\nModule import time: {import_time:.3f}s")
    
    def test_handshake_manager_initialization(self):
        """Test HandshakeManager initialization performance"""
        from secure_p2p_core.network.handshake import HandshakeManager
        
        mock_parent = Mock()
        mock_parent.audit_logger = None
        
        start_time = time.time()
        
        # Initialize 100 times to get average
        for _ in range(100):
            mgr = HandshakeManager(mock_parent)
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 100
        
        # Should initialize in less than 10ms on average
        assert avg_time < 0.01, f"Average initialization took {avg_time*1000:.2f}ms"
        
        print(f"\nAverage HandshakeManager initialization: {avg_time*1000:.3f}ms")
    
    def test_padding_operations_performance(self):
        """Test padding operations performance"""
        from secure_p2p_core.crypto.padding import PaddingOperations
        
        padding_ops = PaddingOperations()
        test_data = b"Test message" * 100  # 1.2KB message
        
        # Test padding performance
        start_time = time.time()
        for _ in range(1000):
            padded = padding_ops.add_military_grade_padding(test_data)
        end_time = time.time()
        
        avg_padding_time = (end_time - start_time) / 1000
        
        # Should pad in less than 1ms on average
        assert avg_padding_time < 0.001, f"Average padding took {avg_padding_time*1000:.2f}ms"
        
        print(f"\nAverage padding operation: {avg_padding_time*1000:.3f}ms")
        
        # Test unpadding performance
        padded = padding_ops.add_military_grade_padding(test_data)
        start_time = time.time()
        for _ in range(1000):
            unpadded = padding_ops.remove_military_grade_padding(padded)
        end_time = time.time()
        
        avg_unpadding_time = (end_time - start_time) / 1000
        
        # Should unpad in less than 1ms on average
        assert avg_unpadding_time < 0.001, f"Average unpadding took {avg_unpadding_time*1000:.2f}ms"
        
        print(f"Average unpadding operation: {avg_unpadding_time*1000:.3f}ms")
    
    def test_key_storage_performance(self):
        """Test key storage performance"""
        from secure_p2p_core.keys.storage import KeyStorage
        
        key_storage = KeyStorage(use_hsm=False, in_memory_only=True)
        test_key = b'\x00' * 32
        
        # Test storage performance
        start_time = time.time()
        for i in range(100):
            key_storage.store_key_internal(f"test_key_{i}", test_key, in_memory_only=True)
        end_time = time.time()
        
        avg_store_time = (end_time - start_time) / 100
        
        # Should store in less than 5ms on average
        assert avg_store_time < 0.005, f"Average key storage took {avg_store_time*1000:.2f}ms"
        
        print(f"\nAverage key storage: {avg_store_time*1000:.3f}ms")
        
        # Test retrieval performance
        start_time = time.time()
        for i in range(100):
            retrieved = key_storage.retrieve_key_internal(f"test_key_{i}")
        end_time = time.time()
        
        avg_retrieve_time = (end_time - start_time) / 100
        
        # Should retrieve in less than 1ms on average
        assert avg_retrieve_time < 0.001, f"Average key retrieval took {avg_retrieve_time*1000:.2f}ms"
        
        print(f"Average key retrieval: {avg_retrieve_time*1000:.3f}ms")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
