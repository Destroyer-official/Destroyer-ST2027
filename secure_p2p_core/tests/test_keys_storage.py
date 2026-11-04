"""
Unit tests for keys/storage.py module
"""

import pytest
import os
from unittest.mock import Mock, patch
from secure_p2p_core.keys.storage import KeyStorage, SecurityError


class TestKeyStorage:
    """Test suite for KeyStorage class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.key_storage = KeyStorage(use_hsm=False, in_memory_only=True)
    
    def test_initialization(self):
        """Test KeyStorage initialization"""
        assert self.key_storage is not None
        assert self.key_storage.in_memory_only is True
        assert self.key_storage._hsm_available is False
        assert isinstance(self.key_storage._key_cache, dict)
    
    def test_store_key_in_memory(self):
        """Test storing key in memory"""
        key_material = b'\x00' * 32
        key_id = "test_key"
        
        result = self.key_storage.store_key_internal(key_id, key_material, in_memory_only=True)
        
        assert result is True
        assert key_id in self.key_storage._key_cache
    
    def test_retrieve_key_from_memory(self):
        """Test retrieving key from memory"""
        key_material = b'\x00' * 32
        key_id = "test_key"
        
        # Store key
        self.key_storage.store_key_internal(key_id, key_material, in_memory_only=True)
        
        # Retrieve key
        retrieved = self.key_storage.retrieve_key_internal(key_id)
        
        assert retrieved == key_material
    
    def test_retrieve_nonexistent_key(self):
        """Test retrieving non-existent key"""
        retrieved = self.key_storage.retrieve_key_internal("nonexistent")
        
        assert retrieved is None
    
    def test_delete_key(self):
        """Test deleting key"""
        key_material = b'\x00' * 32
        key_id = "test_key"
        
        # Store key
        self.key_storage.store_key_internal(key_id, key_material, in_memory_only=True)
        
        # Delete key
        result = self.key_storage.delete_key(key_id)
        
        assert result is True
        assert key_id not in self.key_storage._key_cache
    
    def test_secure_key_storage_legacy(self):
        """Test legacy secure_key_storage method"""
        key_material = b'\x00' * 32
        key_name = "legacy_key"
        
        key_id = self.key_storage.secure_key_storage(key_material, key_name)
        
        assert key_id == key_name
        assert key_name in self.key_storage._key_cache
    
    def test_secure_key_storage_empty_key(self):
        """Test secure_key_storage with empty key"""
        result = self.key_storage.secure_key_storage(b"", "test")
        
        assert result == ""
    
    def test_verify_key_storage(self):
        """Test key storage verification"""
        result = self.key_storage.verify_key_storage()
        
        # Should succeed for in-memory storage
        assert result is True
    
    def test_get_storage_location_memory(self):
        """Test getting storage location for memory-stored key"""
        key_id = "test_key"
        self.key_storage._key_cache[key_id] = b'\x00' * 32
        
        location = self.key_storage.get_storage_location(key_id)
        
        assert location == "memory"
    
    def test_hsm_integration_info(self):
        """Test getting HSM integration information"""
        info = self.key_storage.hsm_integration()
        
        assert isinstance(info, dict)
        assert "hsm_available" in info
        assert "status" in info
    
    def test_store_key_with_metadata(self):
        """Test storing key with metadata"""
        key_material = b'\x00' * 32
        key_id = "test_key"
        metadata = {"key_type": "SESSION", "algorithm": "AES-256"}
        
        result = self.key_storage.store_key_internal(
            key_id, key_material, metadata=metadata, in_memory_only=True
        )
        
        assert result is True
    
    def test_key_roundtrip(self):
        """Test complete key storage and retrieval roundtrip"""
        key_material = os.urandom(32)
        key_id = "roundtrip_key"
        
        # Store
        store_result = self.key_storage.store_key_internal(key_id, key_material, in_memory_only=True)
        assert store_result is True
        
        # Retrieve
        retrieved = self.key_storage.retrieve_key_internal(key_id)
        assert retrieved == key_material
        
        # Delete
        delete_result = self.key_storage.delete_key(key_id)
        assert delete_result is True
        
        # Verify deleted
        retrieved_after_delete = self.key_storage.retrieve_key_internal(key_id)
        assert retrieved_after_delete is None
