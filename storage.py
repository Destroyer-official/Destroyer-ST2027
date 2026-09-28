""" Secure key storage operations. Provides encrypted key storage and retrieval with security. """ 
import os 
import secrets
import time 
import logging 
from typing import Optional 
from base import BaseModule, KeyManagementError 

# Import secure key manager for actual storage operations 
try: 
    import secure_key_manager 
    SECURE_KEY_MANAGER_AVAILABLE = True 
except ImportError: 
    SECURE_KEY_MANAGER_AVAILABLE = False 

class KeyStorage(BaseModule): 
    """ Secure key storage operations. Provides secure storage and retrieval of cryptographic keys using the secure_key_manager module with hardware-backed protection when available. """ 
    def __init__(self, orchestrator): 
        """ Initialize key storage module. Args: orchestrator: Reference to the main orchestrator """ 
        super().__init__(orchestrator) 
        self.logger = logging.getLogger(__name__) 

    def store_key(self, key_material: bytes, key_name: str) -> str: 
        """ Store key securely using secure key manager. Args: key_material: The key material to store key_name: Identifier for the key Returns: str: Key identifier for retrieval. Raises KeyManagementError on any failure (fail-closed, 2028). """ 
        if not key_material or not key_name: 
            raise KeyManagementError(f"Invalid key material or key name provided", category="KEY_MGMT", severity="HIGH", module="keys.storage", function="store_key") 
        try: 
            # Delegate to _secure_key_storage for actual implementation 
            return self._secure_key_storage(key_material, key_name) 
        except KeyManagementError:
            raise
        except Exception as e: 
            self.logger.error(f"Key storage failed: {e}", exc_info=True) 
            raise KeyManagementError( f"Failed to store key '{key_name}': {e}", category="KEY_MGMT", severity="HIGH", module="keys.storage", function="store_key" ) 

    def retrieve_key(self, key_name: str) -> Optional[bytes]: 
        """ Retrieve key securely from storage. Args: key_name: Identifier for the key to retrieve Returns: bytes or None if not found. Raises KeyManagementError if backend unavailable (fail-closed, 2028). """ 
        if not key_name: 
            raise KeyManagementError(f"Invalid key name provided for retrieval", category="KEY_MGMT", severity="HIGH", module="keys.storage", function="retrieve_key") 
        try: 
            if not SECURE_KEY_MANAGER_AVAILABLE: 
                raise KeyManagementError(f"Secure key manager not available for key retrieval", category="KEY_MGMT", severity="HIGH", module="keys.storage", function="retrieve_key") 
            # Use secure key manager to retrieve the key 
            in_memory_only = getattr(self.orchestrator, 'in_memory_only', True) 
            retrieved_key = secure_key_manager.retrieve_key( key_name, in_memory_only=in_memory_only ) 
            if retrieved_key: 
                self.logger.debug(f"Key '{key_name}' retrieved successfully") 
            else: 
                self.logger.warning(f"Key '{key_name}' not found in storage") 
            return retrieved_key 
        except Exception as e: 
            self.logger.error(f"Key retrieval failed: {e}", exc_info=True) 
            raise KeyManagementError( f"Failed to retrieve key '{key_name}': {e}", category="KEY_MGMT", severity="HIGH", module="keys.storage", function="retrieve_key" ) 

    def _secure_key_storage(self, key_material: bytes, key_name: str) -> str: 
        """ Securely store sensitive key material. Args: key_material: The key material to store key_name: Identifier for the key Returns: str: Key identifier. Raises KeyManagementError on failure (fail-closed, 2028). """ 
        if not key_material or not key_name: 
            raise KeyManagementError(f"Invalid key material or key name", category="KEY_MGMT", severity="HIGH", module="keys.storage", function="_secure_key_storage") 
        try: 
            # Check if secure key manager is available 
            if not SECURE_KEY_MANAGER_AVAILABLE: 
                raise KeyManagementError(f"Secure key manager not available for key storage", category="KEY_MGMT", severity="HIGH", module="keys.storage", function="_secure_key_storage") 
            # Use secure key manager to store the key 
            in_memory_only = getattr(self.orchestrator, 'in_memory_only', True) 
            key_id = secure_key_manager.store_key( key_material=key_material, key_name=key_name, in_memory_only=in_memory_only ) 
            if key_id: 
                self.logger.debug(f"Key '{key_name}' stored securely with ID: {key_id}") 
                return key_id 
            else: 
                raise KeyManagementError(f"Failed to store key '{key_name}' securely (backend refused)", category="KEY_MGMT", severity="HIGH", module="keys.storage", function="_secure_key_storage") 
        except KeyManagementError:
            raise
        except Exception as e: 
            self.logger.error(f"Error storing key securely: {e}", exc_info=True) 
            raise KeyManagementError(f"Error storing key securely '{key_name}': {e}", category="KEY_MGMT", severity="HIGH", module="keys.storage", function="_secure_key_storage") 

    def _verify_key_storage(self) -> bool: 
        """ Verify that secure key storage is working properly. Returns: bool: True if secure key storage is available and working """ 
        try: 
            # Skip verification if secure key manager is not available 
            if not SECURE_KEY_MANAGER_AVAILABLE: 
                self.logger.warning("Secure key manager not available for verification") 
                return False 
            # Check if required methods are available 
            if not hasattr(secure_key_manager, 'store_key') or not hasattr(secure_key_manager, 'retrieve_key'): 
                self.logger.warning("Secure key manager missing required methods") 
                return False 
            # Generate test key 
            test_key = secrets.token_bytes(32) 
            test_name = f"verify_test_{int(time.time())}" 
            # Try to store and retrieve the key 
            in_memory_only = getattr(self.orchestrator, 'in_memory_only', True) 
            store_result = secure_key_manager.store_key( key_material=test_key, key_name=test_name, in_memory_only=in_memory_only ) 
            if not store_result: 
                self.logger.warning("Key storage verification failed: could not store test key") 
                return False 
            # Attempt to retrieve the key 
            retrieved_key = secure_key_manager.retrieve_key( test_name, in_memory_only=in_memory_only ) 
            if not retrieved_key or retrieved_key != test_key: 
                self.logger.warning("Key storage verification failed: retrieved key does not match original") 
                return False 
            # Cleanup the test key 
            if hasattr(secure_key_manager, 'delete_key'): 
                secure_key_manager.delete_key(test_name, in_memory_only=in_memory_only) 
            
            if in_memory_only: 
                self.logger.info("In-memory key storage verified successfully") 
            else: 
                self.logger.info("Persistent key storage verified successfully") 
            
            return True 
        except Exception as e: 
            self.logger.error(f"Key storage verification failed with error: {e}", exc_info=True) 
            return False
