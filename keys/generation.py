"""
Key generation operations.

Provides identity and ephemeral key generation for hybrid cryptographic protocols.
"""

import logging
from typing import Dict, Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as crypto_hashes

try:
    from ..base import BaseModule, KeyManagementError
except (ImportError, ValueError):
    from base import BaseModule, KeyManagementError


class KeyGeneration(BaseModule):
    """
    Key generation operations.
    
    Provides generation of identity keys, ephemeral keys, and derived keys
    for the hybrid post-quantum cryptographic protocol.
    """
    
    def __init__(self, orchestrator):
        """
        Initialize key generation module.
        
        Args:
            orchestrator: Reference to the main orchestrator
        """
        super().__init__(orchestrator)
        self.logger = logging.getLogger(__name__)
    
    def generate_identity_keys(self) -> Tuple[Dict[str, bytes], Dict[str, bytes]]:
        """
        Generate identity keypairs for hybrid key exchange.
        
        This method delegates to the hybrid key exchange module to generate
        both classical and post-quantum keypairs for identity authentication.
        
        Returns:
            Tuple[Dict[str, bytes], Dict[str, bytes]]: (public_keys, secret_keys)
            
        The returned dictionaries contain:
        - 'mlkem': ML-KEM-1024 keys for post-quantum key encapsulation
        - 'falcon': FALCON-1024 keys for post-quantum signatures
        """
        try:
            # Check if hybrid_kex is available
            if not hasattr(self.orchestrator, 'hybrid_kex') or not self.orchestrator.hybrid_kex:
                self.logger.error("Hybrid key exchange not available for key generation")
                raise KeyManagementError(
                    "Hybrid key exchange module not initialized",
                    category="KEY_MGMT",
                    severity="CRITICAL",
                    module="keys.generation",
                    function="generate_identity_keys"
                )
                
            # Delegate to hybrid_kex for actual key generation
            if hasattr(self.orchestrator.hybrid_kex, 'generate_identity_keys'):
                public_keys, secret_keys = self.orchestrator.hybrid_kex.generate_identity_keys()
                self.logger.info("Generated identity keys for hybrid key exchange")
                return public_keys, secret_keys
            else:
                self.logger.error("generate_identity_keys method not available in hybrid_kex")
                raise KeyManagementError(
                    "Key generation method not available",
                    category="KEY_MGMT",
                    severity="CRITICAL",
                    module="keys.generation",
                    function="generate_identity_keys"
                )
                
        except Exception as e:
            self.logger.error(f"Identity key generation failed: {e}", exc_info=True)
            raise KeyManagementError(
                f"Failed to generate identity keys: {e}",
                category="KEY_MGMT",
                severity="CRITICAL",
                module="keys.generation",
                function="generate_identity_keys"
            )
    
    def generate_ephemeral_keys(self) -> Dict[str, bytes]:
        """
        Generate ephemeral keypairs for forward secrecy.
        
        Ephemeral keys are short-lived keys used for individual sessions
        to provide forward secrecy. They are rotated regularly.
        
        Returns:
            dict: Dictionary containing ephemeral public and private keys
        """
        try:
            # Check if hybrid_kex is available
            if not hasattr(self.orchestrator, 'hybrid_kex') or not self.orchestrator.hybrid_kex:
                self.logger.error("Hybrid key exchange not available for ephemeral key generation")
                raise KeyManagementError(
                    "Hybrid key exchange module not initialized",
                    category="KEY_MGMT",
                    severity="HIGH",
                    module="keys.generation",
                    function="generate_ephemeral_keys"
                )
            
            # For ephemeral keys, we can use the same identity key generation
            # but mark them as ephemeral in the orchestrator
            public_keys, secret_keys = self.generate_identity_keys()
            
            # Combine into single dict for ephemeral use
            ephemeral_keys = {
                'public': public_keys,
                'secret': secret_keys,
                'ephemeral': True
            }
            
            self.logger.info("Generated ephemeral keys")
            return ephemeral_keys
            
        except Exception as e:
            self.logger.error(f"Ephemeral key generation failed: {e}", exc_info=True)
            raise KeyManagementError(
                f"Failed to generate ephemeral keys: {e}",
                category="KEY_MGMT",
                severity="HIGH",
                module="keys.generation",
                function="generate_ephemeral_keys"
            )
    
    def _derive_auth_key(self, root_key: bytes) -> bytes:
        """
        Derive a key confirmation key from the root key using a hardened KDF.
        
        This method uses HKDF with SHA3-512 to derive an authentication key
        from a shared root key. The derived key is used for key confirmation
        and authentication in the handshake protocol.
        
        Args:
            root_key: The root key material to derive from
            
        Returns:
            bytes: 64-byte derived authentication key
        """
        try:
            if not root_key:
                raise ValueError("Root key cannot be empty")
                
            # Use HKDF with SHA3-512 for key derivation
            hkdf = HKDF(
                algorithm=crypto_hashes.SHA3_512(),
                length=64,  # Use a 64-byte hash for authentication
                salt=b'p2p-key-auth-salt',
                info=b'hybrid-key-confirmation'
            )
            
            derived_key = hkdf.derive(root_key)
            self.logger.debug("Derived authentication key from root key")
            return derived_key
            
        except Exception as e:
            self.logger.error(f"Auth key derivation failed: {e}", exc_info=True)
            raise KeyManagementError(
                f"Failed to derive authentication key: {e}",
                category="KEY_MGMT",
                severity="HIGH",
                module="keys.generation",
                function="_derive_auth_key"
            )
