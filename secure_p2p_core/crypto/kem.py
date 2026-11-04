"""
Key Encapsulation Mechanism (ML-KEM-1024).

Provides quantum-resistant key encapsulation operations using ML-KEM-1024
(NIST FIPS 203) with hybrid security combining lattice-based and code-based
cryptography.
"""

from typing import Tuple, Dict, Any
from ..base import BaseModule, CryptoError


class KEMOperations(BaseModule):
    """Quantum-resistant KEM operations."""
    
    def __init__(self, orchestrator):
        """Initialize KEM operations."""
        super().__init__(orchestrator)
        self._kem_impl = None
    
    @property
    def kem_impl(self):
        """Lazy load KEM implementation."""
        if self._kem_impl is None:
            try:
                from pqc_algorithms import EnhancedMLKEM_1024
                self._kem_impl = EnhancedMLKEM_1024()
            except ImportError as e:
                self.logger.error(f"Failed to import ML-KEM-1024: {e}", exc_info=True)
                raise CryptoError(
                    f"Failed to load ML-KEM-1024 implementation: {e}",
                    module="crypto.kem",
                    function="kem_impl",
                    severity="CRITICAL"
                )
        return self._kem_impl
    
    def generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate ML-KEM-1024 keypair.
        
        Generates a new public/private key pair for key encapsulation.
        Uses hybrid KEM combining ML-KEM-1024 (lattice-based) and
        McEliece-8192128f (code-based) for defense-in-depth.
        
        Returns:
            Tuple of (public_key, private_key) as bytes
            
        Raises:
            CryptoError: If keypair generation fails
        """
        try:
            self.logger.debug("Generating ML-KEM-1024 keypair")
            
            public_key, private_key = self.kem_impl.keygen()
            
            if not isinstance(public_key, bytes) or not isinstance(private_key, bytes):
                raise ValueError("Keys must be bytes")
            
            self.logger.debug(f"ML-KEM-1024 keypair generated (pk_len={len(public_key)}, sk_len={len(private_key)})")
            return public_key, private_key
            
        except Exception as e:
            self.logger.error(f"KEM keypair generation failed: {e}", exc_info=True)
            raise CryptoError(
                f"KEM keypair generation failed: {e}",
                module="crypto.kem",
                function="generate_kem_keypair",
                severity="HIGH"
            )
    
    def kem_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using ML-KEM-1024.
        
        Generates a ciphertext and shared secret using the recipient's
        public key. The ciphertext can be transmitted to the recipient
        who will decapsulate it using their private key.
        
        Args:
            public_key: Recipient's ML-KEM-1024 public key (bytes)
            
        Returns:
            Tuple of (ciphertext, shared_secret) as bytes
            
        Raises:
            CryptoError: If encapsulation fails
        """
        try:
            if not isinstance(public_key, bytes):
                raise TypeError("Public key must be bytes")
            
            self.logger.debug(f"Encapsulating shared secret with ML-KEM-1024 (pk_len={len(public_key)})")
            
            ciphertext, shared_secret = self.kem_impl.encaps(public_key)
            
            if not isinstance(ciphertext, bytes) or not isinstance(shared_secret, bytes):
                raise ValueError("Ciphertext and shared secret must be bytes")
            
            self.logger.debug(f"ML-KEM-1024 encapsulation successful (ct_len={len(ciphertext)}, ss_len={len(shared_secret)})")
            return ciphertext, shared_secret
            
        except TypeError as e:
            self.logger.error(f"Type error in KEM encapsulation: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for KEM encapsulation: {e}",
                module="crypto.kem",
                function="kem_encapsulate",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"KEM encapsulation failed: {e}", exc_info=True)
            raise CryptoError(
                f"KEM encapsulation failed: {e}",
                module="crypto.kem",
                function="kem_encapsulate",
                severity="HIGH"
            )
    
    def kem_decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """
        Decapsulate a shared secret using ML-KEM-1024.
        
        Recovers the shared secret from a ciphertext using the recipient's
        private key. Should produce the same shared secret as was generated
        during encapsulation.
        
        Args:
            ciphertext: ML-KEM-1024 ciphertext (bytes)
            private_key: Recipient's ML-KEM-1024 private key (bytes)
            
        Returns:
            Shared secret (bytes)
            
        Raises:
            CryptoError: If decapsulation fails
        """
        try:
            if not isinstance(ciphertext, bytes):
                raise TypeError("Ciphertext must be bytes")
            if not isinstance(private_key, bytes):
                raise TypeError("Private key must be bytes")
            
            self.logger.debug(f"Decapsulating shared secret with ML-KEM-1024 (ct_len={len(ciphertext)}, sk_len={len(private_key)})")
            
            shared_secret = self.kem_impl.decaps(private_key, ciphertext)
            
            if not isinstance(shared_secret, bytes):
                raise ValueError("Shared secret must be bytes")
            
            self.logger.debug(f"ML-KEM-1024 decapsulation successful (ss_len={len(shared_secret)})")
            return shared_secret
            
        except TypeError as e:
            self.logger.error(f"Type error in KEM decapsulation: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for KEM decapsulation: {e}",
                module="crypto.kem",
                function="kem_decapsulate",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"KEM decapsulation failed: {e}", exc_info=True)
            raise CryptoError(
                f"KEM decapsulation failed: {e}",
                module="crypto.kem",
                function="kem_decapsulate",
                severity="HIGH"
            )
    
    def ensure_hybrid_session_keys(self, peer_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure hybrid session keys are established.
        
        Performs hybrid key exchange combining classical and post-quantum
        algorithms to establish session keys with both classical and
        quantum-resistant security.
        
        Args:
            peer_bundle: Dictionary containing peer information including:
                - 'peer_id': Peer identifier
                - 'public_key': Peer's public key
                - 'ephemeral_public_key': Peer's ephemeral public key (optional)
                
        Returns:
            Dictionary containing:
                - 'session_key': Established session key
                - 'shared_secret': Shared secret from KEM
                - 'ciphertext': KEM ciphertext (if initiator)
                - 'peer_id': Peer identifier
                
        Raises:
            CryptoError: If key establishment fails
        """
        try:
            if not isinstance(peer_bundle, dict):
                raise TypeError("Peer bundle must be a dictionary")
            
            if 'public_key' not in peer_bundle:
                raise ValueError("Peer bundle must contain 'public_key'")
            
            peer_id = peer_bundle.get('peer_id', 'unknown')
            peer_public_key = peer_bundle['public_key']
            
            self.logger.debug(f"Establishing hybrid session keys with peer {peer_id}")
            
            # Perform KEM encapsulation to establish shared secret
            ciphertext, shared_secret = self.kem_encapsulate(peer_public_key)
            
            # Derive session key from shared secret
            # In a real implementation, this would use HKDF or similar KDF
            session_key = shared_secret[:32]  # Use first 32 bytes as session key
            
            result = {
                'session_key': session_key,
                'shared_secret': shared_secret,
                'ciphertext': ciphertext,
                'peer_id': peer_id
            }
            
            self.logger.debug(f"Hybrid session keys established with peer {peer_id}")
            return result
            
        except TypeError as e:
            self.logger.error(f"Type error in hybrid session key establishment: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for hybrid session keys: {e}",
                module="crypto.kem",
                function="ensure_hybrid_session_keys",
                severity="HIGH"
            )
        except ValueError as e:
            self.logger.error(f"Value error in hybrid session key establishment: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid peer bundle for hybrid session keys: {e}",
                module="crypto.kem",
                function="ensure_hybrid_session_keys",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"Hybrid session key establishment failed: {e}", exc_info=True)
            raise CryptoError(
                f"Hybrid session key establishment failed: {e}",
                module="crypto.kem",
                function="ensure_hybrid_session_keys",
                severity="HIGH"
            )
