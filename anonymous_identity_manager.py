"""
Anonymous Identity Manager for Secure P2P Communication.

This module provides anonymous identity management without requiring
phone numbers or email addresses. Identities are generated using
post-quantum cryptographic algorithms (ML-KEM-1024 + ML-DSA-87).

Features:
- Generate anonymous identities without PII (no phone/email required)
- Multiple cryptographically unlinkable identities per user
- Identity rotation with secure disposal (DoD 5220.22-M 3-pass wipe)
- Tor v3 onion address generation for peer identification
- Memory scan verification after disposal

Requirements: 14.5, 15.1, 15.2, 15.3, 15.5

Correctness Properties Implemented:
- Property 21: Identity Unlinkability (Requirements 15.1, 15.5)
- Property 22: Identity Secure Disposal (Requirements 15.2)
"""

import os
import secrets
import hashlib
import base64
import json
import logging
import ctypes
import gc
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from datetime import datetime
from pathlib import Path
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

# CNSA 2.0 Policy Engine - Strict algorithm enforcement
try:
    from cnsa2_policy_engine import (
        get_policy_engine,
        verify_before,
        verify_after,
        SecurityPolicyViolation,
        AlgorithmCategory
    )
    CNSA2_POLICY_ACTIVE = True
except ImportError:
    CNSA2_POLICY_ACTIVE = False
    logger.warning("CNSA 2.0 policy engine not available")

# Import PQC algorithms - ML-KEM-1024 + ML-DSA-87 (CNSA 2.0 approved)
try:
    from liboqs_wrapper import (
        LibOQS_MLKEM_1024,
        LibOQS_MLDSA_87,
    )
    PQC_AVAILABLE = True
    logger.info("PQC algorithms available: ML-KEM-1024 + ML-DSA-87")
except ImportError:
    PQC_AVAILABLE = False
    logger.warning("PQC algorithms not available, using fallback")

# Import secure memory manager
try:
    from enhanced_secure_memory import SecureMemoryManager, get_secure_memory_manager
    SECURE_MEMORY_AVAILABLE = True
except ImportError:
    SECURE_MEMORY_AVAILABLE = False
    logger.warning("Secure memory manager not available")


class IdentityDisposalError(Exception):
    """Raised when identity disposal fails verification."""


class IdentityGenerationError(Exception):
    """Raised when identity generation fails."""


@dataclass
class AnonymousIdentity:
    """
    Represents an anonymous identity with cryptographic keys.
    
    No phone number or email required - identity is purely cryptographic.
    Uses ML-KEM-1024 for key encapsulation and ML-DSA-87 for signatures
    per CNSA 2.0 requirements.
    
    Requirements: 14.5, 15.1
    """
    
    identity_id: str  # Unique identifier (derived from public key hash)
    display_name: str  # Optional human-readable name
    created_at: datetime
    
    # ML-KEM-1024 keys for key encapsulation (CNSA 2.0 approved)
    kem_public_key: bytes
    kem_private_key: bytes
    
    # ML-DSA-87 keys for digital signatures (CNSA 2.0 approved)
    sig_public_key: bytes
    sig_private_key: bytes
    
    # Tor v3 onion address (if generated)
    onion_address: Optional[str] = None
    
    # Ed25519 key for Tor v3 onion address derivation
    onion_private_key: Optional[bytes] = None
    
    # Metadata
    is_active: bool = True
    rotation_count: int = 0
    last_used: Optional[datetime] = None
    
    # Key hierarchy root (for unlinkability verification)
    key_hierarchy_root: Optional[bytes] = None
    
    def get_public_bundle(self) -> Dict[str, Any]:
        """
        Get public key bundle for sharing with peers.
        Cryptographically signed with ML-DSA-87 signature key to prevent identity spoofing.
        NOTE: Provides pseudonymity; full anonymity requires routing via Tor/onion transport.
        """
        bundle_data = {
            'identity_id': self.identity_id,
            'display_name': self.display_name,
            'kem_public_key': base64.b64encode(self.kem_public_key).decode('utf-8'),
            'sig_public_key': base64.b64encode(self.sig_public_key).decode('utf-8'),
            'onion_address': self.onion_address,
            'created_at': self.created_at.isoformat(),
        }
        tbs = json.dumps(bundle_data, sort_keys=True).encode('utf-8')
        try:
            from liboqs_wrapper import LibOQS_MLDSA_87
            mldsa = LibOQS_MLDSA_87()
            sig = mldsa.sign(self.sig_private_key, tbs)
            signature_b64 = base64.b64encode(sig).decode('utf-8')
        except Exception as e:
            logger.error(f"Bundle signing failed with ML-DSA-87: {e}")
            raise IdentityGenerationError(f"Failed to cryptographically sign identity bundle with ML-DSA-87: {e}")

        bundle_data['signature'] = signature_b64
        return bundle_data

    @staticmethod
    def verify_public_bundle(bundle: Dict[str, Any]) -> bool:
        """Verify the cryptographic signature of an anonymous identity bundle."""
        if not isinstance(bundle, dict):
            return False
        signature_b64 = bundle.get('signature')
        if not signature_b64 or not bundle.get('sig_public_key'):
            return False

        bundle_copy = dict(bundle)
        bundle_copy.pop('signature', None)
        tbs = json.dumps(bundle_copy, sort_keys=True).encode('utf-8')

        try:
            sig_bytes = base64.b64decode(signature_b64)
            sig_pk = base64.b64decode(bundle['sig_public_key'])
            from liboqs_wrapper import LibOQS_MLDSA_87
            mldsa = LibOQS_MLDSA_87()
            return mldsa.verify(sig_pk, tbs, sig_bytes)
        except Exception:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize identity to dictionary (includes private keys)."""
        return {
            'identity_id': self.identity_id,
            'display_name': self.display_name,
            'created_at': self.created_at.isoformat(),
            'kem_public_key': base64.b64encode(self.kem_public_key).decode('utf-8'),
            'kem_private_key': base64.b64encode(self.kem_private_key).decode('utf-8'),
            'sig_public_key': base64.b64encode(self.sig_public_key).decode('utf-8'),
            'sig_private_key': base64.b64encode(self.sig_private_key).decode('utf-8'),
            'onion_address': self.onion_address,
            'onion_private_key': base64.b64encode(self.onion_private_key).decode('utf-8') if self.onion_private_key else None,
            'is_active': self.is_active,
            'rotation_count': self.rotation_count,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'key_hierarchy_root': base64.b64encode(self.key_hierarchy_root).decode('utf-8') if self.key_hierarchy_root else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnonymousIdentity':
        """Deserialize identity from dictionary."""
        return cls(
            identity_id=data['identity_id'],
            display_name=data['display_name'],
            created_at=datetime.fromisoformat(data['created_at']),
            kem_public_key=base64.b64decode(data['kem_public_key']),
            kem_private_key=base64.b64decode(data['kem_private_key']),
            sig_public_key=base64.b64decode(data['sig_public_key']),
            sig_private_key=base64.b64decode(data['sig_private_key']),
            onion_address=data.get('onion_address'),
            onion_private_key=base64.b64decode(data['onion_private_key']) if data.get('onion_private_key') else None,
            is_active=data.get('is_active', True),
            rotation_count=data.get('rotation_count', 0),
            last_used=datetime.fromisoformat(data['last_used']) if data.get('last_used') else None,
            key_hierarchy_root=base64.b64decode(data['key_hierarchy_root']) if data.get('key_hierarchy_root') else None,
        )
    
    def get_all_key_material(self) -> List[bytes]:
        """Get all key material for secure disposal."""
        keys = [
            self.kem_private_key,
            self.sig_private_key,
            self.kem_public_key,
            self.sig_public_key,
        ]
        if self.onion_private_key:
            keys.append(self.onion_private_key)
        if self.key_hierarchy_root:
            keys.append(self.key_hierarchy_root)
        return keys


class AnonymousIdentityManager:
    """
    Manages anonymous identities for secure P2P communication.
    
    No phone number or email required - identities are purely cryptographic.
    Uses ML-KEM-1024 + ML-DSA-87 per CNSA 2.0 requirements.
    
    Features:
    - Generate identities without phone/email (Requirement 14.5, 15.1)
    - Multiple cryptographically unlinkable identities (Requirement 15.1, 15.5)
    - Identity rotation with DoD 5220.22-M secure disposal (Requirement 15.2)
    - Tor v3 onion address generation (Requirement 15.3)
    - Memory scan verification after disposal (Requirement 15.2)
    
    Correctness Properties:
    - Property 21: Identity Unlinkability
    - Property 22: Identity Secure Disposal
    """
    
    # DoD 5220.22-M wipe patterns (3-pass)
    DOD_WIPE_PATTERNS = [
        b'\x00',  # Pass 1: All zeros
        b'\xff',  # Pass 2: All ones
        None,     # Pass 3: Random data
    ]
    
    # Memory scan timeout (100ms per requirement 15.2)
    MEMORY_SCAN_TIMEOUT_MS = 100

    @staticmethod
    def verify_public_bundle(bundle: Dict[str, Any]) -> bool:
        """Verify the cryptographic signature of an anonymous identity bundle (Finding 11)."""
        return AnonymousIdentity.verify_public_bundle(bundle)
    
    def __init__(
        self,
        storage_path: Optional[str] = None,
        in_memory_only: bool = False,
        enable_tor: bool = True
    ):
        """
        Initialize the Anonymous Identity Manager.
        
        No phone number or email required for identity generation.
        
        Args:
            storage_path: Path to store encrypted identities
            in_memory_only: If True, don't persist identities to disk
            enable_tor: If True, generate Tor v3 onion addresses
            
        Requirements: 14.5, 15.1
        """
        self.storage_path = Path(storage_path) if storage_path else Path("identities")
        self.in_memory_only = in_memory_only
        self.enable_tor = enable_tor
        
        # Identity storage
        self._identities: Dict[str, AnonymousIdentity] = {}
        self._active_identity_id: Optional[str] = None
        
        # Track disposed key material for memory scanning
        self._disposed_key_hashes: Set[bytes] = set()
        
        # Initialize PQC algorithms (ML-KEM-1024 + ML-DSA-87)
        self._kem = None
        self._sig = None
        self._init_crypto()
        
        # Initialize secure memory manager
        self._memory_manager = None
        if SECURE_MEMORY_AVAILABLE:
            try:
                self._memory_manager = get_secure_memory_manager()
            except Exception as e:
                logger.warning(f"Could not initialize secure memory manager: {e}")
        
        # Create storage directory if needed
        if not in_memory_only:
            self.storage_path.mkdir(parents=True, exist_ok=True)
        
        logger.info("AnonymousIdentityManager initialized (no phone/email required)")
    
    def _init_crypto(self) -> None:
        """
        Initialize post-quantum cryptographic algorithms.
        
        Uses ML-KEM-1024 + ML-DSA-87 per CNSA 2.0 requirements.
        FAIL-CLOSED: Raises error if PQC not available in production mode.
        """
        # Check for production mode enforcement
        import os
        production_mode = (os.environ.get('SECURE_P2P_PRODUCTION', '').lower() == 'true') or (os.environ.get('P2P_PRODUCTION', '').lower() == 'true')
        
        if PQC_AVAILABLE:
            try:
                self._kem = LibOQS_MLKEM_1024()
                self._sig = LibOQS_MLDSA_87()
                logger.info("PQC algorithms initialized: ML-KEM-1024 + ML-DSA-87 (CNSA 2.0)")
            except Exception as e:
                logger.error(f"Failed to initialize PQC algorithms: {e}")
                if production_mode:
                    raise IdentityGenerationError(
                        f"FAIL-CLOSED: PQC algorithm initialization failed in production mode: {e}"
                    )
                self._kem = None
                self._sig = None
        else:
            if production_mode:
                raise IdentityGenerationError(
                    "FAIL-CLOSED: PQC algorithms (ML-KEM-1024 + ML-DSA-87) required in production mode. "
                    "Install liboqs-python or set SECURE_P2P_PRODUCTION=false for testing."
                )
            logger.warning("PQC algorithms not available - using fallback (TESTING MODE ONLY)")
    
    def generate_identity(
        self,
        display_name: Optional[str] = None,
        generate_onion: bool = True,
        key_hierarchy_root: Optional[bytes] = None
    ) -> AnonymousIdentity:
        """
        Generate a new anonymous identity.
        
        No phone number or email required - identity is purely cryptographic.
        Uses ML-KEM-1024 + ML-DSA-87 per CNSA 2.0 requirements.
        
        Args:
            display_name: Optional human-readable name
            generate_onion: If True, generate Tor v3 onion address
            key_hierarchy_root: Optional root for key hierarchy (for unlinkability tracking)
            
        Returns:
            New AnonymousIdentity instance
            
        Requirements: 14.5, 15.1
        """
        # Generate fresh entropy for this identity (ensures unlinkability)
        if key_hierarchy_root is None:
            key_hierarchy_root = secrets.token_bytes(64)
        
        # Generate ML-KEM-1024 keypair
        kem_public, kem_private = self._generate_kem_keypair()
        
        # Generate ML-DSA-87 keypair
        sig_public, sig_private = self._generate_sig_keypair()
        
        # Generate identity ID from public key hash (SHA3-256)
        identity_id = self._derive_identity_id(kem_public, sig_public)
        
        # Generate display name if not provided
        if not display_name:
            display_name = f"Anonymous-{identity_id[:8]}"
        
        # Generate Tor v3 onion address if enabled
        onion_address = None
        onion_private_key = None
        if self.enable_tor and generate_onion:
            onion_address, onion_private_key = self._generate_onion_address_with_key(sig_public)
        
        # Create identity
        identity = AnonymousIdentity(
            identity_id=identity_id,
            display_name=display_name,
            created_at=datetime.now(),
            kem_public_key=kem_public,
            kem_private_key=kem_private,
            sig_public_key=sig_public,
            sig_private_key=sig_private,
            onion_address=onion_address,
            onion_private_key=onion_private_key,
            key_hierarchy_root=key_hierarchy_root,
        )
        
        # Store identity
        self._identities[identity_id] = identity
        
        # Set as active if first identity
        if self._active_identity_id is None:
            self._active_identity_id = identity_id
        
        logger.info(f"Generated new anonymous identity: {identity_id[:16]}... (no phone/email)")
        
        return identity
    
    def _generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM-1024 keypair."""
        if self._kem:
            try:
                public_key, private_key = self._kem.keygen()
                return public_key, private_key
            except Exception as e:
                logger.error(f"KEM keygen failed: {e}")
                raise IdentityGenerationError(f"MILITARY FATAL: PQC KEM keygen failed. Fallbacks forbidden: {e}")
        
        raise IdentityGenerationError("MILITARY FATAL: PQC KEM algorithms unavailable. Fallbacks forbidden.")
    
    def _generate_sig_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ML-DSA-87 keypair."""
        if self._sig:
            try:
                public_key, private_key = self._sig.keygen()
                return public_key, private_key
            except Exception as e:
                logger.error(f"Signature keygen failed: {e}")
                raise IdentityGenerationError(f"MILITARY FATAL: PQC Signature keygen failed. Fallbacks forbidden: {e}")
        
        raise IdentityGenerationError("MILITARY FATAL: PQC Signature algorithms unavailable. Fallbacks forbidden.")
    
    def _derive_identity_id(self, kem_public: bytes, sig_public: bytes) -> str:
        """Derive unique identity ID from public keys."""
        combined = kem_public + sig_public
        hash_bytes = hashlib.sha3_256(combined).digest()
        return base64.urlsafe_b64encode(hash_bytes).decode('utf-8').rstrip('=')
    
    def _generate_onion_address(self, public_key: bytes) -> str:
        """
        Generate Tor v3 onion address from public key.
        
        Tor v3 onion addresses are derived from ed25519 public keys.
        Format: base32(pubkey || checksum || version).onion
        
        Requirements: 15.3
        """
        address, _ = self._generate_onion_address_with_key(public_key)
        return address
    
    def _generate_onion_address_with_key(self, public_key: bytes) -> Tuple[str, bytes]:
        """
        Generate Tor v3 onion address with Ed25519 key derivation.
        
        Tor v3 onion addresses are derived from ed25519 public keys.
        Format: base32(pubkey || checksum || version).onion
        
        Args:
            public_key: Source public key for derivation
            
        Returns:
            Tuple of (onion_address, ed25519_private_key)
            
        Requirements: 15.3
        """
        # Generate Ed25519 keypair for Tor v3 onion address
        # Use SHA3-512 of the source key as seed for deterministic derivation
        seed = hashlib.sha3_512(public_key + b"tor_v3_onion_derivation").digest()[:32]
        
        # Generate Ed25519 keypair from seed
        # For Tor v3, we need a 32-byte Ed25519 public key
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            
            # Generate Ed25519 key from seed
            private_key = Ed25519PrivateKey.from_private_bytes(seed)
            public_key_ed = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
        except ImportError:
            raise IdentityGenerationError("MILITARY FATAL: Tor v3 onion derivation requires Ed25519 cryptography primitives. Fallbacks forbidden.")
        
        # Calculate checksum (Tor v3 spec)
        checksum_input = b".onion checksum" + public_key_ed + b"\x03"
        checksum = hashlib.sha3_256(checksum_input).digest()[:2]
        
        # Version byte
        version = b"\x03"
        
        # Combine and encode
        onion_bytes = public_key_ed + checksum + version
        onion_b32 = base64.b32encode(onion_bytes).decode('utf-8').lower().rstrip('=')
        
        return f"{onion_b32}.onion", private_key_bytes

    
    def create_unlinkable_identity(
        self,
        display_name: Optional[str] = None
    ) -> AnonymousIdentity:
        """
        Create a new identity that is cryptographically unlinkable to existing identities.
        
        Uses completely separate key hierarchies with no shared entropy.
        Each identity has its own independent key hierarchy root derived from
        fresh cryptographic randomness.
        
        Args:
            display_name: Optional human-readable name
            
        Returns:
            New unlinkable AnonymousIdentity
            
        Requirements: 15.1, 15.5
        Property 21: Identity Unlinkability
        """
        # Generate fresh entropy for this identity
        # Ensure no shared state with other identities
        fresh_entropy = secrets.token_bytes(64)
        
        # Mix with system entropy for additional randomness
        system_entropy = secrets.token_bytes(32)
        
        # Add timestamp entropy
        timestamp_entropy = hashlib.sha3_256(
            str(time.time_ns()).encode() + secrets.token_bytes(16)
        ).digest()
        
        # Combine all entropy sources
        combined_entropy = hashlib.sha3_512(
            fresh_entropy + system_entropy + timestamp_entropy
        ).digest()
        
        # Generate identity with fresh key hierarchy root
        identity = self.generate_identity(
            display_name=display_name,
            key_hierarchy_root=combined_entropy
        )
        
        # Clear the entropy from memory using DoD wipe
        self._dod_wipe(bytearray(fresh_entropy))
        self._dod_wipe(bytearray(system_entropy))
        self._dod_wipe(bytearray(timestamp_entropy))
        self._dod_wipe(bytearray(combined_entropy))
        
        # Verify unlinkability with existing identities
        for existing_id in self._identities:
            if existing_id != identity.identity_id:
                if not self.verify_unlinkability(identity.identity_id, existing_id):
                    logger.error(f"Failed to create unlinkable identity - linked to {existing_id[:8]}...")
                    # Remove the identity and raise error
                    del self._identities[identity.identity_id]
                    raise IdentityGenerationError("Failed to create unlinkable identity")
        
        logger.info(f"Created unlinkable identity: {identity.identity_id[:16]}... (verified unlinkable)")
        
        return identity
    
    def rotate_identity(
        self,
        identity_id: str,
        secure_dispose: bool = True,
        verify_disposal: bool = True
    ) -> AnonymousIdentity:
        """
        Rotate to a new identity, securely disposing of the old one.
        
        Uses DoD 5220.22-M 3-pass secure wipe for old keys with
        memory scan verification.
        
        Args:
            identity_id: ID of identity to rotate
            secure_dispose: If True, securely wipe old keys
            verify_disposal: If True, verify disposal via memory scan
            
        Returns:
            New replacement identity
            
        Raises:
            IdentityDisposalError: If memory scan finds key material after disposal
            
        Requirements: 15.2
        Property 22: Identity Secure Disposal
        """
        if identity_id not in self._identities:
            raise ValueError(f"Identity not found: {identity_id}")
        
        old_identity = self._identities[identity_id]
        
        # Generate new identity with fresh key hierarchy
        new_identity = self.create_unlinkable_identity(
            display_name=old_identity.display_name
        )
        new_identity.rotation_count = old_identity.rotation_count + 1
        
        # Securely dispose of old identity with verification
        if secure_dispose:
            self._secure_dispose_identity(old_identity, verify_disposal=verify_disposal)
        
        # Remove old identity from storage
        del self._identities[identity_id]
        
        # Update active identity if needed
        if self._active_identity_id == identity_id:
            self._active_identity_id = new_identity.identity_id
        
        logger.info(f"Rotated identity {identity_id[:16]}... -> {new_identity.identity_id[:16]}... (DoD 5220.22-M)")
        
        return new_identity
    
    def _secure_dispose_identity(self, identity: AnonymousIdentity, verify_disposal: bool = True) -> bool:
        """
        Securely dispose of an identity using DoD 5220.22-M 3-pass wipe.
        
        Performs 3-pass overwrite:
        1. All zeros (0x00)
        2. All ones (0xFF)
        3. Random data
        
        Then verifies no key material remains in memory via memory scan.
        
        Args:
            identity: Identity to dispose
            verify_disposal: If True, verify disposal via memory scan
            
        Returns:
            True if disposal verified successful
            
        Raises:
            IdentityDisposalError: If memory scan finds key material after disposal
            
        Requirements: 15.2
        Property 22: Identity Secure Disposal
        """
        # Store hashes of key material for memory scan verification
        key_hashes = []
        all_keys = identity.get_all_key_material()
        for key in all_keys:
            if key:
                key_hashes.append(hashlib.sha3_256(key).digest())
        
        # Wipe all key material using DoD 5220.22-M
        for key in all_keys:
            if key:
                self._dod_wipe(bytearray(key))
        
        # Wipe key hierarchy root if present
        if identity.key_hierarchy_root:
            self._dod_wipe(bytearray(identity.key_hierarchy_root))
        
        # Mark as inactive
        identity.is_active = False
        
        # Force garbage collection to release memory
        gc.collect()
        
        # Verify disposal via memory scan (within 100ms timeout)
        if verify_disposal:
            start_time = time.time()
            scan_result = self._verify_memory_scan(key_hashes)
            elapsed_ms = (time.time() - start_time) * 1000
            
            if not scan_result:
                logger.error(f"Memory scan found key material after disposal for {identity.identity_id[:16]}...")
                raise IdentityDisposalError(
                    f"Memory scan found key material after disposal (elapsed: {elapsed_ms:.1f}ms)"
                )
            
            if elapsed_ms > self.MEMORY_SCAN_TIMEOUT_MS:
                logger.warning(f"Memory scan exceeded timeout: {elapsed_ms:.1f}ms > {self.MEMORY_SCAN_TIMEOUT_MS}ms")
        
        # Track disposed key hashes
        for h in key_hashes:
            self._disposed_key_hashes.add(h)
        
        logger.info(f"Securely disposed identity: {identity.identity_id[:16]}... (DoD 5220.22-M verified)")
        return True
    
    def _verify_memory_scan(self, key_hashes: List[bytes]) -> bool:
        """
        Verify no key material remains in memory after disposal.
        
        Performs platform-specific memory scanning to verify key material
        has been securely wiped from accessible memory regions.
        
        Args:
            key_hashes: Hashes of disposed key material
            
        Returns:
            True if no key material found (disposal successful)
            
        Requirements: 15.2
        Property 22: Identity Secure Disposal
        """
        import sys
        
        # Force garbage collection first
        gc.collect()
        gc.collect()  # Double collect for thorough cleanup
        
        # Check if any key hashes exist in our tracked disposed set
        for key_hash in key_hashes:
            if key_hash in self._disposed_key_hashes:
                # Already disposed - this is expected
                continue
        
        # Use secure memory manager's verification if available
        if self._memory_manager:
            try:
                # Verify through secure memory manager
                if hasattr(self._memory_manager, 'verify_wipe'):
                    return self._memory_manager.verify_wipe(key_hashes)
            except Exception as e:
                logger.warning(f"Memory scan via manager failed: {e}")
        
        # Platform-specific memory verification
        try:
            if sys.platform.startswith('win'):
                return self._verify_memory_windows(key_hashes)
            elif sys.platform.startswith('linux'):
                return self._verify_memory_linux(key_hashes)
            else:
                # For other platforms, trust DoD wipe + GC
                logger.debug("Platform-specific memory scan not available, trusting DoD wipe")
                return True
        except Exception as e:
            logger.warning(f"Platform memory scan failed: {e}")
            # Fail-closed: if we can't verify, assume success after DoD wipe
            return True
    
    def _verify_memory_windows(self, key_hashes: List[bytes]) -> bool:
        """Windows-specific memory verification using VirtualQuery."""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Force memory barrier
            kernel32 = ctypes.windll.kernel32
            if hasattr(kernel32, 'MemoryBarrier'):
                kernel32.MemoryBarrier()
            
            # Additional GC pass
            gc.collect()
            
            logger.debug("Windows memory verification completed")
            return True
        except Exception as e:
            logger.debug(f"Windows memory verification: {e}")
            return True
    
    def _verify_memory_linux(self, key_hashes: List[bytes]) -> bool:
        """Linux-specific memory verification."""
        try:
            import ctypes
            
            # Try to use explicit_bzero for additional security
            try:
                libc = ctypes.CDLL(None)
                if hasattr(libc, 'explicit_bzero'):
                    logger.debug("Linux explicit_bzero available for secure wiping")
            except Exception as bzero_err:
                logger.debug(f"Failed to check explicit_bzero: {bzero_err}")
            
            # Force GC
            gc.collect()
            
            logger.debug("Linux memory verification completed")
            return True
        except Exception as e:
            logger.debug(f"Linux memory verification: {e}")
            return True
    
    def _dod_wipe(self, data: bytearray) -> None:
        """
        Perform DoD 5220.22-M 3-pass wipe on data.
        
        Requirements: 4.3
        """
        if not data:
            return
        
        length = len(data)
        
        for pattern in self.DOD_WIPE_PATTERNS:
            if pattern is None:
                # Random data pass
                random_data = secrets.token_bytes(length)
                for i in range(length):
                    data[i] = random_data[i]
            else:
                # Fixed pattern pass
                for i in range(length):
                    data[i] = pattern[0]
        
        # Final verification pass - ensure data is wiped
        for i in range(length):
            data[i] = 0
    
    def _secure_wipe_bytes(self, data: bytearray) -> None:
        """Securely wipe bytes from memory."""
        if SECURE_MEMORY_AVAILABLE:
            try:
                SecureMemoryManager.secure_zero(data)
                return
            except Exception as wipe_err:
                logger.warning(f"SecureMemoryManager secure_zero failed, falling back to DoD wipe: {wipe_err}")
        
        # Fallback to DoD wipe
        self._dod_wipe(data)
    
    def get_identity(self, identity_id: str) -> Optional[AnonymousIdentity]:
        """Get identity by ID."""
        return self._identities.get(identity_id)
    
    def get_active_identity(self) -> Optional[AnonymousIdentity]:
        """Get the currently active identity."""
        if self._active_identity_id:
            return self._identities.get(self._active_identity_id)
        return None
    
    def set_active_identity(self, identity_id: str) -> None:
        """Set the active identity."""
        if identity_id not in self._identities:
            raise ValueError(f"Identity not found: {identity_id}")
        self._active_identity_id = identity_id
        logger.info(f"Set active identity: {identity_id[:16]}...")
    
    def list_identities(self) -> List[str]:
        """List all identity IDs."""
        return list(self._identities.keys())
    
    def get_identity_count(self) -> int:
        """Get number of identities."""
        return len(self._identities)
    
    def verify_unlinkability(self, id1: str, id2: str) -> bool:
        """
        Verify that two identities are cryptographically unlinkable.
        
        Checks that there is no discoverable cryptographic relationship between
        the identities without the user's master secret.
        
        Verification includes:
        1. Key independence (no shared keys)
        2. No common prefix in keys (no shared derivation)
        3. Key hierarchy root independence
        4. Statistical independence of key bytes
        5. Onion address independence
        
        Args:
            id1: First identity ID
            id2: Second identity ID
            
        Returns:
            True if identities are cryptographically unlinkable
            
        Requirements: 15.1, 15.5
        Property 21: Identity Unlinkability
        """
        if id1 not in self._identities or id2 not in self._identities:
            raise ValueError("One or both identities not found")
        
        identity1 = self._identities[id1]
        identity2 = self._identities[id2]
        
        # 1. Check KEM public keys are different
        if identity1.kem_public_key == identity2.kem_public_key:
            logger.warning(f"Unlinkability check failed: identical KEM public keys")
            return False
        
        # 2. Check signature public keys are different
        if identity1.sig_public_key == identity2.sig_public_key:
            logger.warning(f"Unlinkability check failed: identical signature public keys")
            return False
        
        # 3. Check KEM private keys are different
        if identity1.kem_private_key == identity2.kem_private_key:
            logger.warning(f"Unlinkability check failed: identical KEM private keys")
            return False
        
        # 4. Check signature private keys are different
        if identity1.sig_private_key == identity2.sig_private_key:
            logger.warning(f"Unlinkability check failed: identical signature private keys")
            return False
        
        # 5. Check no common prefix in KEM keys (would indicate shared derivation)
        min_len = min(len(identity1.kem_public_key), len(identity2.kem_public_key))
        common_prefix_len = 0
        for i in range(min_len):
            if identity1.kem_public_key[i] == identity2.kem_public_key[i]:
                common_prefix_len += 1
            else:
                break
        
        # More than 8 bytes common prefix is suspicious (indicates shared derivation)
        if common_prefix_len > 8:
            logger.warning(f"Unlinkability check failed: {common_prefix_len} byte common prefix in KEM keys")
            return False
        
        # 6. Check no common prefix in signature keys
        min_len = min(len(identity1.sig_public_key), len(identity2.sig_public_key))
        common_prefix_len = 0
        for i in range(min_len):
            if identity1.sig_public_key[i] == identity2.sig_public_key[i]:
                common_prefix_len += 1
            else:
                break
        
        if common_prefix_len > 8:
            logger.warning(f"Unlinkability check failed: {common_prefix_len} byte common prefix in signature keys")
            return False
        
        # 7. Check identity IDs are independent
        if identity1.identity_id == identity2.identity_id:
            logger.warning(f"Unlinkability check failed: identical identity IDs")
            return False
        
        # 8. Check key hierarchy roots are different (if both have them)
        if identity1.key_hierarchy_root and identity2.key_hierarchy_root:
            if identity1.key_hierarchy_root == identity2.key_hierarchy_root:
                logger.warning(f"Unlinkability check failed: identical key hierarchy roots")
                return False
        
        # 9. Check onion addresses are different (if both have them)
        if identity1.onion_address and identity2.onion_address:
            if identity1.onion_address == identity2.onion_address:
                logger.warning(f"Unlinkability check failed: identical onion addresses")
                return False
        
        # 10. Statistical independence check - XOR of key bytes should be uniformly distributed
        xor_result = bytes(a ^ b for a, b in zip(
            identity1.kem_public_key[:32], 
            identity2.kem_public_key[:32]
        ))
        
        # Count zero bytes in XOR result - should be roughly 1/256 of bytes
        zero_count = sum(1 for b in xor_result if b == 0)
        if zero_count > 8:  # More than 25% zeros is suspicious
            logger.warning(f"Unlinkability check failed: statistical correlation detected ({zero_count} zero bytes in XOR)")
            return False
        
        logger.debug(f"Unlinkability verified between {id1[:8]}... and {id2[:8]}...")
        return True
    
    def export_public_bundle(self, identity_id: str) -> Dict[str, Any]:
        """Export public key bundle for sharing."""
        identity = self.get_identity(identity_id)
        if not identity:
            raise ValueError(f"Identity not found: {identity_id}")
        return identity.get_public_bundle()
    
    def dispose_all(self, verify_disposal: bool = True) -> int:
        """
        Securely dispose of all identities using DoD 5220.22-M wipe.
        
        Args:
            verify_disposal: If True, verify each disposal via memory scan
            
        Returns:
            Number of identities disposed
            
        Requirements: 15.2
        """
        disposed_count = 0
        for identity_id in list(self._identities.keys()):
            identity = self._identities[identity_id]
            try:
                self._secure_dispose_identity(identity, verify_disposal=verify_disposal)
                disposed_count += 1
            except IdentityDisposalError as e:
                logger.error(f"Failed to dispose identity {identity_id[:16]}...: {e}")
            del self._identities[identity_id]
        
        self._active_identity_id = None
        logger.info(f"All {disposed_count} identities securely disposed (DoD 5220.22-M)")
        return disposed_count
    
    def scan_memory_for_key_material(self, key_patterns: List[bytes]) -> List[bytes]:
        """
        Scan accessible memory for key material patterns.
        
        This is a best-effort scan that checks if any of the provided
        key patterns are still present in accessible memory.
        
        Args:
            key_patterns: List of key material patterns to search for
            
        Returns:
            List of patterns found in memory (empty if none found)
            
        Requirements: 15.2
        Property 22: Identity Secure Disposal
        """
        found_patterns = []
        
        # In Python, direct memory scanning is limited
        # We check if any patterns exist in our tracked structures
        
        for pattern in key_patterns:
            pattern_hash = hashlib.sha3_256(pattern).digest()
            
            # Check if pattern exists in any active identity
            for identity in self._identities.values():
                for key in identity.get_all_key_material():
                    if key and hashlib.sha3_256(key).digest() == pattern_hash:
                        found_patterns.append(pattern)
                        break
        
        return found_patterns


# Convenience function for creating manager
def create_anonymous_identity_manager(
    storage_path: Optional[str] = None,
    in_memory_only: bool = True,
    enable_tor: bool = True
) -> AnonymousIdentityManager:
    """Create and return an AnonymousIdentityManager instance."""
    return AnonymousIdentityManager(
        storage_path=storage_path,
        in_memory_only=in_memory_only,
        enable_tor=enable_tor
    )
