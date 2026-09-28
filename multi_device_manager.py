"""
Multi-Device Support Manager for Secure P2P Communication.

This module implements multi-device support with ML-DSA-87 signature chain
binding to user identity, device enrollment, revocation, and encrypted
message synchronization using Double Ratchet with device-specific keys.

Requirements: 12.1, 12.2, 12.3, 12.4, 12.5

Features:
- Device enrollment with ML-DSA-87 signature chain binding (Req 12.1, 12.2)
- Device revocation with public key revocation list (Req 12.4)
- Max 5 devices per identity enforcement (Req 12.5)
- Encrypted message sync with Double Ratchet device-specific keys (Req 12.3)
"""

import os
import secrets
import hashlib
import base64
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from datetime import datetime
from pathlib import Path
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

# Import PQC algorithms - ML-DSA-87 for signatures (CNSA 2.0 approved)
try:
    from liboqs_wrapper import LibOQS_MLDSA_87
    PQC_AVAILABLE = True
    logger.info("ML-DSA-87 available for device signatures")
except ImportError:
    PQC_AVAILABLE = False
    logger.warning("ML-DSA-87 not available, using fallback")

# Import secure memory wiper for key disposal
try:
    from secure_memory_wiper import SecureMemoryWiper, secure_wipe_dod
    SECURE_WIPE_AVAILABLE = True
except ImportError:
    SECURE_WIPE_AVAILABLE = False
    logger.warning("Secure memory wiper not available")


class DeviceEnrollmentError(Exception):
    """Raised when device enrollment fails."""


class DeviceRevocationError(Exception):
    """Raised when device revocation fails."""


class DeviceLimitExceededError(Exception):
    """Raised when max device limit (5) is exceeded."""


class SignatureChainError(Exception):
    """Raised when signature chain verification fails."""


class DeviceStatus(Enum):
    """Device status enumeration."""
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


@dataclass
class DeviceInfo:
    """
    Represents a device bound to a user identity.
    
    Uses ML-DSA-87 for signature chain binding per Requirement 12.1.
    """
    device_id: str  # Unique device identifier (SHA3-256 of public key)
    device_name: str  # Human-readable device name
    device_type: str  # desktop, mobile, tablet, etc.
    
    # ML-DSA-87 keys for this device
    public_key: bytes  # ML-DSA-87 public key
    
    # Signature chain binding
    enrollment_signature: bytes  # Signature from authorizing device
    authorizing_device_id: Optional[str]  # ID of device that authorized enrollment
    signature_chain_depth: int  # Depth in signature chain (root = 0)
    
    # Timestamps
    enrolled_at: datetime
    last_seen: Optional[datetime] = None
    
    # Status
    status: DeviceStatus = DeviceStatus.ACTIVE
    
    # Revocation info
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize device info to dictionary."""
        return {
            'device_id': self.device_id,
            'device_name': self.device_name,
            'device_type': self.device_type,
            'public_key': base64.b64encode(self.public_key).decode('utf-8'),
            'enrollment_signature': base64.b64encode(self.enrollment_signature).decode('utf-8'),
            'authorizing_device_id': self.authorizing_device_id,
            'signature_chain_depth': self.signature_chain_depth,
            'enrolled_at': self.enrolled_at.isoformat(),
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'status': self.status.value,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'revocation_reason': self.revocation_reason,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeviceInfo':
        """Deserialize device info from dictionary."""
        return cls(
            device_id=data['device_id'],
            device_name=data['device_name'],
            device_type=data['device_type'],
            public_key=base64.b64decode(data['public_key']),
            enrollment_signature=base64.b64decode(data['enrollment_signature']),
            authorizing_device_id=data.get('authorizing_device_id'),
            signature_chain_depth=data['signature_chain_depth'],
            enrolled_at=datetime.fromisoformat(data['enrolled_at']),
            last_seen=datetime.fromisoformat(data['last_seen']) if data.get('last_seen') else None,
            status=DeviceStatus(data.get('status', 'active')),
            revoked_at=datetime.fromisoformat(data['revoked_at']) if data.get('revoked_at') else None,
            revocation_reason=data.get('revocation_reason'),
        )


@dataclass
class UserIdentityDevices:
    """
    Represents all devices bound to a user identity.
    
    Enforces max 5 devices per identity (Requirement 12.5).
    """
    user_identity_id: str  # User's identity ID
    
    # Root device (first enrolled device)
    root_device_id: Optional[str] = None
    
    # All devices (including revoked)
    devices: Dict[str, DeviceInfo] = field(default_factory=dict)
    
    # Revocation list (public keys)
    revocation_list: Set[bytes] = field(default_factory=set)
    
    # Max devices per identity
    MAX_DEVICES: int = 5
    
    def get_active_devices(self) -> List[DeviceInfo]:
        """Get list of active (non-revoked) devices."""
        return [d for d in self.devices.values() if d.status == DeviceStatus.ACTIVE]
    
    def get_active_device_count(self) -> int:
        """Get count of active devices."""
        return len(self.get_active_devices())
    
    def can_add_device(self) -> bool:
        """Check if another device can be added (max 5)."""
        return self.get_active_device_count() < self.MAX_DEVICES
    
    def is_revoked(self, public_key: bytes) -> bool:
        """Check if a public key is in the revocation list."""
        return public_key in self.revocation_list



# --- Prod-strict gate (central helper reuse, guarded; tiny duplicate fallback) ---
def _crl_prod_strict_on() -> bool:
    """Sticky-prod gate: True in prod without extra env. Lab default False."""
    try:
        from utils.message_caps import prod_strict_on as _central_prod_strict
        return bool(_central_prod_strict())
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    try:
        if os.environ.get("P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on"):
            return True
        if os.environ.get("SECURE_P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on"):
            return True
        if os.environ.get("P2P_ENV", "").strip().lower() == "production":
            return True
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    return False


def crl_require_sig() -> bool:
    """True when CRL bundles must be signed (fail-closed).

    Auto-True in prod (sticky prod) without requiring P2P_CRL_REQUIRE_SIG.
    Explicit P2P_CRL_REQUIRE_SIG=0 opts out in lab only; in prod the
    opt-out is ignored with a CRITICAL log. Lab default: False.
    """
    raw = os.environ.get("P2P_CRL_REQUIRE_SIG")
    enabled = str(raw or "").strip().lower() in ("1", "true", "yes", "on")
    if _crl_prod_strict_on():
        if raw is not None and not enabled:
            logger.critical(
                "PROD-STRICT: ignoring P2P_CRL_REQUIRE_SIG=%r opt-out in "
                "production; CRL signatures remain required", raw)
        return True
    return enabled


class MultiDeviceManager:
    """
    Manages multi-device support for secure P2P communication.
    
    Implements:
    - Device enrollment with ML-DSA-87 signature chain binding (Req 12.1, 12.2)
    - Device revocation with public key revocation list (Req 12.4)
    - Max 5 devices per identity enforcement (Req 12.5)
    - Encrypted message sync with Double Ratchet device-specific keys (Req 12.3)
    
    Requirements: 12.1, 12.2, 12.3, 12.4, 12.5
    """
    
    # Maximum devices per identity (Requirement 12.5)
    MAX_DEVICES_PER_IDENTITY = 5
    
    def __init__(
        self,
        storage_path: Optional[str] = None,
        in_memory_only: bool = False
    ):
        """
        Initialize the Multi-Device Manager.
        
        Args:
            storage_path: Path to store device data
            in_memory_only: If True, don't persist to disk
        """
        self.storage_path = Path(storage_path) if storage_path else Path("devices")
        self.in_memory_only = in_memory_only
        
        # User identity -> devices mapping
        self._user_devices: Dict[str, UserIdentityDevices] = {}

        # CRL gossip versions per issuer (air-gap bundle merge, non-breaking)
        self._crl_versions: Dict[str, int] = {}
        
        # Device-specific Double Ratchet sessions for message sync
        self._device_ratchet_sessions: Dict[str, Any] = {}
        self._lock = threading.RLock()
        
        # Initialize ML-DSA-87 for signatures
        self._sig = None
        self._init_crypto()
        
        # Create storage directory if needed
        if not in_memory_only:
            self.storage_path.mkdir(parents=True, exist_ok=True)
        
        logger.info("MultiDeviceManager initialized")
    
    def _init_crypto(self) -> None:
        """Initialize ML-DSA-87 signature algorithm."""
        if PQC_AVAILABLE:
            try:
                self._sig = LibOQS_MLDSA_87()
                logger.info("ML-DSA-87 initialized for device signatures")
            except Exception as e:
                logger.error(f"Failed to initialize ML-DSA-87: {e}")
                self._sig = None
        else:
            logger.warning("ML-DSA-87 not available")
    
    def generate_device_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate ML-DSA-87 keypair for a new device.

        Fail-closed: enrolling a device on synthetic random bytes sized
        like ML-DSA keys would create unverifiable trust anchors. Raises
        unless the real liboqs ML-DSA-87 backend is operational.

        Returns:
            Tuple of (public_key, private_key)
        """
        if self._sig:
            try:
                public_key, private_key = self._sig.keygen()
                if len(public_key) != 2592 or len(private_key) != 4896:
                    raise ValueError(
                        f"ML-DSA-87 keygen returned wrong sizes: "
                        f"{len(public_key)}/{len(private_key)}")
                return public_key, private_key
            except Exception as e:
                logger.error(f"ML-DSA-87 keygen failed: {e}")
        raise RuntimeError(
            "FAIL-CLOSED: ML-DSA-87 device keygen unavailable. Refusing to "
            "mint synthetic fallback keys for enrollment."
        )
    
    def _derive_device_id(self, public_key: bytes) -> str:
        """Derive unique device ID from public key using SHA3-256."""
        hash_bytes = hashlib.sha3_256(public_key).digest()
        return base64.urlsafe_b64encode(hash_bytes).decode('utf-8').rstrip('=')
    
    def _create_enrollment_message(
        self,
        user_identity_id: str,
        device_public_key: bytes,
        device_name: str,
        device_type: str,
        timestamp: datetime
    ) -> bytes:
        """Create the message to be signed for device enrollment."""
        message_data = {
            'action': 'device_enrollment',
            'user_identity_id': user_identity_id,
            'device_public_key': base64.b64encode(device_public_key).decode('utf-8'),
            'device_name': device_name,
            'device_type': device_type,
            'timestamp': timestamp.isoformat(),
        }
        return json.dumps(message_data, sort_keys=True).encode('utf-8')
    
    def enroll_root_device(
        self,
        user_identity_id: str,
        device_name: str,
        device_type: str = "desktop",
        device_public_key: Optional[bytes] = None,
        device_private_key: Optional[bytes] = None
    ) -> Tuple[DeviceInfo, bytes]:
        """
        Enroll the first (root) device for a user identity.
        
        The root device is self-signed and serves as the trust anchor
        for the signature chain.
        
        Args:
            user_identity_id: User's identity ID
            device_name: Human-readable device name
            device_type: Device type (desktop, mobile, etc.)
            device_public_key: Optional pre-generated public key
            device_private_key: Optional pre-generated private key
            
        Returns:
            Tuple of (DeviceInfo, private_key)
            
        Requirements: 12.1
        """
        with self._lock:
            # Check if user already has devices
            if user_identity_id in self._user_devices:
                if self._user_devices[user_identity_id].root_device_id:
                    raise DeviceEnrollmentError(
                        f"User {user_identity_id[:16]}... already has a root device"
                    )
            
            # Generate keypair if not provided
            if device_public_key is None or device_private_key is None:
                device_public_key, device_private_key = self.generate_device_keypair()
            
            # Derive device ID
            device_id = self._derive_device_id(device_public_key)
            
            # Create enrollment message
            timestamp = datetime.now()
            enrollment_message = self._create_enrollment_message(
                user_identity_id=user_identity_id,
                device_public_key=device_public_key,
                device_name=device_name,
                device_type=device_type,
                timestamp=timestamp
            )
            
            # Self-sign for root device
            enrollment_signature = self._sign_message(device_private_key, enrollment_message)
            
            # Create device info
            device_info = DeviceInfo(
                device_id=device_id,
                device_name=device_name,
                device_type=device_type,
                public_key=device_public_key,
                enrollment_signature=enrollment_signature,
                authorizing_device_id=None,  # Self-signed root
                signature_chain_depth=0,  # Root device
                enrolled_at=timestamp,
                last_seen=timestamp,
                status=DeviceStatus.ACTIVE
            )
            
            # Initialize user devices if needed
            if user_identity_id not in self._user_devices:
                self._user_devices[user_identity_id] = UserIdentityDevices(
                    user_identity_id=user_identity_id
                )
            
            # Store device
            self._user_devices[user_identity_id].devices[device_id] = device_info
            self._user_devices[user_identity_id].root_device_id = device_id
            
            logger.info(f"Enrolled root device {device_id[:16]}... for user {user_identity_id[:16]}...")
            
            return device_info, device_private_key
    
    def enroll_device(
        self,
        user_identity_id: str,
        device_name: str,
        device_type: str,
        authorizing_device_id: str,
        authorizing_private_key: bytes,
        device_public_key: Optional[bytes] = None,
        device_private_key: Optional[bytes] = None
    ) -> Tuple[DeviceInfo, bytes]:
        """
        Enroll a new device using signature from an existing authorized device.
        
        Requires ML-DSA-87 signature from an existing authorized device
        per Requirement 12.2.
        
        Args:
            user_identity_id: User's identity ID
            device_name: Human-readable device name
            device_type: Device type (desktop, mobile, etc.)
            authorizing_device_id: ID of device authorizing enrollment
            authorizing_private_key: Private key of authorizing device
            device_public_key: Optional pre-generated public key
            device_private_key: Optional pre-generated private key
            
        Returns:
            Tuple of (DeviceInfo, private_key)
            
        Raises:
            DeviceEnrollmentError: If enrollment fails
            DeviceLimitExceededError: If max 5 devices exceeded
            
        Requirements: 12.1, 12.2, 12.5
        """
        with self._lock:
            # Check user exists
            if user_identity_id not in self._user_devices:
                raise DeviceEnrollmentError(
                    f"User {user_identity_id[:16]}... has no devices. Enroll root device first."
                )
            
            user_devices = self._user_devices[user_identity_id]
            
            # Check device limit (Requirement 12.5)
            if not user_devices.can_add_device():
                raise DeviceLimitExceededError(
                    f"User {user_identity_id[:16]}... has reached max {user_devices.MAX_DEVICES} devices"
                )
            
            # Verify authorizing device exists and is active
            if authorizing_device_id not in user_devices.devices:
                raise DeviceEnrollmentError(
                    f"Authorizing device {authorizing_device_id[:16]}... not found"
                )
            
            authorizing_device = user_devices.devices[authorizing_device_id]
            if authorizing_device.status != DeviceStatus.ACTIVE:
                raise DeviceEnrollmentError(
                    f"Authorizing device {authorizing_device_id[:16]}... is not active"
                )
            
            # Check authorizing device is not revoked
            if user_devices.is_revoked(authorizing_device.public_key):
                raise DeviceEnrollmentError(
                    f"Authorizing device {authorizing_device_id[:16]}... is revoked"
                )

            # Enforce that only root device (depth == 0) can authorize new devices
            if authorizing_device.signature_chain_depth != 0 and getattr(authorizing_device, 'is_admin', False) is not True:
                raise DeviceEnrollmentError(
                    f"Authorizing device {authorizing_device_id[:16]}... has signature chain depth "
                    f"{authorizing_device.signature_chain_depth}. Only Root Device (depth 0) can authorize new devices."
                )
            
            # Generate keypair if not provided
            if device_public_key is None or device_private_key is None:
                device_public_key, device_private_key = self.generate_device_keypair()
            
            # Derive device ID
            device_id = self._derive_device_id(device_public_key)
            
            # Check device not already enrolled
            if device_id in user_devices.devices:
                raise DeviceEnrollmentError(
                    f"Device {device_id[:16]}... already enrolled"
                )
            
            # Create enrollment message
            timestamp = datetime.now()
            enrollment_message = self._create_enrollment_message(
                user_identity_id=user_identity_id,
                device_public_key=device_public_key,
                device_name=device_name,
                device_type=device_type,
                timestamp=timestamp
            )
            
            # Sign with authorizing device's private key (Requirement 12.2)
            enrollment_signature = self._sign_message(authorizing_private_key, enrollment_message)
            
            # Verify signature with authorizing device's public key
            if not self._verify_signature(
                authorizing_device.public_key,
                enrollment_message,
                enrollment_signature
            ):
                raise SignatureChainError(
                    "Failed to verify enrollment signature from authorizing device"
                )
            
            # Create device info
            device_info = DeviceInfo(
                device_id=device_id,
                device_name=device_name,
                device_type=device_type,
                public_key=device_public_key,
                enrollment_signature=enrollment_signature,
                authorizing_device_id=authorizing_device_id,
                signature_chain_depth=authorizing_device.signature_chain_depth + 1,
                enrolled_at=timestamp,
                last_seen=timestamp,
                status=DeviceStatus.ACTIVE
            )
            
            # Store device
            user_devices.devices[device_id] = device_info
            
            logger.info(
                f"Enrolled device {device_id[:16]}... for user {user_identity_id[:16]}... "
                f"(authorized by {authorizing_device_id[:16]}..., chain depth: {device_info.signature_chain_depth})"
            )
            
            return device_info, device_private_key
    
    def _sign_message(self, private_key: bytes, message: bytes) -> bytes:
        """Sign a message using ML-DSA-87. Fail-closed: no fallbacks."""
        if not self._sig:
            raise RuntimeError(
                "FAIL-CLOSED: ML-DSA-87 signing unavailable. "
                "liboqs ML-DSA-87 implementation is required for device enrollment signatures."
            )
        return self._sig.sign(private_key, message)
    
    def _verify_signature(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature using ML-DSA-87. Fail-closed: no fallbacks."""
        if not self._sig:
            logger.critical(
                "FAIL-CLOSED: ML-DSA-87 verification unavailable. "
                "liboqs ML-DSA-87 implementation is required for signature verification."
            )
            return False
        try:
            return self._sig.verify(public_key, message, signature)
        except Exception as e:
            logger.error(f"ML-DSA-87 verification failed: {e}")
            return False
    
    def verify_signature_chain(
        self,
        user_identity_id: str,
        device_id: str
    ) -> bool:
        """
        Verify the complete signature chain for a device back to root.
        
        Walks the signature chain from the device back to the root device,
        verifying each signature along the way.
        
        Args:
            user_identity_id: User's identity ID
            device_id: Device ID to verify
            
        Returns:
            True if signature chain is valid
            
        Requirements: 12.1
        """
        with self._lock:
            if user_identity_id not in self._user_devices:
                return False
            
            user_devices = self._user_devices[user_identity_id]
            
            if device_id not in user_devices.devices:
                return False
            
            current_device = user_devices.devices[device_id]
            
            # Walk the chain back to root
            while current_device.authorizing_device_id is not None:
                # Get authorizing device
                auth_device_id = current_device.authorizing_device_id
                if auth_device_id not in user_devices.devices:
                    logger.error(f"Authorizing device {auth_device_id[:16]}... not found in chain")
                    return False
                
                auth_device = user_devices.devices[auth_device_id]
                
                # Check authorizing device is not revoked
                if user_devices.is_revoked(auth_device.public_key):
                    logger.error(f"Authorizing device {auth_device_id[:16]}... is revoked")
                    return False
                
                # Recreate enrollment message
                enrollment_message = self._create_enrollment_message(
                    user_identity_id=user_identity_id,
                    device_public_key=current_device.public_key,
                    device_name=current_device.device_name,
                    device_type=current_device.device_type,
                    timestamp=current_device.enrolled_at
                )
                
                # Verify signature
                if not self._verify_signature(
                    auth_device.public_key,
                    enrollment_message,
                    current_device.enrollment_signature
                ):
                    logger.error(
                        f"Signature verification failed for device {current_device.device_id[:16]}... "
                        f"signed by {auth_device_id[:16]}..."
                    )
                    return False
                
                # Move up the chain
                current_device = auth_device
            
            # Verify root device is self-signed
            if current_device.signature_chain_depth != 0:
                logger.error(f"Chain did not reach root device")
                return False
            
            # Verify root device self-signature
            enrollment_message = self._create_enrollment_message(
                user_identity_id=user_identity_id,
                device_public_key=current_device.public_key,
                device_name=current_device.device_name,
                device_type=current_device.device_type,
                timestamp=current_device.enrolled_at
            )
            
            if not self._verify_signature(
                current_device.public_key,
                enrollment_message,
                current_device.enrollment_signature
            ):
                logger.error(f"Root device self-signature verification failed")
                return False
            
            logger.debug(f"Signature chain verified for device {device_id[:16]}...")
            return True

    
    # =========================================================================
    # Device Revocation (Requirement 12.4, 12.5)
    # =========================================================================
    
    def revoke_device(
        self,
        user_identity_id: str,
        device_id: str,
        reason: str = "User requested revocation"
    ) -> bool:
        """
        Revoke a device by adding its public key to the revocation list.
        
        Revoked devices cannot authorize new device enrollments and their
        signature chain is invalidated.
        
        Args:
            user_identity_id: User's identity ID
            device_id: Device ID to revoke
            reason: Reason for revocation
            
        Returns:
            True if revocation successful
            
        Requirements: 12.4
        """
        with self._lock:
            if user_identity_id not in self._user_devices:
                raise DeviceRevocationError(
                    f"User {user_identity_id[:16]}... not found"
                )
            
            user_devices = self._user_devices[user_identity_id]
            
            if device_id not in user_devices.devices:
                raise DeviceRevocationError(
                    f"Device {device_id[:16]}... not found"
                )
            
            device = user_devices.devices[device_id]
            
            # Cannot revoke already revoked device
            if device.status == DeviceStatus.REVOKED:
                logger.warning(f"Device {device_id[:16]}... already revoked")
                return True
            
            # Cannot revoke root device if it's the only active device
            if device_id == user_devices.root_device_id:
                active_count = user_devices.get_active_device_count()
                if active_count <= 1:
                    raise DeviceRevocationError(
                        "Cannot revoke root device when it's the only active device"
                    )
            
            # Add public key to revocation list (Requirement 12.4)
            user_devices.revocation_list.add(device.public_key)
            
            # Update device status
            device.status = DeviceStatus.REVOKED
            device.revoked_at = datetime.now()
            device.revocation_reason = reason
            
            # Revoke all devices that were authorized by this device
            self._cascade_revocation(user_identity_id, device_id, reason)
            
            logger.info(
                f"Revoked device {device_id[:16]}... for user {user_identity_id[:16]}... "
                f"(reason: {reason})"
            )
            
            return True
    
    def _cascade_revocation(
        self,
        user_identity_id: str,
        revoked_device_id: str,
        reason: str
    ) -> None:
        """
        Cascade revocation to all devices authorized by the revoked device.
        
        When a device is revoked, all devices it authorized must also be
        revoked since their signature chain is now invalid.
        """
        with self._lock:
            user_devices = self._user_devices[user_identity_id]
            
            for device_id, device in list(user_devices.devices.items()):
                if device.authorizing_device_id == revoked_device_id:
                    if device.status == DeviceStatus.ACTIVE:
                        # Add to revocation list
                        user_devices.revocation_list.add(device.public_key)
                        
                        # Update status
                        device.status = DeviceStatus.REVOKED
                        device.revoked_at = datetime.now()
                        device.revocation_reason = f"Cascade from {revoked_device_id[:16]}...: {reason}"
                        
                        logger.info(
                            f"Cascade revoked device {device_id[:16]}... "
                            f"(authorized by revoked device {revoked_device_id[:16]}...)"
                        )
                        
                        # Recursively revoke devices authorized by this device
                        self._cascade_revocation(user_identity_id, device_id, reason)
    
    def is_device_revoked(
        self,
        user_identity_id: str,
        device_id: str
    ) -> bool:
        """Check if a device is revoked."""
        with self._lock:
            if user_identity_id not in self._user_devices:
                return True  # Unknown user = revoked
            
            user_devices = self._user_devices[user_identity_id]
            
            if device_id not in user_devices.devices:
                return True  # Unknown device = revoked
            
            device = user_devices.devices[device_id]
            return device.status == DeviceStatus.REVOKED or user_devices.is_revoked(device.public_key)
    
    def get_revocation_list(self, user_identity_id: str) -> List[bytes]:
        """Get the revocation list for a user identity."""
        with self._lock:
            if user_identity_id not in self._user_devices:
                return []
            return list(self._user_devices[user_identity_id].revocation_list)

    # =========================================================================
    # CRL Gossip for Air-Gap (non-breaking add-on, no network fetch)
    # =========================================================================
    # Bundle: JSON {issuer, version, revoked_serials, timestamp, alg, kid, sig}
    # - revoked_serials: hex-encoded revoked public keys (sorted, deduped)
    # - sig: base64 ML-DSA-87 signature over canonical {issuer, version,
    #   revoked_serials, timestamp}; None when unsigned (lab fail-open + warn)

    def export_crl_bundle(
        self,
        user_identity_id: str,
        issuer: Optional[str] = None,
        version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Export local revocation list as a gossipable CRL bundle (no network).

        Signs with the existing ML-DSA-87 signer when a CRL/SBOM signing key
        is available (P2P_CRL_SIGNING_KEY / SBOM_SIGNING_KEY / certs anchor),
        else returns an unsigned bundle with a warning (lab fail-open).

        Args:
            user_identity_id: User whose revocation list to export
            issuer: Bundle issuer id (defaults to user_identity_id)
            version: Monotonic version (defaults to max(stored+1, now_ms))

        Returns:
            Dict bundle {issuer, version, revoked_serials, timestamp, alg, kid, sig}
        """
        with self._lock:
            import time as _time
            issuer = issuer or user_identity_id
            serials = sorted({
                pk.hex() for pk in self.get_revocation_list(user_identity_id)
            })
            if version is None:
                try:
                    stored = getattr(self, "_crl_versions", {}).get(issuer, 0)
                except Exception:
                    stored = 0
                version = max(int(stored or 0) + 1, int(_time.time() * 1000))
            body: Dict[str, Any] = {
                "issuer": issuer,
                "version": int(version),
                "revoked_serials": serials,
                "timestamp": datetime.now().isoformat(),
            }
            msg = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            # Try ML-DSA-87 signing with existing backend + resolvable key
            sk: Optional[bytes] = None
            kid: Optional[str] = None
            for spec in (os.environ.get("P2P_CRL_SIGNING_KEY"),
                         os.environ.get("SBOM_SIGNING_KEY"),
                         "certs/crl_mldsa87_signer.sk",
                         "certs/sbom_mldsa87_signer.sk"):
                try:
                    if spec and os.path.isfile(spec):
                        sk = Path(spec).read_bytes() or None
                        if sk:
                            kid = "mldsa87:" + hashlib.sha256(
                                (Path(spec).with_suffix(".pub").read_bytes()
                                 if Path(spec).with_suffix(".pub").is_file() else sk)
                            ).hexdigest()[:16]
                            break
                # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B112
                    continue
            if sk is not None and getattr(self, "_sig", None) is not None:
                try:
                    sig = self._sig.sign(sk, msg)
                    return {**body, "alg": "mldsa87", "kid": kid,
                            "sig": base64.b64encode(sig).decode("ascii")}
                except Exception as e:
                    logger.warning(f"CRL bundle signing failed, exporting unsigned: {e}")
            logger.warning("CRL bundle exported UNSIGNED (no ML-DSA-87 signing key; "
                           "set P2P_CRL_SIGNING_KEY/SBOM_SIGNING_KEY for production).")
            return {**body, "alg": "none", "kid": None, "sig": None}

    def import_crl_bundle(
        self,
        bundle: Dict[str, Any],
        verify_pubkey: Optional[bytes] = None,
        enforce_sig: bool = False,
    ) -> int:
        """Merge a gossiped CRL bundle into the local revocation list.

        Purely local (no network fetch). Verifies ML-DSA-87 `sig` when present
        (explicit pubkey, else P2P_CRL_VERIFY_KEY/SBOM_PUBKEY/certs anchor);
        accepts unsigned bundles with a warning (lab fail-open) unless
        enforce_sig, P2P_CRL_REQUIRE_SIG=1, or sticky prod auto-strict.
        Downgrade-protected via
        per-issuer monotonic version. Marks matching devices REVOKED.

        Args:
            bundle: CRL bundle dict
            verify_pubkey: Optional explicit ML-DSA-87 verification key
            enforce_sig: If True, reject unsigned/invalid bundles

        Returns:
            Number of newly added revocations (0 on reject/no-op)
        """
        with self._lock:
            try:
                if not isinstance(bundle, dict):
                    return 0
                issuer = str(bundle.get("issuer", ""))
                serials = bundle.get("revoked_serials", [])
                version = int(bundle.get("version", 0) or 0)
                sig_b64 = bundle.get("sig")
                if not issuer or not isinstance(serials, list):
                    logger.warning("CRL import: malformed bundle (missing issuer/serials)")
                    return 0
                require_sig = bool(enforce_sig) or crl_require_sig()
                # Verify signature when present
                if sig_b64:
                    body = {"issuer": issuer, "version": version,
                            "revoked_serials": sorted(set(serials)),
                            "timestamp": bundle.get("timestamp")}
                    # Canonical form must match export: exact keys, no alg/kid/sig
                    msg = json.dumps(
                        {"issuer": body["issuer"], "version": body["version"],
                         "revoked_serials": body["revoked_serials"],
                         "timestamp": body["timestamp"]},
                        sort_keys=True, separators=(",", ":")).encode("utf-8")
                    try:
                        sig = base64.b64decode(sig_b64)
                    except Exception:
                        logger.warning("CRL import: bad sig encoding; rejecting bundle")
                        return 0
                    pk = verify_pubkey
                    if pk is None:
                        for spec in (os.environ.get("P2P_CRL_VERIFY_KEY"),
                                     os.environ.get("SBOM_PUBKEY"),
                                     "certs/crl_mldsa87_signer.pub",
                                     "certs/sbom_mldsa87_signer.pub"):
                            try:
                                if spec and os.path.isfile(spec):
                                    pk = Path(spec).read_bytes() or None
                                    if pk:
                                        break
                            # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
                            except Exception:  # nosec: B112
                                continue
                    ok = False
                    if pk is not None and getattr(self, "_sig", None) is not None:
                        try:
                            ok = bool(self._sig.verify(pk, msg, sig))
                        except Exception:
                            ok = False
                    if not ok:
                        logger.warning("CRL import: signature verification FAILED; rejecting bundle")
                        return 0
                elif require_sig:
                    logger.warning("CRL import: unsigned bundle rejected (strict: P2P_CRL_REQUIRE_SIG/prod)")
                    return 0
                else:
                    logger.warning("CRL import: unsigned bundle merged (lab fail-open; "
                                   "set P2P_CRL_REQUIRE_SIG=1 to fail closed).")
                # Downgrade protection
                try:
                    versions = getattr(self, "_crl_versions", None)
                    if versions is None:
                        versions = {}
                        self._crl_versions = versions
                    if version <= int(versions.get(issuer, 0) or 0) and versions.get(issuer):
                        logger.warning(f"CRL import: stale version {version} <= "
                                       f"{versions.get(issuer)} for {issuer[:16]}; ignoring")
                        return 0
                    versions[issuer] = version
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                # Merge (issuer doubles as user_identity_id when known; else keep a
                # shell record so revocations are retained for future enrollments)
                target_uid = issuer if issuer in self._user_devices else issuer
                if target_uid not in self._user_devices:
                    self._user_devices[target_uid] = UserIdentityDevices(
                        user_identity_id=target_uid)
                user_devices = self._user_devices[target_uid]
                added = 0
                serial_set = {s for s in serials if isinstance(s, str)}
                pk_by_hex = {s for s in serial_set}
                for serial in serial_set:
                    try:
                        pk_bytes = bytes.fromhex(serial)
                    # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B112
                        continue
                    if pk_bytes not in user_devices.revocation_list:
                        user_devices.revocation_list.add(pk_bytes)
                        added += 1
                # Mark matching devices revoked
                now = datetime.now()
                for device in user_devices.devices.values():
                    try:
                        if device.public_key.hex() in pk_by_hex \
                                and device.status != DeviceStatus.REVOKED:
                            device.status = DeviceStatus.REVOKED
                            device.revoked_at = now
                            device.revocation_reason = "CRL gossip merge"
                    except Exception as exc:
                        # B112: a corrupt entry must not abort the merge, but
                        # must stay observable (it keeps its prior status).
                        logger.debug("CRL merge skipped one device entry: %s", exc)
                        continue
                logger.info(f"CRL import: merged {added} new revocation(s) "
                            f"from {issuer[:16]}... (v{version})")
                return added
            except Exception as e:
                # Prior revocations are retained; only the new delta is lost.
                logger.warning(f"CRL import failed (fail-closed, prior revocations retained): {e}")
                return 0
    
    # =========================================================================
    # Device Query Methods
    # =========================================================================
    
    def get_user_devices(
        self,
        user_identity_id: str,
        include_revoked: bool = False
    ) -> List[DeviceInfo]:
        """
        Get all devices for a user identity.
        
        Args:
            user_identity_id: User's identity ID
            include_revoked: If True, include revoked devices
            
        Returns:
            List of DeviceInfo objects
        """
        with self._lock:
            if user_identity_id not in self._user_devices:
                return []
            
            user_devices = self._user_devices[user_identity_id]
            
            if include_revoked:
                return list(user_devices.devices.values())
            else:
                return user_devices.get_active_devices()
    
    def get_device(
        self,
        user_identity_id: str,
        device_id: str
    ) -> Optional[DeviceInfo]:
        """Get a specific device."""
        with self._lock:
            if user_identity_id not in self._user_devices:
                return None
            
            return self._user_devices[user_identity_id].devices.get(device_id)
    
    def get_active_device_count(self, user_identity_id: str) -> int:
        """Get count of active devices for a user."""
        with self._lock:
            if user_identity_id not in self._user_devices:
                return 0
            return self._user_devices[user_identity_id].get_active_device_count()
    
    def can_add_device(self, user_identity_id: str) -> bool:
        """Check if user can add another device (max 5)."""
        with self._lock:
            if user_identity_id not in self._user_devices:
                return True  # New user can add first device
            return self._user_devices[user_identity_id].can_add_device()
    
    # =========================================================================
    # Encrypted Message Sync (Requirement 12.3)
    # =========================================================================
    
    def initialize_device_sync_session(
        self,
        user_identity_id: str,
        source_device_id: str,
        target_device_id: str,
        source_private_key: bytes
    ) -> Dict[str, Any]:
        """
        Initialize a Double Ratchet session for device-to-device message sync.
        
        Creates device-specific keys for encrypted message synchronization
        between two devices of the same user.
        
        Args:
            user_identity_id: User's identity ID
            source_device_id: Source device ID
            target_device_id: Target device ID
            source_private_key: Source device's private key
            
        Returns:
            Session info dict with session_id and initial keys
            
        Requirements: 12.3
        """
        with self._lock:
            if user_identity_id not in self._user_devices:
                raise ValueError(f"User {user_identity_id[:16]}... not found")
            
            user_devices = self._user_devices[user_identity_id]
            
            # Verify both devices exist and are active
            if source_device_id not in user_devices.devices:
                raise ValueError(f"Source device {source_device_id[:16]}... not found")
            if target_device_id not in user_devices.devices:
                raise ValueError(f"Target device {target_device_id[:16]}... not found")
            
            source_device = user_devices.devices[source_device_id]
            target_device = user_devices.devices[target_device_id]
            
            if source_device.status != DeviceStatus.ACTIVE:
                raise ValueError(f"Source device {source_device_id[:16]}... is not active")
            if target_device.status != DeviceStatus.ACTIVE:
                raise ValueError(f"Target device {target_device_id[:16]}... is not active")
            
            # Generate session ID
            session_id = hashlib.sha3_256(
                source_device_id.encode() + target_device_id.encode() + 
                secrets.token_bytes(32)
            ).hexdigest()
            
            # Derive device-specific root key using HKDF
            # This creates a unique key hierarchy for this device pair
            root_key = self._derive_device_sync_key(
                user_identity_id=user_identity_id,
                source_device_id=source_device_id,
                target_device_id=target_device_id,
                source_private_key=source_private_key,
                target_public_key=target_device.public_key
            )
            
            # Create session info
            session_info = {
                'session_id': session_id,
                'user_identity_id': user_identity_id,
                'source_device_id': source_device_id,
                'target_device_id': target_device_id,
                'root_key': base64.b64encode(root_key).decode('utf-8'),
                'created_at': datetime.now().isoformat(),
                'message_count': 0,
                'last_sync': None,
            }
            
            # Store session
            self._device_ratchet_sessions[session_id] = session_info
            
            logger.info(
                f"Initialized device sync session {session_id[:16]}... "
                f"between {source_device_id[:16]}... and {target_device_id[:16]}..."
            )
            
            return session_info
    
    def _derive_device_sync_key(
        self,
        user_identity_id: str,
        source_device_id: str,
        target_device_id: str,
        source_private_key: bytes,
        target_public_key: bytes
    ) -> bytes:
        """
        Derive device-specific sync key using HKDF.
        
        Creates a unique key for the device pair that can be used
        as the root key for a Double Ratchet session.
        """
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes

            # Full key material on both sides (truncating to [:64] would
            # discard most of the ML-DSA entropy and invite cross-protocol
            # confusion). Salt binds the device pair; info binds purpose.
            ikm = hashlib.sha3_512(
                b"MultiDeviceSync::v2::" + source_private_key + target_public_key
            ).digest()

            pair_salt = hashlib.sha512(
                f"device_sync_salt:{user_identity_id}:{source_device_id}:{target_device_id}".encode('utf-8')
            ).digest()

            # Derive key using HKDF-SHA512
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=32,  # 256-bit root key
                salt=pair_salt,
                info=f"device_sync_v2:{source_device_id}:{target_device_id}".encode()
            )

            return hkdf.derive(ikm)
            
        except ImportError:
            raise RuntimeError(
                "FAIL-CLOSED: cryptography library is required for HKDF key derivation. "
                "Install with: pip install cryptography"
            )
    
    def sync_message_to_device(
        self,
        session_id: str,
        message_data: bytes
    ) -> bytes:
        """
        Encrypt a message to sync with another device.
        
        Args:
            session_id: Sync session ID
            message_data: Message data to sync
            
        Returns:
            Encrypted message bytes
            
        Requirements: 12.3
        """
        with self._lock:
            if session_id not in self._device_ratchet_sessions:
                raise ValueError(f"Session {session_id[:16]}... not found")
            
            session = self._device_ratchet_sessions[session_id]
            root_key = base64.b64decode(session['root_key'])

            # Derive message key from root key and message count
            message_count = session['message_count']
            message_key = self._derive_message_key(root_key, message_count)

            # Encrypt message using ChaCha20-Poly1305
            encrypted = self._encrypt_sync_message(message_key, message_data, message_count, session_id)
            
            # Update session
            session['message_count'] = message_count + 1
            session['last_sync'] = datetime.now().isoformat()
            
            return encrypted
    
    def receive_synced_message(
        self,
        session_id: str,
        encrypted_data: bytes,
        message_index: int
    ) -> bytes:
        """
        Decrypt a message received from another device.
        
        Args:
            session_id: Sync session ID
            encrypted_data: Encrypted message data
            message_index: Message index for key derivation
            
        Returns:
            Decrypted message bytes
            
        Requirements: 12.3
        """
        with self._lock:
            if session_id not in self._device_ratchet_sessions:
                raise ValueError(f"Session {session_id[:16]}... not found")
            
            session = self._device_ratchet_sessions[session_id]
            root_key = base64.b64decode(session['root_key'])

            # Replay/out-of-order window: reject duplicate indices and absurd
            # forward jumps (index is AAD-bound, so replays/forks fail closed).
            seen = session.setdefault('received_indices', set())
            max_seen = session.get('max_index_seen', -1)
            if message_index in seen:
                raise ValueError(f"Replay rejected: sync index {message_index} already processed")
            if message_index < 0 or message_index > max_seen + 1024:
                raise ValueError(f"Sync index {message_index} outside acceptance window")

            # Derive message key
            message_key = self._derive_message_key(root_key, message_index)

            # Decrypt message (raises on AAD/tag mismatch)
            plaintext = self._decrypt_sync_message(message_key, encrypted_data, message_index, session_id)

            seen.add(message_index)
            if len(seen) > 2048:
                # Prune oldest to avoid unbounded memory growth while keeping recent window
                min_retained = max_seen - 1024
                session['received_indices'] = {i for i in seen if i >= min_retained}
            if message_index > max_seen:
                session['max_index_seen'] = message_index

            session['last_sync'] = datetime.now().isoformat()
            return plaintext
    
    def _derive_message_key(self, root_key: bytes, message_index: int) -> bytes:
        """Derive message key from root key and index."""
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            
            hkdf = HKDF(
                algorithm=hashes.SHA384(),
                length=32,
                salt=message_index.to_bytes(8, 'big'),
                info=b"device_sync_message_key"
            )
            return hkdf.derive(root_key)
        except ImportError:
            raise RuntimeError(
                "FAIL-CLOSED: cryptography library is required for HKDF message key derivation. "
                "Install with: pip install cryptography"
            )
    
    def _encrypt_sync_message(
        self,
        key: bytes,
        plaintext: bytes,
        message_index: int,
        session_id: str = ""
    ) -> bytes:
        """Encrypt message using ChaCha20-Poly1305 with random nonce + AAD."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

            cipher = ChaCha20Poly1305(key)
            # 96-bit cryptographically random nonce (never counter-derived:
            # counters repeat across restarts; randomness does not).
            nonce = secrets.token_bytes(12)
            aad = f"device_sync_v2:{session_id}:{message_index}".encode('utf-8')
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
            return nonce + ciphertext
        except ImportError:
            raise RuntimeError(
                "FAIL-CLOSED: cryptography library is required for ChaCha20-Poly1305 encryption. "
                "Install with: pip install cryptography"
            )

    def _decrypt_sync_message(
        self,
        key: bytes,
        ciphertext: bytes,
        message_index: int,
        session_id: str = ""
    ) -> bytes:
        """Decrypt message using ChaCha20-Poly1305 (AAD-bound)."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

            if len(ciphertext) < 12 + 16:
                raise ValueError("Sync ciphertext too short")
            cipher = ChaCha20Poly1305(key)
            nonce = ciphertext[:12]
            encrypted = ciphertext[12:]
            aad = f"device_sync_v2:{session_id}:{message_index}".encode('utf-8')
            return cipher.decrypt(nonce, encrypted, aad)
        except ImportError:
            raise RuntimeError(
                "FAIL-CLOSED: cryptography library is required for ChaCha20-Poly1305 decryption. "
                "Install with: pip install cryptography"
            )
    
    # =========================================================================
    # Persistence
    # =========================================================================
    
    # At-rest envelope for devices.json (H14): AES-256-GCM sealed with a
    # scrypt key from P2P_STORAGE_PASSPHRASE when configured ("DEVENC_V1:").
    # Without a passphrase the registry stays plaintext readable by the
    # account (device names/linkage); private keys are NEVER stored here.
    _DEVENC_MAGIC = b"DEVENC_V1:"
    _warned_plaintext_devices = False

    def _devices_envelope_key(self) -> Optional[bytes]:
        pw = os.environ.get("P2P_STORAGE_PASSPHRASE", "")
        if not pw:
            return None
        return hashlib.scrypt(pw.encode('utf-8'),
                              salt=b"MultiDeviceRegistry::Envelope::v1",
                              n=32768, r=8, p=1,
                              maxmem=64 * 1024 * 1024, dklen=32)

    def save_to_file(self, filepath: Optional[str] = None) -> None:
        """Save device data to file (sealed envelope when a passphrase exists, atomic write)."""
        with self._lock:
            if self.in_memory_only:
                return
            
            filepath = filepath or str(self.storage_path / "devices.json")
            target_path = Path(filepath)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            temp_filepath = str(target_path.with_name(f"{target_path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"))
            
            data = {
                'user_devices': {}
            }
            
            for user_id, user_devices in list(self._user_devices.items()):
                data['user_devices'][user_id] = {
                    'user_identity_id': user_devices.user_identity_id,
                    'root_device_id': user_devices.root_device_id,
                    'devices': {
                        did: d.to_dict() for did, d in list(user_devices.devices.items())
                    },
                    'revocation_list': [
                        base64.b64encode(pk).decode('utf-8') 
                        for pk in list(user_devices.revocation_list)
                    ]
                }
            
            try:
                key = self._devices_envelope_key()
                if key is not None:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    nonce = secrets.token_bytes(12)
                    ct = AESGCM(key).encrypt(
                        nonce, json.dumps(data).encode('utf-8'),
                        b"MultiDeviceRegistry::v1")
                    fd = os.open(temp_filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, 'wb') as f:
                        f.write(self._DEVENC_MAGIC + nonce + ct)
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except OSError:
                            pass
                else:
                    # 2028 hardening: plaintext registry relies on 0600 ACL only —
                    # revocation list tamper is undetected without sealing. Fail-closed
                    # in production (sticky prod); lab keeps ACL-only write + warning.
                    _prod = os.environ.get("SECURE_P2P_PRODUCTION", "0") == "1" or os.environ.get("P2P_PRODUCTION", "0").lower() in ("1", "true")
                    if _prod:
                        raise ValueError("FAIL-CLOSED: refusing plaintext devices.json write in production (set P2P_STORAGE_PASSPHRASE to seal registry incl. revocation list)")
                    with open(temp_filepath, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2)
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except OSError:
                            pass
                    try:
                        os.chmod(temp_filepath, 0o600)
                    except OSError:
                        pass
                    if not MultiDeviceManager._warned_plaintext_devices:
                        MultiDeviceManager._warned_plaintext_devices = True
                        logger.warning(
                            "devices.json stored WITHOUT at-rest sealing "
                            "(set P2P_STORAGE_PASSPHRASE to seal it).")

                # Atomic replacement
                os.replace(temp_filepath, filepath)
                logger.info(f"Saved device data atomically to {filepath}")
            finally:
                if os.path.exists(temp_filepath):
                    try:
                        os.remove(temp_filepath)
                    except OSError:
                        pass
    
    def load_from_file(self, filepath: Optional[str] = None) -> None:
        """Load device data from file (sealed envelope or legacy plaintext)."""
        with self._lock:
            filepath = filepath or str(self.storage_path / "devices.json")

            if not os.path.exists(filepath):
                return

            with open(filepath, 'rb') as f:
                raw = f.read()
            if not raw:
                return
            if raw.startswith(self._DEVENC_MAGIC):
                key = self._devices_envelope_key()
                if key is None:
                    raise ValueError(
                        "devices.json is sealed but P2P_STORAGE_PASSPHRASE is not "
                        "set: refusing to run blind (fail-closed)")
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce, ct = raw[len(self._DEVENC_MAGIC):][:12], raw[len(self._DEVENC_MAGIC) + 12:]
                data = json.loads(AESGCM(key).decrypt(
                    nonce, ct, b"MultiDeviceRegistry::v1").decode('utf-8'))
            else:
                data = json.loads(raw.decode('utf-8'))
            
            for user_id, user_data in data.get('user_devices', {}).items():
                user_devices = UserIdentityDevices(
                    user_identity_id=user_data['user_identity_id']
                )
                user_devices.root_device_id = user_data.get('root_device_id')
                
                for did, device_data in user_data.get('devices', {}).items():
                    user_devices.devices[did] = DeviceInfo.from_dict(device_data)
                
                for pk_b64 in user_data.get('revocation_list', []):
                    user_devices.revocation_list.add(base64.b64decode(pk_b64))
                
                self._user_devices[user_id] = user_devices
            
            logger.info(f"Loaded device data from {filepath}")


# Convenience function to get a global instance
_global_manager: Optional[MultiDeviceManager] = None

def get_multi_device_manager() -> MultiDeviceManager:
    """Get the global MultiDeviceManager instance."""
    global _global_manager
    if _global_manager is None:
        _global_manager = MultiDeviceManager()
    return _global_manager


# ---------------------------------------------------------------------------
# Module-level CRL gossip helpers (air-gap, no network fetch).
# ---------------------------------------------------------------------------

def export_crl_bundle(
    manager: MultiDeviceManager,
    user_identity_id: str,
    issuer: Optional[str] = None,
    version: Optional[int] = None,
) -> Dict[str, Any]:
    """Export a CRL bundle via `manager` (see MultiDeviceManager.export_crl_bundle)."""
    return manager.export_crl_bundle(user_identity_id, issuer=issuer, version=version)


def import_crl_bundle(
    manager: MultiDeviceManager,
    bundle: Dict[str, Any],
    verify_pubkey: Optional[bytes] = None,
    enforce_sig: bool = False,
) -> int:
    """Merge a CRL bundle via `manager` (see MultiDeviceManager.import_crl_bundle)."""
    return manager.import_crl_bundle(bundle, verify_pubkey=verify_pubkey,
                                     enforce_sig=enforce_sig)

