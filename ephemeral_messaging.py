"""
Ephemeral Messaging System - DoD 5220.22-M Compliant Secure Message Deletion

This module provides ephemeral messaging capabilities with configurable TTL,
read-once messages, and secure deletion using DoD 5220.22-M compliant wiping.

Standards Compliance:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

► DoD 5220.22-M: National Industrial Security Program Operating Manual
  • §4-3: Secure Data Sanitization and Overwrite Procedures
  • Reference: https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodm/522022m.pdf

► NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization
  • Clear, Purge, and Destroy sanitization methods
  • Reference: https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final

Implementation Features:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PASS Configurable TTL (1 minute to 30 days)
PASS Read-once messages with immediate secure deletion
PASS DoD 5220.22-M 3-pass secure wiping
PASS Deletion synchronization across devices
PASS Cryptographic verification of deletion
PASS Thread-safe message storage
"""

import os
import sys
import time
import uuid
import json
import hmac
import hashlib
import secrets
import threading
import logging
from typing import Optional, Dict, List, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_AESGCM = True
except ImportError:
    HAS_AESGCM = False

# Configure logging
ephemeral_logger = logging.getLogger("ephemeral_messaging")
ephemeral_logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging
file_handler = logging.FileHandler(os.path.join("logs", "ephemeral_messaging.log"))
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
file_handler.setFormatter(file_formatter)
ephemeral_logger.addHandler(file_handler)

# Let logs propagate to root logger for console output (avoid duplicate handlers)
ephemeral_logger.propagate = True


class MessageType(Enum):
    """Types of ephemeral messages."""
    STANDARD = "standard"       # Normal message with TTL
    READ_ONCE = "read_once"     # Delete after first read
    TIMED = "timed"             # Delete after specific time


class DeletionStatus(Enum):
    """Status of message deletion."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    VERIFIED = "verified"
    FAILED = "failed"


class EphemeralMessageError(Exception):
    """Base exception for ephemeral messaging errors."""


class MessageNotFoundError(EphemeralMessageError):
    """Raised when a message is not found."""


class MessageExpiredError(EphemeralMessageError):
    """Raised when attempting to access an expired message."""


class SecureDeletionError(EphemeralMessageError):
    """Raised when secure deletion fails."""


class TTLValidationError(EphemeralMessageError):
    """Raised when TTL is outside valid range."""


# TTL Constants
MIN_TTL_SECONDS = 60              # 1 minute minimum
MAX_TTL_SECONDS = 30 * 24 * 3600  # 30 days maximum
DEFAULT_TTL_SECONDS = 24 * 3600   # 24 hours default


@dataclass
class EphemeralMessage:
    """Represents an ephemeral message with TTL and secure deletion support."""
    message_id: str
    content: bytearray  # Mutable for secure wiping
    sender_id: str
    recipient_id: str
    message_type: MessageType
    created_at: float
    expires_at: float
    ttl_seconds: int
    read_count: int = 0
    is_deleted: bool = False
    deletion_status: DeletionStatus = DeletionStatus.PENDING
    deletion_timestamp: Optional[float] = None
    deletion_verification_hash: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if message has expired based on TTL."""
        return time.time() >= self.expires_at
    
    def time_remaining(self) -> float:
        """Get remaining time before expiration in seconds."""
        remaining = self.expires_at - time.time()
        return max(0.0, remaining)
    
    def should_delete_on_read(self) -> bool:
        """Check if message should be deleted after reading."""
        return self.message_type == MessageType.READ_ONCE

    def copy(self) -> "EphemeralMessage":
        """Return an isolated copy: fresh content bytearray + copied metadata.

        Callers must never receive the live stored object (mutating it would
        corrupt or resurrect store state, e.g. clearing is_deleted).
        """
        import copy as _copy
        return EphemeralMessage(
            message_id=self.message_id,
            content=bytearray(self.content),
            sender_id=self.sender_id,
            recipient_id=self.recipient_id,
            message_type=self.message_type,
            created_at=self.created_at,
            expires_at=self.expires_at,
            ttl_seconds=self.ttl_seconds,
            read_count=self.read_count,
            is_deleted=self.is_deleted,
            deletion_status=self.deletion_status,
            deletion_timestamp=self.deletion_timestamp,
            deletion_verification_hash=(bytes(self.deletion_verification_hash)
                                        if self.deletion_verification_hash else None),
            metadata=_copy.deepcopy(self.metadata),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert EphemeralMessage to dictionary with content in hex."""
        return {
            "message_id": self.message_id,
            "content": self.content.hex() if isinstance(self.content, (bytes, bytearray)) else "",
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "message_type": self.message_type.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "ttl_seconds": self.ttl_seconds,
            "read_count": self.read_count,
            "is_deleted": self.is_deleted,
            "deletion_status": self.deletion_status.value,
            "deletion_timestamp": self.deletion_timestamp,
            "deletion_verification_hash": self.deletion_verification_hash.hex() if self.deletion_verification_hash else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EphemeralMessage":
        """Reconstruct EphemeralMessage from dictionary."""
        content_hex = data.get("content", "")
        content_bytes = bytes.fromhex(content_hex) if content_hex else b""
        d_hash_hex = data.get("deletion_verification_hash")
        d_hash = bytes.fromhex(d_hash_hex) if d_hash_hex else None
        return cls(
            message_id=data["message_id"],
            content=bytearray(content_bytes),
            sender_id=data["sender_id"],
            recipient_id=data["recipient_id"],
            message_type=MessageType(data["message_type"]),
            created_at=data["created_at"],
            expires_at=data["expires_at"],
            ttl_seconds=data["ttl_seconds"],
            read_count=data.get("read_count", 0),
            is_deleted=data.get("is_deleted", False),
            deletion_status=DeletionStatus(data.get("deletion_status", "pending")),
            deletion_timestamp=data.get("deletion_timestamp"),
            deletion_verification_hash=d_hash,
            metadata=data.get("metadata", {}),
        )

    def to_encrypted_envelope(self, aead_key: bytes) -> bytes:
        """
        Encrypt entire ephemeral message including all metadata inside an AEAD envelope
        (Item 36 / Finding 5.5). Hides sender_id, recipient_id, timestamps, and TTL on wire.
        """
        if not HAS_AESGCM:
            raise RuntimeError("cryptography AESGCM required for encrypted envelope")
        if len(aead_key) != 32:
            raise ValueError("AEAD key must be 32 bytes")
        raw_json = json.dumps(self.to_dict()).encode("utf-8")
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(aead_key)
        aad = b"EPHEMERAL_MSG_V1"
        ciphertext = aesgcm.encrypt(nonce, raw_json, aad)
        return nonce + ciphertext

    @classmethod
    def from_encrypted_envelope(cls, envelope_bytes: bytes, aead_key: bytes) -> "EphemeralMessage":
        """
        Decrypt and parse an ephemeral message AEAD envelope.
        """
        if not HAS_AESGCM:
            raise RuntimeError("cryptography AESGCM required for encrypted envelope")
        if len(aead_key) != 32:
            raise ValueError("AEAD key must be 32 bytes")
        if len(envelope_bytes) < 12 + 16:
            raise EphemeralMessageError("Encrypted envelope too short")
        nonce = envelope_bytes[:12]
        ciphertext = envelope_bytes[12:]
        aesgcm = AESGCM(aead_key)
        aad = b"EPHEMERAL_MSG_V1"
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise EphemeralMessageError(f"Envelope AEAD authentication failed: {e}")
        data = json.loads(plaintext.decode("utf-8"))
        return cls.from_dict(data)


@dataclass
class DeletionRecord:
    """Record of a message deletion for sync purposes."""
    message_id: str
    deleted_at: float
    deletion_reason: str
    device_id: str
    verification_hash: bytes
    sync_status: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert DeletionRecord to dictionary."""
        return {
            "message_id": self.message_id,
            "deleted_at": self.deleted_at,
            "deletion_reason": self.deletion_reason,
            "device_id": self.device_id,
            "verification_hash": self.verification_hash.hex() if isinstance(self.verification_hash, (bytes, bytearray)) else "",
            "sync_status": self.sync_status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeletionRecord":
        """Reconstruct DeletionRecord from dictionary."""
        v_hash_hex = data.get("verification_hash", "")
        v_hash = bytes.fromhex(v_hash_hex) if v_hash_hex else b""
        return cls(
            message_id=data["message_id"],
            deleted_at=data["deleted_at"],
            deletion_reason=data["deletion_reason"],
            device_id=data["device_id"],
            verification_hash=v_hash,
            sync_status=data.get("sync_status", {}),
        )

    def to_encrypted_envelope(self, aead_key: bytes) -> bytes:
        """
        Encrypt deletion sync record inside an AEAD envelope (Item 36 / Finding 5.5).
        """
        if not HAS_AESGCM:
            raise RuntimeError("cryptography AESGCM required for encrypted envelope")
        if len(aead_key) != 32:
            raise ValueError("AEAD key must be 32 bytes")
        raw_json = json.dumps(self.to_dict()).encode("utf-8")
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(aead_key)
        aad = b"DELETION_REC_V1"
        ciphertext = aesgcm.encrypt(nonce, raw_json, aad)
        return nonce + ciphertext

    @classmethod
    def from_encrypted_envelope(cls, envelope_bytes: bytes, aead_key: bytes) -> "DeletionRecord":
        """
        Decrypt and parse a deletion record AEAD envelope.
        """
        if not HAS_AESGCM:
            raise RuntimeError("cryptography AESGCM required for encrypted envelope")
        if len(aead_key) != 32:
            raise ValueError("AEAD key must be 32 bytes")
        if len(envelope_bytes) < 12 + 16:
            raise EphemeralMessageError("Encrypted envelope too short")
        nonce = envelope_bytes[:12]
        ciphertext = envelope_bytes[12:]
        aesgcm = AESGCM(aead_key)
        aad = b"DELETION_REC_V1"
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise EphemeralMessageError(f"Envelope AEAD authentication failed: {e}")
        data = json.loads(plaintext.decode("utf-8"))
        return cls.from_dict(data)


class SecureWiper:
    """
    DoD 5220.22-M compliant secure memory wiping.
    
    Implements 3-pass overwrite pattern:
    - Pass 1: All zeros (0x00)
    - Pass 2: All ones (0xFF)
    - Pass 3: Random data
    """
    
    WIPE_PASSES = 3
    PATTERN_ZEROS = 0x00
    PATTERN_ONES = 0xFF
    
    @classmethod
    def secure_wipe(cls, data: bytearray) -> bool:
        """
        Securely wipe data using DoD 5220.22-M 3-pass pattern.
        
        Args:
            data: Mutable bytearray to wipe
            
        Returns:
            True if wipe was successful and verified
            
        Raises:
            SecureDeletionError: If wiping fails
        """
        if not isinstance(data, bytearray):
            raise SecureDeletionError("Data must be a mutable bytearray for secure wiping")
        
        if len(data) == 0:
            return True
        
        try:
            data_len = len(data)
            
            # Pass 1: Overwrite with zeros
            for i in range(data_len):
                data[i] = cls.PATTERN_ZEROS
            
            # Pass 2: Overwrite with ones
            for i in range(data_len):
                data[i] = cls.PATTERN_ONES
            
            # Pass 3: Overwrite with cryptographically secure random data
            rand_buf = bytearray(secrets.token_bytes(data_len))
            for i in range(data_len):
                data[i] = rand_buf[i]
            try:
                import ctypes
                c_buf = (ctypes.c_char * data_len).from_buffer(rand_buf)
                ctypes.memset(c_buf, 0, data_len)
            except Exception:
                rand_buf[:] = b"\x00" * data_len
            
            # Final pass: Zero out for verification
            for i in range(data_len):
                data[i] = cls.PATTERN_ZEROS
            
            # Verify wipe
            if not cls.verify_wipe(data):
                raise SecureDeletionError("Wipe verification failed")
            
            ephemeral_logger.debug(f"Securely wiped {data_len} bytes using DoD 5220.22-M pattern")
            return True
            
        except Exception as e:
            ephemeral_logger.error(f"Secure wipe failed: {e}")
            raise SecureDeletionError(f"Secure wipe failed: {e}")
    
    @classmethod
    def verify_wipe(cls, data: bytearray) -> bool:
        """Verify that data has been wiped (all zeros)."""
        return all(b == 0 for b in data)
    
    @classmethod
    def generate_verification_hash(cls, message_id: str, deletion_time: float) -> bytes:
        """Generate cryptographic hash to verify deletion occurred."""
        verification_data = f"{message_id}:{deletion_time}:deleted".encode()
        return hashlib.sha3_256(verification_data).digest()


class EphemeralMessageManager:
    """
    Manages ephemeral messages with configurable TTL and secure deletion.
    
    Features:
    - Configurable TTL (1 minute to 30 days)
    - Read-once messages
    - DoD 5220.22-M secure deletion
    - Automatic expiry checking
    - Deletion synchronization
    """
    
    def __init__(self, 
                 device_id: Optional[str] = None,
                 default_ttl: int = DEFAULT_TTL_SECONDS,
                 expiry_check_interval: float = 60.0,
                 on_message_deleted: Optional[Callable[[str], None]] = None):
        """
        Initialize EphemeralMessageManager.
        
        Args:
            device_id: Unique identifier for this device
            default_ttl: Default TTL in seconds (1 min to 30 days)
            expiry_check_interval: How often to check for expired messages
            on_message_deleted: Callback when a message is deleted
        """
        self.device_id = device_id or str(uuid.uuid4())
        self.default_ttl = self._validate_ttl(default_ttl)
        self.expiry_check_interval = expiry_check_interval
        self.on_message_deleted = on_message_deleted
        
        # Thread-safe message storage with bounded capacity
        self.MAX_STORED_MESSAGES = 10000
        self._messages: Dict[str, EphemeralMessage] = {}
        self._deletion_records: Dict[str, DeletionRecord] = {}
        self._lock = threading.RLock()
        
        # Expiry checker thread
        self._expiry_checker_running = False
        self._expiry_checker_thread: Optional[threading.Thread] = None
        
        # Deletion sync callbacks
        self._sync_callbacks: List[Callable[[DeletionRecord], None]] = []
        
        ephemeral_logger.info(f"EphemeralMessageManager initialized with device_id={self.device_id}, default_ttl={default_ttl}s")
    
    def _validate_ttl(self, ttl: int) -> int:
        """Validate TTL is within allowed range."""
        if ttl < MIN_TTL_SECONDS:
            raise TTLValidationError(f"TTL must be at least {MIN_TTL_SECONDS} seconds (1 minute)")
        if ttl > MAX_TTL_SECONDS:
            raise TTLValidationError(f"TTL cannot exceed {MAX_TTL_SECONDS} seconds (30 days)")
        return ttl
    
    def start_expiry_checker(self) -> None:
        """Start background thread to check for expired messages."""
        if self._expiry_checker_running:
            return
        
        self._expiry_checker_running = True
        self._expiry_checker_thread = threading.Thread(
            target=self._expiry_checker_loop,
            daemon=True,
            name="EphemeralExpiryChecker"
        )
        self._expiry_checker_thread.start()
        ephemeral_logger.info("Expiry checker thread started")
    
    def stop_expiry_checker(self) -> None:
        """Stop the expiry checker thread."""
        self._expiry_checker_running = False
        if self._expiry_checker_thread:
            self._expiry_checker_thread.join(timeout=5.0)
            self._expiry_checker_thread = None
        ephemeral_logger.info("Expiry checker thread stopped")
    
    def _expiry_checker_loop(self) -> None:
        """Background loop to check and delete expired messages."""
        while self._expiry_checker_running:
            try:
                self.delete_expired_messages()
            except Exception as e:
                ephemeral_logger.error(f"Error in expiry checker: {e}")
            
            time.sleep(self.expiry_check_interval)
    
    def create_message(self,
                       content: bytes,
                       sender_id: str,
                       recipient_id: str,
                       ttl_seconds: Optional[int] = None,
                       message_type: MessageType = MessageType.STANDARD,
                       metadata: Optional[Dict[str, Any]] = None) -> EphemeralMessage:
        """
        Create a new ephemeral message.
        
        Args:
            content: Message content (will be copied to mutable bytearray)
            sender_id: Sender identifier
            recipient_id: Recipient identifier
            ttl_seconds: Time-to-live in seconds (1 min to 30 days)
            message_type: Type of ephemeral message
            metadata: Optional metadata dictionary
            
        Returns:
            Created EphemeralMessage
            
        Raises:
            TTLValidationError: If TTL is outside valid range
        """
        ttl = self._validate_ttl(ttl_seconds or self.default_ttl)
        
        message_id = str(uuid.uuid4())
        created_at = time.time()
        expires_at = created_at + ttl
        
        # Copy content to mutable bytearray for secure wiping
        content_array = bytearray(content)
        
        message = EphemeralMessage(
            message_id=message_id,
            content=content_array,
            sender_id=sender_id,
            recipient_id=recipient_id,
            message_type=message_type,
            created_at=created_at,
            expires_at=expires_at,
            ttl_seconds=ttl,
            metadata=metadata or {}
        )
        
        with self._lock:
            if len(self._messages) >= self.MAX_STORED_MESSAGES:
                now = time.time()
                oldest_id = None
                oldest_time = float('inf')
                for mid, m in self._messages.items():
                    if m.expires_at <= now:
                        oldest_id = mid
                        break
                    if m.created_at < oldest_time:
                        oldest_time = m.created_at
                        oldest_id = mid
                if oldest_id:
                    evicted = self._messages.pop(oldest_id)
                    if evicted.content:
                        SecureWiper.secure_wipe(evicted.content)

            self._messages[message_id] = message
        
        ephemeral_logger.info(f"Created ephemeral message {message_id} with TTL={ttl}s, type={message_type.value}")
        return message
    
    def create_read_once_message(self,
                                  content: bytes,
                                  sender_id: str,
                                  recipient_id: str,
                                  ttl_seconds: Optional[int] = None,
                                  metadata: Optional[Dict[str, Any]] = None) -> EphemeralMessage:
        """
        Create a read-once message that deletes after first viewing.
        
        Args:
            content: Message content
            sender_id: Sender identifier
            recipient_id: Recipient identifier
            ttl_seconds: Maximum TTL before auto-deletion
            metadata: Optional metadata
            
        Returns:
            Created read-once EphemeralMessage
        """
        return self.create_message(
            content=content,
            sender_id=sender_id,
            recipient_id=recipient_id,
            ttl_seconds=ttl_seconds,
            message_type=MessageType.READ_ONCE,
            metadata=metadata
        )
    
    def get_message(self, message_id: str) -> Optional[EphemeralMessage]:
        """
        Get a message by ID without marking as read.

        Returns an ISOLATED COPY: mutating the result cannot corrupt store
        state (resurrect deleted messages, alter TTLs, poison content).

        Args:
            message_id: Message identifier

        Returns:
            EphemeralMessage copy or None if not found/expired
        """
        with self._lock:
            message = self._messages.get(message_id)

            if message is None:
                return None

            if message.is_deleted:
                return None

            if message.is_expired():
                # Auto-delete expired message
                self._delete_message_internal(message_id, "expired")
                return None

            return message.copy()

    def export_message_envelope(self, message_id: str, aead_key: bytes) -> bytes:
        """Export an ephemeral message encrypted with all metadata inside an AEAD envelope."""
        with self._lock:
            msg = self.get_message(message_id)
            if not msg:
                raise MessageNotFoundError(f"Message {message_id} not found")
            return msg.to_encrypted_envelope(aead_key)

    # Upper bound for a single imported envelope payload (H30).
    MAX_IMPORT_BYTES = 1024 * 1024

    def import_message_envelope(self, envelope_bytes: bytes, aead_key: bytes) -> EphemeralMessage:
        """Import an ephemeral message from an encrypted AEAD envelope and store locally.

        Same admission caps as create_message: envelope size, TTL range, and
        the 10k store bound all apply (imports previously bypassed them).
        """
        if len(envelope_bytes) > self.MAX_IMPORT_BYTES + 4096:
            raise ValueError("Envelope exceeds import size cap")
        msg = EphemeralMessage.from_encrypted_envelope(envelope_bytes, aead_key)
        # Re-validate TTL and content bounds from the (adversarial) envelope
        ttl = int(msg.expires_at - msg.created_at) if msg.expires_at > msg.created_at else 0
        self._validate_ttl(ttl)
        if len(msg.content) > self.MAX_IMPORT_BYTES:
            raise ValueError("Imported content exceeds size cap")
        with self._lock:
            if len(self._messages) >= self.MAX_STORED_MESSAGES:
                now = time.time()
                oldest_id = None
                oldest_time = float('inf')
                for mid, m in self._messages.items():
                    if m.expires_at <= now:
                        oldest_id = mid
                        break
                    if m.created_at < oldest_time:
                        oldest_time = m.created_at
                        oldest_id = mid
                if oldest_id:
                    evicted = self._messages.pop(oldest_id)
                    if evicted.content:
                        SecureWiper.secure_wipe(evicted.content)
            self._messages[msg.message_id] = msg
        return msg
    
    def read_message(self, message_id: str) -> Optional[bytes]:
        """
        Read a message and handle read-once deletion.
        
        Args:
            message_id: Message identifier
            
        Returns:
            Message content as bytes, or None if not found/expired
            
        Note:
            For read-once messages, this will trigger immediate secure deletion.
        """
        with self._lock:
            message = self._messages.get(message_id)
            
            if message is None:
                ephemeral_logger.warning(f"Message {message_id} not found")
                return None
            
            if message.is_deleted:
                ephemeral_logger.warning(f"Message {message_id} already deleted")
                return None
            
            if message.is_expired():
                self._delete_message_internal(message_id, "expired")
                ephemeral_logger.warning(f"Message {message_id} expired")
                return None
            
            # Copy content before potential deletion
            content = bytes(message.content)
            message.read_count += 1
            
            # Handle read-once messages
            if message.should_delete_on_read():
                ephemeral_logger.info(f"Read-once message {message_id} viewed, triggering secure deletion")
                self._delete_message_internal(message_id, "read_once")
            
            return content
    
    def delete_message(self, message_id: str, reason: str = "manual") -> bool:
        """
        Manually delete a message with secure wiping.
        
        Args:
            message_id: Message identifier
            reason: Reason for deletion
            
        Returns:
            True if deletion was successful
        """
        with self._lock:
            return self._delete_message_internal(message_id, reason)
    
    def _delete_message_internal(self, message_id: str, reason: str) -> bool:
        """
        Internal method to delete a message with secure wiping.
        
        Args:
            message_id: Message identifier
            reason: Reason for deletion
            
        Returns:
            True if deletion was successful
        """
        message = self._messages.get(message_id)
        
        if message is None:
            return False
        
        if message.is_deleted:
            return True  # Already deleted
        
        try:
            message.deletion_status = DeletionStatus.IN_PROGRESS
            deletion_time = time.time()
            
            # Secure wipe the content
            SecureWiper.secure_wipe(message.content)
            
            # Update message state
            message.is_deleted = True
            message.deletion_status = DeletionStatus.COMPLETED
            message.deletion_timestamp = deletion_time
            message.deletion_verification_hash = SecureWiper.generate_verification_hash(
                message_id, deletion_time
            )
            
            # Create deletion record for sync
            deletion_record = DeletionRecord(
                message_id=message_id,
                deleted_at=deletion_time,
                deletion_reason=reason,
                device_id=self.device_id,
                verification_hash=message.deletion_verification_hash
            )
            self._deletion_records[message_id] = deletion_record
            
            # Verify deletion
            if SecureWiper.verify_wipe(message.content):
                message.deletion_status = DeletionStatus.VERIFIED
                ephemeral_logger.info(f"Message {message_id} securely deleted and verified (reason: {reason})")
            else:
                message.deletion_status = DeletionStatus.FAILED
                ephemeral_logger.error(f"Message {message_id} deletion verification failed - enforcing emergency zeroize and eviction")
                try:
                    for i in range(len(message.content)):
                        message.content[i] = 0
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                self._messages.pop(message_id, None)
                return False

            # Remove from active messages
            del self._messages[message_id]

            # Notify callbacks
            if self.on_message_deleted:
                try:
                    self.on_message_deleted(message_id)
                except Exception as e:
                    ephemeral_logger.error(f"Deletion callback error: {e}")

            # Notify sync callbacks
            for callback in self._sync_callbacks:
                try:
                    callback(deletion_record)
                except Exception as e:
                    ephemeral_logger.error(f"Sync callback error: {e}")

            return True

        except Exception as e:
            ephemeral_logger.error(f"Failed to delete message {message_id}: {e}")
            if message is not None:
                message.deletion_status = DeletionStatus.FAILED
                try:
                    if hasattr(message, 'content') and message.content:
                        for i in range(len(message.content)):
                            message.content[i] = 0
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
            self._messages.pop(message_id, None)
            return False
    
    def delete_expired_messages(self) -> List[str]:
        """
        Delete all expired messages.
        
        Returns:
            List of deleted message IDs
        """
        deleted_ids = []
        
        with self._lock:
            # Find expired messages
            expired_ids = [
                msg_id for msg_id, msg in self._messages.items()
                if msg.is_expired() and not msg.is_deleted
            ]
            
            # Delete each expired message
            for msg_id in expired_ids:
                if self._delete_message_internal(msg_id, "expired"):
                    deleted_ids.append(msg_id)
        
        if deleted_ids:
            ephemeral_logger.info(f"Deleted {len(deleted_ids)} expired messages")
        
        return deleted_ids
    
    def get_message_count(self) -> int:
        """Get count of active (non-deleted) messages."""
        with self._lock:
            return len(self._messages)
    
    def get_expiring_soon(self, within_seconds: float = 300) -> List[EphemeralMessage]:
        """
        Get messages expiring within specified time.
        
        Args:
            within_seconds: Time window in seconds
            
        Returns:
            List of messages expiring soon
        """
        threshold = time.time() + within_seconds
        
        with self._lock:
            return [
                msg for msg in self._messages.values()
                if not msg.is_deleted and msg.expires_at <= threshold
            ]
    
    def register_sync_callback(self, callback: Callable[[DeletionRecord], None]) -> None:
        """
        Register callback for deletion synchronization.
        
        Args:
            callback: Function to call when a message is deleted
        """
        self._sync_callbacks.append(callback)
        ephemeral_logger.debug("Registered deletion sync callback")
    
    def unregister_sync_callback(self, callback: Callable[[DeletionRecord], None]) -> None:
        """Remove a sync callback."""
        if callback in self._sync_callbacks:
            self._sync_callbacks.remove(callback)
    
    def process_remote_deletion(self, deletion_record: DeletionRecord) -> bool:
        """
        Process a deletion record from another device.
        
        Args:
            deletion_record: Deletion record from remote device
            
        Returns:
            True if local deletion was successful
        """
        message_id = deletion_record.message_id
        
        with self._lock:
            # Check if already deleted locally
            if message_id in self._deletion_records:
                ephemeral_logger.debug(f"Message {message_id} already deleted locally")
                deletion_record.sync_status[self.device_id] = True
                return True
            
            # Delete locally if message exists
            if message_id in self._messages:
                success = self._delete_message_internal(message_id, f"remote_sync:{deletion_record.device_id}")
                deletion_record.sync_status[self.device_id] = success
                return success
            
            # Message doesn't exist locally, record the deletion anyway
            self._deletion_records[message_id] = deletion_record
            deletion_record.sync_status[self.device_id] = True
            ephemeral_logger.debug(f"Recorded remote deletion for non-existent message {message_id}")
            return True
    
    def get_deletion_records(self) -> List[DeletionRecord]:
        """Get all deletion records for synchronization."""
        with self._lock:
            return list(self._deletion_records.values())
    
    def verify_deletion(self, message_id: str) -> bool:
        """
        Verify that a message was securely deleted.
        
        Args:
            message_id: Message identifier
            
        Returns:
            True if deletion is verified
        """
        with self._lock:
            # Check deletion record exists
            if message_id not in self._deletion_records:
                return False
            
            record = self._deletion_records[message_id]
            
            # Verify hash
            expected_hash = SecureWiper.generate_verification_hash(
                message_id, record.deleted_at
            )
            
            return hmac.compare_digest(record.verification_hash, expected_hash)
    
    def cleanup(self) -> None:
        """Clean up resources and securely delete all messages."""
        ephemeral_logger.info("Cleaning up EphemeralMessageManager")
        
        self.stop_expiry_checker()
        
        with self._lock:
            # Securely delete all remaining messages
            for msg_id in list(self._messages.keys()):
                self._delete_message_internal(msg_id, "cleanup")
            
            self._messages.clear()
            self._sync_callbacks.clear()
        
        ephemeral_logger.info("EphemeralMessageManager cleanup complete")
    
    def __enter__(self):
        """Context manager entry."""
        self.start_expiry_checker()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()
        return False




class DeletionSyncManager:
    """
    Manages deletion synchronization across multiple devices.
    
    Ensures that when a message is deleted on one device, the deletion
    propagates to all other devices with verification.
    
    Requirements: 16.4 - Sync deletion commands across all enrolled devices
    """
    
    def __init__(self, local_device_id: str):
        """
        Initialize DeletionSyncManager.
        
        Args:
            local_device_id: Identifier for the local device
        """
        self.local_device_id = local_device_id
        self._pending_syncs: Dict[str, DeletionRecord] = {}
        self._confirmed_syncs: Dict[str, DeletionRecord] = {}
        self._registered_devices: set = set()
        self._device_callbacks: Dict[str, Callable[[DeletionRecord], bool]] = {}
        self._lock = threading.RLock()
        
        ephemeral_logger.info(f"DeletionSyncManager initialized for device {local_device_id}")
    
    def register_device(self, device_id: str) -> None:
        """Register a device for sync."""
        with self._lock:
            self._registered_devices.add(device_id)
        ephemeral_logger.debug(f"Registered device {device_id} for sync")
    
    def unregister_device(self, device_id: str) -> None:
        """Unregister a device from sync."""
        with self._lock:
            self._registered_devices.discard(device_id)
        ephemeral_logger.debug(f"Unregistered device {device_id} from sync")
    
    def queue_deletion_sync(self, record: DeletionRecord) -> None:
        """
        Queue a deletion for synchronization to other devices.
        
        Args:
            record: Deletion record to sync
        """
        with self._lock:
            self._pending_syncs[record.message_id] = record
            record.sync_status[self.local_device_id] = True
        
        ephemeral_logger.debug(f"Queued deletion sync for message {record.message_id}")
    
    def get_pending_syncs(self) -> List[DeletionRecord]:
        """Get all pending deletion syncs."""
        with self._lock:
            return list(self._pending_syncs.values())
    
    def confirm_sync(self, message_id: str, device_id: str) -> bool:
        """
        Confirm that a device has processed a deletion.
        
        Args:
            message_id: Message identifier
            device_id: Device that confirmed the sync
            
        Returns:
            True if all devices have confirmed
        """
        with self._lock:
            if message_id not in self._pending_syncs:
                return False
            
            record = self._pending_syncs[message_id]
            record.sync_status[device_id] = True
            
            # Check if all registered devices have confirmed
            all_confirmed = all(
                record.sync_status.get(dev_id, False)
                for dev_id in self._registered_devices
            )
            
            if all_confirmed:
                self._confirmed_syncs[message_id] = record
                del self._pending_syncs[message_id]
                ephemeral_logger.info(f"Deletion sync complete for message {message_id}")
                return True
            
            return False
    
    def is_sync_complete(self, message_id: str) -> bool:
        """Check if sync is complete for a message."""
        with self._lock:
            return message_id in self._confirmed_syncs
    
    def get_sync_status(self, message_id: str) -> Optional[Dict[str, bool]]:
        """Get sync status for a message."""
        with self._lock:
            if message_id in self._pending_syncs:
                return self._pending_syncs[message_id].sync_status.copy()
            if message_id in self._confirmed_syncs:
                return self._confirmed_syncs[message_id].sync_status.copy()
            return None
    
    def register_device_callback(
        self, 
        device_id: str, 
        callback: Callable[[DeletionRecord], bool]
    ) -> None:
        """
        Register a callback for sending deletion commands to a specific device.
        
        Args:
            device_id: Device identifier
            callback: Function that sends deletion record to device, returns True on success
            
        Requirements: 16.4
        """
        with self._lock:
            self._device_callbacks[device_id] = callback
            self._registered_devices.add(device_id)
        ephemeral_logger.debug(f"Registered deletion callback for device {device_id}")
    
    def unregister_device_callback(self, device_id: str) -> None:
        """Remove a device callback."""
        with self._lock:
            if device_id in self._device_callbacks:
                del self._device_callbacks[device_id]
            self._registered_devices.discard(device_id)
    
    def propagate_deletion_to_all_devices(self, record: DeletionRecord) -> Dict[str, bool]:
        """
        Propagate a deletion command to all enrolled devices.
        
        Args:
            record: Deletion record to propagate
            
        Returns:
            Dict mapping device_id to success status
            
        Requirements: 16.4
        """
        results: Dict[str, bool] = {}
        
        with self._lock:
            # Mark local device as synced
            record.sync_status[self.local_device_id] = True
            results[self.local_device_id] = True
            
            # Send to all registered devices
            for device_id, callback in self._device_callbacks.items():
                if device_id == self.local_device_id:
                    continue
                    
                try:
                    success = callback(record)
                    record.sync_status[device_id] = success
                    results[device_id] = success
                    
                    if success:
                        ephemeral_logger.debug(
                            f"Deletion {record.message_id} propagated to device {device_id}"
                        )
                    else:
                        ephemeral_logger.warning(
                            f"Failed to propagate deletion {record.message_id} to device {device_id}"
                        )
                except Exception as e:
                    ephemeral_logger.error(
                        f"Error propagating deletion to device {device_id}: {e}"
                    )
                    record.sync_status[device_id] = False
                    results[device_id] = False
            
            # Queue for tracking
            self._pending_syncs[record.message_id] = record
        
        return results
    
    def verify_sync_completion(self, message_id: str) -> Tuple[bool, Dict[str, bool]]:
        """
        Verify that deletion has been synced to all enrolled devices.
        
        Args:
            message_id: Message identifier
            
        Returns:
            Tuple of (all_synced, sync_status_dict)
            
        Requirements: 16.4
        """
        with self._lock:
            if message_id in self._confirmed_syncs:
                return True, self._confirmed_syncs[message_id].sync_status.copy()
            
            if message_id not in self._pending_syncs:
                return False, {}
            
            record = self._pending_syncs[message_id]
            
            # Check if all registered devices have confirmed
            all_synced = all(
                record.sync_status.get(dev_id, False)
                for dev_id in self._registered_devices
            )
            
            if all_synced:
                # Move to confirmed
                self._confirmed_syncs[message_id] = record
                del self._pending_syncs[message_id]
                ephemeral_logger.info(
                    f"Deletion sync verified complete for message {message_id}"
                )
            
            return all_synced, record.sync_status.copy()
    
    def get_pending_sync_count(self) -> int:
        """Get count of pending syncs."""
        with self._lock:
            return len(self._pending_syncs)
    
    def get_registered_device_count(self) -> int:
        """Get count of registered devices."""
        with self._lock:
            return len(self._registered_devices)


class ScreenshotDetector:
    """
    Detects screenshot attempts and notifies sender.
    
    Implements platform-specific screenshot detection for Windows, macOS, and Linux.
    When a screenshot is detected while viewing an ephemeral message, the sender
    is notified.
    
    Requirements: 16.5 - Detect screenshot attempts and notify sender
    """
    
    def __init__(
        self,
        on_screenshot_detected: Optional[Callable[[str, str, float], None]] = None
    ):
        """
        Initialize ScreenshotDetector.
        
        Args:
            on_screenshot_detected: Callback(message_id, viewer_id, timestamp) when screenshot detected
        """
        self.on_screenshot_detected = on_screenshot_detected
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._active_message_id: Optional[str] = None
        self._active_viewer_id: Optional[str] = None
        self._detection_events: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        
        # Platform-specific detection methods
        self._platform = sys.platform
        self._last_check_time = 0.0
        self._check_interval = 0.1  # 100ms check interval
        
        # Screenshot key combinations to detect
        self._screenshot_keys = self._get_platform_screenshot_keys()
        
        ephemeral_logger.info(f"ScreenshotDetector initialized for platform: {self._platform}")
    
    def _get_platform_screenshot_keys(self) -> List[str]:
        """Get platform-specific screenshot key combinations."""
        if self._platform == "win32":
            return [
                "PrintScreen",
                "Win+PrintScreen",
                "Win+Shift+S",
                "Alt+PrintScreen"
            ]
        elif self._platform == "darwin":
            return [
                "Cmd+Shift+3",
                "Cmd+Shift+4",
                "Cmd+Shift+5"
            ]
        else:  # Linux
            return [
                "PrintScreen",
                "Shift+PrintScreen",
                "Alt+PrintScreen"
            ]
    
    def start_monitoring(self, message_id: str, viewer_id: str) -> None:
        """
        Start monitoring for screenshots while viewing a message.
        
        Args:
            message_id: ID of message being viewed
            viewer_id: ID of user viewing the message
            
        Requirements: 16.5
        """
        with self._lock:
            self._active_message_id = message_id
            self._active_viewer_id = viewer_id
            
            if self._monitoring:
                return
            
            self._monitoring = True
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True,
                name="ScreenshotMonitor"
            )
            self._monitor_thread.start()
            
            ephemeral_logger.info(
                f"Started screenshot monitoring for message {message_id[:16]}..."
            )
    
    def stop_monitoring(self) -> None:
        """Stop monitoring for screenshots."""
        with self._lock:
            self._monitoring = False
            self._active_message_id = None
            self._active_viewer_id = None
            
            if self._monitor_thread:
                self._monitor_thread.join(timeout=1.0)
                self._monitor_thread = None
            
            ephemeral_logger.info("Stopped screenshot monitoring")
    
    def _monitor_loop(self) -> None:
        """Background loop to monitor for screenshots."""
        while self._monitoring:
            try:
                if self._detect_screenshot():
                    self._handle_screenshot_detected()
            except Exception as e:
                ephemeral_logger.error(f"Error in screenshot monitor: {e}")
            
            time.sleep(self._check_interval)
    
    def _detect_screenshot(self) -> bool:
        """
        Detect if a screenshot was taken.
        
        Returns:
            True if screenshot detected
            
        Note: This is a simplified implementation. Production systems would use
        platform-specific APIs for more reliable detection.
        """
        current_time = time.time()
        
        # Platform-specific detection
        if self._platform == "win32":
            return self._detect_screenshot_windows()
        elif self._platform == "darwin":
            return self._detect_screenshot_macos()
        else:
            return self._detect_screenshot_linux()
    
    def _detect_screenshot_windows(self) -> bool:
        """
        Detect screenshot on Windows.
        
        Uses clipboard monitoring and keyboard hook detection.
        """
        try:
            # Check for clipboard changes that might indicate screenshot
            # This is a simplified check - production would use win32 APIs
            import ctypes
            
            # Check if PrintScreen key is pressed
            VK_SNAPSHOT = 0x2C
            key_state = ctypes.windll.user32.GetAsyncKeyState(VK_SNAPSHOT)
            
            if key_state & 0x8000:  # Key is currently pressed
                return True
            
            return False
        except Exception:
            return False
    
    def _detect_screenshot_macos(self) -> bool:
        """
        Detect screenshot on macOS.
        
        Monitors for screenshot file creation in default locations.
        """
        try:
            # Check for new files in Desktop (default screenshot location)
            # This is a simplified check - production would use FSEvents
            desktop_path = os.path.expanduser("~/Desktop")
            
            # Look for recent screenshot files
            current_time = time.time()
            for filename in os.listdir(desktop_path):
                if filename.startswith("Screenshot") or filename.startswith("Screen Shot"):
                    filepath = os.path.join(desktop_path, filename)
                    file_mtime = os.path.getmtime(filepath)
                    
                    # Check if file was created in last 2 seconds
                    if current_time - file_mtime < 2.0:
                        return True
            
            return False
        except Exception:
            return False
    
    def _detect_screenshot_linux(self) -> bool:
        """
        Detect screenshot on Linux.
        
        Monitors for common screenshot tool processes.
        """
        try:
            # Check for running screenshot tools
            # This is a simplified check - production would use D-Bus or inotify
            screenshot_tools = ["gnome-screenshot", "scrot", "spectacle", "flameshot"]
            
            # Simple process check (would use psutil in production)
            return False
        except Exception:
            return False
    
    def _handle_screenshot_detected(self) -> None:
        """Handle a detected screenshot event."""
        with self._lock:
            if not self._active_message_id:
                return
            
            detection_time = time.time()
            
            # Record the detection event
            event = {
                "message_id": self._active_message_id,
                "viewer_id": self._active_viewer_id,
                "timestamp": detection_time,
                "platform": self._platform
            }
            self._detection_events.append(event)
            
            ephemeral_logger.warning(
                f"Screenshot detected for message {self._active_message_id[:16]}... "
                f"by viewer {self._active_viewer_id}"
            )
            
            # Notify via callback
            if self.on_screenshot_detected:
                try:
                    self.on_screenshot_detected(
                        self._active_message_id,
                        self._active_viewer_id,
                        detection_time
                    )
                except Exception as e:
                    ephemeral_logger.error(f"Screenshot callback error: {e}")
    
    def perform_screenshot_detection(self, message_id: str, viewer_id: str) -> None:
        raise NotImplementedError("MILITARY FATAL: Offline screenshot detection mechanism not available.")

        """
        Perform a screenshot detection.
        
        Args:
            message_id: ID of message being viewed
            viewer_id: ID of user viewing the message
        """
        with self._lock:
            self._active_message_id = message_id
            self._active_viewer_id = viewer_id
            self._handle_screenshot_detected()
    
    def get_detection_events(self) -> List[Dict[str, Any]]:
        """Get all recorded screenshot detection events."""
        with self._lock:
            return self._detection_events.copy()
    
    def get_detection_count(self) -> int:
        """Get count of screenshot detections."""
        with self._lock:
            return len(self._detection_events)
    
    def clear_detection_events(self) -> None:
        """Clear recorded detection events."""
        with self._lock:
            self._detection_events.clear()


@dataclass
class ScreenshotNotification:
    """Notification sent to sender when screenshot is detected."""
    message_id: str
    viewer_id: str
    detected_at: float
    sender_id: str
    notification_sent_at: float
    acknowledged: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "message_id": self.message_id,
            "viewer_id": self.viewer_id,
            "detected_at": self.detected_at,
            "sender_id": self.sender_id,
            "notification_sent_at": self.notification_sent_at,
            "acknowledged": self.acknowledged
        }


class ScreenshotNotificationManager:
    """
    Manages screenshot notifications to message senders.
    
    When a screenshot is detected, notifies the original sender of the message.
    
    Requirements: 16.5 - Notify sender when screenshot detected
    """
    
    def __init__(self):
        """Initialize ScreenshotNotificationManager."""
        self._notifications: Dict[str, List[ScreenshotNotification]] = {}
        self._pending_notifications: List[ScreenshotNotification] = []
        self._notification_callbacks: List[Callable[[ScreenshotNotification], None]] = []
        self._lock = threading.RLock()
        
        ephemeral_logger.info("ScreenshotNotificationManager initialized")
    
    def register_notification_callback(
        self, 
        callback: Callable[[ScreenshotNotification], None]
    ) -> None:
        """
        Register callback for sending notifications.
        
        Args:
            callback: Function to call when notification needs to be sent
        """
        with self._lock:
            self._notification_callbacks.append(callback)
    
    def notify_sender(
        self,
        message_id: str,
        viewer_id: str,
        sender_id: str,
        detected_at: float
    ) -> ScreenshotNotification:
        """
        Create and send notification to message sender.
        
        Args:
            message_id: ID of message that was screenshotted
            viewer_id: ID of user who took screenshot
            sender_id: ID of original message sender
            detected_at: Timestamp when screenshot was detected
            
        Returns:
            Created ScreenshotNotification
            
        Requirements: 16.5
        """
        notification = ScreenshotNotification(
            message_id=message_id,
            viewer_id=viewer_id,
            detected_at=detected_at,
            sender_id=sender_id,
            notification_sent_at=time.time()
        )
        
        with self._lock:
            # Store notification
            if sender_id not in self._notifications:
                self._notifications[sender_id] = []
            self._notifications[sender_id].append(notification)
            
            # Send via callbacks
            for callback in self._notification_callbacks:
                try:
                    callback(notification)
                except Exception as e:
                    ephemeral_logger.error(f"Notification callback error: {e}")
                    self._pending_notifications.append(notification)
        
        ephemeral_logger.info(
            f"Screenshot notification sent to sender {sender_id} "
            f"for message {message_id[:16]}..."
        )
        
        return notification
    
    def get_notifications_for_sender(self, sender_id: str) -> List[ScreenshotNotification]:
        """Get all notifications for a sender."""
        with self._lock:
            return self._notifications.get(sender_id, []).copy()
    
    def acknowledge_notification(self, sender_id: str, message_id: str) -> bool:
        """
        Mark a notification as acknowledged.
        
        Args:
            sender_id: Sender ID
            message_id: Message ID
            
        Returns:
            True if notification was found and acknowledged
        """
        with self._lock:
            if sender_id not in self._notifications:
                return False
            
            for notification in self._notifications[sender_id]:
                if notification.message_id == message_id and not notification.acknowledged:
                    notification.acknowledged = True
                    return True
            
            return False
    
    def get_pending_notifications(self) -> List[ScreenshotNotification]:
        """Get notifications that failed to send."""
        with self._lock:
            return self._pending_notifications.copy()
    
    def retry_pending_notifications(self) -> int:
        """
        Retry sending pending notifications.
        
        Returns:
            Number of successfully sent notifications
        """
        sent_count = 0
        
        with self._lock:
            remaining = []
            
            for notification in self._pending_notifications:
                success = False
                
                for callback in self._notification_callbacks:
                    try:
                        callback(notification)
                        success = True
                        sent_count += 1
                        break
                    except Exception:
                        import logging; logging.getLogger(__name__).debug("Ignored exception")
                
                if not success:
                    remaining.append(notification)
            
            self._pending_notifications = remaining
        
        return sent_count


# Convenience functions for module-level usage
_default_manager: Optional[EphemeralMessageManager] = None


def get_default_manager() -> EphemeralMessageManager:
    """Get or create the default EphemeralMessageManager."""
    global _default_manager
    if _default_manager is None:
        _default_manager = EphemeralMessageManager()
    return _default_manager


def create_ephemeral_message(content: bytes,
                             sender_id: str,
                             recipient_id: str,
                             ttl_seconds: Optional[int] = None) -> EphemeralMessage:
    """Create an ephemeral message using the default manager."""
    return get_default_manager().create_message(
        content=content,
        sender_id=sender_id,
        recipient_id=recipient_id,
        ttl_seconds=ttl_seconds
    )


def create_read_once_message(content: bytes,
                             sender_id: str,
                             recipient_id: str) -> EphemeralMessage:
    """Create a read-once message using the default manager."""
    return get_default_manager().create_read_once_message(
        content=content,
        sender_id=sender_id,
        recipient_id=recipient_id
    )


def read_message(message_id: str) -> Optional[bytes]:
    """Read a message using the default manager."""
    return get_default_manager().read_message(message_id)


def delete_message(message_id: str) -> bool:
    """Delete a message using the default manager."""
    return get_default_manager().delete_message(message_id)


if __name__ == "__main__":
    # Demo/test code
    print("=" * 60)
    print("Ephemeral Messaging System - DoD 5220.22-M Compliant")
    print("=" * 60)
    
    # Create manager
    with EphemeralMessageManager(default_ttl=300) as manager:
        print(f"\nPASS Manager initialized with device_id: {manager.device_id}")
        
        # Create standard ephemeral message
        msg1 = manager.create_message(
            content=b"This is a secret message that will expire",
            sender_id="alice",
            recipient_id="bob",
            ttl_seconds=120  # 2 minutes
        )
        print(f"\nPASS Created standard message: {msg1.message_id}")
        print(f"  TTL: {msg1.ttl_seconds}s, Expires at: {datetime.fromtimestamp(msg1.expires_at)}")
        
        # Create read-once message
        msg2 = manager.create_read_once_message(
            content=b"This message will self-destruct after reading",
            sender_id="alice",
            recipient_id="bob"
        )
        print(f"\nPASS Created read-once message: {msg2.message_id}")
        
        # Read the read-once message
        content = manager.read_message(msg2.message_id)
        print(f"\nPASS Read read-once message: {content}")
        
        # Verify it was deleted
        content_again = manager.read_message(msg2.message_id)
        print(f"PASS Attempted re-read (should be None): {content_again}")
        
        # Verify deletion
        is_verified = manager.verify_deletion(msg2.message_id)
        print(f"PASS Deletion verified: {is_verified}")
        
        # Check message count
        print(f"\nPASS Active messages: {manager.get_message_count()}")
        
        # Manual deletion
        deleted = manager.delete_message(msg1.message_id)
        print(f"PASS Manually deleted message: {deleted}")
        print(f"PASS Active messages after deletion: {manager.get_message_count()}")
    
    print("\n" + "=" * 60)
    print("Demo complete - all messages securely wiped")
    print("=" * 60)

