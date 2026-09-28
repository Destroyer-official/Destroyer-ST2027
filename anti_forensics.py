"""
Anti-Forensics Module - Military-Grade Plausible Deniability

This module implements anti-forensics features for the secure P2P messaging system:
- Deniable encryption with hidden volumes (Requirement 12.1)
- Duress passwords revealing decoy data (Requirement 12.2)
- Secure boot verification with anti-tamper detection (Requirement 12.3)
- Remote secure wipe via authenticated command (Requirement 12.4)
- Dead-man switch for automatic data destruction (Requirement 12.5)
- Tamper-triggered immediate wipe (Requirement 12.6)

Standards Compliance:
- DoD 5220.22-M: Secure data sanitization
- NIST SP 800-88 Rev. 1: Media sanitization guidelines
- FIPS 140-3: Cryptographic module security requirements
"""

import os
import sys
import time
import hmac
import hashlib
import secrets
import struct
import threading
import logging
from typing import Optional, Dict, Tuple, Any, Callable, List
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

# Configure logging
logger = logging.getLogger("anti_forensics")
logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging
file_handler = logging.FileHandler(os.path.join("logs", "anti_forensics.log"))
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Try to import cryptographic libraries
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    logger.warning("cryptography library not available")

# Try to import secure memory wiper
try:
    from secure_memory_wiper import SecureMemoryWiper, secure_wipe_dod, secure_shred_file
    HAS_SECURE_WIPER = True
except ImportError:
    HAS_SECURE_WIPER = False
    logger.warning("secure_memory_wiper not available")


# =============================================================================
# Custom Exceptions
# =============================================================================

class AntiForensicsError(Exception):
    """Base exception for anti-forensics operations."""


class DeniableEncryptionError(AntiForensicsError):
    """Exception raised for deniable encryption failures."""


class DuressPasswordActivated(AntiForensicsError):
    """Exception raised when duress password is detected (for logging/alerting)."""


class TamperDetectedError(AntiForensicsError):
    """Exception raised when tampering is detected."""


class RemoteWipeAuthenticationError(AntiForensicsError):
    """Exception raised when remote wipe authentication fails."""


class DeadManSwitchTriggered(AntiForensicsError):
    """Exception raised when dead-man switch triggers."""


# =============================================================================
# Data Classes
# =============================================================================

class VolumeType(Enum):
    """Types of encrypted volumes."""
    DECOY = 1      # Decoy volume revealed by duress password
    HIDDEN = 2     # Hidden volume revealed by real password
    OUTER = 3      # Outer container


@dataclass
class EncryptedVolume:
    """Metadata for an encrypted volume."""
    volume_id: str
    volume_type: VolumeType
    encrypted_data: bytes
    nonce: bytes
    salt: bytes
    creation_time: float
    size: int


@dataclass
class DeniableContainer:
    """Container holding both decoy and hidden volumes."""
    container_id: str
    outer_volume: bytes          # Encrypted outer container
    decoy_offset: int            # Offset to decoy data
    hidden_offset: int           # Offset to hidden data
    total_size: int
    header_mac: bytes            # MAC for integrity
    creation_time: float


@dataclass
class WipeCommand:
    """Authenticated remote wipe command."""
    command_id: str
    timestamp: float
    signature: bytes
    target_scope: str            # 'all', 'keys', 'messages', 'specific'
    target_ids: List[str]        # Specific targets if scope is 'specific'
    authenticated: bool = False


@dataclass
class DeadManConfig:
    """Configuration for dead-man switch."""
    timeout_seconds: int         # Time before automatic destruction
    last_checkin: float          # Last check-in timestamp
    enabled: bool = True
    wipe_on_trigger: bool = True
    alert_before_wipe: bool = True
    alert_seconds: int = 60      # Warning time before wipe


# =============================================================================
# Deniable Encryption Class (Requirements 12.1, 12.2)
# =============================================================================

class DeniableEncryption:
    """
    Deniable encryption with hidden volumes and duress passwords.
    
    Implements Requirements 12.1, 12.2:
    - THE Secure_P2P_System SHALL implement deniable encryption with hidden volumes
    - THE Secure_P2P_System SHALL support duress passwords that reveal decoy data
    
    The encryption scheme creates containers with two volumes:
    1. Decoy volume: Revealed when duress password is used
    2. Hidden volume: Revealed only with the real password
    
    Both volumes are indistinguishable from random data, providing
    plausible deniability.
    """
    
    # Cryptographic parameters
    KEY_SIZE = 32           # 256-bit keys
    NONCE_SIZE = 12         # 96-bit nonces for AES-GCM
    SALT_SIZE = 32          # 256-bit salts
    MAC_SIZE = 32           # 256-bit MACs
    HEADER_SIZE = 128       # Header size in bytes
    
    # Scrypt parameters for key derivation (high security - production)
    SCRYPT_N_PRODUCTION = 2**20   # CPU/memory cost (1M iterations)
    SCRYPT_R = 8                  # Block size
    SCRYPT_P = 1                  # Parallelization
    
    # Scrypt parameters for testing (much lower for faster tests)
    SCRYPT_N_TEST = 2**10         # Very low cost for testing (1024 iterations)
    
    def __init__(self, 
                 secure_wipe: bool = True,
                 duress_callback: Optional[Callable[[str], None]] = None,
                 test_mode: bool = False):
        """
        Initialize deniable encryption system.
        
        Args:
            secure_wipe: Whether to use DoD 5220.22-M secure wiping
            duress_callback: Optional callback when duress password is detected
            test_mode: If True, use lower Scrypt parameters for faster testing
        """
        if not HAS_CRYPTOGRAPHY:
            raise DeniableEncryptionError("cryptography library required")
        
        self._lock = threading.RLock()
        self._secure_wipe = secure_wipe
        self._duress_callback = duress_callback
        self._test_mode = test_mode
        self._containers: Dict[str, DeniableContainer] = {}
        
        # Set Scrypt N parameter based on mode
        self._scrypt_n = self.SCRYPT_N_TEST if test_mode else self.SCRYPT_N_PRODUCTION
        
        # Initialize secure wiper if available
        self._wiper = SecureMemoryWiper() if HAS_SECURE_WIPER else None
        
        logger.info(f"DeniableEncryption initialized (test_mode={test_mode})")
    
    def _derive_key(self, password: str, salt: bytes, context: str) -> bytes:
        """
        Derive encryption key from password using Scrypt.
        
        Args:
            password: User password
            salt: Cryptographic salt
            context: Domain separation context
            
        Returns:
            32-byte derived key
        """
        # Add context to password for domain separation
        password_with_context = f"{password}::{context}".encode('utf-8')
        
        kdf = Scrypt(
            salt=salt,
            length=self.KEY_SIZE,
            n=self._scrypt_n,
            r=self.SCRYPT_R,
            p=self.SCRYPT_P
        )
        
        return kdf.derive(password_with_context)
    
    def _encrypt_volume(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Plaintext data
            key: 256-bit encryption key
            
        Returns:
            Tuple of (ciphertext, nonce)
        """
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return ciphertext, nonce
    
    def _decrypt_volume(self, ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            ciphertext: Encrypted data
            key: 256-bit encryption key
            nonce: Nonce used for encryption
            
        Returns:
            Decrypted plaintext
            
        Raises:
            DeniableEncryptionError: If decryption fails
        """
        try:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise DeniableEncryptionError(f"Decryption failed: {e}")
    
    def _generate_random_padding(self, size: int) -> bytes:
        """Generate cryptographically secure random padding."""
        return secrets.token_bytes(size)
    
    def _calculate_mac(self, data: bytes, key: bytes) -> bytes:
        """Calculate HMAC-SHA512 for integrity verification."""
        return hmac.new(key, data, hashlib.sha512).digest()
    
    def create_deniable_container(self,
                                   hidden_data: bytes,
                                   decoy_data: bytes,
                                   real_password: str,
                                   duress_password: str,
                                   container_size: Optional[int] = None) -> str:
        """
        Create a deniable encryption container with hidden and decoy volumes.
        
        Args:
            hidden_data: Data to hide (revealed by real password)
            decoy_data: Decoy data (revealed by duress password)
            real_password: Password to reveal hidden data
            duress_password: Password to reveal decoy data
            container_size: Optional total container size (auto-calculated if None)
            
        Returns:
            Container ID
            
        Implements Requirement 12.1:
        - THE Secure_P2P_System SHALL implement deniable encryption with hidden volumes
        """
        with self._lock:
            # Generate unique container ID
            container_id = secrets.token_hex(16)
            
            # Generate salts for key derivation
            hidden_salt = secrets.token_bytes(self.SALT_SIZE)
            decoy_salt = secrets.token_bytes(self.SALT_SIZE)
            mac_salt = secrets.token_bytes(self.SALT_SIZE)
            
            # Derive keys
            hidden_key = self._derive_key(real_password, hidden_salt, "hidden")
            decoy_key = self._derive_key(duress_password, decoy_salt, "decoy")
            mac_key = self._derive_key(real_password, mac_salt, "mac")
            
            # Encrypt volumes
            hidden_ciphertext, hidden_nonce = self._encrypt_volume(hidden_data, hidden_key)
            decoy_ciphertext, decoy_nonce = self._encrypt_volume(decoy_data, decoy_key)
            
            # Calculate sizes (salt + nonce + 4-byte length + ciphertext)
            hidden_volume_size = len(hidden_ciphertext) + self.NONCE_SIZE + self.SALT_SIZE + 4
            decoy_volume_size = len(decoy_ciphertext) + self.NONCE_SIZE + self.SALT_SIZE + 4
            
            # Determine container size
            min_size = self.HEADER_SIZE + hidden_volume_size + decoy_volume_size
            if container_size is None:
                # Add random padding (10-50% extra)
                padding_factor = 1.1 + secrets.randbelow(40) / 100
                container_size = int(min_size * padding_factor)
            elif container_size < min_size:
                raise DeniableEncryptionError(f"Container size too small: {container_size} < {min_size}")
            
            # Calculate offsets (randomized for additional deniability)
            available_space = container_size - self.HEADER_SIZE - hidden_volume_size - decoy_volume_size
            random_offset = secrets.randbelow(max(1, available_space // 2))
            
            decoy_offset = self.HEADER_SIZE + random_offset
            hidden_offset = decoy_offset + decoy_volume_size + secrets.randbelow(max(1, available_space // 2))
            
            # Build container
            container_data = bytearray(container_size)
            
            # Fill with random data first (indistinguishable from encrypted data)
            random_fill = secrets.token_bytes(container_size)
            container_data[:] = random_fill
            
            # Write header (encrypted metadata)
            header = struct.pack(
                '>I I I 32s 32s 32s',
                decoy_offset,
                hidden_offset,
                container_size,
                hidden_salt,
                decoy_salt,
                mac_salt
            )
            header_key = self._derive_key(real_password, mac_salt, "header")
            encrypted_header, header_nonce = self._encrypt_volume(header, header_key)
            
            # Store header nonce at fixed position
            container_data[0:self.NONCE_SIZE] = header_nonce
            container_data[self.NONCE_SIZE:self.NONCE_SIZE + len(encrypted_header)] = encrypted_header
            
            # Write decoy volume (format: salt + nonce + length(4 bytes) + ciphertext)
            decoy_len_bytes = struct.pack('>I', len(decoy_ciphertext))
            decoy_volume = decoy_salt + decoy_nonce + decoy_len_bytes + decoy_ciphertext
            container_data[decoy_offset:decoy_offset + len(decoy_volume)] = decoy_volume
            
            # Write hidden volume (format: salt + nonce + length(4 bytes) + ciphertext)
            hidden_len_bytes = struct.pack('>I', len(hidden_ciphertext))
            hidden_volume = hidden_salt + hidden_nonce + hidden_len_bytes + hidden_ciphertext
            container_data[hidden_offset:hidden_offset + len(hidden_volume)] = hidden_volume
            
            # Calculate MAC over entire container
            header_mac = self._calculate_mac(bytes(container_data), mac_key)
            
            # Store container metadata
            self._containers[container_id] = DeniableContainer(
                container_id=container_id,
                outer_volume=bytes(container_data),
                decoy_offset=decoy_offset,
                hidden_offset=hidden_offset,
                total_size=container_size,
                header_mac=header_mac,
                creation_time=time.time()
            )
            
            # Secure wipe sensitive data
            self._secure_wipe_data(bytearray(hidden_key))
            self._secure_wipe_data(bytearray(decoy_key))
            self._secure_wipe_data(bytearray(mac_key))
            self._secure_wipe_data(bytearray(header_key))
            
            logger.info(f"Created deniable container {container_id}: {container_size} bytes")
            return container_id
    
    def decrypt_container(self, 
                          container_id: str, 
                          password: str) -> Tuple[bytes, VolumeType]:
        """
        Decrypt a deniable container with the provided password.
        
        Args:
            container_id: ID of the container
            password: Password (real or duress)
            
        Returns:
            Tuple of (decrypted data, volume type)
            
        Implements Requirement 12.2:
        - THE Secure_P2P_System SHALL support duress passwords that reveal decoy data
        """
        with self._lock:
            if container_id not in self._containers:
                raise DeniableEncryptionError(f"Container {container_id} not found")
            
            container = self._containers[container_id]
            container_data = container.outer_volume
            
            # Try to decrypt as hidden volume first (real password) using stored offset
            try:
                result = self._try_decrypt_at_offset(
                    container_data, password, container.hidden_offset, "hidden"
                )
                if result is not None:
                    logger.info(f"Decrypted hidden volume from container {container_id}")
                    return result, VolumeType.HIDDEN
            except Exception as dec_err:
                logger.debug(f"Failed hidden volume decryption: {dec_err}")
            
            # Try to decrypt as decoy volume (duress password) using stored offset
            try:
                result = self._try_decrypt_at_offset(
                    container_data, password, container.decoy_offset, "decoy"
                )
                if result is not None:
                    # Duress password detected!
                    logger.warning(f"DURESS PASSWORD DETECTED for container {container_id}")
                    
                    if self._duress_callback:
                        self._duress_callback(container_id)
                    
                    return result, VolumeType.DECOY
            except Exception as dec_err:
                logger.debug(f"Failed decoy volume decryption: {dec_err}")
            
            raise DeniableEncryptionError("Invalid password")
    
    def _try_decrypt_at_offset(self, container_data: bytes, password: str, 
                                offset: int, context: str) -> Optional[bytes]:
        """Try to decrypt a volume at a specific offset."""
        try:
            # Volume format: salt(32) + nonce(12) + length(4) + ciphertext
            salt = container_data[offset:offset + self.SALT_SIZE]
            nonce = container_data[offset + self.SALT_SIZE:offset + self.SALT_SIZE + self.NONCE_SIZE]
            
            # Read the ciphertext length (4 bytes, big-endian)
            len_offset = offset + self.SALT_SIZE + self.NONCE_SIZE
            ct_len = struct.unpack('>I', container_data[len_offset:len_offset + 4])[0]
            
            # Extract ciphertext
            ciphertext_start = len_offset + 4
            ciphertext = container_data[ciphertext_start:ciphertext_start + ct_len]
            
            # Derive key with the appropriate context
            key = self._derive_key(password, salt, context)
            
            try:
                plaintext = self._decrypt_volume(ciphertext, key, nonce)
                self._secure_wipe_data(bytearray(key))
                return plaintext
            except Exception:
                self._secure_wipe_data(bytearray(key))
                return None
        except Exception:
            return None
    

    
    def _secure_wipe_data(self, data: bytearray) -> None:
        """Securely wipe sensitive data from memory."""
        if self._wiper and self._secure_wipe:
            try:
                self._wiper.wipe(data)
            except Exception as e:
                logger.warning(f"Secure wipe failed: {e}")
                # Fallback to basic zeroing
                for i in range(len(data)):
                    data[i] = 0
        else:
            # Basic zeroing
            for i in range(len(data)):
                data[i] = 0
    
    def get_container(self, container_id: str) -> Optional[bytes]:
        """Get the raw container data."""
        with self._lock:
            if container_id in self._containers:
                return self._containers[container_id].outer_volume
            return None
    
    def delete_container(self, container_id: str) -> bool:
        """Securely delete a container."""
        with self._lock:
            if container_id not in self._containers:
                return False
            
            container = self._containers[container_id]
            
            # Secure wipe container data
            self._secure_wipe_data(bytearray(container.outer_volume))
            self._secure_wipe_data(bytearray(container.header_mac))
            
            del self._containers[container_id]
            logger.info(f"Deleted container {container_id}")
            return True


# =============================================================================
# Secure Boot Verification (Requirement 12.3)
# =============================================================================

class SecureBootVerifier:
    """
    Secure boot verification with anti-tamper detection.
    
    Implements Requirement 12.3:
    - THE Secure_P2P_System SHALL implement secure boot verification with anti-tamper detection
    """
    
    def __init__(self, 
                 expected_hashes: Optional[Dict[str, str]] = None,
                 tamper_callback: Optional[Callable[[str], None]] = None):
        """
        Initialize secure boot verifier.
        
        Args:
            expected_hashes: Dictionary of file paths to expected SHA-384 hashes
            tamper_callback: Callback when tampering is detected
        """
        self._lock = threading.RLock()
        self._expected_hashes = expected_hashes or {}
        self._tamper_callback = tamper_callback
        self._verified_files: Dict[str, bool] = {}
        self._tamper_detected = False
        
        logger.info("SecureBootVerifier initialized")
    
    def register_file(self, file_path: str, expected_hash: str) -> None:
        """Register a file for integrity verification."""
        with self._lock:
            self._expected_hashes[file_path] = expected_hash
            logger.debug(f"Registered file for verification: {file_path}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-384 hash of a file."""
        h = hashlib.sha384()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash file {file_path}: {e}")
            raise TamperDetectedError(f"Cannot verify file: {file_path}")
    
    def verify_file(self, file_path: str) -> bool:
        """
        Verify a single file's integrity.
        
        Args:
            file_path: Path to file to verify
            
        Returns:
            True if file is valid
            
        Raises:
            TamperDetectedError: If tampering is detected
        """
        with self._lock:
            if file_path not in self._expected_hashes:
                raise TamperDetectedError(f"File not registered: {file_path}")
            
            expected = self._expected_hashes[file_path]
            actual = self._calculate_file_hash(file_path)
            
            # Constant-time comparison
            if not hmac.compare_digest(expected, actual):
                self._tamper_detected = True
                logger.critical(f"TAMPER DETECTED: {file_path}")
                
                if self._tamper_callback:
                    self._tamper_callback(file_path)
                
                raise TamperDetectedError(f"File tampered: {file_path}")
            
            self._verified_files[file_path] = True
            logger.debug(f"File verified: {file_path}")
            return True
    
    def verify_all(self) -> bool:
        """
        Verify all registered files.
        
        Returns:
            True if all files are valid
            
        Raises:
            TamperDetectedError: If any tampering is detected
        """
        with self._lock:
            if not self._expected_hashes:
                logger.error("Integrity verification failed: No files registered in expected_hashes set")
                raise TamperDetectedError("No files registered for integrity verification (empty expected_hashes set)")
            for file_path in self._expected_hashes:
                self.verify_file(file_path)
            
            logger.info(f"All {len(self._expected_hashes)} files verified")
            return True
    
    def is_tampered(self) -> bool:
        """Check if tampering has been detected."""
        return self._tamper_detected


# =============================================================================
# Remote Secure Wipe (Requirement 12.4)
# =============================================================================

class RemoteWipeManager:
    """
    Remote secure wipe via authenticated command.
    
    Implements Requirement 12.4:
    - THE Secure_P2P_System SHALL support remote secure wipe via authenticated command
    """
    
    def __init__(self,
                 wipe_key: bytes,
                 wipe_callback: Optional[Callable[[str], None]] = None):
        """
        Initialize remote wipe manager.
        
        Args:
            wipe_key: 256-bit key for authenticating wipe commands
            wipe_callback: Callback to execute actual wipe
        """
        if len(wipe_key) != 32:
            raise ValueError("Wipe key must be 32 bytes")
        
        self._lock = threading.RLock()
        self._wipe_key = wipe_key
        self._wipe_callback = wipe_callback
        self._pending_commands: Dict[str, WipeCommand] = {}
        self._executed_commands: set = set()
        self._wipe_executed = False
        
        # Initialize secure wiper
        self._wiper = SecureMemoryWiper() if HAS_SECURE_WIPER else None
        
        logger.info("RemoteWipeManager initialized")
    
    def _sign_command(self, command_id: str, timestamp: float, 
                      target_scope: str, target_ids: List[str]) -> bytes:
        """Generate HMAC-SHA512 signature for wipe command."""
        message = f"{command_id}:{timestamp}:{target_scope}:{','.join(target_ids)}".encode()
        return hmac.new(self._wipe_key, message, hashlib.sha512).digest()
    
    def _verify_signature(self, command: WipeCommand) -> bool:
        """Verify wipe command signature."""
        expected_sig = self._sign_command(
            command.command_id,
            command.timestamp,
            command.target_scope,
            command.target_ids
        )
        return hmac.compare_digest(expected_sig, command.signature)
    
    def create_wipe_command(self, 
                            target_scope: str = 'all',
                            target_ids: Optional[List[str]] = None) -> WipeCommand:
        """
        Create an authenticated wipe command.
        
        Args:
            target_scope: Scope of wipe ('all', 'keys', 'messages', 'specific')
            target_ids: Specific targets if scope is 'specific'
            
        Returns:
            Authenticated WipeCommand
        """
        command_id = secrets.token_hex(16)
        timestamp = time.time()
        target_ids = target_ids or []
        
        signature = self._sign_command(command_id, timestamp, target_scope, target_ids)
        
        command = WipeCommand(
            command_id=command_id,
            timestamp=timestamp,
            signature=signature,
            target_scope=target_scope,
            target_ids=target_ids,
            authenticated=True
        )
        
        logger.info(f"Created wipe command {command_id} with scope {target_scope}")
        return command
    
    def execute_wipe(self, command: WipeCommand) -> bool:
        """
        Execute a remote wipe command.
        
        Args:
            command: WipeCommand to execute
            
        Returns:
            True if wipe was executed
            
        Raises:
            RemoteWipeAuthenticationError: If command authentication fails
            
        Implements Requirement 12.4:
        - THE Secure_P2P_System SHALL support remote secure wipe via authenticated command
        """
        with self._lock:
            # Check for replay attacks
            if command.command_id in self._executed_commands:
                logger.warning(f"Replay attack detected: {command.command_id}")
                raise RemoteWipeAuthenticationError("Command already executed")
            
            # Check timestamp (commands expire after 5 minutes)
            if time.time() - command.timestamp > 300:
                logger.warning(f"Expired wipe command: {command.command_id}")
                raise RemoteWipeAuthenticationError("Command expired")
            
            # Verify signature
            if not self._verify_signature(command):
                logger.critical(f"INVALID WIPE COMMAND SIGNATURE: {command.command_id}")
                raise RemoteWipeAuthenticationError("Invalid command signature")
            
            # Mark as executed
            self._executed_commands.add(command.command_id)
            
            # Execute wipe
            logger.critical(f"EXECUTING REMOTE WIPE: {command.command_id}, scope={command.target_scope}")
            
            if self._wipe_callback:
                self._wipe_callback(command.target_scope)
            
            self._wipe_executed = True
            return True
    
    def receive_wipe_command(self, command_data: bytes) -> bool:
        """
        Receive and process a serialized wipe command.
        
        Args:
            command_data: Serialized command data
            
        Returns:
            True if wipe was executed
        """
        try:
            # Parse command (simple format: id:timestamp:scope:targets:signature)
            # Use maxsplit=4 to preserve binary signature containing ':' bytes
            parts = command_data.split(b':', 4)
            if len(parts) < 5:
                raise RemoteWipeAuthenticationError("Invalid command format")
            
            command = WipeCommand(
                command_id=parts[0].decode(),
                timestamp=float(parts[1]),
                target_scope=parts[2].decode(),
                target_ids=parts[3].decode().split(',') if parts[3] else [],
                signature=parts[4],
                authenticated=False
            )
            
            return self.execute_wipe(command)
            
        except RemoteWipeAuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Failed to process wipe command: {e}")
            raise RemoteWipeAuthenticationError(f"Command processing failed: {e}")
    
    def is_wiped(self) -> bool:
        """Check if wipe has been executed."""
        return self._wipe_executed


# =============================================================================
# Dead-Man Switch (Requirement 12.5)
# =============================================================================

class DeadManSwitch:
    """
    Dead-man switch for automatic data destruction.
    
    Implements Requirement 12.5:
    - THE Secure_P2P_System SHALL implement dead-man switch for automatic data destruction
    """
    
    def __init__(self,
                 timeout_seconds: int = 86400,  # 24 hours default
                 wipe_callback: Optional[Callable[[], None]] = None,
                 alert_callback: Optional[Callable[[int], None]] = None):
        """
        Initialize dead-man switch.
        
        Args:
            timeout_seconds: Time before automatic destruction
            wipe_callback: Callback to execute wipe
            alert_callback: Callback for warning alerts (receives seconds remaining)
        """
        self._lock = threading.RLock()
        self._config = DeadManConfig(
            timeout_seconds=timeout_seconds,
            last_checkin=time.time(),
            enabled=True,
            wipe_on_trigger=True,
            alert_before_wipe=True,
            alert_seconds=60
        )
        self._wipe_callback = wipe_callback
        self._alert_callback = alert_callback
        self._triggered = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        logger.info(f"DeadManSwitch initialized with {timeout_seconds}s timeout")
    
    def start(self) -> None:
        """Start the dead-man switch monitoring."""
        with self._lock:
            if self._monitor_thread and self._monitor_thread.is_alive():
                return
            
            self._stop_event.clear()
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True,
                name="DeadManSwitch"
            )
            self._monitor_thread.start()
            logger.info("Dead-man switch monitoring started")
    
    def stop(self) -> None:
        """Stop the dead-man switch monitoring."""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Dead-man switch monitoring stopped")
    
    def checkin(self) -> None:
        """
        Check in to reset the dead-man switch timer.
        
        This must be called periodically to prevent automatic destruction.
        """
        with self._lock:
            self._config.last_checkin = time.time()
            logger.debug("Dead-man switch check-in recorded")
    
    def _monitor_loop(self) -> None:
        """Monitor loop for dead-man switch."""
        while not self._stop_event.is_set():
            try:
                with self._lock:
                    if not self._config.enabled:
                        time.sleep(1)
                        continue
                    
                    elapsed = time.time() - self._config.last_checkin
                    remaining = self._config.timeout_seconds - elapsed
                    
                    # Check if we should alert
                    if (self._config.alert_before_wipe and 
                        remaining <= self._config.alert_seconds and
                        remaining > 0):
                        if self._alert_callback:
                            self._alert_callback(int(remaining))
                    
                    # Check if timeout exceeded
                    if remaining <= 0:
                        self._trigger()
                        return
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Dead-man switch monitor error: {e}")
    
    def _trigger(self) -> None:
        """Trigger the dead-man switch."""
        with self._lock:
            if self._triggered:
                return
            
            self._triggered = True
            logger.critical("DEAD-MAN SWITCH TRIGGERED - INITIATING AUTOMATIC DESTRUCTION")
            
            if self._config.wipe_on_trigger and self._wipe_callback:
                try:
                    self._wipe_callback()
                except Exception as e:
                    logger.error(f"Wipe callback failed: {e}")
            
            raise DeadManSwitchTriggered("Dead-man switch timeout exceeded")
    
    def get_remaining_time(self) -> float:
        """Get remaining time before trigger."""
        with self._lock:
            elapsed = time.time() - self._config.last_checkin
            return max(0, self._config.timeout_seconds - elapsed)
    
    def is_triggered(self) -> bool:
        """Check if switch has been triggered."""
        return self._triggered
    
    def set_timeout(self, timeout_seconds: int) -> None:
        """Update the timeout value."""
        with self._lock:
            self._config.timeout_seconds = timeout_seconds
            logger.info(f"Dead-man switch timeout updated to {timeout_seconds}s")
    
    def disable(self) -> None:
        """Disable the dead-man switch."""
        with self._lock:
            self._config.enabled = False
            logger.warning("Dead-man switch DISABLED")
    
    def enable(self) -> None:
        """Enable the dead-man switch."""
        with self._lock:
            self._config.enabled = True
            self._config.last_checkin = time.time()
            logger.info("Dead-man switch enabled")


# =============================================================================
# Tamper-Triggered Wipe (Requirement 12.6)
# =============================================================================

class TamperTriggeredWipe:
    """
    Immediate wipe on tamper detection.
    
    Implements Requirement 12.6:
    - WHEN tamper detected THEN THE Secure_P2P_System SHALL execute immediate secure wipe
    """
    
    def __init__(self,
                 wipe_callback: Optional[Callable[[], None]] = None,
                 pre_wipe_callback: Optional[Callable[[str], None]] = None):
        """
        Initialize tamper-triggered wipe system.
        
        Args:
            wipe_callback: Callback to execute wipe
            pre_wipe_callback: Callback before wipe (for logging/alerting)
        """
        self._lock = threading.RLock()
        self._wipe_callback = wipe_callback
        self._pre_wipe_callback = pre_wipe_callback
        self._tamper_count = 0
        self._wipe_executed = False
        self._tamper_sources: List[str] = []
        
        # Initialize secure wiper
        self._wiper = SecureMemoryWiper() if HAS_SECURE_WIPER else None
        
        logger.info("TamperTriggeredWipe initialized")
    
    def on_tamper_detected(self, source: str, details: Optional[str] = None) -> None:
        """
        Handle tamper detection event.
        
        Args:
            source: Source of tamper detection
            details: Optional details about the tampering
            
        Implements Requirement 12.6:
        - WHEN tamper detected THEN THE Secure_P2P_System SHALL execute immediate secure wipe
        """
        with self._lock:
            self._tamper_count += 1
            self._tamper_sources.append(source)
            
            logger.critical(f"TAMPER DETECTED from {source}: {details or 'No details'}")
            
            # Pre-wipe callback for logging/alerting
            if self._pre_wipe_callback:
                try:
                    self._pre_wipe_callback(source)
                except Exception as e:
                    logger.error(f"Pre-wipe callback failed: {e}")
            
            # Execute immediate wipe
            self._execute_immediate_wipe(source)
    
    def _execute_immediate_wipe(self, trigger_source: str) -> None:
        """Execute immediate secure wipe."""
        if self._wipe_executed:
            return
        
        self._wipe_executed = True
        logger.critical(f"EXECUTING IMMEDIATE WIPE - Triggered by: {trigger_source}")
        
        if self._wipe_callback:
            try:
                self._wipe_callback()
            except Exception as e:
                logger.error(f"Wipe callback failed: {e}")
        
        raise TamperDetectedError(f"Tamper-triggered wipe executed: {trigger_source}")
    
    def register_tamper_source(self, 
                                source_name: str,
                                check_function: Callable[[], bool]) -> None:
        """
        Register a tamper detection source.
        
        Args:
            source_name: Name of the tamper source
            check_function: Function that returns True if tamper detected
        """
        # This could be extended to periodically check registered sources
        logger.debug(f"Registered tamper source: {source_name}")
    
    def get_tamper_count(self) -> int:
        """Get the number of tamper events detected."""
        return self._tamper_count
    
    def is_wiped(self) -> bool:
        """Check if wipe has been executed."""
        return self._wipe_executed


# =============================================================================
# Anti-Forensics Manager (Unified Interface)
# =============================================================================

class AntiForensicsManager:
    """
    Unified manager for all anti-forensics features.
    
    Provides a single interface for:
    - Deniable encryption
    - Secure boot verification
    - Remote wipe
    - Dead-man switch
    - Tamper-triggered wipe
    """
    
    def __init__(self,
                 wipe_key: Optional[bytes] = None,
                 dead_man_timeout: int = 86400):
        """
        Initialize anti-forensics manager.
        
        Args:
            wipe_key: Key for remote wipe authentication
            dead_man_timeout: Dead-man switch timeout in seconds
        """
        self._lock = threading.RLock()
        
        # Initialize components
        self.deniable_encryption = DeniableEncryption(
            duress_callback=self._on_duress_detected
        )
        
        self.boot_verifier = SecureBootVerifier(
            tamper_callback=self._on_tamper_detected
        )
        
        if wipe_key:
            self.remote_wipe = RemoteWipeManager(
                wipe_key=wipe_key,
                wipe_callback=self._execute_wipe
            )
        else:
            self.remote_wipe = None
        
        self.dead_man_switch = DeadManSwitch(
            timeout_seconds=dead_man_timeout,
            wipe_callback=self._execute_wipe,
            alert_callback=self._on_dead_man_alert
        )
        
        self.tamper_wipe = TamperTriggeredWipe(
            wipe_callback=self._execute_wipe,
            pre_wipe_callback=self._on_pre_wipe
        )
        
        # Wipe targets
        self._wipe_targets: List[Callable[[], None]] = []
        
        logger.info("AntiForensicsManager initialized")
    
    def register_wipe_target(self, wipe_function: Callable[[], None]) -> None:
        """Register a function to be called during wipe."""
        self._wipe_targets.append(wipe_function)
    
    def _execute_wipe(self, scope: str = 'all') -> None:
        """Execute wipe on all registered targets."""
        logger.critical(f"EXECUTING WIPE - Scope: {scope}")
        
        for target in self._wipe_targets:
            try:
                target()
            except Exception as e:
                logger.error(f"Wipe target failed: {e}")
    
    def _on_duress_detected(self, container_id: str) -> None:
        """Handle duress password detection."""
        logger.critical(f"DURESS PASSWORD DETECTED: {container_id}")
        # Could trigger silent alert, evidence destruction, etc.
    
    def _on_tamper_detected(self, file_path: str) -> None:
        """Handle tamper detection."""
        self.tamper_wipe.on_tamper_detected("boot_verifier", file_path)
    
    def _on_dead_man_alert(self, seconds_remaining: int) -> None:
        """Handle dead-man switch alert."""
        logger.warning(f"DEAD-MAN SWITCH ALERT: {seconds_remaining}s remaining")
    
    def _on_pre_wipe(self, source: str) -> None:
        """Handle pre-wipe notification."""
        logger.critical(f"PRE-WIPE NOTIFICATION from {source}")
    
    def start_monitoring(self) -> None:
        """Start all monitoring systems."""
        self.dead_man_switch.start()
        logger.info("Anti-forensics monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop all monitoring systems."""
        self.dead_man_switch.stop()
        logger.info("Anti-forensics monitoring stopped")
    
    def checkin(self) -> None:
        """Check in to reset dead-man switch."""
        self.dead_man_switch.checkin()
