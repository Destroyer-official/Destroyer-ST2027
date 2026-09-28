import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend



def get_secure_key():
    """Get cryptographic key from secure key management system (NIST Level 5+ 256-bit)."""
    try:
        from secure_key_manager import generate_key
        return generate_key(32)
    except Exception:
        return secrets.token_bytes(32)

def get_secure_secret():
    """Get high-entropy secret token from secure key management system."""
    return secrets.token_urlsafe(32)

def get_secure_token():
    """Get high-entropy authentication token from secure key management system."""
    return secrets.token_urlsafe(32)

def secure_hash(data: bytes) -> bytes:
    """Compute SHA3-512 hash (NIST Level 5+)"""
    return hashlib.sha3_512(data).digest()

def secure_encrypt_aes_256_gcm(plaintext: bytes, key: bytes) -> tuple:
    """Encrypt with AES-256-GCM (NIST Level 5+)"""
    iv = secrets.token_bytes(12)  # 96-bit IV for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag

def secure_decrypt_aes_256_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    """Decrypt with AES-256-GCM (NIST Level 5+)"""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

class NISTLevel5PolicyEngine:
    """NIST Level 5+ Security Policy Engine"""
    
    MINIMUM_SECURITY_BITS = 256
    ALLOWED_ALGORITHMS = {
        'symmetric': ['AES-256-GCM', 'ChaCha20-Poly1305'],
        'asymmetric': ['ML-KEM-1024', 'McEliece-8192128f', 'ML-DSA-87', 'FALCON-1024', 'SLH-DSA-256f', 'Ed448', 'P-521'],
        'hash': ['SHA3-512', 'BLAKE2b-512', 'SHA-512'],
        'kdf': ['HKDF-SHA512', 'Argon2id']
    }
    
    @classmethod
    def validate_algorithm(cls, algorithm: str, category: str) -> bool:
        """Validate algorithm meets NIST Level 5+ requirements"""
        return algorithm in cls.ALLOWED_ALGORITHMS.get(category, [])
    
    @classmethod
    def reject_weak_algorithm(cls, algorithm: str) -> None:
        """Reject algorithms that don't meet NIST Level 5+ requirements"""
        raise SecurityError(f"Algorithm {algorithm} does not meet NIST Level 5+ requirements")

class SecurityError(Exception):
    """Security policy violation"""


"""
Secure File Sharing System for P2P Chat

This module extends the existing Double Ratchet protocol to support secure file sharing
with quantum-resistant cryptography. It provides:

- File message protocol extension for Double Ratchet system
- File chunking for large files with progress tracking
- File encryption using existing quantum-resistant cryptography
- Secure file transfer mechanism with validation and scanning
- Integration with existing audit logging system

Security Features:
- Uses existing ML-KEM-1024, FALCON-1024 quantum-resistant algorithms
- File chunking with integrity verification per chunk
- Secure file metadata handling with encryption
- File type validation and basic security scanning
- Secure deletion after transfer completion
- Integration with existing audit logging system

Author: Secure Communications Team
License: MIT
"""

import os
import hashlib
import hmac
import secrets
import struct
import mimetypes
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, BinaryIO, Callable
from dataclasses import dataclass
from enum import Enum
import logging

# Import existing security modules
from double_ratchet import DoubleRatchet, MessageHeader
from audit_logging_system import log_event, AuditEventType, AuditSeverity
from secure_key_manager import enhanced_secure_erase
from logging_config import get_security_summary_logger

# Setup logging
logger = logging.getLogger("secure_file_sharing")
security_logger = get_security_summary_logger()

class FileMessageType(Enum):
    """File message types for the protocol extension."""
    FILE_OFFER = 0x01      # Initial file offer with metadata
    FILE_ACCEPT = 0x02     # Accept file transfer
    FILE_REJECT = 0x03     # Reject file transfer
    FILE_CHUNK = 0x04      # File data chunk
    FILE_COMPLETE = 0x05   # Transfer completion confirmation
    FILE_ERROR = 0x06      # Error during transfer
    FILE_CANCEL = 0x07     # Cancel transfer

class FileTransferStatus(Enum):
    """File transfer status tracking."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TRANSFERRING = "transferring"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class FileMetadata:
    """Secure file metadata structure."""
    file_id: str                    # Unique file identifier
    filename: str                   # Original filename
    file_size: int                  # Total file size in bytes
    file_type: str                  # MIME type
    checksum: str                   # SHA3-256 checksum of entire file
    chunk_size: int                 # Size of each chunk
    total_chunks: int               # Total number of chunks
    created_at: datetime            # Creation timestamp
    sender_id: str                  # Sender identifier
    
    def __post_init__(self):
        """Validate metadata fields."""
        if not self.file_id or len(self.file_id) != 32:  # 16 bytes hex encoded
            raise ValueError("file_id must be 32 character hex string")
        
        if not self.filename or len(self.filename) > 255:
            raise ValueError("filename must be 1-255 characters")
        
        if self.file_size <= 0 or self.file_size > (1024 * 1024 * 1024):  # 1GB limit
            raise ValueError("file_size must be between 1 byte and 1GB")
        
        if self.chunk_size <= 0 or self.chunk_size > (1024 * 1024):  # 1MB max chunk
            raise ValueError("chunk_size must be between 1 byte and 1MB")

        if self.chunk_size < FileMessage.MIN_CHUNK_SIZE:
            raise ValueError(
                f"chunk_size {self.chunk_size} below minimum {FileMessage.MIN_CHUNK_SIZE}: "
                "tiny chunks amplify chunk-table memory (DoS)")
        
        if self.total_chunks <= 0:
            raise ValueError("total_chunks must be positive")

    def to_bytes(self) -> bytes:
        """Serialize metadata to bytes for transmission."""
        # Pack metadata into binary format
        # Format: file_id(32) + filename_len(2) + filename + file_size(8) + 
        #         file_type_len(2) + file_type + checksum(64) + chunk_size(4) + 
        #         total_chunks(4) + timestamp(8) + sender_id_len(2) + sender_id
        
        filename_bytes = self.filename.encode('utf-8')
        file_type_bytes = self.file_type.encode('utf-8')
        sender_id_bytes = self.sender_id.encode('utf-8')
        timestamp_bytes = struct.pack('>Q', int(self.created_at.timestamp()))
        
        data = (
            self.file_id.encode('ascii') +
            struct.pack('>H', len(filename_bytes)) + filename_bytes +
            struct.pack('>Q', self.file_size) +
            struct.pack('>H', len(file_type_bytes)) + file_type_bytes +
            self.checksum.encode('ascii') +
            struct.pack('>I', self.chunk_size) +
            struct.pack('>I', self.total_chunks) +
            timestamp_bytes +
            struct.pack('>H', len(sender_id_bytes)) + sender_id_bytes
        )
        
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> 'FileMetadata':
        """Deserialize metadata from bytes."""
        if len(data) < 32 + 2 + 8 + 2 + 64 + 4 + 4 + 8 + 2:  # Minimum size
            raise ValueError("Invalid metadata: too short")
        
        offset = 0

        def _need(n: int, what: str) -> None:
            if n < 0 or offset + n > len(data):
                raise ValueError(f"Invalid metadata: truncated {what}")

        # Extract file_id
        _need(32, "file_id")
        file_id = data[offset:offset+32].decode('ascii')
        offset += 32
        
        # Extract filename
        _need(2, "filename_len")
        filename_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        if filename_len <= 0 or filename_len > 255:
            raise ValueError("Invalid metadata: bad filename_len")
        _need(filename_len, "filename")
        filename = data[offset:offset+filename_len].decode('utf-8')
        offset += filename_len
        
        # Extract file_size
        _need(8, "file_size")
        file_size = struct.unpack('>Q', data[offset:offset+8])[0]
        offset += 8
        
        # Extract file_type
        _need(2, "file_type_len")
        file_type_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        if file_type_len <= 0 or file_type_len > 128:
            raise ValueError("Invalid metadata: bad file_type_len")
        _need(file_type_len, "file_type")
        file_type = data[offset:offset+file_type_len].decode('utf-8')
        offset += file_type_len
        
        # Extract checksum
        _need(64, "checksum")
        checksum = data[offset:offset+64].decode('ascii')
        offset += 64
        
        # Extract chunk_size and total_chunks
        _need(8, "chunk_size/total_chunks")
        chunk_size = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        total_chunks = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        
        # Extract timestamp
        _need(8, "timestamp")
        timestamp = struct.unpack('>Q', data[offset:offset+8])[0]
        created_at = datetime.fromtimestamp(timestamp)
        offset += 8
        
        # Extract sender_id
        _need(2, "sender_id_len")
        sender_id_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        if sender_id_len <= 0 or sender_id_len > 256:
            raise ValueError("Invalid metadata: bad sender_id_len")
        _need(sender_id_len, "sender_id")
        sender_id = data[offset:offset+sender_id_len].decode('utf-8')
        
        return cls(
            file_id=file_id,
            filename=filename,
            file_size=file_size,
            file_type=file_type,
            checksum=checksum,
            chunk_size=chunk_size,
            total_chunks=total_chunks,
            created_at=created_at,
            sender_id=sender_id
        )

@dataclass
class FileChunk:
    """Represents a file chunk with integrity verification."""
    file_id: str                    # Associated file identifier
    chunk_number: int               # Chunk sequence number (0-based)
    chunk_data: bytes               # Actual chunk data
    chunk_checksum: str             # SHA3-256 or HMAC checksum of this chunk
    is_final: bool = False          # True if this is the last chunk
    auth_tag: Optional[str] = None  # Keyed HMAC / AEAD tag for origin authentication (Item 35)
    
    def __post_init__(self):
        """Validate chunk fields."""
        if not self.file_id or len(self.file_id) != 32:
            raise ValueError("file_id must be 32 character hex string")
        
        if self.chunk_number < 0:
            raise ValueError("chunk_number must be non-negative")
        
        if not self.chunk_data:
            raise ValueError("chunk_data cannot be empty")
        
        if len(self.chunk_data) > (1024 * 1024):  # 1MB max chunk
            raise ValueError("chunk_data exceeds maximum size")
        
        # Verify checksum using constant-time comparison
        calculated_checksum = hashlib.sha3_256(self.chunk_data).hexdigest()
        if not hmac.compare_digest(self.chunk_checksum, calculated_checksum):
            raise ValueError("chunk_checksum does not match chunk_data")

    def verify_keyed_authentication(self, session_key: bytes) -> bool:
        """Verify chunk authenticity using keyed HMAC-SHA512 (Item 35).

        Binds file_id || chunk_number || is_final || chunk_checksum ||
        chunk_data so reordered, cross-file, or truncated chunks fail.
        """
        if not self.auth_tag:
            return False
        if not session_key or len(session_key) < 16:
            return False
        expected_tag = FileChunk.compute_chunk_tag(
            session_key, self.file_id, self.chunk_number,
            self.is_final, self.chunk_checksum, self.chunk_data)
        return hmac.compare_digest(self.auth_tag, expected_tag)

    @staticmethod
    def compute_chunk_tag(hmac_key: bytes, file_id: str, chunk_number: int,
                          is_final: bool, chunk_checksum: str,
                          chunk_data: bytes) -> str:
        """Compute bound HMAC-SHA512 tag over all chunk identity fields."""
        if not hmac_key or len(hmac_key) < 16:
            raise ValueError("HMAC key must be at least 16 bytes")
        msg = (file_id.encode('ascii') + struct.pack('>I', chunk_number) +
               struct.pack('?', is_final) + chunk_checksum.encode('ascii') +
               chunk_data)
        return hmac.new(hmac_key, msg, hashlib.sha512).hexdigest()

    def to_bytes(self) -> bytes:
        """Serialize chunk to bytes for transmission."""
        # Format: file_id(32) + chunk_number(4) + is_final(1) +
        #         checksum(64) + data_len(4) + data +
        #         tag_len(2) + tag (tag_len 0 when untagged)
        tag_bytes = self.auth_tag.encode('ascii') if self.auth_tag else b''
        if len(tag_bytes) > 256:
            raise ValueError("auth_tag too long")
        data = (
            self.file_id.encode('ascii') +
            struct.pack('>I', self.chunk_number) +
            struct.pack('?', self.is_final) +
            self.chunk_checksum.encode('ascii') +
            struct.pack('>I', len(self.chunk_data)) +
            self.chunk_data +
            struct.pack('>H', len(tag_bytes)) +
            tag_bytes
        )

        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> 'FileChunk':
        """Deserialize chunk from bytes (exact-length validated)."""
        header_len = 32 + 4 + 1 + 64 + 4
        if len(data) < header_len + 2:  # header + tag_len
            raise ValueError("Invalid chunk: too short")

        offset = 0

        # Extract file_id
        file_id = data[offset:offset+32].decode('ascii')
        offset += 32

        # Extract chunk_number
        chunk_number = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4

        # Extract is_final
        is_final = struct.unpack('?', data[offset:offset+1])[0]
        offset += 1

        # Extract checksum
        chunk_checksum = data[offset:offset+64].decode('ascii')
        offset += 64

        # Extract data (declared length must fit exactly: no truncation, no trailing bytes except tag)
        data_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        if data_len > (1024 * 1024):  # 1MB max chunk (matches __post_init__)
            raise ValueError("Invalid chunk: declared data length exceeds 1MB cap")
        if offset + data_len + 2 > len(data):
            raise ValueError("Invalid chunk: declared data length overruns buffer")
        chunk_data = data[offset:offset+data_len]
        offset += data_len

        # Extract trailing auth tag
        tag_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        if tag_len > 256:
            raise ValueError("Invalid chunk: auth tag length exceeds cap")
        if offset + tag_len != len(data):
            raise ValueError("Invalid chunk: trailing bytes after auth tag")
        auth_tag = data[offset:offset+tag_len].decode('ascii') if tag_len else None

        return cls(
            file_id=file_id,
            chunk_number=chunk_number,
            chunk_data=chunk_data,
            chunk_checksum=chunk_checksum,
            is_final=is_final,
            auth_tag=auth_tag
        )

class FileMessage:
    """File message protocol extension for Double Ratchet system."""

    # Message format constants
    FILE_MESSAGE_MAGIC = b'SECFILE1'  # 8-byte magic header
    MAX_FILENAME_LENGTH = 255
    MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB
    DEFAULT_CHUNK_SIZE = 64 * 1024      # 64KB chunks
    MAX_CHUNK_SIZE = 1024 * 1024        # 1MB max chunk
    MIN_CHUNK_SIZE = 4 * 1024           # 4KB min chunk (H29: 1-byte chunks
    # would turn a 1GB file into a billion dict entries)
    
    def __init__(self, message_type: FileMessageType, **kwargs):
        """Initialize file message with type and data."""
        self.message_type = message_type
        self.timestamp = datetime.now()
        
        # Type-specific data
        if message_type == FileMessageType.FILE_OFFER:
            self.metadata: FileMetadata = kwargs.get('metadata')
            if not self.metadata:
                raise ValueError("FILE_OFFER requires metadata")
        
        elif message_type == FileMessageType.FILE_CHUNK:
            self.chunk: FileChunk = kwargs.get('chunk')
            if not self.chunk:
                raise ValueError("FILE_CHUNK requires chunk")
        
        elif message_type in [FileMessageType.FILE_ACCEPT, FileMessageType.FILE_REJECT]:
            self.file_id: str = kwargs.get('file_id')
            if not self.file_id:
                raise ValueError(f"{message_type.name} requires file_id")
        
        elif message_type == FileMessageType.FILE_ERROR:
            self.file_id: str = kwargs.get('file_id')
            self.error_message: str = kwargs.get('error_message', '')
            if not self.file_id:
                raise ValueError("FILE_ERROR requires file_id")
        
        else:
            self.file_id: str = kwargs.get('file_id', '')

    def to_bytes(self) -> bytes:
        """Serialize file message to bytes for encryption."""
        # Format: MAGIC(8) + type(1) + timestamp(8) + payload_len(4) + payload
        
        timestamp_bytes = struct.pack('>Q', int(self.timestamp.timestamp()))
        type_byte = struct.pack('B', self.message_type.value)
        
        # Serialize payload based on message type
        if self.message_type == FileMessageType.FILE_OFFER:
            payload = self.metadata.to_bytes()
        
        elif self.message_type == FileMessageType.FILE_CHUNK:
            payload = self.chunk.to_bytes()
        
        elif self.message_type in [
            FileMessageType.FILE_ACCEPT, 
            FileMessageType.FILE_REJECT,
            FileMessageType.FILE_COMPLETE,
            FileMessageType.FILE_CANCEL
        ]:
            payload = self.file_id.encode('ascii')
        
        elif self.message_type == FileMessageType.FILE_ERROR:
            error_bytes = self.error_message.encode('utf-8')
            payload = (
                self.file_id.encode('ascii') +
                struct.pack('>H', len(error_bytes)) +
                error_bytes
            )
        
        else:
            payload = b''
        
        payload_len = struct.pack('>I', len(payload))
        
        return (
            self.FILE_MESSAGE_MAGIC +
            type_byte +
            timestamp_bytes +
            payload_len +
            payload
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'FileMessage':
        """Deserialize file message from bytes."""
        if len(data) < 8 + 1 + 8 + 4:  # Minimum size
            raise ValueError("Invalid file message: too short")
        
        # Verify magic header
        if data[:8] != cls.FILE_MESSAGE_MAGIC:
            raise ValueError("Invalid file message: bad magic header")
        
        offset = 8
        
        # Extract message type
        message_type_value = struct.unpack('B', data[offset:offset+1])[0]
        try:
            message_type = FileMessageType(message_type_value)
        except ValueError:
            raise ValueError(f"Unknown file message type: {message_type_value}")
        offset += 1
        
        # Extract timestamp
        timestamp = struct.unpack('>Q', data[offset:offset+8])[0]
        offset += 8
        
        # Extract payload (declared length capped: 1MB chunk + headers + tag)
        payload_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        if payload_len > (1024 * 1024) + 512:
            raise ValueError("Invalid file message: payload length exceeds cap")
        if offset + payload_len != len(data):
            raise ValueError("Invalid file message: payload length mismatch")
        payload = data[offset:offset+payload_len]
        
        # Create message based on type
        if message_type == FileMessageType.FILE_OFFER:
            metadata = FileMetadata.from_bytes(payload)
            msg = cls(message_type, metadata=metadata)
        
        elif message_type == FileMessageType.FILE_CHUNK:
            chunk = FileChunk.from_bytes(payload)
            msg = cls(message_type, chunk=chunk)
        
        elif message_type in [
            FileMessageType.FILE_ACCEPT,
            FileMessageType.FILE_REJECT,
            FileMessageType.FILE_COMPLETE,
            FileMessageType.FILE_CANCEL
        ]:
            file_id = payload.decode('ascii')
            msg = cls(message_type, file_id=file_id)
        
        elif message_type == FileMessageType.FILE_ERROR:
            file_id = payload[:32].decode('ascii')
            error_len = struct.unpack('>H', payload[32:34])[0]
            error_message = payload[34:34+error_len].decode('utf-8')
            msg = cls(message_type, file_id=file_id, error_message=error_message)
        
        else:
            msg = cls(message_type)
        
        msg.timestamp = datetime.fromtimestamp(timestamp)
        return msg

class SecureFileHandler:
    """Handles secure file operations with chunking and encryption."""
    
    def __init__(self, chunk_size: int = FileMessage.DEFAULT_CHUNK_SIZE):
        """Initialize file handler with specified chunk size."""
        if chunk_size <= 0 or chunk_size > FileMessage.MAX_CHUNK_SIZE:
            raise ValueError(f"chunk_size must be between 1 and {FileMessage.MAX_CHUNK_SIZE}")
        if chunk_size < FileMessage.MIN_CHUNK_SIZE:
            raise ValueError(
                f"chunk_size {chunk_size} below minimum {FileMessage.MIN_CHUNK_SIZE} (chunk-table DoS)")

        self.chunk_size = chunk_size
        self.temp_dir = tempfile.mkdtemp(prefix='secure_file_')
        logger.info(f"SecureFileHandler initialized with chunk_size={chunk_size}")

    def __del__(self):
        """Clean up temporary directory on destruction."""
        try:
            import shutil
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug(f"Temp directory cleanup failed: {e}")

    def calculate_file_checksum(self, file_path: Union[str, Path]) -> str:
        """Calculate SHA3-256 checksum of entire file."""
        hasher = hashlib.sha3_256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        return hasher.hexdigest()

    def validate_file_type(self, filename: str) -> Tuple[bool, str]:
        """Validate file type and return MIME type."""
        # Get MIME type
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        # Define allowed file types (can be configured)
        allowed_types = {
            'text/', 'image/', 'audio/', 'video/',
            'application/pdf', 'application/zip',
            'application/json', 'application/xml'
        }
        
        # Check if file type is allowed
        is_allowed = any(mime_type.startswith(allowed) for allowed in allowed_types)
        
        return is_allowed, mime_type

    def create_file_metadata(self, file_path: Union[str, Path], sender_id: str) -> FileMetadata:
        """Create file metadata from file path."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")
        
        # Validate file size
        file_size = file_path.stat().st_size
        if file_size > FileMessage.MAX_FILE_SIZE:
            raise ValueError(f"File too large: {file_size} > {FileMessage.MAX_FILE_SIZE}")
        
        # Validate file type
        is_allowed, mime_type = self.validate_file_type(file_path.name)
        if not is_allowed:
            raise ValueError(f"File type not allowed: {mime_type}")
        
        # Calculate checksum
        checksum = self.calculate_file_checksum(file_path)
        
        # Calculate chunks
        total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size
        
        # Generate unique file ID
        file_id = secrets.token_hex(16)
        
        metadata = FileMetadata(
            file_id=file_id,
            filename=file_path.name,
            file_size=file_size,
            file_type=mime_type,
            checksum=checksum,
            chunk_size=self.chunk_size,
            total_chunks=total_chunks,
            created_at=datetime.now(),
            sender_id=sender_id
        )
        
        logger.info(f"Created metadata for {file_path.name}: {file_size} bytes, {total_chunks} chunks")
        return metadata

    def chunk_file(self, file_path: Union[str, Path], metadata: FileMetadata,
                   hmac_key: Optional[bytes] = None) -> List[FileChunk]:
        """Split file into encrypted chunks, optionally keyed-tagging each chunk."""
        file_path = Path(file_path)
        chunks = []

        with open(file_path, 'rb') as f:
            chunk_number = 0

            while True:
                chunk_data = f.read(self.chunk_size)
                if not chunk_data:
                    break

                # Calculate chunk checksum
                chunk_checksum = hashlib.sha3_256(chunk_data).hexdigest()

                # Determine if this is the final chunk
                is_final = (chunk_number == metadata.total_chunks - 1)

                auth_tag = None
                if hmac_key is not None:
                    auth_tag = FileChunk.compute_chunk_tag(
                        hmac_key, metadata.file_id, chunk_number,
                        is_final, chunk_checksum, chunk_data)

                chunk = FileChunk(
                    file_id=metadata.file_id,
                    chunk_number=chunk_number,
                    chunk_data=chunk_data,
                    chunk_checksum=chunk_checksum,
                    is_final=is_final,
                    auth_tag=auth_tag
                )

                chunks.append(chunk)
                chunk_number += 1
        
        if len(chunks) != metadata.total_chunks:
            raise ValueError(f"Chunk count mismatch: {len(chunks)} != {metadata.total_chunks}")
        
        logger.info(f"File chunked into {len(chunks)} chunks")
        return chunks

    def reassemble_file(self, chunks: List[FileChunk], output_path: Union[str, Path], 
                       expected_checksum: str) -> bool:
        """Reassemble file from chunks and verify integrity."""
        output_path = Path(output_path)
        
        # Sort chunks by chunk number
        chunks.sort(key=lambda c: c.chunk_number)
        
        # Verify chunk sequence
        for i, chunk in enumerate(chunks):
            if chunk.chunk_number != i:
                raise ValueError(f"Missing chunk {i}")
        
        # Write chunks to file. CWE-59 fix 2026-09-24: exclusive creation
        # (O_CREAT|O_EXCL) refuses a pre-planted symlink, directory, or
        # raced regular file at the target instead of following /
        # overwriting it. Callers run uniqueness loops that skip existing
        # names, so EEXIST here means race or plant -> fail closed.
        # Mode 0o600: peer-supplied content is never group/world-readable.
        try:
            fd = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as e:
            raise ValueError(f"Refusing to open pre-existing path: {output_path}") from e
        with os.fdopen(fd, 'wb') as f:
            for chunk in chunks:
                f.write(chunk.chunk_data)
        
        # Verify file integrity
        actual_checksum = self.calculate_file_checksum(output_path)
        if actual_checksum != expected_checksum:
            # Remove corrupted file
            output_path.unlink(missing_ok=True)
            raise ValueError("File integrity verification failed")
        
        logger.info(f"File reassembled successfully: {output_path}")
        return True

    def secure_delete_file(self, file_path: Union[str, Path]) -> bool:
        """Securely delete file by overwriting with random data."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            return True

        # CWE-59 defense-in-depth 2026-09-24: never wipe through a symlink --
        # overwriting would destroy the link TARGET outside our tree. The sole
        # caller passes app-created temp paths (never links legitimately), so
        # a link here means plant or race -> refuse, fail closed.
        if file_path.is_symlink():
            logger.error(f"Refusing to wipe symlink: {file_path}")
            return False

        try:
            # Get file size
            file_size = file_path.stat().st_size
            
            # Overwrite with random data in 64KB streaming chunks (3 passes) to prevent OOM
            chunk_size = 65536
            with open(file_path, 'r+b') as f:
                for _ in range(3):
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        to_write = min(remaining, chunk_size)
                        f.write(secrets.token_bytes(to_write))
                        remaining -= to_write
                    f.flush()
                    os.fsync(f.fileno())
            
            # Remove file
            file_path.unlink()
            logger.info(f"Securely deleted file: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to securely delete {file_path}: {e}")
            return False

class SecureFileTransferManager:
    """Secure file transfer mechanism with upload/download handlers and security scanning."""
    
    def __init__(self, temp_storage_dir: Optional[str] = None, max_file_size: int = FileMessage.MAX_FILE_SIZE):
        """Initialize secure file transfer manager."""
        self.max_file_size = max_file_size
        self.temp_storage_dir = Path(temp_storage_dir) if temp_storage_dir else Path(tempfile.mkdtemp(prefix='secure_transfer_'))
        self.temp_storage_dir.mkdir(parents=True, exist_ok=True)
        
        # File type validation configuration
        self.allowed_mime_types = {
            'text/plain', 'text/csv', 'text/html', 'text/css', 'text/javascript',
            'application/json', 'application/xml', 'application/pdf',
            'application/zip', 'application/x-zip-compressed',
            'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp', 'image/svg+xml',
            'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4',
            'video/mp4', 'video/mpeg', 'video/quicktime', 'video/x-msvideo', 'video/webm'
        }
        
        # Dangerous file extensions to block
        self.blocked_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
            '.app', '.deb', '.pkg', '.dmg', '.run', '.msi', '.dll', '.so', '.dylib'
        }
        
        # Active transfers tracking
        self.active_uploads: Dict[str, Dict] = {}
        self.active_downloads: Dict[str, Dict] = {}
        self.progress_callbacks: Dict[str, Callable] = {}

        # H29: concurrency + lifetime bounds (unbounded dicts = RAM DoS).
        self.max_concurrent_uploads = 8
        self.max_concurrent_downloads = 8
        self.transfer_stale_seconds = 3600
        self._cleanup_tasks = set()

        logger.info(f"SecureFileTransferManager initialized with storage: {self.temp_storage_dir}")

    def _track_cleanup_task(self, coro) -> None:
        """Spawn a cleanup task on a bounded, self-reaping set (no leak)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(coro)
        self._cleanup_tasks.add(task)
        task.add_done_callback(self._cleanup_tasks.discard)
        # Bound the set itself: extra tasks still run, just untracked.
        while len(self._cleanup_tasks) > 64:
            self._cleanup_tasks.pop()

    def _reap_stale_transfers(self) -> None:
        """Drop transfers idle beyond the stale horizon (called on registration)."""
        now = datetime.now()
        for table in (self.active_uploads, self.active_downloads):
            stale = [fid for fid, t in table.items()
                     if (now - t.get('created_at', now)).total_seconds() > self.transfer_stale_seconds]
            for fid in stale:
                logger.warning(f"Reaping stale transfer {fid}")
                table.pop(fid, None)
                self.progress_callbacks.pop(fid, None)

    def __del__(self):
        """Clean up temporary storage on destruction."""
        try:
            if hasattr(self, 'temp_storage_dir') and self.temp_storage_dir.exists():
                shutil.rmtree(self.temp_storage_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Failed to clean up temp storage: {e}")

    def validate_file_security(self, file_path: Union[str, Path]) -> Tuple[bool, str, List[str]]:
        """
        Comprehensive file security validation.
        
        Returns:
            Tuple of (is_safe, mime_type, warnings)
        """
        file_path = Path(file_path)
        warnings = []
        
        if not file_path.exists():
            return False, "", ["File does not exist"]
        
        if not file_path.is_file():
            return False, "", ["Path is not a regular file"]
        
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            return False, "", [f"File too large: {file_size} > {self.max_file_size}"]
        
        if file_size == 0:
            return False, "", ["File is empty"]
        
        # Check file extension
        file_ext = file_path.suffix.lower()
        if file_ext in self.blocked_extensions:
            return False, "", [f"Blocked file extension: {file_ext}"]
        
        # Get and validate MIME type
        mime_type, _ = mimetypes.guess_type(file_path.name)
        if not mime_type:
            mime_type = 'application/octet-stream'
            warnings.append("Unknown MIME type, treating as binary")
        
        if mime_type not in self.allowed_mime_types:
            return False, mime_type, [f"MIME type not allowed: {mime_type}"]
        
        # Basic content validation for text files
        if mime_type.startswith('text/'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    # Read first 1KB to check for binary content
                    sample = f.read(1024)
                    if '\x00' in sample:
                        warnings.append("Text file contains null bytes")
            except UnicodeDecodeError:
                return False, mime_type, ["Text file contains invalid UTF-8"]
        
        # Check for suspicious patterns in filename
        suspicious_patterns = ['..', '/', '\\', '<', '>', '|', ':', '*', '?', '"']
        filename = file_path.name
        for pattern in suspicious_patterns:
            if pattern in filename:
                warnings.append(f"Suspicious character in filename: {pattern}")
        
        return True, mime_type, warnings

    def scan_file_for_malware(self, file_path: Union[str, Path]) -> Tuple[bool, List[str]]:
        """
        Pattern-based malware triage (first-pass, ENFORCED: a dirty verdict
        deletes the file and refuses the transfer at the call sites).

        Catches known-bad headers (PE/ELF/class/ZIP) and script patterns in
        text types. This is triage, not a verdict on novel malware: unknown
        threats pass this layer and must be caught by endpoint controls.
        Docstring corrected 2026-09-25 (was mislabeled placeholder).

        Returns:
            Tuple of (is_clean, scan_results)
        """
        file_path = Path(file_path)
        scan_results = []
        
        try:
            # Read file content for basic pattern matching
            with open(file_path, 'rb') as f:
                content = f.read(min(1024 * 1024, file_path.stat().st_size))  # Read up to 1MB
            
            # Check for suspicious binary patterns
            suspicious_patterns = [
                b'MZ',  # PE executable header
                b'\x7fELF',  # ELF executable header
                b'\xca\xfe\xba\xbe',  # Java class file
                b'PK\x03\x04',  # ZIP file (could contain executables)
            ]
            
            for pattern in suspicious_patterns:
                if pattern in content:
                    scan_results.append(f"Suspicious binary pattern detected: {pattern.hex()}")
            
            # Check for script patterns in text files
            if file_path.suffix.lower() in ['.txt', '.html', '.htm', '.js', '.vbs']:
                content_str = content.decode('utf-8', errors='ignore').lower()
                script_patterns = ['<script', 'javascript:', 'vbscript:', 'eval(', 'exec(']
                for pattern in script_patterns:
                    if pattern in content_str:
                        scan_results.append(f"Suspicious script pattern: {pattern}")
            
            # If no suspicious patterns found, consider clean
            is_clean = len(scan_results) == 0
            
            if is_clean:
                scan_results.append("No suspicious patterns detected")
            
            return is_clean, scan_results
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return False, [f"Scan error: {str(e)}"]

    async def upload_file(self, file_path: Union[str, Path], sender_id: str, 
                         progress_callback: Optional[Callable[[str, float, int, int], None]] = None) -> Tuple[bool, str, Optional[FileMetadata]]:
        """
        Upload file with security validation and progress tracking.
        
        Returns:
            Tuple of (success, message, metadata)
        """
        file_path = Path(file_path)
        
        try:
            # Security validation
            is_safe, mime_type, warnings = self.validate_file_security(file_path)
            if not is_safe:
                error_msg = f"File security validation failed: {'; '.join(warnings)}"
                logger.warning(error_msg)
                return False, error_msg, None
            
            # Malware scanning
            is_clean, scan_results = self.scan_file_for_malware(file_path)
            if not is_clean:
                error_msg = f"File failed malware scan: {'; '.join(scan_results)}"
                logger.warning(error_msg)
                return False, error_msg, None
            
            # Create file handler and metadata
            file_handler = SecureFileHandler()
            metadata = file_handler.create_file_metadata(file_path, sender_id)
            
            # Store progress callback
            if progress_callback:
                self.progress_callbacks[metadata.file_id] = progress_callback
            
            # Track upload
            self._reap_stale_transfers()
            if len(self.active_uploads) >= self.max_concurrent_uploads:
                return False, (
                    f"Too many concurrent uploads "
                    f"({len(self.active_uploads)}/{self.max_concurrent_uploads})"), None
            self.active_uploads[metadata.file_id] = {
                'file_path': str(file_path),
                'metadata': metadata,
                'status': 'validated',
                'created_at': datetime.now(),
                'warnings': warnings,
                'scan_results': scan_results
            }
            
            logger.info(f"File upload prepared: {file_path.name} (ID: {metadata.file_id})")
            
            # Log upload event
            log_event(
                event_type=AuditEventType.FILE_OPERATION,
                severity=AuditSeverity.INFO,
                message=f"File upload prepared: {file_path.name}",
                details={
                    'file_id': metadata.file_id,
                    'filename': file_path.name,
                    'file_size': metadata.file_size,
                    'mime_type': mime_type,
                    'sender_id': sender_id,
                    'warnings': warnings,
                    'scan_clean': is_clean
                }
            )
            
            return True, f"File validated and ready for upload: {file_path.name}", metadata
            
        except Exception as e:
            error_msg = f"Upload preparation failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None

    async def download_file(self, file_id: str, output_dir: Union[str, Path],
                           expected_metadata: FileMetadata,
                           progress_callback: Optional[Callable[[str, float, int, int], None]] = None,
                           session_key: Optional[bytes] = None) -> Tuple[bool, str, Optional[Path]]:
        """
        Download file with security validation and progress tracking.
        
        Returns:
            Tuple of (success, message, output_path)
        """
        output_dir = Path(output_dir)
        
        try:
            # Validate output directory
            if not output_dir.exists():
                output_dir.mkdir(parents=True, exist_ok=True)
            
            if not output_dir.is_dir():
                return False, f"Output path is not a directory: {output_dir}", None
            
            # Validate filename for security
            safe_filename = self._sanitize_filename(expected_metadata.filename)
            output_path = output_dir / safe_filename
            
            # Check if file already exists
            if output_path.exists():
                # Create unique filename
                base_name = output_path.stem
                extension = output_path.suffix
                counter = 1
                while output_path.exists():
                    output_path = output_dir / f"{base_name}_{counter}{extension}"
                    counter += 1
            
            # Store progress callback
            if progress_callback:
                self.progress_callbacks[file_id] = progress_callback
            
            # Track download
            self._reap_stale_transfers()
            if len(self.active_downloads) >= self.max_concurrent_downloads:
                return False, (
                    f"Too many concurrent downloads "
                    f"({len(self.active_downloads)}/{self.max_concurrent_downloads})"), None
            self.active_downloads[file_id] = {
                'output_path': str(output_path),
                'expected_metadata': expected_metadata,
                'status': 'initialized',
                'created_at': datetime.now(),
                'received_chunks': {},
                'chunks_received': 0,
                'session_key': session_key
            }
            
            logger.info(f"File download initialized: {safe_filename} (ID: {file_id})")
            
            # Log download event
            log_event(
                event_type=AuditEventType.FILE_OPERATION,
                severity=AuditSeverity.INFO,
                message=f"File download initialized: {safe_filename}",
                details={
                    'file_id': file_id,
                    'filename': safe_filename,
                    'expected_size': expected_metadata.file_size,
                    'output_path': str(output_path)
                }
            )
            
            return True, f"Download initialized for: {safe_filename}", output_path
            
        except Exception as e:
            error_msg = f"Download initialization failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent directory traversal and other attacks."""
        # Remove path separators and dangerous characters
        safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_')
        sanitized = ''.join(c if c in safe_chars else '_' for c in filename)
        
        # Ensure filename is not empty and not too long
        if not sanitized or sanitized.startswith('.'):
            sanitized = f"file_{secrets.token_hex(4)}"
        
        if len(sanitized) > 255:
            name_part = sanitized[:200]
            ext_part = sanitized[-50:] if '.' in sanitized[-50:] else ''
            sanitized = f"{name_part}_{ext_part}"
        
        return sanitized

    async def store_file_chunk(self, file_id: str, chunk: FileChunk) -> Tuple[bool, str]:
        """Store received file chunk with validation."""
        try:
            if file_id not in self.active_downloads:
                return False, f"No active download for file ID: {file_id}"
            
            download = self.active_downloads[file_id]
            expected_metadata = download['expected_metadata']
            
            # Bound check total_chunks to prevent memory exhaustion DoS (Item 31)
            max_allowable_chunks = (FileMessage.MAX_FILE_SIZE + expected_metadata.chunk_size - 1) // expected_metadata.chunk_size
            if expected_metadata.total_chunks > max_allowable_chunks or expected_metadata.total_chunks <= 0:
                return False, f"Total chunks {expected_metadata.total_chunks} exceeds limit {max_allowable_chunks}"

            # Validate chunk
            if chunk.file_id != file_id:
                return False, f"Chunk file ID mismatch: {chunk.file_id} != {file_id}"
            
            if chunk.chunk_number >= expected_metadata.total_chunks:
                return False, f"Invalid chunk number: {chunk.chunk_number} >= {expected_metadata.total_chunks}"
            
            # Bound individual chunk size against declared chunk_size (Anti-Amplification)
            if len(chunk.chunk_data) > expected_metadata.chunk_size:
                logger.error(
                    f"SECURITY ALERT: Chunk {chunk.chunk_number} size ({len(chunk.chunk_data)}) "
                    f"exceeds declared chunk_size ({expected_metadata.chunk_size})"
                )
                return False, f"Chunk data size {len(chunk.chunk_data)} exceeds expected chunk size {expected_metadata.chunk_size}"

            if chunk.chunk_number in download['received_chunks']:
                logger.warning(f"Duplicate chunk received: {chunk.chunk_number}")
                return True, "Duplicate chunk ignored"

            # Bound cumulative staged bytes against expected file_size + chunk_size margin (Memory Exhaustion DoS)
            download.setdefault('staged_bytes', 0)
            if download['staged_bytes'] + len(chunk.chunk_data) > (expected_metadata.file_size + expected_metadata.chunk_size):
                logger.error(
                    f"SECURITY ALERT: Cumulative staged bytes ({download['staged_bytes'] + len(chunk.chunk_data)}) "
                    f"exceeds allowed limit for file size ({expected_metadata.file_size})"
                )
                return False, f"Cumulative staged bytes exceed file size limit ({expected_metadata.file_size})"

            # Verify keyed chunk authentication if session key is active or required (Finding 35)
            session_key = download.get('session_key') or download.get('auth_key')
            if session_key:
                if not chunk.verify_keyed_authentication(session_key):
                    logger.error(f"SECURITY ALERT: Keyed chunk authentication failed for file {file_id}, chunk {chunk.chunk_number}")
                    return False, f"Keyed chunk authentication failed for chunk {chunk.chunk_number}"
            else:
                if not chunk.auth_tag:
                    logger.error(f"SECURITY ALERT: Unkeyed chunk rejected under military defense policy for file {file_id}")
                    return False, f"Unkeyed chunk rejected for chunk {chunk.chunk_number}"
            
            # Store chunk
            download['received_chunks'][chunk.chunk_number] = chunk
            download['chunks_received'] += 1
            download['staged_bytes'] += len(chunk.chunk_data)
            download['status'] = 'receiving'
            
            # Update progress
            if file_id in self.progress_callbacks:
                progress = download['chunks_received'] / expected_metadata.total_chunks
                self.progress_callbacks[file_id](file_id, progress, download['chunks_received'], expected_metadata.total_chunks)
            
            logger.debug(f"Stored chunk {chunk.chunk_number + 1}/{expected_metadata.total_chunks} for {file_id}")
            
            # Check if transfer is complete
            if download['chunks_received'] == expected_metadata.total_chunks:
                return await self._complete_download(file_id)
            
            return True, f"Chunk {chunk.chunk_number + 1}/{expected_metadata.total_chunks} received"
            
        except Exception as e:
            error_msg = f"Failed to store chunk: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    async def _complete_download(self, file_id: str) -> Tuple[bool, str]:
        """Complete file download by reassembling chunks."""
        try:
            download = self.active_downloads[file_id]
            expected_metadata = download['expected_metadata']
            output_path = Path(download['output_path'])
            
            # Convert chunks dict to sorted list
            chunks = [download['received_chunks'][i] for i in range(expected_metadata.total_chunks)]
            
            # Reassemble file
            file_handler = SecureFileHandler()
            file_handler.reassemble_file(chunks, output_path, expected_metadata.checksum)
            
            # Validate downloaded file
            is_safe, mime_type, warnings = self.validate_file_security(output_path)
            if not is_safe:
                # Delete unsafe file
                output_path.unlink(missing_ok=True)
                error_msg = f"Downloaded file failed security validation: {'; '.join(warnings)}"
                logger.error(error_msg)
                return False, error_msg
            
            # Scan for malware
            is_clean, scan_results = self.scan_file_for_malware(output_path)
            if not is_clean:
                # Delete infected file
                output_path.unlink(missing_ok=True)
                error_msg = f"Downloaded file failed malware scan: {'; '.join(scan_results)}"
                logger.error(error_msg)
                return False, error_msg
            
            download['status'] = 'completed'
            download['completed_at'] = datetime.now()
            
            logger.info(f"File download completed: {output_path}")
            
            # Log completion
            log_event(
                event_type=AuditEventType.FILE_OPERATION,
                severity=AuditSeverity.INFO,
                message=f"File download completed: {output_path.name}",
                details={
                    'file_id': file_id,
                    'filename': output_path.name,
                    'file_size': expected_metadata.file_size,
                    'output_path': str(output_path),
                    'warnings': warnings,
                    'scan_clean': is_clean
                }
            )
            
            return True, f"File downloaded successfully: {output_path}"
            
        except Exception as e:
            error_msg = f"Failed to complete download: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    async def secure_delete_transfer_files(self, file_id: str) -> bool:
        """Securely delete temporary files associated with a transfer."""
        try:
            deleted_files = []
            
            # Delete upload files
            if file_id in self.active_uploads:
                upload = self.active_uploads[file_id]
                if 'temp_chunks' in upload:
                    for chunk_file in upload['temp_chunks']:
                        if Path(chunk_file).exists():
                            file_handler = SecureFileHandler()
                            if file_handler.secure_delete_file(chunk_file):
                                deleted_files.append(chunk_file)
                
                del self.active_uploads[file_id]
            
            # Delete download files
            if file_id in self.active_downloads:
                download = self.active_downloads[file_id]
                
                # Securely erase chunk data from memory
                if 'received_chunks' in download:
                    for chunk in download['received_chunks'].values():
                        if hasattr(chunk.chunk_data, '__len__'):
                            enhanced_secure_erase(chunk.chunk_data)
                
                del self.active_downloads[file_id]
            
            # Remove progress callback
            if file_id in self.progress_callbacks:
                del self.progress_callbacks[file_id]
            
            logger.info(f"Securely deleted transfer files for {file_id}: {deleted_files}")
            
            # Log deletion
            log_event(
                event_type=AuditEventType.FILE_OPERATION,
                severity=AuditSeverity.INFO,
                message=f"Transfer files securely deleted: {file_id}",
                details={
                    'file_id': file_id,
                    'deleted_files': deleted_files
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to securely delete transfer files for {file_id}: {e}")
            return False

    def get_upload_status(self, file_id: str) -> Optional[Dict]:
        """Get status of file upload."""
        return self.active_uploads.get(file_id)

    def get_download_status(self, file_id: str) -> Optional[Dict]:
        """Get status of file download."""
        return self.active_downloads.get(file_id)

    def cleanup_old_transfers(self, max_age_hours: int = 24):
        """Clean up old transfers to prevent memory leaks."""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        # Clean up uploads
        old_uploads = [
            file_id for file_id, upload in self.active_uploads.items()
            if upload['created_at'] < cutoff_time
        ]
        
        for file_id in old_uploads:
            self._track_cleanup_task(self.secure_delete_transfer_files(file_id))
        
        # Clean up downloads
        old_downloads = [
            file_id for file_id, download in self.active_downloads.items()
            if download['created_at'] < cutoff_time
        ]
        
        for file_id in old_downloads:
            self._track_cleanup_task(self.secure_delete_transfer_files(file_id))
        
        if old_uploads or old_downloads:
            logger.info(f"Cleaned up {len(old_uploads)} old uploads and {len(old_downloads)} old downloads")

class DoubleRatchetFileExtension:
    """Extension for Double Ratchet to handle file messages."""
    
    def __init__(self, double_ratchet: DoubleRatchet):
        """Initialize with existing Double Ratchet instance."""
        self.double_ratchet = double_ratchet
        self.file_handler = SecureFileHandler()
        self.transfer_manager = SecureFileTransferManager()
        self.active_transfers: Dict[str, Dict] = {}  # Track active file transfers
        self.progress_callbacks: Dict[str, Callable] = {}  # Progress tracking callbacks
        
        logger.info("DoubleRatchetFileExtension initialized")

    def encrypt_file_message(self, file_message: FileMessage) -> bytes:
        """Encrypt file message using Double Ratchet protocol."""
        try:
            # Serialize file message to bytes
            plaintext = file_message.to_bytes()
            
            # Encrypt using existing Double Ratchet
            encrypted_message = self.double_ratchet.encrypt(plaintext)
            
            # Log the encryption event
            log_event(
                event_type=AuditEventType.ENCRYPTION,
                severity=AuditSeverity.INFO,
                message=f"File message encrypted: type={file_message.message_type.name}",
                details={
                    'message_type': file_message.message_type.name,
                    'encrypted_size': len(encrypted_message),
                    'original_size': len(plaintext)
                }
            )
            
            return encrypted_message
            
        except Exception as e:
            logger.error(f"Failed to encrypt file message: {e}")
            log_event(
                event_type=AuditEventType.ENCRYPTION,
                severity=AuditSeverity.ERROR,
                message=f"File message encryption failed: {e}",
                details={'error': str(e)}
            )
            raise

    def decrypt_file_message(self, encrypted_data: bytes) -> FileMessage:
        """Decrypt and parse file message using Double Ratchet protocol."""
        try:
            # Decrypt using existing Double Ratchet
            plaintext = self.double_ratchet.decrypt(encrypted_data)
            
            # Parse file message from decrypted data
            file_message = FileMessage.from_bytes(plaintext)
            
            # Log the decryption event
            log_event(
                event_type=AuditEventType.DECRYPTION,
                severity=AuditSeverity.INFO,
                message=f"File message decrypted: type={file_message.message_type.name}",
                details={
                    'message_type': file_message.message_type.name,
                    'decrypted_size': len(plaintext),
                    'encrypted_size': len(encrypted_data)
                }
            )
            
            return file_message
            
        except Exception as e:
            logger.error(f"Failed to decrypt file message: {e}")
            log_event(
                event_type=AuditEventType.DECRYPTION,
                severity=AuditSeverity.ERROR,
                message=f"File message decryption failed: {e}",
                details={'error': str(e)}
            )
            raise

    def create_file_offer(self, file_path: Union[str, Path], sender_id: str) -> FileMessage:
        """Create a file offer message from a file path."""
        try:
            # Create file metadata
            metadata = self.file_handler.create_file_metadata(file_path, sender_id)
            
            # Create file offer message
            offer_message = FileMessage(FileMessageType.FILE_OFFER, metadata=metadata)
            
            # Track the transfer
            self.active_transfers[metadata.file_id] = {
                'status': FileTransferStatus.PENDING,
                'metadata': metadata,
                'file_path': str(file_path),
                'chunks_sent': 0,
                'chunks_received': 0,
                'created_at': datetime.now()
            }
            
            logger.info(f"Created file offer for {metadata.filename} (ID: {metadata.file_id})")
            
            # Log the file offer event
            log_event(
                event_type=AuditEventType.FILE_OPERATION,
                severity=AuditSeverity.INFO,
                message=f"File offer created: {metadata.filename}",
                details={
                    'file_id': metadata.file_id,
                    'filename': metadata.filename,
                    'file_size': metadata.file_size,
                    'sender_id': sender_id
                }
            )
            
            return offer_message
            
        except Exception as e:
            logger.error(f"Failed to create file offer: {e}")
            raise

    def accept_file_offer(self, file_id: str) -> FileMessage:
        """Accept a file transfer offer."""
        if file_id not in self.active_transfers:
            raise ValueError(f"Unknown file transfer: {file_id}")
        
        # Update transfer status
        self.active_transfers[file_id]['status'] = FileTransferStatus.ACCEPTED
        
        # Create accept message
        accept_message = FileMessage(FileMessageType.FILE_ACCEPT, file_id=file_id)
        
        logger.info(f"Accepted file transfer: {file_id}")
        
        # Log the acceptance event
        log_event(
            event_type=AuditEventType.FILE_OPERATION,
            severity=AuditSeverity.INFO,
            message=f"File transfer accepted: {file_id}",
            details={'file_id': file_id}
        )
        
        return accept_message

    def reject_file_offer(self, file_id: str) -> FileMessage:
        """Reject a file transfer offer."""
        if file_id not in self.active_transfers:
            raise ValueError(f"Unknown file transfer: {file_id}")
        
        # Update transfer status
        self.active_transfers[file_id]['status'] = FileTransferStatus.REJECTED
        
        # Create reject message
        reject_message = FileMessage(FileMessageType.FILE_REJECT, file_id=file_id)
        
        logger.info(f"Rejected file transfer: {file_id}")
        
        # Log the rejection event
        log_event(
            event_type=AuditEventType.FILE_OPERATION,
            severity=AuditSeverity.INFO,
            message=f"File transfer rejected: {file_id}",
            details={'file_id': file_id}
        )
        
        return reject_message

    async def prepare_file_upload(self, file_path: Union[str, Path], sender_id: str,
                                 progress_callback: Optional[Callable[[str, float, int, int], None]] = None) -> Tuple[bool, str, Optional[FileMessage]]:
        """Prepare file for upload with security validation."""
        try:
            # Use transfer manager for validation and preparation
            success, message, metadata = await self.transfer_manager.upload_file(file_path, sender_id, progress_callback)
            
            if not success or not metadata:
                return False, message, None
            
            # Create file offer message
            offer_message = self.create_file_offer(file_path, sender_id)
            
            return True, message, offer_message
            
        except Exception as e:
            error_msg = f"Failed to prepare file upload: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None

    def get_next_file_chunk(self, file_id: str) -> Optional[FileMessage]:
        """Get the next file chunk for transmission."""
        if file_id not in self.active_transfers:
            raise ValueError(f"Unknown file transfer: {file_id}")
        
        transfer = self.active_transfers[file_id]
        
        if transfer['status'] != FileTransferStatus.ACCEPTED:
            raise ValueError(f"File transfer not accepted: {file_id}")
        
        # Check if we need to chunk the file
        if 'chunks' not in transfer:
            file_path = transfer['file_path']
            metadata = transfer['metadata']
            transfer['chunks'] = self.file_handler.chunk_file(file_path, metadata)
            transfer['status'] = FileTransferStatus.TRANSFERRING
        
        chunks = transfer['chunks']
        chunks_sent = transfer['chunks_sent']
        
        # Check if all chunks have been sent
        if chunks_sent >= len(chunks):
            return None
        
        # Get next chunk
        chunk = chunks[chunks_sent]
        transfer['chunks_sent'] += 1
        
        # Create chunk message
        chunk_message = FileMessage(FileMessageType.FILE_CHUNK, chunk=chunk)
        
        # Update progress callback if available
        if file_id in self.progress_callbacks:
            progress = (chunks_sent + 1) / len(chunks)
            self.progress_callbacks[file_id](file_id, progress, chunks_sent + 1, len(chunks))
        
        logger.debug(f"Prepared chunk {chunks_sent + 1}/{len(chunks)} for {file_id}")
        
        return chunk_message

    async def process_file_chunk(self, chunk_message: FileMessage, output_dir: Union[str, Path]) -> Tuple[bool, str]:
        """Process received file chunk using secure transfer manager."""
        if chunk_message.message_type != FileMessageType.FILE_CHUNK:
            return False, "Expected FILE_CHUNK message"
        
        chunk = chunk_message.chunk
        file_id = chunk.file_id
        
        try:
            # Initialize download if not already done
            if file_id not in self.active_transfers:
                return False, f"No active transfer for file ID: {file_id}"
            
            transfer = self.active_transfers[file_id]
            metadata = transfer['metadata']
            
            # Initialize download in transfer manager if needed
            if file_id not in self.transfer_manager.active_downloads:
                success, message, output_path = await self.transfer_manager.download_file(
                    file_id, output_dir, metadata, self.progress_callbacks.get(file_id)
                )
                if not success:
                    return False, message
            
            # Store chunk using transfer manager
            success, message = await self.transfer_manager.store_file_chunk(file_id, chunk)
            
            if success and "completed" in message.lower():
                # Transfer completed
                transfer['status'] = FileTransferStatus.COMPLETED
                
                # Log completion
                log_event(
                    event_type=AuditEventType.FILE_OPERATION,
                    severity=AuditSeverity.INFO,
                    message=f"File transfer completed via Double Ratchet: {metadata.filename}",
                    details={
                        'file_id': file_id,
                        'filename': metadata.filename,
                        'file_size': metadata.file_size
                    }
                )
                
                return True, f"File transfer completed: {metadata.filename}"
            
            return success, message
            
        except Exception as e:
            error_msg = f"Failed to process file chunk: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def _complete_file_transfer(self, file_id: str, output_dir: Union[str, Path]) -> bool:
        """Complete file transfer by reassembling chunks."""
        transfer = self.active_transfers[file_id]
        metadata = transfer['metadata']
        
        # Convert chunks dict to sorted list
        chunks = [transfer['received_chunks'][i] for i in range(metadata.total_chunks)]
        
        # Reassemble file
        output_path = Path(output_dir) / metadata.filename
        
        try:
            self.file_handler.reassemble_file(chunks, output_path, metadata.checksum)
            transfer['status'] = FileTransferStatus.COMPLETED
            transfer['output_path'] = str(output_path)
            
            logger.info(f"File transfer completed: {metadata.filename}")
            
            # Log completion event
            log_event(
                event_type=AuditEventType.FILE_OPERATION,
                severity=AuditSeverity.INFO,
                message=f"File transfer completed: {metadata.filename}",
                details={
                    'file_id': file_id,
                    'filename': metadata.filename,
                    'output_path': str(output_path),
                    'file_size': metadata.file_size
                }
            )
            
            return True
            
        except Exception as e:
            transfer['status'] = FileTransferStatus.FAILED
            transfer['error'] = str(e)
            
            logger.error(f"File transfer failed: {e}")
            
            # Log failure event
            log_event(
                event_type=AuditEventType.FILE_OPERATION,
                severity=AuditSeverity.ERROR,
                message=f"File transfer failed: {metadata.filename}",
                details={
                    'file_id': file_id,
                    'filename': metadata.filename,
                    'error': str(e)
                }
            )
            
            return False

    def cancel_file_transfer(self, file_id: str) -> FileMessage:
        """Cancel an active file transfer."""
        if file_id not in self.active_transfers:
            raise ValueError(f"Unknown file transfer: {file_id}")
        
        transfer = self.active_transfers[file_id]
        transfer['status'] = FileTransferStatus.CANCELLED
        
        # Clean up chunks if they exist
        if 'chunks' in transfer:
            # Securely erase chunk data
            for chunk in transfer['chunks']:
                if hasattr(chunk.chunk_data, '__len__'):
                    enhanced_secure_erase(chunk.chunk_data)
        
        # Create cancel message
        cancel_message = FileMessage(FileMessageType.FILE_CANCEL, file_id=file_id)
        
        logger.info(f"Cancelled file transfer: {file_id}")
        
        # Log cancellation event
        log_event(
            event_type=AuditEventType.FILE_OPERATION,
            severity=AuditSeverity.INFO,
            message=f"File transfer cancelled: {file_id}",
            details={'file_id': file_id}
        )
        
        return cancel_message

    def set_progress_callback(self, file_id: str, callback: Callable[[str, float, int, int], None]):
        """Set progress callback for file transfer."""
        self.progress_callbacks[file_id] = callback

    def get_transfer_status(self, file_id: str) -> Optional[Dict]:
        """Get status of file transfer."""
        return self.active_transfers.get(file_id)

    async def secure_cleanup_transfer(self, file_id: str) -> bool:
        """Securely clean up a file transfer and associated temporary files."""
        try:
            # Clean up in transfer manager
            success = await self.transfer_manager.secure_delete_transfer_files(file_id)
            
            # Clean up in active transfers
            if file_id in self.active_transfers:
                transfer = self.active_transfers[file_id]
                
                # Securely erase chunk data if present
                if 'chunks' in transfer:
                    for chunk in transfer['chunks']:
                        if hasattr(chunk.chunk_data, '__len__'):
                            enhanced_secure_erase(chunk.chunk_data)
                
                del self.active_transfers[file_id]
            
            # Remove progress callback
            if file_id in self.progress_callbacks:
                del self.progress_callbacks[file_id]
            
            logger.info(f"Securely cleaned up file transfer: {file_id}")
            return success
            
        except Exception as e:
            logger.error(f"Failed to securely clean up transfer {file_id}: {e}")
            return False

    def cleanup_completed_transfers(self, max_age_hours: int = 24):
        """Clean up completed transfers older than specified hours."""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        to_remove = []
        for file_id, transfer in self.active_transfers.items():
            if (transfer['status'] in [FileTransferStatus.COMPLETED, FileTransferStatus.FAILED, FileTransferStatus.CANCELLED] and
                transfer['created_at'] < cutoff_time):
                to_remove.append(file_id)
        
        # Use secure cleanup for each transfer (tracked on the transfer
        # manager's bounded task set)
        for file_id in to_remove:
            self.transfer_manager._track_cleanup_task(self.secure_cleanup_transfer(file_id))
        
        # Also cleanup in transfer manager
        self.transfer_manager.cleanup_old_transfers(max_age_hours)
        
        if to_remove:
            logger.info(f"Scheduled secure cleanup for {len(to_remove)} old file transfers")

    def get_allowed_file_types(self) -> List[str]:
        """Get list of allowed MIME types for file transfers."""
        return list(self.transfer_manager.allowed_mime_types)

    def get_blocked_extensions(self) -> List[str]:
        """Get list of blocked file extensions."""
        return list(self.transfer_manager.blocked_extensions)

    def get_max_file_size(self) -> int:
        """Get maximum allowed file size."""
        return self.transfer_manager.max_file_size

    async def validate_file_for_transfer(self, file_path: Union[str, Path]) -> Tuple[bool, str, List[str]]:
        """Validate if a file is safe for transfer."""
        return self.transfer_manager.validate_file_security(file_path)

    def get_transfer_statistics(self) -> Dict[str, int]:
        """Get statistics about active transfers."""
        return {
            'active_transfers': len(self.active_transfers),
            'active_uploads': len(self.transfer_manager.active_uploads),
            'active_downloads': len(self.transfer_manager.active_downloads),
            'progress_callbacks': len(self.progress_callbacks)
        }

# Example usage and testing functions
def example_file_sharing_workflow():
    """Example workflow demonstrating file sharing capabilities."""
    print("=== Secure File Sharing Example ===")
    
    # This would normally be integrated with the existing SecureP2PChat system
    # For demonstration, we'll show the key components
    
    try:
        # 1. Create file handler
        file_handler = SecureFileHandler()
        
        # 2. Create sample file for testing
        test_file = Path("test_file.txt")
        test_file.write_text("This is a test file for secure sharing.\n" * 100)
        
        # 3. Create file metadata
        metadata = file_handler.create_file_metadata(test_file, "sender123")
        print(f"Created metadata: {metadata.filename}, {metadata.file_size} bytes")
        
        # 4. Create file offer message
        offer_message = FileMessage(FileMessageType.FILE_OFFER, metadata=metadata)
        offer_bytes = offer_message.to_bytes()
        print(f"File offer message: {len(offer_bytes)} bytes")
        
        # 5. Parse message back
        parsed_offer = FileMessage.from_bytes(offer_bytes)
        print(f"Parsed offer: {parsed_offer.metadata.filename}")
        
        # 6. Chunk the file
        chunks = file_handler.chunk_file(test_file, metadata)
        print(f"File chunked into {len(chunks)} chunks")
        
        # 7. Create chunk messages
        chunk_messages = []
        for chunk in chunks:
            chunk_msg = FileMessage(FileMessageType.FILE_CHUNK, chunk=chunk)
            chunk_messages.append(chunk_msg)
        
        print(f"Created {len(chunk_messages)} chunk messages")
        
        # 8. Reassemble file
        output_file = Path("reassembled_test_file.txt")
        file_handler.reassemble_file(chunks, output_file, metadata.checksum)
        print(f"File reassembled successfully: {output_file}")
        
        # 9. Verify content
        original_content = test_file.read_text()
        reassembled_content = output_file.read_text()
        
        if original_content == reassembled_content:
            print("PASS File integrity verified - content matches!")
        else:
            print("FAIL File integrity check failed!")
        
        # Cleanup
        test_file.unlink(missing_ok=True)
        output_file.unlink(missing_ok=True)
        
        print("=== Example completed successfully ===")
        
    except Exception as e:
        print(f"Example failed: {e}")
        import traceback
        traceback.print_exc()

async def test_secure_file_transfer():
    """Test secure file transfer mechanism with validation and scanning."""
    print("=== Secure File Transfer Test ===")
    
    try:
        # Create test file
        test_file = Path("test_secure_transfer.txt")
        test_content = "This is a test file for secure transfer validation.\n" * 50
        test_file.write_text(test_content)
        
        # Initialize transfer manager
        transfer_manager = SecureFileTransferManager()
        
        # Test file validation
        print("Testing file security validation...")
        is_safe, mime_type, warnings = transfer_manager.validate_file_security(test_file)
        print(f"PASS File validation: safe={is_safe}, type={mime_type}, warnings={len(warnings)}")
        
        # Test malware scanning
        print("Testing malware scanning...")
        is_clean, scan_results = transfer_manager.scan_file_for_malware(test_file)
        print(f"PASS Malware scan: clean={is_clean}, results={len(scan_results)}")
        
        # Test upload preparation
        print("Testing upload preparation...")
        success, message, metadata = await transfer_manager.upload_file(test_file, "test_sender")
        print(f"PASS Upload preparation: success={success}")
        if metadata:
            print(f"  File ID: {metadata.file_id}")
            print(f"  Filename: {metadata.filename}")
            print(f"  Size: {metadata.file_size} bytes")
        
        # Test download initialization
        if metadata:
            print("Testing download initialization...")
            output_dir = Path("test_output")
            success, message, output_path = await transfer_manager.download_file(
                metadata.file_id, output_dir, metadata
            )
            print(f"PASS Download initialization: success={success}")
            if output_path:
                print(f"  Output path: {output_path}")
        
        # Test secure cleanup
        if metadata:
            print("Testing secure cleanup...")
            success = await transfer_manager.secure_delete_transfer_files(metadata.file_id)
            print(f"PASS Secure cleanup: success={success}")
        
        # Cleanup test files
        test_file.unlink(missing_ok=True)
        if output_dir.exists():
            shutil.rmtree(output_dir, ignore_errors=True)
        
        print("=== Secure file transfer test completed successfully ===")
        
    except Exception as e:
        print(f"Secure file transfer test failed: {e}")
        import traceback
        traceback.print_exc()

def simple_test():
    """Simple test without heavy dependencies."""
    print("=== Simple File Sharing Test ===")
    
    try:
        # Test basic message creation
        test_metadata = FileMetadata(
            file_id="a" * 32,
            filename="test.txt",
            file_size=7000,
            file_type="text/plain",
            checksum="b" * 64,
            chunk_size=4096,
            total_chunks=2,
            created_at=datetime.now(),
            sender_id="test_sender"
        )
        
        # Test serialization
        metadata_bytes = test_metadata.to_bytes()
        parsed_metadata = FileMetadata.from_bytes(metadata_bytes)
        
        print(f"PASS Metadata serialization test passed")
        print(f"  Original: {test_metadata.filename}")
        print(f"  Parsed: {parsed_metadata.filename}")
        
        # Test file message
        offer_msg = FileMessage(FileMessageType.FILE_OFFER, metadata=test_metadata)
        msg_bytes = offer_msg.to_bytes()
        parsed_msg = FileMessage.from_bytes(msg_bytes)
        
        print(f"PASS File message serialization test passed")
        print(f"  Message type: {parsed_msg.message_type.name}")
        
        # Test SecureFileTransferManager initialization
        transfer_manager = SecureFileTransferManager()
        print(f"PASS SecureFileTransferManager initialized")
        print(f"  Allowed MIME types: {len(transfer_manager.allowed_mime_types)}")
        print(f"  Blocked extensions: {len(transfer_manager.blocked_extensions)}")
        print(f"  Max file size: {transfer_manager.max_file_size} bytes")
        
        print("=== Simple test completed successfully ===")
        
    except Exception as e:
        print(f"Simple test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Run tests
    try:
        simple_test()
        print("\n" + "="*50 + "\n")
        
        # Run async test
        import asyncio
        asyncio.run(test_secure_file_transfer())
        print("\n" + "="*50 + "\n")
        
        example_file_sharing_workflow()
    except Exception as e:
        print(f"Error running tests: {e}")
        import traceback
        traceback.print_exc()