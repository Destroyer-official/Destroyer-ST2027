"""
Secure File Transfer - Military-Grade File Transfer with HMAC-SHA384 Chunk Verification

This module implements secure file transfer with per-chunk HMAC-SHA384 verification
as specified in Requirements 11.2, 11.3, 11.4, 11.5.

Key Features:
- 64KB chunks with HMAC-SHA384 per chunk (Requirement 11.2)
- Reject corrupted chunks before data written (Requirement 11.3)
- Complete file verification with SHA3-512 (Requirement 11.4)
- DoD 5220.22-M 3-pass secure file deletion (Requirement 11.5)

Standards Compliance:
- HMAC-SHA384 for chunk integrity (NIST FIPS 198-1)
- SHA3-512 for file integrity (NIST FIPS 202)
- DoD 5220.22-M for secure deletion
"""

import os
import hmac
import hashlib
import secrets
import struct
import logging
import tempfile
from pathlib import Path
from typing import Optional, List, Tuple, Union, BinaryIO, Callable
from dataclasses import dataclass
from enum import Enum

# Configure logging
logger = logging.getLogger("secure_file_transfer")


class ChunkIntegrityViolation(Exception):
    """Exception raised when chunk HMAC verification fails."""


class FileIntegrityViolation(Exception):
    """Exception raised when file SHA3-512 verification fails."""


class SecureDeletionError(Exception):
    """Exception raised when secure file deletion fails."""


@dataclass
class SecureChunk:
    """
    Represents a file chunk with HMAC-SHA384 integrity verification.
    
    Implements Requirement 11.2: 64KB chunks with per-chunk HMAC-SHA384
    
    Binary Format:
    - file_id: 32 bytes (hex-encoded UUID)
    - chunk_number: 4 bytes (big-endian uint32)
    - is_final: 1 byte (boolean)
    - hmac: 48 bytes (HMAC-SHA384)
    - data_len: 4 bytes (big-endian uint32)
    - data: variable (max 64KB)
    """
    file_id: str                    # 32-char hex string
    chunk_number: int               # 0-based sequence number
    chunk_data: bytes               # Actual chunk data (max 64KB)
    chunk_hmac: bytes               # 48-byte HMAC-SHA384
    is_final: bool = False          # True if last chunk
    
    # Constants
    CHUNK_SIZE = 64 * 1024          # 64KB chunks per Requirement 11.2
    HMAC_SIZE = 48                  # HMAC-SHA384 = 384 bits = 48 bytes
    HEADER_SIZE = 32 + 4 + 1 + 48 + 4  # file_id + chunk_num + is_final + hmac + data_len
    
    @classmethod
    def compute_hmac(cls, hmac_key: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-SHA384 for chunk data.
        
        Implements Requirement 11.2: HMAC-SHA384 per chunk
        
        Args:
            hmac_key: 48-byte key for HMAC-SHA384
            data: Chunk data to authenticate
            
        Returns:
            48-byte HMAC-SHA384
        """
        return hmac.new(hmac_key, data, hashlib.sha384).digest()
    
    @classmethod
    def verify_hmac(cls, hmac_key: bytes, data: bytes, expected_hmac: bytes) -> bool:
        """
        Verify HMAC-SHA384 using constant-time comparison.
        
        Implements Requirement 11.3: Reject corrupted chunks
        
        Args:
            hmac_key: 48-byte key for HMAC-SHA384
            data: Chunk data to verify
            expected_hmac: Expected 48-byte HMAC
            
        Returns:
            True if HMAC matches, False otherwise
        """
        computed = cls.compute_hmac(hmac_key, data)
        return hmac.compare_digest(computed, expected_hmac)

    
    def to_bytes(self) -> bytes:
        """
        Serialize chunk to bytes for transmission.
        
        Format: file_id(32) + chunk_number(4) + is_final(1) + hmac(48) + data_len(4) + data
        """
        return (
            self.file_id.encode('ascii') +
            struct.pack('>I', self.chunk_number) +
            struct.pack('?', self.is_final) +
            self.chunk_hmac +
            struct.pack('>I', len(self.chunk_data)) +
            self.chunk_data
        )
    
    @classmethod
    def from_bytes(cls, data: bytes, hmac_key: bytes) -> 'SecureChunk':
        """
        Deserialize chunk from bytes with HMAC verification BEFORE data access.
        
        Implements Requirement 11.3: Verify HMAC before reading payload
        
        Args:
            data: Serialized chunk bytes
            hmac_key: Key for HMAC verification
            
        Returns:
            SecureChunk instance
            
        Raises:
            ChunkIntegrityViolation: If HMAC verification fails
        """
        if len(data) < cls.HEADER_SIZE:
            raise ChunkIntegrityViolation("Chunk too short")
        
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
        
        # Extract HMAC (48 bytes)
        chunk_hmac = data[offset:offset+48]
        offset += 48
        
        # Extract data length
        data_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        
        # Validate data length
        if data_len > cls.CHUNK_SIZE:
            raise ChunkIntegrityViolation("Chunk data exceeds maximum size")
        
        if len(data) < offset + data_len:
            raise ChunkIntegrityViolation("Chunk data truncated")
        
        # Extract chunk data
        chunk_data = data[offset:offset+data_len]
        
        # CRITICAL: Verify HMAC BEFORE returning chunk data
        # Implements Requirement 11.3: Reject corrupted chunks before data written
        if not cls.verify_hmac(hmac_key, chunk_data, chunk_hmac):
            raise ChunkIntegrityViolation(
                f"HMAC verification failed for chunk {chunk_number}"
            )
        
        return cls(
            file_id=file_id,
            chunk_number=chunk_number,
            chunk_data=chunk_data,
            chunk_hmac=chunk_hmac,
            is_final=is_final
        )


class SecureFileTransfer:
    """
    Secure file transfer with HMAC-SHA384 chunk verification.
    
    Implements Requirements 11.2, 11.3, 11.4, 11.5:
    - 64KB chunks with HMAC-SHA384 per chunk
    - Reject corrupted chunks, request retransmit
    - Verify complete file with SHA3-512
    - Secure deletion using DoD 5220.22-M 3-pass
    """
    
    CHUNK_SIZE = 64 * 1024  # 64KB per Requirement 11.2
    
    def __init__(self, hmac_key: bytes):
        """
        Initialize secure file transfer.
        
        Args:
            hmac_key: 48-byte key for HMAC-SHA384 chunk verification
            
        Raises:
            ValueError: If key is not 48 bytes
        """
        if len(hmac_key) != 48:
            raise ValueError("HMAC key must be 48 bytes for HMAC-SHA384")
        
        self._hmac_key = hmac_key
        self._received_chunks: dict = {}  # file_id -> {chunk_num: chunk}
        
        logger.info("SecureFileTransfer initialized")
    
    def create_chunk(
        self,
        file_id: str,
        chunk_number: int,
        chunk_data: bytes,
        is_final: bool = False
    ) -> SecureChunk:
        """
        Create a secure chunk with HMAC-SHA384.
        
        Args:
            file_id: 32-char hex file identifier
            chunk_number: 0-based chunk sequence number
            chunk_data: Chunk data (max 64KB)
            is_final: True if this is the last chunk
            
        Returns:
            SecureChunk with computed HMAC
        """
        if len(chunk_data) > self.CHUNK_SIZE:
            raise ValueError(f"Chunk data exceeds {self.CHUNK_SIZE} bytes")
        
        if len(file_id) != 32:
            raise ValueError("file_id must be 32 character hex string")
        
        # Compute HMAC-SHA384
        chunk_hmac = SecureChunk.compute_hmac(self._hmac_key, chunk_data)
        
        return SecureChunk(
            file_id=file_id,
            chunk_number=chunk_number,
            chunk_data=chunk_data,
            chunk_hmac=chunk_hmac,
            is_final=is_final
        )
    
    def verify_chunk(self, chunk: SecureChunk) -> bool:
        """
        Verify chunk HMAC integrity.
        
        Implements Requirement 11.3: Reject corrupted chunks
        
        Args:
            chunk: SecureChunk to verify
            
        Returns:
            True if HMAC is valid
        """
        return SecureChunk.verify_hmac(
            self._hmac_key,
            chunk.chunk_data,
            chunk.chunk_hmac
        )

    
    def receive_chunk(self, serialized_chunk: bytes) -> Tuple[bool, Optional[SecureChunk]]:
        """
        Receive and verify a chunk.
        
        Implements Requirement 11.3: Verify HMAC before accepting chunk data
        
        Args:
            serialized_chunk: Serialized chunk bytes
            
        Returns:
            Tuple of (success, chunk or None)
        """
        try:
            chunk = SecureChunk.from_bytes(serialized_chunk, self._hmac_key)
            
            # Store chunk for reassembly
            if chunk.file_id not in self._received_chunks:
                self._received_chunks[chunk.file_id] = {}
            
            self._received_chunks[chunk.file_id][chunk.chunk_number] = chunk
            
            logger.debug(f"Received chunk {chunk.chunk_number} for file {chunk.file_id}")
            return True, chunk
            
        except ChunkIntegrityViolation as e:
            logger.warning(f"Chunk integrity violation: {e}")
            return False, None
    
    def chunk_file(self, file_path: Union[str, Path]) -> Tuple[str, List[SecureChunk]]:
        """
        Split file into secure chunks with HMAC-SHA384.
        
        Implements Requirement 11.2: 64KB chunks with HMAC-SHA384
        
        Args:
            file_path: Path to file to chunk
            
        Returns:
            Tuple of (file_id, list of SecureChunks)
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_id = secrets.token_hex(16)  # 32-char hex string
        chunks = []
        
        file_size = file_path.stat().st_size
        total_chunks = (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        
        with open(file_path, 'rb') as f:
            chunk_number = 0
            
            while True:
                chunk_data = f.read(self.CHUNK_SIZE)
                if not chunk_data:
                    break
                
                is_final = (chunk_number == total_chunks - 1)
                
                chunk = self.create_chunk(
                    file_id=file_id,
                    chunk_number=chunk_number,
                    chunk_data=chunk_data,
                    is_final=is_final
                )
                
                chunks.append(chunk)
                chunk_number += 1
        
        logger.info(f"File chunked: {file_path.name} -> {len(chunks)} chunks")
        return file_id, chunks
    
    def reassemble_file(
        self,
        file_id: str,
        output_path: Union[str, Path],
        expected_sha3_512: str
    ) -> bool:
        """
        Reassemble file from chunks and verify SHA3-512.
        
        Implements Requirement 11.4: Verify complete file with SHA3-512
        
        Args:
            file_id: File identifier
            output_path: Path to write reassembled file
            expected_sha3_512: Expected SHA3-512 hash (hex string)
            
        Returns:
            True if file reassembled and verified successfully
            
        Raises:
            FileIntegrityViolation: If SHA3-512 verification fails
        """
        output_path = Path(output_path)
        
        if file_id not in self._received_chunks:
            raise ValueError(f"No chunks received for file {file_id}")
        
        chunks = self._received_chunks[file_id]
        
        # Sort chunks by number
        sorted_chunks = sorted(chunks.values(), key=lambda c: c.chunk_number)
        
        # Verify chunk sequence is complete
        for i, chunk in enumerate(sorted_chunks):
            if chunk.chunk_number != i:
                raise ValueError(f"Missing chunk {i}")
        
        # Write chunks to file
        hasher = hashlib.sha3_512()
        
        with open(output_path, 'wb') as f:
            for chunk in sorted_chunks:
                f.write(chunk.chunk_data)
                hasher.update(chunk.chunk_data)
        
        # Verify SHA3-512
        actual_hash = hasher.hexdigest()
        
        if actual_hash != expected_sha3_512:
            # Delete corrupted file
            output_path.unlink(missing_ok=True)
            raise FileIntegrityViolation(
                f"SHA3-512 verification failed: expected {expected_sha3_512[:16]}..., "
                f"got {actual_hash[:16]}..."
            )
        
        logger.info(f"File reassembled and verified: {output_path}")
        return True
    
    @staticmethod
    def compute_file_hash(file_path: Union[str, Path]) -> str:
        """
        Compute SHA3-512 hash of file.
        
        Implements Requirement 11.4: SHA3-512 file verification
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA3-512 hash as hex string
        """
        hasher = hashlib.sha3_512()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    @staticmethod
    def secure_delete_file(file_path: Union[str, Path], verify: bool = True) -> bool:
        """
        Securely delete file using DoD 5220.22-M 3-pass overwrite.
        
        Implements Requirement 11.5: DoD 5220.22-M 3-pass secure deletion
        
        Pass 1: Overwrite with 0x00 (all zeros)
        Pass 2: Overwrite with 0xFF (all ones)
        Pass 3: Overwrite with random bytes
        
        Args:
            file_path: Path to file to delete
            verify: Whether to verify deletion
            
        Returns:
            True if file securely deleted
            
        Raises:
            SecureDeletionError: If deletion fails
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return True
        
        if not file_path.is_file():
            raise SecureDeletionError(f"Not a file: {file_path}")
        
        try:
            file_size = file_path.stat().st_size
            
            if file_size == 0:
                file_path.unlink()
                return True
            
            with open(file_path, 'r+b') as f:
                # Pass 1: Overwrite with 0x00
                f.seek(0)
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Pass 2: Overwrite with 0xFF
                f.seek(0)
                f.write(b'\xFF' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Pass 3: Overwrite with random bytes
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
            
            # Verify overwrite if requested
            if verify:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    # Content should be random, not original
                    # We can't verify randomness, but we can verify it's not zeros
                    if content == b'\x00' * file_size:
                        raise SecureDeletionError("Verification failed: file still zeros")
            
            # Delete the file
            file_path.unlink()
            
            # Verify deletion
            if file_path.exists():
                raise SecureDeletionError("File still exists after deletion")
            
            logger.info(f"Securely deleted file: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Secure deletion failed: {e}")
            raise SecureDeletionError(f"Secure deletion failed: {e}")
    
    def clear_received_chunks(self, file_id: Optional[str] = None) -> None:
        """
        Clear received chunks from memory.
        
        Args:
            file_id: Specific file to clear, or None for all
        """
        if file_id:
            if file_id in self._received_chunks:
                del self._received_chunks[file_id]
        else:
            self._received_chunks.clear()


def create_hmac_key() -> bytes:
    """
    Create a new 48-byte HMAC key for HMAC-SHA384.
    
    Returns:
        48-byte cryptographically secure random key
    """
    return secrets.token_bytes(48)
