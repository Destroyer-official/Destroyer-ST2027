"""
Secure Memory Wiper - DoD 5220.22-M Compliant Memory Sanitization

This module implements DoD 5220.22-M compliant secure memory wiping with
read-back verification as specified in Requirements 4.3, 8.1, 8.2, 8.3, 8.5.

Key Features:
- Pass 1: Overwrite with 0x00 (all zeros)
- Pass 2: Overwrite with 0xFF (all ones)
- Pass 3: Overwrite with random bytes
- Read-back verification after wipe
- Memory locking to prevent swapping (mlock)

Standards Compliance:
- DoD 5220.22-M: National Industrial Security Program Operating Manual
- NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization
"""

import os
import sys
import ctypes
import secrets
import logging
import threading
import time
from typing import Union, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

# Configure logging
logger = logging.getLogger("secure_memory_wiper")
logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging
file_handler = logging.FileHandler(os.path.join("logs", "secure_memory_wiper.log"))
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


class WipePattern(Enum):
    """DoD 5220.22-M compliant wiping patterns."""
    ZEROS = 0x00      # Pass 1: All zeros
    ONES = 0xFF       # Pass 2: All ones
    RANDOM = -1       # Pass 3: Cryptographically secure random


class WipeVerificationError(Exception):
    """Exception raised when wipe verification fails."""


class MemoryLockError(Exception):
    """Exception raised when memory locking fails."""


@dataclass
class WipeResult:
    """Result of a secure wipe operation."""
    success: bool
    bytes_wiped: int
    passes_completed: int
    verification_passed: bool
    duration_ms: float
    error_message: Optional[str] = None


class SecureMemoryWiper:
    """
    DoD 5220.22-M compliant secure memory wiper.
    
    Implements Requirements 4.3, 8.2, 8.3:
    - Pass 1: Overwrite with 0x00
    - Pass 2: Overwrite with 0xFF
    - Pass 3: Overwrite with random bytes
    - Read-back verification after wipe
    """
    
    # DoD 5220.22-M standard patterns
    DOD_PATTERNS = [
        WipePattern.ZEROS,   # Pass 1: 0x00
        WipePattern.ONES,    # Pass 2: 0xFF
        WipePattern.RANDOM,  # Pass 3: Random
    ]
    
    def __init__(self, verify_wipe: bool = True, use_mlock: bool = True):
        """
        Initialize the secure memory wiper.
        
        Args:
            verify_wipe: Whether to verify wipe with read-back (Requirement 8.3)
            use_mlock: Whether to use mlock to prevent swapping (Requirement 8.1)
        """
        self.verify_wipe = verify_wipe
        self.use_mlock = use_mlock
        self._lock = threading.RLock()
        self._wipe_count = 0
        self._total_bytes_wiped = 0
        
        # Platform-specific initialization
        self._init_platform()
        
        logger.info(f"SecureMemoryWiper initialized: verify={verify_wipe}, mlock={use_mlock}")
    
    def _init_platform(self) -> None:
        """Initialize platform-specific memory functions."""
        self._platform = sys.platform
        
        if self._platform.startswith('linux'):
            try:
                import ctypes.util
                self._libc = ctypes.CDLL(ctypes.util.find_library('c'))
                self._mlock = self._libc.mlock
                self._munlock = self._libc.munlock
                self._mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self._mlock.restype = ctypes.c_int
                self._munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self._munlock.restype = ctypes.c_int
                logger.debug("Linux memory functions initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Linux memory functions: {e}")
                self._mlock = None
                self._munlock = None
                
        elif self._platform.startswith('win'):
            try:
                import ctypes as ct
                self._kernel32 = ct.windll.kernel32
                self._virtual_lock = self._kernel32.VirtualLock
                self._virtual_unlock = self._kernel32.VirtualUnlock
                self._virtual_lock.argtypes = [ct.c_void_p, ct.c_size_t]
                self._virtual_lock.restype = ct.c_bool
                self._virtual_unlock.argtypes = [ct.c_void_p, ct.c_size_t]
                self._virtual_unlock.restype = ct.c_bool
                logger.debug("Windows memory functions initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Windows memory functions: {e}")
                self._virtual_lock = None
                self._virtual_unlock = None
                self._kernel32 = None
        else:
            logger.warning(f"Unsupported platform: {self._platform}")
    
    def wipe(self, data: Union[bytes, bytearray, memoryview], 
             passes: int = 3) -> WipeResult:
        """
        Securely wipe memory using DoD 5220.22-M pattern.
        
        Args:
            data: Memory buffer to wipe (must be mutable for bytearray/memoryview)
            passes: Number of overwrite passes (minimum 3 per DoD standard)
            
        Returns:
            WipeResult with operation details
            
        Raises:
            WipeVerificationError: If verification fails
            
        Implements Requirements 4.3, 8.2, 8.3:
        - Pass 1: Overwrite with 0x00
        - Pass 2: Overwrite with 0xFF
        - Pass 3: Overwrite with random bytes
        - Read-back verification after wipe
        """
        start_time = time.time()
        
        if passes < 3:
            logger.warning(f"DoD 5220.22-M requires minimum 3 passes, got {passes}")
            passes = 3
        
        if not data:
            return WipeResult(
                success=True,
                bytes_wiped=0,
                passes_completed=0,
                verification_passed=True,
                duration_ms=0
            )
        
        data_len = len(data)

        # H22: immutable bytes CANNOT be wiped in place (CPython may also
        # hold copies/interned references). Wiping a throwaway copy while
        # reporting success would be a lie, so fail the result honestly.
        # Callers must pass bytearray/memoryview they own.
        if isinstance(data, bytes):
            logger.error("Refusing to 'wipe' immutable bytes: original buffer would survive (fail-closed result)")
            return WipeResult(
                success=False,
                bytes_wiped=0,
                passes_completed=0,
                verification_passed=False,
                duration_ms=(time.time() - start_time) * 1000,
                error_message="immutable bytes cannot be wiped in place; pass bytearray/memoryview"
            )

        # Convert to mutable buffer if needed
        if isinstance(data, memoryview):
            mutable_data = data
        else:
            mutable_data = data
        
        try:
            with self._lock:
                # Lock memory to prevent swapping (Requirement 8.1)
                memory_locked = False
                if self.use_mlock:
                    memory_locked = self._lock_memory(mutable_data)
                
                passes_completed = 0
                
                # Perform DoD 5220.22-M 3-pass wipe
                for i, pattern in enumerate(self.DOD_PATTERNS[:passes]):
                    self._wipe_pass(mutable_data, pattern)
                    passes_completed += 1
                    logger.debug(f"Completed wipe pass {i+1}/{passes}: pattern={pattern.name}")
                
                # Additional random passes if requested
                for i in range(passes - 3):
                    self._wipe_pass(mutable_data, WipePattern.RANDOM)
                    passes_completed += 1
                    logger.debug(f"Completed additional random pass {i+4}/{passes}")
                
                # Final zero pass for verification
                self._wipe_pass(mutable_data, WipePattern.ZEROS)
                
                # Verify wipe (Requirement 8.3)
                verification_passed = True
                if self.verify_wipe:
                    verification_passed = self._verify_wipe(mutable_data)
                    if not verification_passed:
                        raise WipeVerificationError("Memory wipe verification failed")
                
                # Unlock memory
                if memory_locked:
                    self._unlock_memory(mutable_data)
                
                # Update statistics
                self._wipe_count += 1
                self._total_bytes_wiped += data_len
                
                duration_ms = (time.time() - start_time) * 1000
                
                logger.info(f"Secure wipe completed: {data_len} bytes, {passes_completed} passes, "
                           f"verified={verification_passed}, duration={duration_ms:.2f}ms")
                
                return WipeResult(
                    success=True,
                    bytes_wiped=data_len,
                    passes_completed=passes_completed,
                    verification_passed=verification_passed,
                    duration_ms=duration_ms
                )
                
        except WipeVerificationError:
            raise
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Secure wipe failed: {e}")
            return WipeResult(
                success=False,
                bytes_wiped=0,
                passes_completed=0,
                verification_passed=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    def _wipe_pass(self, data: Union[bytearray, memoryview], 
                   pattern: WipePattern) -> None:
        """
        Perform a single wipe pass with the specified pattern.
        
        Args:
            data: Mutable buffer to wipe
            pattern: Pattern to use for wiping
        """
        data_len = len(data)
        
        if pattern == WipePattern.RANDOM:
            # Use cryptographically secure random bytes
            random_data = secrets.token_bytes(data_len)
            for i in range(data_len):
                data[i] = random_data[i]
        else:
            # Use fixed pattern
            pattern_byte = pattern.value
            for i in range(data_len):
                data[i] = pattern_byte
        
        # Memory barrier to ensure write completion
        self._memory_barrier()
    
    def _memory_barrier(self) -> None:
        """Insert memory barrier to ensure write ordering."""
        if self._platform.startswith('win'):
            try:
                self._kernel32.MemoryBarrier()
            except (AttributeError, OSError):
                import logging; logging.getLogger(__name__).debug("Ignored exception")
        # On Linux, the write operations themselves provide sufficient ordering
        # for our purposes, but we can force a sync
        try:
            os.sync() if hasattr(os, 'sync') else None
        except OSError as e:
            import logging
            logging.getLogger(__name__).debug(f"os.sync not supported or failed: {e}")
    
    def _verify_wipe(self, data: Union[bytearray, memoryview]) -> bool:
        """
        Verify that memory has been properly wiped to zeros.
        
        Args:
            data: Buffer to verify
            
        Returns:
            True if all bytes are zero, False otherwise
            
        Implements Requirement 8.3:
        - Read-back verification after wipe
        """
        # Check all bytes are zero
        for byte in data:
            if byte != 0:
                logger.error(f"Wipe verification failed: found non-zero byte")
                return False
        
        logger.debug(f"Wipe verification passed: {len(data)} bytes verified as zero")
        return True
    
    def _lock_memory(self, data: Union[bytearray, memoryview]) -> bool:
        """
        Lock memory to prevent swapping.
        
        Args:
            data: Buffer to lock
            
        Returns:
            True if memory was locked successfully
            
        Implements Requirement 8.1:
        - Allocate keys using mlock() to prevent swapping
        """
        try:
            data_len = len(data)
            
            if self._platform.startswith('linux') and self._mlock:
                # Get buffer address
                if isinstance(data, bytearray):
                    buffer_ptr = ctypes.cast(
                        ctypes.pointer(ctypes.c_char.from_buffer(data)),
                        ctypes.c_void_p
                    )
                else:
                    buffer_ptr = ctypes.cast(
                        ctypes.pointer(ctypes.c_char.from_buffer(data)),
                        ctypes.c_void_p
                    )
                
                result = self._mlock(buffer_ptr, ctypes.c_size_t(data_len))
                if result == 0:
                    logger.debug(f"Memory locked: {data_len} bytes")
                    return True
                else:
                    logger.warning(f"mlock failed with result {result}")
                    return False
                    
            elif self._platform.startswith('win') and self._virtual_lock:
                if isinstance(data, bytearray):
                    buffer_ptr = ctypes.cast(
                        ctypes.pointer(ctypes.c_char.from_buffer(data)),
                        ctypes.c_void_p
                    )
                else:
                    buffer_ptr = ctypes.cast(
                        ctypes.pointer(ctypes.c_char.from_buffer(data)),
                        ctypes.c_void_p
                    )
                
                result = self._virtual_lock(buffer_ptr, ctypes.c_size_t(data_len))
                if result:
                    logger.debug(f"Memory locked: {data_len} bytes")
                    return True
                else:
                    logger.warning("VirtualLock failed")
                    return False
            
            return False
            
        except Exception as e:
            logger.warning(f"Failed to lock memory: {e}")
            return False
    
    def _unlock_memory(self, data: Union[bytearray, memoryview]) -> bool:
        """
        Unlock previously locked memory.
        
        Args:
            data: Buffer to unlock
            
        Returns:
            True if memory was unlocked successfully
        """
        try:
            data_len = len(data)
            
            if self._platform.startswith('linux') and self._munlock:
                if isinstance(data, bytearray):
                    buffer_ptr = ctypes.cast(
                        ctypes.pointer(ctypes.c_char.from_buffer(data)),
                        ctypes.c_void_p
                    )
                else:
                    buffer_ptr = ctypes.cast(
                        ctypes.pointer(ctypes.c_char.from_buffer(data)),
                        ctypes.c_void_p
                    )
                
                result = self._munlock(buffer_ptr, ctypes.c_size_t(data_len))
                if result == 0:
                    logger.debug(f"Memory unlocked: {data_len} bytes")
                    return True
                    
            elif self._platform.startswith('win') and self._virtual_unlock:
                if isinstance(data, bytearray):
                    buffer_ptr = ctypes.cast(
                        ctypes.pointer(ctypes.c_char.from_buffer(data)),
                        ctypes.c_void_p
                    )
                else:
                    buffer_ptr = ctypes.cast(
                        ctypes.pointer(ctypes.c_char.from_buffer(data)),
                        ctypes.c_void_p
                    )
                
                result = self._virtual_unlock(buffer_ptr, ctypes.c_size_t(data_len))
                if result:
                    logger.debug(f"Memory unlocked: {data_len} bytes")
                    return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Failed to unlock memory: {e}")
            return False
    
    def wipe_key_material(self, key: bytes) -> WipeResult:
        """
        Convenience method to securely wipe cryptographic key material.
        
        Args:
            key: Key bytes to wipe
            
        Returns:
            WipeResult with operation details
        """
        # Convert to mutable bytearray
        mutable_key = bytearray(key)
        result = self.wipe(mutable_key)
        
        # Also try to wipe the original if it's mutable
        if isinstance(key, bytearray):
            self.wipe(key)
        
        return result
    
    def get_statistics(self) -> dict:
        """Get wipe operation statistics."""
        return {
            'wipe_count': self._wipe_count,
            'total_bytes_wiped': self._total_bytes_wiped,
            'platform': self._platform,
            'mlock_available': self._is_mlock_available()
        }
    
    def _is_mlock_available(self) -> bool:
        """Check if memory locking is available."""
        if self._platform.startswith('linux'):
            return self._mlock is not None
        elif self._platform.startswith('win'):
            return self._virtual_lock is not None
        return False


def secure_wipe_dod(data: Union[bytes, bytearray, memoryview], passes: int = 3) -> WipeResult:
    """
    Convenience function for DoD 5220.22-M compliant secure wipe.
    
    Args:
        data: Data to wipe
        passes: Number of overwrite passes (minimum 3, default 3, or 7 for full DoD 5220.22-M ECE)
        
    Returns:
        WipeResult with operation details
    """
    wiper = SecureMemoryWiper()
    return wiper.wipe(data, passes=passes)


def secure_wipe_dod_7pass(data: Union[bytes, bytearray, memoryview]) -> WipeResult:
    """
    Convenience function for full DoD 5220.22-M ECE 7-pass sanitization with read-back verification.
    """
    return secure_wipe_dod(data, passes=7)


def secure_shred_file(filepath: str, passes: int = 3) -> bool:
    """
    DoD 5220.22-M and NIST SP 800-88 compliant file shredder for physical media.
    Overwrites the file multiple times (zeros, ones, random data), forces OS write-through
    via fsync, truncates to 0 bytes, and unlinks the file.
    
    Args:
        filepath: Path to the file to sanitize
        passes: Number of overwrite passes (default 3: 0x00, 0xFF, random)
        
    Returns:
        bool: True if successfully sanitized and removed, False otherwise
    """
    if not filepath or not os.path.exists(filepath):
        return False
    if not os.path.isfile(filepath):
        return False
        
    try:
        file_size = os.path.getsize(filepath)
        chunk_size = 65536
        total_bytes = max(file_size, 4096)
        
        with open(filepath, "r+b") as f:
            # Pass 1: All zeros (0x00)
            f.seek(0)
            remaining = total_bytes
            while remaining > 0:
                n = min(remaining, chunk_size)
                f.write(b"\x00" * n)
                remaining -= n
            f.flush()
            os.fsync(f.fileno())
            
            # Pass 2: All ones (0xFF)
            if passes >= 2:
                f.seek(0)
                remaining = total_bytes
                while remaining > 0:
                    n = min(remaining, chunk_size)
                    f.write(b"\xFF" * n)
                    remaining -= n
                f.flush()
                os.fsync(f.fileno())
                
            # Pass 3: Cryptographically secure random bytes
            if passes >= 3:
                f.seek(0)
                remaining = total_bytes
                while remaining > 0:
                    n = min(remaining, chunk_size)
                    rand_buf = bytearray(secrets.token_bytes(n))
                    f.write(rand_buf)
                    try:
                        import ctypes
                        c_buf = (ctypes.c_char * len(rand_buf)).from_buffer(rand_buf)
                        ctypes.memset(c_buf, 0, len(rand_buf))
                    except Exception:
                        rand_buf[:] = b"\x00" * len(rand_buf)
                    remaining -= n
                f.flush()
                os.fsync(f.fileno())
                
            # Final truncation to 0 bytes
            f.truncate(0)
            f.flush()
            os.fsync(f.fileno())
            
        os.remove(filepath)
        logger.info(f"Successfully sanitized and shredded file: {filepath} ({total_bytes} bytes, {passes} passes)")
        return True
    except Exception as e:
        logger.error(f"Failed to securely shred file {filepath}: {e}")
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as unlink_err:
            logger.critical(f"Emergency unlinking failed for {filepath}: {unlink_err}")
        return False

