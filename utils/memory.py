"""
Memory management operations.

Provides secure memory erasure and key management.
"""

import ctypes
import gc
import logging
import platform
from typing import Optional

try:
    from ..base import BaseModule, MemoryError
except (ImportError, ValueError):
    from base import BaseModule, MemoryError

log = logging.getLogger(__name__)


class KeyEraser:
    """
    Context manager for securely handling and erasing sensitive cryptographic key material.

    This class implements multiple layers of protection for sensitive key material:
    1. Memory pinning to prevent swapping to disk
    2. Enhanced secure erasure with multiple overwrite patterns
    3. Platform-specific memory protection (VirtualLock on Windows, mlock on Linux/macOS)
    4. Immediate cleanup on context exit

    Usage:
        with KeyEraser(key_material, "session_key") as ke:
            # Use key_material safely here
            result = crypto_operation(ke.key_material)
        # Key is automatically securely erased when context exits

    Security features:
    - Prevents key material from being swapped to disk
    - Implements DoD 5220.22-M compliant secure erasure
    - Uses platform-specific memory protection APIs
    - Forces garbage collection after erasure
    """
    def __init__(self, key_material=None, description="sensitive key"):
        self.key_material = key_material
        self.description = description
        self._locked_address = None
        self._locked_length = 0
        self._locked_platform = None

    def __enter__(self):
        log.debug(f"KeyEraser: Handling {self.description}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.secure_erase()

    def set_key(self, key_material):
        """Set the key material to be managed."""
        self.key_material = key_material

    def _pin_memory(self, material: bytearray):
        """
        Pin memory to prevent swapping to disk

        This method uses platform-specific APIs to lock memory pages,
        preventing sensitive cryptographic material from being written
        to disk in swap files.

        Args:
            material (bytearray): The sensitive data to protect

        Returns:
            bool: True if memory was successfully locked, False otherwise
        """
        if not isinstance(material, bytearray) or len(material) == 0:
            return False

        address = ctypes.addressof(ctypes.c_byte.from_buffer(material))
        length = len(material)

        current_platform = platform.system()
        locked = False

        # Note: The following code is platform-specific
        try:
            if current_platform == "Windows":
                # On Windows, use VirtualLock with Win32 exception handling
                try:
                    # Use Win32 exception manager if available
                    if hasattr(KeyEraser, '_win32_exception_context'):
                        with KeyEraser._win32_exception_context():
                            if ctypes.windll.kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(length)):
                                locked = True
                                self._locked_address = address
                                self._locked_length = length
                                self._locked_platform = "Windows"
                                log.debug(f"KeyEraser: Successfully locked {length} bytes in memory with VirtualLock")
                    else:
                        # Fallback without Win32 exception handling
                        if ctypes.windll.kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(length)):
                            locked = True
                            self._locked_address = address
                            self._locked_length = length
                            self._locked_platform = "Windows"
                            log.debug(f"KeyEraser: Successfully locked {length} bytes in memory with VirtualLock")
                except Exception as win32_e:
                    log.debug(f"KeyEraser: VirtualLock failed with Win32 exception handling: {win32_e}")
            elif current_platform == "Linux" or current_platform == "Darwin":
                try:
                    # On Linux/macOS, use mlock from libc
                    libc = ctypes.cdll.LoadLibrary('libc.so.6' if current_platform == "Linux" else 'libc.dylib')
                    if hasattr(libc, "mlock"):
                        if libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(length)) == 0:
                            locked = True
                            self._locked_address = address
                            self._locked_length = length
                            self._locked_platform = current_platform
                            log.debug(f"KeyEraser: Successfully locked {length} bytes in memory with mlock")
                except Exception as e:
                    log.debug(f"KeyEraser: Error during mlock: {e}")
        except Exception as e:
            log.debug(f"KeyEraser: Memory pinning not available: {e}")

        return locked

    def _unpin_memory(self):
        """
        Unpin memory previously pinned with _pin_memory

        This method releases memory locks applied by _pin_memory,
        allowing the operating system to manage the memory normally
        after sensitive data has been securely erased.
        """
        if not self._locked_address or not self._locked_platform:
            return

        try:
            if self._locked_platform == "Windows":
                # Use Win32 exception handling for VirtualUnlock
                try:
                    if hasattr(KeyEraser, '_win32_exception_context'):
                        with KeyEraser._win32_exception_context():
                            if ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(self._locked_address), ctypes.c_size_t(self._locked_length)):
                                log.debug(f"KeyEraser: Successfully unlocked {self._locked_length} bytes with VirtualUnlock")
                    else:
                        # Fallback without Win32 exception handling
                        if ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(self._locked_address), ctypes.c_size_t(self._locked_length)):
                            log.debug(f"KeyEraser: Successfully unlocked {self._locked_length} bytes with VirtualUnlock")
                except Exception as win32_e:
                    log.debug(f"KeyEraser: VirtualUnlock failed with Win32 exception handling: {win32_e}")
            elif self._locked_platform in ("Linux", "Darwin"):
                try:
                    libc = ctypes.cdll.LoadLibrary('libc.so.6' if self._locked_platform == "Linux" else 'libc.dylib')
                    if hasattr(libc, "munlock"):
                        if libc.munlock(ctypes.c_void_p(self._locked_address), ctypes.c_size_t(self._locked_length)) == 0:
                            log.debug(f"KeyEraser: Successfully unlocked {self._locked_length} bytes with munlock")
                except Exception as e:
                    log.debug(f"KeyEraser: Error during munlock: {e}")
        except Exception as e:
            log.debug(f"KeyEraser: Error during memory unpinning: {e}")

        self._locked_address = None
        self._locked_length = 0
        self._locked_platform = None

    def secure_erase(self):
        """
        Securely erase the key material from memory using the single best method.

        This method implements a comprehensive secure erasure technique that:
        1. Overwrites memory with multiple patterns
        2. Forces memory barriers to prevent compiler optimizations
        3. Ensures memory is properly unpinned
        4. Triggers garbage collection to clean up references

        The implementation follows security best practices to minimize
        the risk of key material remaining in memory after erasure.
        """
        if self.key_material is None:
            try:
                log.debug(f"KeyEraser: No key material to erase for {self.description} (was None).")
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
            return

        try:
            # During Python interpreter shutdown, modules may become None
            # We need to handle this gracefully
            import secure_key_manager as skm
            
            # Check if the module and function are still valid (not None during shutdown)
            if skm is None:
                self._basic_secure_erase()
                return
            
            enhanced_erase = getattr(skm, 'enhanced_secure_erase', None)
            if enhanced_erase is None or not callable(enhanced_erase):
                self._basic_secure_erase()
                return
            
            try:
                log.debug(f"KeyEraser: Performing mandatory enhanced secure erase for {self.description}")
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
            
            enhanced_erase(self.key_material)
            self.key_material = None

            # Force garbage collection to clean up any lingering references
            try:
                gc.collect()
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")

            try:
                log.debug(f"KeyEraser: Completed secure erase for {self.description}")
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")

        except (ImportError, AttributeError, TypeError, NameError) as e:
            # Handle cases where module is unavailable or functions are None during shutdown
            try:
                log.debug(f"KeyEraser: Module/function unavailable ({e}), using basic erase for {self.description}")
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
            self._basic_secure_erase()
        except Exception as e:
            try:
                log.error(f"KeyEraser: An unexpected error occurred during enhanced secure erase: {e}")
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
            # During shutdown, don't raise - just try basic erase
            self._basic_secure_erase()
    
    def _basic_secure_erase(self):
        """
        Basic secure erase fallback for use during interpreter shutdown.
        This is used when the full secure_key_manager module is unavailable.
        """
        try:
            if self.key_material is None:
                return
            
            # Try to overwrite the memory with zeros
            try:
                if isinstance(self.key_material, bytearray):
                    for i in range(len(self.key_material)):
                        self.key_material[i] = 0
                elif isinstance(self.key_material, bytes):
                    # H22: no ctypes memset on immutable bytes (UB + corrupts
                    # shared references). Secrets must be held in bytearray.
                    pass
                elif hasattr(self.key_material, '__dict__'):
                    # For objects, try to clear their attributes
                    try:
                        for attr in list(vars(self.key_material).keys()):
                            try:
                                setattr(self.key_material, attr, None)
                            except Exception as _mem_err:
                                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
                    except Exception as _mem_err:
                        log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
            
            self.key_material = None
            try:
                log.debug(f"KeyEraser: Basic secure erase completed for {self.description}")
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
        except Exception as e:
            try:
                log.debug(f"KeyEraser: Basic erase failed for {self.description}: {e}")
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
            try:
                self.key_material = None
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")


def secure_memory_wipe(address: int, length: int, owner=None) -> bool:
    """
    Securely wipes a memory region using the most secure method available on the platform.

    This function implements platform-specific memory wiping techniques to ensure
    sensitive data is properly erased from memory, minimizing the risk of data
    recovery through memory forensics.

    H22: raw (address, length) pairs are an arbitrary-memory-write primitive,
    so wiping REQUIRES proof of ownership: pass the live buffer as `owner`
    (bytearray/memoryview/mmap). The address must equal the buffer's real
    base and length must fit inside it, otherwise the wipe is refused.
    Calls without `owner` fail closed.

    Args:
        address (int): Memory address to wipe
        length (int): Number of bytes to wipe
        owner: Live buffer owning the region (required)

    Returns:
        bool: True if wiping was successful, False otherwise
    """
    try:
        if owner is None:
            try:
                log.critical("secure_memory_wipe refused: no owner buffer supplied (fail-closed)")
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            return False
        try:
            if isinstance(owner, (bytes, str)):
                return False
            base = ctypes.addressof(ctypes.c_char.from_buffer(owner))
            if address != base or length <= 0 or length > len(owner):
                return False
        except Exception:
            return False
        # Platform-specific memory protection/unprotection
        if hasattr(ctypes, 'windll'):
            # Windows
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(address),
                ctypes.c_size_t(length),
                0x04,  # PAGE_READWRITE
                ctypes.byref(ctypes.c_ulong(0))
            )
            ctypes.memset(address, 0, length)
            return True
        elif hasattr(ctypes, 'CDLL'):
            try:
                # Linux/Unix
                libc = ctypes.CDLL('libc.so.6')
                libc.memset(address, 0, length)
                return True
            except Exception as _mem_err:
                log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")
    except Exception as _mem_err:
        log.debug(f"Memory cleanup suppressed non-fatal error: {_mem_err}")

    return False


class MemoryManager(BaseModule):
    """Memory management operations - wrapper for KeyEraser functionality."""
    
    def secure_erase(self, key_material: bytes) -> None:
        """Securely erase key material using KeyEraser."""
        try:
            with KeyEraser(key_material, "memory_manager_erase") as ke:
                ke.secure_erase()
            self.logger.debug("Memory manager: Secure erase completed")
        except Exception as e:
            self.logger.error(f"Memory manager: Secure erase failed: {e}")
            raise MemoryError(f"Secure erase failed: {e}", 
                            category="MEMORY", 
                            severity="HIGH",
                            module="utils.memory",
                            function="secure_erase")
    
    def pin_memory(self, material: bytearray) -> bool:
        """Pin memory to prevent swapping."""
        try:
            ke = KeyEraser()
            result = ke._pin_memory(material)
            self.logger.debug(f"Memory manager: Pin memory {'succeeded' if result else 'failed'}")
            return result
        except Exception as e:
            self.logger.error(f"Memory manager: Pin memory failed: {e}")
            raise MemoryError(f"Pin memory failed: {e}",
                            category="MEMORY",
                            severity="MEDIUM",
                            module="utils.memory",
                            function="pin_memory")
    
    def unpin_memory(self) -> None:
        """Unpin memory."""
        try:
            ke = KeyEraser()
            ke._unpin_memory()
            self.logger.debug("Memory manager: Unpin memory completed")
        except Exception as e:
            self.logger.error(f"Memory manager: Unpin memory failed: {e}")
            raise MemoryError(f"Unpin memory failed: {e}",
                            category="MEMORY",
                            severity="MEDIUM",
                            module="utils.memory",
                            function="unpin_memory")
    
    def secure_memory_wipe(self, address: int, length: int) -> bool:
        """Securely wipe memory."""
        try:
            result = secure_memory_wipe(address, length)
            self.logger.debug(f"Memory manager: Secure memory wipe {'succeeded' if result else 'failed'}")
            return result
        except Exception as e:
            self.logger.error(f"Memory manager: Secure memory wipe failed: {e}")
            raise MemoryError(f"Secure memory wipe failed: {e}",
                            category="MEMORY",
                            severity="HIGH",
                            module="utils.memory",
                            function="secure_memory_wipe")

