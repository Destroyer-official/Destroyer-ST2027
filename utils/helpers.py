"""
Helper functions.

Provides utility helper functions.
"""

import base64
import collections
import hmac
import os
import secrets
import threading
import time
from typing import Optional

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule


def _format_binary(data: Optional[bytes], max_len: int = 8) -> str:
    """
    Format binary data for secure logging with length-preserving truncation.

    Creates a safe representation of binary data for logging that:
    1. Base64-encodes the data for readability
    2. Truncates to max_len bytes to avoid log pollution
    3. Preserves the original data length information
    4. Handles None values gracefully

    This function is designed for security-sensitive logging where the
    full key material should never be exposed, but the presence and
    size of cryptographic values needs to be recorded.

    Args:
        data: Binary data to format safely for logs
        max_len: Maximum number of bytes to include before truncating

    Returns:
        str: Formatted string with truncation indicator and length
    """
    if data is None:
        return "None"
    
    # Handle hybrid structures (dict with bytes values)
    if isinstance(data, dict):
        # Format as dict summary
        components = []
        for key, value in data.items():
            if isinstance(value, bytes):
                components.append(f"{key}:{len(value)}bytes")
            else:
                components.append(f"{key}:{type(value).__name__}")
        return f"{{hybrid:{','.join(components)}}}"
    
    # Handle bytes
    if isinstance(data, bytes):
        if len(data) <= max_len:
            # Short data - show full base64
            return base64.b64encode(data).decode('ascii')
        else:
            # Long data - truncate with indicator
            truncated = data[:max_len]
            encoded = base64.b64encode(truncated).decode('ascii')
            return f"{encoded}...[{len(data)}bytes]"
    
    # Fallback for other types
    return str(data)


def generate_nonce(nonce_size: int = 12) -> bytes:
    """
    Generate a unique cryptographic nonce using CSPRNG.

    Args:
        nonce_size: Size of nonce in bytes (default: 12)

    Returns:
        bytes: Cryptographically secure random nonce
    """
    return secrets.token_bytes(nonce_size)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time using hmac.compare_digest
    to prevent timing attacks and length disclosure.

    Args:
        a: First byte string to compare
        b: Second byte string to compare

    Returns:
        bool: True if the strings are equal, False otherwise
    """
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        return False
    return hmac.compare_digest(bytes(a), bytes(b))


class NonceManager:
    """
    Manages nonce generation with collision detection and rotation.
    Employs a bounded sliding window to prevent unbounded memory growth.
    """
    
    def __init__(self, nonce_size: int = 12, max_nonce_uses: int = 1000000, max_history: int = 50000):
        """
        Initialize nonce manager.
        
        Args:
            nonce_size: Size of nonce in bytes
            max_nonce_uses: Maximum number of nonces before rotation
            max_history: Maximum number of recent nonces tracked for collision prevention
        """
        self.nonce_size = nonce_size
        self.max_nonce_uses = max_nonce_uses
        self.max_history = max_history
        self.counter = 0
        self.nonce_prefix = secrets.token_bytes(4)  # Random prefix for uniqueness
        self.used_nonces = set()
        self._nonce_fifo = collections.deque()
        self.last_reset_time = time.time()
        self._lock = threading.Lock()
    
    def generate_nonce(self) -> bytes:
        """
        Generate a unique nonce for cryptographic operations.

        Returns:
            bytes: Unique nonce of nonce_size length

        Raises:
            RuntimeError: If nonce space is exhausted
        """
        with self._lock:
            # Fail-closed (2026-10-14, audit nonce finding): exhaustion under
            # a live key RAISES. The pre-fix code silently called
            # _reset_locked(), re-rolling the 4-byte prefix and zeroing the
            # counter under the SAME key (nonce-space re-entry; birthday
            # collisions on the 32-bit prefix, exact reuse when two resets
            # draw the same prefix because both restart the counter).
            # Caller must rotate the encryption key, then call reset().
            if self.counter >= self.max_nonce_uses:
                raise RuntimeError(
                    f"NONCE SPACE EXHAUSTED: counter {self.counter} reached "
                    f"max_nonce_uses={self.max_nonce_uses} for this key. Rotate "
                    "the encryption key and call reset(); never re-roll the "
                    "prefix under a live key (RFC 8439 Sec 2.8)."
                )

            # Increment counter
            self.counter += 1

            # Generate nonce with prefix and counter
            counter_bytes = self.counter.to_bytes(
                self.nonce_size - len(self.nonce_prefix),
                byteorder='big'
            )
            nonce = self.nonce_prefix + counter_bytes

            # Check for collisions (extremely unlikely but safer)
            retry_count = 0
            while nonce in self.used_nonces and retry_count < 3:
                # In the unlikely event of a collision, generate a completely random nonce
                nonce = secrets.token_bytes(self.nonce_size)
                retry_count += 1

            if retry_count >= 3:
                raise RuntimeError("Failed to generate unique nonce after 3 attempts")

            # Track used nonce with bounded FIFO eviction
            self.used_nonces.add(nonce)
            self._nonce_fifo.append(nonce)
            if len(self._nonce_fifo) > self.max_history:
                evicted = self._nonce_fifo.popleft()
                self.used_nonces.discard(evicted)

            return nonce
    
    def reset(self):
        """Reset nonce manager with new prefix."""
        with self._lock:
            self._reset_locked()

    def _reset_locked(self):
        """Internal reset under lock."""
        self.counter = 0
        self.nonce_prefix = secrets.token_bytes(4)
        self.used_nonces.clear()
        self._nonce_fifo.clear()
        self.last_reset_time = time.time()


class Helpers(BaseModule):
    """Helper functions wrapper class."""
    
    def __init__(self, orchestrator):
        """Initialize helpers with nonce manager."""
        super().__init__(orchestrator)
        self._nonce_manager = NonceManager()
    
    def format_binary(self, data: bytes, max_len: int = 8) -> str:
        """
        Format binary data for display.
        
        Args:
            data: Binary data to format
            max_len: Maximum length before truncation
            
        Returns:
            str: Formatted string representation
        """
        try:
            return _format_binary(data, max_len)
        except Exception as e:
            self.logger.error(f"Error formatting binary data: {e}")
            return f"<error formatting: {e}>"
    
    def generate_nonce(self, nonce_size: int = 12) -> bytes:
        """
        Generate cryptographic nonce.
        
        Args:
            nonce_size: Size of nonce in bytes
            
        Returns:
            bytes: Cryptographically secure random nonce
        """
        if nonce_size == 12:
            # Managed uniqueness path: nonce-space exhaustion must propagate
            # (a raw CSPRNG fallback here could silently reuse a nonce).
            return self._nonce_manager.generate_nonce()
        # Non-standard sizes: direct CSPRNG generation
        return generate_nonce(nonce_size)
    
    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            bool: True if equal, False otherwise
        """
        if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
            return False
        try:
            return hmac.compare_digest(bytes(a), bytes(b))
        except Exception as e:
            self.logger.error(f"Error in constant time compare: {e}")
            return False


def is_env_true(key: str, default: bool = False) -> bool:
    """Parse a boolean, delegating production posture to the canonical gate."""
    if key in ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION"):
        from production_gate import is_production
        return is_production()
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")

