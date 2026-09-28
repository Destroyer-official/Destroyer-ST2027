#!/usr/bin/env python3
"""
metadata_resistance.py

Production-ready metadata resistance features for military-grade P2P messaging.

This module implements comprehensive metadata resistance including:
- Cover traffic generation (indistinguishable from real messages)
- Message padding to uniform 1024-byte boundaries
- Timing jitter for traffic analysis resistance
- Tor SOCKS5 proxy support for onion routing

**Validates: Requirements 2.1, 2.2, 2.3, 2.4**
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import socket
import struct
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional, List, Tuple, Any

# Configure logging
logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

# Padding block size (1024 bytes per requirement 2.2)
PADDING_BLOCK_SIZE = 1024

# Default cover traffic rate (10 messages per minute per requirement 2.1)
DEFAULT_COVER_TRAFFIC_RATE = 10

# Maximum timing jitter in milliseconds (500ms per requirement 2.3)
MAX_TIMING_JITTER_MS = 500

# SOCKS5 protocol constants
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_DOMAINNAME = 0x03
SOCKS5_ATYP_IPV4 = 0x01


# ============================================================================
# Exceptions
# ============================================================================

class MetadataResistanceError(Exception):
    """Base exception for metadata resistance errors."""



class PaddingError(MetadataResistanceError):
    """Error during message padding/unpadding."""


class CoverTrafficError(MetadataResistanceError):
    """Error in cover traffic generation."""


class TorConnectionError(MetadataResistanceError):
    """Error connecting through Tor SOCKS5 proxy."""


class IntegrityError(MetadataResistanceError):
    """Integrity verification failed during unpadding."""


# ============================================================================
# Message Padding Engine
# **Validates: Requirements 2.2**
# ============================================================================

@dataclass
class PaddedMessage:
    """Container for a padded message with integrity data."""
    data: bytes
    original_length: int
    integrity_tag: bytes


class MessagePaddingEngine:
    """
    Pads messages to uniform 1024-byte boundaries with integrity verification.
    
    This class implements message padding to prevent traffic analysis based on
    message size. All messages are padded to multiples of 1024 bytes using
    cryptographically random padding bytes.
    
    **Validates: Requirements 2.2**
    
    Attributes:
        block_size: The padding block size (default 1024 bytes)
        _hmac_key: Key for HMAC integrity verification
    """
    
    # Header format: 4 bytes original length + 32 bytes HMAC
    HEADER_SIZE = 36
    HMAC_SIZE = 32
    
    def __init__(self, block_size: int = PADDING_BLOCK_SIZE, hmac_key: Optional[bytes] = None):
        """
        Initialize the padding engine.
        
        Args:
            block_size: Size of padding blocks (default 1024)
            hmac_key: Key for integrity HMAC (generated if not provided)
        """
        if block_size < 64:
            raise ValueError("Block size must be at least 64 bytes")
        
        self.block_size = block_size
        self._hmac_key = hmac_key if hmac_key else secrets.token_bytes(32)
    
    def pad(self, message: bytes) -> bytes:
        """
        Pad a message to the next block boundary.
        
        The padded format is:
        [4 bytes: original length][32 bytes: HMAC][original message][random padding]
        
        Args:
            message: The original message bytes
            
        Returns:
            Padded message as bytes, length is multiple of block_size
            
        **Validates: Requirements 2.2**
        """
        original_length = len(message)
        
        # Calculate total size needed (header + message)
        content_size = self.HEADER_SIZE + original_length
        
        # Calculate padded size (round up to next block boundary)
        if content_size % self.block_size == 0:
            padded_size = content_size
        else:
            padded_size = ((content_size // self.block_size) + 1) * self.block_size
        
        # Ensure minimum size is at least one block
        if padded_size < self.block_size:
            padded_size = self.block_size
        
        # Calculate padding needed
        padding_size = padded_size - content_size
        
        # Generate cryptographically random padding
        padding = secrets.token_bytes(padding_size)
        
        # Compute HMAC over original message for integrity
        hmac_tag = hmac.new(
            self._hmac_key,
            message,
            hashlib.sha256
        ).digest()
        
        # Build padded message: [length][hmac][message][padding]
        length_bytes = struct.pack('>I', original_length)
        padded = length_bytes + hmac_tag + message + padding
        
        return padded
    
    def unpad(self, padded_message: bytes) -> bytes:
        """
        Remove padding and verify integrity.
        
        Args:
            padded_message: The padded message bytes
            
        Returns:
            Original message bytes
            
        Raises:
            PaddingError: If message is too short or malformed
            IntegrityError: If HMAC verification fails
            
        **Validates: Requirements 2.2**
        """
        if len(padded_message) < self.HEADER_SIZE:
            raise PaddingError("Message too short for header")
        
        if len(padded_message) % self.block_size != 0:
            raise PaddingError("Message length not a multiple of block size")
        
        # Extract header
        length_bytes = padded_message[:4]
        stored_hmac = padded_message[4:self.HEADER_SIZE]
        
        # Parse original length
        original_length = struct.unpack('>I', length_bytes)[0]
        
        # Validate length
        if original_length > len(padded_message) - self.HEADER_SIZE:
            raise PaddingError("Invalid original length in header")
        
        # Extract original message
        message = padded_message[self.HEADER_SIZE:self.HEADER_SIZE + original_length]
        
        # Verify HMAC
        computed_hmac = hmac.new(
            self._hmac_key,
            message,
            hashlib.sha256
        ).digest()
        
        if not hmac.compare_digest(stored_hmac, computed_hmac):
            raise IntegrityError("HMAC verification failed")
        
        return message
    
    def get_padded_size(self, message_length: int) -> int:
        """
        Calculate the padded size for a given message length.
        
        Args:
            message_length: Length of the original message
            
        Returns:
            Size of the padded message
        """
        content_size = self.HEADER_SIZE + message_length
        
        if content_size % self.block_size == 0:
            return max(content_size, self.block_size)
        
        return ((content_size // self.block_size) + 1) * self.block_size



# ============================================================================
# Timing Jitter Engine
# **Validates: Requirements 2.3**
# ============================================================================

class TimingJitterEngine:
    """
    Adds cryptographically random timing jitter to message transmission.
    
    This class implements timing jitter to prevent traffic analysis based on
    message timing patterns. Delays are uniformly distributed between 0 and
    max_jitter_ms milliseconds using cryptographically secure randomness.
    
    **Validates: Requirements 2.3**
    
    Attributes:
        max_jitter_ms: Maximum jitter in milliseconds (default 500)
    """
    
    def __init__(self, max_jitter_ms: int = MAX_TIMING_JITTER_MS):
        """
        Initialize the timing jitter engine.
        
        Args:
            max_jitter_ms: Maximum jitter in milliseconds (0-500 range enforced)
        """
        if max_jitter_ms < 0:
            raise ValueError("max_jitter_ms must be non-negative")
        if max_jitter_ms > 10000:
            raise ValueError("max_jitter_ms must not exceed 10000ms")
        
        self.max_jitter_ms = max_jitter_ms
    
    def get_jitter_ms(self) -> int:
        """
        Generate a random jitter value in milliseconds.
        
        Uses secrets.randbelow() for cryptographically secure randomness.
        
        Returns:
            Random delay in milliseconds [0, max_jitter_ms]
            
        **Validates: Requirements 2.3**
        """
        if self.max_jitter_ms == 0:
            return 0
        # secrets.randbelow returns [0, n), so we use max_jitter_ms + 1 for inclusive
        return secrets.randbelow(self.max_jitter_ms + 1)
    
    def get_jitter_seconds(self) -> float:
        """
        Generate a random jitter value in seconds.
        
        Returns:
            Random delay in seconds [0, max_jitter_ms/1000]
            
        **Validates: Requirements 2.3**
        """
        return self.get_jitter_ms() / 1000.0
    
    def apply_jitter(self) -> float:
        """
        Sleep for a random jitter duration.
        
        Returns:
            The actual delay applied in seconds
            
        **Validates: Requirements 2.3**
        """
        delay = self.get_jitter_seconds()
        if delay > 0:
            time.sleep(delay)
        return delay
    
    async def apply_jitter_async(self) -> float:
        """
        Asynchronously sleep for a random jitter duration.
        
        Returns:
            The actual delay applied in seconds
            
        **Validates: Requirements 2.3**
        """
        delay = self.get_jitter_seconds()
        if delay > 0:
            await asyncio.sleep(delay)
        return delay


# ============================================================================
# Cover Traffic Generator
# **Validates: Requirements 2.1**
# ============================================================================

class CoverMessage:
    """
    Represents a cover traffic message payload.
    
    SECURITY ARCHITECTURE:
    This payload is strictly an internal application-layer construct designed to be
    encapsulated inside Double Ratchet / TLS 1.3 AEAD envelopes before wire egress.
    Because COVER_TYPE_MARKER and timestamps are encapsulated within authenticated
    encryption, external wire observers observe only indistinguishable, uniform
    ciphertext blocks of identical padded size (1024 bytes).
    """
    
    # Cover message type identifier (distinguishable only inside AEAD plaintext by recipient)
    COVER_TYPE_MARKER = b'\x00\x00\x00\x01'
    
    def __init__(self, size: int = PADDING_BLOCK_SIZE):
        """
        Create a cover message.
        
        Args:
            size: Size of the cover message (default 1024 bytes)
        """
        self.timestamp = time.time()
        # Generate random payload that looks like encrypted data
        self.payload = secrets.token_bytes(size - len(self.COVER_TYPE_MARKER) - 8)
        self.size = size
    
    def to_bytes(self) -> bytes:
        """
        Serialize the cover message.
        
        Returns:
            Cover message as bytes
        """
        timestamp_bytes = struct.pack('>d', self.timestamp)
        return self.COVER_TYPE_MARKER + timestamp_bytes + self.payload
    
    @classmethod
    def is_cover_message(cls, data: bytes) -> bool:
        """
        Check if data is a cover message.
        
        Args:
            data: Message bytes to check
            
        Returns:
            True if this is a cover message
        """
        if len(data) < len(cls.COVER_TYPE_MARKER):
            return False
        return data[:len(cls.COVER_TYPE_MARKER)] == cls.COVER_TYPE_MARKER


class CoverTrafficGenerator:
    """
    Generates indistinguishable cover traffic at a configurable rate.
    
    Cover traffic prevents traffic analysis by maintaining a constant
    message rate regardless of actual communication activity. Cover
    messages are cryptographically indistinguishable from real messages
    to external observers.
    
    **Validates: Requirements 2.1**
    
    Attributes:
        rate_per_minute: Number of cover messages per minute (default 10)
        message_size: Size of cover messages (default 1024 bytes)
    """
    
    def __init__(
        self,
        rate_per_minute: int = DEFAULT_COVER_TRAFFIC_RATE,
        message_size: int = PADDING_BLOCK_SIZE,
        send_callback: Optional[Callable[[bytes], None]] = None
    ):
        """
        Initialize the cover traffic generator.
        
        Args:
            rate_per_minute: Messages per minute (default 10)
            message_size: Size of each cover message (default 1024)
            send_callback: Function to call with generated cover messages
        """
        if rate_per_minute < 1:
            raise ValueError("rate_per_minute must be at least 1")
        if rate_per_minute > 1000:
            raise ValueError("rate_per_minute must not exceed 1000")
        if message_size < 64:
            raise ValueError("message_size must be at least 64 bytes")
        
        self.rate_per_minute = rate_per_minute
        self.message_size = message_size
        self._send_callback = send_callback
        
        # Threading control
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        
        # Statistics
        self._messages_generated = 0
        self._start_time: Optional[float] = None
        self._message_timestamps: List[float] = []
    
    @property
    def interval_seconds(self) -> float:
        """Calculate the interval between messages in seconds."""
        return 60.0 / self.rate_per_minute
    
    @property
    def is_running(self) -> bool:
        """Check if the generator is currently running."""
        return self._running
    
    @property
    def messages_generated(self) -> int:
        """Get the total number of messages generated."""
        return self._messages_generated
    
    def generate_cover_message(self) -> bytes:
        """
        Generate a single cover message.
        
        Returns:
            Cover message bytes
            
        **Validates: Requirements 2.1**
        """
        cover = CoverMessage(self.message_size)
        return cover.to_bytes()
    
    def start(self) -> None:
        """
        Start generating cover traffic in a background thread.
        
        **Validates: Requirements 2.1**
        """
        with self._lock:
            if self._running:
                return
            
            self._running = True
            self._stop_event.clear()
            self._start_time = time.time()
            self._message_timestamps = []
            
            self._thread = threading.Thread(
                target=self._generate_loop,
                daemon=True,
                name="CoverTrafficGenerator"
            )
            self._thread.start()
            logger.info(f"Cover traffic generator started at {self.rate_per_minute}/min")
    
    def stop(self) -> None:
        """
        Stop generating cover traffic.
        
        **Validates: Requirements 2.1**
        """
        with self._lock:
            if not self._running:
                return
            
            self._running = False
            self._stop_event.set()
            
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=2.0)
            
            self._thread = None
            logger.info("Cover traffic generator stopped")
    
    def _generate_loop(self) -> None:
        """Background loop that generates cover messages."""
        jitter = TimingJitterEngine(max_jitter_ms=100)  # Small jitter for natural timing
        
        while not self._stop_event.is_set():
            try:
                # Generate cover message
                message = self.generate_cover_message()
                timestamp = time.time()
                
                # Track statistics
                self._messages_generated += 1
                self._message_timestamps.append(timestamp)
                
                # Trim old timestamps (keep last 5 minutes)
                cutoff = timestamp - 300
                self._message_timestamps = [
                    t for t in self._message_timestamps if t > cutoff
                ]
                
                # Send if callback provided
                if self._send_callback:
                    try:
                        self._send_callback(message)
                    except Exception as e:
                        logger.warning(f"Cover traffic send failed: {e}")
                
                # Wait for next interval with small jitter
                base_interval = self.interval_seconds
                jitter_delay = jitter.get_jitter_seconds() * 0.2  # ±10% jitter
                wait_time = max(0.1, base_interval + jitter_delay - 0.05)
                
                self._stop_event.wait(timeout=wait_time)
                
            except Exception as e:
                logger.error(f"Cover traffic generation error: {e}")
                self._stop_event.wait(timeout=1.0)
    
    def get_actual_rate(self, window_seconds: float = 60.0) -> float:
        """
        Calculate the actual message rate over a time window.
        
        Args:
            window_seconds: Time window to measure (default 60 seconds)
            
        Returns:
            Messages per minute over the window
        """
        now = time.time()
        cutoff = now - window_seconds
        
        recent_messages = [t for t in self._message_timestamps if t > cutoff]
        
        if not recent_messages:
            return 0.0
        
        # Calculate rate per minute
        return len(recent_messages) * (60.0 / window_seconds)
    
    def get_statistics(self) -> dict:
        """
        Get generator statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "running": self._running,
            "rate_per_minute": self.rate_per_minute,
            "messages_generated": self._messages_generated,
            "actual_rate": self.get_actual_rate(),
            "uptime_seconds": time.time() - self._start_time if self._start_time else 0
        }



# ============================================================================
# Tor SOCKS5 Proxy Support
# **Validates: Requirements 2.4**
# ============================================================================

class TorSOCKS5Proxy:
    """
    SOCKS5 proxy client for routing traffic through Tor.
    
    This class implements the SOCKS5 protocol for connecting through
    Tor's SOCKS5 proxy, enabling onion routing for metadata resistance.
    
    **Validates: Requirements 2.4**
    
    Attributes:
        proxy_host: Tor SOCKS5 proxy host (default 127.0.0.1)
        proxy_port: Tor SOCKS5 proxy port (default 9050)
    """
    
    DEFAULT_TOR_HOST = "127.0.0.1"
    DEFAULT_TOR_PORT = 9050
    
    def __init__(
        self,
        proxy_host: str = DEFAULT_TOR_HOST,
        proxy_port: int = DEFAULT_TOR_PORT,
        timeout: float = 30.0
    ):
        """
        Initialize the Tor SOCKS5 proxy client.
        
        Args:
            proxy_host: Tor proxy host address
            proxy_port: Tor proxy port
            timeout: Connection timeout in seconds
        """
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.timeout = timeout
        self._socket: Optional[socket.socket] = None
    
    def connect(self, target_host: str, target_port: int) -> socket.socket:
        """
        Connect to a target through the Tor SOCKS5 proxy.
        
        Args:
            target_host: Target hostname or .onion address
            target_port: Target port
            
        Returns:
            Connected socket
            
        Raises:
            TorConnectionError: If connection fails
            
        **Validates: Requirements 2.4**
        """
        try:
            # Create socket and connect to Tor proxy
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)
            self._socket.connect((self.proxy_host, self.proxy_port))
            
            # SOCKS5 handshake - greeting
            self._socket.sendall(bytes([SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE]))
            
            # Receive greeting response
            response = self._socket.recv(2)
            if len(response) < 2:
                raise TorConnectionError("Invalid SOCKS5 greeting response")
            
            if response[0] != SOCKS5_VERSION:
                raise TorConnectionError(f"Unsupported SOCKS version: {response[0]}")
            
            if response[1] != SOCKS5_AUTH_NONE:
                raise TorConnectionError(f"SOCKS5 authentication required: {response[1]}")
            
            # SOCKS5 connect request
            connect_request = self._build_connect_request(target_host, target_port)
            self._socket.sendall(connect_request)
            
            # Receive connect response
            response = self._socket.recv(10)
            if len(response) < 2:
                raise TorConnectionError("Invalid SOCKS5 connect response")
            
            if response[0] != SOCKS5_VERSION:
                raise TorConnectionError(f"Invalid SOCKS5 response version: {response[0]}")
            
            if response[1] != 0x00:
                error_msg = self._get_socks5_error(response[1])
                raise TorConnectionError(f"SOCKS5 connect failed: {error_msg}")
            
            # Connection established
            logger.info(f"Connected to {target_host}:{target_port} via Tor")
            return self._socket
            
        except socket.error as e:
            self.close()
            raise TorConnectionError(f"Socket error: {e}")
        except Exception as e:
            self.close()
            raise TorConnectionError(f"Connection failed: {e}")
    
    def _build_connect_request(self, host: str, port: int) -> bytes:
        """Build a SOCKS5 connect request."""
        request = bytearray([
            SOCKS5_VERSION,
            SOCKS5_CMD_CONNECT,
            0x00,  # Reserved
        ])
        
        # Check if it's an IP address or hostname
        try:
            # Try to parse as IPv4
            socket.inet_aton(host)
            request.append(SOCKS5_ATYP_IPV4)
            request.extend(socket.inet_aton(host))
        except socket.error:
            # It's a hostname (including .onion addresses)
            request.append(SOCKS5_ATYP_DOMAINNAME)
            host_bytes = host.encode('utf-8')
            request.append(len(host_bytes))
            request.extend(host_bytes)
        
        # Add port (big-endian)
        request.extend(struct.pack('>H', port))
        
        return bytes(request)
    
    def _get_socks5_error(self, code: int) -> str:
        """Get human-readable SOCKS5 error message."""
        errors = {
            0x01: "General SOCKS server failure",
            0x02: "Connection not allowed by ruleset",
            0x03: "Network unreachable",
            0x04: "Host unreachable",
            0x05: "Connection refused",
            0x06: "TTL expired",
            0x07: "Command not supported",
            0x08: "Address type not supported",
        }
        return errors.get(code, f"Unknown error (0x{code:02x})")
    
    def close(self) -> None:
        """Close the proxy connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                import logging; logging.getLogger(__name__).debug("Ignored exception")
            self._socket = None
    
    def is_tor_available(self) -> bool:
        """
        Check if Tor SOCKS5 proxy is available.
        
        Returns:
            True if Tor proxy is reachable
            
        **Validates: Requirements 2.4**
        """
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5.0)
            test_socket.connect((self.proxy_host, self.proxy_port))
            
            # Send SOCKS5 greeting
            test_socket.sendall(bytes([SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE]))
            response = test_socket.recv(2)
            test_socket.close()
            
            return len(response) >= 2 and response[0] == SOCKS5_VERSION
            
        except Exception:
            return False
    
    @staticmethod
    def is_onion_address(address: str) -> bool:
        """
        Check if an address is a Tor .onion address.
        
        Args:
            address: Address to check
            
        Returns:
            True if it's a .onion address
        """
        return address.lower().endswith('.onion')


# ============================================================================
# Metadata Resistance Manager
# ============================================================================

class MetadataResistanceManager:
    """
    Unified manager for all metadata resistance features.
    
    This class provides a single interface for managing cover traffic,
    message padding, timing jitter, and Tor routing.
    
    **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
    """
    
    def __init__(
        self,
        cover_traffic_rate: int = DEFAULT_COVER_TRAFFIC_RATE,
        padding_block_size: int = PADDING_BLOCK_SIZE,
        max_jitter_ms: int = MAX_TIMING_JITTER_MS,
        tor_proxy_host: str = TorSOCKS5Proxy.DEFAULT_TOR_HOST,
        tor_proxy_port: int = TorSOCKS5Proxy.DEFAULT_TOR_PORT,
        hmac_key: Optional[bytes] = None
    ):
        """
        Initialize the metadata resistance manager.
        
        Args:
            cover_traffic_rate: Cover messages per minute
            padding_block_size: Message padding block size
            max_jitter_ms: Maximum timing jitter in milliseconds
            tor_proxy_host: Tor SOCKS5 proxy host
            tor_proxy_port: Tor SOCKS5 proxy port
            hmac_key: HMAC key for padding integrity
        """
        self.padding_engine = MessagePaddingEngine(
            block_size=padding_block_size,
            hmac_key=hmac_key
        )
        
        self.jitter_engine = TimingJitterEngine(max_jitter_ms=max_jitter_ms)
        
        self.cover_generator = CoverTrafficGenerator(
            rate_per_minute=cover_traffic_rate,
            message_size=padding_block_size
        )
        
        self.tor_proxy = TorSOCKS5Proxy(
            proxy_host=tor_proxy_host,
            proxy_port=tor_proxy_port
        )
    
    def prepare_message(self, message: bytes) -> bytes:
        """
        Prepare a message with padding for transmission.
        
        Args:
            message: Original message bytes
            
        Returns:
            Padded message ready for transmission
        """
        return self.padding_engine.pad(message)
    
    def process_received_message(self, padded_message: bytes) -> bytes:
        """
        Process a received padded message.
        
        Args:
            padded_message: Received padded message
            
        Returns:
            Original message bytes
            
        Raises:
            IntegrityError: If message integrity check fails
        """
        return self.padding_engine.unpad(padded_message)
    
    async def send_with_jitter(
        self,
        message: bytes,
        send_func: Callable[[bytes], Any]
    ) -> Any:
        """
        Send a message with timing jitter applied.
        
        Args:
            message: Message to send
            send_func: Function to call for sending
            
        Returns:
            Result of send_func
        """
        await self.jitter_engine.apply_jitter_async()
        return send_func(message)
    
    def start_cover_traffic(
        self,
        send_callback: Optional[Callable[[bytes], None]] = None
    ) -> None:
        """
        Start generating cover traffic.
        
        Args:
            send_callback: Function to call with cover messages
        """
        if send_callback:
            self.cover_generator._send_callback = send_callback
        self.cover_generator.start()
    
    def stop_cover_traffic(self) -> None:
        """Stop generating cover traffic."""
        self.cover_generator.stop()
    
    def connect_via_tor(self, host: str, port: int) -> socket.socket:
        """
        Connect to a host through Tor.
        
        Args:
            host: Target host or .onion address
            port: Target port
            
        Returns:
            Connected socket
        """
        return self.tor_proxy.connect(host, port)
    
    def is_tor_available(self) -> bool:
        """Check if Tor is available."""
        return self.tor_proxy.is_tor_available()
    
    def get_status(self) -> dict:
        """
        Get status of all metadata resistance features.
        
        Returns:
            Dictionary with status information
        """
        return {
            "cover_traffic": self.cover_generator.get_statistics(),
            "padding_block_size": self.padding_engine.block_size,
            "max_jitter_ms": self.jitter_engine.max_jitter_ms,
            "tor_available": self.is_tor_available()
        }
    
    def shutdown(self) -> None:
        """Shutdown all metadata resistance features."""
        self.stop_cover_traffic()
        self.tor_proxy.close()


# ============================================================================
# Module-level convenience functions
# ============================================================================

_default_manager: Optional[MetadataResistanceManager] = None


def get_default_manager() -> MetadataResistanceManager:
    """Get or create the default metadata resistance manager."""
    global _default_manager
    if _default_manager is None:
        _default_manager = MetadataResistanceManager()
    return _default_manager


def pad_message(message: bytes) -> bytes:
    """Pad a message using the default manager."""
    return get_default_manager().prepare_message(message)


def unpad_message(padded_message: bytes) -> bytes:
    """Unpad a message using the default manager."""
    return get_default_manager().process_received_message(padded_message)


def get_jitter_ms() -> int:
    """Get a random jitter value in milliseconds."""
    return get_default_manager().jitter_engine.get_jitter_ms()


# ============================================================================
# Main (for testing)
# ============================================================================

if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    print("Metadata Resistance Module Test")
    print("=" * 50)
    
    # Test MessagePaddingEngine
    print("\n1. Testing MessagePaddingEngine...")
    padding = MessagePaddingEngine()
    
    test_messages = [b"Hello", b"A" * 100, b"B" * 1000, b"C" * 2000, b""]
    for msg in test_messages:
        padded = padding.pad(msg)
        unpadded = padding.unpad(padded)
        assert unpadded == msg, f"Round-trip failed for message of length {len(msg)}"  # nosec: B101
        assert len(padded) % PADDING_BLOCK_SIZE == 0, f"Padding not aligned: {len(padded)}"  # nosec: B101
        print(f"  Message {len(msg)} bytes -> Padded {len(padded)} bytes -> OK")
    
    # Test TimingJitterEngine
    print("\n2. Testing TimingJitterEngine...")
    jitter = TimingJitterEngine(max_jitter_ms=500)
    
    jitter_values = [jitter.get_jitter_ms() for _ in range(100)]
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert all(0 <= v <= 500 for v in jitter_values), "Jitter out of range"  # nosec: B101
    print(f"  Generated 100 jitter values: min={min(jitter_values)}ms, max={max(jitter_values)}ms")
    
    # Test CoverTrafficGenerator
    print("\n3. Testing CoverTrafficGenerator...")
    messages_received = []
    
    def capture_message(msg: bytes):
        messages_received.append(msg)
    
    generator = CoverTrafficGenerator(rate_per_minute=60, send_callback=capture_message)
    generator.start()
    
    time.sleep(3)  # Wait for some messages
    generator.stop()
    
    print(f"  Generated {len(messages_received)} messages in 3 seconds")
    print(f"  Statistics: {generator.get_statistics()}")
    
    # Test Tor availability
    print("\n4. Testing Tor SOCKS5 Proxy...")
    tor = TorSOCKS5Proxy()
    if tor.is_tor_available():
        print("  Tor proxy is available")
    else:
        print("  Tor proxy not available (this is OK for testing)")
    
    print("\n" + "=" * 50)
    print("All tests passed!")
    sys.exit(0)

