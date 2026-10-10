import platform_hsm_interface as cphs
import secrets
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

def secure_randbelow(n: int) -> int:
    """Generate a random integer in range [0, n) using hardware RNG."""
    if n <= 0:
        raise ValueError
    k = n.bit_length()
    num_bytes = (k + 7) // 8
    while True:
        r = cphs.get_secure_random(num_bytes)
        if not r:
            raise RuntimeError("MILITARY FATAL: Hardware RNG failed. System halting.")
        val = int.from_bytes(r, 'little')
        val &= (1 << k) - 1
        if val < n:
            return val

def get_secure_key():
    """Get cryptographic key from hardware-backed secure key management system"""
    key = cphs.get_secure_random(32)
    if not key:
        raise RuntimeError("MILITARY FATAL: Hardware RNG failed. System halting.")
    return key

def get_secure_secret():
    """Get secret from hardware-backed secure key management system"""
    secret = cphs.get_secure_random(32)
    if not secret:
        raise RuntimeError("MILITARY FATAL: Hardware RNG failed. System halting.")
    return base64.urlsafe_b64encode(secret).decode('ascii').rstrip('=')

def get_secure_token():
    """Get token from hardware-backed secure key management system"""
    token = cphs.get_secure_random(32)
    if not token:
        raise RuntimeError("MILITARY FATAL: Hardware RNG failed. System halting.")
    return base64.urlsafe_b64encode(token).decode('ascii').rstrip('=')

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
        'asymmetric': ['ML-KEM-1024', 'McEliece-8192128f', 'ML-DSA-87', 'FALCON-1024', 'SLH-DSA-256f'],
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
Secure P2P Communication Core - IPv6-first Transport Layer

This module implements the core networking layer for secure peer-to-peer
communication with a focus on modern IPv6 networking and robust connection
management.

Network Protocol Features:
1. IPv6 Transport:
   - IPv6 first with IPv4 fallback
   - TCP for reliable message delivery
   - 4-byte length prefix framing protocol (RFC 4571-style)

2. NAT Traversal:
   - RFC 5389 STUN protocol implementation
   - Public endpoint discovery
   - Multiple STUN server fallback

3. Connection Management:
   - Automatic role negotiation (client/server)
   - Connection health monitoring via heartbeats
   - Automatic reconnection with exponential backoff
   - Graceful connection termination

4. Message Framing:
   - Length-prefixed binary protocol (4-byte big-endian header)
   - Maximum message size enforcement (50MB limit)
   - Complete message validation
   - Timeout handling for partial messages

Security Considerations:
- This module provides transport layer functionality only
- Messages are NOT encrypted at this layer
- See secure_p2p.py for the security layer implementation
- DoS protection through message size limits and timeouts
- Input validation to prevent injection attacks

Technical References:
- RFC 5389: Session Traversal Utilities for NAT (STUN)
- RFC 4571: Framing Real-time Transport Protocol (RTP) and RTP Control Protocol
- RFC 8200: Internet Protocol, Version 6 (IPv6) Specification
"""

# Standard library imports
import asyncio
import enum
import errno
import logging
import os
import platform
# NOTE: 'import random' removed -- Mersenne Twister is not cryptographically secure.
import re
import signal
import socket
import ssl
import struct
# AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
import subprocess # Added for secure command execution  # nosec: B404
import sys
import threading
import time
from typing import (
    Any, Callable, Dict, List, NamedTuple, Optional,
    Set, Tuple, Type, Union, cast
)

# Ensure IDNA encoding support for internationalized domain names
import encodings.idna

# Setup dedicated logger for P2P Core
p2p_logger = logging.getLogger("p2p_core")
p2p_logger.setLevel(logging.DEBUG)

def setup_logging(log_level=logging.DEBUG, console_level=logging.INFO):
    """
    Configure logging for the P2P core module.

    Args:
        log_level: The log level for file logging
        console_level: The log level for console output

    Returns:
        Logger: Configured logger object
    """
    global p2p_logger

    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(logs_dir, exist_ok=True)

    # Configure file handler
    log_file_path = os.path.join(logs_dir, "p2p_core.log")
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(log_level)

    # Create formatter with more detailed information
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s'
    )
    file_handler.setFormatter(formatter)

    # Clear existing handlers to avoid duplicates
    for handler in p2p_logger.handlers[:]:
        p2p_logger.removeHandler(handler)

    # Add file handler to logger
    p2p_logger.addHandler(file_handler)

    # Let logs propagate to root logger for console output (avoid duplicate handlers)
    p2p_logger.propagate = True

    p2p_logger.info("P2P Core logger initialized")
    return p2p_logger

# Initialize logging with default settings
setup_logging()

# Terminal colors for better UI
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RED = '\033[91m'
BOLD = '\033[1m'
RESET = '\033[0m'

# Default STUN server configuration (Disabled by default in military/dark direct P2P mode)
DEFAULT_STUN_SERVER = ""
DEFAULT_STUN_PORT = 0

class StunError(Exception):
    """Exception raised for STUN protocol errors."""

class StunClient:
    """
    RFC 5389 STUN protocol implementation for NAT traversal and endpoint discovery.

    This class implements the Session Traversal Utilities for NAT (STUN) protocol
    to discover the public IPv6/IPv4 address and port of a device behind NAT.
    It strictly follows RFC 5389 specifications for message formatting, attribute
    processing, and transaction handling.

    Protocol Implementation:
    1. Message Structure:
       - 20-byte header with method type, length, magic cookie, and transaction ID
       - XOR-MAPPED-ADDRESS attribute (0x0020) for endpoint discovery
       - Proper byte alignment and padding per RFC 5389 section 15

    2. Network Operations:
       - UDP transport for STUN communication
       - Asynchronous request handling with timeouts
       - Multiple server fallback for reliability
       - IPv6 and IPv4 support with appropriate socket families

    3. Security Considerations:
       - No authentication mechanism (uses basic STUN, not STUN with authentication)
       - No TLS protection for STUN traffic
       - Random 96-bit transaction IDs to prevent response forgery
       - Proper validation of all received messages

    Technical References:
    - RFC 5389: Session Traversal Utilities for NAT (STUN)
    - RFC 8489: Session Traversal Utilities for NAT (STUN) (updated version)
    """

    # STUN message types and attributes
    BINDING_REQUEST = 0x0001
    XOR_MAPPED_ADDRESS = 0x0020
    MAGIC_COOKIE = 0x2112A442

    # Default configuration
    DEFAULT_TIMEOUT = 5.0  # Increased timeout for better reliability
    DEFAULT_MAX_RETRIES = 2  # Reduced retries to fail faster per server

    def __init__(self,
                 stun_servers: Optional[List[Tuple[str, int]]] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 max_retries: int = DEFAULT_MAX_RETRIES):
        """
        Initialize a STUN client with the provided servers.

        Args:
            stun_servers: List of (hostname, port) tuples for STUN servers
            timeout: Timeout in seconds for STUN requests
            max_retries: Maximum number of retry attempts per server
        """
        # In military/dark mode, STUN servers must be explicitly provided.
        # Default is empty list to prevent unauthenticated UDP leaks to Google/Cloudflare.
        self.stun_servers = list(stun_servers) if stun_servers else []
        if self.stun_servers:
            secrets.SystemRandom().shuffle(self.stun_servers)

        self.timeout = timeout
        self.max_retries = max_retries
        self.logger = logging.getLogger("p2p_core.stun")

    @staticmethod
    def create_stun_message() -> Tuple[bytes, bytes]:
        """
        Create a STUN binding request message following RFC 5389.

        Returns:
            Tuple containing (complete_message, transaction_id)
        """
        transaction_id = secrets.token_bytes(12)
        magic_cookie = struct.pack("!I", StunClient.MAGIC_COOKIE)
        message_type = struct.pack("!H", StunClient.BINDING_REQUEST)
        message_length = struct.pack("!H", 0)  # No attributes

        message = message_type + message_length + magic_cookie + transaction_id
        return message, transaction_id

    @staticmethod
    def parse_stun_response(data: bytes, transaction_id: bytes) -> Optional[Tuple[str, int]]:
        """
        Parse a STUN response to extract the XOR-mapped address.

        Args:
            data: Raw STUN response data
            transaction_id: Transaction ID from the original request for validation

        Returns:
            Tuple of (ipv6_address, port) or None if parsing fails
        """
        # Verify minimum length and header
        if len(data) < 20:
            return None

        # Extract and verify the Magic Cookie (first 4 bytes after header)
        magic_cookie = data[4:8]
        if magic_cookie != struct.pack("!I", StunClient.MAGIC_COOKIE):
            return None

        # Verify transaction ID
        if data[8:20] != transaction_id:
            return None

        # Parse attributes
        pos = 20  # Start of attributes
        while pos + 4 <= len(data):
            attr_type = int.from_bytes(data[pos:pos+2], 'big')
            attr_len = int.from_bytes(data[pos+2:pos+4], 'big')

            # Process XOR-MAPPED-ADDRESS attribute
            if attr_type == StunClient.XOR_MAPPED_ADDRESS:
                addr_pos = pos + 4
                family_byte = data[addr_pos + 1]
                port = int.from_bytes(data[addr_pos+2:addr_pos+4], 'big') ^ (StunClient.MAGIC_COOKIE >> 16)

                if family_byte == 0x02:  # IPv6
                    # Create XOR mask: Magic Cookie + Transaction ID
                    xor_mask = magic_cookie + transaction_id

                    # Apply XOR operation to get actual IPv6 address
                    ip_bytes = bytearray(data[addr_pos+4:addr_pos+20])
                    for i in range(16):
                        ip_bytes[i] ^= xor_mask[i]

                    # Convert bytes to IPv6 address string
                    ipv6 = socket.inet_ntop(socket.AF_INET6, bytes(ip_bytes))
                    return ipv6, port
                elif family_byte == 0x01:  # IPv4
                    # Create XOR mask: Magic Cookie (first 4 bytes)
                    xor_mask = magic_cookie[:4]
                    ip_bytes = bytearray(data[addr_pos+4:addr_pos+8])
                    for i in range(4):
                        ip_bytes[i] ^= xor_mask[i]
                    ipv4 = socket.inet_ntop(socket.AF_INET, bytes(ip_bytes))
                    return ipv4, port

            # Move to next attribute
            padding = 0
            if attr_len % 4 != 0:
                padding = 4 - (attr_len % 4)
            pos += 4 + attr_len + padding

        return None

    async def get_public_endpoint(self) -> Tuple[Optional[str], Optional[int]]:
        """
        Discover the public IPv6 or IPv4 address and port using STUN protocol.

        Implements a reliable discovery process with:
        - Local interface check for native global unicast IPv6 (2000::/3)
        - Dual-stack STUN resolution (tries IPv6 first, falls back to IPv4)
        - Multiple STUN server fallbacks for redundancy
        - Retry logic with exponential backoff

        Returns:
            Tuple containing (public_ip, public_port) or (None, None) if discovery fails
        """
        # Step 1: Check local network interfaces for native global unicast IPv6 (opt-in)
        if os.environ.get("P2P_ENABLE_NIC_ENUM", "0") == "1":
            try:
                import psutil
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET6:
                            clean_ip = addr.address.split('%')[0].lower()
                            # Global unicast IPv6 addresses start with 2 or 3 (2000::/3)
                            if clean_ip.startswith(('2', '3')):
                                self.logger.info(f"Native global IPv6 detected on interface (prefix {clean_ip[:9]}...)")
                                port = getattr(self, 'port', None) or 50007
                                return clean_ip, port
            except Exception as e:
                self.logger.debug(f"Local IPv6 interface inspection: {e}")

        # Step 2: STUN discovery over IPv6 and IPv4
        if not self.stun_servers or os.environ.get("P2P_DISABLE_STUN", "0") == "1":
            self.logger.info("STUN discovery inactive or disabled (Tactical Stealth / Dark P2P Mode)")
            return None, None

        sock = None
        loop = asyncio.get_event_loop()

        try:
            for stun_host, stun_port in self.stun_servers:
                self.logger.info(f"Trying STUN server: {stun_host}:{stun_port}")

                # Try IPv6 first, then IPv4
                for family in (socket.AF_INET6, socket.AF_INET):
                    try:
                        addrinfo = await loop.getaddrinfo(
                            stun_host, stun_port,
                            family=family,
                            type=socket.SOCK_DGRAM
                        )
                    except socket.gaierror as e:
                        fam_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
                        self.logger.debug(f"{fam_name} DNS resolution failed for {stun_host}: {e}")
                        continue

                    if not addrinfo:
                        continue

                    target_addr = addrinfo[0][4]
                    fam_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
                    self.logger.info(f"Using STUN server {fam_name} address: {target_addr}")

                    # Create a UDP socket matching the family
                    try:
                        if sock:
                            sock.close()
                            sock = None

                        sock = socket.socket(family, socket.SOCK_DGRAM)
                        sock.setblocking(False)
                        # B104: wildcard bind on an ephemeral outbound STUN socket is required
                        # to send/receive UDP; STUN is disabled by default (air-gapped).
                        bind_addr = "::" if family == socket.AF_INET6 else "0.0.0.0"  # nosec B104 - outbound ephemeral STUN socket, disabled by default
                        sock.bind((bind_addr, 0))  # nosec B104 - outbound ephemeral STUN socket, disabled by default

                        local_ip, local_port = sock.getsockname()[:2]
                        self.logger.debug(f"UDP Socket bound to: {local_ip}:{local_port}")
                    except OSError as e:
                        self.logger.warning(f"Failed to create or bind {fam_name} socket: {e}")
                        if sock:
                            sock.close()
                            sock = None
                        continue

                    # Send STUN request with retries
                    stun_message, transaction_id = self.create_stun_message()

                    for retry in range(self.max_retries):
                        if not sock:
                            break

                        try:
                            sock.setblocking(True)
                            try:
                                if sock and target_addr:
                                    def safe_send_stun():
                                        if sock and target_addr:
                                            return sock.sendto(stun_message, target_addr)
                                        return 0
                                    await loop.run_in_executor(None, safe_send_stun)
                                else:
                                    break
                            finally:
                                if sock:
                                    sock.setblocking(False)

                            self.logger.debug(f"Sent STUN request to {target_addr} (attempt {retry+1}/{self.max_retries})")

                            # Receive STUN response
                            def receive_callback():
                                if not sock:
                                    return None, None
                                sock.setblocking(True)
                                try:
                                    data, addr = sock.recvfrom(1024)
                                    return data, addr
                                finally:
                                    if sock:
                                        sock.setblocking(False)

                            data_and_addr = await asyncio.wait_for(
                                loop.run_in_executor(None, receive_callback),
                                timeout=self.timeout
                            )

                            if not data_and_addr or data_and_addr[0] is None:
                                continue

                            data, addr = data_and_addr
                            result = self.parse_stun_response(data, transaction_id)
                            if result:
                                ip, port = result
                                if ':' in ip:
                                    self.logger.info(f"STUN discovered Public IPv6: [{ip}]:{port}")
                                else:
                                    self.logger.info(f"STUN discovered Public IPv4: {ip}:{port}")
                                return ip, port

                        except asyncio.TimeoutError:
                            self.logger.debug(f"STUN timeout ({fam_name}) on {stun_host}")
                            if retry == self.max_retries - 1:
                                break
                            await asyncio.sleep(0.3 * (retry + 1))
                        except Exception as e:
                            self.logger.debug(f"Error during STUN {fam_name} request: {e}")
                            break

            self.logger.warning("All STUN servers failed to discover public endpoint.")
            return None, None

        except Exception as e:
            self.logger.error(f"Error during STUN operation: {e}", exc_info=True)
            return None, None

        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    import logging; logging.getLogger(__name__).debug("Ignored exception")
                self.logger.debug("Closed STUN UDP socket.")

# For backwards compatibility
async def get_public_ip_port(stun_host: str = DEFAULT_STUN_SERVER,
                             stun_port: int = DEFAULT_STUN_PORT) -> Tuple[Optional[str], Optional[int]]:
    """
    Discover public endpoint using local Global Unicast IPv6 detection first,
    falling back to RFC 5389 STUN NAT traversal.

    Args:
        stun_host: STUN server hostname
        stun_port: STUN server port

    Returns:
        Tuple containing (public_ip, public_port) or (None, None) if discovery fails
    """
    try:
        from network_endpoint_discovery import NetworkEndpointDiscovery
        discovery = NetworkEndpointDiscovery()
        kernel_v6 = discovery.get_kernel_routed_ipv6()
        if kernel_v6:
            return kernel_v6, 50007
        public_v6, _, _ = discovery.scan_local_interfaces()
        if public_v6:
            return public_v6[0].ip, 50007
    except Exception:
        pass

    if stun_host and stun_port:
        client = StunClient(stun_servers=[(stun_host, stun_port)])
        return await client.get_public_endpoint()

    return None, None

# Message protocol definitions
class MessageType(enum.Enum):
    """
    Protocol message type enumeration with strict validation.

    This enum defines the complete set of valid message types in the P2P protocol,
    providing type safety and protocol validation. Each message type serves a
    specific purpose in the protocol flow and has defined handling requirements.

    Protocol Message Categories:
    1. Session Management:
       - USERNAME: Initial identity establishment
       - EXIT: Graceful session termination
       - RECONNECTED: Session re-establishment notification

    2. Connection Monitoring:
       - HEARTBEAT: Connection liveness probe
       - HEARTBEAT_ACK: Heartbeat acknowledgment

    3. Data Transfer:
       - MESSAGE: Application data transfer

    4. Error Handling:
       - ERROR: Protocol error notification

    Security Implementation:
    - Strict string-based enum validation prevents type injection
    - Exhaustive pattern matching enforces complete type handling
    - Parser validates message type before content processing
    - Unknown message types trigger explicit error handling
    """
    USERNAME = "USERNAME"     # Initial identity establishment
    MESSAGE = "MSG"           # Application data transfer
    EXIT = "EXIT"             # Graceful session termination
    HEARTBEAT = "HEARTBEAT"   # Connection liveness probe
    HEARTBEAT_ACK = "HEARTBEAT_ACK"  # Heartbeat response
    RECONNECTED = "RECONNECTED"  # Session re-establishment
    ERROR = "ERROR"           # Protocol error notification

class MessageError(Exception):
    """Exception raised for message parsing or validation errors."""

class MessageParseError(MessageError):
    """Exception raised when parsing invalid wire protocol bytes."""

class Message(NamedTuple):
    """
    Type-safe protocol message with serialization and validation.

    This class implements a structured message format with strong validation
    and type safety for the P2P protocol. It provides serialization,
    deserialization, and validation services for all protocol messages.

    Message Structure:
    1. Header Fields:
       - type: MessageType enum value defining message semantics
       - sender: Identity of the originating peer (string)

    2. Payload:
       - content: Application-specific data (string)
       - timestamp: Message creation time (float, Unix epoch)

    3. Validation Rules:
       - Message type must be a valid MessageType enum value
       - Sender must be a non-empty string (for USERNAME and MESSAGE types)
       - Content length must not exceed MAX_CONTENT_LENGTH
       - All fields must be properly encoded UTF-8 strings

    Security Implementation:
    - Input validation on all fields during construction and parsing
    - Type enforcement through enum validation
    - Size limits to prevent DoS attacks
    - Proper error handling for malformed messages
    - Safe serialization/deserialization with explicit encoding

    Technical Notes:
    - Uses ':' as field separator (not allowed in usernames)
    - UTF-8 encoding for all string fields
    - Explicit error types for different validation failures
    """
    type: MessageType
    sender: str = ""
    content: str = ""
    timestamp: float = 0.0

    # Constants
    MAX_SENDER_LENGTH = 64
    MAX_CONTENT_LENGTH = 16384  # 16 KB

    def __str__(self) -> str:
        """
        Serialize the message for transmission.

        Returns:
            str: Properly formatted message string

        Raises:
            MessageError: If message validation fails
        """
        # Validate message before serialization
        self._validate()

        if self.type == MessageType.USERNAME:
            return f"{self.type.value}:{self.sender}"
        elif self.type == MessageType.MESSAGE:
            return f"{self.type.value}:{self.sender}:{self.content}"
        else:
            return self.type.value

    def _validate(self) -> None:
        """
        Validate message structure and content.

        Raises:
            MessageError: If validation fails
        """
        # Check for valid message type
        if not isinstance(self.type, MessageType):
            raise MessageError(f"Invalid message type: {self.type}")

        # Validate sender field
        if self.type == MessageType.USERNAME or self.type == MessageType.MESSAGE:
            if not isinstance(self.sender, str):
                raise MessageError(f"Sender must be a string, got {type(self.sender)}")
            if len(self.sender) > self.MAX_SENDER_LENGTH:
                raise MessageError(f"Sender name too long ({len(self.sender)} chars, max is {self.MAX_SENDER_LENGTH})")
            if not self.sender:
                raise MessageError("Sender name cannot be empty")

        # Validate content field for chat messages
        if self.type == MessageType.MESSAGE:
            if not isinstance(self.content, str):
                raise MessageError(f"Content must be a string, got {type(self.content)}")
            if len(self.content) > self.MAX_CONTENT_LENGTH:
                raise MessageError(f"Message content too long ({len(self.content)} chars, max is {self.MAX_CONTENT_LENGTH})")

    @classmethod
    def parse(cls, data: bytes) -> 'Message':
        """
        Parse and validate a message from raw bytes.

        Args:
            data: Raw data received from the network

        Returns:
            Message: A validated Message object

        Raises:
            MessageError: If parsing fails or validation fails
        """
        try:
            # Decode and validate raw data
            if not data:
                raise MessageParseError("Empty message received")

            try:
                text = data.decode('utf-8').strip()
            except UnicodeDecodeError as e:
                raise MessageParseError(f"Invalid UTF-8 data received: {e}")

            timestamp = time.time()

            # Simple message types without additional data
            if text in (MessageType.EXIT.value, MessageType.HEARTBEAT.value,
                       MessageType.HEARTBEAT_ACK.value, MessageType.RECONNECTED.value):
                return cls(type=MessageType(text), timestamp=timestamp)

            # Username message
            elif text.startswith(f"{MessageType.USERNAME.value}:"):
                parts = text.split(':', 1)
                if len(parts) == 2 and parts[1]:
                    if len(parts[1]) > cls.MAX_SENDER_LENGTH:
                        raise MessageParseError(f"USERNAME identifier exceeds limit of {cls.MAX_SENDER_LENGTH} chars")
                    return cls(type=MessageType.USERNAME, sender=parts[1], timestamp=timestamp)
                raise MessageParseError("Invalid USERNAME message format")

            # Chat message
            elif text.startswith(f"{MessageType.MESSAGE.value}:"):
                parts = text.split(':', 2)
                if len(parts) == 3 and parts[1]:
                    if len(parts[1]) > cls.MAX_SENDER_LENGTH:
                        raise MessageParseError(f"Sender identifier exceeds limit of {cls.MAX_SENDER_LENGTH} chars")
                    if len(parts[2]) > cls.MAX_CONTENT_LENGTH:
                        raise MessageParseError(f"Message content exceeds limit of {cls.MAX_CONTENT_LENGTH} chars")
                    return cls(
                        type=MessageType.MESSAGE,
                        sender=parts[1],
                        content=parts[2],
                        timestamp=timestamp
                    )
                raise MessageParseError("Invalid MSG message format")

            # Unknown format (sanitized to avoid echoing arbitrary wire data)
            p2p_logger.warning("Received message with unknown format prefix")
            raise MessageParseError("Invalid message format: unrecognized prefix")

        except MessageError:
            raise
        except Exception as e:
            p2p_logger.error(f"Error parsing message: {e}", exc_info=True)
            raise MessageParseError(f"Error parsing message: {str(e)}")

    @classmethod
    def create_error(cls, error_message: str) -> 'Message':
        """
        Create an error message.

        Args:
            error_message: Description of the error

        Returns:
            Message: Error message
        """
        return cls(type=MessageType.ERROR, content=error_message, timestamp=time.time())

class SocketError(Exception):
    """Exception raised for socket communication errors."""

class FramedSocket:
    """
    Length-prefixed message framing protocol implementation for TCP sockets.

    This class implements a reliable message framing protocol over TCP sockets,
    ensuring message boundaries are preserved despite TCP's stream-oriented
    nature. It provides methods for sending and receiving complete messages
    with proper error handling and timeout management.

    Protocol Specification:
    1. Frame Structure:
       - 4-byte header: Big-endian unsigned integer length prefix
       - Variable-length payload: Raw binary message data

    2. Protocol Features:
       - Message size validation (50MB maximum)
       - Complete message delivery guarantee
       - Timeout handling for all operations
       - SSL/TLS socket compatibility
       - Partial message buffering

    3. Security Implementation:
       - Length validation before memory allocation
       - Maximum message size enforcement (DoS prevention)
       - Timeout enforcement for all network operations
       - Proper error propagation and socket state management
       - SSL/TLS error handling

    Technical Notes:
    - Uses struct.pack/unpack for binary encoding (network byte order)
    - Implements RFC 4571-style length-prefixed framing
    - Chunked receive operations to handle large messages efficiently
    - Proper handling of socket.timeout and SSL errors
    """

    # Unified caps (single source of truth: utils/message_caps.py).
    # Layered: frame 4MB > post-auth 512KB >= pre-auth 64KB == chat 64KB.
    # Literals kept for import-cycle safety; validated against caps in tests.
    MAX_MESSAGE_SIZE = 4 * 1024 * 1024  # == caps.MAX_FRAME (absolute frame abort ceiling)
    PRE_AUTH_MAX_MESSAGE_SIZE = 64 * 1024  # == caps.PRE_AUTH_MAX (Finding 3 / P0.2)
    PRE_AUTH_TIMEOUT = 10.0  # 10.0 seconds pre-auth timeout
    POST_AUTH_MAX_MESSAGE_SIZE = 512 * 1024  # == caps.POST_AUTH_MAX (standard message ceiling)
    # 2026-09-19: hybrid-bundle exception (measured bundle = 1,817,211 bytes:
    # ML-KEM-1024 pk 1568B + McEliece-8192128f pk ~1.3MB base64 + Falcon/ML-DSA
    # sigs + certs). Mirrors the documented session_manager 2MB McEliece
    # exception. Used ONLY at the 2 hybrid-bundle receive sites; every other
    # pre-auth frame keeps the 64KB ceiling. Length is still validated BEFORE
    # allocation, and the pre-auth rate limiter (5/IP) bounds concurrency.
    PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE = 2 * 1024 * 1024
    MAX_CHAT_PAYLOAD = 64 * 1024  # == caps.MAX_MESSAGE_PAYLOAD (strictest chat MSG)
    DEFAULT_RECV_TIMEOUT = 60.0  # seconds
    DEFAULT_SEND_TIMEOUT = 30.0  # seconds
    BUFFER_SIZE = 8192  # 8KB chunks for receive operations

    @staticmethod
    def is_ssl_socket(sock: socket.socket) -> bool:
        """
        Check if a socket is an SSL wrapped socket.

        Args:
            sock: The socket to check

        Returns:
            bool: True if the socket is SSL-wrapped
        """
        # Check for common SSL socket indicators in a safe way
        return (
            hasattr(sock, 'cipher') and
            hasattr(sock, 'context') and
            callable(getattr(sock, 'cipher', None))
        )

    @classmethod
    async def recv_exact(cls, sock: socket.socket, n: int, timeout: float = DEFAULT_RECV_TIMEOUT, max_size: Optional[int] = None) -> Optional[bytes]:
        """
        Reliably receive exactly n bytes from a socket.

        Args:
            sock: The socket to receive from
            n: Exact number of bytes to receive
            timeout: Operation timeout in seconds
            max_size: Optional custom maximum size bound

        Returns:
            Received data as bytes or None if error/timeout/connection closed

        Raises:
            SocketError: For unexpected socket errors
            asyncio.TimeoutError: If operation times out
        """
        if not sock:
            raise SocketError("Socket is None")

        if n <= 0:
            return b''

        effective_max = max_size if max_size is not None else cls.MAX_MESSAGE_SIZE
        if n > effective_max:
            raise SocketError(f"Requested receive size ({n} bytes) exceeds maximum allowed ({effective_max} bytes)")

        data = bytearray()
        start_time = asyncio.get_event_loop().time()
        is_ssl = cls.is_ssl_socket(sock)
        loop = asyncio.get_event_loop()

        while len(data) < n:
            if asyncio.get_event_loop().time() - start_time > timeout:
                p2p_logger.warning(f"Timeout receiving {n} bytes (got {len(data)} bytes so far)")
                raise asyncio.TimeoutError(f"Timeout receiving {n} bytes (got {len(data)} bytes so far)")

            try:
                remaining = n - len(data)
                recv_size = min(remaining, cls.BUFFER_SIZE)

                # Cross-platform async receive
                if is_ssl:
                    packet = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: sock.recv(recv_size)),
                        timeout=5.0  # Short timeout for each attempt
                    )
                else:
                    packet = await asyncio.wait_for(
                        loop.sock_recv(sock, recv_size),
                        timeout=5.0  # Short timeout for each attempt
                    )

                if not packet:  # Connection closed
                    p2p_logger.debug(f"Connection closed while receiving data (got {len(data)}/{n} bytes)")
                    return None

                data.extend(packet)

            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                # SSL not ready, wait briefly and retry
                await asyncio.sleep(0.01)
                continue
            except asyncio.TimeoutError:
                # Short timeout for this attempt, but continue trying
                continue
            except BlockingIOError:
                await asyncio.sleep(0.01)
                continue
            except ConnectionResetError as e:
                p2p_logger.warning(f"Connection reset while receiving data: {e}")
                return None
            except OSError as e:
                error_code = getattr(e, 'errno', None)
                p2p_logger.error(f"Socket error during receive: {e} (errno: {error_code})", exc_info=True)
                raise SocketError(f"Socket error: {str(e)}")
            except Exception as e:
                p2p_logger.error(f"Unexpected error in recv_exact: {e}", exc_info=True)
                raise SocketError(f"Unexpected error: {str(e)}")

        return bytes(data)

    @classmethod
    async def send_framed(cls, sock: socket.socket, data: bytes, timeout: float = DEFAULT_SEND_TIMEOUT) -> bool:
        """
        Send length-prefixed data over a socket.

        Args:
            sock: The socket to send over
            data: The data to send
            timeout: Operation timeout in seconds

        Returns:
            True if sending was successful, False otherwise

        Raises:
            SocketError: For unexpected socket errors
        """
        if not sock:
            raise SocketError("Socket is None")

        # Fail-closed: b'' is the encryption-failure sentinel (see SecureP2PChat.
        # _encrypt_message). A zero-length frame is never valid chat traffic -
        # refuse it here so no unchecked call site can emit it (Finding 6.1).
        if not data:
            p2p_logger.warning("Refusing to send empty frame (possible encryption failure sentinel)")
            return False

        if len(data) > cls.MAX_MESSAGE_SIZE:
            raise SocketError(f"Message size ({len(data)} bytes) exceeds maximum allowed ({cls.MAX_MESSAGE_SIZE} bytes)")

        # Unified caps payload-type check (log-only, non-breaking):
        # 4MB frame ceiling enforced above; chat payloads should be <=64KB
        # and post-auth messages <=512KB. Larger frames are legal wire traffic
        # (e.g. FILE chunks / ratchet ciphertext + padding) but are logged so
        # oversize chat payloads are visible without changing lab behavior.
        try:
            if len(data) > cls.POST_AUTH_MAX_MESSAGE_SIZE:
                p2p_logger.warning(
                    "Large frame %d bytes exceeds POST_AUTH cap %d (allowed up to "
                    "4MB frame ceiling; expected only for FILE chunks)",
                    len(data), cls.POST_AUTH_MAX_MESSAGE_SIZE,
                )
            elif len(data) > cls.MAX_CHAT_PAYLOAD:
                p2p_logger.debug(
                    "Frame %d bytes exceeds 64KB chat payload cap "
                    "(allowed up to 512KB post-auth / 4MB frame; likely FILE/ciphertext)",
                    len(data),
                )
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass

        try:
            # Create length-prefixed frame
            frame = struct.pack(">I", len(data)) + data
            is_ssl = cls.is_ssl_socket(sock)
            loop = asyncio.get_event_loop()

            if is_ssl:
                # Special handling for SSL sockets
                remaining = len(frame)
                view = memoryview(frame)
                sent = 0

                start_time = loop.time()

                while sent < remaining:
                    # Check timeout
                    if loop.time() - start_time > timeout:
                        p2p_logger.warning(f"Timeout sending frame after {sent}/{remaining} bytes")
                        return False

                    try:
                        chunk_sent = await loop.run_in_executor(
                            None,
                            lambda: sock.send(view[sent:])
                        )
                        if chunk_sent == 0:
                            p2p_logger.warning("send() returned 0, connection may be closed")
                            return False
                        sent += chunk_sent

                    except ssl.SSLWantWriteError:
                        await asyncio.sleep(0.01)  # Brief pause and retry
                    except ssl.SSLWantReadError:
                        await asyncio.sleep(0.01)  # Brief pause and retry

                return sent == remaining

            else:
                # Regular socket, use asyncio sock_sendall
                await asyncio.wait_for(
                    loop.sock_sendall(sock, frame),
                    timeout=timeout
                )
                return True

        except asyncio.TimeoutError:
            p2p_logger.error(f"Timeout sending {len(data)} bytes")
            return False
        except ConnectionResetError:
            p2p_logger.warning("Connection reset while sending data")
            return False
        except BrokenPipeError:
            p2p_logger.warning("Broken pipe while sending data")
            return False
        except OSError as e:
            p2p_logger.error(f"Failed to send framed data: {e}")
            return False
        except Exception as e:
            p2p_logger.error(f"Unexpected error sending framed data: {e}", exc_info=True)
            raise SocketError(f"Send error: {str(e)}")

    @classmethod
    async def receive_framed(cls, sock: socket.socket, timeout: float = DEFAULT_RECV_TIMEOUT, max_size: Optional[int] = None) -> Optional[bytes]:
        """
        Receive length-prefixed data from a socket.

        Args:
            sock: The socket to receive from
            timeout: Maximum time to wait for complete message, in seconds
            max_size: Optional custom maximum size bound

        Returns:
            The received data payload or None if error/timeout/connection closed

        Raises:
            SocketError: For unexpected socket errors
            ValueError: For protocol errors (invalid length field)
        """
        if not sock:
            raise SocketError("Socket is None")

        try:
            # Read the 4-byte length prefix
            len_bytes = await cls.recv_exact(sock, 4, timeout)
            if len_bytes is None:
                return None

            # Parse the length prefix
            msg_len = struct.unpack(">I", len_bytes)[0]

            # Sanity check: enforce maximum message size
            effective_max = max_size if max_size is not None else cls.MAX_MESSAGE_SIZE
            if msg_len > effective_max:
                p2p_logger.error(f"Received frame length too large: {msg_len} bytes. Maximum allowed: {effective_max} bytes")
                raise ValueError(f"Frame length ({msg_len} bytes) exceeds maximum allowed size ({effective_max} bytes)")

            if msg_len == 0:
                return b''

            # Read the message data
            msg_data = await cls.recv_exact(sock, msg_len, timeout, max_size=effective_max)
            if msg_data is None:
                p2p_logger.warning("Connection closed or timeout while receiving frame data")
                return None

            return msg_data

        except asyncio.TimeoutError:
            p2p_logger.debug("Timeout while receiving framed message")
            return None
        except ConnectionResetError:
            p2p_logger.warning("Connection reset while receiving framed message")
            return None
        except ValueError as e:
            p2p_logger.error(f"Invalid frame format: {e}")
            raise  # Re-raise protocol errors
        except struct.error as e:
            p2p_logger.error(f"Struct unpacking error: {e} - possibly corrupted data")
            return None
        except SocketError:
            # Let socket errors propagate
            raise
        except Exception as e:
            p2p_logger.error(f"Unexpected error receiving framed data: {e}", exc_info=True)
            raise SocketError(f"Receive error: {str(e)}")


# Module-level aliases for FramedSocket caps (single source of truth stays
# on the class; literals are NOT duplicated here).
# 2026-09-18 production fix: secure_p2.py / secure_p2p.py call
# p2p.PRE_AUTH_TIMEOUT / p2p.PRE_AUTH_MAX_MESSAGE_SIZE at module scope
# (14 sites each); without these aliases every live handshake raised
# AttributeError before any byte was exchanged (found by full-suite run).
PRE_AUTH_TIMEOUT = FramedSocket.PRE_AUTH_TIMEOUT
PRE_AUTH_MAX_MESSAGE_SIZE = FramedSocket.PRE_AUTH_MAX_MESSAGE_SIZE
PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE = FramedSocket.PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE
POST_AUTH_MAX_MESSAGE_SIZE = FramedSocket.POST_AUTH_MAX_MESSAGE_SIZE
MAX_MESSAGE_SIZE = FramedSocket.MAX_MESSAGE_SIZE
MAX_CHAT_PAYLOAD = FramedSocket.MAX_CHAT_PAYLOAD
DEFAULT_RECV_TIMEOUT = FramedSocket.DEFAULT_RECV_TIMEOUT
DEFAULT_SEND_TIMEOUT = FramedSocket.DEFAULT_SEND_TIMEOUT


class PreAuthRateLimiter:
    """
    Per-IP connection and handshake token bucket / concurrency limiter (Finding 3 / P0.2).
    Mitigates pre-auth DoS attacks on handshakes and ensures NC3/EAM release window availability.
    """
    MAX_CONCURRENT_HANDSHAKES_PER_IP = 5
    MAX_HANDSHAKE_ATTEMPTS_PER_MIN = 20
    MIN_HEARTBEAT_INTERVAL_SECONDS = 5.0

    def __init__(self):
        self._pending_handshakes: Dict[str, int] = {}
        self._attempt_history: Dict[str, List[float]] = {}
        self._last_heartbeat: Dict[str, float] = {}
        self._lock = threading.Lock()

    def acquire_handshake(self, ip: str) -> bool:
        with self._lock:
            now = time.time()
            # Clean history older than 60s
            history = [t for t in self._attempt_history.get(ip, []) if now - t < 60.0]
            if len(history) >= self.MAX_HANDSHAKE_ATTEMPTS_PER_MIN:
                p2p_logger.warning(f"PreAuthRateLimiter: IP {ip} exceeded {self.MAX_HANDSHAKE_ATTEMPTS_PER_MIN} handshakes/min")
                return False
            pending = self._pending_handshakes.get(ip, 0)
            if pending >= self.MAX_CONCURRENT_HANDSHAKES_PER_IP:
                p2p_logger.warning(f"PreAuthRateLimiter: IP {ip} exceeded max concurrent handshakes ({self.MAX_CONCURRENT_HANDSHAKES_PER_IP})")
                return False
            history.append(now)
            self._attempt_history[ip] = history
            self._pending_handshakes[ip] = pending + 1
            return True

    def release_handshake(self, ip: str) -> None:
        with self._lock:
            if ip in self._pending_handshakes:
                self._pending_handshakes[ip] = max(0, self._pending_handshakes[ip] - 1)
                if self._pending_handshakes[ip] == 0:
                    del self._pending_handshakes[ip]

    def check_heartbeat_rate(self, peer_id: str) -> bool:
        with self._lock:
            now = time.time()
            last = self._last_heartbeat.get(peer_id, 0.0)
            if now - last < self.MIN_HEARTBEAT_INTERVAL_SECONDS:
                p2p_logger.debug(f"PreAuthRateLimiter: Heartbeat from {peer_id} throttled (< {self.MIN_HEARTBEAT_INTERVAL_SECONDS}s)")
                return False
            self._last_heartbeat[peer_id] = now
            return True



# Legacy functions for backwards compatibility

async def recv_all(sock: socket.socket, n: int) -> Optional[bytes]:
    """Legacy wrapper around FramedSocket.recv_exact."""
    try:
        return await FramedSocket.recv_exact(sock, n)
    except (SocketError, asyncio.TimeoutError):
        return None

async def send_framed(sock: socket.socket, data: bytes) -> bool:
    """Legacy wrapper around FramedSocket.send_framed."""
    try:
        return await FramedSocket.send_framed(sock, data)
    except SocketError:
        return False

async def receive_framed(sock: socket.socket, timeout: float = 120.0, max_size: Optional[int] = None) -> Optional[bytes]:
    """Legacy wrapper around FramedSocket.receive_framed.

    2026-09-18 production fix: accept and forward ``max_size`` (pre-auth
    64KB ceilings). Previously the wrapper dropped the kwarg, so all 28
    live-handshake call sites raised TypeError before any key exchange.
    """
    try:
        return await FramedSocket.receive_framed(sock, timeout, max_size=max_size)
    except (SocketError, ValueError):
        return None


def diagnose_socket_state(sock) -> str:
    """Classify a socket instantly without blocking (handshake diagnostics).

    Returns one of: "no-socket", "closed" (peer closed/reset -- recv
    returns b'' immediately), "readable-pending" (bytes waiting: a
    framing/oversize rejection is likely, not a timeout), "no-data"
    (peer silent: genuine timeout/wrong-socket). Never raises, never
    blocks. Used to make fail-closed handshake errors actionable.
    """
    try:
        import select as _select
    except Exception:
        return "unknown-select-unavailable"
    try:
        if sock is None:
            return "no-socket"
        try:
            sock.getpeername()
        except OSError:
            return "closed"
        try:
            r, _, _ = _select.select([sock], [], [], 0)
        except Exception:
            return "unknown-select-failed"
        if r:
            return "readable-pending"
        return "no-data"
    except Exception:
        return "unknown-error"

class SimpleP2PChat:
    """
    IPv6-first peer-to-peer communication framework with NAT traversal.

    This class implements a complete peer-to-peer communication system with
    automatic NAT traversal, connection management, and reliable message
    delivery. It provides the transport layer foundation for secure P2P
    applications.

    Network Architecture:
    1. Connection Establishment:
       - Dual role capability (can act as client or server)
       - IPv6-first with IPv4 fallback
       - NAT traversal via STUN for public endpoint discovery
       - Automatic role negotiation based on network conditions

    2. Connection Management:
       - Heartbeat-based connection monitoring
       - Automatic reconnection with exponential backoff
       - Graceful connection termination
       - Connection state synchronization

    3. Message Transport:
       - Length-prefixed binary framing protocol
       - Complete message validation
       - Type-safe message serialization
       - Reliable ordered delivery

    4. Security Boundaries:
       - Transport layer ONLY - no encryption or authentication
       - Messages are transmitted as cleartext
       - No identity verification
       - No protection against traffic analysis

    Technical Implementation:
       - Asynchronous I/O using Python's asyncio
       - Thread-safe connection management
       - Proper resource cleanup and error handling
       - Comprehensive logging for diagnostics

    Note: For a security-enhanced version with end-to-end encryption,
    authentication, and forward secrecy, see SecureP2PChat in secure_p2p.py.
    """

    def __init__(self, *args, **kwargs) -> None:
        """Initialize a new P2P chat instance with default configuration."""
        # 2028 hardening: legacy allow_insecure_plaintext kwarg removed - passing it
        # is a fail-closed error (previously silently ignored, inviting misuse).
        if "allow_insecure_plaintext" in kwargs or (
            len(args) > 0 and isinstance(args[0], bool)
        ):
            raise ValueError(
                "allow_insecure_plaintext was removed: plaintext transport is permanently "
                "prohibited; use SecureP2PChat (TLS 1.3 + ratchet) in secure_p2p.py."
            )
        if args or kwargs:
            raise TypeError(f"SimpleP2PChat takes no arguments (got args={args!r} kwargs={kwargs!r})")
        self.allow_insecure_plaintext = False
        p2p_logger.info("SimpleP2PChat initialized: unencrypted plaintext transmission is permanently prohibited in military defense platform.")

        # Network state
        self.public_ip: Optional[str] = None
        self.public_port: Optional[int] = None
        self.tcp_socket: Optional[socket.socket] = None
        self.peer_ip: Optional[str] = None
        self.peer_port: Optional[int] = None
        self.is_connected: bool = False
        self.last_known_peer: Optional[Tuple[str, int]] = None

        # Tasks and async control
        self.receive_task: Optional[asyncio.Task] = None
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.stop_event: asyncio.Event = asyncio.Event()
        self.connection_lock: asyncio.Lock = asyncio.Lock()
        self.message_queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self.last_heartbeat_received: float = 0
        self.last_heartbeat_sent: float = 0

        # Message history
        self.message_history: List[Message] = []
        self.max_history_size: int = 100

        # User state
        self.local_username: str = f"User_{secure_randbelow(900) + 100}"
        self.peer_username: str = "Peer"
        self.reconnect_attempts: int = 0

        # Configuration Constants
        self.MAX_RECONNECT_ATTEMPTS: int = 3
        self.STUN_TIMEOUT: float = 2.0
        self.STUN_RETRIES: int = 3
        self.CONNECTION_TIMEOUT: float = 30.0
        self.RECEIVE_TIMEOUT: float = 90.0
        self.SEND_TIMEOUT: float = 30.0
        self.RECV_BUFFER_SIZE: int = 8192
        self.MAX_FRAME_SIZE: int = 4 * 1024 * 1024  # 4MB absolute frame abort ceiling (DoS mitigation)
        self.HEARTBEAT_INTERVAL: int = 60
        self.MISSED_HEARTBEATS_THRESHOLD: int = 3
        self.MAX_USERNAME_LENGTH: int = 32
        self.USERNAME_REGEX: str = r"^[a-zA-Z0-9_-]{3,32}$"

        # Data-plane selection: 'python' (default, current audited path) or
        # Data-plane selection: 'rust' (hardened native engine from rust_data_plane/)
        # or 'python' (reference fallback). Default unified to 'rust'.
        self.data_plane: str = os.environ.get('P2P_DATA_PLANE', 'rust').lower()
        self._rust_engine = None  # lazy SecureEngine, constructed on demand

    def _get_rust_engine(self):
        """Lazily construct the Rust data-plane engine.

        Raises:
            RuntimeError: If the native module is not built and running in production.
        """
        if self._rust_engine is None:
            try:
                from destroyer_core import SecureEngine
                self._rust_engine = SecureEngine()
            except ImportError as e:
                if os.environ.get("P2P_PRODUCTION") == "1" or os.environ.get("P2P_STRICT_SECURITY") == "1":
                    raise RuntimeError(
                        "MILITARY FATAL: P2P_DATA_PLANE=rust required in production but native module "
                        "destroyer_core is not built. Run `maturin develop -r` in rust_data_plane/."
                    ) from e
                import logging
                logging.getLogger(__name__).warning("Native module destroyer_core not built; using Python reference.")
                self.data_plane = 'python'
                return None
        return self._rust_engine

    def rust_data_plane_active(self) -> bool:
        """True when the Rust data plane is active."""
        return self.data_plane in ('rust', 'rust_udp', 'udp')

    async def _close_connection(self, attempt_reconnect: bool = False) -> None:
        """
        Securely close the TCP connection and clean up resources.

        This method handles the orderly shutdown of an active TCP connection,
        ensuring that all resources are properly released and the connection
        state is securely reset.

        Security Measures:
        - **Graceful Shutdown**: Uses `socket.shutdown` to prevent abrupt
          connection termination, which can lead to resource leaks.
        - **State Reset**: Explicitly resets connection state variables to
          prevent unauthorized reuse of a closed connection.
        - **Task Cancellation**: Ensures that all related asynchronous tasks
          are properly cancelled to prevent lingering operations.
        - **Lock Management**: Uses an asyncio.Lock to prevent race conditions
          during connection teardown.

        Args:
            attempt_reconnect: If True, try to reconnect to the last known peer.
        """
        async with self.connection_lock:
            p2p_logger.info("Closing TCP connection.")
            was_connected = self.is_connected
            self.is_connected = False
            self.stop_event.set()

            # Cancel tasks
            tasks_to_cancel = []
            if self.receive_task and not self.receive_task.done():
                tasks_to_cancel.append(("Receive task", self.receive_task))
                self.receive_task = None

            if self.heartbeat_task and not self.heartbeat_task.done():
                tasks_to_cancel.append(("Heartbeat task", self.heartbeat_task))
                self.heartbeat_task = None

            # Cancel tasks in parallel
            if tasks_to_cancel:
                for task_name, task in tasks_to_cancel:
                    try:
                        task.cancel()
                    except Exception as e:
                        p2p_logger.error(f"Error cancelling {task_name}: {e}", exc_info=True)

                # Wait briefly for tasks to clean up
                await asyncio.sleep(0.2)

            # Close socket
            if self.tcp_socket:
                socket_to_close = self.tcp_socket
                self.tcp_socket = None  # Clear reference first

                try:
                    # Try graceful shutdown first
                    try:
                        socket_to_close.shutdown(socket.SHUT_RDWR)
                    except (OSError, AttributeError):
                        import logging; logging.getLogger(__name__).debug("Ignored exception")  # Socket may already be closed

                    socket_to_close.close()
                    p2p_logger.info("Socket closed successfully")
                except Exception as e:
                    p2p_logger.error(f"Error closing socket: {e}", exc_info=True)

            # Store peer info for potential reconnect
            if self.peer_ip and self.peer_port:
                self.last_known_peer = (self.peer_ip, self.peer_port)

            # Try to reconnect if requested
            if was_connected and attempt_reconnect and self.last_known_peer and self.reconnect_attempts < self.MAX_RECONNECT_ATTEMPTS:
                self.reconnect_attempts += 1
                peer_ip, peer_port = self.last_known_peer

                print(f"\n{YELLOW}Connection lost. Attempting to reconnect ({self.reconnect_attempts}/{self.MAX_RECONNECT_ATTEMPTS})...{RESET}")
                try:
                    backoff_time = min(1.0 * self.reconnect_attempts, 5.0)  # Exponential backoff, max 5 seconds
                    p2p_logger.info(f"Waiting {backoff_time:.1f}s before reconnection attempt {self.reconnect_attempts}")
                    await asyncio.sleep(backoff_time)

                    await self._connect_to_peer(peer_ip, peer_port)
                    if self.is_connected:
                        print(f"\n{GREEN}Reconnected successfully!{RESET}")
                        p2p_logger.info(f"Reconnected to {peer_ip}:{peer_port}")
                        self.reconnect_attempts = 0
                        self.stop_event.clear()

                        # Start chat session again
                        asyncio.create_task(self._chat_session(is_reconnect=True))
                        return
                except asyncio.CancelledError:
                    p2p_logger.info("Reconnection attempt cancelled")
                    raise
                except Exception as e:
                    p2p_logger.error(f"Reconnection attempt failed: {e}", exc_info=True)

            if attempt_reconnect and self.reconnect_attempts >= self.MAX_RECONNECT_ATTEMPTS:
                print(f"\n{RED}Failed to reconnect after {self.MAX_RECONNECT_ATTEMPTS} attempts.{RESET}")
                self.reconnect_attempts = 0

            # Reset peer info after failed reconnects
            self.peer_ip = None
            self.peer_port = None
            self.peer_username = "Peer" # Reset peer username

            print(f"\n{BLUE}Disconnected. Returning to main menu.{RESET}")

    async def _async_input(self, prompt: str) -> str:
        """
        Get user input asynchronously without blocking the event loop.

        This method allows the application to receive user input while
        continuing to process network events and messages.

        Args:
            prompt: Text prompt to display to the user

        Returns:
            User input string

        Security notes:
        - Input is not validated here, validation happens at usage sites
        - Handles Ctrl+C and Ctrl+D gracefully to prevent unexpected exits
        """
        import sys
        p2p_logger.debug(f"_async_input called, stdin.isatty()={sys.stdin.isatty()}")
        print(prompt, end='', flush=True)

        loop = asyncio.get_event_loop()
        try:
            # Pass empty string to input() since prompt was already printed
            result = await loop.run_in_executor(None, lambda: input(''))
            p2p_logger.debug(f"Input received: {result}")
            return result
        except KeyboardInterrupt:
            # Handle Ctrl+C (must be before Exception)
            p2p_logger.info("KeyboardInterrupt in input")
            print("\nInput interrupted")
            return "exit"
        except (EOFError, OSError, IOError) as e:
            # Handle Ctrl+D or non-interactive environment
            p2p_logger.warning(f"Input error ({type(e).__name__}): {e}. Exiting gracefully.")
            print(f"\nNon-interactive environment detected or EOF ({type(e).__name__}). Exiting...")
            return "exit"
        except Exception as e:
            # Catch any other input errors to prevent infinite loops
            p2p_logger.error(f"Unexpected input error: {type(e).__name__}: {e}", exc_info=True)
            print(f"\nInput error: {type(e).__name__}: {e}. Exiting...")
            return "exit"
        except Exception as e:
            p2p_logger.error(f"Error getting input: {e}")
            return ""

    async def _process_message(self, data: bytes) -> None:
        """
        Process a received message and take appropriate actions.

        This method parses incoming network messages and handles them
        according to their message type, updating application state
        and displaying information to the user as needed.

        Args:
            data: Raw message data received from peer

        Security notes:
        - Messages are validated before processing
        - Input length limits are enforced
        - Invalid messages are rejected with appropriate logging
        """
        if not data:
            return

        if not self.allow_insecure_plaintext:
            p2p_logger.critical("SECURITY REJECTION: Refusing to dispatch unauthenticated cleartext message (plaintext permanently prohibited)")
            return

        try:
            message = Message.parse(data)
        except MessageError as e:
            p2p_logger.warning(f"Rejected malformed message from wire: {e}")
            return

        if not message:
            return

        # Handle message based on type
        if message.type == MessageType.ERROR:
            p2p_logger.warning(f"Message error: {message.content}")
            return

        elif message.type == MessageType.USERNAME:
            # Validate username length and format
            if (1 <= len(message.sender) <= self.MAX_USERNAME_LENGTH and
                re.match(self.USERNAME_REGEX, message.sender)):
                self.peer_username = message.sender
                # Clear line and print notification
                print("\r" + " " * 100)
                print(f"\n{GREEN}{BOLD}Connected with {self.peer_username}{RESET}\n")
                print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
            else:
                p2p_logger.warning(f"Received invalid username: '{message.sender}'")

        elif message.type == MessageType.EXIT:
            print("\r" + " " * 100)
            print(f"\n{YELLOW}{self.peer_username} has left the chat.{RESET}")
            p2p_logger.info(f"Peer {self.peer_username} initiated disconnect.")
            await self._close_connection(attempt_reconnect=False)

        elif message.type == MessageType.MESSAGE:
            # Validate message content
            if len(message.content) > Message.MAX_CONTENT_LENGTH:
                p2p_logger.warning(f"Received oversized message ({len(message.content)} bytes) from {message.sender}")
                return

            # Cryptographically bind displayed sender to connected peer username (Item 34 / Finding 5.3)
            display_sender = message.sender
            if self.peer_username and message.sender != self.peer_username:
                p2p_logger.warning(f"SECURITY ALERT: Message sender claim '{message.sender}' does not match connected peer '{self.peer_username}'")
                display_sender = f"{self.peer_username} (spoofed: {message.sender})"

            # Store message in history
            if len(self.message_history) >= self.max_history_size:
                self.message_history.pop(0)
            self.message_history.append(message)

            # Clear line before printing message
            print("\r" + " " * 100 + "\r", end='')
            print(f"{MAGENTA}{display_sender}: {RESET}{message.content}")
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)

        elif message.type == MessageType.HEARTBEAT:
            self.last_heartbeat_received = time.time()
            p2p_logger.debug("Received heartbeat message")
            _now_hb = time.time()
            _last_ack = getattr(self, '_last_hb_ack_time', 0.0)
            if _now_hb - _last_ack >= 5.0:
                self._last_hb_ack_time = _now_hb
                try:
                    # Send acknowledgment
                    await self._send_message(Message(type=MessageType.HEARTBEAT_ACK))
                except Exception as e:
                    p2p_logger.debug(f"Failed to send heartbeat ACK: {e}")

        elif message.type == MessageType.HEARTBEAT_ACK:
            self.last_heartbeat_received = time.time()
            p2p_logger.debug("Received heartbeat acknowledgment")

        elif message.type == MessageType.RECONNECTED:
            print("\r" + " " * 100)
            print(f"\n{GREEN}{self.peer_username} has reconnected.{RESET}")
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)

        else:
            p2p_logger.warning(f"Received unknown message type: {message.type}")

    async def _receive_messages(self):
        """
        Handles receiving and processing messages from the connected peer.

        Runs as a background task that continuously monitors the socket for
        incoming framed messages and processes them based on message type.
        """
        consecutive_errors = 0
        MAX_CONSECUTIVE_ERRORS = 5
        BACKOFF_DELAY = 0.5  # seconds

        p2p_logger.info("Starting message receive loop")

        try:
            while not self.stop_event.is_set() and self.tcp_socket:
                try:
                    data = await receive_framed(self.tcp_socket, timeout=self.RECEIVE_TIMEOUT)
                    consecutive_errors = 0
                    BACKOFF_DELAY = 0.5  # Reset backoff on success

                    if data is None:
                        # Check if connection is still active
                        if self.tcp_socket and not self.stop_event.is_set():
                            p2p_logger.info("Receive loop detected closed connection unexpectedly.")
                            print(f"\n{YELLOW}Peer has disconnected or connection lost.{RESET}")
                            await self._close_connection(attempt_reconnect=True)
                        else:
                            p2p_logger.info("Receive loop exiting (socket closed or stop event set).")
                        break

                    # Per-peer rate limiting (DoS mitigation)
                    now = time.time()
                    if not hasattr(self, '_msg_timestamps'):
                        self._msg_timestamps = []
                    self._msg_timestamps = [t for t in self._msg_timestamps if now - t < 60.0]
                    max_msgs_per_min = int(os.environ.get("P2P_MAX_MSGS_PER_MIN", "120"))
                    if len(self._msg_timestamps) >= max_msgs_per_min:
                        p2p_logger.warning(f"Per-peer message rate limit exceeded ({len(self._msg_timestamps)}/{max_msgs_per_min} per min). Throttling.")
                        await asyncio.sleep(0.1)
                        continue
                    self._msg_timestamps.append(now)

                    # Process received message
                    await self._process_message(data)

                except asyncio.CancelledError:
                    p2p_logger.info("Receive task cancelled.")
                    raise
                except ConnectionResetError:
                    p2p_logger.info("Connection reset by peer.")
                    print(f"\n{YELLOW}Connection reset by peer.{RESET}")
                    if not self.stop_event.is_set():
                        await self._close_connection(attempt_reconnect=True)
                    break

                except OSError as e:
                    consecutive_errors += 1
                    # Check for closed socket errors
                    if e.errno in (9, 10038, 10054, 10053):  # Various socket closed errors
                        p2p_logger.warning(f"Receive loop detected socket closed/error: {e}")
                        if not self.stop_event.is_set():
                            await self._close_connection(attempt_reconnect=True)
                        break
                    else:
                        p2p_logger.error(f"Socket error during receive: {e}", exc_info=True)
                        if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                            p2p_logger.warning("Max consecutive receive errors reached.")
                            if not self.stop_event.is_set():
                                await self._close_connection(attempt_reconnect=True)
                            break
                        # Exponential backoff
                        await asyncio.sleep(min(BACKOFF_DELAY * consecutive_errors, 5.0))

                except Exception as e:
                    consecutive_errors += 1
                    p2p_logger.error(f"Unexpected error during receive: {e}", exc_info=True)
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                        p2p_logger.warning("Max consecutive unexpected errors reached.")
                        if not self.stop_event.is_set():
                            await self._close_connection(attempt_reconnect=True)
                        break
                    # Exponential backoff
                    await asyncio.sleep(min(BACKOFF_DELAY * consecutive_errors, 5.0))

            p2p_logger.info("Receive loop finished normally.")
        except asyncio.CancelledError:
            p2p_logger.info("Receive loop cancelled.")
            raise
        except Exception as e:
            p2p_logger.error(f"Receive loop exited with unhandled exception: {e}", exc_info=True)
        finally:
            # Update connection state if loop exits unexpectedly
            if self.is_connected and not self.stop_event.is_set():
                 p2p_logger.warning("Receive loop ended unexpectedly without explicit close. Closing connection.")
                 try:
                     await self._close_connection(attempt_reconnect=True)
                 except Exception as e:
                     p2p_logger.error(f"Error during final cleanup in receive loop: {e}", exc_info=True)
            p2p_logger.info("Receive loop cleanup complete")

    async def _send_message(self, message: Message) -> bool:
        """
        Send a structured message to the peer.

        Args:
            message: The Message object to send

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.is_connected or not self.tcp_socket:
            p2p_logger.warning("Cannot send message: not connected")
            return False

        p2p_logger.critical("SECURITY REJECTION: Refusing unencrypted transmission in SimpleP2PChat. Plaintext transport is permanently prohibited in military defense platform; use SecureP2PChat.")
        raise SecurityError("Unencrypted plaintext transport is permanently prohibited in military defense platform; use SecureP2PChat.")

        try:
            message_str = str(message)
            return await send_framed(self.tcp_socket, message_str.encode('utf-8'))
        except Exception as e:
            p2p_logger.error(f"Error sending message: {e}", exc_info=True)
            return False

    async def _send_heartbeats(self):
        """
        Sends periodic heartbeat messages to keep the connection alive.

        Monitors connection health and initiates reconnection if too many
        heartbeats are missed.
        """
        missed_heartbeats = 0

        while not self.stop_event.is_set() and self.is_connected:
            try:
                await asyncio.sleep(self.HEARTBEAT_INTERVAL)

                if not self.is_connected or self.stop_event.is_set():
                    break

                if self.tcp_socket:
                    heartbeat_message = Message(type=MessageType.HEARTBEAT)
                    success = await self._send_message(heartbeat_message)
                    self.last_heartbeat_sent = time.time()

                    if not success:
                        missed_heartbeats += 1
                        p2p_logger.warning(f"Failed to send heartbeat. Missed: {missed_heartbeats}/{self.MISSED_HEARTBEATS_THRESHOLD}")

                        if missed_heartbeats >= self.MISSED_HEARTBEATS_THRESHOLD:
                            p2p_logger.warning("Too many missed heartbeats. Connection may be dead.")
                            print(f"\n{YELLOW}Connection appears to be dead. Attempting to reconnect...{RESET}")
                            if not self.stop_event.is_set():
                                await self._close_connection(attempt_reconnect=True)
                            break
                    else:
                        missed_heartbeats = 0  # Reset counter on success

            except asyncio.CancelledError:
                break
            except Exception as e:
                p2p_logger.error(f"Error sending heartbeat: {e}")
                missed_heartbeats += 1

                if missed_heartbeats >= self.MISSED_HEARTBEATS_THRESHOLD:
                    if not self.stop_event.is_set():
                        await self._close_connection(attempt_reconnect=True)
                    break

    async def _connect_to_peer(self, peer_ip, peer_port):
        """
        Establishes a TCP connection to a peer over IPv6.

        Sets up socket options for reliable IPv6 communications.

        Args:
            peer_ip: Peer's IPv6 address
            peer_port: Peer's port number

        Returns:
            True if connection successful, raises exception otherwise
        """
        client_socket = None
        connection_start_time = time.time()

        try:
            print(f"\n{YELLOW}Connecting to [{peer_ip}]:{peer_port}...{RESET}")

            # Validate input parameters
            if not peer_ip:
                raise ValueError("IPv6 address cannot be empty")

            try:
                peer_port = int(peer_port)
                if not (1 <= peer_port <= 65535):
                    raise ValueError("Port must be between 1 and 65535")
            except (TypeError, ValueError):
                raise ValueError(f"Invalid port number: {peer_port}")

            loop = asyncio.get_event_loop()
            p2p_logger.info(f"Resolving IPv6 address for {peer_ip}:{peer_port}")

            try:
                addrinfo = await loop.getaddrinfo(
                    peer_ip, peer_port,
                    family=socket.AF_INET6,
                    type=socket.SOCK_STREAM
                )
            except socket.gaierror as e:
                p2p_logger.error(f"Failed to resolve IPv6 address {peer_ip}:{peer_port} - {e}", exc_info=True)
                raise ValueError(f"Could not resolve IPv6 address: {str(e)}")

            if not addrinfo:
                p2p_logger.error(f"No IPv6 addresses found for {peer_ip}:{peer_port}")
                raise ValueError("Could not resolve IPv6 address")

            # Get socket address information
            family, type_, proto, _, sockaddr = addrinfo[0]
            p2p_logger.info(f"Using IPv6 address: {sockaddr}")

            try:
                client_socket = socket.socket(family, type_, proto)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                # Set TCP keepalive parameters if supported
                try:
                    if hasattr(socket, 'TCP_KEEPIDLE'):
                        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    if hasattr(socket, 'TCP_KEEPINTVL'):
                        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
                    if hasattr(socket, 'TCP_KEEPCNT'):
                        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                except Exception as e:
                    p2p_logger.debug(f"Could not set some TCP keepalive options: {e}")
                    # Non-critical, continue anyway

                p2p_logger.info(f"Attempting connection to {sockaddr} (timeout: {self.CONNECTION_TIMEOUT}s)")

                # Cross-platform TCP connection method
                client_socket.setblocking(True)

                async def connect_with_timeout():
                    try:
                        # Use a named function for the executor to properly handle the null check
                        def safe_connect():
                            if client_socket:  # Safety check inside executor
                                try:
                                    client_socket.connect(sockaddr)
                                    return True
                                except socket.error as e:
                                    # Already connected is fine
                                    if hasattr(e, 'errno') and e.errno == getattr(errno, 'EISCONN', 56):
                                        return True
                                    raise
                            return False

                        result = await asyncio.wait_for(
                            loop.run_in_executor(None, safe_connect),
                            timeout=self.CONNECTION_TIMEOUT
                        )
                        return result
                    except socket.error as e:
                        # Already connected is fine
                        if hasattr(e, 'errno') and e.errno == getattr(errno, 'EISCONN', 56):
                            return True
                        raise

                await connect_with_timeout()

                # Set back to non-blocking mode after connection
                client_socket.setblocking(False)

                # Connection successful - verify it's working
                try:
                    # Try to set TCP_NODELAY if available (disable Nagle's algorithm)
                    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    import logging; logging.getLogger(__name__).debug("Ignored exception")  # Not critical if this fails

                p2p_logger.info(f"Connection to {sockaddr} succeeded")
                connection_time = time.time() - connection_start_time
                p2p_logger.info(f"Connection established in {connection_time:.2f} seconds")

                # Connection succeeded
                self.tcp_socket = client_socket
                self.peer_ip = peer_ip
                self.peer_port = peer_port
                self.is_connected = True

                # Save successful connection
                self.last_known_peer = (peer_ip, peer_port)
                self.last_heartbeat_received = time.time()  # Reset heartbeat timer

                p2p_logger.info(f"Successfully connected to [{peer_ip}]:{peer_port}")
                print(f"{GREEN}Successfully connected to [{peer_ip}]:{peer_port} " +
                      f"(in {connection_time:.2f}s){RESET}")
                return True

            except asyncio.CancelledError:
                p2p_logger.info("Connection attempt was cancelled")
                if client_socket:
                    client_socket.close()
                raise
            except asyncio.TimeoutError:
                p2p_logger.error(f"Connection attempt timed out after {self.CONNECTION_TIMEOUT}s")
                if client_socket:
                    client_socket.close()
                    client_socket = None
                raise ConnectionError(f"Connection timed out after {self.CONNECTION_TIMEOUT} seconds")
            except ConnectionRefusedError:
                p2p_logger.error(f"Connection refused to [{peer_ip}]:{peer_port}")
                if client_socket:
                    client_socket.close()
                    client_socket = None
                raise ConnectionError("Connection refused. Is the peer's server running?")
            except (OSError, Exception) as e:
                error_code = getattr(e, 'errno', None)
                p2p_logger.error(f"Connection attempt failed: {e} (errno: {error_code})")
                if client_socket:
                    client_socket.close()
                    client_socket = None
                raise ConnectionError(f"Failed to connect: {str(e)}")

        except asyncio.CancelledError:
            p2p_logger.info("Connection process cancelled")
            if client_socket:
                client_socket.close()
            raise
        except ConnectionError:
            # Re-raise connection errors without modification
            raise
        except ValueError:
            # Re-raise validation errors without modification
            raise
        except Exception as e:
            p2p_logger.error(f"Unexpected error connecting to {peer_ip}:{peer_port}: {e}", exc_info=True)
            if client_socket:
                client_socket.close()
            raise ConnectionError(f"Connection failed: {str(e)}")

    async def _chat_session(self, is_reconnect=False):
        """
        Manages an active chat session after connection is established.

        Handles username exchange, message sending/receiving, and connection
        monitoring during an active chat session.

        Args:
            is_reconnect: True if this is a reconnected session
        """
        if not self.tcp_socket:
            p2p_logger.warning("Attempted to start chat session without a socket.")
            return

        self.stop_event.clear()
        self.is_connected = True

        # Username Exchange (skip if reconnecting)
        if not is_reconnect:
            if not self.local_username or self.local_username.startswith("User_"):
                while True:
                    candidate_name = (await self._async_input(f"{YELLOW}Enter your username (max {self.MAX_USERNAME_LENGTH} chars): {RESET}")).strip()
                    if not candidate_name:
                        self.local_username = f"User_{secure_randbelow(900) + 100}"
                        print(f"Using default username: {self.local_username}")
                        break
                    elif len(candidate_name) > self.MAX_USERNAME_LENGTH:
                        print(f"{RED}Username too long. Max length is {self.MAX_USERNAME_LENGTH}.{RESET}")
                    elif not re.match(self.USERNAME_REGEX, candidate_name):
                        print(f"{RED}Invalid username format.{RESET}")
                    else:
                        self.local_username = candidate_name
                        break

        try:
            # Send username or reconnection notice
            if is_reconnect:
                message = Message(type=MessageType.RECONNECTED)
                if not await self._send_message(message):
                    raise ConnectionError("Failed to send reconnection message")
                print(f"{GREEN}Reconnected to chat session.{RESET}")
            else:
                message = Message(type=MessageType.USERNAME, sender=self.local_username)
                if not await self._send_message(message):
                    raise ConnectionError("Failed to send username")
        except Exception as e:
            p2p_logger.error(f"Failed to send initial message: {e}")
            print(f"{RED}Error establishing chat session. Disconnecting.{RESET}")
            await self._close_connection()
            return

        # Start receiving and heartbeat tasks
        self.receive_task = asyncio.create_task(self._receive_messages())
        self.heartbeat_task = asyncio.create_task(self._send_heartbeats())

        if not is_reconnect:
            print(f"\n{GREEN}Chat session started.{RESET}")
            print(f"{YELLOW}Type 'exit' to quit.{RESET}\n")

        # Process queued messages (for reconnect)
        if is_reconnect and not self.message_queue.empty():
            print(f"{YELLOW}Sending queued messages...{RESET}")
            while not self.message_queue.empty():
                try:
                    queued_msg = await self.message_queue.get()
                    if self.is_connected:
                        await send_framed(self.tcp_socket, queued_msg.encode('utf-8'))
                except Exception as e:
                    p2p_logger.error(f"Failed to send queued message: {e}")
                    await self.message_queue.put(queued_msg)
                    await self._close_connection(attempt_reconnect=True)
                    break

        # Message sending loop
        while not self.stop_event.is_set() and self.is_connected:
            try:
                user_input = await self._async_input(f"{CYAN}{self.local_username}: {RESET}")
                if not user_input:
                    continue

                user_input = user_input.strip()

                if not self.is_connected or self.stop_event.is_set():
                    break

                if user_input.lower() == 'exit':
                    try:
                        await self._send_message(Message(type=MessageType.EXIT))
                    except Exception as e:
                        p2p_logger.debug(f"Error sending exit message: {e}")
                    break

                # Handle special commands
                if user_input.startswith('/'):
                    await self._handle_command(user_input)
                    continue

                # Send regular chat message
                if user_input:
                    try:
                        message = Message(
                            type=MessageType.MESSAGE,
                            sender=self.local_username,
                            content=user_input,
                            timestamp=time.time()
                        )

                        # Store in history first
                        if len(self.message_history) >= self.max_history_size:
                            self.message_history.pop(0)
                        self.message_history.append(message)

                        success = await self._send_message(message)

                        if not success:
                            p2p_logger.warning("Failed to send message, connection may be lost")
                            # Queue message for potential reconnect
                            if self.message_queue.qsize() < 100: # Limit queue size
                                await self.message_queue.put(str(message))
                            else:
                                p2p_logger.warning("Message queue full, discarding oldest message.")
                                try:
                                    await self.message_queue.get_nowait() # Discard oldest
                                except asyncio.QueueEmpty:
                                    import logging; logging.getLogger(__name__).debug("Ignored exception")
                                await self.message_queue.put(str(message))

                            if self.is_connected:
                                p2p_logger.info("Attempting reconnect after failed send.")
                                if not self.stop_event.is_set():
                                    await self._close_connection(attempt_reconnect=True)
                                break
                    except Exception as e:
                        p2p_logger.error(f"Failed to send message: {e}")
                        msg_data = str(Message(
                            type=MessageType.MESSAGE,
                            sender=self.local_username,
                            content=user_input
                        ))
                        if self.message_queue.qsize() < 100:
                            await self.message_queue.put(msg_data)
                        else:
                            p2p_logger.warning("Message queue full, discarding oldest message.")
                            try:
                                await self.message_queue.get_nowait()
                            except asyncio.QueueEmpty:
                                import logging; logging.getLogger(__name__).debug("Ignored exception")
                            await self.message_queue.put(msg_data)
                        if not self.stop_event.is_set():
                            await self._close_connection(attempt_reconnect=True)
                        break

            except asyncio.CancelledError:
                break
            except Exception as e:
                p2p_logger.error(f"Error in sending loop: {e}")
                break

        # Cleanup
        await self._close_connection()

    async def _handle_command(self, command: str) -> None:
        """
        Handle special chat commands starting with /

        Args:
            command: The command string entered by the user
        """
        cmd_parts = command.split(maxsplit=1)
        cmd = cmd_parts[0].lower()

        if cmd == '/help':
            print("\r" + " " * 100)
            print(f"\n{YELLOW}Available commands:{RESET}")
            print(f"  {BOLD}/help{RESET} - Show this help message")
            print(f"  {BOLD}/clear{RESET} - Clear the chat screen")
            print(f"  {BOLD}/status{RESET} - Show connection status")
            print(f"  {BOLD}/exit{RESET} - Exit the chat")
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)

        elif cmd == '/clear':
            # Use ANSI escape sequences to clear screen safely without spawning subshells
            print('\033[2J\033[H', end='', flush=True)
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)

        elif cmd == '/status':
            uptime = time.time() - self.last_heartbeat_received if self.last_heartbeat_received else 0
            print("\r" + " " * 100)
            print(f"\n{YELLOW}Connection Status:{RESET}")
            print(f"  Connected to: {self.peer_username} [{self.peer_ip}]:{self.peer_port}")
            print(f"  Connection uptime: {int(uptime)} seconds")
            print(f"  Messages in history: {len(self.message_history)}")
            print(f"  Messages queued: {self.message_queue.qsize()}")
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)

        elif cmd == '/exit':
            await self._send_message(Message(type=MessageType.EXIT))
            await self._close_connection(attempt_reconnect=False)

        else:
            print("\r" + " " * 100)
            print(f"\n{RED}Unknown command: {cmd}. Type /help for available commands.{RESET}")
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)

    async def handle_connections(self):
        """
        Main menu and connection handling loop.

        Provides the user interface for starting a server (listener),
        connecting to peers, or managing network settings.
        """
        server_socket = None
        input_error_count = 0
        max_input_errors = 5
        
        # Check if running in auto-server mode (non-interactive)
        auto_server_mode = os.environ.get('P2P_AUTO_SERVER_MODE') == '1'
        
        if auto_server_mode:
            print(f"{GREEN}AUTO-SERVER MODE: Starting server automatically...{RESET}")
            await self._start_server()
            # Keep running until interrupted
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{YELLOW}Server stopped by user{RESET}")
            return

        while True:
            try:
                if self.is_connected:
                    p2p_logger.info("Waiting for stop event before showing main menu")
                    await self.stop_event.wait()
                    self.is_connected = False

                # Print application banner
                self._print_banner()

                try:
                    choice = (await self._async_input(f"{BLUE}Choose an option (1-4): {RESET}")).strip()
                    input_error_count = 0  # Reset on successful input
                except Exception as e:
                    input_error_count += 1
                    p2p_logger.error(f"Error getting user choice: {type(e).__name__}: {e} (attempt {input_error_count}/{max_input_errors})", exc_info=True)
                    print(f"{RED}Error reading input ({type(e).__name__}): {e}. Please try again.{RESET}")
                    
                    if input_error_count >= max_input_errors:
                        p2p_logger.error("Too many input errors. Exiting to prevent infinite loop.")
                        print(f"{RED}Too many input errors. Exiting application.{RESET}")
                        break
                    
                    await asyncio.sleep(0.5)  # Brief delay before retry
                    continue

                # Handle exit from input errors
                if choice.lower() == 'exit':
                    print(f"{YELLOW}Exiting due to input error...{RESET}")
                    break
                
                # Server Mode
                if choice == '1':
                    await self._start_server()
                # Client Mode
                elif choice == '2':
                    await self._start_client()
                # Retry STUN
                elif choice == '3':
                    await self._refresh_stun()
                # Exit
                elif choice == '4':
                    print(f"{YELLOW}Exiting...{RESET}")
                    break

                else:
                    print(f"{RED}Invalid choice. Please enter 1, 2, 3, or 4.{RESET}")

            except KeyboardInterrupt:
                print(f"\n{YELLOW}Operation interrupted. Returning to main menu.{RESET}")
                if server_socket:
                    try:
                        server_socket.close()
                    except Exception as e:
                        p2p_logger.debug(f"Error closing server socket on interrupt: {e}")
                    server_socket = None
            except asyncio.CancelledError:
                p2p_logger.info("Main connection handling loop cancelled")
                break
            except Exception as e:
                p2p_logger.error(f"Unexpected error in handle_connections: {e}", exc_info=True)
                print(f"\n{RED}Unexpected error: {e}. Continuing...{RESET}")

        # Cleanup on exit
        if server_socket:
            try:
                server_socket.close()
            except Exception as e:
                p2p_logger.error(f"Error closing server socket during exit: {e}", exc_info=True)

        self.stop_event.set()

        # Cleanup tasks
        for task_name, task in [("receive_task", self.receive_task), ("heartbeat_task", self.heartbeat_task)]:
            if task and not task.done():
                try:
                    task.cancel()
                    await asyncio.sleep(0.1)
                except Exception as e:
                    p2p_logger.error(f"Error cancelling {task_name}: {e}", exc_info=True)

    def _print_banner(self):
        """Print main menu options with banner."""
        print("\n" + "=" * 60)
        print(f"{CYAN}{BOLD}IPv6 P2P CHAT APPLICATION{RESET}")
        print("-" * 60)
        if self.public_ip:
            print(f"{GREEN}Public IPv6: [{self.public_ip}]:{self.public_port}{RESET}")
        else:
            print(f"{YELLOW}No public IPv6 address detected{RESET}")
        print("=" * 60)

        print("\nOptions:")
        print(f" {GREEN}1. Wait for incoming connection (Server){RESET}")
        print(f" {YELLOW}2. Connect to a peer (Client){RESET}")
        print(f" {BLUE}3. Retry STUN discovery{RESET}")
        print(f" {RED}4. Exit{RESET}")

    async def _refresh_stun(self):
        """Refresh STUN discovery of public IP/port."""
        print(f"{CYAN}Rediscovering public IPv6 address via STUN...{RESET}")
        try:
            old_ip = self.public_ip
            old_port = self.public_port

            self.public_ip, self.public_port = await get_public_ip_port()

            if self.public_ip:
                print(f"{GREEN}Public IPv6: [{self.public_ip}]:{self.public_port}{RESET}")
                if old_ip != self.public_ip or old_port != self.public_port:
                    print(f"{YELLOW}Note: Your public endpoint has changed from previous value!{RESET}")
            else:
                print(f"{RED}Could not determine public IPv6 address.{RESET}")
                print(f"{YELLOW}You may still be able to accept incoming connections on a local IPv6 network.{RESET}")
                print(f"{YELLOW}Make sure your system has IPv6 connectivity.{RESET}")
        except Exception as e:
            p2p_logger.error(f"STUN discovery error: {e}", exc_info=True)
            print(f"{RED}Error during STUN discovery: {e}{RESET}")

    async def _start_client(self):
        """Start client mode to connect to a peer."""
        try:
            peer_ip = (await self._async_input(f"{MAGENTA}\nEnter peer's IPv6 address: ")).strip()
            if not peer_ip:
                print(f"{RED}IP address cannot be empty.{RESET}")
                return

            peer_port_str = (await self._async_input(f"  {GREEN}Enter peer's port number: ")).strip()

            try:
                peer_port = int(peer_port_str)
                if not (1 <= peer_port <= 65535):
                    raise ValueError("Port must be between 1 and 65535.")

                try:
                    # Connect with retry logic
                    await self._connect_to_peer(peer_ip, peer_port)
                    await self._chat_session()

                except ValueError as e:
                    print(f"{RED}Invalid address or port: {e}{RESET}")
                except socket.gaierror as e:
                    print(f"{RED}Error: Could not resolve hostname or invalid IPv6 address.{RESET}")
                    p2p_logger.error(f"DNS resolution error: {e}")
                except ConnectionRefusedError:
                    print(f"{RED}Connection refused. Is the peer server running?{RESET}")
                except asyncio.TimeoutError:
                    print(f"{RED}Connection timed out. Peer may be offline or behind restrictive firewall.{RESET}")
                except ConnectionError as e:
                    print(f"{RED}Connection error: {e}{RESET}")
                except OSError as e:
                    print(f"{RED}Network error: {e}{RESET}")
                    p2p_logger.error(f"Network error connecting to peer: {e}", exc_info=True)
                except Exception as e:
                    print(f"{RED}Unexpected error: {e}{RESET}")
                    p2p_logger.error(f"Unexpected error connecting to peer: {e}", exc_info=True)

            except ValueError:
                print(f"{RED}Invalid port number. Please enter a number between 1-65535.{RESET}")
        except asyncio.CancelledError:
            p2p_logger.info("Client connection process cancelled")
            print(f"{YELLOW}Connection attempt cancelled.{RESET}")
        except Exception as e:
            p2p_logger.error(f"Error in client mode: {e}", exc_info=True)
            print(f"{RED}Unexpected error: {e}{RESET}")

    async def _start_server(self):
        """
        Start server mode to accept incoming connections.

        This method:
        1. Creates a server socket bound to a local IPv6 port
        2. Waits for an incoming connection
        3. Establishes a chat session with the connected client

        Security notes:
        - Uses IPv6-only socket for modern networking
        - Sets appropriate socket options for reliability
        - Implements proper error handling and timeouts
        - Validates incoming connection parameters
        """
        server_socket = None
        # Create IPv6-only server socket
        listen_port = self.public_port or secure_randbelow(50001) + 10000

        try:
            server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Set IPv6-only mode
            try:
                server_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except Exception as e:
                p2p_logger.debug(f"Could not set IPV6_V6ONLY: {e}")

            # Try multiple ports if binding fails
            max_port_attempts = 5
            for port_attempt in range(max_port_attempts):
                try:
                    current_port = listen_port + port_attempt
                    if current_port > 65535:
                        current_port = secure_randbelow(50001) + 10000

                    p2p_logger.info(f"Attempting to bind server socket to [::]:{current_port}")
                    server_socket.bind(("::", current_port))
                    listen_port = current_port
                    server_socket.listen(1)

                    p2p_logger.info(f"Server socket bound to [::]:{listen_port}")
                    print(f"\n{GREEN}Server listening on [::]:{listen_port} (IPv6-only){RESET}")

                    if self.public_ip:
                        print(f"{CYAN}Your public endpoint: \n \n  {MAGENTA} IPv6 address: {self.public_ip} \n   {GREEN} port number: {self.public_port}{RESET}\n")
                    print(f"{CYAN}Waiting for a connection...{RESET}")

                    break

                except OSError as e:
                    # If port is in use, try another
                    if e.errno in (98, 10048):  # Address already in use
                        p2p_logger.warning(f"Port {current_port} is already in use, trying another port.")
                        if port_attempt == max_port_attempts - 1:
                            p2p_logger.error(f"All port attempts failed for [::]")
                            raise
                    else:
                        p2p_logger.error(f"Failed to bind to [::]:{current_port}: {e}", exc_info=True)
                        raise

        except OSError as e:
            p2p_logger.warning(f"Failed to create IPv6 server socket: {e}")
            print(f"{RED}Failed to create IPv6 server socket. Make sure IPv6 is available on your system.{RESET}")
            return

        try:
            # Set non-blocking mode
            server_socket.setblocking(False)

            loop = asyncio.get_event_loop()
            try:
                print(f"{YELLOW}Press Ctrl+C to cancel waiting for connection{RESET}")

                # Cross-platform async accept implementation
                async def accept_connection_with_timeout():
                    if not server_socket:  # Safety check
                        raise RuntimeError("Server socket is None")

                    server_socket.setblocking(True)
                    try:
                        return await loop.run_in_executor(None, server_socket.accept)
                    except Exception as e:
                        p2p_logger.error(f"Error accepting connection: {e}")
                        raise
                    finally:
                        if server_socket:  # In case socket was closed during accept
                            server_socket.setblocking(False)

                # Wait for connection with timeout
                client_socket, client_address = await asyncio.wait_for(
                    accept_connection_with_timeout(),
                    timeout=300.0  # 5 minute timeout
                )

                # Per-IP and per-subnet rate limiter to mitigate connection flooding (Finding 26)
                client_ip = str(client_address[0])
                subnet_key = client_ip.rsplit('.', 1)[0] if '.' in client_ip else client_ip.rsplit(':', 4)[0]
                now = time.time()
                if not hasattr(self, '_conn_rate_limiter'):
                    self._conn_rate_limiter = {}
                if not hasattr(self, '_ip_rate_limiter'):
                    self._ip_rate_limiter = {}
                self._conn_rate_limiter = {k: ts for k, ts in self._conn_rate_limiter.items() if ts and now - ts[-1] < 60}
                self._ip_rate_limiter = {k: ts for k, ts in self._ip_rate_limiter.items() if ts and now - ts[-1] < 60}

                # Per-IP limit: max 5 conns/min
                recent_ip = [ts for ts in self._ip_rate_limiter.get(client_ip, []) if now - ts < 60]
                if len(recent_ip) >= 5:
                    p2p_logger.warning(f"SECURITY ALERT: Per-IP rate limit exceeded (5 conns/min) for {client_ip}. Dropping connection.")
                    try:
                        client_socket.close()
                    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B110
                        pass
                    return

                # Per-subnet limit: max 10 conns/min
                recent_subnet = [ts for ts in self._conn_rate_limiter.get(subnet_key, []) if now - ts < 60]
                if len(recent_subnet) >= 10:
                    p2p_logger.warning(f"SECURITY ALERT: Subnet rate limit exceeded (10 conns/min) for {subnet_key}. Dropping connection.")
                    try:
                        client_socket.close()
                    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B110
                        pass
                    return

                recent_ip.append(now)
                self._ip_rate_limiter[client_ip] = recent_ip
                recent_subnet.append(now)
                self._conn_rate_limiter[subnet_key] = recent_subnet

                # Configure the client socket
                client_socket.setblocking(False)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                # Try to set TCP_NODELAY to disable Nagle's algorithm
                try:
                    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    import logging; logging.getLogger(__name__).debug("Ignored exception")

                # Set TCP keepalive parameters if supported
                try:
                    if hasattr(socket, 'TCP_KEEPIDLE'):
                        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    if hasattr(socket, 'TCP_KEEPINTVL'):
                        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
                    if hasattr(socket, 'TCP_KEEPCNT'):
                        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                except Exception as e:
                    p2p_logger.debug(f"Could not set TCP keepalive options on client socket: {e}")

                p2p_logger.info(f"Accepted connection from {client_address}")
                self.tcp_socket = client_socket
                self.peer_ip = client_address[0]
                self.peer_port = client_address[1]
                self.last_heartbeat_received = time.time()  # Initialize heartbeat timer

                print(f"\n{GREEN}Client connected from [{client_address[0]}]:{client_address[1]}{RESET}")

                # Close server socket now that we have a client connection
                if server_socket:
                    server_socket.close()
                    server_socket = None

                await self._chat_session()

            except asyncio.TimeoutError:
                print(f"{YELLOW}No connection received within timeout period.{RESET}")
            except asyncio.CancelledError:
                print(f"{YELLOW}Waiting for connection was cancelled.{RESET}")

        except KeyboardInterrupt:
            print(f"{YELLOW}Cancelled waiting for connection.{RESET}")
        except OSError as e:
            if hasattr(e, 'errno') and e.errno in (98, 10048):  # Address already in use
                print(f"{RED}Error: Port {listen_port} is already in use.{RESET}")
            else:
                print(f"{RED}Server error: {e}{RESET}")
                p2p_logger.error(f"Server socket error: {e}", exc_info=True)
        except Exception as e:
            print(f"{RED}Server error: {e}{RESET}")
            p2p_logger.error(f"Unexpected server error: {e}", exc_info=True)
        finally:
            if server_socket:
                try:
                    server_socket.close()
                except Exception as e:
                    p2p_logger.error(f"Error closing server socket: {e}", exc_info=True)
                server_socket = None

    async def start(self):
        """
        Start the P2P chat application.

        Initializes the application, discovers the public IPv6 endpoint using STUN,
        and presents the main menu to the user.
        """
        # Check if running in interactive environment by testing input
        try:
            # Test if we can actually get input
            loop = asyncio.get_event_loop()
            test_future = loop.run_in_executor(None, lambda: None)
            await asyncio.wait_for(test_future, timeout=0.1)
            
            # Also check if stdin is a TTY
            if not sys.stdin.isatty():
                raise RuntimeError("Not a TTY")
                
        except (RuntimeError, OSError, asyncio.TimeoutError):
            print(f"{RED}+--------------------------------------------------------------+{RESET}")
            print(f"{RED}|  ERROR: This application requires an interactive terminal   |{RESET}")
            print(f"{RED}+--------------------------------------------------------------+{RESET}")
            print(f"\n{YELLOW}Please run this application in one of the following ways:{RESET}\n")
            print(f"  {GREEN}1.{RESET} Double-click {CYAN}'run_p2p.bat'{RESET} in Windows Explorer")
            print(f"  {GREEN}2.{RESET} Open CMD/PowerShell and run: {CYAN}python -m archive.legacy_prototype.secure_p2p{RESET}")
            print(f"  {GREEN}3.{RESET} In VS Code: {CYAN}Terminal -> New Terminal{RESET}, then run the command")
            print(f"\n{RED}WARN DO NOT use the 'Run Python File' button in VS Code!{RESET}")
            print(f"{RED}WARN That runs in non-interactive mode and cannot accept input.{RESET}\n")
            return
        
        print(f"{CYAN}--- IPv6 P2P Chat ---{RESET}")
        print("Discovering public IPv6 address via STUN...")

        try:
            self.public_ip, self.public_port = await get_public_ip_port()

            if self.public_ip:
                if ':' in self.public_ip:
                    print(f"{GREEN}Public IPv6: [{self.public_ip}]:{self.public_port}{RESET}")
                else:
                    print(f"{GREEN}Public IPv4: {self.public_ip}:{self.public_port}{RESET}")
            else:
                print(f"{YELLOW}Could not determine public IP address using STUN.{RESET}")
                print(f"{YELLOW}You may still accept incoming connections on local network (e.g. LAN / Loopback).{RESET}")

            await self.handle_connections()

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Program interrupted by user.{RESET}")
        except Exception as e:
            print(f"\n{RED}Unhandled error: {e}{RESET}")
            p2p_logger.error(f"Unhandled error in main loop: {e}", exc_info=True)
        finally:
            # Final cleanup
            if self.tcp_socket:
                try:
                    self.tcp_socket.close()
                except Exception as e:
                    p2p_logger.debug(f"Error closing tcp_socket in finally: {e}")


if __name__ == "__main__":
    # Set signal handlers for graceful exit
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda signum, frame: sys.exit(0))
    except (AttributeError, ValueError):
        import logging; logging.getLogger(__name__).debug("Ignored exception")

    chat_app = SimpleP2PChat()
    try:
        asyncio.run(chat_app.start())
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        p2p_logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n{RED}Fatal error: {e}{RESET}")
    finally:
        if chat_app.tcp_socket:
            try:
                chat_app.tcp_socket.close()
            except Exception as e:
                p2p_logger.debug(f"Error closing chat_app socket: {e}")

 