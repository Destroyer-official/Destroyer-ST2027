#!/usr/bin/env python3
"""
Secure Message Serializer - MAC-First Verification

This module implements secure message serialization with MAC verification
BEFORE payload access. Follows fail-closed security model.

Binary Format (Requirements 5.1):
- version: 1 byte
- type: 1 byte  
- flags: 2 bytes
- length: 4 bytes
- sequence: 8 bytes
- timestamp: 8 bytes
- sender_id: 32 bytes
- payload: variable
- mac: 32 bytes (HMAC-SHA384 truncated to 256 bits)

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6
"""

import struct
import time
import hmac
import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any
from enum import IntEnum

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_AESGCM = True
except ImportError:
    HAS_AESGCM = False

# Configure logger
logger = logging.getLogger('secure_serializer')
logger.setLevel(logging.INFO)


class IntegrityViolation(Exception):
    """
    Raised when MAC verification fails.
    System MUST reject message and log failure - NO FALLBACKS.
    """
    def __init__(self, message: str = "MAC verification failed"):
        super().__init__(message)
        self.timestamp = time.time()
        logger.critical(f"INTEGRITY VIOLATION: {message}")


class ParseError(Exception):
    """
    Raised when message parsing fails.
    Returns generic error without revealing parse position (Requirement 5.6).
    """
    def __init__(self, message: str = "Message parsing failed"):
        # Generic message - don't reveal parse position
        super().__init__("Message parsing failed")
        self.timestamp = time.time()
        logger.warning(f"PARSE ERROR: {message}")


class MessageType(IntEnum):
    """Message types for the secure protocol"""
    HANDSHAKE = 0x01
    DATA = 0x02
    ACK = 0x03
    KEY_ROTATION = 0x04
    HEARTBEAT = 0x05
    FILE_TRANSFER = 0x06
    CLOSE = 0x07


class MessageFlags(IntEnum):
    """Message flags"""
    NONE = 0x0000
    ENCRYPTED = 0x0001
    COMPRESSED = 0x0002
    URGENT = 0x0004
    REQUIRES_ACK = 0x0008
    FRAGMENTED = 0x0010


@dataclass
class SecureMessage:
    """
    Secure message structure with all required fields.
    
    Binary format (88 bytes header + variable payload + 32 bytes MAC):
    - version: 1 byte (protocol version)
    - type: 1 byte (message type)
    - flags: 2 bytes (message flags)
    - length: 4 bytes (total message length including header and MAC)
    - sequence: 8 bytes (sequence number for replay protection)
    - timestamp: 8 bytes (Unix timestamp in microseconds)
    - sender_id: 32 bytes (SHA3-256 hash of sender's public key)
    - payload: variable length
    - mac: 32 bytes (HMAC-SHA384 truncated to 256 bits)
    """
    version: int
    msg_type: MessageType
    flags: int
    sequence: int
    timestamp: int
    sender_id: bytes
    payload: bytes
    mac: bytes = b''
    
    # Header size: 1 + 1 + 2 + 4 + 8 + 8 + 32 = 56 bytes
    HEADER_SIZE = 56
    MAC_SIZE = 32
    
    def __post_init__(self):
        """Validate message fields"""
        if len(self.sender_id) != 32:
            raise ValueError("sender_id must be 32 bytes")
        if self.version < 1 or self.version > 255:
            raise ValueError("version must be 1-255")


class SecureMessageSerializer:
    """
    Secure Message Serializer with MAC-First Verification
    
    SECURITY MODEL: FAIL-CLOSED
    - MAC is verified BEFORE payload is accessed
    - Any integrity failure raises IntegrityViolation
    - Parse errors return generic message (no position leak)
    
    Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6
    """
    
    # Protocol version
    PROTOCOL_VERSION = 1
    
    # Header format: version(1) + type(1) + flags(2) + length(4) + sequence(8) + timestamp(8) + sender_id(32)
    HEADER_FORMAT = '>BBHIQQ32s'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 56 bytes
    MAC_SIZE = 32  # HMAC-SHA384 truncated to 256 bits
    MAX_SERIALIZED_SIZE = 128 * 1024  # 128 KB legacy generic pre-MAC ceiling (compat; see below)
    # Unified caps (see utils/message_caps.py, layered: frame 4MB > post-auth
    # 512KB >= pre-auth 64KB == chat 64KB strictest).
    MAX_MSG_PAYLOAD = 65536  # 64KB strictest chat MSG payload
    MAX_FILE_PAYLOAD = 512 * 1024  # 512KB FILE payload (explicit file flag only)
    MAX_SERIALIZED_MSG = MAX_MSG_PAYLOAD + HEADER_SIZE + MAC_SIZE
    MAX_SERIALIZED_FILE = MAX_FILE_PAYLOAD + HEADER_SIZE + MAC_SIZE
    
    def __init__(self, mac_key: bytes):
        """
        Initialize serializer with MAC key.
        
        Args:
            mac_key: 32-byte key for HMAC-SHA384
            
        Raises:
            ValueError: If mac_key is not 32 bytes
        """
        if len(mac_key) != 32:
            raise ValueError("MAC key must be 32 bytes")
        self._mac_key = mac_key
        self._last_sequences: Dict[bytes, int] = {}
        logger.info("SecureMessageSerializer initialized with MAC-first verification")
    
    def _compute_mac(self, data: bytes) -> bytes:
        """
        Compute HMAC-SHA384 truncated to 256 bits (32 bytes).
        
        Requirement 5.2: Use HMAC-SHA384 truncated to 256 bits
        
        Args:
            data: Data to compute MAC over
            
        Returns:
            32-byte MAC
        """
        full_mac = hmac.new(self._mac_key, data, hashlib.sha384).digest()
        return full_mac[:32]  # Truncate to 256 bits
    
    def _verify_mac(self, data: bytes, expected_mac: bytes) -> bool:
        """
        Verify MAC using constant-time comparison.
        
        Args:
            data: Data to verify
            expected_mac: Expected MAC value
            
        Returns:
            True if MAC is valid
        """
        computed_mac = self._compute_mac(data)
        return hmac.compare_digest(computed_mac, expected_mac)
    
    def serialize(self, message: SecureMessage, aead_key: Optional[bytes] = None) -> bytes:
        """
        Serialize a message with MAC.
        
        Requirement 5.1: Binary format with exact structure
        If aead_key is provided, routes through serialize_aead_envelope to hide metadata.
        
        Args:
            message: SecureMessage to serialize
            aead_key: Optional 32-byte key for AES-256-GCM envelope encryption
            
        Returns:
            Serialized message bytes with MAC appended
        """
        if aead_key is not None:
            return self.serialize_aead_envelope(
                msg_type=message.msg_type,
                payload=message.payload,
                sender_id=message.sender_id,
                sequence=message.sequence,
                aead_key=aead_key,
                flags=message.flags
            )
        import os as _os
        if _os.environ.get("SECURE_P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on") or _os.environ.get("P2P_ENV", "").strip().lower() == "production":
            raise ValueError("AEAD envelope required in production: sender_id/sequence/timestamp must be encrypted (CNSA 2.0 metadata protection)")
        
        # Unified caps: 64KB strictest for chat MSG, 512KB for FILE chunks
        # with explicit FILE type flag (layered under 4MB frame ceiling).
        try:
            from utils.message_caps import validate_payload_size as _validate_caps
            _validate_caps(len(message.payload), msg_type=message.msg_type)
        except ImportError:
            # Fallback when caps module unavailable (same policy, local check)
            _is_file = getattr(message.msg_type, "name", str(message.msg_type)).upper().find("FILE") >= 0
            _limit = self.MAX_FILE_PAYLOAD if _is_file else self.MAX_MSG_PAYLOAD
            if len(message.payload) > _limit:
                raise ValueError(
                    f"Message payload {len(message.payload)} exceeds "
                    f"{'FILE' if _is_file else 'chat'} limit {_limit}"
                )
        # Calculate total length (header + payload + MAC)
        total_length = self.HEADER_SIZE + len(message.payload) + self.MAC_SIZE
        _is_file_msg = getattr(message.msg_type, "name", str(message.msg_type)).upper().find("FILE") >= 0
        _ser_limit = self.MAX_SERIALIZED_FILE if _is_file_msg else self.MAX_SERIALIZED_SIZE
        # Non-FILE paths additionally enforce the strict 64KB serialized ceiling
        # (HEADER+64KB+MAC) on top of the legacy 128KB generic ceiling.
        if not _is_file_msg and total_length > self.MAX_SERIALIZED_MSG:
            raise ValueError(
                f"Chat payload exceeds unified 64KB limit "
                f"({len(message.payload)} > {self.MAX_MSG_PAYLOAD})"
            )
        if total_length > _ser_limit:
            raise ValueError(f"Message payload exceeds maximum size limit of {_ser_limit} bytes")
        
        # Pack header
        header = struct.pack(
            self.HEADER_FORMAT,
            message.version,
            message.msg_type,
            message.flags,
            total_length,
            message.sequence,
            message.timestamp,
            message.sender_id
        )
        
        # Combine header and payload
        data = header + message.payload
        
        # Compute MAC over header + payload
        mac = self._compute_mac(data)
        
        # Return complete message
        serialized = data + mac
        
        logger.debug(f"Serialized message: {len(serialized)} bytes, seq={message.sequence}")
        return serialized
    
    def deserialize(
        self,
        data: bytes,
        enforce_sequence: bool = True,
        max_clock_skew_seconds: Optional[float] = None,
        aead_key: Optional[bytes] = None,
        is_file: bool = False
    ) -> SecureMessage:
        """
        Deserialize a message with MAC-first verification.

        CRITICAL: MAC is verified BEFORE payload is accessed.
        If aead_key is provided, routes through deserialize_aead_envelope.

        Requirement 5.3: Verify MAC before reading payload
        Requirement 5.4: Reject message and log failure on MAC failure
        Requirement 5.6: Return generic error without revealing parse position

        Args:
            data: Serialized message bytes
            enforce_sequence: Whether to reject non-monotonic sequence numbers
            max_clock_skew_seconds: Maximum allowed clock skew in seconds (None to disable)
            aead_key: Optional 32-byte key for AES-256-GCM envelope decryption
            is_file: Explicit FILE-chunk flag allowing up to 512KB pre-MAC.
                Default False keeps legacy 128KB generic pre-MAC ceiling
                (lab permissive, existing tests unchanged).

        Returns:
            SecureMessage if valid

        Raises:
            IntegrityViolation: If MAC verification fails (before payload access),
                replay detected, or unified post-auth payload cap violated
                (chat >64KB, FILE >512KB)
            ParseError: If message format is invalid (generic error)
        """
        if aead_key is not None:
            return self.deserialize_aead_envelope(
                data=data,
                aead_key=aead_key,
                enforce_sequence=enforce_sequence,
                max_clock_skew_seconds=max_clock_skew_seconds,
                is_file=is_file
            )
        # Pre-MAC size cap to prevent resource exhaustion / DoS.
        # Layered: generic callers keep legacy 128KB ceiling; explicit FILE
        # callers allow up to 512KB+overhead (still far below 4MB frame).
        _pre_cap = self.MAX_SERIALIZED_FILE if is_file else self.MAX_SERIALIZED_SIZE
        if len(data) > _pre_cap:
            raise ParseError(f"Message exceeds maximum size limit of {_pre_cap} bytes")

        # Minimum message size check
        min_size = self.HEADER_SIZE + self.MAC_SIZE
        if len(data) < min_size:
            raise ParseError("Message too short")
        
        # Extract MAC (last 32 bytes)
        message_data = data[:-self.MAC_SIZE]
        received_mac = data[-self.MAC_SIZE:]
        
        # CRITICAL: Verify MAC BEFORE accessing any payload data
        # Requirement 5.3: Verify MAC before reading payload
        if not self._verify_mac(message_data, received_mac):
            # Requirement 5.4: Reject message and log failure
            raise IntegrityViolation("MAC verification failed - message rejected")
        
        # MAC verified - now safe to parse header
        try:
            header_data = message_data[:self.HEADER_SIZE]
            (
                version,
                msg_type,
                flags,
                total_length,
                sequence,
                timestamp,
                sender_id
            ) = struct.unpack(self.HEADER_FORMAT, header_data)
            
            # Validate protocol version
            if version != self.PROTOCOL_VERSION:
                raise ParseError("Unsupported protocol version")

            # Validate length field
            if total_length != len(data):
                raise ParseError("Length mismatch")
            
            # Temporal clock-skew validation (Item 32 / Finding 5.1)
            if max_clock_skew_seconds is not None:
                current_time_us = int(time.time() * 1000000)
                skew_us = abs(current_time_us - timestamp)
                if skew_us > int(max_clock_skew_seconds * 1000000):
                    raise IntegrityViolation(
                        f"Message timestamp outside permitted clock skew window: skew={skew_us / 1000000:.2f}s > {max_clock_skew_seconds}s"
                    )

            # Monotonic sequence validation (Item 32 / Finding 5.1)
            # 2028 hardening: evicting oldest entry re-admits replay for that
            # sender. For 1:1 military use 4096 peers is ample; fail-closed
            # when full for unknown senders (peer must re-handshake) instead
            # of silently forgetting replay state.
            if enforce_sequence:
                last_seq = self._last_sequences.get(sender_id)
                if last_seq is not None and sequence <= last_seq:
                    raise IntegrityViolation(
                        f"Replay detected: non-monotonic sequence {sequence} <= last seen {last_seq}"
                    )
                if last_seq is None and len(self._last_sequences) >= 4096:
                    raise IntegrityViolation(
                        "Replay table full - unknown sender must re-handshake (DoS/replay protection)"
                    )
                if len(self._last_sequences) >= 4096:
                    evicted = next(iter(self._last_sequences))
                    self._last_sequences.pop(evicted)
                    logger.warning("Replay table full - evicted oldest sender state (re-handshake required for evicted peer)")
                self._last_sequences[sender_id] = sequence

            # Extract payload (after header, before MAC)
            payload = message_data[self.HEADER_SIZE:]

            # Unified post-auth payload caps (fail-closed, after MAC verify):
            # chat MSG/DATA/etc <= 64KB strictest; FILE_TRANSFER <= 512KB.
            try:
                _parsed_type = MessageType(msg_type)
            except Exception:
                _parsed_type = None
            _is_file_type = (_parsed_type == MessageType.FILE_TRANSFER) or bool(is_file)
            if _is_file_type:
                if len(payload) > self.MAX_FILE_PAYLOAD:
                    raise IntegrityViolation(
                        f"FILE payload {len(payload)} exceeds 512KB unified cap"
                    )
            else:
                if len(payload) > self.MAX_MSG_PAYLOAD:
                    raise IntegrityViolation(
                        f"Chat payload {len(payload)} exceeds unified 64KB cap "
                        "(larger only for FILE chunks with explicit file flag)"
                    )

            # Create message object
            message = SecureMessage(
                version=version,
                msg_type=MessageType(msg_type),
                flags=flags,
                sequence=sequence,
                timestamp=timestamp,
                sender_id=sender_id,
                payload=payload,
                mac=received_mac
            )
            
            logger.debug(f"Deserialized message: seq={sequence}, type={msg_type}")
            return message
            
        except IntegrityViolation:
            raise
        except (struct.error, ValueError) as e:
            # Requirement 5.6: Generic error without revealing parse position
            raise ParseError("Message parsing failed")

    def serialize_aead_envelope(
        self,
        msg_type: MessageType,
        payload: bytes,
        sender_id: bytes,
        sequence: int,
        aead_key: bytes,
        flags: int = MessageFlags.ENCRYPTED
    ) -> bytes:
        """
        Serialize message enclosing all sensitive metadata (sender_id, sequence, timestamp)
        inside an authenticated AEAD payload (Item 36 / Finding 5.5).
        Outer header carries dummy/ephemeral values to prevent traffic analysis.
        """
        if not HAS_AESGCM:
            raise RuntimeError("cryptography AESGCM required for AEAD envelope")
        if len(aead_key) != 32:
            raise ValueError("AEAD key must be 32 bytes (AES-256-GCM)")

        # Unified caps on inner plaintext payload (64KB chat, 512KB FILE flag)
        try:
            from utils.message_caps import validate_payload_size as _validate_caps2
            _validate_caps2(len(payload), msg_type=msg_type)
        except ImportError:
            _is_f = getattr(msg_type, "name", str(msg_type)).upper().find("FILE") >= 0
            _lim = self.MAX_FILE_PAYLOAD if _is_f else self.MAX_MSG_PAYLOAD
            if len(payload) > _lim:
                raise ValueError(f"AEAD inner payload {len(payload)} exceeds limit {_lim}")

        timestamp = int(time.time() * 1000000)
        # Inner serialized structure: sequence(8) + timestamp(8) + sender_id(32) + type(1) + payload
        inner_plaintext = struct.pack('>QQ32sB', sequence, timestamp, sender_id, int(msg_type)) + payload
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(aead_key)
        aad = struct.pack('>BH', self.PROTOCOL_VERSION, flags | MessageFlags.ENCRYPTED)
        inner_ciphertext = aesgcm.encrypt(nonce, inner_plaintext, aad)
        envelope_payload = nonce + inner_ciphertext

        outer_msg = SecureMessage(
            version=self.PROTOCOL_VERSION,
            msg_type=MessageType.DATA,
            flags=flags | MessageFlags.ENCRYPTED,
            sequence=0,
            timestamp=0,
            sender_id=b'\x00' * 32,
            payload=envelope_payload
        )
        return self.serialize(outer_msg)

    def deserialize_aead_envelope(
        self,
        data: bytes,
        aead_key: bytes,
        enforce_sequence: bool = True,
        max_clock_skew_seconds: Optional[float] = None,
        is_file: bool = False
    ) -> SecureMessage:
        """
        Deserialize message with outer MAC verification, followed by AEAD decryption
        of enclosed metadata (Item 36 / Finding 5.5).
        """
        if not HAS_AESGCM:
            raise RuntimeError("cryptography AESGCM required for AEAD envelope")
        if len(aead_key) != 32:
            raise ValueError("AEAD key must be 32 bytes (AES-256-GCM)")

        # Verify outer MAC first (fail closed)
        outer_msg = self.deserialize(data, enforce_sequence=False, max_clock_skew_seconds=None, is_file=is_file)
        if len(outer_msg.payload) < 12 + 16:
            raise IntegrityViolation("Encrypted payload too short for AEAD envelope")

        nonce = outer_msg.payload[:12]
        ciphertext = outer_msg.payload[12:]
        aad = struct.pack('>BH', outer_msg.version, outer_msg.flags)

        aesgcm = AESGCM(aead_key)
        try:
            inner_plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise IntegrityViolation(f"AEAD envelope decryption failed: {e}")

        if len(inner_plaintext) < 8 + 8 + 32 + 1:
            raise ParseError("Decrypted metadata payload truncated")

        try:
            sequence, timestamp, sender_id, inner_type = struct.unpack('>QQ32sB', inner_plaintext[:49])
            actual_payload = inner_plaintext[49:]
            inner_msg_type = MessageType(inner_type)
        except (struct.error, ValueError) as e:
            raise ParseError("Decrypted metadata payload malformed") from e

        # Validate temporal clock skew
        if max_clock_skew_seconds is not None:
            current_time_us = int(time.time() * 1000000)
            skew_us = abs(current_time_us - timestamp)
            if skew_us > int(max_clock_skew_seconds * 1000000):
                raise IntegrityViolation(f"Timestamp outside acceptable window in AEAD envelope: {skew_us / 1000000:.2f}s")

        # Validate sequence monotonicity
        if enforce_sequence:
            last_seq = self._last_sequences.get(sender_id)
            if last_seq is not None and sequence <= last_seq:
                raise IntegrityViolation(f"Replay detected: non-monotonic sequence {sequence} <= last seen {last_seq}")
            if len(self._last_sequences) > 1024:
                self._last_sequences.pop(next(iter(self._last_sequences)))
            self._last_sequences[sender_id] = sequence

        # Unified caps on decrypted inner payload (fail-closed)
        _inner_is_file = (inner_msg_type == MessageType.FILE_TRANSFER) or bool(is_file)
        if _inner_is_file:
            if len(actual_payload) > self.MAX_FILE_PAYLOAD:
                raise IntegrityViolation(
                    f"AEAD FILE payload {len(actual_payload)} exceeds 512KB cap"
                )
        else:
            if len(actual_payload) > self.MAX_MSG_PAYLOAD:
                raise IntegrityViolation(
                    f"AEAD chat payload {len(actual_payload)} exceeds unified 64KB cap"
                )

        return SecureMessage(
            version=outer_msg.version,
            msg_type=inner_msg_type,
            flags=outer_msg.flags,
            sequence=sequence,
            timestamp=timestamp,
            sender_id=sender_id,
            payload=actual_payload,
            mac=outer_msg.mac
        )

    def pretty_print(self, message: SecureMessage) -> str:
        """
        Format message for debugging with sensitive fields redacted (Item 42 / Finding 5.1).
        
        Requirement 5.5: Implement pretty_print() for message debugging
        
        Args:
            message: SecureMessage to format
            
        Returns:
            Human-readable string representation
        """
        lines = [
            "=" * 60,
            "SECURE MESSAGE",
            "=" * 60,
            f"Version:   {message.version}",
            f"Type:      {message.msg_type.name} ({message.msg_type})",
            f"Flags:     0x{message.flags:04X}",
            f"Sequence:  {message.sequence}",
            f"Timestamp: {message.timestamp} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(message.timestamp // 1000000)) if message.timestamp else 'N/A'})",
            f"Sender ID: {message.sender_id.hex()[:8]}...[REDACTED]",
            f"Payload:   {len(message.payload)} bytes [REDACTED]",
            f"MAC:       {message.mac.hex()[:8]}...[REDACTED]" if message.mac else "MAC: (not computed)",
            "=" * 60,
        ]
        return "\n".join(lines)
    
    def create_message(
        self,
        msg_type: MessageType,
        payload: bytes,
        sender_id: bytes,
        sequence: int,
        flags: int = MessageFlags.NONE
    ) -> SecureMessage:
        """
        Create a new secure message.
        
        Args:
            msg_type: Message type
            payload: Message payload
            sender_id: 32-byte sender identifier
            sequence: Sequence number
            flags: Message flags
            
        Returns:
            SecureMessage ready for serialization
        """
        return SecureMessage(
            version=self.PROTOCOL_VERSION,
            msg_type=msg_type,
            flags=flags,
            sequence=sequence,
            timestamp=int(time.time() * 1000000),  # Microseconds
            sender_id=sender_id,
            payload=payload
        )


def create_test_serializer() -> SecureMessageSerializer:
    """Create a serializer with a test key for development/testing."""
    import secrets
    test_key = secrets.token_bytes(32)
    return SecureMessageSerializer(test_key)


if __name__ == "__main__":
    # Test the serializer
    import secrets
    
    print("=== Secure Message Serializer Test ===\n")
    
    # Create serializer with random key
    mac_key = secrets.token_bytes(32)
    serializer = SecureMessageSerializer(mac_key)
    
    # Create test message
    sender_id = secrets.token_bytes(32)
    message = serializer.create_message(
        msg_type=MessageType.DATA,
        payload=b"Hello, secure world!",
        sender_id=sender_id,
        sequence=1,
        flags=MessageFlags.ENCRYPTED
    )
    
    # Serialize
    serialized = serializer.serialize(message)
    print(f"Serialized: {len(serialized)} bytes")
    print(f"Hex: {serialized[:32].hex()}...")
    
    # Deserialize
    deserialized = serializer.deserialize(serialized)
    print(f"\nDeserialized successfully!")
    print(serializer.pretty_print(deserialized))
    
    # Test MAC verification failure
    print("\n=== Testing MAC Verification ===")
    corrupted = bytearray(serialized)
    corrupted[60] ^= 0xFF  # Corrupt payload
    try:
        serializer.deserialize(bytes(corrupted))
        print("ERROR: Should have raised IntegrityViolation!")
    except IntegrityViolation as e:
        print(f"PASS: Correctly rejected corrupted message: {e}")
    
    # Test round-trip
    print("\n=== Testing Round-Trip ===")
    serialized2 = serializer.serialize(deserialized)
    if serialized == serialized2:
        print("PASS: Round-trip successful: serialize(deserialize(serialize(m))) == serialize(m)")
    else:
        print("FAIL: Round-trip failed!")
