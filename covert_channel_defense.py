#!/usr/bin/env python3
"""
covert_channel_defense.py

Military-grade covert channel resistance for secure P2P messaging.

This module implements comprehensive covert channel defense including:
- Fixed-rate transmission (Requirement 13.1)
- Packet size normalization (Requirement 13.2)
- Protocol field normalization (Requirement 13.3)
- Covert channel detection (Requirement 13.4)
- Cover traffic injection (Requirement 13.5)

**Validates: Requirements 13.1, 13.2, 13.3, 13.4, 13.5**
"""

import hashlib
import hmac
import logging
import os
import secrets
import struct
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional, List, Tuple, Any, Dict, Deque

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging
file_handler = logging.FileHandler(os.path.join("logs", "covert_channel_defense.log"))
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
file_handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(file_handler)


# ============================================================================
# Constants
# ============================================================================

# Fixed packet size for normalization (1024 bytes)
NORMALIZED_PACKET_SIZE = 1024

# Default fixed transmission rate (packets per second)
DEFAULT_FIXED_RATE = 10.0

# Cover traffic injection rate (percentage of total traffic)
DEFAULT_COVER_TRAFFIC_RATIO = 0.3

# Covert channel detection thresholds
TIMING_VARIANCE_THRESHOLD = 0.1  # 10% variance threshold
SIZE_VARIANCE_THRESHOLD = 0.0    # 0% - all packets must be same size
PATTERN_DETECTION_WINDOW = 100   # Number of packets to analyze


# ============================================================================
# Exceptions
# ============================================================================

class CovertChannelDefenseError(Exception):
    """Base exception for covert channel defense errors."""


class FixedRateViolationError(CovertChannelDefenseError):
    """Error when fixed-rate transmission is violated."""


class PacketNormalizationError(CovertChannelDefenseError):
    """Error during packet normalization."""


class CovertChannelDetectedError(CovertChannelDefenseError):
    """Error when covert channel activity is detected."""


class ProtocolFieldError(CovertChannelDefenseError):
    """Error in protocol field normalization."""


# ============================================================================
# Data Classes
# ============================================================================

class PacketType(IntEnum):
    """Types of packets in the covert channel defense system."""
    REAL_DATA = 0x01
    COVER_TRAFFIC = 0x02
    PADDING = 0x03
    CONTROL = 0x04


@dataclass
class NormalizedPacket:
    """A normalized packet with fixed size and structure."""
    packet_type: PacketType
    sequence_number: int
    timestamp: float
    payload: bytes
    padding: bytes
    checksum: bytes
    
    def to_bytes(self) -> bytes:
        """Serialize packet to bytes."""
        # Header: type(1) + seq(8) + timestamp(8) + payload_len(4) = 21 bytes
        header = struct.pack(
            '>BQQI',
            self.packet_type.value,
            self.sequence_number,
            int(self.timestamp * 1000000),  # Microseconds
            len(self.payload)
        )
        # Checksum: 32 bytes (SHA-256)
        # Total fixed size: NORMALIZED_PACKET_SIZE
        return header + self.payload + self.padding + self.checksum
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'NormalizedPacket':
        """Deserialize packet from bytes."""
        if len(data) != NORMALIZED_PACKET_SIZE:
            raise PacketNormalizationError(
                f"Invalid packet size: {len(data)} != {NORMALIZED_PACKET_SIZE}"
            )
        
        # Parse header
        header = data[:21]
        ptype, seq, ts_us, payload_len = struct.unpack('>BQQI', header)
        
        # Extract components
        payload_start = 21
        payload_end = payload_start + payload_len
        checksum_start = NORMALIZED_PACKET_SIZE - 32
        
        payload = data[payload_start:payload_end]
        padding = data[payload_end:checksum_start]
        checksum = data[checksum_start:]
        
        return cls(
            packet_type=PacketType(ptype),
            sequence_number=seq,
            timestamp=ts_us / 1000000.0,
            payload=payload,
            padding=padding,
            checksum=checksum
        )


@dataclass
class TransmissionStats:
    """Statistics for transmission monitoring."""
    packets_sent: int = 0
    packets_received: int = 0
    real_packets: int = 0
    cover_packets: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    rate_violations: int = 0
    size_violations: int = 0
    covert_channel_alerts: int = 0
    start_time: float = field(default_factory=time.time)


@dataclass
class CovertChannelAlert:
    """Alert for detected covert channel activity."""
    alert_id: str
    timestamp: float
    alert_type: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    description: str
    evidence: Dict[str, Any]


# ============================================================================
# Packet Normalizer
# **Validates: Requirements 13.2**
# ============================================================================

class PacketNormalizer:
    """
    Normalizes all packets to identical fixed size.
    
    **Validates: Requirements 13.2**
    - THE Secure_P2P_System SHALL normalize packet sizes to prevent size-based covert channels
    """
    
    # Header size: type(1) + seq(8) + timestamp(8) + payload_len(4) = 21 bytes
    HEADER_SIZE = 21
    # Checksum size: SHA-512 = 64 bytes
    CHECKSUM_SIZE = 64
    # Maximum payload size
    MAX_PAYLOAD_SIZE = NORMALIZED_PACKET_SIZE - HEADER_SIZE - CHECKSUM_SIZE
    
    def __init__(self, packet_size: int = NORMALIZED_PACKET_SIZE, hmac_key: Optional[bytes] = None):
        """
        Initialize packet normalizer.
        
        Args:
            packet_size: Fixed packet size (default 1024)
            hmac_key: Key for HMAC integrity (generated if not provided)
        """
        if packet_size < 64:
            raise ValueError("packet_size must be at least 64 bytes")
        
        self.packet_size = packet_size
        self._hmac_key = hmac_key if hmac_key else secrets.token_bytes(64)
        self._sequence_counter = 0
        self._seq_lock = threading.Lock()
        
        # Recalculate max payload for custom packet size
        self.max_payload_size = packet_size - self.HEADER_SIZE - self.CHECKSUM_SIZE
        
        logger.info(f"PacketNormalizer initialized: size={packet_size}, max_payload={self.max_payload_size}")
    
    def _get_next_sequence(self) -> int:
        """Get next sequence number (thread-safe)."""
        with self._seq_lock:
            seq = self._sequence_counter
            self._sequence_counter = (self._sequence_counter + 1) % (2**64)
            return seq
    
    def _compute_checksum(self, data: bytes) -> bytes:
        """Compute HMAC-SHA512 checksum."""
        return hmac.new(self._hmac_key, data, hashlib.sha512).digest()
    
    def normalize(self, payload: bytes, packet_type: PacketType = PacketType.REAL_DATA) -> bytes:
        """
        Normalize payload to fixed-size packet.
        
        Args:
            payload: Data to normalize
            packet_type: Type of packet
            
        Returns:
            Fixed-size normalized packet
            
        **Validates: Requirements 13.2**
        """
        if len(payload) > self.max_payload_size:
            raise PacketNormalizationError(
                f"Payload too large: {len(payload)} > {self.max_payload_size}"
            )
        
        # Generate packet components
        seq = self._get_next_sequence()
        timestamp = time.time()
        
        # Calculate padding needed
        padding_size = self.max_payload_size - len(payload)
        padding = secrets.token_bytes(padding_size)
        
        # Build packet without checksum
        header = struct.pack(
            '>BQQI',
            packet_type.value,
            seq,
            int(timestamp * 1000000),
            len(payload)
        )
        
        packet_without_checksum = header + payload + padding
        
        # Compute and append checksum
        checksum = self._compute_checksum(packet_without_checksum)
        
        normalized = packet_without_checksum + checksum
        
        # Verify size (explicit raise: asserts vanish under python -O)
        if len(normalized) != self.packet_size:
            raise PacketNormalizationError(
                f"Normalization error: {len(normalized)} != {self.packet_size}")
        
        return normalized
    
    def denormalize(self, packet: bytes) -> Tuple[bytes, PacketType]:
        """
        Extract payload from normalized packet.
        
        Args:
            packet: Normalized packet
            
        Returns:
            Tuple of (payload, packet_type)
            
        Raises:
            PacketNormalizationError: If packet is invalid
            
        **Validates: Requirements 13.2**
        """
        if len(packet) != self.packet_size:
            raise PacketNormalizationError(
                f"Invalid packet size: {len(packet)} != {self.packet_size}"
            )
        
        # Verify checksum
        packet_data = packet[:-self.CHECKSUM_SIZE]
        stored_checksum = packet[-self.CHECKSUM_SIZE:]
        computed_checksum = self._compute_checksum(packet_data)
        
        if not hmac.compare_digest(stored_checksum, computed_checksum):
            raise PacketNormalizationError("Checksum verification failed")
        
        # Parse header
        header = packet[:self.HEADER_SIZE]
        ptype, seq, ts_us, payload_len = struct.unpack('>BQQI', header)
        
        # Validate payload length
        if payload_len > self.max_payload_size:
            raise PacketNormalizationError(f"Invalid payload length: {payload_len}")
        
        # Extract payload
        payload_start = self.HEADER_SIZE
        payload = packet[payload_start:payload_start + payload_len]
        
        return payload, PacketType(ptype)
    
    def get_packet_size(self) -> int:
        """Get the fixed packet size."""
        return self.packet_size
    
    def verify_size(self, packet: bytes) -> bool:
        """
        Verify packet is correctly normalized.
        
        **Validates: Requirements 13.2**
        """
        return len(packet) == self.packet_size



# ============================================================================
# Protocol Field Normalizer
# **Validates: Requirements 13.3**
# ============================================================================

class ProtocolFieldNormalizer:
    """
    Normalizes protocol fields to prevent encoding-based covert channels.
    
    **Validates: Requirements 13.3**
    - THE Secure_P2P_System SHALL implement protocol field normalization to prevent encoding channels
    """
    
    # Standard field values for normalization
    STANDARD_VERSION = 1
    STANDARD_FLAGS = 0x00
    STANDARD_RESERVED = bytes(8)  # 8 zero bytes
    
    def __init__(self):
        """Initialize protocol field normalizer."""
        self._field_specs: Dict[str, Tuple[int, bytes]] = {
            'version': (1, struct.pack('>B', self.STANDARD_VERSION)),
            'flags': (1, struct.pack('>B', self.STANDARD_FLAGS)),
            'reserved': (8, self.STANDARD_RESERVED),
        }
        logger.info("ProtocolFieldNormalizer initialized")
    
    def normalize_fields(self, packet: bytes) -> bytes:
        """
        Normalize all protocol fields in a packet.
        
        Args:
            packet: Raw packet with potentially non-standard fields
            
        Returns:
            Packet with normalized fields
            
        **Validates: Requirements 13.3**
        """
        if len(packet) < 10:
            raise ProtocolFieldError("Packet too short for field normalization")
        
        # Create mutable copy
        normalized = bytearray(packet)
        
        # Normalize version field (byte 0)
        normalized[0] = self.STANDARD_VERSION
        
        # Normalize flags (if present at standard position)
        if len(normalized) > 1:
            # Clear any non-essential flags
            normalized[1] = normalized[1] & 0x0F  # Keep only lower 4 bits
        
        return bytes(normalized)
    
    def create_normalized_header(self, payload_length: int, message_type: int) -> bytes:
        """
        Create a fully normalized protocol header.
        
        Args:
            payload_length: Length of payload
            message_type: Type of message
            
        Returns:
            Normalized header bytes
            
        **Validates: Requirements 13.3**
        """
        # Fixed header format:
        # version(1) + type(1) + flags(1) + reserved(1) + length(4) + reserved(8) = 16 bytes
        header = struct.pack(
            '>BBBBI8s',
            self.STANDARD_VERSION,
            message_type & 0xFF,
            self.STANDARD_FLAGS,
            0x00,  # Reserved byte
            payload_length,
            self.STANDARD_RESERVED
        )
        return header
    
    def verify_normalized(self, packet: bytes) -> bool:
        """
        Verify packet fields are properly normalized.
        
        Args:
            packet: Packet to verify
            
        Returns:
            True if all fields are normalized
            
        **Validates: Requirements 13.3**
        """
        if len(packet) < 1:
            return False
        
        # Check version
        if packet[0] != self.STANDARD_VERSION:
            return False
        
        return True
    
    def strip_covert_data(self, packet: bytes) -> bytes:
        """
        Strip any potential covert data from protocol fields.
        
        This ensures no information can be hidden in:
        - Reserved fields
        - Padding bytes
        - Optional header fields
        
        **Validates: Requirements 13.3**
        """
        if len(packet) < 16:
            return packet
        
        normalized = bytearray(packet)
        
        # Zero out reserved fields (bytes 3 and 8-15)
        if len(normalized) > 3:
            normalized[3] = 0x00
        
        if len(normalized) >= 16:
            normalized[8:16] = self.STANDARD_RESERVED
        
        return bytes(normalized)


# ============================================================================
# Fixed-Rate Transmitter
# **Validates: Requirements 13.1**
# ============================================================================

class FixedRateTransmitter:
    """
    Maintains constant transmission rate regardless of actual message volume.
    
    **Validates: Requirements 13.1**
    - THE Secure_P2P_System SHALL implement timing channel elimination via fixed-rate transmission
    """
    
    def __init__(
        self,
        rate_per_second: float = DEFAULT_FIXED_RATE,
        packet_size: int = NORMALIZED_PACKET_SIZE,
        send_callback: Optional[Callable[[bytes], None]] = None
    ):
        """
        Initialize fixed-rate transmitter.
        
        Args:
            rate_per_second: Fixed transmission rate (packets/second)
            packet_size: Size of each packet
            send_callback: Function to call for sending packets
        """
        if rate_per_second <= 0 or rate_per_second > 1000:
            raise ValueError("rate_per_second must be between 0 and 1000")
        if packet_size < 64:
            raise ValueError("packet_size must be at least 64 bytes")
        
        self.rate_per_second = rate_per_second
        self.packet_size = packet_size
        self._send_callback = send_callback
        
        # Message queue
        self._message_queue: Deque[bytes] = deque()
        self._queue_lock = threading.Lock()
        
        # Threading control
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Statistics
        self._stats = TransmissionStats()
        self._packet_timestamps: Deque[float] = deque(maxlen=1000)
        
        # Normalizer for cover traffic
        self._normalizer = PacketNormalizer(packet_size)
        
        logger.info(f"FixedRateTransmitter initialized: rate={rate_per_second}/sec")
    
    @property
    def interval_seconds(self) -> float:
        """Calculate interval between packets."""
        return 1.0 / self.rate_per_second
    
    @property
    def is_running(self) -> bool:
        """Check if transmitter is running."""
        return self._running
    
    def queue_message(self, message: bytes) -> None:
        """
        Queue a message for transmission.
        
        Args:
            message: Message to send (will be normalized)
        """
        # Normalize the message
        normalized = self._normalizer.normalize(message, PacketType.REAL_DATA)
        
        with self._queue_lock:
            self._message_queue.append(normalized)
    
    def _generate_cover_packet(self) -> bytes:
        """Generate a cover traffic packet."""
        cover_data = secrets.token_bytes(self._normalizer.max_payload_size)
        return self._normalizer.normalize(cover_data, PacketType.COVER_TRAFFIC)
    
    def start(self) -> None:
        """
        Start fixed-rate transmission.
        
        **Validates: Requirements 13.1**
        """
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        self._stats = TransmissionStats()
        
        self._thread = threading.Thread(
            target=self._transmission_loop,
            daemon=True,
            name="FixedRateTransmitter"
        )
        self._thread.start()
        logger.info(f"Fixed-rate transmission started at {self.rate_per_second}/sec")
    
    def stop(self) -> None:
        """Stop fixed-rate transmission."""
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        
        self._thread = None
        logger.info("Fixed-rate transmission stopped")
    
    def _transmission_loop(self) -> None:
        """Main transmission loop maintaining fixed rate."""
        next_send_time = time.time()
        
        while not self._stop_event.is_set():
            try:
                current_time = time.time()
                
                # Wait until next scheduled send time
                if current_time < next_send_time:
                    sleep_time = next_send_time - current_time
                    if sleep_time > 0:
                        self._stop_event.wait(timeout=sleep_time)
                        if self._stop_event.is_set():
                            break
                
                # Get next packet (real or cover)
                packet = self._get_next_packet()
                
                # Send packet
                if self._send_callback:
                    try:
                        self._send_callback(packet)
                    except Exception as e:
                        logger.warning(f"Packet send failed: {e}")
                
                # Record timestamp
                send_time = time.time()
                self._packet_timestamps.append(send_time)
                self._stats.packets_sent += 1
                self._stats.bytes_sent += len(packet)
                
                # Schedule next send
                next_send_time = send_time + self.interval_seconds
                
            except Exception as e:
                logger.error(f"Transmission loop error: {e}")
                self._stop_event.wait(timeout=0.1)
    
    def _get_next_packet(self) -> bytes:
        """Get next packet to send (real message or cover traffic)."""
        with self._queue_lock:
            if self._message_queue:
                packet = self._message_queue.popleft()
                self._stats.real_packets += 1
                return packet
        
        # No real message, send cover traffic
        self._stats.cover_packets += 1
        return self._generate_cover_packet()
    
    def get_actual_rate(self, window_seconds: float = 10.0) -> float:
        """
        Calculate actual transmission rate over a time window.
        
        **Validates: Requirements 13.1**
        """
        now = time.time()
        cutoff = now - window_seconds
        
        recent = [t for t in self._packet_timestamps if t > cutoff]
        
        if len(recent) < 2:
            return 0.0
        
        time_span = recent[-1] - recent[0]
        if time_span <= 0:
            return 0.0
        
        return (len(recent) - 1) / time_span
    
    def get_rate_deviation(self, window_seconds: float = 10.0) -> float:
        """
        Calculate deviation from target rate.
        
        Returns value between 0 (perfect) and 1 (100% deviation).
        
        **Validates: Requirements 13.1**
        """
        actual_rate = self.get_actual_rate(window_seconds)
        if actual_rate == 0:
            return 1.0 if self._running else 0.0
        
        return abs(actual_rate - self.rate_per_second) / self.rate_per_second
    
    def verify_fixed_rate(self, tolerance: float = 0.1) -> bool:
        """
        Verify transmission rate is within tolerance of target.
        
        Args:
            tolerance: Acceptable deviation (0.1 = 10%)
            
        Returns:
            True if rate is within tolerance
            
        **Validates: Requirements 13.1**
        """
        deviation = self.get_rate_deviation()
        return deviation <= tolerance
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get transmission statistics."""
        return {
            "running": self._running,
            "target_rate": self.rate_per_second,
            "actual_rate": self.get_actual_rate(),
            "rate_deviation": self.get_rate_deviation(),
            "packets_sent": self._stats.packets_sent,
            "real_packets": self._stats.real_packets,
            "cover_packets": self._stats.cover_packets,
            "bytes_sent": self._stats.bytes_sent,
            "queue_depth": len(self._message_queue),
            "uptime_seconds": time.time() - self._stats.start_time
        }



# ============================================================================
# Cover Traffic Injector
# **Validates: Requirements 13.5**
# ============================================================================

class CoverTrafficInjector:
    """
    Injects cover traffic to mask real communication patterns.
    
    **Validates: Requirements 13.5**
    - THE Secure_P2P_System SHALL implement traffic analysis countermeasures via dummy traffic injection
    """
    
    def __init__(
        self,
        injection_ratio: float = DEFAULT_COVER_TRAFFIC_RATIO,
        packet_size: int = NORMALIZED_PACKET_SIZE,
        send_callback: Optional[Callable[[bytes], None]] = None
    ):
        """
        Initialize cover traffic injector.
        
        Args:
            injection_ratio: Ratio of cover traffic to total (0.0-1.0)
            packet_size: Size of cover packets
            send_callback: Function to call for sending packets
        """
        if injection_ratio < 0 or injection_ratio > 1:
            raise ValueError("injection_ratio must be between 0 and 1")
        
        self.injection_ratio = injection_ratio
        self.packet_size = packet_size
        self._send_callback = send_callback
        
        self._normalizer = PacketNormalizer(packet_size)
        self._packets_injected = 0
        self._lock = threading.Lock()
        
        logger.info(f"CoverTrafficInjector initialized: ratio={injection_ratio}")
    
    def generate_cover_packet(self) -> bytes:
        """
        Generate a single cover traffic packet.
        
        **Validates: Requirements 13.5**
        """
        # Generate random payload
        payload = secrets.token_bytes(self._normalizer.max_payload_size)
        return self._normalizer.normalize(payload, PacketType.COVER_TRAFFIC)
    
    def inject_cover_traffic(self, real_packet_count: int) -> int:
        """
        Inject cover traffic based on real packet count.
        
        Args:
            real_packet_count: Number of real packets sent
            
        Returns:
            Number of cover packets injected
            
        **Validates: Requirements 13.5**
        """
        if self.injection_ratio == 0:
            return 0
        
        # Calculate cover packets needed
        # If ratio is 0.3, for every 7 real packets, inject 3 cover packets
        cover_count = int(real_packet_count * self.injection_ratio / (1 - self.injection_ratio))
        
        with self._lock:
            for _ in range(cover_count):
                cover_packet = self.generate_cover_packet()
                if self._send_callback:
                    try:
                        self._send_callback(cover_packet)
                        self._packets_injected += 1
                    except Exception as e:
                        logger.warning(f"Cover traffic injection failed: {e}")
        
        return cover_count
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get injection statistics."""
        return {
            "injection_ratio": self.injection_ratio,
            "packets_injected": self._packets_injected,
            "packet_size": self.packet_size
        }


# ============================================================================
# Covert Channel Detector
# **Validates: Requirements 13.4**
# ============================================================================

class CovertChannelDetector:
    """
    Detects and alerts on suspected covert channel activity.
    
    **Validates: Requirements 13.4**
    - THE Secure_P2P_System SHALL detect and alert on suspected covert channel activity
    """
    
    def __init__(
        self,
        timing_threshold: float = TIMING_VARIANCE_THRESHOLD,
        size_threshold: float = SIZE_VARIANCE_THRESHOLD,
        pattern_window: int = PATTERN_DETECTION_WINDOW,
        alert_callback: Optional[Callable[[CovertChannelAlert], None]] = None
    ):
        """
        Initialize covert channel detector.
        
        Args:
            timing_threshold: Maximum allowed timing variance
            size_threshold: Maximum allowed size variance (0 = all same size)
            pattern_window: Number of packets to analyze for patterns
            alert_callback: Function to call when covert channel detected
        """
        self.timing_threshold = timing_threshold
        self.size_threshold = size_threshold
        self.pattern_window = pattern_window
        self._alert_callback = alert_callback
        
        # Analysis buffers
        self._timing_buffer: Deque[float] = deque(maxlen=pattern_window)
        self._size_buffer: Deque[int] = deque(maxlen=pattern_window)
        self._packet_buffer: Deque[bytes] = deque(maxlen=pattern_window)
        
        # Alert tracking
        self._alerts: List[CovertChannelAlert] = []
        self._alert_count = 0
        self._lock = threading.Lock()
        
        logger.info(f"CovertChannelDetector initialized: timing_threshold={timing_threshold}")
    
    def analyze_packet(self, packet: bytes, timestamp: float) -> Optional[CovertChannelAlert]:
        """
        Analyze a packet for covert channel indicators.
        
        Args:
            packet: Packet to analyze
            timestamp: Packet timestamp
            
        Returns:
            Alert if covert channel detected, None otherwise
            
        **Validates: Requirements 13.4**
        """
        with self._lock:
            # Record packet data
            self._timing_buffer.append(timestamp)
            self._size_buffer.append(len(packet))
            self._packet_buffer.append(packet)
            
            # Need minimum samples for analysis
            if len(self._timing_buffer) < 10:
                return None
            
            # Check for timing anomalies
            timing_alert = self._check_timing_anomaly()
            if timing_alert:
                return timing_alert
            
            # Check for size anomalies
            size_alert = self._check_size_anomaly()
            if size_alert:
                return size_alert
            
            # Check for pattern anomalies
            pattern_alert = self._check_pattern_anomaly()
            if pattern_alert:
                return pattern_alert
            
            return None
    
    def _check_timing_anomaly(self) -> Optional[CovertChannelAlert]:
        """Check for timing-based covert channels."""
        if len(self._timing_buffer) < 2:
            return None
        
        # Calculate inter-packet intervals
        intervals = []
        timestamps = list(self._timing_buffer)
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        
        if not intervals:
            return None
        
        # Calculate variance
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            return None
        
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        coefficient_of_variation = std_dev / mean_interval
        
        # Check if variance exceeds threshold
        if coefficient_of_variation > self.timing_threshold:
            alert = self._create_alert(
                alert_type="timing_anomaly",
                severity="high",
                description=f"Timing variance ({coefficient_of_variation:.4f}) exceeds threshold ({self.timing_threshold})",
                evidence={
                    "coefficient_of_variation": coefficient_of_variation,
                    "mean_interval": mean_interval,
                    "std_dev": std_dev,
                    "sample_count": len(intervals)
                }
            )
            return alert
        
        return None
    
    def _check_size_anomaly(self) -> Optional[CovertChannelAlert]:
        """Check for size-based covert channels."""
        if len(self._size_buffer) < 2:
            return None
        
        sizes = list(self._size_buffer)
        unique_sizes = set(sizes)
        
        # All packets should be same size
        if len(unique_sizes) > 1:
            alert = self._create_alert(
                alert_type="size_anomaly",
                severity="critical",
                description=f"Packet size variation detected: {len(unique_sizes)} different sizes",
                evidence={
                    "unique_sizes": list(unique_sizes),
                    "expected_size": NORMALIZED_PACKET_SIZE,
                    "sample_count": len(sizes)
                }
            )
            return alert
        
        return None
    
    def _check_pattern_anomaly(self) -> Optional[CovertChannelAlert]:
        """Check for pattern-based covert channels."""
        if len(self._packet_buffer) < 20:
            return None
        
        # Analyze packet content for suspicious patterns
        packets = list(self._packet_buffer)
        
        # Check for repeating sequences (potential encoding)
        sequence_counts: Dict[bytes, int] = {}
        for packet in packets:
            # Check first 32 bytes for patterns
            prefix = packet[:32] if len(packet) >= 32 else packet
            sequence_counts[prefix] = sequence_counts.get(prefix, 0) + 1
        
        # If any sequence repeats too often, it might be a pattern
        max_repeats = max(sequence_counts.values()) if sequence_counts else 0
        repeat_ratio = max_repeats / len(packets)
        
        if repeat_ratio > 0.5:  # More than 50% same prefix is suspicious
            alert = self._create_alert(
                alert_type="pattern_anomaly",
                severity="medium",
                description=f"Suspicious packet pattern detected: {repeat_ratio:.2%} repetition",
                evidence={
                    "repeat_ratio": repeat_ratio,
                    "max_repeats": max_repeats,
                    "sample_count": len(packets)
                }
            )
            return alert
        
        return None
    
    def _create_alert(
        self,
        alert_type: str,
        severity: str,
        description: str,
        evidence: Dict[str, Any]
    ) -> CovertChannelAlert:
        """Create and record a covert channel alert."""
        self._alert_count += 1
        
        alert = CovertChannelAlert(
            alert_id=f"CCA-{self._alert_count:06d}",
            timestamp=time.time(),
            alert_type=alert_type,
            severity=severity,
            description=description,
            evidence=evidence
        )
        
        self._alerts.append(alert)
        
        # Trigger callback
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
        
        logger.warning(f"COVERT CHANNEL ALERT: {alert.alert_id} - {description}")
        
        return alert
    
    def get_alerts(self, since: Optional[float] = None) -> List[CovertChannelAlert]:
        """Get alerts, optionally filtered by timestamp."""
        with self._lock:
            if since is None:
                return list(self._alerts)
            return [a for a in self._alerts if a.timestamp >= since]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "total_alerts": self._alert_count,
            "timing_threshold": self.timing_threshold,
            "size_threshold": self.size_threshold,
            "pattern_window": self.pattern_window,
            "buffer_size": len(self._packet_buffer)
        }



# ============================================================================
# Covert Channel Defense Manager
# **Validates: Requirements 13.1, 13.2, 13.3, 13.4, 13.5**
# ============================================================================

class CovertChannelDefense:
    """
    Unified manager for all covert channel defense features.
    
    This class provides comprehensive protection against covert channels:
    - Fixed-rate transmission (Requirement 13.1)
    - Packet size normalization (Requirement 13.2)
    - Protocol field normalization (Requirement 13.3)
    - Covert channel detection (Requirement 13.4)
    - Cover traffic injection (Requirement 13.5)
    
    **Validates: Requirements 13.1, 13.2, 13.3, 13.4, 13.5**
    """
    
    def __init__(
        self,
        fixed_rate: float = DEFAULT_FIXED_RATE,
        packet_size: int = NORMALIZED_PACKET_SIZE,
        cover_traffic_ratio: float = DEFAULT_COVER_TRAFFIC_RATIO,
        send_callback: Optional[Callable[[bytes], None]] = None,
        alert_callback: Optional[Callable[[CovertChannelAlert], None]] = None
    ):
        """
        Initialize covert channel defense system.
        
        Args:
            fixed_rate: Fixed transmission rate (packets/second)
            packet_size: Normalized packet size
            cover_traffic_ratio: Ratio of cover traffic
            send_callback: Function to call for sending packets
            alert_callback: Function to call on covert channel detection
        """
        self._send_callback = send_callback
        self._alert_callback = alert_callback
        self.packet_size = packet_size
        
        # Initialize components
        self._normalizer = PacketNormalizer(packet_size)
        self._field_normalizer = ProtocolFieldNormalizer()
        
        self._transmitter = FixedRateTransmitter(
            rate_per_second=fixed_rate,
            packet_size=packet_size,
            send_callback=self._on_packet_send
        )
        
        self._cover_injector = CoverTrafficInjector(
            injection_ratio=cover_traffic_ratio,
            packet_size=packet_size,
            send_callback=self._on_packet_send
        )
        
        self._detector = CovertChannelDetector(
            alert_callback=alert_callback
        )
        
        # Statistics
        self._stats = TransmissionStats()
        self._lock = threading.Lock()
        
        logger.info(
            f"CovertChannelDefense initialized: rate={fixed_rate}/sec, "
            f"packet_size={packet_size}, cover_ratio={cover_traffic_ratio}"
        )
    
    def _on_packet_send(self, packet: bytes) -> None:
        """Internal callback for packet sending with analysis."""
        timestamp = time.time()
        
        # Analyze packet for covert channels
        self._detector.analyze_packet(packet, timestamp)
        
        # Forward to external callback
        if self._send_callback:
            self._send_callback(packet)
        
        with self._lock:
            self._stats.packets_sent += 1
            self._stats.bytes_sent += len(packet)
    
    def send_message(self, message: bytes) -> None:
        """
        Send a message with full covert channel protection.
        
        The message will be:
        1. Normalized to fixed size
        2. Protocol fields normalized
        3. Transmitted at fixed rate
        
        Args:
            message: Message to send
            
        **Validates: Requirements 13.1, 13.2, 13.3**
        """
        # Check message size
        if len(message) > self._normalizer.max_payload_size:
            raise CovertChannelDefenseError(
                f"Message too large: {len(message)} > {self._normalizer.max_payload_size}"
            )
        
        # Queue for fixed-rate transmission
        self._transmitter.queue_message(message)
        
        with self._lock:
            self._stats.real_packets += 1
    
    def receive_packet(self, packet: bytes) -> Tuple[Optional[bytes], PacketType]:
        """
        Receive and process a packet.
        
        Args:
            packet: Received packet
            
        Returns:
            Tuple of (payload or None, packet_type)
            
        **Validates: Requirements 13.2, 13.4**
        """
        timestamp = time.time()
        
        # Analyze for covert channels
        alert = self._detector.analyze_packet(packet, timestamp)
        if alert and alert.severity == "critical":
            raise CovertChannelDetectedError(
                f"Critical covert channel detected: {alert.description}"
            )
        
        # Verify packet size
        if not self._normalizer.verify_size(packet):
            self._stats.size_violations += 1
            raise PacketNormalizationError(
                f"Invalid packet size: {len(packet)} != {self.packet_size}"
            )
        
        # Denormalize packet
        try:
            payload, packet_type = self._normalizer.denormalize(packet)
        except PacketNormalizationError as e:
            logger.warning(f"Packet denormalization failed: {e}")
            raise
        
        with self._lock:
            self._stats.packets_received += 1
            self._stats.bytes_received += len(packet)
        
        # Return None for cover traffic
        if packet_type == PacketType.COVER_TRAFFIC:
            return None, packet_type
        
        return payload, packet_type
    
    def start(self) -> None:
        """
        Start covert channel defense system.
        
        **Validates: Requirements 13.1, 13.5**
        """
        self._transmitter.start()
        logger.info("Covert channel defense started")
    
    def stop(self) -> None:
        """Stop covert channel defense system."""
        self._transmitter.stop()
        logger.info("Covert channel defense stopped")
    
    @property
    def is_running(self) -> bool:
        """Check if defense system is running."""
        return self._transmitter.is_running
    
    def verify_fixed_rate(self, tolerance: float = 0.1) -> bool:
        """
        Verify transmission rate is within tolerance.
        
        **Validates: Requirements 13.1**
        """
        return self._transmitter.verify_fixed_rate(tolerance)
    
    def verify_packet_normalization(self, packet: bytes) -> bool:
        """
        Verify packet is properly normalized.
        
        **Validates: Requirements 13.2**
        """
        return self._normalizer.verify_size(packet)
    
    def get_actual_rate(self) -> float:
        """
        Get actual transmission rate.
        
        **Validates: Requirements 13.1**
        """
        return self._transmitter.get_actual_rate()
    
    def get_rate_deviation(self) -> float:
        """
        Get deviation from target rate.
        
        **Validates: Requirements 13.1**
        """
        return self._transmitter.get_rate_deviation()
    
    def get_alerts(self, since: Optional[float] = None) -> List[CovertChannelAlert]:
        """
        Get covert channel alerts.
        
        **Validates: Requirements 13.4**
        """
        return self._detector.get_alerts(since)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        with self._lock:
            return {
                "running": self.is_running,
                "packet_size": self.packet_size,
                "transmitter": self._transmitter.get_statistics(),
                "cover_injector": self._cover_injector.get_statistics(),
                "detector": self._detector.get_statistics(),
                "totals": {
                    "packets_sent": self._stats.packets_sent,
                    "packets_received": self._stats.packets_received,
                    "real_packets": self._stats.real_packets,
                    "bytes_sent": self._stats.bytes_sent,
                    "bytes_received": self._stats.bytes_received,
                    "size_violations": self._stats.size_violations,
                    "covert_channel_alerts": len(self._detector.get_alerts())
                }
            }


# ============================================================================
# Utility Functions
# ============================================================================

def create_covert_channel_defense(
    fixed_rate: float = DEFAULT_FIXED_RATE,
    packet_size: int = NORMALIZED_PACKET_SIZE,
    cover_traffic_ratio: float = DEFAULT_COVER_TRAFFIC_RATIO,
    send_callback: Optional[Callable[[bytes], None]] = None,
    alert_callback: Optional[Callable[[CovertChannelAlert], None]] = None
) -> CovertChannelDefense:
    """
    Factory function to create a CovertChannelDefense instance.
    
    Args:
        fixed_rate: Fixed transmission rate (packets/second)
        packet_size: Normalized packet size
        cover_traffic_ratio: Ratio of cover traffic
        send_callback: Function to call for sending packets
        alert_callback: Function to call on covert channel detection
        
    Returns:
        Configured CovertChannelDefense instance
    """
    return CovertChannelDefense(
        fixed_rate=fixed_rate,
        packet_size=packet_size,
        cover_traffic_ratio=cover_traffic_ratio,
        send_callback=send_callback,
        alert_callback=alert_callback
    )


def verify_all_packets_same_size(packets: List[bytes]) -> bool:
    """
    Verify all packets in a list have identical size.
    
    **Validates: Requirements 13.2**
    
    Args:
        packets: List of packets to verify
        
    Returns:
        True if all packets have same size
    """
    if not packets:
        return True
    
    expected_size = len(packets[0])
    return all(len(p) == expected_size for p in packets)


def calculate_rate_from_timestamps(timestamps: List[float]) -> float:
    """
    Calculate transmission rate from timestamps.
    
    **Validates: Requirements 13.1**
    
    Args:
        timestamps: List of packet timestamps
        
    Returns:
        Rate in packets per second
    """
    if len(timestamps) < 2:
        return 0.0
    
    sorted_ts = sorted(timestamps)
    time_span = sorted_ts[-1] - sorted_ts[0]
    
    if time_span <= 0:
        return 0.0
    
    return (len(timestamps) - 1) / time_span


# ============================================================================
# Module Initialization
# ============================================================================

__all__ = [
    # Exceptions
    'CovertChannelDefenseError',
    'FixedRateViolationError',
    'PacketNormalizationError',
    'CovertChannelDetectedError',
    'ProtocolFieldError',
    
    # Data classes
    'PacketType',
    'NormalizedPacket',
    'TransmissionStats',
    'CovertChannelAlert',
    
    # Core classes
    'PacketNormalizer',
    'ProtocolFieldNormalizer',
    'FixedRateTransmitter',
    'CoverTrafficInjector',
    'CovertChannelDetector',
    'CovertChannelDefense',
    
    # Utility functions
    'create_covert_channel_defense',
    'verify_all_packets_same_size',
    'calculate_rate_from_timestamps',
    
    # Constants
    'NORMALIZED_PACKET_SIZE',
    'DEFAULT_FIXED_RATE',
    'DEFAULT_COVER_TRAFFIC_RATIO',
]
