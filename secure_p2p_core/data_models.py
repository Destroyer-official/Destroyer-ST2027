"""
Data models for the P2P system.

Provides structured data classes for handshake context, security events,
user profiles, and peer information.
"""

import base64
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime


class HandshakeState(Enum):
    """Handshake state machine states."""
    INIT = "INIT"
    CLIENT_HELLO_SENT = "CLIENT_HELLO_SENT"
    SERVER_HELLO_RECEIVED = "SERVER_HELLO_RECEIVED"
    KEY_EXCHANGE_SENT = "KEY_EXCHANGE_SENT"
    KEY_EXCHANGE_RECEIVED = "KEY_EXCHANGE_RECEIVED"
    VERIFY_SENT = "VERIFY_SENT"
    VERIFY_RECEIVED = "VERIFY_RECEIVED"
    ACK_SENT = "ACK_SENT"
    ACK_RECEIVED = "ACK_RECEIVED"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


@dataclass
class HandshakeContext:
    """
    Context for tracking handshake state and progress.
    
    Attributes:
        peer_id: Identifier of the peer
        state: Current handshake state
        ephemeral_keys: Dictionary of ephemeral keys
        shared_secret: Computed shared secret (None until complete)
        session_key: Derived session key (None until complete)
        timestamp: When handshake started
        retry_count: Number of retry attempts
        timeout: Timeout in seconds
        error_message: Error message if handshake failed
    """
    peer_id: str
    state: HandshakeState = HandshakeState.INIT
    ephemeral_keys: Dict[str, bytes] = field(default_factory=dict)
    shared_secret: Optional[bytes] = None
    session_key: Optional[bytes] = None
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    retry_count: int = 0
    timeout: float = 30.0
    error_message: Optional[str] = None
    function: Optional[str] = None
    module: str = "network.handshake"
    
    def transition_to(self, new_state: HandshakeState, function_or_logger=None) -> None:
        """
        Transition to new state with logging or function tracking.
        
        Args:
            new_state: Target handshake state
            function_or_logger: Optional logger or function name
        """
        old_state = self.state
        self.state = new_state
        if isinstance(function_or_logger, str):
            self.function = function_or_logger
        elif hasattr(function_or_logger, 'info'):
            function_or_logger.info(f"Handshake state transition: {old_state.value} -> {new_state.value}")

    def mark_failed(self, error_message: str, function: str = "unknown") -> None:
        """Mark handshake as failed with error context."""
        self.state = HandshakeState.FAILED
        self.error_message = error_message
        self.function = function

    
    def is_complete(self) -> bool:
        """Check if handshake is complete."""
        return self.state == HandshakeState.COMPLETE
    
    def is_failed(self) -> bool:
        """Check if handshake failed."""
        return self.state == HandshakeState.FAILED
    
    def elapsed_time(self) -> float:
        """Get elapsed time since handshake started."""
        return datetime.now().timestamp() - self.timestamp
    
    def is_timed_out(self) -> bool:
        """Check if handshake has timed out."""
        return self.elapsed_time() > self.timeout
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/serialization."""
        return {
            'peer_id': self.peer_id,
            'state': self.state.value,
            'ephemeral_keys': {k: base64.b64encode(v).decode() for k, v in self.ephemeral_keys.items()},
            'shared_secret': base64.b64encode(self.shared_secret).decode() if self.shared_secret else None,
            'session_key': base64.b64encode(self.session_key).decode() if self.session_key else None,
            'timestamp': self.timestamp,
            'retry_count': self.retry_count,
            'timeout': self.timeout,
            'error_message': self.error_message,
            'elapsed_time': self.elapsed_time()
        }


@dataclass
class SecurityEvent:
    """
    Security event for audit logging.
    
    Attributes:
        event_type: Type of security event (HANDSHAKE, KEY_ROTATION, AUTH_FAILURE, etc.)
        severity: Event severity (LOW, MEDIUM, HIGH, CRITICAL)
        timestamp: When event occurred
        module: Module where event occurred
        function: Function where event occurred
        error_code: Optional error code
        details: Additional event details
        signature: Cryptographic signature of event
    """
    event_type: str
    severity: str
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    module: str = "unknown"
    function: str = "unknown"
    error_code: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[bytes] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            'event_type': self.event_type,
            'severity': self.severity,
            'timestamp': self.timestamp,
            'module': self.module,
            'function': self.function,
            'error_code': self.error_code,
            'details': self.details,
            'signature': base64.b64encode(self.signature).decode() if self.signature else None
        }


@dataclass
class UserProfile:
    """
    Encrypted user profile.
    
    Attributes:
        username: Username (unique identifier)
        display_name: Display name for UI
        user_id: Unique user ID
        ipv6: IPv6 address
        port: Port number
        public_key: Public key for encryption
        private_key: Encrypted private key
        created_at: Profile creation timestamp
        last_login: Last login timestamp
    """
    username: str
    display_name: str
    user_id: str
    ipv6: str
    port: int
    public_key: bytes
    private_key: bytes
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    last_login: float = field(default_factory=lambda: datetime.now().timestamp())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            'username': self.username,
            'display_name': self.display_name,
            'user_id': self.user_id,
            'ipv6': self.ipv6,
            'port': self.port,
            'public_key': base64.b64encode(self.public_key).decode(),
            'private_key': base64.b64encode(self.private_key).decode(),
            'created_at': self.created_at,
            'last_login': self.last_login
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserProfile':
        """Create UserProfile from dictionary."""
        return cls(
            username=data['username'],
            display_name=data['display_name'],
            user_id=data['user_id'],
            ipv6=data['ipv6'],
            port=data['port'],
            public_key=base64.b64decode(data['public_key']),
            private_key=base64.b64decode(data['private_key']),
            created_at=data.get('created_at', datetime.now().timestamp()),
            last_login=data.get('last_login', datetime.now().timestamp())
        )


@dataclass
class PeerInfo:
    """
    Peer connection information.
    
    Attributes:
        username: Peer's username
        display_name: Peer's display name
        ipv6: Peer's IPv6 address
        port: Peer's port number
        public_key: Peer's public key
        connection_status: Connection status (ONLINE, OFFLINE, CONNECTING)
        last_seen: Last time peer was seen
        connection_quality: Connection quality metric (0.0-1.0)
    """
    username: str
    display_name: str
    ipv6: str
    port: int
    public_key: bytes
    connection_status: str = "OFFLINE"
    last_seen: float = field(default_factory=lambda: datetime.now().timestamp())
    connection_quality: float = 0.0
    
    def is_online(self) -> bool:
        """Check if peer is online."""
        return self.connection_status == "ONLINE"
    
    def is_connecting(self) -> bool:
        """Check if peer is connecting."""
        return self.connection_status == "CONNECTING"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            'username': self.username,
            'display_name': self.display_name,
            'ipv6': self.ipv6,
            'port': self.port,
            'public_key': base64.b64encode(self.public_key).decode(),
            'connection_status': self.connection_status,
            'last_seen': self.last_seen,
            'connection_quality': self.connection_quality
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PeerInfo':
        """Create PeerInfo from dictionary."""
        return cls(
            username=data['username'],
            display_name=data['display_name'],
            ipv6=data['ipv6'],
            port=data['port'],
            public_key=base64.b64decode(data['public_key']),
            connection_status=data.get('connection_status', 'OFFLINE'),
            last_seen=data.get('last_seen', datetime.now().timestamp()),
            connection_quality=data.get('connection_quality', 0.0)
        )
