"""
Data models for the P2P system.

Provides structured data classes for handshake context, security events,
user profiles, and peer information.
"""

import base64
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any, Set
from datetime import datetime, timezone


def _utcnow() -> datetime:
    """Timezone-aware UTC now (replaces deprecated naive utcnow)."""
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    """Attach UTC to naive datetimes parsed from legacy stored strings."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


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
        timestamp: When the handshake started
        error: Error message if handshake failed
    """
    peer_id: str
    state: HandshakeState = HandshakeState.INIT
    ephemeral_keys: Dict[str, bytes] = field(default_factory=dict)
    shared_secret: Optional[bytes] = None
    session_key: Optional[bytes] = None
    timestamp: datetime = field(default_factory=_utcnow)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'peer_id': self.peer_id,
            'state': self.state.value,
            'timestamp': self.timestamp.isoformat(),
            'error': self.error,
        }


@dataclass
class SecurityEvent:
    """
    Security event for audit logging.
    
    Attributes:
        event_type: Type of security event
        severity: Severity level (INFO, WARNING, ERROR, CRITICAL)
        source: Source of the event
        description: Human-readable description
        timestamp: When the event occurred
        peer_id: Related peer ID (if applicable)
        details: Additional event details
    """
    event_type: str
    severity: str
    source: str
    description: str
    timestamp: datetime = field(default_factory=_utcnow)
    peer_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'event_type': self.event_type,
            'severity': self.severity,
            'source': self.source,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'peer_id': self.peer_id,
            'details': self.details,
        }


class SecurityRole(Enum):
    """
    Role-Based Access Control (RBAC) security roles.
    Follows hierarchical privilege separation for military defense networks.
    """
    ANONYMOUS = "ANONYMOUS"
    AUDITOR = "AUDITOR"
    OPERATOR = "OPERATOR"
    OFFICER = "OFFICER"
    COMMANDER = "COMMANDER"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"


class SecurityPermission(Enum):
    """
    Granular security permissions for P2P network operations.
    """
    SEND_CHAT = "SEND_CHAT"
    SEND_FILE = "SEND_FILE"
    SEND_NC3 = "SEND_NC3"
    INITIATE_KEY_ROTATION = "INITIATE_KEY_ROTATION"
    UPDATE_CONFIG = "UPDATE_CONFIG"
    READ_AUDIT_LOGS = "READ_AUDIT_LOGS"
    DISPOSE_IDENTITY = "DISPOSE_IDENTITY"
    EMERGENCY_RELEASE = "EMERGENCY_RELEASE"
    ADMIN_COMMAND = "ADMIN_COMMAND"


@dataclass
class RoleAssignment:
    """Cryptographically verifiable role assignment for a user or peer."""
    principal_id: str
    role: SecurityRole
    permissions: Set[SecurityPermission] = field(default_factory=set)
    granted_by: str = "SYSTEM"
    granted_at: datetime = field(default_factory=_utcnow)
    expires_at: Optional[datetime] = None
    signature: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'principal_id': self.principal_id,
            'role': self.role.value,
            'permissions': [p.value for p in self.permissions],
            'granted_by': self.granted_by,
            'granted_at': self.granted_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'signature': base64.b64encode(self.signature).decode('utf-8') if self.signature else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RoleAssignment':
        sig = base64.b64decode(data['signature'].encode('utf-8')) if data.get('signature') else None
        perms = {SecurityPermission(p) for p in data.get('permissions', [])}
        return cls(
            principal_id=data['principal_id'],
            role=SecurityRole(data.get('role', SecurityRole.OPERATOR.value)),
            permissions=perms,
            granted_by=data.get('granted_by', 'SYSTEM'),
            granted_at=_aware(datetime.fromisoformat(data['granted_at'])) if data.get('granted_at') else _utcnow(),
            expires_at=_aware(datetime.fromisoformat(data['expires_at'])) if data.get('expires_at') else None,
            signature=sig,
        )


@dataclass
class UserProfile:
    """
    User profile information.
    
    Attributes:
        user_id: Unique user identifier
        display_name: User's display name
        public_key: User's public key (base64 encoded)
        sig_public_key: User's signature public key (base64 encoded)
        role: SecurityRole assigned to the user
        created_at: When the profile was created
        last_seen: When the user was last active
        metadata: Additional profile metadata
    """
    user_id: str
    display_name: str
    public_key: str  # Base64 encoded
    sig_public_key: str  # Base64 encoded
    role: str = SecurityRole.OPERATOR.value
    created_at: datetime = field(default_factory=_utcnow)
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'user_id': self.user_id,
            'display_name': self.display_name,
            'public_key': self.public_key,
            'sig_public_key': self.sig_public_key,
            'role': self.role,
            'created_at': self.created_at.isoformat(),
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'metadata': self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserProfile':
        """Create from dictionary."""
        return cls(
            user_id=data['user_id'],
            display_name=data['display_name'],
            public_key=data['public_key'],
            sig_public_key=data['sig_public_key'],
            role=data.get('role', SecurityRole.OPERATOR.value),
            created_at=_aware(datetime.fromisoformat(data['created_at'])) if data.get('created_at') else _utcnow(),
            last_seen=_aware(datetime.fromisoformat(data['last_seen'])) if data.get('last_seen') else None,
            metadata=data.get('metadata', {}),
        )


@dataclass
class PeerInfo:
    """
    Information about a connected peer.
    
    Attributes:
        peer_id: Unique peer identifier
        address: Network address (IP:port)
        public_key: Peer's public key (base64 encoded)
        sig_public_key: Peer's signature public key (base64 encoded)
        role: SecurityRole of the connected peer
        connected_at: When the connection was established
        last_message: When the last message was received
        trust_level: Trust level (0-100)
        verified: Whether the peer has been verified
        metadata: Additional peer metadata
    """
    peer_id: str
    address: str
    public_key: str  # Base64 encoded
    sig_public_key: str  # Base64 encoded
    role: str = SecurityRole.OPERATOR.value
    connected_at: datetime = field(default_factory=_utcnow)
    last_message: Optional[datetime] = None
    trust_level: int = 0
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'peer_id': self.peer_id,
            'address': self.address,
            'public_key': self.public_key,
            'sig_public_key': self.sig_public_key,
            'role': self.role,
            'connected_at': self.connected_at.isoformat(),
            'last_message': self.last_message.isoformat() if self.last_message else None,
            'trust_level': self.trust_level,
            'verified': self.verified,
            'metadata': self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PeerInfo':
        """Create from dictionary."""
        return cls(
            peer_id=data['peer_id'],
            address=data['address'],
            public_key=data['public_key'],
            sig_public_key=data['sig_public_key'],
            role=data.get('role', SecurityRole.OPERATOR.value),
            connected_at=_aware(datetime.fromisoformat(data['connected_at'])) if data.get('connected_at') else _utcnow(),
            last_message=_aware(datetime.fromisoformat(data['last_message'])) if data.get('last_message') else None,
            trust_level=data.get('trust_level', 0),
            verified=data.get('verified', False),
            metadata=data.get('metadata', {}),
        )


__all__ = [
    'HandshakeState',
    'HandshakeContext',
    'SecurityEvent',
    'SecurityRole',
    'SecurityPermission',
    'RoleAssignment',
    'UserProfile',
    'PeerInfo',
]
