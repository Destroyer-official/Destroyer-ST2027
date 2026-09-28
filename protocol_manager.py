"""
Protocol Manager - Secure Handshake and Session Management

This module implements a comprehensive protocol manager for secure P2P communications
with NIST Level 5+ security requirements. It provides:

1. Secure Handshake Protocol:
   - Mutual authentication with certificate verification
   - Post-quantum key exchange (ML-KEM-1024 + X25519)
   - Forward secrecy with ephemeral keys
   - Session key derivation with HKDF-SHA512

2. Session Management:
   - Session timeouts and graceful teardown
   - Key rotation based on time and usage
   - Session state validation
   - Replay attack prevention

3. Security Features:
   - Constant-time operations
   - Side-channel protection
   - Memory protection for sensitive material
   - Comprehensive error handling

Author: Security Team
License: MIT
"""

import asyncio
import logging
import time
import secrets
import hashlib
import struct
from typing import Dict, Optional, Tuple, Any, List
from collections import deque
from enum import Enum
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509

# Import our enhanced PQC implementations
from pqc_algorithms import EnhancedMLKEM_1024, EnhancedFALCON_1024, ConstantTime
from hybrid_kex import HybridKeyExchange, verify_key_material
from dep_impl    import secure_erase
from secure_key_manager import SecureKeyManager
import tls_channel_manager

# Import comprehensive error handling system
from cryptographic_errors import (
    CryptographicError,
    KeyGenerationError,
    SignatureVerificationError,
    EncryptionError,
    DecryptionError,
    HardwareSecurityError,
    AuthenticationError,
    ProtocolViolationError,
    MemoryCorruptionError,
    ConfigurationError,
    SecureErrorReporter,
    SecureExceptionHandler,
    SecurityEvent,
    SecurityEventType,
    SecuritySeverity,
    get_error_reporter
)

# Configure logging only if not already configured (avoid duplicate handlers)
log = logging.getLogger(__name__)
if not log.handlers and not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO)

# Initialize secure error reporter
error_reporter = get_error_reporter()


class SessionState(Enum):
    """Session states for secure communication."""
    UNINITIALIZED = "UNINITIALIZED"
    HANDSHAKE_INITIATED = "HANDSHAKE_INITIATED"
    HANDSHAKE_COMPLETED = "HANDSHAKE_COMPLETED"
    ACTIVE = "ACTIVE"
    ESTABLISHED = "ACTIVE"  # Alias for ACTIVE
    KEY_ROTATION = "KEY_ROTATION"
    EXPIRED = "EXPIRED"
    TERMINATED = "TERMINATED"


class HandshakePhase(Enum):
    """Phases of the secure handshake protocol."""
    INIT = "INIT"
    CERTIFICATE_EXCHANGE = "CERTIFICATE_EXCHANGE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    AUTHENTICATION = "AUTHENTICATION"
    SESSION_ESTABLISHMENT = "SESSION_ESTABLISHMENT"
    COMPLETED = "COMPLETED"


@dataclass
class PeerIdentity:
    """Peer identity information for secure communication."""
    peer_id: str
    public_key: bytes
    certificate: Optional[x509.Certificate] = None
    verified: bool = False
    trust_level: str = "UNKNOWN"


@dataclass
class SessionParameters:
    """Parameters for secure session establishment."""
    session_id: str
    peer_identity: PeerIdentity
    session_keys: Dict[str, bytes]
    creation_time: float
    last_activity: float
    key_rotation_count: int = 0
    message_count: int = 0
    max_session_time: int = 3600  # 1 hour
    max_messages: int = 5000
    max_key_rotations: int = 10


@dataclass
class KEXParameters:
    """Key exchange parameters."""
    algorithm: str = "ML-KEM-1024"
    hybrid_mode: bool = True
    ephemeral_keys: bool = True
    forward_secrecy: bool = True


class SecureChannel:
    """
    Represents a secure communication channel with enhanced state management.

    This class provides:
    - Secure message encryption/decryption with AEAD
    - State transition validation
    - Replay attack prevention
    - Session expiration management
    - Comprehensive security logging
    """

    def __init__(self, session_params: SessionParameters, aead_cipher: ChaCha20Poly1305):
        self.session_params = session_params
        self.aead_cipher = aead_cipher
        self.state = SessionState.ACTIVE
        self.nonce_counter = 0
        self.last_nonce = b""
        self.nonce_window_size = 1024
        self.seen_nonces = set()
        self.nonce_queue = deque()
        self.state_history = [SessionState.ACTIVE]  # Track state transitions
        self.last_state_change = time.time()

    def transition_state(self, new_state: SessionState, protocol_manager=None) -> bool:
        """
        Safely transition to a new session state with validation.

        Args:
            new_state: Target state to transition to
            protocol_manager: Optional protocol manager for validation

        Returns:
            True if transition successful, False otherwise
        """
        if protocol_manager and hasattr(protocol_manager, 'validate_state_transition'):
            if not protocol_manager.validate_state_transition(self.state, new_state):
                return False

        old_state = self.state
        self.state = new_state
        self.state_history.append(new_state)
        self.last_state_change = time.time()

        log.info(f"Session state transition: {old_state.value} -> {new_state.value}")

        return True

    def encrypt_message(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypt a message with the session key."""
        if self.state != SessionState.ACTIVE:
            raise ValueError(f"Channel not active: {self.state}")

        # Generate unique nonce
        nonce = self._generate_nonce()

        # Encrypt with AEAD
        ciphertext = self.aead_cipher.encrypt(
            nonce, plaintext, associated_data)

        # Update message count
        self.session_params.message_count += 1
        self.session_params.last_activity = time.time()

        return nonce + ciphertext

    def decrypt_message(self, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt a message with the session key."""
        if self.state != SessionState.ACTIVE:
            raise ValueError(f"Channel not active: {self.state}")

        if len(ciphertext) < 12:  # Minimum nonce size
            raise ValueError("Ciphertext too short")

        # Extract nonce and ciphertext
        nonce = ciphertext[:12]
        encrypted_data = ciphertext[12:]

        # Verify nonce uniqueness (1024-entry sliding window replay protection)
        if nonce in self.seen_nonces or nonce == self.last_nonce:
            raise ValueError("Nonce reuse detected - possible replay attack")
        self.seen_nonces.add(nonce)
        self.nonce_queue.append(nonce)
        self.last_nonce = nonce
        if len(self.nonce_queue) > self.nonce_window_size:
            oldest = self.nonce_queue.popleft()
            self.seen_nonces.discard(oldest)

        # Decrypt with AEAD
        plaintext = self.aead_cipher.decrypt(
            nonce, encrypted_data, associated_data)

        # Update activity
        self.session_params.last_activity = time.time()

        return plaintext

    def _generate_nonce(self) -> bytes:
        """Generate a unique nonce for encryption."""
        self.nonce_counter += 1

        # Combine counter with random data for uniqueness
        counter_bytes = struct.pack('>Q', self.nonce_counter)
        random_bytes = secrets.token_bytes(4)

        return counter_bytes + random_bytes

    def is_expired(self) -> bool:
        """Check if the session has expired."""
        current_time = time.time()

        # Check time-based expiration
        if current_time - self.session_params.creation_time > self.session_params.max_session_time:
            return True

        # Check message-based expiration
        if self.session_params.message_count >= self.session_params.max_messages:
            return True

        # Check key rotation limit
        if self.session_params.key_rotation_count >= self.session_params.max_key_rotations:
            return True

        return False

    def needs_key_rotation(self) -> bool:
        """
        Check if key rotation is needed based on production security policies.

        Key rotation is triggered by:
        - Time-based: Every 15 minutes (900 seconds)
        - Usage-based: Every 500 messages
        - Security-based: After any security event

        Returns:
            True if key rotation is needed, False otherwise
        """
        current_time = time.time()

        # Production-grade rotation thresholds (NIST Level 5+ requirements)
        time_threshold = 900   # 15 minutes (900 seconds)
        message_threshold = 500  # Conservative message limit for high security

        # Check time-based rotation
        time_since_creation = current_time - self.session_params.creation_time
        time_expired = time_since_creation > time_threshold

        # Check usage-based rotation
        message_limit = self.session_params.message_count >= message_threshold

        # Check rotation count limit (prevent excessive rotations)
        rotation_limit = self.session_params.key_rotation_count >= self.session_params.max_key_rotations

        return (time_expired or message_limit) and not rotation_limit


class ProtocolManager:
    """
    Manages secure communication protocols with comprehensive security features.

    This class implements a defense-in-depth approach to secure communications:

    1. Handshake Protocol:
       - Mutual certificate authentication
       - Post-quantum key exchange with ML-KEM-1024
       - Hybrid classical + post-quantum security
       - Forward secrecy with ephemeral keys

    2. Session Management:
       - Automatic key rotation
       - Session timeout enforcement
       - Replay attack prevention
       - Graceful session teardown

    3. Security Features:
       - Constant-time operations
       - Memory protection for keys
       - Comprehensive audit logging
       - Side-channel attack resistance

    4. Protocol Version Management:
       - Secure version negotiation
       - Backward compatibility restrictions
       - Version-specific security policies
       - Upgrade path enforcement
    """

    # Protocol version constants for secure negotiation
    PROTOCOL_VERSION = "SecureP2P-v1.0"
    MIN_SUPPORTED_VERSION = "SecureP2P-v1.0"
    MAX_SUPPORTED_VERSION = "SecureP2P-v1.0"

    # Version compatibility matrix - only allow secure versions
    VERSION_COMPATIBILITY = {
        "SecureP2P-v1.0": ["SecureP2P-v1.0"],  # Only compatible with itself for security
        # Future versions would be added here with careful security review
    }

    def __init__(self, key_manager: SecureKeyManager, config: Dict[str, Any] = None):
        """Initialize the protocol manager with enhanced security features."""
        self.key_manager = key_manager
        self.config = config or {}

        # Initialize cryptographic components
        self.ml_kem = EnhancedMLKEM_1024()
        self.falcon = EnhancedFALCON_1024()
        self.hybrid_kex = HybridKeyExchange()

        # Session management
        self.active_sessions: Dict[str, SecureChannel] = {}
        self.session_lock = asyncio.Lock()

        # Security configuration
        self.max_concurrent_sessions = self.config.get(
            "max_concurrent_sessions", 10)
        self.handshake_timeout = self.config.get("handshake_timeout", 30)
        self.session_timeout = self.config.get("session_timeout", 3600)

        # Protocol version enforcement
        self.enforce_version_security = self.config.get("enforce_version_security", True)
        self.allow_version_downgrade = self.config.get("allow_version_downgrade", False)  # Always False for security

        # State transition validation
        self.valid_state_transitions = {
            SessionState.UNINITIALIZED: [SessionState.HANDSHAKE_INITIATED],
            SessionState.HANDSHAKE_INITIATED: [SessionState.HANDSHAKE_COMPLETED, SessionState.TERMINATED],
            SessionState.HANDSHAKE_COMPLETED: [SessionState.ACTIVE, SessionState.TERMINATED],
            SessionState.ACTIVE: [SessionState.KEY_ROTATION, SessionState.EXPIRED, SessionState.TERMINATED],
            SessionState.KEY_ROTATION: [SessionState.ACTIVE, SessionState.TERMINATED],
            SessionState.EXPIRED: [SessionState.TERMINATED],
            SessionState.TERMINATED: []  # Terminal state
        }

        log.info(f"ProtocolManager initialized with protocol version {self.PROTOCOL_VERSION}")
        log.info("Enhanced security features: version negotiation, state validation, audit logging")

    def validate_protocol_version(self, peer_version: str) -> bool:
        """
        Validate peer protocol version for security compliance.

        This method enforces strict version compatibility to prevent
        downgrade attacks and ensure only secure protocol versions are used.

        Args:
            peer_version: Protocol version reported by peer

        Returns:
            True if version is compatible and secure, False otherwise

        Security Policy:
        - No version downgrades allowed
        - Only explicitly approved versions accepted
        - Unknown versions rejected by default
        """
        if not peer_version:
            log.warning("Empty protocol version received from peer")
            return False

        # Check if version is in compatibility matrix
        compatible_versions = self.VERSION_COMPATIBILITY.get(self.PROTOCOL_VERSION, [])

        if peer_version not in compatible_versions:
            log.warning(f"Incompatible protocol version: {peer_version} (current: {self.PROTOCOL_VERSION})")
            self._audit_log("VERSION_INCOMPATIBLE", {
                "peer_version": peer_version,
                "our_version": self.PROTOCOL_VERSION,
                "action": "rejected"
            })
            return False

        # Additional security checks
        if self.enforce_version_security:
            # Reject any version that might be insecure
            if "v0." in peer_version or "beta" in peer_version.lower():
                log.warning(f"Rejected potentially insecure version: {peer_version}")
                return False

        log.info(f"Protocol version {peer_version} validated successfully")
        return True

    def negotiate_protocol_version(self, peer_versions: List[str]) -> Optional[str]:
        """
        Negotiate the highest mutually supported secure protocol version.

        Args:
            peer_versions: List of protocol versions supported by peer

        Returns:
            Negotiated version string, or None if no compatible version found

        Security Policy:
        - Always prefer the highest security version
        - Never downgrade from current version
        - Reject all versions not in whitelist
        """
        if not peer_versions:
            log.warning("No protocol versions provided by peer")
            return None

        # Get our supported versions
        our_versions = self.VERSION_COMPATIBILITY.get(self.PROTOCOL_VERSION, [])

        # Find intersection of supported versions
        compatible_versions = []
        for peer_version in peer_versions:
            if peer_version in our_versions and self.validate_protocol_version(peer_version):
                compatible_versions.append(peer_version)

        if not compatible_versions:
            log.warning(f"No compatible protocol versions found. Peer: {peer_versions}, Ours: {our_versions}")
            return None

        # Select the highest version (assuming semantic versioning)
        # For now, we only support v1.0, so return it if compatible
        negotiated_version = max(compatible_versions)

        log.info(f"Negotiated protocol version: {negotiated_version}")
        self._audit_log("VERSION_NEGOTIATED", {
            "peer_versions": peer_versions,
            "negotiated_version": negotiated_version
        })

        return negotiated_version

    def validate_state_transition(self, current_state: SessionState, new_state: SessionState) -> bool:
        """
        Validate that a session state transition is allowed.

        Args:
            current_state: Current session state
            new_state: Requested new state

        Returns:
            True if transition is valid, False otherwise
        """
        valid_transitions = self.valid_state_transitions.get(current_state, [])

        if new_state not in valid_transitions:
            log.warning(f"Invalid state transition: {current_state} -> {new_state}")
            self._audit_log("INVALID_STATE_TRANSITION", {
                "from_state": current_state.value,
                "to_state": new_state.value,
                "action": "rejected"
            })
            return False

        return True

    async def establish_secure_channel(self, peer_identity: PeerIdentity,
                                       transport_socket) -> SecureChannel:
        """
        Establish a secure communication channel with a peer.

        This method implements a comprehensive secure handshake protocol:
        1. Certificate exchange and validation
        2. Post-quantum key exchange
        3. Session key derivation
        4. Channel establishment

        Args:
            peer_identity: Identity information for the peer
            transport_socket: Underlying transport connection

        Returns:
            SecureChannel: Established secure communication channel

        Raises:
            RuntimeError: Sanitized error message if handshake fails
        """
        try:
            with SecureExceptionHandler("Secure channel establishment", "ProtocolManager", error_reporter):
                log.info(
                    f"Establishing secure channel with peer {peer_identity.peer_id}")

                # Check session limits
                if len(self.active_sessions) >= self.max_concurrent_sessions:
                    raise ProtocolViolationError(
                        "Maximum concurrent sessions exceeded", "SESSION_LIMIT_EXCEEDED")

                # Generate session ID
                session_id = secrets.token_hex(16)

                # Perform secure handshake
                session_params = await self._perform_handshake(
                    session_id, peer_identity, transport_socket
                )

                # Derive session keys
                session_keys = self._derive_session_keys(
                    session_params.session_keys["shared_secret"],
                    salt=session_id.encode('utf-8')
                )

                # Create AEAD cipher
                try:
                    aead_cipher = ChaCha20Poly1305(
                        session_keys["encryption_key"])
                except Exception as e:
                    raise KeyGenerationError(
                        "Failed to create AEAD cipher", "AEAD_INIT_FAIL")

                # Create secure channel
                channel = SecureChannel(session_params, aead_cipher)

                # Store active session
                async with self.session_lock:
                    self.active_sessions[session_id] = channel

                log.info(f"Secure channel established: {session_id}")
                return channel
        except Exception as e:
            log.error(f"Failed to establish secure channel: {e}")
            raise ProtocolViolationError(f"Handshake failed: {e}")

    async def _perform_handshake(self, session_id: str, peer_identity: PeerIdentity,
                                 transport_socket) -> SessionParameters:
        """
        Perform the secure handshake protocol with enhanced security validation.

        Enhanced Handshake Protocol:
        1. Protocol version negotiation
        2. Certificate exchange and validation
        3. Post-quantum key exchange
        4. Mutual authentication
        5. Session establishment with security validation
        """
        handshake_start = time.time()
        current_phase = HandshakePhase.INIT

        # Per-peer rate limiting to prevent handshake flooding (Finding 26)
        peer_key = getattr(peer_identity, 'identity_id', None) or getattr(peer_identity, 'node_id', 'unknown_peer')
        now = time.time()
        if not hasattr(self, '_handshake_rate_limiter'):
            self._handshake_rate_limiter = {}
        self._handshake_rate_limiter = {k: ts for k, ts in self._handshake_rate_limiter.items() if ts and now - ts[-1] < 60}
        recent = [ts for ts in self._handshake_rate_limiter.get(peer_key, []) if now - ts < 60]
        if len(recent) >= 10:
            raise ProtocolViolationError(f"Handshake rate limit exceeded (10 attempts/min) for peer {peer_key}")
        recent.append(now)
        self._handshake_rate_limiter[peer_key] = recent

        try:
            # Phase 0: Protocol Version Negotiation
            current_phase = HandshakePhase.INIT
            log.info(f"Starting handshake phase: {current_phase.value}")

            # Receive peer protocol version from transport
            # The transport_socket must provide the peer's version during handshake
            if hasattr(transport_socket, 'peer_protocol_version'):
                peer_version = transport_socket.peer_protocol_version
            elif hasattr(transport_socket, 'recv_protocol_version'):
                peer_version = await transport_socket.recv_protocol_version()
            else:
                # FAIL-CLOSED: Cannot negotiate without peer version
                raise ProtocolViolationError(
                    "FAIL-CLOSED: Transport does not support protocol version exchange. "
                    "Peer version must be obtained from the transport layer."
                )

            if not self.validate_protocol_version(peer_version):
                raise ProtocolViolationError(f"Incompatible protocol version: {peer_version}")

            log.info(f"Protocol version negotiated: {peer_version}")

            # Phase 1: Certificate Exchange
            current_phase = HandshakePhase.CERTIFICATE_EXCHANGE
            log.info(f"Starting handshake phase: {current_phase.value}")
            await self._exchange_certificates(peer_identity, transport_socket)

            # Phase 2: Key Exchange
            current_phase = HandshakePhase.KEY_EXCHANGE
            log.info(f"Starting handshake phase: {current_phase.value}")
            shared_secret = await self._perform_key_exchange(peer_identity, transport_socket)

            # Phase 3: Authentication
            current_phase = HandshakePhase.AUTHENTICATION
            log.info(f"Starting handshake phase: {current_phase.value}")
            await self._perform_mutual_authentication(peer_identity, shared_secret, transport_socket)

            # Phase 4: Session Establishment
            current_phase = HandshakePhase.SESSION_ESTABLISHMENT
            log.info(f"Starting handshake phase: {current_phase.value}")
            session_params = SessionParameters(
                session_id=session_id,
                peer_identity=peer_identity,
                session_keys={"shared_secret": shared_secret},
                creation_time=time.time(),
                last_activity=time.time()
            )

            # Phase 5: Completion
            current_phase = HandshakePhase.COMPLETED
            handshake_time = time.time() - handshake_start
            log.info(f"Handshake completed successfully in {handshake_time:.2f}s")

            # Audit successful handshake
            self._audit_log("HANDSHAKE_COMPLETED", {
                "session_id": session_id,
                "peer_id": peer_identity.peer_id,
                "protocol_version": peer_version,
                "duration_ms": int(handshake_time * 1000),
                "phases_completed": [phase.value for phase in HandshakePhase]
            })

            return session_params

        except asyncio.TimeoutError:
            log.error(f"Handshake timeout in phase: {current_phase.value}")
            self._audit_log("HANDSHAKE_TIMEOUT", {
                "session_id": session_id,
                "failed_phase": current_phase.value,
                "duration_ms": int((time.time() - handshake_start) * 1000)
            })
            raise ProtocolViolationError("Handshake timeout exceeded")
        except Exception as e:
            log.error(f"Handshake failed in phase {current_phase.value}: {e}")
            self._audit_log("HANDSHAKE_FAILED", {
                "session_id": session_id,
                "failed_phase": current_phase.value,
                "error": str(e),
                "duration_ms": int((time.time() - handshake_start) * 1000)
            })
            raise ProtocolViolationError(f"Handshake failed: {e}")

    async def _exchange_certificates(self, peer_identity: PeerIdentity, transport_socket):
        """Exchange and validate certificates. Fail-closed: strict testing."""
        # FAIL-CLOSED: Certificate validation must be performed by the TLS layer.
        # The transport_socket must provide verified certificate state.
        if hasattr(transport_socket, 'is_peer_certificate_verified'):
            if not transport_socket.is_peer_certificate_verified():
                raise ProtocolViolationError(
                    "FAIL-CLOSED: Peer certificate verification failed at TLS layer."
                )
            peer_identity.verified = True
            peer_identity.trust_level = "VERIFIED"
        else:
            raise ProtocolViolationError(
                "FAIL-CLOSED: Transport does not support certificate verification. "
                "TLS mutual authentication is required for secure channel establishment."
            )

    async def _perform_key_exchange(self, peer_identity: PeerIdentity,
                                    transport_socket) -> bytes:
        """Perform hybrid post-quantum key exchange."""

        # FAIL-CLOSED: The key exchange protocol must be performed over the transport socket.
        # This local key encapsulation is insecure and prohibited.
        if not hasattr(transport_socket, 'perform_key_exchange'):
            raise ProtocolViolationError(
                "FAIL-CLOSED: Transport does not support real key exchange protocol. "
                "Insecure key exchange is prohibited."
            )
        
        shared_secret = await transport_socket.perform_key_exchange(self.ml_kem)
        
        if not shared_secret:
            raise ProtocolViolationError("Key exchange failed over transport.")

        # Verify key material
        verify_key_material(shared_secret, 32, "ML-KEM shared secret")

        return shared_secret

    async def _perform_mutual_authentication(self, peer_identity: PeerIdentity,
                                             shared_secret: bytes, transport_socket):
        """Perform mutual authentication using FALCON signatures. Fail-closed."""
        # FAIL-CLOSED: Mutual authentication requires real challenge-response
        # over the transport. The transport must support this protocol.
        if not hasattr(transport_socket, 'perform_mutual_auth'):
            raise ProtocolViolationError(
                "FAIL-CLOSED: Transport does not support mutual authentication protocol. "
                "Real challenge-response authentication with FALCON signatures is required."
            )

        # Generate authentication challenge
        challenge = secrets.token_bytes(32)

        # Create authentication data (NIST Level 5: full 32-byte shared secret)
        auth_data = (
            peer_identity.peer_id.encode() +
            challenge +
            shared_secret  # Full 32 bytes (256-bit) shared secret for Level 5 strength
        )

        # Hash authentication data using SHA-512
        auth_hash = hashlib.sha512(auth_data).digest()

        # Delegate to transport for real mutual authentication
        auth_result = await transport_socket.perform_mutual_auth(
            challenge=challenge,
            auth_hash=auth_hash,
            falcon=self.falcon
        )

        if not auth_result:
            raise ProtocolViolationError(
                "FAIL-CLOSED: Mutual authentication failed. Peer could not prove identity."
            )

    def _derive_session_keys(self, shared_secret: bytes, salt: bytes = None) -> Dict[str, bytes]:
        """
        Derive session keys from shared secret using HKDF with forward secrecy.

        Args:
            shared_secret: The shared secret from key exchange
            salt: Optional salt for key rotation (provides forward secrecy)

        Returns:
            Dictionary containing derived keys for encryption and authentication
        """

        # Use unique salt for each key derivation to ensure forward secrecy
        if salt is None:
            salt = b"SecureP2P-SessionKeys-v1-" + secrets.token_bytes(32)
        else:
            salt = b"SecureP2P-SessionKeys-v1-" + salt

        # Use HKDF to derive multiple keys with SHA-512 for enhanced security
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=96,  # 32 bytes encryption + 32 bytes MAC + 32 bytes for future use
            salt=salt,
            info=b"session-key-derivation-forward-secrecy"
        )

        key_material = hkdf.derive(shared_secret)

        keys = {
            "encryption_key": key_material[:32],
            "mac_key": key_material[32:64],
            "kdf_key": key_material[64:96]  # For future key derivation
        }

        # Verify key material
        for key_name, key_value in keys.items():
            verify_key_material(key_value, 32, f"Derived {key_name}")

        return keys

    async def rotate_session_keys(self, session_id: str) -> bool:
        """
        Rotate keys for an active session with forward secrecy.

        This method implements secure key rotation with:
        - Forward secrecy by generating new ephemeral keys
        - Secure erasure of old key material
        - Atomic key update to prevent race conditions
        - Comprehensive audit logging
        """
        async with self.session_lock:
            if session_id not in self.active_sessions:
                log.warning(
                    f"Key rotation requested for non-existent session: {session_id}")
                return False

            channel = self.active_sessions[session_id]

            if channel.state != SessionState.ACTIVE:
                log.warning(
                    f"Key rotation requested for inactive session: {session_id} (state: {channel.state})")
                return False

            try:
                log.info(f"Starting key rotation for session {session_id}")

                # Mark session as rotating
                old_state = channel.state
                channel.state = SessionState.KEY_ROTATION

                # Store old key material for secure erasure
                old_cipher = channel.aead_cipher

                # FAIL-CLOSED: Real session key rotation requires network protocol interaction
                # to securely agree on a new ephemeral shared secret. The insecure
                # local generation is unacceptable. Callers (session_management_task)
                # terminate sessions that cannot rotate, forcing re-handshake.
                raise ProtocolViolationError(
                    "FAIL-CLOSED: Cannot perform key rotation without active transport support. "
                    "Insecure key rotation is prohibited."
                )

            except Exception as e:
                log.error(f"Key rotation failed for session {session_id}: {e}")
                # Restore previous state on failure
                channel.state = old_state

                # Audit log for failed rotation
                self._audit_log("KEY_ROTATION_FAILED", {
                    "session_id": session_id,
                    "error": str(e),
                    "timestamp": time.time()
                })

                return False

    async def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        expired_sessions = []

        async with self.session_lock:
            for session_id, channel in self.active_sessions.items():
                if channel.is_expired():
                    expired_sessions.append(session_id)

            for session_id in expired_sessions:
                log.info(f"Cleaning up expired session: {session_id}")
                del self.active_sessions[session_id]

        return len(expired_sessions)

    def _audit_log(self, event_type: str, event_data: Dict[str, Any]):
        """Log security events for audit trail."""
        audit_entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "data": event_data,
            "source": "ProtocolManager"
        }

        # In production, this would write to a secure audit log
        log.info(f"AUDIT: {event_type} - {event_data}")

    async def terminate_session(self, session_id: str):
        """Gracefully terminate a session."""
        async with self.session_lock:
            if session_id in self.active_sessions:
                channel = self.active_sessions[session_id]
                channel.state = SessionState.TERMINATED

                # Secure cleanup of session keys
                if hasattr(channel.aead_cipher, '_key'):
                    secure_erase(channel.aead_cipher._key)

                del self.active_sessions[session_id]
                log.info(f"Session terminated: {session_id}")

    async def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get status information for a session."""
        async with self.session_lock:
            if session_id not in self.active_sessions:
                return None

            channel = self.active_sessions[session_id]

            return {
                "session_id": session_id,
                "state": channel.state.value,
                "peer_id": channel.session_params.peer_identity.peer_id,
                "creation_time": channel.session_params.creation_time,
                "last_activity": channel.session_params.last_activity,
                "message_count": channel.session_params.message_count,
                "key_rotation_count": channel.session_params.key_rotation_count,
                "expired": channel.is_expired(),
                "needs_rotation": channel.needs_key_rotation()
            }


class SecurityError(Exception):
    """Exception raised for security-related errors.

    This exception is raised when security policies are violated
    or when security-critical operations fail.
    """

    def __init__(self, message: str, error_code: str = None, context: dict = None):
        """Initialize SecurityError with detailed context.

        Args:
            message: Detailed error message
            error_code: Optional error code for categorization
            context: Optional dictionary with additional context
        """
        super().__init__(message)
        self.error_code = error_code
        self.context = context or {}

        # Log security error for audit trail
        import logging
        logger = logging.getLogger(__name__)
        logger.error(
            f"Security error: {message} (code={error_code}, context={context})")

# Session management task


async def session_management_task(protocol_manager: ProtocolManager):
    """Background task for session management."""
    while True:
        try:
            # Clean up expired sessions
            cleaned = await protocol_manager.cleanup_expired_sessions()
            if cleaned > 0:
                log.info(f"Cleaned up {cleaned} expired sessions")

            # Check for sessions needing key rotation. Decide under lock,
            # act outside it (terminate_session takes session_lock).
            to_terminate = []
            async with protocol_manager.session_lock:
                rotation_due = [sid for sid, channel in protocol_manager.active_sessions.items()
                                if channel.needs_key_rotation()]
            for session_id in rotation_due:
                # Transport re-key is not implemented on this channel:
                # rotate_session_keys fails closed (False). A session
                # that needs rotation but cannot re-key must NOT keep
                # running on old keys -> terminate to force a fresh
                # handshake (forward secrecy over availability).
                rotated = await protocol_manager.rotate_session_keys(session_id)
                if not rotated:
                    log.warning(
                        f"Rotation unavailable for session {session_id}; "
                        "terminating to force re-handshake (fail-closed)")
                    to_terminate.append(session_id)
            for session_id in to_terminate:
                try:
                    await protocol_manager.terminate_session(session_id)
                except Exception as e:
                    log.error(f"Failed to terminate unrotatable session {session_id}: {e}")

        except Exception as e:
            log.error(f"Session management task error: {e}")

        # Run every 60 seconds
        await asyncio.sleep(60)
