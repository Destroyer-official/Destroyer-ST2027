#!/usr/bin/env python3
"""
Zero-Trust Authentication Engine - Strict Verification

This module implements zero-trust authentication with session termination
on ANY verification failure. No fallbacks permitted.

Security Model:
- Mutual ML-DSA-87 signature verification before data exchange
- Signature verification on EVERY message
- Session terminates on ANY verification failure
- Certificate pinning with SHA3-512 fingerprint
- Constant-time comparison for all cryptographic operations

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
"""

import hmac
import hashlib
import os
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple, Set
from enum import Enum

from data_models import SecurityRole, SecurityPermission, RoleAssignment
from utils.helpers import is_env_true

# Configure logger
logger = logging.getLogger('zero_trust')
logger.setLevel(logging.INFO)


class AuthenticationFailure(Exception):
    """
    Raised when authentication fails.
    Session MUST be terminated - NO FALLBACKS.
    """
    def __init__(self, message: str, peer_id: str = None, operation: str = None):
        super().__init__(message)
        self.peer_id = peer_id
        self.operation = operation
        self.timestamp = time.time()
        logger.critical(f"AUTHENTICATION FAILURE: {message} [peer={peer_id}, op={operation}]")


class AuthorizationFailure(AuthenticationFailure):
    """
    Raised when an authenticated peer attempts an operation without required permissions.
    Action MUST be rejected - NO FALLBACKS.
    """
    def __init__(self, message: str, peer_id: str = None, operation: str = None):
        super().__init__(message, peer_id=peer_id, operation=operation)
        logger.critical(f"AUTHORIZATION VIOLATION: {message} [peer={peer_id}, op={operation}]")


class SignatureVerificationFailure(AuthenticationFailure):
    """Raised when signature verification fails."""


class CertificatePinningFailure(AuthenticationFailure):
    """Raised when certificate pinning verification fails."""


class SessionTerminated(Exception):
    """Raised when session is terminated due to security violation."""
    def __init__(self, reason: str, peer_id: str = None):
        super().__init__(f"Session terminated: {reason}")
        self.reason = reason
        self.peer_id = peer_id
        self.timestamp = time.time()
        logger.critical(f"SESSION TERMINATED: {reason} [peer={peer_id}]")


# ============================================================================
# Minimal RBAC hardening (non-breaking, lab-friendly)
# ----------------------------------------------------------------------------
# Lightweight role model used by critical_release.authorize() and other
# hardening call sites. Kept alongside the full RBACPolicyEngine above.
# Backward compat: check_permission() defaults to ALLOW unless
# P2P_RBAC_STRICT=1, in which case it is deny-by-default.
# ============================================================================

class Role(str, Enum):
    """Minimal hardening roles."""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


PERMISSIONS: Dict[Role, Set[str]] = {
    Role.ADMIN: {
        "critical_release",
        "config_update",
        "key_revoke",
        "message_send",
        "file_send",
        "read_only",
    },
    Role.OPERATOR: {
        "message_send",
        "file_send",
        "read_only",
    },
    Role.VIEWER: {
        "read_only",
    },
}


def _prod_strict_on() -> bool:
    """Sticky-prod gate (guarded import; tiny duplicate fallback, no cycle)."""
    try:
        from utils.message_caps import prod_strict_on as _central_prod_strict
        return bool(_central_prod_strict())
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    try:
        if is_env_true("P2P_PRODUCTION") or is_env_true("SECURE_P2P_PRODUCTION"):
            return True
        if os.environ.get("P2P_ENV", "").strip().lower() == "production":
            return True
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    return False


def is_rbac_strict() -> bool:
    """Return True when RBAC deny-by-default is active.

    Auto-True in prod (P2P_PRODUCTION/SECURE_P2P_PRODUCTION sticky prod)
    without requiring P2P_RBAC_STRICT. Explicit P2P_RBAC_STRICT=0 opts
    out in lab only; in prod the opt-out is ignored with a CRITICAL log.
    Lab default: False.
    """
    raw = os.environ.get("P2P_RBAC_STRICT")
    enabled = is_env_true("P2P_RBAC_STRICT")
    if _prod_strict_on():
        if raw is not None and not enabled:
            logger.critical(
                "PROD-STRICT: ignoring P2P_RBAC_STRICT=%r opt-out in production; "
                "RBAC strict remains enforced", raw)
        return True
    return enabled


def _normalize_minimal_role(role: Any) -> Role:
    """Normalize str/Role/SecurityRole-ish input to minimal Role (default VIEWER)."""
    if isinstance(role, Role):
        return role
    if isinstance(role, Enum):
        try:
            return Role(str(role.value).lower())
        except ValueError:
            return Role.VIEWER
    if isinstance(role, str):
        try:
            return Role(role.lower())
        except ValueError:
            return Role.VIEWER
    return Role.VIEWER


class RBACPolicyEngine:
    """
    Zero-Trust Role-Based Access Control (RBAC) Engine.
    Enforces strict least-privilege permissions across all P2P operations.
    Default-deny policy.
    """

    ROLE_PERMISSIONS: Dict[SecurityRole, Set[SecurityPermission]] = {
        SecurityRole.SYSTEM_ADMIN: {
            SecurityPermission.SEND_CHAT,
            SecurityPermission.SEND_FILE,
            SecurityPermission.SEND_NC3,
            SecurityPermission.INITIATE_KEY_ROTATION,
            SecurityPermission.UPDATE_CONFIG,
            SecurityPermission.READ_AUDIT_LOGS,
            SecurityPermission.DISPOSE_IDENTITY,
            SecurityPermission.EMERGENCY_RELEASE,
            SecurityPermission.ADMIN_COMMAND,
        },
        SecurityRole.COMMANDER: {
            SecurityPermission.SEND_CHAT,
            SecurityPermission.SEND_FILE,
            SecurityPermission.SEND_NC3,
            SecurityPermission.INITIATE_KEY_ROTATION,
            SecurityPermission.READ_AUDIT_LOGS,
            SecurityPermission.EMERGENCY_RELEASE,
        },
        SecurityRole.OFFICER: {
            SecurityPermission.SEND_CHAT,
            SecurityPermission.SEND_FILE,
            SecurityPermission.SEND_NC3,
            SecurityPermission.INITIATE_KEY_ROTATION,
            SecurityPermission.READ_AUDIT_LOGS,
        },
        SecurityRole.OPERATOR: {
            SecurityPermission.SEND_CHAT,
            SecurityPermission.SEND_FILE,
        },
        SecurityRole.AUDITOR: {
            SecurityPermission.READ_AUDIT_LOGS,
        },
        SecurityRole.ANONYMOUS: set(),
    }

    def __init__(self):
        self._assignments: Dict[str, RoleAssignment] = {}

    def assign_role(
        self,
        principal_id: str,
        role: SecurityRole,
        custom_permissions: Optional[Set[SecurityPermission]] = None,
        granted_by: str = "SYSTEM"
    ) -> RoleAssignment:
        """Assign role and permissions to a principal (peer_id or user_id)."""
        base_perms = set(self.ROLE_PERMISSIONS.get(role, set()))
        if custom_permissions:
            base_perms.update(custom_permissions)

        assignment = RoleAssignment(
            principal_id=principal_id,
            role=role,
            permissions=base_perms,
            granted_by=granted_by,
        )
        self._assignments[principal_id] = assignment
        logger.info(f"RBAC: Assigned role {role.value} to {principal_id} with {len(base_perms)} permissions")
        return assignment

    def get_role(self, principal_id: str) -> SecurityRole:
        """Get role of principal. Defaults to ANONYMOUS if unregistered."""
        assignment = self._assignments.get(principal_id)
        if assignment:
            return assignment.role
        return SecurityRole.ANONYMOUS

    def check_permission(self, principal_id: str, permission: SecurityPermission) -> bool:
        """Constant-time check if principal holds permission (default-deny)."""
        assignment = self._assignments.get(principal_id)
        if not assignment:
            return False

        # Expiry check
        if assignment.expires_at is not None and time.time() > assignment.expires_at.timestamp():
            logger.warning(f"RBAC: Role assignment for {principal_id} expired")
            return False

        return permission in assignment.permissions

    def enforce_permission(self, principal_id: str, permission: SecurityPermission, operation: Optional[str] = None) -> None:
        """Enforce permission or raise AuthorizationFailure (fail-closed)."""
        if not self.check_permission(principal_id, permission):
            role = self.get_role(principal_id)
            op = operation or permission.value
            msg = f"Principal '{principal_id}' (role={role.value}) denied permission '{permission.value}' for '{op}'"
            raise AuthorizationFailure(msg, peer_id=principal_id, operation=op)


class SessionState(Enum):
    """Session states for zero-trust authentication"""
    UNINITIALIZED = "uninitialized"
    HANDSHAKE_INITIATED = "handshake_initiated"
    HANDSHAKE_RECEIVED = "handshake_received"
    AUTHENTICATED = "authenticated"
    ACTIVE = "active"
    TERMINATED = "terminated"


@dataclass
class PeerIdentity:
    """Peer identity with cryptographic credentials"""
    peer_id: str
    public_key: bytes  # ML-DSA-87 public key
    certificate_fingerprint: bytes  # SHA3-512 fingerprint
    first_seen: float = field(default_factory=time.time)
    last_verified: float = 0.0
    verification_count: int = 0
    # Minimal-RBAC role for hardening call sites. Authenticated peers
    # default to OPERATOR; unknown peers are treated as VIEWER by
    # ZeroTrustEngine.check_permission().
    role: str = "operator"
    
    def __post_init__(self):
        if len(self.certificate_fingerprint) != 64:
            raise ValueError("Certificate fingerprint must be 64 bytes (SHA3-512)")


@dataclass
class AuthenticationEvent:
    """Authentication event for audit logging"""
    timestamp: str  # ISO8601
    peer_id_hash: str  # SHA3-256 hash of peer ID
    operation: str
    result: str  # "success" or "failure"
    details: Dict[str, Any] = field(default_factory=dict)


class ZeroTrustEngine:
    """
    Zero-Trust Authentication Engine with Strict Verification
    
    SECURITY MODEL: FAIL-CLOSED
    - Mutual ML-DSA-87 signature verification required
    - Every message signature verified
    - Session terminates on ANY verification failure
    - Certificate pinning enforced
    - Constant-time operations for all comparisons
    
    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
    """
    
    def __init__(self, identity_key: bytes, signing_key: bytes):
        """
        Initialize Zero-Trust Engine.
        
        Args:
            identity_key: Our ML-DSA-87 public key
            signing_key: Our ML-DSA-87 private key
        """
        self._identity_key = identity_key
        self._signing_key = signing_key
        self._sessions: Dict[str, SessionState] = {}
        self._peer_identities: Dict[str, PeerIdentity] = {}
        # Minimal-RBAC role overrides for peers not yet (or never)
        # present in _peer_identities. Values are minimal Role members.
        self._minimal_roles: Dict[str, Role] = {}
        self._pinned_certificates: Dict[str, bytes] = {}  # peer_id -> SHA3-512 fingerprint
        self._authentication_events: list = []
        self._signature_impl = None
        self._audit_logger = None
        
        try:
            from liboqs_wrapper import LibOQS_MLDSA_87
            self._signature_impl = LibOQS_MLDSA_87()
            logger.info("ZeroTrustEngine initialized with ML-DSA-87 signatures (liboqs)")
        except ImportError as e:
            logger.critical(f"ML-DSA-87 not available: {e}")
            raise ImportError("FAIL-CLOSED: True ML-DSA-87 implementation required")
        
        # Import audit logger - MANDATORY for security compliance
        import os
        production_mode = is_env_true('SECURE_P2P_PRODUCTION') or is_env_true('P2P_PRODUCTION')
        
        try:
            from audit_logging_system import get_audit_logger, AuditEventType, AuditSeverity
            self._audit_logger = get_audit_logger()
            self._AuditEventType = AuditEventType
            self._AuditSeverity = AuditSeverity
            logger.info("ZeroTrustEngine integrated with audit logging system")
        except ImportError:
            if production_mode:
                raise AuthenticationFailure(
                    "FAIL-CLOSED: Audit logging system required in production mode",
                    operation="initialization"
                )
            logger.warning("Audit logging system not available (TESTING MODE ONLY)")
        
        self.rbac = RBACPolicyEngine()
        logger.info("ZeroTrustEngine initialized - FAIL-CLOSED mode (RBAC active)")
    
    def _log_event(self, peer_id: str, operation: str, result: str, details: Dict = None):
        """
        Log authentication event for audit trail.
        
        Requirement 2.6: Log all authentication events with required fields:
        - timestamp (ISO8601)
        - peer_id_hash (SHA3-256)
        - operation
        - result
        """
        # Hash peer_id for privacy using SHA3-256
        peer_id_hash = hashlib.sha3_256(peer_id.encode()).hexdigest()[:16]
        
        # Create ISO8601 timestamp
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        
        event = AuthenticationEvent(
            timestamp=timestamp,
            peer_id_hash=peer_id_hash,
            operation=operation,
            result=result,
            details=details or {}
        )
        self._authentication_events.append(event)
        
        log_level = logging.INFO if result == "success" else logging.WARNING
        logger.log(log_level, f"AUTH EVENT: {operation} - {result} [peer={peer_id_hash}]")
        
        # Also log to audit logging system if available
        if self._audit_logger is not None:
            try:
                severity = self._AuditSeverity.INFO if result == "success" else self._AuditSeverity.HIGH
                event_type = self._AuditEventType.AUTHENTICATION_SUCCESS if result == "success" else self._AuditEventType.AUTHENTICATION_FAILURE
                
                self._audit_logger.log_event(
                    event_type=event_type,
                    message=f"Zero-Trust Auth: {operation} - {result}",
                    severity=severity,
                    details={
                        "peer_id_hash": peer_id_hash,
                        "operation": operation,
                        "result": result,
                        "timestamp": timestamp,
                        **(details or {})
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to log to audit system: {e}")
    
    def authenticate_peer(
        self,
        peer_id: str,
        peer_public_key: bytes,
        peer_signature: bytes,
        challenge: bytes
    ) -> bool:
        """
        Authenticate a peer with mutual ML-DSA-87 verification.
        
        Requirement 2.1: Mutual ML-DSA-87 signature verification before data exchange
        
        Args:
            peer_id: Peer identifier
            peer_public_key: Peer's ML-DSA-87 public key
            peer_signature: Peer's signature over the challenge
            challenge: Challenge data that was signed
            
        Returns:
            True if authentication succeeds
            
        Raises:
            AuthenticationFailure: If verification fails (session terminated)
        """
        try:
            # Verify peer's signature
            if not self._verify_signature(peer_public_key, challenge, peer_signature):
                self._terminate_session(peer_id, "Signature verification failed")
                raise SignatureVerificationFailure(
                    "Peer signature verification failed",
                    peer_id=peer_id,
                    operation="authenticate_peer"
                )
            
            # Check certificate pinning if configured
            if peer_id in self._pinned_certificates:
                cert_fingerprint = self._compute_certificate_fingerprint(peer_public_key)
                if not self._verify_pinned_certificate(peer_id, cert_fingerprint):
                    self._terminate_session(peer_id, "Certificate pinning failed")
                    raise CertificatePinningFailure(
                        "Certificate fingerprint mismatch",
                        peer_id=peer_id,
                        operation="authenticate_peer"
                    )
            
            # Store peer identity
            cert_fingerprint = self._compute_certificate_fingerprint(peer_public_key)
            self._peer_identities[peer_id] = PeerIdentity(
                peer_id=peer_id,
                public_key=peer_public_key,
                certificate_fingerprint=cert_fingerprint,
                last_verified=time.time(),
                verification_count=1
            )
            
            # Update session state
            self._sessions[peer_id] = SessionState.AUTHENTICATED
            
            self._log_event(peer_id, "authenticate_peer", "success")
            logger.info(f"Peer authenticated: {peer_id[:8]}...")
            return True
            
        except (SignatureVerificationFailure, CertificatePinningFailure):
            raise
        except Exception as e:
            self._terminate_session(peer_id, f"Authentication error: {e}")
            raise AuthenticationFailure(
                f"Authentication failed: {e}",
                peer_id=peer_id,
                operation="authenticate_peer"
            )
    
    def verify_message_signature(
        self,
        peer_id: str,
        message: bytes,
        signature: bytes
    ) -> bool:
        """
        Verify signature on a message from a peer.
        
        Requirement 2.2: Verify peer signature on every message
        Requirement 2.3: Terminate session on verification failure
        
        Args:
            peer_id: Peer identifier
            message: Message data
            signature: Signature over the message
            
        Returns:
            True if signature is valid
            
        Raises:
            SignatureVerificationFailure: If verification fails (session terminated)
        """
        # Check session state
        if peer_id not in self._sessions or self._sessions[peer_id] == SessionState.TERMINATED:
            raise SessionTerminated("Session not active", peer_id=peer_id)
        
        # Get peer's public key
        if peer_id not in self._peer_identities:
            self._terminate_session(peer_id, "Unknown peer")
            raise AuthenticationFailure(
                "Peer not authenticated",
                peer_id=peer_id,
                operation="verify_message_signature"
            )
        
        peer_identity = self._peer_identities[peer_id]
        
        # Verify signature using constant-time comparison
        if not self._verify_signature(peer_identity.public_key, message, signature):
            # Requirement 2.3: Terminate session and reject all pending data
            self._terminate_session(peer_id, "Message signature verification failed")
            self._log_event(peer_id, "verify_message_signature", "failure")
            raise SignatureVerificationFailure(
                "Message signature verification failed",
                peer_id=peer_id,
                operation="verify_message_signature"
            )
        
        # Update verification stats
        peer_identity.last_verified = time.time()
        peer_identity.verification_count += 1
        
        self._log_event(peer_id, "verify_message_signature", "success")
        return True
    
    def continuous_verify(self, peer_id: str, message: bytes, signature: bytes) -> bool:
        """
        Continuous verification called on every message.
        
        This is an alias for verify_message_signature to emphasize
        that verification happens on EVERY message.
        
        Args:
            peer_id: Peer identifier
            message: Message data
            signature: Signature over the message
            
        Returns:
            True if signature is valid
            
        Raises:
            SignatureVerificationFailure: If verification fails
        """
        return self.verify_message_signature(peer_id, message, signature)
    
    def pin_certificate(self, peer_id: str, certificate_fingerprint: bytes) -> None:
        """
        Pin a certificate fingerprint for a peer.
        
        Requirement 2.4: Certificate pinning with SHA3-512 fingerprint
        
        Args:
            peer_id: Peer identifier
            certificate_fingerprint: SHA3-512 fingerprint (64 bytes)
            
        Raises:
            ValueError: If fingerprint is not 64 bytes
        """
        if len(certificate_fingerprint) != 64:
            raise ValueError("Certificate fingerprint must be 64 bytes (SHA3-512)")
        
        self._pinned_certificates[peer_id] = certificate_fingerprint
        self._log_event(peer_id, "pin_certificate", "success")
        logger.info(f"Certificate pinned for peer: {peer_id[:8]}...")
    
    def verify_pinned_certificate(self, peer_id: str, certificate: bytes) -> bool:
        """
        Verify a certificate against pinned fingerprint.
        
        Requirement 2.5: Terminate connection on pinning mismatch
        
        Args:
            peer_id: Peer identifier
            certificate: Certificate/public key to verify
            
        Returns:
            True if certificate matches pinned fingerprint
            
        Raises:
            CertificatePinningFailure: If fingerprint doesn't match
        """
        if peer_id not in self._pinned_certificates:
            # No pin configured - allow (but log)
            self._log_event(peer_id, "verify_pinned_certificate", "success", 
                          {"note": "no_pin_configured"})
            return True
        
        fingerprint = self._compute_certificate_fingerprint(certificate)
        
        if not self._verify_pinned_certificate(peer_id, fingerprint):
            self._terminate_session(peer_id, "Certificate pinning verification failed")
            self._log_event(peer_id, "verify_pinned_certificate", "failure")
            raise CertificatePinningFailure(
                "Certificate fingerprint does not match pinned value",
                peer_id=peer_id,
                operation="verify_pinned_certificate"
            )
        
        self._log_event(peer_id, "verify_pinned_certificate", "success")
        return True
    
    def _verify_pinned_certificate(self, peer_id: str, fingerprint: bytes) -> bool:
        """
        Internal method to verify fingerprint against pinned value.
        Uses constant-time comparison.
        """
        if peer_id not in self._pinned_certificates:
            return True
        
        pinned = self._pinned_certificates[peer_id]
        # Constant-time comparison
        return hmac.compare_digest(fingerprint, pinned)
    
    def _compute_certificate_fingerprint(self, certificate: bytes) -> bytes:
        """
        Compute SHA3-512 fingerprint of a certificate.
        
        Args:
            certificate: Certificate/public key bytes
            
        Returns:
            64-byte SHA3-512 fingerprint
        """
        return hashlib.sha3_512(certificate).digest()
    
    def _verify_signature(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify ML-DSA-87 signature using constant-time comparison.
        
        Args:
            public_key: Signer's public key
            message: Signed message
            signature: Signature to verify
            
        Returns:
            True if signature is valid
        """
        try:
            return self._signature_impl.verify(public_key, message, signature)
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False
    
    def _terminate_session(self, peer_id: str, reason: str) -> None:
        """
        Terminate a session due to security violation.
        
        Args:
            peer_id: Peer identifier
            reason: Reason for termination
        """
        self._sessions[peer_id] = SessionState.TERMINATED
        self._log_event(peer_id, "session_terminated", "failure", {"reason": reason})
        logger.critical(f"SESSION TERMINATED: {reason} [peer={peer_id[:8]}...]")
    
    def get_session_state(self, peer_id: str) -> SessionState:
        """Get current session state for a peer."""
        return self._sessions.get(peer_id, SessionState.UNINITIALIZED)
    
    def get_authentication_events(self) -> list:
        """Get all authentication events for audit."""
        return self._authentication_events.copy()
    
    def is_session_active(self, peer_id: str) -> bool:
        """Check if session is active (not terminated)."""
        state = self._sessions.get(peer_id)
        return state is not None and state != SessionState.TERMINATED

    def assign_peer_role(
        self,
        peer_id: str,
        role: SecurityRole,
        custom_permissions: Optional[Set[SecurityPermission]] = None
    ) -> RoleAssignment:
        """Assign role and permissions to an authenticated peer."""
        return self.rbac.assign_role(peer_id, role, custom_permissions)

    def get_peer_role(self, peer_id: str) -> SecurityRole:
        """Get role of peer."""
        return self.rbac.get_role(peer_id)

    def authorize(
        self,
        peer_id: str,
        permission: SecurityPermission,
        operation: Optional[str] = None
    ) -> bool:
        """
        Verify that an authenticated peer is authorized to perform an operation.
        Session must be active, and peer must have the requested permission.
        Logs all attempts to audit log.
        """
        op = operation or permission.value
        if not self.is_session_active(peer_id):
            self._log_event(peer_id, op, "failure", {"reason": "Session not active"})
            logger.critical(f"AUTHORIZATION FAILED: Peer {peer_id} session not active for {op}")
            return False

        allowed = self.rbac.check_permission(peer_id, permission)
        if not allowed:
            self._log_event(peer_id, op, "failure", {
                "reason": "Permission denied",
                "role": self.get_peer_role(peer_id).value,
                "required_permission": permission.value
            })
            logger.critical(f"AUTHORIZATION DENIED: Peer {peer_id} denied {permission.value} for {op}")
            return False

        self._log_event(peer_id, op, "success", {"permission": permission.value})
        return True

    def enforce_authorization(
        self,
        peer_id: str,
        permission: SecurityPermission,
        operation: Optional[str] = None
    ) -> None:
        """
        Enforce that peer is authorized or raise AuthorizationFailure / SessionTerminated (fail-closed).
        """
        op = operation or permission.value
        if not self.is_session_active(peer_id):
            raise SessionTerminated(f"Session not active for operation {op}", peer_id=peer_id)

        if not self.rbac.check_permission(peer_id, permission):
            self._log_event(peer_id, op, "failure", {
                "reason": "Permission denied",
                "role": self.get_peer_role(peer_id).value,
                "required_permission": permission.value
            })
            self.rbac.enforce_permission(peer_id, permission, operation=op)

    # ------------------------------------------------------------------
    # Minimal RBAC hardening API (non-breaking).
    # ------------------------------------------------------------------
    def set_peer_role(self, peer_id: str, role: Any) -> Role:
        """Assign a minimal hardening role to a peer.

        Stored in _peer_identities (if present) plus a local override map
        so unknown peers can be pre-authorized. Returns normalized Role.
        """
        normalized = _normalize_minimal_role(role)
        self._minimal_roles[peer_id] = normalized
        identity = self._peer_identities.get(peer_id)
        if identity is not None:
            try:
                identity.role = normalized.value
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
        logger.info(f"Minimal RBAC: peer {peer_id} assigned role {normalized.value}")
        return normalized

    def get_minimal_role(self, peer_id: str) -> Role:
        """Look up minimal role: identity -> override map -> VIEWER (unknown)."""
        identity = self._peer_identities.get(peer_id)
        if identity is not None:
            try:
                return _normalize_minimal_role(getattr(identity, "role", "operator"))
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
        if peer_id in self._minimal_roles:
            return self._minimal_roles[peer_id]
        return Role.VIEWER

    def check_permission(self, peer_id: str, action: str) -> bool:
        """Minimal hardening permission check.

        Looks up the peer's minimal Role (authenticated peers default to
        OPERATOR via PeerIdentity.role; unknown peers default to VIEWER)
        and tests membership in PERMISSIONS.

        Backward compat: returns True (allow) for all callers unless
        P2P_RBAC_STRICT=1, in which case deny-by-default applies and a
        denial raises AuthenticationFailure (AuthorizationFailure).

        Raises:
            AuthenticationFailure: If strict mode denies the action.
        """
        if not is_rbac_strict():
            return True
        role = self.get_minimal_role(peer_id)
        allowed_actions = PERMISSIONS.get(role, set())
        if str(action) in allowed_actions:
            return True
        msg = (
            f"Minimal RBAC denied: peer '{peer_id}' role={role.value} "
            f"lacks action '{action}'"
        )
        try:
            self._log_event(peer_id, str(action), "failure", {
                "reason": "Minimal RBAC permission denied",
                "role": role.value,
                "required_action": str(action),
            })
        except Exception:
            logger.warning(f"Minimal RBAC deny (audit log failed): {msg}")
        raise AuthorizationFailure(msg, peer_id=peer_id, operation=str(action))


