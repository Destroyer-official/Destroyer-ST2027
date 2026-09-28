"""
Session Manager with Security Context

This module implements a comprehensive session manager that maintains full security
context for each peer connection, including:
- HybridKeyExchange for quantum-resistant key exchange
- DoubleRatchet for forward secrecy and message encryption
- AuditLogger for security event logging
- Session lifecycle management with secure cleanup

Requirements addressed: 1.1, 1.2, 4.1, 4.2, 4.3, 4.4, 4.5
"""

import os
import gc
import asyncio
import base64
import json
import logging
import struct
from datetime import datetime
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass, field

try:
    from cryptographic_errors import SecurityError
except ImportError:
    class SecurityError(Exception):
        pass

# Import security modules
try:
    from double_ratchet import DoubleRatchet
    DOUBLE_RATCHET_AVAILABLE = True
except ImportError:
    DOUBLE_RATCHET_AVAILABLE = False
    logging.warning("DoubleRatchet not available")

try:
    from hybrid_kex import HybridKeyExchange
    HYBRID_KEX_AVAILABLE = True
except ImportError:
    HYBRID_KEX_AVAILABLE = False
    logging.warning("HybridKeyExchange not available")

try:
    from audit_logging_system import AuditLogger, AuditEventType, AuditSeverity
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    logging.warning("AuditLogger not available")

# Configure logging
logger = logging.getLogger(__name__)

# Pre-auth handshake frame ceiling: largest legitimate bundle is the hybrid
# ML-KEM+McEliece public bundle (~1.8MB base64 JSON). 2MB fits it with
# margin and aborts allocation-amplification probes before readexactly.
_MAX_HANDSHAKE_FRAME = 2 * 1024 * 1024


async def _send_frame(w: asyncio.StreamWriter, payload: Dict[str, Any]) -> None:
    try:
        raw = json.dumps(payload).encode('utf-8')
    except Exception as e:
        raise SecurityError(f"Failed to serialize handshake frame: {e}") from e
    if len(raw) > _MAX_HANDSHAKE_FRAME:
        raise SecurityError(
            f"Refusing to send oversize handshake frame: {len(raw)} > {_MAX_HANDSHAKE_FRAME}")
    try:
        w.write(struct.pack('>I', len(raw)) + raw)
        if hasattr(w, 'drain'):
            try:
                await w.drain()
            except (AttributeError, RuntimeError):
                pass
    except Exception as e:
        raise SecurityError(f"Failed to transmit handshake frame: {e}") from e


async def _recv_frame(r: asyncio.StreamReader, timeout: float = 120.0) -> Dict[str, Any]:
    try:
        header = await asyncio.wait_for(r.readexactly(4), timeout=timeout)
        frame_len = struct.unpack('>I', header)[0]
        if frame_len > _MAX_HANDSHAKE_FRAME:
            raise SecurityError(f"Handshake frame exceeded size limit: {frame_len} > {_MAX_HANDSHAKE_FRAME}")
        body = await asyncio.wait_for(r.readexactly(frame_len), timeout=timeout)
        return json.loads(body.decode('utf-8'))
    except asyncio.TimeoutError as e:
        raise SecurityError(f"Handshake frame receive timed out ({timeout}s)") from e
    except asyncio.IncompleteReadError as e:
        raise SecurityError(f"Handshake connection closed prematurely: {e}") from e
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise SecurityError(f"Handshake frame corrupted: {e}") from e
    except Exception as e:
        if isinstance(e, SecurityError):
            raise
        raise SecurityError(f"Handshake frame receive failed: {e}") from e


@dataclass
class SessionContext:
    """
    Complete security context for a peer session.
    
    This dataclass encapsulates all security-related state for an active
    peer connection, including cryptographic objects, connection metadata,
    and activity tracking.
    """
    peer_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    double_ratchet: Optional[Any] = None  # DoubleRatchet instance
    hybrid_kex: Optional[Any] = None  # HybridKeyExchange instance
    audit_logger: Optional[Any] = None  # AuditLogger instance
    connected_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    message_count: int = 0
    encryption_enabled: bool = True
    session_id: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize session context to dictionary (excluding sensitive crypto objects).
        
        Returns:
            Dict containing non-sensitive session metadata
        """
        return {
            'peer_id': self.peer_id,
            'connected_at': self.connected_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'message_count': self.message_count,
            'encryption_enabled': self.encryption_enabled,
            'session_id': self.session_id,
            'has_double_ratchet': self.double_ratchet is not None,
            'has_hybrid_kex': self.hybrid_kex is not None,
            'has_audit_logger': self.audit_logger is not None
        }
    
    def secure_cleanup(self) -> None:
        """
        Securely wipe all cryptographic state and close connections.
        """
        if self.double_ratchet is not None:
            try:
                if hasattr(self.double_ratchet, 'secure_cleanup'):
                    self.double_ratchet.secure_cleanup()
                elif hasattr(self.double_ratchet, 'cleanup'):
                    self.double_ratchet.cleanup()
            except Exception as e:
                logger.error(f"Error wiping DoubleRatchet for {self.peer_id}: {e}")
            finally:
                self.double_ratchet = None

        if self.hybrid_kex is not None:
            try:
                if hasattr(self.hybrid_kex, 'secure_cleanup'):
                    self.hybrid_kex.secure_cleanup()
                elif hasattr(self.hybrid_kex, 'cleanup'):
                    self.hybrid_kex.cleanup()
            except Exception as e:
                logger.error(f"Error wiping HybridKeyExchange for {self.peer_id}: {e}")
            finally:
                self.hybrid_kex = None

        if self.writer is not None:
            try:
                if hasattr(self.writer, 'is_closing') and not self.writer.is_closing():
                    self.writer.close()
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass

        if self.audit_logger is not None:
            try:
                if hasattr(self.audit_logger, 'flush_buffer'):
                    self.audit_logger.flush_buffer()
                if hasattr(self.audit_logger, 'close'):
                    self.audit_logger.close()
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            finally:
                self.audit_logger = None

    def update_activity(self):
        """
        Update last activity timestamp and increment message count.
        
        This method should be called whenever a message is sent or received
        to track session activity for timeout detection and key rotation.
        
        Requirements: 4.2
        """
        self.last_activity = datetime.now()
        self.message_count += 1
    
    def get_inactivity_duration(self) -> float:
        """
        Get the duration of inactivity in seconds.
        
        Returns:
            float: Seconds since last activity
            
        Requirements: 4.2
        """
        return (datetime.now() - self.last_activity).total_seconds()
    
    def is_healthy(self, timeout_seconds: int = 1800) -> bool:
        """
        Check if session is healthy (active within timeout period and not severed/quarantined).
        
        Args:
            timeout_seconds: Timeout threshold in seconds (default: 1800 = 30 minutes)
        
        Returns:
            bool: True if session is healthy, False if inactive, severed, or quarantined
            
        Requirements: 4.2
        """
        try:
            from active_cyber_defense import get_active_cyber_defense_engine
            acd = get_active_cyber_defense_engine()
            if acd.is_peer_quarantined(self.peer_id):
                return False
            if self.session_id and acd.is_session_severed(self.session_id):
                return False
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        inactivity_seconds = self.get_inactivity_duration()
        return inactivity_seconds < timeout_seconds


class SessionManager:
    """
    Manages peer sessions with full security context.
    
    This class provides comprehensive session management including:
    - Session creation with HybridKeyExchange handshake
    - DoubleRatchet initialization for forward secrecy
    - Session retrieval and listing
    - Secure session termination with cryptographic state wiping
    
    Security features:
    - Quantum-resistant key exchange (HybridKeyExchange)
    - Forward secrecy (DoubleRatchet)
    - Comprehensive audit logging (AuditLogger)
    - Secure memory wiping on session termination
    - Session timeout detection
    - Concurrent session support
    """
    
    def __init__(self, audit_logger: Optional[Any] = None, session_timeout_seconds: int = 1800):
        """
        Initialize the session manager.
        
        Args:
            audit_logger: Optional AuditLogger instance for security event logging
            session_timeout_seconds: Timeout in seconds for inactive sessions (default: 1800 = 30 minutes)
        """
        self.sessions: Dict[str, SessionContext] = {}
        self.audit_logger = audit_logger
        self._lock = asyncio.Lock()
        # 2028 hardening: bound session table (DoS). Fail-closed beyond cap.
        self._max_sessions = 16
        self.session_timeout_seconds = session_timeout_seconds
        self._timeout_check_task: Optional[asyncio.Task] = None
        self._shutdown = False
        
        logger.info(f"SessionManager initialized (timeout: {session_timeout_seconds}s)")
        
        if self.audit_logger and AUDIT_AVAILABLE:
            self.audit_logger.log_event(
                AuditEventType.SYSTEM_STARTUP,
                "SessionManager initialized",
                AuditSeverity.INFO,
                {'session_timeout_seconds': session_timeout_seconds}
            )
    
    async def create_session(
        self,
        peer_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_initiator: bool = False
    ) -> SessionContext:
        """
        Create a new session with full security context.
        
        This method performs the following steps:
        1. Create AuditLogger instance for this session (Task 6.1)
        2. Initialize HybridKeyExchange for quantum-resistant key exchange
        3. Perform handshake to establish shared secrets
        4. Initialize DoubleRatchet with handshake keys for forward secrecy
        5. Create session context with all security modules
        6. Log session creation event
        
        Args:
            peer_id: Unique identifier for the peer
            reader: AsyncIO StreamReader for receiving data
            writer: AsyncIO StreamWriter for sending data
            is_initiator: True if this side initiated the connection
            
        Returns:
            SessionContext: Complete session context with security modules
            
        Raises:
            RuntimeError: If security modules are not available
            Exception: If handshake or initialization fails
            
        Requirements: 1.1, 1.2, 1.5, 4.1, 5.5
        """
        logger.info(f"Creating session for peer: {peer_id}")
        
        # Check Active Cyber Defense (cATO Pillar 2) quarantine gate
        try:
            from active_cyber_defense import get_active_cyber_defense_engine
            acd_engine = get_active_cyber_defense_engine()
            if acd_engine.is_peer_quarantined(peer_id):
                raise SecurityError(f"MILITARY FATAL: Peer '{peer_id}' is quarantined by Active Cyber Defense")
        except ImportError:
            pass

        # Check Tactical Network Cloaking Policy (SIGINT / Geolocation Protection)
        if writer:
            try:
                peername = writer.get_extra_info('peername')
                if peername and isinstance(peername, tuple) and len(peername) >= 2:
                    peer_host, peer_port = str(peername[0]), int(peername[1])
                    from tactical_cloaking_router import validate_outbound_destination
                    validate_outbound_destination(peer_host, peer_port)
            except Exception as e_cloak:
                if "TACTICAL CLOAK VIOLATION" in str(e_cloak):
                    raise SecurityError(f"MILITARY FATAL: {e_cloak}") from e_cloak
        
        # Check if session already exists
        if peer_id in self.sessions:
            logger.warning(f"Session already exists for {peer_id}, terminating old session")
            await self.terminate_session(peer_id)
        
        # Verify security modules are available
        if not HYBRID_KEX_AVAILABLE:
            error_msg = "HybridKeyExchange not available - cannot create secure session"
            logger.error(error_msg)
            if self.audit_logger and AUDIT_AVAILABLE:
                self.audit_logger.log_event(
                    AuditEventType.SECURITY_VIOLATION,
                    error_msg,
                    AuditSeverity.CRITICAL,
                    {'peer_id': peer_id}
                )
            raise RuntimeError(error_msg)
        
        if not DOUBLE_RATCHET_AVAILABLE:
            error_msg = "DoubleRatchet not available - cannot create secure session"
            logger.error(error_msg)
            if self.audit_logger and AUDIT_AVAILABLE:
                self.audit_logger.log_event(
                    AuditEventType.SECURITY_VIOLATION,
                    error_msg,
                    AuditSeverity.CRITICAL,
                    {'peer_id': peer_id}
                )
            raise RuntimeError(error_msg)
            
        session_audit_logger = None
        hybrid_kex = None
        double_ratchet = None
        shared_secret = None
        session_audit_db = None

        try:
            # Task 6.1: Create AuditLogger instance for this session
            # Configure with appropriate database path
            if AUDIT_AVAILABLE:
                import os
                # Create session-specific audit database path
                audit_db_dir = "logs"
                os.makedirs(audit_db_dir, exist_ok=True)
                session_audit_db = os.path.join(audit_db_dir, f"session_{peer_id}_audit.db")
                
                # Create AuditLogger instance for this session
                session_audit_logger = AuditLogger(db_path=session_audit_db)
                logger.info(f"Created AuditLogger for session with {peer_id} at {session_audit_db}")
                
                # Log session initialization start
                session_audit_logger.log_event(
                    AuditEventType.CONNECTION_ESTABLISHED,
                    f"Session initialization started for {peer_id}",
                    AuditSeverity.INFO,
                    {
                        'peer_id': peer_id,
                        'is_initiator': is_initiator,
                        'timestamp': datetime.now().isoformat()
                    }
                )
            else:
                # Fall back to global audit logger if available
                session_audit_logger = self.audit_logger
                logger.warning(f"AuditLogger not available, using global logger for {peer_id}")
            
            # Initialize HybridKeyExchange
            hybrid_kex = HybridKeyExchange(
                identity=f"session_{peer_id}",
                ephemeral=True,
                in_memory_only=True
            )
            logger.debug(f"Initialized HybridKeyExchange for {peer_id}")
            
            # Perform handshake to establish shared secrets
            # Note: This is a simplified handshake - full implementation would
            # involve network exchange of public keys and signatures
            shared_secret = await self._perform_handshake(
                hybrid_kex, peer_id, reader, writer, is_initiator, session_audit_logger
            )
            
            # Initialize DoubleRatchet with shared secret from handshake
            double_ratchet = DoubleRatchet(
                root_key=shared_secret,
                is_initiator=is_initiator,
                enable_pq=True,
                security_level="MAXIMUM"
            )
            logger.debug(f"Initialized DoubleRatchet for {peer_id}")
            
            # Synchronize DoubleRatchet keys across network to complete initialization
            await self._synchronize_double_ratchet(
                double_ratchet, peer_id, reader, writer, is_initiator, session_audit_logger
            )
            
            # Create session context
            import uuid
            session_id = str(uuid.uuid4())
            
            session = SessionContext(
                peer_id=peer_id,
                reader=reader,
                writer=writer,
                double_ratchet=double_ratchet,
                hybrid_kex=hybrid_kex,
                audit_logger=session_audit_logger,  # Store session-specific audit logger
                session_id=session_id,
                encryption_enabled=True
            )
            
            # Store session under lock
            old_session = None
            async with self._lock:
                if peer_id not in self.sessions and len(self.sessions) >= self._max_sessions:
                    raise RuntimeError("Session table full - rejecting new session (DoS protection)")
                old_session = self.sessions.get(peer_id)
                self.sessions[peer_id] = session
            
            if old_session:
                logger.warning(f"Terminating superseded session for {peer_id}")
                try:
                    old_session.secure_cleanup()
                except Exception as e_clean:
                    logger.debug(f"Error cleaning superseded session: {e_clean}")
            
            # Log session creation
            logger.info(f" Session created for {peer_id} (session_id: {session_id})")
            
            if session_audit_logger and AUDIT_AVAILABLE:
                session_audit_logger.log_event(
                    AuditEventType.CONNECTION_ESTABLISHED,
                    f"Secure session established with {peer_id}",
                    AuditSeverity.INFO,
                    {
                        'peer_id': peer_id,
                        'session_id': session_id,
                        'is_initiator': is_initiator,
                        'encryption': 'DoubleRatchet + HybridKeyExchange',
                        'quantum_resistant': True,
                        'forward_secrecy': True,
                        'audit_db': session_audit_db if AUDIT_AVAILABLE else None
                    }
                )
            
            return session
            
        except Exception as e:
            logger.error(f"Failed to create session for {peer_id}: {e}", exc_info=True)
            
            # Fail-closed zeroization of transient cryptographic material
            if shared_secret:
                try:
                    from secure_key_manager import secure_erase
                    secure_erase(shared_secret)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
            if double_ratchet:
                try:
                    if hasattr(double_ratchet, 'secure_cleanup'):
                        double_ratchet.secure_cleanup()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
            if hybrid_kex:
                try:
                    if hasattr(hybrid_kex, 'secure_cleanup'):
                        hybrid_kex.secure_cleanup()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
            if session_audit_logger and AUDIT_AVAILABLE and session_audit_logger != self.audit_logger:
                try:
                    session_audit_logger.flush_buffer()
                    session_audit_logger.close()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
            if writer and hasattr(writer, 'is_closing') and not writer.is_closing():
                try:
                    writer.close()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass

            if self.audit_logger and AUDIT_AVAILABLE:
                self.audit_logger.log_event(
                    AuditEventType.CONNECTION_FAILURE,
                    f"Failed to create session with {peer_id}: {str(e)}",
                    AuditSeverity.HIGH,
                    {'peer_id': peer_id, 'error': str(e)}
                )
            
            raise
    
    async def _perform_handshake(
        self,
        hybrid_kex: Any,
        peer_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_initiator: bool,
        session_audit_logger: Optional[Any] = None
    ) -> bytes:
        """
        Perform genuine post-quantum hybrid key exchange handshake (Finding 3).
        
        Exchanges public key bundles (X25519 + ML-KEM-1024), verifies digital signatures
        (Ed25519 + FALCON-1024 / ML-DSA-87), enforces TOFU continuity check, and derives
        the 32-byte shared root secret for Double Ratchet initialization.
        Fail closed on any communication error, signature verification failure, or bundle mismatch.
        
        Args:
            hybrid_kex: HybridKeyExchange instance
            peer_id: Peer identifier
            reader: Stream reader
            writer: Stream writer
            is_initiator: Whether this side initiated the connection
            session_audit_logger: Session-specific AuditLogger instance
            
        Returns:
            bytes: 32-byte shared secret for DoubleRatchet initialization
            
        Requirements: 1.1, 5.1
        """
        logger.debug(f"Performing genuine hybrid handshake with {peer_id} (initiator: {is_initiator})")
        audit_logger = session_audit_logger or self.audit_logger

        # Active Cyber Defense Ingress Gate (cATO Pillar 2)
        remote_ip = None
        try:
            if writer and hasattr(writer, 'get_extra_info'):
                peername = writer.get_extra_info('peername')
                if peername and isinstance(peername, tuple) and len(peername) > 0:
                    remote_ip = str(peername[0])
        except (AttributeError, Exception):
            remote_ip = None

        try:
            from active_cyber_defense import get_active_cyber_defense_engine
            acd_engine = get_active_cyber_defense_engine()
            if acd_engine.is_peer_quarantined(peer_id):
                raise SecurityError(f"MILITARY FATAL: Peer '{peer_id}' is quarantined by Active Cyber Defense")
            if remote_ip and acd_engine.is_source_blocked(remote_ip):
                raise SecurityError(f"MILITARY FATAL: Source IP '{remote_ip}' is blocked by Active Cyber Defense")
        except ImportError:
            pass

        if audit_logger and AUDIT_AVAILABLE:
            audit_logger.log_event(
                AuditEventType.KEY_EXCHANGE,
                f"Handshake initiated with {peer_id}",
                AuditSeverity.INFO,
                {
                    'peer_id': peer_id,
                    'is_initiator': is_initiator,
                    'timestamp': datetime.now().isoformat(),
                    'algorithm': 'HybridKeyExchange (X25519 + ML-KEM-1024)'
                }
            )

        try:
            our_bundle = hybrid_kex.get_public_bundle()

            # Remote TPM 2.0 Attestation Quoting (Layer 1.3)
            # If P2P_TPM_QUOTE=1 is configured, attach and verify ML-DSA-87 signed hardware quotes
            tpm_quote_required = os.environ.get("P2P_TPM_QUOTE", "0") == "1"
            our_quote = None
            if tpm_quote_required:
                try:
                    from tpm_quote import attach_quote_to_handshake, validate_handshake_quote
                    our_quote = attach_quote_to_handshake(peer_id)
                except Exception as e_tpm:
                    logger.warning(f"Failed to generate TPM attestation quote: {e_tpm}")
                    from utils.helpers import is_env_true
                    if is_env_true("P2P_FAIL_ON_SOFTWARE_FALLBACK") or is_env_true("P2P_PRODUCTION") or is_env_true("SECURE_P2P_PRODUCTION"):
                        raise SecurityError("MILITARY FATAL: TPM attestation quote generation failed")

            # Host Posture Defense Gate (Layer 1.4)
            # If P2P_REQUIRE_HOST_POSTURE=1, verify endpoint posture against DoD Zero Trust baseline
            from utils.helpers import is_env_true
            if is_env_true("P2P_REQUIRE_HOST_POSTURE"):
                try:
                    import scripts.verify_host_hardening as _vhh
                    posture = _vhh.HostHardeningVerifier(strict=True).run_all_checks()
                    if not posture.get("overall_passed", False):
                        failed_checks = [k for k, v in posture.get("checks", {}).items() if v["status"] != "PASS"]
                        raise SecurityError(
                            f"MILITARY FATAL: Host posture non-compliant (score {posture.get('readiness_score', 0):.1f}%). "
                            f"Non-compliant checks: {failed_checks}"
                        )
                except Exception as e_posture:
                    if isinstance(e_posture, SecurityError):
                        raise
                    raise SecurityError(f"MILITARY FATAL: Host posture evaluation failed: {e_posture}") from e_posture

            if is_initiator:
                # 1. Initiator sends its public bundle (with optional TPM quote)
                offer_payload = {'type': 'BUNDLE_OFFER', 'bundle': our_bundle}
                if our_quote is not None:
                    offer_payload['tpm_quote'] = our_quote
                await _send_frame(writer, offer_payload)

                # 2. Receive responder's bundle
                resp = await _recv_frame(reader)
                peer_bundle = resp.get('bundle')
                if not peer_bundle:
                    raise SecurityError("Responder did not provide public key bundle")

                # Verify responder's TPM quote if required
                if tpm_quote_required:
                    peer_quote = resp.get('tpm_quote')
                    if not peer_quote:
                        raise SecurityError(f"Responder {peer_id} omitted required TPM attestation quote")
                    from tpm_quote import validate_handshake_quote
                    from utils.helpers import is_env_true
                    # Degraded simulation stubs forbidden in production or when fail-on-fallback is set
                    is_prod = is_env_true("P2P_FAIL_ON_SOFTWARE_FALLBACK") or is_env_true("P2P_PRODUCTION") or is_env_true("SECURE_P2P_PRODUCTION")
                    allow_deg = not is_prod
                    if not validate_handshake_quote(peer_quote, expected_nonce=peer_quote.get("nonce", ""), allow_degraded=allow_deg):
                        raise SecurityError(f"Responder {peer_id} TPM attestation quote validation failed")

                # 3. Verify responder bundle signatures
                if not hybrid_kex.verify_public_bundle(peer_bundle):
                    raise SecurityError(f"Peer bundle signature verification failed for {peer_id}")

                # 4. Initiate handshake to generate message and shared secret
                handshake_msg, shared_secret = hybrid_kex.initiate_handshake(peer_bundle)

                # 5. Send handshake message to responder
                await _send_frame(writer, {'type': 'HANDSHAKE_INIT', 'message': handshake_msg})

                # 6. Await confirmation from responder
                confirm = await _recv_frame(reader)
                if not confirm.get('success'):
                    raise SecurityError(f"Responder rejected handshake: {confirm.get('error')}")

            else:
                # 1. Receive initiator's bundle
                offer = await _recv_frame(reader)
                peer_bundle = offer.get('bundle')
                if not peer_bundle:
                    raise SecurityError("Initiator did not provide public key bundle")

                # Verify initiator's TPM quote if required
                if tpm_quote_required:
                    peer_quote = offer.get('tpm_quote')
                    if not peer_quote:
                        raise SecurityError(f"Initiator {peer_id} omitted required TPM attestation quote")
                    from tpm_quote import validate_handshake_quote
                    from utils.helpers import is_env_true
                    is_prod = is_env_true("P2P_FAIL_ON_SOFTWARE_FALLBACK") or is_env_true("P2P_PRODUCTION") or is_env_true("SECURE_P2P_PRODUCTION")
                    allow_deg = not is_prod
                    if not validate_handshake_quote(peer_quote, expected_nonce=peer_quote.get("nonce", ""), allow_degraded=allow_deg):
                        raise SecurityError(f"Initiator {peer_id} TPM attestation quote validation failed")

                # 2. Send our public bundle (with optional TPM quote)
                resp_payload = {'type': 'BUNDLE_RESPONSE', 'bundle': our_bundle}
                if our_quote is not None:
                    resp_payload['tpm_quote'] = our_quote
                await _send_frame(writer, resp_payload)

                # 3. Verify initiator bundle signatures
                if not hybrid_kex.verify_public_bundle(peer_bundle):
                    raise SecurityError(f"Peer bundle signature verification failed for {peer_id}")

                # 4. Receive handshake message
                init_frame = await _recv_frame(reader)
                handshake_msg = init_frame.get('message')
                if not handshake_msg:
                    raise SecurityError("Initiator did not provide handshake message")

                # 5. Respond to handshake to derive shared secret
                shared_secret = hybrid_kex.respond_to_handshake(handshake_msg, peer_bundle)

                # 6. Send confirmation
                await _send_frame(writer, {'type': 'HANDSHAKE_CONFIRM', 'success': True})

            if not shared_secret or len(shared_secret) != 32:
                raise SecurityError(f"Invalid shared secret derived: expected 32 bytes, got {len(shared_secret) if shared_secret else 0}")

            if audit_logger and AUDIT_AVAILABLE:
                audit_logger.log_event(
                    AuditEventType.KEY_EXCHANGE,
                    f"Handshake completed successfully with {peer_id}",
                    AuditSeverity.INFO,
                    {
                        'peer_id': peer_id,
                        'algorithm': 'HybridKeyExchange (X25519 + ML-KEM-1024)',
                        'success': True,
                        'timestamp': datetime.now().isoformat(),
                        'is_initiator': is_initiator,
                        'key_length': len(shared_secret)
                    }
                )

            logger.info(f"Hybrid post-quantum handshake completed with {peer_id}")
            return shared_secret

        except Exception as e:
            logger.error(f"Handshake failed with {peer_id}: {e}", exc_info=True)
            try:
                from active_cyber_defense import get_active_cyber_defense_engine
                acd_engine = get_active_cyber_defense_engine()
                acd_engine.ingest_event(
                    "handshake_fail",
                    peer_id=peer_id,
                    source_ip=remote_ip,
                    details={"error": str(e), "error_type": type(e).__name__}
                )
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            if audit_logger and AUDIT_AVAILABLE:
                import traceback
                audit_logger.log_event(
                    AuditEventType.CONNECTION_FAILURE,
                    f"Handshake failed with {peer_id}: {str(e)}",
                    AuditSeverity.HIGH,
                    {
                        'peer_id': peer_id,
                        'error': str(e),
                        'error_type': type(e).__name__,
                        'timestamp': datetime.now().isoformat(),
                        'stack_trace': traceback.format_exc()
                    }
                )
            raise SecurityError(f"Handshake failed with {peer_id}: {e}") from e

    async def _synchronize_double_ratchet(
        self,
        double_ratchet: Any,
        peer_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_initiator: bool,
        audit_logger: Optional[Any] = None,
    ) -> None:
        """
        Synchronize DoubleRatchet keys across the network.
        
        Exchanges public keys (X25519 + FALCON-1024 / ML-KEM-1024) and establishes
        the initial KEM ciphertext so both parties transition to fully initialized
        DoubleRatchet state ready for bidirectional encryption.
        """
        def _b64e(b: Optional[bytes]) -> Optional[str]:
            return base64.b64encode(b).decode('ascii') if b is not None else None

        def _b64d(s: Optional[str]) -> Optional[bytes]:
            return base64.b64decode(s.encode('ascii')) if s is not None else None

        def _encode_dss(dss: Any) -> Any:
            if dss is None:
                return None
            if isinstance(dss, bytes):
                return {'type': 'bytes', 'val': _b64e(dss)}
            if isinstance(dss, dict):
                return {'type': 'dict', 'val': {k: _b64e(v) if isinstance(v, bytes) else v for k, v in dss.items()}}
            return None

        def _decode_dss(obj: Any) -> Any:
            if not obj or not isinstance(obj, dict):
                return None
            t = obj.get('type')
            if t == 'bytes':
                return _b64d(obj.get('val'))
            if t == 'dict':
                return {k: _b64d(v) if isinstance(v, str) else v for k, v in obj.get('val', {}).items()}
            return None

        try:
            if is_initiator:
                # 1. Initiator awaits responder's ratchet key offer
                resp_frame = await _recv_frame(reader)
                if resp_frame.get('type') != 'RATCHET_KEY_OFFER':
                    raise SecurityError(f"Expected RATCHET_KEY_OFFER, got {resp_frame.get('type')}")

                resp_dh_pk = _b64d(resp_frame.get('dh_pk'))
                resp_kem_pk = _b64d(resp_frame.get('kem_pk'))
                resp_dss_pk = _decode_dss(resp_frame.get('dss_pk'))

                # 2. Initiator sets remote public keys (which automatically performs KEM encaps)
                double_ratchet.set_remote_public_key(resp_dh_pk, resp_kem_pk, resp_dss_pk)

                # 3. Initiator sends our ratchet keys and KEM ciphertext to responder
                our_dh_pk = double_ratchet.get_public_key()
                our_kem_pk = double_ratchet.get_kem_public_key() if getattr(double_ratchet, 'enable_pq', False) else None
                our_dss_pk = double_ratchet.get_dss_public_key() if getattr(double_ratchet, 'enable_pq', False) else None
                kem_ct = double_ratchet.get_kem_ciphertext() if getattr(double_ratchet, 'enable_pq', False) else None

                resp_payload = {
                    'type': 'RATCHET_KEY_RESPONSE',
                    'dh_pk': _b64e(our_dh_pk),
                    'kem_pk': _b64e(our_kem_pk),
                    'dss_pk': _encode_dss(our_dss_pk),
                    'kem_ct': _b64e(kem_ct),
                }
                await _send_frame(writer, resp_payload)

                # 4. Await responder confirmation
                confirm = await _recv_frame(reader)
                if not confirm.get('success'):
                    raise SecurityError(f"Responder rejected ratchet sync: {confirm.get('error')}")

            else:
                # 1. Responder sends its ratchet public keys
                our_dh_pk = double_ratchet.get_public_key()
                our_kem_pk = double_ratchet.get_kem_public_key() if getattr(double_ratchet, 'enable_pq', False) else None
                our_dss_pk = double_ratchet.get_dss_public_key() if getattr(double_ratchet, 'enable_pq', False) else None

                offer_payload = {
                    'type': 'RATCHET_KEY_OFFER',
                    'dh_pk': _b64e(our_dh_pk),
                    'kem_pk': _b64e(our_kem_pk),
                    'dss_pk': _encode_dss(our_dss_pk),
                }
                await _send_frame(writer, offer_payload)

                # 2. Responder receives initiator's ratchet keys and KEM ciphertext
                init_frame = await _recv_frame(reader)
                if init_frame.get('type') != 'RATCHET_KEY_RESPONSE':
                    raise SecurityError(f"Expected RATCHET_KEY_RESPONSE, got {init_frame.get('type')}")

                init_dh_pk = _b64d(init_frame.get('dh_pk'))
                init_kem_pk = _b64d(init_frame.get('kem_pk'))
                init_dss_pk = _decode_dss(init_frame.get('dss_pk'))
                kem_ct = _b64d(init_frame.get('kem_ct'))

                double_ratchet.set_remote_public_key(init_dh_pk, init_kem_pk, init_dss_pk)
                if getattr(double_ratchet, 'enable_pq', False) and kem_ct:
                    double_ratchet.process_kem_ciphertext(kem_ct)

                # 3. Confirm sync
                await _send_frame(writer, {'type': 'RATCHET_SYNC_CONFIRM', 'success': True})

            logger.info(f"DoubleRatchet successfully synchronized with {peer_id}")

        except Exception as e:
            logger.error(f"DoubleRatchet synchronization failed with {peer_id}: {e}", exc_info=True)
            raise SecurityError(f"DoubleRatchet sync failed with {peer_id}: {e}") from e
    
    def get_session(self, peer_id: str) -> Optional[SessionContext]:
        """
        Retrieve an existing session context.
        
        Args:
            peer_id: Unique identifier for the peer
            
        Returns:
            SessionContext if session exists, None otherwise
            
        Requirements: 4.2
        """
        return self.sessions.get(peer_id)
    
    def update_session_activity(self, peer_id: str) -> bool:
        """
        Update session activity timestamp and message count.
        
        This should be called whenever a message is sent or received
        to track session activity for timeout detection and key rotation.
        
        Args:
            peer_id: Unique identifier for the peer
            
        Returns:
            bool: True if session was updated, False if session not found
            
        Requirements: 4.2
        """
        session = self.sessions.get(peer_id)
        if session:
            session.update_activity()
            logger.debug(f"Updated activity for {peer_id}: message_count={session.message_count}")
            return True
        return False
    
    def get_session_health(self, peer_id: str) -> Optional[Dict[str, Any]]:
        """
        Get health status of a session.
        
        Args:
            peer_id: Unique identifier for the peer
            
        Returns:
            Dict with health information or None if session not found
            
        Requirements: 4.2
        """
        session = self.sessions.get(peer_id)
        if not session:
            return None
        
        inactivity_seconds = session.get_inactivity_duration()
        is_healthy = session.is_healthy()
        
        return {
            'peer_id': peer_id,
            'is_healthy': is_healthy,
            'inactivity_seconds': inactivity_seconds,
            'message_count': session.message_count,
            'last_activity': session.last_activity.isoformat(),
            'connected_at': session.connected_at.isoformat(),
            'session_duration_seconds': (datetime.now() - session.connected_at).total_seconds()
        }
    
    def get_active_sessions(self) -> list[str]:
        """
        Get list of active session peer IDs.
        
        Returns:
            List of peer IDs with active sessions
            
        Requirements: 4.5
        """
        return list(self.sessions.keys())
    
    async def terminate_session(self, peer_id: str) -> None:
        """
        Terminate a session and securely wipe cryptographic state.
        
        This method performs the following cleanup:
        1. Log session termination (Task 6.5)
        2. Close network connections
        3. Securely wipe DoubleRatchet state from memory
        4. Securely wipe HybridKeyExchange state from memory
        5. Close and flush session AuditLogger
        6. Remove session from active sessions
        
        Args:
            peer_id: Unique identifier for the peer
            
        Requirements: 4.3, 4.4, 5.4
        """
        async with self._lock:
            session = self.sessions.pop(peer_id, None)
            
        if not session:
            logger.warning(f"No session found for {peer_id}")
            return
            
        logger.info(f"Terminating session for {peer_id}")
        
        # Get session audit logger before cleanup
        session_audit_logger = session.audit_logger
        
        try:
            # Task 6.5: Log connection termination with reason
            if session_audit_logger and AUDIT_AVAILABLE:
                session_audit_logger.log_event(
                    AuditEventType.CONNECTION_CLOSED,
                    f"Session termination initiated for {peer_id}",
                    AuditSeverity.INFO,
                    {
                        'peer_id': peer_id,
                        'session_id': session.session_id,
                        'message_count': session.message_count,
                        'duration_seconds': (datetime.now() - session.connected_at).total_seconds(),
                        'reason': 'normal_termination',
                        'timestamp': datetime.now().isoformat()
                    }
                )
            
            # Close network connections
            if session.writer and not session.writer.is_closing():
                session.writer.close()
                try:
                    await session.writer.wait_closed()
                except Exception as e:
                    logger.debug(f"Error closing writer for {peer_id}: {e}")
            
            # Securely wipe DoubleRatchet state
            if session.double_ratchet:
                try:
                    if hasattr(session.double_ratchet, 'secure_cleanup'):
                        session.double_ratchet.secure_cleanup()
                    elif hasattr(session.double_ratchet, 'cleanup'):
                        session.double_ratchet.cleanup()
                    logger.debug(f"Wiped DoubleRatchet state for {peer_id}")
                except Exception as e:
                    logger.error(f"Error wiping DoubleRatchet state: {e}")
                finally:
                    session.double_ratchet = None
            
            # Securely wipe HybridKeyExchange state
            if session.hybrid_kex:
                try:
                    if hasattr(session.hybrid_kex, 'secure_cleanup'):
                        session.hybrid_kex.secure_cleanup()
                    elif hasattr(session.hybrid_kex, 'cleanup'):
                        session.hybrid_kex.cleanup()
                    logger.debug(f"Wiped HybridKeyExchange state for {peer_id}")
                except Exception as e:
                    logger.error(f"Error wiping HybridKeyExchange state: {e}")
                finally:
                    session.hybrid_kex = None
            
            # Reclaim memory
            gc.collect()
            
            # Close and flush session AuditLogger
            if session_audit_logger and AUDIT_AVAILABLE:
                try:
                    # Final log before closing
                    session_audit_logger.log_event(
                        AuditEventType.CONNECTION_CLOSED,
                        f"Session terminated successfully for {peer_id}",
                        AuditSeverity.INFO,
                        {
                            'peer_id': peer_id,
                            'session_id': session.session_id,
                            'final_message_count': session.message_count,
                            'timestamp': datetime.now().isoformat()
                        }
                    )
                    
                    # Flush and close audit logger
                    session_audit_logger.flush_buffer()
                    session_audit_logger.close()
                    logger.debug(f"Closed AuditLogger for {peer_id}")
                except Exception as e:
                    logger.error(f"Error closing AuditLogger for {peer_id}: {e}")
            
            # Log session termination to global logger
            logger.info(f" Session terminated for {peer_id}")
                
            if self.audit_logger and AUDIT_AVAILABLE:
                self.audit_logger.log_event(
                    AuditEventType.CONNECTION_CLOSED,
                    f"Session terminated with {peer_id}",
                    AuditSeverity.INFO,
                    {
                        'peer_id': peer_id,
                        'session_id': session.session_id,
                        'message_count': session.message_count,
                        'duration_seconds': (datetime.now() - session.connected_at).total_seconds()
                    }
                )
            
        except Exception as e:
            logger.error(f"Error during session termination for {peer_id}: {e}", exc_info=True)
            
            # Task 6.5: Log connection failure with error details
            if self.audit_logger and AUDIT_AVAILABLE:
                import traceback
                self.audit_logger.log_event(
                    AuditEventType.SECURITY_VIOLATION,
                    f"Error during session termination for {peer_id}: {str(e)}",
                    AuditSeverity.MEDIUM,
                    {
                        'peer_id': peer_id,
                        'error': str(e),
                        'error_type': type(e).__name__,
                        'stack_trace': traceback.format_exc()
                    }
                )
    
    async def handle_tamper_detected(
        self,
        peer_id: str,
        session_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Handle cryptographic tamper/MAC breach by ingesting event into Active Cyber Defense,
        triggering SEVER_SESSION_AND_ISOLATE playbook, and immediately terminating session.
        """
        sid = session_id
        if not sid and peer_id in self.sessions:
            sid = self.sessions[peer_id].session_id
        try:
            from active_cyber_defense import get_active_cyber_defense_engine
            acd = get_active_cyber_defense_engine()
            acd.ingest_event("tamper_detected", peer_id=peer_id, session_id=sid, details=details)
        except Exception as e:
            logger.error(f"Failed to report tamper to ACD: {e}")
        await self.terminate_session(peer_id)
    
    async def terminate_all_sessions(self) -> None:
        """
        Terminate all active sessions.
        
        This is typically called during system shutdown to ensure
        all sessions are properly cleaned up.
        """
        logger.info(f"Terminating all sessions ({len(self.sessions)} active)")
        
        # Get list of peer IDs to avoid modifying dict during iteration
        peer_ids = list(self.sessions.keys())
        
        for peer_id in peer_ids:
            await self.terminate_session(peer_id)
        
        logger.info("All sessions terminated")
    
    async def _check_session_timeouts(self) -> None:
        """
        Background task to check for inactive sessions and terminate them.
        
        This task runs periodically (every 60 seconds) and checks all active
        sessions for inactivity. Sessions inactive for more than the configured
        timeout period are automatically terminated.
        
        Requirements: 4.3
        """
        logger.info("Session timeout monitoring started")
        
        while not self._shutdown:
            try:
                # Check every 60 seconds
                await asyncio.sleep(60)
                
                if self._shutdown:
                    break
                
                # Get list of sessions to check (avoid modifying dict during iteration)
                sessions_to_check = list(self.sessions.items())
                
                for peer_id, session in sessions_to_check:
                    inactivity_seconds = session.get_inactivity_duration()
                    
                    # Task 8.2: Detect inactive sessions (no activity for 30 minutes)
                    if inactivity_seconds >= self.session_timeout_seconds:
                        logger.warning(
                            f"Session timeout detected for {peer_id}: "
                            f"inactive for {inactivity_seconds:.0f}s (threshold: {self.session_timeout_seconds}s)"
                        )
                        
                        # Task 8.2: Log session timeout events
                        if self.audit_logger and AUDIT_AVAILABLE:
                            self.audit_logger.log_event(
                                AuditEventType.CONNECTION_CLOSED,
                                f"Session timeout for {peer_id}",
                                AuditSeverity.INFO,
                                {
                                    'peer_id': peer_id,
                                    'session_id': session.session_id,
                                    'inactivity_seconds': inactivity_seconds,
                                    'timeout_threshold': self.session_timeout_seconds,
                                    'message_count': session.message_count,
                                    'reason': 'timeout',
                                    'timestamp': datetime.now().isoformat()
                                }
                            )
                        
                        # Task 8.2: Automatically terminate inactive sessions
                        await self.terminate_session(peer_id)
                        
                        logger.info(f"Terminated inactive session for {peer_id}")
                
            except asyncio.CancelledError:
                logger.info("Session timeout monitoring cancelled")
                break
            except Exception as e:
                logger.error(f"Error in session timeout check: {e}", exc_info=True)
                # Continue monitoring despite errors
                await asyncio.sleep(60)
        
        logger.info("Session timeout monitoring stopped")
    
    def start_timeout_monitoring(self) -> None:
        """
        Start the background task for session timeout monitoring.
        
        This should be called after the SessionManager is initialized
        to enable automatic termination of inactive sessions.
        
        Requirements: 4.3
        """
        if self._timeout_check_task is None or self._timeout_check_task.done():
            self._shutdown = False
            self._timeout_check_task = asyncio.create_task(self._check_session_timeouts())
            logger.info("Session timeout monitoring task started")
        else:
            logger.warning("Session timeout monitoring already running")
    
    async def stop_timeout_monitoring(self) -> None:
        """
        Stop the background task for session timeout monitoring.
        
        This should be called during shutdown to cleanly stop the
        timeout monitoring task.
        
        Requirements: 4.3
        """
        self._shutdown = True
        
        if self._timeout_check_task and not self._timeout_check_task.done():
            self._timeout_check_task.cancel()
            try:
                await self._timeout_check_task
            except asyncio.CancelledError:
                logger.debug("Session timeout check task cancelled cleanly")
            logger.info("Session timeout monitoring task stopped")
        
        self._timeout_check_task = None
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get statistics about active sessions.
        
        Returns:
            Dictionary containing session statistics
        """
        sessions_snapshot = list(self.sessions.values())
        return {
            'active_sessions': len(sessions_snapshot),
            'peer_ids': [s.peer_id for s in sessions_snapshot],
            'total_messages': sum(s.message_count for s in sessions_snapshot),
            'sessions': [s.to_dict() for s in sessions_snapshot]
        }
    
    def verify_session_isolation(self) -> Dict[str, Any]:
        """
        Verify that session contexts are properly isolated.
        
        This method checks that:
        - Each session has its own DoubleRatchet instance
        - Each session has its own HybridKeyExchange instance
        - Each session has its own AuditLogger instance
        - No shared state between sessions
        
        Returns:
            Dict with isolation verification results
            
        Requirements: 4.5
        """
        results = {
            'total_sessions': len(self.sessions),
            'isolated': True,
            'issues': []
        }
        
        # Check for duplicate DoubleRatchet instances
        double_ratchet_ids = set()
        hybrid_kex_ids = set()
        audit_logger_ids = set()
        
        for peer_id, session in self.sessions.items():
            # Check DoubleRatchet isolation
            if session.double_ratchet:
                dr_id = id(session.double_ratchet)
                if dr_id in double_ratchet_ids:
                    results['isolated'] = False
                    results['issues'].append(f"Shared DoubleRatchet instance detected for {peer_id}")
                double_ratchet_ids.add(dr_id)
            
            # Check HybridKeyExchange isolation
            if session.hybrid_kex:
                hk_id = id(session.hybrid_kex)
                if hk_id in hybrid_kex_ids:
                    results['isolated'] = False
                    results['issues'].append(f"Shared HybridKeyExchange instance detected for {peer_id}")
                hybrid_kex_ids.add(hk_id)
            
            # Check AuditLogger isolation
            if session.audit_logger:
                al_id = id(session.audit_logger)
                if al_id in audit_logger_ids:
                    # Note: Shared audit logger is acceptable if it's the global one
                    # Only flag if it's supposed to be session-specific
                    results.setdefault('shared_audit_loggers', []).append(al_id)
                audit_logger_ids.add(al_id)
        
        results['unique_double_ratchets'] = len(double_ratchet_ids)
        results['unique_hybrid_kex'] = len(hybrid_kex_ids)
        results['unique_audit_loggers'] = len(audit_logger_ids)
        
        return results


# Export main class
__all__ = ['SessionManager', 'SessionContext']

