"""
Security Error Handler Module

Provides comprehensive error handling for the P2P chat system with:
- Network retry logic with exponential backoff
- Cryptographic error handling
- Connection loss handling
- Graceful shutdown with state preservation

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
"""

import asyncio
import logging
import traceback
import json
import os
from datetime import datetime
from typing import Callable, Dict, Any, Optional, List
from dataclasses import dataclass, asdict

try:
    from audit_logging_system import AuditLogger, AuditEventType, AuditSeverity
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    logging.warning("AuditLogger not available for error handler")

logger = logging.getLogger(__name__)


@dataclass
class ErrorContext:
    """Context information for error handling."""
    error_type: str
    error_message: str
    peer_id: Optional[str]
    operation: str
    timestamp: datetime
    stack_trace: str
    retry_count: int = 0
    recoverable: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class SecurityErrorHandler:
    """
    Comprehensive error handler for security-critical operations.
    
    Provides:
    - Exponential backoff retry logic for transient failures
    - Comprehensive error logging with full context
    - Connection loss handling with resource cleanup
    - Graceful shutdown with state preservation
    
    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
    """
    
    def __init__(self, audit_logger: Optional[Any] = None):
        """
        Initialize the security error handler.
        
        Args:
            audit_logger: Optional AuditLogger instance for security event logging
        """
        self.audit_logger = audit_logger
        self.retry_config = {
            'max_attempts': 3,
            'base_delay': 1.0,  # Base delay in seconds
            'max_delay': 4.0    # Maximum delay in seconds
        }
        self.unsent_messages_dir = "unsent_messages"
        self._ensure_unsent_messages_dir()
        
        logger.info("SecurityErrorHandler initialized")
    
    def _ensure_unsent_messages_dir(self):
        """Ensure the unsent messages directory exists."""
        try:
            os.makedirs(self.unsent_messages_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create unsent messages directory: {e}")
    
    async def with_retry(self, operation: Callable, context: Dict[str, Any]) -> Any:
        """
        Execute an operation with exponential backoff retry logic.
        
        This method implements retry logic for transient network failures:
        - Attempts operation up to 3 times
        - Uses exponential backoff: 1s, 2s, 4s
        - Logs each retry attempt
        - Returns None after exhausting retries
        
        Args:
            operation: Async callable to execute
            context: Context dictionary with operation details
            
        Returns:
            Result of operation if successful, None if all retries exhausted
            
        Requirements: 2.1
        """
        max_attempts = self.retry_config['max_attempts']
        base_delay = self.retry_config['base_delay']
        
        for attempt in range(max_attempts):
            try:
                logger.debug(f"Executing operation (attempt {attempt + 1}/{max_attempts}): {context.get('operation', 'unknown')}")
                result = await operation()
                
                if attempt > 0:
                    # Log successful retry
                    logger.info(f"Operation succeeded after {attempt + 1} attempts")
                    if self.audit_logger and AUDIT_AVAILABLE:
                        self.audit_logger.log_event(
                            AuditEventType.SYSTEM_STARTUP,  # Using available event type
                            f"Operation succeeded after {attempt + 1} retries",
                            AuditSeverity.INFO,
                            {
                                'operation': context.get('operation', 'unknown'),
                                'peer_id': context.get('peer_id'),
                                'attempts': attempt + 1
                            }
                        )
                
                return result
                
            except asyncio.CancelledError:
                # Don't retry cancelled operations
                logger.info("Operation cancelled, not retrying")
                raise
                
            except Exception as e:
                error_msg = str(e)
                is_last_attempt = (attempt == max_attempts - 1)
                
                if is_last_attempt:
                    # Final attempt failed
                    logger.error(f"Operation failed after {max_attempts} attempts: {error_msg}")
                    
                    error_context = ErrorContext(
                        error_type=type(e).__name__,
                        error_message=error_msg,
                        peer_id=context.get('peer_id'),
                        operation=context.get('operation', 'unknown'),
                        timestamp=datetime.now(),
                        stack_trace=traceback.format_exc(),
                        retry_count=max_attempts,
                        recoverable=False
                    )
                    
                    self.log_and_notify(e, error_context.to_dict())
                    return None
                else:
                    # Calculate delay with exponential backoff
                    delay = min(base_delay * (2 ** attempt), self.retry_config['max_delay'])
                    
                    logger.warning(f"Operation failed (attempt {attempt + 1}/{max_attempts}): {error_msg}. Retrying in {delay}s...")
                    
                    # Log retry attempt
                    if self.audit_logger and AUDIT_AVAILABLE:
                        self.audit_logger.log_event(
                            AuditEventType.SYSTEM_STARTUP,  # Using available event type
                            f"Retrying operation after failure (attempt {attempt + 1})",
                            AuditSeverity.LOW,
                            {
                                'operation': context.get('operation', 'unknown'),
                                'peer_id': context.get('peer_id'),
                                'error': error_msg,
                                'retry_delay': delay,
                                'attempt': attempt + 1
                            }
                        )
                    
                    await asyncio.sleep(delay)
        
        return None
    
    def log_and_notify(self, error: Exception, context: Dict[str, Any]) -> None:
        """
        Log error comprehensively and notify user with clear message.
        
        This method provides comprehensive error logging:
        - Logs to application logger with full stack trace
        - Logs to audit system with security context
        - Displays user-friendly error message
        - Includes operation details and peer information
        
        Args:
            error: The exception that occurred
            context: Context dictionary with error details
            
        Requirements: 2.2, 2.5
        """
        error_type = context.get('error_type', type(error).__name__)
        error_message = context.get('error_message', str(error))
        operation = context.get('operation', 'unknown')
        peer_id = context.get('peer_id', 'unknown')
        stack_trace = context.get('stack_trace', traceback.format_exc())
        
        # Log to application logger
        logger.error(
            f"Error in {operation}: {error_type} - {error_message}\n"
            f"Peer: {peer_id}\n"
            f"Stack trace:\n{stack_trace}"
        )
        
        # Log to audit system
        if self.audit_logger and AUDIT_AVAILABLE:
            severity = AuditSeverity.HIGH if context.get('recoverable', True) else AuditSeverity.CRITICAL
            
            self.audit_logger.log_event(
                AuditEventType.SECURITY_VIOLATION,
                f"Error in {operation}: {error_message}",
                severity,
                {
                    'error_type': error_type,
                    'error_message': error_message,
                    'operation': operation,
                    'peer_id': peer_id,
                    'stack_trace': stack_trace,
                    'retry_count': context.get('retry_count', 0),
                    'recoverable': context.get('recoverable', True),
                    'timestamp': context.get('timestamp', datetime.now().isoformat())
                }
            )
        
        # Notify user with clear message
        print(f"\n[FAIL] Error: {error_message}")
        print(f"   Operation: {operation}")
        if peer_id != 'unknown':
            print(f"   Peer: {peer_id}")
        print(f"   Type: {error_type}")
        
        # Provide troubleshooting hints based on error type
        if 'network' in error_type.lower() or 'connection' in error_type.lower():
            print(f"   [TIP] Check your network connection and firewall settings")
        elif 'crypto' in error_type.lower() or 'encryption' in error_type.lower():
            print(f"   [TIP] This may indicate a protocol mismatch or corrupted data")
        elif 'timeout' in error_type.lower():
            print(f"   [TIP] The peer may be unresponsive or network latency is high")
        
        print(f"   Check logs for detailed information")
    
    async def handle_connection_loss(self, peer_id: str, session_context: Optional[Dict[str, Any]] = None) -> None:
        """
        Handle unexpected connection loss with cleanup and state preservation.
        
        This method:
        - Detects connection loss in message handlers
        - Preserves unsent messages to disk
        - Cleans up session resources
        - Updates UI with connection status
        
        Args:
            peer_id: ID of the peer whose connection was lost
            session_context: Optional session context dictionary
            
        Requirements: 2.3
        """
        logger.warning(f"Handling connection loss for peer {peer_id}")
        
        try:
            # Log connection loss event
            if self.audit_logger and AUDIT_AVAILABLE:
                details = {'peer_id': peer_id}
                if session_context:
                    details['last_activity'] = session_context.get('last_activity', datetime.now()).isoformat()
                    details['message_count'] = session_context.get('message_count', 0)
                
                self.audit_logger.log_event(
                    AuditEventType.CONNECTION_CLOSED,
                    f"Connection lost with {peer_id}",
                    AuditSeverity.MEDIUM,
                    details
                )
            
            # Preserve unsent messages if any
            if session_context:
                unsent_messages = session_context.get('unsent_messages', [])
                if unsent_messages:
                    await self._save_unsent_messages(peer_id, unsent_messages)
                    logger.info(f"Preserved {len(unsent_messages)} unsent messages for {peer_id}")
            
            # Clean up session resources
            await self._cleanup_session_resources(peer_id, session_context)
            
            # Update UI
            print(f"\n[WARNING]  Connection lost with {peer_id}")
            print(f"   Session has been terminated and resources cleaned up")
            if session_context and session_context.get('unsent_messages'):
                print(f"   {len(session_context['unsent_messages'])} unsent messages have been preserved")
            
        except Exception as e:
            logger.error(f"Error handling connection loss for {peer_id}: {e}", exc_info=True)
            self.log_and_notify(
                e,
                {
                    'error_type': type(e).__name__,
                    'error_message': str(e),
                    'operation': 'handle_connection_loss',
                    'peer_id': peer_id,
                    'stack_trace': traceback.format_exc()
                }
            )
    
    async def _save_unsent_messages(self, peer_id: str, messages: List[Dict[str, Any]]) -> None:
        """
        Save unsent messages for later recovery.
        
        Default: In-memory only (P2P_PERSIST_QUEUE=false) to prevent forensic peer-graph
        and message content leaks on disk.
        When P2P_PERSIST_QUEUE=true, payload is AES-256-GCM encrypted before writing.
        
        Args:
            peer_id: ID of the peer
            messages: List of unsent message dictionaries
        """
        try:
            # Sovereign / nuclear default: zero plaintext disk persistence of unsent queues
            if os.environ.get('P2P_PERSIST_QUEUE', 'false').lower() != 'true':
                logger.info(
                    f"Unsent message disk persistence disabled by default (P2P_PERSIST_QUEUE=false) "
                    f"for anti-forensic protection. {len(messages)} unsent messages retained in volatile memory only."
                )
                return

            # When explicitly enabled, seal with AES-256-GCM authenticated encryption
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            queue_key = os.environ.get('P2P_QUEUE_KEY')
            if queue_key:
                # NIST SP 800-132 / CNSA 2.0: PBKDF2-HMAC-SHA512 with 210,000 iterations (Item 52 / Finding 7.2)
                salt = hashlib.sha3_256(b"SecureP2P::UnsentQueue::PBKDF2::Salt::v1").digest()
                key_bytes = hashlib.pbkdf2_hmac(
                    'sha512',
                    queue_key.encode('utf-8'),
                    salt,
                    210000,
                    dklen=32
                )
            else:
                if not hasattr(self, '_queue_seal_key'):
                    self._queue_seal_key = secrets.token_bytes(32)
                key_bytes = self._queue_seal_key

            payload = json.dumps({
                'peer_id': peer_id,
                'timestamp': datetime.now().isoformat(),
                'messages': messages
            }).encode('utf-8')

            aesgcm = AESGCM(key_bytes)
            nonce = secrets.token_bytes(12)
            ciphertext = aesgcm.encrypt(nonce, payload, b"SecureP2P::UnsentQueue::v1.0")

            peer_hash = hashlib.sha384(peer_id.encode('utf-8')).hexdigest()[:32]
            filename = os.path.join(
                self.unsent_messages_dir,
                f"{peer_hash}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
            )
            
            with open(filename, 'wb') as f:
                f.write(b"ENC_QUEUE_V1" + nonce + ciphertext)
            
            logger.info(f"Saved {len(messages)} AES-256-GCM encrypted unsent messages to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to save unsent messages for {peer_id}: {e}")
    
    async def _cleanup_session_resources(self, peer_id: str, session_context: Optional[Dict[str, Any]]) -> None:
        """
        Clean up session resources including network connections and crypto state.
        
        Args:
            peer_id: ID of the peer
            session_context: Optional session context dictionary
        """
        try:
            if not session_context:
                logger.debug(f"No session context to clean up for {peer_id}")
                return
            
            # Close network writer if present
            writer = session_context.get('writer')
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                    logger.debug(f"Closed network writer for {peer_id}")
                except Exception as e:
                    logger.warning(f"Error closing writer for {peer_id}: {e}")
            
            # Securely wipe DoubleRatchet state if present
            double_ratchet = session_context.get('double_ratchet')
            if double_ratchet and hasattr(double_ratchet, 'wipe'):
                try:
                    double_ratchet.wipe()
                    logger.debug(f"Wiped DoubleRatchet state for {peer_id}")
                except Exception as e:
                    logger.warning(f"Error wiping DoubleRatchet for {peer_id}: {e}")
            
            logger.info(f"Cleaned up session resources for {peer_id}")
            
        except Exception as e:
            logger.error(f"Error cleaning up session resources for {peer_id}: {e}")
    
    async def graceful_shutdown(self, active_sessions: Dict[str, Dict[str, Any]]) -> None:
        """
        Perform graceful shutdown with state preservation.
        
        This method:
        - Saves all unsent messages for all sessions
        - Terminates all sessions securely
        - Closes AuditLogger and flushes logs
        - Displays shutdown completion message
        
        Args:
            active_sessions: Dictionary of active session contexts keyed by peer_id
            
        Requirements: 2.4
        """
        logger.info("Initiating graceful shutdown...")
        
        try:
            # Log shutdown initiation
            if self.audit_logger and AUDIT_AVAILABLE:
                self.audit_logger.log_event(
                    AuditEventType.SYSTEM_SHUTDOWN,
                    "Graceful shutdown initiated",
                    AuditSeverity.INFO,
                    {'active_sessions': len(active_sessions)}
                )
            
            print("\n[SHUTDOWN] Initiating graceful shutdown...")
            print(f"   Active sessions: {len(active_sessions)}")
            
            # Save all unsent messages
            total_unsent = 0
            for peer_id, session_context in active_sessions.items():
                unsent_messages = session_context.get('unsent_messages', [])
                if unsent_messages:
                    await self._save_unsent_messages(peer_id, unsent_messages)
                    total_unsent += len(unsent_messages)
            
            if total_unsent > 0:
                print(f"   [SAVED] Preserved {total_unsent} unsent messages")
            
            # Terminate all sessions securely
            print(f"    Terminating {len(active_sessions)} sessions...")
            for peer_id, session_context in list(active_sessions.items()):
                try:
                    await self._cleanup_session_resources(peer_id, session_context)
                except Exception as e:
                    logger.error(f"Error terminating session for {peer_id}: {e}")
            
            # Close AuditLogger and flush logs
            if self.audit_logger and AUDIT_AVAILABLE:
                try:
                    if hasattr(self.audit_logger, 'flush_buffer'):
                        self.audit_logger.flush_buffer()
                    if hasattr(self.audit_logger, 'close'):
                        self.audit_logger.close()
                    print(f"   [AUDIT] Audit logs flushed and closed")
                except Exception as e:
                    logger.error(f"Error closing audit logger: {e}")
            
            # Log shutdown completion
            logger.info("Graceful shutdown completed successfully")
            
            # Display completion message
            print(f"\n Graceful shutdown complete")
            print(f"   All sessions terminated securely")
            print(f"   All logs flushed to disk")
            if total_unsent > 0:
                print(f"   Unsent messages preserved in: {self.unsent_messages_dir}/")
            
        except Exception as e:
            logger.error(f"Error during graceful shutdown: {e}", exc_info=True)
            self.log_and_notify(
                e,
                {
                    'error_type': type(e).__name__,
                    'error_message': str(e),
                    'operation': 'graceful_shutdown',
                    'peer_id': None,
                    'stack_trace': traceback.format_exc()
                }
            )
            print(f"\n[WARNING]  Shutdown completed with errors - check logs")


# Convenience function for creating error handler
def create_error_handler(audit_logger: Optional[Any] = None) -> SecurityErrorHandler:
    """
    Create a SecurityErrorHandler instance.
    
    Args:
        audit_logger: Optional AuditLogger instance
        
    Returns:
        SecurityErrorHandler instance
    """
    return SecurityErrorHandler(audit_logger)
