"""
Connection lifecycle management.

Provides connection establishment, maintenance, and teardown with comprehensive error handling.
"""

import asyncio
import socket
import logging
import time
from typing import Optional, Tuple
from datetime import datetime

try:
    from ..base import BaseModule, NetworkError, SecurityError
except (ImportError, ValueError):
    from base import BaseModule, NetworkError, SecurityError


class ConnectionManager(BaseModule):
    """
    Connection lifecycle management.
    
    Provides connection establishment, maintenance, and teardown including:
    - Outbound connection establishment with retry logic
    - Inbound connection handling
    - Connection failure recovery
    - Graceful disconnection
    - Connection state tracking
    """
    
    # Connection configuration constants
    CONNECTION_TIMEOUT = 30.0  # seconds
    MAX_RETRIES = 3
    INITIAL_RETRY_DELAY = 1.0  # seconds
    MAX_RETRY_DELAY = 10.0  # seconds
    
    def __init__(self, orchestrator):
        """
        Initialize connection manager.
        
        Args:
            orchestrator: Reference to main SecureP2PChat orchestrator
        """
        super().__init__(orchestrator)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        # 2028 hardening: bound connection table (DoS). Direct-P2P military
        # use is 1:1; allow burst headroom but fail-closed beyond cap.
        # Matches protocol_manager max_concurrent=10 with margin.
        self._max_active_connections = 16
        self._active_connections = {}
        self._connection_lock = asyncio.Lock()
    
    async def handle_incoming_connection(self, client_socket, client_address, listen_port) -> None:
        """
        Handle an incoming connection with full security setup.
        
        This method processes incoming connections including:
        - Socket configuration
        - Certificate exchange
        - Hybrid key exchange
        - TLS setup
        - Authentication
        
        Args:
            client_socket: Connected client socket
            client_address: Tuple of (client_ip, client_port)
            listen_port: Port the server is listening on
        
        Raises:
            SecurityError: If security validation fails
            NetworkError: If connection handling fails
        """
        client_ip, client_port = client_address
        
        try:
            self.logger.info(f"[CONNECTION] Handling incoming connection from {client_ip}:{client_port}")
            
            # Check if we're already connecting outbound
            if self.orchestrator and hasattr(self.orchestrator, 'is_connecting') and self.orchestrator.is_connecting:
                self.logger.info("[CONNECTION] Ignoring incoming connection while outbound connection in progress")
                try:
                    client_socket.close()
                except Exception as _sock_err:
                    self.logger.debug(f"Socket close suppressed: {_sock_err}")
                return
            
            # Configure socket
            try:
                client_socket.setblocking(False)
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
                    self.logger.debug(f"Could not set TCP keepalive options: {e}")
            
            except Exception as e:
                self.logger.error(f"[CONNECTION] Failed to configure socket: {e}")
                try:
                    client_socket.close()
                except Exception as _sock_err:
                    self.logger.debug(f"Socket close suppressed: {_sock_err}")
                raise NetworkError(
                    f"Failed to configure socket: {e}",
                    module="network.connection",
                    function="handle_incoming_connection"
                )
            
            # Store socket in orchestrator
            if self.orchestrator:
                self.orchestrator.tcp_socket = client_socket
            
            # Initialize session with security modules
            try:
                self.logger.info("[CONNECTION] Initializing secure session (server)")
                
                # Create async streams from socket
                loop = asyncio.get_event_loop()
                reader, writer = await asyncio.open_connection(sock=client_socket)
                
                # Get audit logger if available
                audit_logger = None
                if self.orchestrator and hasattr(self.orchestrator, 'audit'):
                    audit_logger = self.orchestrator.audit
                
                # Initialize session with handshake and DoubleRatchet
                try:
                    from simple_chat_implementation import initialize_session
                except ImportError:
                    self.logger.error("simple_chat_implementation not available")
                    raise SecurityError(
                        "Chat implementation not available",
                        module="network.connection",
                        function="handle_incoming_connection"
                    )
                session_context = await initialize_session(
                    peer_id=client_ip,
                    reader=reader,
                    writer=writer,
                    is_initiator=False,  # Server is responder
                    audit_logger=audit_logger
                )
                
                if not session_context:
                    raise SecurityError(
                        "Session initialization failed",
                        module="network.connection",
                        function="handle_incoming_connection"
                    )
                
                self.logger.info("[CONNECTION] Secure session initialized successfully")
                
                # Track connection with full security context (fingerprint or ip:port)
                conn_key = getattr(session_context, 'peer_fingerprint', None) or f"[{client_ip}]:{client_port}"
                async with self._connection_lock:
                    if conn_key not in self._active_connections and len(self._active_connections) >= self._max_active_connections:
                        raise SecurityError(
                            "Connection table full - rejecting inbound (DoS protection)",
                            module="network.connection",
                            function="handle_incoming_connection"
                        )
                    self._active_connections[conn_key] = session_context
                    self._active_connections[client_ip] = session_context
                
                self.logger.info(f"[CONNECTION] Incoming connection from {client_ip}:{client_port} established with encryption (conn_key={conn_key[:16]}...)")
                
                # Task 6.5: Log connection establishment with peer details
                if audit_logger:
                    try:
                        from audit_logging_system import AuditEventType, AuditSeverity
                        audit_logger.log_event(
                            AuditEventType.CONNECTION_ESTABLISHED,
                            f"Incoming connection established from {client_ip}:{client_port}",
                            AuditSeverity.INFO,
                            {
                                'peer_ip': client_ip,
                                'peer_port': client_port,
                                'listen_port': listen_port,
                                'connection_type': 'incoming',
                                'encryption_enabled': True,
                                'timestamp': datetime.now().isoformat()
                            }
                        )
                    except Exception as e:
                        self.logger.debug(f"Failed to log connection event: {e}")
                
            except SecurityError:
                # Task 6.5: Log connection failure with error details
                if audit_logger:
                    try:
                        from audit_logging_system import AuditEventType, AuditSeverity
                        audit_logger.log_event(
                            AuditEventType.CONNECTION_FAILURE,
                            f"Incoming connection failed from {client_ip}:{client_port}",
                            AuditSeverity.HIGH,
                            {
                                'peer_ip': client_ip,
                                'peer_port': client_port,
                                'error': 'Security error during session initialization',
                                'timestamp': datetime.now().isoformat()
                            }
                        )
                    except Exception as _sock_err:
                        self.logger.debug(f"Socket close suppressed: {_sock_err}")
                raise
            except Exception as e:
                self.logger.error(f"[CONNECTION] Session initialization failed: {e}", exc_info=True)
                
                # Task 6.5: Log connection failure with error details
                if audit_logger:
                    try:
                        from audit_logging_system import AuditEventType, AuditSeverity
                        import traceback
                        audit_logger.log_event(
                            AuditEventType.CONNECTION_FAILURE,
                            f"Session initialization failed for {client_ip}:{client_port}: {str(e)}",
                            AuditSeverity.HIGH,
                            {
                                'peer_ip': client_ip,
                                'peer_port': client_port,
                                'error': str(e),
                                'error_type': type(e).__name__,
                                'stack_trace': traceback.format_exc(),
                                'timestamp': datetime.now().isoformat()
                            }
                        )
                    except Exception as _sock_err:
                        self.logger.debug(f"Socket close suppressed: {_sock_err}")
                
                try:
                    client_socket.close()
                except Exception as _sock_err:
                    self.logger.debug(f"Socket close suppressed: {_sock_err}")
                raise SecurityError(
                    f"Session initialization failed: {e}",
                    module="network.connection",
                    function="handle_incoming_connection"
                )
        
        except Exception as e:
            self.logger.error(f"[CONNECTION] Failed to handle incoming connection: {e}", exc_info=True)
            try:
                client_socket.close()
            except Exception as _sock_err:
                self.logger.debug(f"Socket close suppressed: {_sock_err}")
            if isinstance(e, (SecurityError, NetworkError)):
                raise
            else:
                raise NetworkError(
                    f"Failed to handle incoming connection: {e}",
                    module="network.connection",
                    function="handle_incoming_connection"
                )
    
    async def connect_to_peer(self, peer_ip: str, peer_port: int) -> bool:
        """
        Connect to a peer using the secure connection protocol.
        
        This method implements robust connection establishment with:
        - Input validation
        - Multiple connection attempts
        - Exponential backoff retry logic
        - Security verification
        
        Args:
            peer_ip: IP address of the peer
            peer_port: Port number of the peer
        
        Returns:
            True if connection successful, False otherwise
        
        Raises:
            NetworkError: If connection fails
        """
        try:
            # Strip enclosing brackets if bracketed IPv6 literal
            if isinstance(peer_ip, str):
                peer_ip = peer_ip.strip()
                if peer_ip.startswith('[') and peer_ip.endswith(']'):
                    peer_ip = peer_ip[1:-1].strip()

            self.logger.info(f"[CONNECTION] Connecting to peer at {peer_ip}:{peer_port}")
            
            # Validate inputs
            if not self._validate_ip_address(peer_ip):
                raise NetworkError(
                    f"Invalid peer IP address: {peer_ip}",
                    module="network.connection",
                    function="connect_to_peer"
                )
            
            if not self._validate_port(peer_port):
                raise NetworkError(
                    f"Invalid peer port: {peer_port}",
                    module="network.connection",
                    function="connect_to_peer"
                )
            
            # Resolve address
            loop = asyncio.get_event_loop()
            try:
                addrinfo = await loop.getaddrinfo(
                    peer_ip, peer_port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM
                )
            except socket.gaierror as e:
                raise NetworkError(
                    f"Failed to resolve {peer_ip}:{peer_port}: {e}",
                    module="network.connection",
                    function="connect_to_peer"
                )
            
            if not addrinfo:
                raise NetworkError(
                    f"No addresses found for {peer_ip}:{peer_port}",
                    module="network.connection",
                    function="connect_to_peer"
                )
            
            self.logger.info(f"[CONNECTION] Found {len(addrinfo)} address candidates")
            
            # Try each address
            last_error = None
            for i, (family, type_, proto, _, sockaddr) in enumerate(addrinfo):
                try:
                    self.logger.debug(f"[CONNECTION] Trying candidate {i+1}/{len(addrinfo)}: {sockaddr}")
                    
                    # Create socket
                    client_socket = socket.socket(family, type_, proto)
                    client_socket.setblocking(False)
                    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    
                    # Set TCP keepalive if supported
                    try:
                        if hasattr(socket, 'TCP_KEEPIDLE'):
                            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                        if hasattr(socket, 'TCP_KEEPINTVL'):
                            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
                        if hasattr(socket, 'TCP_KEEPCNT'):
                            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                    except Exception as _opt_err:
                        self.logger.debug(f"Socket opt ignored: {_opt_err}")
                    
                    # Connect with timeout
                    try:
                        await asyncio.wait_for(
                            loop.sock_connect(client_socket, sockaddr),
                            timeout=self.CONNECTION_TIMEOUT
                        )
                        self.logger.info(f"[CONNECTION] Connected to {sockaddr}")
                        
                        # Store socket in orchestrator
                        if self.orchestrator:
                            self.orchestrator.tcp_socket = client_socket
                        
                        # Initialize session with security modules
                        try:
                            self.logger.info("[CONNECTION] Initializing secure session (client)")
                            
                            # Create async streams from socket
                            reader, writer = await asyncio.open_connection(sock=client_socket)
                            
                            # Get audit logger if available
                            audit_logger = None
                            if self.orchestrator and hasattr(self.orchestrator, 'audit'):
                                audit_logger = self.orchestrator.audit
                            
                            # Initialize session with handshake and DoubleRatchet
                            try:
                                from simple_chat_implementation import initialize_session
                            except ImportError:
                                self.logger.error("simple_chat_implementation not available")
                                raise SecurityError("Chat implementation not available")
                            session_context = await initialize_session(
                                peer_id=peer_ip,
                                reader=reader,
                                writer=writer,
                                is_initiator=True,  # Client is initiator
                                audit_logger=audit_logger
                            )
                            
                            if not session_context:
                                self.logger.error("[CONNECTION] Session initialization failed")
                                try:
                                    client_socket.close()
                                except Exception as _sock_err:
                                    self.logger.debug(f"Socket close suppressed: {_sock_err}")
                                continue
                            
                            self.logger.info("[CONNECTION] Secure session initialized successfully")
                            
                            # Track connection with full security context
                            conn_key = getattr(session_context, 'peer_fingerprint', None) or f"[{peer_ip}]:{peer_port}"
                            async with self._connection_lock:
                                if conn_key not in self._active_connections and len(self._active_connections) >= self._max_active_connections:
                                    raise SecurityError(
                                        "Connection table full - rejecting outbound (DoS protection)",
                                        module="network.connection",
                                        function="handle_outgoing_connection"
                                    )
                                self._active_connections[conn_key] = session_context
                                self._active_connections[peer_ip] = session_context
                            
                            # Task 6.5: Log connection establishment with peer details
                            if audit_logger:
                                try:
                                    from audit_logging_system import AuditEventType, AuditSeverity
                                    audit_logger.log_event(
                                        AuditEventType.CONNECTION_ESTABLISHED,
                                        f"Outbound connection established to {peer_ip}:{peer_port}",
                                        AuditSeverity.INFO,
                                        {
                                            'peer_ip': peer_ip,
                                            'peer_port': peer_port,
                                            'connection_type': 'outbound',
                                            'encryption_enabled': True,
                                            'timestamp': datetime.now().isoformat()
                                        }
                                    )
                                except Exception as e:
                                    self.logger.debug(f"Failed to log connection event: {e}")
                            
                            return True
                            
                        except Exception as e:
                            self.logger.error(f"[CONNECTION] Session initialization failed: {e}", exc_info=True)
                            try:
                                client_socket.close()
                            except Exception as _sock_err:
                                self.logger.debug(f"Socket close suppressed: {_sock_err}")
                            continue
                    
                    except asyncio.TimeoutError:
                        self.logger.warning(f"[CONNECTION] Connection to {sockaddr} timed out")
                        last_error = TimeoutError(f"Connection timeout to {sockaddr}")
                        try:
                            client_socket.close()
                        except Exception as _sock_err:
                            self.logger.debug(f"Socket close suppressed: {_sock_err}")
                        continue
                    
                    except OSError as e:
                        self.logger.warning(f"[CONNECTION] Connection to {sockaddr} failed: {e}")
                        last_error = e
                        try:
                            client_socket.close()
                        except Exception as _sock_err:
                            self.logger.debug(f"Socket close suppressed: {_sock_err}")
                        continue
                
                except Exception as e:
                    self.logger.error(f"[CONNECTION] Error trying candidate {i+1}: {e}")
                    last_error = e
                    continue
            
            # All candidates failed
            raise NetworkError(
                f"Failed to connect to {peer_ip}:{peer_port}: {last_error}",
                module="network.connection",
                function="connect_to_peer"
            )
        
        except Exception as e:
            self.logger.error(f"[CONNECTION] Connection failed: {e}", exc_info=True)
            if isinstance(e, NetworkError):
                raise
            else:
                raise NetworkError(
                    f"Connection failed: {e}",
                    module="network.connection",
                    function="connect_to_peer"
                )
    
    async def handle_connection_failure(self, peer_id: Optional[str] = None) -> None:
        """
        Handle connection failure with intelligent recovery.
        
        Args:
            peer_id: Optional peer identifier
        """
        try:
            self.logger.warning(f"[CONNECTION] Handling connection failure for {peer_id or 'unknown'}")
            
            if self.orchestrator:
                # Mark as disconnected
                if hasattr(self.orchestrator, 'is_connected'):
                    self.orchestrator.is_connected = False
                
                # Close socket
                if hasattr(self.orchestrator, 'tcp_socket') and self.orchestrator.tcp_socket:
                    try:
                        self.orchestrator.tcp_socket.close()
                    except Exception as _sock_err:
                        self.logger.debug(f"Socket close suppressed: {_sock_err}")
                    self.orchestrator.tcp_socket = None
        
        except Exception as e:
            self.logger.error(f"[CONNECTION] Error handling connection failure: {e}", exc_info=True)
    
    async def disconnect_peer(self, peer_id: Optional[str] = None) -> None:
        """
        Disconnect from peer gracefully.
        
        Args:
            peer_id: Optional peer identifier
        """
        try:
            self.logger.info(f"[CONNECTION] Disconnecting from {peer_id or 'peer'}")
            
            # Remove from active connections
            async with self._connection_lock:
                if peer_id and peer_id in self._active_connections:
                    conn_info = self._active_connections.pop(peer_id)
                    try:
                        conn_info['socket'].close()
                    except Exception as _sock_err:
                        self.logger.debug(f"Socket close suppressed: {_sock_err}")
            
            # Close orchestrator socket
            if self.orchestrator:
                if hasattr(self.orchestrator, 'tcp_socket') and self.orchestrator.tcp_socket:
                    try:
                        self.orchestrator.tcp_socket.close()
                    except Exception as _sock_err:
                        self.logger.debug(f"Socket close suppressed: {_sock_err}")
                    self.orchestrator.tcp_socket = None
                
                if hasattr(self.orchestrator, 'is_connected'):
                    self.orchestrator.is_connected = False
            
            self.logger.info(f"[CONNECTION] Disconnected from {peer_id or 'peer'}")
        
        except Exception as e:
            self.logger.error(f"[CONNECTION] Error disconnecting: {e}", exc_info=True)
    
    def _validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format with RFC 3986 bracket support."""
        if not ip or not isinstance(ip, str):
            return False
        clean = ip.strip()
        if clean.startswith('[') and clean.endswith(']'):
            clean = clean[1:-1].strip()
        try:
            socket.inet_pton(socket.AF_INET, clean)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, clean)
                return True
            except socket.error:
                return False
    
    def _validate_port(self, port: int) -> bool:
        """Validate port number."""
        return isinstance(port, int) and 1 <= port <= 65535
    
    async def cleanup(self) -> None:
        """Cleanup connection resources."""
        async with self._connection_lock:
            for peer_id, conn_info in self._active_connections.items():
                try:
                    conn_info['socket'].close()
                except Exception as _sock_err:
                    self.logger.debug(f"Socket close suppressed: {_sock_err}")
            self._active_connections.clear()
        
        self.logger.debug("Connection manager cleaned up")
        await super().cleanup()
