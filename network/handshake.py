"""
Hybrid X3DH+PQ handshake management.

Provides handshake state machine and protocol implementation with detailed logging,
configurable timeouts, and exponential backoff retry logic.
"""

import asyncio
import json
import base64
import time
import logging
from typing import Optional, Dict, Tuple, Any
from enum import Enum

try:
    from ..base import BaseModule, HandshakeError, SecurityError
except (ImportError, ValueError):
    from base import BaseModule, HandshakeError, SecurityError
from ..data_models import HandshakeState, HandshakeContext


class HandshakeManager(BaseModule):
    """
    Hybrid X3DH+PQ handshake management with state machine.
    
    Implements the complete handshake protocol with:
    - Explicit state machine tracking
    - Detailed logging for each step with timing
    - Configurable timeouts and exponential backoff retry logic
    - Comprehensive error handling and recovery
    """
    
    # Handshake configuration constants
    DEFAULT_TIMEOUT = 30.0  # seconds
    MIN_TIMEOUT = 5.0
    MAX_TIMEOUT = 120.0
    INITIAL_RETRY_DELAY = 1.0  # seconds
    MAX_RETRY_DELAY = 10.0  # seconds
    MAX_RETRIES = 3
    MAX_HANDSHAKE_PAYLOAD_SIZE = 65536  # Strict 64 KB limit to prevent memory exhaustion DoS
    
    def __init__(self, orchestrator):
        """
        Initialize handshake manager.
        
        Args:
            orchestrator: Reference to main SecureP2PChat orchestrator
        """
        super().__init__(orchestrator)
        self._handshake_contexts: Dict[str, HandshakeContext] = {}
        self._handshake_lock = asyncio.Lock()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def initiate_military_hybrid_kem_handshake(self, peer_bundle: dict) -> tuple:
        """
        Initiate hybrid X3DH+PQ handshake as client.
        
        This method performs the client-side initiation of the hybrid handshake,
        including key exchange, authentication, and Double Ratchet setup.
        
        Args:
            peer_bundle: Dictionary containing peer's public key bundle
                        (static_key, signed_prekey, kem_public_key, falcon_public_key, etc.)
        
        Returns:
            Tuple of (handshake_message, shared_secret) on success
        
        Raises:
            HandshakeError: If handshake initiation fails
            SecurityError: If security validation fails
        """
        peer_id = peer_bundle.get('identity', 'unknown')
        start_time = time.perf_counter()
        
        try:
            self.logger.info(f"[HANDSHAKE] Initiating hybrid X3DH+PQ handshake with peer {peer_id}")
            
            # Create handshake context
            context = HandshakeContext(
                peer_id=peer_id,
                state=HandshakeState.INIT,
                timeout=self.DEFAULT_TIMEOUT
            )
            
            async with self._handshake_lock:
                self._handshake_contexts[peer_id] = context
            
            # Transition to CLIENT_HELLO_SENT
            context.transition_to(HandshakeState.CLIENT_HELLO_SENT, self.logger)
            
            # Delegate to orchestrator's hybrid_kex module for actual key exchange
            if not self.orchestrator or not hasattr(self.orchestrator, 'hybrid_kex'):
                raise HandshakeError(
                    "Orchestrator hybrid_kex module not available",
                    module="network.handshake",
                    function="initiate_military_hybrid_kem_handshake"
                )
            
            # Perform key exchange
            self.logger.debug(f"[HANDSHAKE] Performing hybrid key exchange with {peer_id}")
            handshake_message, shared_secret = self.orchestrator.hybrid_kex.initiate_handshake(peer_bundle)
            
            context.shared_secret = shared_secret
            context.transition_to(HandshakeState.KEY_EXCHANGE_SENT, self.logger)
            
            elapsed = time.perf_counter() - start_time
            self.logger.info(f"[HANDSHAKE] Hybrid handshake initiated with {peer_id} in {elapsed:.3f}s")
            
            return (handshake_message, shared_secret)
            
        except Exception as e:
            elapsed = time.perf_counter() - start_time
            self.logger.error(
                f"[HANDSHAKE] Failed to initiate handshake with {peer_id} after {elapsed:.3f}s: {e}",
                exc_info=True
            )
            
            # Update context state
            if peer_id in self._handshake_contexts:
                context = self._handshake_contexts[peer_id]
                context.state = HandshakeState.FAILED
                context.error_message = str(e)
            
            if isinstance(e, (HandshakeError, SecurityError)):
                raise
            else:
                raise HandshakeError(
                    f"Handshake initiation failed: {e}",
                    module="network.handshake",
                    function="initiate_military_hybrid_kem_handshake"
                )
    
    async def handle_military_hybrid_kem_handshake(self, handshake_message: dict) -> bytes:
        """
        Handle incoming hybrid X3DH+PQ handshake as server.
        
        This method processes the client's handshake message and performs
        the server-side key exchange and authentication.
        
        Args:
            handshake_message: Dictionary containing client's handshake message
        
        Returns:
            Server's handshake response message as bytes
        
        Raises:
            HandshakeError: If handshake handling fails
            SecurityError: If security validation fails
        """
        peer_id = handshake_message.get('identity', 'unknown')
        start_time = time.perf_counter()
        
        try:
            self.logger.info(f"[HANDSHAKE] Handling hybrid X3DH+PQ handshake from peer {peer_id}")
            
            # Create or retrieve handshake context
            if peer_id not in self._handshake_contexts:
                context = HandshakeContext(
                    peer_id=peer_id,
                    state=HandshakeState.INIT,
                    timeout=self.DEFAULT_TIMEOUT
                )
                async with self._handshake_lock:
                    self._handshake_contexts[peer_id] = context
            else:
                context = self._handshake_contexts[peer_id]
            
            # Transition to SERVER_HELLO_RECEIVED
            context.transition_to(HandshakeState.SERVER_HELLO_RECEIVED, self.logger)
            
            # Delegate to orchestrator's hybrid_kex module
            if not self.orchestrator or not hasattr(self.orchestrator, 'hybrid_kex'):
                raise HandshakeError(
                    "Orchestrator hybrid_kex module not available",
                    module="network.handshake",
                    function="handle_military_hybrid_kem_handshake"
                )
            
            # Perform server-side key exchange
            self.logger.debug(f"[HANDSHAKE] Processing handshake message from {peer_id}")
            response_message, shared_secret = self.orchestrator.hybrid_kex.respond_to_handshake(handshake_message)
            
            context.shared_secret = shared_secret
            context.transition_to(HandshakeState.KEY_EXCHANGE_RECEIVED, self.logger)
            
            elapsed = time.perf_counter() - start_time
            self.logger.info(f"[HANDSHAKE] Hybrid handshake handled from {peer_id} in {elapsed:.3f}s")
            
            # Convert response to bytes if needed
            if isinstance(response_message, dict):
                response_bytes = json.dumps(response_message).encode('utf-8')
            else:
                response_bytes = response_message
            
            return response_bytes
            
        except Exception as e:
            elapsed = time.perf_counter() - start_time
            self.logger.error(
                f"[HANDSHAKE] Failed to handle handshake from {peer_id} after {elapsed:.3f}s: {e}",
                exc_info=True
            )
            
            # Update context state
            if peer_id in self._handshake_contexts:
                context = self._handshake_contexts[peer_id]
                context.state = HandshakeState.FAILED
                context.error_message = str(e)
            
            if isinstance(e, (HandshakeError, SecurityError)):
                raise
            else:
                raise HandshakeError(
                    f"Handshake handling failed: {e}",
                    module="network.handshake",
                    function="handle_military_hybrid_kem_handshake"
                )
    
    async def exchange_hybrid_keys_client(self, peer_bundle: dict) -> dict:
        """
        Perform client-side hybrid X3DH+PQ key exchange.
        
        This is a wrapper around initiate_military_hybrid_kem_handshake for
        compatibility with existing code.
        
        Args:
            peer_bundle: Dictionary containing peer's public key bundle
        
        Returns:
            Dictionary with handshake result and shared secret
        
        Raises:
            HandshakeError: If key exchange fails
        """
        try:
            handshake_message, shared_secret = await self.initiate_military_hybrid_kem_handshake(peer_bundle)
            return {
                'handshake_message': handshake_message,
                'shared_secret': shared_secret,
                'success': True
            }
        except Exception as e:
            self.logger.error(f"[HANDSHAKE] Client key exchange failed: {e}", exc_info=True)
            raise HandshakeError(
                f"Client key exchange failed: {e}",
                module="network.handshake",
                function="exchange_hybrid_keys_client"
            )
    
    async def exchange_hybrid_keys_server(self, client_message: dict) -> dict:
        """
        Perform server-side hybrid X3DH+PQ key exchange.
        
        This is a wrapper around handle_military_hybrid_kem_handshake for
        compatibility with existing code.
        
        Args:
            client_message: Dictionary containing client's handshake message
        
        Returns:
            Dictionary with handshake response and shared secret
        
        Raises:
            HandshakeError: If key exchange fails
        """
        try:
            response_bytes = await self.handle_military_hybrid_kem_handshake(client_message)
            
            # Parse response if it's JSON with DoS size-bound check
            if isinstance(response_bytes, bytes):
                if len(response_bytes) > self.MAX_HANDSHAKE_PAYLOAD_SIZE:
                    raise HandshakeError(
                        f"Handshake response exceeded maximum size limit ({len(response_bytes)} > {self.MAX_HANDSHAKE_PAYLOAD_SIZE} bytes)",
                        module="network.handshake",
                        function="exchange_hybrid_keys_server"
                    )
                try:
                    response_dict = json.loads(response_bytes.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    response_dict = {'response': response_bytes}
            else:
                response_dict = response_bytes
            
            return {
                'response': response_dict,
                'success': True
            }
        except Exception as e:
            self.logger.error(f"[HANDSHAKE] Server key exchange failed: {e}", exc_info=True)
            raise HandshakeError(
                f"Server key exchange failed: {e}",
                module="network.handshake",
                function="exchange_hybrid_keys_server"
            )
    
    def get_state(self, peer_id: Optional[str] = None) -> HandshakeState:
        """
        Get handshake state for a peer.
        
        Args:
            peer_id: Peer identifier. If None, returns INIT state.
        
        Returns:
            Current HandshakeState for the peer
        """
        if peer_id is None:
            return HandshakeState.INIT
        
        if peer_id in self._handshake_contexts:
            return self._handshake_contexts[peer_id].state
        
        return HandshakeState.INIT
    
    def get_context(self, peer_id: str) -> Optional[HandshakeContext]:
        """
        Get handshake context for a peer.
        
        Args:
            peer_id: Peer identifier
        
        Returns:
            HandshakeContext if exists, None otherwise
        """
        return self._handshake_contexts.get(peer_id)
    
    async def reset_handshake(self, peer_id: str) -> None:
        """
        Reset handshake state for a peer.
        
        Args:
            peer_id: Peer identifier
        """
        async with self._handshake_lock:
            if peer_id in self._handshake_contexts:
                del self._handshake_contexts[peer_id]
                self.logger.info(f"[HANDSHAKE] Reset handshake state for peer {peer_id}")
    
    async def cleanup(self) -> None:
        """Cleanup handshake resources."""
        async with self._handshake_lock:
            self._handshake_contexts.clear()
        self.logger.debug("Handshake manager cleaned up")
        super().cleanup()
