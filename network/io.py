"""
Network I/O operations.

Provides low-level network communication primitives with error handling and logging.
"""

import asyncio
import logging
import json
from typing import Optional, Tuple

try:
    from ..base import BaseModule, NetworkError
except (ImportError, ValueError):
    from base import BaseModule, NetworkError


class NetworkIO(BaseModule):
    """
    Network I/O operations.
    
    Provides low-level network communication primitives including:
    - Framed message sending and receiving
    - Encrypted message handling
    - Error handling and logging
    - Connection state management
    """
    
    # I/O configuration constants
    DEFAULT_TIMEOUT = 30.0  # seconds
    FRAME_SIZE_BYTES = 4  # 4 bytes for frame size header
    MAX_FRAME_SIZE = 4 * 1024 * 1024  # 4 MB absolute frame abort ceiling
    
    def __init__(self, orchestrator):
        """
        Initialize network I/O manager.
        
        Args:
            orchestrator: Reference to main SecureP2PChat orchestrator
        """
        super().__init__(orchestrator)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def send_message(self, socket, message: bytes, timeout: Optional[float] = None) -> bool:
        """
        Send a framed message over socket.
        
        Sends a message with a 4-byte length prefix for framing.
        
        Args:
            socket: Socket to send on
            message: Message bytes to send
            timeout: Optional timeout in seconds
        
        Returns:
            True if send successful, False otherwise
        
        Raises:
            NetworkError: If send fails
        """
        if timeout is None:
            timeout = self.DEFAULT_TIMEOUT
        
        try:
            if not socket:
                raise NetworkError(
                    "Socket is None",
                    module="network.io",
                    function="send_message"
                )
            
            if not isinstance(message, bytes):
                raise NetworkError(
                    f"Message must be bytes, got {type(message).__name__}",
                    module="network.io",
                    function="send_message"
                )
            
            # Check message size
            if len(message) > self.MAX_FRAME_SIZE:
                raise NetworkError(
                    f"Message size {len(message)} exceeds max {self.MAX_FRAME_SIZE}",
                    module="network.io",
                    function="send_message"
                )
            
            # Create framed message: 4-byte length + message
            frame_size = len(message).to_bytes(self.FRAME_SIZE_BYTES, byteorder='big')
            framed_message = frame_size + message
            
            # Send with timeout
            try:
                await asyncio.wait_for(
                    socket.sendall(framed_message),
                    timeout=timeout
                )
                self.logger.debug(f"Sent {len(message)} bytes")
                return True
            except asyncio.TimeoutError:
                raise NetworkError(
                    f"Send timeout after {timeout}s",
                    module="network.io",
                    function="send_message"
                )
        
        except Exception as e:
            self.logger.error(f"Failed to send message: {e}", exc_info=True)
            if isinstance(e, NetworkError):
                raise
            else:
                raise NetworkError(
                    f"Send failed: {e}",
                    module="network.io",
                    function="send_message"
                )
    
    async def receive_message(self, socket, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Receive a framed message from socket.
        
        Receives a message with a 4-byte length prefix for framing.
        
        Args:
            socket: Socket to receive from
            timeout: Optional timeout in seconds
        
        Returns:
            Message bytes if received, None if connection closed
        
        Raises:
            NetworkError: If receive fails
        """
        if timeout is None:
            timeout = self.DEFAULT_TIMEOUT
        
        try:
            if not socket:
                raise NetworkError(
                    "Socket is None",
                    module="network.io",
                    function="receive_message"
                )
            
            # Receive frame size (4 bytes)
            try:
                frame_size_data = await asyncio.wait_for(
                    self._receive_exact(socket, self.FRAME_SIZE_BYTES),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                raise NetworkError(
                    f"Receive timeout after {timeout}s",
                    module="network.io",
                    function="receive_message"
                )
            
            if not frame_size_data:
                self.logger.debug("Connection closed by peer (no frame size)")
                return None
            
            # Parse frame size
            frame_size = int.from_bytes(frame_size_data, byteorder='big')
            
            if frame_size > self.MAX_FRAME_SIZE:
                raise NetworkError(
                    f"Frame size {frame_size} exceeds max {self.MAX_FRAME_SIZE}",
                    module="network.io",
                    function="receive_message"
                )
            
            # Receive message data
            try:
                message_data = await asyncio.wait_for(
                    self._receive_exact(socket, frame_size),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                raise NetworkError(
                    f"Receive timeout after {timeout}s",
                    module="network.io",
                    function="receive_message"
                )
            
            if not message_data:
                self.logger.debug("Connection closed by peer (during message receive)")
                return None
            
            self.logger.debug(f"Received {len(message_data)} bytes")
            return message_data
        
        except Exception as e:
            self.logger.error(f"Failed to receive message: {e}", exc_info=True)
            if isinstance(e, NetworkError):
                raise
            else:
                raise NetworkError(
                    f"Receive failed: {e}",
                    module="network.io",
                    function="receive_message"
                )
    
    async def send_encrypted_message(self, peer_id: str, message: str) -> bool:
        """
        Send an encrypted message to a peer.
        
        This method encrypts the message using the orchestrator's encryption
        and sends it to the peer.
        
        Args:
            peer_id: Peer identifier
            message: Plaintext message to encrypt and send
        
        Returns:
            True if send successful, False otherwise
        
        Raises:
            NetworkError: If send fails
        """
        try:
            if not self.orchestrator:
                raise NetworkError(
                    "Orchestrator not available",
                    module="network.io",
                    function="send_encrypted_message"
                )
            
            # Encrypt message using orchestrator's encryption
            if not hasattr(self.orchestrator, '_encrypt_message'):
                raise NetworkError(
                    "Orchestrator encryption not available",
                    module="network.io",
                    function="send_encrypted_message"
                )
            
            encrypted_data = await self.orchestrator._encrypt_message(message)
            
            if not encrypted_data:
                raise NetworkError(
                    "Encryption returned empty data",
                    module="network.io",
                    function="send_encrypted_message"
                )
            
            # Get socket from orchestrator
            if not hasattr(self.orchestrator, 'tcp_socket') or not self.orchestrator.tcp_socket:
                raise NetworkError(
                    "TCP socket not available",
                    module="network.io",
                    function="send_encrypted_message"
                )
            
            # Send encrypted message
            return await self.send_message(self.orchestrator.tcp_socket, encrypted_data)
        
        except Exception as e:
            self.logger.error(f"Failed to send encrypted message to {peer_id}: {e}", exc_info=True)
            if isinstance(e, NetworkError):
                raise
            else:
                raise NetworkError(
                    f"Send encrypted message failed: {e}",
                    module="network.io",
                    function="send_encrypted_message"
                )
    
    async def receive_encrypted_message(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Receive and decrypt a message.
        
        This method receives an encrypted message from the socket and
        decrypts it using the orchestrator's decryption.
        
        Returns:
            Tuple of (sender_id, decrypted_message) or (None, None) if connection closed
        
        Raises:
            NetworkError: If receive fails
        """
        try:
            if not self.orchestrator:
                raise NetworkError(
                    "Orchestrator not available",
                    module="network.io",
                    function="receive_encrypted_message"
                )
            
            # Get socket from orchestrator
            if not hasattr(self.orchestrator, 'tcp_socket') or not self.orchestrator.tcp_socket:
                raise NetworkError(
                    "TCP socket not available",
                    module="network.io",
                    function="receive_encrypted_message"
                )
            
            # Receive encrypted message
            encrypted_data = await self.receive_message(self.orchestrator.tcp_socket)
            
            if not encrypted_data:
                return (None, None)
            
            # Decrypt message using orchestrator's decryption
            if not hasattr(self.orchestrator, '_decrypt_message'):
                raise NetworkError(
                    "Orchestrator decryption not available",
                    module="network.io",
                    function="receive_encrypted_message"
                )
            
            decrypted_message = await self.orchestrator._decrypt_message(encrypted_data)
            
            # Get sender ID from orchestrator
            sender_id = getattr(self.orchestrator, 'peer_username', 'unknown')
            
            return (sender_id, decrypted_message)
        
        except Exception as e:
            self.logger.error(f"Failed to receive encrypted message: {e}", exc_info=True)
            if isinstance(e, NetworkError):
                raise
            else:
                raise NetworkError(
                    f"Receive encrypted message failed: {e}",
                    module="network.io",
                    function="receive_encrypted_message"
                )
    
    async def _receive_exact(self, socket, num_bytes: int) -> bytes:
        """
        Receive exactly num_bytes from socket.
        
        Args:
            socket: Socket to receive from
            num_bytes: Number of bytes to receive
        
        Returns:
            Bytes received, or empty bytes if connection closed
        """
        data = b''
        while len(data) < num_bytes:
            chunk = await asyncio.get_event_loop().sock_recv(socket, num_bytes - len(data))
            if not chunk:
                return data  # Connection closed
            data += chunk
        return data
    
    async def cleanup(self) -> None:
        """Cleanup network I/O resources."""
        self.logger.debug("Network I/O cleaned up")
        await super().cleanup()
