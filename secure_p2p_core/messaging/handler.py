"""
Message handling operations.

Provides message routing and processing.
"""

import time
import re
import asyncio
from ..base import BaseModule

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"


class MessageHandler(BaseModule):
    """Message handling operations."""
    
    async def handle_message(self, decrypted_message: str) -> None:
        """
        Handle incoming decrypted message.
        
        Routes messages to appropriate handlers based on message type.
        
        Args:
            decrypted_message: The decrypted message string
        """
        try:
            orchestrator = self.orchestrator
            
            # Handle username announcement
            if decrypted_message.startswith('USERNAME:'):
                peer_name_candidate = decrypted_message[len('USERNAME:'):].strip()
                if (1 <= len(peer_name_candidate) <= orchestrator.MAX_USERNAME_LENGTH and 
                    re.match(orchestrator.USERNAME_REGEX, peer_name_candidate)):
                    orchestrator.peer_username = peer_name_candidate
                    # Clear line and print notification
                    print("\r" + " " * 100)
                    print(f"\n{GREEN}{BOLD}Connected with {orchestrator.peer_username}{RESET}\n")
                    print(f"{CYAN}{orchestrator.local_username}: {RESET}", end='', flush=True)
                else:
                    self.logger.warning(f"Received invalid username: '{peer_name_candidate}'")
            
            # Handle exit message
            elif decrypted_message == 'EXIT':
                print("\r" + " " * 100)
                print(f"\n{YELLOW}{orchestrator.peer_username} has left the chat.{RESET}")
                self.logger.info(f"Peer {orchestrator.peer_username} initiated disconnect.")
                # Trigger clean close, but don't attempt reconnect here as it was intentional
                await orchestrator._close_connection(attempt_reconnect=False)
                
                # Return to the main menu automatically
                print("\nDisconnected. Returning to main menu.")
                orchestrator.stop_event.set()
                # Schedule a task to restart the handle_connections method
                asyncio.create_task(orchestrator.handle_connections())
            
            # Handle regular messages
            elif decrypted_message.startswith('MSG:'):
                parts = decrypted_message.split(':', 2)
                if len(parts) == 3:
                    sender, content = parts[1], parts[2]
                    # Store message in history
                    if hasattr(orchestrator, 'message_history'):
                        if len(orchestrator.message_history) >= orchestrator.max_history_size:
                            orchestrator.message_history.pop(0)
                        orchestrator.message_history.append({
                            "sender": sender, 
                            "content": content, 
                            "timestamp": time.time()
                        })
                    
                    # Clear line before printing message
                    print("\r" + " " * 100 + "\r", end='')
                    print(f"{MAGENTA}{sender}: {RESET}{content}")
                    print(f"{CYAN}{orchestrator.local_username}: {RESET}", end='', flush=True)
                else:
                    self.logger.warning(f"Received malformed message: {decrypted_message}")
            
            # Handle heartbeat
            elif decrypted_message == 'HEARTBEAT':
                orchestrator.last_heartbeat_received = time.time()
                self.logger.debug("Received heartbeat message")
                # Send heartbeat response
                try:
                    heartbeat_ack = await orchestrator._encrypt_message("HEARTBEAT_ACK")
                    await orchestrator.p2p.send_framed(orchestrator.tcp_socket, heartbeat_ack)
                except Exception as e:
                    self.logger.debug(f"Failed to send heartbeat ACK: {e}")
            
            # Handle heartbeat acknowledgment
            elif decrypted_message == 'HEARTBEAT_ACK':
                orchestrator.last_heartbeat_received = time.time()
                self.logger.debug("Received heartbeat acknowledgment")
            
            # Handle reconnection notification
            elif decrypted_message == 'RECONNECTED':
                print("\r" + " " * 100)
                print(f"\n{GREEN}{orchestrator.peer_username} has reconnected.{RESET}")
                print(f"{CYAN}{orchestrator.local_username}: {RESET}", end='', flush=True)
            
            # Handle key rotation
            elif decrypted_message.startswith('KEY_ROTATION:'):
                self.logger.debug("Received key rotation message")
                await orchestrator._handle_key_rotation(decrypted_message)
            
            # Handle key rotation acknowledgment
            elif decrypted_message.startswith('KEY_ROTATION_ACK:'):
                self.logger.debug("Received key rotation acknowledgment")
                try:
                    ack_time = int(decrypted_message.split(':', 1)[1])
                    self.logger.debug(f"Key rotation acknowledged at {time.ctime(ack_time)}")
                except Exception as _ts_err:
                    self.logger.debug(f"Non-critical rotation ts parse error: {_ts_err}")
            
            # Handle file messages
            elif decrypted_message.startswith('FILE:'):
                await orchestrator._handle_file_message(decrypted_message)
            
            # Unknown message type
            else:
                self.logger.warning(f"Received unknown message type: {decrypted_message[:50]}...")
        
        except Exception as e:
            self.logger.error(f"Error handling message: {e}", exc_info=True)
            raise
    
    async def route_message(self, message_type: str, message: dict) -> None:
        """
        Route message to appropriate handler based on type.
        
        Args:
            message_type: Type of message (MSG, FILE, HEARTBEAT, etc.)
            message: Message data dictionary
        """
        try:
            if message_type == 'MSG':
                # Handle regular message
                await self.handle_message(f"MSG:{message.get('sender', 'Unknown')}:{message.get('content', '')}")
            elif message_type == 'FILE':
                # Handle file message
                await self.handle_message(f"FILE:{message.get('data', '')}")
            elif message_type == 'HEARTBEAT':
                # Handle heartbeat
                await self.handle_message('HEARTBEAT')
            elif message_type == 'KEY_ROTATION':
                # Handle key rotation
                await self.handle_message(f"KEY_ROTATION:{message.get('data', '')}")
            else:
                self.logger.warning(f"Unknown message type for routing: {message_type}")
        
        except Exception as e:
            self.logger.error(f"Error routing message: {e}", exc_info=True)
            raise
    
    async def process_incoming_message(self, encrypted_message: bytes) -> str:
        """
        Process incoming encrypted message.
        
        Decrypts the message and handles it appropriately.
        
        Args:
            encrypted_message: The encrypted message bytes
            
        Returns:
            str: The decrypted message content
        """
        try:
            # Decrypt the message
            decrypted_message = await self.orchestrator._decrypt_message(encrypted_message)
            
            if not decrypted_message:
                self.logger.warning("Failed to decrypt message")
                return ""
            
            # Handle the decrypted message
            await self.handle_message(decrypted_message)
            
            return decrypted_message
        
        except UnicodeDecodeError:
            self.logger.warning("Received non-UTF8 data, ignoring.")
            return ""
        except Exception as e:
            self.logger.error(f"Error processing incoming message: {e}", exc_info=True)
            return ""

    async def receive_messages(self) -> None:
        """Receive incoming messages."""
        if self.orchestrator and hasattr(self.orchestrator, '_receive_messages'):
            res = self.orchestrator._receive_messages()
            if asyncio.iscoroutine(res):
                await res

    async def handle_command(self, command: str) -> None:
        """Handle slash command."""
        if self.orchestrator and hasattr(self.orchestrator, '_handle_command'):
            res = self.orchestrator._handle_command(command)
            if asyncio.iscoroutine(res):
                await res

