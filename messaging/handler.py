"""
Message handling operations.

Provides message routing and processing.
"""

import time
import re
import asyncio
import hashlib
try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule

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
                    self.logger.warning("Received invalid username format from peer")
            
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
                    # Validate sender format and length (Item 38 / Finding 6.1)
                    if len(sender) > 64 or not re.match(r'^[a-zA-Z0-9_-]{1,64}$', sender):
                        self.logger.warning(f"Rejected message with invalid sender identifier: {sender[:16]}")
                        return
                    # Unified caps: chat content <= 64KB strictest (see utils/message_caps).
                    try:
                        from utils.message_caps import MAX_MESSAGE_PAYLOAD as _CAP_MSG
                    except ImportError:
                        try:
                            from ..utils.message_caps import MAX_MESSAGE_PAYLOAD as _CAP_MSG  # type: ignore
                        except ImportError:
                            _CAP_MSG = 65536
                    if len(content) > _CAP_MSG:
                        self.logger.warning(f"Rejected oversized message content ({len(content)} bytes)")
                        return
                    # Bind displayed sender to verified peer identity (Finding 34 / Item 34)
                    if orchestrator.peer_username and sender != orchestrator.peer_username:
                        self.logger.warning(f"SECURITY ALERT: Message sender claim does not match authenticated peer '{orchestrator.peer_username}'. Rejecting unauthenticated message.")
                        return

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
                    # Sanitize logging: avoid leaking plaintext message content into logs (Item 38)
                    content_digest = hashlib.sha384(decrypted_message.encode('utf-8', errors='replace')).hexdigest()[:16]
                    self.logger.warning(f"Received malformed MSG (length: {len(decrypted_message)}, sha384: {content_digest}...)")
            
            # Handle relayed messages with hop count limit (Item 30)
            # 2028 hardening: unify to MESH_MAX_HOPS=5 (strict, no downgrade).
            # Old limit 8 allowed wider amplification than mesh layer.
            elif decrypted_message.startswith('RELAY:'):
                parts = decrypted_message.split(':', 2)
                if len(parts) >= 2:
                    try:
                        hop_count = int(parts[1])
                        if hop_count >= 5:
                            self.logger.warning(f"SECURITY ALERT: Dropping relayed packet exceeding MAX_HOPS limit (hops={hop_count} >= 5)")
                            return
                    except ValueError:
                        self.logger.warning("Invalid hop count format in RELAY message")
                        return

            # Handle heartbeat acknowledgment FIRST: 'HEARTBEAT_ACK...' also
            # startswith 'HEARTBEAT', so this branch must precede the
            # heartbeat branch or ACKs would be answered (ping-pong).
            # ACKs never trigger a send (Item 30 / audit 4.5).
            elif decrypted_message.startswith('HEARTBEAT_ACK'):
                orchestrator.last_heartbeat_received = time.time()
                self.logger.debug("Received heartbeat acknowledgment")

            # Handle heartbeat (inbound flood throttle: max 1 ACK / 5s;
            # txid reflected only when short + alnum, else dropped)
            elif decrypted_message.startswith('HEARTBEAT'):
                orchestrator.last_heartbeat_received = time.time()
                self.logger.debug("Received heartbeat message")
                # Send heartbeat response with transaction ID to prevent ping-pong loops (Item 30)
                try:
                    now_hb = time.time()
                    last_ack = getattr(orchestrator, '_last_hb_ack_time', 0.0)
                    if now_hb - last_ack < 5.0:
                        return
                    orchestrator._last_hb_ack_time = now_hb
                    parts = decrypted_message.split(':', 1)
                    txid = parts[1] if len(parts) > 1 else ""
                    if len(txid) > 64 or (txid and not re.fullmatch(r'[A-Za-z0-9_-]+', txid)):
                        self.logger.warning("Dropping heartbeat with malformed txid")
                        return
                    ack_msg = f"HEARTBEAT_ACK:{txid}" if txid else "HEARTBEAT_ACK"
                    heartbeat_ack = await orchestrator._encrypt_message(ack_msg)
                    if heartbeat_ack:
                        await orchestrator.p2p.send_framed(orchestrator.tcp_socket, heartbeat_ack)
                except Exception as e:
                    self.logger.debug(f"Failed to send heartbeat ACK: {e}")
            
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
            
            # Unknown message type (log digest only, never plaintext)
            else:
                unknown_digest = hashlib.sha384(decrypted_message.encode('utf-8', errors='replace')).hexdigest()[:16]
                self.logger.warning(f"Received unknown message type (length: {len(decrypted_message)}, sha384: {unknown_digest})")
        
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
