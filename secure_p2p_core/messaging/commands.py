"""
Command processing operations.

Provides command handling and execution for chat commands.
"""

import sys
import time
import subprocess
from typing import Any, Dict, Optional
from ..base import BaseModule

# ANSI color codes for terminal output
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"


class CommandProcessor(BaseModule):
    """Command processing operations for chat commands."""
    
    async def handle_command(self, command: str, args: list) -> None:
        """
        Handle special chat commands starting with /
        
        Args:
            command: The command string entered by the user
            args: Additional arguments (not used in current implementation)
        """
        try:
            # Special case for 'security' command without slash prefix
            if command.strip().lower() == 'security':
                self.orchestrator.display_security_recommendations()
                print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
                return

            # Validate command format using security validation module
            if not self.orchestrator.security.validation.validate_command(command):
                print(f"\n{RED}Invalid command format. Type /help for available commands.{RESET}")
                print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
                return

            # Parse command
            cmd_parts = command.split(maxsplit=1)
            cmd = cmd_parts[0].lower()

            # Execute the appropriate command
            await self.execute_command(cmd, cmd_parts)
            
        except Exception as e:
            self.logger.error(f"Command handling failed: {e}", exc_info=True)
            print(f"\n{RED}Error executing command: {e}{RESET}")
            print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
    
    async def execute_command(self, command: str, args: list) -> Any:
        """
        Execute a specific command.
        
        Args:
            command: The command to execute (e.g., '/help', '/status')
            args: Command arguments (parsed command parts)
            
        Returns:
            Command execution result (if any)
        """
        try:
            cmd = command.lower()
            
            if cmd == '/help':
                self._show_help()
                
            elif cmd == '/clear':
                self._clear_screen()
                
            elif cmd == '/status':
                self._show_status()
                
            elif cmd == '/identity':
                self._show_identity()
                
            elif cmd == '/config':
                self._show_config()
                
            elif cmd == '/security':
                self.orchestrator.display_security_recommendations()
                print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
                
            elif cmd == '/rotate':
                await self._rotate_identity()
                
            elif cmd == '/sendfile':
                if len(args) < 2:
                    print("\r" + " " * 100)
                    print(f"\n{RED}Usage: /sendfile <file_path>{RESET}")
                    print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
                else:
                    file_path = args[1].strip()
                    await self.orchestrator.send_file(file_path)
                    
            elif cmd == '/transfers':
                self._show_transfers()
                
            elif cmd == '/exit':
                encrypted_exit = await self.orchestrator._encrypt_message("EXIT")
                await self.orchestrator.p2p.send_framed(self.orchestrator.tcp_socket, encrypted_exit)
                await self.orchestrator._close_connection(attempt_reconnect=False)
                
            else:
                print("\r" + " " * 100)
                print(f"\n{RED}Unknown command: {cmd}. Type /help for available commands.{RESET}")
                print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
                
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}", exc_info=True)
            raise
    
    async def process_command(self, peer_id: str, command_message: dict) -> None:
        """
        Process command message from a peer.
        
        Args:
            peer_id: The peer sending the command
            command_message: The command message data
        """
        try:
            # Log the command message
            self.logger.info(f"Processing command from peer {peer_id}: {command_message}")
            
            # Extract command details
            command = command_message.get('command', '')
            args = command_message.get('args', [])
            
            # Process the command (currently just logging)
            # In a full implementation, this would handle peer-to-peer commands
            self.logger.info(f"Peer command: {command} with args: {args}")
            
        except Exception as e:
            self.logger.error(f"Command processing failed: {e}", exc_info=True)
            raise
    
    # ========== Private Helper Methods ==========
    
    def _show_help(self) -> None:
        """Display help message with available commands."""
        print("\r" + " " * 100)
        print(f"\n{YELLOW}Available commands:{RESET}")
        print(f"  {BOLD}/help{RESET} - Show this help message")
        print(f"  {BOLD}/clear{RESET} - Clear the chat screen")
        print(f"  {BOLD}/status{RESET} - Show connection status")
        print(f"  {BOLD}/security{RESET} - Show security recommendations")
        print(f"  {BOLD}/identity{RESET} - Show identity information (ephemeral by default)")
        print(f"  {BOLD}/config{RESET} - Show configuration options and environment variables")
        print(f"  {BOLD}/sendfile <path>{RESET} - Send a file to the connected peer")
        print(f"  {BOLD}/transfers{RESET} - Show active file transfers")
        if self.orchestrator.use_ephemeral_identity:
            print(f"  {BOLD}/rotate{RESET} - Rotate to a new ephemeral identity (when disconnected)")
        print(f"  {BOLD}/exit{RESET} - Exit the chat")
        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
    
    def _clear_screen(self) -> None:
        """Clear the terminal screen using safe ANSI escape sequences."""
        # Use standard ANSI escape codes to clear screen and move cursor to home
        print('\033[2J\033[H', end='', flush=True)
        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
    
    def _show_status(self) -> None:
        """Display connection status information."""
        uptime = time.time() - self.orchestrator.last_heartbeat_received if self.orchestrator.last_heartbeat_received else 0
        print("\r" + " " * 100)
        print(f"\n{YELLOW}Secure Connection Status:{RESET}")
        print(f"  Connected to: {self.orchestrator.peer_username} [{self.orchestrator.peer_ip}]:{self.orchestrator.peer_port}")
        print(f"  Connection uptime: {int(uptime)} seconds")
        print(f"  Security: Hybrid X3DH+PQ & Double Ratchet active")

        # Show certificate verification status
        cert_status = f"{GREEN}Verified{RESET}" if self.orchestrator.security_verified.get('cert_exchange', False) else f"{YELLOW}Not verified{RESET}"
        print(f"  Certificate verification: {cert_status}")

        if hasattr(self.orchestrator, 'message_history'):
            print(f"  Messages in history: {len(self.orchestrator.message_history)}")
        print(f"  Messages queued: {self.orchestrator.message_queue.qsize()}")

        # Show ephemeral identity details if enabled
        if self.orchestrator.use_ephemeral_identity and hasattr(self.orchestrator, 'hybrid_kex'):
            time_left = int(self.orchestrator.hybrid_kex.next_rotation_time - time.time())
            print(f"  Ephemeral identity: {self.orchestrator.hybrid_kex.identity}")
            print(f"  Identity expires in: {time_left} seconds")

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
    
    def _show_identity(self) -> None:
        """Display identity information."""
        print("\r" + " " * 100)
        print(f"\n{YELLOW}Identity Information:{RESET}")

        if hasattr(self.orchestrator, 'hybrid_kex'):
            if self.orchestrator.use_ephemeral_identity:
                print(f"  Mode: {GREEN}Ephemeral (automatic rotation){RESET}")
                print(f"  Current identity: {self.orchestrator.hybrid_kex.identity}")
                time_left = int(self.orchestrator.hybrid_kex.next_rotation_time - time.time())
                print(f"  Expires in: {time_left} seconds")
                print(f"  Rotation interval: {self.orchestrator.ephemeral_key_lifetime} seconds")
            else:
                print(f"  Mode: {YELLOW}Persistent{RESET}")
                print(f"  Identity: {self.orchestrator.hybrid_kex.identity}")

            if self.orchestrator.in_memory_only:
                print(f"  Storage: {GREEN}Memory only (no disk persistence){RESET}")
            else:
                print(f"  Storage: {YELLOW}Disk-based{RESET}")
        else:
            print(f"  {RED}Identity information not available{RESET}")

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
    
    def _show_config(self) -> None:
        """Display configuration options and current settings."""
        print("\r" + " " * 100)
        print(f"\n{YELLOW}Configuration Options:{RESET}")
        print(f"The following environment variables can be used to configure the application:")

        print(f"\n{GREEN}Storage Configuration:{RESET}")
        print(f"  P2P_IN_MEMORY_ONLY=true|false - Store keys in memory only (default: true)")
        print(f"  P2P_BASE_DIR=/path - Base directory for all files (default: script directory)")
        print(f"  P2P_CERT_DIR=/path - Certificate directory (default: BASE_DIR/cert)")
        print(f"  P2P_KEYS_DIR=/path - Key directory (default: BASE_DIR/keys)")
        print(f"  P2P_CERT_PATH=/path - Path to TLS certificate (default: CERT_DIR/server.crt)")
        print(f"  P2P_KEY_PATH=/path - Path to TLS key (default: CERT_DIR/server.key)")
        print(f"  P2P_CA_PATH=/path - Path to CA certificate (default: CERT_DIR/ca.crt)")

        print(f"\n{GREEN}Identity Configuration:{RESET}")
        print(f"  P2P_EPHEMERAL_IDENTITY=true|false - Use ephemeral identities (default: true)")
        print(f"  P2P_EPHEMERAL_LIFETIME=seconds - Lifetime of ephemeral identities (default: {getattr(self.orchestrator, 'DEFAULT_KEY_LIFETIME', 3072)})")

        print(f"\n{GREEN}Authentication Configuration (Enforced by Default):{RESET}")
        print(f"  P2P_REQUIRE_AUTH=true|false - Require authentication (default: true, mutual ML-DSA-87)")
        print(f"  P2P_ENABLE_OAUTH=true|false - Enable optional OAuth device flow (default: false)")
        print(f"  P2P_OAUTH_PROVIDER=provider - OAuth provider (default: google, used if OAuth enabled)")
        print(f"  P2P_OAUTH_CLIENT_ID=id - OAuth client ID (REQUIRED if P2P_ENABLE_OAUTH=true)")

        print(f"\n{GREEN}Security Configuration:{RESET}")
        print(f"  P2P_POST_QUANTUM=true|false - Enable post-quantum cryptography (default: true)")

        print(f"\n{GREEN}Current Configuration:{RESET}")
        print(f"  Base directory: {self.orchestrator.base_dir}")
        print(f"  Certificate directory: {self.orchestrator.cert_dir}")
        print(f"  Keys directory: {self.orchestrator.keys_dir}")
        print(f"  In-memory only: {self.orchestrator.in_memory_only} (default: true)")
        print(f"  Ephemeral identity: {self.orchestrator.use_ephemeral_identity} (default: true)")
        print(f"  Authentication required: {self.orchestrator.require_authentication} (default: true)")
        if self.orchestrator.require_authentication:
            if getattr(self.orchestrator, 'enable_oauth', False):
                if not getattr(self.orchestrator, 'oauth_client_id', None):
                    print(f"  {RED}OAuth Client ID (P2P_OAUTH_CLIENT_ID): NOT SET (CRITICAL for current P2P_ENABLE_OAUTH=true setting){RESET}")
                else:
                    print(f"  OAuth Client ID (P2P_OAUTH_CLIENT_ID): {'Set (value hidden)' if self.orchestrator.oauth_client_id else 'NOT SET'}")
            else:
                print(f"  Auth Mechanism: {GREEN}Sovereign Mutual ML-DSA-87 Certificate Pinning (OAuth disabled){RESET}")

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
    
    async def _rotate_identity(self) -> None:
        """Rotate ephemeral identity."""
        if not self.orchestrator.use_ephemeral_identity:
            print("\r" + " " * 100)
            print(f"\n{RED}Ephemeral identity mode is not enabled (this is unexpected with default settings).{RESET}")
            print(f"{YELLOW}Ensure P2P_EPHEMERAL_IDENTITY is true (default).{RESET}")
        elif self.orchestrator.is_connected:
            print("\r" + " " * 100)
            print(f"\n{YELLOW}Cannot rotate identity while connected.{RESET}")
            print(f"{YELLOW}Disconnect first, then use /rotate.{RESET}")
        else:
            print("\r" + " " * 100)
            old_id = self.orchestrator.hybrid_kex.identity
            self.orchestrator.hybrid_kex.rotate_keys()
            new_id = self.orchestrator.hybrid_kex.identity
            print(f"\n{GREEN}Identity rotated successfully:{RESET}")
            print(f"  Old: {old_id}")
            print(f"  New: {new_id}")
            print(f"  Next rotation: {time.ctime(self.orchestrator.hybrid_kex.next_rotation_time)}")

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
    
    def _show_transfers(self) -> None:
        """Display active file transfers."""
        print("\r" + " " * 100)
        print(f"\n{YELLOW}Active File Transfers:{RESET}")
        if not self.orchestrator.active_file_transfers:
            print(f"  No active transfers")
        else:
            for file_id, transfer in self.orchestrator.active_file_transfers.items():
                metadata = transfer['metadata']
                status = transfer['status'].value
                transfer_type = "[SEND] Outgoing" if transfer['type'].startswith('outgoing') else "[RECV] Incoming"
                print(f"  {transfer_type}: {metadata.filename} ({metadata.file_size:,} bytes) - {status}")
                if transfer['type'] == 'incoming_offer' and 'chunks_received' in transfer:
                    received = len(transfer['chunks_received'])
                    total = metadata.total_chunks
                    progress = (received / total) * 100 if total > 0 else 0
                    print(f"    Progress: {progress:.1f}% ({received}/{total} chunks)")
        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
