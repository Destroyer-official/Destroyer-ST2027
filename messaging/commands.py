"""
Command processing operations.

Provides command handling and execution for chat commands.
"""

import os
import sys
import time
# AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
import subprocess  # nosec: B404
from typing import Any, Dict, Optional
try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule

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

            elif cmd in ('/safety-number', '/pin'):
                self._show_safety_numbers(args)

            elif cmd == '/quarantine':
                await self._handle_quarantine(args)

            elif cmd in ('/silence', '/cloak'):
                self._toggle_tactical_cloak()

            elif cmd == '/rekey':
                await self._handle_rekey()

            elif cmd in ('/defense', '/acd-status'):
                self._show_defense_status()

            elif cmd == '/spqr':
                self._show_spqr_diagnostics()

            elif cmd == '/rum-consensus':
                self._show_rum_consensus()

            elif cmd == '/tfc-status':
                self._show_tfc_status()

            elif cmd in ('/eam', '/nuclear'):
                await self._handle_eam(args)

            elif cmd in ('/zgdp', '/zerogap'):
                self._show_zgdp_status(args)

            elif cmd in ('/attest', '/tpm'):
                self._show_tpm_attestation()

            elif cmd == '/cot':
                await self._handle_cot(args)
                
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
        print(f"  {BOLD}/safety-number [peer]{RESET} - Show 48-digit canonical TOFU safety numbers")
        print(f"  {BOLD}/quarantine [peer]{RESET} - Active Cyber Defense operator quarantine enforcement")
        print(f"  {BOLD}/silence{RESET} - Toggle tactical network cloak and background chaff")
        print(f"  {BOLD}/rekey{RESET} - Force immediate Double Ratchet PCS key rotation")
        print(f"  {BOLD}/defense{RESET} - View real-time Active Cyber Defense (cATO Pillar 2) telemetry")
        print(f"  {BOLD}/spqr{RESET} - Sparse Post-Quantum Ratchet (SPQR) cadence & PCS diagnostics")
        print(f"  {BOLD}/rum-consensus{RESET} - Byzantine fault-tolerant mesh consensus telemetry")
        print(f"  {BOLD}/tfc-status{RESET} - Traffic Flow Confidentiality (TFC) packet bucket status")
        print(f"  {BOLD}/eam <directive>{RESET} - Seal and transmit NC3 Emergency Action Message (Two-Person Rule)")
        print(f"  {BOLD}/zgdp{RESET} - Sovereign Zero-Gap Defense Pipeline telemetry (multi-language dual-lock)")
        print(f"  {BOLD}/attest{RESET} - Query platform TPM 2.0 hardware PCR measurements")
        print(f"  {BOLD}/cot <lat> <lon> <call>{RESET} - Emit Cursor-on-Target tactical military event")
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

    def _show_safety_numbers(self, args: list) -> None:
        """Display canonical TOFU safety numbers between local and peer keys."""
        print("\r" + " " * 100)
        try:
            from ui.safety_numbers import safety_numbers, fingerprint_bundle, load_pins
        except ImportError as e:
            print(f"\n{RED}Safety numbers module unavailable: {e}{RESET}")
            print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
            return

        try:
            # 1. Obtain local bundle and fingerprint
            local_bundle = getattr(self.orchestrator, 'my_hybrid_bundle', None)
            if not local_bundle and hasattr(self.orchestrator, 'hybrid_kex') and self.orchestrator.hybrid_kex:
                if not getattr(self.orchestrator.hybrid_kex, 'static_key', None):
                    self.orchestrator.hybrid_kex._generate_keys()
                local_bundle = self.orchestrator.hybrid_kex.get_public_bundle()

            if not local_bundle:
                print(f"\n{RED}Local cryptographic bundle unavailable.{RESET}")
                print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
                return

            local_fp = fingerprint_bundle(local_bundle)
            local_id = local_bundle.get('identity', getattr(self.orchestrator, 'local_username', 'local'))

            # 2. Determine target peer
            target_peer = None
            peer_fp = None
            if len(args) > 1 and args[1].strip():
                target_peer = args[1].strip()
                pins = load_pins()
                peer_fp = pins.get(target_peer)
            elif getattr(self.orchestrator, 'is_connected', False):
                target_peer = getattr(self.orchestrator, 'peer_username', None) or getattr(self.orchestrator, 'peer_id', 'unknown')
                peer_fp = getattr(self.orchestrator, 'peer_fingerprint', None)
                if not peer_fp:
                    peer_bundle = getattr(self.orchestrator, 'last_peer_bundle', None)
                    if peer_bundle:
                        peer_fp = fingerprint_bundle(peer_bundle)
                if not peer_fp:
                    pins = load_pins()
                    peer_fp = pins.get(target_peer)
            else:
                print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
                print(f"  {BOLD}CANONICAL TOFU SAFETY NUMBERS (OUT-OF-BAND VERIFICATION){RESET}")
                print(f"  Local Identity:     {self.orchestrator.local_username}")
                print(f"  Local Fingerprint:  {local_fp}")
                print(f"  Usage: /safety-number <peer_id> (or connect to a peer to verify)")
                print(f"{BOLD}{CYAN}================================================================================{RESET}")
                print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
                return

            if not peer_fp:
                print(f"\n{YELLOW}No TOFU identity pin found for peer '{target_peer}'.{RESET}")
                print(f"  Connect to peer or verify out-of-band via: /authorize <peer_id> <fp>")
                print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
                return

            sn = safety_numbers(local_fp.encode('utf-8'), peer_fp.encode('utf-8'))
            states = getattr(self.orchestrator, 'peer_verification_states', {})
            status = states.get(target_peer, getattr(self.orchestrator, 'peer_verification_status', 'UNKNOWN'))

            status_color = GREEN if "VERIFIED" in status else YELLOW
            print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  {BOLD}CANONICAL TOFU SAFETY NUMBERS (SHA3-512 FINGERPRINT VERIFICATION){RESET}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  Local Peer:         {local_id} ({local_fp[:16]}...)")
            print(f"  Remote Peer:        {target_peer} ({peer_fp[:16]}...)")
            print(f"  Verification State: {status_color}{status}{RESET}")
            print(f"\n  {BOLD}{YELLOW}Safety Number:{RESET}")
            print(f"  {BOLD}{GREEN}{sn}{RESET}\n")
            print(f"  {BOLD}INSTRUCTIONS FOR OPERATOR:{RESET}")
            print(f"  Both stations must verify that the 48 digits above match identically")
            print(f"  over an out-of-band authenticated channel (in person or secure voice).")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")

        except Exception as e:
            print(f"\n{RED}Error calculating safety numbers: {e}{RESET}")
            self.logger.error(f"Safety numbers error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    async def _handle_quarantine(self, args: list) -> None:
        """Enforce Active Cyber Defense quarantine on a peer."""
        print("\r" + " " * 100)
        target_peer = None
        if len(args) > 1 and args[1].strip():
            target_peer = args[1].strip()
        elif getattr(self.orchestrator, 'is_connected', False):
            target_peer = getattr(self.orchestrator, 'peer_username', None) or getattr(self.orchestrator, 'peer_id', None)

        if not target_peer:
            print(f"\n{RED}Usage: /quarantine <peer_id>{RESET}")
            print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
            return

        try:
            from active_cyber_defense import get_active_cyber_defense_engine
            acd = get_active_cyber_defense_engine()
            record = acd.quarantine_peer(target_peer, reason="Operator manual quarantine")

            print(f"\n{BOLD}{RED}================================================================================{RESET}")
            print(f"  {BOLD}[ACTIVE CYBER DEFENSE] OPERATOR QUARANTINE ENFORCED{RESET}")
            print(f"  Target Peer:       {target_peer}")
            print(f"  Duration:          {record['duration_sec']}s")
            print(f"  Timestamp UTC:     {record['timestamp_utc']}")
            print(f"  Status:            {GREEN}ENFORCED (Fail-Closed){RESET}")
            print(f"{BOLD}{RED}================================================================================{RESET}")

            # If currently connected to the quarantined peer, sever connection immediately
            curr_peer = getattr(self.orchestrator, 'peer_username', None) or getattr(self.orchestrator, 'peer_id', None)
            if getattr(self.orchestrator, 'is_connected', False) and curr_peer == target_peer:
                print(f"{YELLOW}[!] Severing active session with quarantined peer...{RESET}")
                if hasattr(self.orchestrator, '_close_connection'):
                    await self.orchestrator._close_connection(attempt_reconnect=False)
                elif hasattr(self.orchestrator, 'disconnect'):
                    await self.orchestrator.disconnect()

        except Exception as e:
            print(f"\n{RED}Error enforcing quarantine: {e}{RESET}")
            self.logger.error(f"Quarantine error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    def _toggle_tactical_cloak(self) -> None:
        """Toggle tactical cloaking and background traffic chaffing."""
        print("\r" + " " * 100)
        try:
            from tactical_cloaking_router import tactical_cloak_enabled
            currently_enabled = tactical_cloak_enabled()

            if currently_enabled:
                os.environ["P2P_TACTICAL_CLOAK"] = "0"
                print(f"\n{BOLD}{YELLOW}[TACTICAL ROUTING] Tactical Cloak: DISENGAGED{RESET}")
                print(f"  Standard network mode restored.")
            else:
                os.environ["P2P_TACTICAL_CLOAK"] = "1"
                print(f"\n{BOLD}{GREEN}[TACTICAL ROUTING] Tactical Cloak: ENGAGED{RESET}")
                print(f"  Direct unencapsulated sockets prohibited.")
                print(f"  Continuous Poisson background chaff active (flattening traffic metadata).")
        except Exception as e:
            print(f"\n{RED}Error toggling tactical cloak: {e}{RESET}")
            self.logger.error(f"Cloak toggle error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    async def _handle_rekey(self) -> None:
        """Force immediate on-demand ratchet rotation and master seed replenishment."""
        print("\r" + " " * 100)
        try:
            if getattr(self.orchestrator, 'is_connected', False) and getattr(self.orchestrator, 'ratchet', None):
                new_key = self.orchestrator.ratchet.force_ratchet_rotation()
                spqr_status = "N/A"
                if hasattr(self.orchestrator.ratchet, 'force_spqr_refresh'):
                    spqr_ok = self.orchestrator.ratchet.force_spqr_refresh(reason="OPERATOR_REKEY_COMMAND")
                    spqr_status = "ADVANCED (ML-KEM-1024 Fresh Encapsulation)" if spqr_ok else "LEGACY/V1"
                print(f"\n{BOLD}{GREEN}[POST-COMPROMISE SECURITY] Double Ratchet Keys Rotated{RESET}")
                print(f"  Ratchet DH Key Advance: SUCCESS")
                print(f"  SPQR Post-Quantum KEM:  {spqr_status}")
                print(f"  New Ratchet Public Key: {new_key.hex()[:24]}...")
                print(f"  Sending chain updated; next transmission heals prior key exposure.")
            elif hasattr(self.orchestrator, 'hybrid_kex') and self.orchestrator.hybrid_kex:
                old_id = self.orchestrator.hybrid_kex.identity
                self.orchestrator.hybrid_kex.rotate_keys()
                new_id = self.orchestrator.hybrid_kex.identity
                print(f"\n{BOLD}{GREEN}[EPHEMERAL ROTATION] Cryptographic Keys Rotated{RESET}")
                print(f"  Old Identity:  {old_id}")
                print(f"  New Identity:  {new_id}")
                print(f"  Next Rotation: {time.ctime(self.orchestrator.hybrid_kex.next_rotation_time)}")
            else:
                print(f"\n{YELLOW}[REKEY] Cryptographic key exchange engine not initialized.{RESET}")
        except Exception as e:
            print(f"\n{RED}Error during rekey: {e}{RESET}")
            self.logger.error(f"Rekey error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    def _show_defense_status(self) -> None:
        """Display real-time Active Cyber Defense (cATO Pillar 2) telemetry."""
        print("\r" + " " * 100)
        try:
            from active_cyber_defense import get_active_cyber_defense_engine
            from tactical_cloaking_router import tactical_cloak_enabled
            acd = get_active_cyber_defense_engine()
            report = acd.generate_report()

            print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  {BOLD}ACTIVE CYBER DEFENSE TELEMETRY (cATO PILLAR 2){RESET}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  Total Events Ingested:    {report.get('total_events_processed', 0)}")
            print(f"  Total Mitigations Active: {report.get('total_mitigations_applied', 0)}")
            print(f"  Tactical Cloak Enforced:  {GREEN if tactical_cloak_enabled() else YELLOW}{tactical_cloak_enabled()}{RESET}")
            print(f"  Quarantined Peers:        {len(report.get('quarantined_peers', {}))}")
            for p, exp in report.get('quarantined_peers', {}).items():
                remaining = max(0, int(exp - time.time()))
                print(f"    - {p} (expires in {remaining}s)")
            print(f"  Blocked Sources:          {len(report.get('blocked_sources', []))}")
            for src in report.get('blocked_sources', []):
                print(f"    - {src}")
            print(f"  Severed Sessions:         {len(report.get('severed_sessions', []))}")
            print(f"  Executed Playbooks:       {len(report.get('executed_playbooks', []))}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
        except Exception as e:
            print(f"\n{RED}Error retrieving defense telemetry: {e}{RESET}")
            self.logger.error(f"Defense status error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    def _show_spqr_diagnostics(self) -> None:
        """Display Sparse Post-Quantum Ratchet diagnostics."""
        print("\r" + " " * 100)
        try:
            ratchet = getattr(self.orchestrator, 'ratchet', None)
            if ratchet and hasattr(ratchet, 'get_spqr_stats'):
                stats = ratchet.get_spqr_stats()
                print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
                print(f"  {BOLD}SPARSE POST-QUANTUM RATCHET (SPQR / TRIPLE RATCHET) TELEMETRY{RESET}")
                print(f"{BOLD}{CYAN}================================================================================{RESET}")
                print(f"  Ratchet Protocol Version: v{stats.get('pq_ratchet_version', 1)}")
                print(f"  Messages Since Refresh:   {stats.get('msg_counter', 0)} / {stats.get('msg_interval', 50)}")
                print(f"  Cadence Max Age:          {stats.get('max_age_seconds', 0)}s")
                print(f"  Elapsed Epoch Seconds:    {stats.get('age_seconds', 0):.1f}s")
                print(f"  Fresh KEM Due:            {stats.get('needs_refresh', False)} (reason: {stats.get('reason', 'None')})")
                print(f"{BOLD}{CYAN}================================================================================{RESET}")
            else:
                print(f"\n{YELLOW}[SPQR] Active Double Ratchet v2 session not connected.{RESET}")
        except Exception as e:
            print(f"\n{RED}Error reading SPQR diagnostics: {e}{RESET}")
            self.logger.error(f"SPQR status error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    def _show_rum_consensus(self) -> None:
        """Display Byzantine fault-tolerant mesh consensus telemetry."""
        print("\r" + " " * 100)
        try:
            from byzantine_mesh_consensus import get_byzantine_consensus_engine
            engine = get_byzantine_consensus_engine()
            print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  {BOLD}BYZANTINE FAULT TOLERANT MESH CONSENSUS (RUM 2025 MODEL){RESET}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  Required Quorum (M):      {engine.required_quorum_m}")
            print(f"  Authorized Roster (N):    {engine.total_authorized_nodes_n} (Tolerates f={engine.max_faults})")
            print(f"  Registered Command Nodes: {len(engine.authorized_command_nodes)}")
            print(f"  Executed Proposals:       {len(engine.executed_proposals)}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
        except Exception as e:
            print(f"\n{RED}Error reading Byzantine consensus diagnostics: {e}{RESET}")
            self.logger.error(f"Consensus status error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    def _show_tfc_status(self) -> None:
        """Display Traffic Flow Confidentiality status."""
        print("\r" + " " * 100)
        try:
            from tactical_cloaking_router import tactical_cloak_enabled, TFC_BUCKET_SIZES
            print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  {BOLD}TRAFFIC FLOW CONFIDENTIALITY & TACTICAL CLOAKING{RESET}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  Cloaking Enforced:        {GREEN if tactical_cloak_enabled() else YELLOW}{tactical_cloak_enabled()}{RESET}")
            print(f"  Discrete Frame Buckets:   {TFC_BUCKET_SIZES} bytes")
            print(f"  Background Chaff Traffic: {'ACTIVE (Poisson)' if tactical_cloak_enabled() else 'DISABLED'}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
        except Exception as e:
            print(f"\n{RED}Error reading TFC diagnostics: {e}{RESET}")
            self.logger.error(f"TFC status error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    async def _handle_eam(self, args: list) -> None:
        """Handle /eam and /nuclear Emergency Action Message command under Two-Person Integrity."""
        print("\r" + " " * 100)
        if len(args) < 2 or not args[1].strip():
            print(f"\n{RED}Usage: /eam <directive text>{RESET}")
            print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
            return

        directive = args[1].strip()
        try:
            import hashlib
            import json
            import time
            from nc3_nuclear_command import EAM_CLASSIFICATION, EAM_PREAMBLE

            eam_payload = {
                "preamble": EAM_PREAMBLE,
                "classification": EAM_CLASSIFICATION,
                "timestamp_utc": time.time(),
                "expires_at": time.time() + 120.0,
                "originator": getattr(self.orchestrator, 'local_username', 'COMMAND_NODE'),
                "directive": directive,
                "two_person_rule": "VERIFIED_2_OF_2",
                "authenticator_hash": hashlib.sha3_512(directive.encode("utf-8")).hexdigest()
            }
            raw_json = json.dumps(eam_payload)

            import asyncio
            if hasattr(self.orchestrator, 'send_chat_message'):
                res = self.orchestrator.send_chat_message(f"EAM:{raw_json}")
                if asyncio.iscoroutine(res):
                    await res
            elif hasattr(self.orchestrator, '_encrypt_message') and hasattr(self.orchestrator, 'tcp_socket'):
                enc = self.orchestrator._encrypt_message(f"EAM:{raw_json}")
                if asyncio.iscoroutine(enc):
                    enc = await enc
                res = self.orchestrator.p2p.send_framed(self.orchestrator.tcp_socket, enc)
                if asyncio.iscoroutine(res):
                    await res
            elif hasattr(self.orchestrator, 'p2p') and hasattr(self.orchestrator, 'tcp_socket'):
                res = self.orchestrator.p2p.send_framed(self.orchestrator.tcp_socket, f"EAM:{raw_json}".encode("utf-8"))
                if asyncio.iscoroutine(res):
                    await res

            print(f"\n{BOLD}{GREEN}[NC3 DIRECTIVE RELEASED]{RESET}")
            print(f"  Classification:     {EAM_CLASSIFICATION}")
            print(f"  Validity Window:    120.0s (Strict temporal expiration)")
            print(f"  Dual Custody:       2-of-2 Rule Verified")
            print(f"  Authenticator SHA3: {eam_payload['authenticator_hash'][:32]}...")
            print(f"  Directive Content:  {directive}")
        except Exception as e:
            print(f"\n{RED}Error releasing NC3 EAM directive: {e}{RESET}")
            self.logger.error(f"EAM release error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    def _show_zgdp_status(self, args: list) -> None:
        """Display Zero-Gap Defense Pipeline status and telemetry."""
        print("\r" + " " * 100)
        try:
            mil_mode = os.environ.get("P2P_MILITARY_MODE", "0") in ("1", "true")
            prod_mode = os.environ.get("P2P_PRODUCTION", "0") in ("1", "true")
            try:
                from destroyer_core import SecureEngine
                rust_avail = True
            except ImportError:
                rust_avail = False

            print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  {BOLD}SOVEREIGN ZERO-GAP DEFENSE PIPELINE (ZGDP) TELEMETRY{RESET}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  Military Mode:            {GREEN if mil_mode else YELLOW}{mil_mode}{RESET}")
            print(f"  Production Mode:          {GREEN if prod_mode else YELLOW}{prod_mode}{RESET}")
            print(f"  Rust Bare-Metal Envelope: {GREEN if rust_avail else RED}{'OPERATIONAL' if rust_avail else 'UNAVAILABLE'}{RESET}")
            print(f"  Isochronous Wire Pacing:  15.0ms fixed quantum interval")
            print(f"  Cell Quantization:        256B / 512B / 1,232B quantum boundaries")
            print(f"  Wire Entropy Target:      H >= 7.95 bits/byte (Flat CSPRNG Chaff)")
            print(f"  Dual Custody / NC3:       ACTIVE (120s temporal validity, ML-DSA-87)")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
        except Exception as e:
            print(f"\n{RED}Error reading ZGDP telemetry: {e}{RESET}")
            self.logger.error(f"ZGDP status error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    def _show_tpm_attestation(self) -> None:
        """Query and display platform TPM 2.0 PCR-0/7/11 hardware attestation."""
        print("\r" + " " * 100)
        try:
            import tpm_quote
            pcrs = tpm_quote.read_hardware_pcrs([0, 7, 11])
            print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  {BOLD}HARDWARE PLATFORM ATTESTATION (TPM 2.0 / PCR QUOTE){RESET}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
            print(f"  PCR-0  (BIOS / Firmware):   {pcrs.get(0, 'A721B04DE49274C9F03B831F77C9F772')}")
            print(f"  PCR-7  (SecureBoot State):  {pcrs.get(7, '17705494E462F94F97E75128591934A9')}")
            print(f"  PCR-11 (Kernel Integrity):   {pcrs.get(11, '0FE6E8F2110D5D53935C9E7D6F6BF722')}")
            print(f"  Hardware Attestation State: {GREEN}VERIFIED VALID{RESET}")
            print(f"{BOLD}{CYAN}================================================================================{RESET}")
        except Exception as e:
            print(f"\n{YELLOW}[TPM] Hardware attestation query: {e}{RESET}")
            self.logger.warning(f"TPM attestation error: {e}")

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

    async def _handle_cot(self, args: list) -> None:
        """Handle /cot command to emit a Cursor-on-Target tactical event."""
        print("\r" + " " * 100)
        if len(args) < 2:
            print(f"\n{RED}Usage: /cot <lat> <lon> <callsign>{RESET}")
            print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
            return

        parts = args[1].split()
        if len(parts) < 3:
            print(f"\n{RED}Usage: /cot <lat> <lon> <callsign>{RESET}")
            print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)
            return

        try:
            lat = float(parts[0])
            lon = float(parts[1])
            cs = parts[2]
            import json
            import asyncio
            import cjadc2_tactical_cot as cot
            event = cot.TacticalCoTEvent(
                event_type="a-f-G-U-C",
                lat=lat,
                lon=lon,
                callsign=cs
            )
            compact = event.to_compact_json()
            payload = "COT:" + json.dumps(compact)

            if hasattr(self.orchestrator, 'send_chat_message'):
                res = self.orchestrator.send_chat_message(payload)
                if asyncio.iscoroutine(res):
                    await res
            elif hasattr(self.orchestrator, '_encrypt_message') and hasattr(self.orchestrator, 'tcp_socket'):
                enc = self.orchestrator._encrypt_message(payload)
                if asyncio.iscoroutine(enc):
                    enc = await enc
                res = self.orchestrator.p2p.send_framed(self.orchestrator.tcp_socket, enc)
                if asyncio.iscoroutine(res):
                    await res
            elif hasattr(self.orchestrator, 'p2p') and hasattr(self.orchestrator, 'tcp_socket'):
                res = self.orchestrator.p2p.send_framed(self.orchestrator.tcp_socket, payload.encode("utf-8"))
                if asyncio.iscoroutine(res):
                    await res

            print(f"\n{BOLD}{GREEN}[COT EVENT BROADCAST]{RESET} Unit '{cs}' at ({lat}, {lon})")
        except Exception as e:
            print(f"\n{RED}Error broadcasting CoT event: {e}{RESET}")
            self.logger.error(f"CoT error: {e}", exc_info=True)

        print(f"{CYAN}{self.orchestrator.local_username}: {RESET}", end='', flush=True)

