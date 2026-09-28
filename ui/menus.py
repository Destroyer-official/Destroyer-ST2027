"""
Menu operations.

Provides menu handling and navigation.
"""

import asyncio
import logging
try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule

log = logging.getLogger(__name__)


class MenuManager(BaseModule):
    """Menu operations for handling user menus and navigation."""
    
    async def handle_connections(self) -> None:
        """
        Handle connections menu - main menu and connection handling loop.
        
        Note: This method delegates to the main secure_p2p.py handle_connections
        method since it's extremely complex (400+ lines) and tightly integrated
        with the orchestrator. Full migration will be done in a future refactoring.
        """
        log.info("Menu: handle_connections delegating to orchestrator")
        if hasattr(self.orchestrator, 'handle_connections') and callable(self.orchestrator.handle_connections):
            return await self.orchestrator.handle_connections()
        raise RuntimeError("Orchestrator handle_connections is not available.")
    
    async def connect_by_username(self) -> None:
        """
        Connect to peer by username.
        
        This functionality is currently embedded in handle_connections menu option 2.
        """
        log.info("Menu: connect_by_username called")
        print("\n[SEARCH] Connect by Username")
        print("=" * 60)
        
        try:
            # Get username from user
            username = await self.orchestrator.ui.prompts.async_input("Enter peer username: ")
            
            if not username or username.strip() == "":
                print("[FAIL] Username cannot be empty")
                return
            
            # Look up peer by username
            peer_info = await self.orchestrator.data.peer_mgmt.lookup_peer_by_username(username)
            
            if not peer_info:
                print(f"[FAIL] Peer '{username}' not found in stored connections")
                return
            
            # Connect to peer
            print(f"[NETWORK] Connecting to {peer_info.get('display_name', username)}...")
            success = await self.orchestrator.network.connection.connect_to_peer(
                peer_info.get('ipv6'),
                peer_info.get('port')
            )
            
            if success:
                print(f"[OK] Connected to {username}")
            else:
                print(f"[FAIL] Failed to connect to {username}")
                
        except Exception as e:
            log.error(f"Error connecting by username: {e}", exc_info=True)
            print(f"[FAIL] Error: {e}")
    
    async def connect_by_ip(self) -> None:
        """
        Connect to peer by IP address and port.
        
        This functionality is currently embedded in handle_connections menu option 3.
        
        Requirements: 3.1, 3.5
        """
        log.info("Menu: connect_by_ip called")
        print("\n[CONNECT] Connect by IP/Port")
        print("=" * 60)
        
        try:
            # Get IP address from user
            ip_address = await self.orchestrator.ui.prompts.async_input("Enter peer IP address: ")
            
            if not ip_address or ip_address.strip() == "":
                print("[FAIL] IP address cannot be empty")
                return
            
            ip_address = ip_address.strip()
            
            # Intelligently parse endpoint (handles [ipv6]:port, ipv4:port, etc.)
            has_explicit_port = False
            default_port = 50007
            try:
                from network_endpoint_discovery import parse_endpoint
                parsed_host, parsed_port = parse_endpoint(ip_address, default_port=50007)
                has_explicit_port = (ip_address.startswith('[') and ']:' in ip_address) or (not ip_address.startswith('[') and ip_address.count(':') == 1)
                ip_address = parsed_host
                default_port = parsed_port
            except Exception:
                pass

            # Task 5.2: Validate IPv6 address before connection attempt.
            # Live validator first (scanned, maintained); legacy snapshot
            # only as fallback. Fixed 2026-09-24: validation must not
            # depend solely on unscanned code.
            try:
                from security.validation import InputValidator
            except ImportError:
                from secure_p2p_core.security.validation import InputValidator
            
            # Determine if this is IPv6 (contains colons)
            if ':' in ip_address and not ip_address.count(':') == 1:  # Not just host:port
                # Validate as IPv6
                is_valid, error_msg = InputValidator.validate_ipv6(ip_address)
                if not is_valid:
                    print(f"[FAIL] Invalid IPv6 address: {error_msg}")
                    log.error(f"IPv6 validation failed for {ip_address}: {error_msg}")
                    return
                log.info(f"IPv6 address validated: {ip_address}")
            else:
                # Validate as IPv4 or hostname using existing validator
                if not InputValidator.validate_ip_address(ip_address):
                    print(f"[FAIL] Invalid IP address or hostname: {ip_address}")
                    log.error(f"IP address validation failed for {ip_address}")
                    return
                log.info(f"IP address validated: {ip_address}")
            
            # Get port from user if not already supplied
            if has_explicit_port:
                port = default_port
                print(f"[NETWORK] Using port {port} from endpoint specification")
            else:
                port_str = await self.orchestrator.ui.prompts.async_input(f"Enter peer port (default {default_port}): ")
                try:
                    port = int(port_str) if port_str.strip() else default_port
                except ValueError:
                    print("[FAIL] Invalid port number")
                    return
            
            # Validate port range
            if port < 1 or port > 65535:
                print("[FAIL] Port must be between 1 and 65535")
                return
            
            # Connect to peer
            print(f"[NETWORK] Connecting to {ip_address}:{port}...")
            
            try:
                # Create TCP connection
                import asyncio
                reader, writer = await asyncio.open_connection(ip_address, port)
                
                # Create peer ID
                peer_id = f"{ip_address}:{port}"
                
                # Initialize secure session with handshake
                try:
                    from simple_chat_implementation import initialize_session, handle_incoming_messages
                    
                    # Get audit logger if available
                    audit_logger = None
                    if hasattr(self.orchestrator, 'audit'):
                        audit_logger = self.orchestrator.audit
                    
                    print(f"[SECURE] Performing secure handshake...")
                    
                    # Initialize session with security modules
                    session_context = await initialize_session(
                        peer_id=peer_id,
                        reader=reader,
                        writer=writer,
                        is_initiator=True,  # UI connection is always initiator
                        audit_logger=audit_logger
                    )
                    
                    if not session_context:
                        print(f"[FAIL] Handshake failed - could not establish secure session")
                        try:
                            writer.close()
                            await writer.wait_closed()
                        except Exception as _close_err:
                            log.debug(f"Writer close suppressed: {_close_err}")
                        return
                    
                    # Start message handler in background
                    handler_task = asyncio.create_task(
                        handle_incoming_messages(self.orchestrator, peer_id, reader, writer)
                    )
                    
                    print(f"[OK] Secure connection established with {ip_address}:{port}")
                    print(f"  [ENCRYPTION] DoubleRatchet + ChaCha20-Poly1305")
                    print(f"  [KEY EXCHANGE] X25519 + ML-KEM-1024 (Post-Quantum)")
                    print(f"  [SESSION] Connection stored as: {peer_id}")
                    print(f"   Use option 3 (Chat with Connected Peer) to start chatting")
                    
                except ImportError as e:
                    log.error(f"Security modules not available: {e}")
                    print(f"[FAIL] Security modules not available - cannot establish secure connection")
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception as _close_err:
                            log.debug(f"Writer close suppressed: {_close_err}")
                except Exception as e:
                    log.error(f"Handshake failed: {e}", exc_info=True)
                    print(f"[FAIL] Handshake failed: {e}")
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception as _close_err:
                            log.debug(f"Writer close suppressed: {_close_err}")
                
            except ConnectionRefusedError:
                print(f"[FAIL] Connection refused - peer not listening on {ip_address}:{port}")
            except asyncio.TimeoutError:
                print(f"[FAIL] Connection timeout - peer not reachable")
            except Exception as e:
                print(f"[FAIL] Connection failed: {e}")
                
        except Exception as e:
            log.error(f"Error connecting by IP: {e}", exc_info=True)
            print(f"[FAIL] Error: {e}")
    
    def show_stored_peers(self) -> None:
        """
        Show stored peer connections.
        
        This functionality is currently embedded in handle_connections menu option 4.
        """
        log.info("Menu: show_stored_peers called")
        print("\n[PEERS] Stored Peer Connections")
        print("=" * 60)
        
        try:
            # Get list of peers from data module
            peers = self.orchestrator.data.peer_mgmt.list_peers()
            
            if not peers or len(peers) == 0:
                print("No stored peer connections found.")
                print("\nTo add peers, connect to them first using options 2 or 3.")
                return
            
            print(f"Found {len(peers)} stored peer(s):\n")
            
            for i, peer in enumerate(peers, 1):
                username = peer.get('username', 'Unknown')
                display_name = peer.get('display_name', username)
                ipv6 = peer.get('ipv6', 'Unknown')
                port = peer.get('port', 'Unknown')
                last_seen = peer.get('last_seen', 'Never')
                status = peer.get('connection_status', 'Unknown')
                
                print(f"{i}. {display_name} (@{username})")
                print(f"   Address: [{ipv6}]:{port}")
                print(f"   Status: {status}")
                print(f"   Last seen: {last_seen}")
                print()
                
        except Exception as e:
            log.error(f"Error showing stored peers: {e}", exc_info=True)
            print(f"[FAIL] Error retrieving peer list: {e}")
    
    async def handle_user_management(self) -> None:
        """
        Handle user management menu.
        
        This functionality is currently embedded in handle_connections menu option 6.
        """
        log.info("Menu: handle_user_management called")
        print("\n[USERS] User Management")
        print("=" * 60)
        print("1. Create new user profile")
        print("2. Switch user profile")
        print("3. View current user profile")
        print("4. Delete user profile")
        print("5. Back to main menu")
        print("=" * 60)
        
        try:
            choice = await self.orchestrator.ui.prompts.async_input("Choose an option (1-5): ")
            
            if choice == "1":
                await self._create_user_profile()
            elif choice == "2":
                await self._switch_user_profile()
            elif choice == "3":
                await self._view_user_profile()
            elif choice == "4":
                await self._delete_user_profile()
            elif choice == "5":
                return
            else:
                print("[FAIL] Invalid option")
                
        except Exception as e:
            log.error(f"Error in user management: {e}", exc_info=True)
            print(f"[FAIL] Error: {e}")
    
    async def _create_user_profile(self) -> None:
        """Create a new user profile."""
        print("\n[PROFILE] Create New User Profile")
        print("-" * 60)
        
        try:
            username = await self.orchestrator.ui.prompts.async_input("Enter username: ")
            if not username or username.strip() == "":
                print("[FAIL] Username cannot be empty")
                return
            
            display_name = await self.orchestrator.ui.prompts.async_input("Enter display name: ")
            if not display_name or display_name.strip() == "":
                display_name = username
            
            # Create user profile
            success = await self.orchestrator.data.user_mgmt.create_new_user(
                username, display_name, "::", 50007
            )
            
            if success:
                print(f"[OK] User profile '{username}' created successfully")
            else:
                print(f"[FAIL] Failed to create user profile")
                
        except Exception as e:
            log.error(f"Error creating user profile: {e}", exc_info=True)
            print(f"[FAIL] Error: {e}")
    
    async def _switch_user_profile(self) -> None:
        """Switch to a different user profile."""
        print("\n[SWITCH] Switch User Profile")
        print("-" * 60)
        print("This feature is not yet implemented.")
    
    async def _view_user_profile(self) -> None:
        """View current user profile."""
        print("\n[PROFILE] Current User Profile")
        print("-" * 60)
        
        try:
            profile = await self.orchestrator.data.user_mgmt.load_profile()
            
            if profile:
                print(f"Username: {profile.get('username', 'Unknown')}")
                print(f"Display Name: {profile.get('display_name', 'Unknown')}")
                print(f"User ID: {profile.get('user_id', 'Unknown')}")
                print(f"IPv6: {profile.get('ipv6', 'Unknown')}")
                print(f"Port: {profile.get('port', 'Unknown')}")
            else:
                print("No user profile loaded")
                
        except Exception as e:
            log.error(f"Error viewing user profile: {e}", exc_info=True)
            print(f"[FAIL] Error: {e}")
    
    async def _delete_user_profile(self) -> None:
        """Delete a user profile."""
        print("\n[DELETE] Delete User Profile")
        print("-" * 60)
        print("This feature is not yet implemented.")
    
    async def run_system_tests(self) -> None:
        """
        Run comprehensive system tests.
        
        This runs all system tests including crypto operations, network operations,
        security features, key management, message encryption, and audit logging.
        """
        log.info("Menu: run_system_tests called")
        
        try:
            # Run system tests
            results = await self.orchestrator.system_tests.run_system_tests()
            
            # Wait for user to review results
            await self.orchestrator.ui.prompts.async_input("\nPress Enter to continue...")
            
        except Exception as e:
            log.error(f"Error running system tests: {e}", exc_info=True)
            print(f"[FAIL] Error running system tests: {e}")
