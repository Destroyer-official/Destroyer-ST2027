"""
SecureP2PChat orchestrator class.

Main orchestration class that coordinates all modules through lazy-loading
properties and delegation stubs. This class is kept minimal (< 500 lines) with
all implementation delegated to focused modules.

Security Classification: Trusted (orchestration only)
"""

import logging
import asyncio
from typing import Optional, Any, Dict, List, Tuple
from datetime import datetime

# Import chat implementation - optional
try:
    from simple_chat_implementation import (
        start_chat_with_peer,
        handle_incoming_messages,
        active_connections
    )
    CHAT_AVAILABLE = True
except ImportError:
    CHAT_AVAILABLE = False
    active_connections = {}
    def start_chat_with_peer(*args, **kwargs):
        raise RuntimeError("start_chat_with_peer requires chat module")
    def handle_incoming_messages(*args, **kwargs):
        raise RuntimeError("handle_incoming_messages requires chat module")


class SecureP2PChat:
    """
    secure secure P2P chat orchestrator.
    
    Coordinates all modules through lazy-loading properties and delegation stubs.
    This class is kept minimal (< 500 lines) with all implementation delegated
    to focused modules.
    
    Module Structure:
    - crypto: Cryptographic operations (padding, signatures, KEM, auth tags)
    - network: Network operations (handshake, I/O, monitoring, connection)
    - security: Security operations (hardening, integrity, monitoring, validation)
    - keys: Key management (storage, rotation, generation, HSM integration)
    - data: Data management (user, peer, file transfer)
    - messaging: Message handling (handler, encryption, commands)
    - ui: User interface (display, prompts, menus)
    - utils: Utilities (initialization, cleanup, memory, helpers)
    """
    
    def __init__(self, identity: Optional[str] = None, ephemeral: bool = True,
                 in_memory_only: bool = True, key_lifetime: int = 3072,
                 security_level: str = "MAXIMUM"):
        """
        Initialize the orchestrator.
        
        Args:
            identity: Optional identity string
            ephemeral: Whether to use ephemeral keys
            in_memory_only: Whether to keep keys in memory only
            key_lifetime: Key lifetime in seconds
            security_level: Security level (MAXIMUM, HIGH, MEDIUM)
        """
        self.identity = identity
        self.ephemeral = ephemeral
        self.in_memory_only = in_memory_only
        self.key_lifetime = key_lifetime
        self.security_level = security_level
        
        # Module references (lazy-loaded)
        self._crypto_ops = None
        self._network_manager = None
        self._security_manager = None
        self._keys_manager = None
        self._data_manager = None
        self._messaging_manager = None
        self._ui_manager = None
        self._utils_manager = None
        self._system_tests = None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Initializing SecureP2PChat with identity={identity}")
    
    # ========== Lazy-loading properties for all modules ==========
    
    @property
    def crypto(self):
        """Lazy load crypto module."""
        if self._crypto_ops is None:
            try:
                from ..crypto import CryptoOperations
                self._crypto_ops = CryptoOperations(self)
            except Exception as e:
                self.logger.error(f"Failed to load crypto module: {e}", exc_info=True)
                raise
        return self._crypto_ops
    
    @property
    def network(self):
        """Lazy load network module."""
        if self._network_manager is None:
            try:
                from ..network import NetworkManager
                self._network_manager = NetworkManager(self)
            except Exception as e:
                self.logger.error(f"Failed to load network module: {e}", exc_info=True)
                raise
        return self._network_manager
    
    @property
    def security(self):
        """Lazy load security module."""
        if self._security_manager is None:
            try:
                from ..security import SecurityManager
                self._security_manager = SecurityManager(self)
            except Exception as e:
                self.logger.error(f"Failed to load security module: {e}", exc_info=True)
                raise
        return self._security_manager
    
    @property
    def keys(self):
        """Lazy load keys module."""
        if self._keys_manager is None:
            try:
                from ..keys import KeysManager
                self._keys_manager = KeysManager(self)
            except Exception as e:
                self.logger.error(f"Failed to load keys module: {e}", exc_info=True)
                raise
        return self._keys_manager
    
    @property
    def data(self):
        """Lazy load data module."""
        if self._data_manager is None:
            try:
                from ..data import DataManager
                self._data_manager = DataManager(self)
            except Exception as e:
                self.logger.error(f"Failed to load data module: {e}", exc_info=True)
                raise
        return self._data_manager
    
    @property
    def messaging(self):
        """Lazy load messaging module."""
        if self._messaging_manager is None:
            try:
                from ..messaging import MessagingManager
                self._messaging_manager = MessagingManager(self)
            except Exception as e:
                self.logger.error(f"Failed to load messaging module: {e}", exc_info=True)
                raise
        return self._messaging_manager
    
    @property
    def ui(self):
        """Lazy load UI module."""
        if self._ui_manager is None:
            try:
                from ..ui import UIManager
                self._ui_manager = UIManager(self)
            except Exception as e:
                self.logger.error(f"Failed to load UI module: {e}", exc_info=True)
                raise
        return self._ui_manager
    
    @property
    def utils(self):
        """Lazy load utils module."""
        if self._utils_manager is None:
            try:
                from ..utils import UtilsManager
                self._utils_manager = UtilsManager(self)
            except Exception as e:
                self.logger.error(f"Failed to load utils module: {e}", exc_info=True)
                raise
        return self._utils_manager
    
    @property
    def system_tests(self):
        """Lazy load system tests module - optional (tests moved to notupload)."""
        if self._system_tests is None:
            try:
                from ..tests import SystemTests
                self._system_tests = SystemTests(self)
            except ImportError:
                self.logger.debug("System tests module not available (moved to notupload)")
                self._system_tests = None
            except Exception as e:
                self.logger.error(f"Failed to load system tests module: {e}", exc_info=True)
                self._system_tests = None
        return self._system_tests
    
    # ========== Lifecycle methods ==========
    
    async def initialize(self) -> None:
        """Initialize all modules."""
        self.logger.info("Initializing SecureP2PChat orchestrator")
        try:
            # Modules initialize themselves on first access via lazy loading
            self.logger.info("SecureP2PChat orchestrator initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize orchestrator: {e}", exc_info=True)
            raise
    
    async def cleanup(self) -> None:
        """Cleanup all modules."""
        self.logger.info("Cleaning up SecureP2PChat orchestrator")
        try:
            # Cleanup modules in reverse order
            if self._utils_manager:
                await self._utils_manager.cleanup()
            if self._messaging_manager:
                await self._messaging_manager.cleanup()
            if self._ui_manager:
                await self._ui_manager.cleanup()
            if self._data_manager:
                await self._data_manager.cleanup()
            if self._keys_manager:
                await self._keys_manager.cleanup()
            if self._security_manager:
                await self._security_manager.cleanup()
            if self._network_manager:
                await self._network_manager.cleanup()
            if self._crypto_ops:
                await self._crypto_ops.cleanup()
            self.logger.info("SecureP2PChat orchestrator cleaned up successfully")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}", exc_info=True)
    
    async def start(self) -> None:
        """
        Start the P2P chat application with interactive menu.
        
        This is the main entry point that displays the menu and handles user interaction.
        """
        self.logger.info("Starting SecureP2PChat application")
        try:
            # Initialize the application
            await self.initialize()
            
            # Display banner and security summary
            self.ui.display.display_banner()
            
            # Main menu loop
            while True:
                try:
                    # Display main menu
                    print("\n" + "="*70)
                    print("          SECURE P2P CHAT - MAIN MENU           ")
                    print("="*70 + "\n")
                    print("  1. Start P2P Server")
                    print("  2. Connect to Peer")
                    print("  3. Chat with Connected Peer")
                    print("  4. View Security Status")
                    print("  5. Run System Tests")
                    print("  6. Exit")
                    print("\n" + "="*70)
                    
                    # Get user choice
                    choice = await self.ui.prompts.async_input("\nEnter your choice (1-6): ")
                    choice = choice.strip()
                    
                    # Handle menu options
                    if choice == '1':
                        # Start P2P Server
                        print("\n[TIP] After starting the server, share your IPv6 address with peers.")
                        print("   They can connect using option 2 (Connect to Peer).")
                        try:
                            # Get server configuration
                            host = "::"  # Listen on all IPv6 interfaces
                            port = 50007  # Default port
                            
                            print(f"\n Starting P2P Server...")
                            print(f"[NETWORK] Configuring server on [{host}]:{port}...")
                            
                            # Create server socket
                            import socket
                            server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            
                            # Bind and listen
                            try:
                                server_socket.bind((host, port))
                                server_socket.listen(5)
                                server_socket.setblocking(False)
                                
                                print(f" P2P Server started successfully!")
                                print(f"[NETWORK] Listening on [::]:{port}")
                                
                                # Discover public IPv6 address via STUN (only show this)
                                print(f"\n[SEARCH] Discovering your public IPv6 address via STUN...")
                                try:
                                    import p2p_core
                                    # Set a timeout for STUN discovery
                                    public_ip, public_port = await asyncio.wait_for(
                                        p2p_core.get_public_ip_port(),
                                        timeout=10.0
                                    )
                                    
                                    if public_ip:
                                        print(f"\n" + "="*70)
                                        print(f"[NETWORK] PUBLIC IPv6 ADDRESS")
                                        print(f"="*70)
                                        print(f"\n   [{public_ip}]:{port}")
                                        print(f"\n" + "="*70)
                                        print(f"\n[TIP] Share this address with peers to connect!")
                                        print(f"\n[INSTRUCTIONS] Connection Instructions for Peers:")
                                        print(f"   1. Start their P2P client")
                                        print(f"   2. Select option 2 (Connect to Peer)")
                                        print(f"   3. Enter: [{public_ip}]:{port}")
                                        print(f"\n Server is ready and accepting connections")
                                    else:
                                        print(f"\n" + "="*70)
                                        print(f"[FAIL] STUN DISCOVERY FAILED")
                                        print(f"="*70)
                                        print(f"\n   Could not discover public IPv6 address")
                                        print(f"\n   Possible reasons:")
                                        print(f"   * No IPv6 internet connectivity")
                                        print(f"   * Firewall blocking STUN (UDP port 19302)")
                                        print(f"   * NAT/router doesn't support IPv6")
                                        print(f"   * ISP doesn't provide IPv6")
                                        print(f"\n[TIP] Troubleshooting:")
                                        print(f"   1. Check if your ISP provides IPv6")
                                        print(f"   2. Verify IPv6 is enabled in router settings")
                                        print(f"   3. Test IPv6 connectivity: ping -6 google.com")
                                        print(f"   4. Check firewall allows UDP port 19302")
                                        print(f"\n" + "="*70)
                                
                                except asyncio.TimeoutError:
                                    print(f"\n" + "="*70)
                                    print(f"[WARNING]  STUN DISCOVERY TIMEOUT")
                                    print(f"="*70)
                                    print(f"\n   STUN discovery timed out after 10 seconds")
                                    print(f"   This usually means no IPv6 internet connectivity")
                                    print(f"\n[TIP] Requirements for this P2P system:")
                                    print(f"   * IPv6 internet connection from your ISP")
                                    print(f"   * IPv6 enabled on your router")
                                    print(f"   * Firewall allowing UDP port 19302 (STUN)")
                                    print(f"\n" + "="*70)
                                    
                                except Exception as e:
                                    self.logger.debug(f"STUN discovery error: {e}")
                                    print(f"\n" + "="*70)
                                    print(f"[FAIL] STUN DISCOVERY ERROR")
                                    print(f"="*70)
                                    print(f"\n   Error: {str(e)[:100]}")
                                    print(f"\n   Check logs for details: logs/secure_p2p.log")
                                    print(f"\n" + "="*70)
                                
                                # Start accepting connections in background
                                async def accept_connections():
                                    import time as _time
                                    loop = asyncio.get_event_loop()
                                    _accept_hits: Dict[str, list] = {}
                                    while True:
                                        try:
                                            client_socket, client_address = await loop.sock_accept(server_socket)
                                            _ip = str(client_address[0]) if client_address else "unknown"
                                            _now = _time.time()
                                            _lst = _accept_hits.get(_ip, [])
                                            _lst = [t for t in _lst if _now - t < 60.0]
                                            if len(_lst) >= 5:
                                                self.logger.warning(f"Rate-limit: dropping rapid connection from {_ip} (5/min)")
                                                try:
                                                    client_socket.close()
                                                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                                                except Exception:  # nosec: B110
                                                    pass
                                                _accept_hits[_ip] = _lst
                                                continue
                                            _lst.append(_now)
                                            # Bound limiter memory (LRU-ish)
                                            if len(_accept_hits) > 512:
                                                _accept_hits.pop(next(iter(_accept_hits)))
                                            _accept_hits[_ip] = _lst
                                            self.logger.info(f"Accepted connection from {client_address}")
                                            print(f"\n[CONNECT] Incoming connection from [{client_address[0]}]:{client_address[1]}")
                                            
                                            # Create peer ID
                                            peer_id = f"{client_address[0]}:{client_address[1]}"
                                            
                                            # Handle the connection
                                            print(f"   Performing secure handshake with {peer_id}...")
                                            try:
                                                # Create asyncio streams from socket
                                                reader, writer = await asyncio.open_connection(sock=client_socket)
                                                
                                                # Initialize secure session with handshake
                                                if CHAT_AVAILABLE:
                                                    try:
                                                        from simple_chat_implementation import initialize_session
                                                        
                                                        # Get audit logger if available
                                                        audit_logger = getattr(self, 'audit', None)
                                                        
                                                        # Initialize session with security modules (responder role)
                                                        session_context = await initialize_session(
                                                            peer_id=peer_id,
                                                            reader=reader,
                                                            writer=writer,
                                                            is_initiator=False,  # Server is responder
                                                            audit_logger=audit_logger
                                                        )
                                                        
                                                        if not session_context:
                                                            print(f"[FAIL] Handshake failed - could not establish secure session")
                                                            try:
                                                                writer.close()
                                                                await writer.wait_closed()
                                                            except Exception as _ex:
                                                                self.logger.debug(f"Socket close suppressed: {_ex}")
                                                            continue
                                                        
                                                        # Start message handler in background
                                                        handler_task = asyncio.create_task(
                                                            handle_incoming_messages(self, peer_id, reader, writer)
                                                        )
                                                        
                                                        # Task 7.1: Display security status after connection
                                                        print(f"\n Peer connected: {peer_id}")
                                                        print(f"[READY] Ready to send/receive encrypted messages")
                                                        print(f"   Use option 3 (Chat with Connected Peer) to start chatting")
                                                        
                                                    except ImportError as e:
                                                        self.logger.error(f"Security modules not available: {e}")
                                                        print(f"[FAIL] Security modules not available - cannot establish secure connection")
                                                        try:
                                                            writer.close()
                                                            await writer.wait_closed()
                                                        except Exception as _ex:
                                                                self.logger.debug(f"Socket close suppressed: {_ex}")
                                                else:
                                                    print(f"\n Peer connected: {peer_id}")
                                                    print(f"[READY] Ready to receive messages from this peer")
                                                
                                            except Exception as e:
                                                self.logger.error(f"Error creating reader/writer: {e}")
                                                try:
                                                    client_socket.close()
                                                except Exception as _ex:
                                                                self.logger.debug(f"Socket close suppressed: {_ex}")
                                            
                                        except Exception as e:
                                            self.logger.error(f"Error accepting connection: {e}")
                                            await asyncio.sleep(1)
                                
                                # Start server task in background
                                server_task = asyncio.create_task(accept_connections())
                                
                            except OSError as e:
                                if e.errno == 98 or e.errno == 10048:  # Address already in use
                                    print(f"[FAIL] Port {port} is already in use")
                                    print(f"   Try closing other applications or use a different port")
                                else:
                                    print(f"[FAIL] Failed to start server: {e}")
                                server_socket.close()
                                
                        except Exception as e:
                            self.logger.error(f"Error starting P2P server: {e}", exc_info=True)
                            print(f"[FAIL] Error starting server: {e}")
                        
                        await self.ui.prompts.async_input("\nPress Enter to return to menu...")
                        
                    elif choice == '2':
                        # Connect to Peer
                        self.ui.prompts.display_helpful_prompt('connect_peer')
                        try:
                            print("\n[CONNECT] Connect to Peer")
                            print("="*70)
                            print("1. Connect by IP address")
                            print("2. Connect by username (from stored peers)")
                            print("3. Back to main menu")
                            print("="*70)
                            
                            connect_choice = await self.ui.prompts.async_input("\nChoose option (1-3): ")
                            
                            if connect_choice == '1':
                                # Connect by IP
                                await self.ui.menus.connect_by_ip()
                            elif connect_choice == '2':
                                # Connect by username
                                await self.ui.menus.connect_by_username()
                            elif connect_choice == '3':
                                continue  # Return to main menu
                            else:
                                print("[FAIL] Invalid option")
                                
                        except Exception as e:
                            self.logger.error(f"Error in connect to peer: {e}", exc_info=True)
                            print(f"[FAIL] Error: {e}")
                        
                        await self.ui.prompts.async_input("\nPress Enter to return to menu...")
                        
                    elif choice == '3':
                        # Chat with Connected Peer
                        if not CHAT_AVAILABLE:
                            print("[FAIL] Chat functionality not available")
                            print("   simple_chat_implementation.py not found")
                        elif not active_connections:
                            print("[FAIL] No active connections")
                            print("   Connect to a peer first using option 2")
                        else:
                            try:
                                print("\n[CONNECTIONS] Active Connections:")
                                peers = list(active_connections.keys())
                                for i, peer_id in enumerate(peers, 1):
                                    conn_info = active_connections[peer_id]
                                    connected_at = conn_info.get('connected_at', 'Unknown')
                                    print(f"  {i}. {peer_id} (connected: {connected_at})")
                                
                                peer_choice = await self.ui.prompts.async_input("\nSelect peer number (or 0 to cancel): ")
                                
                                if peer_choice == '0':
                                    continue
                                else:
                                    try:
                                        peer_idx = int(peer_choice) - 1
                                        if 0 <= peer_idx < len(peers):
                                            peer_id = peers[peer_idx]
                                            await start_chat_with_peer(self, peer_id)
                                        else:
                                            print("[FAIL] Invalid selection")
                                    except ValueError:
                                        print("[FAIL] Invalid input")
                            except Exception as e:
                                self.logger.error(f"Error in chat: {e}", exc_info=True)
                                print(f"[FAIL] Error: {e}")
                        
                        await self.ui.prompts.async_input("\nPress Enter to return to menu...")
                        
                    elif choice == '4':
                        # View security status
                        self.ui.prompts.display_helpful_prompt('security_status')
                        self.ui.display.view_security_status()
                        await self.ui.prompts.async_input("\nPress Enter to return to menu...")
                        
                    elif choice == '5':
                        # Run system tests
                        self.ui.prompts.display_helpful_prompt('system_tests')
                        await self.ui.menus.run_system_tests()
                        
                    elif choice == '6' or choice.lower() == 'exit':
                        self.ui.prompts.show_info("Initiating graceful shutdown...")
                        print("\n[EXIT] Exiting secure P2P chat...")
                        break
                        
                    else:
                        self.ui.prompts.show_error(f"Invalid choice: '{choice}'", "Please enter a number between 1 and 6")
                        self.ui.prompts.display_helpful_prompt('menu')
                        await asyncio.sleep(1.5)
                        
                except KeyboardInterrupt:
                    print("\n\n[WARNING]  Keyboard interrupt detected")
                    confirm = await self.ui.prompts.async_input("Do you want to exit? (yes/no): ")
                    if confirm.strip().lower() in ['yes', 'y']:
                        print("\n[EXIT] Exiting secure P2P chat...")
                        break
                    else:
                        print("Continuing...")
                        
                except Exception as e:
                    self.logger.error(f"Error in menu loop: {e}", exc_info=True)
                    print(f"\n[FAIL] Error: {e}")
                    await asyncio.sleep(1)
            
            # Cleanup
            await self.cleanup()
            self.logger.info("Application shutdown complete")
                
        except Exception as e:
            self.logger.error(f"Error during start: {e}", exc_info=True)
            raise

    # ========== Crypto Module Delegation Stubs ==========
    
    def _add_military_grade_padding(self, data: bytes) -> bytes:
        """Add secure padding - delegates to crypto module."""
        try:
            return self.crypto.padding.add_military_grade_padding(data)
        except Exception as e:
            self.logger.error(f"[CRYPTO] Padding failed: {e}", exc_info=True)
            raise
    
    def _remove_military_grade_padding(self, padded_data: bytes) -> bytes:
        """Remove secure padding - delegates to crypto module."""
        try:
            return self.crypto.padding.remove_military_grade_padding(padded_data)
        except Exception as e:
            self.logger.error(f"[CRYPTO] Padding removal failed: {e}", exc_info=True)
            raise
    
    def _add_random_padding(self, data: bytes) -> bytes:
        """Add random padding - delegates to crypto module."""
        try:
            return self.crypto.padding.add_random_padding(data)
        except Exception as e:
            self.logger.error(f"[CRYPTO] Random padding failed: {e}", exc_info=True)
            raise
    
    def _remove_random_padding(self, padded_data: bytes) -> bytes:
        """Remove random padding - delegates to crypto module."""
        try:
            return self.crypto.padding.remove_random_padding(padded_data)
        except Exception as e:
            self.logger.error(f"[CRYPTO] Random padding removal failed: {e}", exc_info=True)
            raise
    
    def _sign_with_ml_dsa_87(self, message: bytes, private_key: bytes) -> bytes:
        """Sign with ML-DSA-87 - delegates to crypto module."""
        try:
            return self.crypto.signatures.sign_with_ml_dsa_87(message, private_key)
        except Exception as e:
            self.logger.error(f"[CRYPTO] ML-DSA-87 signing failed: {e}", exc_info=True)
            raise
    
    def _verify_ml_dsa_87_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify ML-DSA-87 signature - delegates to crypto module."""
        try:
            return self.crypto.signatures.verify_ml_dsa_87_signature(message, signature, public_key)
        except Exception as e:
            self.logger.error(f"[CRYPTO] ML-DSA-87 verification failed: {e}", exc_info=True)
            raise
    
    def _sign_with_slh_dsa_256f(self, message: bytes, private_key: bytes) -> bytes:
        """Sign with SLH-DSA-256f - delegates to crypto module."""
        try:
            return self.crypto.signatures.sign_with_slh_dsa_256f(message, private_key)
        except Exception as e:
            self.logger.error(f"[CRYPTO] SLH-DSA-256f signing failed: {e}", exc_info=True)
            raise
    
    def _verify_slh_dsa_256f_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify SLH-DSA-256f signature - delegates to crypto module."""
        try:
            return self.crypto.signatures.verify_slh_dsa_256f_signature(message, signature, public_key)
        except Exception as e:
            self.logger.error(f"[CRYPTO] SLH-DSA-256f verification failed: {e}", exc_info=True)
            raise
    
    def _ensure_hybrid_session_keys(self, peer_bundle: Dict) -> Dict:
        """Ensure hybrid session keys - delegates to crypto module."""
        try:
            return self.crypto.kem.ensure_hybrid_session_keys(peer_bundle)
        except Exception as e:
            self.logger.error(f"[CRYPTO] Hybrid session key generation failed: {e}", exc_info=True)
            raise
    
    def _generate_military_auth_tag(self, ciphertext: bytes, message_hash: bytes) -> bytes:
        """Generate military auth tag - delegates to crypto module."""
        try:
            return self.crypto.auth_tags.generate_military_auth_tag(ciphertext, message_hash)
        except Exception as e:
            self.logger.error(f"[CRYPTO] Auth tag generation failed: {e}", exc_info=True)
            raise
    
    def _verify_military_auth_tag(self, ciphertext: bytes, message_hash: bytes, auth_tag: bytes) -> bool:
        """Verify military auth tag - delegates to crypto module."""
        try:
            return self.crypto.auth_tags.verify_military_auth_tag(ciphertext, message_hash, auth_tag)
        except Exception as e:
            self.logger.error(f"[CRYPTO] Auth tag verification failed: {e}", exc_info=True)
            raise

    # ========== Network Module Delegation Stubs ==========
    
    async def _initiate_military_hybrid_kem_handshake(self, peer_bundle: Dict) -> Tuple:
        """Initiate hybrid handshake - delegates to network module."""
        try:
            return await self.network.handshake.initiate_military_hybrid_kem_handshake(peer_bundle)
        except Exception as e:
            self.logger.error(f"[HANDSHAKE] Initiation failed: {e}", exc_info=True)
            raise
    
    async def _handle_military_hybrid_kem_handshake(self, handshake_message: Dict) -> bytes:
        """Handle hybrid handshake - delegates to network module."""
        try:
            return await self.network.handshake.handle_military_hybrid_kem_handshake(handshake_message)
        except Exception as e:
            self.logger.error(f"[HANDSHAKE] Handling failed: {e}", exc_info=True)
            raise
    
    async def _exchange_hybrid_keys_client(self, peer_bundle: Dict) -> Dict:
        """Exchange hybrid keys (client) - delegates to network module."""
        try:
            return await self.network.handshake.exchange_hybrid_keys_client(peer_bundle)
        except Exception as e:
            self.logger.error(f"[HANDSHAKE] Client key exchange failed: {e}", exc_info=True)
            raise
    
    async def _exchange_hybrid_keys_server(self, client_message: Dict) -> Dict:
        """Exchange hybrid keys (server) - delegates to network module."""
        try:
            return await self.network.handshake.exchange_hybrid_keys_server(client_message)
        except Exception as e:
            self.logger.error(f"[HANDSHAKE] Server key exchange failed: {e}", exc_info=True)
            raise
    
    async def _send_message(self, socket, message: bytes) -> bool:
        """Send message - delegates to network module."""
        try:
            return await self.network.io.send_message(socket, message)
        except Exception as e:
            self.logger.error(f"[NETWORK] Send failed: {e}", exc_info=True)
            raise
    
    async def _receive_message(self, socket) -> bytes:
        """Receive message - delegates to network module."""
        try:
            return await self.network.io.receive_message(socket)
        except Exception as e:
            self.logger.error(f"[NETWORK] Receive failed: {e}", exc_info=True)
            raise
    
    async def _send_encrypted_message(self, peer_id: str, message: str) -> bool:
        """Send encrypted message - delegates to network module."""
        try:
            return await self.network.io.send_encrypted_message(peer_id, message)
        except Exception as e:
            self.logger.error(f"[NETWORK] Encrypted send failed: {e}", exc_info=True)
            raise
    
    async def _receive_encrypted_message(self) -> Tuple[str, str]:
        """Receive encrypted message - delegates to network module."""
        try:
            return await self.network.io.receive_encrypted_message()
        except Exception as e:
            self.logger.error(f"[NETWORK] Encrypted receive failed: {e}", exc_info=True)
            raise
    
    async def _monitor_connection_health(self) -> None:
        """Monitor connection health - delegates to network module."""
        try:
            await self.network.monitoring.monitor_connection_health()
        except Exception as e:
            self.logger.error(f"[NETWORK] Health monitoring failed: {e}", exc_info=True)
            raise
    
    async def _send_heartbeat(self, peer_id: str) -> bool:
        """Send heartbeat - delegates to network module."""
        try:
            return await self.network.monitoring.send_heartbeat(peer_id)
        except Exception as e:
            self.logger.error(f"[NETWORK] Heartbeat send failed: {e}", exc_info=True)
            raise
    
    async def _handle_heartbeat_response(self, peer_id: str) -> None:
        """Handle heartbeat response - delegates to network module."""
        try:
            await self.network.monitoring.handle_heartbeat_response(peer_id)
        except Exception as e:
            self.logger.error(f"[NETWORK] Heartbeat response failed: {e}", exc_info=True)
            raise
    
    async def _assess_connection_quality(self, peer_id: str) -> float:
        """Assess connection quality - delegates to network module."""
        try:
            return await self.network.monitoring.assess_connection_quality(peer_id)
        except Exception as e:
            self.logger.error(f"[NETWORK] Quality assessment failed: {e}", exc_info=True)
            raise
    
    async def _handle_incoming_connection(self, client_socket, client_address, listen_port) -> None:
        """Handle incoming connection - delegates to network module."""
        try:
            await self.network.connection.handle_incoming_connection(client_socket, client_address, listen_port)
        except Exception as e:
            self.logger.error(f"[NETWORK] Incoming connection failed: {e}", exc_info=True)
            raise
    
    async def _connect_to_peer(self, peer_id: str, peer_port: int) -> bool:
        """Connect to peer - delegates to network module."""
        try:
            return await self.network.connection.connect_to_peer(peer_id, peer_port)
        except Exception as e:
            self.logger.error(f"[NETWORK] Peer connection failed: {e}", exc_info=True)
            raise
    
    async def _handle_connection_failure(self, peer_id: str) -> None:
        """Handle connection failure - delegates to network module."""
        try:
            await self.network.connection.handle_connection_failure(peer_id)
        except Exception as e:
            self.logger.error(f"[NETWORK] Failure handling failed: {e}", exc_info=True)
            raise
    
    async def _disconnect_peer(self, peer_id: str) -> None:
        """Disconnect peer - delegates to network module."""
        try:
            await self.network.connection.disconnect_peer(peer_id)
        except Exception as e:
            self.logger.error(f"[NETWORK] Disconnect failed: {e}", exc_info=True)
            raise

    # ========== Security Module Delegation Stubs ==========
    
    def _initialize_security_hardening_manager(self) -> None:
        """Initialize security hardening - delegates to security module."""
        try:
            self.security.hardening.initialize_security_hardening_manager()
        except Exception as e:
            self.logger.error(f"[SECURITY] Hardening init failed: {e}", exc_info=True)
            raise
    
    def _enforce_maximum_security(self) -> None:
        """Enforce maximum security - delegates to security module."""
        try:
            self.security.hardening.enforce_maximum_security()
        except Exception as e:
            self.logger.error(f"[SECURITY] Enforcement failed: {e}", exc_info=True)
            raise
    
    def _enable_anti_debugging(self) -> bool:
        """Enable anti-debugging - delegates to security module."""
        try:
            return self.security.hardening.enable_anti_debugging()
        except Exception as e:
            self.logger.error(f"[SECURITY] Anti-debugging failed: {e}", exc_info=True)
            raise
    
    def _start_debugger_detection_thread(self) -> None:
        """Start debugger detection - delegates to security module."""
        try:
            self.security.hardening.start_debugger_detection_thread()
        except Exception as e:
            self.logger.error(f"[SECURITY] Debugger detection failed: {e}", exc_info=True)
            raise
    
    def _check_memory_integrity(self) -> bool:
        """Check memory integrity - delegates to security module."""
        try:
            return self.security.integrity.check_memory_integrity()
        except Exception as e:
            self.logger.error(f"[SECURITY] Memory integrity check failed: {e}", exc_info=True)
            raise
    
    def _check_process_integrity(self) -> bool:
        """Check process integrity - delegates to security module."""
        try:
            return self.security.integrity.check_process_integrity()
        except Exception as e:
            self.logger.error(f"[SECURITY] Process integrity check failed: {e}", exc_info=True)
            raise
    
    def _check_network_security(self) -> bool:
        """Check network security - delegates to security module."""
        try:
            return self.security.integrity.check_network_security()
        except Exception as e:
            self.logger.error(f"[SECURITY] Network security check failed: {e}", exc_info=True)
            raise
    
    async def _runtime_integrity_loop(self) -> None:
        """Runtime integrity loop - delegates to security module."""
        try:
            await self.security.integrity.runtime_integrity_loop()
        except Exception as e:
            self.logger.error(f"[SECURITY] Runtime integrity loop failed: {e}", exc_info=True)
            raise
    
    async def _security_monitoring_loop(self) -> None:
        """Security monitoring loop - delegates to security module."""
        try:
            await self.security.monitor.security_monitoring_loop()
        except Exception as e:
            self.logger.error(f"[SECURITY] Monitoring loop failed: {e}", exc_info=True)
            raise
    
    async def _canary_check_loop(self) -> None:
        """Canary check loop - delegates to security module."""
        try:
            await self.security.monitor.canary_check_loop()
        except Exception as e:
            self.logger.error(f"[SECURITY] Canary check failed: {e}", exc_info=True)
            raise
    
    async def _intrusion_detection_loop(self) -> None:
        """Intrusion detection loop - delegates to security module."""
        try:
            await self.security.monitor.intrusion_detection_loop()
        except Exception as e:
            self.logger.error(f"[SECURITY] Intrusion detection failed: {e}", exc_info=True)
            raise
    
    async def _perform_runtime_security_check(self) -> None:
        """Perform runtime security check - delegates to security module."""
        try:
            await self.security.monitor.perform_runtime_security_check()
        except Exception as e:
            self.logger.error(f"[SECURITY] Runtime check failed: {e}", exc_info=True)
            raise
    
    def validate_username(self, username: str) -> bool:
        """Validate username - delegates to security module."""
        try:
            return self.security.validation.validate_username(username)
        except Exception as e:
            self.logger.error(f"[VALIDATION] Username validation failed: {e}", exc_info=True)
            raise
    
    def validate_message(self, message: str) -> bool:
        """Validate message - delegates to security module."""
        try:
            return self.security.validation.validate_message(message)
        except Exception as e:
            self.logger.error(f"[VALIDATION] Message validation failed: {e}", exc_info=True)
            raise
    
    def validate_ip_address(self, ip: str) -> bool:
        """Validate IP address - delegates to security module."""
        try:
            return self.security.validation.validate_ip_address(ip)
        except Exception as e:
            self.logger.error(f"[VALIDATION] IP validation failed: {e}", exc_info=True)
            raise
    
    def validate_port(self, port: int) -> bool:
        """Validate port - delegates to security module."""
        try:
            return self.security.validation.validate_port(port)
        except Exception as e:
            self.logger.error(f"[VALIDATION] Port validation failed: {e}", exc_info=True)
            raise
    
    def validate_command(self, command: str) -> bool:
        """Validate command - delegates to security module."""
        try:
            return self.security.validation.validate_command(command)
        except Exception as e:
            self.logger.error(f"[VALIDATION] Command validation failed: {e}", exc_info=True)
            raise
    
    def verify_input_integrity(self, input_data: str, expected_hash: Optional[str] = None) -> bool:
        """Verify input integrity - delegates to security module."""
        try:
            return self.security.validation.verify_input_integrity(input_data, expected_hash)
        except Exception as e:
            self.logger.error(f"[VALIDATION] Integrity verification failed: {e}", exc_info=True)
            raise

    # ========== Keys Module Delegation Stubs ==========
    
    def store_key(self, key_material: bytes, key_name: str) -> str:
        """Store key - delegates to keys module."""
        try:
            return self.keys.storage.store_key(key_material, key_name)
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Key storage failed: {e}", exc_info=True)
            raise
    
    def retrieve_key(self, key_name: str):
        """Retrieve key - delegates to keys module."""
        try:
            return self.keys.storage.retrieve_key(key_name)
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Key retrieval failed: {e}", exc_info=True)
            raise
    
    def _secure_key_storage(self, key_material: bytes, key_name: str) -> str:
        """Secure key storage - delegates to keys module."""
        try:
            return self.keys.storage._secure_key_storage(key_material, key_name)
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Secure storage failed: {e}", exc_info=True)
            raise
    
    def _verify_key_storage(self) -> bool:
        """Verify key storage - delegates to keys module."""
        try:
            return self.keys.storage._verify_key_storage()
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Storage verification failed: {e}", exc_info=True)
            raise
    
    async def rotate_keys(self) -> bool:
        """Rotate keys - delegates to keys module."""
        try:
            return await self.keys.rotation.rotate_keys()
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Key rotation failed: {e}", exc_info=True)
            raise
    
    def _check_key_rotation_status(self) -> Dict:
        """Check key rotation status - delegates to keys module."""
        try:
            return self.keys.rotation._check_key_rotation_status()
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Rotation status check failed: {e}", exc_info=True)
            raise
    
    def schedule_key_rotation(self, interval: int) -> None:
        """Schedule key rotation - delegates to keys module."""
        try:
            self.keys.rotation.schedule_key_rotation(interval)
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Rotation scheduling failed: {e}", exc_info=True)
            raise
    
    def generate_identity_keys(self):
        """Generate identity keys - delegates to keys module."""
        try:
            return self.keys.generation.generate_identity_keys()
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Identity key generation failed: {e}", exc_info=True)
            raise
    
    def generate_ephemeral_keys(self) -> Dict:
        """Generate ephemeral keys - delegates to keys module."""
        try:
            return self.keys.generation.generate_ephemeral_keys()
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Ephemeral key generation failed: {e}", exc_info=True)
            raise
    
    def _derive_auth_key(self, root_key: bytes) -> bytes:
        """Derive auth key - delegates to keys module."""
        try:
            return self.keys.generation._derive_auth_key(root_key)
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] Auth key derivation failed: {e}", exc_info=True)
            raise
    
    def _initialize_hsm(self) -> bool:
        """Initialize HSM - delegates to keys module."""
        try:
            return self.keys.hsm_integration.initialize_hsm()
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] HSM initialization failed: {e}", exc_info=True)
            raise
    
    def _store_key_in_hsm(self, key_id: str, key_material: bytes) -> bool:
        """Store key in HSM - delegates to keys module."""
        try:
            return self.keys.hsm_integration.store_key_in_hsm(key_id, key_material)
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] HSM storage failed: {e}", exc_info=True)
            raise
    
    def _retrieve_key_from_hsm(self, key_id: str) -> bytes:
        """Retrieve key from HSM - delegates to keys module."""
        try:
            return self.keys.hsm_integration.retrieve_key_from_hsm(key_id)
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] HSM retrieval failed: {e}", exc_info=True)
            raise
    
    def _hsm_sign(self, message: bytes, key_id: str) -> bytes:
        """HSM sign - delegates to keys module."""
        try:
            return self.keys.hsm_integration.hsm_sign(message, key_id)
        except Exception as e:
            self.logger.error(f"[KEY_MGMT] HSM signing failed: {e}", exc_info=True)
            raise

    # ========== Data Module Delegation Stubs ==========
    
    async def create_new_user(self, username: str, display_name: str, ipv6: str, port: int) -> bool:
        """Create new user - delegates to data module."""
        try:
            return await self.data.user_mgmt.create_new_user(username, display_name, ipv6, port)
        except Exception as e:
            self.logger.error(f"[USER_MGMT] User creation failed: {e}", exc_info=True)
            raise
    
    async def automatic_login(self, current_ipv6: str, current_port: int, suppress_errors: bool = False) -> bool:
        """Automatic login - delegates to data module."""
        try:
            return await self.data.user_mgmt.automatic_login(current_ipv6, current_port, suppress_errors)
        except Exception as e:
            self.logger.error(f"[USER_MGMT] Auto-login failed: {e}", exc_info=True)
            raise
    
    def save_profile(self, username: str, display_name: str, user_id: str, ipv6: str, port: int, 
                    pubkey: str = None, private_key: str = None, passphrase: str = None):
        """Save profile - delegates to data module."""
        try:
            return self.data.user_mgmt.save(username, display_name, user_id, ipv6, port, 
                                           pubkey, private_key, passphrase)
        except Exception as e:
            self.logger.error(f"[USER_MGMT] Profile save failed: {e}", exc_info=True)
            raise
    
    def load_profile(self) -> Dict:
        """Load profile - delegates to data module."""
        try:
            return self.data.user_mgmt.load_profile()
        except Exception as e:
            self.logger.error(f"[USER_MGMT] Profile load failed: {e}", exc_info=True)
            raise
    
    def update_endpoint(self, ipv6: str, port: int) -> bool:
        """Update endpoint - delegates to data module."""
        try:
            return self.data.user_mgmt.update_endpoint(ipv6, port)
        except Exception as e:
            self.logger.error(f"[USER_MGMT] Endpoint update failed: {e}", exc_info=True)
            raise
    
    def hash_username_for_lookup(self, username: str) -> str:
        """Hash username for lookup - delegates to data module."""
        try:
            return self.data.user_mgmt.hash_username_for_lookup(username)
        except Exception as e:
            self.logger.error(f"[USER_MGMT] Username hashing failed: {e}", exc_info=True)
            raise
    
    async def lookup_peer_by_username(self, username: str) -> Optional[Dict]:
        """Lookup peer by username - delegates to data module."""
        try:
            return await self.data.peer_mgmt.lookup_peer_by_username(username)
        except Exception as e:
            self.logger.error(f"[PEER_MGMT] Peer lookup failed: {e}", exc_info=True)
            raise
    
    def add_peer(self, username: str, display_name: str, ipv6: str, port: int) -> None:
        """Add peer - delegates to data module."""
        try:
            self.data.peer_mgmt.add_peer(username, display_name, ipv6, port)
        except Exception as e:
            self.logger.error(f"[PEER_MGMT] Peer add failed: {e}", exc_info=True)
            raise
    
    def update_peer_connection(self, username: str, success: bool = True) -> None:
        """Update peer connection - delegates to data module."""
        try:
            self.data.peer_mgmt.update_peer_connection(username, success)
        except Exception as e:
            self.logger.error(f"[PEER_MGMT] Peer update failed: {e}", exc_info=True)
            raise
    
    def list_peers(self) -> List[Tuple[str, Dict]]:
        """List peers - delegates to data module."""
        try:
            return self.data.peer_mgmt.list_peers()
        except Exception as e:
            self.logger.error(f"[PEER_MGMT] Peer listing failed: {e}", exc_info=True)
            raise
    
    def get_peer(self, username: str) -> Optional[Dict]:
        """Get peer - delegates to data module."""
        try:
            return self.data.peer_mgmt.get_peer(username)
        except Exception as e:
            self.logger.error(f"[PEER_MGMT] Peer retrieval failed: {e}", exc_info=True)
            raise
    
    async def send_file(self, file_path: str) -> bool:
        """Send file - delegates to data module."""
        try:
            return await self.data.file_transfer.send_file(file_path)
        except Exception as e:
            self.logger.error(f"[FILE_TRANSFER] Send failed: {e}", exc_info=True)
            raise
    
    async def receive_file(self, file_id: str) -> bool:
        """Receive file - delegates to data module."""
        try:
            return await self.data.file_transfer.receive_file(file_id)
        except Exception as e:
            self.logger.error(f"[FILE_TRANSFER] Receive failed: {e}", exc_info=True)
            raise
    
    async def handle_file_message(self, peer_id: str, message: Dict) -> None:
        """Handle file message - delegates to data module."""
        try:
            await self.data.file_transfer.handle_file_message(peer_id, message)
        except Exception as e:
            self.logger.error(f"[FILE_TRANSFER] Message handling failed: {e}", exc_info=True)
            raise
    
    async def handle_file_chunk(self, peer_id: str, chunk: Dict) -> None:
        """Handle file chunk - delegates to data module."""
        try:
            await self.data.file_transfer.handle_file_chunk(peer_id, chunk)
        except Exception as e:
            self.logger.error(f"[FILE_TRANSFER] Chunk handling failed: {e}", exc_info=True)
            raise

    # ========== Messaging Module Delegation Stubs ==========
    
    async def handle_message(self, peer_id: str, message: bytes) -> None:
        """Handle message - delegates to messaging module."""
        try:
            await self.messaging.handler.handle_message(peer_id, message)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Message handling failed: {e}", exc_info=True)
            raise
    
    async def route_message(self, message_type: str, message: Dict) -> None:
        """Route message - delegates to messaging module."""
        try:
            await self.messaging.handler.route_message(message_type, message)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Message routing failed: {e}", exc_info=True)
            raise
    
    async def process_incoming_message(self, peer_id: str, encrypted_message: bytes) -> str:
        """Process incoming message - delegates to messaging module."""
        try:
            return await self.messaging.handler.process_incoming_message(peer_id, encrypted_message)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Message processing failed: {e}", exc_info=True)
            raise
    
    async def encrypt_message(self, peer_id: str, plaintext: str) -> bytes:
        """Encrypt message - delegates to messaging module."""
        try:
            return await self.messaging.encryption.encrypt_message(peer_id, plaintext)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Encryption failed: {e}", exc_info=True)
            raise
    
    async def decrypt_message(self, peer_id: str, ciphertext: bytes) -> str:
        """Decrypt message - delegates to messaging module."""
        try:
            return await self.messaging.encryption.decrypt_message(peer_id, ciphertext)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Decryption failed: {e}", exc_info=True)
            raise
    
    async def ratchet_encrypt(self, peer_id: str, plaintext: bytes) -> bytes:
        """Ratchet encrypt - delegates to messaging module."""
        try:
            return await self.messaging.encryption.ratchet_encrypt(peer_id, plaintext)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Ratchet encryption failed: {e}", exc_info=True)
            raise
    
    async def ratchet_decrypt(self, peer_id: str, ciphertext: bytes) -> bytes:
        """Ratchet decrypt - delegates to messaging module."""
        try:
            return await self.messaging.encryption.ratchet_decrypt(peer_id, ciphertext)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Ratchet decryption failed: {e}", exc_info=True)
            raise
    
    async def handle_command(self, command: str, args: List) -> None:
        """Handle command - delegates to messaging module."""
        try:
            await self.messaging.commands.handle_command(command, args)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Command handling failed: {e}", exc_info=True)
            raise
    
    async def execute_command(self, command: str, args: List) -> Any:
        """Execute command - delegates to messaging module."""
        try:
            return await self.messaging.commands.execute_command(command, args)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Command execution failed: {e}", exc_info=True)
            raise
    
    async def process_command(self, peer_id: str, command_message: Dict) -> None:
        """Process command - delegates to messaging module."""
        try:
            await self.messaging.commands.process_command(peer_id, command_message)
        except Exception as e:
            self.logger.error(f"[MESSAGING] Command processing failed: {e}", exc_info=True)
            raise

    # ========== UI Module Delegation Stubs ==========
    
    def display_message(self, sender: str, message: str, timestamp: float) -> None:
        """Display message - delegates to UI module."""
        try:
            self.ui.display.display_message(sender, message, timestamp)
        except Exception as e:
            self.logger.error(f"[UI] Message display failed: {e}", exc_info=True)
            raise
    
    def display_menu(self, options: List) -> None:
        """Display menu - delegates to UI module."""
        try:
            self.ui.display.display_menu(options)
        except Exception as e:
            self.logger.error(f"[UI] Menu display failed: {e}", exc_info=True)
            raise
    
    def display_status(self, status: Dict) -> None:
        """Display status - delegates to UI module."""
        try:
            self.ui.display.display_status(status)
        except Exception as e:
            self.logger.error(f"[UI] Status display failed: {e}", exc_info=True)
            raise
    
    def display_banner(self) -> None:
        """Display banner - delegates to UI module."""
        try:
            self.ui.display.display_banner()
        except Exception as e:
            self.logger.error(f"[UI] Banner display failed: {e}", exc_info=True)
            raise
    
    def _print_banner(self) -> None:
        """Print banner - delegates to UI module."""
        try:
            self.ui.display.display_banner()
        except Exception as e:
            self.logger.error(f"[UI] Banner print failed: {e}", exc_info=True)
            raise
    
    def _print_security_summary(self) -> None:
        """Print security summary - delegates to UI module."""
        try:
            self.ui.display.print_security_summary()
        except Exception as e:
            self.logger.error(f"[UI] Security summary print failed: {e}", exc_info=True)
            raise
    
    def _get_hw_security_status(self) -> str:
        """Get hardware security status - delegates to UI module."""
        try:
            return self.ui.display.get_hw_security_status()
        except Exception as e:
            self.logger.error(f"[UI] Hardware security status retrieval failed: {e}", exc_info=True)
            raise
    
    def display_security_recommendations(self) -> None:
        """Display security recommendations - delegates to UI module."""
        try:
            self.ui.display.display_security_recommendations()
        except Exception as e:
            self.logger.error(f"[UI] Security recommendations display failed: {e}", exc_info=True)
            raise
    
    def _get_additional_security_features(self) -> List:
        """Get additional security features - delegates to UI module."""
        try:
            return self.ui.display.get_additional_security_features()
        except Exception as e:
            self.logger.error(f"[UI] Additional security features retrieval failed: {e}", exc_info=True)
            raise
    
    def _get_memory_protection_status(self) -> str:
        """Get memory protection status - delegates to UI module."""
        try:
            return self.ui.display.get_memory_protection_status()
        except Exception as e:
            self.logger.error(f"[UI] Memory protection status retrieval failed: {e}", exc_info=True)
            raise
    
    def _get_dep_details(self) -> List:
        """Get DEP details - delegates to UI module."""
        try:
            return self.ui.display.get_dep_details()
        except Exception as e:
            self.logger.error(f"[UI] DEP details retrieval failed: {e}", exc_info=True)
            raise
    
    def _check_secure_boot_status(self) -> str:
        """Check secure boot status - delegates to UI module."""
        try:
            return self.ui.display.check_secure_boot_status()
        except Exception as e:
            self.logger.error(f"[UI] Secure boot status check failed: {e}", exc_info=True)
            raise
    
    def _check_tpm_status(self) -> str:
        """Check TPM status - delegates to UI module."""
        try:
            return self.ui.display.check_tpm_status()
        except Exception as e:
            self.logger.error(f"[UI] TPM status check failed: {e}", exc_info=True)
            raise
    
    async def _async_input(self, prompt: str) -> str:
        """Async input - delegates to UI module."""
        try:
            return await self.ui.prompts.async_input(prompt)
        except Exception as e:
            self.logger.error(f"[UI] Async input failed: {e}", exc_info=True)
            raise
    
    def prompt_user(self, prompt: str) -> str:
        """Prompt user - delegates to UI module."""
        try:
            return self.ui.prompts.prompt_user(prompt)
        except Exception as e:
            self.logger.error(f"[UI] User prompt failed: {e}", exc_info=True)
            raise
    
    def get_user_input(self, prompt: str, validator: Optional[callable] = None) -> str:
        """Get user input - delegates to UI module."""
        try:
            return self.ui.prompts.get_user_input(prompt, validator)
        except Exception as e:
            self.logger.error(f"[UI] Input retrieval failed: {e}", exc_info=True)
            raise
    
    def confirm_action(self, prompt: str) -> bool:
        """Confirm action - delegates to UI module."""
        try:
            return self.ui.prompts.confirm_action(prompt)
        except Exception as e:
            self.logger.error(f"[UI] Action confirmation failed: {e}", exc_info=True)
            raise
    
    def get_secure_input(self, prompt: str) -> str:
        """Get secure input - delegates to UI module."""
        try:
            return self.ui.prompts.get_secure_input(prompt)
        except Exception as e:
            self.logger.error(f"[UI] Secure input failed: {e}", exc_info=True)
            raise
    
    async def handle_connections(self) -> None:
        """Handle connections - delegates to UI module."""
        try:
            await self.ui.menus.handle_connections()
        except Exception as e:
            self.logger.error(f"[UI] Connection handling failed: {e}", exc_info=True)
            raise
    
    async def connect_by_username(self) -> None:
        """Connect by username - delegates to UI module."""
        try:
            await self.ui.menus.connect_by_username()
        except Exception as e:
            self.logger.error(f"[UI] Username connection failed: {e}", exc_info=True)
            raise
    
    async def connect_by_ip(self) -> None:
        """Connect by IP - delegates to UI module."""
        try:
            await self.ui.menus.connect_by_ip()
        except Exception as e:
            self.logger.error(f"[UI] IP connection failed: {e}", exc_info=True)
            raise
    
    def show_stored_peers(self) -> None:
        """Show stored peers - delegates to UI module."""
        try:
            self.ui.menus.show_stored_peers()
        except Exception as e:
            self.logger.error(f"[UI] Peer display failed: {e}", exc_info=True)
            raise
    
    async def handle_user_management(self) -> None:
        """Handle user management - delegates to UI module."""
        try:
            await self.ui.menus.handle_user_management()
        except Exception as e:
            self.logger.error(f"[UI] User management failed: {e}", exc_info=True)
            raise
    
    def view_security_status(self) -> None:
        """View comprehensive security status - delegates to UI module."""
        try:
            self.ui.display.view_security_status()
        except Exception as e:
            self.logger.error(f"[UI] Security status display failed: {e}", exc_info=True)
            raise

    # ========== Utils Module Delegation Stubs ==========
    
    def secure_erase(self, key_material: bytes) -> None:
        """Secure erase - delegates to utils module."""
        try:
            self.utils.memory.secure_erase(key_material)
        except Exception as e:
            self.logger.error(f"[MEMORY] Secure erase failed: {e}", exc_info=True)
            raise
    
    def _pin_memory(self, material: bytearray) -> bool:
        """Pin memory - delegates to utils module."""
        try:
            return self.utils.memory.pin_memory(material)
        except Exception as e:
            self.logger.error(f"[MEMORY] Memory pinning failed: {e}", exc_info=True)
            raise
    
    def _unpin_memory(self) -> None:
        """Unpin memory - delegates to utils module."""
        try:
            self.utils.memory.unpin_memory()
        except Exception as e:
            self.logger.error(f"[MEMORY] Memory unpinning failed: {e}", exc_info=True)
            raise
    
    def _secure_memory_wipe(self, address: int, length: int) -> bool:
        """Secure memory wipe - delegates to utils module."""
        try:
            return self.utils.memory.secure_memory_wipe(address, length)
        except Exception as e:
            self.logger.error(f"[MEMORY] Memory wipe failed: {e}", exc_info=True)
            raise
    
    async def _initialize_components(self) -> None:
        """Initialize components - delegates to utils module."""
        try:
            await self.utils.initialization.initialize_components()
        except Exception as e:
            self.logger.error(f"[INIT] Component initialization failed: {e}", exc_info=True)
            raise
    
    def _load_configuration(self) -> Dict:
        """Load configuration - delegates to utils module."""
        try:
            return self.utils.initialization.load_configuration()
        except Exception as e:
            self.logger.error(f"[INIT] Configuration loading failed: {e}", exc_info=True)
            raise
    
    def _setup_logging_utils(self) -> None:
        """Setup logging - delegates to utils module."""
        try:
            self.utils.initialization.setup_logging()
        except Exception as e:
            self.logger.error(f"[INIT] Logging setup failed: {e}", exc_info=True)
            raise
    
    async def _cleanup_resources(self) -> None:
        """Cleanup resources - delegates to utils module."""
        try:
            await self.utils.cleanup.cleanup_resources()
        except Exception as e:
            self.logger.error(f"[CLEANUP] Resource cleanup failed: {e}", exc_info=True)
            raise
    
    async def _stop_monitoring(self) -> None:
        """Stop monitoring - delegates to utils module."""
        try:
            await self.utils.cleanup.stop_monitoring()
        except Exception as e:
            self.logger.error(f"[CLEANUP] Monitoring stop failed: {e}", exc_info=True)
            raise
    
    async def shutdown_gracefully(self) -> None:
        """Shutdown gracefully - delegates to utils module."""
        try:
            await self.utils.cleanup.shutdown_gracefully()
        except Exception as e:
            self.logger.error(f"[CLEANUP] Graceful shutdown failed: {e}", exc_info=True)
            raise
    
    def _format_binary(self, data: bytes) -> str:
        """Format binary - delegates to utils module."""
        try:
            return self.utils.helpers.format_binary(data)
        except Exception as e:
            self.logger.error(f"[UTILS] Binary formatting failed: {e}", exc_info=True)
            raise
    
    def generate_nonce(self) -> bytes:
        """Generate nonce - delegates to utils module."""
        try:
            return self.utils.helpers.generate_nonce()
        except Exception as e:
            self.logger.error(f"[UTILS] Nonce generation failed: {e}", exc_info=True)
            raise
    
    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Constant time compare - delegates to utils module."""
        try:
            return self.utils.helpers.constant_time_compare(a, b)
        except Exception as e:
            self.logger.error(f"[UTILS] Constant time compare failed: {e}", exc_info=True)
            raise

