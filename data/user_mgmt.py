"""
User management operations.

Provides user profile creation, authentication, and management with secure
encryption and hashing.
"""

import os
import json
import secrets
import hashlib
import base64
import getpass
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidTag

try:
    from ..base import BaseModule, UserManagementError
except (ImportError, ValueError):
    from base import BaseModule, UserManagementError

# Check if database is available
try:
    from Neon_PostgreSQL.core import (
        initialize_secure_system,
        create_or_register_user,
        Ed25519APIClient
    )
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False


class MilitaryGradeCrypto:
    """secure cryptographic operations for hashed identifiers."""
    
    SYSTEM_SALT: str = "MILITARY_GRADE_P2P_QUANTUM_RESISTANT_SALT_2025_SHA3_512"

    @staticmethod
    def generate_secure_salt() -> str:
        """Generate cryptographically secure 256-bit salt."""
        return secrets.token_hex(32)

    @staticmethod
    def quantum_resistant_hash(data: str, salt: str) -> str:
        """Quantum-resistant hash using SHA3-512."""
        hasher = hashlib.sha3_512()
        hasher.update(salt.encode('utf-8'))
        hasher.update(data.encode('utf-8'))
        return hasher.hexdigest()

    @staticmethod
    def hash_username_for_lookup(username: str) -> str:
        """Hash username for secure database lookup."""
        return MilitaryGradeCrypto.quantum_resistant_hash(
            username, 
            MilitaryGradeCrypto.SYSTEM_SALT
        )

    @staticmethod
    def hash_user_id_for_storage(user_id: str) -> str:
        """Hash user_id for secure database storage."""
        salt = MilitaryGradeCrypto.generate_secure_salt()
        hashed = MilitaryGradeCrypto.quantum_resistant_hash(user_id, salt)
        return f"{salt}:{hashed}"


class EnhancedUserManager(BaseModule):
    """
    Enhanced user profile management with hashed storage and database integration.
    
    Provides secure encryption for user profiles using AES-256-GCM and
    SHA3-512 hashing for secure storage and lookup.
    """
    
    def __init__(self, orchestrator=None):
        """Initialize the enhanced user manager."""
        super().__init__(orchestrator)
        self.log = self.logger
        self.profile_file = Path("enhanced_user_profile.json")
        self.data = {}
        self.database_available = DATABASE_AVAILABLE
        self.api_client = None
        self.discovery_initialized = False
        self._encryption_key = None  # To hold the derived key
        self._salt = None
        
        if self.database_available:
            try:
                # Initialize the secure system using existing functions
                initialize_secure_system()
                self.discovery_initialized = True
                self.log.info("P2P Discovery Service initialized")
            except Exception as e:
                self.log.warning(f"Database initialization failed: {e}")
                self.database_available = False

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """
        Derive a 256-bit key from the passphrase and salt.
        
        Args:
            passphrase: User passphrase
            salt: Cryptographic salt
            
        Returns:
            Derived 256-bit key
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            return kdf.derive(passphrase.encode())
        except Exception as e:
            self.log.error(f"Key derivation failed: {e}", exc_info=True)
            raise UserManagementError(
                f"Key derivation failed: {e}",
                severity="HIGH",
                module="data.user_mgmt",
                function="_derive_key"
            )

    def _get_passphrase(self, confirm=False):
        """
        Securely get passphrase from user.
        
        Args:
            confirm: Whether to confirm passphrase
            
        Returns:
            Passphrase string or None if confirmation fails
        """
        try:
            if confirm:
                passphrase = getpass.getpass("Enter a new passphrase for your profile: ")
                passphrase_confirm = getpass.getpass("Confirm passphrase: ")
                if passphrase != passphrase_confirm:
                    print("[FAIL] Passphrases do not match.")
                    return None
                return passphrase
            else:
                return getpass.getpass("Enter passphrase to unlock your profile: ")
        except Exception as e:
            self.log.error(f"Passphrase input failed: {e}", exc_info=True)
            return None

    def exists(self) -> bool:
        """Check if user profile exists locally."""
        return self.profile_file.exists()

    def load(self) -> bool:
        """
        Load and decrypt user profile from local storage.
        
        Returns:
            True if profile loaded successfully, False otherwise
        """
        if not self.profile_file.exists():
            return False

        passphrase = self._get_passphrase()
        if not passphrase:
            return False

        try:
            with open(self.profile_file, 'rb') as f:
                encrypted_data = f.read()

            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]

            self._salt = salt
            self._encryption_key = self._derive_key(passphrase, salt)
            aesgcm = AESGCM(self._encryption_key)

            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            self.data = json.loads(decrypted_data)
            self.log.info("Profile decrypted and loaded successfully")
            return bool(self.data.get('username'))
            
        except InvalidTag:
            print("[FAIL] Decryption failed. Incorrect passphrase.")
            self._encryption_key = None
            return False
        except Exception as e:
            self.log.error(f"Failed to load profile: {e}", exc_info=True)
            print(f"[FAIL] Failed to load profile: {e}")
            self._encryption_key = None
            return False

    async def create_new_user(self, username: str, display_name: str, ipv6: str, port: int) -> bool:
        """
        Create new user with P2P Discovery Service registration.
        
        Args:
            username: Username
            display_name: Display name
            ipv6: IPv6 address
            port: Port number
            
        Returns:
            True if user created successfully, False otherwise
        """
        try:
            self.log.info(f"Creating secure user profile for '{username}'")

            passphrase = self._get_passphrase(confirm=True)
            if not passphrase:
                return False

            # Initialize P2P Discovery Service if available
            await self._ensure_discovery_service()

            # Register with P2P Discovery Service if available
            if DATABASE_AVAILABLE and self.discovery_initialized:
                try:
                    self.log.info("Registering with P2P Discovery Service")
                    # Use the existing create_or_register_user function
                    result = create_or_register_user(
                        display_name=display_name,
                        public_ip=ipv6,
                        port=port
                    )

                    if result.get('success'):
                        user_id = result.get('user_id')
                        private_key_b64 = result.get('private_key')
                        pubkey = result.get('public_key')

                        self.log.info("P2P Discovery Service registration successful")

                        # Save locally with secure encryption
                        self.save(username, display_name, user_id, ipv6, port, 
                                pubkey, private_key_b64, passphrase)
                        self.log.info("Local profile created with secure encryption")
                        return True
                    else:
                        self.log.warning(f"P2P Discovery Service registration failed: {result.get('message', 'Unknown error')}")
                        return False

                except Exception as e:
                    self.log.error(f"P2P Discovery Service registration error: {e}", exc_info=True)
                    return False
            else:
                # Offline mode - generate local profile only
                user_id = secrets.token_hex(8)
                private_key = ed25519.Ed25519PrivateKey.generate()
                pubkey = private_key.public_key()
                private_key_b64 = base64.b64encode(
                    private_key.private_bytes_raw()
                ).decode('utf-8')
                pubkey_hex = pubkey.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ).hex()

                self.save(username, display_name, user_id, ipv6, port, 
                        pubkey_hex, private_key_b64, passphrase)
                self.log.info("Local profile created (offline mode)")
                return True

        except Exception as e:
            self.log.error(f"User creation failed: {e}", exc_info=True)
            raise UserManagementError(
                f"User creation failed: {e}",
                severity="HIGH",
                module="data.user_mgmt",
                function="create_new_user"
            )

    async def automatic_login(self, current_ipv6: str, current_port: int, 
                            suppress_errors: bool = False) -> bool:
        """
        Perform automatic login for returning users.
        
        Args:
            current_ipv6: Current IPv6 address
            current_port: Current port
            suppress_errors: Whether to suppress error messages
            
        Returns:
            True if login successful, False otherwise
        """
        if not self.exists():
            return False

        if not self.load():  # This will prompt for passphrase and decrypt
            return False

        try:
            self.log.info(f"Automatic login for user '{self.data.get('username')}'")

            # Update endpoint information locally
            self.update_endpoint(current_ipv6, current_port)

            # Initialize P2P Discovery Service if available
            await self._ensure_discovery_service()

            # Update P2P Discovery Service if available
            await self._ensure_api_client()
            if self.api_client and self.data.get('user_id') and self.data.get('pubkey'):
                try:
                    if not suppress_errors:
                        self.log.info("Updating endpoint in P2P Discovery Service")

                    # Temporarily suppress specific logger messages for new users
                    if suppress_errors:
                        # Get the API client logger and temporarily increase its level
                        api_logger = logging.getLogger('core.api_client')
                        original_level = api_logger.level
                        api_logger.setLevel(logging.CRITICAL)

                        try:
                            success = await self.api_client.update_user_status(
                                user_id=self.data['user_id'],
                                pubkey=self.data['pubkey'],
                                public_ip=current_ipv6,
                                port=current_port,
                                online_status=True
                            )
                        finally:
                            # Always restore the original logging level
                            api_logger.setLevel(original_level)
                    else:
                        success = await self.api_client.update_user_status(
                            user_id=self.data['user_id'],
                            pubkey=self.data['pubkey'],
                            public_ip=current_ipv6,
                            port=current_port,
                            online_status=True
                        )

                    if success and not suppress_errors:
                        self.log.info("P2P Discovery Service endpoint updated")

                except Exception as e:
                    if not suppress_errors:
                        self.log.warning(f"P2P Discovery Service update error: {e}")

            self.log.info("Automatic login successful")
            return True

        except Exception as e:
            if not suppress_errors:
                self.log.error(f"Automatic login failed: {e}", exc_info=True)
            return False

    def save(self, username: str, display_name: str, user_id: str, ipv6: str, port: int,
            pubkey: str = None, private_key: str = None, passphrase: str = None,
            role: str = "OPERATOR"):
        """
        Save and encrypt user profile with secure hashing and RBAC role.
        
        Args:
            username: Username
            display_name: Display name
            user_id: User ID
            ipv6: IPv6 address
            port: Port number
            pubkey: Public key (optional)
            private_key: Private key (optional)
            passphrase: Passphrase for encryption (optional)
            role: SecurityRole string (default: OPERATOR)
        """
        try:
            if passphrase:
                salt = secrets.token_bytes(16)
                self._salt = salt
                self._encryption_key = self._derive_key(passphrase, salt)
            elif self._encryption_key:
                salt = getattr(self, '_salt', None)
                if not salt and Path(self.profile_file).exists():
                    try:
                        with open(self.profile_file, 'rb') as f:
                            salt = f.read(16)
                    except Exception:
                        salt = None
                if not salt:
                    salt = secrets.token_bytes(16)
                self._salt = salt
            else:
                raise ValueError("Passphrase is required to save a new profile.")

            username_hash = MilitaryGradeCrypto.hash_username_for_lookup(username)
            user_id_hash = MilitaryGradeCrypto.hash_user_id_for_storage(user_id)

            self.data = {
                'username': username,
                'display_name': display_name,
                'user_id': user_id,
                'role': role,
                'username_hash': username_hash,
                'user_id_hash': user_id_hash,
                'ipv6_address': ipv6,
                'port': port,
                'pubkey': pubkey or secrets.token_hex(32),
                'private_key': private_key,  # Storing the b64 encoded private key
                'created_at': datetime.now().isoformat(),
                'last_login': datetime.now().isoformat(),
                'security_level': 'MILITARY_GRADE'
            }

            profile_json = json.dumps(self.data, indent=2).encode('utf-8')

            aesgcm = AESGCM(self._encryption_key)
            nonce = secrets.token_bytes(12)
            ciphertext = aesgcm.encrypt(nonce, profile_json, None)

            with open(self.profile_file, 'wb') as f:
                f.write(salt + nonce + ciphertext)
                
            self.log.info("Profile saved and encrypted successfully")
            
        except Exception as e:
            self.log.error(f"Failed to save profile: {e}", exc_info=True)
            raise UserManagementError(
                f"Failed to save profile: {e}",
                severity="HIGH",
                module="data.user_mgmt",
                function="save"
            )

    def load_profile(self) -> Dict:
        """
        Load user profile (alias for load method).
        
        Returns:
            Profile dictionary if successful, empty dict otherwise
        """
        if self.load():
            return self.get_profile()
        return {}

    def save_profile(self):
        """Save and encrypt the current profile data to file."""
        try:
            if self.data and self._encryption_key:
                profile_json = json.dumps(self.data, indent=2).encode('utf-8')

                # Read the old salt
                try:
                    with open(self.profile_file, 'rb') as f:
                        old_salt = f.read(16)
                except FileNotFoundError:
                    # This should not happen if we are updating
                    old_salt = secrets.token_bytes(16)

                aesgcm = AESGCM(self._encryption_key)
                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, profile_json, None)

                with open(self.profile_file, 'wb') as f:
                    f.write(old_salt + nonce + ciphertext)
                    
                self.log.info("Profile saved successfully")
                
        except Exception as e:
            self.log.error(f"Failed to save profile: {e}", exc_info=True)
            raise UserManagementError(
                f"Failed to save profile: {e}",
                severity="MEDIUM",
                module="data.user_mgmt",
                function="save_profile"
            )

    def update_endpoint(self, ipv6: str, port: int):
        """
        Update user endpoint information and re-save the encrypted profile.
        
        Args:
            ipv6: New IPv6 address
            port: New port number
        """
        try:
            if self.data and self._encryption_key:
                self.data.update({
                    'ipv6_address': ipv6,
                    'port': port,
                    'last_login': datetime.now().isoformat()
                })
                self.save_profile()
                self.log.info(f"Endpoint updated: {ipv6}:{port}")
        except Exception as e:
            self.log.error(f"Failed to update endpoint: {e}", exc_info=True)
            raise UserManagementError(
                f"Failed to update endpoint: {e}",
                severity="MEDIUM",
                module="data.user_mgmt",
                function="update_endpoint"
            )

    def get_profile(self) -> Dict:
        """Get current user profile."""
        return self.data.copy() if self.data else {}

    def hash_username_for_lookup(self, username: str) -> str:
        """
        Hash username for secure database lookup.
        
        Args:
            username: Username to hash
            
        Returns:
            Hashed username
        """
        return MilitaryGradeCrypto.hash_username_for_lookup(username)

    async def _ensure_api_client(self):
        """Ensure API client is properly initialized."""
        if DATABASE_AVAILABLE and not self.api_client:
            try:
                self.api_client = Ed25519APIClient()
                await self.api_client.initialize()

                # Cache user keys if we have a profile
                if self.exists():
                    user_id = self.data.get('user_id')
                    private_key = self.data.get('private_key')
                    pubkey = self.data.get('pubkey')

                    if user_id and private_key and pubkey:
                        # Cache the keys in the API client for authentication
                        try:
                            # Convert base64 private key to Ed25519 private key object
                            private_key_bytes = base64.b64decode(private_key)
                            private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(
                                private_key_bytes
                            )

                            # Cache the keys in the API client
                            self.api_client._user_keys[user_id] = {
                                'public_key': pubkey,
                                'private_key_obj': private_key_obj
                            }
                            self.log.info("User authentication keys cached in API client")
                        except Exception as key_error:
                            self.log.warning(f"Failed to cache user keys: {key_error}")
                            # Try hex format as fallback
                            try:
                                private_key_bytes = bytes.fromhex(private_key)
                                private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(
                                    private_key_bytes
                                )

                                self.api_client._user_keys[user_id] = {
                                    'public_key': pubkey,
                                    'private_key_obj': private_key_obj
                                }
                                self.log.info("User authentication keys cached (hex fallback)")
                            except Exception as hex_error:
                                self.log.warning(f"Failed to cache user keys (both formats): {hex_error}")

                self.log.info("API client initialized")
            except Exception as e:
                self.log.warning(f"API client initialization failed: {e}")
                self.api_client = None

    async def _ensure_discovery_service(self):
        """Ensure P2P Discovery Service is properly initialized."""
        if DATABASE_AVAILABLE and not self.discovery_initialized:
            try:
                # Initialize the P2P Discovery Service
                result = initialize_secure_system()

                # Handle both bool and dict return types
                if isinstance(result, bool):
                    success = result
                else:
                    success = result.get('success', False)

                if success:
                    self.discovery_initialized = True
                    self.log.info("P2P Discovery Service initialized")
                else:
                    error_msg = result.get('message', 'Unknown error') if isinstance(result, dict) else 'Initialization failed'
                    self.log.warning(f"P2P Discovery Service initialization failed: {error_msg}")
            except Exception as e:
                self.log.warning(f"P2P Discovery Service initialization error: {e}")
                self.discovery_initialized = False
