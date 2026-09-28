"""
System initialization operations.

Provides system initialization and setup.
"""

import os
import logging
from typing import Dict, Optional

try:
    from ..base import BaseModule
except (ImportError, ValueError):
    from base import BaseModule

log = logging.getLogger(__name__)


class Initialization(BaseModule):
    """System initialization operations."""
    
    async def initialize(self) -> None:
        """Initialize system components."""
        try:
            self.logger.info("Starting system initialization")
            
            # Setup logging first
            self.setup_logging()
            
            # Load configuration
            config = self.load_configuration()
            
            # Initialize components
            await self.initialize_components()
            
            self.logger.info("System initialization completed successfully")
        except Exception as e:
            self.logger.error(f"System initialization failed: {e}")
            raise
    
    async def initialize_components(self) -> None:
        """Initialize all system components."""
        try:
            self.logger.info("Initializing system components")
            
            # Components are initialized through the orchestrator's lazy loading
            # This method serves as a hook for any additional initialization logic
            
            self.logger.debug("System components initialization completed")
        except Exception as e:
            self.logger.error(f"Component initialization failed: {e}")
            raise
    
    def load_configuration(self) -> Dict:
        """
        Load configuration from environment variables or defaults.
        
        Returns:
            Dict: Configuration dictionary
        """
        try:
            self.logger.info("Loading configuration")
            
            config = {
                # Security settings
                'security_level': os.environ.get('P2P_SECURITY_LEVEL', 'MAXIMUM'),
                'use_secure_enclave': os.environ.get('P2P_USE_SECURE_ENCLAVE', 'true').lower() == 'true',
                
                # Directory settings
                'secure_dir': os.environ.get('P2P_SECURE_DIR', None),
                'cert_dir': os.environ.get('P2P_CERT_DIR', os.path.join(os.path.dirname(__file__), '..', '..', 'certs')),
                'keys_dir': os.environ.get('P2P_KEYS_DIR', os.path.join(os.path.dirname(__file__), '..', '..', 'keys')),
                'base_dir': os.environ.get('P2P_BASE_DIR', os.path.dirname(__file__)),
                
                # Authentication settings (Enforced by default)
                'require_authentication': os.environ.get('P2P_REQUIRE_AUTH', 'true').lower() == 'true',
                'oauth_provider': os.environ.get('P2P_OAUTH_PROVIDER', 'google'),
                'oauth_client_id': os.environ.get('P2P_OAUTH_CLIENT_ID', None),
                
                # DANE TLSA validation settings (Enforced by default)
                'enforce_dane_validation': os.environ.get('P2P_ENFORCE_DANE', 'true').lower() == 'true',
            }
            
            # Create directories if they don't exist
            for dir_key in ['cert_dir', 'keys_dir']:
                if config[dir_key]:
                    os.makedirs(config[dir_key], exist_ok=True)
                    self.logger.debug(f"Ensured directory exists: {config[dir_key]}")
            
            self.logger.info(f"Configuration loaded with security level: {config['security_level']}")
            return config
            
        except Exception as e:
            self.logger.error(f"Configuration loading failed: {e}")
            raise
    
    def setup_logging(self) -> None:
        """
        Setup logging for the system.
        
        Smart logging is already configured globally, this ensures
        the logger is properly initialized.
        """
        try:
            # Logging is already configured at module level
            # Just ensure our logger is working
            self.logger.info("Logging setup completed")
        except Exception as e:
            # Fallback to print if logging fails
            print(f"Warning: Logging setup failed: {e}")
