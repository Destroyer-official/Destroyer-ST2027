"""
Configuration management for the P2P system.

Handles loading, validation, and management of system configuration.
"""

import os
import json
import logging
from typing import Dict, Any, Optional


class ConfigManager:
    """
    Configuration manager for the P2P system.
    
    Handles loading configuration from files and environment variables,
    with validation and default values.
    """
    
    # Default configuration
    DEFAULTS = {
        'security_level': 'MAXIMUM',
        'key_lifetime': 3072,
        'handshake_timeout': 30.0,
        'connection_timeout': 60.0,
        'heartbeat_interval': 30.0,
        'max_retries': 3,
        'log_level': 'INFO',
        'audit_enabled': True,
        'memory_protection': True,
        'anti_debugging': True,
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Optional path to configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config = self.DEFAULTS.copy()
        
        if config_file and os.path.exists(config_file):
            self._load_from_file(config_file)
        
        self._load_from_environment()
    
    def _load_from_file(self, config_file: str) -> None:
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                self.config.update(file_config)
                self.logger.info(f"Loaded configuration from {config_file}")
        except Exception as e:
            self.logger.error(f"Failed to load configuration from {config_file}: {e}")
    
    def _load_from_environment(self) -> None:
        """Load configuration from environment variables."""
        env_mappings = {
            'P2P_SECURITY_LEVEL': 'security_level',
            'P2P_KEY_LIFETIME': 'key_lifetime',
            'P2P_HANDSHAKE_TIMEOUT': 'handshake_timeout',
            'P2P_LOG_LEVEL': 'log_level',
            'P2P_AUDIT_ENABLED': 'audit_enabled',
        }
        
        for env_var, config_key in env_mappings.items():
            if env_var in os.environ:
                value = os.environ[env_var]
                # Convert to appropriate type
                if config_key in ['key_lifetime', 'max_retries']:
                    self.config[config_key] = int(value)
                elif config_key in ['handshake_timeout', 'connection_timeout', 'heartbeat_interval']:
                    self.config[config_key] = float(value)
                elif config_key in ['audit_enabled', 'memory_protection', 'anti_debugging']:
                    self.config[config_key] = value.lower() in ('true', '1', 'yes')
                else:
                    self.config[config_key] = value
                self.logger.debug(f"Loaded {config_key} from environment variable {env_var}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value
        """
        self.config[key] = value
        self.logger.debug(f"Set configuration {key}={value}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary."""
        return self.config.copy()
