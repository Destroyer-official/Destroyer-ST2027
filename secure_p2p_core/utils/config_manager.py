"""
Configuration Manager with Backward Compatibility

This module provides configuration management with full backward compatibility:
- Loads existing configurations without errors
- Provides default values for all new settings
- Supports graceful degradation when security modules are unavailable
- Maintains existing configuration format

Requirements: 7.4, 7.3
"""

import json
import logging
import os
import secrets
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration loading fails (fail-closed, mirrors config.py / Finding 7.1)."""
    pass


class ConfigManager:
    """
    Configuration manager with backward compatibility support.
    
    This class ensures that:
    1. Existing configurations load without errors (Requirement 7.4)
    2. New security settings are optional with defaults
    3. Missing settings don't cause failures
    4. Configuration format is preserved
    """
    
    # Default configuration values for new security settings
    DEFAULT_SECURITY_SETTINGS = {
        "security": {
            "level": "MAXIMUM",
            "quantum_resistance": {
                "enabled": True,
                "preferred_algorithm": "ML-KEM-1024"
            },
            "algorithms": {
                "key_exchange": ["ML-KEM-1024"],
                "signatures": ["ML-DSA-87", "SLH-DSA-256f"],
                "encryption": ["ChaCha20-Poly1305", "AES-256-GCM"],
                "hash": ["SHA-512"],
                "kdf": ["HKDF-SHA512"]
            },
            "key_management": {
                "mandatory_key_rotation": True,
                "key_rotation_seconds": 900,
                "max_key_operations": 2500,
                "forward_secrecy": {
                    "enabled": True,
                    "ephemeral_keys_only": True
                }
            },
            "hardware_security": {
                "enabled": True,
                "tpm_required": False,
                "hsm_required": False
            },
            "memory_protection": {
                "enabled": True,
                "secure_erase": True,
                "canary_values": True
            },
            # Settings enforcing military fail-closed policy (zero fallbacks)
            "double_ratchet": {
                "enabled": True,
                "fallback_to_basic": False  # Military policy: fallback prohibited
            },
            "hybrid_kex": {
                "enabled": True,
                "fallback_to_x25519": False  # Military policy: classical-only fallback prohibited
            },
            "audit_logging": {
                "enabled": True,
                "fallback_to_file": False  # Military policy: tamper-evident logging required
            }
        },
        "networking": {
            "tls": {
                "version": "1.3",
                "min_version": "1.3",
                "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                "allow_plaintext_fallback": False,
                "allow_unauthenticated_fallback": False
            },
            "secure_channels": {
                "mutual_authentication": True,
                "mandatory_authentication": True
            },
            "certificate_validation": True,
            "stun_servers": []
        },
        "platform": {
            "hardware_security": {
                "secure_memory_enabled": True,
                "tpm_integration": True,
                "hsm_integration": True
            }
        },
        "authentication": {
            "required": False,
            "anonymous_mode": True,
            "ephemeral_identities": True
        },
        "logging": {
            "level": "INFO",
            "security_events": True,
            "audit_trail": True
        }
    }
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """
        Load configuration from file with backward compatibility.
        
        This method:
        1. Loads existing configuration if it exists
        2. Merges with default values for missing settings
        3. Ensures no errors occur with old configurations
        
        Requirements: 7.4
        """
        try:
            if os.path.exists(self.config_path):
                logger.info(f"Loading configuration from {self.config_path}")
                
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                
                # Merge loaded config with defaults
                # Existing settings take precedence
                self.config = self._merge_configs(loaded_config, self.DEFAULT_SECURITY_SETTINGS)
                
                logger.info("Configuration loaded successfully with backward compatibility")
            else:
                logger.info(f"Configuration file not found at {self.config_path}, using defaults")
                self.config = self.DEFAULT_SECURITY_SETTINGS.copy()
                
        except json.JSONDecodeError as e:
            logger.critical(f"FAIL-CLOSED: Corrupted or invalid configuration file '{self.config_path}': {e}")
            raise ConfigurationError(
                f"Corrupted or invalid configuration file '{self.config_path}': {e}"
            ) from e

        except ConfigurationError:
            raise

        except Exception as e:
            logger.critical(f"FAIL-CLOSED: Error loading configuration file '{self.config_path}': {e}")
            raise ConfigurationError(
                f"Failed to load configuration file '{self.config_path}': {e}"
            ) from e
    
    def _merge_configs(self, user_config: Dict[str, Any], default_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge user configuration with defaults.
        
        User settings take precedence over defaults.
        Missing settings are filled in from defaults.
        
        Args:
            user_config: User-provided configuration
            default_config: Default configuration values
            
        Returns:
            Merged configuration dictionary
        """
        merged = default_config.copy()
        
        for key, value in user_config.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries
                merged[key] = self._merge_configs(value, merged[key])
            else:
                # User value takes precedence
                merged[key] = value
        
        return merged
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-separated key path.
        
        Examples:
            config.get("security.level")
            config.get("security.double_ratchet.enabled", True)
        
        Args:
            key_path: Dot-separated path to configuration value
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set configuration value by dot-separated key path.
        
        Args:
            key_path: Dot-separated path to configuration value
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to the parent dictionary
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
    
    def is_security_module_enabled(self, module_name: str) -> bool:
        """
        Check if a security module is enabled in configuration.
        
        Args:
            module_name: Name of the security module (e.g., "double_ratchet", "hybrid_kex")
            
        Returns:
            True if module is enabled, False otherwise
        """
        return self.get(f"security.{module_name}.enabled", True)
    
    def should_fallback(self, module_name: str) -> bool:
        """
        Check if fallback is allowed when a security module is unavailable.
        
        Args:
            module_name: Name of the security module
            
        Returns:
            True if fallback is allowed, False otherwise
            
        Requirements: 7.3
        """
        fallback_key = f"security.{module_name}.fallback_to_basic"
        if "hybrid_kex" in module_name:
            fallback_key = "security.hybrid_kex.fallback_to_x25519"
        elif "audit" in module_name:
            fallback_key = "security.audit_logging.fallback_to_file"
        
        return bool(self.get(fallback_key, False))
    
    def save(self, path: Optional[str] = None) -> bool:
        """
        Save current configuration to file atomically.
        
        Args:
            path: Optional path to save to (defaults to original path)
            
        Returns:
            True if saved successfully, False otherwise
        """
        save_path = path or self.config_path
        target_dir = os.path.dirname(save_path) if os.path.dirname(save_path) else '.'
        temp_path = None
        
        try:
            # Ensure directory exists
            os.makedirs(target_dir, exist_ok=True)
            
            # Atomic persistence: write to temp file, flush, fsync, and atomic swap via os.replace
            temp_path = f"{save_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            
            os.replace(temp_path, save_path)
            logger.info(f"Configuration saved atomically to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration atomically: {e}")
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            return False
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get the entire configuration dictionary.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config.copy()
    
    def validate(self) -> tuple[bool, list[str]]:
        """
        Validate configuration for required settings.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check for critical settings
        if not self.get("security.level"):
            errors.append("Missing security.level setting")
        
        if not self.get("logging.level"):
            errors.append("Missing logging.level setting")
        
        # Validate security level
        valid_levels = ["LOW", "MEDIUM", "HIGH", "MAXIMUM"]
        security_level = self.get("security.level", "")
        if security_level not in valid_levels:
            errors.append(f"Invalid security.level: {security_level}. Must be one of {valid_levels}")
        
        return (len(errors) == 0, errors)


# Global configuration instance
_config_instance: Optional[ConfigManager] = None


def get_config(config_path: str = "config.json") -> ConfigManager:
    """
    Get or create global configuration instance.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        ConfigManager instance
    """
    global _config_instance
    
    if _config_instance is None:
        _config_instance = ConfigManager(config_path)
    
    return _config_instance


def reload_config(config_path: str = "config.json") -> ConfigManager:
    """
    Reload configuration from file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        New ConfigManager instance
    """
    global _config_instance
    _config_instance = ConfigManager(config_path)
    return _config_instance
