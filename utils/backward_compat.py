"""
Backward Compatibility Module

This module ensures backward compatibility for:
- Existing UI behavior and menu options
- Existing command-line interface
- Existing error messages
- Existing function signatures

Requirements: 7.1, 7.2, 7.5
"""

import logging
from typing import Any, Callable, Optional
from functools import wraps

logger = logging.getLogger(__name__)


class BackwardCompatibilityManager:
    """
    Manager for maintaining backward compatibility across the system.
    
    This class ensures that:
    1. All existing menu options remain functional (Requirement 7.1)
    2. Existing error messages still work (Requirement 7.2)
    3. Existing command-line interface is preserved (Requirement 7.5)
    """
    
    def __init__(self):
        """Initialize backward compatibility manager."""
        self._legacy_error_messages = {}
        self._legacy_menu_options = {}
        self._legacy_cli_commands = {}
    
    def register_legacy_error_message(self, error_code: str, message: str) -> None:
        """
        Register a legacy error message that should be preserved.
        
        Args:
            error_code: Unique error code
            message: Error message text
            
        Requirements: 7.2
        """
        self._legacy_error_messages[error_code] = message
        logger.debug(f"Registered legacy error message: {error_code}")
    
    def get_legacy_error_message(self, error_code: str) -> Optional[str]:
        """
        Get a legacy error message by code.
        
        Args:
            error_code: Error code to look up
            
        Returns:
            Error message or None if not found
            
        Requirements: 7.2
        """
        return self._legacy_error_messages.get(error_code)
    
    def register_legacy_menu_option(self, option_id: str, handler: Callable) -> None:
        """
        Register a legacy menu option that should be preserved.
        
        Args:
            option_id: Unique menu option identifier
            handler: Function to handle the menu option
            
        Requirements: 7.1
        """
        self._legacy_menu_options[option_id] = handler
        logger.debug(f"Registered legacy menu option: {option_id}")
    
    def get_legacy_menu_handler(self, option_id: str) -> Optional[Callable]:
        """
        Get a legacy menu option handler.
        
        Args:
            option_id: Menu option identifier
            
        Returns:
            Handler function or None if not found
            
        Requirements: 7.1
        """
        return self._legacy_menu_options.get(option_id)
    
    def register_legacy_cli_command(self, command: str, handler: Callable) -> None:
        """
        Register a legacy CLI command that should be preserved.
        
        Args:
            command: Command name
            handler: Function to handle the command
            
        Requirements: 7.5
        """
        self._legacy_cli_commands[command] = handler
        logger.debug(f"Registered legacy CLI command: {command}")
    
    def get_legacy_cli_handler(self, command: str) -> Optional[Callable]:
        """
        Get a legacy CLI command handler.
        
        Args:
            command: Command name
            
        Returns:
            Handler function or None if not found
            
        Requirements: 7.5
        """
        return self._legacy_cli_commands.get(command)
    
    @staticmethod
    def preserve_function_signature(original_func: Callable) -> Callable:
        """
        Decorator to preserve function signature for backward compatibility.
        
        This ensures that existing code calling the function continues to work
        even if the function implementation changes.
        
        Args:
            original_func: Original function to wrap
            
        Returns:
            Wrapped function with preserved signature
            
        Requirements: 7.1, 7.2, 7.5
        """
        @wraps(original_func)
        def wrapper(*args, **kwargs):
            try:
                return original_func(*args, **kwargs)
            except TypeError as e:
                # Log the error but try to handle it gracefully
                logger.warning(f"Function signature mismatch in {original_func.__name__}: {e}")
                logger.warning("Attempting to call with compatible arguments")
                
                # Try calling with fewer arguments if there are too many
                try:
                    # Get function signature
                    import inspect
                    sig = inspect.signature(original_func)
                    param_count = len(sig.parameters)
                    
                    # Call with only the number of parameters the function expects
                    if len(args) > param_count:
                        return original_func(*args[:param_count], **kwargs)
                    else:
                        # Re-raise if we can't fix it
                        raise
                except Exception:
                    # If all else fails, re-raise the original error
                    raise e
        
        return wrapper
    
    @staticmethod
    def ensure_menu_option_exists(menu_options: dict, option_key: str, 
                                   default_handler: Callable) -> dict:
        """
        Ensure a menu option exists for backward compatibility.
        
        If the option doesn't exist in the new menu structure, add it
        with a default handler to maintain backward compatibility.
        
        Args:
            menu_options: Dictionary of menu options
            option_key: Key for the menu option
            default_handler: Default handler if option doesn't exist
            
        Returns:
            Updated menu options dictionary
            
        Requirements: 7.1
        """
        if option_key not in menu_options:
            logger.info(f"Adding legacy menu option for backward compatibility: {option_key}")
            menu_options[option_key] = default_handler
        
        return menu_options
    
    @staticmethod
    def wrap_error_message(new_message: str, legacy_code: Optional[str] = None) -> str:
        """
        Wrap a new error message to include legacy error code if needed.
        
        This ensures that existing error handling code that looks for specific
        error messages continues to work.
        
        Args:
            new_message: New error message
            legacy_code: Optional legacy error code to include
            
        Returns:
            Wrapped error message
            
        Requirements: 7.2
        """
        if legacy_code:
            return f"{new_message} [Legacy Code: {legacy_code}]"
        return new_message
    
    @staticmethod
    def translate_legacy_config_key(legacy_key: str) -> str:
        """
        Translate legacy configuration keys to new format.
        
        This allows old configuration files to work with new code.
        
        Args:
            legacy_key: Legacy configuration key
            
        Returns:
            New configuration key
            
        Requirements: 7.4
        """
        # Map of legacy keys to new keys
        key_mapping = {
            'security_level': 'security.level',
            'key_lifetime': 'security.key_management.key_rotation_seconds',
            'enable_hsm': 'security.hardware_security.enabled',
            'audit_logging': 'logging.audit_trail',
            'log_level': 'logging.level',
            'listen_address': 'networking.listen_address',
            'listen_port': 'networking.listen_port',
        }
        
        return key_mapping.get(legacy_key, legacy_key)


# Global backward compatibility manager instance
_compat_manager: Optional[BackwardCompatibilityManager] = None


def get_compat_manager() -> BackwardCompatibilityManager:
    """
    Get or create global backward compatibility manager instance.
    
    Returns:
        BackwardCompatibilityManager instance
    """
    global _compat_manager
    
    if _compat_manager is None:
        _compat_manager = BackwardCompatibilityManager()
    
    return _compat_manager


def register_legacy_components():
    """
    Register all legacy components for backward compatibility.
    
    This function should be called during system initialization to ensure
    all legacy error messages, menu options, and CLI commands are registered.
    
    Requirements: 7.1, 7.2, 7.5
    """
    manager = get_compat_manager()
    
    # Register legacy error messages (Requirement 7.2)
    manager.register_legacy_error_message(
        "CONNECTION_REFUSED",
        "Connection refused - peer not listening"
    )
    manager.register_legacy_error_message(
        "HANDSHAKE_FAILED",
        "Handshake failed - could not establish secure connection"
    )
    manager.register_legacy_error_message(
        "ENCRYPTION_FAILED",
        "Message encryption failed"
    )
    manager.register_legacy_error_message(
        "DECRYPTION_FAILED",
        "Message decryption failed"
    )
    manager.register_legacy_error_message(
        "INVALID_ADDRESS",
        "Invalid IP address or hostname"
    )
    manager.register_legacy_error_message(
        "PEER_NOT_FOUND",
        "Peer not found in stored connections"
    )
    
    logger.info("Legacy components registered for backward compatibility")


# Initialize legacy components on module import
register_legacy_components()
