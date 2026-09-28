"""
Security Degradation Enforcement Module

Under military fail-closed policy:
- Detection of missing or degraded security modules is strictly fail-closed.
- Fallback to basic encryption or unauthenticated channels is permanently PROHIBITED.
- Any degradation attempts trigger immediate SecurityViolation and process termination.
"""

import logging
import os
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _is_production() -> bool:
    """Return True if running in production mode."""
    return (
        os.environ.get("P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes")
        or os.environ.get("SECURE_P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes")
    )


class SecurityDegradationManager:
    """
    Manager for graceful security degradation.
    
    This class handles scenarios where secure security modules
    are unavailable and provides fallback implementations.
    
    Requirements: 7.3
    """
    
    def __init__(self):
        """Initialize security degradation manager."""
        self.degradation_warnings_logged = set()
        self.fallback_mode = False
        self.available_modules = self._check_module_availability()
        self.security_level = self._determine_security_level()
    
    def _check_module_availability(self) -> Dict[str, bool]:
        """
        Check availability of all security modules.
        
        Returns:
            Dictionary mapping module names to availability status
        """
        modules = {}
        
        # Check DoubleRatchet
        try:
            import double_ratchet
            modules['double_ratchet'] = True
        except ImportError:
            modules['double_ratchet'] = False
        
        # Check HybridKeyExchange
        try:
            import hybrid_kex
            modules['hybrid_kex'] = True
        except ImportError:
            modules['hybrid_kex'] = False
        
        # Check MilitaryGradeCrypto
        try:
            import military_grade_crypto
            modules['military_crypto'] = True
        except ImportError:
            modules['military_crypto'] = False
        
        # Check AuditLogger
        try:
            import audit_logging_system
            modules['audit_logging'] = True
        except ImportError:
            modules['audit_logging'] = False
        
        # Check SecurityErrorHandler
        try:
            from secure_p2p_core.utils.error_handler import SecurityErrorHandler
            modules['error_handler'] = True
        except ImportError:
            modules['error_handler'] = False
        
        return modules
    
    def _determine_security_level(self) -> str:
        """
        Determine effective security level based on available modules.
        
        Returns:
            Security level string: "MAXIMUM", "HIGH", "MEDIUM", or "BASIC"
        """
        if all([
            self.available_modules.get('double_ratchet', False),
            self.available_modules.get('hybrid_kex', False),
            self.available_modules.get('military_crypto', False)
        ]):
            return "MAXIMUM"
        elif self.available_modules.get('double_ratchet', False) or \
             self.available_modules.get('hybrid_kex', False):
            return "HIGH"
        elif self.available_modules.get('military_crypto', False):
            return "MEDIUM"
        else:
            return "BASIC"
    
    def is_module_available(self, module_name: str) -> bool:
        """
        Check if a specific security module is available.
        
        Args:
            module_name: Name of the module to check
            
        Returns:
            True if module is available, False otherwise
        """
        return self.available_modules.get(module_name, False)
    
    def log_degradation_warning(self, module_name: str, fallback_description: str) -> None:
        """
        Log a warning about security degradation.
        
        Only logs each warning once to avoid spam.
        
        Args:
            module_name: Name of the unavailable module
            fallback_description: Description of the fallback being used
            
        Requirements: 7.3
        """
        warning_key = f"{module_name}:{fallback_description}"
        
        if warning_key not in self.degradation_warnings_logged:
            logger.warning(f"[WARNING]  SECURITY DEGRADATION: {module_name} unavailable")
            logger.warning(f"   Fallback: {fallback_description}")
            logger.warning(f"   Security Level: {self.security_level}")
            
            self.degradation_warnings_logged.add(warning_key)
            self.fallback_mode = True
    
    def get_encryption_fallback(self) -> Tuple[Optional[Any], str]:
        """
        Get fallback encryption implementation when DoubleRatchet is unavailable.
        
        Returns:
            Tuple of (encryption_module, description)
            
        Requirements: 7.3
        """
        if not self.is_module_available('double_ratchet'):
            logger.critical("FATAL: DoubleRatchet unavailable. Military fail-closed policy strictly prohibits degraded non-forward-secret fallback.")
            raise RuntimeError("DoubleRatchet is strictly required for military forward secrecy. Fallbacks prohibited.")
        return None, "DoubleRatchet (no fallback needed)"
    
    def get_key_exchange_fallback(self) -> Tuple[Optional[Any], str]:
        """
        Get fallback key exchange implementation when HybridKeyExchange is unavailable.
        
        Returns:
            Tuple of (key_exchange_module, description)
            
        Requirements: 7.3
        """
        if not self.is_module_available('hybrid_kex'):
            logger.critical("FATAL: HybridKeyExchange unavailable. Military fail-closed policy strictly prohibits classical-only fallback.")
            raise RuntimeError("HybridKeyExchange is strictly required for post-quantum defense. Classical-only fallbacks prohibited.")
        return None, "HybridKeyExchange (no fallback needed)"
    
    def get_audit_logging_fallback(self) -> Tuple[Optional[Any], str]:
        """
        Get fallback audit logging implementation when AuditLogger is unavailable.
        
        Returns:
            Tuple of (logging_module, description)
            
        Requirements: 7.3
        """
        if self.is_module_available('audit_logging'):
            return None, "AuditLogger (no fallback needed)"
        
        if _is_production():
            logger.critical("FATAL: AuditLogger unavailable in production mode. Tamper-evident Merkle-chained logging is strictly mandatory.")
            raise RuntimeError("AuditLogger is strictly required in production mode. Fallback to standard logging is prohibited.")

        # Log degradation warning
        self.log_degradation_warning(
            "AuditLogger",
            "Standard file logging (no tamper-evident properties)"
        )
        
        # Use standard Python logging as fallback
        return logging, "Standard Python logging"
    
    def get_security_status_report(self) -> Dict[str, Any]:
        """
        Get comprehensive security status report.
        
        Returns:
            Dictionary with security status information
        """
        return {
            'security_level': self.security_level,
            'fallback_mode': self.fallback_mode,
            'available_modules': self.available_modules.copy(),
            'degraded_features': list(self.degradation_warnings_logged),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def display_security_status(self) -> None:
        """
        Display security status to user.
        
        Shows current security level and any degradations.
        
        Requirements: 7.3
        """
        print("\n" + "="*70)
        print("SECURITY STATUS")
        print("="*70)
        print(f"Security Level: {self.security_level}")
        print(f"Fallback Mode: {'ACTIVE' if self.fallback_mode else 'INACTIVE'}")
        print()
        print("Module Availability:")
        
        for module, available in self.available_modules.items():
            status = " Available" if available else "[FAIL] Unavailable"
            print(f"  * {module}: {status}")
        
        if self.fallback_mode:
            print()
            print("[WARNING]  SECURITY WARNINGS:")
            print(f"  * System is operating in degraded security mode")
            print(f"  * {len(self.degradation_warnings_logged)} security feature(s) using fallback")
            print(f"  * Review logs for detailed degradation information")
        
        print("="*70 + "\n")
    
    def can_proceed_with_connection(self) -> Tuple[bool, str]:
        """
        Determine if connection can proceed under military security policy.
        
        Returns:
            Tuple of (can_connect, reason)
        """
        if self.security_level == "BASIC":
            return False, "Refusing connection: BASIC security level violates military fail-closed policy (no degradation permitted)."
        
        if not self.is_module_available('double_ratchet'):
            return False, "DoubleRatchet forward secrecy unavailable"
        
        if not self.is_module_available('hybrid_kex'):
            return False, "HybridKeyExchange post-quantum protection unavailable"
        
        return True, f"Security level: {self.security_level}"
    
    can_establish_secure_connection = can_proceed_with_connection
    
    def get_fallback_encryption_handler(self):
        """
        Get a fallback encryption handler when DoubleRatchet is unavailable.
        
        Returns:
            Raises RuntimeError under military policy.
            
        Requirements: 7.3
        """
        logger.critical("Security violation: attempt to use BasicEncryptionHandler without forward secrecy.")
        raise RuntimeError("Fallback to basic encryption without forward secrecy is strictly prohibited under military fail-closed policy.")


class BasicEncryptionHandler:
    """
    Basic encryption handler for fallback when DoubleRatchet is unavailable.
    
    This provides basic ChaCha20-Poly1305 AEAD encryption without forward secrecy.
    
    Requirements: 7.3
    """
    
    def __init__(self, cipher_class=None):
        """
        Initialize basic encryption handler - forbidden under military policy.
        """
        logger.critical("CRITICAL: BasicEncryptionHandler without forward secrecy is forbidden in production.")
        raise RuntimeError("BasicEncryptionHandler is strictly prohibited under military fail-closed policy.")
    
    def initialize(self, key: bytes) -> None:
        raise RuntimeError("BasicEncryptionHandler is strictly prohibited under military fail-closed policy.")
    
    def encrypt(self, plaintext: bytes) -> bytes:
        raise RuntimeError("BasicEncryptionHandler is strictly prohibited under military fail-closed policy.")
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        raise RuntimeError("BasicEncryptionHandler is strictly prohibited under military fail-closed policy.")


# Global security degradation manager instance
_degradation_manager: Optional[SecurityDegradationManager] = None


def get_degradation_manager() -> SecurityDegradationManager:
    """
    Get or create global security degradation manager instance.
    
    Returns:
        SecurityDegradationManager instance
    """
    global _degradation_manager
    
    if _degradation_manager is None:
        _degradation_manager = SecurityDegradationManager()
    
    return _degradation_manager


def check_security_requirements() -> Tuple[bool, str]:
    """
    Check if minimum security requirements are met.
    
    Returns:
        Tuple of (requirements_met, message)
    """
    manager = get_degradation_manager()
    return manager.can_establish_secure_connection()


def display_security_warnings() -> None:
    """
    Display security warnings if system is in degraded mode.
    
    Requirements: 7.3
    """
    manager = get_degradation_manager()
    
    if manager.fallback_mode:
        manager.display_security_status()
