"""
Balanced Logging Configuration for Secure P2P
Shows critical, warning, and minor security issues while maintaining performance
"""

import logging
import sys
import os
from typing import Set

class SecurityAwareFilter(logging.Filter):
    """Filter that shows security-relevant messages at all levels"""
    
    def __init__(self):
        super().__init__()
        
        # Critical security keywords - always show
        self.critical_keywords = {
            "THREAT DETECTED", "SECURITY BREACH", "MAXIMUM SECURITY ACHIEVED",
            "[SECURE]", "[PASS]", "[FAIL]", "Security Score:", "CRITICAL",
            "EMERGENCY", "ATTACK", "BREACH", "COMPROMISE", "VIOLATION"
        }
        
        # Warning keywords - show warnings and above
        self.warning_keywords = {
            "WARNING", "WARN", "Administrator privileges", "CFG", "DEP",
            "Hardware security", "TPM", "HSM", "Memory protection",
            "Process monitoring", "Exception handling", "Recovery failed",
            "Automatic recovery", "Health check failed", "Threat details",
            "VirtualUnlock failed", "Registry configuration failed"
        }
        
        # Minor issue keywords - show info level for these
        self.minor_issue_keywords = {
            "fallback", "unavailable", "limited", "basic mode", "software only",
            "non-admin", "missing dependency", "alternative", "degraded",
            "reduced functionality", "compatibility mode", "workaround"
        }
        
        # Security status keywords - show important status updates
        self.status_keywords = {
            "initialized successfully", "enabled successfully", "protection enabled",
            "security active", "monitoring started", "validation successful",
            "compliance verified", "algorithms validated", "keys generated",
            "Public IPv6:", "Public IPv4:", "STUN discovered", "Choose an option"
        }
        
        # Suppress these noisy patterns completely
        self.suppress_patterns = {
            "Generated 32 bytes", "Generated 1024 bytes", "Configuration: pk=",
            "Cross-platform secure memory", "Memory locking is available",
            "pythoncom module available", "Windows APIs loaded",
            "Initialized 2 entropy sources", "Derived 256-bit key",
            "Key separation verified", "libsodium.dll from current directory",
            "Using direct libsodium bindings", "SecureProcessIsolation initialized",
            "Created Enhanced", "implementation from pqc_algorithms",
            "Using SPHINCS+ fallback", "Initialized PQ algorithm instances",
            "DEP Implementation logger", "TLS Channel Manager logger",
            "Double Ratchet logger", "Constant-time operations available",
            "Hardware security via cphs", "Using EnhancedFALCON_1024",
            "Hybrid Key Exchange logger", "Successfully imported PQC algorithms",
            "Side-channel protections applied", "P2P Core logger initialized",
            "CA Services logger initialized", "Secure P2P logger initialized"
        }

    def filter(self, record):
        message = record.getMessage()
        
        # Always suppress noisy patterns
        for pattern in self.suppress_patterns:
            if pattern in message:
                return False
        
        # Always show critical security messages
        for keyword in self.critical_keywords:
            if keyword in message:
                return True
        
        # Show warnings and above for warning keywords
        if record.levelno >= logging.WARNING:
            for keyword in self.warning_keywords:
                if keyword in message:
                    return True
        
        # Show info level for minor issues
        if record.levelno >= logging.INFO:
            for keyword in self.minor_issue_keywords:
                if keyword in message:
                    return True
        
        # Show important status updates
        if record.levelno >= logging.INFO:
            for keyword in self.status_keywords:
                if keyword in message:
                    return True
        
        # Show all ERROR and above
        if record.levelno >= logging.ERROR:
            return True
        
        # Show WARNING from security-related modules
        if record.levelno >= logging.WARNING:
            security_modules = ['security', 'threat', 'maximum', 'hardening', 'dep']
            if any(mod in record.name.lower() for mod in security_modules):
                return True
        
        # Show INFO from main application modules only
        if record.levelno >= logging.INFO:
            main_modules = ['secure_p2p', '__main__', 'p2p_core.stun']
            if record.name in main_modules:
                return True
        
        return False

def enable_balanced_startup():
    """Enable balanced logging during startup - shows security issues but suppresses noise"""
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Remove ALL existing handlers from root logger
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        try:
            handler.close()
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    
    # Add console handler with security filter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.addFilter(SecurityAwareFilter())
    console_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
    
    root_logger.addHandler(console_handler)
    
    # Prevent duplicate logging by removing handlers from child loggers
    # and ensuring they propagate to root only
    all_loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
    for logger in all_loggers:
        # Remove any handlers that might cause duplicates
        for handler in logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler):
                logger.removeHandler(handler)
                try:
                    handler.close()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
        # Ensure propagation to root logger
        logger.propagate = True
    
    # Configure loggers to appropriate levels
    noisy_loggers = [
        'pqc_algorithms', 'secure_key_manager', 'platform_hsm_interface',
        'hybrid_kex', 'double_ratchet', 'tls_channel_manager', 'dep_implementation',
        'windows_cfg_handler', 'libsodium_manager', 'ca_services'
    ]
    
    for logger_name in noisy_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.WARNING)
        logger.propagate = True
    
    # Security loggers at INFO level to catch minor issues
    security_loggers = [
        'security_hardening_manager', 'threat_detection_engine', 
        'maximum_security_hardening', 'security_status_monitor',
        'security_recovery_manager'
    ]
    
    for logger_name in security_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = True
    
    # Main application loggers
    main_loggers = ['secure_p2p', '__main__', 'p2p_core']
    for logger_name in main_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = True
    
    return True

def enable_startup_logging():
    """Enable startup logging with security awareness"""
    
    # Restore stdout if it was redirected
    if hasattr(sys.stdout, 'name') and sys.stdout.name == os.devnull:
        sys.stdout = sys.__stdout__
    
    # Print startup message
    print("\n[SECURE P2P] QUANTUM-RESISTANT COMMUNICATIONS")
    print("Initializing military-grade security...")
    
    # Enable balanced logging (simplified to avoid hangs)
    try:
        enable_balanced_startup()
    except Exception as e:
        print(f"Warning: Balanced logging setup failed: {e}")
        # Continue without balanced logging

def enable_full_logging():
    """Enable full logging after security initialization"""
    
    print("[INIT] Security initialization complete - monitoring active")
    
    # Create logs directory
    os.makedirs("logs", exist_ok=True)
    
    # Add file handler for complete logs
    root_logger = logging.getLogger()
    
    # Check if file handler already exists
    has_file_handler = any(isinstance(h, logging.FileHandler) for h in root_logger.handlers)
    
    if not has_file_handler:
        file_handler = logging.FileHandler('logs/secure_p2p_full.log')
        file_handler.setLevel(logging.WARNING)
        file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    # Security events file
    security_handler = logging.FileHandler('logs/security_events.log')
    security_handler.setLevel(logging.WARNING)
    security_formatter = logging.Formatter('%(asctime)s [%(levelname)s] [SECURITY] %(message)s')
    security_handler.setFormatter(security_formatter)
    root_logger.addHandler(security_handler)

def cleanup_duplicate_handlers():
    """Remove duplicate StreamHandlers from all loggers to prevent duplicate output.
    
    Call this after all modules are imported to clean up any handlers they added.
    """
    root_logger = logging.getLogger()
    
    # Keep only one StreamHandler on root logger
    stream_handlers = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)]
    if len(stream_handlers) > 1:
        # Keep the first one, remove the rest
        for handler in stream_handlers[1:]:
            root_logger.removeHandler(handler)
            try:
                handler.close()
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
    
    # Remove all StreamHandlers from child loggers (they should propagate to root)
    for name in logging.root.manager.loggerDict:
        logger = logging.getLogger(name)
        for handler in logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                logger.removeHandler(handler)
                try:
                    handler.close()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
        # Ensure propagation
        logger.propagate = True

if __name__ == "__main__":
    enable_balanced_startup()