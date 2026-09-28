"""
High-Performance Logging Configuration for Secure P2P
Optimized for speed and minimal I/O operations
"""

import logging
import os
import sys
from typing import Dict, Set
from enum import Enum

class LogLevel(Enum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR" 
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"

class PerformanceLogFilter(logging.Filter):
    """Ultra-fast log filter optimized for performance"""
    
    def __init__(self):
        super().__init__()
        # Use sets for O(1) lookup performance
        self.seen_messages: Set[str] = set()
        self.message_counts: Dict[str, int] = {}
        self.max_repeats = 2  # Reduced from 3 to 2
        
        # Pre-compile patterns for faster matching
        self.suppress_keywords = {
            "Registered secure memory cleanup",
            "Memory locking is available", 
            "Cross-platform secure memory",
            "Secure memory protection enabled",
            "Configuration: pk=",
            "Windows APIs loaded",
            "WindowsCFGHandler initialized",
            "pythoncom module available",
            "Initialized 2 entropy sources",
            "ML-KEM-1024 parameter set validation",
            "Generated 32 bytes",
            "Generated 1024 bytes",
            "Algorithm ML-KEM-1024 APPROVED",
            "Algorithm HQC-256 APPROVED",
            "Algorithm FALCON-1024 APPROVED",
            "Algorithm AES-256-GCM APPROVED",
            "Algorithm ChaCha20-Poly1305 APPROVED",
            "Algorithm SHA-512 APPROVED",
            "Algorithm HKDF-SHA512 APPROVED",
            "Derived 256-bit key",
            "Key separation verified",
            "hardcoded key scan",
            "No hardcoded keys detected",
            "Post-quantum algorithm classes",
            "class will be defined later",
            "Post-quantum algorithm implementations",
            "DEBUG:",
            "libsodium.dll from current directory",
            "Using direct libsodium bindings",
            "SecureProcessIsolation initialized",
            "Created Enhanced",
            "implementation from pqc_algorithms",
            "Using SPHINCS+ fallback",
            "Initialized PQ algorithm instances",
            "DEP Implementation logger",
            "TLS Channel Manager logger",
            "Double Ratchet logger",
            "Constant-time operations available",
            "Hardware security via cphs",
            "Using EnhancedFALCON_1024",
            "Hybrid Key Exchange logger",
            "Successfully imported PQC algorithms",
            "Side-channel protections applied",
            "P2P Core logger initialized",
            "CA Services logger initialized",
        }
        
        # Critical messages that must always show
        self.critical_keywords = {
            "THREAT DETECTED",
            "SECURITY BREACH", 
            "MAXIMUM SECURITY ACHIEVED",
            "[SECURE]",
            "[PASS]",
            "[FAIL]",
            "Security Score:",
            "Public IPv6:",
            "STUN discovered",
            "Exiting...",
            "Choose an option",
        }

    def filter(self, record):
        # Fast path: check critical messages first
        message = record.getMessage()
        
        # Always show critical security messages (fastest check)
        for keyword in self.critical_keywords:
            if keyword in message:
                return True
        
        # Fast suppression check
        for keyword in self.suppress_keywords:
            if keyword in message:
                return False
        
        # Level-based filtering (faster than string operations)
        if record.levelno >= logging.ERROR:
            return True
        elif record.levelno >= logging.WARNING:
            # Only show warnings from security modules
            return any(mod in record.name for mod in ['security', 'threat', 'maximum'])
        elif record.levelno >= logging.INFO:
            # Very selective INFO logging
            return record.name in ['secure_p2p', '__main__', 'p2p_core.stun']
        
        return False  # Suppress all DEBUG by default



def setup_performance_logging():
    """Configure high-performance logging optimized for speed"""
    
    # Root logger configuration - set to WARNING to reduce processing
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)
    
    # Clear existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler with performance filter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.addFilter(PerformanceLogFilter())
    
    # Ultra-minimal console format for speed
    console_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    console_handler.setFormatter(console_formatter)
    
    # Only add console handler - skip file logging during startup for speed
    root_logger.addHandler(console_handler)
    
    # Aggressively suppress noisy loggers
    noisy_loggers = [
        'pqc_algorithms', 'secure_key_manager', 'platform_hsm_interface',
        'hybrid_kex', 'double_ratchet', 'tls_channel_manager', 'dep_implementation',
        'windows_cfg_handler', 'cross_platform_exception_handler', 
        'security_hardening_manager', 'win32_exception_manager', 'libsodium_manager',
        'ca_services', 'threat_detection_engine', 'security_status_monitor',
        'security_recovery_manager', 'maximum_security_hardening'
    ]
    
    for logger_name in noisy_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.ERROR)  # Only errors
        logger.propagate = False  # Don't propagate to root logger
    
    # Keep only essential loggers active
    essential_loggers = ['secure_p2p', '__main__']
    for logger_name in essential_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
    
    return True

def setup_full_logging():
    """Setup complete logging after application startup"""
    
    # Create logs directory only when needed
    os.makedirs("logs", exist_ok=True)
    
    root_logger = logging.getLogger()
    
    # Add file handler for full logs
    file_handler = logging.FileHandler('logs/secure_p2p_full.log')
    file_handler.setLevel(logging.WARNING)  # Only warnings and above to file
    file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    # Security events handler
    security_handler = logging.FileHandler('logs/security_events.log')
    security_handler.setLevel(logging.WARNING)
    security_formatter = logging.Formatter('%(asctime)s [%(levelname)s] [SECURITY] %(message)s')
    security_handler.setFormatter(security_formatter)
    root_logger.addHandler(security_handler)

# Alias for backward compatibility
setup_smart_logging = setup_performance_logging

def get_security_summary_logger():
    """Get a logger specifically for security summaries"""
    logger = logging.getLogger('security_summary')
    logger.setLevel(logging.INFO)
    return logger

if __name__ == "__main__":
    setup_smart_logging()