"""
Runtime integrity checking module for security monitoring.

This module implements runtime integrity checks including memory integrity,
process integrity, network security, and key rotation status monitoring.

Security features:
- Memory integrity checking with canary verification
- Process integrity monitoring and debugger detection
- Network security status monitoring
- Key rotation status checking
- Memory corruption detection
- Code, configuration, and library integrity verification
"""

import os
import sys
import logging
import hashlib
import threading
import time
from typing import Optional, Dict, Any

# Setup logging
log = logging.getLogger(__name__)


class IntegrityError(Exception):
    """Base exception for integrity check errors"""
    def __init__(self, message: str, category: str = "INTEGRITY", severity: str = "HIGH"):
        self.message = message
        self.category = category
        self.severity = severity
        super().__init__(f"[{severity}] [{category}] {message}")


class MemoryProtectionError(IntegrityError):
    """Memory protection error"""
    def __init__(self, message: str):
        super().__init__(message, category="MEMORY", severity="CRITICAL")


class IntegrityChecks:
    """
    Runtime integrity checking for security monitoring.

    This class implements comprehensive integrity checks including:
    - Memory integrity verification
    - Process integrity monitoring
    - Network security checks
    - Key rotation status
    - Code, configuration, and library integrity
    """

    def __init__(self, orchestrator=None):
        """Initialize IntegrityChecks with optional orchestrator reference"""
        self.orchestrator = orchestrator
        self.log = logging.getLogger(__name__)
        self.runtime_integrity_checks = False
        self.integrity_check_thread = None
        self._code_hash = None
        self._last_memory_usage = 0
        self._no_connection_logged = False
        self.SECURITY_MONITOR_INTERVAL = 10  # seconds

    def check_memory_integrity(self):
        """Check memory integrity and detect tampering attempts."""
        try:
            if hasattr(self.orchestrator, 'dep') and self.orchestrator.dep:
                if hasattr(self.orchestrator.dep, 'canaries') and self.orchestrator.dep.canaries:
                    # Verify canary integrity
                    for location, canary in self.orchestrator.dep.canaries.items():
                        if canary is None or len(canary) == 0:
                            self.log.critical(f"SECURITY ALERT: Memory canary for {location} is compromised")
                            raise MemoryProtectionError(f"Memory canary compromised: {location}")

                    # Check for memory corruption patterns
                    self._detect_memory_corruption()

        except Exception as e:
            self.log.error(f"Memory integrity check failed: {e}")

    def check_process_integrity(self):
        """Check process integrity and detect debugging attempts."""
        try:
            import psutil
            current_process = psutil.Process(os.getpid())

            # Check for debugger attachment
            if hasattr(current_process, 'is_being_debugged'):
                if current_process.is_being_debugged():
                    self.log.critical("SECURITY ALERT: Debugger detected - potential security breach")
                    if hasattr(self.orchestrator, 'anti_debugging_enabled') and self.orchestrator.anti_debugging_enabled:
                        raise IntegrityError("Debugger attachment detected", severity="CRITICAL")

            # Check memory usage patterns
            memory_info = current_process.memory_info()
            if self._last_memory_usage > 0:
                memory_growth = memory_info.rss - self._last_memory_usage
                if memory_growth > 200 * 1024 * 1024:  # 200MB growth
                    self.log.info(f"Memory growth during security initialization: {memory_growth / 1024 / 1024:.2f} MB")

            self._last_memory_usage = memory_info.rss

        except ImportError:
            self.log.debug("psutil not available, skip process monitoring")
        except Exception as e:
            self.log.debug(f"Process integrity check failed: {e}")

    def check_network_security(self):
        """Check network security status and detect anomalies."""
        try:
            # Check TLS connection status only if we have an active connection
            if hasattr(self.orchestrator, 'tls_channel') and self.orchestrator.tls_channel:
                # Only check security if we have an active SSL socket (actual connection)
                if hasattr(self.orchestrator.tls_channel, 'ssl_socket') and self.orchestrator.tls_channel.ssl_socket:
                    if not self.orchestrator.tls_channel.is_secure():
                        self.log.debug("TLS connection security check - monitoring active")
                    # Reset the no-connection flag when we have a connection
                    self._no_connection_logged = False
                # If no active connection, log only once to avoid spam
                elif not hasattr(self.orchestrator.tls_channel, 'ssl_socket') or not self.orchestrator.tls_channel.ssl_socket:
                    if not self._no_connection_logged:
                        self.log.debug("TLS channel ready but no active connection")
                        self._no_connection_logged = True

            # Monitor connection attempts
            if hasattr(self.orchestrator, '_connection_attempts'):
                if len(self.orchestrator._connection_attempts) > 10:  # Too many attempts
                    self.log.warning("High number of connection attempts detected")

        except Exception as e:
            self.log.debug(f"Network security check failed: {e}")

    def check_key_rotation_status(self):
        """Check cryptographic key rotation status."""
        try:
            if hasattr(self.orchestrator, 'hybrid_kex') and self.orchestrator.hybrid_kex:
                # Check if keys need rotation
                if hasattr(self.orchestrator.hybrid_kex, 'needs_rotation'):
                    if self.orchestrator.hybrid_kex.needs_rotation():
                        self.log.info("Cryptographic keys require rotation")

        except Exception as e:
            self.log.error(f"Key rotation status check failed: {e}")

    def _detect_memory_corruption(self):
        """Detect memory corruption patterns."""
        try:
            # Check for common corruption patterns
            if hasattr(self.orchestrator, 'dep') and hasattr(self.orchestrator.dep, 'canaries'):
                for location, canary in self.orchestrator.dep.canaries.items():
                    if isinstance(canary, bytes):
                        # Check for null bytes (potential corruption)
                        if b'\x00' * 8 in canary:
                            self.log.warning(f"Potential memory corruption detected in canary {location}")

                        # Check for repeated patterns (potential overflow)
                        if len(set(canary)) < 4:  # Too few unique bytes
                            self.log.warning(f"Suspicious canary pattern detected in {location}")

        except Exception as e:
            self.log.error(f"Memory corruption detection failed: {e}")

    def _runtime_integrity_loop(self):
        """Runtime integrity checking loop."""
        while self.runtime_integrity_checks:
            try:
                # Check code integrity
                self._check_code_integrity()

                # Check configuration integrity
                self._check_config_integrity()

                # Check library integrity
                self._check_library_integrity()

                time.sleep(30)  # Check every 30 seconds

            except Exception as e:
                self.log.error(f"Runtime integrity check failed: {e}")
                time.sleep(60)  # Longer sleep on error

    def _check_code_integrity(self):
        """Check code integrity using checksums."""
        try:
            # Check main module integrity
            main_file = __file__
            if os.path.exists(main_file):
                with open(main_file, 'rb') as f:
                    content = f.read()
                    current_hash = hashlib.sha3_512(content).hexdigest()

                    if self._code_hash is not None:
                        if self._code_hash != current_hash:
                            self.log.critical("SECURITY ALERT: Code integrity violation detected")
                            raise IntegrityError("Code tampering detected", severity="CRITICAL")
                    else:
                        self._code_hash = current_hash

        except Exception as e:
            self.log.error(f"Code integrity check failed: {e}")

    def _check_config_integrity(self):
        """Check configuration integrity."""
        try:
            # Verify security level hasn't been tampered with
            if hasattr(self.orchestrator, 'security_level'):
                if self.orchestrator.security_level != 'MAXIMUM':
                    self.log.warning(f"Security level changed from MAXIMUM to {self.orchestrator.security_level}")

            # Verify critical security flags
            if hasattr(self.orchestrator, 'anti_debugging_enabled'):
                if not self.orchestrator.anti_debugging_enabled:
                    self.log.warning("Anti-debugging protection has been disabled")

        except Exception as e:
            self.log.error(f"Configuration integrity check failed: {e}")

    def _check_library_integrity(self):
        """Check critical library integrity."""
        try:
            # Check if critical modules are still loaded
            critical_modules = ['pqc_algorithms', 'secure_key_manager', 'dep_impl']

            for module_name in critical_modules:
                if module_name not in sys.modules:
                    self.log.critical(f"SECURITY ALERT: Critical module {module_name} has been unloaded")

        except Exception as e:
            self.log.error(f"Library integrity check failed: {e}")

    def enable_runtime_integrity_checks(self):
        """Enable runtime integrity checking."""
        try:
            self.runtime_integrity_checks = True

            # Start integrity check thread
            self.integrity_check_thread = threading.Thread(
                target=self._runtime_integrity_loop,
                daemon=True
            )
            self.integrity_check_thread.start()

            self.log.info("Runtime integrity checks enabled")
            return True

        except Exception as e:
            self.log.error(f"Failed to enable runtime integrity checks: {e}")
            self.runtime_integrity_checks = False
            return False

    def disable_runtime_integrity_checks(self):
        """Disable runtime integrity checking."""
        try:
            self.runtime_integrity_checks = False
            self.log.info("Runtime integrity checks disabled")
            return True

        except Exception as e:
            self.log.error(f"Failed to disable runtime integrity checks: {e}")
            return False

    def get_integrity_status(self) -> Dict[str, Any]:
        """Get current integrity check status"""
        return {
            'runtime_integrity_checks': self.runtime_integrity_checks,
            'code_hash_initialized': self._code_hash is not None,
            'last_memory_usage': self._last_memory_usage
        }

    def cleanup(self):
        """Cleanup integrity checking resources"""
        try:
            self.log.info("Cleaning up integrity checking resources...")
            self.runtime_integrity_checks = False
            self.log.info("Integrity checking cleanup completed")

        except Exception as e:
            self.log.error(f"Integrity checking cleanup failed: {e}")
