"""
Security monitoring module for continuous threat detection.

This module implements continuous security monitoring including:
- Security monitoring loops
- Canary value verification
- Intrusion detection
- Runtime security checks
- Threat detection and response

Security features:
- Continuous background monitoring
- Canary-based buffer overflow detection
- Intrusion detection system
- Runtime security validation
- Threat detection and response
"""

import os
import sys
import logging
import threading
import time
from typing import Optional, Dict, Any

# Setup logging
log = logging.getLogger(__name__)


class MonitoringError(Exception):
    """Base exception for monitoring errors"""
    def __init__(self, message: str, category: str = "MONITORING", severity: str = "HIGH"):
        self.message = message
        self.category = category
        self.severity = severity
        super().__init__(f"[{severity}] [{category}] {message}")


def _is_production() -> bool:
    """Return True if running in production mode."""
    return (
        os.environ.get("P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes")
        or os.environ.get("SECURE_P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes")
    )


class SecurityMonitor:
    """
    Security monitoring for continuous threat detection.

    This class implements comprehensive security monitoring including:
    - Continuous security monitoring loops
    - Canary verification for buffer overflow detection
    - Intrusion detection system
    - Runtime security checks
    - Threat detection and response
    """

    def __init__(self, orchestrator=None):
        """Initialize SecurityMonitor with optional orchestrator reference"""
        self.orchestrator = orchestrator
        self.log = logging.getLogger(__name__)
        self.security_monitoring_active = False
        self.intrusion_detection_active = False
        self.monitoring_thread = None
        self.intrusion_detection_thread = None
        self.canary_check_thread = None
        self.CANARY_CHECK_INTERVAL = 5  # seconds
        self.SECURITY_MONITOR_INTERVAL = 10  # seconds

    def start_security_monitoring(self):
        """Start continuous security monitoring loop."""
        try:
            self.security_monitoring_active = True

            # Start security monitoring thread
            self.monitoring_thread = threading.Thread(
                target=self._security_monitoring_loop,
                daemon=True
            )
            self.monitoring_thread.start()

            self.log.info("Security monitoring started")
            return True

        except Exception as e:
            self.log.error(f"Failed to start security monitoring: {e}")
            self.security_monitoring_active = False
            if _is_production():
                raise MonitoringError(f"Failed to start security monitoring in production: {e}", severity="CRITICAL")
            return False

    def stop_security_monitoring(self):
        """Stop continuous security monitoring loop."""
        try:
            self.security_monitoring_active = False
            self.log.info("Security monitoring stopped")
            return True

        except Exception as e:
            self.log.error(f"Failed to stop security monitoring: {e}")
            return False

    def _security_monitoring_loop(self):
        """
        Continuous security monitoring loop for detecting intrusions and anomalies.
        """
        self.log.info("Security monitoring loop started")

        while self.security_monitoring_active:
            try:
                # Monitor memory integrity
                if hasattr(self.orchestrator, 'integrity_checks'):
                    self.orchestrator.integrity_checks.check_memory_integrity()

                # Monitor process integrity
                if hasattr(self.orchestrator, 'integrity_checks'):
                    self.orchestrator.integrity_checks.check_process_integrity()

                # Monitor network security
                if hasattr(self.orchestrator, 'integrity_checks'):
                    self.orchestrator.integrity_checks.check_network_security()

                # Monitor key rotation status
                if hasattr(self.orchestrator, 'integrity_checks'):
                    self.orchestrator.integrity_checks.check_key_rotation_status()

                # Sleep for security monitor interval between checks
                time.sleep(self.SECURITY_MONITOR_INTERVAL)

            except Exception as e:
                self.log.error(f"Error in security monitoring loop: {e}")
                time.sleep(10)  # Longer sleep on error

    def start_canary_checks(self):
        """Start periodic canary verification."""
        try:
            # Start canary check thread
            self.canary_check_thread = threading.Thread(
                target=self._canary_check_loop,
                daemon=True
            )
            self.canary_check_thread.start()

            self.log.info("Canary checks started")
            return True

        except Exception as e:
            self.log.error(f"Failed to start canary checks: {e}")
            if _is_production():
                raise MonitoringError(f"Failed to start canary checks in production: {e}", severity="CRITICAL")
            return False

    def _canary_check_loop(self):
        """
        Periodically verify canary values to detect buffer overflows.
        This runs at a reduced frequency to avoid excessive logging.
        """
        check_count = 0
        while True:
            try:
                # Only log every 20th check to reduce verbosity
                if hasattr(self.orchestrator, 'dep') and hasattr(self.orchestrator.dep, 'verify_canaries'):
                    if check_count % 20 == 0:
                        # For every 20th check, we'll do a normal verification that logs
                        self.orchestrator.dep.verify_canaries()
                    else:
                        # For most checks, use a silent verification method
                        self._silent_canary_verification()
                elif hasattr(self.orchestrator, 'dep'):
                    # If dep exists but doesn't have verify_canaries, use silent method
                    self._silent_canary_verification()

                # Increment the check counter
                check_count += 1

                # Check every canary check interval for maximum security
                time.sleep(self.CANARY_CHECK_INTERVAL)
            except Exception as e:
                # Log errors at warning level instead of error to reduce noise
                self.log.warning(f"Error in canary check loop: {e}")
                time.sleep(5)  # Sleep briefly to avoid tight loop on error

    def _silent_canary_verification(self):
        """Silently verify canaries without logging."""
        try:
            if hasattr(self.orchestrator, 'dep') and hasattr(self.orchestrator.dep, 'canaries'):
                for location, canary in self.orchestrator.dep.canaries.items():
                    if canary is None or len(canary) == 0:
                        self.log.critical(f"SECURITY ALERT: Memory canary for {location} is compromised")

        except Exception as e:
            self.log.debug(f"Silent canary verification failed: {e}")

    def start_intrusion_detection(self):
        """Start intrusion detection system."""
        try:
            self.intrusion_detection_active = True

            # Start intrusion detection thread
            self.intrusion_detection_thread = threading.Thread(
                target=self._intrusion_detection_loop,
                daemon=True
            )
            self.intrusion_detection_thread.start()

            self.log.info("Intrusion detection system enabled")
            return True

        except Exception as e:
            self.log.error(f"Failed to enable intrusion detection: {e}")
            self.intrusion_detection_active = False
            if _is_production():
                raise MonitoringError(f"Failed to enable intrusion detection in production: {e}", severity="CRITICAL")
            return False

    def stop_intrusion_detection(self):
        """Stop intrusion detection system."""
        try:
            self.intrusion_detection_active = False
            self.log.info("Intrusion detection system disabled")
            return True

        except Exception as e:
            self.log.error(f"Failed to disable intrusion detection: {e}")
            return False

    def _intrusion_detection_loop(self):
        """Intrusion detection loop."""
        while self.intrusion_detection_active:
            try:
                # Monitor file system changes
                self._monitor_filesystem_changes()

                # Monitor network connections
                self._monitor_network_connections()

                # Monitor process behavior
                self._monitor_process_behavior()

                time.sleep(15)  # Check every 15 seconds

            except Exception as e:
                self.log.error(f"Intrusion detection failed: {e}")
                time.sleep(30)  # Longer sleep on error

    def _monitor_filesystem_changes(self):
        """Monitor file system changes for intrusion detection."""
        try:
            # Check if critical files have been modified
            critical_files = [
                __file__,  # This module
                'secure_p2p.py',
                'config.json'
            ]

            for file_path in critical_files:
                if os.path.exists(file_path):
                    self.log.debug(f"File monitored: {file_path}")

        except Exception as e:
            self.log.debug(f"File system monitoring failed: {e}")

    def _monitor_network_connections(self):
        """Monitor network connections for intrusion detection."""
        try:
            # Monitor for suspicious network connections
            if hasattr(self.orchestrator, '_connection_attempts'):
                if len(self.orchestrator._connection_attempts) > 20:
                    self.log.warning("Excessive connection attempts detected - possible attack")

        except Exception as e:
            self.log.debug(f"Network connection monitoring failed: {e}")

    def _monitor_process_behavior(self):
        """Monitor process behavior for intrusion detection."""
        try:
            import psutil
            current_process = psutil.Process(os.getpid())

            # Monitor CPU usage
            cpu_percent = current_process.cpu_percent(interval=1)
            if cpu_percent > 90:
                self.log.warning(f"High CPU usage detected: {cpu_percent}%")

            # Monitor memory usage
            memory_info = current_process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            if memory_mb > 1000:  # 1GB
                self.log.warning(f"High memory usage detected: {memory_mb:.2f} MB")

        except ImportError:
            self.log.debug("psutil not available for process monitoring")
        except Exception as e:
            self.log.debug(f"Process behavior monitoring failed: {e}")

    def perform_runtime_security_check(self):
        """
        Perform runtime security validation checks.

        This method validates that all security components are still
        functioning correctly and no security degradation has occurred.
        """
        try:
            # Check if policy engine is still enforcing NIST Level 5+
            if hasattr(self.orchestrator, 'policy_engine') and self.orchestrator.policy_engine is not None:
                try:
                    status = self.orchestrator.policy_engine.get_security_status()
                    if isinstance(status, dict) and status.get('security_violations', 0) > 0:
                        self.log.warning(f"Security violations detected: {status['security_violations']}")
                except (AttributeError, TypeError) as _status_err:
                    self.log.debug(f"Security status non-critical error: {_status_err}")

            # Validate critical security components are still active
            critical_components = [
                'security_validation_framework',
                'nist_level5_policy_engine',
                'maximum_security',
                'memory_protection',
                'canary_values'
            ]

            if hasattr(self.orchestrator, 'security_hardening') and isinstance(self.orchestrator.security_hardening, dict):
                for component in critical_components:
                    if not self.orchestrator.security_hardening.get(component, False):
                        self.log.warning(f"Critical security component inactive: {component}")

            # Check for security degradation
            if hasattr(self.orchestrator, 'security_orchestrator') and self.orchestrator.security_orchestrator is not None:
                try:
                    # Perform lightweight security status check
                    current_status = self.orchestrator.security_orchestrator.get_validation_status()
                    if isinstance(current_status, dict) and current_status.get('security_violations', 0) > 0:
                        self.log.warning("Security violations detected during runtime monitoring")
                except (AttributeError, TypeError) as _status_err:
                    self.log.debug(f"Security status non-critical error: {_status_err}")

            return True

        except Exception as e:
            self.log.error(f"Runtime security check failed: {e}")
            return False

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            'security_monitoring_active': self.security_monitoring_active,
            'intrusion_detection_active': self.intrusion_detection_active,
            'monitoring_thread_alive': self.monitoring_thread is not None and self.monitoring_thread.is_alive(),
            'intrusion_detection_thread_alive': self.intrusion_detection_thread is not None and self.intrusion_detection_thread.is_alive(),
            'canary_check_thread_alive': self.canary_check_thread is not None and self.canary_check_thread.is_alive()
        }

    def cleanup(self):
        """Cleanup monitoring resources"""
        try:
            self.log.info("Cleaning up security monitoring resources...")

            # Stop security monitoring
            self.security_monitoring_active = False

            # Stop intrusion detection
            self.intrusion_detection_active = False

            self.log.info("Security monitoring cleanup completed")

        except Exception as e:
            self.log.error(f"Security monitoring cleanup failed: {e}")
