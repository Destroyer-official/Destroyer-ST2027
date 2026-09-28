"""
Security hardening module for secure protection.

This module implements security hardening operations including anti-debugging,
maximum security enforcement, and security manager initialization.

Security features:
- Anti-debugging protection with ptrace detection
- Maximum security enforcement with no fallbacks
- Security hardening manager initialization
- Process monitoring and exception handling
- Self-healing and monitoring capabilities
"""

import os
import sys
import logging
import threading
from typing import Optional, Dict, Any

# Setup logging
log = logging.getLogger(__name__)


class SecurityError(Exception):
    """Base exception for security errors"""
    SEVERITY_LOW = "LOW"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_CRITICAL = "CRITICAL"

    def __init__(self, message: str, severity: str = "HIGH", mitigation_required: bool = False):
        self.message = message
        self.severity = severity
        self.mitigation_required = mitigation_required
        super().__init__(f"[{severity}] {message}")


def _is_production() -> bool:
    """Return True if running in production mode."""
    return (
        os.environ.get("P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes")
        or os.environ.get("SECURE_P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes")
    )


class SecurityHardening:
    """
    Security hardening operations for secure protection.

    This class implements security hardening features including:
    - Anti-debugging protection
    - Maximum security enforcement
    - Security manager initialization
    - Process monitoring
    """

    def __init__(self, orchestrator=None):
        """Initialize SecurityHardening with optional orchestrator reference"""
        self.orchestrator = orchestrator
        self.log = logging.getLogger(__name__)
        self.security_hardening_manager = None
        self.process_monitor = None
        self.win32_exception_manager = None
        self.anti_debugging_enabled = False
        self.maximum_security = False
        self.security_hardening = {}

    def initialize_security_hardening_manager(self):
        """Initialize the SecurityHardeningManager for coordinated security management."""
        try:
            from security_hardening_manager import SecurityHardeningManager
            from process_monitor_manager import ProcessMonitorManager, MonitoringConfig
            from cross_platform_exception_handler import CrossPlatformExceptionHandler, ExceptionHandlingConfig

            # Initialize the security hardening manager
            self.security_hardening_manager = SecurityHardeningManager()

            # Initialize process monitoring with robust ProcessMonitorManager
            self.log.info("Initializing robust process monitoring...")
            monitoring_config = MonitoringConfig(
                check_interval=5.0,
                recovery_attempts=3,
                enable_automatic_recovery=True,
                enable_integrity_checking=True,
                log_level="INFO"
            )

            self.process_monitor = ProcessMonitorManager(
                config=monitoring_config,
                logger=self.log,
                enable_threat_detection=True
            )

            # Start process monitoring
            if self.process_monitor.start_monitoring():
                self.log.debug("Process monitoring started successfully")
                # Add current process to monitoring
                import os
                current_pid = os.getpid()
                if self.process_monitor.add_process(current_pid):
                    self.log.info(f"Added current process {current_pid} to monitoring")
            else:
                self.log.warning("Failed to start process monitoring")

            # Initialize Win32 exception handling
            self.log.info("Initializing Win32 exception handling...")
            exception_config = ExceptionHandlingConfig(
                suppress_com_exceptions=True,
                suppress_iunknown_exceptions=True,
                log_suppressed_exceptions=True,
                enable_com_cleanup=True,
                auto_garbage_collection=True,
                thread_safe_operations=True
            )

            self.win32_exception_manager = CrossPlatformExceptionHandler(exception_config)

            # Configure Win32 exception handling
            if self.win32_exception_manager.configure_exception_handling():
                self.log.info("Win32 exception handling configured successfully")
            else:
                self.log.warning("Win32 exception handling configuration failed")

            # Enable all security protections
            results = self.security_hardening_manager.enable_all_protections()

            # Log results
            for protection, (success, message) in results.items():
                if success:
                    self.log.info(f"Security protection enabled: {protection} - {message}")
                else:
                    self.log.warning(f"Security protection failed: {protection} - {message}")

            # Get comprehensive security status
            security_status = self.security_hardening_manager.get_security_status()
            self.log.info(f"Security hardening manager status: {security_status.security_level}")

            # Enable self-healing and monitoring
            self.security_hardening_manager.enable_self_healing(True)
            self.security_hardening_manager.enable_monitoring(True)

            # Update security hardening status to reflect new components
            self.security_hardening['process_monitoring'] = True
            self.security_hardening['win32_exception_handling'] = True
            self.security_hardening['security_hardening_manager'] = True

            self.log.debug("Enhanced security hardening initialization completed successfully")
            return True

        except ImportError as e:
            self.log.error(f"Security hardening components not available: {e}")
            if _is_production():
                raise SecurityError(
                    f"Security hardening components not available in production: {e}",
                    severity=SecurityError.SEVERITY_CRITICAL,
                    mitigation_required=True
                )
            # Initialize fallback components
            return self._initialize_fallback_security_components()
        except Exception as e:
            self.log.error(f"Security hardening initialization failed: {e}")
            if _is_production():
                raise SecurityError(
                    f"Security hardening initialization failed in production: {e}",
                    severity=SecurityError.SEVERITY_CRITICAL,
                    mitigation_required=True
                )
            # Initialize fallback components
            return self._initialize_fallback_security_components()

    def _initialize_fallback_security_components(self):
        """Initialize fallback security components when enhanced components are not available."""
        if _is_production():
            raise SecurityError(
                "Fallback security components strictly prohibited in production mode",
                severity=SecurityError.SEVERITY_CRITICAL,
                mitigation_required=True
            )
        try:
            self.log.warning("Initializing fallback security components...")

            # Initialize basic process monitoring fallback
            self.process_monitor = None
            self.win32_exception_manager = None

            # Try to initialize basic SecurityHardeningManager if available
            try:
                from security_hardening_manager import SecurityHardeningManager
                self.security_hardening_manager = SecurityHardeningManager()
                self.log.info("Basic SecurityHardeningManager initialized")
            except ImportError:
                self.security_hardening_manager = None
                self.log.warning("SecurityHardeningManager not available - using minimal security")

            # Update security hardening status
            self.security_hardening['process_monitoring'] = False
            self.security_hardening['win32_exception_handling'] = False
            self.security_hardening['security_hardening_manager'] = self.security_hardening_manager is not None

            self.log.warning("Fallback security components initialized")
            return True

        except Exception as e:
            self.log.error(f"Fallback security initialization failed: {e}")
            # Set all components to None for graceful degradation
            self.security_hardening_manager = None
            self.process_monitor = None
            self.win32_exception_manager = None
            return False

    def enforce_maximum_security(self):
        """Enforce maximum security requirements with no fallbacks."""
        try:
            from maximum_security_hardening import enforce_maximum_security_or_fail

            self.log.info("Enforcing maximum security requirements...")

            # This will either succeed or terminate the application
            self.maximum_security = enforce_maximum_security_or_fail()

            # If we reach here, maximum security is achieved
            print("[OK] MAXIMUM SECURITY ACHIEVED")

            # Update security hardening status to reflect maximum security
            self.security_hardening['maximum_security'] = True
            self.security_hardening['admin_privileges'] = True
            self.security_hardening['cfg_strict_mode'] = True
            self.security_hardening['no_fallbacks'] = True

            self.log.info("Maximum security enforcement successful")
            return True

        except SystemExit:
            # Expected exit for security failures - re-raise
            raise
        except ImportError as e:
            self.log.critical(f"Maximum security module not available: {e}")
            raise SecurityError(
                "Maximum security enforcement not available",
                severity=SecurityError.SEVERITY_CRITICAL,
                mitigation_required=True
            )
        except Exception as e:
            self.log.critical(f"Maximum security enforcement failed: {e}")
            raise SecurityError(
                f"Maximum security enforcement failed: {e}",
                severity=SecurityError.SEVERITY_CRITICAL,
                mitigation_required=True
            )

    def enable_anti_debugging(self):
        """
        Enable anti-debugging protection using ptrace detection to prevent reverse engineering
        and tampering with the secure communication system.
        """
        # Check environment variable for test mode
        if os.environ.get("DISABLE_ANTI_DEBUGGING", "false").lower() == "true":
            if _is_production():
                raise SecurityError(
                    "DISABLE_ANTI_DEBUGGING is strictly prohibited in production mode",
                    severity=SecurityError.SEVERITY_CRITICAL,
                    mitigation_required=True
                )
            self.log.info("Anti-debugging protection disabled via environment variable for testing")
            return True

        try:
            import platform_hsm_interface as cphs

            # Check if a debugger is attached
            if hasattr(cphs, 'detect_debugger') and cphs.detect_debugger():
                self.log.critical("SECURITY ALERT: Debugger detected! Initiating emergency security response.")

                # Wipe sensitive data
                self._emergency_wipe()

                # Terminate process via platform_hsm_interface
                if hasattr(cphs, 'emergency_security_response'):
                    cphs.emergency_security_response()
                else:
                    # Fallback termination
                    sys.exit(1)

            # Start periodic debugger checks in background thread
            self._start_debugger_detection_thread()

            self.anti_debugging_enabled = True
            self.log.info("Anti-debugging protection enabled")
            return True
        except Exception as e:
            self.log.warning(f"Failed to enable anti-debugging protection: {e}")
            if _is_production():
                raise SecurityError(
                    f"Failed to enable anti-debugging protection in production: {e}",
                    severity=SecurityError.SEVERITY_CRITICAL,
                    mitigation_required=True
                )
            return False

    def _start_debugger_detection_thread(self):
        """
        Start a background thread that periodically checks for debuggers.
        """
        # Check environment variable for test mode
        if os.environ.get("DISABLE_ANTI_DEBUGGING", "false").lower() == "true":
            if _is_production():
                raise SecurityError(
                    "DISABLE_ANTI_DEBUGGING is strictly prohibited in production mode",
                    severity=SecurityError.SEVERITY_CRITICAL,
                    mitigation_required=True
                )
            self.log.info("Debugger detection thread disabled via environment variable for testing")
            return

        try:
            import platform_hsm_interface as cphs

            if not hasattr(cphs, 'detect_debugger'):
                self.log.warning("Debugger detection not available in platform_hsm_interface")
                return

            def _debugger_check_loop():
                while True:
                    try:
                        import secrets
                        import time

                        # Cryptographically secure random interval (2.0 to 5.0 seconds) to resist side-channel timing analysis
                        jitter = 2.0 + (secrets.randbelow(3000) / 1000.0)
                        time.sleep(jitter)

                        # Check environment variable again in case it was changed during runtime
                        if os.environ.get("DISABLE_ANTI_DEBUGGING", "false").lower() == "true":
                            time.sleep(5)  # Sleep and check again
                            continue

                        # Perform debugger check
                        if cphs.detect_debugger():
                            self.log.critical("SECURITY ALERT: Debugger detected during runtime!")
                            self._emergency_wipe()

                            if hasattr(cphs, 'emergency_security_response'):
                                cphs.emergency_security_response()
                            else:
                                sys.exit(1)

                    except Exception as e:
                        self.log.error(f"Debugger detection thread error: {e}")
                        time.sleep(10)

            # Start debugger detection thread as daemon
            debugger_thread = threading.Thread(target=_debugger_check_loop, daemon=True)
            debugger_thread.start()
            self.log.debug("Debugger detection thread started")

        except Exception as e:
            self.log.warning(f"Failed to start debugger detection thread: {e}")

    def _emergency_wipe(self):
        """
        Perform emergency wipe of sensitive data before termination.
        """
        try:
            self.log.critical("Performing emergency wipe of sensitive data...")

            # Wipe sensitive attributes
            sensitive_attrs = [
                'security_hardening_manager',
                'process_monitor',
                'win32_exception_manager',
                'maximum_security'
            ]

            for attr in sensitive_attrs:
                if hasattr(self, attr):
                    try:
                        obj = getattr(self, attr)
                        if obj is not None and hasattr(obj, 'cleanup'):
                            obj.cleanup()
                        setattr(self, attr, None)
                    except Exception as e:
                        self.log.error(f"Failed to wipe {attr}: {e}")

            # Cascade emergency wipe to orchestrator (sessions, ratchets, keys)
            if self.orchestrator is not None:
                try:
                    if hasattr(self.orchestrator, 'cleanup'):
                        self.orchestrator.cleanup()
                    elif hasattr(self.orchestrator, 'emergency_wipe'):
                        self.orchestrator.emergency_wipe()
                except Exception as e:
                    self.log.error(f"Failed to wipe orchestrator: {e}")
                self.orchestrator = None

            # Wipe security hardening dictionary
            self.security_hardening.clear()

            self.log.critical("Emergency wipe completed")

        except Exception as e:
            self.log.error(f"Emergency wipe failed: {e}")

    def get_security_status(self) -> Dict[str, Any]:
        """Get current security hardening status"""
        return {
            'anti_debugging_enabled': self.anti_debugging_enabled,
            'maximum_security': self.maximum_security,
            'security_hardening_manager': self.security_hardening_manager is not None,
            'process_monitor': self.process_monitor is not None,
            'win32_exception_manager': self.win32_exception_manager is not None,
            'hardening_status': self.security_hardening.copy()
        }

    def cleanup(self):
        """Cleanup security hardening resources"""
        try:
            self.log.info("Cleaning up security hardening resources...")

            # Stop process monitoring
            if self.process_monitor is not None:
                try:
                    if hasattr(self.process_monitor, 'stop_monitoring'):
                        self.process_monitor.stop_monitoring()
                except Exception as e:
                    self.log.error(f"Failed to stop process monitoring: {e}")

            # Cleanup security hardening manager
            if self.security_hardening_manager is not None:
                try:
                    if hasattr(self.security_hardening_manager, 'cleanup'):
                        self.security_hardening_manager.cleanup()
                except Exception as e:
                    self.log.error(f"Failed to cleanup security hardening manager: {e}")

            # Cleanup exception handler
            if self.win32_exception_manager is not None:
                try:
                    if hasattr(self.win32_exception_manager, 'cleanup'):
                        self.win32_exception_manager.cleanup()
                except Exception as e:
                    self.log.error(f"Failed to cleanup exception handler: {e}")

            self.log.info("Security hardening cleanup completed")

        except Exception as e:
            self.log.error(f"Security hardening cleanup failed: {e}")
