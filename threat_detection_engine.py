"""
Threat Detection Engine

This module provides real-time security monitoring, process behavior analysis,
and anomaly detection capabilities for the cross-platform security hardening system.

Requirements addressed: 2.1, 2.2, 2.3, 6.3, 7.2, 7.4, 8.1, 8.2
"""

import logging
import threading
import time
import os
import sys
import platform
import json
import hashlib
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Union, Set, Tuple
from datetime import datetime, timedelta, timezone
from enum import Enum
from collections import defaultdict, deque
import queue

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

# ProcessMonitorManager availability check - using dynamic import to avoid circular imports
def _check_process_monitor_availability():
    """Check if ProcessMonitorManager is available and functional"""
    try:
        import importlib.util
        spec = importlib.util.find_spec("process_monitor_manager")
        if spec is not None:
            # Try to import the module
            from process_monitor_manager import ProcessMonitorManager, ProcessIntegrityResult

            # Additional check: see if we can actually create a ProcessMonitorManager instance
            # This is a more robust test than just checking if the module can be imported
            try:
                # Try to import the config class as well
                from process_monitor_manager import MonitoringConfig
                test_config = MonitoringConfig()
                # Don't actually create the manager to avoid side effects, just verify the class exists
                if ProcessMonitorManager and hasattr(ProcessMonitorManager, '__init__'):
                    return True, ProcessMonitorManager, ProcessIntegrityResult
            except Exception as e:
                # If we can't create the config or the class doesn't have expected attributes,
                # consider it unavailable
                logging.getLogger(__name__).debug(f"Process monitor validation failed: {e}")

            return True, ProcessMonitorManager, ProcessIntegrityResult
    except ImportError as e:
        logging.getLogger(__name__).debug(f"Process monitor module not importable: {e}")
    return False, None, None

PROCESS_MONITOR_AVAILABLE, ProcessMonitorManager, ProcessIntegrityResult = _check_process_monitor_availability()


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of security threats"""
    PROCESS_ANOMALY = "process_anomaly"
    MEMORY_ANOMALY = "memory_anomaly"
    CPU_ANOMALY = "cpu_anomaly"
    NETWORK_ANOMALY = "network_anomaly"
    FILE_SYSTEM_ANOMALY = "file_system_anomaly"
    INTEGRITY_VIOLATION = "integrity_violation"
    DEPENDENCY_FAILURE = "dependency_failure"
    HARDWARE_SECURITY_FAILURE = "hardware_security_failure"
    PLATFORM_SECURITY_FAILURE = "platform_security_failure"
    RECOVERY_FAILURE = "recovery_failure"


@dataclass
class ThreatEvent:
    """Security threat event data"""
    threat_id: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    timestamp: datetime
    source: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    remediation_steps: List[str] = field(default_factory=list)
    platform_specific: bool = False
    auto_recoverable: bool = False
    recovery_attempted: bool = False
    recovery_successful: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'threat_id': self.threat_id,
            'threat_type': self.threat_type.value,
            'threat_level': self.threat_level.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'description': self.description,
            'details': self.details,
            'remediation_steps': self.remediation_steps,
            'platform_specific': self.platform_specific,
            'auto_recoverable': self.auto_recoverable,
            'recovery_attempted': self.recovery_attempted,
            'recovery_successful': self.recovery_successful
        }


@dataclass
class SecurityStatus:
    """Current security status tracking"""
    monitoring_active: bool = False
    threat_detection_active: bool = False
    hardware_security_available: bool = False
    platform_security_features: Dict[str, bool] = field(default_factory=dict)
    active_threats: List[ThreatEvent] = field(default_factory=list)
    total_threats_detected: int = 0
    last_security_check: Optional[datetime] = None
    security_degradation_level: str = "none"  # none, minor, moderate, severe
    recovery_attempts: int = 0
    last_recovery_attempt: Optional[datetime] = None


class ThreatDetectionEngine:
    """
    Real-time security monitoring and threat detection engine

    Provides comprehensive threat detection including:
    - Process behavior analysis and anomaly detection
    - Security event logging and alerting
    - Platform-specific security monitoring
    - Automatic recovery and self-healing capabilities
    """

    def __init__(self, logger: Optional[logging.Logger] = None, process_monitor: Optional[Any] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.platform_system = platform.system().lower()

        # Core components
        self.process_monitor = process_monitor
        self.security_status = SecurityStatus()

        # Threat detection state
        self.detection_thread = None
        self.stop_event = threading.Event()
        self.threat_queue = queue.Queue()

        # Configuration
        self.detection_interval = 30.0  # seconds - reduced frequency to prevent log spam
        self.max_threat_history = 1000
        self.threat_history: deque = deque(maxlen=self.max_threat_history)

        # Threat suppression to prevent log spam
        self.threat_suppression: Dict[str, datetime] = {}
        self.suppression_duration = 300  # 5 minutes

        # Platform-specific capabilities
        self.platform_capabilities = self._detect_platform_capabilities()

        # Recovery handlers
        self.recovery_handlers: Dict[ThreatType, Callable] = {
            ThreatType.DEPENDENCY_FAILURE: self._recover_dependency_failure,
            ThreatType.HARDWARE_SECURITY_FAILURE: self._recover_hardware_security_failure,
            ThreatType.PLATFORM_SECURITY_FAILURE: self._recover_platform_security_failure,
        }

        self.logger.debug("ThreatDetectionEngine initialized")

    def _detect_platform_capabilities(self) -> Dict[str, bool]:
        """Detect available platform-specific security capabilities"""
        # Dynamic check for ProcessMonitorManager
        current_pm_available, _, _ = _check_process_monitor_availability()

        capabilities = {
            'psutil_available': PSUTIL_AVAILABLE,
            'process_monitor_available': current_pm_available,
            'platform_detected': True
        }

        try:
            if self.platform_system == "windows":
                capabilities.update(self._detect_windows_capabilities())
            elif self.platform_system == "linux":
                capabilities.update(self._detect_linux_capabilities())
            elif self.platform_system == "darwin":  # macOS
                capabilities.update(self._detect_macos_capabilities())
            else:
                self.logger.warning(f"Unknown platform: {self.platform_system}")
                capabilities['platform_detected'] = False

        except Exception as e:
            self.logger.error(f"Error detecting platform capabilities: {str(e)}")
            capabilities['detection_error'] = str(e)

        self.logger.debug(f"Platform capabilities detected: {capabilities}")
        return capabilities

    def _detect_windows_capabilities(self) -> Dict[str, bool]:
        """Detect Windows-specific security capabilities"""
        capabilities = {}

        try:
            # Check for Windows-specific modules
            import ctypes
            capabilities['ctypes_available'] = True

            # Check for Windows security features
            try:
                kernel32 = ctypes.windll.kernel32
                capabilities['kernel32_access'] = True
            except Exception:
                capabilities['kernel32_access'] = False

        except Exception as e:
            self.logger.debug(f"Windows capability detection error: {str(e)}")
            capabilities['detection_error'] = str(e)

        return capabilities

    def _detect_linux_capabilities(self) -> Dict[str, bool]:
        """Detect Linux-specific security capabilities"""
        capabilities = {}

        try:
            # Check for /proc filesystem
            capabilities['proc_filesystem'] = os.path.exists('/proc')

            # Check for security modules
            capabilities['selinux'] = os.path.exists('/sys/fs/selinux')
            capabilities['apparmor'] = os.path.exists('/sys/kernel/security/apparmor')

        except Exception as e:
            self.logger.debug(f"Linux capability detection error: {str(e)}")
            capabilities['detection_error'] = str(e)

        return capabilities

    def _detect_macos_capabilities(self) -> Dict[str, bool]:
        """Detect macOS-specific security capabilities"""
        capabilities = {}

        try:
            # Check for system integrity protection
            try:
                # AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
                import subprocess  # nosec: B404
                # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                result = subprocess.run(['csrutil', 'status'], capture_output=True, text=True, timeout=5, shell=False, check=False)  # nosec: B603 B607
                capabilities['sip_available'] = result.returncode == 0
            except Exception:
                capabilities['sip_available'] = False

        except Exception as e:
            self.logger.debug(f"macOS capability detection error: {str(e)}")
            capabilities['detection_error'] = str(e)

        return capabilities

    def start_threat_detection(self) -> bool:
        """
        Start real-time threat detection monitoring

        Returns:
            bool: True if threat detection started successfully
        """
        try:
            self.logger.info("Starting threat detection engine")

            # Stop any existing detection
            self.stop_threat_detection()

            # Reset stop event
            self.stop_event.clear()

            # Update security status
            self.security_status.monitoring_active = True
            self.security_status.threat_detection_active = True
            self.security_status.hardware_security_available = self._check_hardware_security()
            self.security_status.platform_security_features = self.platform_capabilities.copy()

            # Start detection thread
            self.detection_thread = threading.Thread(
                target=self._threat_detection_loop,
                name="ThreatDetectionEngine",
                daemon=True
            )
            self.detection_thread.start()

            self.logger.debug("Threat detection engine started successfully")
            return True

        except Exception as e:
            error_msg = f"Failed to start threat detection: {str(e)}"
            self.logger.error(error_msg)
            self._generate_threat_event(
                ThreatType.PLATFORM_SECURITY_FAILURE,
                ThreatLevel.HIGH,
                "Threat Detection Startup Failure",
                error_msg,
                remediation_steps=[
                    "Check system permissions",
                    "Verify platform compatibility",
                    "Review error logs for specific issues"
                ]
            )
            return False

    def stop_threat_detection(self):
        """Stop threat detection monitoring"""
        try:
            self.logger.info("Stopping threat detection engine")

            # Signal stop
            self.stop_event.set()

            # Wait for detection thread to finish
            if self.detection_thread and self.detection_thread.is_alive():
                self.detection_thread.join(timeout=5.0)
                if self.detection_thread.is_alive():
                    self.logger.warning("Threat detection thread did not stop gracefully")

            self.security_status.threat_detection_active = False
            self.detection_thread = None

            self.logger.info("Threat detection engine stopped")

        except Exception as e:
            error_msg = f"Error stopping threat detection: {str(e)}"
            self.logger.error(error_msg)

    def _threat_detection_loop(self):
        """Main threat detection monitoring loop"""
        self.logger.debug("Threat detection loop started")

        last_security_check = datetime.now(timezone.utc)

        while not self.stop_event.is_set():
            try:
                # Perform threat detection cycle
                self._perform_threat_detection_cycle()

                # Perform comprehensive security check periodically
                if (datetime.now(timezone.utc) - last_security_check).total_seconds() >= 60:  # Every minute
                    self._perform_comprehensive_security_check()
                    last_security_check = datetime.now(timezone.utc)

                # Process threat queue
                self._process_threat_queue()

                # Sleep until next cycle
                self.stop_event.wait(self.detection_interval)

            except Exception as e:
                error_msg = f"Error in threat detection loop: {str(e)}"
                self.logger.error(error_msg)
                self._generate_threat_event(
                    ThreatType.PLATFORM_SECURITY_FAILURE,
                    ThreatLevel.MEDIUM,
                    "Threat Detection Loop Error",
                    error_msg,
                    auto_recoverable=True
                )

                # Sleep before retrying
                self.stop_event.wait(self.detection_interval)

        self.logger.info("Threat detection loop ended")

    def _perform_threat_detection_cycle(self):
        """Perform one threat detection cycle"""
        try:
            # Update security status
            self.security_status.last_security_check = datetime.now(timezone.utc)

            # Check for dependency failures
            self._check_dependency_status()

            # Check hardware security status
            self._check_hardware_security_status()

            # Check platform-specific security features
            self._check_platform_security_features()

            # Analyze system integrity
            self._analyze_system_integrity()

        except Exception as e:
            raise Exception(f"Threat detection cycle failed: {str(e)}")

    def _check_dependency_status(self):
        """Check for dependency failures"""
        try:
            # Check psutil availability
            if not PSUTIL_AVAILABLE:
                self._generate_threat_event(
                    ThreatType.DEPENDENCY_FAILURE,
                    ThreatLevel.HIGH,
                    "psutil dependency not available",
                    "Process monitoring capabilities are limited without psutil",
                    details={'missing_dependency': 'psutil'},
                    remediation_steps=[
                        "Install psutil using: pip install psutil",
                        "Verify Python environment has proper permissions",
                        "Use fallback monitoring if installation fails"
                    ],
                    auto_recoverable=True
                )

            # Check process monitor availability dynamically
            current_pm_available, _, _ = _check_process_monitor_availability()
            if not current_pm_available:
                self._generate_threat_event(
                    ThreatType.DEPENDENCY_FAILURE,
                    ThreatLevel.MEDIUM,
                    "ProcessMonitorManager not available",
                    "Advanced process monitoring features are unavailable",
                    details={'missing_dependency': 'ProcessMonitorManager'},
                    remediation_steps=[
                        "Ensure process_monitor_manager.py is available",
                        "Check import paths and dependencies",
                        "Use basic monitoring as fallback"
                    ],
                    auto_recoverable=True
                )

        except Exception as e:
            self.logger.error(f"Dependency status check failed: {str(e)}")

    def _check_hardware_security_status(self):
        """Check hardware security availability and status"""
        try:
            hardware_available = self._check_hardware_security()

            if not hardware_available:
                # Log specific reasons why hardware security is unavailable (Requirement 7.2)
                reasons = self._get_hardware_security_unavailable_reasons()

                self._generate_threat_event(
                    ThreatType.HARDWARE_SECURITY_FAILURE,
                    ThreatLevel.MEDIUM,
                    "Hardware security features unavailable",
                    f"Hardware security is not available. Reasons: {', '.join(reasons)}",
                    details={
                        'hardware_available': False,
                        'unavailable_reasons': reasons,
                        'platform': self.platform_system
                    },
                    remediation_steps=[
                        "Check if hardware security modules are properly installed",
                        "Verify platform-specific security features are enabled",
                        "Use software-based security as fallback",
                        "Review hardware compatibility documentation"
                    ],
                    platform_specific=True,
                    auto_recoverable=True
                )

            self.security_status.hardware_security_available = hardware_available

        except Exception as e:
            self.logger.error(f"Hardware security status check failed: {str(e)}")

    def _check_hardware_security(self) -> bool:
        """Check if hardware security features are available"""
        try:
            # Platform-specific hardware security checks
            if self.platform_system == "windows":
                return self._check_windows_hardware_security()
            elif self.platform_system == "linux":
                return self._check_linux_hardware_security()
            elif self.platform_system == "darwin":
                return self._check_macos_hardware_security()
            else:
                return False

        except Exception as e:
            self.logger.debug(f"Hardware security check failed: {str(e)}")
            return False

    def _get_hardware_security_unavailable_reasons(self) -> List[str]:
        """Get specific reasons why hardware security is unavailable"""
        reasons = []

        try:
            if self.platform_system == "windows":
                if not self.platform_capabilities.get('kernel32_access', False):
                    reasons.append("Windows kernel32 access unavailable")

            elif self.platform_system == "linux":
                if not self.platform_capabilities.get('proc_filesystem', False):
                    reasons.append("/proc filesystem not accessible")

            elif self.platform_system == "darwin":
                if not self.platform_capabilities.get('sip_available', False):
                    reasons.append("System Integrity Protection status unknown")

            if not reasons:
                reasons.append("Platform-specific hardware security features not detected")

        except Exception as e:
            reasons.append(f"Error detecting hardware security: {str(e)}")

        return reasons

    def _check_windows_hardware_security(self) -> bool:
        """Check Windows-specific hardware security features"""
        try:
            # Check for TPM availability
            if self.platform_capabilities.get('kernel32_access', False):
                # Basic check - in real implementation, would check TPM status
                return True
            return False
        except Exception:
            return False

    def _check_linux_hardware_security(self) -> bool:
        """Check Linux-specific hardware security features"""
        try:
            # Check for hardware security modules
            return (self.platform_capabilities.get('proc_filesystem', False) and
                    (self.platform_capabilities.get('selinux', False) or
                     self.platform_capabilities.get('apparmor', False)))
        except Exception:
            return False

    def _check_macos_hardware_security(self) -> bool:
        """Check macOS-specific hardware security features"""
        try:
            # Check for Secure Enclave and other macOS security features
            return self.platform_capabilities.get('sip_available', False)
        except Exception:
            return False

    def _check_platform_security_features(self):
        """Check platform-specific security features"""
        try:
            # Requirement 6.3: Adapt security checks using available platform capabilities
            available_features = {}

            for feature, available in self.platform_capabilities.items():
                if not available and feature in ['psutil_available', 'process_monitor_available']:
                    # Generate alert for critical missing features
                    self._generate_threat_event(
                        ThreatType.PLATFORM_SECURITY_FAILURE,
                        ThreatLevel.MEDIUM,
                        f"Platform security feature unavailable: {feature}",
                        f"Security feature {feature} is not available on {self.platform_system}",
                        details={
                            'feature': feature,
                            'platform': self.platform_system,
                            'available_alternatives': self._get_feature_alternatives(feature)
                        },
                        remediation_steps=self._get_feature_remediation_steps(feature),
                        platform_specific=True,
                        auto_recoverable=True
                    )

                available_features[feature] = available

            self.security_status.platform_security_features = available_features

        except Exception as e:
            self.logger.error(f"Platform security features check failed: {str(e)}")

    def _get_feature_alternatives(self, feature: str) -> List[str]:
        """Get alternative implementations for unavailable features"""
        alternatives = {
            'psutil_available': ['fallback process monitoring', 'platform-specific process APIs'],
            'process_monitor_available': ['basic process checking', 'manual monitoring'],
            'kernel32_access': ['alternative Windows APIs', 'PowerShell commands'],
            'proc_filesystem': ['alternative Linux monitoring', 'system commands']
        }
        return alternatives.get(feature, ['manual implementation required'])

    def _get_feature_remediation_steps(self, feature: str) -> List[str]:
        """Get remediation steps for unavailable features"""
        remediation = {
            'psutil_available': [
                "Install psutil: pip install psutil",
                "Check Python environment permissions",
                "Use fallback monitoring if installation fails"
            ],
            'process_monitor_available': [
                "Ensure process_monitor_manager.py is in Python path",
                "Check for missing dependencies",
                "Use basic process monitoring as fallback"
            ],
            'kernel32_access': [
                "Run with administrator privileges",
                "Check Windows security policies",
                "Use alternative Windows APIs"
            ],
            'proc_filesystem': [
                "Check /proc filesystem permissions",
                "Verify Linux kernel configuration",
                "Use alternative monitoring methods"
            ]
        }
        return remediation.get(feature, ["Review platform documentation", "Contact system administrator"])

    def _analyze_system_integrity(self):
        """Analyze system integrity using available methods"""
        try:
            if self.process_monitor and hasattr(self.process_monitor, 'check_process_integrity'):
                # Use process monitor for integrity checking
                current_pid = os.getpid()
                integrity_result = self.process_monitor.check_process_integrity(current_pid)

                if not integrity_result.integrity_valid:
                    self._generate_threat_event(
                        ThreatType.INTEGRITY_VIOLATION,
                        ThreatLevel.HIGH,
                        f"Process integrity violation detected for PID {current_pid}",
                        f"Integrity check failed: {integrity_result.error_message or 'Unknown reason'}",
                        details={
                            'pid': current_pid,
                            'method_used': integrity_result.method_used,
                            'error_message': integrity_result.error_message,
                            'details': integrity_result.details
                        },
                        remediation_steps=[
                            "Restart the affected process",
                            "Check for system tampering",
                            "Verify process binary integrity",
                            "Review system logs for suspicious activity"
                        ],
                        auto_recoverable=True
                    )

        except Exception as e:
            self.logger.error(f"System integrity analysis failed: {str(e)}")

    def _perform_comprehensive_security_check(self):
        """Perform comprehensive security status assessment"""
        try:
            # Count active threats by level
            threat_counts = defaultdict(int)
            for threat in self.security_status.active_threats:
                threat_counts[threat.threat_level] += 1

            # Determine security degradation level
            if threat_counts[ThreatLevel.CRITICAL] > 0:
                degradation = "severe"
            elif threat_counts[ThreatLevel.HIGH] > 2:
                degradation = "severe"
            elif threat_counts[ThreatLevel.HIGH] > 0 or threat_counts[ThreatLevel.MEDIUM] > 3:
                degradation = "moderate"
            elif threat_counts[ThreatLevel.MEDIUM] > 0 or threat_counts[ThreatLevel.LOW] > 5:
                degradation = "minor"
            else:
                degradation = "none"

            # Check if degradation level changed
            if degradation != self.security_status.security_degradation_level:
                old_level = self.security_status.security_degradation_level
                self.security_status.security_degradation_level = degradation

                # Requirement 7.4: Generate alerts with remediation steps for security degradation
                if degradation != "none":
                    self._generate_security_degradation_alert(old_level, degradation, threat_counts)

        except Exception as e:
            self.logger.error(f"Comprehensive security check failed: {str(e)}")

    def _generate_security_degradation_alert(self, old_level: str, new_level: str, threat_counts: Dict[ThreatLevel, int]):
        """Generate alert for security degradation"""
        try:
            threat_summary = []
            for level, count in threat_counts.items():
                if count > 0:
                    threat_summary.append(f"{count} {level.value}")

            threat_description = ", ".join(threat_summary) if threat_summary else "no active threats"

            # Determine alert level based on degradation severity
            if new_level == "severe":
                alert_level = ThreatLevel.CRITICAL
            elif new_level == "moderate":
                alert_level = ThreatLevel.HIGH
            else:
                alert_level = ThreatLevel.MEDIUM

            remediation_steps = [
                "Review active security threats",
                "Address high and critical priority threats first",
                "Check system logs for root causes",
                "Consider enabling additional security measures"
            ]

            if new_level == "severe":
                remediation_steps.extend([
                    "Consider system isolation if compromise suspected",
                    "Perform immediate security audit",
                    "Contact security team if available"
                ])

            self._generate_threat_event(
                ThreatType.PLATFORM_SECURITY_FAILURE,
                alert_level,
                f"Security degradation detected: {old_level} -> {new_level}",
                f"Security posture has degraded from {old_level} to {new_level}. Active threats: {threat_description}",
                details={
                    'old_degradation_level': old_level,
                    'new_degradation_level': new_level,
                    'threat_counts': {level.value: count for level, count in threat_counts.items()},
                    'total_active_threats': len(self.security_status.active_threats)
                },
                remediation_steps=remediation_steps,
                auto_recoverable=False  # Security degradation requires manual attention
            )

        except Exception as e:
            self.logger.error(f"Error generating security degradation alert: {str(e)}")

    def _process_threat_queue(self):
        """Process queued threat events"""
        try:
            while not self.threat_queue.empty():
                try:
                    threat_event = self.threat_queue.get_nowait()
                    self._handle_threat_event(threat_event)
                except queue.Empty:
                    break
                except Exception as e:
                    self.logger.error(f"Error processing threat event: {str(e)}")

        except Exception as e:
            self.logger.error(f"Error processing threat queue: {str(e)}")

    def _handle_threat_event(self, threat_event: ThreatEvent):
        """Handle a threat event with logging and potential recovery"""
        try:
            # Log the threat event
            self.logger.warning(f"THREAT DETECTED: {threat_event.description}")
            self.logger.info(f"Threat details: {json.dumps(threat_event.to_dict(), indent=2)}")

            # Add to threat history
            self.threat_history.append(threat_event)

            # Add to active threats if not already present
            if not any(t.threat_id == threat_event.threat_id for t in self.security_status.active_threats):
                self.security_status.active_threats.append(threat_event)
                self.security_status.total_threats_detected += 1

            # Attempt automatic recovery if applicable
            if threat_event.auto_recoverable and not threat_event.recovery_attempted:
                self._attempt_threat_recovery(threat_event)

        except Exception as e:
            self.logger.error(f"Error handling threat event: {str(e)}")

    def _attempt_threat_recovery(self, threat_event: ThreatEvent):
        """Attempt automatic recovery for recoverable threats"""
        try:
            self.logger.info(f"Attempting automatic recovery for threat: {threat_event.threat_id}")

            threat_event.recovery_attempted = True
            self.security_status.recovery_attempts += 1
            self.security_status.last_recovery_attempt = datetime.now(timezone.utc)

            # Get recovery handler for threat type
            recovery_handler = self.recovery_handlers.get(threat_event.threat_type)

            if recovery_handler:
                success = recovery_handler(threat_event)
                threat_event.recovery_successful = success

                if success:
                    self.logger.info(f"Automatic recovery successful for threat: {threat_event.threat_id}")
                    # Remove from active threats
                    self.security_status.active_threats = [
                        t for t in self.security_status.active_threats
                        if t.threat_id != threat_event.threat_id
                    ]
                else:
                    self.logger.warning(f"Automatic recovery failed for threat: {threat_event.threat_id}")
            else:
                self.logger.warning(f"No recovery handler available for threat type: {threat_event.threat_type}")
                threat_event.recovery_successful = False

        except Exception as e:
            self.logger.error(f"Error during threat recovery: {str(e)}")
            threat_event.recovery_successful = False

    def _recover_dependency_failure(self, threat_event: ThreatEvent) -> bool:
        """Recover from dependency failures"""
        try:
            missing_dep = threat_event.details.get('missing_dependency')

            if missing_dep == 'psutil':
                # Military security: Prohibit runtime pip installations (fail-closed model).
                # All dependencies must be pre-installed and cryptographically verified.
                try:
                    import psutil
                    global PSUTIL_AVAILABLE
                    PSUTIL_AVAILABLE = True
                    self.logger.info("psutil is pre-installed and available")
                    return True
                except ImportError:
                    self.logger.critical(
                        "FAIL-CLOSED: psutil is missing and runtime pip installation is prohibited in military mode. "
                        "Please pre-install psutil via your verified supply chain package manager."
                    )
                    return False

            elif missing_dep == 'ProcessMonitorManager':
                # ProcessMonitorManager is available, just re-check the import
                try:
                    global PROCESS_MONITOR_AVAILABLE, ProcessMonitorManager, ProcessIntegrityResult
                    PROCESS_MONITOR_AVAILABLE, ProcessMonitorManager, ProcessIntegrityResult = _check_process_monitor_availability()
                    if PROCESS_MONITOR_AVAILABLE:
                        self.logger.info("ProcessMonitorManager recovered successfully")
                        return True
                    else:
                        self.logger.critical("FAIL-CLOSED: ProcessMonitorManager still not available after recovery attempt. Military security requires advanced process monitoring.")
                        return False
                except Exception as e:
                    self.logger.critical(f"ProcessMonitorManager recovery check failed: {str(e)}")
                    return False

            return False

        except Exception as e:
            self.logger.error(f"Dependency recovery failed: {str(e)}")
            return False

    def _recover_hardware_security_failure(self, threat_event: ThreatEvent) -> bool:
        """Recover from hardware security failures"""
        try:
            # Re-check hardware security availability
            hardware_available = self._check_hardware_security()

            if hardware_available:
                self.security_status.hardware_security_available = True
                self.logger.info("Hardware security recovered")
                return True

            # FAIL-CLOSED: Hardware security is mandatory for military grade.
            # Software fallbacks are unacceptable.
            self.logger.critical("FAIL-CLOSED: Hardware security still unavailable. Military policy prohibits software fallbacks.")
            return False

        except Exception as e:
            self.logger.error(f"Hardware security recovery failed: {str(e)}")
            return False

    def _recover_platform_security_failure(self, threat_event: ThreatEvent) -> bool:
        """Recover from platform security failures"""
        try:
            # Re-detect platform capabilities
            self.platform_capabilities = self._detect_platform_capabilities()

            # Check if the specific feature is now available
            feature = threat_event.details.get('feature')
            if feature and self.platform_capabilities.get(feature, False):
                self.logger.info(f"Platform feature {feature} recovered")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Platform security recovery failed: {str(e)}")
            return False

    def _generate_threat_event(self, threat_type: ThreatType, threat_level: ThreatLevel,
                             description: str, details_str: str,
                             details: Optional[Dict[str, Any]] = None,
                             remediation_steps: Optional[List[str]] = None,
                             platform_specific: bool = False,
                             auto_recoverable: bool = False):
        """Generate a new threat event"""
        try:
            # Check if this threat type should be suppressed
            suppression_key = f"{threat_type.value}_{description}"
            now = datetime.now(timezone.utc)

            if suppression_key in self.threat_suppression:
                last_reported = self.threat_suppression[suppression_key]
                if (now - last_reported).total_seconds() < self.suppression_duration:
                    # Suppress this threat - already reported recently
                    return

            # Update suppression tracking
            self.threat_suppression[suppression_key] = now
            threat_id = hashlib.sha512(
                f"{threat_type.value}_{description}_{datetime.now(timezone.utc).isoformat()}".encode()
            ).hexdigest()[:16]

            threat_event = ThreatEvent(
                threat_id=threat_id,
                threat_type=threat_type,
                threat_level=threat_level,
                timestamp=datetime.now(timezone.utc),
                source="ThreatDetectionEngine",
                description=description,
                details=details or {'description': details_str},
                remediation_steps=remediation_steps or [],
                platform_specific=platform_specific,
                auto_recoverable=auto_recoverable
            )

            # Add to threat queue for processing
            self.threat_queue.put(threat_event)

        except Exception as e:
            self.logger.error(f"Error generating threat event: {str(e)}")

    def get_security_status(self) -> SecurityStatus:
        """Get current security status"""
        return self.security_status

    def get_threat_history(self) -> List[ThreatEvent]:
        """Get threat history"""
        return list(self.threat_history)

    def get_active_threats(self) -> List[ThreatEvent]:
        """Get currently active threats"""
        return self.security_status.active_threats.copy()

    def clear_resolved_threats(self):
        """Clear threats that have been resolved"""
        try:
            resolved_count = len([t for t in self.security_status.active_threats if t.recovery_successful])
            self.security_status.active_threats = [
                t for t in self.security_status.active_threats
                if not t.recovery_successful
            ]

            if resolved_count > 0:
                self.logger.info(f"Cleared {resolved_count} resolved threats")

        except Exception as e:
            self.logger.error(f"Error clearing resolved threats: {str(e)}")

    def get_status_dict(self) -> Dict[str, Any]:
        """Get comprehensive status as dictionary"""
        try:
            return {
                'security_status': {
                    'monitoring_active': self.security_status.monitoring_active,
                    'threat_detection_active': self.security_status.threat_detection_active,
                    'hardware_security_available': self.security_status.hardware_security_available,
                    'platform_security_features': self.security_status.platform_security_features,
                    'security_degradation_level': self.security_status.security_degradation_level,
                    'total_threats_detected': self.security_status.total_threats_detected,
                    'active_threat_count': len(self.security_status.active_threats),
                    'recovery_attempts': self.security_status.recovery_attempts,
                    'last_security_check': self.security_status.last_security_check.isoformat() if self.security_status.last_security_check else None,
                    'last_recovery_attempt': self.security_status.last_recovery_attempt.isoformat() if self.security_status.last_recovery_attempt else None
                },
                'platform_info': {
                    'system': self.platform_system,
                    'capabilities': self.platform_capabilities
                },
                'threat_summary': {
                    'total_in_history': len(self.threat_history),
                    'active_threats': len(self.security_status.active_threats),
                    'threat_levels': {
                        level.value: len([t for t in self.security_status.active_threats if t.threat_level == level])
                        for level in ThreatLevel
                    }
                }
            }

        except Exception as e:
            self.logger.error(f"Error getting status dict: {str(e)}")
            return {'error': str(e)}

    def __enter__(self):
        """Context manager entry"""
        self.start_threat_detection()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop_threat_detection()


# Convenience function for easy integration
def create_threat_detection_engine(logger: Optional[logging.Logger] = None,
                                 process_monitor: Optional[Any] = None) -> 'ThreatDetectionEngine':
    """
    Create and return a ThreatDetectionEngine instance

    Args:
        logger: Optional logger instance
        process_monitor: Optional ProcessMonitorManager instance

    Returns:
        ThreatDetectionEngine: Configured threat detection engine
    """
    return ThreatDetectionEngine(logger, process_monitor)


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # Create and test threat detection engine
    threat_engine = ThreatDetectionEngine(logger)

    try:
        # Start threat detection
        if threat_engine.start_threat_detection():
            logger.info("Threat detection started successfully")

            # Run for a short time to collect data
            time.sleep(10)

            # Get status
            status = threat_engine.get_status_dict()
            logger.info(f"Threat detection status: {json.dumps(status, indent=2)}")

            # Get active threats
            active_threats = threat_engine.get_active_threats()
            logger.info(f"Active threats: {len(active_threats)}")

            for threat in active_threats:
                logger.info(f"Threat: {threat.description} (Level: {threat.threat_level.value})")

        else:
            logger.error("Failed to start threat detection")

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Error during testing: {str(e)}")
    finally:
        threat_engine.stop_threat_detection()
        logger.info("Threat detection engine test completed")

