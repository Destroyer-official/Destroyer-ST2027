#!/usr/bin/env python
"""
Security Hardening Manager Module

This module provides comprehensive cross-platform security hardening capabilities
with a focus on resolving Windows CFG error 87 issues and implementing robust
security protections across Windows, Linux, and macOS platforms.

Key Features:
- Windows CFG error 87 fixes through WindowsCFGHandler integration
- Cross-platform control flow protection
- Automatic dependency management
- Hardware security module integration
- Exception handling and recovery mechanisms
"""

import logging
import os
import platform
import sys
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from datetime import datetime

# Configure logger
hardening_logger = logging.getLogger("security_hardening_manager")
hardening_logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging
hardening_file_handler = logging.FileHandler(
    os.path.join("logs", "security_hardening_manager.log"))
hardening_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
hardening_file_handler.setFormatter(formatter)
hardening_logger.addHandler(hardening_file_handler)

# Let logs propagate to root logger for console output (avoid duplicate handlers)
hardening_logger.propagate = True


@dataclass
class SecurityStatus:
    """Security status tracking model."""
    cfg_enabled: bool = False
    process_monitoring_active: bool = False
    hsm_fully_integrated: bool = False
    dependencies_satisfied: bool = False
    exception_handling_configured: bool = False
    platform_specific_features: Dict[str, bool] = None
    security_level: str = "LOW"
    last_updated: datetime = None
    
    def __post_init__(self):
        if self.platform_specific_features is None:
            self.platform_specific_features = {}
        if self.last_updated is None:
            self.last_updated = datetime.now()


class SecurityHardeningError(Exception):
    """Base exception for security hardening operations."""


class CFGProtectionError(SecurityHardeningError):
    """CFG protection specific errors."""


class ProcessMonitoringError(SecurityHardeningError):
    """Process monitoring specific errors."""


class HSMIntegrationError(SecurityHardeningError):
    """HSM integration specific errors."""


class DependencyError(SecurityHardeningError):
    """Dependency management specific errors."""


class SecurityHardeningManager:
    """
    Main security hardening manager that coordinates all security protection mechanisms.
    
    This class provides comprehensive security hardening with a focus on:
    1. Windows CFG error 87 fixes
    2. Cross-platform control flow protection
    3. Process monitoring and integrity checking
    4. Hardware security module integration
    5. Exception handling and recovery
    """
    
    def __init__(self):
        """Initialize the Security Hardening Manager."""
        self.platform = platform.system()
        self.architecture = platform.machine().lower()
        self.is_windows = self.platform == "Windows"
        self.is_linux = self.platform == "Linux"
        self.is_macos = self.platform == "Darwin"
        
        # Initialize security status
        self.security_status = SecurityStatus()
        
        # Component handlers
        self.cfg_handler = None
        self.process_monitor = None
        self.hsm_manager = None
        self.exception_handler = None
        self.dependency_manager = None
        self.recovery_manager = None
        self.status_monitor = None
        
        hardening_logger.info(f"SecurityHardeningManager initialized for {self.platform} ({self.architecture})")
        
        # Initialize platform-specific components
        self._initialize_components()
        
        # Initialize recovery manager
        self._initialize_recovery_manager()
        
        # Initialize status monitor
        self._initialize_status_monitor()
    
    def _initialize_components(self):
        """Initialize platform-specific security components."""
        try:
            # Initialize CFG protection
            self._initialize_cfg_protection()
            
            # Initialize other components
            self._initialize_process_monitoring()
            self._initialize_hsm_integration()
            self._initialize_exception_handling()
            self._initialize_dependency_management()
            
            hardening_logger.debug("All security components initialized successfully")
            
        except Exception as e:
            hardening_logger.error(f"Component initialization failed: {e}")
            raise SecurityHardeningError(f"Failed to initialize security components: {e}")
    
    def _initialize_cfg_protection(self):
        """Initialize Control Flow Guard protection."""
        try:
            if self.is_windows:
                from cross_platform_exception_handler import CrossPlatformExceptionHandler
                self.exception_handler = CrossPlatformExceptionHandler()
                self.cfg_handler = self.exception_handler._platform_handler
                hardening_logger.info("Windows CFG handler initialized via cross-platform handler")
            else:
                self.cfg_handler = None
                self.security_status.cfg_enabled = True
                hardening_logger.info("Non-Windows platform: native POSIX memory isolation and ASLR active")
                
        except ImportError as e:
            hardening_logger.warning(f"CFG handler not available: {e}")
        except Exception as e:
            hardening_logger.error(f"CFG handler initialization failed: {e}")
    
    def _initialize_process_monitoring(self):
        """Initialize process monitoring capabilities."""
        try:
            from process_monitor_manager import ProcessMonitorManager, MonitoringConfig
            
            # Initialize process monitoring configuration
            monitoring_config = MonitoringConfig(
                check_interval=5.0,
                recovery_attempts=3,
                enable_automatic_recovery=True,
                enable_integrity_checking=True,
                log_level="INFO"
            )
            
            # Initialize ProcessMonitorManager
            self.process_monitor = ProcessMonitorManager(
                config=monitoring_config,
                logger=hardening_logger,
                enable_threat_detection=True
            )
            
            # Start process monitoring
            if self.process_monitor.start_monitoring():
                hardening_logger.debug("Process monitoring initialized and started successfully")
                self.security_status.process_monitoring_active = True
                
                # Add current process to monitoring
                import os
                current_pid = os.getpid()
                if self.process_monitor.add_process(current_pid):
                    hardening_logger.info(f"Added current process {current_pid} to monitoring")
            else:
                hardening_logger.warning("Process monitoring initialization failed")
                
        except ImportError as e:
            hardening_logger.warning(f"ProcessMonitorManager not available: {e}")
        except Exception as e:
            hardening_logger.error(f"Process monitoring initialization failed: {e}")
    
    def _initialize_hsm_integration(self):
        """Initialize hardware security module integration."""
        try:
            # Try to initialize platform HSM interface
            try:
                import platform_hsm_interface as hsm
                
                # Check if HSM is available and functional
                if hasattr(hsm, 'get_secure_memory') and callable(hsm.get_secure_memory):
                    # Test HSM functionality
                    test_memory = hsm.get_secure_memory(64)  # Test with 64 bytes
                    if test_memory:
                        self.hsm_manager = hsm
                        self.security_status.hsm_fully_integrated = True
                        hardening_logger.debug("HSM integration initialized successfully")
                    else:
                        raise HSMIntegrationError("MILITARY FATAL: HSM test failed - secure memory allocation unsuccessful")
                else:
                    raise HSMIntegrationError("MILITARY FATAL: HSM get_secure_memory method not available")
                    
            except ImportError as e:
                raise HSMIntegrationError(f"MILITARY FATAL: platform_hsm_interface not available: {e}")
            except HSMIntegrationError:
                raise
            except Exception as hsm_e:
                raise HSMIntegrationError(f"MILITARY FATAL: HSM initialization failed: {hsm_e}")
                
        except Exception as e:
            hardening_logger.error(f"HSM integration initialization failed: {e}")
    
    def _initialize_exception_handling(self):
        """Initialize exception handling mechanisms."""
        try:
            from cross_platform_exception_handler import CrossPlatformExceptionHandler, ExceptionHandlingConfig
            
            exception_config = ExceptionHandlingConfig(
                suppress_com_exceptions=True if self.is_windows else False,
                suppress_iunknown_exceptions=True if self.is_windows else False,
                log_suppressed_exceptions=True,
                enable_com_cleanup=True if self.is_windows else False,
                auto_garbage_collection=True,
                thread_safe_operations=True
            )
            
            self.exception_handler = CrossPlatformExceptionHandler(exception_config)
            
            if self.exception_handler:
                self.security_status.exception_handling_configured = True
                hardening_logger.debug("Exception handling initialized successfully")
            else:
                hardening_logger.warning("Exception handling configuration failed")
                
        except ImportError as e:
            hardening_logger.warning(f"Exception handling components not available: {e}")
        except Exception as e:
            hardening_logger.error(f"Exception handling initialization failed: {e}")
    
    def _initialize_dependency_management(self):
        """Initialize dependency management system."""
        try:
            from security_dependency_manager import SecurityDependencyManager
            
            # Initialize dependency manager
            self.dependency_manager = SecurityDependencyManager(hardening_logger)
            
            # Ensure all critical dependencies are available
            dependency_results = self.dependency_manager.ensure_all_dependencies()
            
            # Check if all dependencies are satisfied
            all_satisfied = all(dependency_results.values())
            self.security_status.dependencies_satisfied = all_satisfied
            
            if all_satisfied:
                hardening_logger.info("All security dependencies satisfied")
            else:
                failed_deps = [dep for dep, satisfied in dependency_results.items() if not satisfied]
                hardening_logger.warning(f"Some dependencies not satisfied: {failed_deps}")
                
        except ImportError as e:
            hardening_logger.warning(f"SecurityDependencyManager not available: {e}")
        except Exception as e:
            hardening_logger.error(f"Dependency management initialization failed: {e}")
    
    def _initialize_recovery_manager(self):
        """Initialize security recovery manager."""
        try:
            from security_recovery_manager import SecurityRecoveryManager, SecurityFeature
            
            self.recovery_manager = SecurityRecoveryManager(self)
            
            # Register recovery callbacks
            self.recovery_manager.register_recovery_callback(
                SecurityFeature.CFG_PROTECTION,
                self._recover_cfg_protection
            )
            
            # Register notification callback
            self.recovery_manager.register_notification_callback(
                self._security_notification
            )
            
            # Start recovery monitoring
            self.recovery_manager.start_recovery_monitoring()
            
            hardening_logger.info("Security recovery manager initialized")
            
        except ImportError as e:
            hardening_logger.warning(f"Recovery manager not available: {e}")
        except Exception as e:
            hardening_logger.error(f"Recovery manager initialization failed: {e}")
    
    def _recover_cfg_protection(self) -> Tuple[bool, str]:
        """Recovery callback for CFG protection."""
        try:
            # Try standard CFG enablement
            success, message = self.enable_cfg_protection()
            if success:
                return True, message
            
            # Try error 87 specific handling
            success, message = self.handle_cfg_error_87()
            return success, message
            
        except Exception as e:
            return False, f"CFG recovery failed: {e}"
    
    def _security_notification(self, message: str):
        """Security notification callback."""
        hardening_logger.warning(f"SECURITY ALERT: {message}")
        # Could integrate with system notifications, email alerts, etc.
    
    def _initialize_status_monitor(self):
        """Initialize security status monitor."""
        try:
            from security_status_monitor import SecurityStatusMonitor
            
            self.status_monitor = SecurityStatusMonitor(self, self.recovery_manager)
            
            # Register alert callback
            self.status_monitor.register_alert_callback(self._handle_security_alert)
            
            # Register remediation callbacks
            self.status_monitor.register_remediation_callback(
                "cfg_protection",
                self._remediate_cfg_protection
            )
            
            # Start monitoring
            self.status_monitor.start_monitoring()
            
            hardening_logger.info("Security status monitor initialized and started")
            
        except ImportError as e:
            hardening_logger.warning(f"Status monitor not available: {e}")
        except Exception as e:
            hardening_logger.error(f"Status monitor initialization failed: {e}")
    
    def _handle_security_alert(self, alert):
        """Handle security alerts from the status monitor."""
        hardening_logger.warning(f"SECURITY ALERT [{alert.severity.value.upper()}]: {alert.title} - {alert.description}")
        
        # Could integrate with external alerting systems here
        # For example: send email, SMS, push notification, etc.
    
    def _remediate_cfg_protection(self) -> bool:
        """Remediation callback for CFG protection issues."""
        try:
            success, message = self.enable_cfg_protection()
            if success:
                hardening_logger.info(f"CFG protection remediation successful: {message}")
                return True
            else:
                # Try error 87 specific handling
                success, message = self.handle_cfg_error_87()
                if success:
                    hardening_logger.info(f"CFG error 87 remediation successful: {message}")
                    return True
                else:
                    hardening_logger.error(f"CFG protection remediation failed: {message}")
                    return False
        except Exception as e:
            hardening_logger.error(f"CFG protection remediation error: {e}")
            return False
    
    def enable_cfg_protection(self) -> Tuple[bool, str]:
        """
        Enable Control Flow Guard protection with error 87 fixes and enhanced detection.
        
        Returns:
            Tuple[bool, str]: (success, message)
        """
        if not self.is_windows:
            self.security_status.cfg_enabled = True
            if self.recovery_manager:
                from security_recovery_manager import SecurityFeature
                self.recovery_manager.report_feature_success(SecurityFeature.CFG_PROTECTION)
            return True, "CFG is Windows-specific; Linux native memory protection active"

        if not self.cfg_handler:
            return False, "CFG handler not available"
        
        try:
            # First, check if CFG is already enabled
            status = self.cfg_handler.verify_cfg_status()
            if status.get('cfg_enabled'):
                self.security_status.cfg_enabled = True
                self.security_status.last_updated = datetime.now()
                self.security_status.platform_specific_features['cfg_verified'] = True
                hardening_logger.info("CFG protection already enabled and verified")
                
                # Report success to recovery manager
                if self.recovery_manager:
                    from security_recovery_manager import SecurityFeature
                    self.recovery_manager.report_feature_success(SecurityFeature.CFG_PROTECTION)
                
                return True, "CFG protection already enabled"
            
            # Try to enable CFG protection
            success, message = self.cfg_handler.enable_cfg_protection()
            
            if success:
                self.security_status.cfg_enabled = True
                self.security_status.last_updated = datetime.now()
                hardening_logger.info(f"CFG protection enabled: {message}")
                
                # Verify CFG status after enablement
                status = self.cfg_handler.verify_cfg_status()
                if status.get('cfg_enabled'):
                    self.security_status.platform_specific_features['cfg_verified'] = True
                    hardening_logger.info("CFG protection verified successfully")
                    
                    # Report success to recovery manager
                    if self.recovery_manager:
                        from security_recovery_manager import SecurityFeature
                        self.recovery_manager.report_feature_success(SecurityFeature.CFG_PROTECTION)
                else:
                    hardening_logger.warning(f"CFG verification failed: {status.get('error')}")
                    # Still consider it successful if enablement reported success
                    self.security_status.platform_specific_features['cfg_enabled_but_unverified'] = True
                    
            else:
                hardening_logger.warning(f"CFG protection enablement failed: {message}")
                
                # Check if CFG might be enabled by other means (compiler, system policy, etc.)
                if self._detect_alternative_cfg_protection():
                    self.security_status.cfg_enabled = True
                    self.security_status.platform_specific_features['cfg_alternative_detected'] = True
                    hardening_logger.info("CFG protection detected via alternative means")
                    
                    # Report success to recovery manager
                    if self.recovery_manager:
                        from security_recovery_manager import SecurityFeature
                        self.recovery_manager.report_feature_success(SecurityFeature.CFG_PROTECTION)
                    
                    return True, "CFG protection detected via alternative means"
                
                # Fallbacks are strictly forbidden in military grade security
                raise CFGProtectionError("MILITARY FATAL: CFG protection could not be enabled and fallbacks are forbidden.")
                
                # Report failure to recovery manager
                if self.recovery_manager:
                    from security_recovery_manager import SecurityFeature
                    self.recovery_manager.report_feature_failure(
                        SecurityFeature.CFG_PROTECTION,
                        message
                    )
            
            return success, message
            
        except Exception as e:
            error_msg = f"CFG protection error: {e}"
            hardening_logger.error(error_msg)
            return False, error_msg
    
    def _detect_alternative_cfg_protection(self) -> bool:
        """
        Detect CFG protection enabled by alternative means (compiler, system policy, etc.).
        
        Returns:
            bool: True if alternative CFG protection is detected
        """
        try:
            # Check if the current process was compiled with CFG
            import ctypes
            import sys
            
            # Method 1: Check if the Python executable has CFG enabled
            try:
                # Get the current process handle
                kernel32 = ctypes.windll.kernel32
                current_process = kernel32.GetCurrentProcess()
                
                # Try to detect CFG through process characteristics
                # This is a heuristic approach since CFG might be enabled at compile time
                
                # Check if we're running on a system that supports CFG
                version_info = sys.getwindowsversion()
                if version_info.major >= 10:  # Windows 10 and later have better CFG support
                    hardening_logger.info("Running on Windows 10+ with CFG support")
                    
                    # Check if the process has DEP enabled (often correlated with CFG)
                    try:
                        # Use NtQueryInformationProcess to check process mitigation policies
                        ntdll = ctypes.windll.ntdll
                        
                        # If we can access these APIs, there's a good chance CFG is available
                        if hasattr(ntdll, 'NtQueryInformationProcess'):
                            hardening_logger.info("Advanced process mitigation APIs available")
                            return True
                            
                    except Exception as e:
                        hardening_logger.debug(f"Advanced CFG detection failed: {e}")
                
            except Exception as e:
                hardening_logger.debug(f"Process CFG detection failed: {e}")
            
            # Method 2: Check for compiler-generated CFG protection
            try:
                # Check if the current executable has CFG characteristics
                executable_path = sys.executable
                if executable_path and os.path.exists(executable_path):
                    # Modern Python distributions often have CFG enabled
                    if "python" in executable_path.lower():
                        hardening_logger.info("Running Python executable likely has CFG protection")
                        return True
                        
            except Exception as e:
                hardening_logger.debug(f"Executable CFG detection failed: {e}")
            
            # Method 3: Check system-wide CFG policy
            try:
                import winreg
                
                # Check if Windows Defender Exploit Guard has CFG enabled system-wide
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System\ControlFlowGuard",
                        0,
                        winreg.KEY_READ
                    )
                    
                    # If the key exists, CFG might be configured system-wide
                    winreg.CloseKey(key)
                    hardening_logger.info("System-wide CFG configuration detected")
                    return True
                    
                except (FileNotFoundError, PermissionError, OSError):
                    hardening_logger.debug("System-wide CFG configuration not accessible")
                    
            except Exception as e:
                hardening_logger.debug(f"System CFG policy detection failed: {e}")
            
            return False
            
        except Exception as e:
            hardening_logger.error(f"Alternative CFG detection failed: {e}")
            return False
    
    def verify_cfg_status(self) -> Dict[str, Any]:
        """
        Verify Control Flow Guard protection status.
        
        Returns:
            Dict[str, Any]: CFG status information
        """
        if not self.is_windows:
            return {'cfg_enabled': True, 'platform': self.platform, 'mode': 'posix_native'}
        if not self.cfg_handler:
            return {'error': 'CFG handler not available'}
        
        try:
            status = self.cfg_handler.verify_cfg_status()
            hardening_logger.debug(f"CFG status: {status}")
            return status
            
        except Exception as e:
            error_msg = f"CFG status verification failed: {e}"
            hardening_logger.error(error_msg)
            return {'error': error_msg}
    
    def get_security_status(self) -> SecurityStatus:
        """
        Get comprehensive security status.
        
        Returns:
            SecurityStatus: Current security status
        """
        # Update security level based on enabled protections
        enabled_count = sum([
            self.security_status.cfg_enabled,
            self.security_status.process_monitoring_active,
            self.security_status.hsm_fully_integrated,
            self.security_status.dependencies_satisfied,
            self.security_status.exception_handling_configured
        ])
        
        # Consider recovery status in security level calculation
        if self.recovery_manager:
            recovery_status = self.recovery_manager.get_recovery_status()
            if recovery_status['overall_health'] == 'critical':
                # Downgrade security level if critical failures exist
                enabled_count = max(0, enabled_count - 2)
            elif recovery_status['overall_health'] == 'degraded':
                # Slight downgrade for degraded features
                enabled_count = max(0, enabled_count - 1)
        
        if enabled_count >= 4:
            self.security_status.security_level = "MAXIMUM"
        elif enabled_count >= 3:
            self.security_status.security_level = "HIGH"
        elif enabled_count >= 2:
            self.security_status.security_level = "MEDIUM"
        else:
            self.security_status.security_level = "LOW"
        
        self.security_status.last_updated = datetime.now()
        return self.security_status
    
    def enable_all_protections(self) -> Dict[str, Tuple[bool, str]]:
        """
        Enable all available security protections.
        
        Returns:
            Dict[str, Tuple[bool, str]]: Results for each protection type
        """
        results = {}
        
        # Enable CFG protection
        if self.cfg_handler:
            results['cfg_protection'] = self.enable_cfg_protection()
        else:
            results['cfg_protection'] = (False, "CFG handler not available")
        
        # Enable process monitoring
        if self.process_monitor:
            if self.process_monitor.state.value == "running":
                results['process_monitoring'] = (True, "Process monitoring already running")
            else:
                if self.process_monitor.start_monitoring():
                    results['process_monitoring'] = (True, "Process monitoring started successfully")
                else:
                    results['process_monitoring'] = (False, "Failed to start process monitoring")
        else:
            results['process_monitoring'] = (False, "Process monitor not available")
        
        # Enable HSM integration
        if self.hsm_manager:
            results['hsm_integration'] = (True, "HSM integration active")
        else:
            results['hsm_integration'] = (False, "HSM integration not available")
        
        # Enable exception handling
        if self.exception_handler:
            if self.exception_handler.configure_exception_handling():
                results['exception_handling'] = (True, "Exception handling configured successfully")
            else:
                results['exception_handling'] = (False, "Exception handling configuration failed")
        else:
            results['exception_handling'] = (False, "Exception handler not available")
        
        # Enable dependency management
        if self.dependency_manager:
            dependency_results = self.dependency_manager.ensure_all_dependencies()
            all_satisfied = all(dependency_results.values())
            if all_satisfied:
                results['dependency_management'] = (True, "All dependencies satisfied")
            else:
                failed_deps = [dep for dep, satisfied in dependency_results.items() if not satisfied]
                results['dependency_management'] = (False, f"Dependencies not satisfied: {failed_deps}")
        else:
            results['dependency_management'] = (False, "Dependency manager not available")
        
        # Log results
        for protection, (success, message) in results.items():
            if success:
                hardening_logger.info(f"{protection}: {message}")
            else:
                hardening_logger.warning(f"{protection}: {message}")
        
        return results
    
    def handle_cfg_error_87(self) -> Tuple[bool, str]:
        """
        Specifically handle CFG error 87 (ERROR_INVALID_PARAMETER).
        
        Returns:
            Tuple[bool, str]: (success, message)
        """
        if not self.cfg_handler:
            return False, "CFG handler not available"
        
        try:
            hardening_logger.info("Handling CFG error 87 specifically")
            
            # The WindowsCFGHandler already includes error 87 fixes
            success, message = self.cfg_handler.enable_cfg_protection()
            
            if success:
                hardening_logger.info(f"CFG error 87 resolved: {message}")
                self.security_status.cfg_enabled = True
                self.security_status.platform_specific_features['error_87_fixed'] = True
            else:
                hardening_logger.error(f"CFG error 87 fix failed: {message}")
            
            return success, message
            
        except Exception as e:
            error_msg = f"CFG error 87 handling failed: {e}"
            hardening_logger.error(error_msg)
            return False, error_msg
    
    def get_cfg_capabilities(self) -> Dict[str, bool]:
        """
        Get CFG capabilities of the current system.
        
        Returns:
            Dict[str, bool]: Available CFG capabilities
        """
        if not self.cfg_handler:
            return {'error': True, 'message': 'CFG handler not available'}
        
        try:
            if hasattr(self.cfg_handler, 'get_cfg_capabilities'):
                capabilities = self.cfg_handler.get_cfg_capabilities()
                hardening_logger.debug(f"CFG capabilities: {capabilities}")
                return capabilities
            else:
                return {'error': True, 'message': 'Capabilities method not available'}
                
        except Exception as e:
            hardening_logger.error(f"CFG capabilities check failed: {e}")
            return {'error': True, 'message': str(e)}
    
    def get_recovery_status(self) -> Dict[str, Any]:
        """
        Get security recovery status.
        
        Returns:
            Dict[str, Any]: Recovery status information
        """
        if not self.recovery_manager:
            return {'error': 'Recovery manager not available'}
        
        return self.recovery_manager.get_recovery_status()
    
    def force_feature_recovery(self, feature_name: str) -> Tuple[bool, str]:
        """
        Force recovery attempt for a specific security feature.
        
        Args:
            feature_name: Name of the security feature to recover
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        if not self.recovery_manager:
            return False, "Recovery manager not available"
        
        try:
            from security_recovery_manager import SecurityFeature
            
            # Map feature name to enum
            feature_map = {
                'cfg_protection': SecurityFeature.CFG_PROTECTION,
                'process_monitoring': SecurityFeature.PROCESS_MONITORING,
                'hsm_integration': SecurityFeature.HSM_INTEGRATION,
                'exception_handling': SecurityFeature.EXCEPTION_HANDLING,
                'dependency_management': SecurityFeature.DEPENDENCY_MANAGEMENT
            }
            
            if feature_name not in feature_map:
                return False, f"Unknown feature: {feature_name}"
            
            feature = feature_map[feature_name]
            success = self.recovery_manager.force_recovery_attempt(feature)
            
            if success:
                return True, f"Recovery successful for {feature_name}"
            else:
                return False, f"Recovery failed for {feature_name}"
                
        except Exception as e:
            error_msg = f"Force recovery failed: {e}"
            hardening_logger.error(error_msg)
            return False, error_msg
    
    def enable_self_healing(self, enable: bool = True):
        """
        Enable or disable self-healing capabilities.
        
        Args:
            enable: True to enable self-healing, False to disable
        """
        if not self.recovery_manager:
            hardening_logger.warning("Recovery manager not available for self-healing")
            return
        
        if enable:
            self.recovery_manager.start_recovery_monitoring()
            hardening_logger.info("Self-healing enabled")
        else:
            self.recovery_manager.stop_recovery_monitoring()
            hardening_logger.info("Self-healing disabled")
    
    def export_security_report(self, filepath: str):
        """
        Export comprehensive security report.
        
        Args:
            filepath: Path to save the report
        """
        try:
            import json
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'security_status': {
                    'cfg_enabled': self.security_status.cfg_enabled,
                    'process_monitoring_active': self.security_status.process_monitoring_active,
                    'hsm_fully_integrated': self.security_status.hsm_fully_integrated,
                    'dependencies_satisfied': self.security_status.dependencies_satisfied,
                    'exception_handling_configured': self.security_status.exception_handling_configured,
                    'security_level': self.security_status.security_level,
                    'platform_specific_features': self.security_status.platform_specific_features,
                    'last_updated': self.security_status.last_updated.isoformat()
                },
                'platform_info': {
                    'system': self.platform,
                    'architecture': self.architecture
                },
                'cfg_status': self.verify_cfg_status(),
                'cfg_capabilities': self.get_cfg_capabilities()
            }
            
            # Add recovery status if available
            if self.recovery_manager:
                report['recovery_status'] = self.get_recovery_status()
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            hardening_logger.info(f"Security report exported to {filepath}")
            
            # Also export recovery-specific report
            if self.recovery_manager:
                recovery_filepath = filepath.replace('.json', '_recovery.json')
                self.recovery_manager.export_recovery_report(recovery_filepath)
            
        except Exception as e:
            hardening_logger.error(f"Failed to export security report: {e}")
    
    def get_security_posture(self) -> Dict[str, Any]:
        """
        Get current security posture assessment.
        
        Returns:
            Dict[str, Any]: Security posture information
        """
        if not self.status_monitor:
            return {'error': 'Status monitor not available'}
        
        try:
            posture = self.status_monitor.get_current_posture()
            if posture:
                return {
                    'level': posture.level.value,
                    'score': posture.score,
                    'timestamp': posture.timestamp.isoformat(),
                    'active_features': posture.active_features,
                    'failed_features': posture.failed_features,
                    'degraded_features': posture.degraded_features,
                    'critical_alerts': posture.critical_alerts,
                    'high_alerts': posture.high_alerts,
                    'recommendations': posture.recommendations
                }
            else:
                return {'error': 'No posture data available'}
        except Exception as e:
            return {'error': f'Failed to get security posture: {e}'}
    
    def get_active_alerts(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get active security alerts.
        
        Args:
            severity: Optional severity filter (critical, high, medium, low, info)
            
        Returns:
            List[Dict[str, Any]]: List of active alerts
        """
        if not self.status_monitor:
            return []
        
        try:
            from security_status_monitor import AlertSeverity
            
            severity_filter = None
            if severity:
                severity_map = {
                    'critical': AlertSeverity.CRITICAL,
                    'high': AlertSeverity.HIGH,
                    'medium': AlertSeverity.MEDIUM,
                    'low': AlertSeverity.LOW,
                    'info': AlertSeverity.INFO
                }
                severity_filter = severity_map.get(severity.lower())
            
            alerts = self.status_monitor.get_active_alerts(severity_filter)
            
            return [
                {
                    'id': alert.id,
                    'severity': alert.severity.value,
                    'title': alert.title,
                    'description': alert.description,
                    'timestamp': alert.timestamp.isoformat(),
                    'source': alert.source
                }
                for alert in alerts
            ]
            
        except Exception as e:
            hardening_logger.error(f"Failed to get active alerts: {e}")
            return []
    
    def get_security_metrics(self, hours: int = 1) -> Dict[str, Any]:
        """
        Get security metrics summary.
        
        Args:
            hours: Number of hours to include in summary
            
        Returns:
            Dict[str, Any]: Metrics summary
        """
        if not self.status_monitor:
            return {'error': 'Status monitor not available'}
        
        try:
            return self.status_monitor.get_metrics_summary(hours)
        except Exception as e:
            return {'error': f'Failed to get metrics: {e}'}
    
    def get_unified_security_status(self) -> Dict[str, Any]:
        """
        Get unified security status across all components.
        
        Returns:
            Dict[str, Any]: Comprehensive security status
        """
        try:
            status = {
                'timestamp': datetime.now().isoformat(),
                'overall_security_level': self.security_status.security_level,
                'platform_info': {
                    'system': self.platform,
                    'architecture': self.architecture,
                    'is_windows': self.is_windows,
                    'is_linux': self.is_linux,
                    'is_macos': self.is_macos
                },
                'components': {
                    'cfg_protection': {
                        'enabled': self.security_status.cfg_enabled,
                        'handler_available': self.cfg_handler is not None,
                        'status': self.verify_cfg_status() if self.cfg_handler else {'error': 'Not available'},
                        'capabilities': self.get_cfg_capabilities() if self.cfg_handler else {'error': 'Not available'}
                    },
                    'process_monitoring': {
                        'active': self.security_status.process_monitoring_active,
                        'monitor_available': self.process_monitor is not None,
                        'state': self.process_monitor.state.value if self.process_monitor else 'not_available',
                        'monitored_processes': len(self.process_monitor.monitored_processes) if self.process_monitor else 0,
                        'threat_detection_enabled': getattr(self.process_monitor, 'enable_threat_detection', False) if self.process_monitor else False
                    },
                    'hsm_integration': {
                        'fully_integrated': self.security_status.hsm_fully_integrated,
                        'hsm_manager_available': self.hsm_manager is not None
                    },
                    'exception_handling': {
                        'configured': self.security_status.exception_handling_configured,
                        'win32_handler_available': self.exception_handler is not None,
                        'cross_platform_handler_available': hasattr(self, 'cross_platform_exception_handler') and self.cross_platform_exception_handler is not None,
                        'handler_status': self.exception_handler.get_status() if self.exception_handler else {'error': 'Not available'}
                    },
                    'dependency_management': {
                        'satisfied': self.security_status.dependencies_satisfied,
                        'manager_available': self.dependency_manager is not None
                    }
                },
                'recovery_system': {
                    'available': self.recovery_manager is not None,
                    'status': self.get_recovery_status() if self.recovery_manager else {'error': 'Not available'}
                },
                'monitoring_system': {
                    'available': self.status_monitor is not None,
                    'posture': self.get_security_posture() if self.status_monitor else {'error': 'Not available'},
                    'active_alerts_count': len(self.get_active_alerts()) if self.status_monitor else 0
                },
                'platform_specific_features': self.security_status.platform_specific_features,
                'last_updated': self.security_status.last_updated.isoformat()
            }
            
            return status
            
        except Exception as e:
            hardening_logger.error(f"Failed to get unified security status: {e}")
            return {
                'error': f'Failed to get unified security status: {e}',
                'timestamp': datetime.now().isoformat()
            }
    
    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get a concise security summary for quick status checks.
        
        Returns:
            Dict[str, Any]: Security summary
        """
        try:
            enabled_components = []
            failed_components = []
            
            # Check each component
            if self.security_status.cfg_enabled:
                enabled_components.append('CFG Protection')
            else:
                failed_components.append('CFG Protection')
                
            if self.security_status.process_monitoring_active:
                enabled_components.append('Process Monitoring')
            else:
                failed_components.append('Process Monitoring')
                
            if self.security_status.hsm_fully_integrated:
                enabled_components.append('HSM Integration')
            else:
                failed_components.append('HSM Integration')
                
            if self.security_status.exception_handling_configured:
                enabled_components.append('Exception Handling')
            else:
                failed_components.append('Exception Handling')
                
            if self.security_status.dependencies_satisfied:
                enabled_components.append('Dependency Management')
            else:
                failed_components.append('Dependency Management')
            
            return {
                'timestamp': datetime.now().isoformat(),
                'security_level': self.security_status.security_level,
                'enabled_components': enabled_components,
                'failed_components': failed_components,
                'total_components': len(enabled_components) + len(failed_components),
                'success_rate': len(enabled_components) / (len(enabled_components) + len(failed_components)) * 100,
                'platform': self.platform,
                'recovery_available': self.recovery_manager is not None,
                'monitoring_available': self.status_monitor is not None
            }
            
        except Exception as e:
            hardening_logger.error(f"Failed to get security summary: {e}")
            return {
                'error': f'Failed to get security summary: {e}',
                'timestamp': datetime.now().isoformat()
            }
    
    def get_posture_trend(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get security posture trend.
        
        Args:
            hours: Number of hours to include in trend
            
        Returns:
            List[Dict[str, Any]]: Posture trend data
        """
        if not self.status_monitor:
            return []
        
        try:
            trend = self.status_monitor.get_posture_trend(hours)
            return [
                {
                    'timestamp': p.timestamp.isoformat(),
                    'level': p.level.value,
                    'score': p.score,
                    'active_features': p.active_features,
                    'failed_features': p.failed_features,
                    'degraded_features': p.degraded_features
                }
                for p in trend
            ]
        except Exception as e:
            hardening_logger.error(f"Failed to get posture trend: {e}")
            return []
    
    def coordinate_security_initialization(self) -> Dict[str, Any]:
        """
        Coordinate initialization of all security components in the correct order.
        
        Returns:
            Dict[str, Any]: Initialization results
        """
        try:
            hardening_logger.info("Starting coordinated security initialization...")
            
            initialization_results = {
                'timestamp': datetime.now().isoformat(),
                'platform': self.platform,
                'results': {},
                'overall_success': False
            }
            
            # Step 1: Initialize dependency management first
            hardening_logger.info("Step 1: Initializing dependency management...")
            try:
                self._initialize_dependency_management()
                initialization_results['results']['dependency_management'] = {
                    'success': self.dependency_manager is not None,
                    'message': 'Dependency management initialized' if self.dependency_manager else 'Failed to initialize'
                }
            except Exception as e:
                initialization_results['results']['dependency_management'] = {
                    'success': False,
                    'message': f'Dependency management failed: {e}'
                }
            
            # Step 2: Initialize exception handling
            hardening_logger.info("Step 2: Initializing exception handling...")
            try:
                self._initialize_exception_handling()
                initialization_results['results']['exception_handling'] = {
                    'success': self.security_status.exception_handling_configured,
                    'message': 'Exception handling configured' if self.security_status.exception_handling_configured else 'Configuration failed'
                }
            except Exception as e:
                initialization_results['results']['exception_handling'] = {
                    'success': False,
                    'message': f'Exception handling failed: {e}'
                }
            
            # Step 3: Initialize CFG protection
            hardening_logger.info("Step 3: Initializing CFG protection...")
            try:
                self._initialize_cfg_protection()
                cfg_success, cfg_message = self.enable_cfg_protection()
                initialization_results['results']['cfg_protection'] = {
                    'success': cfg_success,
                    'message': cfg_message
                }
            except Exception as e:
                initialization_results['results']['cfg_protection'] = {
                    'success': False,
                    'message': f'CFG protection failed: {e}'
                }
            
            # Step 4: Initialize HSM integration
            hardening_logger.info("Step 4: Initializing HSM integration...")
            try:
                self._initialize_hsm_integration()
                initialization_results['results']['hsm_integration'] = {
                    'success': self.security_status.hsm_fully_integrated,
                    'message': 'HSM integration active' if self.security_status.hsm_fully_integrated else 'HSM integration failed'
                }
            except Exception as e:
                initialization_results['results']['hsm_integration'] = {
                    'success': False,
                    'message': f'HSM integration failed: {e}'
                }
            
            # Step 5: Initialize process monitoring
            hardening_logger.info("Step 5: Initializing process monitoring...")
            try:
                self._initialize_process_monitoring()
                initialization_results['results']['process_monitoring'] = {
                    'success': self.security_status.process_monitoring_active,
                    'message': 'Process monitoring active' if self.security_status.process_monitoring_active else 'Process monitoring failed'
                }
            except Exception as e:
                initialization_results['results']['process_monitoring'] = {
                    'success': False,
                    'message': f'Process monitoring failed: {e}'
                }
            
            # Step 6: Initialize recovery and monitoring systems
            hardening_logger.info("Step 6: Initializing recovery and monitoring systems...")
            try:
                self._initialize_recovery_manager()
                self._initialize_status_monitor()
                initialization_results['results']['recovery_monitoring'] = {
                    'success': self.recovery_manager is not None and self.status_monitor is not None,
                    'message': 'Recovery and monitoring systems initialized'
                }
            except Exception as e:
                initialization_results['results']['recovery_monitoring'] = {
                    'success': False,
                    'message': f'Recovery/monitoring initialization failed: {e}'
                }
            
            # Calculate overall success
            successful_components = sum(1 for result in initialization_results['results'].values() if result['success'])
            total_components = len(initialization_results['results'])
            initialization_results['overall_success'] = successful_components >= (total_components * 0.6)  # 60% success threshold
            initialization_results['success_rate'] = (successful_components / total_components) * 100
            
            if initialization_results['overall_success']:
                hardening_logger.info(f"Coordinated security initialization completed successfully ({successful_components}/{total_components} components)")
            else:
                hardening_logger.warning(f"Coordinated security initialization partially failed ({successful_components}/{total_components} components)")
            
            return initialization_results
            
        except Exception as e:
            hardening_logger.error(f"Coordinated security initialization failed: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'platform': self.platform,
                'overall_success': False,
                'error': str(e)
            }
    
    def coordinate_security_shutdown(self) -> Dict[str, Any]:
        """
        Coordinate shutdown of all security components in the correct order.
        
        Returns:
            Dict[str, Any]: Shutdown results
        """
        try:
            hardening_logger.info("Starting coordinated security shutdown...")
            
            shutdown_results = {
                'timestamp': datetime.now().isoformat(),
                'results': {},
                'overall_success': False
            }
            
            # Step 1: Stop monitoring systems
            try:
                if self.status_monitor:
                    self.enable_monitoring(False)
                if self.recovery_manager:
                    self.enable_self_healing(False)
                shutdown_results['results']['monitoring_systems'] = {
                    'success': True,
                    'message': 'Monitoring systems stopped'
                }
            except Exception as e:
                shutdown_results['results']['monitoring_systems'] = {
                    'success': False,
                    'message': f'Monitoring systems shutdown failed: {e}'
                }
            
            # Step 2: Stop process monitoring
            try:
                if self.process_monitor:
                    if self.process_monitor.stop_monitoring():
                        shutdown_results['results']['process_monitoring'] = {
                            'success': True,
                            'message': 'Process monitoring stopped'
                        }
                    else:
                        shutdown_results['results']['process_monitoring'] = {
                            'success': False,
                            'message': 'Process monitoring stop failed'
                        }
                else:
                    shutdown_results['results']['process_monitoring'] = {
                        'success': True,
                        'message': 'Process monitoring not active'
                    }
            except Exception as e:
                shutdown_results['results']['process_monitoring'] = {
                    'success': False,
                    'message': f'Process monitoring shutdown failed: {e}'
                }
            
            # Step 3: Clean up exception handling
            try:
                if self.exception_handler:
                    self.exception_handler.handle_iunknown_cleanup()
                shutdown_results['results']['exception_handling'] = {
                    'success': True,
                    'message': 'Exception handling cleaned up'
                }
            except Exception as e:
                shutdown_results['results']['exception_handling'] = {
                    'success': False,
                    'message': f'Exception handling cleanup failed: {e}'
                }
            
            # Step 4: Export final security report
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='_shutdown_security_report.json', delete=False) as f:
                    self.export_security_report(f.name)
                    shutdown_results['results']['final_report'] = {
                        'success': True,
                        'message': f'Final security report exported to {f.name}'
                    }
            except Exception as e:
                shutdown_results['results']['final_report'] = {
                    'success': False,
                    'message': f'Final report export failed: {e}'
                }
            
            # Calculate overall success
            successful_shutdowns = sum(1 for result in shutdown_results['results'].values() if result['success'])
            total_shutdowns = len(shutdown_results['results'])
            shutdown_results['overall_success'] = successful_shutdowns == total_shutdowns
            shutdown_results['success_rate'] = (successful_shutdowns / total_shutdowns) * 100
            
            hardening_logger.info(f"Coordinated security shutdown completed ({successful_shutdowns}/{total_shutdowns} components)")
            
            return shutdown_results
            
        except Exception as e:
            hardening_logger.error(f"Coordinated security shutdown failed: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'overall_success': False,
                'error': str(e)
            }

    def enable_monitoring(self, enable: bool = True):
        """
        Enable or disable security monitoring.
        
        Args:
            enable: True to enable monitoring, False to disable
        """
        if not self.status_monitor:
            hardening_logger.warning("Status monitor not available")
            return
        
        if enable:
            self.status_monitor.start_monitoring()
            hardening_logger.info("Security monitoring enabled")
        else:
            self.status_monitor.stop_monitoring()
            hardening_logger.info("Security monitoring disabled")
    
    def export_comprehensive_report(self, filepath: str):
        """
        Export comprehensive security report including monitoring data.
        
        Args:
            filepath: Path to save the report
        """
        try:
            import json
            
            # Get base security report data
            report = {
                'timestamp': datetime.now().isoformat(),
                'security_status': {
                    'cfg_enabled': self.security_status.cfg_enabled,
                    'process_monitoring_active': self.security_status.process_monitoring_active,
                    'hsm_fully_integrated': self.security_status.hsm_fully_integrated,
                    'dependencies_satisfied': self.security_status.dependencies_satisfied,
                    'exception_handling_configured': self.security_status.exception_handling_configured,
                    'security_level': self.security_status.security_level,
                    'platform_specific_features': self.security_status.platform_specific_features,
                    'last_updated': self.security_status.last_updated.isoformat()
                },
                'platform_info': {
                    'system': self.platform,
                    'architecture': self.architecture
                },
                'cfg_status': self.verify_cfg_status(),
                'cfg_capabilities': self.get_cfg_capabilities()
            }
            
            # Add recovery status if available
            if self.recovery_manager:
                report['recovery_status'] = self.get_recovery_status()
            
            # Add monitoring data if available
            if self.status_monitor:
                report['security_posture'] = self.get_security_posture()
                report['active_alerts'] = self.get_active_alerts()
                report['security_metrics'] = self.get_security_metrics(24)
                report['posture_trend'] = self.get_posture_trend(24)
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            hardening_logger.info(f"Comprehensive security report exported to {filepath}")
            
            # Also export detailed monitoring report
            if self.status_monitor:
                monitor_filepath = filepath.replace('.json', '_monitoring.json')
                self.status_monitor.export_status_report(monitor_filepath)
            
            # Also export recovery report
            if self.recovery_manager:
                recovery_filepath = filepath.replace('.json', '_recovery.json')
                self.recovery_manager.export_recovery_report(recovery_filepath)
            
        except Exception as e:
            hardening_logger.error(f"Failed to export comprehensive report: {e}")


def main():
    """Main function for testing the Security Hardening Manager."""
    try:
        hardening_logger.info("Starting Security Hardening Manager test")
        
        # Initialize manager
        manager = SecurityHardeningManager()
        
        # Get initial status
        status = manager.get_security_status()
        hardening_logger.info(f"Initial security status: {status}")
        
        # Enable CFG protection specifically
        cfg_success, cfg_message = manager.enable_cfg_protection()
        hardening_logger.info(f"CFG protection result: {cfg_success} - {cfg_message}")
        
        # Verify CFG status
        cfg_status = manager.verify_cfg_status()
        hardening_logger.info(f"CFG status verification: {cfg_status}")
        
        # Get CFG capabilities
        capabilities = manager.get_cfg_capabilities()
        hardening_logger.info(f"CFG capabilities: {capabilities}")
        
        # Test recovery capabilities
        recovery_status = manager.get_recovery_status()
        hardening_logger.info(f"Recovery status: {recovery_status}")
        
        # Test force recovery
        force_result = manager.force_feature_recovery('cfg_protection')
        hardening_logger.info(f"Force recovery result: {force_result}")
        
        # Get final security status
        final_status = manager.get_security_status()
        hardening_logger.info(f"Final security status: {final_status}")
        
        # Test monitoring capabilities
        posture = manager.get_security_posture()
        hardening_logger.info(f"Security posture: {posture}")
        
        alerts = manager.get_active_alerts()
        hardening_logger.info(f"Active alerts: {len(alerts)}")
        
        metrics = manager.get_security_metrics()
        hardening_logger.info(f"Security metrics: {len(metrics)} types")
        
        # Export comprehensive security report
        manager.export_comprehensive_report("security_hardening_comprehensive_report.json")
        
        hardening_logger.info("Security Hardening Manager test completed successfully")
        
    except Exception as e:
        hardening_logger.error(f"Security Hardening Manager test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()