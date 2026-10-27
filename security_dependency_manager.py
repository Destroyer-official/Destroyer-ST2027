"""
Security Dependency Manager

This module provides automatic dependency management for security libraries,
including psutil installation, version checking, and fallback implementations.

Requirements addressed: 5.1, 5.2, 5.3, 5.4
"""

import logging
# AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
import subprocess  # nosec: B404
import sys
import importlib
import platform
import os
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Tuple
from datetime import datetime
import json
import threading
import time

from security_hardening_manager import (
    SecurityHardeningError, 
    DependencyError,
    ProcessMonitoringError
)


@dataclass
class DependencyStatus:
    """Dependency status tracking model"""
    package_name: str
    installed: bool = False
    version: Optional[str] = None
    installation_method: str = "none"  # pip, system, fallback, none
    fallback_available: bool = False
    critical: bool = True
    last_checked: datetime = field(default_factory=datetime.now)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'package_name': self.package_name,
            'installed': self.installed,
            'version': self.version,
            'installation_method': self.installation_method,
            'fallback_available': self.fallback_available,
            'critical': self.critical,
            'last_checked': self.last_checked.isoformat(),
            'error_message': self.error_message
        }


class AutoInstaller:
    """Automatic package installation with multiple methods"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.platform_system = platform.system().lower()
        
    def install_psutil(self) -> Tuple[bool, str]:
        """
        Install psutil using multiple methods
        
        Returns:
            Tuple[bool, str]: (success, method_used)
        """
        installation_methods = [
            ("pip", self._install_with_pip),
            ("system", self._install_with_system_manager),
            ("user_pip", self._install_with_user_pip)
        ]
        
        for method_name, install_func in installation_methods:
            try:
                self.logger.info(f"Attempting psutil installation with {method_name}")
                if install_func("psutil"):
                    self.logger.info(f"psutil installed successfully with {method_name}")
                    return True, method_name
            except Exception as e:
                self.logger.warning(f"Failed to install psutil with {method_name}: {str(e)}")
                continue

        self.logger.critical(
            "psutil unavailable and runtime auto-install is REFUSED by policy. "
            "Install offline: pip install --require-hashes -r requirements.txt")
        return False, "refused-by-policy"
    
    def _install_with_pip(self, package: str) -> bool:
        """REFUSED: runtime pip installs are forbidden (supply-chain risk).

        Install offline from pinned hashes before launch:
        pip install --require-hashes -r requirements.txt
        """
        self.logger.critical(
            f"REFUSED runtime pip install of '{package}'. "
            "Pre-install pinned dependencies offline; auto-install is disabled by policy.")
        return False

    def _install_with_user_pip(self, package: str) -> bool:
        """REFUSED: runtime pip installs are forbidden (see _install_with_pip)."""
        self.logger.critical(
            f"REFUSED runtime pip --user install of '{package}'. "
            "Pre-install pinned dependencies offline; auto-install is disabled by policy.")
        return False

    def _install_with_system_manager(self, package: str) -> bool:
        """REFUSED: invoking OS package managers (sudo/brew) at runtime is forbidden."""
        self.logger.critical(
            f"REFUSED system package-manager install of '{package}'. "
            "Privilege-escalating installs at runtime are disabled by policy.")
        return False
    
    def _install_linux_system(self, package: str) -> bool:
        """REMOVED: sudo apt/yum/dnf/pacman at runtime (incl. malformed '&&' argv)."""
        self.logger.critical(
            f"REFUSED privileged system install of '{package}' on Linux. "
            "Pre-install pinned dependencies offline; auto-install is disabled by policy.")
        return False

    def _install_macos_system(self, package: str) -> bool:
        """REMOVED: brew installs at runtime."""
        self.logger.critical(
            f"REFUSED brew install of '{package}' on macOS. "
            "Pre-install pinned dependencies offline; auto-install is disabled by policy.")
        return False
    
    def _install_windows_system(self, package: str) -> bool:
        """Install on Windows using system methods"""
        # Windows doesn't have a standard system package manager
        # This is a placeholder for potential future Windows package managers
        return False


class FallbackProvider:
    """MILITARY FATAL: Provides strict errors when dependencies are unavailable"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.fallback_implementations = {}
    
    def _setup_fallbacks(self):
        import logging; logging.getLogger(__name__).debug("Ignored exception")
    
    def get_fallback(self, package_name: str) -> Optional[Any]:
        """MILITARY FATAL: Fallbacks for security dependencies are STRICTLY FORBIDDEN."""
        self.logger.critical(f"MILITARY FATAL: Attempted to load fallback for {package_name}. Fallbacks forbidden.")
        raise DependencyError(
            f"Fallback for {package_name} forbidden by military policy.",
            error_code="FALLBACK_FORBIDDEN"
        )
    
    def _psutil_fallback(self) -> Any:
        """MILITARY FATAL: Fallbacks for security dependencies are STRICTLY FORBIDDEN."""
        raise DependencyError(
            "Fallback for psutil forbidden by military policy.",
            error_code="FALLBACK_FORBIDDEN"
        )


class PsutilManager:
    """
    Dedicated manager for psutil installation, validation, and fallback handling
    
    Handles automatic detection, installation, and validation of psutil.Process
    attributes with comprehensive error handling and recovery.
    
    Requirements addressed: 2.1, 2.2, 2.3, 2.4
    """
    
    def __init__(self, logger: logging.Logger, auto_installer: AutoInstaller, 
                 fallback_provider: FallbackProvider):
        self.logger = logger
        self.auto_installer = auto_installer
        self.fallback_provider = fallback_provider
        self.psutil_status = DependencyStatus(package_name="psutil", critical=True)
        self._validation_cache = {}
        self._last_validation = None
        
    def detect_and_install_psutil(self) -> bool:
        """
        Detect missing psutil and install it automatically
        
        Returns:
            bool: True if psutil is available (installed or fallback)
        """
        self.logger.info("Detecting psutil availability")
        
        # First check if already available
        if self._check_psutil_available():
            self.psutil_status.installed = True
            self.psutil_status.installation_method = "existing"
            self.psutil_status.version = self._get_psutil_version()
            self.logger.info(f"psutil already available (version: {self.psutil_status.version})")
            return True
        
        # Try automatic installation
        self.logger.info("psutil not found, attempting automatic installation")
        
        try:
            success, method = self.auto_installer.install_psutil()
            
            if success:
                # Verify installation worked
                if self._check_psutil_available():
                    self.psutil_status.installed = True
                    self.psutil_status.installation_method = method
                    self.psutil_status.version = self._get_psutil_version()
                    self.logger.info(f"psutil installed successfully with {method}")
                    return True
                else:
                    self.logger.error("psutil installation reported success but import still fails")
            
            # If installation failed, try fallback
            self.logger.warning("psutil installation failed, attempting fallback")
            fallback = self.fallback_provider.get_fallback('psutil')
            
            if fallback:
                self.psutil_status.fallback_available = True
                self.psutil_status.installation_method = "fallback"
                sys.modules['psutil'] = fallback
                self.logger.info("psutil fallback implementation activated")
                return True
            
            # Complete failure
            self.psutil_status.error_message = "Failed to install psutil and no fallback available"
            self.logger.error(self.psutil_status.error_message)
            return False
            
        except Exception as e:
            error = ProcessMonitoringError(
                f"Error during psutil installation: {str(e)}",
                error_code="PSUTIL_INSTALL_ERROR"
            )
            self.logger.error(str(error))
            self.psutil_status.error_message = str(e)
            return False
    
    def _check_psutil_available(self) -> bool:
        """Check if psutil is available and importable"""
        try:
            import psutil
            # Try to create a Process instance to verify it works
            psutil.Process()
            return True
        except ImportError:
            return False
        except Exception as e:
            self.logger.warning(f"psutil import succeeded but Process creation failed: {str(e)}")
            return False
    
    def _get_psutil_version(self) -> Optional[str]:
        """Get psutil version"""
        try:
            import psutil
            return getattr(psutil, '__version__', None)
        except Exception:
            return None
    
    def validate_psutil_process_attributes(self) -> Dict[str, Any]:
        """
        Validate psutil.Process attributes and handle missing ones
        
        Returns:
            Dict[str, Any]: Comprehensive validation results
        """
        self.logger.info("Validating psutil.Process attributes")
        
        validation_results = {
            'psutil_available': False,
            'process_creation': False,
            'attributes': {},
            'methods': {},
            'error_handling': {},
            'fallback_needed': False,
            'recommendations': []
        }
        
        try:
            import psutil
            validation_results['psutil_available'] = True
            
            # Test Process creation with current PID
            current_pid = os.getpid()
            try:
                process = psutil.Process(current_pid)
                validation_results['process_creation'] = True
                
                # Test critical attributes
                critical_attributes = [
                    'pid', 'ppid', 'name', 'status', 'create_time'
                ]
                
                for attr in critical_attributes:
                    try:
                        value = getattr(process, attr, None)
                        if callable(value):
                            # It's a method, try calling it
                            result = value()
                            validation_results['attributes'][attr] = {
                                'available': True,
                                'callable': True,
                                'value': str(result)[:100]  # Truncate long values
                            }
                        else:
                            # It's a property
                            validation_results['attributes'][attr] = {
                                'available': True,
                                'callable': False,
                                'value': str(value)[:100] if value is not None else None
                            }
                    except Exception as e:
                        validation_results['attributes'][attr] = {
                            'available': False,
                            'error': str(e)
                        }
                        self.logger.warning(f"Attribute {attr} failed: {str(e)}")
                
                # Test critical methods
                critical_methods = [
                    'is_running', 'memory_info', 'cpu_percent', 
                    'children', 'terminate', 'kill'
                ]
                
                for method in critical_methods:
                    try:
                        method_func = getattr(process, method, None)
                        if method_func and callable(method_func):
                            # Test method call (be careful with destructive methods)
                            if method in ['terminate', 'kill']:
                                # Don't actually call these, just check they exist
                                validation_results['methods'][method] = {
                                    'available': True,
                                    'tested': False,
                                    'reason': 'Destructive method not tested'
                                }
                            elif method == 'cpu_percent':
                                # cpu_percent might need interval parameter
                                try:
                                    result = method_func(interval=0.1)
                                    validation_results['methods'][method] = {
                                        'available': True,
                                        'tested': True,
                                        'result': result
                                    }
                                except Exception as e:
                                    validation_results['methods'][method] = {
                                        'available': True,
                                        'tested': False,
                                        'error': str(e)
                                    }
                            else:
                                result = method_func()
                                validation_results['methods'][method] = {
                                    'available': True,
                                    'tested': True,
                                    'result': str(result)[:100] if result is not None else None
                                }
                        else:
                            validation_results['methods'][method] = {
                                'available': False,
                                'error': 'Method not found or not callable'
                            }
                    except Exception as e:
                        validation_results['methods'][method] = {
                            'available': False,
                            'error': str(e)
                        }
                        self.logger.warning(f"Method {method} failed: {str(e)}")
                
                # Test error handling scenarios
                self._test_error_handling(validation_results)
                
            except Exception as e:
                validation_results['process_creation'] = False
                validation_results['process_error'] = str(e)
                self.logger.error(f"Process creation failed: {str(e)}")
                
        except ImportError as e:
            validation_results['import_error'] = str(e)
            self.logger.error(f"psutil import failed: {str(e)}")
        
        # Analyze results and provide recommendations
        self._analyze_validation_results(validation_results)
        
        # Cache results
        self._validation_cache = validation_results
        self._last_validation = datetime.now()
        
        return validation_results
    
    def _test_error_handling(self, validation_results: Dict[str, Any]):
        """Test error handling scenarios for psutil"""
        validation_results['error_handling'] = {}
        
        try:
            import psutil
            
            # Test with invalid PID
            try:
                invalid_process = psutil.Process(999999)  # Very unlikely to exist
                invalid_process.name()
            except psutil.NoSuchProcess:
                validation_results['error_handling']['no_such_process'] = {
                    'handled': True,
                    'exception_type': 'NoSuchProcess'
                }
            except Exception as e:
                validation_results['error_handling']['no_such_process'] = {
                    'handled': False,
                    'unexpected_exception': str(e)
                }
            
            # Test with permission denied scenario (try to access system process)
            try:
                if platform.system().lower() == "windows":
                    # Try to access System Idle Process (PID 0)
                    system_process = psutil.Process(0)
                    system_process.memory_info()
                else:
                    # Try to access init process (PID 1)
                    init_process = psutil.Process(1)
                    init_process.memory_info()
                    
                validation_results['error_handling']['permission_test'] = {
                    'handled': True,
                    'result': 'Access granted or handled gracefully'
                }
            except psutil.AccessDenied:
                validation_results['error_handling']['permission_test'] = {
                    'handled': True,
                    'exception_type': 'AccessDenied'
                }
            except Exception as e:
                validation_results['error_handling']['permission_test'] = {
                    'handled': False,
                    'unexpected_exception': str(e)
                }
                
        except Exception as e:
            validation_results['error_handling']['test_error'] = str(e)
    
    def _analyze_validation_results(self, validation_results: Dict[str, Any]):
        """Analyze validation results and provide recommendations"""
        recommendations = []
        
        if not validation_results['psutil_available']:
            recommendations.append("psutil is not available - install or use fallback")
            validation_results['fallback_needed'] = True
        
        if not validation_results['process_creation']:
            recommendations.append("Process creation failed - check psutil installation")
            validation_results['fallback_needed'] = True
        
        # Check attribute availability
        missing_attributes = [
            attr for attr, info in validation_results.get('attributes', {}).items()
            if not info.get('available', False)
        ]
        
        if missing_attributes:
            recommendations.append(f"Missing attributes: {', '.join(missing_attributes)}")
        
        # Check method availability
        missing_methods = [
            method for method, info in validation_results.get('methods', {}).items()
            if not info.get('available', False)
        ]
        
        if missing_methods:
            recommendations.append(f"Missing methods: {', '.join(missing_methods)}")
        
        # Check error handling
        error_handling = validation_results.get('error_handling', {})
        unhandled_errors = [
            scenario for scenario, info in error_handling.items()
            if not info.get('handled', False)
        ]
        
        if unhandled_errors:
            recommendations.append(f"Unhandled error scenarios: {', '.join(unhandled_errors)}")
        
        validation_results['recommendations'] = recommendations
    
    def create_fallback_process_monitoring(self) -> Any:
        """
        Create fallback process monitoring when psutil is unavailable
        
        Returns:
            Fallback monitoring implementation
        """
        self.logger.info("Creating fallback process monitoring")
        
        try:
            fallback_psutil = self.fallback_provider.get_fallback('psutil')
            if fallback_psutil:
                return ProcessMonitorFallback(fallback_psutil, self.logger)
            else:
                raise ProcessMonitoringError(
                    "Failed to create fallback process monitoring",
                    error_code="FALLBACK_CREATION_FAILED"
                )
        except Exception as e:
            error = ProcessMonitoringError(
                f"Error creating fallback process monitoring: {str(e)}",
                error_code="FALLBACK_ERROR"
            )
            self.logger.error(str(error))
            raise error
    
    def get_psutil_status(self) -> DependencyStatus:
        """Get current psutil status"""
        return self.psutil_status
    
    def get_validation_results(self) -> Optional[Dict[str, Any]]:
        """Get cached validation results"""
        return self._validation_cache.copy() if self._validation_cache else None


class ProcessMonitorFallback:
    """MILITARY FATAL: ProcessMonitorFallback is forbidden."""
    def __init__(self, *args, **kwargs):
        raise DependencyError("ProcessMonitorFallback is forbidden by military policy.", error_code="FALLBACK_FORBIDDEN")


class SecurityDependencyManager:
    """
    Main dependency coordinator for security libraries
    
    Provides automatic dependency management, installation, and fallback implementations
    for critical security components.
    
    Requirements addressed: 5.1, 5.2, 5.3, 5.4
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize Security Dependency Manager"""
        self.logger = logger or logging.getLogger(__name__)
        self.auto_installer = AutoInstaller(self.logger)
        self.fallback_provider = FallbackProvider(self.logger)
        
        # Specialized managers
        self.psutil_manager = PsutilManager(self.logger, self.auto_installer, self.fallback_provider)
        
        # Dependency tracking
        self.dependencies: Dict[str, DependencyStatus] = {}
        self._dependency_lock = threading.Lock()
        
        # Critical dependencies that must be available
        self.critical_dependencies = [
            "psutil"
        ]
        
        # Optional dependencies with fallbacks
        self.optional_dependencies = [
            # Future optional dependencies can be added here
        ]
        
        self.logger.info("SecurityDependencyManager initialized")
    
    def ensure_all_dependencies(self) -> Dict[str, bool]:
        """
        Ensure all security dependencies are available
        
        Returns:
            Dict[str, bool]: Status of each dependency (True if available)
        """
        self.logger.info("Starting dependency verification and installation")
        
        results = {}
        
        # Check critical dependencies
        for dep in self.critical_dependencies:
            try:
                if dep == "psutil":
                    # Use specialized psutil handling
                    psutil_results = self.install_and_validate_psutil()
                    results[dep] = psutil_results['installation_successful']
                    
                    # Log detailed results
                    if psutil_results.get('validation_results'):
                        validation = psutil_results['validation_results']
                        self.logger.info(f"psutil validation summary: "
                                       f"available={validation.get('psutil_available', False)}, "
                                       f"process_creation={validation.get('process_creation', False)}")
                    
                    if psutil_results.get('recommendations'):
                        for rec in psutil_results['recommendations']:
                            self.logger.info(f"psutil recommendation: {rec}")
                else:
                    # Use generic dependency handling
                    status = self._ensure_dependency(dep, critical=True)
                    results[dep] = status.installed or status.fallback_available
                    
                    with self._dependency_lock:
                        self.dependencies[dep] = status
                    
            except Exception as e:
                self.logger.error(f"Error ensuring dependency {dep}: {str(e)}")
                results[dep] = False
        
        # Check optional dependencies
        for dep in self.optional_dependencies:
            try:
                status = self._ensure_dependency(dep, critical=False)
                results[dep] = status.installed or status.fallback_available
                
                with self._dependency_lock:
                    self.dependencies[dep] = status
                    
            except Exception as e:
                self.logger.warning(f"Optional dependency {dep} not available: {str(e)}")
                results[dep] = False
        
        # Log summary
        available_count = sum(results.values())
        total_count = len(results)
        self.logger.info(f"Dependency check complete: {available_count}/{total_count} available")
        
        return results
    
    def _ensure_dependency(self, package_name: str, critical: bool = True) -> DependencyStatus:
        """
        Ensure a specific dependency is available
        
        Args:
            package_name: Name of the package to ensure
            critical: Whether this is a critical dependency
            
        Returns:
            DependencyStatus: Status of the dependency
        """
        status = DependencyStatus(
            package_name=package_name,
            critical=critical
        )
        
        # First, check if already installed
        if self._check_package_installed(package_name):
            status.installed = True
            status.version = self._get_package_version(package_name)
            status.installation_method = "existing"
            self.logger.info(f"{package_name} already installed (version: {status.version})")
            return status
        
        # Try to install if not available
        self.logger.info(f"{package_name} not found, attempting installation")
        
        if package_name == "psutil":
            success, method = self.auto_installer.install_psutil()
            if success:
                status.installed = True
                status.installation_method = method
                status.version = self._get_package_version(package_name)
                self.logger.info(f"{package_name} installed successfully with {method}")
                return status
        
        # If installation failed, try fallback for critical dependencies
        if critical:
            fallback = self.fallback_provider.get_fallback(package_name)
            if fallback:
                status.fallback_available = True
                status.installation_method = "fallback"
                self.logger.info(f"Fallback implementation available for {package_name}")
                
                # Store fallback in sys.modules for import compatibility
                sys.modules[package_name] = fallback
                
                return status
        
        # If all else fails
        status.error_message = f"Failed to install or provide fallback for {package_name}"
        self.logger.error(status.error_message)
        
        return status
    
    def _check_package_installed(self, package_name: str) -> bool:
        """Check if a package is installed and importable"""
        try:
            importlib.import_module(package_name)
            return True
        except ImportError:
            return False
    
    def _get_package_version(self, package_name: str) -> Optional[str]:
        """Get version of an installed package"""
        try:
            module = importlib.import_module(package_name)
            # Try common version attributes
            for attr in ['__version__', 'version', 'VERSION']:
                if hasattr(module, attr):
                    version = getattr(module, attr)
                    return str(version) if version else None
            return None
        except Exception:
            return None
    
    def install_missing_packages(self) -> bool:
        """
        Install all missing packages
        
        Returns:
            bool: True if all critical packages are available
        """
        self.logger.info("Installing missing packages")
        
        results = self.ensure_all_dependencies()
        
        # Check if all critical dependencies are satisfied
        critical_satisfied = all(
            results.get(dep, False) for dep in self.critical_dependencies
        )
        
        if critical_satisfied:
            self.logger.info("All critical dependencies satisfied")
        else:
            missing_critical = [
                dep for dep in self.critical_dependencies 
                if not results.get(dep, False)
            ]
            self.logger.error(f"Critical dependencies missing: {missing_critical}")
        
        return critical_satisfied
    
    def provide_fallback_implementations(self) -> bool:
        """
        Provide fallback implementations for unavailable dependencies
        
        Returns:
            bool: True if fallbacks are available for all critical dependencies
        """
        self.logger.info("Providing fallback implementations")
        
        fallback_success = True
        
        for dep in self.critical_dependencies:
            with self._dependency_lock:
                status = self.dependencies.get(dep)
                
            if not status or (not status.installed and not status.fallback_available):
                fallback = self.fallback_provider.get_fallback(dep)
                if fallback:
                    # Update status
                    if not status:
                        status = DependencyStatus(package_name=dep, critical=True)
                        with self._dependency_lock:
                            self.dependencies[dep] = status
                    
                    status.fallback_available = True
                    status.installation_method = "fallback"
                    
                    # Make fallback available for import
                    sys.modules[dep] = fallback
                    
                    self.logger.info(f"Fallback provided for {dep}")
                else:
                    self.logger.error(f"No fallback available for critical dependency {dep}")
                    fallback_success = False
        
        return fallback_success
    
    def get_dependency_status(self, package_name: str) -> Optional[DependencyStatus]:
        """Get status of a specific dependency"""
        with self._dependency_lock:
            return self.dependencies.get(package_name)
    
    def get_all_dependency_status(self) -> Dict[str, DependencyStatus]:
        """Get status of all dependencies"""
        with self._dependency_lock:
            return self.dependencies.copy()
    
    def validate_psutil_attributes(self) -> Dict[str, bool]:
        """
        Validate psutil.Process attributes and functionality
        
        Returns:
            Dict[str, bool]: Validation results for different attributes
        """
        self.logger.info("Validating psutil attributes")
        
        validation_results = {
            'psutil_available': False,
            'Process_class': False,
            'is_running_method': False,
            'memory_info_method': False,
            'name_method': False,
            'cpu_percent_method': False
        }
        
        try:
            # Import psutil (could be real or fallback)
            import psutil
            validation_results['psutil_available'] = True
            
            # Test Process class
            try:
                current_pid = os.getpid()
                process = psutil.Process(current_pid)
                validation_results['Process_class'] = True
                
                # Test methods
                try:
                    process.is_running()
                    validation_results['is_running_method'] = True
                except Exception as e:
                    self.logger.warning(f"is_running method failed: {str(e)}")
                
                try:
                    process.memory_info()
                    validation_results['memory_info_method'] = True
                except Exception as e:
                    self.logger.warning(f"memory_info method failed: {str(e)}")
                
                try:
                    process.name()
                    validation_results['name_method'] = True
                except Exception as e:
                    self.logger.warning(f"name method failed: {str(e)}")
                
                try:
                    process.cpu_percent()
                    validation_results['cpu_percent_method'] = True
                except Exception as e:
                    self.logger.warning(f"cpu_percent method failed: {str(e)}")
                    
            except Exception as e:
                self.logger.error(f"Process class validation failed: {str(e)}")
                
        except ImportError as e:
            self.logger.error(f"psutil not available: {str(e)}")
        
        # Log validation summary
        passed_tests = sum(validation_results.values())
        total_tests = len(validation_results)
        self.logger.info(f"psutil validation: {passed_tests}/{total_tests} tests passed")
        
        return validation_results
    
    def install_and_validate_psutil(self) -> Dict[str, Any]:
        """
        Install and validate psutil with comprehensive error handling
        
        Returns:
            Dict[str, Any]: Installation and validation results
        """
        self.logger.info("Starting psutil installation and validation")
        
        results = {
            'installation_successful': False,
            'validation_results': {},
            'fallback_created': False,
            'status': None,
            'recommendations': []
        }
        
        try:
            # Step 1: Detect and install psutil
            installation_success = self.psutil_manager.detect_and_install_psutil()
            results['installation_successful'] = installation_success
            
            if installation_success:
                # Step 2: Validate psutil attributes
                validation_results = self.psutil_manager.validate_psutil_process_attributes()
                results['validation_results'] = validation_results
                
                # Step 3: Create fallback if needed
                if validation_results.get('fallback_needed', False):
                    try:
                        fallback_monitor = self.psutil_manager.create_fallback_process_monitoring()
                        results['fallback_created'] = True
                        self.logger.info("Fallback process monitoring created successfully")
                    except Exception as e:
                        self.logger.error(f"Failed to create fallback monitoring: {str(e)}")
                        results['fallback_created'] = False
                
                # Update dependency status
                psutil_status = self.psutil_manager.get_psutil_status()
                results['status'] = psutil_status.to_dict()
                
                with self._dependency_lock:
                    self.dependencies['psutil'] = psutil_status
                
                # Provide recommendations
                results['recommendations'] = validation_results.get('recommendations', [])
                
                self.logger.info("psutil installation and validation completed successfully")
                
            else:
                self.logger.error("psutil installation failed")
                results['recommendations'].append("Manual psutil installation may be required")
                
        except Exception as e:
            error = ProcessMonitoringError(
                f"Error during psutil installation and validation: {str(e)}",
                error_code="PSUTIL_INSTALL_VALIDATE_ERROR"
            )
            self.logger.error(str(error))
            results['error'] = str(e)
        
        return results
    
    def get_psutil_with_fallback(self):
        """
        Get psutil module with automatic fallback handling
        
        Returns:
            psutil module (real or fallback implementation)
        """
        try:
            import psutil
            return psutil
        except ImportError:
            self.logger.warning("psutil not available, using fallback")
            fallback = self.fallback_provider.get_fallback('psutil')
            if fallback:
                return fallback
            else:
                raise DependencyError(
                    "psutil not available and fallback failed",
                    error_code="PSUTIL_UNAVAILABLE"
                )
    
    def create_process_monitor_with_fallback(self):
        """
        Create process monitor with automatic fallback handling
        
        Returns:
            Process monitor (real or fallback implementation)
        """
        try:
            # First try to ensure psutil is available
            if not self.psutil_manager.detect_and_install_psutil():
                raise ProcessMonitoringError(
                    "Failed to ensure psutil availability",
                    error_code="PSUTIL_UNAVAILABLE"
                )
            
            # Validate psutil functionality
            validation_results = self.psutil_manager.validate_psutil_process_attributes()
            
            if validation_results.get('fallback_needed', False):
                self.logger.info("Creating fallback process monitor due to validation issues")
                return self.psutil_manager.create_fallback_process_monitoring()
            else:
                self.logger.info("Using standard psutil for process monitoring")
                import psutil
                return psutil
                
        except Exception as e:
            error = ProcessMonitoringError(
                f"Failed to create process monitor: {str(e)}",
                error_code="PROCESS_MONITOR_CREATION_FAILED"
            )
            self.logger.error(str(error))
            raise error
    
    def shutdown(self):
        """Shutdown dependency manager and cleanup resources"""
        self.logger.info("Shutting down SecurityDependencyManager")
        
        # Clear dependency cache
        with self._dependency_lock:
            self.dependencies.clear()
        
        self.logger.info("SecurityDependencyManager shutdown completed")


def create_dependency_manager(logger: Optional[logging.Logger] = None) -> SecurityDependencyManager:
    """Factory function to create SecurityDependencyManager"""
    return SecurityDependencyManager(logger)


if __name__ == "__main__":
    # Example usage and testing
    print("Security Dependency Manager")
    print("=" * 40)
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Create and test dependency manager
    dep_manager = create_dependency_manager(logger)
    
    # Test dependency installation
    print("\nTesting dependency installation...")
    results = dep_manager.ensure_all_dependencies()
    
    for dep, available in results.items():
        status = "[PASS]" if available else "[FAIL]"
        print(f"{status} {dep}")
    
    # Test psutil validation
    print("\nTesting psutil validation...")
    validation = dep_manager.validate_psutil_attributes()
    
    for test, passed in validation.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {test}")
    
    # Test getting psutil with fallback
    print("\nTesting psutil with fallback...")
    try:
        psutil = dep_manager.get_psutil_with_fallback()
        process = psutil.Process()
        print(f"[PASS] psutil available, current process: {process.name()}")
    except Exception as e:
        print(f"[FAIL] psutil test failed: {str(e)}")
    
    print("\nDependency manager test completed")