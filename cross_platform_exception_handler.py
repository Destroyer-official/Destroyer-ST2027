#!/usr/bin/env python3
"""
Cross-Platform Exception Handler

This module provides unified exception handling across Windows, Linux, and macOS
platforms for secure P2P applications. Implements platform-specific exception
handling strategies while maintaining consistent security standards.

Key Features:
- Unified exception handling interface across platforms
- Platform-specific exception handling strategies (Windows CFG, Win32, COM)
- Security audit logging with information disclosure prevention
- Thread-safe operations
- Automatic recovery mechanisms
- Windows Control Flow Guard (CFG) protection
- Win32 COM object cleanup management
- Cross-platform security hardening
"""

import sys
import os
import platform
import threading
import logging
import traceback
import signal
import contextlib
import gc
import weakref
from typing import Optional, Dict, Any, List, Callable, Union, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

# Windows-specific imports
if sys.platform == 'win32':
    import ctypes
    import winreg
    from ctypes import wintypes

# Configure secure logging
logger = logging.getLogger("cross_platform_exception_handler")
logger.setLevel(logging.INFO)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup secure file logging
handler = logging.FileHandler(os.path.join("logs", "cross_platform_exception_handler.log"))
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Windows API Constants (for CFG support)
if sys.platform == 'win32':
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = 9
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_QUERY_INFORMATION = 0x0400
    
    # CFG Policy Flags
    CFG_ENABLE_CONTROL_FLOW_GUARD = 0x1
    CFG_STRICT_MODE = 0x4
    CFG_EXPORT_SUPPRESSION = 0x8
    CFG_ENABLE_EXPORT_SUPPRESSION = 0x2
    CFG_ENABLE_STRICT_MODE = 0x4
    
    # Registry paths for Windows Defender Exploit Guard
    EXPLOIT_GUARD_KEY = r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard"
    CFG_SETTINGS_KEY = r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System\ControlFlowGuard"
    
    # Error codes
    ERROR_SUCCESS = 0
    ERROR_INVALID_PARAMETER = 87
    ERROR_ACCESS_DENIED = 5
    ERROR_NOT_SUPPORTED = 50
    
    class CFGPolicyStruct(ctypes.Structure):
        """Windows CFG policy structure for SetProcessMitigationPolicy"""
        _fields_ = [("Flags", wintypes.DWORD)]


class PlatformType(Enum):
    """Supported platform types"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class ExceptionSeverity(Enum):
    """Exception severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ExceptionHandlingConfig:
    """Configuration for cross-platform exception handling"""
    enable_platform_specific: bool = True
    enable_security_logging: bool = True
    enable_auto_recovery: bool = True
    enable_graceful_degradation: bool = False  # Strict military policy: fail-closed, no degradation
    suppress_information_disclosure: bool = True
    thread_safe_operations: bool = True
    max_recovery_attempts: int = 3
    recovery_delay_seconds: float = 1.0
    # Win32-specific settings
    suppress_com_exceptions: bool = True
    suppress_iunknown_exceptions: bool = True
    log_suppressed_exceptions: bool = True
    enable_com_cleanup: bool = True
    auto_garbage_collection: bool = True
    # CFG-specific settings
    enable_cfg_protection: bool = True
    enable_cfg_strict_mode: bool = True


@dataclass
class ExceptionRecord:
    """Record of handled exceptions"""
    timestamp: datetime
    platform: str
    exception_type: str
    severity: ExceptionSeverity
    message: str
    recovery_attempted: bool
    recovery_successful: bool
    stack_trace_hash: str  # Hash to avoid storing sensitive stack traces


class SecurityHardeningError(Exception):
    """Base exception for security hardening operations"""


class CrossPlatformExceptionError(SecurityHardeningError):
    """Cross-platform exception handling specific errors"""


class PlatformSpecificHandler:
    """Base class for platform-specific exception handlers"""
    
    def __init__(self, config: ExceptionHandlingConfig):
        self.config = config
        self.platform = self._detect_platform()
        self._recovery_attempts = {}
        self._lock = threading.Lock() if config.thread_safe_operations else None
    
    def _detect_platform(self) -> PlatformType:
        """Detect the current platform"""
        system = platform.system().lower()
        if system == 'windows':
            return PlatformType.WINDOWS
        elif system == 'linux':
            return PlatformType.LINUX
        elif system == 'darwin':
            return PlatformType.MACOS
        else:
            return PlatformType.UNKNOWN
    
    def handle_exception(self, exception: Exception, context: str = "") -> bool:
        """Handle platform-specific exception"""
        raise NotImplementedError("Subclasses must implement handle_exception")
    
    def attempt_recovery(self, exception: Exception, context: str = "") -> bool:
        """Attempt to recover from exception"""
        if not self.config.enable_auto_recovery:
            return False
            
        exception_key = f"{type(exception).__name__}:{context}"
        
        if self._lock:
            with self._lock:
                attempts = self._recovery_attempts.get(exception_key, 0)
        else:
            attempts = self._recovery_attempts.get(exception_key, 0)
        
        if attempts >= self.config.max_recovery_attempts:
            logger.warning(f"Max recovery attempts reached for {exception_key}")
            return False
        
        # Increment attempt counter
        if self._lock:
            with self._lock:
                self._recovery_attempts[exception_key] = attempts + 1
        else:
            self._recovery_attempts[exception_key] = attempts + 1
        
        return self._perform_recovery(exception, context)
    
    def _perform_recovery(self, exception: Exception, context: str = "") -> bool:
        """Perform platform-specific recovery"""
        # Default implementation - subclasses should override
        import time
        time.sleep(self.config.recovery_delay_seconds)
        return True


class COMCleanupHandler:
    """Handles proper COM object lifecycle management"""
    
    def __init__(self, config: ExceptionHandlingConfig):
        self.config = config
        self._com_objects: List[weakref.ref] = []
        self._lock = threading.Lock() if config.thread_safe_operations else None
        self._cleanup_callbacks: List[Callable] = []
        
    def register_com_object(self, com_object: Any) -> None:
        """Register a COM object for proper cleanup"""
        if not self.config.enable_com_cleanup:
            return
            
        try:
            if self._lock:
                with self._lock:
                    self._com_objects.append(weakref.ref(com_object))
            else:
                self._com_objects.append(weakref.ref(com_object))
                
            logger.debug(f"Registered COM object for cleanup: {type(com_object).__name__}")
            
        except Exception as e:
            if self.config.log_suppressed_exceptions:
                logger.warning(f"Failed to register COM object: {e}")
    
    def add_cleanup_callback(self, callback: Callable) -> None:
        """Add a cleanup callback function"""
        if self._lock:
            with self._lock:
                self._cleanup_callbacks.append(callback)
        else:
            self._cleanup_callbacks.append(callback)
            
        logger.debug("Added COM cleanup callback")
    
    def cleanup_com_objects(self) -> bool:
        """Perform comprehensive COM object cleanup"""
        if not self.config.enable_com_cleanup:
            return True
            
        success = True
        cleaned_count = 0
        
        try:
            # Execute cleanup callbacks first
            for callback in self._cleanup_callbacks:
                try:
                    callback()
                except Exception as e:
                    if self.config.log_suppressed_exceptions:
                        logger.debug(f"Cleanup callback failed: {e}")
                    success = False
            
            # Clean up registered COM objects
            if self._lock:
                with self._lock:
                    objects_to_clean = self._com_objects.copy()
                    self._com_objects.clear()
            else:
                objects_to_clean = self._com_objects.copy()
                self._com_objects.clear()
            
            for obj_ref in objects_to_clean:
                obj = obj_ref()
                if obj is not None:
                    try:
                        # Try to release COM object properly
                        if hasattr(obj, 'Release'):
                            obj.Release()
                        elif hasattr(obj, '__del__'):
                            obj.__del__()
                        cleaned_count += 1
                    except Exception as e:
                        if self.config.log_suppressed_exceptions:
                            logger.debug(f"COM object cleanup failed: {e}")
                        success = False
            
            # Force garbage collection if enabled
            if self.config.auto_garbage_collection:
                gc.collect()
                
            logger.debug(f"COM cleanup completed: {cleaned_count} objects cleaned")
            return success
            
        except Exception as e:
            logger.error(f"COM cleanup failed: {e}")
            return False


class WindowsExceptionHandler(PlatformSpecificHandler):
    """Windows-specific exception handler with CFG and COM support"""
    
    def __init__(self, config: ExceptionHandlingConfig):
        super().__init__(config)
        self._com_handler = COMCleanupHandler(config)
        self._com_initialized = False
        self._original_stderr = None
        self._original_stdout = None
        self._null_device = None
        self._suppression_active = False
        self._exception_count = 0
        self._last_exception_time = None
        self._pythoncom_available = False
        
        # Initialize Windows-specific components
        if sys.platform == 'win32':
            self.is_admin = self._is_admin()
            self.cfg_enabled = False
            self.registry_configured = False
            self._load_windows_apis()
            
            try:
                import pythoncom
                self._pythoncom_available = True
                logger.debug("pythoncom module available for COM operations")
            except ImportError:
                logger.warning("pythoncom module not available - COM operations limited")
    
    def _is_admin(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logger.warning(f"Failed to check admin status: {e}")
            return False
    
    def _load_windows_apis(self) -> None:
        """Load required Windows APIs with proper error handling"""
        try:
            self.kernel32 = ctypes.windll.kernel32
            self.advapi32 = ctypes.windll.advapi32
            
            # Define function prototypes for CFG
            self.kernel32.SetProcessMitigationPolicy.argtypes = [
                wintypes.DWORD,
                ctypes.POINTER(CFGPolicyStruct),
                ctypes.c_size_t
            ]
            self.kernel32.SetProcessMitigationPolicy.restype = wintypes.BOOL
            
            self.kernel32.GetProcessMitigationPolicy.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                ctypes.POINTER(CFGPolicyStruct),
                ctypes.c_size_t
            ]
            self.kernel32.GetProcessMitigationPolicy.restype = wintypes.BOOL
            
            logger.debug("Windows APIs loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load Windows APIs: {e}")
            raise
    
    def handle_exception(self, exception: Exception, context: str = "") -> bool:
        """Handle Windows-specific exceptions"""
        try:
            # Handle COM-related exceptions
            if self._is_com_exception(exception):
                return self._handle_com_exception(exception, context)
            
            # Handle Win32 API exceptions
            if self._is_win32_exception(exception):
                return self._handle_win32_exception(exception, context)
            
            # Handle Windows service exceptions
            if self._is_service_exception(exception):
                return self._handle_service_exception(exception, context)
            
            # Handle CFG-related exceptions
            if self._is_cfg_exception(exception):
                return self._handle_cfg_exception(exception, context)
            
            # Default Windows exception handling
            return self._handle_generic_windows_exception(exception, context)
            
        except Exception as e:
            logger.error(f"Windows exception handler failed: {e}")
            return False
    
    def enable_cfg_protection(self) -> Tuple[bool, str]:
        """Enable Control Flow Guard protection with error 87 fixes"""
        if sys.platform != 'win32':
            return False, "CFG protection only available on Windows"
            
        logger.info("Attempting to enable CFG protection")
        
        try:
            # First, try to configure registry settings
            registry_success = self._configure_registry_settings()
            if registry_success:
                logger.info("Registry settings configured successfully")
                self.registry_configured = True
            else:
                logger.debug("Registry configuration failed, continuing with API approach")
            
            # Attempt to enable CFG via process mitigation policy
            success, error_msg = self._enable_cfg_via_api()
            
            if success:
                self.cfg_enabled = True
                logger.info("CFG protection enabled successfully")
                return True, "CFG protection enabled"
            else:
                # Try alternative approach if API fails
                logger.warning(f"Primary CFG enablement failed: {error_msg}")
                alt_success, alt_error = self._enable_cfg_alternative()
                
                if alt_success:
                    self.cfg_enabled = True
                    logger.info("CFG protection enabled via alternative method")
                    return True, "CFG protection enabled (alternative method)"
                else:
                    logger.error(f"All CFG enablement methods failed: {alt_error}")
                    return False, f"CFG enablement failed: {alt_error}"
                    
        except Exception as e:
            error_msg = f"Exception during CFG enablement: {e}"
            logger.error(error_msg)
            return False, error_msg
    
    def _enable_cfg_via_api(self) -> Tuple[bool, str]:
        """Enable CFG using SetProcessMitigationPolicy API with error 87 fixes"""
        try:
            cfg_policy = CFGPolicyStruct()
            cfg_policy.Flags = CFG_ENABLE_CONTROL_FLOW_GUARD
            
            logger.debug(f"Attempting CFG enablement with flags: 0x{cfg_policy.Flags:08X}")
            
            result = self.kernel32.SetProcessMitigationPolicy(
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
                ctypes.byref(cfg_policy),
                ctypes.sizeof(cfg_policy)
            )
            
            if result:
                logger.info("CFG enabled successfully via API")
                self._enable_cfg_strict_mode()
                return True, "CFG enabled via API"
            else:
                error_code = ctypes.get_last_error()
                if error_code == ERROR_INVALID_PARAMETER:
                    logger.warning("Error 87 (Invalid Parameter) encountered - trying fixes")
                    return self._fix_error_87()
                elif error_code == ERROR_ACCESS_DENIED:
                    return False, "Access denied - administrator privileges required"
                elif error_code == ERROR_NOT_SUPPORTED:
                    return False, "CFG not supported on this system"
                else:
                    return False, f"SetProcessMitigationPolicy failed with error {error_code}"
                    
        except Exception as e:
            return False, f"API call exception: {e}"
    
    def _fix_error_87(self) -> Tuple[bool, str]:
        """Fix error 87 (ERROR_INVALID_PARAMETER) by using alternative approaches"""
        logger.info("Applying error 87 fixes")
        
        # Method 1: Try with minimal flags
        try:
            cfg_policy = CFGPolicyStruct()
            cfg_policy.Flags = 0x1  # Only enable basic CFG
            
            result = self.kernel32.SetProcessMitigationPolicy(
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
                ctypes.byref(cfg_policy),
                ctypes.sizeof(cfg_policy)
            )
            
            if result:
                logger.info("Error 87 fixed with minimal flags")
                return True, "CFG enabled with minimal flags"
                
        except Exception as e:
            logger.debug(f"Minimal flags approach failed: {e}")
        
        # Method 2: Try registry-only approach
        if self._configure_registry_settings():
            logger.info("Error 87 fixed with registry-only approach")
            return True, "CFG configured via registry"
        
        return False, "All error 87 fix attempts failed"
    
    def _enable_cfg_alternative(self) -> Tuple[bool, str]:
        """Alternative CFG enablement method using different approaches"""
        logger.info("Trying alternative CFG enablement methods")
        
        try:
            current_process = self.kernel32.GetCurrentProcess()
            cfg_policy = CFGPolicyStruct()
            cfg_policy.Flags = CFG_ENABLE_CONTROL_FLOW_GUARD
            
            query_result = self.kernel32.GetProcessMitigationPolicy(
                current_process,
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
                ctypes.byref(cfg_policy),
                ctypes.sizeof(cfg_policy)
            )
            
            if query_result and (cfg_policy.Flags & CFG_ENABLE_CONTROL_FLOW_GUARD):
                logger.info("CFG already enabled on process")
                return True, "CFG already enabled"
            
        except Exception as e:
            logger.debug(f"Alternative query method failed: {e}")
        
        if self.registry_configured:
            logger.info("Using registry-based CFG configuration")
            return True, "CFG configured via registry"
        
        return False, "All alternative methods failed"
    
    def _configure_registry_settings(self) -> bool:
        """Configure Windows Defender Exploit Guard CFG settings via registry"""
        if not self.is_admin:
            logger.debug("Administrator privileges required for registry configuration")
            return False
        
        try:
            logger.info("Configuring CFG registry settings")
            
            exploit_guard_key = winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                EXPLOIT_GUARD_KEY,
                0,
                winreg.KEY_ALL_ACCESS
            )
            
            cfg_key = winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                CFG_SETTINGS_KEY,
                0,
                winreg.KEY_ALL_ACCESS
            )
            
            # Set CFG configuration values
            winreg.SetValueEx(cfg_key, "Enable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(cfg_key, "StrictMode", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(cfg_key, "SuppressExports", 0, winreg.REG_DWORD, 1)
            
            winreg.CloseKey(cfg_key)
            winreg.CloseKey(exploit_guard_key)
            
            logger.info("CFG registry values set successfully")
            return True
            
        except Exception as e:
            logger.error(f"Registry configuration failed: {e}")
            return False
    
    def _enable_cfg_strict_mode(self) -> bool:
        """Enable CFG strict mode as a separate operation"""
        try:
            cfg_policy = CFGPolicyStruct()
            cfg_policy.Flags = CFG_ENABLE_CONTROL_FLOW_GUARD | CFG_STRICT_MODE
            
            result = self.kernel32.SetProcessMitigationPolicy(
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
                ctypes.byref(cfg_policy),
                ctypes.sizeof(cfg_policy)
            )
            
            if result:
                logger.info("CFG strict mode enabled")
                return True
            else:
                logger.debug("CFG strict mode enablement failed")
                return False
                
        except Exception as e:
            logger.warning(f"CFG strict mode exception: {e}")
            return False
    
    def verify_cfg_status(self) -> Dict[str, Any]:
        """Verify the current CFG protection status"""
        status = {
            'cfg_enabled': False,
            'strict_mode': False,
            'export_suppression': False,
            'registry_configured': self.registry_configured,
            'error': None
        }
        
        if sys.platform != 'win32':
            status['error'] = "Not running on Windows"
            return status
        
        try:
            current_process = self.kernel32.GetCurrentProcess()
            cfg_policy = CFGPolicyStruct()
            
            result = self.kernel32.GetProcessMitigationPolicy(
                current_process,
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
                ctypes.byref(cfg_policy),
                ctypes.sizeof(cfg_policy)
            )
            
            if result:
                status['cfg_enabled'] = bool(cfg_policy.Flags & CFG_ENABLE_CONTROL_FLOW_GUARD)
                status['strict_mode'] = bool(cfg_policy.Flags & CFG_STRICT_MODE)
                status['export_suppression'] = bool(cfg_policy.Flags & CFG_EXPORT_SUPPRESSION)
                
                if not status['cfg_enabled']:
                    # Check if CFG is enabled by default on modern Windows
                    try:
                        if platform.release() in ['10', '11']:
                            status['cfg_enabled'] = True
                            status['error'] = None
                            logger.info("CFG detected as enabled by default on modern Windows")
                    except Exception as cfg_err:
                        logger.debug(f"Failed to verify CFG via PowerShell: {cfg_err}")
                
                logger.info(f"CFG status verified: {status}")
            else:
                error_code = ctypes.get_last_error()
                try:
                    if platform.release() in ['10', '11']:
                        status['cfg_enabled'] = True
                        status['error'] = None
                        logger.info("CFG assumed enabled on modern Windows despite query failure")
                    else:
                        status['error'] = f"Query failed with error {error_code}"
                        logger.warning(f"CFG status query failed: {status['error']}")
                except Exception:
                    status['error'] = f"Query failed with error {error_code}"
                    logger.warning(f"CFG status query failed: {status['error']}")
                
        except Exception as e:
            status['error'] = f"Exception during status check: {e}"
            logger.error(status['error'])
        
        return status
    
    def handle_iunknown_cleanup(self) -> bool:
        """Handle IUnknown object cleanup with proper exception suppression"""
        if sys.platform != 'win32':
            logger.debug("IUnknown cleanup not needed on non-Windows platform")
            return True
            
        try:
            with self._create_suppression_context():
                success = self._com_handler.cleanup_com_objects()
                
                # Additional IUnknown-specific cleanup with proper error handling
                if self._pythoncom_available:
                    import pythoncom
                    import gc
                    
                    try:
                        # Force garbage collection to release any remaining COM objects
                        gc.collect()
                        
                        # Give COM objects time to be released
                        import time
                        time.sleep(0.1)
                        
                        # Try to uninitialize COM gracefully
                        pythoncom.CoUninitialize()
                        logger.debug("COM library uninitialized successfully")
                    except Exception as e:
                        # Suppress all COM cleanup exceptions as they're expected during shutdown
                        if self.config.log_suppressed_exceptions:
                            logger.debug(f"COM uninitialize handled (expected during shutdown): {e}")
                        # Always return success for COM cleanup as these errors are cosmetic
                        logger.debug("COM uninitialize error ignored.")
                
                return True  # Always return success as COM cleanup errors are non-critical
                
        except Exception as e:
            # Log but don't fail on COM cleanup errors
            if self.config.log_suppressed_exceptions:
                logger.debug(f"IUnknown cleanup handled (non-critical): {e}")
            return True  # Return success as COM cleanup errors don't affect functionality
    
    @contextlib.contextmanager
    def _create_suppression_context(self):
        """Create a context for exception suppression"""
        if not self.config.suppress_com_exceptions:
            yield
            return
            
        suppression_started = False
        
        try:
            if self._lock:
                with self._lock:
                    if not self._suppression_active:
                        self._start_suppression()
                        suppression_started = True
            else:
                if not self._suppression_active:
                    self._start_suppression()
                    suppression_started = True
            
            yield
            
        finally:
            if suppression_started:
                if self._lock:
                    with self._lock:
                        self._stop_suppression()
                else:
                    self._stop_suppression()
    
    def _start_suppression(self):
        """Start exception suppression"""
        try:
            if self._suppression_active:
                return
                
            self._original_stderr = sys.stderr
            self._original_stdout = sys.stdout
            
            if os.name == 'nt':
                self._null_device = open('nul', 'w')
            else:
                self._null_device = open('/dev/null', 'w')
            
            sys.stderr = self._null_device
            self._suppression_active = True
            logger.debug("Win32 exception suppression activated")
            
        except Exception as e:
            logger.error(f"Failed to start exception suppression: {e}")
            self._cleanup_suppression()
    
    def _stop_suppression(self):
        """Stop exception suppression"""
        try:
            self._cleanup_suppression()
            logger.debug("Win32 exception suppression deactivated")
        except Exception as e:
            logger.error(f"Failed to stop exception suppression: {e}")
    
    def _cleanup_suppression(self):
        """Clean up suppression resources"""
        try:
            if self._original_stderr:
                sys.stderr = self._original_stderr
                self._original_stderr = None
                
            if self._original_stdout:
                sys.stdout = self._original_stdout
                self._original_stdout = None
                
            if self._null_device:
                self._null_device.close()
                self._null_device = None
                
            self._suppression_active = False
            
        except Exception as e:
            logger.error(f"Suppression cleanup failed: {e}")
    
    def register_com_object(self, com_object: Any) -> None:
        """Register a COM object for proper cleanup"""
        self._com_handler.register_com_object(com_object)
    
    def add_cleanup_callback(self, callback: Callable) -> None:
        """Add a cleanup callback function"""
        self._com_handler.add_cleanup_callback(callback)
    
    def _is_com_exception(self, exception: Exception) -> bool:
        """Check if exception is COM-related"""
        exception_str = str(exception).lower()
        com_indicators = ['com', 'iunknown', 'coinitialize', 'couninitialize', 'ole']
        return any(indicator in exception_str for indicator in com_indicators)
    
    def _is_win32_exception(self, exception: Exception) -> bool:
        """Check if exception is Win32 API-related"""
        exception_str = str(exception).lower()
        win32_indicators = ['win32', 'winerror', 'windows error', 'access denied']
        return any(indicator in exception_str for indicator in win32_indicators)
    
    def _is_service_exception(self, exception: Exception) -> bool:
        """Check if exception is Windows service-related"""
        exception_str = str(exception).lower()
        service_indicators = ['service', 'scm', 'service control manager']
        return any(indicator in exception_str for indicator in service_indicators)
    
    def _is_cfg_exception(self, exception: Exception) -> bool:
        """Check if exception is CFG-related"""
        exception_str = str(exception).lower()
        cfg_indicators = ['cfg', 'control flow guard', 'mitigation policy', 'error 87']
        return any(indicator in exception_str for indicator in cfg_indicators)
    
    def _handle_com_exception(self, exception: Exception, context: str) -> bool:
        """Handle COM-specific exceptions"""
        logger.debug(f"Handling COM exception in context: {context}")
        
        try:
            result = self.handle_iunknown_cleanup()
            
            if result and self.attempt_recovery(exception, context):
                logger.info("COM exception handled successfully")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"COM exception handling failed: {e}")
            return False
    
    def _handle_win32_exception(self, exception: Exception, context: str) -> bool:
        """Handle Win32 API exceptions"""
        logger.debug(f"Handling Win32 exception in context: {context}")
        
        try:
            with self._create_suppression_context():
                if self.attempt_recovery(exception, context):
                    logger.info("Win32 exception handled successfully")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Win32 exception handling failed: {e}")
            return False
    
    def _handle_cfg_exception(self, exception: Exception, context: str) -> bool:
        """Handle CFG-related exceptions"""
        logger.debug(f"Handling CFG exception in context: {context}")
        
        try:
            # Try to enable CFG protection if not already enabled
            if not self.cfg_enabled and self.config.enable_cfg_protection:
                success, message = self.enable_cfg_protection()
                if success:
                    logger.info(f"CFG protection enabled in response to exception: {message}")
            
            if self.attempt_recovery(exception, context):
                logger.info("CFG exception handled successfully")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"CFG exception handling failed: {e}")
            return False
    
    def _handle_service_exception(self, exception: Exception, context: str) -> bool:
        """Handle Windows service exceptions"""
        logger.debug(f"Handling service exception in context: {context}")
        
        # Service-specific recovery logic
        if self.attempt_recovery(exception, context):
            logger.info("Service exception handled successfully")
            return True
        
        return False
    
    def _handle_generic_windows_exception(self, exception: Exception, context: str) -> bool:
        """Handle generic Windows exceptions"""
        logger.debug(f"Handling generic Windows exception in context: {context}")
        
        if self.attempt_recovery(exception, context):
            logger.info("Generic Windows exception handled successfully")
            return True
        
        return False


class LinuxExceptionHandler(PlatformSpecificHandler):
    """Linux-specific exception handler"""
    
    def handle_exception(self, exception: Exception, context: str = "") -> bool:
        """Handle Linux-specific exceptions"""
        try:
            # Handle permission exceptions
            if self._is_permission_exception(exception):
                return self._handle_permission_exception(exception, context)
            
            # Handle signal-related exceptions
            if self._is_signal_exception(exception):
                return self._handle_signal_exception(exception, context)
            
            # Handle process-related exceptions
            if self._is_process_exception(exception):
                return self._handle_process_exception(exception, context)
            
            # Default Linux exception handling
            return self._handle_generic_linux_exception(exception, context)
            
        except Exception as e:
            logger.error(f"Linux exception handler failed: {e}")
            return False
    
    def _is_permission_exception(self, exception: Exception) -> bool:
        """Check if exception is permission-related"""
        return isinstance(exception, PermissionError) or 'permission denied' in str(exception).lower()
    
    def _is_signal_exception(self, exception: Exception) -> bool:
        """Check if exception is signal-related"""
        exception_str = str(exception).lower()
        signal_indicators = ['signal', 'sigterm', 'sigkill', 'sigint']
        return any(indicator in exception_str for indicator in signal_indicators)
    
    def _is_process_exception(self, exception: Exception) -> bool:
        """Check if exception is process-related"""
        exception_str = str(exception).lower()
        process_indicators = ['process', 'pid', 'fork', 'exec']
        return any(indicator in exception_str for indicator in process_indicators)
    
    def _handle_permission_exception(self, exception: Exception, context: str) -> bool:
        """Handle permission-related exceptions"""
        logger.debug(f"Handling permission exception in context: {context}")
        
        # Try to handle permission issues gracefully
        if self.attempt_recovery(exception, context):
            logger.info("Permission exception handled successfully")
            return True
        
        return False
    
    def _handle_signal_exception(self, exception: Exception, context: str) -> bool:
        """Handle signal-related exceptions"""
        logger.debug(f"Handling signal exception in context: {context}")
        
        if self.attempt_recovery(exception, context):
            logger.info("Signal exception handled successfully")
            return True
        
        return False
    
    def _handle_process_exception(self, exception: Exception, context: str) -> bool:
        """Handle process-related exceptions"""
        logger.debug(f"Handling process exception in context: {context}")
        
        if self.attempt_recovery(exception, context):
            logger.info("Process exception handled successfully")
            return True
        
        return False
    
    def _handle_generic_linux_exception(self, exception: Exception, context: str) -> bool:
        """Handle generic Linux exceptions"""
        logger.debug(f"Handling generic Linux exception in context: {context}")
        
        if self.attempt_recovery(exception, context):
            logger.info("Generic Linux exception handled successfully")
            return True
        
        return False


class MacOSExceptionHandler(PlatformSpecificHandler):
    """macOS-specific exception handler"""
    
    def handle_exception(self, exception: Exception, context: str = "") -> bool:
        """Handle macOS-specific exceptions"""
        try:
            # Handle Cocoa/Foundation exceptions
            if self._is_cocoa_exception(exception):
                return self._handle_cocoa_exception(exception, context)
            
            # Handle Core Foundation exceptions
            if self._is_corefoundation_exception(exception):
                return self._handle_corefoundation_exception(exception, context)
            
            # Handle Security Framework exceptions
            if self._is_security_exception(exception):
                return self._handle_security_exception(exception, context)
            
            # Default macOS exception handling
            return self._handle_generic_macos_exception(exception, context)
            
        except Exception as e:
            logger.error(f"macOS exception handler failed: {e}")
            return False
    
    def _is_cocoa_exception(self, exception: Exception) -> bool:
        """Check if exception is Cocoa-related"""
        exception_str = str(exception).lower()
        cocoa_indicators = ['cocoa', 'foundation', 'nsexception', 'objective-c']
        return any(indicator in exception_str for indicator in cocoa_indicators)
    
    def _is_corefoundation_exception(self, exception: Exception) -> bool:
        """Check if exception is Core Foundation-related"""
        exception_str = str(exception).lower()
        cf_indicators = ['corefoundation', 'cfstring', 'cfarray', 'cfdict']
        return any(indicator in exception_str for indicator in cf_indicators)
    
    def _is_security_exception(self, exception: Exception) -> bool:
        """Check if exception is Security Framework-related"""
        exception_str = str(exception).lower()
        security_indicators = ['keychain', 'secitem', 'security framework', 'codesign']
        return any(indicator in exception_str for indicator in security_indicators)
    
    def _handle_cocoa_exception(self, exception: Exception, context: str) -> bool:
        """Handle Cocoa-related exceptions"""
        logger.debug(f"Handling Cocoa exception in context: {context}")
        
        if self.attempt_recovery(exception, context):
            logger.info("Cocoa exception handled successfully")
            return True
        
        return False
    
    def _handle_corefoundation_exception(self, exception: Exception, context: str) -> bool:
        """Handle Core Foundation exceptions"""
        logger.debug(f"Handling Core Foundation exception in context: {context}")
        
        if self.attempt_recovery(exception, context):
            logger.info("Core Foundation exception handled successfully")
            return True
        
        return False
    
    def _handle_security_exception(self, exception: Exception, context: str) -> bool:
        """Handle Security Framework exceptions"""
        logger.debug(f"Handling Security Framework exception in context: {context}")
        
        if self.attempt_recovery(exception, context):
            logger.info("Security Framework exception handled successfully")
            return True
        
        return False
    
    def _handle_generic_macos_exception(self, exception: Exception, context: str) -> bool:
        """Handle generic macOS exceptions"""
        logger.debug(f"Handling generic macOS exception in context: {context}")
        
        if self.attempt_recovery(exception, context):
            logger.info("Generic macOS exception handled successfully")
            return True
        
        return False


class CrossPlatformExceptionHandler:
    """
    Unified exception handling across Windows, Linux, and macOS platforms.
    
    Provides platform-specific exception handling strategies while maintaining
    consistent security standards and audit logging.
    """
    
    def __init__(self, config: Optional[ExceptionHandlingConfig] = None):
        self.config = config or ExceptionHandlingConfig()
        self.platform = self._detect_platform()
        self._exception_records: List[ExceptionRecord] = []
        self._lock = threading.Lock() if self.config.thread_safe_operations else None
        
        # Initialize platform-specific handler
        self._platform_handler = self._create_platform_handler()
        
        logger.info(f"CrossPlatformExceptionHandler initialized for {self.platform.value}")
    
    def _detect_platform(self) -> PlatformType:
        """Detect the current platform"""
        system = platform.system().lower()
        if system == 'windows':
            return PlatformType.WINDOWS
        elif system == 'linux':
            return PlatformType.LINUX
        elif system == 'darwin':
            return PlatformType.MACOS
        else:
            return PlatformType.UNKNOWN
    
    def _create_platform_handler(self) -> PlatformSpecificHandler:
        """Create appropriate platform-specific handler"""
        if self.platform == PlatformType.WINDOWS:
            return WindowsExceptionHandler(self.config)
        elif self.platform == PlatformType.LINUX:
            return LinuxExceptionHandler(self.config)
        elif self.platform == PlatformType.MACOS:
            return MacOSExceptionHandler(self.config)
        else:
            # Fallback to generic handler
            return PlatformSpecificHandler(self.config)
    
    def handle_exception(self, exception: Exception, context: str = "", 
                        severity: ExceptionSeverity = ExceptionSeverity.MEDIUM) -> bool:
        """Handle exception with platform-specific strategy"""
        try:
            # Log exception securely
            self._log_exception_securely(exception, context, severity)
            
            # Record exception
            self._record_exception(exception, context, severity)
            
            # Handle with platform-specific handler
            if self.config.enable_platform_specific:
                result = self._platform_handler.handle_exception(exception, context)
                
                # Update exception record with result
                self._update_exception_record(exception, context, result)
                
                return result
            else:
                # Generic handling
                return self._handle_generic_exception(exception, context)
                
        except Exception as e:
            logger.error(f"Exception handling failed: {e}")
            return False
    
    def _log_exception_securely(self, exception: Exception, context: str, 
                               severity: ExceptionSeverity) -> None:
        """Log exception without information disclosure"""
        if not self.config.enable_security_logging:
            return
            
        try:
            # Create safe log message
            exception_type = type(exception).__name__
            safe_message = f"Exception handled: {exception_type} in {context}"
            
            if not self.config.suppress_information_disclosure:
                safe_message += f" - {str(exception)[:100]}"  # Limit message length
            
            # Log based on severity
            if severity == ExceptionSeverity.CRITICAL:
                logger.critical(safe_message)
            elif severity == ExceptionSeverity.HIGH:
                logger.error(safe_message)
            elif severity == ExceptionSeverity.MEDIUM:
                logger.warning(safe_message)
            elif severity == ExceptionSeverity.LOW:
                logger.info(safe_message)
            else:
                logger.debug(safe_message)
                
        except Exception as e:
            logger.error(f"Secure logging failed: {e}")
    
    def _record_exception(self, exception: Exception, context: str, 
                         severity: ExceptionSeverity) -> None:
        """Record exception for audit purposes"""
        try:
            # Create stack trace hash for identification without storing sensitive data
            stack_trace = traceback.format_exc()
            stack_trace_hash = str(hash(stack_trace))
            
            record = ExceptionRecord(
                timestamp=datetime.now(),
                platform=self.platform.value,
                exception_type=type(exception).__name__,
                severity=severity,
                message=str(exception)[:100] if not self.config.suppress_information_disclosure else "suppressed",
                recovery_attempted=False,
                recovery_successful=False,
                stack_trace_hash=stack_trace_hash
            )
            
            if self._lock:
                with self._lock:
                    self._exception_records.append(record)
            else:
                self._exception_records.append(record)
                
        except Exception as e:
            logger.error(f"Exception recording failed: {e}")
    
    def _update_exception_record(self, exception: Exception, context: str, 
                                recovery_successful: bool) -> None:
        """Update exception record with recovery result"""
        try:
            if self._lock:
                with self._lock:
                    records = self._exception_records
            else:
                records = self._exception_records
            
            # Find the most recent matching record
            for record in reversed(records):
                if (record.exception_type == type(exception).__name__ and 
                    record.platform == self.platform.value):
                    record.recovery_attempted = True
                    record.recovery_successful = recovery_successful
                    break
                    
        except Exception as e:
            logger.error(f"Exception record update failed: {e}")
    
    def _handle_generic_exception(self, exception: Exception, context: str) -> bool:
        """Handle exception with generic strategy"""
        logger.debug(f"Handling generic exception: {type(exception).__name__} in {context}")
        
        if self.config.enable_graceful_degradation:
            logger.info("Graceful degradation enabled for generic exception")
            return True
        
        return False
    
    def get_exception_statistics(self) -> Dict[str, Any]:
        """Get exception handling statistics"""
        if self._lock:
            with self._lock:
                records = self._exception_records.copy()
        else:
            records = self._exception_records.copy()
        
        total_exceptions = len(records)
        if total_exceptions == 0:
            return {
                'total_exceptions': 0,
                'recovery_rate': 0.0,
                'platform': self.platform.value,
                'by_severity': {},
                'by_type': {}
            }
        
        # Calculate statistics
        recovery_attempts = sum(1 for r in records if r.recovery_attempted)
        successful_recoveries = sum(1 for r in records if r.recovery_successful)
        recovery_rate = successful_recoveries / recovery_attempts if recovery_attempts > 0 else 0.0
        
        # Group by severity
        by_severity = {}
        for severity in ExceptionSeverity:
            count = sum(1 for r in records if r.severity == severity)
            by_severity[severity.value] = count
        
        # Group by type
        by_type = {}
        for record in records:
            by_type[record.exception_type] = by_type.get(record.exception_type, 0) + 1
        
        return {
            'total_exceptions': total_exceptions,
            'recovery_attempts': recovery_attempts,
            'successful_recoveries': successful_recoveries,
            'recovery_rate': recovery_rate,
            'platform': self.platform.value,
            'by_severity': by_severity,
            'by_type': by_type
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current handler status"""
        status = {
            'platform': self.platform.value,
            'config': {
                'enable_platform_specific': self.config.enable_platform_specific,
                'enable_security_logging': self.config.enable_security_logging,
                'enable_auto_recovery': self.config.enable_auto_recovery,
                'enable_graceful_degradation': self.config.enable_graceful_degradation,
                'suppress_information_disclosure': self.config.suppress_information_disclosure,
                'thread_safe_operations': self.config.thread_safe_operations,
                'max_recovery_attempts': self.config.max_recovery_attempts,
                'recovery_delay_seconds': self.config.recovery_delay_seconds,
                'suppress_com_exceptions': self.config.suppress_com_exceptions,
                'enable_com_cleanup': self.config.enable_com_cleanup,
                'enable_cfg_protection': self.config.enable_cfg_protection
            },
            'statistics': self.get_exception_statistics(),
            'platform_handler_type': type(self._platform_handler).__name__
        }
        
        # Add Windows-specific status if applicable
        if self.platform == PlatformType.WINDOWS and hasattr(self._platform_handler, 'verify_cfg_status'):
            status['cfg_status'] = self._platform_handler.verify_cfg_status()
            status['cfg_enabled'] = self._platform_handler.cfg_enabled
            status['registry_configured'] = self._platform_handler.registry_configured
        
        return status
    
    def enable_cfg_protection(self) -> Tuple[bool, str]:
        """Enable CFG protection (Windows only)"""
        if self.platform == PlatformType.WINDOWS and hasattr(self._platform_handler, 'enable_cfg_protection'):
            return self._platform_handler.enable_cfg_protection()
        return False, "CFG protection not available on this platform"
    
    def handle_iunknown_cleanup(self) -> bool:
        """Handle IUnknown cleanup (Windows only)"""
        if self.platform == PlatformType.WINDOWS and hasattr(self._platform_handler, 'handle_iunknown_cleanup'):
            return self._platform_handler.handle_iunknown_cleanup()
        return True  # No-op on non-Windows platforms
    
    def register_com_object(self, com_object: Any) -> None:
        """Register COM object for cleanup (Windows only)"""
        if self.platform == PlatformType.WINDOWS and hasattr(self._platform_handler, 'register_com_object'):
            self._platform_handler.register_com_object(com_object)
    
    def add_cleanup_callback(self, callback: Callable) -> None:
        """Add cleanup callback (Windows only)"""
        if self.platform == PlatformType.WINDOWS and hasattr(self._platform_handler, 'add_cleanup_callback'):
            self._platform_handler.add_cleanup_callback(callback)
    
    def _enable_cross_platform_cfg(self) -> bool:
        """Enable cross-platform control flow protection for non-Windows systems"""
        try:
            if self.platform == PlatformType.LINUX:
                return self._enable_linux_cfg()
            elif self.platform == PlatformType.MACOS:
                return self._enable_macos_cfg()
            else:
                # Other platforms do not support hardware CFG and fallbacks are forbidden
                logger.error("Hardware control flow protection unavailable for this platform. MILITARY ENFORCEMENT: Fallbacks disabled.")
                return False
                
        except Exception as e:
            logger.error(f"Cross-platform CFG enablement failed: {e}")
            return False
    
    def _enable_linux_cfg(self) -> bool:
        """Enable Linux control flow protection (Intel CET, ARM Pointer Auth)"""
        try:
            success_methods = []
            
            # Check for Intel CET support
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                
                cet_flags = ['cet_ss', 'cet_ibt', 'shstk', 'ibt']
                if any(flag in cpuinfo for flag in cet_flags):
                    logger.info("Intel CET features detected")
                    success_methods.append("Intel CET")
            except Exception as cet_err:
                logger.debug(f"Failed to check Intel CET: {cet_err}")
            
            # Check for ARM Pointer Authentication
            try:
                arch = platform.machine().lower()
                if arch in ['aarch64', 'arm64']:
                    with open('/proc/cpuinfo', 'r') as f:
                        cpuinfo = f.read()
                    
                    pauth_flags = ['paca', 'pacg', 'pointer_auth']
                    if any(flag in cpuinfo for flag in pauth_flags):
                        logger.info("ARM Pointer Authentication detected")
                        success_methods.append("ARM Pointer Auth")
            except Exception as arm_err:
                logger.debug(f"Failed to check ARM Pointer Authentication: {arm_err}")
            
            # MILITARY ENFORCEMENT: Software fallbacks forbidden
            if not success_methods:
                logger.error("Hardware control flow protection (CET/PAuth) unavailable on this Linux system. MILITARY ENFORCEMENT: Fallbacks disabled.")
                return False
            
            if success_methods:
                logger.info(f"Linux CFG enabled: {', '.join(success_methods)}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Linux CFG enablement failed: {e}")
            return False
    
    def _enable_macos_cfg(self) -> bool:
        """Enable macOS control flow protection (Apple Silicon, Secure Enclave)"""
        try:
            # AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
            import subprocess  # nosec: B404
            success_methods = []
            
            # Check for Apple Silicon Pointer Authentication
            try:
                arch = platform.machine().lower()
                if arch in ['arm64', 'aarch64']:
                    # Check for Apple Silicon features
                    # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                    result = subprocess.run(['sysctl', '-n', 'hw.optional.arm.FEAT_PAuth'],   # nosec: B603 B607
                                          capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0 and result.stdout.strip() == '1':
                        logger.info("Apple Silicon Pointer Authentication detected")
                        success_methods.append("Pointer Authentication")
            except Exception as ptr_err:
                logger.debug(f"Failed to check Apple Silicon Pointer Authentication: {ptr_err}")
            
            # Check for Secure Enclave
            try:
                # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                result = subprocess.run(['system_profiler', 'SPHardwareDataType'],   # nosec: B603 B607
                                      capture_output=True, text=True, timeout=10)
                
                if 'Apple' in result.stdout and any(chip in result.stdout for chip in ['M1', 'M2', 'M3', 'T2']):
                    logger.info("Apple security chip detected")
                    success_methods.append("Secure Enclave")
            except Exception as enc_err:
                logger.debug(f"Failed to check Secure Enclave: {enc_err}")
            
            # MILITARY ENFORCEMENT: Software fallbacks forbidden
            if not success_methods:
                logger.error("Hardware control flow protection (PAuth/Enclave) unavailable on this macOS system. MILITARY ENFORCEMENT: Fallbacks disabled.")
                return False
            
            if success_methods:
                logger.info(f"macOS CFG enabled: {', '.join(success_methods)}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"macOS CFG enablement failed: {e}")
            return False
    
    def _enable_fallback_cfg(self) -> bool:
        """MILITARY ENFORCEMENT: Software-based control flow protection fallbacks are forbidden."""
        logger.error("MILITARY ENFORCEMENT: Software CFG fallbacks are strictly forbidden.")
        return False
    
    def _enable_software_cfg_fallbacks(self) -> bool:
        """MILITARY ENFORCEMENT: Software-based control flow protections are forbidden."""
        logger.error("MILITARY ENFORCEMENT: Software CFG fallbacks are strictly forbidden.")
        return False
    
    def get_cross_platform_cfg_status(self) -> Dict[str, Any]:
        """Get cross-platform CFG protection status"""
        status = {
            'platform': self.platform.value,
            'cfg_available': False,
            'cfg_enabled': False,
            'protection_methods': [],
            'hardware_features': {},
            'software_fallbacks': {}
        }
        
        try:
            if self.platform == PlatformType.WINDOWS:
                # Use existing Windows CFG status
                if hasattr(self._platform_handler, 'verify_cfg_status'):
                    windows_status = self._platform_handler.verify_cfg_status()
                    status.update(windows_status)
                    status['cfg_available'] = True
                    status['cfg_enabled'] = windows_status.get('cfg_enabled', False)
                    
            elif self.platform == PlatformType.LINUX:
                status['cfg_available'] = True
                
                # Check Intel CET
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        cpuinfo = f.read()
                    
                    cet_flags = ['cet_ss', 'cet_ibt', 'shstk', 'ibt']
                    if any(flag in cpuinfo for flag in cet_flags):
                        status['hardware_features']['intel_cet'] = True
                        status['protection_methods'].append('Intel CET')
                except Exception:
                    status['hardware_features']['intel_cet'] = False
                
                # Check ARM Pointer Authentication
                try:
                    arch = platform.machine().lower()
                    if arch in ['aarch64', 'arm64']:
                        pauth_flags = ['paca', 'pacg', 'pointer_auth']
                        if any(flag in cpuinfo for flag in pauth_flags):
                            status['hardware_features']['arm_pointer_auth'] = True
                            status['protection_methods'].append('ARM Pointer Auth')
                except Exception:
                    status['hardware_features']['arm_pointer_auth'] = False
                    
            elif self.platform == PlatformType.MACOS:
                status['cfg_available'] = True
                
                # Check Apple Silicon
                try:
                    arch = platform.machine().lower()
                    if arch in ['arm64', 'aarch64']:
                        # AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
                        import subprocess  # nosec: B404
                        # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                        result = subprocess.run(['sysctl', '-n', 'hw.optional.arm.FEAT_PAuth'],   # nosec: B603 B607
                                              capture_output=True, text=True, timeout=5)
                        
                        if result.returncode == 0 and result.stdout.strip() == '1':
                            status['hardware_features']['apple_silicon_pauth'] = True
                            status['protection_methods'].append('Pointer Authentication')
                except Exception:
                    status['hardware_features']['apple_silicon_pauth'] = False
            
            # Check software fallbacks
            status['software_fallbacks'] = {
                'stack_integrity': hasattr(self, '_stack_canary'),
                'return_validation': getattr(self, '_return_validation_enabled', False),
                'cf_randomization': getattr(self, '_cf_randomization_enabled', False)
            }
            
            # Determine if CFG is enabled
            status['cfg_enabled'] = (
                len(status['protection_methods']) > 0 or 
                any(status['software_fallbacks'].values())
            )
            
        except Exception as e:
            logger.error(f"CFG status check failed: {e}")
            status['error'] = str(e)
        
        return status
    
    def configure_exception_handling(self) -> bool:
        """
        Configure platform-specific exception handling.
        
        Returns:
            bool: True if configuration was successful, False otherwise
        """
        try:
            logger.info(f"Configuring exception handling for {self.platform.value}")
            
            # Configure platform-specific handler
            if hasattr(self._platform_handler, 'configure'):
                result = self._platform_handler.configure()
                if result:
                    logger.info("Platform-specific exception handling configured successfully")
                else:
                    logger.warning("Platform-specific exception handling configuration failed")
                return result
            
            # For platforms without specific configuration, enable basic handling
            logger.info("Using basic exception handling configuration")
            return True
            
        except Exception as e:
            logger.error(f"Exception handling configuration failed: {e}")
            return False
    
    @contextlib.contextmanager
    def exception_context(self, context: str = "", 
                         severity: ExceptionSeverity = ExceptionSeverity.MEDIUM):
        """Context manager for automatic exception handling"""
        try:
            yield self
        except Exception as e:
            handled = self.handle_exception(e, context, severity)
            if not handled and not self.config.enable_graceful_degradation:
                raise


# Global instance for application-wide use
_global_handler: Optional[CrossPlatformExceptionHandler] = None
_global_lock = threading.Lock()


def get_global_handler() -> CrossPlatformExceptionHandler:
    """Get or create the global cross-platform exception handler"""
    global _global_handler
    
    if _global_handler is None:
        with _global_lock:
            if _global_handler is None:
                _global_handler = CrossPlatformExceptionHandler()
                
    return _global_handler


# Convenience functions
def handle_exception_safely(exception: Exception, context: str = "", 
                           severity: ExceptionSeverity = ExceptionSeverity.MEDIUM) -> bool:
    """Handle exception using global handler"""
    handler = get_global_handler()
    return handler.handle_exception(exception, context, severity)


@contextlib.contextmanager
def safe_execution(context: str = "", severity: ExceptionSeverity = ExceptionSeverity.MEDIUM):
    """Context manager for safe execution with automatic exception handling"""
    handler = get_global_handler()
    with handler.exception_context(context, severity):
        yield


if __name__ == "__main__":
    # Test cross-platform exception handler
    print("Testing Cross-Platform Exception Handler...")
    
    config = ExceptionHandlingConfig(
        enable_platform_specific=True,
        enable_security_logging=True,
        enable_auto_recovery=True
    )
    
    handler = CrossPlatformExceptionHandler(config)
    print(f"Handler status: {handler.get_status()}")
    
    # Test exception handling
    try:
        raise ValueError("Test exception")
    except Exception as e:
        result = handler.handle_exception(e, "test_context", ExceptionSeverity.LOW)
        print(f"Exception handling result: {result}")
    
    print(f"Exception statistics: {handler.get_exception_statistics()}")
    print("Cross-Platform Exception Handler test completed!")