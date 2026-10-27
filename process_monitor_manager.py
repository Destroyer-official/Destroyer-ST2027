#!/usr/bin/env python
"""
Process Monitor Manager

This module provides robust process monitoring with automatic recovery capabilities,
psutil dependency management, and process integrity checking with fallback mechanisms.

Requirements addressed: 2.1, 2.2, 2.3, 8.1, 8.2
"""

import logging
import os
import platform
import sys
import threading
import time
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

# Import security components
from security_hardening_manager import SecurityHardeningError
from security_dependency_manager import SecurityDependencyManager, ProcessMonitoringError

# Threat detection engine will be imported dynamically to avoid circular imports
ThreatDetectionEngine = None
ThreatType = None
ThreatLevel = None
THREAT_DETECTION_AVAILABLE = False


class MonitoringState(Enum):
    """Process monitoring states"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    RECOVERING = "recovering"
    FAILED = "failed"


@dataclass
class ProcessInfo:
    """Process information model"""
    pid: int
    name: str = "unknown"
    status: str = "unknown"
    cpu_percent: float = 0.0
    memory_rss: int = 0
    memory_vms: int = 0
    create_time: Optional[datetime] = None
    is_running: bool = False
    last_checked: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'pid': self.pid,
            'name': self.name,
            'status': self.status,
            'cpu_percent': self.cpu_percent,
            'memory_rss': self.memory_rss,
            'memory_vms': self.memory_vms,
            'create_time': self.create_time.isoformat() if self.create_time else None,
            'is_running': self.is_running,
            'last_checked': self.last_checked.isoformat()
        }


@dataclass
class MonitoringConfig:
    """Process monitoring configuration"""
    check_interval: float = 5.0  # seconds
    recovery_attempts: int = 3
    recovery_delay: float = 2.0  # seconds
    integrity_check_interval: float = 30.0  # seconds
    memory_threshold_mb: int = 1000  # MB
    cpu_threshold_percent: float = 90.0  # %
    enable_automatic_recovery: bool = True
    enable_integrity_checking: bool = True
    log_level: str = "INFO"


@dataclass
class ProcessIntegrityResult:
    """Process integrity check result"""
    pid: int
    is_running: bool = False
    integrity_valid: bool = False
    method_used: str = "unknown"
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)


class ProcessMonitorManager:
    """
    Main process monitoring coordinator with automatic recovery capabilities
    
    Provides comprehensive process monitoring with:
    - Automatic psutil dependency management
    - Process monitoring restart on failures
    - Process integrity checking with fallback mechanisms
    - Cross-platform compatibility
    - Automatic recovery mechanisms
    
    Requirements addressed: 2.1, 2.2, 2.3, 8.1, 8.2
    """
    
    def __init__(self, config: Optional[MonitoringConfig] = None, 
                 logger: Optional[logging.Logger] = None,
                 enable_threat_detection: bool = True):
        """Initialize Process Monitor Manager"""
        self.config = config or MonitoringConfig()
        self.logger = logger or self._setup_logger()
        
        # Initialize dependency manager
        self.dependency_manager = SecurityDependencyManager(self.logger)
        
        # Monitoring state
        self.state = MonitoringState.STOPPED
        self.monitored_processes: Dict[int, ProcessInfo] = {}
        self.monitoring_thread: Optional[threading.Thread] = None
        self.integrity_thread: Optional[threading.Thread] = None
        self.recovery_thread: Optional[threading.Thread] = None
        
        # Control flags
        self._stop_monitoring = threading.Event()
        self._monitoring_lock = threading.RLock()
        
        # Recovery tracking
        self.recovery_attempts: Dict[int, int] = {}
        self.last_recovery_time: Dict[int, datetime] = {}
        
        # Callbacks
        self.process_failure_callbacks: List[Callable[[ProcessInfo], None]] = []
        self.recovery_callbacks: List[Callable[[ProcessInfo, bool], None]] = []
        
        # Platform-specific setup
        self.platform_system = platform.system().lower()
        
        # Initialize threat detection engine (dynamically to avoid circular imports)
        self.threat_detection_engine = None
        self.enable_threat_detection = enable_threat_detection
        
        if self.enable_threat_detection:
            self._initialize_threat_detection()
        
        self.logger.info(f"ProcessMonitorManager initialized for {self.platform_system}")
        
        # Ensure psutil is available
        self._ensure_psutil_available()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup dedicated logger for process monitoring"""
        logger = logging.getLogger("process_monitor_manager")
        logger.setLevel(getattr(logging, self.config.log_level))
        
        # Ensure logs directory exists
        if not os.path.exists("logs"):
            os.makedirs("logs")
        
        # File handler
        file_handler = logging.FileHandler(
            os.path.join("logs", "process_monitor_manager.log"))
        file_handler.setLevel(logging.DEBUG)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Let logs propagate to root logger for console output (avoid duplicate handlers)
        logger.propagate = True
        
        return logger
    
    def _initialize_threat_detection(self):
        """Initialize threat detection engine dynamically to avoid circular imports"""
        try:
            # Import dynamically to avoid circular import
            from threat_detection_engine import ThreatDetectionEngine, ThreatType, ThreatLevel
            
            self.threat_detection_engine = ThreatDetectionEngine(self.logger, self)
            self.logger.debug("ThreatDetectionEngine initialized successfully")
            
            # Update global flags
            global THREAT_DETECTION_AVAILABLE
            THREAT_DETECTION_AVAILABLE = True
            
        except ImportError as e:
            self.logger.warning(f"ThreatDetectionEngine not available: {e}")
            self.enable_threat_detection = False
        except Exception as e:
            self.logger.error(f"Failed to initialize ThreatDetectionEngine: {str(e)}")
            self.enable_threat_detection = False
    
    def _ensure_psutil_available(self) -> bool:
        """
        Ensure psutil is available with automatic installation and fallback
        
        Returns:
            bool: True if psutil is available (installed or fallback)
        """
        self.logger.info("Ensuring psutil availability")
        
        try:
            # Use dependency manager to handle psutil
            psutil_available = self.dependency_manager.psutil_manager.detect_and_install_psutil()
            
            if psutil_available:
                # Validate psutil functionality
                validation_results = self.dependency_manager.psutil_manager.validate_psutil_process_attributes()
                
                if validation_results.get('fallback_needed', False):
                    self.logger.warning("psutil validation indicates fallback needed")
                    self._setup_fallback_monitoring()
                else:
                    self.logger.info("psutil validation successful")
                
                return True
            else:
                self.logger.error("Failed to ensure psutil availability")
                return False
                
        except Exception as e:
            error = ProcessMonitoringError(
                f"Error ensuring psutil availability: {str(e)}",
                error_code="PSUTIL_SETUP_ERROR"
            )
            self.logger.error(str(error))
            return False
    
    def _setup_fallback_monitoring(self):
        """Setup fallback monitoring when psutil is limited"""
        try:
            self.fallback_monitor = self.dependency_manager.psutil_manager.create_fallback_process_monitoring()
            self.logger.info("Fallback process monitoring setup complete")
        except Exception as e:
            self.logger.error(f"Failed to setup fallback monitoring: {str(e)}")
    
    def start_monitoring(self) -> bool:
        """
        Start process monitoring with automatic recovery
        
        Returns:
            bool: True if monitoring started successfully
        """
        with self._monitoring_lock:
            if self.state == MonitoringState.RUNNING:
                self.logger.warning("Process monitoring already running")
                return True
            
            try:
                self.logger.info("Starting process monitoring")
                self.state = MonitoringState.STARTING
                
                # Clear stop event
                self._stop_monitoring.clear()
                
                # Start threat detection engine if enabled
                if self.enable_threat_detection and self.threat_detection_engine:
                    if not self.threat_detection_engine.start_threat_detection():
                        self.logger.warning("Failed to start threat detection - continuing without it")
                        self.enable_threat_detection = False
                
                # Start monitoring thread
                self.monitoring_thread = threading.Thread(
                    target=self._monitoring_loop,
                    name="ProcessMonitoringThread",
                    daemon=True
                )
                self.monitoring_thread.start()
                
                # Start integrity checking thread if enabled
                if self.config.enable_integrity_checking:
                    self.integrity_thread = threading.Thread(
                        target=self._integrity_check_loop,
                        name="IntegrityCheckThread",
                        daemon=True
                    )
                    self.integrity_thread.start()
                
                self.state = MonitoringState.RUNNING
                self.logger.debug("Process monitoring started successfully")
                return True
                
            except Exception as e:
                self.state = MonitoringState.FAILED
                error = ProcessMonitoringError(
                    f"Failed to start process monitoring: {str(e)}",
                    error_code="MONITORING_START_ERROR"
                )
                self.logger.error(str(error))
                return False
    
    def stop_monitoring(self) -> bool:
        """
        Stop process monitoring
        
        Returns:
            bool: True if monitoring stopped successfully
        """
        with self._monitoring_lock:
            if self.state == MonitoringState.STOPPED:
                self.logger.warning("Process monitoring already stopped")
                return True
            
            try:
                self.logger.info("Stopping process monitoring")
                
                # Stop threat detection engine
                if self.enable_threat_detection and self.threat_detection_engine:
                    self.threat_detection_engine.stop_threat_detection()
                
                # Signal threads to stop
                self._stop_monitoring.set()
                
                # Wait for threads to finish
                if self.monitoring_thread and self.monitoring_thread.is_alive():
                    self.monitoring_thread.join(timeout=10.0)
                
                if self.integrity_thread and self.integrity_thread.is_alive():
                    self.integrity_thread.join(timeout=5.0)
                
                if self.recovery_thread and self.recovery_thread.is_alive():
                    self.recovery_thread.join(timeout=5.0)
                
                self.state = MonitoringState.STOPPED
                self.logger.info("Process monitoring stopped successfully")
                return True
                
            except Exception as e:
                error = ProcessMonitoringError(
                    f"Failed to stop process monitoring: {str(e)}",
                    error_code="MONITORING_STOP_ERROR"
                )
                self.logger.error(str(error))
                return False
    
    def add_process(self, pid: int) -> bool:
        """
        Add process to monitoring
        
        Args:
            pid: Process ID to monitor
            
        Returns:
            bool: True if process added successfully
        """
        try:
            self.logger.info(f"Adding process {pid} to monitoring")
            
            # Get process information
            process_info = self._get_process_info(pid)
            
            if process_info and process_info.is_running:
                with self._monitoring_lock:
                    self.monitored_processes[pid] = process_info
                    self.recovery_attempts[pid] = 0
                
                self.logger.info(f"Process {pid} ({process_info.name}) added to monitoring")
                return True
            else:
                self.logger.error(f"Process {pid} not found or not running")
                return False
                
        except Exception as e:
            error = ProcessMonitoringError(
                f"Failed to add process {pid} to monitoring: {str(e)}",
                error_code="ADD_PROCESS_ERROR"
            )
            self.logger.error(str(error))
            return False
    
    def remove_process(self, pid: int) -> bool:
        """
        Remove process from monitoring
        
        Args:
            pid: Process ID to remove
            
        Returns:
            bool: True if process removed successfully
        """
        try:
            with self._monitoring_lock:
                if pid in self.monitored_processes:
                    process_info = self.monitored_processes.pop(pid)
                    self.recovery_attempts.pop(pid, None)
                    self.last_recovery_time.pop(pid, None)
                    
                    self.logger.info(f"Process {pid} ({process_info.name}) removed from monitoring")
                    return True
                else:
                    self.logger.warning(f"Process {pid} not in monitoring list")
                    return False
                    
        except Exception as e:
            error = ProcessMonitoringError(
                f"Failed to remove process {pid} from monitoring: {str(e)}",
                error_code="REMOVE_PROCESS_ERROR"
            )
            self.logger.error(str(error))
            return False  
  
    def _monitoring_loop(self):
        """Main monitoring loop"""
        self.logger.info("Process monitoring loop started")
        
        while not self._stop_monitoring.is_set():
            try:
                with self._monitoring_lock:
                    pids_to_check = list(self.monitored_processes.keys())
                
                for pid in pids_to_check:
                    try:
                        self._check_process(pid)
                    except Exception as e:
                        self.logger.error(f"Error checking process {pid}: {str(e)}")
                
                # Wait for next check interval
                self._stop_monitoring.wait(self.config.check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(1.0)  # Brief pause before continuing
        
        self.logger.info("Process monitoring loop stopped")
    
    def _integrity_check_loop(self):
        """Integrity checking loop"""
        self.logger.info("Process integrity checking loop started")
        
        while not self._stop_monitoring.is_set():
            try:
                with self._monitoring_lock:
                    pids_to_check = list(self.monitored_processes.keys())
                
                for pid in pids_to_check:
                    try:
                        self._check_process_integrity(pid)
                    except Exception as e:
                        self.logger.error(f"Error checking integrity for process {pid}: {str(e)}")
                
                # Wait for next integrity check interval
                self._stop_monitoring.wait(self.config.integrity_check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in integrity check loop: {str(e)}")
                time.sleep(5.0)  # Brief pause before continuing
        
        self.logger.info("Process integrity checking loop stopped")
    
    def _check_process(self, pid: int):
        """Check individual process status"""
        try:
            # Get current process info
            current_info = self._get_process_info(pid)
            
            with self._monitoring_lock:
                if pid not in self.monitored_processes:
                    return  # Process was removed from monitoring
                
                previous_info = self.monitored_processes[pid]
                
                if current_info and current_info.is_running:
                    # Update process info
                    self.monitored_processes[pid] = current_info
                    
                    # Check thresholds
                    self._check_thresholds(current_info)
                    
                    # Reset recovery attempts on successful check
                    if self.recovery_attempts.get(pid, 0) > 0:
                        self.logger.info(f"Process {pid} recovered successfully")
                        self.recovery_attempts[pid] = 0
                        
                        # Notify recovery callbacks
                        for callback in self.recovery_callbacks:
                            try:
                                callback(current_info, True)
                            except Exception as e:
                                self.logger.error(f"Recovery callback error: {str(e)}")
                
                else:
                    # Process is not running
                    self.logger.warning(f"Process {pid} ({previous_info.name}) is not running")
                    
                    # Notify failure callbacks
                    for callback in self.process_failure_callbacks:
                        try:
                            callback(previous_info)
                        except Exception as e:
                            self.logger.error(f"Failure callback error: {str(e)}")
                    
                    # Generate threat event for process failure
                    if self.enable_threat_detection and self.threat_detection_engine:
                        try:
                            self.threat_detection_engine._generate_threat_event(
                                ThreatType.PROCESS_ANOMALY,
                                ThreatLevel.HIGH,
                                f"Process {pid} ({previous_info.name}) stopped unexpectedly",
                                f"Monitored process {pid} is no longer running",
                                details={
                                    'pid': pid,
                                    'process_name': previous_info.name,
                                    'last_status': previous_info.status,
                                    'recovery_attempts': self.recovery_attempts.get(pid, 0)
                                },
                                remediation_steps=[
                                    "Check process logs for crash information",
                                    "Verify system resources are available",
                                    "Consider automatic restart if appropriate",
                                    "Monitor for repeated failures"
                                ],
                                auto_recoverable=self.config.enable_automatic_recovery
                            )
                        except Exception as e:
                            self.logger.error(f"Error generating threat event for process failure: {str(e)}")
                    
                    # Attempt recovery if enabled
                    if self.config.enable_automatic_recovery:
                        self._attempt_recovery(pid, previous_info)
                    else:
                        # Remove from monitoring if recovery is disabled
                        self.monitored_processes.pop(pid, None)
                        self.recovery_attempts.pop(pid, None)
                        self.last_recovery_time.pop(pid, None)
                        
        except Exception as e:
            self.logger.error(f"Error checking process {pid}: {str(e)}")
    
    def _check_process_integrity(self, pid: int):
        """Check process integrity using advanced methods"""
        try:
            with self._monitoring_lock:
                if pid not in self.monitored_processes:
                    return
                
                process_info = self.monitored_processes[pid]
            
            # Use dependency manager for integrity checking
            integrity_ok = self.dependency_manager.psutil_manager.psutil_status.installed
            
            if integrity_ok:
                try:
                    import psutil
                    process = psutil.Process(pid)
                    
                    # Check if process is still the same (not replaced)
                    current_create_time = datetime.fromtimestamp(process.create_time())
                    
                    if (process_info.create_time and 
                        abs((current_create_time - process_info.create_time).total_seconds()) > 1.0):
                        self.logger.warning(f"Process {pid} may have been replaced (create time mismatch)")
                        integrity_ok = False
                    
                    # Check process name consistency
                    current_name = process.name()
                    if current_name != process_info.name:
                        self.logger.warning(f"Process {pid} name changed from {process_info.name} to {current_name}")
                        # Update name but don't fail integrity
                        with self._monitoring_lock:
                            self.monitored_processes[pid].name = current_name
                    
                except Exception as e:
                    self.logger.error(f"Integrity check failed for process {pid}: {str(e)}")
                    integrity_ok = False
            else:
                # Use fallback integrity checking
                integrity_ok = self._fallback_integrity_check(pid)
            
            if not integrity_ok:
                self.logger.error(f"Process {pid} failed integrity check")
                
                # Generate threat event for integrity violation
                if self.enable_threat_detection and self.threat_detection_engine:
                    try:
                        self.threat_detection_engine._generate_threat_event(
                            ThreatType.INTEGRITY_VIOLATION,
                            ThreatLevel.HIGH,
                            f"Process integrity violation detected for PID {pid}",
                            f"Process {process_info.name} failed integrity verification",
                            details={
                                'pid': pid,
                                'process_name': process_info.name,
                                'integrity_check_method': 'process_monitor_integrity_check'
                            },
                            remediation_steps=[
                                "Restart the affected process",
                                "Check for system tampering or malware",
                                "Verify process binary integrity",
                                "Review system logs for suspicious activity",
                                "Consider isolating the system if compromise is suspected"
                            ],
                            auto_recoverable=self.config.enable_automatic_recovery
                        )
                    except Exception as e:
                        self.logger.error(f"Error generating integrity violation threat event: {str(e)}")
                
                # Trigger recovery if enabled
                if self.config.enable_automatic_recovery:
                    self._attempt_recovery(pid, process_info)
                    
        except Exception as e:
            self.logger.error(f"Error in integrity check for process {pid}: {str(e)}")
    
    def _fallback_integrity_check(self, pid: int) -> bool:
        """Fallback integrity check when psutil is limited"""
        try:
            if hasattr(self, 'fallback_monitor'):
                return self.fallback_monitor.check_process_integrity(pid)
            else:
                # Basic platform-specific check
                if self.platform_system == "windows":
                    return self._windows_process_exists(pid)
                else:
                    return self._unix_process_exists(pid)
        except Exception as e:
            self.logger.error(f"Fallback integrity check failed for {pid}: {str(e)}")
            return False
    
    def _windows_process_exists(self, pid: int) -> bool:
        """Check if process exists on Windows"""
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x400, False, pid)  # PROCESS_QUERY_INFORMATION
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    
    def _unix_process_exists(self, pid: int) -> bool:
        """Check if process exists on Unix-like systems"""
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False
    
    def _check_thresholds(self, process_info: ProcessInfo):
        """Check if process exceeds configured thresholds"""
        try:
            # Memory threshold check
            memory_mb = process_info.memory_rss / (1024 * 1024)  # Convert to MB
            if memory_mb > self.config.memory_threshold_mb:
                self.logger.warning(
                    f"Process {process_info.pid} ({process_info.name}) "
                    f"exceeds memory threshold: {memory_mb:.1f}MB > {self.config.memory_threshold_mb}MB"
                )
                
                # Generate threat event for memory anomaly
                if self.enable_threat_detection and self.threat_detection_engine:
                    try:
                        self.threat_detection_engine._generate_threat_event(
                            ThreatType.MEMORY_ANOMALY,
                            ThreatLevel.MEDIUM,
                            f"High memory usage detected in process {process_info.pid}",
                            f"Process {process_info.name} is using {memory_mb:.1f}MB, exceeding threshold of {self.config.memory_threshold_mb}MB",
                            details={
                                'pid': process_info.pid,
                                'process_name': process_info.name,
                                'memory_usage_mb': memory_mb,
                                'threshold_mb': self.config.memory_threshold_mb,
                                'memory_rss': process_info.memory_rss,
                                'memory_vms': process_info.memory_vms
                            },
                            remediation_steps=[
                                "Monitor process for memory leaks",
                                "Check if high memory usage is expected",
                                "Consider restarting process if memory continues to grow",
                                "Review process configuration and limits"
                            ],
                            auto_recoverable=False
                        )
                    except Exception as e:
                        self.logger.error(f"Error generating memory anomaly threat event: {str(e)}")
            
            # CPU threshold check
            if process_info.cpu_percent > self.config.cpu_threshold_percent:
                self.logger.warning(
                    f"Process {process_info.pid} ({process_info.name}) "
                    f"exceeds CPU threshold: {process_info.cpu_percent:.1f}% > {self.config.cpu_threshold_percent}%"
                )
                
                # Generate threat event for CPU anomaly
                if self.enable_threat_detection and self.threat_detection_engine:
                    try:
                        self.threat_detection_engine._generate_threat_event(
                            ThreatType.CPU_ANOMALY,
                            ThreatLevel.MEDIUM,
                            f"High CPU usage detected in process {process_info.pid}",
                            f"Process {process_info.name} is using {process_info.cpu_percent:.1f}% CPU, exceeding threshold of {self.config.cpu_threshold_percent}%",
                            details={
                                'pid': process_info.pid,
                                'process_name': process_info.name,
                                'cpu_percent': process_info.cpu_percent,
                                'threshold_percent': self.config.cpu_threshold_percent
                            },
                            remediation_steps=[
                                "Monitor process for CPU-intensive operations",
                                "Check if high CPU usage is expected",
                                "Consider process optimization or resource limits",
                                "Review system load and other processes"
                            ],
                            auto_recoverable=False
                        )
                    except Exception as e:
                        self.logger.error(f"Error generating CPU anomaly threat event: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error checking thresholds for process {process_info.pid}: {str(e)}")
    
    def _attempt_recovery(self, pid: int, process_info: ProcessInfo):
        """Attempt to recover a failed process"""
        try:
            with self._monitoring_lock:
                current_attempts = self.recovery_attempts.get(pid, 0)
                
                if current_attempts >= self.config.recovery_attempts:
                    self.logger.error(
                        f"Process {pid} ({process_info.name}) exceeded maximum recovery attempts ({current_attempts})"
                    )
                    # Remove from monitoring
                    self.monitored_processes.pop(pid, None)
                    self.recovery_attempts.pop(pid, None)
                    self.last_recovery_time.pop(pid, None)
                    
                    # Notify recovery callbacks with failure
                    for callback in self.recovery_callbacks:
                        try:
                            callback(process_info, False)
                        except Exception as e:
                            self.logger.error(f"Recovery callback error: {str(e)}")
                    
                    return
                
                # Check recovery delay
                last_recovery = self.last_recovery_time.get(pid)
                if last_recovery:
                    time_since_last = datetime.now() - last_recovery
                    if time_since_last.total_seconds() < self.config.recovery_delay:
                        return  # Too soon for another recovery attempt
                
                # Increment recovery attempts
                self.recovery_attempts[pid] = current_attempts + 1
                self.last_recovery_time[pid] = datetime.now()
            
            self.logger.info(
                f"Attempting recovery for process {pid} ({process_info.name}) "
                f"- attempt {current_attempts + 1}/{self.config.recovery_attempts}"
            )
            
            # Start recovery in separate thread to avoid blocking monitoring
            if not self.recovery_thread or not self.recovery_thread.is_alive():
                self.recovery_thread = threading.Thread(
                    target=self._recovery_worker,
                    args=(pid, process_info),
                    name=f"RecoveryThread-{pid}",
                    daemon=True
                )
                self.recovery_thread.start()
                
        except Exception as e:
            self.logger.error(f"Error attempting recovery for process {pid}: {str(e)}")
    
    def _recovery_worker(self, pid: int, process_info: ProcessInfo):
        """Worker thread for process recovery"""
        try:
            self.logger.info(f"Starting recovery worker for process {pid}")
            
            # Wait for recovery delay
            time.sleep(self.config.recovery_delay)
            
            # Check if process has recovered on its own
            current_info = self._get_process_info(pid)
            if current_info and current_info.is_running:
                self.logger.info(f"Process {pid} recovered automatically")
                with self._monitoring_lock:
                    self.monitored_processes[pid] = current_info
                    self.recovery_attempts[pid] = 0
                return
            
            # Implement recovery logic here
            # This is a placeholder for actual recovery mechanisms
            # which would depend on the specific application requirements
            self.logger.warning(f"Recovery worker completed for process {pid} - no automatic recovery implemented")
            
        except Exception as e:
            self.logger.error(f"Error in recovery worker for process {pid}: {str(e)}")
    
    def _get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get comprehensive process information"""
        try:
            # Try using psutil first
            if self.dependency_manager.psutil_manager.psutil_status.installed:
                try:
                    import psutil
                    process = psutil.Process(pid)
                    
                    # Get memory info
                    memory_info = process.memory_info()
                    
                    return ProcessInfo(
                        pid=pid,
                        name=process.name(),
                        status=process.status(),
                        cpu_percent=process.cpu_percent(),
                        memory_rss=memory_info.rss,
                        memory_vms=memory_info.vms,
                        create_time=datetime.fromtimestamp(process.create_time()),
                        is_running=process.is_running(),
                        last_checked=datetime.now()
                    )
                    
                except Exception as e:
                    self.logger.warning(f"psutil failed for process {pid}: {str(e)}")
                    # Fall through to fallback
            
            # Use fallback methods
            return self._get_fallback_process_info(pid)
            
        except Exception as e:
            self.logger.error(f"Error getting process info for {pid}: {str(e)}")
            return None
    
    def _get_fallback_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get process information using fallback methods"""
        try:
            if hasattr(self, 'fallback_monitor'):
                monitor_result = self.fallback_monitor.monitor_current_process()
                if monitor_result.get('pid') == pid:
                    return ProcessInfo(
                        pid=pid,
                        name=monitor_result.get('name', 'unknown'),
                        status='running' if monitor_result.get('is_running', False) else 'stopped',
                        cpu_percent=monitor_result.get('cpu_percent', 0.0),
                        memory_rss=getattr(monitor_result.get('memory_info', {}), 'rss', 0),
                        memory_vms=getattr(monitor_result.get('memory_info', {}), 'vms', 0),
                        is_running=monitor_result.get('is_running', False),
                        last_checked=datetime.now()
                    )
            
            # Basic fallback - just check if process exists
            if self.platform_system == "windows":
                is_running = self._windows_process_exists(pid)
            else:
                is_running = self._unix_process_exists(pid)
            
            if is_running:
                return ProcessInfo(
                    pid=pid,
                    name=f"process_{pid}",
                    status='running',
                    is_running=True,
                    last_checked=datetime.now()
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in fallback process info for {pid}: {str(e)}")
            return None
    
    def get_monitored_processes(self) -> Dict[int, ProcessInfo]:
        """Get all monitored processes"""
        with self._monitoring_lock:
            return {pid: info for pid, info in self.monitored_processes.items()}
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get comprehensive monitoring status"""
        with self._monitoring_lock:
            return {
                'state': self.state.value,
                'monitored_process_count': len(self.monitored_processes),
                'monitored_pids': list(self.monitored_processes.keys()),
                'recovery_attempts': dict(self.recovery_attempts),
                'psutil_status': self.dependency_manager.psutil_manager.get_psutil_status().to_dict(),
                'config': {
                    'check_interval': self.config.check_interval,
                    'recovery_attempts': self.config.recovery_attempts,
                    'recovery_delay': self.config.recovery_delay,
                    'integrity_check_interval': self.config.integrity_check_interval,
                    'enable_automatic_recovery': self.config.enable_automatic_recovery,
                    'enable_integrity_checking': self.config.enable_integrity_checking
                },
                'threads': {
                    'monitoring_thread_alive': self.monitoring_thread.is_alive() if self.monitoring_thread else False,
                    'integrity_thread_alive': self.integrity_thread.is_alive() if self.integrity_thread else False,
                    'recovery_thread_alive': self.recovery_thread.is_alive() if self.recovery_thread else False
                }
            }
    
    def add_process_failure_callback(self, callback: Callable[[ProcessInfo], None]):
        """Add callback for process failure events"""
        self.process_failure_callbacks.append(callback)
    
    def add_recovery_callback(self, callback: Callable[[ProcessInfo, bool], None]):
        """Add callback for recovery events"""
        self.recovery_callbacks.append(callback)
    
    def restart_monitoring(self) -> bool:
        """Restart monitoring after failure"""
        try:
            self.logger.info("Restarting process monitoring")
            
            # Stop current monitoring
            if self.state != MonitoringState.STOPPED:
                self.stop_monitoring()
            
            # Brief pause
            time.sleep(1.0)
            
            # Restart monitoring
            return self.start_monitoring()
            
        except Exception as e:
            error = ProcessMonitoringError(
                f"Failed to restart monitoring: {str(e)}",
                error_code="MONITORING_RESTART_ERROR"
            )
            self.logger.error(str(error))
            return False
    
    def get_threat_detection_status(self) -> Dict[str, Any]:
        """
        Get current threat detection status
        
        Returns:
            Dict containing threat detection status information
        """
        try:
            if not self.enable_threat_detection or not self.threat_detection_engine:
                return {
                    'enabled': False,
                    'available': THREAT_DETECTION_AVAILABLE,
                    'reason': 'Threat detection not enabled or not available'
                }
            
            security_status = self.threat_detection_engine.get_security_status()
            
            return {
                'enabled': True,
                'available': True,
                'monitoring_active': security_status.monitoring_active,
                'threat_detection_active': security_status.threat_detection_active,
                'hardware_security_available': security_status.hardware_security_available,
                'platform_security_features': security_status.platform_security_features,
                'active_threats_count': len(security_status.active_threats),
                'total_threats_detected': security_status.total_threats_detected,
                'security_degradation_level': security_status.security_degradation_level,
                'last_security_check': security_status.last_security_check.isoformat() if security_status.last_security_check else None
            }
            
        except Exception as e:
            self.logger.error(f"Error getting threat detection status: {str(e)}")
            return {
                'enabled': self.enable_threat_detection,
                'available': THREAT_DETECTION_AVAILABLE,
                'error': str(e)
            }
    
    def get_active_threats(self) -> List[Dict[str, Any]]:
        """
        Get list of currently active security threats
        
        Returns:
            List of active threat events
        """
        try:
            if not self.enable_threat_detection or not self.threat_detection_engine:
                return []
            
            security_status = self.threat_detection_engine.get_security_status()
            return [threat.to_dict() for threat in security_status.active_threats]
            
        except Exception as e:
            self.logger.error(f"Error getting active threats: {str(e)}")
            return []
    
    def get_threat_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get threat detection history
        
        Args:
            limit: Maximum number of historical threats to return
            
        Returns:
            List of historical threat events
        """
        try:
            if not self.enable_threat_detection or not self.threat_detection_engine:
                return []
            
            history = self.threat_detection_engine.get_threat_history(limit)
            return [threat.to_dict() for threat in history]
            
        except Exception as e:
            self.logger.error(f"Error getting threat history: {str(e)}")
            return []
    
    def add_threat_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Add callback for threat detection events
        
        Args:
            callback: Function to call when threats are detected
        """
        try:
            if self.enable_threat_detection and self.threat_detection_engine:
                # Wrap the callback to convert ThreatEvent to dict
                def wrapped_callback(threat_event):
                    try:
                        callback(threat_event.to_dict())
                    except Exception as e:
                        self.logger.error(f"Error in threat callback: {str(e)}")
                
                self.threat_detection_engine.add_threat_callback(wrapped_callback)
                self.logger.info("Threat detection callback added")
            else:
                self.logger.warning("Cannot add threat callback - threat detection not available")
                
        except Exception as e:
            self.logger.error(f"Error adding threat callback: {str(e)}")
    
    def trigger_security_check(self) -> bool:
        """
        Manually trigger a comprehensive security check
        
        Returns:
            bool: True if security check was triggered successfully
        """
        try:
            if not self.enable_threat_detection or not self.threat_detection_engine:
                self.logger.warning("Cannot trigger security check - threat detection not available")
                return False
            
            # Trigger immediate security check
            self.threat_detection_engine._perform_comprehensive_security_check()
            self.logger.info("Manual security check triggered")
            return True
            
        except Exception as e:
            self.logger.error(f"Error triggering security check: {str(e)}")
            return False
    
    def analyze_process_behavior(self, pid: int) -> Dict[str, Any]:
        """
        Analyze behavior of a specific process for anomalies
        
        Args:
            pid: Process ID to analyze
            
        Returns:
            Dict containing behavior analysis results
        """
        try:
            if not self.enable_threat_detection or not self.threat_detection_engine:
                return {
                    'pid': pid,
                    'analysis_available': False,
                    'reason': 'Threat detection not available'
                }
            
            # Get current process info
            process_info = self._get_process_info(pid)
            if not process_info:
                return {
                    'pid': pid,
                    'analysis_available': False,
                    'reason': 'Process not found or not accessible'
                }
            
            # Perform basic behavior analysis
            analysis = {
                'pid': pid,
                'analysis_available': True,
                'process_name': process_info.name,
                'status': process_info.status,
                'cpu_percent': process_info.cpu_percent,
                'memory_rss_mb': process_info.memory_rss / (1024 * 1024),
                'memory_vms_mb': process_info.memory_vms / (1024 * 1024),
                'is_running': process_info.is_running,
                'anomalies_detected': []
            }
            
            # Check for anomalies
            if process_info.cpu_percent > self.config.cpu_threshold_percent:
                analysis['anomalies_detected'].append({
                    'type': 'high_cpu_usage',
                    'severity': 'medium',
                    'value': process_info.cpu_percent,
                    'threshold': self.config.cpu_threshold_percent
                })
            
            memory_mb = process_info.memory_rss / (1024 * 1024)
            if memory_mb > self.config.memory_threshold_mb:
                analysis['anomalies_detected'].append({
                    'type': 'high_memory_usage',
                    'severity': 'medium',
                    'value': memory_mb,
                    'threshold': self.config.memory_threshold_mb
                })
            
            # Check if process has been restarted frequently
            recovery_count = self.recovery_attempts.get(pid, 0)
            if recovery_count > 0:
                analysis['anomalies_detected'].append({
                    'type': 'frequent_restarts',
                    'severity': 'high' if recovery_count >= self.config.recovery_attempts else 'medium',
                    'value': recovery_count,
                    'threshold': self.config.recovery_attempts
                })
            
            analysis['anomaly_count'] = len(analysis['anomalies_detected'])
            analysis['risk_level'] = self._calculate_risk_level(analysis['anomalies_detected'])
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing process behavior for {pid}: {str(e)}")
            return {
                'pid': pid,
                'analysis_available': False,
                'error': str(e)
            }
    
    def _calculate_risk_level(self, anomalies: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level based on detected anomalies"""
        if not anomalies:
            return 'low'
        
        high_severity_count = sum(1 for a in anomalies if a.get('severity') == 'high')
        medium_severity_count = sum(1 for a in anomalies if a.get('severity') == 'medium')
        
        if high_severity_count >= 2:
            return 'critical'
        elif high_severity_count >= 1:
            return 'high'
        elif medium_severity_count >= 3:
            return 'high'
        elif medium_severity_count >= 1:
            return 'medium'
        else:
            return 'low'


def main():
    """Main function for testing ProcessMonitorManager"""
    try:
        print("Testing ProcessMonitorManager...")
        
        # Create configuration
        config = MonitoringConfig(
            check_interval=2.0,
            recovery_attempts=2,
            enable_automatic_recovery=True,
            enable_integrity_checking=True,
            log_level="DEBUG"
        )
        
        # Create manager
        manager = ProcessMonitorManager(config)
        
        # Start monitoring
        if manager.start_monitoring():
            print("Monitoring started successfully")
            
            # Add current process to monitoring
            current_pid = os.getpid()
            if manager.add_process(current_pid):
                print(f"Added process {current_pid} to monitoring")
                
                # Let it run for a bit
                time.sleep(10)
                
                # Get status
                status = manager.get_monitoring_status()
                print(f"Monitoring status: {status}")
                
                # Get monitored processes
                processes = manager.get_monitored_processes()
                print(f"Monitored processes: {processes}")
            
            # Stop monitoring
            if manager.stop_monitoring():
                print("Monitoring stopped successfully")
        
        print("ProcessMonitorManager test completed")
        
    except Exception as e:
        print(f"ProcessMonitorManager test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()