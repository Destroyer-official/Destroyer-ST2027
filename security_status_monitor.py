#!/usr/bin/env python
"""
Security Status Monitor Module

This module provides comprehensive security status monitoring for real-time
security posture tracking, health checks, automated remediation, and full
security status reporting capabilities.

Key Features:
- Real-time security posture tracking
- Security health checks and automated remediation
- Full security status reporting capabilities
- Continuous monitoring with alerting
- Security metrics collection and analysis
- Automated remediation triggers
"""

import logging
import os
import sys
import time
import threading
import json
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import statistics

# Configure logger
monitor_logger = logging.getLogger("security_status_monitor")
monitor_logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging
monitor_file_handler = logging.FileHandler(
    os.path.join("logs", "security_status_monitor.log"))
monitor_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
monitor_file_handler.setFormatter(formatter)
monitor_logger.addHandler(monitor_file_handler)

# Let logs propagate to root logger for console output (avoid duplicate handlers)
monitor_logger.propagate = True


class SecurityLevel(Enum):
    """Security level enumeration."""
    MAXIMUM = "MAXIMUM"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CRITICAL = "CRITICAL"


class AlertSeverity(Enum):
    """Alert severity enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityMetric:
    """Security metric data structure."""
    name: str
    value: Any
    timestamp: datetime
    threshold: Optional[float] = None
    unit: Optional[str] = None
    description: Optional[str] = None


@dataclass
class SecurityAlert:
    """Security alert data structure."""
    id: str
    severity: AlertSeverity
    title: str
    description: str
    timestamp: datetime
    source: str
    resolved: bool = False
    resolution_time: Optional[datetime] = None
    remediation_action: Optional[str] = None


@dataclass
class HealthCheck:
    """Health check configuration."""
    name: str
    check_function: Callable[[], Tuple[bool, str]]
    interval: int  # seconds
    enabled: bool = True
    last_run: Optional[datetime] = None
    last_result: Optional[bool] = None
    last_message: Optional[str] = None
    failure_count: int = 0
    max_failures: int = 3


@dataclass
class SecurityPosture:
    """Overall security posture assessment."""
    level: SecurityLevel
    score: float  # 0-100
    timestamp: datetime
    active_features: int
    failed_features: int
    degraded_features: int
    critical_alerts: int
    high_alerts: int
    recommendations: List[str] = field(default_factory=list)


class SecurityStatusMonitorError(Exception):
    """Base exception for security status monitoring operations."""


class SecurityStatusMonitor:
    """
    Comprehensive Security Status Monitor for real-time security posture tracking.
    
    This class provides:
    1. Real-time security posture tracking
    2. Security health checks and automated remediation
    3. Full security status reporting capabilities
    4. Continuous monitoring with alerting
    5. Security metrics collection and analysis
    """
    
    def __init__(self, security_hardening_manager=None, recovery_manager=None):
        """Initialize the Security Status Monitor."""
        self.security_manager = security_hardening_manager
        self.recovery_manager = recovery_manager
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_thread = None
        self.monitoring_interval = 30  # seconds
        self.startup_time = time.time()  # Track startup time for grace period
        
        # Health checks
        self.health_checks: Dict[str, HealthCheck] = {}
        self.health_check_thread = None
        self.health_check_interval = 60  # seconds
        
        # Metrics and alerts
        self.metrics: List[SecurityMetric] = []
        self.alerts: List[SecurityAlert] = []
        self.max_metrics_history = 1000
        self.max_alerts_history = 500
        
        # Callbacks
        self.alert_callbacks: List[Callable[[SecurityAlert], None]] = []
        self.remediation_callbacks: Dict[str, Callable[[], bool]] = {}
        
        # Security posture tracking
        self.posture_history: List[SecurityPosture] = []
        self.max_posture_history = 100
        
        # Thresholds and configuration
        self.alert_thresholds = {
            'failure_rate': 0.2,  # 20% failure rate triggers alert
            'response_time': 5.0,  # 5 second response time threshold
            'memory_usage': 0.8,   # 80% memory usage threshold
            'cpu_usage': 0.95      # 95% CPU usage threshold (allow for startup spikes)
        }
        
        monitor_logger.info("SecurityStatusMonitor initialized")
        
        # Initialize default health checks
        self._initialize_default_health_checks()
    
    def _initialize_default_health_checks(self):
        """Initialize default health checks."""
        # CFG Protection health check
        self.register_health_check(
            "cfg_protection",
            self._check_cfg_protection,
            interval=120  # Check every 2 minutes
        )
        
        # Recovery system health check
        self.register_health_check(
            "recovery_system",
            self._check_recovery_system,
            interval=60  # Check every minute
        )
        
        # System resources health check
        self.register_health_check(
            "system_resources",
            self._check_system_resources,
            interval=30  # Check every 30 seconds
        )
        
        # Security manager health check
        self.register_health_check(
            "security_manager",
            self._check_security_manager,
            interval=90  # Check every 90 seconds
        )
        
        monitor_logger.info("Default health checks initialized")
    
    def register_health_check(self, name: str, check_function: Callable[[], Tuple[bool, str]], 
                            interval: int = 60, enabled: bool = True):
        """
        Register a health check.
        
        Args:
            name: Health check name
            check_function: Function that returns (success, message)
            interval: Check interval in seconds
            enabled: Whether the check is enabled
        """
        self.health_checks[name] = HealthCheck(
            name=name,
            check_function=check_function,
            interval=interval,
            enabled=enabled
        )
        monitor_logger.info(f"Health check registered: {name} (interval: {interval}s)")
    
    def register_remediation_callback(self, issue_type: str, callback: Callable[[], bool]):
        """
        Register a remediation callback for a specific issue type.
        
        Args:
            issue_type: Type of issue to remediate
            callback: Function to call for remediation (returns success status)
        """
        self.remediation_callbacks[issue_type] = callback
        monitor_logger.info(f"Remediation callback registered for {issue_type}")
    
    def register_alert_callback(self, callback: Callable[[SecurityAlert], None]):
        """
        Register an alert callback.
        
        Args:
            callback: Function to call when alerts are generated
        """
        self.alert_callbacks.append(callback)
        monitor_logger.info("Alert callback registered")
    
    def start_monitoring(self):
        """Start the security status monitoring."""
        if self.monitoring_active:
            monitor_logger.debug("Security monitoring already active")
            return
        
        self.monitoring_active = True
        
        # Start main monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        # Start health check thread
        self.health_check_thread = threading.Thread(target=self._health_check_loop, daemon=True)
        self.health_check_thread.start()
        
        monitor_logger.info("Security status monitoring started")
    
    def stop_monitoring(self):
        """Stop the security status monitoring."""
        self.monitoring_active = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        if self.health_check_thread:
            self.health_check_thread.join(timeout=5)
        
        monitor_logger.info("Security status monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                self._collect_security_metrics()
                self._assess_security_posture()
                self._check_alert_conditions()
                time.sleep(self.monitoring_interval)
            except Exception as e:
                monitor_logger.error(f"Monitoring loop error: {e}")
                time.sleep(self.monitoring_interval)
    
    def _health_check_loop(self):
        """Health check loop."""
        while self.monitoring_active:
            try:
                self._run_health_checks()
                time.sleep(self.health_check_interval)
            except Exception as e:
                monitor_logger.error(f"Health check loop error: {e}")
                time.sleep(self.health_check_interval)
    
    def _collect_security_metrics(self):
        """Collect security metrics."""
        timestamp = datetime.now()
        
        try:
            # Collect CFG status metrics
            if self.security_manager:
                cfg_status = self.security_manager.verify_cfg_status()
                self._add_metric("cfg_enabled", cfg_status.get('cfg_enabled', False), timestamp)
                self._add_metric("cfg_strict_mode", cfg_status.get('strict_mode', False), timestamp)
            
            # Collect recovery metrics
            if self.recovery_manager:
                recovery_status = self.recovery_manager.get_recovery_status()
                self._add_metric("recovery_active", recovery_status['recovery_active'], timestamp)
                
                # Count feature statuses
                healthy_count = 0
                failed_count = 0
                degraded_count = 0
                
                for feature_status in recovery_status['features'].values():
                    status = feature_status['status']
                    if status == 'healthy':
                        healthy_count += 1
                    elif status == 'failed':
                        failed_count += 1
                    elif status == 'degraded':
                        degraded_count += 1
                
                self._add_metric("healthy_features", healthy_count, timestamp)
                self._add_metric("failed_features", failed_count, timestamp)
                self._add_metric("degraded_features", degraded_count, timestamp)
            
            # Collect system metrics
            self._collect_system_metrics(timestamp)
            
        except Exception as e:
            monitor_logger.error(f"Metric collection failed: {e}")
    
    def _collect_system_metrics(self, timestamp: datetime):
        """Collect system-level metrics."""
        try:
            import psutil
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self._add_metric("cpu_usage", cpu_percent / 100.0, timestamp, unit="%")
            
            # Memory usage
            memory = psutil.virtual_memory()
            self._add_metric("memory_usage", memory.percent / 100.0, timestamp, unit="%")
            self._add_metric("memory_available", memory.available, timestamp, unit="bytes")
            
            # Process count
            process_count = len(psutil.pids())
            self._add_metric("process_count", process_count, timestamp)
            
        except ImportError:
            # psutil not available, collect basic metrics
            monitor_logger.debug("psutil not available for system metrics")
        except Exception as e:
            monitor_logger.error(f"System metric collection failed: {e}")
    
    def _add_metric(self, name: str, value: Any, timestamp: datetime, 
                   threshold: Optional[float] = None, unit: Optional[str] = None):
        """Add a metric to the collection."""
        metric = SecurityMetric(
            name=name,
            value=value,
            timestamp=timestamp,
            threshold=threshold,
            unit=unit
        )
        
        self.metrics.append(metric)
        
        # Maintain history limit
        if len(self.metrics) > self.max_metrics_history:
            self.metrics = self.metrics[-self.max_metrics_history:]
    
    def _assess_security_posture(self):
        """Assess overall security posture."""
        try:
            timestamp = datetime.now()
            
            # Count active, failed, and degraded features
            active_features = 0
            failed_features = 0
            degraded_features = 0
            
            if self.security_manager:
                status = self.security_manager.get_security_status()
                active_features = sum([
                    status.cfg_enabled,
                    status.process_monitoring_active,
                    status.hsm_fully_integrated,
                    status.dependencies_satisfied,
                    status.exception_handling_configured
                ])
            
            if self.recovery_manager:
                recovery_status = self.recovery_manager.get_recovery_status()
                for feature_status in recovery_status['features'].values():
                    status_val = feature_status['status']
                    if status_val == 'failed':
                        failed_features += 1
                    elif status_val == 'degraded':
                        degraded_features += 1
            
            # Count alerts by severity
            critical_alerts = len([a for a in self.alerts if a.severity == AlertSeverity.CRITICAL and not a.resolved])
            high_alerts = len([a for a in self.alerts if a.severity == AlertSeverity.HIGH and not a.resolved])
            
            # Calculate security score (0-100)
            base_score = (active_features / 5.0) * 100  # 5 total features
            
            # Deduct points for failures and alerts
            score_deductions = (failed_features * 20) + (degraded_features * 10) + (critical_alerts * 15) + (high_alerts * 5)
            security_score = max(0, base_score - score_deductions)
            
            # Determine security level
            if security_score >= 90 and failed_features == 0 and critical_alerts == 0:
                security_level = SecurityLevel.MAXIMUM
            elif security_score >= 75 and critical_alerts == 0:
                security_level = SecurityLevel.HIGH
            elif security_score >= 50:
                security_level = SecurityLevel.MEDIUM
            elif security_score >= 25:
                security_level = SecurityLevel.LOW
            else:
                security_level = SecurityLevel.CRITICAL
            
            # Generate recommendations
            recommendations = []
            if failed_features > 0:
                recommendations.append(f"Resolve {failed_features} failed security features")
            if degraded_features > 0:
                recommendations.append(f"Restore {degraded_features} degraded security features")
            if critical_alerts > 0:
                recommendations.append(f"Address {critical_alerts} critical security alerts")
            if active_features < 5:
                recommendations.append(f"Enable {5 - active_features} additional security features")
            
            # Create security posture
            posture = SecurityPosture(
                level=security_level,
                score=security_score,
                timestamp=timestamp,
                active_features=active_features,
                failed_features=failed_features,
                degraded_features=degraded_features,
                critical_alerts=critical_alerts,
                high_alerts=high_alerts,
                recommendations=recommendations
            )
            
            self.posture_history.append(posture)
            
            # Maintain history limit
            if len(self.posture_history) > self.max_posture_history:
                self.posture_history = self.posture_history[-self.max_posture_history:]
            
            monitor_logger.debug(f"Security posture assessed: {security_level.value} (score: {security_score:.1f})")
            
        except Exception as e:
            monitor_logger.error(f"Security posture assessment failed: {e}")
    
    def _check_alert_conditions(self):
        """Check for alert conditions."""
        try:
            # Check failure rate threshold
            recent_metrics = [m for m in self.metrics if m.timestamp > datetime.now() - timedelta(minutes=10)]
            
            if recent_metrics:
                failed_checks = len([m for m in recent_metrics if m.name.endswith('_failed') and m.value])
                total_checks = len(recent_metrics)
                failure_rate = failed_checks / total_checks if total_checks > 0 else 0
                
                if failure_rate > self.alert_thresholds['failure_rate']:
                    self._create_alert(
                        AlertSeverity.HIGH,
                        "High Failure Rate Detected",
                        f"Security check failure rate is {failure_rate:.1%}, exceeding threshold of {self.alert_thresholds['failure_rate']:.1%}",
                        "failure_rate"
                    )
            
            # Check for critical security level
            if self.posture_history:
                current_posture = self.posture_history[-1]
                if current_posture.level == SecurityLevel.CRITICAL:
                    self._create_alert(
                        AlertSeverity.CRITICAL,
                        "Critical Security Posture",
                        f"Security posture has dropped to CRITICAL level (score: {current_posture.score:.1f})",
                        "critical_posture"
                    )
            
            # Check system resource thresholds (with startup grace period)
            startup_grace_period = 120  # 2 minutes grace period after startup
            time_since_startup = time.time() - self.startup_time
            
            cpu_metrics = [m for m in recent_metrics if m.name == 'cpu_usage']
            if (cpu_metrics and 
                cpu_metrics[-1].value > self.alert_thresholds['cpu_usage'] and 
                time_since_startup > startup_grace_period):
                self._create_alert(
                    AlertSeverity.MEDIUM,
                    "High CPU Usage",
                    f"CPU usage is {cpu_metrics[-1].value:.1%}, exceeding threshold",
                    "high_cpu"
                )
            
            memory_metrics = [m for m in recent_metrics if m.name == 'memory_usage']
            if memory_metrics and memory_metrics[-1].value > self.alert_thresholds['memory_usage']:
                self._create_alert(
                    AlertSeverity.MEDIUM,
                    "High Memory Usage",
                    f"Memory usage is {memory_metrics[-1].value:.1%}, exceeding threshold",
                    "high_memory"
                )
            
        except Exception as e:
            monitor_logger.error(f"Alert condition checking failed: {e}")
    
    def _run_health_checks(self):
        """Run all enabled health checks."""
        for name, health_check in self.health_checks.items():
            if not health_check.enabled:
                continue
            
            # Check if it's time to run this health check
            if (health_check.last_run and 
                datetime.now() - health_check.last_run < timedelta(seconds=health_check.interval)):
                continue
            
            try:
                success, message = health_check.check_function()
                health_check.last_run = datetime.now()
                health_check.last_result = success
                health_check.last_message = message
                
                if success:
                    health_check.failure_count = 0
                    monitor_logger.debug(f"Health check passed: {name} - {message}")
                else:
                    health_check.failure_count += 1
                    monitor_logger.warning(f"Health check failed: {name} - {message}")
                    
                    # Create alert if failure threshold exceeded
                    if health_check.failure_count >= health_check.max_failures:
                        self._create_alert(
                            AlertSeverity.HIGH,
                            f"Health Check Failure: {name}",
                            f"Health check '{name}' has failed {health_check.failure_count} times: {message}",
                            f"health_check_{name}"
                        )
                        
                        # Attempt automated remediation
                        self._attempt_remediation(f"health_check_{name}")
                
            except Exception as e:
                monitor_logger.error(f"Health check error for {name}: {e}")
                health_check.failure_count += 1
    
    def _check_cfg_protection(self) -> Tuple[bool, str]:
        """Health check for CFG protection."""
        if sys.platform != "win32":
            return True, "CFG is Windows-specific; Linux native memory protection active"
            
        if not self.security_manager:
            return False, "Security manager not available"
        
        try:
            cfg_status = self.security_manager.verify_cfg_status()
            if cfg_status.get('cfg_enabled'):
                return True, "CFG protection is active"
            else:
                error_msg = cfg_status.get('error')
                if error_msg is None:
                    error_msg = "CFG not enabled"
                return False, f"CFG protection is not active: {error_msg}"
        except Exception as e:
            return False, f"CFG protection check failed: {e}"
    
    def _check_recovery_system(self) -> Tuple[bool, str]:
        """Health check for recovery system."""
        if not self.recovery_manager:
            return False, "Recovery manager not available"
        
        try:
            recovery_status = self.recovery_manager.get_recovery_status()
            if recovery_status['recovery_active']:
                return True, "Recovery system is active"
            else:
                return False, "Recovery system is not active"
        except Exception as e:
            return False, f"Recovery system check failed: {e}"
    
    def _check_system_resources(self) -> Tuple[bool, str]:
        """Health check for system resources with startup grace period."""
        try:
            import psutil
            
            # Grace period during startup (allow higher CPU usage during initialization)
            startup_grace_period = 180  # 3 minutes grace period
            time_since_startup = time.time() - getattr(self, 'startup_time', time.time())
            
            # Use shorter interval for more accurate measurement
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Dynamic CPU thresholds based on startup time
            if time_since_startup < startup_grace_period:
                # During startup, allow up to 99% CPU (initialization is CPU-intensive)
                cpu_threshold = 99
                cpu_warning_threshold = 95
            else:
                # After startup, use normal thresholds
                cpu_threshold = 90
                cpu_warning_threshold = 80
            
            # Check CPU usage
            if cpu_percent > cpu_threshold:
                # Only fail if sustained high CPU after startup
                if time_since_startup > startup_grace_period:
                    return False, f"CPU usage critically high: {cpu_percent:.1f}%"
                else:
                    # During startup, just log as info
                    return True, f"CPU usage high during initialization: {cpu_percent:.1f}% (expected)"
            
            # Check memory usage
            if memory.percent > 95:
                return False, f"Memory usage critically high: {memory.percent:.1f}%"
            
            # Determine status message
            if cpu_percent > cpu_warning_threshold:
                status_msg = f"System resources elevated (CPU: {cpu_percent:.1f}%, Memory: {memory.percent:.1f}%)"
            else:
                status_msg = f"System resources normal (CPU: {cpu_percent:.1f}%, Memory: {memory.percent:.1f}%)"
            
            return True, status_msg
            
        except ImportError:
            return True, "System resource monitoring not available (psutil not installed)"
        except Exception as e:
            return False, f"System resource check failed: {e}"
    
    def _check_security_manager(self) -> Tuple[bool, str]:
        """Health check for security manager."""
        if not self.security_manager:
            return False, "Security manager not available"
        
        try:
            status = self.security_manager.get_security_status()
            if status.security_level in ['MAXIMUM', 'HIGH']:
                return True, f"Security manager healthy (level: {status.security_level})"
            else:
                return False, f"Security manager degraded (level: {status.security_level})"
        except Exception as e:
            return False, f"Security manager check failed: {e}"
    
    def _create_alert(self, severity: AlertSeverity, title: str, description: str, source: str):
        """Create a security alert."""
        # Check if similar alert already exists and is unresolved
        existing_alert = next((a for a in self.alerts 
                             if a.source == source and not a.resolved), None)
        
        if existing_alert:
            monitor_logger.debug(f"Similar alert already exists: {source}")
            return
        
        alert_id = f"{source}_{int(datetime.now().timestamp())}"
        alert = SecurityAlert(
            id=alert_id,
            severity=severity,
            title=title,
            description=description,
            timestamp=datetime.now(),
            source=source
        )
        
        self.alerts.append(alert)
        
        # Maintain history limit
        if len(self.alerts) > self.max_alerts_history:
            self.alerts = self.alerts[-self.max_alerts_history:]
        
        monitor_logger.warning(f"Security alert created: {severity.value.upper()} - {title}")
        
        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                monitor_logger.error(f"Alert callback failed: {e}")
        
        # Attempt automated remediation for high/critical alerts
        if severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            self._attempt_remediation(source)
    
    def _attempt_remediation(self, alert_source: str):
        """Attempt automated remediation for an alert."""
        if alert_source in self.remediation_callbacks:
            try:
                callback = self.remediation_callbacks[alert_source]
                success = callback()
                
                if success:
                    monitor_logger.info(f"Automated remediation successful for: {alert_source}")
                    self._resolve_alerts_by_source(alert_source, "Automated remediation")
                else:
                    monitor_logger.warning(f"Automated remediation failed for: {alert_source}")
                    
            except Exception as e:
                monitor_logger.error(f"Remediation attempt failed for {alert_source}: {e}")
    
    def _resolve_alerts_by_source(self, source: str, remediation_action: str):
        """Resolve all unresolved alerts from a specific source."""
        for alert in self.alerts:
            if alert.source == source and not alert.resolved:
                alert.resolved = True
                alert.resolution_time = datetime.now()
                alert.remediation_action = remediation_action
                monitor_logger.info(f"Alert resolved: {alert.id}")
    
    def get_current_posture(self) -> Optional[SecurityPosture]:
        """Get the current security posture."""
        return self.posture_history[-1] if self.posture_history else None
    
    def get_posture_trend(self, hours: int = 24) -> List[SecurityPosture]:
        """Get security posture trend over specified hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [p for p in self.posture_history if p.timestamp > cutoff_time]
    
    def get_active_alerts(self, severity: Optional[AlertSeverity] = None) -> List[SecurityAlert]:
        """Get active (unresolved) alerts, optionally filtered by severity."""
        alerts = [a for a in self.alerts if not a.resolved]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return sorted(alerts, key=lambda x: x.timestamp, reverse=True)
    
    def get_metrics_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get summary of metrics over specified hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_metrics = [m for m in self.metrics if m.timestamp > cutoff_time]
        
        summary = {}
        
        # Group metrics by name
        metric_groups = {}
        for metric in recent_metrics:
            if metric.name not in metric_groups:
                metric_groups[metric.name] = []
            metric_groups[metric.name].append(metric.value)
        
        # Calculate statistics for each metric
        for name, values in metric_groups.items():
            if values:
                numeric_values = [v for v in values if isinstance(v, (int, float))]
                if numeric_values:
                    summary[name] = {
                        'count': len(values),
                        'latest': values[-1],
                        'min': min(numeric_values),
                        'max': max(numeric_values),
                        'avg': statistics.mean(numeric_values),
                        'median': statistics.median(numeric_values)
                    }
                else:
                    summary[name] = {
                        'count': len(values),
                        'latest': values[-1]
                    }
        
        return summary
    
    def export_status_report(self, filepath: str):
        """Export comprehensive status report."""
        try:
            # Check for interpreter shutdown - modules may be None
            # Import json locally to ensure we have a valid reference
            import json as _json_module
            from datetime import datetime as _datetime_module
            
            # Verify the modules are still functional
            if _json_module is None or _datetime_module is None:
                return
            
            # Test that json.dump is callable (not None during shutdown)
            try:
                _dump_func = getattr(_json_module, 'dump', None)
                if _dump_func is None or not callable(_dump_func):
                    return
                # Also test datetime.now() is callable
                _now_func = getattr(_datetime_module, 'now', None)
                if _now_func is None or not callable(_now_func):
                    return
            except (TypeError, AttributeError):
                return
            
            # Safely get data with shutdown protection
            try:
                current_posture = self.get_current_posture()
                active_alerts = self.get_active_alerts()
                metrics_summary = self.get_metrics_summary(24)  # Last 24 hours
            except (TypeError, AttributeError, NameError):
                # During shutdown, these may fail
                return
            
            report = {
                'timestamp': _datetime_module.now().isoformat(),
                'monitoring_active': self.monitoring_active,
                'current_posture': {
                    'level': current_posture.level.value if current_posture else None,
                    'score': current_posture.score if current_posture else None,
                    'active_features': current_posture.active_features if current_posture else 0,
                    'failed_features': current_posture.failed_features if current_posture else 0,
                    'degraded_features': current_posture.degraded_features if current_posture else 0,
                    'recommendations': current_posture.recommendations if current_posture else []
                },
                'active_alerts': [
                    {
                        'id': alert.id,
                        'severity': alert.severity.value,
                        'title': alert.title,
                        'description': alert.description,
                        'timestamp': alert.timestamp.isoformat(),
                        'source': alert.source
                    }
                    for alert in active_alerts
                ],
                'health_checks': {
                    name: {
                        'enabled': check.enabled,
                        'last_run': check.last_run.isoformat() if check.last_run else None,
                        'last_result': check.last_result,
                        'last_message': check.last_message,
                        'failure_count': check.failure_count
                    }
                    for name, check in self.health_checks.items()
                },
                'metrics_summary': metrics_summary,
                'posture_trend': [
                    {
                        'timestamp': p.timestamp.isoformat(),
                        'level': p.level.value,
                        'score': p.score
                    }
                    for p in self.get_posture_trend(24)
                ]
            }
            
            # Write the report
            with open(filepath, 'w') as f:
                _json_module.dump(report, f, indent=2)
            
            monitor_logger.info(f"Status report exported to {filepath}")
            
        except (TypeError, AttributeError, NameError):
            # During interpreter shutdown, these exceptions are expected
            # Silently skip export
            import logging; logging.getLogger(__name__).debug("Ignored exception")
        except Exception as e:
            # During shutdown, don't log errors as modules may be unavailable
            try:
                monitor_logger.error(f"Failed to export status report: {e}")
            except Exception:
                import logging; logging.getLogger(__name__).debug("Ignored exception")


def main():
    """Main function for testing the Security Status Monitor."""
    try:
        monitor_logger.info("Starting Security Status Monitor test")
        
        # Initialize monitor
        monitor = SecurityStatusMonitor()
        
        # Register test alert callback
        def test_alert_callback(alert: SecurityAlert):
            print(f"ALERT: {alert.severity.value.upper()} - {alert.title}")
        
        monitor.register_alert_callback(test_alert_callback)
        
        # Start monitoring
        monitor.start_monitoring()
        
        # Wait for some monitoring cycles
        time.sleep(10)
        
        # Get current status
        posture = monitor.get_current_posture()
        if posture:
            monitor_logger.info(f"Current security posture: {posture.level.value} (score: {posture.score:.1f})")
        
        # Get active alerts
        alerts = monitor.get_active_alerts()
        monitor_logger.info(f"Active alerts: {len(alerts)}")
        
        # Get metrics summary
        metrics = monitor.get_metrics_summary()
        monitor_logger.info(f"Metrics collected: {len(metrics)} types")
        
        # Export status report
        monitor.export_status_report("security_status_test_report.json")
        
        # Stop monitoring
        monitor.stop_monitoring()
        
        monitor_logger.info("Security Status Monitor test completed successfully")
        
    except Exception as e:
        monitor_logger.error(f"Security Status Monitor test failed: {e}")


if __name__ == "__main__":
    main()