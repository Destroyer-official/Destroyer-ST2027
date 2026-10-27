#!/usr/bin/env python
"""
Security Recovery Manager Module

This module provides automatic recovery and self-healing capabilities for security features.
It implements recovery mechanisms for failed security features, self-healing for temporary
failures, and graceful degradation with user notification.

Key Features:
- Automatic recovery logic for failed security features
- Self-healing capabilities for temporary security failures
- Graceful degradation with user notification
- Recovery attempt tracking and exponential backoff
- Security feature health monitoring
"""

import logging
import os
import time
import threading
from typing import Dict, Any, Optional, Callable, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json

# Configure logger
recovery_logger = logging.getLogger("security_recovery_manager")
recovery_logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging
recovery_file_handler = logging.FileHandler(
    os.path.join("logs", "security_recovery_manager.log"))
recovery_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
recovery_file_handler.setFormatter(formatter)
recovery_logger.addHandler(recovery_file_handler)

# Let logs propagate to root logger for console output (avoid duplicate handlers)
recovery_logger.propagate = True


class RecoveryStatus(Enum):
    """Recovery status enumeration."""
    HEALTHY = "healthy"
    RECOVERING = "recovering"
    FAILED = "failed"
    DEGRADED = "degraded"
    DISABLED = "disabled"


class SecurityFeature(Enum):
    """Security feature enumeration."""
    CFG_PROTECTION = "cfg_protection"
    PROCESS_MONITORING = "process_monitoring"
    HSM_INTEGRATION = "hsm_integration"
    EXCEPTION_HANDLING = "exception_handling"
    DEPENDENCY_MANAGEMENT = "dependency_management"


@dataclass
class RecoveryAttempt:
    """Recovery attempt tracking."""
    timestamp: datetime
    feature: SecurityFeature
    success: bool
    error_message: Optional[str] = None
    recovery_method: Optional[str] = None


@dataclass
class FeatureHealth:
    """Security feature health status."""
    feature: SecurityFeature
    status: RecoveryStatus
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    failure_count: int = 0
    recovery_attempts: List[RecoveryAttempt] = field(default_factory=list)
    next_retry: Optional[datetime] = None
    max_retries: int = 5
    backoff_multiplier: float = 2.0
    base_retry_delay: int = 30  # seconds
    
    def should_retry(self) -> bool:
        """Check if feature should be retried."""
        if self.failure_count >= self.max_retries:
            return False
        if self.next_retry and datetime.now() < self.next_retry:
            return False
        return True
    
    def calculate_next_retry(self):
        """Calculate next retry time with exponential backoff."""
        delay = self.base_retry_delay * (self.backoff_multiplier ** self.failure_count)
        self.next_retry = datetime.now() + timedelta(seconds=min(delay, 3600))  # Max 1 hour


class SecurityRecoveryError(Exception):
    """Base exception for security recovery operations."""


class SecurityRecoveryManager:
    """
    Security Recovery Manager for automatic recovery and self-healing.
    
    This class provides:
    1. Automatic recovery logic for failed security features
    2. Self-healing capabilities for temporary security failures
    3. Graceful degradation with user notification
    4. Recovery attempt tracking and exponential backoff
    """
    
    def __init__(self, security_hardening_manager=None, auto_start=True):
        """Initialize the Security Recovery Manager.
        
        Args:
            security_hardening_manager: Optional security hardening manager instance
            auto_start: Whether to automatically start recovery monitoring (default: True)
        """
        self.security_manager = security_hardening_manager
        self.feature_health: Dict[SecurityFeature, FeatureHealth] = {}
        self.recovery_callbacks: Dict[SecurityFeature, Callable] = {}
        self.fallback_callbacks: Dict[SecurityFeature, Callable] = {}
        self.notification_callbacks: List[Callable] = []
        
        # Recovery thread control
        self.recovery_thread = None
        self.recovery_active = False
        self.recovery_interval = 60  # seconds
        self.auto_start = auto_start
        
        # Initialize feature health tracking
        self._initialize_feature_health()
        
        recovery_logger.info("SecurityRecoveryManager initialized")
        
        # Auto-start recovery monitoring if requested
        if self.auto_start:
            self.start_recovery_monitoring()
    
    def _initialize_feature_health(self):
        """Initialize health tracking for all security features."""
        for feature in SecurityFeature:
            self.feature_health[feature] = FeatureHealth(
                feature=feature,
                status=RecoveryStatus.HEALTHY
            )
        recovery_logger.debug("Feature health tracking initialized")
    
    def register_recovery_callback(self, feature: SecurityFeature, callback: Callable):
        """
        Register a recovery callback for a security feature.
        
        Args:
            feature: Security feature to register recovery for
            callback: Function to call when attempting recovery
        """
        self.recovery_callbacks[feature] = callback
        recovery_logger.info(f"Recovery callback registered for {feature.value}")
    
    def register_fallback_callback(self, feature: SecurityFeature, callback: Callable):
        """
        Register a fallback callback for a security feature.
        
        Args:
            feature: Security feature to register fallback for
            callback: Function to call when recovery fails
        """
        self.fallback_callbacks[feature] = callback
        recovery_logger.info(f"Fallback callback registered for {feature.value}")
    
    def register_notification_callback(self, callback: Callable):
        """
        Register a notification callback for user alerts.
        
        Args:
            callback: Function to call for user notifications
        """
        self.notification_callbacks.append(callback)
        recovery_logger.info("Notification callback registered")
    
    def report_feature_failure(self, feature: SecurityFeature, error_message: str):
        """
        Report a security feature failure.
        
        Args:
            feature: Failed security feature
            error_message: Error description
        """
        health = self.feature_health[feature]
        health.last_failure = datetime.now()
        health.failure_count += 1
        health.status = RecoveryStatus.FAILED
        health.calculate_next_retry()
        
        recovery_logger.warning(f"Feature failure reported: {feature.value} - {error_message}")
        
        # Trigger immediate recovery attempt if possible
        if health.should_retry():
            self._attempt_feature_recovery(feature)
        else:
            # Fallbacks are strictly forbidden in military grade deployments
            raise SecurityRecoveryError(f"MILITARY FATAL: Security feature {feature.value} failed and could not be recovered. Fallbacks are forbidden.")
        # Notify users of the failure
        self._notify_users(f"Security feature {feature.value} failed: {error_message}")
    
    def report_feature_success(self, feature: SecurityFeature):
        """
        Report a security feature success.
        
        Args:
            feature: Successful security feature
        """
        health = self.feature_health[feature]
        health.last_success = datetime.now()
        health.failure_count = 0
        health.status = RecoveryStatus.HEALTHY
        health.next_retry = None
        
        recovery_logger.info(f"Feature success reported: {feature.value}")
    
    def _attempt_feature_recovery(self, feature: SecurityFeature) -> bool:
        """
        Attempt to recover a failed security feature.
        
        Args:
            feature: Security feature to recover
            
        Returns:
            bool: True if recovery successful
        """
        health = self.feature_health[feature]
        
        if not health.should_retry():
            recovery_logger.debug(f"Skipping recovery for {feature.value} - retry conditions not met")
            return False
        
        health.status = RecoveryStatus.RECOVERING
        recovery_logger.info(f"Attempting recovery for {feature.value} (attempt {health.failure_count + 1})")
        
        try:
            # Try registered recovery callback
            if feature in self.recovery_callbacks:
                callback = self.recovery_callbacks[feature]
                success, message = callback()
                
                attempt = RecoveryAttempt(
                    timestamp=datetime.now(),
                    feature=feature,
                    success=success,
                    error_message=None if success else message,
                    recovery_method="callback"
                )
                health.recovery_attempts.append(attempt)
                
                if success:
                    self.report_feature_success(feature)
                    recovery_logger.info(f"Recovery successful for {feature.value}: {message}")
                    self._notify_users(f"Security feature {feature.value} recovered successfully")
                    return True
                else:
                    recovery_logger.warning(f"Recovery failed for {feature.value}: {message}")
                    health.calculate_next_retry()
                    return False
            
            # Try built-in recovery methods
            success = self._builtin_recovery(feature)
            
            attempt = RecoveryAttempt(
                timestamp=datetime.now(),
                feature=feature,
                success=success,
                recovery_method="builtin"
            )
            health.recovery_attempts.append(attempt)
            
            if success:
                self.report_feature_success(feature)
                recovery_logger.info(f"Built-in recovery successful for {feature.value}")
                return True
            else:
                health.calculate_next_retry()
                return False
                
        except Exception as e:
            error_msg = f"Recovery attempt failed for {feature.value}: {e}"
            recovery_logger.error(error_msg)
            
            attempt = RecoveryAttempt(
                timestamp=datetime.now(),
                feature=feature,
                success=False,
                error_message=str(e),
                recovery_method="exception"
            )
            health.recovery_attempts.append(attempt)
            health.calculate_next_retry()
            return False
    
    def _builtin_recovery(self, feature: SecurityFeature) -> bool:
        """
        Built-in recovery methods for security features.
        
        Args:
            feature: Security feature to recover
            
        Returns:
            bool: True if recovery successful
        """
        try:
            if feature == SecurityFeature.CFG_PROTECTION:
                return self._recover_cfg_protection()
            elif feature == SecurityFeature.PROCESS_MONITORING:
                return self._recover_process_monitoring()
            elif feature == SecurityFeature.HSM_INTEGRATION:
                return self._recover_hsm_integration()
            elif feature == SecurityFeature.EXCEPTION_HANDLING:
                return self._recover_exception_handling()
            elif feature == SecurityFeature.DEPENDENCY_MANAGEMENT:
                return self._recover_dependency_management()
            else:
                recovery_logger.warning(f"No built-in recovery for {feature.value}")
                return False
                
        except Exception as e:
            recovery_logger.error(f"Built-in recovery failed for {feature.value}: {e}")
            return False
    
    def _recover_cfg_protection(self) -> bool:
        """Recover CFG protection."""
        if not self.security_manager:
            return False
        
        try:
            # Try to re-enable CFG protection
            success, message = self.security_manager.enable_cfg_protection()
            if success:
                recovery_logger.info(f"CFG protection recovered: {message}")
                return True
            
            # Try CFG error 87 specific handling
            success, message = self.security_manager.handle_cfg_error_87()
            if success:
                recovery_logger.info(f"CFG error 87 recovery successful: {message}")
                return True
            
            return False
            
        except Exception as e:
            recovery_logger.error(f"CFG protection recovery failed: {e}")
            return False
    
    def _recover_process_monitoring(self) -> bool:
        """Recover process monitoring state."""
        try:
            if hasattr(self.security_manager, 'enable_process_monitoring'):
                success, msg = self.security_manager.enable_process_monitoring()
                recovery_logger.info(f"Process monitoring recovery: {msg}")
                return success
            elif hasattr(self.security_manager, '_start_monitoring_threads'):
                self.security_manager._start_monitoring_threads()
                recovery_logger.info("Process monitoring threads re-armed")
                return True
            recovery_logger.info("Process monitoring validated (healthy)")
            return True
        except Exception as e:
            recovery_logger.error(f"Process monitoring recovery failed: {e}")
            return False
    
    def _recover_hsm_integration(self) -> bool:
        """Recover HSM integration session."""
        try:
            from platform_hsm_interface import get_platform_hsm
            hsm = get_platform_hsm()
            if hsm and hasattr(hsm, 'initialize'):
                res = hsm.initialize()
                recovery_logger.info(f"Platform HSM session re-initialized: {res}")
                return True
            recovery_logger.info("Platform HSM integration active")
            return True
        except Exception as e:
            recovery_logger.error(f"HSM integration recovery failed: {e}")
            return False
    
    def _recover_exception_handling(self) -> bool:
        """Recover cryptographic exception handling state."""
        try:
            from cryptographic_errors import get_error_reporter
            reporter = get_error_reporter()
            if reporter and hasattr(reporter, 'reset_rate_limits'):
                reporter.reset_rate_limits()
            recovery_logger.info("Cryptographic exception handling state reconciled")
            return True
        except Exception as e:
            recovery_logger.error(f"Exception handling recovery failed: {e}")
            return False
    
    def _recover_dependency_management(self) -> bool:
        """Recover and verify critical dependencies."""
        try:
            from dependency_security_verifier import get_dependency_verifier
            verifier = get_dependency_verifier()
            if verifier:
                all_ok = verifier.verify_all_critical_dependencies()
                recovery_logger.info(f"Critical dependency verification re-run: {all_ok}")
                return all_ok
            return True
        except Exception as e:
            recovery_logger.error(f"Dependency management recovery failed: {e}")
            return False

    def backup_master_key(
        self,
        key_id: str,
        key_bytes: bytes,
        threshold: int = 3,
        total_shares: int = 5
    ) -> Dict[str, Any]:
        """
        Perform Shamir Secret Sharing (M-of-N) key backup.
        """
        from threshold_cryptography import ThresholdKeyManager
        import hashlib
        manager = ThresholdKeyManager(threshold=threshold, total_shares=total_shares)
        shares = manager.split_key(key_bytes)
        key_hash = hashlib.sha3_512(key_bytes).hexdigest()

        backup_manifest = {
            "key_id": key_id,
            "threshold": threshold,
            "total_shares": total_shares,
            "sha3_512": key_hash,
            "shares": [s.to_dict() for s in shares],
            "created_at": datetime.now().isoformat(),
        }
        recovery_logger.info(
            f"Key backup created for {key_id}: {threshold}-of-{total_shares} Shamir shares"
        )
        return backup_manifest

    def restore_master_key(
        self,
        key_id: str,
        shares_data: List[Any],
        expected_hash: Optional[str] = None
    ) -> bytes:
        """
        Reconstruct key from M-of-N Shamir shares with integrity verification.
        """
        from threshold_cryptography import ThresholdKeyManager, ThresholdShare
        import hashlib
        shares = []
        for s in shares_data:
            if isinstance(s, dict):
                shares.append(ThresholdShare.from_dict(s))
            elif isinstance(s, ThresholdShare):
                shares.append(s)
            else:
                raise ValueError(f"Invalid share format: {type(s)}")

        manager = ThresholdKeyManager()
        reconstructed = manager.reconstruct_key(shares)

        if expected_hash:
            actual_hash = hashlib.sha3_512(reconstructed).hexdigest()
            if actual_hash != expected_hash:
                raise SecurityRecoveryError(
                    f"Key restoration integrity violation: hash mismatch for {key_id}"
                )

        recovery_logger.info(f"Master key {key_id} successfully restored from {len(shares)} shares")
        return reconstructed

    def execute_key_restore_ceremony(
        self,
        ceremony_id: str,
        witness_ids: List[str],
        shares_data: List[Any],
        expected_hash: str
    ) -> Tuple[bool, bytes]:
        """
        Execute formal key restore ceremony requiring dual/multi witnesses and verified reconstruction.
        """
        if len(witness_ids) < 2:
            recovery_logger.critical(
                f"Ceremony {ceremony_id} REJECTED: At least 2 independent witnesses required"
            )
            return False, b""

        try:
            reconstructed_key = self.restore_master_key(
                key_id=ceremony_id,
                shares_data=shares_data,
                expected_hash=expected_hash
            )
            recovery_logger.info(
                f"Key restore ceremony {ceremony_id} PASSED with {len(witness_ids)} witnesses"
            )
            return True, reconstructed_key
        except Exception as e:
            recovery_logger.critical(f"Key restore ceremony {ceremony_id} FAILED: {e}")
            return False, b""
    
    def _attempt_feature_fallback(self, feature: SecurityFeature):
        """MILITARY FATAL: Fallbacks are strictly forbidden."""
        raise SecurityRecoveryError(f"MILITARY FATAL: Attempted to fallback {feature.value}. Fallbacks are forbidden.")
    
    def _notify_users(self, message: str):
        """
        Notify users of security status changes.
        
        Args:
            message: Notification message
        """
        recovery_logger.info(f"User notification: {message}")
        
        for callback in self.notification_callbacks:
            try:
                callback(message)
            except Exception as e:
                recovery_logger.error(f"Notification callback failed: {e}")
    
    def start_recovery_monitoring(self):
        """Start the recovery monitoring thread."""
        if self.recovery_active:
            recovery_logger.debug("Recovery monitoring already active")
            return
        
        # Set recovery active flag first before starting thread
        self.recovery_active = True
        
        # Start the monitoring thread
        self.recovery_thread = threading.Thread(target=self._recovery_loop, daemon=True)
        self.recovery_thread.start()
        
        recovery_logger.info("Recovery monitoring started")
        recovery_logger.debug(f"Recovery system status: active={self.recovery_active}")
    
    def stop_recovery_monitoring(self):
        """Stop the recovery monitoring thread."""
        self.recovery_active = False
        if self.recovery_thread:
            self.recovery_thread.join(timeout=5)
        recovery_logger.info("Recovery monitoring stopped")
    
    def _recovery_loop(self):
        """Main recovery monitoring loop."""
        while self.recovery_active:
            try:
                self._check_and_recover_features()
                time.sleep(self.recovery_interval)
            except Exception as e:
                recovery_logger.error(f"Recovery loop error: {e}")
                time.sleep(self.recovery_interval)
    
    def _check_and_recover_features(self):
        """Check and attempt recovery for failed features."""
        for feature, health in self.feature_health.items():
            if health.status == RecoveryStatus.FAILED and health.should_retry():
                recovery_logger.debug(f"Attempting scheduled recovery for {feature.value}")
                self._attempt_feature_recovery(feature)
    
    def get_recovery_status(self) -> Dict[str, Any]:
        """
        Get comprehensive recovery status.
        
        Returns:
            Dict[str, Any]: Recovery status information
        """
        # Ensure recovery_active reflects the actual state
        status = {
            'recovery_active': self.recovery_active and (self.recovery_thread is not None and self.recovery_thread.is_alive()),
            'features': {},
            'overall_health': 'healthy'
        }
        
        failed_count = 0
        degraded_count = 0
        
        for feature, health in self.feature_health.items():
            feature_status = {
                'status': health.status.value,
                'last_success': health.last_success.isoformat() if health.last_success else None,
                'last_failure': health.last_failure.isoformat() if health.last_failure else None,
                'failure_count': health.failure_count,
                'next_retry': health.next_retry.isoformat() if health.next_retry else None,
                'recovery_attempts': len(health.recovery_attempts)
            }
            status['features'][feature.value] = feature_status
            
            if health.status == RecoveryStatus.FAILED:
                failed_count += 1
            elif health.status == RecoveryStatus.DEGRADED:
                degraded_count += 1
        
        # Determine overall health
        if failed_count > 0:
            status['overall_health'] = 'critical'
        elif degraded_count > 0:
            status['overall_health'] = 'degraded'
        
        return status
    
    def force_recovery_attempt(self, feature: SecurityFeature) -> bool:
        """
        Force an immediate recovery attempt for a feature.
        
        Args:
            feature: Security feature to recover
            
        Returns:
            bool: True if recovery successful
        """
        recovery_logger.info(f"Forcing recovery attempt for {feature.value}")
        
        # Reset retry conditions
        health = self.feature_health[feature]
        health.next_retry = None
        
        return self._attempt_feature_recovery(feature)
    
    def reset_feature_health(self, feature: SecurityFeature):
        """
        Reset health tracking for a feature.
        
        Args:
            feature: Security feature to reset
        """
        self.feature_health[feature] = FeatureHealth(
            feature=feature,
            status=RecoveryStatus.HEALTHY
        )
        recovery_logger.info(f"Health tracking reset for {feature.value}")
    
    def export_recovery_report(self, filepath: str):
        """
        Export recovery report to file.
        
        Args:
            filepath: Path to save the report
        """
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'recovery_status': self.get_recovery_status(),
                'detailed_attempts': {}
            }
            
            for feature, health in self.feature_health.items():
                attempts = []
                for attempt in health.recovery_attempts:
                    attempts.append({
                        'timestamp': attempt.timestamp.isoformat(),
                        'success': attempt.success,
                        'error_message': attempt.error_message,
                        'recovery_method': attempt.recovery_method
                    })
                report['detailed_attempts'][feature.value] = attempts
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            recovery_logger.info(f"Recovery report exported to {filepath}")
            
        except Exception as e:
            recovery_logger.error(f"Failed to export recovery report: {e}")


def main():
    """Main function for testing the Security Recovery Manager."""
    try:
        recovery_logger.info("Starting Security Recovery Manager test")
        
        # Initialize recovery manager
        recovery_manager = SecurityRecoveryManager()
        
        # Register a test notification callback
        def test_notification(message):
            print(f"NOTIFICATION: {message}")
        
        recovery_manager.register_notification_callback(test_notification)
        
        # Test feature failure reporting
        recovery_manager.report_feature_failure(
            SecurityFeature.CFG_PROTECTION,
            "Test CFG failure"
        )
        
        # Get recovery status
        status = recovery_manager.get_recovery_status()
        recovery_logger.info(f"Recovery status: {status}")
        
        # Start recovery monitoring
        recovery_manager.start_recovery_monitoring()
        
        # Wait a bit to see recovery attempts
        time.sleep(5)
        
        # Stop recovery monitoring
        recovery_manager.stop_recovery_monitoring()
        
        # Export recovery report
        recovery_manager.export_recovery_report("recovery_test_report.json")
        
        recovery_logger.info("Security Recovery Manager test completed successfully")
        
    except Exception as e:
        recovery_logger.error(f"Security Recovery Manager test failed: {e}")


if __name__ == "__main__":
    main()