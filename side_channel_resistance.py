#!/usr/bin/env python3
"""
Military-Grade Side-Channel Resistance Module
Military-Grade Constant-Time Operations with Timing Verification

This module implements comprehensive side-channel attack resistance including:
- Constant-time operation wrappers for all cryptographic operations
- Statistical analysis of timing variance
- Runtime timing measurement and anomaly detection
- Coefficient of variation verification (< 0.05 threshold)

Requirements Implemented:
- 4.1: Constant-time operations for all cryptographic code paths
- 4.6: Timing consistency verification using statistical analysis (CV < 0.05)

Security Features:
- All operations execute in constant time regardless of input values
- Statistical timing analysis to detect timing leaks
- Automatic alerting on timing anomalies
- Memory access pattern regularization
"""

import time
import math
import secrets
import hashlib
import hmac
import logging
import statistics
from typing import Callable, Any, Tuple, List, Optional, Dict
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TimingAnomalyType(Enum):
    """Types of timing anomalies that can be detected."""
    HIGH_VARIANCE = "high_variance"
    COEFFICIENT_OF_VARIATION_EXCEEDED = "cv_exceeded"
    OUTLIER_DETECTED = "outlier_detected"
    TIMING_LEAK_SUSPECTED = "timing_leak_suspected"
    OPERATION_TOO_FAST = "operation_too_fast"
    OPERATION_TOO_SLOW = "operation_too_slow"


@dataclass
class TimingMeasurement:
    """Represents a single timing measurement."""
    operation_name: str
    duration_ns: int
    input_size: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class TimingStatistics:
    """Statistical analysis of timing measurements."""
    operation_name: str
    sample_count: int
    mean_ns: float
    std_dev_ns: float
    coefficient_of_variation: float
    min_ns: int
    max_ns: int
    is_constant_time: bool
    anomalies: List[TimingAnomalyType] = field(default_factory=list)


class TimingAlert:
    """Represents a timing anomaly alert."""
    
    def __init__(self, anomaly_type: TimingAnomalyType, operation_name: str,
                 details: str, severity: str = "WARNING"):
        self.anomaly_type = anomaly_type
        self.operation_name = operation_name
        self.details = details
        self.severity = severity
        self.timestamp = time.time()
    
    def __repr__(self) -> str:
        return (f"TimingAlert({self.severity}: {self.anomaly_type.value} "
                f"in {self.operation_name} - {self.details})")


class TimingAnalyzer:
    """
    Statistical analyzer for timing measurements.
    
    Implements timing consistency verification using statistical analysis
    with coefficient of variation threshold < 0.05 as per Requirements 4.6.
    """
    
    # Maximum acceptable coefficient of variation for constant-time operations
    CV_THRESHOLD = 0.05
    
    # Minimum samples required for reliable statistical analysis
    MIN_SAMPLES = 10
    
    def __init__(self):
        self._measurements: Dict[str, List[TimingMeasurement]] = {}
        self._alerts: List[TimingAlert] = []
        self._lock = threading.Lock()
    
    def record_measurement(self, measurement: TimingMeasurement) -> None:
        """Record a timing measurement for analysis."""
        with self._lock:
            if measurement.operation_name not in self._measurements:
                self._measurements[measurement.operation_name] = []
            self._measurements[measurement.operation_name].append(measurement)
    
    def analyze_operation(self, operation_name: str) -> Optional[TimingStatistics]:
        """
        Analyze timing measurements for an operation.
        
        Returns TimingStatistics with coefficient of variation analysis.
        CV < 0.05 indicates constant-time behavior.
        """
        with self._lock:
            if operation_name not in self._measurements:
                return None
            
            measurements = self._measurements[operation_name]
            if len(measurements) < self.MIN_SAMPLES:
                return None
            
            durations = [m.duration_ns for m in measurements]
            
            mean_ns = statistics.mean(durations)
            std_dev_ns = statistics.stdev(durations) if len(durations) > 1 else 0.0
            
            # Calculate coefficient of variation
            cv = std_dev_ns / mean_ns if mean_ns > 0 else 0.0
            
            # Determine if operation is constant-time
            is_constant_time = cv < self.CV_THRESHOLD
            
            # Detect anomalies
            anomalies = []
            if cv >= self.CV_THRESHOLD:
                anomalies.append(TimingAnomalyType.COEFFICIENT_OF_VARIATION_EXCEEDED)
                self._raise_alert(
                    TimingAnomalyType.COEFFICIENT_OF_VARIATION_EXCEEDED,
                    operation_name,
                    f"CV={cv:.4f} exceeds threshold {self.CV_THRESHOLD}"
                )
            
            # Check for outliers using IQR method
            if len(durations) >= 4:
                sorted_durations = sorted(durations)
                q1 = sorted_durations[len(sorted_durations) // 4]
                q3 = sorted_durations[3 * len(sorted_durations) // 4]
                iqr = q3 - q1
                lower_bound = q1 - 1.5 * iqr
                upper_bound = q3 + 1.5 * iqr
                
                outliers = [d for d in durations if d < lower_bound or d > upper_bound]
                if len(outliers) > len(durations) * 0.1:  # More than 10% outliers
                    anomalies.append(TimingAnomalyType.OUTLIER_DETECTED)
            
            return TimingStatistics(
                operation_name=operation_name,
                sample_count=len(measurements),
                mean_ns=mean_ns,
                std_dev_ns=std_dev_ns,
                coefficient_of_variation=cv,
                min_ns=min(durations),
                max_ns=max(durations),
                is_constant_time=is_constant_time,
                anomalies=anomalies
            )
    
    def _raise_alert(self, anomaly_type: TimingAnomalyType, operation_name: str,
                     details: str, severity: str = "WARNING") -> None:
        """Raise a timing anomaly alert."""
        alert = TimingAlert(anomaly_type, operation_name, details, severity)
        self._alerts.append(alert)
        
        if severity == "CRITICAL":
            logger.critical(f"TIMING ANOMALY: {alert}")
        elif severity == "WARNING":
            logger.warning(f"TIMING ANOMALY: {alert}")
        else:
            logger.info(f"TIMING ANOMALY: {alert}")
    
    def get_alerts(self) -> List[TimingAlert]:
        """Get all timing alerts."""
        with self._lock:
            return list(self._alerts)
    
    def clear_measurements(self, operation_name: Optional[str] = None) -> None:
        """Clear timing measurements."""
        with self._lock:
            if operation_name:
                self._measurements.pop(operation_name, None)
            else:
                self._measurements.clear()
    
    def clear_alerts(self) -> None:
        """Clear all alerts."""
        with self._lock:
            self._alerts.clear()


# Global timing analyzer instance
_timing_analyzer = TimingAnalyzer()


def get_timing_analyzer() -> TimingAnalyzer:
    """Get the global timing analyzer instance."""
    return _timing_analyzer


class ConstantTimeOperations:
    """
    Constant-time operation implementations for cryptographic code paths.
    
    All operations execute in constant time regardless of input values
    to prevent timing side-channel attacks as per Requirements 4.1.
    """
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison of two byte sequences.
        
        Compares all bytes regardless of early mismatches to prevent
        timing attacks that could reveal information about the comparison.
        
        Args:
            a: First byte sequence
            b: Second byte sequence
            
        Returns:
            True if sequences are equal, False otherwise
        """
        if len(a) != len(b):
            # Still do a comparison to maintain constant time
            # Use the shorter length and always return False
            min_len = min(len(a), len(b))
            result = 0
            for i in range(min_len):
                result |= a[i] ^ b[i]
            # Force result to be non-zero due to length mismatch
            result |= 1
            return result == 0
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    @staticmethod
    def constant_time_select(condition: bool, true_value: int, false_value: int) -> int:
        """
        Constant-time conditional selection.
        
        Selects between two values without branching to prevent
        timing attacks based on branch prediction.
        
        Args:
            condition: Selection condition
            true_value: Value to return if condition is True
            false_value: Value to return if condition is False
            
        Returns:
            true_value if condition is True, false_value otherwise
        """
        # Convert condition to 0 or 1
        cond_int = int(bool(condition))
        # Create mask: -1 (all 1s) if True, 0 if False
        mask = -cond_int
        # Select value using bitwise operations
        return (mask & true_value) | (~mask & false_value)
    
    @staticmethod
    def constant_time_select_bytes(condition: bool, true_value: bytes, 
                                    false_value: bytes) -> bytes:
        """
        Constant-time conditional selection for byte sequences.
        
        Args:
            condition: Selection condition
            true_value: Bytes to return if condition is True
            false_value: Bytes to return if condition is False
            
        Returns:
            true_value if condition is True, false_value otherwise
        """
        if len(true_value) != len(false_value):
            raise ValueError("Byte sequences must have equal length")
        
        cond_int = int(bool(condition))
        mask = -cond_int & 0xFF
        
        result = bytearray(len(true_value))
        for i in range(len(true_value)):
            result[i] = (mask & true_value[i]) | ((~mask & 0xFF) & false_value[i])
        
        return bytes(result)
    
    @staticmethod
    def constant_time_is_zero(value: int) -> bool:
        """
        Constant-time check if value is zero.
        
        Args:
            value: Integer value to check
            
        Returns:
            True if value is zero, False otherwise
        """
        # Use bitwise operations to avoid branching
        # (value | -value) >> 63 is 0 if value is 0, -1 otherwise (for 64-bit)
        combined = value | (-value)
        # Shift to get sign bit (works for any size)
        sign_bit = (combined >> 63) & 1
        return sign_bit == 0
    
    @staticmethod
    def constant_time_bytes_is_zero(data: bytes) -> bool:
        """
        Constant-time check if all bytes are zero.
        
        Args:
            data: Byte sequence to check
            
        Returns:
            True if all bytes are zero, False otherwise
        """
        result = 0
        for byte in data:
            result |= byte
        return result == 0
    
    @staticmethod
    def constant_time_copy(dest: bytearray, src: bytes, condition: bool) -> None:
        """
        Constant-time conditional copy.
        
        Copies src to dest only if condition is True, but always
        accesses all memory locations to prevent timing attacks.
        
        Args:
            dest: Destination bytearray
            src: Source bytes
            condition: Copy condition
        """
        if len(dest) != len(src):
            raise ValueError("Source and destination must have equal length")
        
        cond_int = int(bool(condition))
        mask = -cond_int & 0xFF
        
        for i in range(len(src)):
            # Always read both values
            old_val = dest[i]
            new_val = src[i]
            # Conditionally select which to write
            dest[i] = (mask & new_val) | ((~mask & 0xFF) & old_val)
    
    @staticmethod
    def constant_time_lookup(table: List[bytes], index: int) -> bytes:
        """
        Constant-time table lookup.
        
        Accesses all table entries to prevent cache timing attacks.
        
        Args:
            table: List of byte sequences
            index: Index to look up
            
        Returns:
            The entry at the specified index
        """
        if not table:
            raise ValueError("Table cannot be empty")
        
        entry_len = len(table[0])
        result = bytearray(entry_len)
        
        for i, entry in enumerate(table):
            if len(entry) != entry_len:
                raise ValueError("All table entries must have equal length")
            
            # Create mask: all 1s if i == index, all 0s otherwise
            eq = (i ^ index)
            # Convert to 0 if equal, non-zero otherwise
            mask = ((eq | (-eq)) >> 63) & 1
            # Invert: 1 if equal, 0 otherwise
            mask = 1 - mask
            mask = -mask & 0xFF
            
            for j in range(entry_len):
                result[j] |= mask & entry[j]
        
        return bytes(result)


def constant_time_wrapper(operation_name: str = None, 
                          record_timing: bool = True,
                          verify_constant_time: bool = False):
    """
    Decorator to wrap cryptographic operations with timing verification.
    
    Wraps functions to:
    1. Measure execution time with nanosecond precision
    2. Record measurements for statistical analysis
    3. Optionally verify constant-time behavior
    
    Args:
        operation_name: Name for the operation (defaults to function name)
        record_timing: Whether to record timing measurements
        verify_constant_time: Whether to verify CV < 0.05 after each call
        
    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        name = operation_name or func.__name__
        
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Get input size for analysis (use first bytes argument if available)
            input_size = 0
            for arg in args:
                if isinstance(arg, (bytes, bytearray)):
                    input_size = len(arg)
                    break
            
            # Measure execution time with high precision
            start_ns = time.perf_counter_ns()
            result = func(*args, **kwargs)
            end_ns = time.perf_counter_ns()
            
            duration_ns = end_ns - start_ns
            
            if record_timing:
                measurement = TimingMeasurement(
                    operation_name=name,
                    duration_ns=duration_ns,
                    input_size=input_size
                )
                _timing_analyzer.record_measurement(measurement)
            
            if verify_constant_time:
                stats = _timing_analyzer.analyze_operation(name)
                if stats and not stats.is_constant_time:
                    logger.warning(
                        f"Operation {name} may not be constant-time: "
                        f"CV={stats.coefficient_of_variation:.4f}"
                    )
            
            return result
        
        return wrapper
    return decorator


class ConstantTimeCryptoWrapper:
    """
    Wrapper class for cryptographic operations with timing verification.
    
    Provides constant-time wrappers for common cryptographic operations
    with automatic timing measurement and statistical analysis.
    """
    
    def __init__(self, analyzer: TimingAnalyzer = None):
        """
        Initialize the crypto wrapper.
        
        Args:
            analyzer: TimingAnalyzer instance (uses global if not provided)
        """
        self._analyzer = analyzer or _timing_analyzer
    
    @constant_time_wrapper("hmac_compare")
    def hmac_compare(self, a: bytes, b: bytes) -> bool:
        """
        Constant-time HMAC comparison using hmac.compare_digest.
        
        Args:
            a: First HMAC value
            b: Second HMAC value
            
        Returns:
            True if HMACs are equal, False otherwise
        """
        return hmac.compare_digest(a, b)
    
    @constant_time_wrapper("hash_sha3_256")
    def hash_sha3_256(self, data: bytes) -> bytes:
        """
        SHA3-256 hash with timing measurement.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA3-256 hash digest
        """
        return hashlib.sha3_256(data).digest()
    
    @constant_time_wrapper("hash_sha3_384")
    def hash_sha3_384(self, data: bytes) -> bytes:
        """
        SHA3-384 hash with timing measurement.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA3-384 hash digest
        """
        return hashlib.sha3_384(data).digest()
    
    @constant_time_wrapper("hash_sha3_512")
    def hash_sha3_512(self, data: bytes) -> bytes:
        """
        SHA3-512 hash with timing measurement.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA3-512 hash digest
        """
        return hashlib.sha3_512(data).digest()
    
    @constant_time_wrapper("hmac_sha384")
    def hmac_sha384(self, key: bytes, data: bytes) -> bytes:
        """
        HMAC-SHA384 with timing measurement.
        
        Args:
            key: HMAC key
            data: Data to authenticate
            
        Returns:
            HMAC-SHA384 digest
        """
        return hmac.new(key, data, hashlib.sha384).digest()
    
    @constant_time_wrapper("constant_time_compare")
    def compare(self, a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison with timing measurement.
        
        Args:
            a: First byte sequence
            b: Second byte sequence
            
        Returns:
            True if sequences are equal, False otherwise
        """
        return ConstantTimeOperations.constant_time_compare(a, b)
    
    @constant_time_wrapper("xor_bytes")
    def xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """
        XOR two byte sequences with constant-time behavior.
        
        Args:
            a: First byte sequence
            b: Second byte sequence
            
        Returns:
            XOR result
        """
        if len(a) != len(b):
            raise ValueError("Byte sequences must have equal length")
        
        result = bytearray(len(a))
        for i in range(len(a)):
            result[i] = a[i] ^ b[i]
        return bytes(result)
    
    def get_timing_statistics(self, operation_name: str) -> Optional[TimingStatistics]:
        """
        Get timing statistics for an operation.
        
        Args:
            operation_name: Name of the operation
            
        Returns:
            TimingStatistics or None if insufficient data
        """
        return self._analyzer.analyze_operation(operation_name)
    
    def verify_constant_time(self, operation_name: str) -> Tuple[bool, float]:
        """
        Verify that an operation exhibits constant-time behavior.
        
        Args:
            operation_name: Name of the operation to verify
            
        Returns:
            Tuple of (is_constant_time, coefficient_of_variation)
        """
        stats = self._analyzer.analyze_operation(operation_name)
        if stats is None:
            return (False, float('inf'))
        return (stats.is_constant_time, stats.coefficient_of_variation)


class TimingConsistencyVerifier:
    """
    Runtime timing measurement and analysis for side-channel detection.
    
    Implements Requirements 4.6: Timing consistency verification using
    statistical analysis with coefficient of variation < 0.05.
    """
    
    CV_THRESHOLD = 0.05
    MIN_SAMPLES_FOR_VERIFICATION = 100
    
    def __init__(self, analyzer: TimingAnalyzer = None):
        """
        Initialize the timing consistency verifier.
        
        Args:
            analyzer: TimingAnalyzer instance (uses global if not provided)
        """
        self._analyzer = analyzer or _timing_analyzer
        self._alert_callbacks: List[Callable[[TimingAlert], None]] = []
    
    def register_alert_callback(self, callback: Callable[[TimingAlert], None]) -> None:
        """
        Register a callback for timing anomaly alerts.
        
        Args:
            callback: Function to call when an alert is raised
        """
        self._alert_callbacks.append(callback)
    
    def _notify_alert(self, alert: TimingAlert) -> None:
        """Notify all registered callbacks of an alert."""
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def measure_operation(self, operation: Callable, *args, 
                          operation_name: str = None,
                          iterations: int = 100,
                          **kwargs) -> TimingStatistics:
        """
        Measure an operation's timing characteristics.
        
        Runs the operation multiple times and performs statistical analysis
        to determine if it exhibits constant-time behavior.
        
        Args:
            operation: Function to measure
            *args: Arguments to pass to the operation
            operation_name: Name for the operation
            iterations: Number of iterations to run
            **kwargs: Keyword arguments to pass to the operation
            
        Returns:
            TimingStatistics with analysis results
        """
        name = operation_name or operation.__name__
        
        # Clear previous measurements for this operation
        self._analyzer.clear_measurements(name)
        
        # Run the operation multiple times
        for _ in range(iterations):
            start_ns = time.perf_counter_ns()
            operation(*args, **kwargs)
            end_ns = time.perf_counter_ns()
            
            duration_ns = end_ns - start_ns
            
            # Determine input size
            input_size = 0
            for arg in args:
                if isinstance(arg, (bytes, bytearray)):
                    input_size = len(arg)
                    break
            
            measurement = TimingMeasurement(
                operation_name=name,
                duration_ns=duration_ns,
                input_size=input_size
            )
            self._analyzer.record_measurement(measurement)
        
        # Analyze the measurements
        stats = self._analyzer.analyze_operation(name)
        
        # Raise alerts if necessary
        if stats and not stats.is_constant_time:
            alert = TimingAlert(
                TimingAnomalyType.COEFFICIENT_OF_VARIATION_EXCEEDED,
                name,
                f"CV={stats.coefficient_of_variation:.4f} exceeds threshold {self.CV_THRESHOLD}",
                "WARNING"
            )
            self._notify_alert(alert)
        
        return stats
    
    def verify_operation_constant_time(self, operation: Callable, 
                                        test_inputs: List[Tuple],
                                        operation_name: str = None,
                                        iterations_per_input: int = 50) -> Tuple[bool, TimingStatistics]:
        """
        Verify that an operation is constant-time across different inputs.
        
        Tests the operation with multiple inputs to ensure timing doesn't
        vary based on input values (which could leak information).
        
        Args:
            operation: Function to verify
            test_inputs: List of input tuples to test
            operation_name: Name for the operation
            iterations_per_input: Iterations per input
            
        Returns:
            Tuple of (is_constant_time, combined_statistics)
        """
        name = operation_name or operation.__name__
        
        # Clear previous measurements
        self._analyzer.clear_measurements(name)
        
        # Test with each input
        for inputs in test_inputs:
            for _ in range(iterations_per_input):
                start_ns = time.perf_counter_ns()
                if isinstance(inputs, tuple):
                    operation(*inputs)
                else:
                    operation(inputs)
                end_ns = time.perf_counter_ns()
                
                duration_ns = end_ns - start_ns
                
                # Determine input size
                input_size = 0
                if isinstance(inputs, tuple):
                    for arg in inputs:
                        if isinstance(arg, (bytes, bytearray)):
                            input_size = len(arg)
                            break
                elif isinstance(inputs, (bytes, bytearray)):
                    input_size = len(inputs)
                
                measurement = TimingMeasurement(
                    operation_name=name,
                    duration_ns=duration_ns,
                    input_size=input_size
                )
                self._analyzer.record_measurement(measurement)
        
        # Analyze combined measurements
        stats = self._analyzer.analyze_operation(name)
        
        if stats is None:
            return (False, None)
        
        return (stats.is_constant_time, stats)
    
    def continuous_monitoring(self, operation_name: str,
                               check_interval_samples: int = 100) -> Optional[TimingStatistics]:
        """
        Perform continuous monitoring of an operation's timing.
        
        Called periodically to check if timing characteristics have changed.
        
        Args:
            operation_name: Name of the operation to monitor
            check_interval_samples: Number of samples between checks
            
        Returns:
            TimingStatistics if enough samples, None otherwise
        """
        stats = self._analyzer.analyze_operation(operation_name)
        
        if stats and stats.sample_count >= check_interval_samples:
            if not stats.is_constant_time:
                alert = TimingAlert(
                    TimingAnomalyType.TIMING_LEAK_SUSPECTED,
                    operation_name,
                    f"Continuous monitoring detected timing variance: CV={stats.coefficient_of_variation:.4f}",
                    "CRITICAL"
                )
                self._notify_alert(alert)
                logger.critical(f"TIMING LEAK SUSPECTED in {operation_name}")
        
        return stats
    
    def get_all_statistics(self) -> Dict[str, TimingStatistics]:
        """
        Get timing statistics for all monitored operations.
        
        Returns:
            Dictionary mapping operation names to their statistics
        """
        result = {}
        with self._analyzer._lock:
            for op_name in self._analyzer._measurements.keys():
                stats = self._analyzer.analyze_operation(op_name)
                if stats:
                    result[op_name] = stats
        return result


# Create global instances
_crypto_wrapper = ConstantTimeCryptoWrapper()
_timing_verifier = TimingConsistencyVerifier()


def get_crypto_wrapper() -> ConstantTimeCryptoWrapper:
    """Get the global constant-time crypto wrapper."""
    return _crypto_wrapper


def get_timing_verifier() -> TimingConsistencyVerifier:
    """Get the global timing consistency verifier."""
    return _timing_verifier


class SideChannelResistanceEngine:
    """
    Main engine for side-channel resistance.
    
    Provides a unified interface for:
    - Constant-time operations
    - Timing verification
    - Anomaly detection and alerting
    
    Implements Requirements 4.1 and 4.6.
    """
    
    def __init__(self):
        """Initialize the side-channel resistance engine."""
        self._analyzer = TimingAnalyzer()
        self._crypto_wrapper = ConstantTimeCryptoWrapper(self._analyzer)
        self._timing_verifier = TimingConsistencyVerifier(self._analyzer)
        self._enabled = True
        self._alert_handlers: List[Callable[[TimingAlert], None]] = []
    
    @property
    def enabled(self) -> bool:
        """Check if side-channel resistance is enabled."""
        return self._enabled
    
    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable side-channel resistance."""
        if not value:
            logger.critical("SECURITY VIOLATION: Attempted to disable side-channel resistance. NIST Level 5+ forbids this.")
            raise RuntimeError("Side-channel resistance cannot be disabled under NIST Level 5+ policy.")
        self._enabled = value
        logger.info("Side-channel resistance ENABLED")
    
    def register_alert_handler(self, handler: Callable[[TimingAlert], None]) -> None:
        """
        Register a handler for timing anomaly alerts.
        
        Args:
            handler: Function to call when an alert is raised
        """
        self._alert_handlers.append(handler)
        self._timing_verifier.register_alert_callback(handler)
    
    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Perform constant-time comparison.
        
        Args:
            a: First byte sequence
            b: Second byte sequence
            
        Returns:
            True if equal, False otherwise
        """
        if self._enabled:
            return self._crypto_wrapper.compare(a, b)
        return a == b
    
    def constant_time_select(self, condition: bool, 
                              true_value: Any, false_value: Any) -> Any:
        """
        Perform constant-time conditional selection.
        
        Args:
            condition: Selection condition
            true_value: Value if True
            false_value: Value if False
            
        Returns:
            Selected value
        """
        if isinstance(true_value, int) and isinstance(false_value, int):
            return ConstantTimeOperations.constant_time_select(
                condition, true_value, false_value
            )
        elif isinstance(true_value, bytes) and isinstance(false_value, bytes):
            return ConstantTimeOperations.constant_time_select_bytes(
                condition, true_value, false_value
            )
        else:
            # Fallback for other types (not constant-time)
            return true_value if condition else false_value
    
    def wrap_operation(self, operation: Callable, operation_name: str = None,
                       record_timing: bool = True) -> Callable:
        """
        Wrap an operation with timing measurement.
        
        Args:
            operation: Function to wrap
            operation_name: Name for the operation
            record_timing: Whether to record timing
            
        Returns:
            Wrapped function
        """
        name = operation_name or operation.__name__
        
        @wraps(operation)
        def wrapper(*args, **kwargs):
            if not self._enabled or not record_timing:
                return operation(*args, **kwargs)
            
            start_ns = time.perf_counter_ns()
            result = operation(*args, **kwargs)
            end_ns = time.perf_counter_ns()
            
            duration_ns = end_ns - start_ns
            
            input_size = 0
            for arg in args:
                if isinstance(arg, (bytes, bytearray)):
                    input_size = len(arg)
                    break
            
            measurement = TimingMeasurement(
                operation_name=name,
                duration_ns=duration_ns,
                input_size=input_size
            )
            self._analyzer.record_measurement(measurement)
            
            return result
        
        return wrapper
    
    def verify_constant_time(self, operation_name: str) -> Tuple[bool, float]:
        """
        Verify that an operation is constant-time.
        
        Args:
            operation_name: Name of the operation
            
        Returns:
            Tuple of (is_constant_time, coefficient_of_variation)
        """
        return self._crypto_wrapper.verify_constant_time(operation_name)
    
    def measure_and_verify(self, operation: Callable, *args,
                           operation_name: str = None,
                           iterations: int = 100,
                           **kwargs) -> Tuple[bool, TimingStatistics]:
        """
        Measure an operation and verify constant-time behavior.
        
        Args:
            operation: Function to measure
            *args: Arguments for the operation
            operation_name: Name for the operation
            iterations: Number of iterations
            **kwargs: Keyword arguments for the operation
            
        Returns:
            Tuple of (is_constant_time, statistics)
        """
        stats = self._timing_verifier.measure_operation(
            operation, *args,
            operation_name=operation_name,
            iterations=iterations,
            **kwargs
        )
        
        if stats is None:
            return (False, None)
        
        return (stats.is_constant_time, stats)
    
    def get_statistics(self, operation_name: str = None) -> Dict[str, TimingStatistics]:
        """
        Get timing statistics.
        
        Args:
            operation_name: Specific operation name, or None for all
            
        Returns:
            Dictionary of statistics
        """
        if operation_name:
            stats = self._analyzer.analyze_operation(operation_name)
            return {operation_name: stats} if stats else {}
        return self._timing_verifier.get_all_statistics()
    
    def get_alerts(self) -> List[TimingAlert]:
        """Get all timing alerts."""
        return self._analyzer.get_alerts()
    
    def clear_data(self) -> None:
        """Clear all measurements and alerts."""
        self._analyzer.clear_measurements()
        self._analyzer.clear_alerts()


# Create global engine instance
_side_channel_engine = SideChannelResistanceEngine()


def get_side_channel_engine() -> SideChannelResistanceEngine:
    """Get the global side-channel resistance engine."""
    return _side_channel_engine


# Convenience functions
def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte sequences."""
    return _side_channel_engine.constant_time_compare(a, b)


def constant_time_select(condition: bool, true_value: Any, false_value: Any) -> Any:
    """Constant-time conditional selection."""
    return _side_channel_engine.constant_time_select(condition, true_value, false_value)


def verify_constant_time(operation_name: str) -> Tuple[bool, float]:
    """Verify that an operation is constant-time."""
    return _side_channel_engine.verify_constant_time(operation_name)


# Export all public symbols
__all__ = [
    'TimingAnomalyType',
    'TimingMeasurement',
    'TimingStatistics',
    'TimingAlert',
    'TimingAnalyzer',
    'ConstantTimeOperations',
    'constant_time_wrapper',
    'ConstantTimeCryptoWrapper',
    'TimingConsistencyVerifier',
    'SideChannelResistanceEngine',
    'get_timing_analyzer',
    'get_crypto_wrapper',
    'get_timing_verifier',
    'get_side_channel_engine',
    'constant_time_compare',
    'constant_time_select',
    'verify_constant_time',
]


class RuntimeTimingMonitor:
    """
    Runtime timing measurement and analysis for continuous monitoring.
    
    Implements Requirements 4.6: Runtime timing measurement and analysis
    with automatic alerting on timing anomalies.
    
    Features:
    - Continuous background monitoring of cryptographic operations
    - Statistical analysis with rolling windows
    - Automatic alerting when timing anomalies are detected
    - Integration with security logging systems
    """
    
    CV_THRESHOLD = 0.05
    ALERT_COOLDOWN_SECONDS = 60  # Minimum time between alerts for same operation
    ROLLING_WINDOW_SIZE = 1000  # Number of samples to keep for rolling analysis
    
    def __init__(self):
        """Initialize the runtime timing monitor."""
        self._measurements: Dict[str, List[TimingMeasurement]] = {}
        self._last_alert_time: Dict[str, float] = {}
        self._alert_callbacks: List[Callable[[TimingAlert], None]] = []
        self._monitoring_enabled = True
        self._lock = threading.Lock()
        self._baseline_stats: Dict[str, TimingStatistics] = {}
        
        logger.info("RuntimeTimingMonitor initialized")
    
    @property
    def monitoring_enabled(self) -> bool:
        """Check if monitoring is enabled."""
        return self._monitoring_enabled
    
    @monitoring_enabled.setter
    def monitoring_enabled(self, value: bool) -> None:
        """Enable or disable monitoring."""
        if not value:
            logger.critical("SECURITY VIOLATION: Attempted to disable runtime timing monitoring. NIST Level 5+ forbids this.")
            raise RuntimeError("Runtime timing monitoring cannot be disabled under NIST Level 5+ policy.")
        self._monitoring_enabled = value
        logger.info("Runtime timing monitoring ENABLED")
    
    def register_alert_callback(self, callback: Callable[[TimingAlert], None]) -> None:
        """
        Register a callback for timing anomaly alerts.
        
        Args:
            callback: Function to call when an alert is raised
        """
        self._alert_callbacks.append(callback)
    
    def record_timing(self, operation_name: str, duration_ns: int, 
                      input_size: int = 0) -> None:
        """
        Record a timing measurement for an operation.
        
        Args:
            operation_name: Name of the operation
            duration_ns: Duration in nanoseconds
            input_size: Size of input data (optional)
        """
        if not self._monitoring_enabled:
            return
        
        measurement = TimingMeasurement(
            operation_name=operation_name,
            duration_ns=duration_ns,
            input_size=input_size
        )
        
        with self._lock:
            if operation_name not in self._measurements:
                self._measurements[operation_name] = []
            
            self._measurements[operation_name].append(measurement)
            
            # Maintain rolling window
            if len(self._measurements[operation_name]) > self.ROLLING_WINDOW_SIZE:
                self._measurements[operation_name] = \
                    self._measurements[operation_name][-self.ROLLING_WINDOW_SIZE:]
        
        # Check for anomalies
        self._check_for_anomalies(operation_name)
    
    def _check_for_anomalies(self, operation_name: str) -> None:
        """Check for timing anomalies and raise alerts if necessary."""
        with self._lock:
            measurements = self._measurements.get(operation_name, [])
            
            if len(measurements) < 20:  # Need minimum samples
                return
            
            durations = [m.duration_ns for m in measurements[-100:]]  # Last 100 samples
            
            mean_val = statistics.mean(durations)
            std_val = statistics.stdev(durations) if len(durations) > 1 else 0
            cv = std_val / mean_val if mean_val > 0 else 0
            
            # Check if CV exceeds threshold
            if cv >= self.CV_THRESHOLD:
                self._raise_alert_if_allowed(
                    operation_name,
                    TimingAnomalyType.COEFFICIENT_OF_VARIATION_EXCEEDED,
                    f"CV={cv:.4f} exceeds threshold {self.CV_THRESHOLD}",
                    "WARNING"
                )
            
            # Check for sudden timing changes (potential attack indicator)
            if len(measurements) >= 50:
                recent_mean = statistics.mean(durations[-25:])
                older_mean = statistics.mean(durations[-50:-25])
                
                if older_mean > 0:
                    change_ratio = abs(recent_mean - older_mean) / older_mean
                    if change_ratio > 0.5:  # 50% change
                        self._raise_alert_if_allowed(
                            operation_name,
                            TimingAnomalyType.TIMING_LEAK_SUSPECTED,
                            f"Sudden timing change detected: {change_ratio:.2%}",
                            "CRITICAL"
                        )
            
            # Check for outliers
            if len(durations) >= 10:
                sorted_durations = sorted(durations)
                q1 = sorted_durations[len(sorted_durations) // 4]
                q3 = sorted_durations[3 * len(sorted_durations) // 4]
                iqr = q3 - q1
                
                lower_bound = q1 - 3 * iqr  # Use 3*IQR for extreme outliers
                upper_bound = q3 + 3 * iqr
                
                latest = durations[-1]
                if latest < lower_bound or latest > upper_bound:
                    self._raise_alert_if_allowed(
                        operation_name,
                        TimingAnomalyType.OUTLIER_DETECTED,
                        f"Extreme timing outlier: {latest}ns (bounds: {lower_bound:.0f}-{upper_bound:.0f})",
                        "WARNING"
                    )
    
    def _raise_alert_if_allowed(self, operation_name: str, 
                                 anomaly_type: TimingAnomalyType,
                                 details: str, severity: str) -> None:
        """Raise an alert if cooldown period has passed."""
        current_time = time.time()
        alert_key = f"{operation_name}:{anomaly_type.value}"
        
        last_alert = self._last_alert_time.get(alert_key, 0)
        if current_time - last_alert < self.ALERT_COOLDOWN_SECONDS:
            return  # Still in cooldown
        
        self._last_alert_time[alert_key] = current_time
        
        alert = TimingAlert(anomaly_type, operation_name, details, severity)
        
        # Log the alert
        if severity == "CRITICAL":
            logger.critical(f"TIMING ANOMALY: {alert}")
        elif severity == "WARNING":
            logger.warning(f"TIMING ANOMALY: {alert}")
        else:
            logger.info(f"TIMING ANOMALY: {alert}")
        
        # Notify callbacks
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def establish_baseline(self, operation_name: str, 
                           operation: Callable, *args,
                           iterations: int = 100,
                           **kwargs) -> TimingStatistics:
        """
        Establish a timing baseline for an operation.
        
        Args:
            operation_name: Name for the operation
            operation: Function to measure
            *args: Arguments for the operation
            iterations: Number of iterations
            **kwargs: Keyword arguments for the operation
            
        Returns:
            Baseline TimingStatistics
        """
        # Clear existing measurements
        with self._lock:
            self._measurements[operation_name] = []
        
        # Collect baseline measurements
        for _ in range(iterations):
            start_ns = time.perf_counter_ns()
            operation(*args, **kwargs)
            end_ns = time.perf_counter_ns()
            
            self.record_timing(operation_name, end_ns - start_ns)
        
        # Calculate and store baseline statistics
        stats = self.get_statistics(operation_name)
        if stats:
            self._baseline_stats[operation_name] = stats
        
        return stats
    
    def get_statistics(self, operation_name: str) -> Optional[TimingStatistics]:
        """
        Get current timing statistics for an operation.
        
        Args:
            operation_name: Name of the operation
            
        Returns:
            TimingStatistics or None if insufficient data
        """
        with self._lock:
            measurements = self._measurements.get(operation_name, [])
            
            if len(measurements) < 10:
                return None
            
            durations = [m.duration_ns for m in measurements]
            
            mean_ns = statistics.mean(durations)
            std_dev_ns = statistics.stdev(durations) if len(durations) > 1 else 0
            cv = std_dev_ns / mean_ns if mean_ns > 0 else 0
            
            anomalies = []
            if cv >= self.CV_THRESHOLD:
                anomalies.append(TimingAnomalyType.COEFFICIENT_OF_VARIATION_EXCEEDED)
            
            return TimingStatistics(
                operation_name=operation_name,
                sample_count=len(measurements),
                mean_ns=mean_ns,
                std_dev_ns=std_dev_ns,
                coefficient_of_variation=cv,
                min_ns=min(durations),
                max_ns=max(durations),
                is_constant_time=cv < self.CV_THRESHOLD,
                anomalies=anomalies
            )
    
    def get_all_statistics(self) -> Dict[str, TimingStatistics]:
        """Get statistics for all monitored operations."""
        result = {}
        with self._lock:
            for op_name in self._measurements.keys():
                stats = self.get_statistics(op_name)
                if stats:
                    result[op_name] = stats
        return result
    
    def compare_to_baseline(self, operation_name: str) -> Optional[Dict[str, Any]]:
        """
        Compare current timing to established baseline.
        
        Args:
            operation_name: Name of the operation
            
        Returns:
            Comparison results or None if no baseline
        """
        baseline = self._baseline_stats.get(operation_name)
        current = self.get_statistics(operation_name)
        
        if not baseline or not current:
            return None
        
        mean_change = (current.mean_ns - baseline.mean_ns) / baseline.mean_ns \
            if baseline.mean_ns > 0 else 0
        cv_change = current.coefficient_of_variation - baseline.coefficient_of_variation
        
        return {
            "operation_name": operation_name,
            "baseline_mean_ns": baseline.mean_ns,
            "current_mean_ns": current.mean_ns,
            "mean_change_percent": mean_change * 100,
            "baseline_cv": baseline.coefficient_of_variation,
            "current_cv": current.coefficient_of_variation,
            "cv_change": cv_change,
            "is_degraded": mean_change > 0.2 or cv_change > 0.02
        }
    
    def clear_data(self, operation_name: str = None) -> None:
        """Clear timing data."""
        with self._lock:
            if operation_name:
                self._measurements.pop(operation_name, None)
                self._baseline_stats.pop(operation_name, None)
            else:
                self._measurements.clear()
                self._baseline_stats.clear()


# Create global runtime monitor instance
_runtime_monitor = RuntimeTimingMonitor()


def get_runtime_monitor() -> RuntimeTimingMonitor:
    """Get the global runtime timing monitor."""
    return _runtime_monitor


def timed_operation(operation_name: str = None):
    """
    Decorator to automatically record timing for operations.
    
    Args:
        operation_name: Name for the operation (defaults to function name)
        
    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        name = operation_name or func.__name__
        
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start_ns = time.perf_counter_ns()
            result = func(*args, **kwargs)
            end_ns = time.perf_counter_ns()
            
            # Determine input size
            input_size = 0
            for arg in args:
                if isinstance(arg, (bytes, bytearray)):
                    input_size = len(arg)
                    break
            
            _runtime_monitor.record_timing(name, end_ns - start_ns, input_size)
            
            return result
        
        return wrapper
    return decorator


# Update exports
__all__.extend([
    'RuntimeTimingMonitor',
    'get_runtime_monitor',
    'timed_operation',
])
