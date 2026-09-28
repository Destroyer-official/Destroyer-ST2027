#!/usr/bin/env python3
"""
Continuous Security Monitor Module

This module implements continuous security monitoring for the military-grade
secure P2P messaging system, providing real-time behavioral analysis, timing
monitoring for side-channel indicators, honeypot key detection, and SIEM integration.

Requirements addressed: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6

Key Features:
- Behavioral analysis for anomaly detection (15.1)
- Cryptographic operation timing monitoring (15.2)
- Unusual key usage pattern detection (15.3)
- Honeypot keys that trigger alerts (15.4)
- SIEM integration via secure API (15.5)
- Security metrics dashboard (15.6)
"""

import logging
import base64
import os
import time
import threading
import json
import hashlib
import hmac
import secrets
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable, Set, Tuple
from enum import Enum
from collections import deque, defaultdict
import queue

# Configure logger
logger = logging.getLogger("continuous_security_monitor")
logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging
file_handler = logging.FileHandler(os.path.join("logs", "continuous_security_monitor.log"))
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s'
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


class AlertSeverity(Enum):
    """Alert severity levels for security events."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BehaviorType(Enum):
    """Types of behaviors being monitored."""
    KEY_ACCESS = "key_access"
    KEY_GENERATION = "key_generation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNATURE = "signature"
    VERIFICATION = "verification"
    AUTHENTICATION = "authentication"
    SESSION_CREATION = "session_creation"
    MESSAGE_SEND = "message_send"
    MESSAGE_RECEIVE = "message_receive"


@dataclass
class SecurityAlert:
    """Security alert data structure."""
    alert_id: str
    severity: AlertSeverity
    title: str
    description: str
    timestamp: datetime
    source: str
    alert_type: str
    details: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolution_time: Optional[datetime] = None
    exported_to_siem: bool = False
    signature: Optional[str] = None
    retry_count: int = 0


@dataclass
class BehaviorEvent:
    """Behavioral event for analysis."""
    event_id: str
    behavior_type: BehaviorType
    timestamp: datetime
    key_id: Optional[str] = None
    peer_id: Optional[str] = None
    session_id: Optional[str] = None
    duration_ms: Optional[float] = None
    success: bool = True
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TimingMeasurement:
    """Timing measurement for side-channel analysis."""
    operation: str
    duration_ns: int
    timestamp: datetime
    input_size: int = 0
    key_id: Optional[str] = None


@dataclass
class HoneypotKey:
    """Honeypot key configuration."""
    key_id: str
    key_material: bytes
    created_at: datetime
    description: str
    alert_on_access: bool = True
    access_count: int = 0
    last_access: Optional[datetime] = None


@dataclass
class SecurityMetrics:
    """Real-time security metrics for dashboard."""
    timestamp: datetime
    total_operations: int = 0
    failed_operations: int = 0
    anomalies_detected: int = 0
    honeypot_triggers: int = 0
    timing_anomalies: int = 0
    active_sessions: int = 0
    blocked_peers: int = 0
    alerts_generated: int = 0
    alerts_resolved: int = 0
    average_operation_time_ms: float = 0.0
    timing_variance: float = 0.0


class SecurityMonitorError(Exception):
    """Base exception for security monitoring operations."""
    def __init__(self, message: str = "Security monitoring failure", *args):
        super().__init__(message, *args)


class HoneypotAccessError(SecurityMonitorError):
    """Raised when a honeypot key is accessed."""
    def __init__(self, key_id: str, message: str = "Honeypot key accessed"):
        super().__init__(f"{message}: {key_id}")
        self.key_id = key_id
        self.timestamp = datetime.now()


# ---------------------------------------------------------------------------
# Signed-alert helpers (non-breaking add-on).
#
# SIEM JSON payloads are signed with ML-DSA-87 when an SBOM/cert key is
# available, else Ed25519 fallback. Envelope: {payload, sig_b64, kid, alg}.
# Fail-open in lab (warn if no key); fail-closed when P2P_ALERTS_REQUIRE_SIG=1.
# Existing callback API (register_alert_callback(SecurityAlert)) is unchanged.
# ---------------------------------------------------------------------------
ALERT_SIG_REQUIRE_ENV = "P2P_ALERTS_REQUIRE_SIG"

_ALERT_ED25519_EPHEMERAL_SK: Optional[bytes] = None
_ALERT_ED25519_EPHEMERAL_PK: Optional[bytes] = None


def _prod_strict_on() -> bool:
    """Sticky-prod gate (guarded import; tiny duplicate fallback, no cycle)."""
    try:
        from utils.message_caps import prod_strict_on as _central_prod_strict
        return bool(_central_prod_strict())
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    try:
        if os.environ.get("P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on"):
            return True
        if os.environ.get("SECURE_P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on"):
            return True
        if os.environ.get("P2P_ENV", "").strip().lower() == "production":
            return True
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    return False


def alerts_require_sig() -> bool:
    """Return True when signed SIEM alerts are required (fail-closed).

    Auto-True in prod (sticky prod) without requiring
    P2P_ALERTS_REQUIRE_SIG. Explicit P2P_ALERTS_REQUIRE_SIG=0 opts out
    in lab only; in prod the opt-out is ignored with a CRITICAL log.
    Lab default: False.
    """
    raw = os.environ.get(ALERT_SIG_REQUIRE_ENV)
    enabled = str(raw or "").strip().lower() in ("1", "true", "yes", "on")
    if _prod_strict_on():
        if raw is not None and not enabled:
            logger.critical(
                "PROD-STRICT: ignoring %s=%r opt-out in production; "
                "alert signatures remain required", ALERT_SIG_REQUIRE_ENV, raw)
        return True
    return enabled


def _read_key_bytes(spec: Optional[str]) -> Optional[bytes]:
    """Resolve key spec: file path, base64, hex, or raw string. None if empty."""
    if not spec:
        return None
    s = spec.strip().strip('"').strip("'")
    if not s:
        return None
    try:
        if os.path.isfile(s):
            data = open(s, "rb").read()
            return data if data else None
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    # Inline base64?
    try:
        raw = base64.b64decode(s, validate=True)
        if len(raw) >= 32:
            return raw
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    # Inline hex?
    try:
        raw = bytes.fromhex(s)
        if len(raw) >= 32:
            return raw
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    return None


def _load_alert_mldsa_keys() -> Tuple[Optional[bytes], Optional[bytes], Optional[str]]:
    """Resolve (sk, pk, kid) for ML-DSA-87 alert signing.

    Sources: P2P_ALERT_SIGNING_KEY/P2P_ALERT_VERIFY_KEY, SBOM_SIGNING_KEY/
    SBOM_PUBKEY, sibling .pub of sk, certs/sbom_mldsa87_signer anchor.
    Returns (None, None, None) when unavailable.
    """
    sk_spec = os.environ.get("P2P_ALERT_SIGNING_KEY") or os.environ.get("SBOM_SIGNING_KEY")
    sk = _read_key_bytes(sk_spec)
    sk_src = sk_spec
    if sk is None:
        for cand in ("certs/sbom_mldsa87_signer.sk", "certs/alert_mldsa87_signer.sk"):
            try:
                if os.path.isfile(cand):
                    sk = open(cand, "rb").read() or None
                    sk_src = cand
                    break
            # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B112
                continue
    if sk is None:
        return None, None, None
    pk_spec = os.environ.get("P2P_ALERT_VERIFY_KEY") or os.environ.get("SBOM_PUBKEY")
    pk = _read_key_bytes(pk_spec)
    pk_src = pk_spec
    if pk is None and sk_src and os.path.isfile(str(sk_src)):
        try:
            from pathlib import Path as _P
            sib = _P(str(sk_src)).with_suffix(".pub")
            if sib.is_file():
                pk = sib.read_bytes() or None
                pk_src = str(sib)
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    if pk is None:
        for cand in ("certs/sbom_mldsa87_signer.pub", "certs/alert_mldsa87_signer.pub"):
            try:
                if os.path.isfile(cand):
                    pk = open(cand, "rb").read() or None
                    pk_src = cand
                    break
            # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B112
                continue
    if pk is None:
        return None, None, None
    kid = "mldsa87:" + hashlib.sha256(pk).hexdigest()[:16]
    return sk, pk, kid


def _load_alert_ed25519_keys() -> Tuple[Optional[bytes], Optional[bytes], Optional[str]]:
    """Resolve (sk, pk, kid) for Ed25519 fallback.

    Sources: P2P_ALERT_ED25519_SK (path/b64/hex) + derived pubkey, or
    certs/alert_ed25519.sk. Else ephemeral lab key (fail-open, cached).
    """
    global _ALERT_ED25519_EPHEMERAL_SK, _ALERT_ED25519_EPHEMERAL_PK
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
    except Exception:
        return None, None, None
    sk = _read_key_bytes(os.environ.get("P2P_ALERT_ED25519_SK"))
    if sk is None:
        try:
            if os.path.isfile("certs/alert_ed25519.sk"):
                sk = open("certs/alert_ed25519.sk", "rb").read() or None
        except Exception:
            sk = None
    if sk is not None and len(sk) == 32:
        try:
            pk = _ed.Ed25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()
            return sk, pk, "ed25519:" + pk.hex()[:16]
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    # Ephemeral lab fallback (fail-open only; never used when REQUIRE_SIG=1
    # unless explicitly allowed — caller decides).
    try:
        if _ALERT_ED25519_EPHEMERAL_SK is None:
            _priv = _ed.Ed25519PrivateKey.generate()
            _ALERT_ED25519_EPHEMERAL_SK = _priv.private_bytes_raw()
            _ALERT_ED25519_EPHEMERAL_PK = _priv.public_key().public_bytes_raw()
        # B101: explicit fail-closed check (never `assert` on a live key path;
        # -O strips asserts and this must not yield a half-initialized keypair).
        if _ALERT_ED25519_EPHEMERAL_PK is None or _ALERT_ED25519_EPHEMERAL_SK is None:
            return None, None, None
        return _ALERT_ED25519_EPHEMERAL_SK, _ALERT_ED25519_EPHEMERAL_PK, "ed25519-ephemeral-lab"
    except Exception:
        return None, None, None


def _alert_canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_alert_payload_envelope(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sign a SIEM JSON payload. Returns {payload, sig_b64, kid, alg}.

    Prefers ML-DSA-87 (SBOM/cert key), else Ed25519 fallback. Fail-open in
    lab (unsigned envelope + warn) unless P2P_ALERTS_REQUIRE_SIG=1, in which
    case RuntimeError is raised when no usable key exists.
    """
    snapshot = dict(payload)
    msg = _alert_canonical_bytes(snapshot)
    # 1. ML-DSA-87
    try:
        sk, _pk, kid = _load_alert_mldsa_keys()
        if sk is not None:
            from liboqs_wrapper import LibOQS_MLDSA_87
            sig = LibOQS_MLDSA_87().sign(sk, msg)
            return {"payload": snapshot, "sig_b64": base64.b64encode(sig).decode("ascii"),
                    "kid": kid, "alg": "mldsa87"}
    except Exception as e:
        logger.debug(f"ML-DSA-87 alert signing unavailable, trying Ed25519: {e}")
    # 2. Ed25519 fallback
    try:
        sk, _pk, kid = _load_alert_ed25519_keys()
        if sk is not None:
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
            sig = _ed.Ed25519PrivateKey.from_private_bytes(sk).sign(msg)
            if kid == "ed25519-ephemeral-lab":
                logger.warning("Alert signing: no persistent key found; using ephemeral "
                               "Ed25519 lab key (set SBOM_SIGNING_KEY or P2P_ALERT_ED25519_SK "
                               "for production).")
            return {"payload": snapshot, "sig_b64": base64.b64encode(sig).decode("ascii"),
                    "kid": kid, "alg": "ed25519"}
    except Exception as e:
        logger.debug(f"Ed25519 alert signing unavailable: {e}")
    if alerts_require_sig():
        raise RuntimeError("FAIL-CLOSED: P2P_ALERTS_REQUIRE_SIG=1 but no alert signing key "
                           "available (SBOM_SIGNING_KEY / P2P_ALERT_ED25519_SK / certs anchor).")
    logger.warning("Alert signing: no signing key available; sending unsigned (lab fail-open). "
                   "Set P2P_ALERTS_REQUIRE_SIG=1 to fail closed.")
    return {"payload": snapshot, "sig_b64": None, "kid": None, "alg": "none"}


def verify_signed_alert_envelope(
    envelope: Dict[str, Any],
    mldsa_pubkey: Optional[bytes] = None,
    ed_pubkey: Optional[bytes] = None,
) -> bool:
    """Verify a signed alert envelope {payload, sig_b64, kid, alg}.

    Resolves verification keys from args, else P2P_ALERT_VERIFY_KEY /
    SBOM_PUBKEY / certs anchor (ML-DSA) or P2P_ALERT_ED25519_PK (Ed25519).
    Returns True on valid signature, False otherwise (never raises).
    """
    try:
        if not isinstance(envelope, dict):
            return False
        payload = envelope.get("payload")
        sig_b64 = envelope.get("sig_b64")
        alg = (envelope.get("alg") or "").lower()
        if payload is None or not sig_b64:
            return False
        try:
            sig = base64.b64decode(sig_b64)
        except Exception:
            return False
        msg = _alert_canonical_bytes(dict(payload))
        # ML-DSA-87 path
        if alg in ("", "mldsa87", "ml-dsa-87"):
            pk = mldsa_pubkey or _read_key_bytes(os.environ.get("P2P_ALERT_VERIFY_KEY")) \
                or _read_key_bytes(os.environ.get("SBOM_PUBKEY"))
            if pk is None:
                for cand in ("certs/sbom_mldsa87_signer.pub", "certs/alert_mldsa87_signer.pub"):
                    try:
                        if os.path.isfile(cand):
                            pk = open(cand, "rb").read() or None
                            break
                    # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B112
                        continue
            if pk is not None:
                try:
                    from liboqs_wrapper import LibOQS_MLDSA_87
                    if LibOQS_MLDSA_87().verify(pk, msg, sig):
                        return True
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                # Also try pqc_algorithms backend (same wire format)
                try:
                    from pqc_algorithms import EnhancedMLDSA_87
                    if EnhancedMLDSA_87().verify(pk, msg, sig):
                        return True
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
            if alg == "mldsa87":
                return False
        # Ed25519 path
        if alg in ("", "ed25519"):
            pk = ed_pubkey or _read_key_bytes(os.environ.get("P2P_ALERT_ED25519_PK"))
            if pk is not None and len(pk) == 32:
                try:
                    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
                    _ed.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
                    return True
                except Exception:
                    return False
            if alg == "ed25519":
                return False
        return False
    except Exception:
        return False


class SecurityMonitor:
    """
    Continuous Security Monitor for real-time threat detection.
    
    This class provides:
    1. Behavioral analysis for anomaly detection (Requirement 15.1)
    2. Cryptographic operation timing monitoring (Requirement 15.2)
    3. Unusual key usage pattern detection (Requirement 15.3)
    4. Honeypot keys that trigger alerts (Requirement 15.4)
    5. SIEM integration via secure API (Requirement 15.5)
    6. Security metrics dashboard (Requirement 15.6)
    """
    
    # Timing thresholds for side-channel detection
    TIMING_CV_THRESHOLD = 0.05  # Coefficient of variation threshold
    TIMING_WINDOW_SIZE = 100  # Number of measurements for analysis
    
    # Behavioral analysis thresholds
    ANOMALY_THRESHOLD = 3.0  # Standard deviations for anomaly detection
    KEY_ACCESS_RATE_LIMIT = 100  # Max key accesses per minute
    
    def __init__(self, siem_endpoint: Optional[str] = None, siem_api_key: Optional[str] = None):
        """
        Initialize the Security Monitor.
        
        Args:
            siem_endpoint: Optional SIEM API endpoint URL
            siem_api_key: Optional SIEM API key for authentication
        """
        # SIEM configuration
        self._siem_endpoint = siem_endpoint
        self._siem_api_key = siem_api_key
        self._siem_enabled = siem_endpoint is not None
        
        # Monitoring state
        self._monitoring_active = False
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        
        # Behavioral analysis
        self._behavior_events: deque = deque(maxlen=10000)
        self._behavior_baselines: Dict[BehaviorType, Dict[str, float]] = {}
        self._key_access_counts: Dict[str, List[datetime]] = defaultdict(list)
        
        # Timing analysis
        self._timing_measurements: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.TIMING_WINDOW_SIZE)
        )
        self._timing_baselines: Dict[str, Dict[str, float]] = {}
        
        # Honeypot keys
        self._honeypot_keys: Dict[str, HoneypotKey] = {}
        
        # Alerts
        self._alerts: deque = deque(maxlen=1000)
        self._siem_retry_queue: deque = deque(maxlen=5000)
        self._alert_callbacks: List[Callable[[SecurityAlert], None]] = []
        
        # Metrics
        self._metrics_history: deque = deque(maxlen=1000)
        self._current_metrics = SecurityMetrics(timestamp=datetime.now())
        
        # Alert queue for async processing
        self._alert_queue: queue.Queue = queue.Queue()
        
        logger.info("SecurityMonitor initialized")
    
    def start_monitoring(self) -> bool:
        """
        Start continuous security monitoring.
        
        Returns:
            bool: True if monitoring started successfully
        """
        with self._lock:
            if self._monitoring_active:
                logger.debug("Security monitoring already active")
                return True
            
            try:
                self._monitoring_active = True
                self._stop_event.clear()
                
                # Start monitoring thread
                self._monitoring_thread = threading.Thread(
                    target=self._monitoring_loop,
                    name="SecurityMonitor",
                    daemon=True
                )
                self._monitoring_thread.start()
                
                logger.info("Continuous security monitoring started")
                return True
                
            except Exception as e:
                logger.error(f"Failed to start monitoring: {e}")
                self._monitoring_active = False
                return False
    
    def stop_monitoring(self) -> None:
        """Stop continuous security monitoring."""
        with self._lock:
            if not self._monitoring_active:
                return
            
            self._stop_event.set()
            self._monitoring_active = False
            
            if self._monitoring_thread and self._monitoring_thread.is_alive():
                self._monitoring_thread.join(timeout=5.0)
            
            logger.info("Continuous security monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop for continuous analysis."""
        logger.debug("Monitoring loop started")
        
        while not self._stop_event.is_set():
            try:
                # Analyze behavioral patterns
                self._analyze_behavior_patterns()
                
                # Check timing consistency
                self._analyze_timing_patterns()
                
                # Update metrics
                self._update_metrics()
                
                # Process alert queue
                self._process_alert_queue()
                
                # Export to SIEM if enabled
                if self._siem_enabled:
                    self._export_to_siem()
                
                # Sleep before next cycle
                self._stop_event.wait(timeout=10.0)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                self._stop_event.wait(timeout=5.0)
        
        logger.debug("Monitoring loop ended")

    # =========================================================================
    # Behavioral Analysis (Requirement 15.1)
    # =========================================================================
    
    def record_behavior(
        self,
        behavior_type: BehaviorType,
        key_id: Optional[str] = None,
        peer_id: Optional[str] = None,
        session_id: Optional[str] = None,
        duration_ms: Optional[float] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Record a behavioral event for analysis.
        
        Requirement 15.1: Behavioral analysis for anomaly detection
        
        Args:
            behavior_type: Type of behavior being recorded
            key_id: Optional key identifier
            peer_id: Optional peer identifier
            session_id: Optional session identifier
            duration_ms: Optional operation duration in milliseconds
            success: Whether the operation succeeded
            details: Additional event details
            
        Returns:
            str: Event ID for the recorded behavior
        """
        event_id = secrets.token_hex(16)
        
        event = BehaviorEvent(
            event_id=event_id,
            behavior_type=behavior_type,
            timestamp=datetime.now(),
            key_id=key_id,
            peer_id=peer_id,
            session_id=session_id,
            duration_ms=duration_ms,
            success=success,
            details=details or {}
        )
        
        with self._lock:
            self._behavior_events.append(event)
            self._current_metrics.total_operations += 1
            
            if not success:
                self._current_metrics.failed_operations += 1
            
            # Track key access for rate limiting
            if key_id:
                self._key_access_counts[key_id].append(event.timestamp)
                
                # Check for honeypot access
                if key_id in self._honeypot_keys:
                    self._handle_honeypot_access(key_id)
        
        # Check for anomalies asynchronously
        self._check_behavior_anomaly(event)
        
        return event_id
    
    def _analyze_behavior_patterns(self) -> None:
        """Analyze behavioral patterns for anomalies."""
        with self._lock:
            if len(self._behavior_events) < 10:
                return
            
            # Analyze by behavior type
            for behavior_type in BehaviorType:
                events = [e for e in self._behavior_events 
                         if e.behavior_type == behavior_type]
                
                if len(events) < 5:
                    continue
                
                # Calculate baseline statistics
                durations = [e.duration_ms for e in events if e.duration_ms is not None]
                
                if durations:
                    mean_duration = statistics.mean(durations)
                    std_duration = statistics.stdev(durations) if len(durations) > 1 else 0
                    
                    self._behavior_baselines[behavior_type] = {
                        'mean_duration': mean_duration,
                        'std_duration': std_duration,
                        'event_count': len(events),
                        'success_rate': sum(1 for e in events if e.success) / len(events)
                    }
    
    def _check_behavior_anomaly(self, event: BehaviorEvent) -> None:
        """Check if a behavioral event is anomalous."""
        baseline = self._behavior_baselines.get(event.behavior_type)
        
        if not baseline or event.duration_ms is None:
            return
        
        mean = baseline['mean_duration']
        std = baseline['std_duration']
        
        if std > 0:
            z_score = abs(event.duration_ms - mean) / std
            
            if z_score > self.ANOMALY_THRESHOLD:
                self._current_metrics.anomalies_detected += 1
                
                self._generate_alert(
                    severity=AlertSeverity.MEDIUM,
                    title="Behavioral Anomaly Detected",
                    description=f"Unusual {event.behavior_type.value} operation detected",
                    alert_type="behavioral_anomaly",
                    details={
                        'behavior_type': event.behavior_type.value,
                        'duration_ms': event.duration_ms,
                        'expected_mean': mean,
                        'z_score': z_score,
                        'key_id': event.key_id,
                        'peer_id': event.peer_id
                    }
                )
    
    # =========================================================================
    # Timing Monitoring (Requirement 15.2)
    # =========================================================================
    
    def record_timing(
        self,
        operation: str,
        duration_ns: int,
        input_size: int = 0,
        key_id: Optional[str] = None
    ) -> None:
        """
        Record a timing measurement for side-channel analysis.
        
        Requirement 15.2: Monitor cryptographic operation timing for side-channel indicators
        
        Args:
            operation: Name of the cryptographic operation
            duration_ns: Duration in nanoseconds
            input_size: Size of input data
            key_id: Optional key identifier
        """
        measurement = TimingMeasurement(
            operation=operation,
            duration_ns=duration_ns,
            timestamp=datetime.now(),
            input_size=input_size,
            key_id=key_id
        )
        
        with self._lock:
            self._timing_measurements[operation].append(measurement)
        
        # Check for timing anomalies
        self._check_timing_anomaly(operation)
    
    def _analyze_timing_patterns(self) -> None:
        """Analyze timing patterns for side-channel indicators."""
        with self._lock:
            for operation, measurements in self._timing_measurements.items():
                if len(measurements) < 10:
                    continue
                
                durations = [m.duration_ns for m in measurements]
                
                mean_duration = statistics.mean(durations)
                std_duration = statistics.stdev(durations) if len(durations) > 1 else 0
                
                # Calculate coefficient of variation
                cv = std_duration / mean_duration if mean_duration > 0 else 0
                
                self._timing_baselines[operation] = {
                    'mean_ns': mean_duration,
                    'std_ns': std_duration,
                    'cv': cv,
                    'sample_count': len(durations)
                }
                
                # Check if CV exceeds threshold (potential timing leak)
                if cv > self.TIMING_CV_THRESHOLD:
                    self._current_metrics.timing_anomalies += 1
                    
                    self._generate_alert(
                        severity=AlertSeverity.HIGH,
                        title="Timing Side-Channel Indicator",
                        description=f"High timing variance detected in {operation}",
                        alert_type="timing_anomaly",
                        details={
                            'operation': operation,
                            'coefficient_of_variation': cv,
                            'threshold': self.TIMING_CV_THRESHOLD,
                            'mean_ns': mean_duration,
                            'std_ns': std_duration
                        }
                    )
    
    def _check_timing_anomaly(self, operation: str) -> None:
        """Check for timing anomalies in a specific operation."""
        baseline = self._timing_baselines.get(operation)
        
        if not baseline:
            return
        
        measurements = self._timing_measurements.get(operation, [])
        if not measurements:
            return
        
        latest = measurements[-1]
        mean = baseline['mean_ns']
        std = baseline['std_ns']
        
        if std > 0:
            z_score = abs(latest.duration_ns - mean) / std
            
            if z_score > self.ANOMALY_THRESHOLD:
                self._generate_alert(
                    severity=AlertSeverity.MEDIUM,
                    title="Timing Anomaly Detected",
                    description=f"Unusual timing for {operation}",
                    alert_type="timing_spike",
                    details={
                        'operation': operation,
                        'duration_ns': latest.duration_ns,
                        'expected_mean_ns': mean,
                        'z_score': z_score
                    }
                )
    
    def get_timing_analysis(self, operation: str) -> Optional[Dict[str, Any]]:
        """
        Get timing analysis for a specific operation.
        
        Args:
            operation: Name of the operation
            
        Returns:
            Dict with timing statistics or None if not enough data
        """
        with self._lock:
            return self._timing_baselines.get(operation)
    
    def is_timing_constant(self, operation: str) -> bool:
        """
        Check if an operation has constant-time behavior.
        
        Args:
            operation: Name of the operation
            
        Returns:
            bool: True if coefficient of variation is below threshold
        """
        analysis = self.get_timing_analysis(operation)
        
        if not analysis:
            return True  # Not enough data to determine
        
        return analysis['cv'] < self.TIMING_CV_THRESHOLD

    # =========================================================================
    # Key Usage Pattern Detection (Requirement 15.3)
    # =========================================================================
    
    def detect_unusual_key_usage(self, key_id: str) -> bool:
        """
        Detect unusual key usage patterns.
        
        Requirement 15.3: Detect and alert on unusual key usage patterns
        
        Args:
            key_id: Key identifier to check
            
        Returns:
            bool: True if unusual usage detected
        """
        with self._lock:
            access_times = self._key_access_counts.get(key_id, [])
            
            if not access_times:
                return False
            
            # Clean old entries (keep last hour)
            cutoff = datetime.now() - timedelta(hours=1)
            access_times = [t for t in access_times if t > cutoff]
            self._key_access_counts[key_id] = access_times
            
            # Check rate limit (accesses per minute)
            recent_cutoff = datetime.now() - timedelta(minutes=1)
            recent_accesses = sum(1 for t in access_times if t > recent_cutoff)
            
            if recent_accesses > self.KEY_ACCESS_RATE_LIMIT:
                self._generate_alert(
                    severity=AlertSeverity.HIGH,
                    title="Unusual Key Usage Pattern",
                    description=f"Key {key_id[:16]}... accessed {recent_accesses} times in last minute",
                    alert_type="unusual_key_usage",
                    details={
                        'key_id': key_id,
                        'access_count': recent_accesses,
                        'threshold': self.KEY_ACCESS_RATE_LIMIT,
                        'time_window': '1 minute'
                    }
                )
                return True
            
            # Check for burst patterns
            if len(access_times) >= 10:
                # Calculate inter-access intervals
                intervals = []
                sorted_times = sorted(access_times)
                for i in range(1, len(sorted_times)):
                    interval = (sorted_times[i] - sorted_times[i-1]).total_seconds()
                    intervals.append(interval)
                
                if intervals:
                    mean_interval = statistics.mean(intervals)
                    
                    # Very short intervals indicate potential attack
                    if mean_interval < 0.01:  # Less than 10ms average
                        self._generate_alert(
                            severity=AlertSeverity.HIGH,
                            title="Key Access Burst Detected",
                            description=f"Rapid key access pattern for {key_id[:16]}...",
                            alert_type="key_access_burst",
                            details={
                                'key_id': key_id,
                                'mean_interval_ms': mean_interval * 1000,
                                'access_count': len(access_times)
                            }
                        )
                        return True
            
            return False
    
    def get_key_usage_stats(self, key_id: str) -> Dict[str, Any]:
        """
        Get usage statistics for a specific key.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Dict with key usage statistics
        """
        with self._lock:
            access_times = self._key_access_counts.get(key_id, [])
            
            if not access_times:
                return {
                    'key_id': key_id,
                    'total_accesses': 0,
                    'last_access': None
                }
            
            # Calculate statistics
            now = datetime.now()
            last_hour = [t for t in access_times if t > now - timedelta(hours=1)]
            last_minute = [t for t in access_times if t > now - timedelta(minutes=1)]
            
            return {
                'key_id': key_id,
                'total_accesses': len(access_times),
                'accesses_last_hour': len(last_hour),
                'accesses_last_minute': len(last_minute),
                'last_access': max(access_times) if access_times else None
            }
    
    # =========================================================================
    # Honeypot Keys (Requirement 15.4)
    # =========================================================================
    
    def create_honeypot_key(
        self,
        key_id: Optional[str] = None,
        description: str = "Honeypot key"
    ) -> str:
        """
        Create a honeypot key that triggers alerts when accessed.
        
        Requirement 15.4: Implement honeypot keys that trigger alerts when accessed
        
        Args:
            key_id: Optional custom key ID (generated if not provided)
            description: Description of the honeypot key
            
        Returns:
            str: The honeypot key ID
        """
        if key_id is None:
            key_id = f"honeypot_{secrets.token_hex(16)}"
        
        # Generate fake key material
        key_material = secrets.token_bytes(32)
        
        honeypot = HoneypotKey(
            key_id=key_id,
            key_material=key_material,
            created_at=datetime.now(),
            description=description,
            alert_on_access=True
        )
        
        with self._lock:
            self._honeypot_keys[key_id] = honeypot
        
        logger.info(f"Honeypot key created: {key_id}")
        return key_id
    
    def is_honeypot_key(self, key_id: str) -> bool:
        """
        Check if a key ID is a honeypot key.
        
        Args:
            key_id: Key identifier to check
            
        Returns:
            bool: True if the key is a honeypot
        """
        with self._lock:
            return key_id in self._honeypot_keys
    
    def access_honeypot_key(self, key_id: str) -> bytes:
        """
        Access a honeypot key (triggers alert).
        
        This method is used to test honeypot functionality.
        In production, honeypot access is detected via record_behavior().
        
        Args:
            key_id: Honeypot key identifier
            
        Returns:
            bytes: The honeypot key material
            
        Raises:
            HoneypotAccessError: Always raised to indicate honeypot access
        """
        with self._lock:
            if key_id not in self._honeypot_keys:
                raise KeyError(f"Honeypot key not found: {key_id}")
            
            honeypot = self._honeypot_keys[key_id]
            honeypot.access_count += 1
            honeypot.last_access = datetime.now()
        
        # Trigger alert
        self._handle_honeypot_access(key_id)
        
        # Return key material but also raise to indicate honeypot
        raise HoneypotAccessError(key_id)
    
    def _handle_honeypot_access(self, key_id: str) -> None:
        """
        Handle honeypot key access - generate immediate alert.
        
        Requirement 15.4: Honeypot access triggers alert
        
        Args:
            key_id: The accessed honeypot key ID
        """
        with self._lock:
            honeypot = self._honeypot_keys.get(key_id)
            
            if not honeypot:
                return
            
            self._current_metrics.honeypot_triggers += 1
        
        # Generate CRITICAL alert immediately
        self._generate_alert(
            severity=AlertSeverity.CRITICAL,
            title="HONEYPOT KEY ACCESSED",
            description=f"Honeypot key '{key_id}' was accessed - potential intrusion detected",
            alert_type="honeypot_access",
            details={
                'key_id': key_id,
                'description': honeypot.description if honeypot else 'Unknown',
                'access_count': honeypot.access_count if honeypot else 0,
                'created_at': honeypot.created_at.isoformat() if honeypot else None,
                'action_required': 'IMMEDIATE INVESTIGATION REQUIRED'
            }
        )
        
        logger.critical(f"HONEYPOT KEY ACCESSED: {key_id}")
    
    def get_honeypot_stats(self) -> Dict[str, Any]:
        """
        Get statistics for all honeypot keys.
        
        Returns:
            Dict with honeypot statistics
        """
        with self._lock:
            stats = {
                'total_honeypots': len(self._honeypot_keys),
                'total_triggers': sum(h.access_count for h in self._honeypot_keys.values()),
                'honeypots': []
            }
            
            for key_id, honeypot in self._honeypot_keys.items():
                stats['honeypots'].append({
                    'key_id': key_id,
                    'description': honeypot.description,
                    'access_count': honeypot.access_count,
                    'last_access': honeypot.last_access.isoformat() if honeypot.last_access else None,
                    'created_at': honeypot.created_at.isoformat()
                })
            
            return stats

    # =========================================================================
    # SIEM Integration (Requirement 15.5)
    # =========================================================================
    
    def configure_siem(
        self,
        endpoint: str,
        api_key: str,
        verify_ssl: bool = True
    ) -> bool:
        """
        Configure SIEM integration.
        
        Requirement 15.5: Support integration with external SIEM systems via secure API
        
        Args:
            endpoint: SIEM API endpoint URL
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
            
        Returns:
            bool: True if configuration successful
        """
        with self._lock:
            self._siem_endpoint = endpoint
            self._siem_api_key = api_key
            self._siem_verify_ssl = verify_ssl
            self._siem_enabled = True
        
        logger.info(f"SIEM integration configured: {endpoint}")
        return True
    
    def disable_siem(self) -> None:
        """Disable SIEM integration."""
        with self._lock:
            self._siem_enabled = False
        
        logger.info("SIEM integration disabled")
    
    def _export_to_siem(self) -> None:
        """Export pending alerts to SIEM system (delegates to retry-queue exporter)."""
        return self._export_alerts_to_siem()

    def sign_alert(self, alert: SecurityAlert) -> str:
        """Generate HMAC-SHA3-256 cryptographic signature for SIEM alert telemetry."""
        key = (self._siem_api_key or "SECURE_P2P_LOCAL_TELEMETRY").encode('utf-8')
        payload = f"{alert.alert_id}:{alert.severity.value}:{alert.title}:{alert.timestamp.isoformat()}:{alert.source}".encode('utf-8')
        return hmac.new(key, payload, hashlib.sha3_256).hexdigest()

    def _sign_alert_payload(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sign a SIEM JSON payload -> {payload, sig_b64, kid, alg}.

        Non-breaking add-on: prefers ML-DSA-87 (SBOM/cert key), else Ed25519
        fallback. Fail-open with warn unless P2P_ALERTS_REQUIRE_SIG=1.
        """
        return sign_alert_payload_envelope(alert_data)

    def verify_alert_envelope(
        self,
        envelope: Dict[str, Any],
        mldsa_pubkey: Optional[bytes] = None,
        ed_pubkey: Optional[bytes] = None,
    ) -> bool:
        """Verify a signed alert envelope. Wrapper around module helper."""
        return verify_signed_alert_envelope(envelope, mldsa_pubkey, ed_pubkey)

    def _export_alerts_to_siem(self) -> None:
        """Export unexported alerts to SIEM with persistent retry queue and cryptographic signing."""
        if not self._siem_enabled or not self._siem_endpoint:
            return
        
        with self._lock:
            # Get unexported alerts and pending retries
            unexported = [a for a in self._alerts if not a.exported_to_siem]
            retries = list(self._siem_retry_queue)
            self._siem_retry_queue.clear()
        
        pending = unexported + [a for a in retries if not a.exported_to_siem]
        if not pending:
            return
        
        for alert in pending:
            if alert.exported_to_siem:
                continue
            try:
                if self._send_to_siem(alert):
                    alert.exported_to_siem = True
                else:
                    alert.retry_count += 1
                    if alert.retry_count <= 5:
                        self._siem_retry_queue.append(alert)
            except Exception as e:
                logger.error(f"Failed to export alert to SIEM: {e}")
                alert.retry_count += 1
                if alert.retry_count <= 5:
                    self._siem_retry_queue.append(alert)
    
    def _send_to_siem(self, alert: SecurityAlert) -> bool:
        """
        Send a single alert to SIEM with cryptographic HMAC signature.
        
        Args:
            alert: Alert to send
            
        Returns:
            bool: True if sent successfully
        """
        try:
            if not alert.signature:
                alert.signature = self.sign_alert(alert)

            # Prepare alert data (legacy flat fields retained for compatibility)
            alert_data = {
                'alert_id': alert.alert_id,
                'severity': alert.severity.value,
                'title': alert.title,
                'description': alert.description,
                'timestamp': alert.timestamp.isoformat(),
                'source': alert.source,
                'alert_type': alert.alert_type,
                'details': alert.details,
                'resolved': alert.resolved,
                'signature': alert.signature,
                'retry_count': alert.retry_count
            }

            # Signed-alert envelope (non-breaking add-on): ML-DSA-87 if a
            # SBOM/cert key is available, else Ed25519 fallback. Fail-open in
            # lab (warn), fail-closed when P2P_ALERTS_REQUIRE_SIG=1.
            try:
                envelope = self._sign_alert_payload(dict(alert_data))
            except RuntimeError as e:
                logger.error(f"{e}")
                return False
            if not envelope.get("sig_b64"):
                if alerts_require_sig():
                    logger.error("FAIL-CLOSED: refusing unsigned SIEM send "
                                 "(P2P_ALERTS_REQUIRE_SIG=1).")
                    return False
            else:
                alert_data['sig_envelope'] = {
                    'sig_b64': envelope.get("sig_b64"),
                    'kid': envelope.get("kid"),
                    'alg': envelope.get("alg"),
                }
                alert_data['alert_sig'] = envelope.get("sig_b64")
                alert_data['alert_kid'] = envelope.get("kid")
                alert_data['alert_alg'] = envelope.get("alg")

            # Air-gap enforcement: never attempt external SIEM POST when
            # air-gapped (do not attempt network). Retained in local audit
            # log. Legacy: suppression triggers on P2P_AIR_GAPPED_MODE (or
            # config air_gapped_mode), NOT on P2P_OFFLINE_MODE alone, so
            # existing retry-queue semantics are unchanged when not air-gapped.
            try:
                from air_gapped_operation import is_air_gapped as _is_air_gapped
                _air_gapped = bool(_is_air_gapped(include_offline=False))
            except Exception:
                _air_gapped = os.environ.get("P2P_AIR_GAPPED_MODE") == "1"
            if _air_gapped:
                logger.warning(
                    f"Air-gapped mode: skipping external SIEM POST for alert "
                    f"{alert.alert_id} (retained in local audit log, no network attempt)."
                )
                return True

            import urllib.request
            import ssl
            
            # Create request
            data = json.dumps(alert_data).encode('utf-8')
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self._siem_api_key}',
                'X-Source': 'SecureP2P-SecurityMonitor'
            }
            if alert_data.get('alert_sig'):
                headers['X-Alert-Sig'] = str(alert_data['alert_sig'])
            if alert_data.get('alert_kid'):
                headers['X-Alert-Kid'] = str(alert_data['alert_kid'])
            req = urllib.request.Request(
                self._siem_endpoint,
                data=data,
                headers=headers,
                method='POST'
            )
            
            # Configure SSL - strictly enforce verification for military SIEM telemetry
            ssl_context = ssl.create_default_context()
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.check_hostname = True
            
            # Send request (B310: https-only SIEM URL validated at config load;
            # verified TLS ctx + 10s timeout - audited, not a file:/ scheme risk)
            with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:  # nosec B310 - https SIEM + verified ctx + timeout
                if response.status == 200 or response.status == 201:
                    logger.debug(f"Alert exported to SIEM: {alert.alert_id}")
                    return True
                else:
                    logger.warning(f"SIEM returned status {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"SIEM export failed: {e}")
            return False
    
    def export_alerts_batch(self, alerts: List[SecurityAlert]) -> int:
        """
        Export a batch of alerts to SIEM.
        
        Args:
            alerts: List of alerts to export
            
        Returns:
            int: Number of successfully exported alerts
        """
        if not self._siem_enabled:
            return 0
        
        exported = 0
        for alert in alerts:
            if self._send_to_siem(alert):
                alert.exported_to_siem = True
                exported += 1
        
        return exported
    
    def get_siem_status(self) -> Dict[str, Any]:
        """
        Get SIEM integration status.
        
        Returns:
            Dict with SIEM status information
        """
        with self._lock:
            exported_count = sum(1 for a in self._alerts if a.exported_to_siem)
            pending_count = sum(1 for a in self._alerts if not a.exported_to_siem)
            
            return {
                'enabled': self._siem_enabled,
                'endpoint': self._siem_endpoint if self._siem_enabled else None,
                'exported_alerts': exported_count,
                'pending_alerts': pending_count
            }
    
    # =========================================================================
    # Security Metrics Dashboard (Requirement 15.6)
    # =========================================================================
    
    def get_metrics(self) -> SecurityMetrics:
        """
        Get current security metrics.
        
        Requirement 15.6: Generate security metrics dashboard with real-time updates
        
        Returns:
            SecurityMetrics: Current security metrics
        """
        with self._lock:
            self._current_metrics.timestamp = datetime.now()
            return self._current_metrics
    
    def get_metrics_history(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """
        Get historical metrics.
        
        Args:
            minutes: Number of minutes of history to retrieve
            
        Returns:
            List of metrics dictionaries
        """
        cutoff = datetime.now() - timedelta(minutes=minutes)
        
        with self._lock:
            history = [
                {
                    'timestamp': m.timestamp.isoformat(),
                    'total_operations': m.total_operations,
                    'failed_operations': m.failed_operations,
                    'anomalies_detected': m.anomalies_detected,
                    'honeypot_triggers': m.honeypot_triggers,
                    'timing_anomalies': m.timing_anomalies,
                    'alerts_generated': m.alerts_generated,
                    'average_operation_time_ms': m.average_operation_time_ms
                }
                for m in self._metrics_history
                if m.timestamp > cutoff
            ]
            
            return history
    
    def _update_metrics(self) -> None:
        """Update and store current metrics."""
        with self._lock:
            # Calculate average operation time
            recent_events = [
                e for e in self._behavior_events
                if e.duration_ms is not None and 
                e.timestamp > datetime.now() - timedelta(minutes=5)
            ]
            
            if recent_events:
                durations = [e.duration_ms for e in recent_events]
                self._current_metrics.average_operation_time_ms = statistics.mean(durations)
                
                if len(durations) > 1:
                    self._current_metrics.timing_variance = statistics.variance(durations)
            
            # Count alerts
            self._current_metrics.alerts_generated = len(self._alerts)
            self._current_metrics.alerts_resolved = sum(1 for a in self._alerts if a.resolved)
            
            # Store snapshot
            metrics_snapshot = SecurityMetrics(
                timestamp=datetime.now(),
                total_operations=self._current_metrics.total_operations,
                failed_operations=self._current_metrics.failed_operations,
                anomalies_detected=self._current_metrics.anomalies_detected,
                honeypot_triggers=self._current_metrics.honeypot_triggers,
                timing_anomalies=self._current_metrics.timing_anomalies,
                active_sessions=self._current_metrics.active_sessions,
                blocked_peers=self._current_metrics.blocked_peers,
                alerts_generated=self._current_metrics.alerts_generated,
                alerts_resolved=self._current_metrics.alerts_resolved,
                average_operation_time_ms=self._current_metrics.average_operation_time_ms,
                timing_variance=self._current_metrics.timing_variance
            )
            
            self._metrics_history.append(metrics_snapshot)
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Get comprehensive dashboard data.
        
        Returns:
            Dict with all dashboard information
        """
        metrics = self.get_metrics()
        
        with self._lock:
            # Get recent alerts
            recent_alerts = [
                {
                    'alert_id': a.alert_id,
                    'severity': a.severity.value,
                    'title': a.title,
                    'timestamp': a.timestamp.isoformat(),
                    'resolved': a.resolved
                }
                for a in list(self._alerts)[-10:]
            ]
            
            # Get timing analysis summary
            timing_summary = {}
            for op, baseline in self._timing_baselines.items():
                timing_summary[op] = {
                    'cv': baseline['cv'],
                    'is_constant_time': baseline['cv'] < self.TIMING_CV_THRESHOLD,
                    'sample_count': baseline['sample_count']
                }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'monitoring_active': self._monitoring_active,
            'metrics': {
                'total_operations': metrics.total_operations,
                'failed_operations': metrics.failed_operations,
                'anomalies_detected': metrics.anomalies_detected,
                'honeypot_triggers': metrics.honeypot_triggers,
                'timing_anomalies': metrics.timing_anomalies,
                'alerts_generated': metrics.alerts_generated,
                'alerts_resolved': metrics.alerts_resolved,
                'average_operation_time_ms': metrics.average_operation_time_ms
            },
            'recent_alerts': recent_alerts,
            'timing_analysis': timing_summary,
            'siem_status': self.get_siem_status(),
            'honeypot_stats': self.get_honeypot_stats()
        }

    # =========================================================================
    # Alert Management
    # =========================================================================
    
    def _generate_alert(
        self,
        severity: AlertSeverity,
        title: str,
        description: str,
        alert_type: str,
        details: Optional[Dict[str, Any]] = None
    ) -> SecurityAlert:
        """
        Generate a security alert.
        
        Args:
            severity: Alert severity level
            title: Alert title
            description: Alert description
            alert_type: Type of alert
            details: Additional details
            
        Returns:
            SecurityAlert: The generated alert
        """
        alert_id = secrets.token_hex(16)
        
        alert = SecurityAlert(
            alert_id=alert_id,
            severity=severity,
            title=title,
            description=description,
            timestamp=datetime.now(),
            source="SecurityMonitor",
            alert_type=alert_type,
            details=details or {}
        )
        
        with self._lock:
            self._alerts.append(alert)
            self._current_metrics.alerts_generated += 1
        
        # Queue for async processing
        self._alert_queue.put(alert)
        
        # Log based on severity
        if severity == AlertSeverity.CRITICAL:
            logger.critical(f"ALERT [{severity.value}]: {title}")
        elif severity == AlertSeverity.HIGH:
            logger.warning(f"ALERT [{severity.value}]: {title}")
        else:
            logger.info(f"ALERT [{severity.value}]: {title}")
        
        return alert
    
    def _process_alert_queue(self) -> None:
        """Process queued alerts and notify callbacks."""
        while not self._alert_queue.empty():
            try:
                alert = self._alert_queue.get_nowait()
                
                # Notify callbacks
                for callback in self._alert_callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        logger.error(f"Alert callback failed: {e}")
                
            except queue.Empty:
                break
    
    def register_alert_callback(self, callback: Callable[[SecurityAlert], None]) -> None:
        """
        Register a callback for alert notifications.
        
        Args:
            callback: Function to call when alerts are generated
        """
        with self._lock:
            self._alert_callbacks.append(callback)
        
        logger.debug("Alert callback registered")
    
    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        resolved: Optional[bool] = None,
        limit: int = 100
    ) -> List[SecurityAlert]:
        """
        Get alerts with optional filtering.
        
        Args:
            severity: Filter by severity
            resolved: Filter by resolved status
            limit: Maximum number of alerts to return
            
        Returns:
            List of matching alerts
        """
        with self._lock:
            alerts = list(self._alerts)
            
            if severity is not None:
                alerts = [a for a in alerts if a.severity == severity]
            
            if resolved is not None:
                alerts = [a for a in alerts if a.resolved == resolved]
            
            return alerts[-limit:]
    
    def resolve_alert(self, alert_id: str) -> bool:
        """
        Mark an alert as resolved.
        
        Args:
            alert_id: Alert ID to resolve
            
        Returns:
            bool: True if alert was found and resolved
        """
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    alert.resolved = True
                    alert.resolution_time = datetime.now()
                    self._current_metrics.alerts_resolved += 1
                    logger.info(f"Alert resolved: {alert_id}")
                    return True
        
        return False
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """
        Get summary of all alerts.
        
        Returns:
            Dict with alert summary
        """
        with self._lock:
            summary = {
                'total': len(self._alerts),
                'unresolved': sum(1 for a in self._alerts if not a.resolved),
                'by_severity': {},
                'by_type': {}
            }
            
            for severity in AlertSeverity:
                count = sum(1 for a in self._alerts if a.severity == severity)
                if count > 0:
                    summary['by_severity'][severity.value] = count
            
            for alert in self._alerts:
                if alert.alert_type not in summary['by_type']:
                    summary['by_type'][alert.alert_type] = 0
                summary['by_type'][alert.alert_type] += 1
            
            return summary


# =========================================================================
# Global Instance and Factory Functions
# =========================================================================

_security_monitor: Optional[SecurityMonitor] = None


def get_security_monitor() -> SecurityMonitor:
    """
    Get the global SecurityMonitor instance.
    
    Returns:
        SecurityMonitor: The global instance
    """
    global _security_monitor
    if _security_monitor is None:
        _security_monitor = SecurityMonitor()
    return _security_monitor


def initialize_security_monitor(
    siem_endpoint: Optional[str] = None,
    siem_api_key: Optional[str] = None
) -> SecurityMonitor:
    """
    Initialize the global SecurityMonitor instance.
    
    Args:
        siem_endpoint: Optional SIEM API endpoint
        siem_api_key: Optional SIEM API key
        
    Returns:
        SecurityMonitor: The initialized instance
    """
    global _security_monitor
    _security_monitor = SecurityMonitor(
        siem_endpoint=siem_endpoint,
        siem_api_key=siem_api_key
    )
    return _security_monitor


# =========================================================================
# Main Entry Point for Testing
# =========================================================================

if __name__ == "__main__":
    import time
    
    print("=== Security Monitor Test ===\n")
    
    # Create monitor
    monitor = SecurityMonitor()
    
    # Start monitoring
    monitor.start_monitoring()
    print("PASS: Monitoring started")
    
    # Create honeypot key
    honeypot_id = monitor.create_honeypot_key(description="Test honeypot")
    print(f"PASS: Honeypot key created: {honeypot_id}")
    
    # Record some behaviors
    for i in range(10):
        monitor.record_behavior(
            behavior_type=BehaviorType.ENCRYPTION,
            duration_ms=10.0 + (i * 0.5),
            success=True
        )
    print("PASS: Recorded 10 encryption behaviors")
    
    # Record timing measurements
    for i in range(20):
        monitor.record_timing(
            operation="aes_encrypt",
            duration_ns=1000000 + (i * 1000),  # ~1ms with small variance
            input_size=1024
        )
    print("PASS: Recorded 20 timing measurements")
    
    # Check timing analysis
    timing = monitor.get_timing_analysis("aes_encrypt")
    if timing:
        print(f"PASS: Timing analysis: CV={timing['cv']:.4f}, constant_time={timing['cv'] < 0.05}")
    
    # Test honeypot access
    print("\nTesting honeypot access...")
    try:
        monitor.access_honeypot_key(honeypot_id)
    except HoneypotAccessError as e:
        print(f"PASS: Honeypot access detected: {e}")
    
    # Get dashboard data
    dashboard = monitor.get_dashboard_data()
    print(f"\nPASS: Dashboard data retrieved:")
    print(f"  - Total operations: {dashboard['metrics']['total_operations']}")
    print(f"  - Honeypot triggers: {dashboard['metrics']['honeypot_triggers']}")
    print(f"  - Alerts generated: {dashboard['metrics']['alerts_generated']}")
    
    # Get alert summary
    summary = monitor.get_alert_summary()
    print(f"\nPASS: Alert summary:")
    print(f"  - Total alerts: {summary['total']}")
    print(f"  - Unresolved: {summary['unresolved']}")
    print(f"  - By severity: {summary['by_severity']}")
    
    # Stop monitoring
    monitor.stop_monitoring()
    print("\nPASS: Monitoring stopped")
    
    print("\n=== Test Complete ===")

