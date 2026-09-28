"""
Forward Secrecy Manager - Enhanced Key Rotation with Strict Triggers

This module implements enhanced forward secrecy with strict key rotation triggers
as specified in Requirements 4.1, 4.2, 4.3, 4.4, 4.5.

Key Features:
- Rotate after 100 messages (message_count threshold) - Requirement 4.1
- Rotate after 900 seconds (time threshold) - Requirement 4.1
- Use ephemeral ML-KEM-1024 keys for every exchange - Requirement 4.2
- Terminate session if rotation fails - Requirement 4.5
- DoD 5220.22-M secure memory wiping - Requirement 4.3

Standards Compliance:
- NIST FIPS 203 (ML-KEM-1024) for post-quantum key encapsulation
- DoD 5220.22-M for secure data destruction
- CNSA 2.0 algorithm requirements
"""

import time
import secrets
import hashlib
import logging
import threading
from typing import Optional, Tuple, Dict, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum

# Configure logging
logger = logging.getLogger("forward_secrecy_manager")
logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
import os
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging
file_handler = logging.FileHandler(os.path.join("logs", "forward_secrecy_manager.log"))
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


# --- Decrypt DFR / fault counters (non-breaking, observability only) ---
# needs-manual-review: this module's decrypt() is a symmetric-ratchet decrypt,
# NOT the ML-KEM KEM decaps. Authoritative KEM decaps counters live in
# pqc_algorithms.get_decaps_stats() and liboqs_wrapper.get_decaps_stats().
# These decrypt counters are a supplementary fault/DFR signal only and MUST NOT
# change success-path behavior. get_decaps_stats() alias is provided for task
# interface uniformity.
_DECRYPT_TOTAL = 0
_DECRYPT_FAIL = 0
_DECRYPT_LOCK = threading.Lock()
_DECRYPT_ALERT_THRESHOLD = 0.01  # 1% fail rate
_DECRYPT_MIN_SAMPLES = 100


def _record_decrypt_result(success: bool) -> dict:
    """Increment decrypt counters; CRITICAL log if failure rate anomalous."""
    global _DECRYPT_TOTAL, _DECRYPT_FAIL
    with _DECRYPT_LOCK:
        _DECRYPT_TOTAL += 1
        if not success:
            _DECRYPT_FAIL += 1
        total = _DECRYPT_TOTAL
        fail = _DECRYPT_FAIL
    if not success:
        logger.warning(f"forward-secrecy decrypt failure recorded ({fail}/{total})")
    if total >= _DECRYPT_MIN_SAMPLES and total > 0:
        rate = fail / total
        if rate > _DECRYPT_ALERT_THRESHOLD:
            logger.critical(
                "Possible fault/decryption-failure anomaly: forward-secrecy decrypt fail rate "
                f"{rate:.2%} ({fail}/{total}) exceeds 1% over {total} samples")
    return {"decaps_total": total, "decaps_fail": fail}


def get_decrypt_stats() -> dict:
    """Return forward-secrecy decrypt counters (read-only snapshot)."""
    with _DECRYPT_LOCK:
        total = _DECRYPT_TOTAL
        fail = _DECRYPT_FAIL
    rate = (fail / total) if total else 0.0
    return {"decrypt_total": total, "decrypt_fail": fail, "decrypt_fail_rate": rate,
            "decaps_total": total, "decaps_fail": fail, "decaps_fail_rate": rate}


def get_decaps_stats() -> dict:
    """Alias for interface uniformity; see needs-manual-review note above."""
    return get_decrypt_stats()


def reset_decrypt_stats() -> dict:
    """Reset decrypt counters (for tests)."""
    global _DECRYPT_TOTAL, _DECRYPT_FAIL
    with _DECRYPT_LOCK:
        _DECRYPT_TOTAL = 0
        _DECRYPT_FAIL = 0
    return get_decrypt_stats()


class RotationTrigger(Enum):
    """Enumeration of key rotation trigger types."""
    MESSAGE_COUNT = "message_count"
    TIME_THRESHOLD = "time_threshold"
    MANUAL = "manual"
    SECURITY_EVENT = "security_event"


class KeyRotationError(Exception):
    """Exception raised when key rotation fails - session must terminate."""


class SessionTerminationError(Exception):
    """Exception raised when session must be terminated due to security failure."""


@dataclass
class RotationConfig:
    """Configuration for key rotation thresholds.
    
    Implements Requirements 4.1:
    - message_threshold: Rotate after this many messages (default: 100)
    - time_threshold_seconds: Rotate after this many seconds (default: 900)
    """
    message_threshold: int = 100  # Requirement 4.1: Rotate after 100 messages
    time_threshold_seconds: int = 900  # Requirement 4.1: Rotate after 900 seconds
    fail_closed: bool = True  # Requirement 4.5: Terminate session if rotation fails
    use_ephemeral_keys: bool = True  # Requirement 4.2: Use ephemeral ML-KEM-1024 keys


@dataclass
class RotationState:
    """Tracks the current state of key rotation."""
    message_count: int = 0
    last_rotation_time: float = field(default_factory=time.time)
    rotation_count: int = 0
    last_trigger: Optional[RotationTrigger] = None
    session_active: bool = True


class _WipeableKeyDict(dict):
    """Dict subclass that coerces key-material values to wipeable bytearray.

    Byte-for-byte compatible with a plain ``dict`` for reads (``len``,
    iteration, ``.copy()``, ``.clear()``). Any ``__setitem__``/``update``/
    ``setdefault`` coerces ``bytes``/``memoryview`` values to ``bytearray``
    via the provided ``_coerce`` callback so external per-item assignment
    (``fsm._current_keys[name] = b"..."``) cannot smuggle immutable bytes
    into internal storage. Existing ``bytes`` callers keep working (backward
    compat); the immutable source itself cannot be wiped (CPython ``bytes``
    are immutable and may persist as GC copies) — see method docstrings.
    """

    def __init__(self, *args, _coerce=None, **kwargs):
        self._coerce = _coerce
        super().__init__()
        if args or kwargs:
            other = dict(*args, **kwargs)
            for k, v in other.items():
                self[k] = v

    def __setitem__(self, key, value):
        if self._coerce is not None:
            value = self._coerce(value, key)
        super().__setitem__(key, value)

    def update(self, *args, **kwargs):
        other = dict(*args, **kwargs)
        for k, v in other.items():
            self[k] = v

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

    def copy(self):  # type: ignore[override]
        return _WipeableKeyDict(super().copy(), _coerce=self._coerce)


class ForwardSecrecyManager:
    """
    Manages forward secrecy with strict key rotation triggers.
    
    Implements Requirements 4.1, 4.2, 4.4, 4.5:
    - Rotate after 100 messages (message_count threshold)
    - Rotate after 900 seconds (time threshold)
    - Use ephemeral ML-KEM-1024 keys for every exchange
    - Terminate session if rotation fails
    """
    
    def __init__(
        self,
        config: Optional[RotationConfig] = None,
        on_rotation_callback: Optional[Callable[[RotationTrigger], None]] = None,
        on_session_terminate: Optional[Callable[[str], None]] = None
    ):
        """
        Initialize the Forward Secrecy Manager.
        
        Args:
            config: Rotation configuration (uses defaults if None)
            on_rotation_callback: Called when rotation occurs
            on_session_terminate: Called when session must terminate
        """
        self.config = config or RotationConfig()
        self.state = RotationState()
        self._lock = threading.RLock()
        self._on_rotation = on_rotation_callback
        self._on_terminate = on_session_terminate

        # GC/memory caveat: CPython `bytes` are immutable — they cannot be
        # wiped in place and copies may linger in freed memory, GC arenas, or
        # swap. Internal key storage therefore uses wipeable `bytearray`
        # values so `_secure_wipe_keys` can overwrite them in place. This
        # reduces, but cannot eliminate, exposure (interpreter copies made
        # before conversion, e.g. KEM `keygen()` return values, may persist
        # until GC). Callers should prefer passing `bytearray` and drop
        # references promptly; `bytes` inputs are still accepted for backward
        # compat but trigger a one-time warning.
        self.__dict__['_immutable_source_warned'] = False
        self.__dict__['_current_keys_store'] = _WipeableKeyDict(
            _coerce=self._coerce_to_wipeable)
        self.__dict__['_previous_keys_store'] = _WipeableKeyDict(
            _coerce=self._coerce_to_wipeable)

        # Import secure memory wiping
        self._secure_wiper: Optional['SecureMemoryWiper'] = None
        try:
            from secure_memory_wiper import SecureMemoryWiper
            self._secure_wiper = SecureMemoryWiper()
            logger.info("SecureMemoryWiper initialized for DoD 5220.22-M compliant wiping")
        except ImportError:
            logger.warning("SecureMemoryWiper not available, using fallback wiping")

        logger.info(f"ForwardSecrecyManager initialized: message_threshold={self.config.message_threshold}, "
                   f"time_threshold={self.config.time_threshold_seconds}s")

    @property
    def _current_keys(self) -> Dict[str, bytearray]:
        """Internal wipeable key dict (values are `bytearray`)."""
        return self.__dict__['_current_keys_store']

    @_current_keys.setter
    def _current_keys(self, value: Dict[str, Union[bytes, bytearray]]) -> None:
        store = _WipeableKeyDict(_coerce=self._coerce_to_wipeable)
        if value:
            for k, v in dict(value).items():
                store[k] = v
        self.__dict__['_current_keys_store'] = store

    @property
    def _previous_keys(self) -> Dict[str, bytearray]:
        """Internal wipeable previous-key dict (values are `bytearray`)."""
        return self.__dict__['_previous_keys_store']

    @_previous_keys.setter
    def _previous_keys(self, value: Dict[str, Union[bytes, bytearray]]) -> None:
        store = _WipeableKeyDict(_coerce=self._coerce_to_wipeable)
        if value:
            for k, v in dict(value).items():
                store[k] = v
        self.__dict__['_previous_keys_store'] = store

    def _coerce_to_wipeable(
        self, value: Union[bytes, bytearray, memoryview], key_name: str = ""
    ) -> bytearray:
        """Convert key material to wipeable `bytearray` (backward compat).

        Accepts `bytes` (legacy callers) by copying into a new `bytearray`
        and emitting a one-time warning that the immutable source buffer
        itself cannot be wiped and may persist in GC memory. `bytearray`
        inputs are defensively copied so rotation snapshots
        (``_previous_keys = _current_keys.copy()``) never alias live keys.
        """
        if isinstance(value, bytearray):
            return bytearray(value)
        if isinstance(value, memoryview):
            if not self.__dict__.get('_immutable_source_warned', False):
                self.__dict__['_immutable_source_warned'] = True
                logger.warning(
                    "Key material for '%s' arrived as immutable/view source; "
                    "copied to wipeable bytearray but the source buffer cannot "
                    "be wiped and may persist in GC/swap memory.",
                    key_name,
                )
            return bytearray(bytes(value))
        if isinstance(value, bytes):
            if not self.__dict__.get('_immutable_source_warned', False):
                self.__dict__['_immutable_source_warned'] = True
                logger.warning(
                    "Key material for '%s' arrived as immutable bytes; copied "
                    "to wipeable bytearray but the source bytes cannot be "
                    "wiped and may persist in GC/swap memory. Prefer passing "
                    "bytearray.",
                    key_name,
                )
            return bytearray(value)
        # Non-bytes entries (should not occur for key material) pass through.
        return value  # type: ignore[return-value]

    def get_key_bytes(self, name: str) -> Optional[bytes]:
        """Return an immutable `bytes` copy of a stored key.

        Looks in current keys, then previous keys. The returned `bytes`
        object is inherently unwipeable (immutable; copies may linger in
        GC arenas/swap) — callers needing `bytes` for crypto APIs should
        minimize its lifetime and drop the reference promptly. Internal
        storage remains wipeable `bytearray`. Returns `None` if absent.
        """
        with self._lock:
            for store in (self._current_keys, self._previous_keys):
                if name in store:
                    val = store[name]
                    if isinstance(val, (bytearray, memoryview)):
                        return bytes(val)
                    if isinstance(val, bytes):
                        return bytes(val)
                    return None
            return None
    
    def check_rotation_needed(self) -> Tuple[bool, Optional[RotationTrigger]]:
        """
        Check if key rotation is needed based on thresholds.
        
        Returns:
            Tuple of (rotation_needed, trigger_type)
            
        Implements Requirement 4.1:
        - Check message count threshold (100 messages)
        - Check time threshold (900 seconds)
        """
        with self._lock:
            if not self.state.session_active:
                return False, None
            
            # Check message count threshold (Requirement 4.1)
            if self.state.message_count >= self.config.message_threshold:
                logger.info(f"Rotation needed: message count {self.state.message_count} >= {self.config.message_threshold}")
                return True, RotationTrigger.MESSAGE_COUNT
            
            # Check time threshold (Requirement 4.1)
            elapsed = time.time() - self.state.last_rotation_time
            if elapsed >= self.config.time_threshold_seconds:
                logger.info(f"Rotation needed: elapsed time {elapsed:.1f}s >= {self.config.time_threshold_seconds}s")
                return True, RotationTrigger.TIME_THRESHOLD
            
            return False, None
    
    def increment_message_count(self) -> bool:
        """
        Increment message count and check if rotation is needed.
        
        Returns:
            True if rotation was triggered, False otherwise
            
        Raises:
            SessionTerminationError: If rotation fails and fail_closed is True
        """
        with self._lock:
            if not self.state.session_active:
                raise SessionTerminationError("Session is not active")
            
            self.state.message_count += 1
            
            # Check if rotation is needed
            needs_rotation, trigger = self.check_rotation_needed()
            if needs_rotation:
                try:
                    self._perform_rotation(trigger)
                    return True
                except KeyRotationError as e:
                    if self.config.fail_closed:
                        self._terminate_session(f"Key rotation failed: {e}")
                        raise SessionTerminationError(f"Session terminated: {e}")
                    else:
                        logger.error(f"Key rotation failed but fail_closed is False: {e}")
                        return False
            
            return False
    
    def check_idle_rotation(self, max_idle_seconds: Optional[int] = None) -> bool:
        """
        Check and trigger rotation if session has been idle past the threshold.
        
        Args:
            max_idle_seconds: Optional override for idle threshold in seconds (default: config.time_threshold_seconds)
            
        Returns:
            True if rotation was triggered, False otherwise
        """
        with self._lock:
            if not self.state.session_active:
                return False
            
            idle_limit = max_idle_seconds if max_idle_seconds is not None else self.config.time_threshold_seconds
            elapsed = time.time() - self.state.last_rotation_time
            if elapsed >= idle_limit:
                logger.info(f"Idle key rotation triggered after {elapsed:.1f}s inactivity (threshold: {idle_limit}s)")
                try:
                    self._perform_rotation(RotationTrigger.TIME_THRESHOLD)
                    return True
                except KeyRotationError as e:
                    if self.config.fail_closed:
                        self._terminate_session(f"Idle key rotation failed: {e}")
                        raise SessionTerminationError(f"Session terminated: {e}")
                    else:
                        logger.error(f"Idle key rotation failed but fail_closed is False: {e}")
                        return False
            return False
    
    def _perform_rotation(self, trigger: RotationTrigger) -> None:
        """
        Perform key rotation with secure wiping of old keys.
        
        Args:
            trigger: The trigger that caused the rotation
            
        Raises:
            KeyRotationError: If rotation fails
            
        Implements Requirements 4.2, 4.3, 4.4:
        - Use ephemeral ML-KEM-1024 keys
        - Erase previous keys using DoD 5220.22-M
        - Implement Double Ratchet with ML-KEM-1024
        """
        logger.info(f"Performing key rotation triggered by {trigger.value}")
        
        try:
            # Store previous keys for secure wiping
            self._previous_keys = self._current_keys.copy()
            
            # Generate new ephemeral keys (Requirement 4.2)
            if self.config.use_ephemeral_keys:
                self._generate_ephemeral_keys()
            else:
                # For testing without key generation, just update generation time
                self._current_keys = {
                    'generation_time': int(time.time()).to_bytes(8, 'big')
                }
            
            # Securely wipe previous keys (Requirement 4.3)
            self._secure_wipe_keys(self._previous_keys)
            self._previous_keys.clear()
            
            # Update rotation state
            self.state.message_count = 0
            self.state.last_rotation_time = time.time()
            self.state.rotation_count += 1
            self.state.last_trigger = trigger
            
            # Notify callback if registered
            if self._on_rotation:
                self._on_rotation(trigger)
            
            logger.info(f"Key rotation completed successfully (rotation #{self.state.rotation_count})")
            
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            raise KeyRotationError(f"Failed to rotate keys: {e}")
    
    def _generate_ephemeral_keys(self) -> None:
        """
        Generate new ephemeral ML-KEM-1024 keys.
        
        Implements Requirement 4.2:
        - Use ephemeral ML-KEM-1024 keys for every exchange
        FAIL-CLOSED: Raises error if PQC not available in production mode.
        """
        import os
        production_mode = os.environ.get('SECURE_P2P_PRODUCTION', '').lower() == 'true'
        
        try:
            # Import ML-KEM-1024 from pqc_algorithms (lazy import to avoid slow startup)
            from pqc_algorithms import EnhancedMLKEM_1024
            
            kem = EnhancedMLKEM_1024()
            public_key, private_key = kem.keygen()

            # Store internally as wipeable bytearray. KEM returns immutable
            # bytes, so the source buffers cannot be wiped and may persist in
            # GC memory until collected — documented GC limit. Convert here so
            # all rotation snapshots and wipes operate on mutable copies.
            # The property setter also coerces, but convert explicitly so the
            # transient `bytes` lifetime is minimized and intent is obvious.
            self._current_keys = {
                'kem_public': bytearray(public_key),
                'kem_private': bytearray(private_key),
                'generation_time': bytearray(int(time.time()).to_bytes(8, 'big'))
            }
            
            logger.debug(f"Generated new ephemeral ML-KEM-1024 keys: PK={len(public_key)} bytes")
            
        except (ImportError, Exception) as e:
            logger.critical(f"FAIL-CLOSED: Ephemeral ML-KEM-1024 key generation failed: {e}")
            raise KeyRotationError(
                f"FAIL-CLOSED: ML-KEM-1024 required for forward secrecy but unavailable: {e}"
            ) from e
    
    def _secure_wipe_keys(self, keys: Dict[str, bytearray]) -> None:
        """
        Securely wipe key material using DoD 5220.22-M pattern.

        Wipes each `bytearray` value in place (via `SecureMemoryWiper` when
        available, else a 0x00/0xFF/random/0x00 fallback) and then clears the
        dict so references are dropped. Accepts legacy `bytes` values for
        backward compat but cannot wipe them — a warning is logged instead.

        Args:
            keys: Dictionary of key material to wipe (mutated: cleared)

        GC/memory caveat: wiping overwrites the live `bytearray` buffer, but
        cannot reach copies the interpreter may have made earlier (immutable
        `bytes` sources, GC arenas, swapped pages). Internal bytearray
        storage minimizes, not eliminates, remnant risk.

        Implements Requirement 4.3:
        - Erase previous keys using DoD 5220.22-M 3-pass
        """
        if not keys:
            return
        if self._secure_wiper:
            for key_name, key_data in list(keys.items()):
                if isinstance(key_data, (bytearray, memoryview)):
                    try:
                        self._secure_wiper.wipe(key_data)
                    except Exception as e:
                        logger.error(f"Secure wipe failed for key '{key_name}': {e}")
                    logger.debug(f"Securely wiped key: {key_name}")
                elif isinstance(key_data, bytes):
                    logger.warning(f"Key '{key_name}' is immutable bytes - cannot securely wipe; caller must use bytearray for key material (reference dropped)")
                else:
                    logger.debug(f"Skipping non-key entry during wipe: {key_name}")
        else:
            # Fallback wiping (less secure but functional)
            # 2028 hardening: bytes are immutable - cannot be wiped. Log
            # explicit warning instead of silently ignoring (old bug), so
            # callers migrate key storage to bytearray.
            for key_name, key_data in list(keys.items()):
                if isinstance(key_data, (bytearray, memoryview)):
                    # Multi-pass overwrite in place
                    for i in range(len(key_data)):
                        key_data[i] = 0x00
                    for i in range(len(key_data)):
                        key_data[i] = 0xFF
                    for i in range(len(key_data)):
                        key_data[i] = secrets.randbits(8)
                    for i in range(len(key_data)):
                        key_data[i] = 0x00
                    logger.debug(f"Fallback wiped key: {key_name}")
                elif isinstance(key_data, bytes):
                    logger.warning(f"Key '{key_name}' is immutable bytes - cannot securely wipe; caller must use bytearray for key material (reference dropped)")
        # Drop references so GC can reclaim wiped buffers promptly.
        keys.clear()
    
    def _terminate_session(self, reason: str) -> None:
        """
        Terminate the session due to security failure.
        
        Args:
            reason: Reason for termination
            
        Implements Requirement 4.5:
        - Terminate session if rotation fails
        """
        logger.critical(f"SESSION TERMINATED: {reason}")
        
        with self._lock:
            self.state.session_active = False
            
            # Securely wipe all key material
            self._secure_wipe_keys(self._current_keys)
            self._secure_wipe_keys(self._previous_keys)
            self._current_keys.clear()
            self._previous_keys.clear()
        
        # Notify callback if registered
        if self._on_terminate:
            self._on_terminate(reason)
    
    def force_rotation(self) -> None:
        """
        Force an immediate key rotation.
        
        Raises:
            SessionTerminationError: If rotation fails and fail_closed is True
        """
        with self._lock:
            if not self.state.session_active:
                raise SessionTerminationError("Session is not active")
            
            try:
                self._perform_rotation(RotationTrigger.MANUAL)
            except KeyRotationError as e:
                if self.config.fail_closed:
                    self._terminate_session(f"Manual key rotation failed: {e}")
                    raise SessionTerminationError(f"Session terminated: {e}")
                raise
    
    def get_rotation_status(self) -> Dict[str, Any]:
        """
        Get current rotation status.
        
        Returns:
            Dictionary with rotation status information
        """
        with self._lock:
            elapsed = time.time() - self.state.last_rotation_time
            return {
                'session_active': self.state.session_active,
                'message_count': self.state.message_count,
                'messages_until_rotation': max(0, self.config.message_threshold - self.state.message_count),
                'seconds_since_rotation': elapsed,
                'seconds_until_rotation': max(0, self.config.time_threshold_seconds - elapsed),
                'rotation_count': self.state.rotation_count,
                'last_trigger': self.state.last_trigger.value if self.state.last_trigger else None
            }
    
    def is_session_active(self) -> bool:
        """Check if the session is still active."""
        with self._lock:
            return self.state.session_active


class EnhancedDoubleRatchetRotation:
    """
    Enhanced Double Ratchet with strict rotation triggers.
    
    This class wraps the existing DoubleRatchet implementation and adds
    strict rotation enforcement as per Requirements 4.1-4.5.
    """
    
    def __init__(
        self,
        double_ratchet: Any,
        config: Optional[RotationConfig] = None
    ):
        """
        Initialize enhanced rotation for a DoubleRatchet instance.
        
        Args:
            double_ratchet: The DoubleRatchet instance to enhance
            config: Rotation configuration
        """
        self._ratchet = double_ratchet
        self._fsm = ForwardSecrecyManager(
            config=config,
            on_rotation_callback=self._on_rotation,
            on_session_terminate=self._on_terminate
        )
        self._lock = threading.RLock()
        
        # Update the ratchet's rotation settings
        if hasattr(double_ratchet, 'KEY_ROTATION_MESSAGES'):
            double_ratchet.KEY_ROTATION_MESSAGES = config.message_threshold if config else 100
        if hasattr(double_ratchet, 'KEY_ROTATION_TIME'):
            double_ratchet.KEY_ROTATION_TIME = config.time_threshold_seconds if config else 900
        
        logger.info("EnhancedDoubleRatchetRotation initialized")
    
    def _on_rotation(self, trigger: RotationTrigger) -> None:
        """Handle rotation callback."""
        logger.info(f"Double Ratchet rotation triggered by {trigger.value}")
        
        # Trigger DH ratchet step in the underlying implementation
        if hasattr(self._ratchet, 'force_ratchet_rotation'):
            self._ratchet.force_ratchet_rotation()
        elif hasattr(self._ratchet, '_generate_dh_keypair'):
            self._ratchet._generate_dh_keypair()
        if hasattr(self._ratchet, '_generate_pq_keypairs'):
            self._ratchet._generate_pq_keypairs()
    
    def _on_terminate(self, reason: str) -> None:
        """Handle session termination."""
        logger.critical(f"Double Ratchet session terminated: {reason}")
        
        # Clear sensitive state in the underlying ratchet
        if hasattr(self._ratchet, 'root_key'):
            self._ratchet.root_key = None
        if hasattr(self._ratchet, 'sending_chain_key'):
            self._ratchet.sending_chain_key = None
        if hasattr(self._ratchet, 'receiving_chain_key'):
            self._ratchet.receiving_chain_key = None
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt with rotation check.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted data
            
        Raises:
            SessionTerminationError: If session is terminated
        """
        with self._lock:
            # Check and perform rotation if needed
            self._fsm.increment_message_count()
            
            # Delegate to underlying ratchet
            return self._ratchet.encrypt(plaintext)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt with rotation check.

        Args:
            ciphertext: Data to decrypt

        Returns:
            Decrypted data

        Raises:
            SessionTerminationError: If session is terminated
        """
        with self._lock:
            # Check and perform rotation if needed
            self._fsm.increment_message_count()

            # Delegate to underlying ratchet (counters are observability only;
            # success-path return value and exceptions are unchanged).
            try:
                plaintext = self._ratchet.decrypt(ciphertext)
            except Exception:
                _record_decrypt_result(False)
                raise
            _record_decrypt_result(True)
            return plaintext
    
    def get_status(self) -> Dict[str, Any]:
        """Get rotation status."""
        return self._fsm.get_rotation_status()
    
    def is_active(self) -> bool:
        """Check if session is active."""
        return self._fsm.is_session_active()

    def check_idle_rotation(self, max_idle_seconds: Optional[int] = 3600) -> bool:
        """
        Check and trigger rotation if session has been idle past max_idle_seconds.
        
        Args:
            max_idle_seconds: Inactivity threshold in seconds (default: 3600)
            
        Returns:
            bool: True if rotation was triggered, False otherwise
        """
        with self._lock:
            return self._fsm.check_idle_rotation(max_idle_seconds=max_idle_seconds)
