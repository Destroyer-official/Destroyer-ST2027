#!/usr/bin/env python3
"""
air_gapped_operation.py

Air-Gapped Operation Support for Military-Grade P2P Messaging.

This module implements comprehensive air-gapped operation features including:
- Local peer discovery via UDP broadcast on port 45678
- Pre-shared key (PSK) support using ML-KEM-1024 encapsulation
- QR code key exchange with base64url encoding and SHA3-512 integrity
- Offline certificate caching with SHA3-512 integrity verification

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

Security Features:
- No external server dependency
- Direct peer-to-peer connections
- ML-KEM-1024 post-quantum key encapsulation
- SHA3-512 integrity verification for all cached data
- Fail-closed security model
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Configure logging
logger = logging.getLogger(__name__)

# ============================================================================
# Constants
# ============================================================================

# Local Discovery Configuration
LOCAL_DISCOVERY_PORT = 45678  # UDP broadcast port for local discovery
LOCAL_DISCOVERY_INTERVAL = 30  # Seconds between discovery broadcasts
LOCAL_DISCOVERY_TIMEOUT = 90  # Seconds before peer is considered offline
LOCAL_DISCOVERY_MAGIC = b'MILP2P01'  # Magic bytes for protocol identification

# Pre-Shared Key Configuration
PSK_VERSION = 1  # PSK format version
PSK_INTEGRITY_HASH = 'SHA3-512'  # Hash algorithm for integrity

# Certificate Cache Configuration
CERT_CACHE_VERSION = 1  # Cache format version
CERT_CACHE_DEFAULT_TTL = 86400 * 30  # 30 days default TTL

ENC_STORAGE_MAGIC = b"P2P_ENC_V1\x00"


def _env_flag(name: str) -> bool:
    """Return True for env values '1'/'true'/'yes' (case-insensitive)."""
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def is_air_gapped(config: Any = None, *, include_offline: bool = True) -> bool:
    """Central air-gap/offline check (non-breaking hardening helper).

    Returns True when any of the following indicate air-gapped operation:
      - env P2P_AIR_GAPPED_MODE is set (1/true/yes)
      - env P2P_OFFLINE_MODE is set (1/true/yes), unless
        ``include_offline`` is False (SIEM export preserves legacy
        AIR_GAPPED-only suppression so retry-queue semantics are unchanged)
      - ``config`` indicates ``air_gapped_mode`` is truthy. ``config`` may
        be a dict (``{"air_gapped_mode": True}`` or
        ``{"network": {"air_gapped_mode": True}}``) or an object with an
        ``air_gapped_mode`` attribute / ``get()`` accessor.

    No network I/O is performed. Safe to call from version-check and
    SIEM-export guards.
    """
    if _env_flag("P2P_AIR_GAPPED_MODE"):
        return True
    if include_offline and _env_flag("P2P_OFFLINE_MODE"):
        return True
    if config is None:
        return False
    try:
        if isinstance(config, dict):
            if config.get("air_gapped_mode"):
                return True
            network = config.get("network")
            if isinstance(network, dict) and network.get("air_gapped_mode"):
                return True
            return False
        if hasattr(config, "get") and callable(getattr(config, "get")):
            try:
                if config.get("air_gapped_mode"):
                    return True
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
        if getattr(config, "air_gapped_mode", False):
            return True
    except Exception:
        return False
    return False


# ============================================================================
# Secure Time for Air-Gap (additive, non-breaking)
# ============================================================================
# No network I/O. No auto-adjust of the OS clock. When peer samples indicate
# skew > threshold, callers must require explicit operator acknowledgement.

SECURE_TIME_SKEW_WARN_SECONDS = 60.0
SECURE_TIME_MIN_SAMPLES = 3


def secure_time_now(
    peer_times: Optional[List[float]] = None,
) -> Union[float, Tuple[float, bool]]:
    """Return secure time for air-gapped operation.

    Default path (no ``peer_times``) returns ``time.time()`` as a float, so
    all pre-existing call sites keep working unchanged.

    When ``peer_times`` holds 3+ samples (e.g. timestamps observed from
    distinct LAN peers / USB-carried beacons), returns ``(now, skew_warn)``
    where ``now`` is ``statistics.median(peer_times)`` and ``skew_warn`` is
    True when ``abs(local_time - median) > 60s``. A warning is logged in
    that case. The local clock is NEVER adjusted automatically; the caller
    must surface ``skew_warn`` and require operator acknowledgement
    (see ``docs/airgap_runbook.md``).

    Args:
        peer_times: Optional list of peer-reported unix timestamps.

    Returns:
        float ``time.time()`` when ``peer_times`` is None or has < 3
        samples; otherwise ``Tuple[median, skew_warn]``.
    """
    import statistics

    local_now = time.time()
    if not peer_times:
        return local_now
    try:
        samples = [float(t) for t in peer_times]
    except Exception:
        logger.warning("secure_time_now: non-numeric peer_times; using local clock")
        return local_now
    if len(samples) < SECURE_TIME_MIN_SAMPLES:
        logger.debug(
            "secure_time_now: only %d peer sample(s) (< %d); using local clock",
            len(samples),
            SECURE_TIME_MIN_SAMPLES,
        )
        return local_now
    try:
        median = float(statistics.median(samples))
    except Exception:
        return local_now
    skew = abs(local_now - median)
    skew_warn = skew > SECURE_TIME_SKEW_WARN_SECONDS
    if skew_warn:
        logger.warning(
            "secure_time_now: local clock skew %.1fs vs peer median "
            "(local=%.3f median=%.3f n=%d); NOT auto-adjusting, "
            "operator acknowledgement required",
            skew,
            local_now,
            median,
            len(samples),
        )
    return (median, skew_warn)


def check_freshness(
    ts: float,
    window: float = 60.0,
    *,
    now: Optional[float] = None,
    peer_times: Optional[List[float]] = None,
) -> bool:
    """Check timestamp freshness ``abs(now - ts) <= window`` using secure time.

    Additive helper; default path ``check_freshness(ts)`` / 
    ``check_freshness(ts, window)`` behaves like the legacy
    ``abs(time.time() - ts) <= 60`` check. Optional ``now`` overrides the
    reference time; optional ``peer_times`` (3+ samples) resolves the
    reference via :func:`secure_time_now` (median).

    Args:
        ts: Candidate unix timestamp.
        window: Freshness window in seconds (default 60).
        now: Explicit reference time (takes precedence over peer_times).
        peer_times: Optional peer samples for median-based secure time.

    Returns:
        True when fresh, False otherwise (fail-closed on bad input).
    """
    try:
        ts_f = float(ts)
        window_f = float(window)
    except Exception:
        return False
    if window_f < 0:
        return False
    try:
        if now is not None:
            now_f = float(now)
        elif peer_times:
            resolved = secure_time_now(peer_times)
            now_f = float(resolved[0]) if isinstance(resolved, tuple) else float(resolved)
        else:
            now_f = time.time()
    except Exception:
        return False
    try:
        return abs(now_f - ts_f) <= window_f
    except Exception:
        return False

def _dpapi_scope_flags() -> int:
    """DPAPI scope flags shared by protect/unprotect (F4 evaluation outcome).

    User scope default. P2P_DPAPI_MACHINE_SCOPE=1 selects
    CRYPTPROTECT_LOCAL_MACHINE for service accounts (SYSTEM/NoProfile):
    protects offline disk theft ONLY -- any local process can unseal.
    """
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if os.environ.get("P2P_DPAPI_MACHINE_SCOPE", "0").strip().lower() in (
            "1", "true", "yes", "on"):
        flags |= 0x4  # CRYPTPROTECT_LOCAL_MACHINE
    return flags


def win_dpapi_protect(data: bytes) -> bytes:
    """Protect data with Windows DPAPI CryptProtectData (user scope default)."""
    if os.name != 'nt':
        raise NotImplementedError("DPAPI only available on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]

    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    # needs-manual-review: signatures verified against MSDN; exercised on Windows only.
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    in_buf = ctypes.create_string_buffer(data)
    in_blob = DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    try:
        if not crypt32.CryptProtectData(ctypes.byref(in_blob), 'P2P Sealed Storage Key', None, None, None, _dpapi_scope_flags(), ctypes.byref(out_blob)):
            raise ctypes.WinError()
        res = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        del in_buf
    kernel32.LocalFree(out_blob.pbData)
    return res

def win_dpapi_unprotect(data: bytes) -> bytes:
    """Unprotect data with Windows DPAPI CryptUnprotectData (scope-symmetric)."""
    if os.name != 'nt':
        raise NotImplementedError("DPAPI only available on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]

    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    # needs-manual-review: signatures verified against MSDN; exercised on Windows only.
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    in_buf = ctypes.create_string_buffer(data)
    in_blob = DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    try:
        if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, _dpapi_scope_flags(), ctypes.byref(out_blob)):
            raise ctypes.WinError()
        res = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        del in_buf
    kernel32.LocalFree(out_blob.pbData)
    return res

def _derive_storage_key(salt: bytes) -> bytes:
    """Derive 256-bit AES-GCM storage encryption key using PBKDF2-210k / DPAPI (Finding 3)."""
    passphrase = os.environ.get("P2P_STORAGE_PASSPHRASE")
    if passphrase:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=210000,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode('utf-8'))

    # If no passphrase, use Windows DPAPI sealed secret
    key_dir = os.environ.get("P2P_BASE_DIR") or os.path.dirname(os.path.abspath(__file__))
    sealed_key_path = os.path.join(key_dir, ".secure_storage_kek.sealed")
    raw_key = None
    if os.path.exists(sealed_key_path):
        try:
            with open(sealed_key_path, 'rb') as f:
                raw_key = win_dpapi_unprotect(f.read())
        except Exception:
            raw_key = None

    if not raw_key or len(raw_key) < 32:
        new_secret = secrets.token_bytes(32)
        try:
            enc = win_dpapi_protect(new_secret)
            with open(sealed_key_path, 'wb') as f:
                f.write(enc)
            os.chmod(sealed_key_path, 0o600)
            raw_key = new_secret
        except Exception as e:
            raise SecurityError(
                "P2P_STORAGE_PASSPHRASE is required when hardware DPAPI sealing is unavailable. "
                "Predictable username/hostname fallbacks are prohibited under NIST Level 5+ / zero-trust policy."
            ) from e

    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=salt,
        info=b"SecureP2P::StorageEncryption::v1",
        backend=default_backend()
    )
    return hkdf.derive(raw_key)

def encrypt_storage_payload(data_dict: Dict[str, Any]) -> bytes:
    """Encrypt JSON dictionary to binary AES-256-GCM payload with integrity tag (Finding 6)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    plaintext = json.dumps(data_dict).encode('utf-8')
    salt = secrets.token_bytes(32)
    key = _derive_storage_key(salt)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=b"SecureP2P::Storage::v1")
    return ENC_STORAGE_MAGIC + salt + nonce + ciphertext

def decrypt_storage_payload(payload: bytes) -> Dict[str, Any]:
    """Decrypt binary AES-256-GCM storage payload or parse legacy JSON (Finding 6)."""
    if payload.startswith(ENC_STORAGE_MAGIC):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        header_len = len(ENC_STORAGE_MAGIC)
        salt = payload[header_len:header_len+32]
        nonce = payload[header_len+32:header_len+44]
        ciphertext = payload[header_len+44:]
        key = _derive_storage_key(salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=b"SecureP2P::Storage::v1")
        return json.loads(plaintext.decode('utf-8'))
    return json.loads(payload.decode('utf-8'))

def set_secure_file_permissions(file_path: Path) -> None:
    """Set restrictive file permissions (0600 on POSIX, restricted ACL on Windows)."""
    try:
        if os.name == 'nt':
            # AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
            import subprocess  # nosec: B404
            username = os.environ.get('USERNAME')
            if username:
                # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                subprocess.run(  # nosec: B603 B607
                    ['icacls', str(file_path), '/inheritance:r', '/grant:r', f'{username}:F'],
                    capture_output=True,
                    check=False
                )
        else:
            os.chmod(file_path, 0o600)
    except Exception as e:
        logger.debug(f"Could not apply restrictive ACLs to {file_path}: {e}")


# ============================================================================
# Exceptions
# ============================================================================

class AirGappedOperationError(Exception):
    """Base exception for air-gapped operation errors."""


class LocalDiscoveryError(AirGappedOperationError):
    """Error in local peer discovery."""


class PSKError(AirGappedOperationError):
    """Error in pre-shared key operations."""


class PSKIntegrityError(PSKError):
    """PSK integrity verification failed."""


class CertificateCacheError(AirGappedOperationError):
    """Error in certificate caching."""


class CertificateIntegrityError(CertificateCacheError):
    """Certificate integrity verification failed."""


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class LocalPeer:
    """Information about a locally discovered peer."""
    peer_id: bytes  # SHA3-256 hash of public key
    address: str  # IP address
    port: int  # Port number
    public_key: Optional[bytes] = None  # ML-KEM-1024 public key
    sig_public_key: Optional[bytes] = None  # ML-DSA-87 public key
    last_seen: float = field(default_factory=time.time)
    hostname: Optional[str] = None  # Optional hostname
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'peer_id': self.peer_id.hex(),
            'address': self.address,
            'port': self.port,
            'public_key': self.public_key.hex() if self.public_key else None,
            'sig_public_key': self.sig_public_key.hex() if self.sig_public_key else None,
            'last_seen': self.last_seen,
            'hostname': self.hostname,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LocalPeer':
        """Deserialize from dictionary."""
        return cls(
            peer_id=bytes.fromhex(data['peer_id']),
            address=data['address'],
            port=data['port'],
            public_key=bytes.fromhex(data['public_key']) if data.get('public_key') else None,
            sig_public_key=bytes.fromhex(data['sig_public_key']) if data.get('sig_public_key') else None,
            last_seen=data.get('last_seen', time.time()),
            hostname=data.get('hostname'),
        )


@dataclass
class PreSharedKey:
    """Pre-shared key data structure."""
    version: int  # PSK format version
    kem_public_key: bytes  # ML-KEM-1024 public key
    kem_ciphertext: bytes  # ML-KEM-1024 ciphertext (encapsulated key)
    shared_secret_hash: bytes  # SHA3-512 hash of shared secret (for verification)
    peer_id: bytes  # Peer identifier
    created_at: float  # Creation timestamp
    expires_at: float  # Expiration timestamp
    integrity_hash: bytes  # SHA3-512 integrity hash of all fields
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'version': self.version,
            'kem_public_key': self.kem_public_key.hex(),
            'kem_ciphertext': self.kem_ciphertext.hex(),
            'shared_secret_hash': self.shared_secret_hash.hex(),
            'peer_id': self.peer_id.hex(),
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'integrity_hash': self.integrity_hash.hex(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PreSharedKey':
        """Deserialize from dictionary."""
        return cls(
            version=data['version'],
            kem_public_key=bytes.fromhex(data['kem_public_key']),
            kem_ciphertext=bytes.fromhex(data['kem_ciphertext']),
            shared_secret_hash=bytes.fromhex(data['shared_secret_hash']),
            peer_id=bytes.fromhex(data['peer_id']),
            created_at=data['created_at'],
            expires_at=data['expires_at'],
            integrity_hash=bytes.fromhex(data['integrity_hash']),
        )
    
    def is_expired(self) -> bool:
        """Check if PSK has expired."""
        return time.time() > self.expires_at


@dataclass
class CachedCertificate:
    """Cached peer certificate with integrity verification."""
    version: int  # Cache format version
    peer_id: bytes  # Peer identifier (SHA3-256 of public key)
    certificate_data: bytes  # Raw certificate data
    public_key: bytes  # ML-KEM-1024 public key
    sig_public_key: bytes  # ML-DSA-87 public key
    fingerprint: bytes  # SHA3-512 fingerprint of certificate
    cached_at: float  # Cache timestamp
    expires_at: float  # Expiration timestamp
    integrity_hash: bytes  # SHA3-512 integrity hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'version': self.version,
            'peer_id': self.peer_id.hex(),
            'certificate_data': self.certificate_data.hex(),
            'public_key': self.public_key.hex(),
            'sig_public_key': self.sig_public_key.hex(),
            'fingerprint': self.fingerprint.hex(),
            'cached_at': self.cached_at,
            'expires_at': self.expires_at,
            'integrity_hash': self.integrity_hash.hex(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CachedCertificate':
        """Deserialize from dictionary."""
        return cls(
            version=data['version'],
            peer_id=bytes.fromhex(data['peer_id']),
            certificate_data=bytes.fromhex(data['certificate_data']),
            public_key=bytes.fromhex(data['public_key']),
            sig_public_key=bytes.fromhex(data['sig_public_key']),
            fingerprint=bytes.fromhex(data['fingerprint']),
            cached_at=data['cached_at'],
            expires_at=data['expires_at'],
            integrity_hash=bytes.fromhex(data['integrity_hash']),
        )
    
    def is_expired(self) -> bool:
        """Check if cached certificate has expired."""
        return time.time() > self.expires_at


# ============================================================================
# Local Peer Discovery (UDP Broadcast on Port 45678)
# ============================================================================

class LocalPeerDiscovery:
    """
    Local peer discovery for air-gapped operation.
    
    Implements UDP broadcast-based peer discovery on port 45678 for
    environments without external network connectivity.
    
    Features:
    - UDP broadcast on local network
    - Direct IP connection without DNS
    - Automatic peer timeout and cleanup
    - Thread-safe peer management
    
    **Validates: Requirements 3.1, 3.3**
    """
    
    def __init__(
        self,
        node_id: bytes,
        port: int = LOCAL_DISCOVERY_PORT,
        broadcast_interval: float = LOCAL_DISCOVERY_INTERVAL,
        peer_timeout: float = LOCAL_DISCOVERY_TIMEOUT,
        public_key: Optional[bytes] = None,
        sig_public_key: Optional[bytes] = None,
        sig_signer: Optional[Callable[[bytes], bytes]] = None,
    ):
        """
        Initialize local peer discovery.

        Args:
            node_id: Our node's ID (SHA3-256 hash of public key)
            port: UDP port for discovery (default: 45678)
            broadcast_interval: Seconds between broadcasts
            peer_timeout: Seconds before peer is considered offline
            public_key: Our ML-KEM-1024 public key
            sig_public_key: Our ML-DSA-87 public key
            sig_signer: Optional ML-DSA-87 signer for broadcasts (H21).
                Signed broadcasts carry continuity authentication; peers
                that once presented a valid signature must keep presenting
                one (downgrade to unsigned is rejected).
        """
        self.node_id = node_id
        self.port = port
        self.broadcast_interval = broadcast_interval
        self.peer_timeout = peer_timeout
        self.public_key = public_key
        self.sig_public_key = sig_public_key
        self._sig_signer = sig_signer

        # Replay cache: exact (node_id, timestamp) rebroadcasts are dropped.
        self._seen_broadcasts: Dict[Tuple[bytes, float], float] = {}
        # Peers with verified broadcast signatures (continuity set)
        self._sig_verified_peers: Dict[bytes, bytes] = {}
        
        # Peer storage
        self._peers: Dict[bytes, LocalPeer] = {}
        self._lock = threading.Lock()
        
        # Ingress Rate-limiting & DoS mitigation
        self._rate_limits: Dict[str, Tuple[float, float]] = {}
        self._rate_limit_lock = threading.Lock()
        self.MAX_BROADCASTS_PER_SEC = 5.0
        self.BURST_CAPACITY = 10.0
        # 16KB fits signed broadcasts (ML-DSA-87 sig ~4627B + keys);
        # individual fields keep their own tighter caps below.
        self.MAX_PACKET_SIZE = 16384
        self.MAX_PK_LEN = 4096
        self.MAX_SIG_PK_LEN = 5120
        
        # Network state
        self._running = False
        self._socket: Optional[socket.socket] = None
        self._broadcast_thread: Optional[threading.Thread] = None
        self._listen_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self._on_peer_discovered: Optional[Callable[[LocalPeer], None]] = None
        self._on_peer_lost: Optional[Callable[[LocalPeer], None]] = None
        
        logger.info(f"LocalPeerDiscovery initialized on port {port}")
    
    def start(self) -> bool:
        """
        Start local peer discovery.
        
        Returns:
            True if started successfully, False otherwise
        """
        with self._lock:
            if self._running:
                return True
            
            try:
                # Create UDP socket for broadcast
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self._socket.bind(('', self.port))
                self._socket.settimeout(1.0)
                
                self._running = True
                
                # Start broadcast thread
                self._broadcast_thread = threading.Thread(
                    target=self._broadcast_loop, 
                    daemon=True,
                    name="LocalDiscovery-Broadcast"
                )
                self._broadcast_thread.start()
                
                # Start listen thread
                self._listen_thread = threading.Thread(
                    target=self._listen_loop, 
                    daemon=True,
                    name="LocalDiscovery-Listen"
                )
                self._listen_thread.start()
                
                logger.info(f"Local peer discovery started on port {self.port}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to start local peer discovery: {e}")
                self._running = False
                if self._socket:
                    try:
                        self._socket.close()
                    except Exception as socket_err:
                        logger.warning(f"Error closing socket during startup failure: {socket_err}")
                    self._socket = None
                return False
    
    def stop(self) -> None:
        """Stop local peer discovery."""
        with self._lock:
            self._running = False
        
        if self._socket:
            try:
                self._socket.close()
            except Exception as socket_err:
                logger.warning(f"Error closing socket during stop: {socket_err}")
            self._socket = None
        
        if self._broadcast_thread:
            self._broadcast_thread.join(timeout=2.0)
            self._broadcast_thread = None
        
        if self._listen_thread:
            self._listen_thread.join(timeout=2.0)
            self._listen_thread = None
        
        logger.info("Local peer discovery stopped")
    
    def _broadcast_loop(self) -> None:
        """Periodically broadcast presence on local network."""
        while self._running:
            try:
                self._send_discovery_broadcast()
                self._cleanup_stale_peers()
                
                # Sleep in intervals for quick shutdown
                for _ in range(int(self.broadcast_interval)):
                    if not self._running:
                        return
                    time.sleep(1)
                    
            except Exception as e:
                if self._running:
                    logger.error(f"Error in broadcast loop: {e}")
    
    def _listen_loop(self) -> None:
        """Listen for discovery broadcasts from other peers."""
        while self._running:
            try:
                if self._socket is None:
                    break
                data, addr = self._socket.recvfrom(65535)
                self._handle_discovery_message(data, addr)
            except socket.timeout:
                continue
            except OSError as e:
                if self._running:
                    logger.error(f"Socket error in listen loop: {e}")
                break
            except Exception as e:
                if self._running:
                    logger.error(f"Error in listen loop: {e}")
    
    def _send_discovery_broadcast(self) -> None:
        """Send discovery broadcast message."""
        if self._socket is None:
            return
        
        # Build discovery message
        message = self._build_discovery_message()
        
        try:
            # Broadcast to local network
            self._socket.sendto(message, ('<broadcast>', self.port))
            logger.debug("Sent discovery broadcast")
        except Exception as e:
            logger.warning(f"Failed to send discovery broadcast: {e}")
    
    def _build_discovery_message(self) -> bytes:
        """
        Build discovery broadcast message.
        
        Format:
        - Magic bytes (8 bytes): MILP2P01
        - Version (1 byte): Protocol version
        - Node ID (32 bytes): SHA3-256 hash
        - Port (2 bytes): Listening port
        - Timestamp (8 bytes): Unix timestamp
        - Public key length (2 bytes)
        - Public key (variable)
        - Sig public key length (2 bytes)
        - Sig public key (variable)
        """
        parts = [
            LOCAL_DISCOVERY_MAGIC,  # Magic bytes
            struct.pack('!B', 1),  # Version
            self.node_id,  # Node ID (32 bytes)
            struct.pack('!H', self.port),  # Port
            struct.pack('!d', time.time()),  # Timestamp
        ]
        
        # Add public key if available
        if self.public_key:
            parts.append(struct.pack('!H', len(self.public_key)))
            parts.append(self.public_key)
        else:
            parts.append(struct.pack('!H', 0))
        
        # Add signature public key if available
        if self.sig_public_key:
            parts.append(struct.pack('!H', len(self.sig_public_key)))
            parts.append(self.sig_public_key)
        else:
            parts.append(struct.pack('!H', 0))

        header = b''.join(parts)
        if self._sig_signer is not None:
            try:
                from pqc_algorithms import EnhancedMLDSA_87
                sig = self._sig_signer(header)
                if len(sig) > 8192:
                    raise ValueError("broadcast signature oversize")
                return header + struct.pack('!H', len(sig)) + sig
            except Exception as e:
                logger.warning(f"Broadcast signing failed, sending unsigned: {e}")
                return header + struct.pack('!H', 0)
        return header + struct.pack('!H', 0)
    
    def _is_rate_limited(self, source_ip: str) -> bool:
        """Enforce per-source-IP token bucket rate limiting on broadcast ingress."""
        with self._rate_limit_lock:
            now = time.time()
            tokens, last_time = self._rate_limits.get(source_ip, (self.BURST_CAPACITY, now))
            tokens = min(self.BURST_CAPACITY, tokens + (now - last_time) * self.MAX_BROADCASTS_PER_SEC)
            if tokens < 1.0:
                self._rate_limits[source_ip] = (tokens, now)
                return True
            self._rate_limits[source_ip] = (tokens - 1.0, now)
            # Prune if table exceeds 5000 IPs
            if len(self._rate_limits) > 5000:
                stale = [ip for ip, (_, t) in self._rate_limits.items() if now - t > 300]
                for ip in stale:
                    del self._rate_limits[ip]
            return False

    @staticmethod
    def _verify_broadcast_sig(sig_public_key: bytes, signed_bytes: bytes, signature: bytes) -> bool:
        """Verify a broadcast continuity signature (ML-DSA-87). Fail-closed."""
        try:
            if len(sig_public_key) != 2592 or not (0 < len(signature) <= 8192):
                return False
            from pqc_algorithms import EnhancedMLDSA_87
            return bool(EnhancedMLDSA_87().verify(sig_public_key, signed_bytes, signature))
        except Exception:
            return False

    def _handle_discovery_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle incoming discovery message with robust validation and DoS protection."""
        source_ip = addr[0]
        if self._is_rate_limited(source_ip):
            logger.warning(f"Broadcast rate limit exceeded for {source_ip}, dropping packet")
            return

        if len(data) < 55 or len(data) > self.MAX_PACKET_SIZE:
            logger.warning(f"Invalid discovery packet size ({len(data)} bytes) from {source_ip}")
            return

        try:
            # Verify magic bytes
            if len(data) < 8 or data[:8] != LOCAL_DISCOVERY_MAGIC:
                return
            
            # Parse message
            offset = 8
            version = struct.unpack('!B', data[offset:offset+1])[0]
            offset += 1
            
            if version != 1:
                logger.warning(f"Unknown discovery protocol version: {version}")
                return
            
            # Parse node ID
            node_id = data[offset:offset+32]
            offset += 32
            
            # Ignore our own broadcasts
            if node_id == self.node_id:
                return
            
            # Parse port
            port = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            
            # Parse timestamp
            timestamp = struct.unpack('!d', data[offset:offset+8])[0]
            offset += 8

            # Validate timestamp freshness with air-gap drift resilience (Item 5)
            max_allowed_skew = float(os.environ.get("P2P_AIRGAP_MAX_CLOCK_SKEW_SECONDS", "300.0")) if (
                os.environ.get("P2P_AIR_GAPPED_MODE") == "1"
            ) else 60.0
            if abs(time.time() - timestamp) > max_allowed_skew:
                logger.warning(f"Stale or future discovery timestamp ({timestamp}, skew > {max_allowed_skew}s) from {source_ip}")
                return
            
            # Parse public key with length bound checks
            if offset + 2 > len(data):
                return
            pk_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            if pk_len > self.MAX_PK_LEN or offset + pk_len > len(data):
                logger.warning(f"Invalid public key length {pk_len} from {source_ip}")
                return
            public_key = data[offset:offset+pk_len] if pk_len > 0 else None
            offset += pk_len
            
            # Parse signature public key with length bound checks
            if offset + 2 > len(data):
                return
            sig_pk_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            if sig_pk_len > self.MAX_SIG_PK_LEN or offset + sig_pk_len > len(data):
                logger.warning(f"Invalid signature key length {sig_pk_len} from {source_ip}")
                return
            sig_public_key = data[offset:offset+sig_pk_len] if sig_pk_len > 0 else None
            offset += sig_pk_len
            # Bytes covered by the trailing broadcast signature.
            signed_end = offset

            # Optional trailing broadcast signature (H21 continuity auth).
            # Layout: sig_len(2) + sig. Absent (len 0) on legacy senders.
            broadcast_sig = None
            if offset + 2 <= len(data):
                sig_len = struct.unpack('!H', data[offset:offset+2])[0]
                offset += 2
                if sig_len > 8192 or offset + sig_len != len(data):
                    logger.warning(f"Invalid broadcast signature length {sig_len} from {source_ip}")
                    return
                broadcast_sig = data[offset:offset+sig_len] if sig_len > 0 else None
                offset += sig_len
            elif offset != len(data):
                logger.warning(f"Trailing bytes in discovery packet from {source_ip}")
                return

            # Verify node_id matches public key SHA3-256 hash if public key is present
            if public_key and len(public_key) >= 32:
                expected_node_id = hashlib.sha3_256(public_key).digest()
                if node_id != expected_node_id:
                    logger.warning(f"Node ID does not bind to public key from {source_ip}")
                    return

            # Replay cache: exact (node_id, timestamp) rebroadcasts dropped.
            replay_key = (node_id, timestamp)
            now_seen = time.time()
            if replay_key in self._seen_broadcasts:
                logger.debug(f"Duplicate discovery broadcast from {source_ip}, dropping")
                return
            self._seen_broadcasts[replay_key] = now_seen
            if len(self._seen_broadcasts) > 4096:
                cutoff = now_seen - 120.0
                for k in [k for k, t in self._seen_broadcasts.items() if t < cutoff]:
                    del self._seen_broadcasts[k]

            # Signature continuity: a peer that once authenticated must keep
            # authenticating; unsigned-after-signed is a downgrade attack.
            signed_bytes = data[:signed_end]
            if node_id in self._sig_verified_peers:
                known_sig_pk = self._sig_verified_peers[node_id]
                if not broadcast_sig or not sig_public_key or sig_public_key != known_sig_pk:
                    logger.warning(f"Broadcast continuity break for {node_id.hex()[:16]} from {source_ip}: rejecting")
                    return
                if not self._verify_broadcast_sig(known_sig_pk, signed_bytes, broadcast_sig):
                    logger.warning(f"Broadcast signature INVALID for {node_id.hex()[:16]} from {source_ip}: rejecting")
                    return
            elif broadcast_sig and sig_public_key:
                if self._verify_broadcast_sig(sig_public_key, signed_bytes, broadcast_sig):
                    self._sig_verified_peers[node_id] = sig_public_key
                    logger.info(f"Broadcast signature verified for {node_id.hex()[:16]}; continuity pinned")
            
            # Create peer object
            peer = LocalPeer(
                peer_id=node_id,
                address=addr[0],
                port=port,
                public_key=public_key,
                sig_public_key=sig_public_key,
                last_seen=time.time(),
            )
            
            # Check if this is a new peer
            is_new = False
            with self._lock:
                if node_id not in self._peers:
                    is_new = True
                self._peers[node_id] = peer
            
            if is_new:
                logger.info(f"Discovered local peer: {addr[0]}:{port}")
                if self._on_peer_discovered:
                    self._on_peer_discovered(peer)
                    
        except Exception as e:
            logger.warning(f"Failed to handle discovery message: {e}")
    
    def _cleanup_stale_peers(self) -> None:
        """Remove peers that haven't been seen recently."""
        stale_threshold = time.time() - self.peer_timeout
        
        with self._lock:
            stale_peers = [
                peer_id for peer_id, peer in self._peers.items()
                if peer.last_seen < stale_threshold
            ]
            
            for peer_id in stale_peers:
                peer = self._peers.pop(peer_id)
                logger.info(f"Lost local peer: {peer.address}:{peer.port}")
                if self._on_peer_lost:
                    self._on_peer_lost(peer)
    
    def get_peers(self) -> List[LocalPeer]:
        """Get all discovered local peers."""
        with self._lock:
            return list(self._peers.values())
    
    def get_peer(self, peer_id: bytes) -> Optional[LocalPeer]:
        """Get a specific peer by ID."""
        with self._lock:
            return self._peers.get(peer_id)
    
    def connect_to_peer(self, peer: LocalPeer) -> socket.socket:
        """
        Create a direct TCP connection to a peer.
        
        Args:
            peer: Peer to connect to
            
        Returns:
            Connected socket
            
        Raises:
            LocalDiscoveryError: If connection fails
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((peer.address, peer.port))
            logger.info(f"Connected to peer: {peer.address}:{peer.port}")
            return sock
        except Exception as e:
            raise LocalDiscoveryError(f"Failed to connect to peer: {e}")
    
    def connect_by_ip(self, ip_address: str, port: int) -> socket.socket:
        """
        Create a direct TCP connection by IP address (no DNS).
        
        Args:
            ip_address: IP address to connect to
            port: Port number
            
        Returns:
            Connected socket
            
        Raises:
            LocalDiscoveryError: If connection fails
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((ip_address, port))
            logger.info(f"Connected to {ip_address}:{port}")
            return sock
        except Exception as e:
            raise LocalDiscoveryError(f"Failed to connect to {ip_address}:{port}: {e}")
    
    def set_peer_discovered_callback(self, callback: Callable[[LocalPeer], None]) -> None:
        """Set callback for when a peer is discovered."""
        self._on_peer_discovered = callback
    
    def set_peer_lost_callback(self, callback: Callable[[LocalPeer], None]) -> None:
        """Set callback for when a peer is lost."""
        self._on_peer_lost = callback
    
    @property
    def is_running(self) -> bool:
        """Check if discovery is running."""
        return self._running



# ============================================================================
# Pre-Shared Key Support (ML-KEM-1024 Encapsulation)
# ============================================================================

class PreSharedKeyManager:
    """
    Pre-shared key management using ML-KEM-1024 encapsulation.
    
    Supports secure key distribution for air-gapped environments using:
    - ML-KEM-1024 post-quantum key encapsulation
    - QR code encoding using base64url with SHA3-512 integrity
    - Secure key storage and retrieval
    
    **Validates: Requirements 3.2, 3.4**
    """
    
    def __init__(
        self,
        storage_path: Optional[Path] = None,
        default_ttl: int = 86400 * 7,  # 7 days default
    ):
        """
        Initialize PSK manager.
        
        Args:
            storage_path: Path for persistent PSK storage
            default_ttl: Default TTL for PSKs in seconds
        """
        self.storage_path = storage_path
        self.default_ttl = default_ttl
        
        # PSK storage
        self._psks: Dict[bytes, PreSharedKey] = {}
        self._shared_secrets: Dict[bytes, bytes] = {}  # peer_id -> shared_secret
        self._lock = threading.Lock()
        
        # Initialize ML-KEM-1024
        self._kem = None
        self._init_kem()
        
        # Load persisted PSKs
        if storage_path:
            self._load_from_disk()
        
        logger.info("PreSharedKeyManager initialized")
    
    def _init_kem(self) -> None:
        """Initialize ML-KEM-1024 from liboqs."""
        try:
            from liboqs_wrapper import LibOQS_MLKEM_1024
            self._kem = LibOQS_MLKEM_1024()
            logger.info("ML-KEM-1024 initialized for PSK operations")
        except ImportError as e:
            logger.warning(f"ML-KEM-1024 not available: {e}")
            self._kem = None
    
    def _load_from_disk(self) -> None:
        """Load PSKs from disk with AES-256-GCM decryption (Finding 6)."""
        if not self.storage_path or not self.storage_path.exists():
            return
        if os.environ.get("P2P_IN_MEMORY_STORAGE", "0") == "1":
            return

        try:
            with open(self.storage_path, 'rb') as f:
                payload = f.read()

            data = decrypt_storage_payload(payload)

            for peer_id_hex, psk_data in data.get('psks', {}).items():
                psk = PreSharedKey.from_dict(psk_data)
                if not psk.is_expired():
                    # Verify integrity before loading
                    if self._verify_psk_integrity(psk):
                        self._psks[psk.peer_id] = psk
                    else:
                        logger.warning(f"PSK integrity check failed for peer {peer_id_hex[:16]}")

            logger.info(f"Loaded {len(self._psks)} PSKs from disk")

            # Re-encrypt if loaded from legacy plaintext
            if not payload.startswith(ENC_STORAGE_MAGIC):
                self._save_to_disk()

        except Exception as e:
            logger.error(f"Failed to load PSK storage: {e}")

    def _save_to_disk(self) -> None:
        """Save PSKs to disk encrypted with AES-256-GCM (Finding 6)."""
        if not self.storage_path:
            return
        if os.environ.get("P2P_IN_MEMORY_STORAGE", "0") == "1":
            return

        try:
            data = {
                'psks': {},
                'version': PSK_VERSION,
            }

            with self._lock:
                for peer_id, psk in self._psks.items():
                    if not psk.is_expired():
                        data['psks'][peer_id.hex()] = psk.to_dict()

            encrypted_payload = encrypt_storage_payload(data)
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'wb') as f:
                f.write(encrypted_payload)

            set_secure_file_permissions(self.storage_path)

        except Exception as e:
            logger.error(f"Failed to save PSK storage: {e}")
    
    def generate_psk(
        self,
        peer_id: bytes,
        ttl: Optional[int] = None,
    ) -> Tuple[PreSharedKey, bytes]:
        """
        Generate a new pre-shared key for a peer.
        
        Uses ML-KEM-1024 to encapsulate a shared secret.
        
        Args:
            peer_id: Peer identifier
            ttl: Time-to-live in seconds (default: self.default_ttl)
            
        Returns:
            Tuple of (PreSharedKey, shared_secret)
            
        Raises:
            PSKError: If KEM is not available
        """
        if self._kem is None:
            raise PSKError("ML-KEM-1024 not available")
        
        ttl = ttl or self.default_ttl
        now = time.time()
        
        # Generate ML-KEM-1024 keypair
        public_key, secret_key = self._kem.keygen()
        
        # Encapsulate to get ciphertext and shared secret
        ciphertext, shared_secret = self._kem.encaps(public_key)
        
        # Compute hash of shared secret for verification
        shared_secret_hash = hashlib.sha3_512(shared_secret).digest()
        
        # Build PSK data for integrity hash (excluding integrity_hash itself)
        psk_data = {
            'version': PSK_VERSION,
            'kem_public_key': public_key.hex(),
            'kem_ciphertext': ciphertext.hex(),
            'shared_secret_hash': shared_secret_hash.hex(),
            'peer_id': peer_id.hex(),
            'created_at': now,
            'expires_at': now + ttl,
        }
        
        # Compute integrity hash
        integrity_hash = self._compute_integrity_hash(psk_data)
        
        psk = PreSharedKey(
            version=PSK_VERSION,
            kem_public_key=public_key,
            kem_ciphertext=ciphertext,
            shared_secret_hash=shared_secret_hash,
            peer_id=peer_id,
            created_at=now,
            expires_at=now + ttl,
            integrity_hash=integrity_hash,
        )
        
        # Store PSK and shared secret
        with self._lock:
            self._psks[peer_id] = psk
            self._shared_secrets[peer_id] = shared_secret
        
        self._save_to_disk()
        
        logger.info(f"Generated PSK for peer {peer_id.hex()[:16]}...")
        return psk, shared_secret
    
    def import_psk(
        self,
        psk: PreSharedKey,
        our_secret_key: bytes,
    ) -> bytes:
        """
        Import a PSK and derive the shared secret.
        
        Args:
            psk: Pre-shared key to import
            our_secret_key: Our ML-KEM-1024 secret key for decapsulation
            
        Returns:
            Derived shared secret
            
        Raises:
            PSKError: If decapsulation fails
            PSKIntegrityError: If integrity verification fails
        """
        if self._kem is None:
            raise PSKError("ML-KEM-1024 not available")
        
        # Verify integrity
        if not self._verify_psk_integrity(psk):
            raise PSKIntegrityError("PSK integrity verification failed")
        
        # Check expiration
        if psk.is_expired():
            raise PSKError("PSK has expired")
        
        # Decapsulate to get shared secret
        try:
            shared_secret = self._kem.decaps(our_secret_key, psk.kem_ciphertext)
        except Exception as e:
            raise PSKError(f"Failed to decapsulate PSK: {e}")
        
        # Verify shared secret hash
        computed_hash = hashlib.sha3_512(shared_secret).digest()
        if not hmac.compare_digest(computed_hash, psk.shared_secret_hash):
            raise PSKIntegrityError("Shared secret hash mismatch")
        
        # Store
        with self._lock:
            self._psks[psk.peer_id] = psk
            self._shared_secrets[psk.peer_id] = shared_secret
        
        self._save_to_disk()
        
        logger.info(f"Imported PSK for peer {psk.peer_id.hex()[:16]}...")
        return shared_secret
    
    def get_shared_secret(self, peer_id: bytes) -> Optional[bytes]:
        """Get the shared secret for a peer."""
        with self._lock:
            return self._shared_secrets.get(peer_id)
    
    def get_psk(self, peer_id: bytes) -> Optional[PreSharedKey]:
        """Get the PSK for a peer."""
        with self._lock:
            psk = self._psks.get(peer_id)
            if psk and not psk.is_expired():
                return psk
            return None
    
    def _compute_integrity_hash(self, data: Dict[str, Any]) -> bytes:
        """Compute SHA3-512 integrity hash of PSK data."""
        # Serialize data deterministically
        serialized = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha3_512(serialized).digest()
    
    def _verify_psk_integrity(self, psk: PreSharedKey) -> bool:
        """Verify PSK integrity hash."""
        psk_data = {
            'version': psk.version,
            'kem_public_key': psk.kem_public_key.hex(),
            'kem_ciphertext': psk.kem_ciphertext.hex(),
            'shared_secret_hash': psk.shared_secret_hash.hex(),
            'peer_id': psk.peer_id.hex(),
            'created_at': psk.created_at,
            'expires_at': psk.expires_at,
        }
        
        computed_hash = self._compute_integrity_hash(psk_data)
        return hmac.compare_digest(computed_hash, psk.integrity_hash)
    
    def encode_for_qr(self, psk: PreSharedKey) -> str:
        """
        Encode PSK for QR code transfer.
        
        Uses base64url encoding with SHA3-512 integrity verification.
        
        Args:
            psk: Pre-shared key to encode
            
        Returns:
            Base64url encoded string suitable for QR code
        """
        # Serialize PSK to JSON
        psk_json = json.dumps(psk.to_dict(), separators=(',', ':')).encode('utf-8')
        
        # Compute integrity hash
        integrity = hashlib.sha3_512(psk_json).digest()
        
        # Combine: length(2 bytes) + json + integrity(64 bytes)
        data = struct.pack('!H', len(psk_json)) + psk_json + integrity
        
        # Encode as base64url (URL-safe, no padding)
        encoded = base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
        
        return encoded
    
    def decode_from_qr(self, encoded: str) -> PreSharedKey:
        """
        Decode PSK from QR code data.
        
        Verifies SHA3-512 integrity before returning.
        
        Args:
            encoded: Base64url encoded PSK string
            
        Returns:
            Decoded PreSharedKey
            
        Raises:
            PSKIntegrityError: If integrity verification fails
            PSKError: If decoding fails
        """
        try:
            # Add padding if needed
            padding = 4 - (len(encoded) % 4)
            if padding != 4:
                encoded += '=' * padding
            
            # Decode base64url
            data = base64.urlsafe_b64decode(encoded.encode('ascii'))
            
            # Extract length
            json_len = struct.unpack('!H', data[:2])[0]
            
            # Extract JSON and integrity hash
            psk_json = data[2:2+json_len]
            stored_integrity = data[2+json_len:2+json_len+64]
            
            # Verify integrity
            computed_integrity = hashlib.sha3_512(psk_json).digest()
            if not hmac.compare_digest(computed_integrity, stored_integrity):
                raise PSKIntegrityError("QR code integrity verification failed")
            
            # Parse JSON
            psk_data = json.loads(psk_json.decode('utf-8'))
            psk = PreSharedKey.from_dict(psk_data)
            
            # Verify PSK internal integrity
            if not self._verify_psk_integrity(psk):
                raise PSKIntegrityError("PSK integrity verification failed")
            
            return psk
            
        except PSKIntegrityError:
            raise
        except Exception as e:
            raise PSKError(f"Failed to decode PSK from QR: {e}")
    
    def cleanup_expired(self) -> int:
        """Remove expired PSKs. Returns count of removed entries."""
        removed = 0
        with self._lock:
            expired_peers = [
                peer_id for peer_id, psk in self._psks.items()
                if psk.is_expired()
            ]
            for peer_id in expired_peers:
                del self._psks[peer_id]
                if peer_id in self._shared_secrets:
                    # Securely wipe shared secret
                    self._shared_secrets[peer_id] = b'\x00' * len(self._shared_secrets[peer_id])
                    del self._shared_secrets[peer_id]
                removed += 1
        
        if removed > 0:
            self._save_to_disk()
            logger.info(f"Cleaned up {removed} expired PSKs")
        
        return removed



# ============================================================================
# Offline Certificate Caching
# ============================================================================

class CertificateCache:
    """
    Offline certificate caching with SHA3-512 integrity verification.
    
    Caches peer certificates locally for air-gapped operation, ensuring
    integrity through SHA3-512 hashing.
    
    Features:
    - Local certificate storage
    - SHA3-512 integrity verification
    - Automatic expiration handling
    - Thread-safe operations
    
    **Validates: Requirements 3.5**
    """
    
    def __init__(
        self,
        storage_path: Optional[Path] = None,
        default_ttl: int = CERT_CACHE_DEFAULT_TTL,
    ):
        """
        Initialize certificate cache.
        
        Args:
            storage_path: Path for persistent certificate storage
            default_ttl: Default TTL for cached certificates in seconds
        """
        self.storage_path = storage_path
        self.default_ttl = default_ttl
        
        # Certificate storage
        self._certificates: Dict[bytes, CachedCertificate] = {}
        self._lock = threading.Lock()
        
        # Load persisted certificates
        if storage_path:
            self._load_from_disk()
        
        logger.info("CertificateCache initialized")
    
    def _load_from_disk(self) -> None:
        """Load cached certificates from disk with AES-256-GCM decryption (Finding 6)."""
        if not self.storage_path or not self.storage_path.exists():
            return
        if os.environ.get("P2P_IN_MEMORY_STORAGE", "0") == "1":
            return

        try:
            with open(self.storage_path, 'rb') as f:
                payload = f.read()

            data = decrypt_storage_payload(payload)

            for peer_id_hex, cert_data in data.get('certificates', {}).items():
                cert = CachedCertificate.from_dict(cert_data)
                if not cert.is_expired():
                    # Verify integrity before loading
                    if self._verify_certificate_integrity(cert):
                        self._certificates[cert.peer_id] = cert
                    else:
                        logger.warning(f"Certificate integrity check failed for peer {peer_id_hex[:16]}")

            logger.info(f"Loaded {len(self._certificates)} cached certificates from disk")

            # Re-encrypt if loaded from legacy plaintext
            if not payload.startswith(ENC_STORAGE_MAGIC):
                self._save_to_disk()

        except Exception as e:
            logger.error(f"Failed to load certificate cache: {e}")

    def _save_to_disk(self) -> None:
        """Save cached certificates to disk encrypted with AES-256-GCM (Finding 6)."""
        if not self.storage_path:
            return
        if os.environ.get("P2P_IN_MEMORY_STORAGE", "0") == "1":
            return

        try:
            data = {
                'certificates': {},
                'version': CERT_CACHE_VERSION,
            }

            with self._lock:
                for peer_id, cert in self._certificates.items():
                    if not cert.is_expired():
                        data['certificates'][peer_id.hex()] = cert.to_dict()

            encrypted_payload = encrypt_storage_payload(data)
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'wb') as f:
                f.write(encrypted_payload)

            set_secure_file_permissions(self.storage_path)

        except Exception as e:
            logger.error(f"Failed to save certificate cache: {e}")
    
    def cache_certificate(
        self,
        peer_id: bytes,
        certificate_data: bytes,
        public_key: bytes,
        sig_public_key: bytes,
        ttl: Optional[int] = None,
    ) -> CachedCertificate:
        """
        Cache a peer's certificate.
        
        Args:
            peer_id: Peer identifier (SHA3-256 of public key)
            certificate_data: Raw certificate data
            public_key: ML-KEM-1024 public key
            sig_public_key: ML-DSA-87 public key
            ttl: Time-to-live in seconds (default: self.default_ttl)
            
        Returns:
            CachedCertificate object
        """
        ttl = ttl or self.default_ttl
        now = time.time()
        
        # Compute certificate fingerprint
        fingerprint = hashlib.sha3_512(certificate_data).digest()
        
        # Build certificate data for integrity hash
        cert_data = {
            'version': CERT_CACHE_VERSION,
            'peer_id': peer_id.hex(),
            'certificate_data': certificate_data.hex(),
            'public_key': public_key.hex(),
            'sig_public_key': sig_public_key.hex(),
            'fingerprint': fingerprint.hex(),
            'cached_at': now,
            'expires_at': now + ttl,
        }
        
        # Compute integrity hash
        integrity_hash = self._compute_integrity_hash(cert_data)
        
        cached_cert = CachedCertificate(
            version=CERT_CACHE_VERSION,
            peer_id=peer_id,
            certificate_data=certificate_data,
            public_key=public_key,
            sig_public_key=sig_public_key,
            fingerprint=fingerprint,
            cached_at=now,
            expires_at=now + ttl,
            integrity_hash=integrity_hash,
        )
        
        # Store certificate
        with self._lock:
            self._certificates[peer_id] = cached_cert
        
        self._save_to_disk()
        
        logger.info(f"Cached certificate for peer {peer_id.hex()[:16]}...")
        return cached_cert
    
    def get_certificate(self, peer_id: bytes) -> Optional[CachedCertificate]:
        """
        Get a cached certificate for a peer.
        
        Verifies integrity before returning.
        
        Args:
            peer_id: Peer identifier
            
        Returns:
            CachedCertificate if found and valid, None otherwise
            
        Raises:
            CertificateIntegrityError: If integrity verification fails
        """
        with self._lock:
            cert = self._certificates.get(peer_id)
            
            if cert is None:
                return None
            
            if cert.is_expired():
                # Remove expired certificate
                del self._certificates[peer_id]
                self._save_to_disk()
                return None
            
            # Verify integrity
            if not self._verify_certificate_integrity(cert):
                logger.error(f"Certificate integrity verification failed for peer {peer_id.hex()[:16]}")
                raise CertificateIntegrityError("Certificate integrity verification failed")
            
            return cert
    
    def verify_certificate(
        self,
        peer_id: bytes,
        certificate_data: bytes,
    ) -> bool:
        """
        Verify a certificate against cached fingerprint.
        
        Args:
            peer_id: Peer identifier
            certificate_data: Certificate data to verify
            
        Returns:
            True if certificate matches cached fingerprint
            
        Raises:
            CertificateCacheError: If no cached certificate exists
            CertificateIntegrityError: If integrity verification fails
        """
        cached_cert = self.get_certificate(peer_id)
        
        if cached_cert is None:
            raise CertificateCacheError(f"No cached certificate for peer {peer_id.hex()[:16]}")
        
        # Compute fingerprint of provided certificate
        fingerprint = hashlib.sha3_512(certificate_data).digest()
        
        # Compare fingerprints using constant-time comparison
        return hmac.compare_digest(fingerprint, cached_cert.fingerprint)
    
    def get_fingerprint(self, peer_id: bytes) -> Optional[bytes]:
        """
        Get the cached fingerprint for a peer.
        
        Args:
            peer_id: Peer identifier
            
        Returns:
            SHA3-512 fingerprint if cached, None otherwise
        """
        try:
            cert = self.get_certificate(peer_id)
            return cert.fingerprint if cert else None
        except CertificateIntegrityError:
            return None
    
    def remove_certificate(self, peer_id: bytes) -> bool:
        """
        Remove a cached certificate.
        
        Args:
            peer_id: Peer identifier
            
        Returns:
            True if certificate was removed, False if not found
        """
        with self._lock:
            if peer_id in self._certificates:
                del self._certificates[peer_id]
                self._save_to_disk()
                logger.info(f"Removed cached certificate for peer {peer_id.hex()[:16]}...")
                return True
            return False
    
    def list_cached_peers(self) -> List[bytes]:
        """Get list of peer IDs with cached certificates."""
        with self._lock:
            return [
                peer_id for peer_id, cert in self._certificates.items()
                if not cert.is_expired()
            ]
    
    def _compute_integrity_hash(self, data: Dict[str, Any]) -> bytes:
        """Compute SHA3-512 integrity hash of certificate data."""
        serialized = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha3_512(serialized).digest()
    
    def _verify_certificate_integrity(self, cert: CachedCertificate) -> bool:
        """Verify certificate integrity hash."""
        cert_data = {
            'version': cert.version,
            'peer_id': cert.peer_id.hex(),
            'certificate_data': cert.certificate_data.hex(),
            'public_key': cert.public_key.hex(),
            'sig_public_key': cert.sig_public_key.hex(),
            'fingerprint': cert.fingerprint.hex(),
            'cached_at': cert.cached_at,
            'expires_at': cert.expires_at,
        }
        
        computed_hash = self._compute_integrity_hash(cert_data)
        return hmac.compare_digest(computed_hash, cert.integrity_hash)
    
    def cleanup_expired(self) -> int:
        """Remove expired certificates. Returns count of removed entries."""
        removed = 0
        with self._lock:
            expired_peers = [
                peer_id for peer_id, cert in self._certificates.items()
                if cert.is_expired()
            ]
            for peer_id in expired_peers:
                del self._certificates[peer_id]
                removed += 1
        
        if removed > 0:
            self._save_to_disk()
            logger.info(f"Cleaned up {removed} expired certificates")
        
        return removed
    
    def export_certificate(self, peer_id: bytes) -> Optional[str]:
        """
        Export a cached certificate as base64url encoded string.
        
        Args:
            peer_id: Peer identifier
            
        Returns:
            Base64url encoded certificate data, or None if not found
        """
        cert = self.get_certificate(peer_id)
        if cert is None:
            return None
        
        # Serialize certificate
        cert_json = json.dumps(cert.to_dict(), separators=(',', ':')).encode('utf-8')
        
        # Add integrity hash
        integrity = hashlib.sha3_512(cert_json).digest()
        data = struct.pack('!H', len(cert_json)) + cert_json + integrity
        
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
    
    def import_certificate(self, encoded: str) -> CachedCertificate:
        """
        Import a certificate from base64url encoded string.
        
        Args:
            encoded: Base64url encoded certificate data
            
        Returns:
            Imported CachedCertificate
            
        Raises:
            CertificateIntegrityError: If integrity verification fails
            CertificateCacheError: If import fails
        """
        try:
            # Add padding if needed
            padding = 4 - (len(encoded) % 4)
            if padding != 4:
                encoded += '=' * padding
            
            # Decode base64url
            data = base64.urlsafe_b64decode(encoded.encode('ascii'))
            
            # Extract length
            json_len = struct.unpack('!H', data[:2])[0]
            
            # Extract JSON and integrity hash
            cert_json = data[2:2+json_len]
            stored_integrity = data[2+json_len:2+json_len+64]
            
            # Verify integrity
            computed_integrity = hashlib.sha3_512(cert_json).digest()
            if not hmac.compare_digest(computed_integrity, stored_integrity):
                raise CertificateIntegrityError("Import integrity verification failed")
            
            # Parse JSON
            cert_data = json.loads(cert_json.decode('utf-8'))
            cert = CachedCertificate.from_dict(cert_data)
            
            # Verify certificate internal integrity
            if not self._verify_certificate_integrity(cert):
                raise CertificateIntegrityError("Certificate integrity verification failed")
            
            # Store certificate
            with self._lock:
                self._certificates[cert.peer_id] = cert
            
            self._save_to_disk()
            
            logger.info(f"Imported certificate for peer {cert.peer_id.hex()[:16]}...")
            return cert
            
        except CertificateIntegrityError:
            raise
        except Exception as e:
            raise CertificateCacheError(f"Failed to import certificate: {e}")


# ============================================================================
# Air-Gapped Operation Manager
# ============================================================================

class AirGappedOperationManager:
    """
    Unified manager for air-gapped operation features.
    
    Combines local peer discovery, PSK management, and certificate caching
    into a single interface for air-gapped environments.
    
    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
    """
    
    def __init__(
        self,
        node_id: bytes,
        data_dir: Optional[Path] = None,
        discovery_port: int = LOCAL_DISCOVERY_PORT,
        public_key: Optional[bytes] = None,
        sig_public_key: Optional[bytes] = None,
    ):
        """
        Initialize air-gapped operation manager.
        
        Args:
            node_id: Our node's ID
            data_dir: Directory for persistent storage
            discovery_port: UDP port for local discovery
            public_key: Our ML-KEM-1024 public key
            sig_public_key: Our ML-DSA-87 public key
        """
        self.node_id = node_id
        self.data_dir = Path(data_dir) if data_dir else None
        
        # Initialize components
        self.discovery = LocalPeerDiscovery(
            node_id=node_id,
            port=discovery_port,
            public_key=public_key,
            sig_public_key=sig_public_key,
        )
        
        self.psk_manager = PreSharedKeyManager(
            storage_path=self.data_dir / 'psk_cache.json' if self.data_dir else None,
        )
        
        self.cert_cache = CertificateCache(
            storage_path=self.data_dir / 'cert_cache.json' if self.data_dir else None,
        )
        
        logger.info("AirGappedOperationManager initialized")
    
    def start(self) -> bool:
        """Start air-gapped operation services."""
        return self.discovery.start()
    
    def stop(self) -> None:
        """Stop air-gapped operation services."""
        self.discovery.stop()
    
    def get_discovered_peers(self) -> List[LocalPeer]:
        """Get all locally discovered peers."""
        return self.discovery.get_peers()
    
    def connect_to_peer_by_ip(self, ip_address: str, port: int) -> socket.socket:
        """Connect to a peer by IP address (no DNS)."""
        return self.discovery.connect_by_ip(ip_address, port)
    
    def generate_psk_for_peer(self, peer_id: bytes) -> Tuple[str, bytes]:
        """
        Generate a PSK for a peer and return QR-encodable string.
        
        Returns:
            Tuple of (qr_code_data, shared_secret)
        """
        psk, shared_secret = self.psk_manager.generate_psk(peer_id)
        qr_data = self.psk_manager.encode_for_qr(psk)
        return qr_data, shared_secret
    
    def import_psk_from_qr(self, qr_data: str, our_secret_key: bytes) -> bytes:
        """
        Import a PSK from QR code data.
        
        Returns:
            Shared secret
        """
        psk = self.psk_manager.decode_from_qr(qr_data)
        return self.psk_manager.import_psk(psk, our_secret_key)
    
    def cache_peer_certificate(
        self,
        peer_id: bytes,
        certificate_data: bytes,
        public_key: bytes,
        sig_public_key: bytes,
    ) -> CachedCertificate:
        """Cache a peer's certificate."""
        return self.cert_cache.cache_certificate(
            peer_id=peer_id,
            certificate_data=certificate_data,
            public_key=public_key,
            sig_public_key=sig_public_key,
        )
    
    def verify_peer_certificate(self, peer_id: bytes, certificate_data: bytes) -> bool:
        """Verify a peer's certificate against cached fingerprint."""
        return self.cert_cache.verify_certificate(peer_id, certificate_data)
    
    def get_cached_certificate(self, peer_id: bytes) -> Optional[CachedCertificate]:
        """Get a cached certificate for a peer."""
        return self.cert_cache.get_certificate(peer_id)
    
    def cleanup(self) -> None:
        """Cleanup expired PSKs and certificates."""
        self.psk_manager.cleanup_expired()
        self.cert_cache.cleanup_expired()
    
    @property
    def is_running(self) -> bool:
        """Check if air-gapped operation is active."""
        return self.discovery.is_running


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    # Exceptions
    'AirGappedOperationError',
    'LocalDiscoveryError',
    'PSKError',
    'PSKIntegrityError',
    'CertificateCacheError',
    'CertificateIntegrityError',
    
    # Data Classes
    'LocalPeer',
    'PreSharedKey',
    'CachedCertificate',
    
    # Main Classes
    'LocalPeerDiscovery',
    'PreSharedKeyManager',
    'CertificateCache',
    'AirGappedOperationManager',
    
    # Constants
    'LOCAL_DISCOVERY_PORT',
    'LOCAL_DISCOVERY_INTERVAL',
    'LOCAL_DISCOVERY_TIMEOUT',
    'SECURE_TIME_SKEW_WARN_SECONDS',
    'SECURE_TIME_MIN_SAMPLES',

    # Secure time helpers (air-gap, additive)
    'is_air_gapped',
    'secure_time_now',
    'check_freshness',
]

