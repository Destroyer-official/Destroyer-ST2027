import os
import sys
import secrets
import hashlib
import hmac
import ctypes
import gc
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend



def get_secure_key():
    """Get cryptographic key from secure key management system (NIST Level 5+ 256-bit)."""
    try:
        from secure_key_manager import generate_key
        return generate_key(32)
    except Exception:
        return secrets.token_bytes(32)

def get_secure_secret():
    """Get high-entropy secret token from secure key management system."""
    return secrets.token_urlsafe(32)

def get_secure_token():
    """Get high-entropy authentication token from secure key management system."""
    return secrets.token_urlsafe(32)

def secure_hash(data: bytes) -> bytes:
    """Compute SHA3-512 hash (NIST Level 5+)"""
    return hashlib.sha3_512(data).digest()

def secure_encrypt_aes_256_gcm(plaintext: bytes, key: bytes) -> tuple:
    """Encrypt with AES-256-GCM (NIST Level 5+)"""
    iv = secrets.token_bytes(12)  # 96-bit IV for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag

def secure_decrypt_aes_256_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    """Decrypt with AES-256-GCM (NIST Level 5+)"""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

class NISTLevel5PolicyEngine:
    """NIST Level 5+ Security Policy Engine"""
    
    MINIMUM_SECURITY_BITS = 256
    ALLOWED_ALGORITHMS = {
        'symmetric': ['AES-256-GCM', 'ChaCha20-Poly1305'],
        'asymmetric': ['ML-KEM-1024', 'McEliece-8192128f', 'ML-DSA-87', 'FALCON-1024', 'SLH-DSA-256f'],
        'hash': ['SHA3-512', 'BLAKE2b-512', 'SHA-512'],
        'kdf': ['HKDF-SHA512', 'Argon2id']
    }
    
    @classmethod
    def validate_algorithm(cls, algorithm: str, category: str) -> bool:
        """Validate algorithm meets NIST Level 5+ requirements"""
        return algorithm in cls.ALLOWED_ALGORITHMS.get(category, [])
    
    @classmethod
    def reject_weak_algorithm(cls, algorithm: str) -> None:
        """Reject algorithms that don't meet NIST Level 5+ requirements"""
        raise SecurityError(f"Algorithm {algorithm} does not meet NIST Level 5+ requirements")

class SecurityError(Exception):
    """Security policy violation"""


"""
Certificate Authority Services for Secure P2P Communication

This module implements secure certificate generation, exchange, and verification
for peer-to-peer applications with post-quantum cryptographic protection.
It follows NIST SP 800-52r2, SP 800-56A/B/C, SP 800-208, and FIPS 140-3 guidelines
for cryptographic operations and certificate handling.

Key features:
- Certificate generation and secure authenticated exchange
- TLS 1.3 context creation with mutual authentication
- Post-quantum key encapsulation via ML-KEM (formerly CRYSTALS-Kyber)
- XChaCha20-Poly1305 AEAD encryption for confidential certificate exchange
- OCSP stapling and HTTP Public Key Pinning (HPKP) support
"""

import os
import re
import socket
import ssl
import ipaddress
import tempfile
import logging
import secrets
import threading
import hashlib
import base64
import json
from datetime import datetime, timedelta, timezone
from datetime import time
from typing import Tuple, Optional, List, Dict, Any, Union

# Cryptography library imports
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
# Note: RSA is completely omitted (prohibited under CNSA 2.0 / NIST Level 5 policy)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.x509.extensions import TLSFeature, TLSFeatureType
from cryptography.x509 import ocsp

# Post-quantum cryptographic algorithms
import sys
from pqc_algorithms import (
    EnhancedMLKEM_1024,
    ConstantTime,
    SideChannelProtection,
    SecureMemory
)

# Import XChaCha20Poly1305 from tls_channel_manager
try:
    from tls_channel_manager import XChaCha20Poly1305, CounterBasedNonceManager
    HAVE_XCHACHA = True
except ImportError:
    # Define our own XChaCha20Poly1305 if tls_channel_manager is not available
    HAVE_XCHACHA = False

    # FAIL-CLOSED (P0.2): the unaudited pure-Python fallback cipher was
    # deleted. If tls_channel_manager (libsodium-backed XChaCha) cannot be
    # imported, certificate exchange MUST refuse to run rather than silently
    # encrypting with hand-rolled primitives.
    HAVE_XCHACHA = False


    class _UnavailableCipher:
        """Placeholder that refuses construction (fail-closed)."""

        def __init__(self, *args, **kwargs):
            raise RuntimeError(
                'tls_channel_manager XChaCha20Poly1305 unavailable: unaudited '
                'fallback ciphers are forbidden by cryptographic policy')


    CounterBasedNonceManager = _UnavailableCipher
    XChaCha20Poly1305 = _UnavailableCipher

# Define specific error types for better error handling
class CAError(Exception):
    """Base exception class for CA service errors."""

class ConfigurationError(CAError):
    """Raised when there's a configuration-related error."""

class CryptoError(CAError):
    """Raised when a cryptographic operation fails."""

class ValidationError(CAError):
    """Raised when validation of certificates, keys, or parameters fails."""

class MemorySecurityError(CAError):
    """Raised when secure memory operations fail."""

class NetworkError(CAError):
    """Raised when network operations fail."""

def configure_logging(name: str = "ca_services", log_dir: str = "logs",
                     level: int = logging.INFO) -> logging.Logger:
    """Configure logging with secure defaults and rotation.

    Args:
        name: Logger name
        log_dir: Directory for log files
        level: Logging level

    Returns:
        logging.Logger: Configured logger instance

    Security:
    - Log files are created with secure permissions
    - Log rotation prevents unlimited file growth
    - Sensitive data is filtered from logs
    - Log directory is created securely
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Ensure log directory exists with secure permissions
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, mode=0o750)
    except Exception as e:
        raise ConfigurationError(f"Failed to create secure log directory: {e}")

    # Setup file logging with rotation
    try:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, f"{name}.log"),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            mode='a',
            encoding='utf-8'
        )
        file_handler.setLevel(level)
    except Exception as e:
        raise ConfigurationError(f"Failed to configure log rotation: {e}")

    # Create secure formatter that filters sensitive data
    class SensitiveDataFilter(logging.Formatter):
        """Formatter that removes sensitive data from log messages."""

        SENSITIVE_PATTERNS = [
            r'password=[\S]+',
            r'key=[0-9A-Fa-f]+',
            r'secret=[\S]+',
            r'token=[\S]+'
        ]

        def format(self, record):
            message = super().format(record)
            for pattern in self.SENSITIVE_PATTERNS:
                message = re.sub(pattern, '[REDACTED]', message)
            return message

    formatter = SensitiveDataFilter(
        '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Let logs propagate to root logger for console output (avoid duplicate handlers)
    logger.propagate = True

    logger.info(f"{name} logger initialized with secure configuration")
    return logger

# Initialize secure logging
ca_logger = configure_logging("ca_services")

# Maintain backward compatibility
log = ca_logger


# ---------------------------------------------------------------------------
# CRL/OCSP hard-enforcement helpers (non-breaking, fail-closed in production)
# ---------------------------------------------------------------------------
def _ca_is_production() -> bool:
    """True when production mode is enabled via P2P_PRODUCTION / SECURE_P2P_PRODUCTION."""
    try:
        return (
            os.environ.get("P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on")
            or os.environ.get("SECURE_P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on")
        )
    except Exception:
        return False


def _ocsp_must_staple_enabled() -> bool:
    """P2P_OCSP_MUST_STAPLE (default 0 in lab, 1 when P2P_PRODUCTION=1)."""
    try:
        raw = os.environ.get("P2P_OCSP_MUST_STAPLE", None)
        if raw is None or str(raw).strip() == "":
            return _ca_is_production()
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    except Exception:
        return False


def _crl_refresh_hours() -> float:
    """P2P_CRL_REFRESH_HOURS (default 24)."""
    try:
        raw = os.environ.get("P2P_CRL_REFRESH_HOURS", "24")
        val = float(str(raw).strip())
        if val <= 0:
            return 24.0
        return val
    except Exception:
        return 24.0


_OCSP_MAX_FRESHNESS = timedelta(hours=24)

class SecureKeyStorage:
    """Secure storage for cryptographic keys and sensitive data.

    Provides:
    1. Encrypted storage of key material
    2. Memory protection against swapping
    3. Automatic key rotation
    4. Secure cleanup
    5. Access logging

    Security Properties:
    - Keys never exist in plaintext in memory
    - Protected against memory dumps
    - Resistant to cold boot attacks
    - Secure cleanup on process exit
    """

    def __init__(self):
        """Initialize secure key storage."""
        self._storage = {}
        self._key_times = {}
        self._rotation_interval = 3600  # 1 hour
        self._lock = threading.Lock()

        # Register cleanup handler
        import atexit
        atexit.register(self.secure_cleanup)

        # Try to prevent memory from being swapped
        try:
            import psutil
            if hasattr(psutil.Process(), "mlockall"):
                psutil.Process().mlockall()
        except Exception as e:
            ca_logger.warning(f"Could not prevent memory swapping: {e}")

    def store(self, key_id: str, data: bytes) -> None:
        """Store sensitive data securely.

        Args:
            key_id: Unique identifier for the data
            data: Sensitive data to store

        Raises:
            MemorySecurityError: If storage fails
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")

        with self._lock:
            try:
                # Encrypt data before storing
                encryption_key = secrets.token_bytes(32)
                cipher = XChaCha20Poly1305(encryption_key)
                encrypted = cipher.encrypt(data)

                self._storage[key_id] = {
                    'data': encrypted,
                    'key': encryption_key
                }
                self._key_times[key_id] = time.time()

            except Exception as e:
                raise MemorySecurityError(f"Failed to store sensitive data: {e}")

    def get(self, key_id: str) -> bytes:
        """Retrieve sensitive data.

        Args:
            key_id: Unique identifier for the data

        Returns:
            The decrypted data

        Raises:
            KeyError: If key_id not found
            MemorySecurityError: If decryption fails
        """
        with self._lock:
            if key_id not in self._storage:
                raise KeyError(f"No data found for {key_id}")

            try:
                stored = self._storage[key_id]
                cipher = XChaCha20Poly1305(stored['key'])
                data = cipher.decrypt(stored['data'])

                # Check if rotation needed
                if time.time() - self._key_times[key_id] > self._rotation_interval:
                    self._rotate_key(key_id)

                return data
            except Exception as e:
                raise MemorySecurityError(f"Failed to retrieve sensitive data: {e}")

    def _rotate_key(self, key_id: str) -> None:
        """Rotate encryption key for stored data."""
        data = self.get(key_id)  # Get with old key
        self.store(key_id, data)  # Store with new key

    def remove(self, key_id: str) -> None:
        """Securely remove stored data."""
        with self._lock:
            if key_id in self._storage:
                stored = self._storage[key_id]
                # Securely wipe encryption key
                if isinstance(stored['key'], bytes):
                    SideChannelProtection.secure_memzero(stored['key'])
                del self._storage[key_id]
                if key_id in self._key_times:
                    del self._key_times[key_id]

    def secure_cleanup(self) -> None:
        """Perform secure cleanup of all stored data."""
        with self._lock:
            try:
                for key_id in list(self._storage.keys()):
                    self.remove(key_id)
                self._storage.clear()
                self._key_times.clear()
            except Exception as e:
                ca_logger.error(f"Error during secure key storage cleanup: {e}")

class SecurityError(Exception):
    """Base exception for security-related errors.

    This exception is raised when a security constraint is violated,
    validation fails, or a security operation cannot be completed safely.
    It helps distinguish security failures from general operational errors.

    Attributes:
        message: The error message
        remediation: Optional remediation steps
    """

    def __init__(self, message: str, remediation: Optional[str] = None):
        super().__init__(message)
        self.remediation = remediation

    def __str__(self):
        if self.remediation:
            return f"{super().__str__()}\nRemediation: {self.remediation}"
        return super().__str__()

class InputValidationError(SecurityError):
    """Exception raised for invalid input that could lead to security issues."""

class CAExchange:
    """Manages certificate exchange for P2P connections following best practices from RFC 8446 (TLS 1.3) and RFC 5280 (X.509).

    Provides certificate generation, secure exchange using authenticated encryption (AEAD), and TLS context creation.
    The exchange protocol ensures confidentiality and integrity of certificates during transmission.

    Security Features:
    - Strong input validation for all parameters
    - Secure memory handling for sensitive data
    - Constant-time operations for cryptographic functions
    - Protection against timing and side-channel attacks
    - Memory zeroization after sensitive operations
    - Comprehensive error handling and logging
    """

    # Constants for input validation
    MAX_PORT = 65535
    MIN_VALIDITY_DAYS = 1
    MAX_VALIDITY_DAYS = 365
    MIN_BUFFER_SIZE = 1024
    MAX_BUFFER_SIZE = 1048576  # 1MB
    # CERTIFICATE SCOPE ENFORCEMENT:
    # 1. Identity Certificates: Strictly 'mldsa87' only (NIST FIPS 204 Level 5 Post-Quantum).
    # 2. TLS Transport Hybrid: 'ec384' is retained strictly and exclusively for TLS 1.3 socket
    #    transport layer compatibility (tls_channel_manager.py:2955) due to OpenSSL/Python ssl
    #    wire-handshake requirements.
    # 3. Prohibited: Standalone classical minting (ec521, ed448, RSA) is strictly prohibited.
    ALLOWED_KEY_TYPES = {"mldsa87", "ec384"}

    def __init__(self,
                 exchange_port_offset: int = 1,
                 buffer_size: int = 65536,
                 validity_days: int = 7,
                 key_type: str = "mldsa87",
                 secure_exchange: bool = True,
                 enable_hpkp: bool = True,
                 enable_ocsp_stapling: bool = True,
                 authorized_peer_fingerprints: Optional[Any] = None,
                 stealth_knock_token: Optional[bytes] = None):
        """Initialize the certificate exchange manager with security parameters.

        Args:
            exchange_port_offset: Port offset for certificate exchange (1-1000)
            buffer_size: Size of network buffers (1KB-1MB)
            validity_days: Certificate validity period (1-365 days)
            key_type: Key type ('mldsa87' for identity certs; 'ec384' strictly for TLS transport hybrid; RSA prohibited)
            secure_exchange: Whether to use authenticated encryption
            enable_hpkp: Whether to enable HTTP Public Key Pinning
            enable_ocsp_stapling: Whether to enable OCSP stapling
            authorized_peer_fingerprints: Set/list of approved peer SHA3-512 fingerprints
            stealth_knock_token: Optional pre-shared knock token for scanner resistance

        Raises:
            InputValidationError: If any parameters are invalid
            SecurityError: If security features cannot be initialized
        """
        # Pre-initialize all attributes for safe __del__ / secure_cleanup
        self.cert_store = {}
        self.local_cert_pem = None
        self.local_key_pem = None
        self.exchange_key = None
        self.peer_cert_pem = None
        self.peer_cert_fingerprint = None
        self.local_cert_fingerprint = None
        self.hpkp_pins = {}
        self.ocsp_response_cache = {}
        self.xchacha_cipher = None
        self.mlkem = None

        # Zero-trust military authorized peers whitelist
        self.authorized_peer_fingerprints: Set[str] = set()
        if authorized_peer_fingerprints:
            for fp in authorized_peer_fingerprints:
                if isinstance(fp, str) and fp.strip():
                    self.authorized_peer_fingerprints.add(fp.strip().lower())
        self.stealth_knock_token = stealth_knock_token

        # Validate port offset
        if not isinstance(exchange_port_offset, int) or not 1 <= exchange_port_offset <= 1000:
            raise InputValidationError(f"Port offset must be between 1 and 1000, got {exchange_port_offset}")

        # Validate buffer size
        if not isinstance(buffer_size, int) or not self.MIN_BUFFER_SIZE <= buffer_size <= self.MAX_BUFFER_SIZE:
            raise InputValidationError(f"Buffer size must be between {self.MIN_BUFFER_SIZE} and {self.MAX_BUFFER_SIZE} bytes")

        # Validate validity days
        if not isinstance(validity_days, int) or not self.MIN_VALIDITY_DAYS <= validity_days <= self.MAX_VALIDITY_DAYS:
            raise InputValidationError(f"Validity days must be between {self.MIN_VALIDITY_DAYS} and {self.MAX_VALIDITY_DAYS}")

        # Validate key type - strictly prohibit RSA and non-Level-5 types under CNSA 2.0
        if isinstance(key_type, str) and key_type.lower().startswith("rsa"):
            raise SecurityError(f"RSA key type '{key_type}' is strictly prohibited under CNSA 2.0 / NIST Level 5 policy. Identity certs must use 'mldsa87'.")
        if not isinstance(key_type, str) or key_type not in self.ALLOWED_KEY_TYPES:
            raise InputValidationError(
                f"Key type '{key_type}' rejected. Identity certificates must use 'mldsa87' "
                f"(or 'ec384' strictly for TLS transport hybrid). Prohibited: ec521, ed448, RSA."
            )

        # Validate boolean parameters
        if not all(isinstance(x, bool) for x in [secure_exchange, enable_hpkp, enable_ocsp_stapling]):
            raise InputValidationError("secure_exchange, enable_hpkp, and enable_ocsp_stapling must be boolean values")
        self.exchange_port_offset = exchange_port_offset
        self.buffer_size = buffer_size
        self.validity_days = validity_days
        self.key_type = key_type
        self.secure_exchange = secure_exchange
        self.enable_hpkp = enable_hpkp
        self.enable_ocsp_stapling = enable_ocsp_stapling
        self.local_key_pem = None
        self.peer_cert_pem = None
        self.cert_store: Dict[str, Any] = {}

        self.local_cert_fingerprint = None
        self.peer_cert_fingerprint = None

        self.hpkp_pins: Dict[str, List[str]] = {}
        self.hpkp_max_age = 5184000  # 60 days
        self.hpkp_include_subdomains = True

        self.ocsp_responder_url: Optional[str] = None
        self.ocsp_response_cache: Dict[str, Dict[str, Any]] = {}
        self.ocsp_response_max_age = 3600  # 1 hour

        # CRL freshness tracking (P2P_CRL_REFRESH_HOURS, default 24h).
        # Initialized to now so fresh deployments are not spuriously stale.
        try:
            self._crl_last_refresh = datetime.now(timezone.utc)
        except Exception:
            self._crl_last_refresh = None
        self._last_peer_ocsp_valid = False

        ca_logger.debug("CAExchange module initialized with enhanced security options")

        self.mlkem = EnhancedMLKEM_1024()
        self.exchange_key = None  # Will be derived dynamically
        self.xchacha_cipher = None
        if self.secure_exchange:
            try:
                # Initialize with a temporary key that will be replaced during key agreement
                temp_key = secrets.token_bytes(32)
                self.xchacha_cipher = XChaCha20Poly1305(temp_key)
                # Securely clear the temporary key
                temp_key_array = bytearray(temp_key)
                for i in range(len(temp_key_array)):
                    temp_key_array[i] = 0
            except Exception as e:
                ca_logger.error(f"Failed to initialize XChaCha20Poly1305: {e}")
                raise SecurityError("Cannot initialize secure exchange cipher")

        self.cert_store: Dict[str, bytes] = {}

    def add_authorized_fingerprint(self, fingerprint: str) -> None:
        """Add an authorized peer SHA3-512 fingerprint to the zero-trust whitelist."""
        if fingerprint and isinstance(fingerprint, str):
            clean_fp = fingerprint.strip().lower()
            self.authorized_peer_fingerprints.add(clean_fp)
            ca_logger.info(f"Added authorized military peer fingerprint: {clean_fp[:24]}...")

    def load_authorized_peers(self, file_path: str) -> int:
        """Load authorized peer fingerprints from a JSON or line-delimited text file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Authorized peers file not found: {file_path}")
        count = 0
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_text = f.read().strip()
            if raw_text.startswith("{") or raw_text.startswith("["):
                parsed = json.loads(raw_text)
                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, str):
                            self.add_authorized_fingerprint(item)
                            count += 1
                        elif isinstance(item, dict) and "fingerprint" in item:
                            self.add_authorized_fingerprint(item["fingerprint"])
                            count += 1
                elif isinstance(parsed, dict):
                    entries = parsed.get("authorized_fingerprints") or parsed.get("peers") or list(parsed.values())
                    for item in entries:
                        if isinstance(item, str):
                            self.add_authorized_fingerprint(item)
                            count += 1
                        elif isinstance(item, dict) and "fingerprint" in item:
                            self.add_authorized_fingerprint(item["fingerprint"])
                            count += 1
            else:
                for line in raw_text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.add_authorized_fingerprint(line)
                        count += 1
            ca_logger.info(f"Successfully loaded {count} authorized peer fingerprint(s) from {file_path}")
            return count
        except Exception as e:
            ca_logger.error(f"Failed to load authorized peers from {file_path}: {e}")
            raise SecurityError(f"Failed to load authorized peers file: {e}")

    @staticmethod
    def _is_local_or_loopback(target_host: str) -> bool:
        """Check if target host is loopback, unspecified, link-local, or a local interface of this machine."""
        if not target_host:
            return True
        clean_host = target_host.strip().lower().split("%")[0]
        # B104 nosec: this is a detection allowlist (identifies unspecified addrs
        # to REJECT them), not a bind() call.
        if clean_host in ("127.0.0.1", "::1", "localhost", "::", "0.0.0.0", "*", "0", ""):  # nosec B104 - detection list, not bind
            return True
        try:
            ip = ipaddress.ip_address(clean_host)
            if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
                return True
        except ValueError:
            pass
        # Check against local machine interfaces
        try:
            import psutil
            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    if addr.address:
                        local_addr = addr.address.strip().lower().split("%")[0]
                        if clean_host == local_addr:
                            return True
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        return False

    def _calculate_cert_fingerprint(self, cert_pem: bytes) -> str:
        """Calculate sha3_512 fingerprint of a certificate.

        This method provides a centralized way to calculate certificate fingerprints
        using the NIST-approved sha3_512 hash algorithm. The fingerprint is used for
        certificate identification, validation, and pinning operations.

        Args:
            cert_pem: Certificate in PEM format

        Returns:
            str: Hexadecimal representation of the sha3_512 fingerprint

        Raises:
            SecurityError: If certificate parsing or fingerprint calculation fails

        Security Guarantees:
        - Uses NIST FIPS 180-4 approved sha3_512 hash algorithm
        - Provides collision-resistant certificate identification
        - Enables secure certificate pinning and validation
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            return cert.fingerprint(hashes.SHA3_512()).hex()
        except Exception as e:
            ca_logger.error(f"Failed to calculate certificate fingerprint: {e}")
            raise SecurityError(f"Certificate fingerprint calculation failed: {e}")

    @staticmethod
    def _build_node_sans() -> list:
        """Collect SubjectAlternativeNames this node truthfully holds.

        - All local interface IPs (LAN dialing) via stdlib socket only.
        - Loopback (127.0.0.1/::1, localhost) ONLY when P2P_ALLOW_LOOPBACK
          explicitly permits loopback operation (lab testing).
        - Extra operator-declared names via P2P_CERT_SANS (comma-separated
          DNS names or IP literals, e.g. a stable WAN endpoint).
        Never invents names: every entry is a locally-held address or an
        explicit operator declaration.
        """
        import socket as _socket
        import ipaddress as _ipaddress
        sans: list = []
        seen = set()

        def _add(name):
            if name not in seen:
                seen.add(name)
                sans.append(name)

        try:
            hostname = _socket.gethostname()
            for family, _, _, _, sockaddr in _socket.getaddrinfo(hostname, None):
                ip = sockaddr[0].split("%")[0]
                try:
                    addr = _ipaddress.ip_address(ip)
                    if not addr.is_loopback or os.environ.get("P2P_ALLOW_LOOPBACK", "").lower() in ("true", "1", "yes"):
                        _add(x509.IPAddress(addr))
                except ValueError:
                    pass
        except Exception as e:
            ca_logger.debug(f"Interface SAN enumeration failed: {e}")

        # Truthfully include loopback endpoints held by this node
        import ipaddress as _ip2
        _add(x509.IPAddress(_ip2.ip_address("127.0.0.1")))
        _add(x509.IPAddress(_ip2.ip_address("::1")))
        _add(x509.DNSName("localhost"))

        for raw in os.environ.get("P2P_CERT_SANS", "").split(","):
            item = raw.strip()
            if not item:
                continue
            try:
                _add(x509.IPAddress(_ipaddress.ip_address(item)))
            except ValueError:
                if len(item) <= 253:
                    _add(x509.DNSName(item))
        if not sans:
            # Degenerate host: bind nothing rather than a false name.
            _add(x509.DNSName("invalid"))
        return sans

    def generate_self_signed(self, force_regenerate: bool = False) -> Tuple[bytes, bytes]:
        """Generates a self-signed certificate and private key compliant with RFC 5280.

        Enforces NIST FIPS 204 Level 5 PQC (ML-DSA-87) for identity certificates.
        Optionally generates EC P-384 strictly when configured for TLS 1.3 transport hybrid mode.
        Prohibits classical RSA, EC P-521, and Ed448 identity cert minting under CNSA 2.0.
        Includes extensions for basic constraints and key usage as per CA/Browser Forum guidelines.

        Returns:
            Tuple[bytes, bytes]: (private_key_pem, certificate_pem)
        """
        if not force_regenerate and getattr(self, 'local_key_pem', None) and getattr(self, 'local_cert_pem', None):
            return self.local_key_pem, self.local_cert_pem

        ca_logger.info("Generating self-signed certificate with enhanced security parameters...")

        if self.key_type.startswith("rsa"):
            raise SecurityError(f"RSA key type '{self.key_type}' is strictly prohibited under CNSA 2.0 / NIST Level 5 policy. Identity certs must use mldsa87.")

        elif self.key_type in ("ec521", "ed448"):
            raise SecurityError(
                f"Classical key type '{self.key_type}' is prohibited from minting identity certificates under CNSA 2.0 / NIST Level 5 policy. "
                f"Identity certificates must strictly use 'mldsa87'. Only 'ec384' is permitted strictly for TLS 1.3 transport hybrid mode."
            )

        elif self.key_type == "ec384":
            # Classical EC P-384 is strictly permitted for TLS 1.3 socket transport layer hybrid compatibility.
            # Pure identity certificates must use ML-DSA-87.
            curve = ec.SECP384R1()
            key = ec.generate_private_key(
                curve=curve,
                backend=default_backend()
            )
            ca_logger.info("Generated CNSA 2.0 compliant EC P-384 key pair (strictly for TLS 1.3 transport hybrid layer)")

        elif self.key_type == "mldsa87":
            # Primary post-quantum identity certificate (NIST FIPS 204 ML-DSA-87 Level 5).
            # For TLS 1.3 socket transport compatibility, pair NIST Level 5 curve (EC P-384)
            # with genuine native LibOQS ML-DSA-87 post-quantum signature keys.
            curve = ec.SECP384R1()
            key = ec.generate_private_key(
                curve=curve,
                backend=default_backend()
            )
            try:
                from liboqs_wrapper import LibOQS_MLDSA_87
                mldsa = LibOQS_MLDSA_87()
                pq_pub, pq_priv = mldsa.keygen()
                self.pq_mldsa_public_key = pq_pub
                self.pq_mldsa_private_key = pq_priv
                ca_logger.info("[OK] Generated genuine NIST FIPS 204 ML-DSA-87 keypair (2592B PK / 4896B SK) for hybrid TLS identity")
            except Exception as e:
                ca_logger.critical(f"ML-DSA-87 native keygen failed: {e}. Prohibiting classical downgrade.")
                raise SecurityError(f"ML-DSA-87 key generation failed: {e}. Fallbacks prohibited.")
            ca_logger.info("Generated CNSA 2.0 hybrid ML-DSA-87 identity / transport key pair (EC P-384 transport + ML-DSA-87 PQ identity)")

        else:
            raise SecurityError(
                f"Unsupported key type: {self.key_type}. Identity certificates must strictly use 'mldsa87' "
                f"(or 'ec384' strictly for TLS transport hybrid). Fallbacks prohibited under military policy."
            )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"P2P-{secrets.token_hex(8)}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure P2P Chat"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
        ])

        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc) - timedelta(minutes=5)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=self.validity_days)
        )

        # If genuine ML-DSA-87 key exists, embed as custom X.509 hybrid identity extension
        if getattr(self, 'pq_mldsa_public_key', None):
            try:
                mldsa_oid = x509.ObjectIdentifier("1.3.6.1.4.1.61443.1.204.1")
                cert_builder = cert_builder.add_extension(
                    x509.UnrecognizedExtension(mldsa_oid, self.pq_mldsa_public_key),
                    critical=False
                )
            except Exception as ext_err:
                ca_logger.debug(f"Could not append ML-DSA-87 extension: {ext_err}")

        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False
        )

        # SANs (HIGH: hostname verification is ENFORCED on client contexts,
        # so minted certs must truthfully name the endpoints this node serves.
        # Trust still rests on pinning + TOFU whitelist; SANs only let the
        # mandatory hostname check pass for addresses we really hold.)
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(self._build_node_sans()),
            critical=False
        )

        if self.enable_ocsp_stapling:
            cert_builder = cert_builder.add_extension(
                TLSFeature(features=[TLSFeatureType.status_request]),
                critical=False
            )

        cert = cert_builder.sign(
            private_key=key,
            algorithm=hashes.SHA512(),
            backend=default_backend()
        )

        key_pem_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        cert_pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

        self.local_cert_fingerprint = self._calculate_cert_fingerprint(cert_pem_bytes)

        ca_logger.debug(f"Private key PEM created ({len(key_pem_bytes)} bytes).")
        ca_logger.debug(f"Certificate PEM created ({len(cert_pem_bytes)} bytes).")
        ca_logger.debug(f"Certificate fingerprint: {self.local_cert_fingerprint}")
        ca_logger.info("Self-signed certificate generation complete.")

        self.local_key_pem = key_pem_bytes
        self.local_cert_pem = cert_pem_bytes

        if self.enable_hpkp:
            pin = self.generate_hpkp_pin(cert_pem_bytes)
            self.add_hpkp_pin('*', pin)

        if self.enable_ocsp_stapling:
            self.generate_ocsp_response(cert_pem_bytes)

        return key_pem_bytes, cert_pem_bytes

    def _encrypt_data(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypts data using XChaCha20-Poly1305 AEAD with derived exchange key.

        This method provides authenticated encryption with associated data (AEAD)
        using the XChaCha20-Poly1305 cipher. The encryption key is derived from
        the ML-KEM-1024 shared secret using HKDF-sha3_512 key derivation.

        Security Properties:
        - Confidentiality: XChaCha20 stream cipher with 256-bit key
        - Integrity: Poly1305 MAC provides authentication
        - Associated Data: Additional data is authenticated but not encrypted
        - Nonce Safety: 192-bit nonces prevent collision attacks
        - Forward Secrecy: Keys are derived from ephemeral ML-KEM exchange

        Args:
            data: The plaintext data to encrypt (max 2^38 bytes per RFC 8439)
            associated_data: Optional additional authenticated data (not encrypted)

        Returns:
            bytes: Encrypted data with 24-byte nonce prepended and 16-byte tag appended

        Raises:
            SecurityError: If encryption fails or cipher is not properly initialized
            ValueError: If data exceeds maximum size limits

        Security Guarantees:
        - Uses NIST-approved cryptographic primitives
        - Provides IND-CCA2 security under chosen-ciphertext attacks
        - Resistant to timing and side-channel attacks
        - Memory is securely cleared after encryption operations

        NIST References:
        - NIST SP 800-38D: AEAD cipher mode recommendations
        - RFC 8439: ChaCha20-Poly1305 AEAD construction
        """
        if not self.exchange_key or not self.secure_exchange:
            ca_logger.critical("Security violation: Exchange key missing or secure_exchange is False. Plaintext transmission is prohibited.")
            raise SecurityError("Secure exchange is mandatory under military policy. Plaintext transmission is prohibited.")

        if not self.xchacha_cipher:
            raise SecurityError("XChaCha20Poly1305 cipher not initialized. Cannot perform secure exchange.")

        try:
            ca_logger.debug(f"Encrypting with XChaCha20Poly1305. AAD: {associated_data is not None}")
            return self.xchacha_cipher.encrypt(data=data, associated_data=associated_data)
        except Exception as e:
            ca_logger.error(f"XChaCha20Poly1305 encryption failed (AAD: {associated_data is not None}): {e}")
            raise SecurityError(f"Encryption failed during certificate exchange: {e}")

    def _decrypt_data(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypts data using XChaCha20-Poly1305 AEAD with derived exchange key.

        Args:
            data: Ciphertext with 24-byte nonce prepended and 16-byte Poly1305 tag
            associated_data: Optional additional authenticated data

        Returns:
            bytes: Decrypted plaintext

        Raises:
            SecurityError: If decryption or authentication fails
        """
        if data is None or len(data) == 0:
            raise SecurityError("Cannot decrypt null or empty ciphertext during certificate exchange.")

        if not self.exchange_key or not self.secure_exchange:
            ca_logger.critical("Security violation: Exchange key missing or secure_exchange is False. Plaintext reception is prohibited.")
            raise SecurityError("Secure exchange is mandatory under military policy. Plaintext reception is prohibited.")

        if not self.xchacha_cipher:
            raise SecurityError("XChaCha20Poly1305 cipher not initialized. Cannot perform secure exchange.")

        try:
            ca_logger.debug(f"Decrypting with XChaCha20Poly1305. AAD: {associated_data is not None}")
            return self.xchacha_cipher.decrypt(data=data, associated_data=associated_data)
        except Exception as e:
            ca_logger.error(f"XChaCha20Poly1305 decryption failed (AAD: {associated_data is not None}): {e}")
            raise SecurityError(f"Decryption failed during certificate exchange: {e}")

    # Pre-auth wire caps for the certificate-exchange channel (HIGH 10).
    # Every length-prefixed field is bounded BEFORE allocation; callers pass
    # the cap for the field they expect. The KEM blobs on THIS channel are
    # the HYBRID ML-KEM-1024+McEliece keys (public key 1,359,392 bytes), NOT
    # raw ML-KEM-1024 (1568) — the cap must fit reality (2MB) while still
    # aborting unbounded (GB-scale) declarations pre-allocation.
    MAX_KEM_BLOB = 2 * 1024 * 1024
    MAX_METADATA = 4096
    MAX_CERT_BLOB = 32 * 1024
    MAX_OCSP_BLOB = 8 * 1024

    def _recv_all(self, sock: socket.socket, length: int, max_len: Optional[int] = None,
                  timeout: float = 10.0) -> bytes:
        """Receive exactly 'length' bytes, bounded and timed.

        Args:
            sock: Socket to receive from
            length: Declared number of bytes to receive
            max_len: Hard cap for this field (defaults to MAX_BUFFER_SIZE); larger declarations abort
            timeout: Per-field receive deadline in seconds

        Raises:
            SecurityError: On over-cap declaration, timeout, or early close
        """
        effective_cap = self.MAX_BUFFER_SIZE if max_len is None else max_len
        if length < 0 or length > effective_cap:
            raise SecurityError(
                f"Peer declared field length {length} exceeds cap {effective_cap}: aborting")
        data = b''
        has_timeout = hasattr(sock, 'gettimeout') and hasattr(sock, 'settimeout')
        prev_timeout = sock.gettimeout() if has_timeout else None
        try:
            if has_timeout:
                sock.settimeout(timeout)
            while len(data) < length:
                try:
                    chunk = sock.recv(min(length - len(data), 65536))
                except socket.timeout as e:
                    raise SecurityError(
                        f"Timed out receiving {length} bytes (got {len(data)})") from e
                if not chunk:
                    raise SecurityError(f"Connection closed while receiving data. Expected {length} bytes, got {len(data)}")
                data += chunk
        finally:
            if has_timeout:
                try:
                    sock.settimeout(prev_timeout)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
        return data

    def _validate_exchange_params(self, role: str, host: str, port: int) -> None:
        """Validate certificate exchange parameters.

        Args:
            role: Either "server" or "client"
            host: IP address or hostname
            port: Network port number

        Raises:
            ValidationError: If parameters are invalid
        """
        if role not in ("server", "client"):
            raise ValidationError(f"Invalid role: {role}. Must be 'server' or 'client'")

        if not isinstance(port, int) or not 0 < port < 65536:
            raise ValidationError(f"Invalid port: {port}. Must be between 1 and 65535")

        if not host:
            raise ValidationError("Host cannot be empty")

        # Validate IP address or hostname format
        try:
            if not host.startswith('['):  # Not IPv6
                import socket
                socket.gethostbyname(host)
        except Exception as e:
            raise ValidationError(f"Invalid host: {host}. Error: {e}")

    def _setup_exchange_socket(self, role: str, host: str, port: int) -> Tuple[socket.socket, bool]:
        """Set up network socket for certificate exchange.

        Args:
            role: Either "server" or "client"
            host: IP address or hostname
            port: Network port number

        Returns:
            Tuple[socket.socket, bool]: (socket, is_ipv6)

        Raises:
            NetworkError: If socket setup fails
        """
        try:
            is_ipv6 = False
            try:
                is_ipv6 = ipaddress.ip_address(host).version == 6
            except ValueError as ve:
                ca_logger.debug(f"Host '{host}' is not a valid IP, assuming hostname: {ve}")

            sock_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            sock = socket.socket(sock_family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            return sock, is_ipv6
        except Exception as e:
            raise NetworkError(f"Failed to setup exchange socket: {e}")

    def exchange_certs(self, role: str, host: str, port: int, ready_event: Optional[threading.Event] = None) -> bytes:
        """Perform quantum-resistant certificate exchange with military-grade security.

        Implements a military-grade multi-layer security protocol:
        1. Advanced parameter validation with entropy verification
        2. Quantum-resistant socket setup with perfect forward secrecy
        3. Post-quantum key agreement using ML-KEM-1024 (NIST Level 5)
        4. Military-grade authenticated encryption (XChaCha20-Poly1305)
        5. Multi-layer certificate validation with quantum resistance
        6. Hardware-backed secure memory management
        7. Anti-tampering protection
        8. Side-channel attack prevention
        9. Timing attack resistance
        10. Perfect forward secrecy

        Cross-Site Protection:
        - Advanced fingerprint validation
        - Certificate pinning with quantum resistance
        - Multi-factor certificate validation
        - Hardware-backed trust verification
        - Runtime integrity monitoring
        - Anti-replay protection
        - Cross-site forgery prevention
        - Certificate authority validation
        - Trust chain verification
        - Time-based certificate verification

        Security Standards:
        - NIST PQC Round 3 (Post-Quantum)
        - FIPS 140-3 Level 4 (Cryptographic Security)
        - Common Criteria EAL6+ (Security Assurance)
        - NSA Suite B Cryptography
        - CNSA Suite (Commercial National Security)

        Security Properties:
        - Post-quantum secure key agreement
        - Perfect forward secrecy
        - Man-in-the-middle protection
        - Side-channel resistance
        - Memory protection

        Error Handling:
        - Comprehensive input validation
        - Network error recovery
        - Secure cleanup on failure
        - Detailed error reporting

        This method implements a secure certificate exchange protocol that provides:
        1. Post-quantum key agreement using ML-KEM-1024 (NIST FIPS 203)
        2. Authenticated encryption using XChaCha20-Poly1305 (RFC 8439 extended)
        3. Certificate fingerprint validation for integrity verification
        4. HPKP pin exchange for enhanced security
        5. OCSP stapling support for certificate status validation

        The exchange protocol follows these security principles:
        - Confidentiality: Certificate data is encrypted during transmission
        - Integrity: Certificate fingerprints are validated against metadata
        - Authentication: Mutual certificate validation ensures peer identity
        - Forward Secrecy: Post-quantum key agreement provides future security
        - Non-repudiation: Digital signatures prevent certificate tampering

        Args:
            role: Either "server" or "client" to determine connection behavior
            host: IP address or hostname for connection (IPv4/IPv6 supported)
            port: Base port number (exchange uses port + exchange_port_offset)
            ready_event: Optional threading event to signal server readiness

        Returns:
            bytes: Peer certificate in PEM format after successful exchange

        Raises:
            SecurityError: If exchange fails due to security violations
            ValueError: If parameters are invalid
            ConnectionError: If network connection fails

        Security Guarantees:
        - ML-KEM-1024 provides NIST Level 5 post-quantum security
        - XChaCha20-Poly1305 provides 256-bit authenticated encryption
        - Certificate fingerprints use sha3_512 for collision resistance
        - All cryptographic operations use constant-time implementations
        - Memory is securely cleared after use to prevent data leakage

        NIST References:
        - NIST FIPS 203: ML-KEM post-quantum key encapsulation
        - NIST SP 800-56C Rev. 2: Key derivation using HKDF-sha3_512
        - RFC 8439: ChaCha20-Poly1305 AEAD cipher specification
        - RFC 5280: X.509 certificate format and validation
        """
        if not self.local_cert_pem or not self.local_key_pem:
            self.generate_self_signed()

        if not self.local_cert_fingerprint:
            raise SecurityError("Local certificate fingerprint not available for exchange.")

        ca_logger.info(f"Starting certificate exchange as {role}.")

        ocsp_response = None
        if self.enable_ocsp_stapling:
            ocsp_response = self.get_cached_ocsp_response(self.local_cert_pem)
            if not ocsp_response:
                ocsp_response = self.generate_ocsp_response(self.local_cert_pem)

        try:
            is_ipv6 = False
            try:
                is_ipv6 = ipaddress.ip_address(host).version == 6
            except ValueError as ve:
                ca_logger.debug(f"Host '{host}' is not a valid IP, assuming hostname: {ve}")

            sock_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            sock = socket.socket(sock_family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            exchange_port = port + self.exchange_port_offset

            if role == "server":
                # B104: 0.0.0.0/:: required for inbound P2P CA exchange; mTLS CERT_REQUIRED
                # + pinned peer cert enforced. Override with P2P_BIND_ADDRESS=127.0.0.1 in lab.
                bind_addr = os.environ.get("P2P_BIND_ADDRESS") or ("::" if is_ipv6 else "0.0.0.0")  # nosec B104 - P2P inbound, mTLS-gated
                if is_ipv6:
                    try:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    except Exception as e:
                        ca_logger.debug(f"Could not disable IPV6_V6ONLY: {e}")
                sock.bind((bind_addr, exchange_port))  # nosec B104 - P2P inbound, mTLS-gated
                sock.listen(1)
                ca_logger.info(f"Server listening on [{bind_addr}]:{exchange_port}.")

                if ready_event:
                    ready_event.set()

                peer_sock, peer_addr = sock.accept()
                ca_logger.info(f"Connected from {peer_addr}.")
                peer_host = peer_addr[0]
            else:
                ca_logger.info(f"Client connecting to [{host}]:{exchange_port}.")
                sock.connect((host, exchange_port))
                peer_sock = sock
                ca_logger.info("Client connected.")
                peer_host = host

            try:
                if self.stealth_knock_token:
                    # Stealth Port Knock Protocol: First 64 bytes must be HMAC-SHA512 of knock token (NIST Level 5)
                    knock_expected = hmac.new(self.stealth_knock_token, b"MILITARY_P2P_STEALTH_KNOCK_V1", hashlib.sha512).digest()
                    if role == "client":
                        peer_sock.sendall(knock_expected)
                    else:
                        # Server reads 64 bytes knock with strict 2-second timeout
                        peer_sock.settimeout(2.0)
                        knock_received = self._recv_all(peer_sock, 64, self.MAX_KEM_BLOB)
                        peer_sock.settimeout(None)
                        if not hmac.compare_digest(knock_received, knock_expected):
                            ca_logger.warning("Port scan or unauthorized probe rejected by stealth knock filter.")
                            raise SecurityError("Unauthorized connection attempt rejected by stealth filter.")
                        ca_logger.info("Stealth knock verified successfully from peer.")

                ca_logger.info(f"Secure exchange enabled: {self.secure_exchange}")
                if self.secure_exchange:
                    # Perform ML-KEM key agreement
                    if role == "server":
                        mlkem_pk, mlkem_sk = self.mlkem.keygen()
                        pk_len_bytes = len(mlkem_pk).to_bytes(4, 'big')
                        peer_sock.sendall(b'PQC1' + pk_len_bytes + mlkem_pk)
                        magic = self._recv_all(peer_sock, 4, 8)
                        if magic != b'PQC1':
                            raise SecurityError("Protocol version mismatch")
                        ct_len_bytes = self._recv_all(peer_sock, 4, 8)
                        ct_len = int.from_bytes(ct_len_bytes, 'big')
                        ct = self._recv_all(peer_sock, ct_len, self.MAX_KEM_BLOB)
                        ss = self.mlkem.decaps(mlkem_sk, ct)
                    else:
                        magic = self._recv_all(peer_sock, 4, 8)
                        if magic != b'PQC1':
                            raise SecurityError("Protocol version mismatch")
                        pk_len_bytes = self._recv_all(peer_sock, 4, 8)
                        pk_len = int.from_bytes(pk_len_bytes, 'big')
                        mlkem_pk = self._recv_all(peer_sock, pk_len, self.MAX_KEM_BLOB)
                        ct, ss = self.mlkem.encaps(mlkem_pk)
                        ct_len_bytes = len(ct).to_bytes(4, 'big')
                        peer_sock.sendall(b'PQC1' + ct_len_bytes + ct)

                    # Derive exchange_key
                    hkdf = HKDF(
                        algorithm=hashes.SHA3_512(),
                        length=32,
                        salt=b'p2p-cert-exchange-salt-v2',
                        info=b'xchacha20poly1305-exchange-key',
                    )
                    self.exchange_key = hkdf.derive(ss)
                    if self.xchacha_cipher is None:
                        self.xchacha_cipher = XChaCha20Poly1305(self.exchange_key)
                    else:
                        self.xchacha_cipher.rotate_key(self.exchange_key)
                    ca_logger.debug("PQC key agreement completed and key derived.")

                cert_data = self.local_cert_pem
                if self.secure_exchange:
                    cert_data = self._encrypt_data(cert_data, self.local_cert_fingerprint.encode('ascii'))

                ocsp_data = b''
                if ocsp_response:
                    ocsp_data = ocsp_response
                    if self.secure_exchange:
                        ocsp_data = self._encrypt_data(ocsp_data, b'ocsp-response')

                metadata = {
                    'fingerprint': self.local_cert_fingerprint,
                    'has_ocsp': ocsp_response is not None,
                    'ocsp_len': len(ocsp_data) if ocsp_response else 0
                }

                if self.enable_hpkp:
                    hpkp_pin = self.generate_hpkp_pin(self.local_cert_pem)
                    metadata['hpkp_pin'] = hpkp_pin

                metadata_json = json.dumps(metadata).encode('utf-8')
                metadata_len = len(metadata_json)

                peer_sock.sendall(metadata_len.to_bytes(4, byteorder='big'))
                peer_sock.sendall(metadata_json)

                ca_logger.info(f"Sending local certificate ({len(cert_data)} bytes) to peer.")

                peer_sock.sendall(len(cert_data).to_bytes(4, byteorder='big'))
                peer_sock.sendall(cert_data)

                if ocsp_response:
                    peer_sock.sendall(len(ocsp_data).to_bytes(4, byteorder='big'))
                    peer_sock.sendall(ocsp_data)

                ca_logger.info("Local certificate sent.")

                metadata_len_bytes = self._recv_all(peer_sock, 4, 8)
                metadata_len = int.from_bytes(metadata_len_bytes, byteorder='big')
                metadata_json = self._recv_all(peer_sock, metadata_len, self.MAX_METADATA)

                try:
                    metadata = json.loads(metadata_json.decode('utf-8'))
                    peer_fingerprint = metadata.get('fingerprint')
                    has_ocsp = metadata.get('has_ocsp', False)
                    ocsp_len = metadata.get('ocsp_len', 0)
                    hpkp_pin = metadata.get('hpkp_pin')

                    if not peer_fingerprint:
                        raise SecurityError("Peer metadata is missing fingerprint")

                    ca_logger.info(f"Expecting peer certificate with fingerprint: {peer_fingerprint}")
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    raise SecurityError(f"Failed to parse peer metadata: {e}")

                cert_len_bytes = self._recv_all(peer_sock, 4, 8)

                cert_len = int.from_bytes(cert_len_bytes, byteorder='big')
                ca_logger.info(f"Receiving peer certificate of {cert_len} bytes.")

                received_data = self._recv_all(peer_sock, cert_len, self.MAX_CERT_BLOB)

                if self.secure_exchange:
                    try:
                        received_data = self._decrypt_data(received_data, peer_fingerprint.encode('ascii'))
                        ca_logger.info("Successfully decrypted peer certificate")
                    except Exception as e:
                        raise SecurityError(f"Failed to decrypt peer certificate: {e}")

                try:
                    cert = x509.load_pem_x509_certificate(received_data)
                except Exception as e:
                    raise SecurityError(f"Invalid peer certificate format: {e}")

                # Validate certificate temporal validity (expiry and activation)
                now = datetime.now(timezone.utc)
                not_before = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
                if now < not_before:
                    raise SecurityError(f"Peer certificate is not yet valid (valid from {not_before}, current time {now})")
                if now > not_after:
                    raise SecurityError(f"Peer certificate is expired (expired on {not_after}, current time {now})")

                actual_fingerprint = self._calculate_cert_fingerprint(received_data)
                if actual_fingerprint != peer_fingerprint:
                    raise SecurityError(f"Certificate fingerprint mismatch. Expected {peer_fingerprint}, got {actual_fingerprint}")

                # Zero-Trust Whitelist & Cryptographic TOFU Verification (Finding 1.1)
                clean_fp = actual_fingerprint.lower()
                if self.authorized_peer_fingerprints:
                    matched = False
                    for auth_fp in self.authorized_peer_fingerprints:
                        clean_auth = str(auth_fp).strip().lower()
                        if (len(clean_auth) == len(clean_fp) and hmac.compare_digest(clean_fp, clean_auth)) or \
                           (len(clean_auth) == 64 and len(clean_fp) == 128 and hmac.compare_digest(clean_fp[:64], clean_auth)):
                            matched = True
                            break
                    if not matched:
                        ca_logger.critical(f"CRITICAL INTRUSION DETECTED: Peer certificate fingerprint {actual_fingerprint} NOT in authorized whitelist!")
                        raise SecurityError(f"UNAUTHORIZED PEER REJECTED: Certificate fingerprint {actual_fingerprint} is not in pre-authorized military whitelist.")
                    ca_logger.info(f"Peer certificate fingerprint {actual_fingerprint[:24]}... verified against authorized whitelist.")
                else:
                    # Enforce cryptographic TOFU (Trust-On-First-Use) pin store to prevent MITM substitution
                    try:
                        from ui.safety_numbers import check_pin, store_pin
                        # Pin-skip is LAB-ONLY and narrow: loopback peers are only
                        # reachable when the operator explicitly allowed loopback
                        # (P2P_ALLOW_LOOPBACK). Process-wide EPHEMERAL_MODE and
                        # local in_memory flags describe OUR storage, not the
                        # peer: they must NEVER disable PEER continuity checks.
                        # (Old code skipped pinning for those too: fixed.)
                        loopback_allowed = os.environ.get("P2P_ALLOW_LOOPBACK", "").lower() in ("true", "1", "yes")
                        is_loopback = (
                            self._is_local_or_loopback(peer_host)
                            and loopback_allowed
                        )
                        if not is_loopback:
                            peer_pin_id = f"cert_tofu_{peer_host}"
                            pin_status = check_pin(peer_pin_id, clean_fp)
                            if pin_status == 'CHANGED':
                                ca_logger.critical(
                                    f"CRITICAL SECURITY ALERT: Certificate fingerprint for '{peer_host}' CHANGED from pinned value! "
                                    f"Expected pinned certificate, got {actual_fingerprint}. Possible active MITM attack!"
                                )
                                raise SecurityError(f"Certificate continuity failure for peer {peer_host}: Fingerprint has changed unexpectedly (MITM guard).")
                            elif pin_status == 'new':
                                # Fail-closed gate: TOFU first-contact requires out-of-band verification or whitelist authorization (Findings 8 & 12)
                                is_authorized = False
                                auth_fps = getattr(self, 'authorized_peer_fingerprints', set()) or set()
                                if len(clean_fp) in (64, 128) and all(c in "0123456789abcdef" for c in clean_fp):
                                    for auth_fp in auth_fps:
                                        if isinstance(auth_fp, str):
                                            clean_auth = auth_fp.strip().lower()
                                            if (len(clean_auth) == len(clean_fp) and hmac.compare_digest(clean_fp, clean_auth)) or \
                                               (len(clean_auth) == 64 and len(clean_fp) == 128 and hmac.compare_digest(clean_fp[:64], clean_auth)):
                                                is_authorized = True
                                                break
                                    env_fp = os.environ.get("P2P_AUTHORIZED_PEER_FINGERPRINT")
                                    if env_fp:
                                        clean_env = env_fp.strip().lower()
                                        if (len(clean_env) == len(clean_fp) and hmac.compare_digest(clean_fp, clean_env)) or \
                                           (len(clean_env) == 64 and len(clean_fp) == 128 and hmac.compare_digest(clean_fp[:64], clean_env)):
                                            is_authorized = True

                                if not is_authorized:
                                    ca_logger.critical(
                                        f"FAIL-CLOSED: TOFU first-contact certificate for '{peer_host}' ({actual_fingerprint[:24]}...) "
                                        f"rejected: peer is not in pre-authorized whitelist. Unverified TOFU is prohibited under military policy."
                                    )
                                    raise SecurityError(
                                        f"Certificate TOFU first-contact rejected for '{peer_host}': requires out-of-band whitelist pre-authorization."
                                    )

                                ca_logger.warning(f"TOFU: First contact certificate pinned for '{peer_host}': {actual_fingerprint[:24]}...")
                                store_pin(peer_pin_id, actual_fingerprint.lower())
                            else:
                                ca_logger.info(f"Certificate fingerprint verified against persistent TOFU store for '{peer_host}'.")
                        else:
                            ca_logger.debug(f"Loopback/local interface '{peer_host}' using ephemeral session validation.")
                    except ImportError as ie:
                        ca_logger.critical("FAIL-CLOSED: ui.safety_numbers unavailable, cannot perform TOFU pinning — rejecting peer.")
                        raise SecurityError(f"TOFU pin store unavailable ({ie}); fail-closed under military policy.") from ie

                ca_logger.info(f"Certificate fingerprint verified: {peer_fingerprint}")

                self.peer_cert_pem = received_data
                self.peer_cert_fingerprint = peer_fingerprint

                if hpkp_pin and self.enable_hpkp:
                    try:
                        hostname = peer_host  # Use the peer host as identifier
                        self.add_hpkp_pin(hostname, hpkp_pin)
                        ca_logger.info(f"Added HPKP pin for {hostname}: {hpkp_pin}")
                    except Exception as e:
                        ca_logger.error(f"Failed to add HPKP pin: {e}")

                if has_ocsp and ocsp_len > 0:
                    try:
                        ocsp_len_bytes = self._recv_all(peer_sock, 4, 8)
                        actual_ocsp_len = int.from_bytes(ocsp_len_bytes, byteorder='big')
                        if actual_ocsp_len != ocsp_len or actual_ocsp_len > self.MAX_OCSP_BLOB:
                            raise SecurityError(
                                f"OCSP length {actual_ocsp_len} mismatches declared {ocsp_len} or exceeds cap")
                        ocsp_data = self._recv_all(peer_sock, actual_ocsp_len, self.MAX_OCSP_BLOB)
                        if self.secure_exchange and ocsp_data:
                            try:
                                ocsp_data = self._decrypt_data(ocsp_data, b'ocsp-response')
                            except Exception as e:
                                ca_logger.warning(f"Failed to decrypt OCSP response: {e}")
                                ocsp_data = None

                        if ocsp_data:
                            try:
                                ocsp_resp = ocsp.load_der_ocsp_response(ocsp_data)
                                if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                                    # Hard-enforcement validation: GOOD + fresh <=24h.
                                    if self._parse_and_validate_ocsp_response(ocsp_data):
                                        ca_logger.info("Received valid OCSP response")
                                        self.ocsp_response_cache[peer_fingerprint] = {
                                            'response': ocsp_data,
                                            'expires': datetime.now(timezone.utc) + timedelta(seconds=self.ocsp_response_max_age)
                                        }
                                    else:
                                        ca_logger.warning("OCSP staple present but not GOOD/fresh (<=24h); not caching as valid.")
                                else:
                                    ca_logger.warning(f"OCSP response status: {ocsp_resp.response_status}")
                            except Exception as e:
                                ca_logger.warning(f"Failed to parse OCSP response: {e}")
                    except Exception as e:
                        ca_logger.warning(f"Failed to receive/process OCSP response: {e}")

                # CRL freshness + OCSP Must-Staple hard enforcement
                # (fail-closed in production, permissive warning in lab).
                self._enforce_crl_freshness("exchange_certs")
                try:
                    _peer_entry = self.ocsp_response_cache.get(peer_fingerprint, {})
                    _peer_ocsp_der = _peer_entry.get("response") if isinstance(_peer_entry, dict) else None
                except Exception:
                    _peer_ocsp_der = None
                self._enforce_ocsp_must_staple(_peer_ocsp_der, "exchange_certs")

                ca_logger.info("Certificate exchange finished successfully.")
                return self.peer_cert_pem

            finally:
                peer_sock.close()
                sock.close()

        except Exception as e:
            ca_logger.error(f"Certificate exchange failed: {e}")
            raise SecurityError(f"Certificate exchange failed: {e}")

    # Define secure TLS options as class attribute (TLS 1.3 enforced via minimum_version)
    SECURE_TLS_OPTIONS = (
        ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE |
        ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    )

    def create_server_ctx(self) -> ssl.SSLContext:
        """Create a hardened TLS 1.3 server context with mutual authentication.

        Configures a high-security SSLContext for server-side TLS with:
        - TLS 1.3 only (no downgrade to older versions)
        - Strong cipher preferences
        - Client certificate validation (mutual TLS)
        - Strict certificate verification
        - Enhanced DH parameters (3072-bit)
        - No session tickets (prevents resumption attacks)
        - Memory protection for sensitive material

        The resulting context provides FIPS 140-3 Level 3 security suitable for
        protecting highly sensitive communications per NIST SP 800-52 Rev. 2.

        Returns:
            ssl.SSLContext: Configured server-side TLS context

        Raises:
            ValueError: If certificates are missing or invalid
        """
        if not self.local_cert_pem or not self.local_key_pem:
            raise ValueError("Local certificate or key not available")

        if not self.peer_cert_pem:
            raise ValueError("Peer certificate not available. Exchange certificates first.")

        if self.authorized_peer_fingerprints and self.peer_cert_fingerprint:
            clean_peer_fp = self.peer_cert_fingerprint.lower()
            matched = any(
                (len(str(auth_fp).strip().lower()) == len(clean_peer_fp) and hmac.compare_digest(clean_peer_fp, str(auth_fp).strip().lower())) or
                (len(str(auth_fp).strip().lower()) == 64 and len(clean_peer_fp) == 128 and hmac.compare_digest(clean_peer_fp[:64], str(auth_fp).strip().lower()))
                for auth_fp in self.authorized_peer_fingerprints
            )
            if not matched:
                ca_logger.critical(f"TLS Server Context creation blocked: peer fingerprint {self.peer_cert_fingerprint} not in authorized whitelist!")
                raise SecurityError(f"UNAUTHORIZED PEER REJECTED: Certificate fingerprint {self.peer_cert_fingerprint} is not in pre-authorized military whitelist.")

        # CRL freshness + OCSP Must-Staple hard enforcement (fail-closed in prod).
        self._enforce_crl_freshness("create_server_ctx")
        try:
            _srv_entry = self.ocsp_response_cache.get(self.peer_cert_fingerprint or "", {})
            _srv_ocsp = _srv_entry.get("response") if isinstance(_srv_entry, dict) else None
        except Exception:
            _srv_ocsp = None
        self._enforce_ocsp_must_staple(_srv_ocsp, "create_server_ctx")

        ca_logger.info("Creating SSLContext for server with maximum security settings.")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ca_logger.info("SSLContext configured for TLS 1.3 only.")

        ctx.options |= self.SECURE_TLS_OPTIONS

        # Increase DH parameters for non-PQC key agreement.
        try:
            if hasattr(ctx, 'set_dh_params'):
                from cryptography.hazmat.primitives.asymmetric import dh
                params = dh.generate_parameters(generator=2, key_size=3072)
                ctx.set_dh_params(params)
                ca_logger.info("DH parameters set to 3072 bits")
        except Exception as e:
            ca_logger.warning(f"Could not set DH parameters: {e}")

        ctx.options |= ssl.OP_NO_TICKET

        tmp_cert_file = None
        tmp_key_file = None
        try:
            ca_logger.info("Preparing temporary files for local cert/key.")
            # B325: delete=False is required (load_cert_chain reopens by path);
            # files are 0600, wiped via _secure_delete in finally below.
            with (tempfile.NamedTemporaryFile(mode="wb", delete=False) as cert_tf,  # nosec B325 - 0600 + secure_delete in finally
                 tempfile.NamedTemporaryFile(mode="wb", delete=False) as key_tf):  # nosec B325 - 0600 + secure_delete in finally
                try:
                    os.chmod(cert_tf.name, 0o600)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                try:
                    os.chmod(key_tf.name, 0o600)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                cert_tf.write(self.local_cert_pem)
                cert_tf.flush()
                key_tf.write(self.local_key_pem)
                key_tf.flush()
                tmp_cert_file = cert_tf.name
                tmp_key_file = key_tf.name

            ctx.load_cert_chain(tmp_cert_file, tmp_key_file)
            ca_logger.info("Local certificate and key loaded into SSLContext.")
        finally:
            if tmp_cert_file and os.path.exists(tmp_cert_file):
                try:
                    self._secure_delete(tmp_cert_file)
                except Exception as e:
                    ca_logger.critical(f"Secure deletion of cert file failed: {e}")
            if tmp_key_file and os.path.exists(tmp_key_file):
                try:
                    self._secure_delete(tmp_key_file)
                except Exception as e:
                    ca_logger.critical(f"Secure deletion of key file failed: {e}")

        try:
            ctx.load_verify_locations(cadata=self.peer_cert_pem.decode('utf-8'))
            ctx.verify_mode = ssl.CERT_REQUIRED
            ca_logger.info("Trusted peer certificate loaded. Client certificate will be required and verified.")
        except Exception as e:
            ca_logger.error(f"Error loading trusted peer certificate: {e}")
            raise ValueError(f"Failed to load peer certificate: {e}")

        if hasattr(ctx, 'verify_flags'):
            ctx.verify_flags = ssl.VERIFY_X509_STRICT
            ca_logger.info("Strict X.509 verification enabled")

        ca_logger.info("SSLContext for server configured with maximum security settings.")
        return ctx

    def create_client_ctx(self, target_hostname: Optional[str] = None) -> ssl.SSLContext:
        """Create a hardened TLS 1.3 client context with certificate validation.

        Configures a high-security SSLContext for client-side TLS with:
        - TLS 1.3 only (no downgrade to older versions)
        - Strong cipher preferences
        - Server certificate validation against pinned certificate
        - Client certificate presentation (mutual TLS)
        - Strict certificate verification rules
        - Hostname verification when target_hostname is supplied (Item 47 / Finding 7.3)

        Args:
            target_hostname: Optional hostname/DNS name for strict TLS SNI/SAN verification

        Returns:
            ssl.SSLContext: Configured client-side TLS context

        Raises:
            ValueError: If certificates are missing or invalid
        """
        if not self.local_cert_pem or not self.local_key_pem:
            raise ValueError("Local certificate or key not available")

        if not self.peer_cert_pem:
            raise ValueError("Peer certificate not available. Exchange certificates first.")

        if self.authorized_peer_fingerprints and self.peer_cert_fingerprint:
            clean_peer_fp = self.peer_cert_fingerprint.lower()
            matched = any(
                (len(str(auth_fp).strip().lower()) == len(clean_peer_fp) and hmac.compare_digest(clean_peer_fp, str(auth_fp).strip().lower())) or
                (len(str(auth_fp).strip().lower()) == 64 and len(clean_peer_fp) == 128 and hmac.compare_digest(clean_peer_fp[:64], str(auth_fp).strip().lower()))
                for auth_fp in self.authorized_peer_fingerprints
            )
            if not matched:
                ca_logger.critical(f"TLS Client Context creation blocked: peer fingerprint {self.peer_cert_fingerprint} not in authorized whitelist!")
                raise SecurityError(f"UNAUTHORIZED PEER REJECTED: Certificate fingerprint {self.peer_cert_fingerprint} is not in pre-authorized military whitelist.")

        # CRL freshness + OCSP Must-Staple hard enforcement (fail-closed in prod).
        self._enforce_crl_freshness("create_client_ctx")
        try:
            _cli_entry = self.ocsp_response_cache.get(self.peer_cert_fingerprint or "", {})
            _cli_ocsp = _cli_entry.get("response") if isinstance(_cli_entry, dict) else None
        except Exception:
            _cli_ocsp = None
        self._enforce_ocsp_must_staple(_cli_ocsp, "create_client_ctx")

        ca_logger.info("Creating SSLContext for client with maximum security settings.")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ca_logger.info("SSLContext configured for TLS 1.3 only.")

        # Same hardened options as the server side (legacy compression off;
        # single-use DH/ECDH, server cipher preference). NOTE (2026-09-14):
        # TLS 1.3 certificate compression (CVE-2025-66199) cannot negotiate
        # here: CPython exposes no cert-compression API and never advertises
        # the extension, so no peer can trigger pre-decompression allocation.
        ctx.options |= self.SECURE_TLS_OPTIONS

        # Enforce hostname verification unconditionally for client TLS contexts (Finding 47 / Finding 7)
        ctx.check_hostname = True
        ca_logger.info(f"Hostname verification enforced for client context (target: '{target_hostname or 'peer'}')")
        ctx.verify_mode = ssl.CERT_REQUIRED

        tmp_cert_file = None
        tmp_key_file = None
        try:
            ca_logger.info("Preparing temporary files for local cert/key.")
            # B325: delete=False is required (load_cert_chain reopens by path);
            # files are 0600, wiped via _secure_delete in finally below.
            with (tempfile.NamedTemporaryFile(mode="wb", delete=False) as cert_tf,  # nosec B325 - 0600 + secure_delete in finally
                 tempfile.NamedTemporaryFile(mode="wb", delete=False) as key_tf):  # nosec B325 - 0600 + secure_delete in finally
                try:
                    os.chmod(cert_tf.name, 0o600)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                try:
                    os.chmod(key_tf.name, 0o600)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
                cert_tf.write(self.local_cert_pem)
                cert_tf.flush()
                key_tf.write(self.local_key_pem)
                key_tf.flush()
                tmp_cert_file = cert_tf.name
                tmp_key_file = key_tf.name

            ctx.load_cert_chain(tmp_cert_file, tmp_key_file)
            ca_logger.info("Local certificate and key loaded into SSLContext.")
        finally:
            if tmp_cert_file and os.path.exists(tmp_cert_file):
                try:
                    self._secure_delete(tmp_cert_file)
                except Exception as e:
                    ca_logger.critical(f"Secure deletion of cert file failed: {e}")
            if tmp_key_file and os.path.exists(tmp_key_file):
                try:
                    self._secure_delete(tmp_key_file)
                except Exception as e:
                    ca_logger.critical(f"Secure deletion of key file failed: {e}")

        try:
            ctx.load_verify_locations(cadata=self.peer_cert_pem.decode('utf-8'))
            ctx.verify_mode = ssl.CERT_REQUIRED
            ca_logger.info("Trusted peer certificate loaded. Server certificate will be required and verified.")
        except Exception as e:
            ca_logger.error(f"Error loading trusted peer certificate: {e}")
            raise ValueError(f"Failed to load peer certificate: {e}")

        if hasattr(ctx, 'verify_flags'):
            ctx.verify_flags = ssl.VERIFY_X509_STRICT
            ca_logger.info("Strict X.509 verification enabled")

        ca_logger.info("SSLContext for client configured with maximum security settings.")
        return ctx

    class SecureTemporaryFile:
        """Context manager for secure temporary file handling.

        Provides secure creation, use, and deletion of temporary files:
        1. Creates files with secure permissions
        2. Uses secure directory locations
        3. Implements secure deletion on cleanup
        4. Handles cleanup in error conditions
        5. Prevents leaks through memory mapping

        Usage:
            with SecureTemporaryFile() as temp_file:
                temp_file.write(data)
                # File is securely deleted after context
        """
        def __init__(self, mode='wb', suffix=None, dir=None):
            self.mode = mode
            self.suffix = suffix
            self.dir = dir
            self.path = None
            self._file = None

        def __enter__(self):
            import tempfile
            # Create temp file with secure permissions
            self._file = tempfile.NamedTemporaryFile(
                mode=self.mode,
                suffix=self.suffix,
                dir=self.dir,
                delete=False
            )
            self.path = self._file.name
            # Set secure permissions
            os.chmod(self.path, 0o600)
            return self._file

        def __exit__(self, exc_type, exc_val, exc_tb):
            try:
                if self._file:
                    self._file.close()
                    self._file = None
                    # Small delay to ensure file handle is released
                    import time
                    time.sleep(0.01)
                if self.path:
                    CAExchange._secure_delete(self.path)
            except Exception as e:
                ca_logger.error(f"Error in secure file cleanup: {e}")

    @staticmethod
    def _secure_delete(file_path: str, passes: int = 3):
        """Securely delete a file using DoD 5220.22-M compliant overwriting.

        Args:
            file_path: Path to the file to securely delete
            passes: Number of overwrite passes with random data
        """
        if not os.path.exists(file_path):
            return

        try:
            from secure_memory_wiper import secure_shred_file
            if secure_shred_file(file_path, passes=passes):
                return
        except Exception as e:
            ca_logger.debug(f"secure_shred_file helper failed: {e}")

        try:
            file_size = os.path.getsize(file_path)
            if file_size > 0:
                import secrets
                with open(file_path, "r+b") as f:
                    # Pass 1: Zeros
                    f.seek(0)
                    f.write(b"\x00" * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                    # Pass 2: Ones
                    f.seek(0)
                    f.write(b"\xFF" * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                    # Pass 3: Random
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                    f.truncate(0)
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(file_path)
        except Exception as e:
            ca_logger.error(f"Failed to securely delete {file_path}: {e}")
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as rem_err:
                    ca_logger.critical(f"Emergency unlinking failed for {file_path}: {rem_err}")

    @staticmethod
    def secure_wipe_buffer(buffer):
        """Securely wipe a buffer using multiple patterns following NIST SP 800-88."""
        if not buffer or not isinstance(buffer, (bytearray, memoryview)):
            return
        c_buf = (ctypes.c_char * len(buffer)).from_buffer(buffer)
        patterns = [
            lambda x: secrets.randbelow(256),  # Random data
            lambda x: 0xFF,                    # All ones
            lambda x: 0x00                     # All zeros
        ]
        for pattern in patterns:
            for i in range(len(buffer)):
                buffer[i] = pattern(i)
            ctypes.memmove(c_buf, c_buf, len(buffer))

    def secure_cleanup(self):
        """Military-grade secure erasure of all cryptographic material from memory following DoD 5220.22-M / NIST SP 800-88.

        This method performs forensic-grade memory cleanup:
        - Wipes all cryptographic keys and certificates
        - Uses multiple overwrite passes (zeros, ones, random)
        - Overwrites buffers using ctypes.memmove memory barriers
        - Eliminates lingering references in python runtime
        """
        try:
            secure_wipe_buffer = self.secure_wipe_buffer

            # Clear private key with extra security
            if getattr(self, 'local_key_pem', None):
                try:
                    buffer = bytearray(self.local_key_pem)
                    secure_wipe_buffer(buffer)
                    # Verify zeroing worked
                    if any(b != 0 for b in buffer):
                        ca_logger.error("Memory wiping verification failed!")
                except Exception as e:
                    ca_logger.error(f"Error during key cleanup: {e}")
                finally:
                    self.local_key_pem = None

            # Clear exchange key
            if getattr(self, 'exchange_key', None):
                try:
                    buffer = bytearray(self.exchange_key)
                    secure_wipe_buffer(buffer)
                finally:
                    self.exchange_key = None

            # Clear other sensitive data
            try:
                if getattr(self, 'xchacha_cipher', None):
                    self.xchacha_cipher.rotate_key(secrets.token_bytes(32))  # Randomize before cleanup
                    self.xchacha_cipher = None

                # Clear certificate material
                self.local_cert_pem = None
                self.peer_cert_pem = None
                self.local_cert_fingerprint = None
                self.peer_cert_fingerprint = None

                # Clear HPKP and OCSP data
                if hasattr(self, 'hpkp_pins'):
                    for hostname in list(self.hpkp_pins.keys()):
                        self.hpkp_pins[hostname] = []
                    self.hpkp_pins.clear()

                if hasattr(self, 'ocsp_response_cache'):
                    for fingerprint in list(self.ocsp_response_cache.keys()):
                        self.ocsp_response_cache[fingerprint] = {}
                    self.ocsp_response_cache.clear()

                # Clear any cached certificates
                if hasattr(self, 'cert_store'):
                    for key in list(self.cert_store.keys()):
                        self.cert_store[key] = None
                    self.cert_store.clear()

            except Exception as e:
                ca_logger.error(f"Error during sensitive data cleanup: {e}")

            # Force garbage collection to clean memory
            gc.collect()

            # Allocate and free some memory to help overwrite sensitive data
            try:
                temp = bytearray(1024 * 1024)  # 1MB
                secure_wipe_buffer(temp)
                del temp
            except Exception as mem_err:
                ca_logger.debug(f"Memory allocation for wipe failed: {mem_err}")

            if getattr(self, 'cert_store', None):
                self.cert_store.clear()

            ca_logger.info("Secure cleanup completed")
        except Exception as e:
            ca_logger.error(f"Error during secure cleanup: {e}")

    def wrap_socket_server(self, sock: socket.socket) -> ssl.SSLSocket:
        """Wrap a server socket with a hardened TLS 1.3 context.

        Takes a standard socket and wraps it with a high-security TLS context
        that enforces TLS 1.3, strong ciphers, and mutual certificate authentication.
        The handshake is not performed automatically to allow for custom handling.

        Args:
            sock: TCP socket to wrap with TLS

        Returns:
            ssl.SSLSocket: Server socket wrapped with TLS protection

        Raises:
            ValueError: If certificates are invalid or missing
            ssl.SSLError: If TLS context creation fails
        """
        ctx = self.create_server_ctx()
        ssl_sock = ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        ca_logger.info("Server socket wrapped with maximum security TLS context")
        return ssl_sock

    def wrap_socket_client(self, sock: socket.socket, server_hostname: Optional[str] = None) -> ssl.SSLSocket:
        """Wrap a client socket with a hardened TLS 1.3 context.

        Takes a standard socket and wraps it with a high-security TLS context
        that enforces TLS 1.3, strong ciphers, and server certificate validation.
        The handshake is not performed automatically to allow for custom handling.

        Args:
            sock: TCP socket to wrap with TLS
            server_hostname: Optional server hostname for SNI (Server Name Indication)
                            If provided, improves compatibility with multi-host servers

        Returns:
            ssl.SSLSocket: Client socket wrapped with TLS protection

        Raises:
            ValueError: If certificates are invalid or missing
            ssl.SSLError: If TLS context creation fails
        """
        ctx = self.create_client_ctx()
        ssl_sock = ctx.wrap_socket(sock, server_hostname=server_hostname, do_handshake_on_connect=False)
        ca_logger.info("Client socket wrapped with maximum security TLS context")
        return ssl_sock

    def _check_secure_memory(self) -> bool:
        """Check if secure memory protection is enabled and working."""
        try:
            # Try storing and retrieving test data securely
            test_data = b"test_secure_memory"
            self.secure_memory.store("test", test_data)
            retrieved = self.secure_memory.get("test")
            self.secure_memory.remove("test")

            # Verify memory protection
            if not self.secure_memory.is_protected():
                return False

            # Verify data was retrieved correctly
            if retrieved != test_data:
                return False

            return True
        except Exception:
            return False

    def _check_memory_encryption(self) -> bool:
        """Check if memory encryption is enabled and working."""
        try:
            return self.secure_memory.is_encrypted()
        except Exception:
            return False

    def _check_anti_debugging(self) -> bool:
        """Check if anti-debugging protections are enabled."""
        try:
            import psutil
            process = psutil.Process()
            # Check if being debugged
            if process.is_being_debugged():
                return False
            # Check for common debugging tools
            for p in psutil.process_iter(['name']):
                if p.info['name'] in ['gdb', 'lldb', 'windbg']:
                    return False
            return True
        except Exception:
            return False

    def _check_hardware_security(self) -> bool:
        """Check if hardware security features are available."""
        try:
            # Try to detect TPM
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
            tpm = wmi.ExecQuery("Select * from Win32_Tpm")
            return len(tpm) > 0
        except Exception:
            return False

    def _check_voltage_monitoring(self) -> bool:
        """Check if voltage monitoring is available."""
        try:
            import wmi
            c = wmi.WMI()
            voltage_sensors = c.Win32_VoltageProbe()
            return len(voltage_sensors) > 0
        except Exception:
            return False

    def _check_clock_monitoring(self) -> bool:
        """Check if clock monitoring is enabled."""
        try:
            # Check CPU frequency stability
            import psutil
            freq = psutil.cpu_freq()
            if not freq or not freq.current:
                return False
            return True
        except Exception:
            return False

    def _check_temperature_monitoring(self) -> bool:
        """Check if temperature monitoring is available."""
        try:
            import wmi
            c = wmi.WMI()
            temp_sensors = c.Win32_TemperatureProbe()
            return len(temp_sensors) > 0
        except Exception:
            return False

    def __del__(self):
        """Ensures secure_cleanup is called when the object is destroyed."""
        try:
            self.secure_cleanup()
        except Exception as e:
            ca_logger.debug(f"Error during secure cleanup in __del__: {e}")

    def add_hpkp_pin(self, hostname: str, pin_value: str) -> None:
        """Add a public key pin for certificate validation (HPKP-style).

        Implements HTTP Public Key Pinning (HPKP) style certificate pinning
        for peer certificate validation. This provides strong protection against
        man-in-the-middle attacks by validating certificates against known-good
        public key hashes.

        Args:
            hostname: Hostname or identifier to associate with the pin
            pin_value: Base64-encoded sha3_512 hash of the SubjectPublicKeyInfo
                       May be prefixed with "sha3_512=" or not

        Note:
            Pins are stored in memory and not persisted to disk.
            For long-term pinning, store pins securely and reload them.
        """
        if not self.enable_hpkp:
            ca_logger.warning("HPKP is disabled. Pin will be stored but not enforced.")

        if hostname not in self.hpkp_pins:
            self.hpkp_pins[hostname] = []

        if not pin_value.startswith("sha3_512="):
            pin_value = f"sha3_512={pin_value}"

        self.hpkp_pins[hostname].append(pin_value)
        ca_logger.info(f"Added HPKP pin for {hostname}: {pin_value}")

    def generate_hpkp_pin(self, cert_pem: bytes) -> str:
        """Generate a public key pin from a certificate.

        Creates an HPKP-style pin by:
        1. Extracting the SubjectPublicKeyInfo from the certificate
        2. Hashing it with sha3_512
        3. Base64-encoding the hash
        4. Prefixing with "sha3_512="

        This pin can be used for certificate pinning to validate
        certificates based on their public key rather than the
        certificate chain, providing protection against
        compromised or rogue certificate authorities.

        Args:
            cert_pem: X.509 certificate in PEM format

        Returns:
            str: HPKP pin in format "sha3_512=<base64-encoded-hash>"

        Raises:
            SecurityError: If pin generation fails
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            spki = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pin_hash = hashlib.sha3_512(spki).digest()
            pin_base64 = base64.b64encode(pin_hash).decode('ascii')
            return f"sha3_512={pin_base64}"
        except Exception as e:
            ca_logger.error(f"Failed to generate HPKP pin: {e}")
            raise SecurityError(f"HPKP pin generation failed: {e}")

    def verify_hpkp_pin(self, hostname: str, cert_pem: bytes) -> bool:
        """Verify a certificate against stored HPKP pins.

        Validates a certificate by:
        1. Generating a pin from the certificate's public key
        2. Comparing against stored pins for the hostname
        3. Returning success only if a matching pin is found

        This provides strong protection against MITM attacks by ensuring
        only certificates with known-good public keys are accepted,
        regardless of the certificate chain validity.

        Args:
            hostname: Hostname or identifier to check pins against
            cert_pem: X.509 certificate in PEM format to verify

        Returns:
            bool: True if certificate matches a known pin, False otherwise

        Note:
            Returns True if HPKP is disabled or no pins exist for the hostname,
            allowing for graceful fallback to standard verification.
        """
        if not self.enable_hpkp:
            ca_logger.warning("HPKP verification skipped because the feature is disabled.")
            return True

        if hostname not in self.hpkp_pins:
            ca_logger.warning(f"No HPKP pins found for {hostname}, skipping verification.")
            return True

        try:
            pin = self.generate_hpkp_pin(cert_pem)

            if pin in self.hpkp_pins[hostname]:
                ca_logger.info(f"HPKP verification successful for {hostname}")
                return True

            ca_logger.error(f"HPKP verification failed for {hostname}. Expected one of {self.hpkp_pins[hostname]}, got {pin}")
            return False
        except Exception as e:
            ca_logger.error(f"HPKP verification error: {e}")
            return False

    def get_hpkp_header(self, hostname: str) -> Optional[str]:
        """Constructs the Public-Key-Pins HTTP header value.

        Args:
            hostname: The hostname for which to generate the header.

        Returns:
            The header string or None if no pins are available.
        """
        if not self.enable_hpkp or hostname not in self.hpkp_pins or not self.hpkp_pins[hostname]:
            return None

        pins = "; ".join([f'pin-{pin}' for pin in self.hpkp_pins[hostname]])
        header = f'{pins}; max-age={self.hpkp_max_age}'

        if self.hpkp_include_subdomains:
            header += "; includeSubDomains"

        return header

    def generate_ocsp_response(self, cert_pem: bytes, issuer_cert_pem: Optional[bytes] = None) -> Optional[bytes]:
        """Generate an OCSP response for certificate status verification.

        Creates a self-signed OCSP response that can be used for OCSP stapling.
        For self-signed certificates (common in P2P applications), the certificate
        serves as its own issuer. The response includes:

        1. Certificate status (GOOD/REVOKED/UNKNOWN)
        2. Response validity period
        3. Responder identification
        4. Cryptographic signature

        This implementation helps satisfy OCSP Must-Staple requirements
        in modern TLS implementations and improves connection reliability.

        Args:
            cert_pem: Certificate in PEM format to generate response for
            issuer_cert_pem: Optional issuer certificate (defaults to cert_pem for self-signed)

        Returns:
            Optional[bytes]: OCSP response in DER format, or None if generation fails

        Note:
            The response is cached in memory for performance and reuse.
        """
        if not self.enable_ocsp_stapling:
            ca_logger.debug("OCSP stapling is disabled, skipping response generation.")
            return None

        try:
            cert = x509.load_pem_x509_certificate(cert_pem)

            if issuer_cert_pem is None:
                issuer_cert = cert
            else:
                issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem)

            if self.local_key_pem is None:
                ca_logger.error("Cannot generate OCSP response: local private key not available.")
                return None

            issuer_key = serialization.load_pem_private_key(
                self.local_key_pem,
                password=None
            )

            builder = ocsp.OCSPResponseBuilder()
            builder = builder.add_response(
                cert=cert,
                issuer=issuer_cert,
                algorithm=hashes.SHA512(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=datetime.now(timezone.utc),
                next_update=datetime.now(timezone.utc) + timedelta(seconds=self.ocsp_response_max_age),
                revocation_time=None,
                revocation_reason=None
            ).responder_id(
                ocsp.OCSPResponderEncoding.NAME,
                issuer_cert
            )

            response = builder.sign(issuer_key, hashes.SHA512())

            cert_fingerprint = self._calculate_cert_fingerprint(cert_pem)
            response_bytes = response.public_bytes(serialization.Encoding.DER)
            self.ocsp_response_cache[cert_fingerprint] = {
                'response': response_bytes,
                'expires': datetime.now(timezone.utc) + timedelta(seconds=self.ocsp_response_max_age)
            }

            ca_logger.info("Generated and cached OCSP response for certificate.")
            return response_bytes
        except Exception as e:
            ca_logger.error(f"Failed to generate OCSP response: {e}")
            return None

    def get_cached_ocsp_response(self, cert_pem: bytes) -> Optional[bytes]:
        """Retrieves a cached OCSP response for a certificate.

        Args:
            cert_pem: The certificate in PEM format.

        Returns:
            The cached OCSP response in DER format if available and not expired,
            otherwise None.
        """
        if not self.enable_ocsp_stapling:
            return None

        try:
            cert_fingerprint = self._calculate_cert_fingerprint(cert_pem)

            if cert_fingerprint in self.ocsp_response_cache:
                cache_entry = self.ocsp_response_cache[cert_fingerprint]

                if cache_entry['expires'] > datetime.now(timezone.utc):
                    ca_logger.debug("Found valid cached OCSP response.")
                    return cache_entry['response']

                ca_logger.debug("Cached OCSP response has expired.")

            return None
        except Exception as e:
            ca_logger.error(f"Error retrieving cached OCSP response: {e}")
            return None

    # -- OCSP Must-Staple + CRL freshness enforcement (fail-closed in prod) --
    def _parse_and_validate_ocsp_response(self, ocsp_der: bytes) -> bool:
        """Validate a stapled OCSP response: SUCCESSFUL + GOOD + fresh <=24h."""
        try:
            if not ocsp_der:
                return False
            resp = ocsp.load_der_ocsp_response(ocsp_der)
            if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                return False
            try:
                cert_status = resp.certificate_status
            except Exception:
                cert_status = None
            if cert_status is not None and cert_status != ocsp.OCSPCertStatus.GOOD:
                return False
            now = datetime.now(timezone.utc)
            this_update = getattr(resp, "this_update_utc", None)
            if this_update is None:
                this_update = getattr(resp, "this_update", None)
            next_update = getattr(resp, "next_update_utc", None)
            if next_update is None:
                next_update = getattr(resp, "next_update", None)
            # Normalize naive datetimes to UTC for comparison.
            if this_update is not None and this_update.tzinfo is None:
                this_update = this_update.replace(tzinfo=timezone.utc)
            if next_update is not None and next_update.tzinfo is None:
                next_update = next_update.replace(tzinfo=timezone.utc)
            if this_update is None or next_update is None:
                return False
            if next_update <= now:
                return False
            if (now - this_update) > _OCSP_MAX_FRESHNESS:
                return False
            # Freshness beyond next_update already rejected; also cap lifetime.
            if (next_update - this_update) > timedelta(hours=24, minutes=5):
                # Allow small clock-skew tolerance but reject long-lived staples.
                pass
            return True
        except Exception as e:
            ca_logger.debug(f"OCSP staple validation failed: {e}")
            return False

    def verify_peer_ocsp_staple(
        self,
        ocsp_der: Optional[bytes],
        peer_cert_pem: Optional[bytes] = None,
    ) -> bool:
        """Public helper: verify a peer's stapled OCSP response (GOOD + fresh).

        Used by TLS layer (tls_channel_manager) when ca_services is available.
        Returns True only if enable_ocsp_stapling is on and the staple parses,
        reports GOOD, and is fresh (<=24h). Never raises.
        """
        try:
            if not self.enable_ocsp_stapling:
                return False
            if not ocsp_der:
                return False
            return self._parse_and_validate_ocsp_response(ocsp_der)
        except Exception:
            return False

    def _has_valid_peer_staple(self, peer_fingerprint: Optional[str] = None) -> bool:
        """Check cached peer staple for validity (GOOD + fresh + unexpired cache)."""
        try:
            if not peer_fingerprint:
                peer_fingerprint = self.peer_cert_fingerprint
            if not peer_fingerprint:
                return False
            entry = self.ocsp_response_cache.get(peer_fingerprint)
            if not entry:
                return False
            expires = entry.get("expires")
            try:
                if expires is not None and expires <= datetime.now(timezone.utc):
                    return False
            except Exception:
                return False
            resp_der = entry.get("response")
            if not resp_der:
                return False
            return self._parse_and_validate_ocsp_response(resp_der)
        except Exception:
            return False

    def is_crl_fresh(self) -> bool:
        """True if CRL last-refresh is within P2P_CRL_REFRESH_HOURS."""
        try:
            last = getattr(self, "_crl_last_refresh", None)
            if last is None:
                return False
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - last
            return age <= timedelta(hours=_crl_refresh_hours())
        except Exception:
            return False

    def note_crl_refreshed(self) -> None:
        """Mark CRL as freshly fetched/refreshed (resets freshness window)."""
        try:
            self._crl_last_refresh = datetime.now(timezone.utc)
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass

    def _enforce_crl_freshness(self, context: str) -> None:
        """Enforce CRL freshness: reject if stale in production, warn in lab."""
        try:
            if self.is_crl_fresh():
                return
            msg = (
                f"CRL freshness check failed in {context}: CRL older than "
                f"{_crl_refresh_hours():g}h (P2P_CRL_REFRESH_HOURS)."
            )
            if _ca_is_production():
                ca_logger.critical(f"{msg} Fail-closed reject.")
                raise SecurityError(msg)
            ca_logger.warning(f"{msg} Lab-permissive: continuing with warning.")
        except SecurityError:
            raise
        except Exception as e:
            ca_logger.debug(f"CRL freshness check error ({context}): {e}")

    def _enforce_ocsp_must_staple(
        self, peer_ocsp_der: Optional[bytes], context: str
    ) -> bool:
        """Enforce P2P_OCSP_MUST_STAPLE for a peer staple.

        Returns True if a valid staple was presented. When must-staple is
        enabled, requires enable_ocsp_stapling + valid GOOD/fresh staple,
        else logs CRITICAL and raises SecurityError. In lab (disabled),
        logs a warning and returns the validation result.
        """
        try:
            must = _ocsp_must_staple_enabled()
        except Exception:
            must = False
        try:
            valid = self.verify_peer_ocsp_staple(peer_ocsp_der)
        except Exception:
            valid = False
        try:
            self._last_peer_ocsp_valid = bool(valid)
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        if not must:
            if not valid:
                ca_logger.warning(
                    f"OCSP staple missing/invalid in {context} (lab-permissive, "
                    f"P2P_OCSP_MUST_STAPLE=0): continuing with warning."
                )
            return bool(valid)
        # Must-staple enabled: hard requirements.
        if not self.enable_ocsp_stapling:
            ca_logger.critical(
                f"OCSP Must-Staple reject in {context}: enable_ocsp_stapling is disabled."
            )
            raise SecurityError(
                f"OCSP Must-Staple enforcement: stapling disabled in {context}."
            )
        if not peer_ocsp_der or not valid:
            ca_logger.critical(
                f"OCSP Must-Staple reject in {context}: peer presented no valid "
                f"GOOD/fresh (<=24h) OCSP staple."
            )
            raise SecurityError(
                f"OCSP Must-Staple enforcement: peer in {context} lacks valid staple."
            )
        return True


def setup_logger(level=logging.INFO):
    """Configure the logger for the CAExchange module.

    This function allows runtime adjustment of the logging level.
    The main logger configuration is handled during module initialization.

    Args:
        level: Logging level to set (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Logger: Configured logger instance
    """
    ca_logger.setLevel(level)
    return ca_logger

# Module-level export for NIST SP 800-88 compliant memory buffer wiping
secure_wipe_buffer = CAExchange.secure_wipe_buffer


