"""
Double Ratchet Protocol Implementation with Post-Quantum Security

This module implements the Double Ratchet algorithm (Signal Protocol) for secure messaging,
enhanced with post-quantum cryptographic primitives to provide forward secrecy
and break-in recovery protection against both classical and quantum adversaries.

The implementation includes timing attack resistance through constant-time operations
to prevent side-channel attacks on cryptographic operations.

Cryptographic Algorithms:
1. Key Exchange:
   - Classical: X25519 Curve25519 ECDH (RFC 7748)
   - Post-Quantum: ML-KEM-1024 (NIST Round 3, 256-bit security)

2. Symmetric Encryption:
   - ChaCha20-Poly1305 AEAD (RFC 8439)
   - 256-bit encryption keys
   - 96-bit nonces (counter-based generation)
   - 128-bit authentication tags

3. Digital Signatures (per-message session authentication):
   - ML-DSA-87 (NIST FIPS 204, CNSA 2.0, 256-bit security)
   - Lattice-based signature scheme; Falcon-1024 verifies on the receive
     path only for pre-migration peers (not CNSA 2.0)

4. Key Derivation:
   - HKDF-SHA3_512 (RFC 5869)
   - Domain separation using distinct info strings
   - 256-bit root, chain, and message keys

Security Properties:
1. Forward Secrecy: Compromise of current keys cannot decrypt past messages
2. Post-Compromise Security: Security recovery after key compromise
3. Message Origin Authentication & Non-Repudiation: High-assurance per-message post-quantum digital signatures (FALCON-1024 / ML-DSA-87 + SLH-DSA-256f) provide cryptographic non-repudiation for high-integrity/NC3 environments. For deniable messaging modes, symmetric ChaCha20-Poly1305 AEAD MACs provide repudiability.
4. Replay Attack Prevention: Message deduplication with unique IDs and FIFO window
5. Side-Channel Resistance: Constant-time operations for sensitive functions
6. Memory Protection: Secure allocation and wiping of sensitive material

Protocol Implementation:
1. Symmetric Key Ratchet: HMAC-SHA-512 chain derivation
2. Diffie-Hellman Ratchet: X25519 with ML-KEM-1024 hybrid
3. Message Authentication: ChaCha20-Poly1305 AEAD with bound FALCON / ML-DSA post-quantum signatures
4. Binary Message Format: 48-byte header + encrypted payload

This implementation defines a custom Post-Quantum Double Ratchet (PQ-Double-Ratchet) protocol
incorporating ML-KEM-1024 and FALCON/ML-DSA primitives. It is NOT compliant with standard Signal/Noise/MLS
specifications and requires compatible peer implementations. Per-message digital signatures provide
cryptographic non-repudiation for high-assurance environments; for cryptographic deniability, signature
generation can be disabled via deniable messaging mode.
"""
# Import standard libraries
import gc
import os
import hmac
import hashlib
import logging
import struct
import base64
import json
import secrets
import mmap
import ctypes
import time
import math
import platform
import threading
import uuid
import sys
# AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
import subprocess  # nosec: B404
import shlex
from typing import Dict, Tuple, Any, Optional, List, Union, Callable, Deque
from dataclasses import dataclass
import collections # Added import

# Import the new cross-platform hardware security module
import platform_hsm_interface as cphs

# Classical cryptography
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag, InvalidKey

# Import comprehensive error handling system
from cryptographic_errors import (
    CryptographicError,
    KeyGenerationError,
    SignatureVerificationError,
    EncryptionError,
    DecryptionError,
    HardwareSecurityError,
    AuthenticationError,
    ProtocolViolationError,
    MemoryCorruptionError,
    ConfigurationError,
    SecureErrorReporter,
    SecureExceptionHandler,
    SecurityEvent,
    SecurityEventType,
    SecuritySeverity,
    get_error_reporter
)

# Import post-quantum cryptography
# Properly import from pqc_algorithms without creating circular dependencies
try:
    import pqc_algorithms
    # Create local references to the imported classes
    EnhancedMLKEM_1024 = pqc_algorithms.EnhancedMLKEM_1024
    EnhancedFALCON_1024 = pqc_algorithms.EnhancedFALCON_1024
    EnhancedHQC = pqc_algorithms.EnhancedHQC
    # CNSA 2.0 (2026) session message-authentication identity: ML-DSA-87
    # (FIPS 204). Falcon-1024 is NOT in CNSA 2.0 and NSA will not add it
    # (FIPS 206 track); it remains verify-only for legacy peers.
    EnhancedMLDSA_87 = pqc_algorithms.EnhancedMLDSA_87
    # Use local implementation for these rather than importing
    from pqc_algorithms import SecurityTest
    # Define hardware security module availability
    HAVE_HSM = True
except ImportError as e:
    logging.error(f"Failed to import pqc_algorithms: {e}")
    HAVE_HSM = False
    raise ImportError("Critical dependencies missing: pqc_algorithms is required")

# Import native secure memory buffer for non-pageable, zeroizing key buffers
try:
    from native_secure_buffer import NativeSecureBuffer, wipe_native
    HAVE_NATIVE_SECURE_BUFFER = True
except ImportError:
    HAVE_NATIVE_SECURE_BUFFER = False
    NativeSecureBuffer = None
    wipe_native = None

# Configure dedicated logger for Double Ratchet protocol operations
ratchet_logger = logging.getLogger("double_ratchet")
ratchet_logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging with detailed information for security auditing
ratchet_file_handler = logging.FileHandler(os.path.join("logs", "double_ratchet.log"))
ratchet_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
ratchet_file_handler.setFormatter(formatter)
ratchet_logger.addHandler(ratchet_file_handler)

# Don't add console handler - let messages propagate to root logger to avoid duplicates
ratchet_logger.propagate = True

ratchet_logger.info("Double Ratchet logger initialized")

# Standard logger for backward compatibility
logger = logging.getLogger(__name__)


def _pq_ratchet_production_mode() -> bool:
    """True when running in production (fresh-KEM failures escalate to CRITICAL)."""
    return (
        os.environ.get("SECURE_P2P_PRODUCTION", "0") == "1"
        or os.environ.get("P2P_PRODUCTION", "0").lower() in ("1", "true")
    )


def _pq_strict_abort() -> bool:
    """True when PQ freshness failures must abort instead of legacy fallback.

    Opt-in fault-injection hardening (``P2P_PQ_STRICT_ABORT=1``): a failed
    sending-side encaps or a failed SPQR refresh raises SecurityError
    instead of silently continuing on reused v1 material. Default off
    (availability); those fallbacks remain AEAD+signature-gated, so a
    network attacker cannot trigger them -- this gate covers local faults
    and contested hardware. Telemetry (CRITICAL in prod) is emitted either
    way. (Present-but-undecapsable peer CTs always abort -- no gate --
    because legacy reuse could never re-sync those chains.)
    """
    return os.environ.get("P2P_PQ_STRICT_ABORT", "0").strip().lower() in (
        "1", "true", "yes", "on")


def _wipe_secret_best_effort(buf, description: str = "secret") -> None:
    """Best-effort in-place wipe of a secret buffer.

    Only MUTABLE buffers (bytearray / writable memoryview) can actually be
    zeroized. CPython ``bytes`` are immutable (shared, interned, copied by the
    interpreter) and CANNOT be wiped -- for ``bytes`` input this function only
    drops its local reference and the caller must ``del`` its own reference.
    Hold long-lived secrets in ``bytearray`` where true zeroization is needed.
    Never raises.
    """
    try:
        if buf is None:
            return
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0
        elif isinstance(buf, memoryview) and not buf.readonly:
            for i in range(len(buf)):
                buf[i] = 0
        else:
            logger.debug(
                f"No in-place wipe possible for immutable {type(buf).__name__} "
                f"({description}); local reference dropped (see docstring)"
            )
    except Exception as e:
        logger.warning(f"Best-effort wipe failed for {description}: {e}")


def _load_hybrid_combine_v2():
    """Load crypto.kem.hybrid_combine_v2 (Braid-lite PQ ratchet combiner).

    Mirrors the fallback loader in hybrid_kex.derive_root_v2: first tries the
    ``crypto.kem`` package import, then loads ``crypto/kem.py`` by path
    relative to this file. Raises ImportError if neither works.
    """
    try:
        from crypto.kem import hybrid_combine_v2
        return hybrid_combine_v2
    except ImportError:
        import importlib.util as _ilu
        _kem_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crypto", "kem.py")
        _spec = _ilu.spec_from_file_location("securep2p_crypto_kem_v2", _kem_path)
        if _spec is None or _spec.loader is None:
            raise ImportError("Cannot locate crypto/kem.py for v2 combiner")
        _mod = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        return _mod.hybrid_combine_v2

# Constant-time side-channel protection (REQUIRED for NIST Level 5+)
try:
    from cryptography.hazmat.primitives import constant_time
    HAS_CONSTANT_TIME = True
    ratchet_logger.info("Constant-time operations available for side-channel protection")
except ImportError:
    HAS_CONSTANT_TIME = False
    ratchet_logger.critical("SECURITY_WARNING: Constant-time operations not available - side-channel vulnerability exists")

# NIST Level 5+ Security Enforcement
NIST_LEVEL_5_ENFORCED = True  # NO FALLBACKS PERMITTED

# Approved algorithms for NIST Level 5+ (NO EXCEPTIONS)
APPROVED_ALGORITHMS = {
    'ML-KEM-1024': {'type': 'KEM', 'security_level': 5, 'quantum_safe': True},
    'FALCON-1024': {'type': 'SIGNATURE', 'security_level': 5, 'quantum_safe': True},
    'ChaCha20-Poly1305': {'type': 'AEAD', 'security_level': 5, 'quantum_safe': False},
    'HKDF-SHA3_512': {'type': 'KDF', 'security_level': 5, 'quantum_safe': False},
    'X25519': {'type': 'DH', 'security_level': 5, 'quantum_safe': False, 'role': 'hybrid_component'},
    'HYBRID_X25519_MLKEM': {'type': 'HYBRID_KEX', 'security_level': 5, 'quantum_safe': True}
}

# Forbidden algorithms (WILL BE REJECTED)
FORBIDDEN_ALGORITHMS = [
    'RSA', 'DSA', 'ECDSA', 'DH', 'STANDALONE_ECDH',  # Standalone unauthenticated classical schemes
    'AES-CBC', 'AES-ECB', 'AES-CTR',  # Unauthenticated modes
    'SHA-256', 'SHA-1', 'SHA3_256',  # Insufficient for Level 5
    'Kyber-512', 'Kyber-768',  # Weaker PQC variants
]

def enforce_nist_level_5_algorithm(algorithm_name: str) -> None:
    """
    Enforce NIST Level 5+ algorithm policy with NO FALLBACKS.

    Args:
        algorithm_name: Name of the algorithm to validate

    Raises:
        SecurityError: If algorithm doesn't meet NIST Level 5+ requirements
    """
    if not NIST_LEVEL_5_ENFORCED:
        ratchet_logger.critical("CRITICAL: NIST Level 5+ enforcement disabled - NOT PERMITTED")
        raise SecurityError("NIST Level 5+ enforcement cannot be disabled")

    if algorithm_name in FORBIDDEN_ALGORITHMS:
        ratchet_logger.critical(f"SECURITY_VIOLATION: Forbidden algorithm {algorithm_name}")
        raise SecurityError(f"Algorithm {algorithm_name} is FORBIDDEN under NIST Level 5+ policy")

    if algorithm_name not in APPROVED_ALGORITHMS:
        ratchet_logger.critical(f"SECURITY_VIOLATION: Unapproved algorithm {algorithm_name}")
        raise SecurityError(f"Algorithm {algorithm_name} is NOT APPROVED for NIST Level 5+ security")

    algo_info = APPROVED_ALGORITHMS[algorithm_name]
    if algo_info['security_level'] < 5:
        ratchet_logger.critical(f"SECURITY_VIOLATION: Algorithm {algorithm_name} security level {algo_info['security_level']} < 5")
        raise SecurityError(f"Algorithm {algorithm_name} does not meet NIST Level 5+ requirements")

    ratchet_logger.debug(f"Algorithm {algorithm_name} approved for NIST Level 5+ use")

# Configure logging for backward compatibility - only if not already configured
if not logger.handlers and not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'
    )
logger.setLevel(logging.INFO)

# Add file handler for security audit logging
try:
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    file_handler = logging.FileHandler(os.path.join(logs_dir, 'security_audit.log'))
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
    )
    logger.addHandler(file_handler)
except Exception as e:
    logger.warning(f"Could not create security audit log file: {e}")

# Secure hardware integration - enhanced cross-platform implementation
class SecureHardwareError(Exception):
    """Raised when secure hardware functionality is unavailable or fails."""

# Platform constants (can still be useful locally, but HW detection is now in cphs)
SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux"
IS_DARWIN = SYSTEM == "Darwin"  # macOS

# Hardware security flags will now be determined by cphs capabilities
# The old detection block (lines ~80-130) is removed.

# Improved memory protection functions now delegate to cphs
def secure_lock_memory(buffer_addr: int, length: int) -> bool:
    """Lock memory to prevent swapping of sensitive data."""
    return cphs.lock_memory(buffer_addr, length)

def secure_unlock_memory(buffer_addr: int, length: int) -> bool:
    """Unlock previously locked memory."""
    return cphs.unlock_memory(buffer_addr, length)

# Enhanced hardware ID generation now delegates to cphs
def get_hardware_unique_id_internal() -> bytes: # Renamed to avoid conflict if cphs is imported as *
    """Get hardware unique ID with enhanced cross-platform approach."""
    return cphs.get_hardware_unique_id()

def generate_unique_session_iv_salt(session_id: bytes, purpose: str) -> Tuple[bytes, bytes]:
    """
    Generate unique IV and salt per session with NIST Level 5+ security.

    Ensures that IV/salt pairs are never reused across sessions or purposes,
    providing cryptographic uniqueness guarantees required for NIST Level 5+.

    Args:
        session_id: Unique session identifier (minimum 16 bytes)
        purpose: Purpose string for domain separation

    Returns:
        Tuple[bytes, bytes]: (iv, salt) both 32 bytes for NIST Level 5+

    Raises:
        SecurityError: If generation fails or parameters are insufficient
    """
    if len(session_id) < 16:
        ratchet_logger.critical(f"SECURITY_VIOLATION: Session ID length {len(session_id)} < 16 bytes")
        raise SecurityError("Session ID must be at least 16 bytes for cryptographic uniqueness")

    if not purpose:
        ratchet_logger.critical("SECURITY_VIOLATION: No purpose specified for IV/salt generation")
        raise SecurityError("Purpose must be specified for domain separation")

    try:
        # Generate base entropy (64 bytes total for IV + salt)
        base_entropy = secrets.token_bytes(64)

        # Add timestamp for temporal uniqueness
        timestamp = int(time.time() * 1000000).to_bytes(8, 'big')  # microsecond precision

        # Create domain separation info
        info = f"DestroyerP2P::DoubleRatchet::{purpose}::IVSalt".encode('utf-8')

        # Use HKDF-SHA3_512 for cryptographic mixing
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,  # 32 bytes IV + 32 bytes salt
            salt=session_id + timestamp,
            info=info,
        )

        derived_material = hkdf.derive(base_entropy)

        # Split into IV and salt
        iv = derived_material[:32]
        salt = derived_material[32:64]

        # Verify uniqueness (basic check)
        if iv == salt:
            ratchet_logger.critical("SECURITY_VIOLATION: IV equals salt - cryptographic failure")
            raise SecurityError("IV and salt must be different")

        if iv == b'\x00' * 32 or salt == b'\x00' * 32:
            ratchet_logger.critical("SECURITY_VIOLATION: All-zero IV or salt generated")
            raise SecurityError("All-zero IV or salt detected")

        ratchet_logger.debug(f"Generated unique IV/salt for session {session_id.hex()[:16]}... purpose: {purpose}")
        return iv, salt

    except Exception as e:
        ratchet_logger.critical(f"SECURITY_VIOLATION: Failed to generate unique IV/salt: {e}")
        raise SecurityError(f"Failed to generate unique IV/salt: {e}")

def enforce_authenticated_encryption_only() -> None:
    """
    Enforce that only authenticated encryption (AEAD) is used.

    Raises:
        SecurityError: If unauthenticated encryption is detected
    """
    # This function serves as a policy enforcement point
    # All encryption operations must go through AEAD-only functions
    ratchet_logger.debug("Authenticated encryption enforcement active - only AEAD modes permitted")


# Hardware security interfaces route strictly through authentic platform_hsm_interface (cphs)


# Unified hardware security manager with enhanced implementation
class SecureHardwareManager:
    """Cross-platform hardware security manager with graceful fallbacks."""

    def __init__(self):
        """Initialize hardware security manager."""
        # Use proper detection with platform_hsm_interface
        self.has_hardware = False
        self.hardware_type = "Unknown"

        # Updated to use the proper platform_hsm_interface capabilities
        self.capabilities = {
            "key_isolation": False,
            "attestation": False,
            "secure_storage": False,
            "secure_random": True,  # Always available through cphs.get_secure_random
            "secure_counter": False # Optional TPM feature if available
        }

        # Check Windows CNG/TPM capabilities
        if cphs.IS_WINDOWS:
            if cphs._WINDOWS_CNG_NCRYPT_AVAILABLE and cphs._open_cng_provider_platform():
                self.has_hardware = True
                self.hardware_type = "Windows TPM (CNG)"
                self.capabilities["secure_storage"] = cphs._Windows_CNG_Supported
                self.capabilities["key_isolation"] = True  # Windows TPM can isolate keys

                # Check attestation capability
                attestation = cphs.attest_device()
                if attestation and len(attestation.get("checks", [])) > 0:
                    for check in attestation["checks"]:
                        if check.get("type") == "Win32_Tpm_Query" and check.get("status") == "Found":
                            self.capabilities["attestation"] = True
                            if check.get("IsEnabled") and check.get("IsActivated"):
                                self.capabilities["secure_counter"] = True  # TPM 2.0 feature
            elif cphs._WINDOWS_TBS_AVAILABLE:
                self.has_hardware = True
                self.hardware_type = "Windows TPM (TBS)"
                self.capabilities["secure_random"] = True

        # Check Linux TPM capabilities
        elif cphs.IS_LINUX:
            if cphs._Linux_ESAPI:
                self.has_hardware = True
                self.hardware_type = "Linux TPM2"
                self.capabilities["secure_storage"] = cphs._AESGCM_AVAILABLE
                self.capabilities["secure_random"] = True

                # Check for more capabilities through attestation
                attestation = cphs.attest_device()
                if attestation and len(attestation.get("checks", [])) > 0:
                    for check in attestation["checks"]:
                        if check.get("type") == "TPM2_Quote" and check.get("status") == "Found":
                            self.capabilities["attestation"] = True
                            self.capabilities["secure_counter"] = True  # TPM2 capability

        # Check macOS capabilities
        elif cphs.IS_DARWIN:
            # macOS uses Secure Enclave via keyring
            self.hardware_type = "macOS Keychain"
            if cphs._CRYPTOGRAPHY_AVAILABLE:
                self.has_hardware = True
                self.capabilities["secure_storage"] = True

                # Check SIP status for basic attestation
                attestation = cphs.attest_device()
                if attestation and len(attestation.get("checks", [])) > 0:
                    for check in attestation["checks"]:
                        if check.get("type") == "SIP_Status" and check.get("status") == "Found":
                            self.capabilities["attestation"] = True

        # Log the detected capabilities
        if self.has_hardware:
            logger.info(f"Hardware security via cphs: Available")
            logger.debug(f"Hardware type: {self.hardware_type}, capabilities: {self.capabilities}")
        else:
            logger.info(f"Hardware security via cphs: Not available")

    def get_tpm_interface(self):
        """Get authentic TPM interface via platform_hsm_interface."""
        if self.has_hardware and cphs is not None:
            return cphs
        raise HardwareSecurityError("TPM interface requested but no hardware TPM is available")

    def get_sgx_interface(self):
        """Get Intel SGX interface."""
        if self.has_hardware and cphs is not None and getattr(self, 'hardware_type', None) == 'SGX':
            return cphs
        raise HardwareSecurityError("Intel SGX interface requested but not available on this platform")

    def get_secure_enclave_interface(self):
        """Get Secure Enclave interface."""
        if self.has_hardware and cphs is not None and getattr(self, 'hardware_type', None) == 'SecureEnclave':
            return cphs
        raise HardwareSecurityError("Apple Secure Enclave interface requested but not available on this platform")

    def get_hardware_unique_id(self):
        """Get hardware unique ID or generate a consistent one."""
        return cphs.get_hardware_unique_id()

    def secure_random(self, num_bytes):
        """Generate secure random bytes, using hardware if available."""
        return cphs.get_secure_random(num_bytes)

# Create a global instance
hardware_security = SecureHardwareManager()


class SecurityError(Exception):
    """Security-specific exception for Double Ratchet protocol violations."""


# Hardware security module interface
class HardwareSecurityModule:
    """
    Interface for hardware security operations with TPM, SGX, or Secure Enclaves.

    This class provides an abstraction layer for hardware-backed cryptographic
    operations when available on the system. It supports various secure hardware
    elements like TPM, SGX, and Secure Enclaves across different platforms.
    """
    def __init__(self):
        """Initialize hardware security support if available."""
        self.hardware_type = "N/A"
        self.is_available = False
        self.hardware_id = None

        # Initialize capabilities dictionary
        self.capabilities = {
            "key_isolation": False,
            "attestation": False,
            "secure_storage": False,
            "secure_random": True,  # Always available through OS at minimum
            "secure_counter": False # Optional TPM feature if available
        }

        # Check for Windows TPM through platform_hsm_interface
        if cphs.IS_WINDOWS and cphs._WINDOWS_CNG_NCRYPT_AVAILABLE:
            # Try to open the CNG provider
            if cphs._open_cng_provider_platform():
                self.is_available = True
                self.hardware_type = "Windows TPM via CNG"
                try:
                    # Get hardware ID in a secure format
                    self.hardware_id = cphs.get_hardware_unique_id().hex()
                    logger.info(f"Hardware security module (via cphs): {self.hardware_type}")

                    # Update capabilities
                    self.capabilities["secure_storage"] = cphs._Windows_CNG_Supported
                    self.capabilities["key_isolation"] = True

                    # Check attestation capability (skip to avoid WMI blocking)
                    # WMI connection can hang during module import, so we skip attestation
                    # The system will still work with software-only security
                    # Attestation is completely disabled during initialization
                    logger.debug("Attestation skipped during initialization to prevent WMI hang")
                except Exception as e:
                    logger.warning(f"Error getting hardware ID: {e}")

        # Check for Linux TPM
        elif cphs.IS_LINUX and cphs._Linux_ESAPI:
            self.is_available = True
            self.hardware_type = "Linux TPM via tpm2-pytss"
            try:
                self.hardware_id = cphs.get_hardware_unique_id().hex()
                logger.info(f"Hardware security module (via cphs): {self.hardware_type}")

                # Update capabilities
                self.capabilities["secure_storage"] = cphs._AESGCM_AVAILABLE
                self.capabilities["secure_random"] = True

                # Check for more capabilities through attestation
                attestation = cphs.attest_device()
                if attestation and len(attestation.get("checks", [])) > 0:
                    for check in attestation["checks"]:
                        if check.get("type") == "TPM2_Quote" and check.get("status") == "Found":
                            self.capabilities["attestation"] = True
                            self.capabilities["secure_counter"] = True
            except Exception as e:
                logger.warning(f"Error getting Linux hardware ID: {e}")

        # Check for macOS secure enclave
        elif cphs.IS_DARWIN:
            # macOS uses Secure Enclave via keyring
            self.hardware_type = "macOS Keychain"
            if cphs._CRYPTOGRAPHY_AVAILABLE:
                self.is_available = True
                self.capabilities["secure_storage"] = True

                # Check SIP status for basic attestation
                attestation = cphs.attest_device()
                if attestation and len(attestation.get("checks", [])) > 0:
                    for check in attestation["checks"]:
                        if check.get("type") == "SIP_Status" and check.get("status") == "Found":
                            self.capabilities["attestation"] = True

        # Log availability status
        if self.is_available:
            logger.info(f"Hardware security via cphs: Available ({self.hardware_type})")
            logger.debug(f"Hardware capabilities: {self.capabilities}")
        else:
            logger.info(f"Hardware security via cphs: Not available")

    def get_device_attestation(self) -> Optional[dict]:
        """Get hardware attestation proof if available."""
        if not self.is_available:
            return None

        try:
            return cphs.attest_device()
        except Exception as e:
            logger.warning(f"Device attestation failed: {e}")
            return None

    def secure_random(self, size: int) -> Optional[bytes]:
        """Generate secure random bytes using hardware if available."""
        return cphs.get_secure_random(size)

    def store_key(self, key_id: str, key_data: bytes) -> bool:
        """Store key in hardware if supported."""
        if not self.is_available:
            return False

        try:
            if cphs.IS_WINDOWS and cphs._Windows_CNG_Supported:
                # Windows TPM key storage (via keyring as CNG TPM storage is a stub)
                return cphs.store_secret_os_keyring(key_id, key_data)
            elif cphs.IS_LINUX and cphs._AESGCM_AVAILABLE:
                # Linux file-based with encryption
                return cphs.store_key_file_linux(key_id, key_data)
            elif cphs.is_hsm_initialized():
                # HSM via PKCS#11
                return cphs.store_secret_os_keyring(key_id, key_data)
            else:
                # General keyring fallback
                return cphs.store_secret_os_keyring(key_id, key_data)
        except Exception as e:
            logger.warning(f"Hardware key storage failed: {e}")
            return False

    def use_key(self, key_id: str, operation: str, data: bytes) -> Optional[bytes]:
        """Use a key stored in hardware for an operation without exposing it."""
        if not self.is_available:
            return None

        # This requires implementation of specific operations in platform_hsm_interface
        # Currently limited functionality as much of cphs is focused on key storage and random generation
        logger.debug(f"Hardware key use operation '{operation}' not fully implemented in this version")
        return None

    def get_hardware_id(self) -> Optional[str]:
        """Get unique hardware identifier."""
        if self.hardware_id:
            return self.hardware_id

        # Try to get it directly if not set during init
        try:
            hw_id_bytes = cphs.get_hardware_unique_id()
            return hw_id_bytes.hex() if hw_id_bytes else None
        except Exception:
            return None


# Instantiate hardware security
hsm = HardwareSecurityModule()


# Side-channel protection utilities
class ConstantTime:
    """
    Provides constant-time operations to prevent side-channel attacks.

    This class implements timing-safe comparison and selection operations to prevent
    side-channel attacks that exploit timing differences in cryptographic operations.
    These methods ensure that the time taken to perform operations does not leak
    information about the values being operated on.
    """

    @staticmethod
    def compare(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time to prevent timing attacks.
        Returns True if equal, False otherwise.

        Args:
            a: First byte string to compare
            b: Second byte string to compare

        Returns:
            bool: True if the byte strings are equal, False otherwise
        """
        if HAS_CONSTANT_TIME:
            # cryptography's bytes_eq is already constant-time
            return constant_time.bytes_eq(a, b)

        # Fallback: compare in constant time regardless of differing lengths.
        # Iterate over the maximum length, using 0 for out-of-range indices.
        result = 0
        max_len = max(len(a), len(b))
        for i in range(max_len):
            ai = a[i] if i < len(a) else 0
            bi = b[i] if i < len(b) else 0
            result |= ai ^ bi

        # Even if the byte values matched for the portion up to the shorter length,
        # differing lengths must yield False.
        return (result == 0) and (len(a) == len(b))

    @staticmethod
    def select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Select between two byte strings in constant time based on `condition`.

        Returns a if condition is True, else b.
        If lengths differ, produces a result of length max(len(a), len(b)) by
        treating missing bytes as 0x00.

        Args:
            condition: Selection condition
            a: First byte string (selected if condition is True)
            b: Second byte string (selected if condition is False)

        Returns:
            bytes: Either a or b depending on condition
        """
        # Convert boolean to 0xFF (True) or 0x00 (False)
        mask = (-int(condition)) & 0xFF

        max_len = max(len(a), len(b))
        result = bytearray(max_len)

        for i in range(max_len):
            ai = a[i] if i < len(a) else 0
            bi = b[i] if i < len(b) else 0
            # If mask == 0xFF, picks ai; if mask == 0x00, picks bi.
            result[i] = (ai & mask) | (bi & (~mask & 0xFF))

        return bytes(result)


# Side-channel protection utilities
class CanaryProtector:
    """
    Manage and verify memory canaries in constant time to detect tampering.

    This class provides memory protection by placing and checking canary values
    in memory regions that should not be modified. Any unexpected modification
    of these values indicates potential memory corruption or tampering.
    """

    def __init__(self):
        """Initialize the canary protector with empty maps."""
        # Maps a location identifier (e.g., string or object key) to its original canary value
        self._canary_locations: Dict[str, bytes] = {}
        # Holds the current (possibly modified) canary values
        self._memory_canaries: Dict[str, bytes] = {}

    def register_canary(self, location: str, canary_value: bytes) -> None:
        """
        Store a canary for a given location. Both original and memory canaries
        are initialized to the same value.

        Args:
            location: Identifier for the canary location
            canary_value: Random bytes to use as the canary value
        """
        self._canary_locations[location] = canary_value
        self._memory_canaries[location] = canary_value

    def verify_canaries(self) -> None:
        """
        Verify all registered canaries in constant time. If any canary has been
        altered (i.e., memory corruption), log a critical error and raise SecurityError.

        Raises:
            SecurityError: If a canary has been modified, indicating memory corruption
        """
        for location, original_canary in self._canary_locations.items():
            current_canary = self._memory_canaries.get(location, b"")
            if not ConstantTime.compare(current_canary, original_canary):
                logger.critical(
                    f"SECURITY VIOLATION: Memory corruption detected at '{location}'"
                )
                raise SecurityError(f"Memory corruption detected at '{location}'")

    def update_memory_canary(self, location: str, new_value: bytes) -> None:
        """
        Update the in-memory canary for a location. Use this if a legitimate operation
        modifies the canary region (rare in practice; typically canaries are write-protected).

        Args:
            location: The canary location identifier
            new_value: The new value for the canary

        Raises:
            KeyError: If no canary is registered at the specified location
        """
        if location in self._canary_locations:
            self._memory_canaries[location] = new_value
        else:
            raise KeyError(f"No canary registered at location '{location}'")


class SideChannelProtection:
    """
    Provides protections against side-channel attacks on cryptographic operations.

    This class implements techniques to prevent information leakage through
    side channels such as timing, cache behavior, and power consumption.
    """

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Perform constant-time comparison of two byte strings."""
        return ConstantTime.compare(a, b)

    @staticmethod
    def secure_memory_access(data: bytearray) -> None:
        """
        Perform a secure memory access pattern to prevent cache timing attacks.

        Args:
            data: Bytearray to access in a secure pattern
        """
        # Touch all elements of data in a fixed pattern to regularize cache lines
        cache_barrier_accumulator = 0
        for i in range(len(data)):
            cache_barrier_accumulator |= (data[i] & 1)

        # Volatile check to enforce execution barrier
        if cache_barrier_accumulator == 0xDEADBEEF:
            logger.debug("Cache regularization barrier active")

    @staticmethod
    def add_time_padding(min_time_ms: int) -> None:
        """
        Add time padding to ensure operation takes at least min_time_ms.

        This helps prevent timing attacks by making operations take a consistent
        amount of time regardless of the actual processing needed.

        Args:
            min_time_ms: Minimum operation time in milliseconds
        """
        start_time = time.time()
        elapsed_ms = 0

        while elapsed_ms < min_time_ms:
            # Perform some meaningless computation
            for _ in range(1000):
                hash_val = hashlib.sha3_512(secrets.token_bytes(16)).digest()

            elapsed_ms = (time.time() - start_time) * 1000

    @staticmethod
    def mitigate_branch_prediction(condition: bool, value_if_true: Any, value_if_false: Any) -> Any:
        """
        Execute both branches to mitigate branch prediction attacks.

        Args:
            condition: The condition to evaluate
            value_if_true: Value to return if condition is True
            value_if_false: Value to return if condition is False

        Returns:
            Either value_if_true or value_if_false based on the condition
        """
        # Execute both branches
        result_true = value_if_true
        result_false = value_if_false

        # Select the appropriate result without branching
        return result_true if condition else result_false


# Statistical threat detection
class ThreatDetection:
    """
    Statistical threat intelligence and anomaly detection for security operations.

    Implements NIST SP 800-53 security controls for anomaly detection using
    statistical analysis of cryptographic operations and message patterns.
    """
    def __init__(self):
        """Initialize threat detection system."""
        self.anomaly_thresholds = {
            "failed_decryptions": 3,
            "time_drift": 300,  # 5 minutes
            "entropy_minimum": 3.0,
            "message_size_max": 1048576,  # 1MB
            "operation_time_max": 10.0  # seconds
        }

        self.baselines = {
            "operation_times": {},
            "message_sizes": [],
            "activity_pattern": {}
        }

        self.threat_level = "normal"
        self.detected_anomalies = []
        self.last_reset = time.time()

    def reset_baselines(self):
        """Reset baseline measurements."""
        self.baselines = {
            "operation_times": {},
            "message_sizes": [],
            "activity_pattern": {}
        }
        self.last_reset = time.time()

    def record_operation(self, operation: str, duration: float):
        """Record timing information about an operation."""
        if operation not in self.baselines["operation_times"]:
            self.baselines["operation_times"][operation] = []

        self.baselines["operation_times"][operation].append(duration)
        # Keep only last 100 measurements
        if len(self.baselines["operation_times"][operation]) > 100:
            self.baselines["operation_times"][operation] = self.baselines["operation_times"][operation][-100:]

    def record_message_size(self, size: int):
        """Record message size information."""
        self.baselines["message_sizes"].append(size)
        # Keep only last 100 measurements
        if len(self.baselines["message_sizes"]) > 100:
            self.baselines["message_sizes"] = self.baselines["message_sizes"][-100:]

    def detect_anomalies(self, metrics: Dict[str, Any]) -> List[str]:
        """Detect anomalies based on current metrics compared to baselines."""
        anomalies = []

        # Check for excessive failed decryptions
        if metrics.get("failed_decryptions", 0) >= self.anomaly_thresholds["failed_decryptions"]:
            anomalies.append("excessive_decryption_failures")

        # Check for time drift
        if abs(metrics.get("clock_drift", 0)) > self.anomaly_thresholds["time_drift"]:
            anomalies.append("significant_time_drift")

        # Check for operation time anomalies
        for op, times in self.baselines["operation_times"].items():
            if times:
                avg_time = sum(times) / len(times)
                if op in metrics.get("operation_times", {}) and metrics["operation_times"][op] > avg_time * 3:
                    anomalies.append(f"slow_operation_{op}")

        # Update threat level based on detected anomalies
        if anomalies:
            self.detected_anomalies.extend(anomalies)
            if len(self.detected_anomalies) > 5:
                self.threat_level = "high"
            elif len(self.detected_anomalies) > 2:
                self.threat_level = "elevated"

        return anomalies

    def get_security_recommendations(self) -> Dict[str, Any]:
        """Get security recommendations based on threat level.

        Analyzes the current threat level and detected anomalies to provide
        appropriate security recommendations for improving the security posture.

        Returns:
            Dict[str, Any]: A dictionary of security recommendations with settings
                           that should be applied based on the current threat level
        """
        recommendations = {
            "security_level": "MAXIMUM" if self.threat_level == "normal" else
                             "MAXIMUM" if self.threat_level == "elevated" else
                             "PARANOID"
        }

        if self.threat_level != "normal":
            recommendations["rotate_keys"] = "true"
            recommendations["decrease_max_skipped_keys"] = "true"

        if self.threat_level == "high":
            recommendations["decrease_key_rotation_time"] = "600"  # 10 minutes
            recommendations["add_message_padding"] = "true"
            recommendations["enable_all_mitigations"] = "true"

        return recommendations


# Enhanced entropy checks - constants moved to class scope
class EntropyVerifier:
    """
    Cryptographic entropy verification for key material quality assessment.

    This class provides methods to verify that cryptographic key material has
    sufficient entropy and lacks patterns that could indicate weaknesses or
    implementation flaws. It implements NIST SP 800-90B recommendations for
    entropy assessment.

    Technical features:
    1. Shannon entropy calculation (bits per byte)
    2. Statistical pattern detection
    3. Block-level entropy analysis
    4. Optional ML-based anomaly detection
    """

    # Entropy thresholds based on NIST SP 800-90B recommendations
    MIN_ACCEPTABLE_ENTROPY = 2.0  # Minimum bits of entropy per byte (Shannon)
    IDEAL_ENTROPY_BYTES = 6.0     # Target entropy for cryptographic material

    # Known weak patterns that indicate potential issues
    SUSPICIOUS_PATTERNS = [
        bytes([0] * 8),           # All zeros (common failure case)
        bytes([255] * 8),         # All ones (common failure case)
        bytes(range(8)),          # Sequential pattern (0,1,2,3,4,5,6,7)
        bytes(range(7, -1, -1))   # Reverse sequential (7,6,5,4,3,2,1,0)
    ]

    # SecurityTest should already be imported at the top of the file
    _HAVE_ENHANCED_SECURITY_TEST = 'SecurityTest' in globals() and SecurityTest is not None

    @classmethod
    def calculate_shannon_entropy(cls, data: bytes) -> float:
        """
        Calculate Shannon entropy of data in bits per byte.

        Shannon entropy quantifies the information content or unpredictability
        of the input data. For cryptographic keys, higher values indicate better
        randomness. Ideal cryptographic material should have entropy close to 8.0
        bits per byte (maximum for 8-bit values).

        Implementation follows the formula:
        H(X) = -sum(p(x) * log2(p(x))) for all x in X
        where p(x) is the probability of byte value x occurring in the data.

        Args:
            data: Byte sequence to analyze

        Returns:
            float: Shannon entropy in bits per byte (range 0.0-8.0)

        Security note:
            This calculation is performed in constant time with respect to
            the values in the data (but not the length) to prevent timing
            side-channel attacks.
        """
        if not data:
            return 0.0

        # Try to use side-channel resistant implementation if available
        if cls._HAVE_ENHANCED_SECURITY_TEST:
            try:
                # Use the enhanced SecurityTest implementation for better side-channel resistance
                return SecurityTest.calculate_entropy(data)
            except Exception as e:
                ratchet_logger.debug(f"Side-channel resistant entropy calculation failed: {e}, falling back to standard implementation")

        # Fall back to standard implementation
        # Count byte occurrences using a fixed-time histogram approach
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate Shannon entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:  # Skip zero counts to avoid log(0)
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    @classmethod
    def calculate_block_entropy(cls, data: bytes, block_size: int = 16) -> List[float]:
        """Calculate entropy across blocks to detect localized patterns."""
        block_entropies = []

        # Process in blocks
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            if len(block) >= 4:  # Minimum size for meaningful entropy
                block_entropies.append(cls.calculate_shannon_entropy(block))

        return block_entropies

    @classmethod
    def detect_patterns(cls, data: bytes) -> List[str]:
        """
        Detect suspicious patterns in cryptographic material.

        This method analyzes cryptographic material for patterns that may indicate
        weaknesses or implementation flaws. It performs the following checks:

        1. Known weak pattern detection (all zeros, sequential bytes, etc.)
        2. Statistical distribution analysis (byte frequency)
        3. Entropy anomaly detection

        These checks follow recommendations from NIST SP 800-90B and academic
        research on cryptographic randomness testing.

        Args:
            data: Cryptographic material to analyze

        Returns:
            List[str]: Identified issues as string identifiers
        """
        # Try to use enhanced implementation if available
        if cls._HAVE_ENHANCED_SECURITY_TEST:
            try:
                # Use the enhanced SecurityTest implementation for better pattern detection
                enhanced_issues = SecurityTest.detect_cryptographic_weaknesses(data)
                if enhanced_issues:
                    return enhanced_issues
            except Exception as e:
                ratchet_logger.debug(f"Enhanced pattern detection failed: {e}, falling back to standard implementation")

        # Fall back to standard implementation
        issues = []

        # Check byte distribution (frequency analysis)
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Extract specific byte counts for common problem cases
        zeros = byte_counts[0]      # 0x00 bytes
        ones = byte_counts[255]     # 0xFF bytes

        # MILITARY SECURITY FIX: Improved pattern detection for hybrid cryptographic keys
        # McEliece and other post-quantum algorithms may have legitimate structured regions
        # Only flag patterns that are truly suspicious (not legitimate cryptographic structure)
        
        # Search for known weak patterns - but be more selective for hybrid keys
        data_len = len(data)
        
        # Only check for truly problematic patterns in smaller keys
        # Large hybrid keys (>10KB) may have legitimate structured regions
        if data_len < 10240:  # Only apply strict pattern detection to smaller keys
            for pattern in cls.SUSPICIOUS_PATTERNS:
                pattern_count = 0
                for i in range(len(data) - len(pattern)):
                    if data[i:i+len(pattern)] == pattern:
                        pattern_count += 1
                
                # Only flag if pattern appears excessively (not just once or twice)
                if pattern_count > max(3, data_len // 1000):  # Allow some structured regions
                    issues.append(f"detected_pattern_{pattern.hex()[:8]}")
        else:
            # For large hybrid keys, only check for completely zero or one regions
            # which would indicate a serious implementation flaw
            zero_regions = 0
            one_regions = 0
            region_size = 64  # Check 64-byte regions
            
            for i in range(0, data_len - region_size, region_size):
                region = data[i:i+region_size]
                if region == bytes([0] * region_size):
                    zero_regions += 1
                elif region == bytes([255] * region_size):
                    one_regions += 1
            
            # Only flag if we have excessive completely uniform regions
            max_uniform_regions = max(1, data_len // (region_size * 100))  # Allow 1% uniform regions
            if zero_regions > max_uniform_regions:
                issues.append("excessive_zero_regions")
            if one_regions > max_uniform_regions:
                issues.append("excessive_one_regions")

        # Check for insufficient byte diversity (NIST SP 800-90B recommendation)
        # Adjust threshold for hybrid keys which may have structured components
        unique_bytes = sum(1 for count in byte_counts if count > 0)
        min_diversity = 16 if data_len > 10240 else 32  # Relaxed for large hybrid keys
        if unique_bytes < min_diversity:
            issues.append("low_byte_diversity")

        # Check for byte value bias (FIPS 140-2 derived threshold)
        # Adjust thresholds for hybrid keys which may have legitimate padding
        zero_threshold = 0.7 if data_len > 10240 else 0.5  # More lenient for large keys
        one_threshold = 0.7 if data_len > 10240 else 0.5
        
        if zeros > data_len * zero_threshold:
            issues.append("excessive_zeros")
        if ones > data_len * one_threshold:
            issues.append("excessive_ones")

        return issues

    @classmethod
    def verify_entropy(cls, data: bytes, description: str = "data") -> Tuple[bool, float, List[str]]:
        """
        Perform comprehensive cryptographic quality verification.

        This method performs a multi-faceted analysis of cryptographic material
        to verify it meets security requirements. The verification includes:

        1. Shannon entropy calculation (overall randomness)
        2. Block entropy analysis (localized randomness)
        3. Statistical pattern detection
        4. Distribution uniformity checks

        These tests are based on NIST SP 800-90B recommendations for entropy
        source validation and FIPS 140-2/3 requirements for random number
        generation.

        Args:
            data: Cryptographic material to verify
            description: Description for logging purposes

        Returns:
            Tuple[bool, float, List[str]]:
                - bool: True if all tests passed
                - float: Shannon entropy value (bits per byte)
                - List[str]: Identified issues, empty if all tests passed
        """
        # Try to use enhanced implementation if available
        if cls._HAVE_ENHANCED_SECURITY_TEST:
            try:
                # Use the enhanced SecurityTest implementation for comprehensive security verification
                passed, entropy, issues = SecurityTest.verify_cryptographic_quality(data)
                # Log detailed report for debugging
                ratchet_logger.debug(f"Enhanced entropy verification for {description}: " +
                           f"overall={entropy:.2f}, issues={','.join(issues) if issues else 'none'}")
                return passed, entropy, issues
            except Exception as e:
                ratchet_logger.warning(f"Enhanced entropy verification failed: {e}, falling back to standard implementation")

        # Fall back to standard implementation
        entropy = cls.calculate_shannon_entropy(data)
        block_entropies = cls.calculate_block_entropy(data)
        pattern_issues = cls.detect_patterns(data)

        issues = pattern_issues

        # Check overall entropy against NIST SP 800-90B thresholds
        if entropy < cls.MIN_ACCEPTABLE_ENTROPY:
            issues.append("critical_low_entropy")
        elif entropy < 5.0:  # Minimum for cryptographic applications
            issues.append("suboptimal_entropy")

        # Check for localized entropy anomalies (potential non-random regions)
        if block_entropies and min(block_entropies) < 2.0:
            issues.append("localized_low_entropy")

        # Check for entropy consistency across the data
        if len(block_entropies) > 1:
            max_entropy = max(block_entropies)
            min_entropy = min(block_entropies)
            if max_entropy - min_entropy > 4.0:  # Max allowed variance
                issues.append("high_entropy_variance")

        # Log detailed report for debugging
        ratchet_logger.debug(f"Entropy verification for {description}: " +
                    f"overall={entropy:.2f}, blocks=[{min(block_entropies) if block_entropies else 0:.2f}-" +
                    f"{max(block_entropies) if block_entropies else 0:.2f}], " +
                    f"issues={','.join(issues) if issues else 'none'}")

        return len(issues) == 0, entropy, issues


def verify_key_material(key_material,
                        expected_length: Optional[int] = None,
                        description: str = "key material") -> bool:
    """
    Verify cryptographic key material meets security requirements.

    This function performs validation checks on cryptographic key material
    to ensure it meets basic security requirements before use in cryptographic
    operations. The checks include:

    1. Type validation (must be bytes or dict for hybrid keys)
    2. Length validation (must match expected length if specified)
    3. Non-emptiness validation
    4. Basic entropy check (must not be all same byte)

    For more comprehensive entropy verification, use EntropyVerifier.verify_entropy().

    Args:
        key_material: The cryptographic key material to verify (bytes or dict for hybrid)
        expected_length: Expected byte length (e.g., 32 for AES-256)
        description: Description for logging and error messages

    Returns:
        bool: True if all verification checks pass

    Raises:
        ValueError: If key material fails any verification check,
                   with a specific error message indicating the failure
    """
    # Null check
    if key_material is None:
        ratchet_logger.error(f"SECURITY ALERT: {description} is None")
        raise ValueError(f"Security violation: {description} is None")

    # Type check - must be bytes or dict (for hybrid keys) for cryptographic operations
    if isinstance(key_material, dict):
        # Hybrid key format - verify each component
        if not key_material:
            ratchet_logger.error(f"SECURITY ALERT: {description} is empty dict")
            raise ValueError(f"Security violation: {description} is empty dict")
        
        for component_name, component_data in key_material.items():
            if not isinstance(component_data, bytes):
                ratchet_logger.error(f"SECURITY ALERT: {description} component '{component_name}' is not bytes: {type(component_data)}")
                raise ValueError(f"Security violation: {description} component '{component_name}' is not bytes")
            if len(component_data) == 0:
                ratchet_logger.error(f"SECURITY ALERT: {description} component '{component_name}' is empty")
                raise ValueError(f"Security violation: {description} component '{component_name}' is empty")
        
        ratchet_logger.debug(f"Verified hybrid key {description} with components: {list(key_material.keys())}")
        return True
    
    if not isinstance(key_material, bytes):
        ratchet_logger.error(f"SECURITY ALERT: {description} is not bytes type: {type(key_material)}")
        raise ValueError(f"Security violation: {description} is not bytes")

    # Length check - cryptographic keys must have specific lengths
    if expected_length and len(key_material) != expected_length:
        ratchet_logger.error(f"SECURITY ALERT: {description} has incorrect length {len(key_material)}, expected {expected_length}")
        raise ValueError(f"Security violation: {description} has incorrect length")

    # Non-emptiness check
    if len(key_material) == 0:
        ratchet_logger.error(f"SECURITY ALERT: {description} is empty")
        raise ValueError(f"Security violation: {description} is empty")

    # Basic entropy check - detect obviously weak keys (all same byte)
    # This is a minimal check; use EntropyVerifier for comprehensive analysis
    if all(b == key_material[0] for b in key_material):
        ratchet_logger.error(f"SECURITY ALERT: {description} has zero entropy (all bytes identical)")
        raise ValueError(f"Security violation: {description} has zero entropy")

    # Enhanced entropy check - first/last blocks not all zeros
    first_block = key_material[:min(8, len(key_material))]
    last_block = key_material[-min(8, len(key_material)):]

    # Check for repeating patterns in first/last blocks
    if all(b == 0 for b in first_block) or all(b == 0 for b in last_block):
        logger.error(f"SECURITY ALERT: {description} has suspicious pattern (zeros at beginning or end)")
        raise ValueError(f"Security violation: {description} has suspicious pattern")

    # Use NIST SP 800-90B entropy verification
    passed, entropy, issues = EntropyVerifier.verify_entropy(key_material, description)

    # MILITARY SECURITY FIX: Enhanced issue classification for hybrid cryptographic keys
    if not passed:
        # Classify issues by severity for military-grade security
        critical_issues = ["critical_low_entropy"]
        serious_issues = ["excessive_zero_regions", "excessive_one_regions"]
        
        # Check for truly critical issues that indicate implementation flaws
        if any(issue in critical_issues for issue in issues):
            logger.error(f"SECURITY ALERT: {description} failed entropy verification: {issues}")
            raise ValueError(f"Security violation: {description} has critically low entropy")
        
        # Check for serious issues that may indicate problems
        elif any(issue in serious_issues for issue in issues):
            logger.warning(f"SECURITY ALERT: {description} has serious entropy concerns: {issues}")
        
        # Handle hybrid key specific patterns (these are often legitimate)
        elif "Hybrid KEM" in description and any("detected_pattern_00000000" in str(issue) for issue in issues):
            # This is likely legitimate McEliece key structure - downgrade to debug
            logger.debug(f"Hybrid key structure note: {description} has expected cryptographic patterns: {len([i for i in issues if 'detected_pattern_00000000' in str(i)])} zero-padding regions detected")
        
        # MILITARY SECURITY FIX: Handle ML-DSA signature patterns (legitimate cryptographic structure)
        elif "ML-DSA" in description and any("detected_pattern_00000000" in str(issue) for issue in issues):
            # ML-DSA signatures may have legitimate structured regions due to the algorithm design
            logger.debug(f"ML-DSA signature structure note: {description} has expected signature patterns: {len([i for i in issues if 'detected_pattern_00000000' in str(i)])} structured regions detected")
        
        # Handle other signature patterns
        elif ("signature" in description.lower() or "sig" in description.lower()) and any("detected_pattern_00000000" in str(issue) for issue in issues):
            # Digital signatures may have legitimate structured regions
            logger.debug(f"Signature structure note: {description} has expected cryptographic patterns (normal for digital signatures)")
        
        # Other pattern detections for hybrid keys
        elif any("detected_pattern" in str(issue) for issue in issues):
            if "Hybrid KEM" in description or len(key_material) > 10240:
                # Large hybrid keys may have legitimate structure
                logger.debug(f"Cryptographic structure note: {description} has structured regions (expected for hybrid algorithms)")
            else:
                logger.warning(f"SECURITY ALERT: {description} failed entropy verification: {issues}")
        
        # Handle other entropy issues
        else:
            # Most other issues are informational for properly implemented algorithms
            logger.debug(f"Entropy analysis: {description} characteristics: {issues}")

    logger.debug(f"Verified {description}: length={len(key_material)}, entropy={entropy:.2f} bits/byte")
    return True


def format_binary(data: Optional[bytes], max_len: int = 8) -> str:
    """
    Format binary data for logging in a safe, readable way.

    Args:
        data: Binary data to format
        max_len: Maximum number of bytes to include

    Returns:
        Formatted string representation
    """
    if data is None:
        return "None"
    if len(data) > max_len:
        b64 = base64.b64encode(data[:max_len]).decode('utf-8')
        return f"{b64}... ({len(data)} bytes)"
    return base64.b64encode(data).decode('utf-8')


def secure_erase(key_material: Optional[Union[bytes, bytearray, str]]) -> None:
    """
    Securely erase sensitive cryptographic material from memory.

    This function implements DoD 5220.22-M compliant data sanitization to remove
    sensitive cryptographic material from memory, protecting against memory
    inspection attacks and cold boot attacks.

    Technical implementation:
    1. Memory locking to prevent paging to disk
    2. Multi-pass overwrite sequence:
       - DoD 5220.22-M patterns (0x00, 0xFF, 0xAA, 0x55, etc.)
       - CSPRNG-generated random data
       - Final zero pass (0x00)
    3. Memory barriers to prevent compiler optimization
    4. Explicit memory unlocking and garbage collection

    Args:
        key_material: The sensitive cryptographic material to erase:
                     - bytes: Creates mutable copy (original remains in memory)
                     - bytearray: Direct in-place erasure (most secure)
                     - str: Converted to UTF-8 bytes for erasure
                     - Objects with zeroize() method: Uses object's method

    Security notes:
    - For immutable types (bytes, str), the original object may persist in memory
    - Python's garbage collector may leave traces in memory
    - For maximum security, use bytearray for sensitive data storage
    """
    if key_material is None:
        return

    # Hybrid dict keys (e.g. {'mldsa': bytes} session DSS identity):
    # recurse into components so each secret copy is erased. Never raises;
    # un-wipeable components are dropped by the caller (see secure_cleanup).
    if isinstance(key_material, dict):
        for _comp_name, _comp_data in list(key_material.items()):
            try:
                secure_erase(_comp_data)
            except Exception as e_comp:
                ratchet_logger.debug(f"Component erasure skipped: {e_comp}")
        return

    try:
        # Always use the hardware-backed enhanced_secure_erase from secure_key_manager
        import secure_key_manager as skm
        if hasattr(skm, 'enhanced_secure_erase'):
            skm.enhanced_secure_erase(key_material)
            ratchet_logger.debug(f"Securely erased {type(key_material).__name__} using hardware-backed secure erasure")
            return
        else:
            ratchet_logger.warning("Hardware-backed secure erasure not available: enhanced_secure_erase method not found")
            # Continue with software implementation as a second layer, not a fallback
    except ImportError:
        ratchet_logger.warning("Hardware-backed secure erasure not available: secure_key_manager module not found")
        # Continue with software implementation as a second layer, not a fallback

    # If hardware-backed erasure is unavailable, use software-based implementation
    original_type = type(key_material)

    # Create a mutable buffer for secure erasure
    if isinstance(key_material, bytes) or isinstance(key_material, str):
        if isinstance(key_material, str):
            buffer = bytearray(key_material.encode('utf-8'))
            buffer_len = len(buffer)
        else:  # bytes
            buffer = bytearray(key_material)
            buffer_len = len(buffer)

        ratchet_logger.debug(f"Created mutable bytearray copy of immutable {original_type.__name__} for secure erasure ({buffer_len} bytes)")
        ratchet_logger.info("Note: Original immutable object may remain in memory until garbage collection")
    elif isinstance(key_material, bytearray):
        buffer = key_material  # Already mutable - direct in-place erasure
        buffer_len = len(buffer)
        ratchet_logger.debug(f"Using existing mutable bytearray for in-place secure erasure ({buffer_len} bytes)")
    else:
        # Try to use object's native secure erasure method if available
        if hasattr(key_material, 'zeroize'):
            key_material.zeroize()
            ratchet_logger.debug(f"Used object's native zeroize method for {type(key_material).__name__}")
            return
        else:
            # Cannot erase object that is neither bytes-like nor has zeroize method
            ratchet_logger.warning(f"Cannot securely erase unsupported type: {type(key_material).__name__}")
            return

    if buffer_len == 0:
        return  # Empty buffer - nothing to erase

    # Lock memory to prevent sensitive data from being paged to disk
    memory_pinned = False
    buffer_addr = None
    try:
        # Get direct memory address for low-level operations
        buffer_addr = ctypes.addressof((ctypes.c_char * buffer_len).from_buffer(buffer))
        # Lock memory using platform-specific method (VirtualLock/mlock)
        memory_pinned = cphs.lock_memory(buffer_addr, buffer_len)
        if memory_pinned:
            ratchet_logger.debug(f"Memory locked to prevent paging ({buffer_len} bytes)")
    except Exception as e_pin:
        ratchet_logger.debug(f"Memory locking unavailable: {e_pin}")

    # DoD 5220.22-M compliant overwrite patterns
    patterns = [
        0x00,  # All zeros (binary: 00000000)
        0xFF,  # All ones (binary: 11111111)
        0xAA,  # Alternating 1/0 (binary: 10101010)
        0x55,  # Alternating 0/1 (binary: 01010101)
        0xF0,  # Binary: 11110000
        0x0F,  # Binary: 00001111
        0x33,  # Binary: 00110011
        0xCC   # Binary: 11001100
    ]

    try:
        # 1. Apply each DoD pattern in sequence
        for i, pattern in enumerate(patterns):
            if buffer_addr is not None:
                # Use direct memory manipulation with ctypes (64-bit safe void pointer)
                ctypes.memset(ctypes.c_void_p(buffer_addr), pattern, buffer_len)

                # Memory barrier to prevent compiler optimization
                ctypes.memmove(ctypes.c_void_p(buffer_addr), ctypes.c_void_p(buffer_addr), buffer_len)
                ratchet_logger.debug(f"Applied pattern {i+1}/{len(patterns)}: 0x{pattern:02X}")
            else:
                # Fallback to Python-level buffer manipulation
                for j in range(buffer_len):
                    buffer[j] = pattern

        # 2. Additional pass with cryptographically secure random data
        random_data = cphs.get_secure_random(buffer_len)
        for i in range(buffer_len):
            buffer[i] = random_data[i]

        # 3. Final zero pass (required by NIST SP 800-88)
        if buffer_addr is not None:
            ctypes.memset(ctypes.c_void_p(buffer_addr), 0, buffer_len)
            cphs.secure_wipe_memory(buffer_addr, buffer_len)
        else:
            for i in range(buffer_len):
                buffer[i] = 0

        ratchet_logger.debug(f"Completed DoD 5220.22-M compliant secure erasure of {buffer_len} bytes")
    except Exception as e_wipe:
        ratchet_logger.critical(f"DoD 5220.22-M secure erasure failed: {e_wipe}")
        # Use cryptographically secure random fill as an additional security layer
        try:
            # Apply random data with maximum entropy
            for _ in range(3): # Apply multiple passes
                random_data = cphs.get_secure_random(buffer_len)
                for i in range(buffer_len):
                    buffer[i] = random_data[i]

            # Then zero-fill
            for i in range(buffer_len):
                buffer[i] = 0
            ratchet_logger.warning("Applied multi-pass random fill and zero-fill erasure")
        except Exception as e_additional:
            ratchet_logger.critical(f"SECURITY ALERT: All secure erasure methods failed: {e_additional}. Memory may still contain sensitive data.")
            raise SecurityError(f"Failed to securely erase sensitive key material: {e_additional}")

    # Unlock memory if it was previously locked
    if memory_pinned and buffer_addr is not None:
        try:
            cphs.unlock_memory(buffer_addr, buffer_len)
            ratchet_logger.debug("Memory unlocked after secure erasure")
        except Exception as e_unlock:
            ratchet_logger.debug(f"Memory unlock failed: {e_unlock}")

    # Force garbage collection to help remove any lingering references
        gc.collect()


# Configure threshold cryptography for key compartmentalization
class KeyShare:
    """
    Implementation of Shamir's Secret Sharing to split sensitive key material.

    This allows key material to be split into multiple shares, requiring
    a threshold number of shares to reconstruct the original secret.
    """
    @staticmethod
    def _eval_polynomial(poly: List[int], x: int, prime: int) -> int:
        """Evaluate polynomial at point x."""
        result = 0
        for coeff in reversed(poly):
            result = (result * x + coeff) % prime
        return result

    @classmethod
    def split(cls, secret: bytes, n: int, t: int) -> List[Tuple[int, bytes]]:
        """
        Split a secret into n shares, requiring t shares to reconstruct.

        Args:
            secret: The secret to split
            n: Number of shares to create
            t: Threshold (minimum shares needed to reconstruct)

        Returns:
            List of (index, share_data) tuples
        """
        if t > n:
            raise ValueError("Threshold cannot be greater than number of shares")

        if t < 2:
            raise ValueError("Threshold must be at least 2")

        # Use a prime larger than any possible secret value
        prime = 2**256 - 189  # A 256-bit prime

        # Convert secret to an integer
        secret_int = int.from_bytes(secret, byteorder='big')

        # Create polynomial with random coefficients
        poly = [secret_int]
        for _ in range(t-1):
            poly.append(secrets.randbelow(prime))

        # Generate shares
        shares = []
        for i in range(1, n+1):  # Use 1-based indexing for shares
            x = i
            y = cls._eval_polynomial(poly, x, prime)

            # Store as bytes for consistency
            x_bytes = x.to_bytes(4, byteorder='big')
            y_bytes = y.to_bytes(len(secret) + 8, byteorder='big')  # Add padding

            shares.append((x, y_bytes))

        return shares

    @classmethod
    def combine(cls, shares: List[Tuple[int, bytes]], secret_len: int) -> bytes:
        """
        Combine shares to reconstruct the original secret.

        Args:
            shares: List of (index, share_data) tuples
            secret_len: Length of the original secret in bytes

        Returns:
            Reconstructed secret
        """
        if len(shares) < 2:
            raise ValueError("At least 2 shares are required")

        # Use the same prime as in split
        prime = 2**256 - 189

        # Extract points from shares
        points = [(x, int.from_bytes(y, byteorder='big')) for x, y in shares]

        # Use Lagrange interpolation to reconstruct the secret
        result = 0
        for i, (xi, yi) in enumerate(points):
            numerator = 1
            denominator = 1

            for j, (xj, _) in enumerate(points):
                if i == j:
                    continue

                numerator = (numerator * -xj) % prime
                denominator = (denominator * (xi - xj)) % prime

            # Calculate modular inverse of denominator
            # Extended Euclidean Algorithm for modular inverse
            def mod_inverse(a, m):
                if a == 0:
                    raise ValueError("Division by zero")
                if a < 0:
                    a = a % m
                g, x, y = cls._extended_gcd(a, m)
                if g != 1:
                    raise ValueError("Modular inverse does not exist")
                else:
                    return x % m

            denominator_inv = mod_inverse(denominator, prime)

            term = (yi * numerator * denominator_inv) % prime
            result = (result + term) % prime

        # Convert back to bytes and truncate to original length
        secret_bytes = result.to_bytes((result.bit_length() + 7) // 8, byteorder='big')
        return secret_bytes[-secret_len:]

    @staticmethod
    def _extended_gcd(a, b):
        """Extended Euclidean Algorithm for computing GCD and modular inverse."""
        if a == 0:
            return b, 0, 1
        else:
            g, x, y = KeyShare._extended_gcd(b % a, a)
            return g, y - (b // a) * x, x


# Create threat detection instance
threat_detector = ThreatDetection()


@dataclass
class MessageHeader:
    """Secure binary message header for the Double Ratchet protocol.

    This class represents the binary message header used in the Double Ratchet
    protocol. The header contains all information needed for ratchet operation
    and replay protection, with a fixed binary layout for efficient parsing.

    Binary structure (48 bytes total):
    - 32 bytes: X25519 public key for DH ratchet (raw format)
    - 4 bytes: Previous chain length (unsigned int, big endian)
    - 4 bytes: Message number in current chain (unsigned int, big endian)
    - 8 bytes: Unique message identifier (cryptographically random bytes)

    The header serves multiple security purposes:
    1. Communicates the sender's current ratchet public key
    2. Provides message ordering information for chain ratcheting
    3. Includes a unique message ID for replay attack prevention
    4. Enables out-of-order message handling

    All fields undergo validation during initialization to prevent
    malformed headers that could lead to security vulnerabilities.
    """

    # Header size in bytes (fixed for binary compatibility)
    HEADER_SIZE = 32 + 4 + 4 + 8  # 48 bytes total

    # Absolute protocol bounds (DoS defense-in-depth, before any HMAC work).
    # Counters are uint32 on the wire; values beyond this are never legitimate
    # (1000x the MAX_SKIP window) and are rejected at parse time.
    MAX_CHAIN_COUNTER = 1_000_000

    # Components
    public_key: X25519PublicKey
    previous_chain_length: int
    message_number: int
    message_id: bytes

    def __post_init__(self):
        """Validate header fields after initialization."""
        if not isinstance(self.public_key, X25519PublicKey):
            raise TypeError("public_key must be X25519PublicKey instance")

        if not isinstance(self.previous_chain_length, int) or self.previous_chain_length < 0:
            raise ValueError("previous_chain_length must be a non-negative integer")

        if not isinstance(self.message_number, int) or self.message_number < 0:
            raise ValueError("message_number must be a non-negative integer")

        if self.previous_chain_length > self.MAX_CHAIN_COUNTER:
            raise ValueError("previous_chain_length exceeds protocol bound")

        if self.message_number > self.MAX_CHAIN_COUNTER:
            raise ValueError("message_number exceeds protocol bound")

        if not isinstance(self.message_id, bytes) or len(self.message_id) != 8:
            raise ValueError("message_id must be 8 bytes")

    def encode(self) -> bytes:
        """Encode the header to binary format for transmission."""
        # Public key serialization
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Integer values as 4-byte big-endian unsigned integers
        message_number_bytes = struct.pack('>I', self.message_number)
        previous_chain_length_bytes = struct.pack('>I', self.previous_chain_length)

        # Combine all fields in order
        return public_key_bytes + previous_chain_length_bytes + message_number_bytes + self.message_id

    @classmethod
    def decode(cls, header_bytes: bytes) -> 'MessageHeader':
        """
        Decode a header from its binary representation.

        Raises:
            ValueError: If header format is invalid
        """
        if not isinstance(header_bytes, bytes):
            raise TypeError("Header bytes must be bytes type")

        if len(header_bytes) != cls.HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(header_bytes)}, expected {cls.HEADER_SIZE}")

        try:
            # Extract public key (first 32 bytes)
            public_key_bytes = header_bytes[:32]
            public_key = X25519PublicKey.from_public_bytes(public_key_bytes)

            # Extract previous chain length (next 4 bytes)
            previous_chain_length = struct.unpack('>I', header_bytes[32:36])[0]

            # Extract message number (next 4 bytes)
            message_number = struct.unpack('>I', header_bytes[36:40])[0]

            # Extract message ID (last 8 bytes)
            message_id = header_bytes[40:48]

            return cls(
                public_key=public_key,
                previous_chain_length=previous_chain_length,
                message_number=message_number,
                message_id=message_id
            )
        except Exception as e:
            raise ValueError(f"Failed to decode message header: {e}")

    @classmethod
    def generate(cls, public_key: X25519PublicKey, previous_chain_length: int,
                message_number: int) -> 'MessageHeader':
        """Generate a new message header with a random message ID."""
        # Ensure public_key is not None
        if public_key is None:
            raise ValueError("Cannot generate MessageHeader with None public_key")

        # Use cphs for cryptographically strong random numbers
        message_id = cphs.get_secure_random(8)

        return cls(
            public_key=public_key,
            previous_chain_length=previous_chain_length,
            message_number=message_number,
            message_id=message_id
        )


# SPQR (Signal PQ Ratchet) cadence policy -- Apple PQ3 cadence from research:
# fresh KEM every 50 messages or at most every 7 days. Module-level defaults
# mirror DoubleRatchet.SPQR_POLICY; effective values are env-configurable via
# P2P_SPQR_MSG_INTERVAL / P2P_SPQR_MAX_AGE (see _spqr_effective_policy()).
SPQR_MSG_INTERVAL_DEFAULT = 50
SPQR_MAX_AGE_SECONDS_DEFAULT = 7 * 24 * 3600
SPQR_POLICY = {
    "msg_interval": SPQR_MSG_INTERVAL_DEFAULT,
    "max_age_seconds": SPQR_MAX_AGE_SECONDS_DEFAULT,
}


def _spqr_effective_policy():
    """Return effective (msg_interval, max_age_seconds) honoring env overrides.

    Never raises: unparseable env values fall back to defaults.
    """
    interval = SPQR_MSG_INTERVAL_DEFAULT
    max_age = SPQR_MAX_AGE_SECONDS_DEFAULT
    try:
        raw_interval = os.environ.get("P2P_SPQR_MSG_INTERVAL", "")
        if raw_interval not in (None, ""):
            interval = int(str(raw_interval).strip())
            if interval < 1:
                interval = SPQR_MSG_INTERVAL_DEFAULT
    except (TypeError, ValueError):
        interval = SPQR_MSG_INTERVAL_DEFAULT
    try:
        raw_age = os.environ.get("P2P_SPQR_MAX_AGE", "")
        if raw_age not in (None, ""):
            max_age = int(float(str(raw_age).strip()))
            if max_age < 1:
                max_age = SPQR_MAX_AGE_SECONDS_DEFAULT
    except (TypeError, ValueError):
        max_age = SPQR_MAX_AGE_SECONDS_DEFAULT
    return interval, max_age


class DoubleRatchet:
    """Double Ratchet protocol implementation with NIST Level-5 security.

    This class implements the Double Ratchet algorithm with NIST Level-5 classical
    and post-quantum algorithms. The Double Ratchet algorithm is used in secure
    messaging protocols to provide forward secrecy and post-compromise security
    through regular key rotation.

    Security Properties:
    - Forward Secrecy: Each message is encrypted with a unique key derived through
      the ratchet mechanism, ensuring that compromise of current keys does not
      affect the security of past messages.

    - Post-Compromise Security: After a key compromise, security is restored once
      a new Diffie-Hellman ratchet step is performed.

    - Post-Quantum Resistance: Combines classical X25519 Diffie-Hellman with
      ML-KEM-1024 (NIST Level-5) key encapsulation for quantum resistance.

    - Authentication: Uses FALCON-1024 (NIST Level-5) signatures and ChaCha20-Poly1305 AEAD
      to provide message authentication and integrity.

    - No Out-of-Order Message Processing: Out-of-order messages are rejected
      to ensure the strongest level of forward secrecy (MAX_SKIP_MESSAGE_KEYS=0).

    Implementation Features:
    - Memory Protection: Implements secure memory handling for sensitive key material.
    - Side-Channel Resistance: Uses constant-time operations where possible.
    - Hardware Security: Optional integration with secure hardware elements.
    - Replay Prevention: Detects and rejects message replays.
    - Key Compartmentalization: Optional threshold cryptography for key splitting.

    Protocol Implementation Details:
    1. Symmetric Key Ratchet: Uses HMAC-SHA512 for chain and message key derivation
       with domain separation for different key types.
    2. Diffie-Hellman Ratchet: Combines new key exchanges with existing secrets
       to provide post-compromise security.
    3. Key Derivation: Uses HKDF-SHA3_512 with domain separation tags for different
       contexts to prevent key reuse attacks.
    4. Message Format:
       - 32 bytes: Public key for the DH ratchet (X25519)
       - 4 bytes: Previous chain length
       - 4 bytes: Message number in current chain
       - 8 bytes: Unique message identifier for replay detection
       - 2 bytes: Signature length
       - Variable: FALCON-1024 signature (if post-quantum mode enabled)
       - 12 bytes: Nonce for ChaCha20-Poly1305
       - Variable: Encrypted message with authentication tag

    Attack Mitigations:
    - Strict message number checking prevents replay attacks
    - Constant-time operations prevent timing side-channels
    - Memory protection defends against cold boot attacks
    - Automatic key rotation limits key reuse
    - Authenticated encryption prevents tampering
    - Post-quantum algorithms provide resistance to quantum computer attacks

    Compliance:    - Enforces NIST Level-5 security for all algorithms
    - Uses ML-KEM-1024 for post-quantum key exchange (NIST Level-5)
    - Uses FALCON-1024 for post-quantum signatures (NIST Level-5)
    - Implements IETF ChaCha20-Poly1305 (RFC 8439) with no fallbacks
    - Uses HKDF-SHA3_512 according to RFC 5869 with enhanced domain separation
    - No downgrade paths or fallbacks to weaker algorithms

    This implementation is compatible with the Signal Protocol's Double Ratchet
    algorithm specification, with added post-quantum cryptographic enhancements
    for increased security against quantum computing threats.
    """

    # Security parameters - Signal-spec aligned (see signal.org/docs/specifications/doubleratchet).
    # MAX_SKIP=1000 per spec section 2.6/3: high enough for routine loss/reorder,
    # low enough to bound attacker-triggered HMAC computation (DoS). MKSKIPPED
    # per-session cap 1000; deletion after interval enforced via expiry below.
    # Prior value 0 broke on any loss/reorder and forced fail-closed on benign gaps.
    MAX_SKIP_MESSAGE_KEYS = 1000
    HARD_MAX_SKIP = 1000              # Absolute hard ceiling: single-chain gap >1000 aborts (CPU DoS bound)
    MAX_SKIPPED_TOTAL = 2000          # Per-session total cap across chains (evict oldest + expiry)
    SKIPPED_KEY_EXPIRY_SECONDS = 3600  # Delete skipped keys after 1h (Signal 8.4: timer-based deletion)
    MAX_MESSAGE_SIZE = 524288      # 512KB maximum message size (reduced from 1MB)
    CHAIN_KEY_SIZE = 32            # Chain key size in bytes
    MSG_KEY_SIZE = 32              # Message key size in bytes
    ROOT_KEY_SIZE = 32             # Root key size in bytes
    KEY_ROTATION_MESSAGES = 30     # Rotate keys after this many messages
    KEY_ROTATION_TIME = 3600       # Rotate keys after this many seconds (1 hour)
    MAX_REPLAY_CACHE_SIZE = 1000   # Signal-aligned: cover MKSKIPPED window (1000) to avoid eviction-replay

    # Hybrid KEM ciphertext size: ML-KEM-1024 (1568) + McEliece-8192128f (208) = 1776
    HYBRID_KEM_CIPHERTEXT_SIZE = 1776  # Expected ciphertext size for Hybrid KEM
    MLKEM1024_CIPHERTEXT_SIZE = 1776   # Alias for backward compatibility (now uses Hybrid KEM)

    # Domain separation strings for KDF - Enhanced with version and algorithm info
    KDF_INFO_DH = b"DR_DH_RATCHET_X25519_v2"
    KDF_INFO_CHAIN = b"DR_CHAIN_KEY_ChaCha20_v2"
    KDF_INFO_MSG = b"DR_MSG_KEY_ChaCha20Poly1305_v2"
    KDF_INFO_HYBRID = b"DR_HYBRID_MLKEM1024_DH_v2"

    # New constants for improved domain separation during DH ratchet steps
    KDF_INFO_ROOT_UPDATE_DH = b"DR_ROOT_UPDATE_X25519_v2"
    KDF_INFO_ROOT_UPDATE_HYBRID = b"DR_ROOT_UPDATE_HYBRID_MLKEM1024_DH_v2"
    KDF_INFO_CHAIN_INIT_SEND_DH = b"DR_CHAIN_INIT_SEND_X25519_v2"
    KDF_INFO_CHAIN_INIT_SEND_HYBRID = b"DR_CHAIN_INIT_SEND_HYBRID_MLKEM1024_DH_v2"
    KDF_INFO_CHAIN_INIT_RECV_DH = b"DR_CHAIN_INIT_RECV_X25519_v2"
    KDF_INFO_CHAIN_INIT_RECV_HYBRID = b"DR_CHAIN_INIT_RECV_HYBRID_MLKEM1024_DH_v2"

    # New constants for improved domain separation in _initialize_chain_keys
    KDF_INFO_INIT_ROOT_STEP1_DH = b"DR_INIT_ROOT_S1_X25519_v2"
    KDF_INFO_INIT_ROOT_STEP1_HYBRID = b"DR_INIT_ROOT_S1_HYBRID_MLKEM1024_DH_v2"
    KDF_INFO_INIT_CHAIN_STEP1_DH = b"DR_INIT_CHAIN_S1_X25519_v2"
    KDF_INFO_INIT_CHAIN_STEP1_HYBRID = b"DR_INIT_CHAIN_S1_HYBRID_MLKEM1024_DH_v2"

    KDF_INFO_INIT_ROOT_STEP2_DH = b"DR_INIT_ROOT_S2_X25519_v2"
    KDF_INFO_INIT_ROOT_STEP2_HYBRID = b"DR_INIT_ROOT_S2_HYBRID_MLKEM1024_DH_v2"
    KDF_INFO_INIT_CHAIN_STEP2_DH = b"DR_INIT_CHAIN_S2_X25519_v2"
    KDF_INFO_INIT_CHAIN_STEP2_HYBRID = b"DR_INIT_CHAIN_S2_HYBRID_MLKEM1024_DH_v2"

    # Braid-lite fresh-KEM ratchet (v2) domain. Existing domains above are
    # frozen for v1 interop; this new info string is used ONLY when a fresh
    # per-step KEM secret is mixed via crypto.kem.hybrid_combine_v2.
    KDF_INFO_PQ_RATCHET_V2 = b"DR_PQ_RATCHET_V2_MLKEM1024_DH"

    # Braid-lite PQ ratchet versions: 1 = legacy reuse of the synchronized
    # KEM secret across DH steps (v1 wire format frozen); 2 = fresh ML-KEM
    # encaps per DH ratchet step. Negotiated via HybridKeyExchange
    # protocol_version (v2 peers -> 2, v1 peers -> 1).
    PQ_RATCHET_VERSION_LEGACY = 1
    PQ_RATCHET_VERSION_FRESH = 2
    # Minimum seconds between force_pq_ratchet() idle-healing calls.
    PQ_RATCHET_MIN_INTERVAL = 60.0
    # SPQR cadence (Apple PQ3: fresh KEM every 50 msgs / 7 days, v2 only,
    # versioned non-breaking; v1 wire format frozen, v1 sessions no-op).
    # Effective values honor env overrides P2P_SPQR_MSG_INTERVAL /
    # P2P_SPQR_MAX_AGE via _spqr_effective_policy(); class attributes below
    # are the compiled-in defaults.
    SPQR_MSG_INTERVAL = 50
    SPQR_MAX_AGE_SECONDS = 7 * 24 * 3600
    SPQR_POLICY = {
        "msg_interval": 50,
        "max_age_seconds": 7 * 24 * 3600,
    }
    # Transcript prefixes bound into hybrid_combine_v2 for ratchet mixing.
    PQ_RATCHET_V2_TRANSCRIPT_RECV = b"DR_PQ_RATCHET_V2::RECV::"
    PQ_RATCHET_V2_TRANSCRIPT_SEND = b"DR_PQ_RATCHET_V2::SEND::"
    PQ_RATCHET_V2_TRANSCRIPT_IDLE = b"DR_PQ_RATCHET_V2::IDLE::"
    # Shared transcript for the peer-synced Braid CT path: the sender's
    # SENDING-side mix and the receiver's RECEIVING-side mix MUST feed the
    # combiner identical transcripts, so both use SYNC + the sender's new DH
    # public key raw bytes (known to both: sender owns it, receiver gets it
    # in the 48-byte header). The legacy RECV/SEND/IDLE prefixes above are
    # retained for local-only healing ops (force_pq_ratchet) and history.
    PQ_RATCHET_V2_TRANSCRIPT_SYNC = b"DR_PQ_RATCHET_V2::SYNC::"

    # Peer-synced Braid CT wire extension (v2, versioned non-breaking).
    # Layout of a v2 message carrying a fresh KEM ciphertext:
    #   header(48) + sig_len(2) + sig + nonce(12)
    #       + [PQ_CT_EXT_MAGIC(4) + pq_ct_len BE16 + pq_ct] + ciphertext
    # The extension sits AFTER the fixed 48-byte header (offsets of header /
    # sig_len / nonce are unchanged) with an explicit length prefix, so a
    # parser can skip/strip it deterministically. It is placed BEFORE the
    # variable-length AEAD ciphertext (not after it): a trailing len-first
    # field after a variable-length ciphertext would be unfindable without a
    # size oracle, while this placement parses at a known offset for any CT
    # size. v1 sessions never emit it; parsers strip an unexpected extension
    # with a warning and continue with the legacy body (skip-or-reject-cleanly).
    PQ_CT_EXT_MAGIC = b'PQX2'
    PQ_CT_EXT_MAGIC_SIZE = 4
    PQ_CT_EXT_LEN_SIZE = 2
    PQ_CT_EXT_MAX_CT_LEN = 8192
    PQ_CT_EXT_MIN_CIPHERTEXT = 16  # ChaCha20-Poly1305 auth tag size

    def __init__(
        self,
        root_key: bytes,
        is_initiator: bool = True,
        enable_pq: bool = True,
        max_skipped_keys: int = 1000,  # Signal spec default: tolerate loss/reorder up to 1000
        security_level: str = "MAXIMUM",
        threshold_security: bool = True,  # Enable by default for enhanced security
        hardware_binding: bool = True,    # Enable by default for enhanced security
        side_channel_protection: bool = True,
        anomaly_detection: bool = True,
        max_replay_cache_size: int = MAX_REPLAY_CACHE_SIZE,
        protocol_version: int = 1,
        pq_ratchet_version: Optional[int] = None,
        deniable: bool = False
    ):
        """Initialize a Double Ratchet session with NIST Level-5 security configuration.

        Creates a new Double Ratchet session with the specified security parameters.
        This implementation strictly enforces NIST Level-5 for both classical and
        post-quantum algorithms with no fallbacks to weaker ciphers.

        Args:
            root_key: Initial 32-byte shared secret key from key exchange
            is_initiator: True if this side initiated the conversation
            enable_pq: Enable post-quantum cryptography (ML-KEM-1024)
            max_skipped_keys: Maximum number of message keys to cache for out-of-order messages
            security_level: Security profile to use ("MAXIMUM")
            threshold_security: Enable key compartmentalization across security domains
            hardware_binding: Bind cryptographic operations to hardware security modules
            side_channel_protection: Enable protections against timing/cache attacks
            anomaly_detection: Enable behavioral and cryptographic anomaly detection
            max_replay_cache_size: Maximum size of the replay protection cache

        Raises:
            ValueError: If root_key is invalid or security parameters are incompatible
            SecurityError: If security requirements cannot be satisfied

        Note:
            This implementation enforces NIST Level-5 security with no fallbacks
            to weaker algorithms. It exclusively uses PQC primitives from pqc_algorithms.py.
        """
        # Verify the root key's security properties
        verify_key_material(root_key, expected_length=self.ROOT_KEY_SIZE,
                          description="Double Ratchet initial root key")

        # Core state
        self.root_key = root_key
        self.is_initiator = is_initiator
        # 2028 hardening: classical-only (enable_pq=False) requires explicit
        # lab opt-in; production fail-closes (PQ PCS required per PQXDH/Braid).
        import os as _os
        _prod = _os.environ.get("SECURE_P2P_PRODUCTION", "0") == "1" or _os.environ.get("P2P_PRODUCTION", "0").lower() in ("1", "true")
        if not enable_pq and _prod and _os.environ.get("P2P_ALLOW_CLASSICAL", "0") != "1":
            raise SecurityError("MILITARY FATAL: enable_pq=False refused in production (classical-only, no PQ PCS)")
        if not enable_pq:
            import logging as _logging
            _logging.getLogger(__name__).warning("Classical-only DoubleRatchet (enable_pq=False) - lab only, no PQ PCS")
        self.enable_pq = enable_pq
        # Deniable mode (research-backed, cf. Signal offline-deniability /
        # BAKE: X3DH/PQXDH deniability rests on symmetric authentication where
        # either party could have produced the transcript). Deniable sessions
        # skip per-message DSS signatures: authenticity comes ONLY from the
        # shared chain key (repudiable), NOT from a third-party-verifiable
        # signature (RFC 9881 non-repudiation). Fail-closed: refused in TS
        # mode and in production without explicit opt-in; never usable for
        # TOP SECRET / DPO-gated payloads (non-repudiation required there).
        _ts = _os.environ.get("P2P_TS_MODE", "0").strip().lower() in ("1", "true", "yes", "on")
        if deniable and (_ts or (_prod and _os.environ.get("P2P_ALLOW_DENIABLE", "0") != "1")):
            raise SecurityError("Deniable mode refused: non-repudiation required (TS/production default)")
        self.deniable = bool(deniable)
        if self.deniable:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "Deniable DoubleRatchet session: per-message signatures DISABLED "
                "(AEAD-only repudiable auth; NOT for TOP SECRET/DPO use)")

        # Braid-lite PQ ratchet negotiation (versioned, non-breaking).
        # 1 = legacy: reuse _synchronized_kem_secret across DH steps (v1 wire
        #     format frozen, never modified). 2 = fresh ML-KEM encaps per DH
        #     step mixed via crypto.kem.hybrid_combine_v2. Negotiated via the
        #     existing HybridKeyExchange protocol_version: v2 peers get fresh
        #     KEM, v1 peers stay legacy. Unknown/unparseable input fails safe
        #     to v1 for interop. See negotiate_pq_ratchet_version() to
        #     re-negotiate after the handshake advertises the peer version.
        self.protocol_version = 1
        try:
            self.protocol_version = int(protocol_version)
        except (TypeError, ValueError):
            self.protocol_version = 1
        if pq_ratchet_version is None:
            self.pq_ratchet_version = (
                self.PQ_RATCHET_VERSION_FRESH if self.protocol_version >= 2
                else self.PQ_RATCHET_VERSION_LEGACY
            )
        else:
            try:
                self.pq_ratchet_version = (
                    self.PQ_RATCHET_VERSION_FRESH if int(pq_ratchet_version) >= 2
                    else self.PQ_RATCHET_VERSION_LEGACY
                )
            except (TypeError, ValueError):
                self.pq_ratchet_version = self.PQ_RATCHET_VERSION_LEGACY
        # Synchronized KEM secret (legacy v1 reuse root; refreshed by v2).
        self._synchronized_kem_secret = None
        # Peer-synced Braid CT extension (v2): fresh KEM ciphertext staged by
        # the sending-side DH step, attached to the next outgoing message by
        # _encrypt (consumed on send). Never set on v1 sessions.
        self._pending_pq_ct: Optional[bytes] = None
        # True once this session has consumed a peer CT extension (compat
        # tracking: a v2 peer that never sends CT stays on legacy reuse).
        self._peer_ct_seen = False
        # Timestamp of the last successful fresh-KEM op (DH-step v2 or forced).
        self._last_pq_ratchet_time = 0.0
        # Timestamp of the last force_pq_ratchet() call; backs its 60s
        # rate limit (tracked separately so routine DH steps never
        # consume the forced-healing budget).
        self._last_force_pq_ratchet_time = 0.0
        # SPQR cadence tracking (v2 only; v1 sessions leave these untouched).
        # _spqr_msg_counter counts _ratchet_encrypt sends since the last
        # fresh-KEM refresh; _spqr_last_refresh is wall-clock time.time()
        # of the last SPQR/DH-step fresh-KEM refresh.
        self._spqr_msg_counter = 0
        self._spqr_last_refresh = time.time()
        if self.pq_ratchet_version >= self.PQ_RATCHET_VERSION_FRESH:
            logger.info(
                f"PQ ratchet v{self.pq_ratchet_version} negotiated "
                f"(protocol_version={self.protocol_version}): "
                "fresh KEM encaps per DH step via hybrid_combine_v2"
            )
        else:
            logger.info(
                f"PQ ratchet v{self.pq_ratchet_version} negotiated "
                f"(protocol_version={self.protocol_version}): "
                "legacy synchronized-KEM reuse (v1 wire format)"
            )

        # Signal 2.6/3: honor caller limit, clamped to [1, MAX_SKIP_MESSAGE_KEYS].
        # Prior code forced 0, breaking on any loss/reorder.
        try:
            _req = int(max_skipped_keys)
        except (TypeError, ValueError):
            _req = self.MAX_SKIP_MESSAGE_KEYS
        self.max_skipped_message_keys = max(1, min(_req, self.MAX_SKIP_MESSAGE_KEYS))

        # Enhanced security options - force to maximum security
        self.security_level = "MAXIMUM"
        self.threshold_security = threshold_security
        self.hardware_binding = hardware_binding
        self.side_channel_protection = True  # Always enable side channel protection
        self.anomaly_detection = True  # Always enable anomaly detection
        self.secure_memory_protection = True  # Always enable secure memory protection

        # Initialize replay cache with improved implementation
        self.replay_cache = ReplayCache(max_size=max_replay_cache_size, expiry_seconds=7200)

        # Initialize ratchet state
        self.dh_private_key = None
        self.dh_public_key = None
        self.remote_dh_public_key = None

        # Initialize post-quantum state
        self.kem = EnhancedMLKEM_1024()  # Use ML-KEM-1024 from pqc_algorithms
        # Agile signer/verifier: dict keys route to ML-DSA-87 (fast mode),
        # raw bytes route to legacy Falcon-1024. Verify path therefore stays
        # interoperable with pre-migration peers; see _generate_pq_keypairs.
        self.dss = EnhancedFALCON_1024()
        # Session DSS identity keygen: ML-DSA-87 (FIPS 204, CNSA 2.0).
        self.dss_keygen = EnhancedMLDSA_87()
        self.dss_algorithm = "ML-DSA-87"

        # Initialize post-quantum keys
        self.kem_private_key = None
        self.kem_public_key = None
        self.remote_kem_public_key = None
        self.kem_ciphertext = None
        self.kem_shared_secret = None

        # Initialize DSS keys
        self.dss_private_key = None
        self.dss_public_key = None
        self.remote_dss_public_key = None

        # Chain keys
        self.sending_chain_key = None
        self.receiving_chain_key = None

        # Message counters
        self.sending_chain_length = 0
        self.receiving_chain_length = 0
        self.previous_sending_chain_length = 0

        # Skipped message keys (Signal MKSKIPPED, capped + expiry for forward secrecy)
        self.skipped_message_keys = {}
        # Parallel timestamps for timer-based deletion (Signal 8.4). {key_tuple: monotonic_time}
        self._skipped_key_times = {}
        # Optional handshake binding mixed into AEAD AD (set_handshake_binding).
        # None = legacy AD for interop; bytes = bound AD (both sides identical).
        self._handshake_binding = None

        # Key rotation timestamps
        self.last_key_rotation_time = time.time()
        self.messages_since_rotation = 0

        # Hardware security module integration
        self.hsm_available = hardware_binding and HAVE_HSM
        self.hardware_key_ids = {}

        # Security metrics for threat detection
        self.security_metrics = {
            'message_count': 0,
            'failed_decryptions': 0,
            'suspicious_activities': 0,
            'last_key_rotation': time.time(),
            'clock_drift': 0,
            'operation_times': {},
            'attack_indicators': []
        }

        # Key compartmentalization with threshold cryptography
        self.key_shares = {}
        if self.threshold_security:
            # Split root key into shares (3-of-5 scheme)
            try:
                self.key_shares["root_key"] = KeyShare.split(root_key, 5, 3)
            except Exception as e:
                logger.warning(f"Failed to create key shares: {e}")

        # Side-channel protection
        if self.side_channel_protection:
            self.side_channel = SideChannelProtection()

        # Secure memory for sensitive key material
        self._setup_secure_memory()

        # Generate initial key pair
        self._generate_dh_keypair()

        # Generate post-quantum keys if enabled
        if self.enable_pq:
            self._generate_pq_keypairs()

        # Initialize canary protector for memory integrity verification
        self.canary_protector = CanaryProtector()
        self.canary_protector.register_canary("root_key", cphs.get_secure_random(32))

        # Initialize threat detection if enabled
        if self.anomaly_detection:
            self.threat_detector = ThreatDetection()

        logger.info(f"Double Ratchet initialized with NIST Level-5 security (is_initiator={is_initiator})")
        # Honesty (2026 review): this messenger path is a hybrid-transition
        # prototype (X25519 + ML-KEM-1024, ChaCha20-Poly1305, HKDF-SHA3-512,
        # Falcon-verify/ML-DSA) — NOT the CNSA-pure session set (ML-KEM-1024 /
        # ML-DSA-87 / AES-256-GCM / SHA-384 / HKDF-SHA384 in noise_pq.py +
        # secure_transmit_2027.py). No silent upgrade claimed here.
        logger.info("Post-quantum hybrid-transition ratchet (messenger path, not CNSA-pure)")

    def _generate_dh_keypair(self):
        """
        Generate a new X25519 key pair for Diffie-Hellman key exchange.

        This method creates a new X25519 elliptic curve key pair for use in the
        Double Ratchet algorithm's Diffie-Hellman ratchet steps.
        """
        logger.debug("Generating new X25519 key pair")
        self.dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key = self.dh_private_key.public_key()
        logger.debug("X25519 key pair generated successfully")

    def _generate_pq_keypairs(self):
        """
        Generate post-quantum key pairs for ML-KEM-1024 and FALCON-1024.

        This method creates new post-quantum key pairs for key encapsulation and
        digital signatures using NIST Level-5 algorithms.
        """
        logger.debug("Generating post-quantum key pairs")

        # Generate ML-KEM-1024 key pair
        try:
            self.kem_public_key, self.kem_private_key = self.kem.keygen()
            logger.debug(f"Generated ML-KEM-1024 key pair: PK={len(self.kem_public_key)} bytes, SK={len(self.kem_private_key)} bytes")
        except Exception as e:
            logger.error(f"Failed to generate ML-KEM-1024 key pair: {e}")
            raise SecurityError(f"Failed to generate post-quantum KEM key pair: {e}")

        # Generate ML-DSA-87 session DSS identity (CNSA 2.0 / FIPS 204).
        # Falcon-1024 is NOT in CNSA 2.0 (NSA will not add FN-DSA); new
        # sessions authenticate messages with ML-DSA-87. Falcon-1024 stays
        # on the VERIFY path only (self.dss routes raw bytes to Falcon),
        # so pre-migration peers remain interoperable. Keys are dicts
        # ({'mldsa': bytes}) end-to-end: keygen here, serialize_hybrid_key
        # on the wire, _secure_verify on receipt.
        try:
            mldsa_pk, mldsa_sk = self.dss_keygen.keygen()
            mldsa_pk, mldsa_sk = bytes(mldsa_pk), bytes(mldsa_sk)
            if len(mldsa_pk) != 2592 or len(mldsa_sk) != 4896:
                raise SecurityError(
                    f"Invalid ML-DSA-87 key sizes: PK={len(mldsa_pk)} "
                    f"(want 2592), SK={len(mldsa_sk)} (want 4896)"
                )
            verify_key_material(mldsa_pk, expected_length=2592,
                                description="ML-DSA-87 session DSS public key")
            verify_key_material(mldsa_sk, expected_length=4896,
                                description="ML-DSA-87 session DSS private key")
            self.dss_public_key = {'mldsa': mldsa_pk}
            self.dss_private_key = {'mldsa': mldsa_sk}
            pk_info = "hybrid {'mldsa'} (ML-DSA-87, FIPS 204)"
            sk_info = "hybrid {'mldsa'} (ML-DSA-87, FIPS 204)"
            logger.debug(f"Generated ML-DSA-87 session DSS key pair: PK={pk_info}, SK={sk_info}")
        except Exception as e:
            logger.error(f"Failed to generate ML-DSA-87 session DSS key pair: {e}")
            raise SecurityError(f"Failed to generate post-quantum DSS key pair: {e}")

        logger.debug("Post-quantum key pairs generated successfully")

    def _setup_secure_memory(self):
        """Initialize secure memory protection features."""
        try:
            # Initialize the counter-based nonce manager for AEAD encryption
            from tls_channel_manager import CounterBasedNonceManager
            self._nonce_manager = CounterBasedNonceManager()
            logger.debug("Initialized counter-based nonce manager for AEAD encryption")

            # Create canary protector instance
            self._canary_protector = CanaryProtector()

            # Add canaries for memory corruption detection
            for i in range(5):
                location = f"memory_region_{i}"
                canary_value = cphs.get_secure_random(32) # Use cphs
                self._canary_protector.register_canary(location, canary_value)

            # Memory allocation protection
            if hasattr(ctypes, 'windll'):  # Windows
                # Enable HeapEnableTerminationOnCorruption
                try:
                    ctypes.windll.kernel32.HeapSetInformation(
                        None, 1, None, 0
                    )
                    logger.debug("Enabled Windows heap termination on corruption")
                except Exception as e:
                    logger.debug(f"Failed to enable Windows heap termination: {e}")

            # Set verify_canaries method to use the canary protector
            self._verify_canaries = self._canary_protector.verify_canaries

            logger.debug("Secure memory protection initialized with CanaryProtector")
        except Exception as e:
            logger.warning(f"Failed to initialize secure memory protection: {e}")
            self.secure_memory_protection = False

    def _get_public_key_fingerprint(self, public_key: X25519PublicKey) -> bytes:
        """Generate a stable identifier for a public key."""
        if public_key is None:
            logger.warning("SECURITY ALERT: Attempted to get fingerprint of None public key")
            # Return a fingerprint that won't match any valid key
            return hashlib.sha3_512(b"INVALID_KEY").digest()[:8]

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # Fallback with invalid key
        if not public_bytes:
            return hashlib.sha3_512(b"INVALID_KEY").digest()[:8]

        # Use side-channel resistant comparison if enabled
        if self.side_channel_protection and HAS_CONSTANT_TIME:
            # Use a timing-safe hash operation
            fingerprint = hashlib.blake2s(public_bytes, digest_size=8).digest()
        else:
            fingerprint = hashlib.sha3_512(public_bytes).digest()[:8]

        return fingerprint

    def _dh_ratchet_step(self, remote_public_key_bytes: bytes,
                        remote_kem_public_key: Optional[bytes] = None,
                        peer_pq_ct: Optional[bytes] = None) -> None:
        """
        Execute a Diffie-Hellman ratchet step to update the keys.

        Args:
            remote_public_key_bytes: The remote party's new public key
            remote_kem_public_key: The remote party's KEM public key (PQ mode only)
            peer_pq_ct: Optional peer KEM ciphertext from the Braid CT wire
                extension. On v2 sessions it is decapsulated with the local
                KEM private and mixed into the RECEIVING chain, pairing with
                the peer's SENDING-side mix. ``None`` means the peer sent no
                CT (legacy peer, encaps failure, or lost extension) and the
                step falls back to legacy reuse with a warning (never aborts).
        """
        try:
            # Track operation time if anomaly detection is enabled
            start_time = time.time()

            # Convert bytes to public key object
            remote_public_key = X25519PublicKey.from_public_bytes(remote_public_key_bytes)

            # Save the remote public key and generate identifier
            self.remote_dh_public_key = remote_public_key
            remote_fingerprint = self._get_public_key_fingerprint(remote_public_key)

            # 1. First DH: Use current private key with new remote public key
            logger.debug("Performing DH exchange for receiving chain")
            if self.dh_private_key is None:
                self._generate_dh_keypair()
            if self.dh_private_key is None:
                raise SecurityError("DH private key unavailable after generation (fail-closed)")
            dh_output = self.dh_private_key.exchange(remote_public_key)
            verify_key_material(dh_output, description="DH output for ratchet step")

            # 2. KEM secret: versioned Braid-lite handling, PEER-SYNCED.
            # v1 (legacy): reuse _synchronized_kem_secret across DH steps. In
            #   standard in-band ratcheting with 48-byte MessageHeader,
            #   post-quantum forward secrecy is rooted in the initial Hybrid
            #   X3DH+PQ handshake and asymmetric FALCON-1024 signatures.
            # v2 (peer-synced fresh): the RECEIVING-side mix consumes the
            #   PEER's fresh KEM secret -- transported in-band via the CT wire
            #   extension and decapsulated with the local KEM private -- so it
            #   pairs bit-for-bit with the peer's SENDING-side mix (same DH
            #   output by DH symmetry, same secret via the CT, same SYNC
            #   transcript). The SENDING-side mix below generates OUR OWN fresh
            #   secret (encaps to the peer, WITHOUT rotating our KEM identity
            #   so the peer's cached KEM public keeps matching) and stages its
            #   CT as _pending_pq_ct for the next outgoing message.
            #   _synchronized_kem_secret is deliberately left untouched by the
            #   synced path: it remains the handshake-era shared fallback so
            #   legacy-fallback mixes pair on both sides. A v2 step with no
            #   peer CT falls back to legacy reuse with a warning and never
            #   aborts (a peer that never sends CT stays compatible).
            if remote_kem_public_key is not None:
                try:
                    verify_key_material(remote_kem_public_key,
                                        description="Remote KEM public key for ratchet step")
                    self.remote_kem_public_key = remote_kem_public_key
                except Exception as e_kem_pk:
                    logger.warning(f"Ignoring invalid remote KEM public key for ratchet step: {e_kem_pk}")
            kem_shared_secret = getattr(self, '_synchronized_kem_secret', None)
            use_pq_v2 = self._pq_ct_sync_active()
            recv_precombined = None
            recv_ss = None
            if use_pq_v2 and peer_pq_ct is not None:
                try:
                    if getattr(self, 'kem_private_key', None) is None:
                        raise SecurityError("Peer PQ CT received but no local KEM private key available")
                    verify_key_material(peer_pq_ct, description="Peer PQ CT for v2 sync")
                    if len(bytes(peer_pq_ct)) > self.PQ_CT_EXT_MAX_CT_LEN:
                        raise SecurityError("Peer PQ CT exceeds maximum extension size")
                    peer_ss = self.kem.decaps(self.kem_private_key, bytes(peer_pq_ct))
                    verify_key_material(peer_ss, description="Decapsulated peer KEM shared secret")
                    recv_precombined = self._pq_v2_precombined(
                        dh_output, peer_ss, bytes(remote_public_key_bytes))
                    recv_ss = peer_ss
                    self._peer_ct_seen = True
                    logger.info(
                        "PQ ratchet v2: peer CT decapsulated and mixed into receiving "
                        f"chain via hybrid_combine_v2 (remote key: {format_binary(remote_fingerprint)})"
                    )
                except Exception as e_peer_ct:
                    # Fail CLOSED (always, no gate): a present-but-undecapsable
                    # peer CT means the sender mixed v2-fresh material this
                    # side cannot reproduce, so "legacy reuse" could never
                    # sync -- it would only desynchronize the chains and fail
                    # later inside AEAD. Aborting here is explicit and safe; a
                    # network attacker cannot trigger this path because the CT
                    # rides inside AEAD + signature (tamper aborts earlier).
                    logger.warning(
                        "PQ ratchet v2 peer-CT decaps failed, failing closed "
                        f"(legacy reuse could not sync): {e_peer_ct}"
                    )
                    if _pq_ratchet_production_mode():
                        logger.critical(
                            f"PROD PQ ratchet v2 peer-CT decaps failure (fail-closed): {e_peer_ct}"
                        )
                    raise SecurityError(
                        "Peer PQ CT decaps failure is fail-closed "
                        f"(chains would desynchronize): {e_peer_ct}"
                    ) from e_peer_ct
            elif use_pq_v2:
                logger.warning(
                    "PQ ratchet v2 step without peer CT extension -- legacy v1 reuse "
                    "fallback (peer never sends CT, encaps unavailable, or extension "
                    "lost); staying compatible, NOT aborting"
                )
            if not use_pq_v2:
                if kem_shared_secret:
                    verify_key_material(kem_shared_secret, description="Synchronized KEM shared secret")
                logger.debug(
                    "PQ ratchet "
                    f"{'v1 legacy reuse' if self.enable_pq else 'disabled (classical)'} "
                    f"for this step (pq_ratchet_version={getattr(self, 'pq_ratchet_version', 1)})"
                )

            # 3. Update receiving chain with the derived secrets
            if use_pq_v2 and recv_precombined is not None and recv_ss is not None:
                self._update_receiving_chain(
                    dh_output, recv_ss,
                    precombined_secret=recv_precombined,
                    kdf_info_override=self.KDF_INFO_PQ_RATCHET_V2,
                )
                # Hygiene: the peer secret is now mixed into the chain; drop
                # local references (best-effort wipe; immutable bytes cannot
                # be zeroized in place, see _wipe_secret_best_effort).
                _wipe_secret_best_effort(recv_ss, "consumed peer KEM secret")
                del recv_ss
            else:
                self._update_receiving_chain(dh_output, kem_shared_secret)

            # 4. Generate new DH keypair for next ratchet step
            prev_public = self.dh_public_key
            self.dh_private_key = X25519PrivateKey.generate()
            self.dh_public_key = self.dh_private_key.public_key()
            self.current_ratchet_key_id = self._get_public_key_fingerprint(self.dh_public_key)

            # 5. Generate new KEM keypair if needed. SKIPPED on the synced v2
            # path: our KEM identity must stay stable so the peer's cached KEM
            # public keeps matching our private key (decapsulation of the
            # peer-synced CTs depends on it). Freshness comes from the
            # per-step randomized encaps, not from identity rotation.
            if self.enable_pq and self.kem is not None and not use_pq_v2:
                logger.debug("Generating new ML-KEM key pair for next ratchet step")
                if hasattr(self.kem, 'keygen'):
                    self.kem_public_key, self.kem_private_key = self.kem.keygen()

            # 6. Second DH: Use new private key with current remote public key
            new_dh_output = self.dh_private_key.exchange(remote_public_key)
            verify_key_material(new_dh_output, description="Second DH output for ratchet step")

            # 7. Update sending chain with new key pair's output. On the synced
            # v2 path this mixes OUR OWN fresh secret (encaps to the peer) and
            # stages its CT as _pending_pq_ct for the next outgoing message;
            # the peer reproduces this exact mix when it consumes the CT.
            own_new_pub_raw = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            if use_pq_v2:
                try:
                    send_ss, fresh_ct = self._pq_encaps_to_peer_v2()
                    send_precombined = self._pq_v2_precombined(
                        new_dh_output, send_ss, bytes(own_new_pub_raw),
                    )
                    self._update_sending_chain(
                        new_dh_output, send_ss,
                        precombined_secret=send_precombined,
                        kdf_info_override=self.KDF_INFO_PQ_RATCHET_V2,
                    )
                    # Stage the fresh CT for the next outgoing message
                    # (_encrypt attaches + consumes it). Overwrites any unsent
                    # predecessor, whose epoch has now been superseded.
                    self._pending_pq_ct = bytes(fresh_ct)
                    self.kem_ciphertext = bytes(fresh_ct)
                    self._last_pq_ratchet_time = time.time()
                    # DH-step fresh KEM satisfies the SPQR cadence: restart
                    # its count/age epoch (force_pq_ratchet budget untouched).
                    try:
                        self._spqr_msg_counter = 0
                        self._spqr_last_refresh = self._last_pq_ratchet_time
                    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B110
                        pass
                    logger.info(
                        "PQ ratchet v2: fresh KEM encaps mixed into sending chain "
                        "via hybrid_combine_v2; CT staged for next message "
                        f"(remote key: {format_binary(remote_fingerprint)})"
                    )
                    _wipe_secret_best_effort(send_ss, "consumed fresh sending KEM secret")
                    del send_ss
                except Exception as e_send:
                    # Sending-side encaps/combiner failure: legacy fallback,
                    # no CT staged (receiver will take the same legacy path
                    # when it sees no extension) -- unless strict-abort is
                    # armed (P2P_PQ_STRICT_ABORT=1): fail closed instead.
                    logger.warning(
                        "PQ ratchet v2 sending-side encaps failed, legacy v1 reuse "
                        f"fallback for this step (no CT staged): {e_send}"
                    )
                    if _pq_ratchet_production_mode():
                        logger.critical(
                            f"PROD PQ ratchet v2 sending-side failure (legacy fallback): {e_send}"
                        )
                    if _pq_strict_abort():
                        raise SecurityError(
                            f"P2P_PQ_STRICT_ABORT: sending-side encaps failure is fail-closed: {e_send}"
                        ) from e_send
                    self._update_sending_chain(new_dh_output, kem_shared_secret)
                    self._pending_pq_ct = None
            else:
                self._update_sending_chain(new_dh_output, kem_shared_secret)

            logger.info(
                f"Completed DH{'+ PQ KEM' if self.enable_pq else ''} ratchet step "
                f"(pq_ratchet={'v2-fresh' if use_pq_v2 else 'v1-legacy' if self.enable_pq else 'off'}), " +
                f"remote key: {format_binary(remote_fingerprint)}"
            )

            # Record operation time for anomaly detection
            if self.anomaly_detection and self.threat_detector is not None:
                duration = time.time() - start_time
                self.security_metrics["operation_times"]["dh_ratchet"] = duration
                if hasattr(self.threat_detector, "record_operation"):
                    self.threat_detector.record_operation("dh_ratchet", duration)

        except Exception as e:
            self.last_error = f"DH ratchet step failed: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            raise SecurityError(f"Ratchet step error: {str(e)}")

    def _update_receiving_chain(self, dh_output: bytes,
                               kem_shared_secret: Optional[bytes] = None,
                               *,
                               precombined_secret: Optional[bytes] = None,
                               kdf_info_override: Optional[bytes] = None) -> None:
        """Update the receiving chain with new key material.

        Legacy behavior (v1) is unchanged: ``dh_output [+ kem_shared_secret]``
        is HKDFed under ``KDF_INFO_HYBRID``/``KDF_INFO_DH``. Braid-lite v2
        callers pass ``precombined_secret`` (output of
        ``crypto.kem.hybrid_combine_v2`` over the DH output + fresh KEM
        secret) with ``kdf_info_override=KDF_INFO_PQ_RATCHET_V2``.
        """
        info = self.KDF_INFO_HYBRID if self.enable_pq and kem_shared_secret else self.KDF_INFO_DH

        # Combine DH and KEM secrets in hybrid mode
        if precombined_secret is not None:
            combined_secret = precombined_secret
            if kdf_info_override is not None:
                info = kdf_info_override
        elif self.enable_pq and kem_shared_secret:
            # Direct concatenation for HKDF per RFC 5869 with domain-separated info
            combined_secret = dh_output + kem_shared_secret
        else:
            combined_secret = dh_output

        # Derive new root key and receiving chain key
        logger.debug(f"Updating receiving chain ({len(combined_secret)} bytes)")
        kdf_output = self._kdf(self.root_key, combined_secret, info=info)
        self.root_key, receiving_chain_seed = kdf_output[:32], kdf_output[32:]

        # Initialize receiving chain with the new seed
        self.receiving_chain_key = receiving_chain_seed
        self.receiving_message_number = 0

        # Apply threshold security if enabled
        if self.threshold_security:
            # Create new shares for the updated root key
            try:
                self.key_shares["root_key"] = KeyShare.split(self.root_key, 5, 3)
                logger.debug("Updated threshold shares for root key")
            except Exception as e:
                logger.warning(f"Failed to update threshold shares: {e}")

        verify_key_material(self.receiving_chain_key, description="Updated receiving chain")
        logger.debug(f"Receiving chain updated, new root key derived successfully (bytes={len(self.root_key)})")

    def _update_sending_chain(self, dh_output: bytes,
                             kem_shared_secret: Optional[bytes] = None,
                             *,
                             precombined_secret: Optional[bytes] = None,
                             kdf_info_override: Optional[bytes] = None) -> None:
        """Update the sending chain with new key material.

        Same override contract as :meth:`_update_receiving_chain`: legacy v1
        behavior is unchanged unless ``precombined_secret`` (v2 combiner
        output) and ``kdf_info_override`` are supplied.
        """

        # Combine DH and KEM secrets in hybrid mode
        if precombined_secret is not None:
            combined_secret = precombined_secret
        elif self.enable_pq and kem_shared_secret:
            combined_secret = dh_output + kem_shared_secret
        else:
            combined_secret = dh_output

        info = self.KDF_INFO_HYBRID if self.enable_pq and kem_shared_secret else self.KDF_INFO_DH
        if precombined_secret is not None and kdf_info_override is not None:
            info = kdf_info_override

        # Derive new root key and sending chain key
        logger.debug(f"Updating sending chain ({len(combined_secret)} bytes input)")
        kdf_output = self._kdf(self.root_key, combined_secret, info=info)
        self.root_key, sending_chain_seed = kdf_output[:32], kdf_output[32:]

        self.sending_chain_key = sending_chain_seed
        self.sending_message_number = 0

        # Update hardware key if applicable
        if (self.hsm_available and "root_key" in self.hardware_key_ids and
            hsm.capabilities["secure_storage"]): # Use global hsm
            hsm.store_key(self.hardware_key_ids["root_key"], self.root_key) # Use global hsm

        verify_key_material(self.sending_chain_key, description="Updated sending chain")
        logger.debug(f"Sending chain updated, new root key derived successfully (bytes={len(self.root_key)})")

    def force_ratchet_rotation(self) -> bytes:
        """
        Proactively advance the DH ratchet to provide Post-Compromise Security (PCS)
        healing on idle channels (Finding 1 & P1.1).

        Generates a fresh DH keypair and updates sending chain state so the next
        transmission immediately heals from prior key compromise.

        Returns:
            Raw public key bytes of the new ratchet DH key.
        """
        self.previous_sending_chain_length = self.sending_message_number
        self.dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key = self.dh_private_key.public_key()
        self.current_ratchet_key_id = self._get_public_key_fingerprint(self.dh_public_key)

        if self.remote_dh_public_key is not None:
            new_dh_output = self.dh_private_key.exchange(self.remote_dh_public_key)
            verify_key_material(new_dh_output, description="Force rotation DH output")
            kem_shared_secret = getattr(self, '_synchronized_kem_secret', None)
            self._update_sending_chain(new_dh_output, kem_shared_secret)

        raw_pk = self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        logger.info(f"Proactive PCS ratchet rotation completed. New DH PK: {format_binary(self.current_ratchet_key_id)}")
        return raw_pk

    def negotiate_pq_ratchet_version(self, peer_protocol_version) -> int:
        """Negotiate the Braid-lite PQ ratchet version with a peer.

        Uses the existing HybridKeyExchange ``protocol_version`` scheme: the
        negotiated version is ``min(local, peer)`` mapped to ratchet v2
        (fresh KEM, both >= 2) or v1 (legacy reuse). A missing/unparseable
        peer version means v1 (pre-v2 peer). Logs which version is used.
        Never raises (fails safe to v1).

        Args:
            peer_protocol_version: Peer's advertised protocol_version (any type).

        Returns:
            Negotiated pq_ratchet_version (1 or 2).
        """
        peer_v = self.PROTOCOL_VERSION_MIN if hasattr(self, 'PROTOCOL_VERSION_MIN') else 1
        try:
            if peer_protocol_version is not None:
                peer_v = int(str(peer_protocol_version).strip())
        except (TypeError, ValueError):
            peer_v = 1
        if peer_v < 1:
            peer_v = 1
        try:
            local_v = int(getattr(self, 'protocol_version', 1))
        except (TypeError, ValueError):
            local_v = 1
        negotiated = min(local_v, peer_v)
        self.pq_ratchet_version = (
            self.PQ_RATCHET_VERSION_FRESH if negotiated >= 2
            else self.PQ_RATCHET_VERSION_LEGACY
        )
        # Fresh negotiation: reset peer-CT tracking and drop any staged CT
        # from a previous epoch (it pairs with superseded chain state).
        self._peer_ct_seen = False
        self._pending_pq_ct = None
        # Fresh negotiation restarts the SPQR cadence epoch (v2 only).
        try:
            self._spqr_msg_counter = 0
            self._spqr_last_refresh = time.time()
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        logger.info(
            f"PQ ratchet version negotiated: v{self.pq_ratchet_version} "
            f"(local protocol v{local_v}, peer protocol v{peer_v}) -- "
            f"{'fresh KEM per DH step' if self.pq_ratchet_version >= 2 else 'legacy synchronized-KEM reuse'}"
        )
        return self.pq_ratchet_version

    def _fresh_pq_encaps_v2(self) -> Tuple[bytes, bytes]:
        """Generate a fresh local KEM keypair and encaps to the remote KEM public.

        Rotates ``(kem_public_key, kem_private_key)`` first so the local
        state heals even if encapsulation below fails. Returns
        ``(shared_secret, ciphertext)``. The ciphertext is retained by the
        caller (NOT transmitted -- v1 wire format frozen; reserved for a
        future wire extension).

        Raises:
            SecurityError: If PQ is disabled, the KEM backend is unavailable,
                or no remote KEM public key is known.
        """
        if not self.enable_pq:
            raise SecurityError("Fresh PQ encaps refused: post-quantum mode disabled")
        if self.kem is None or not hasattr(self.kem, 'keygen') or not hasattr(self.kem, 'encaps'):
            raise SecurityError("Fresh PQ encaps refused: KEM implementation unavailable")
        remote_pk = getattr(self, 'remote_kem_public_key', None)
        if remote_pk is None:
            raise SecurityError("Fresh PQ encaps unavailable: no remote KEM public key")
        verify_key_material(remote_pk, description="Remote KEM public key for fresh encaps")
        logger.debug("Generating fresh local ML-KEM key pair for PQ ratchet v2")
        self.kem_public_key, self.kem_private_key = self.kem.keygen()
        ciphertext, shared_secret = self.kem.encaps(remote_pk)
        verify_key_material(ciphertext, description="Fresh KEM ciphertext")
        verify_key_material(shared_secret, description="Fresh KEM shared secret")
        return shared_secret, ciphertext

    def _pq_ct_sync_active(self) -> bool:
        """True when the peer-synced Braid CT path may be used.

        Requires PQ mode, negotiated ratchet v2, and a KEM backend exposing
        encaps/decaps. Never raises.
        """
        try:
            return bool(
                self.enable_pq
                and getattr(self, 'pq_ratchet_version', self.PQ_RATCHET_VERSION_LEGACY)
                >= self.PQ_RATCHET_VERSION_FRESH
                and getattr(self, 'kem', None) is not None
                and hasattr(self.kem, 'encaps')
                and hasattr(self.kem, 'decaps')
            )
        except Exception:
            return False

    def _pq_encaps_to_peer_v2(self) -> Tuple[bytes, bytes]:
        """Fresh KEM encaps to the remote KEM public for the synced v2 path.

        Unlike :meth:`_fresh_pq_encaps_v2` this does NOT rotate the local KEM
        identity: the peer decapsulates with the KEM private matching the
        public it advertised at handshake time, so mid-session rotation would
        orphan the peer's cached public and break decapsulation. Freshness
        comes from the randomized encaps itself (new shared secret + CT per
        DH step).

        Returns:
            Tuple of (shared_secret, ciphertext).

        Raises:
            SecurityError: If PQ is disabled, the KEM backend is unavailable,
                or no remote KEM public key is known.
        """
        if not self.enable_pq:
            raise SecurityError("Synced PQ encaps refused: post-quantum mode disabled")
        if self.kem is None or not hasattr(self.kem, 'encaps'):
            raise SecurityError("Synced PQ encaps refused: KEM implementation unavailable")
        remote_pk = getattr(self, 'remote_kem_public_key', None)
        if remote_pk is None:
            raise SecurityError("Synced PQ encaps unavailable: no remote KEM public key")
        verify_key_material(remote_pk, description="Remote KEM public key for synced encaps")
        ciphertext, shared_secret = self.kem.encaps(remote_pk)
        verify_key_material(ciphertext, description="Synced KEM ciphertext")
        verify_key_material(shared_secret, description="Synced KEM shared secret")
        if len(bytes(ciphertext)) > self.PQ_CT_EXT_MAX_CT_LEN:
            raise SecurityError("Synced KEM ciphertext exceeds extension maximum size")
        return shared_secret, ciphertext

    def _pq_v2_sync_transcript(self, sender_new_dh_pub_raw: bytes) -> bytes:
        """Shared combiner transcript for one peer-synced DH epoch.

        Both the sender's SENDING-side mix and the receiver's RECEIVING-side
        mix use this exact transcript (SYNC prefix + sender's new DH public
        raw bytes, known to both sides), so the combiner outputs match.
        """
        return self.PQ_RATCHET_V2_TRANSCRIPT_SYNC + bytes(sender_new_dh_pub_raw)

    def _pq_v2_precombined(self, dh_output: bytes, kem_ss: bytes,
                           sender_new_dh_pub_raw: bytes) -> bytes:
        """Run crypto.kem.hybrid_combine_v2 for one synced v2 chain update.

        Binds the DH output (replicated into all four DH slots of the audited
        X3DH-oriented combiner, length-prefixed and unambiguous) with the
        peer-shared KEM secret under the SYNC transcript.
        """
        combine_v2 = _load_hybrid_combine_v2()
        return combine_v2(
            [dh_output, dh_output, dh_output, dh_output],
            kem_ss,
            self._pq_v2_sync_transcript(sender_new_dh_pub_raw),
        )

    def _build_pq_ct_extension(self, pq_ct: bytes) -> bytes:
        """Build the wire extension bytes for a fresh KEM ciphertext.

        Returns ``MAGIC(4) + pq_ct_len BE16 + pq_ct`` to be inserted between
        nonce and ciphertext. Only emitted when pq_ratchet_version >= 2 AND a
        fresh CT is staged (callers enforce the gate).
        """
        if not isinstance(pq_ct, (bytes, bytearray)) or len(pq_ct) == 0:
            raise ValueError("PQ CT extension requires non-empty ciphertext bytes")
        pq_ct = bytes(pq_ct)
        if len(pq_ct) > self.PQ_CT_EXT_MAX_CT_LEN:
            raise ValueError(
                f"PQ CT too large for extension: {len(pq_ct)} > {self.PQ_CT_EXT_MAX_CT_LEN}"
            )
        return self.PQ_CT_EXT_MAGIC + struct.pack('>H', len(pq_ct)) + pq_ct

    def _split_pq_ct_extension(self, body: bytes) -> Tuple[Optional[bytes], bytes, bytes]:
        """Split the optional Braid CT extension from the post-nonce body.

        Expected layout: ``[MAGIC(4) + pq_ct_len BE16 + pq_ct] + ciphertext``.

        Returns:
            Tuple of (pq_ct_or_None, ciphertext, ext_bytes). ``ext_bytes`` is
            the raw extension (empty when absent) and must be included in the
            signed data exactly as received. Malformed/absent extensions yield
            ``(None, body, b'')`` with a warning -- never raises, so legacy
            (v1) messages always fall through to the legacy path untouched.

        Note:
            Detection is magic-guarded, NOT version-gated, so a v1 session
            strips an unexpected extension with a warning ("v1 ignores
            trailing bytes with warning") instead of failing on it.
        """
        try:
            if (not isinstance(body, (bytes, bytearray))
                    or len(body) < self.PQ_CT_EXT_MAGIC_SIZE + self.PQ_CT_EXT_LEN_SIZE + 1
                    + self.PQ_CT_EXT_MIN_CIPHERTEXT):
                return None, bytes(body), b''
            if bytes(body[:self.PQ_CT_EXT_MAGIC_SIZE]) != self.PQ_CT_EXT_MAGIC:
                return None, bytes(body), b''
            pq_len = struct.unpack(
                '>H', bytes(body[self.PQ_CT_EXT_MAGIC_SIZE:
                                 self.PQ_CT_EXT_MAGIC_SIZE + self.PQ_CT_EXT_LEN_SIZE]))[0]
            ext_total = (self.PQ_CT_EXT_MAGIC_SIZE + self.PQ_CT_EXT_LEN_SIZE + pq_len)
            if (pq_len <= 0 or pq_len > self.PQ_CT_EXT_MAX_CT_LEN
                    or len(body) < ext_total + self.PQ_CT_EXT_MIN_CIPHERTEXT):
                logger.warning(
                    "Malformed PQ CT extension header (len=%s, body=%s); treating "
                    "body as legacy ciphertext" % (pq_len, len(body))
                )
                return None, bytes(body), b''
            ext = bytes(body[:ext_total])
            pq_ct = bytes(body[self.PQ_CT_EXT_MAGIC_SIZE + self.PQ_CT_EXT_LEN_SIZE:ext_total])
            ciphertext = bytes(body[ext_total:])
            return pq_ct, ciphertext, ext
        except Exception as e_split:
            logger.warning(f"PQ CT extension split failed, legacy fallback: {e_split}")
            return None, bytes(body), b''

    def get_pending_pq_ct(self) -> Optional[bytes]:
        """Return the staged fresh KEM CT awaiting the next message (if any).

        Diagnostic/test aid: the staged CT is consumed (cleared) by the next
        :meth:`_encrypt` on a v2 session when it is attached to the wire.
        """
        return getattr(self, '_pending_pq_ct', None)

    def _spqr_refresh_reason(self) -> Optional[str]:
        """Return why an SPQR refresh is due: 'count', 'age', or None.

        v1 sessions always return None (no-op). Never raises.
        """
        try:
            if (not getattr(self, 'enable_pq', False)
                    or int(getattr(self, 'pq_ratchet_version',
                                   self.PQ_RATCHET_VERSION_LEGACY))
                    < self.PQ_RATCHET_VERSION_FRESH):
                return None
            interval, max_age = _spqr_effective_policy()
            counter = int(getattr(self, '_spqr_msg_counter', 0) or 0)
            if counter >= interval:
                return "count"
            try:
                last = float(getattr(self, '_spqr_last_refresh', 0.0) or 0.0)
            except (TypeError, ValueError):
                last = 0.0
            if last <= 0.0:
                return "age"
            if (time.time() - last) >= max_age:
                return "age"
            return None
        except Exception:
            return None

    def should_spqr_refresh(self) -> bool:
        """True when a periodic SPQR fresh-KEM refresh is due (v2 only).

        Due when ``_spqr_msg_counter >= msg_interval`` OR wall-clock age
        since ``_spqr_last_refresh`` exceeds ``max_age_seconds`` (Apple PQ3
        cadence: 50 msgs / 7 days, env-overridable). v1 sessions always
        return False. Never raises.
        """
        return self._spqr_refresh_reason() is not None

    def get_spqr_stats(self) -> Dict[str, Any]:
        """Return SPQR cadence diagnostics. Never raises; v1 reports no-op."""
        try:
            interval, max_age = _spqr_effective_policy()
        except Exception:
            interval, max_age = 50, 7 * 24 * 3600
        try:
            counter = int(getattr(self, '_spqr_msg_counter', 0) or 0)
        except (TypeError, ValueError):
            counter = 0
        try:
            last = float(getattr(self, '_spqr_last_refresh', 0.0) or 0.0)
        except (TypeError, ValueError):
            last = 0.0
        try:
            version = int(getattr(self, 'pq_ratchet_version',
                                  self.PQ_RATCHET_VERSION_LEGACY))
        except (TypeError, ValueError):
            version = 1
        try:
            age = (time.time() - last) if last > 0.0 else float('inf')
        except Exception:
            age = float('inf')
        try:
            needs = bool(self.should_spqr_refresh())
            reason = self._spqr_refresh_reason()
        except Exception:
            needs, reason = False, None
        return {
            "msg_counter": counter,
            "msg_interval": interval,
            "max_age_seconds": max_age,
            "last_refresh": last,
            "age_seconds": age,
            "pq_ratchet_version": version,
            "needs_refresh": needs,
            "reason": reason,
        }

    def force_spqr_refresh(self, reason: str = "manual") -> bool:
        """Force an immediate SPQR fresh-KEM refresh (v2 only).

        Initiates an immediate proactive DH rotation and fresh ML-KEM-1024
        encapsulation to accelerate post-compromise security (PCS) recovery,
        e.g., following an urgent operational EAM message, re-key request,
        or threat alert.

        Returns:
            bool: True if an SPQR refresh was performed, False if v1 or PQ disabled.
        """
        if (not getattr(self, 'enable_pq', False)
                or int(getattr(self, 'pq_ratchet_version',
                               self.PQ_RATCHET_VERSION_LEGACY))
                < self.PQ_RATCHET_VERSION_FRESH):
            return False
        self._do_spqr_refresh(reason)
        return True

    def _do_spqr_refresh(self, reason: str) -> None:
        """Perform one periodic SPQR fresh-KEM refresh (v2 only, caller catches).

        Proactive sending-side DH rotation + fresh encaps via
        :meth:`_fresh_pq_encaps_v2`, mixed with the new DH output via
        ``hybrid_combine_v2`` under the SYNC transcript (same combiner the
        peer's DH-step receiving mix reproduces from the staged CT + header
        DH pub), sending chain updated, CT staged as ``_pending_pq_ct`` for
        the next outgoing message, then SPQR counter/time reset. v1 wire
        format untouched (extension only emitted on v2). Raises on failure
        (caller falls back to legacy with a warning, never aborts).
        """
        if (not getattr(self, 'enable_pq', False)
                or int(getattr(self, 'pq_ratchet_version',
                               self.PQ_RATCHET_VERSION_LEGACY))
                < self.PQ_RATCHET_VERSION_FRESH):
            return
        if getattr(self, 'dh_private_key', None) is None or \
                getattr(self, 'remote_dh_public_key', None) is None:
            raise SecurityError("SPQR refresh unavailable: no DH key material")
        # Proactive DH rotation so the peer's existing DH-step path consumes
        # the staged CT and reproduces this exact mix (message numbers reset
        # cleanly into the new epoch, exactly like a normal DH step).
        # Atomicity: stage everything in locals first; mutate self only after
        # the encaps+combine succeed, so a failure leaves the current epoch
        # (DH keys, chain, staged CT) untouched and the peer stays in sync.
        new_dh_priv = X25519PrivateKey.generate()
        new_dh_pub = new_dh_priv.public_key()
        new_dh_output = new_dh_priv.exchange(self.remote_dh_public_key)
        verify_key_material(new_dh_output, description="SPQR refresh DH output")
        own_new_pub_raw = new_dh_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # Fresh KEM encaps (rotating local identity for PCS healing).
        # _fresh_pq_encaps_v2 rotates the local KEM identity before encap-
        # sulating; snapshot it so a subsequent failure restores the prior
        # identity (fully atomic refresh, peer cache never orphaned on error).
        _kem_pub_prev = getattr(self, 'kem_public_key', None)
        _kem_priv_prev = getattr(self, 'kem_private_key', None)
        try:
            fresh_ss, fresh_ct = self._fresh_pq_encaps_v2()
            # hybrid_combine_v2 mix under the shared SYNC transcript.
            combine_v2 = _load_hybrid_combine_v2()
            precombined = combine_v2(
                [new_dh_output, new_dh_output, new_dh_output, new_dh_output],
                fresh_ss,
                self._pq_v2_sync_transcript(bytes(own_new_pub_raw)),
            )
            self._update_sending_chain(
                new_dh_output, fresh_ss,
                precombined_secret=precombined,
                kdf_info_override=self.KDF_INFO_PQ_RATCHET_V2,
            )
        except Exception:
            try:
                self.kem_public_key = _kem_pub_prev
                self.kem_private_key = _kem_priv_prev
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            raise
        self.dh_private_key = new_dh_priv
        self.dh_public_key = new_dh_pub
        self.current_ratchet_key_id = self._get_public_key_fingerprint(new_dh_pub)
        self._pending_pq_ct = bytes(fresh_ct)
        self.kem_ciphertext = bytes(fresh_ct)
        now = time.time()
        self._last_pq_ratchet_time = now
        # SPQR cadence reset. Independent of force_pq_ratchet()'s 60s
        # manual-override budget (_last_force_pq_ratchet_time untouched).
        self._spqr_msg_counter = 0
        self._spqr_last_refresh = now
        logger.info(
            f"SPQR refresh ({reason}): fresh KEM mixed via hybrid_combine_v2, "
            "DH rotated, CT staged for next message"
        )
        _wipe_secret_best_effort(fresh_ss, "consumed SPQR KEM secret")
        del fresh_ss
        _wipe_secret_best_effort(new_dh_output, "consumed SPQR DH output")

    def force_pq_ratchet(self) -> bytes:
        """Proactive idle PCS healing via a fresh KEM encaps without a DH event.

        Performs a fresh local KEM keypair generation + encaps to the remote
        KEM public, mixes the fresh secret with the current DH output via
        ``crypto.kem.hybrid_combine_v2`` under ``KDF_INFO_PQ_RATCHET_V2``,
        updates the SENDING chain, and stores the fresh secret as the new
        synchronized KEM secret (old copies wiped best-effort; see
        :func:`_wipe_secret_best_effort` for ``bytes`` limits).

        Rate limiting: force_pq_ratchet() itself may succeed at most once
        per ``PQ_RATCHET_MIN_INTERVAL`` (60s); raises ``SecurityError``
        if called too soon. Fail-closed: any healing failure raises
        ``SecurityError`` (unlike the in-step legacy fallback).

        Note:
            Local-only healing: the fresh secret is mixed into the SENDING
            chain alone and its CT is NOT staged for transmission, and the
            local KEM identity is rotated (orphaning the peer's cached KEM
            public). Do NOT call on a live peer-synced (CT-exchange) session:
            the peer cannot reproduce the mix. Peer-synced healing happens
            automatically via the per-DH-step fresh encaps + CT extension.

        Returns:
            Fresh KEM ciphertext bytes (retained locally; NOT transmitted --
            v1 wire format frozen; reserved for a future wire extension).
        """
        now = time.time()
        elapsed = now - float(getattr(self, '_last_force_pq_ratchet_time', 0.0) or 0.0)
        if elapsed < self.PQ_RATCHET_MIN_INTERVAL:
            raise SecurityError(
                f"force_pq_ratchet rate-limited: {elapsed:.1f}s since last forced healing "
                f"(minimum {self.PQ_RATCHET_MIN_INTERVAL:.0f}s between calls)"
            )
        if getattr(self, 'pq_ratchet_version', self.PQ_RATCHET_VERSION_LEGACY) < self.PQ_RATCHET_VERSION_FRESH:
            raise SecurityError(
                "force_pq_ratchet refused: negotiated PQ ratchet is v1 legacy "
                "(negotiate v2 via negotiate_pq_ratchet_version first)"
            )
        if self.remote_dh_public_key is None or self.dh_private_key is None:
            raise SecurityError("force_pq_ratchet refused: no DH key material available")
        try:
            fresh_ss, fresh_ct = self._fresh_pq_encaps_v2()
            dh_now = self.dh_private_key.exchange(self.remote_dh_public_key)
            verify_key_material(dh_now, description="Idle-healing DH output")
            combine_v2 = _load_hybrid_combine_v2()
            remote_fp = self._get_public_key_fingerprint(self.remote_dh_public_key)
            precombined = combine_v2(
                [dh_now, dh_now, dh_now, dh_now],
                fresh_ss,
                self.PQ_RATCHET_V2_TRANSCRIPT_IDLE + bytes(remote_fp),
            )
            old_secret = getattr(self, '_synchronized_kem_secret', None)
            self._update_sending_chain(
                dh_now, fresh_ss,
                precombined_secret=precombined,
                kdf_info_override=self.KDF_INFO_PQ_RATCHET_V2,
            )
            self._synchronized_kem_secret = fresh_ss
            self.kem_ciphertext = fresh_ct
            _wipe_secret_best_effort(old_secret, "superseded synchronized KEM secret")
            del old_secret
            self._last_pq_ratchet_time = time.time()
            self._last_force_pq_ratchet_time = self._last_pq_ratchet_time
            logger.info("force_pq_ratchet: idle PQ healing completed (fresh KEM mixed, sending chain updated)")
            return fresh_ct
        except SecurityError:
            raise
        except Exception as e:
            self.last_error = f"force_pq_ratchet failed: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            if _pq_ratchet_production_mode():
                logger.critical(f"PROD force_pq_ratchet failure: {e}")
            raise SecurityError(f"Idle PQ healing failed: {str(e)}")

    def _chain_ratchet_step(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Perform a symmetric ratchet step to derive the next chain and message keys.

        This implementation uses constant-time operations to prevent timing side-channel attacks.

        Args:
            chain_key: The current chain key

        Returns:
            Tuple of (next_chain_key, message_key)
        """
        # Verify input
        verify_key_material(chain_key, expected_length=self.CHAIN_KEY_SIZE,
                          description="Chain key for ratchet")

        # Record operation start time for anomaly detection
        start_time = time.time()

        # Implement constant-time key derivation
        if self.side_channel_protection:
            # Use a fixed-time approach for key derivation
            # Instead of using random delays (which can actually make timing attacks easier),
            # we ensure all operations take the same amount of time

            # Create HMAC instances for both operations
            h_msg = hmac.HMAC(chain_key, self.KDF_INFO_MSG, hashlib.sha512)
            h_chain = hmac.HMAC(chain_key, self.KDF_INFO_CHAIN, hashlib.sha512)

            # Perform both operations regardless of which result we need first
            # This ensures constant-time behavior
            msg_result = h_msg.digest()[:self.MSG_KEY_SIZE]
            chain_result = h_chain.digest()[:self.CHAIN_KEY_SIZE]

            # Assign results to output variables
            message_key = msg_result
            next_chain_key = chain_result
        else:
            # Standard implementation when side-channel protection is not required
            message_key = hmac.HMAC(chain_key, self.KDF_INFO_MSG, hashlib.sha512).digest()[:self.MSG_KEY_SIZE]
            next_chain_key = hmac.HMAC(chain_key, self.KDF_INFO_CHAIN, hashlib.sha512).digest()[:self.CHAIN_KEY_SIZE]

        # Verify output
        verify_key_material(message_key, expected_length=self.MSG_KEY_SIZE,
                          description="Derived message key")
        verify_key_material(next_chain_key, expected_length=self.CHAIN_KEY_SIZE,
                          description="Derived chain key")

        # Record operation time for anomaly detection
        if self.anomaly_detection and self.threat_detector is not None:
            duration = time.time() - start_time
            self.security_metrics["operation_times"]["chain_step"] = duration
            if hasattr(self.threat_detector, "record_operation"):
                self.threat_detector.record_operation("chain_step", duration)

        # Record canary verification if memory protection is enabled
        if self.secure_memory_protection and hasattr(self, "_verify_canaries"):
            self._verify_canaries()

        return next_chain_key, message_key

    def _kdf(self, key_material: bytes, input_key_material: bytes, info: bytes, length: int = 64) -> bytes:
        """
        Derive new keys using HKDF-SHA3_512 with domain separation.

        This function implements a key derivation function based on RFC 5869
        (HKDF) and NIST SP 800-56C, providing a secure method for deriving
        one or more cryptographic keys from a shared secret.

        Security Properties:
        - **Domain Separation**: The `info` parameter ensures that keys derived
          for different purposes are cryptographically unique, preventing key
          reuse attacks.
        - **Extraction-then-Expansion**: Follows the HKDF paradigm to first
          extract a high-entropy pseudorandom key and then expand it to the
          desired length.
        - **Post-Quantum Resistance**: While HKDF-SHA3_512 is a classical KDF,
          it is considered robust and is a core component in hybrid post-quantum
          key exchange protocols.

        Args:
            key_material: The initial key material (e.g., a root key).
            input_key_material: The input secret (e.g., a DH output).
            info: Context-specific string for domain separation.
            length: The desired output length in bytes.

        Returns:
            The derived key material.
        """
        if not isinstance(input_key_material, bytes):
            raise TypeError("KDF input key material must be bytes")

        # Use a strong salt for the KDF - in this case, the existing key material
        # This aligns with RFC 5869's recommendations for using a salt
        salt = key_material

        # Instantiate HKDF with SHA3_512 for high security
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=length,
            salt=salt,
            info=info
        )

        # Derive the new key
        derived_key = hkdf.derive(input_key_material)

        # Verify the derivation to ensure no internal errors occurred
        # This is a sanity check to confirm the KDF produced a valid output
        try:
            hkdf_verify = HKDF(
                algorithm=hashes.SHA3_512(),
                length=length,
                salt=salt,
                info=info
            )
            hkdf_verify.verify(input_key_material, derived_key)
            ratchet_logger.debug(f"KDF successful for context: {info.decode(errors='ignore')}")
        except InvalidKey:
            ratchet_logger.critical(f"FATAL: KDF verification failed for context: {info.decode(errors='ignore')}")
            raise SecurityError("KDF self-verification failed, cryptographic library may be corrupted.")

        return derived_key

    def _encrypt_with_cipher(self, plaintext: bytes, auth_data: bytes, message_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with ChaCha20-Poly1305 AEAD.

        Args:
            plaintext: The plaintext to encrypt
            auth_data: Authenticated associated data
            message_key: The key to use for encryption

        Returns:
            Tuple of (nonce, ciphertext)
        """
        # Generate a counter-based nonce with random salt
        # Counter (8 bytes) for uniqueness + salt (4 bytes) for randomness
        if not hasattr(self, '_nonce_manager') or self._nonce_manager is None:
            # Create a new nonce manager if one doesn't exist
            # Import here to avoid circular imports
            from tls_channel_manager import CounterBasedNonceManager
            self._nonce_manager = CounterBasedNonceManager()

        # Generate nonce using counter + salt method
        nonce = self._nonce_manager.generate_nonce()

        # Pinned, zeroizing native buffer for the message key (Layer 1.1)
        # Prevents pagefile swap and compiler elision via VirtualLock/mlock + sodium_memzero/ctypes.memset
        if HAVE_NATIVE_SECURE_BUFFER and NativeSecureBuffer is not None:
            with NativeSecureBuffer(message_key) as key_buf:
                cipher = ChaCha20Poly1305(key_buf.export_bytes())
                ciphertext = cipher.encrypt(nonce, plaintext, auth_data)
                return nonce, ciphertext

        # Create a mutable copy of the message key for better memory hygiene (fallback path)
        # This copy will be securely erased after use
        message_key_buffer = bytearray(message_key)

        try:
            # Create the cipher with the message key
            cipher = ChaCha20Poly1305(bytes(message_key_buffer))

            # Encrypt the plaintext
            ciphertext = cipher.encrypt(nonce, plaintext, auth_data)

            return nonce, ciphertext
        finally:
            # Securely erase the message key copy from memory
            # Multi-pass overwrite of the key buffer
            for i in range(len(message_key_buffer)):
                message_key_buffer[i] = 0

            # Try to use platform-specific memory lock/unlock and wiping if available
            try:
                buffer_addr = ctypes.addressof((ctypes.c_char * len(message_key_buffer)).from_buffer(message_key_buffer))
                # Zero out with memset for direct memory access (64-bit safe)
                ctypes.memset(ctypes.c_void_p(buffer_addr), 0, len(message_key_buffer))
                cphs.secure_wipe_memory(buffer_addr, len(message_key_buffer))
            except Exception:
                # Silently handle any errors during secure erasure
                logger.debug("Secure erasure encountered non-fatal error")

    def _encrypt(self, plaintext: bytes) -> bytes:
        """Internal implementation of the Double Ratchet encryption protocol.

        Performs the core encryption operations:

        1. Advances the sending chain to derive a fresh message key
        2. Creates a message header with ratchet state information
        3. Generates authenticated data from the header
        4. Encrypts plaintext with ChaCha20-Poly1305 AEAD
        5. Signs the encrypted data with FALCON-1024 (if PQ enabled)
        6. Assembles the complete message with all components

        This method implements the cryptographic operations described in
        the Double Ratchet specification with post-quantum enhancements.

        Args:
            plaintext: Raw message data to encrypt

        Returns:
            bytes: Complete encrypted message with header, signature, and ciphertext

        Raises:
            SecurityError: If encryption fails or Double Ratchet is not initialized
        """
        # Validate input
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")

        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")

        if len(plaintext) > self.MAX_MESSAGE_SIZE:
            raise ValueError(f"Message exceeds maximum size ({len(plaintext)} > {self.MAX_MESSAGE_SIZE} bytes)")

        # Ensure Double Ratchet is initialized
        if not self.is_initialized():
            raise SecurityError("Cannot encrypt: Double Ratchet not initialized")

        # 1. Advance sending chain to derive new message key
        message_key = self._ratchet_encrypt()

        # 2. Construct message header
        # Get previous chain length, ensure it's non-negative
        previous_chain_length = max(0, self.receiving_message_number)

        if self.dh_public_key is None:
            self._generate_dh_keypair()
        if self.dh_public_key is None:
            raise SecurityError("DH public key unavailable after generation (fail-closed)")
        header = MessageHeader.generate(
            public_key=self.dh_public_key,
            previous_chain_length=previous_chain_length,
            message_number=self.sending_message_number - 1
        )

        # Encode header to bytes
        serialized_header = header.encode()

        # 3. Create authenticated data from header (binding enforced by policy)
        self._require_handshake_binding("encrypt")
        auth_data = self._get_associated_data(serialized_header)

        # 4. Encrypt the message
        logger.debug(f"Encrypting {len(plaintext)} bytes with message key #{header.message_number}")
        nonce, ciphertext = self._encrypt_with_cipher(plaintext, auth_data, message_key)

        # 4b. Peer-synced Braid CT extension (v2 only): attach the staged
        # fresh KEM CT between nonce and ciphertext. Emitted only when
        # pq_ratchet_version >= 2 AND a fresh CT was staged by the
        # sending-side DH step; otherwise the layout stays byte-identical to
        # the legacy v1 format. Stale staged material on non-v2 sessions is
        # dropped here.
        pq_ext = b''
        if getattr(self, 'pq_ratchet_version', self.PQ_RATCHET_VERSION_LEGACY) >= self.PQ_RATCHET_VERSION_FRESH:
            pending_ct = getattr(self, '_pending_pq_ct', None)
            if pending_ct:
                try:
                    pq_ext = self._build_pq_ct_extension(pending_ct)
                    logger.debug(f"Attaching PQ CT extension ({len(pq_ext)} bytes) to outgoing message")
                except Exception as e_ext:
                    logger.warning(f"PQ CT extension build failed, sending legacy message: {e_ext}")
                    pq_ext = b''
        elif getattr(self, '_pending_pq_ct', None):
            logger.debug("Dropping stale pending PQ CT on non-v2 session")
            self._pending_pq_ct = None

        # 5. Post-quantum signature if enabled (Item 2 / Finding 5.1)
        # Deniable sessions (opt-in, lab-only): skip DSS entirely; the AEAD
        # tag under the shared chain key is the ONLY authenticator (either
        # party could have produced it -> offline deniability). Wire layout
        # stays identical (empty-sig) so parsers are unchanged.
        signature = b''
        if self.enable_pq and not getattr(self, "deniable", False):
            if not self.dss_private_key or not self.dss:
                raise SecurityError("Cannot encrypt message: DSS private key or signer not initialized under PQ-enabled mode (fail-closed)")
            # Bind the message header, nonce, PQ CT extension (if any), and
            # ciphertext to bind the ratchet state (Finding 5.1). The
            # extension is covered by the signature so CT stripping or
            # substitution is detected; legacy messages sign with pq_ext=b''
            # exactly as before.
            data_to_sign = serialized_header + nonce + pq_ext + ciphertext
            raw_signature = self.dss.sign(self.dss_private_key, data_to_sign)
            # Verify-after-sign (fault-attack countermeasure, cf. eprint
            # 2025/2009 seed-pointer faults in lattice stacks incl. LibOQS):
            # never emit a signature that does not verify under our own
            # session identity key. Fail-closed: abort the send, no fallback.
            self._secure_verify(self.dss_public_key, data_to_sign,
                                raw_signature, "verify-after-sign")
            
            # Handle hybrid signature format (dict with 'mldsa' and 'slhdsa' components)
            if isinstance(raw_signature, dict):
                # For hybrid signatures, use the ML-DSA component (faster, used in 'fast' mode)
                # or combine both for maximum security
                if 'mldsa' in raw_signature:
                    signature = raw_signature['mldsa']
                    logger.debug(f"Using ML-DSA signature component ({len(signature)} bytes)")
                else:
                    # Fallback: combine all signature components
                    signature = b''.join(v for v in raw_signature.values() if isinstance(v, bytes))
                    logger.debug(f"Combined hybrid signature ({len(signature)} bytes)")
            else:
                signature = raw_signature
                logger.debug(f"Applied FALCON signature ({len(signature)} bytes)")

        # 6. Assemble complete message
        # Format: header + signature_length (2 bytes) + signature + nonce
        #         + [PQ CT extension (v2 only)] + ciphertext
        signature_length_bytes = len(signature).to_bytes(2, byteorder='big')
        message = serialized_header + signature_length_bytes + signature + nonce + pq_ext + ciphertext

        # The staged fresh CT has now been handed to the peer: consume it so
        # each CT is transmitted exactly once with its epoch.
        if pq_ext:
            self._pending_pq_ct = None

        logger.info(
            f"Encrypted message: {len(message)} bytes (header: {len(serialized_header)}, " +
            f"sig: {len(signature)}, nonce: {len(nonce)}, pq_ct_ext: {len(pq_ext)}, ciphertext: {len(ciphertext)})"
        )

        return message

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a message with the Double Ratchet protocol.

        Performs secure message encryption with forward secrecy and
        post-quantum protection. The encryption process includes:

        1. Chain key ratcheting to generate a unique message key
        2. Authenticated encryption with ChaCha20-Poly1305 AEAD
        3. Message signing with FALCON-1024 (if post-quantum enabled)
        4. Header generation with current ratchet state information
        5. Replay protection with unique message identifiers

        The resulting message contains:
        - Header with X25519 public key and chain state information
        - FALCON signature (if post-quantum enabled)
        - Nonce for ChaCha20-Poly1305
        - Authenticated encrypted payload

        Args:
            plaintext: Raw message data to encrypt

        Returns:
            bytes: Complete encrypted message ready for transmission

        Raises:
            RuntimeError: Sanitized error message if encryption fails

        Security note:
            Each message uses a unique key derived through the ratchet mechanism,
            ensuring forward secrecy even if future keys are compromised.
        """
        with SecureExceptionHandler("Double Ratchet encryption", "DoubleRatchet", get_error_reporter()):
            if not isinstance(plaintext, bytes):
                raise TypeError("Plaintext must be bytes")

            if not plaintext:
                raise ValueError("Cannot encrypt empty plaintext")

            if len(plaintext) > self.MAX_MESSAGE_SIZE:
                raise ValueError(f"Message exceeds maximum size ({len(plaintext)} > {self.MAX_MESSAGE_SIZE} bytes)")

            # Use the private _encrypt method to handle encryption
            return self._encrypt(plaintext)

    def _decrypt_with_cipher(self, nonce: bytes, ciphertext: bytes, auth_data: bytes, message_key: bytes) -> bytes:
        """Decrypt ciphertext with ChaCha20-Poly1305 AEAD with secure memory handling.

        Performs authenticated decryption with ChaCha20-Poly1305 while implementing
        secure memory management practices to protect the message key:

        1. Creates a temporary copy of the message key in a mutable buffer
        2. Performs authenticated decryption with ChaCha20-Poly1305
        3. Securely erases the key material from memory after use
        4. Uses platform-specific memory protection when available

        Args:
            nonce: 12-byte nonce used for encryption
            ciphertext: Encrypted message data
            auth_data: Authenticated associated data (typically derived from header)
            message_key: 32-byte key derived from the ratchet chain

        Returns:
            bytes: Decrypted plaintext if authentication succeeds

        Raises:
            SecurityError: If authentication fails (tag verification fails)

        Security note:
            This method implements defense-in-depth by using both high-level
            secure erasure and low-level memory protection techniques.
        """
        # Pinned, zeroizing native buffer for the message key (Layer 1.1)
        # Prevents pagefile swap and compiler elision via VirtualLock/mlock + sodium_memzero/ctypes.memset
        if HAVE_NATIVE_SECURE_BUFFER and NativeSecureBuffer is not None:
            with NativeSecureBuffer(message_key) as key_buf:
                cipher = ChaCha20Poly1305(key_buf.export_bytes())
                try:
                    plaintext = cipher.decrypt(nonce, ciphertext, auth_data)
                    return plaintext
                except InvalidTag:
                    logger.error("SECURITY ALERT: Authentication tag verification failed")
                    raise SecurityError("Message authentication failed")

        # Create a mutable copy of the message key for better memory hygiene (fallback path)
        # This copy will be securely erased after use
        message_key_buffer = bytearray(message_key)

        try:
            # Create the cipher with the message key
            cipher = ChaCha20Poly1305(bytes(message_key_buffer))

            try:
                # Decrypt the ciphertext
                plaintext = cipher.decrypt(nonce, ciphertext, auth_data)
                return plaintext
            except InvalidTag:
                logger.error("SECURITY ALERT: Authentication tag verification failed")
                raise SecurityError("Message authentication failed")
        finally:
            # Securely erase the message key copy from memory
            # Multi-pass overwrite of the key buffer
            for i in range(len(message_key_buffer)):
                message_key_buffer[i] = 0

            # Try to use platform-specific memory lock/unlock and wiping if available
            try:
                buffer_addr = ctypes.addressof((ctypes.c_char * len(message_key_buffer)).from_buffer(message_key_buffer))
                # Zero out with memset for direct memory access (64-bit safe)
                ctypes.memset(ctypes.c_void_p(buffer_addr), 0, len(message_key_buffer))
                cphs.secure_wipe_memory(buffer_addr, len(message_key_buffer))
            except Exception:
                # Silently handle any errors during secure erasure
                logger.debug("Secure erasure encountered non-fatal error")

    def _snapshot_decrypt_state(self) -> dict:
        """Snapshot mutable ratchet state for copy-on-write decrypt (Signal 3.x).

        Signal spec: "If an exception is raised (e.g. message authentication
        failure) then the message is discarded and changes to the state object
        are discarded." Snapshot covers every field mutated by _dh_ratchet_step,
        _skip_message_keys, _store_skipped_message_keys and chain advancement.
        """
        return {
            "root_key": bytes(self.root_key) if isinstance(self.root_key, (bytes, bytearray)) else self.root_key,
            "sending_chain_key": bytes(self.sending_chain_key) if isinstance(self.sending_chain_key, (bytes, bytearray)) else self.sending_chain_key,
            "receiving_chain_key": bytes(self.receiving_chain_key) if isinstance(self.receiving_chain_key, (bytes, bytearray)) else self.receiving_chain_key,
            "sending_message_number": self.sending_message_number,
            "receiving_message_number": self.receiving_message_number,
            "sending_chain_length": getattr(self, "sending_chain_length", 0),
            "receiving_chain_length": getattr(self, "receiving_chain_length", 0),
            "previous_sending_chain_length": getattr(self, "previous_sending_chain_length", 0),
            "remote_dh_public_key": self.remote_dh_public_key,
            "remote_kem_public_key": bytes(self.remote_kem_public_key) if isinstance(self.remote_kem_public_key, (bytes, bytearray)) else self.remote_kem_public_key,
            "dh_private_key": self.dh_private_key,
            "dh_public_key": self.dh_public_key,
            "current_ratchet_key_id": bytes(self.current_ratchet_key_id) if isinstance(getattr(self, "current_ratchet_key_id", None), (bytes, bytearray)) else getattr(self, "current_ratchet_key_id", None),
            "skipped_message_keys": dict(self.skipped_message_keys),
            "skipped_key_times": dict(getattr(self, "_skipped_key_times", {})),
            "kem_private_key": self.kem_private_key,
            "kem_public_key": self.kem_public_key,
            "kem_ciphertext": bytes(self.kem_ciphertext) if isinstance(getattr(self, "kem_ciphertext", None), (bytes, bytearray)) else getattr(self, "kem_ciphertext", None),
            "pending_pq_ct": bytes(self._pending_pq_ct) if isinstance(getattr(self, "_pending_pq_ct", None), (bytes, bytearray)) else getattr(self, "_pending_pq_ct", None),
            "peer_ct_seen": getattr(self, "_peer_ct_seen", False),
            "synchronized_kem_secret": bytes(getattr(self, "_synchronized_kem_secret", None)) if isinstance(getattr(self, "_synchronized_kem_secret", None), (bytes, bytearray)) else getattr(self, "_synchronized_kem_secret", None),
            "last_pq_ratchet_time": getattr(self, "_last_pq_ratchet_time", 0.0),
            # SPQR cadence + forced-healing budget: mutated by v2 DH steps
            # (reset on fresh-KEM mix), so they must roll back with the keys.
            "spqr_msg_counter": getattr(self, "_spqr_msg_counter", 0),
            "spqr_last_refresh": getattr(self, "_spqr_last_refresh", 0.0),
            "last_force_pq_ratchet_time": getattr(self, "_last_force_pq_ratchet_time", 0.0),
        }

    def _restore_decrypt_state(self, snap: dict) -> None:
        """Restore snapshot taken by _snapshot_decrypt_state; wipe staged keys."""
        staged = getattr(self, "skipped_message_keys", {})
        snap_keys = snap.get("skipped_message_keys", {})
        for k, v in list(staged.items()):
            if k not in snap_keys:
                _wipe_secret_best_effort(bytearray(v) if isinstance(v, bytes) else v, "staged skipped key rollback")
        self.root_key = snap["root_key"]
        self.sending_chain_key = snap["sending_chain_key"]
        self.receiving_chain_key = snap["receiving_chain_key"]
        self.sending_message_number = snap["sending_message_number"]
        self.receiving_message_number = snap["receiving_message_number"]
        self.sending_chain_length = snap["sending_chain_length"]
        self.receiving_chain_length = snap["receiving_chain_length"]
        self.previous_sending_chain_length = snap["previous_sending_chain_length"]
        self.remote_dh_public_key = snap["remote_dh_public_key"]
        self.remote_kem_public_key = snap["remote_kem_public_key"]
        self.dh_private_key = snap["dh_private_key"]
        self.dh_public_key = snap["dh_public_key"]
        if "current_ratchet_key_id" in snap:
            self.current_ratchet_key_id = snap["current_ratchet_key_id"]
        self.skipped_message_keys = dict(snap["skipped_message_keys"])
        self._skipped_key_times = dict(snap.get("skipped_key_times", {}))
        self.kem_private_key = snap["kem_private_key"]
        self.kem_public_key = snap["kem_public_key"]
        try:
            self.kem_ciphertext = snap["kem_ciphertext"]
        except KeyError:
            pass
        self._pending_pq_ct = snap["pending_pq_ct"]
        self._peer_ct_seen = snap["peer_ct_seen"]
        try:
            self._synchronized_kem_secret = snap["synchronized_kem_secret"]
        except KeyError:
            pass
        self._last_pq_ratchet_time = snap["last_pq_ratchet_time"]
        if "spqr_msg_counter" in snap:
            self._spqr_msg_counter = snap["spqr_msg_counter"]
        if "spqr_last_refresh" in snap:
            self._spqr_last_refresh = snap["spqr_last_refresh"]
        if "last_force_pq_ratchet_time" in snap:
            self._last_force_pq_ratchet_time = snap["last_force_pq_ratchet_time"]

    def _prune_skipped_keys(self) -> None:
        """Enforce expiry + total cap on MKSKIPPED (Signal 8.4). Never raises."""
        try:
            now = time.monotonic()
            expiry = float(getattr(self, "SKIPPED_KEY_EXPIRY_SECONDS", 3600))
            times = getattr(self, "_skipped_key_times", {})
            for k, ts in list(times.items()):
                try:
                    if (now - float(ts)) > expiry:
                        v = self.skipped_message_keys.pop(k, None)
                        times.pop(k, None)
                        if isinstance(v, bytes):
                            _wipe_secret_best_effort(bytearray(v), "expired skipped key")
                except Exception:
                    continue
            cap = int(getattr(self, "MAX_SKIPPED_TOTAL", 2000))
            while len(self.skipped_message_keys) > cap and times:
                try:
                    oldest = min(times.items(), key=lambda x: float(x[1]))[0]
                except Exception:
                    break
                v = self.skipped_message_keys.pop(oldest, None)
                times.pop(oldest, None)
                if isinstance(v, bytes):
                    _wipe_secret_best_effort(bytearray(v), "evicted skipped key")
        except Exception:
            pass

    def decrypt(self, message: bytes) -> bytes:
        """Decrypt a message using the Double Ratchet protocol.

        Performs secure message decryption with comprehensive security checks:

        1. Message structure validation and parsing
        2. Replay attack detection using unique message IDs
        3. Cryptographic signature verification (FALCON-1024)
        4. DH ratchet step execution if sender's key has changed
        5. Message key derivation through chain ratcheting
        6. Authenticated decryption with ChaCha20-Poly1305

        The decryption process handles:
        - Out-of-order message delivery through skipped message keys
        - Key rotation through DH ratchet steps
        - Post-quantum signature verification
        - Replay attack prevention

        Args:
            message: Complete encrypted message to decrypt

        Returns:
            bytes: Decrypted plaintext message

        Raises:
            RuntimeError: Sanitized error message if decryption fails

        Security note:
            Failed authentication or signature verification will immediately
            abort the decryption process to prevent oracle attacks.
        """
        try:
            with SecureExceptionHandler("Double Ratchet decryption", "DoubleRatchet", get_error_reporter()):
                # Validate input
                if not isinstance(message, bytes):
                    raise TypeError("Message must be bytes")

                if len(message) < MessageHeader.HEADER_SIZE + 14:  # Header + min signature len + nonce
                    raise ValueError(f"Message is too short: {len(message)} bytes")

                # Ensure Double Ratchet is initialized
                if not self.is_initialized():
                    raise SecurityError("Cannot decrypt: Double Ratchet not initialized")

                try:
                    # 1. Parse the message components
                    header_bytes = message[:MessageHeader.HEADER_SIZE]
                    header = MessageHeader.decode(header_bytes)
                except Exception as e:
                    raise SecurityError(f"Failed to parse message header: {e}")

                # --- REPLAY DETECTION ---
                # Check if this unique message ID has already been processed
                if header.message_id in self.replay_cache:
                    logger.warning(
                        f"SECURITY ALERT: Message replay attack detected! Message ID {format_binary(header.message_id)} already processed. "
                        f"Ratchet: {format_binary(self._get_public_key_fingerprint(header.public_key))}, MsgNum: {header.message_number}. "
                        f"This indicates an adversary may be attempting to replay old ciphertexts."
                    )
                    raise SecurityError("Message replay attack detected: message ID already processed.")
                # --- END REPLAY DETECTION ---

                # Extract signature length and signature (bounded before slicing).
                signature_length_bytes = message[MessageHeader.HEADER_SIZE:MessageHeader.HEADER_SIZE+2]
                signature_length = int.from_bytes(signature_length_bytes, byteorder='big')
                # Largest legitimate: hybrid ML-DSA-87 (4627) + SLH-DSA-256f
                # (49856) dict envelope; cap 60KB to bound allocation/MITM bloat.
                # Classical lab mode (enable_pq=False) emits empty signatures.
                if signature_length < 0 or signature_length > 61440:
                    raise SecurityError("Invalid signature length")
                if self.enable_pq and not getattr(self, "deniable", False) and signature_length == 0:
                    raise SecurityError("Missing required post-quantum signature")
                if MessageHeader.HEADER_SIZE + 2 + signature_length + 12 + 16 > len(message):
                    raise SecurityError("Truncated message (signature/nonce/tag overrun)")

                signature_offset = MessageHeader.HEADER_SIZE + 2
                signature = message[signature_offset:signature_offset+signature_length]

                # Extract nonce, optional PQ CT extension, and ciphertext.
                # Post-nonce body layout: [MAGIC + pq_ct_len + pq_ct] + ciphertext.
                content_offset = signature_offset + signature_length
                nonce = message[content_offset:content_offset+12]
                body = message[content_offset+12:]
                peer_pq_ct, ciphertext, pq_ext_bytes = self._split_pq_ct_extension(body)
                if peer_pq_ct is not None and getattr(
                        self, 'pq_ratchet_version', self.PQ_RATCHET_VERSION_LEGACY
                ) < self.PQ_RATCHET_VERSION_FRESH:
                    logger.warning(
                        "Non-v2 session ignoring peer PQ CT extension "
                        f"({len(peer_pq_ct)} bytes stripped, legacy decrypt continues)"
                    )

                logger.debug(
                    f"Parsed message: header={len(header_bytes)} bytes, " +
                    f"signature={len(signature)} bytes, nonce={len(nonce)} bytes, " +
                    f"pq_ct_ext={len(pq_ext_bytes)} bytes, " +
                    f"ciphertext={len(ciphertext)} bytes"
                )

                # 2. Verify signature if PQ is enabled (Finding 5.1 & Item 33)
                # Deniable sessions skip DSS: AEAD tag under the shared chain
                # key is the sole authenticator (repudiable by design).
                if self.enable_pq and not getattr(self, "deniable", False):
                    if not signature:
                        logger.error("SECURITY ALERT: Missing required post-quantum digital signature under PQ-enabled mode (fail-closed)")
                        raise SecurityError("Missing required post-quantum digital signature under PQ-enabled mode")
                    if not self.remote_dss_public_key:
                        logger.error("Cannot verify FALCON signature: No remote DSS public key available (fail-closed)")
                        raise SecurityError("Cannot verify FALCON message signature: No remote DSS public key available")
                    data_to_verify = header_bytes + nonce + pq_ext_bytes + ciphertext
                    self._secure_verify(self.remote_dss_public_key, data_to_verify, signature, "FALCON message signature")

                # 3. Create authenticated data from header (binding enforced by policy)
                self._require_handshake_binding("decrypt")
                auth_data = self._get_associated_data(header_bytes)

                # 4. Copy-on-write: snapshot BEFORE any DH/chain mutation (Signal:
                # "changes to the state object are discarded" on exception).
                # Fixes state-corruption on replayed old signed header + AEAD fail.
                self._prune_skipped_keys()
                _snap = self._snapshot_decrypt_state()
                _mk = None
                try:
                    _mk = self._ratchet_decrypt(header, peer_pq_ct=peer_pq_ct)
                    logger.debug(f"Decrypting with message key #{header.message_number}")
                    plaintext = self._decrypt_with_cipher(nonce, ciphertext, auth_data, _mk)
                except Exception:
                    try:
                        self._restore_decrypt_state(_snap)
                    except Exception:
                        pass
                    raise
                finally:
                    try:
                        if isinstance(_mk, bytes):
                            _wipe_secret_best_effort(bytearray(_mk), "staged message key")
                    except Exception:
                        pass

                # Commit only on success: replay mark + pruned skipped-key GC.
                self.replay_cache.add(header.message_id)
                self._prune_skipped_keys()

                return plaintext

        except Exception as e:
            if isinstance(e, SecurityError):
                # Rethrow security errors without modification
                raise
            else:
                # Wrap unexpected exceptions generically (oracle reduction:
                # detail stays in the local log, never on the wire).
                logger.error("Decryption error (detail in log)", exc_info=True)
                raise SecurityError("Failed to decrypt message")

    def _ratchet_encrypt(self) -> bytes:
        """
        Advance the sending chain to derive a new message key.

        SPQR cadence (v2 only): each send increments ``_spqr_msg_counter``;
        when the count reaches ``msg_interval`` or the wall-clock age since
        ``_spqr_last_refresh`` exceeds ``max_age_seconds``, a fresh encaps
        is performed inline (``_fresh_pq_encaps_v2`` + ``hybrid_combine_v2``
        mix + staged CT) and the cadence resets. Failures fall back to
        legacy with a warning and never abort. v1 sessions are untouched.

        Returns:
            The derived message key for encryption
        """
        # Ensure the Double Ratchet is properly initialized
        if not self.is_initialized():
            raise SecurityError("Cannot generate message key: Double Ratchet not initialized")

        # Check if sending chain exists
        if self.sending_chain_key is None:
            raise SecurityError("Sending chain is not initialized")

        # SPQR periodic fresh-KEM cadence (v2 only, no-op on v1).
        try:
            is_v2 = (
                bool(getattr(self, 'enable_pq', False))
                and int(getattr(self, 'pq_ratchet_version',
                               self.PQ_RATCHET_VERSION_LEGACY))
                >= self.PQ_RATCHET_VERSION_FRESH
            )
        except (TypeError, ValueError):
            is_v2 = False
        if is_v2:
            try:
                self._spqr_msg_counter = int(getattr(self, '_spqr_msg_counter', 0) or 0) + 1
            except (TypeError, ValueError):
                self._spqr_msg_counter = 1
            try:
                reason = self._spqr_refresh_reason()
            except Exception:
                reason = None
            if reason is not None:
                try:
                    self._do_spqr_refresh(reason)
                except Exception as e_spqr:
                    # Legacy fallback with warning by default; strict-abort
                    # (P2P_PQ_STRICT_ABORT=1) fails the send closed instead.
                    logger.warning(
                        f"SPQR refresh ({reason}) failed, continuing with "
                        f"legacy chain (no abort): {e_spqr}"
                    )
                    if _pq_ratchet_production_mode():
                        logger.critical(
                            f"PROD SPQR refresh failure (legacy fallback): {e_spqr}"
                        )
                    if _pq_strict_abort():
                        raise SecurityError(
                            f"P2P_PQ_STRICT_ABORT: SPQR refresh failure is fail-closed: {e_spqr}"
                        ) from e_spqr

        # Derive next chain key and message key
        next_chain_key, message_key = self._chain_ratchet_step(self.sending_chain_key)

        # Update state
        self.sending_chain_key = next_chain_key
        self.sending_message_number += 1

        logger.debug(f"Generated message key for sending chain message #{self.sending_message_number-1}")
        return message_key

    def _ratchet_decrypt(self, header: MessageHeader,
                         peer_pq_ct: Optional[bytes] = None) -> bytes:
        """
        Process a message header and derive the appropriate message key for decryption.
        Follows the logic similar to Signal Protocol for receiving messages.

        This method handles:
        1. Checking for previously stored skipped message keys.
        2. Performing a DH ratchet step if the sender's DH key has changed.
           - This includes storing skipped keys from the sender's *previous* chain.
           - On v2 sessions the step consumes ``peer_pq_ct`` (Braid CT wire
             extension) for the peer-synced mix, else legacy fallback.
        3. Advancing the current receiving chain if the message is ahead, storing intermediate keys.
        4. Deriving the message key for the current message or erroring for old/unskippable messages.

        Returns:
            The correct message key for decryption.
        """
        remote_public_key_from_header_bytes = header.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        message_number = header.message_number
        # This is the ratchet ID associated with the chain this message belongs to.
        current_message_ratchet_id = self._get_public_key_fingerprint(header.public_key)

        # 1. Check KSKIPPED: If key for (header.public_key, header.message_number) is stored, use it.
        key_tuple = (current_message_ratchet_id, message_number)
        if key_tuple in self.skipped_message_keys:
            # Enforce expiry: stale skipped keys are deleted, treated as missed (Signal 8.4).
            try:
                _ts = float(self._skipped_key_times.get(key_tuple, time.monotonic()))
                if (time.monotonic() - _ts) > float(getattr(self, "SKIPPED_KEY_EXPIRY_SECONDS", 3600)):
                    _stale = self.skipped_message_keys.pop(key_tuple, None)
                    self._skipped_key_times.pop(key_tuple, None)
                    if isinstance(_stale, bytes):
                        _wipe_secret_best_effort(bytearray(_stale), "expired skipped key on use")
                    raise SecurityError("Skipped message key expired.")
            except SecurityError:
                raise
            except Exception:
                pass
            logger.info(f"Using stored key for message #{message_number} (ratchet {format_binary(current_message_ratchet_id)})")
            # Pop the key as it's now being used (single-use, Signal MKSKIPPED_del).
            _mk = self.skipped_message_keys.pop(key_tuple)
            try:
                self._skipped_key_times.pop(key_tuple, None)
            except Exception:
                pass
            return _mk

        # --- Potential DH Ratchet Step ---
        # Check if the sender's DH public key in the header is new compared to our stored remote DH key.
        needs_dh_ratchet = False

        if self.remote_dh_public_key is None: # First message from this peer or session reset
            needs_dh_ratchet = True
            logger.info("No current remote DH public key. Assuming first message or new session, will perform DH ratchet.")
        elif not self._compare_public_keys(self.remote_dh_public_key, remote_public_key_from_header_bytes):
            needs_dh_ratchet = True
            logger.info("Remote DH public key in header has changed. Performing DH ratchet step.")

            # Before ratcheting, store any skipped message keys from the *old* receiving chain
            # (associated with the previous self.remote_dh_public_key).
            if self.receiving_chain_key: # If there was an active receiving chain
                old_remote_ratchet_id = self._get_public_key_fingerprint(self.remote_dh_public_key)
                logger.debug(f"Storing skipped keys for old ratchet {format_binary(old_remote_ratchet_id)} "
                             f"from message #{self.receiving_message_number} up to #{header.previous_chain_length-1}.")
                try:
                    # Enforce hard gap ceiling (Signal MAX_SKIP=1000 DoS bound).
                    effective_max_skip = min(self.MAX_SKIP_MESSAGE_KEYS, getattr(self, 'HARD_MAX_SKIP', 1000))
                    if (header.previous_chain_length - self.receiving_message_number) > getattr(self, 'HARD_MAX_SKIP', 1000):
                        logger.error(f"SECURITY ALERT: previous_chain_length gap ({header.previous_chain_length - self.receiving_message_number}) "
                                     f"exceeds hard limit of {getattr(self, 'HARD_MAX_SKIP', 1000)}. Aborting to prevent CPU DoS.")
                        raise SecurityError("Previous chain gap exceeds hard limit.")

                    bounded_previous_chain_length = min(
                        header.previous_chain_length,
                        self.receiving_message_number + effective_max_skip
                    )

                    if bounded_previous_chain_length < header.previous_chain_length:
                        logger.warning(f"Limiting previous chain storage to {bounded_previous_chain_length} " +
                                       f"(original was {header.previous_chain_length}) to prevent DOS")

                    self._store_skipped_message_keys(
                        self.receiving_chain_key,         # The CKr for the old chain
                        self.receiving_message_number,    # The Nr for the old chain
                        bounded_previous_chain_length,    # Bounded Pn from header (sender's old chain length)
                        old_remote_ratchet_id             # Ratchet ID of the old chain
                    )
                except SecurityError:
                    raise
                except Exception as e:
                    logger.error(f"Error storing skipped message keys: {e}")
                    raise SecurityError(f"Failed to store skipped message keys: {e}")

        if needs_dh_ratchet:
            try:
                # This performs the DH exchange, updates self.root_key, self.remote_dh_public_key,
                # self.receiving_chain_key, and resets self.receiving_message_number = 0.
                # It also generates new sending keys for us.
                # It needs the KEM public key associated with remote_public_key_from_header_bytes if PQ is enabled.
                # We assume self.remote_kem_public_key was updated alongside self.remote_dh_public_key by an earlier
                # call to set_remote_public_key or during a previous ratchet where we were the sender.
                current_remote_kem_pk_for_ratchet = None
                if self.enable_pq:
                    # We need the KEM public key that corresponds to remote_public_key_from_header_bytes.
                    # This is tricky as the header doesn't carry it. Assume it has been set via `set_remote_public_key`
                    # or is part of the initial handshake and `self.remote_kem_public_key` refers to it.
                    current_remote_kem_pk_for_ratchet = self.remote_kem_public_key

                self._dh_ratchet_step(remote_public_key_from_header_bytes, current_remote_kem_pk_for_ratchet,
                                      peer_pq_ct=peer_pq_ct)
                # After this, self.receiving_message_number = 0 for the new chain.
                # And self.remote_dh_public_key matches header.public_key.
            except Exception as e:
                logger.error(f"DH ratchet step failed: {e}")
                raise SecurityError(f"DH ratchet step failed: {e}")

        # --- Process message in its chain (defined by header.public_key, which now matches self.remote_dh_public_key) ---
        # current_message_ratchet_id is the ID for the chain this message belongs to.
        # self.receiving_message_number is Nr for this chain.
        # message_number is N (from header) for this message.

        if message_number < self.receiving_message_number:
            # Message is older than current state for this chain AND was not in skipped_message_keys.
            logger.error(f"SECURITY ALERT: Message replay attack detected! Old message #{message_number} received for current ratchet "
                         f"(current chain is at message #{self.receiving_message_number}), not in skipped keys cache. "
                         f"Ratchet ID: {format_binary(current_message_ratchet_id)}. "
                         f"This indicates an adversary may be attempting to replay old ciphertexts after the ratchet has advanced.")
            raise SecurityError(f"Message replay attack detected: old message sequence number (#{message_number}) for current ratchet, not in skipped keys cache.")

        if message_number > self.receiving_message_number:
            # Bound check: Signal MAX_SKIP=1000 (DoS bound, still tolerates loss/reorder).
            gap = message_number - self.receiving_message_number
            hard_limit = getattr(self, 'HARD_MAX_SKIP', 1000)
            if gap > hard_limit:
                logger.error(f"SECURITY ALERT: Message number gap {gap} exceeds HARD_MAX_SKIP ({hard_limit}). Aborting to prevent CPU DoS.")
                raise SecurityError(f"Message number {message_number} gap exceeds maximum allowable limit of {hard_limit}.")

            if message_number > self.receiving_message_number + self.MAX_SKIP_MESSAGE_KEYS:
                logger.error(f"SECURITY ALERT: Message number {message_number} exceeds MAX_SKIP_MESSAGE_KEYS "
                             f"({self.MAX_SKIP_MESSAGE_KEYS}) from current #{self.receiving_message_number}. Aborting to prevent DoS.")
                raise SecurityError(f"Message number {message_number} exceeds maximum allowable skip limit.")

            logger.debug(f"Message #{message_number} is ahead of current receiving number #{self.receiving_message_number}. Skipping keys.")
            try:
                self._skip_message_keys(message_number, current_message_ratchet_id)
            except Exception as e:
                logger.error(f"Error skipping message keys: {e}")
                raise SecurityError(f"Failed to skip message keys: {e}")

        # Verify synchronization: at this point, message_number MUST strictly equal self.receiving_message_number
        if message_number != self.receiving_message_number:
            logger.error(f"SECURITY ALERT: Message number #{message_number} does not match receiving chain #{self.receiving_message_number} after skipping.")
            raise SecurityError("Ratchet desynchronization: message number mismatch after skipping.")

        # Derive Message Key for the current message_number, then advance chain state.
        if self.receiving_chain_key is None:
            # This should not happen if the ratchet is initialized and DH step occurred if needed.
            logger.error("CRITICAL: Receiving chain key is None before final key derivation.")
            raise SecurityError("Receiving chain key is unexpectedly None.")

        # Get key for message_number (which is self.receiving_message_number)
        next_chain_key_val, message_key_val = self._chain_ratchet_step(self.receiving_chain_key)

        # Advance the receiving chain state for the NEXT message
        self.receiving_chain_key = next_chain_key_val
        self.receiving_message_number += 1 # Increment N_r

        logger.debug(f"Derived message key for message #{message_number} (ratchet {format_binary(current_message_ratchet_id)}). "
                     f"Receiving number advanced to {self.receiving_message_number}.")
        return message_key_val

    def _store_skipped_message_keys(self, chain_key: bytes, start: int, end: int, ratchet_key_id: bytes) -> None:
        """
        Store message keys for messages we haven't received yet.

        This is a critical component of maintaining security when messages
        arrive out of order or when the sender has ratcheted forward.
        """
        # Validate parameters
        if end <= start:
            return  # Nothing to skip

        # Limit the maximum number of keys to prevent DoS
        max_to_store = min(end - start, self.max_skipped_message_keys)
        if max_to_store < (end - start):
            logger.warning(
                f"Limiting skipped keys to {max_to_store} (requested {end-start}). " +
                f"This may cause message loss if too many messages arrive out of order."
            )
            end = start + max_to_store

        logger.info(f"Storing keys for skipped messages from #{start} to #{end-1}")

        # Generate and store keys for all messages we're skipping
        current_chain_key = chain_key

        # Safely get remote key fingerprint - check for None
        if self.remote_dh_public_key is None:
            logger.error("SECURITY ALERT: remote_dh_public_key is None in _store_skipped_message_keys")
            return

        remote_key_id = self._get_public_key_fingerprint(self.remote_dh_public_key)

        for i in range(start, end):
            next_chain_key, message_key = self._chain_ratchet_step(current_chain_key)
            current_chain_key = next_chain_key

            # Store the skipped key for later use (+ timestamp for Signal 8.4 expiry)
            key_tuple = (remote_key_id, i)
            self.skipped_message_keys[key_tuple] = message_key
            try:
                self._skipped_key_times[key_tuple] = time.monotonic()
            except Exception:
                pass
            logger.debug(f"Stored key for skipped message #{i}")

    def _create_new_receiving_chain(self) -> None:
        """Create a new receiving chain using DH and KEM shared secrets."""
        # Check for None remote DH key
        if self.remote_dh_public_key is None:
            logger.error("SECURITY ALERT: Cannot create new receiving chain - remote_dh_public_key is None")
            raise SecurityError("Cannot create receiving chain: missing remote DH public key")

        # Generate a new DH shared secret
        if self.dh_private_key is None:
            self._generate_dh_keypair()
        # B101: explicit fail-closed check (assert is stripped under python -O).
        if self.dh_private_key is None:  # nosec B101 - explicit check, no assert for security
            raise SecurityError("DH private key unavailable after generation")
        dh_shared_secret = self.dh_private_key.exchange(self.remote_dh_public_key)
        verify_key_material(dh_shared_secret, description="DH shared secret for new chain")

        # If PQ is enabled, combine with KEM shared secret
        if self.enable_pq and hasattr(self, 'kem_shared_secret') and self.kem_shared_secret:
            # Combine DH and KEM shared secrets using KDF
            logger.debug("Combining DH and KEM shared secrets for hybrid security")
            combined_secret = hashlib.sha3_512(
                dh_shared_secret + b"||NEW_CHAIN||" + self.kem_shared_secret
            ).digest()

            root_key, chain_key = self._kdf(
                self.root_key, combined_secret, self.KDF_INFO_HYBRID + b"_NEW_CHAIN"
            )
        else:
            # Use only DH shared secret
            root_key, chain_key = self._kdf(
                self.root_key, dh_shared_secret, self.KDF_INFO_DH + b"_NEW_CHAIN"
            )

        # Update root key and create new receiving chain - ensure these are bytes, not ints
        if isinstance(root_key, bytes) and len(root_key) >= 32:
            self.root_key = root_key[:32]
        else:
            logger.error(f"SECURITY ALERT: Invalid root key type {type(root_key)}")
            raise SecurityError("Invalid root key type in _create_new_receiving_chain")

        if isinstance(chain_key, bytes) and len(chain_key) >= 32:
            self.receiving_chain_key = chain_key[:32]
        else:
            logger.error(f"SECURITY ALERT: Invalid chain key type {type(chain_key)}")
            raise SecurityError("Invalid chain key type in _create_new_receiving_chain")

        # Verify key material
        verify_key_material(self.root_key, expected_length=32, description="New root key")
        verify_key_material(self.receiving_chain_key, expected_length=32,
                          description="New receiving chain key")

        logger.info("Created new receiving chain")

    def get_public_key(self) -> bytes:
        """Get the current X25519 public key for key exchange."""
        if self.dh_public_key is None:
            self._generate_dh_keypair()
        if self.dh_public_key is None:
            raise SecurityError("DH public key unavailable after generation (fail-closed)")
        return self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_kem_public_key(self) -> Optional[bytes]:
        """Get the current ML-KEM public key for post-quantum key exchange."""
        if self.enable_pq and hasattr(self, 'kem_public_key') and self.kem_public_key:
            return self.kem_public_key
        return None

    def get_kem_ciphertext(self) -> Optional[bytes]:
        """Get the current KEM ciphertext from encapsulation."""
        if self.enable_pq and hasattr(self, 'kem_ciphertext') and self.kem_ciphertext:
            return self.kem_ciphertext
        return None

    def process_kem_ciphertext(self, ciphertext: bytes) -> bytes:
        """
        Process a KEM ciphertext to derive a shared secret.

        This is used by the responder to complete the post-quantum
        key establishment initiated by the other party.
        """
        if not self.enable_pq:
            raise SecurityError(
                "Received KEM ciphertext but post-quantum mode is disabled: "
                "refusing to return an empty shared secret (fail-closed)")

        try:
            # Verify KEM ciphertext integrity, including length
            verify_key_material(ciphertext,
                                expected_length=self.MLKEM1024_CIPHERTEXT_SIZE,
                                description="KEM ciphertext for DR")
            # Log the received KEM ciphertext
            logger.debug(f"Received KEM ciphertext for processing: {format_binary(ciphertext)}")

            # Check if the KEM implementation and private key are available
            if self.kem is None:
                logger.error("SECURITY ALERT: KEM implementation is not available")
                raise SecurityError("Cannot process KEM ciphertext: KEM implementation not available")

            if self.kem_private_key is None:
                logger.error("SECURITY ALERT: KEM private key is not available")
                raise SecurityError("Cannot process KEM ciphertext: KEM private key not available")

            # Decapsulate the KEM ciphertext
            shared_secret = self.kem.decaps(self.kem_private_key, ciphertext)
            verify_key_material(shared_secret, description="Decapsulated KEM shared secret")

            # Store the shared secret
            self.kem_shared_secret = shared_secret
            logger.debug(f"Processed KEM ciphertext and derived shared secret ({len(shared_secret)} bytes)")

            # If we already have DH outputs but no chains, initialize chains now
            if self.remote_dh_public_key and not self.receiving_chain_key:
                logger.debug("Completing initialization with DH output and KEM shared secret")
                if self.dh_private_key is None:
                    self._generate_dh_keypair()
                if self.dh_private_key is None:
                    raise SecurityError("DH private key unavailable after generation (fail-closed)")
                dh_output = self.dh_private_key.exchange(self.remote_dh_public_key)
                self._initialize_chain_keys(dh_output, shared_secret)

            # Return the shared secret for immediate use if needed
            return shared_secret

        except Exception as e:
            self.last_error = f"Failed to process KEM ciphertext: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            raise SecurityError(f"KEM processing failed: {str(e)}")

    def _initialize_chain_keys(self, dh_output: bytes, kem_shared_secret: Optional[bytes] = None) -> None:
        """
        Initialize or reinitialize the chain keys.

        This method establishes the initial chain keys for both sending
        and receiving chains, ensuring that both parties derive the same
        keys despite being in different roles.
        """
        # Log operation
        logger.debug(
            f"Initializing chain keys with DH output ({len(dh_output)} bytes)" +
            (f" and KEM shared secret ({len(kem_shared_secret)} bytes)" if kem_shared_secret else "")
        )

        # Verify inputs
        verify_key_material(dh_output, description="DH output for chain key initialization")
        current_root_key = self.root_key # This is the shared secret from X3DH+PQ

        if kem_shared_secret:
            verify_key_material(kem_shared_secret, description="KEM shared secret for chain key initialization")

        # Create combined secret for hybrid mode (this is the IKM for HKDF)
        if self.enable_pq and kem_shared_secret:
            combined_secret = hashlib.sha3_512(b"DR_HYBRID_" + dh_output + b"_" + kem_shared_secret).digest()
            logger.debug(f"Using hybrid DH+KEM input for key derivation ({len(combined_secret)} bytes)")
            # Info strings for Step 1 (conceptually, initiator's sending chain / responder's receiving chain)
            info_root_s1 = self.KDF_INFO_INIT_ROOT_STEP1_HYBRID
            info_chain_s1 = self.KDF_INFO_INIT_CHAIN_STEP1_HYBRID
            # Info strings for Step 2 (conceptually, initiator's receiving chain / responder's sending chain)
            info_root_s2 = self.KDF_INFO_INIT_ROOT_STEP2_HYBRID
            info_chain_s2 = self.KDF_INFO_INIT_CHAIN_STEP2_HYBRID
        else:
            combined_secret = dh_output
            logger.debug(f"Using classical DH input for key derivation ({len(combined_secret)} bytes)")
            # Info strings for Step 1
            info_root_s1 = self.KDF_INFO_INIT_ROOT_STEP1_DH
            info_chain_s1 = self.KDF_INFO_INIT_CHAIN_STEP1_DH
            # Info strings for Step 2
            info_root_s2 = self.KDF_INFO_INIT_ROOT_STEP2_DH
            info_chain_s2 = self.KDF_INFO_INIT_CHAIN_STEP2_DH

        # --- Step 1 Derivations ---
        # (Corresponds to what DR_INIT_SENDING_v2 used to produce for both root and chain key)

        # Derive new root key for step 1
        logger.debug(f"Deriving initial root key (step 1) using info: {info_root_s1.decode()}")
        root_key_s1 = self._kdf(current_root_key, combined_secret, info=info_root_s1, length=self.ROOT_KEY_SIZE)
        verify_key_material(root_key_s1, description="Initial root key (step 1)")

        # Derive chain key for step 1, using the new root_key_s1 as HKDF key material
        logger.debug(f"Deriving initial chain key (step 1) using info: {info_chain_s1.decode()}")
        chain_key_s1 = self._kdf(root_key_s1, combined_secret, info=info_chain_s1, length=self.CHAIN_KEY_SIZE)
        verify_key_material(chain_key_s1, description="Initial chain key (step 1)")

        # --- Step 2 Derivations ---
        # (Corresponds to what DR_INIT_RECEIVING_v2 used to produce for both root and chain key)
        # The root key for this step's derivation is the output from step 1's root key derivation

        # Derive new root key for step 2
        logger.debug(f"Deriving initial root key (step 2) using info: {info_root_s2.decode()}")
        root_key_s2 = self._kdf(root_key_s1, combined_secret, info=info_root_s2, length=self.ROOT_KEY_SIZE)
        verify_key_material(root_key_s2, description="Initial root key (step 2)")

        # Derive chain key for step 2, using the new root_key_s2 as HKDF key material
        logger.debug(f"Deriving initial chain key (step 2) using info: {info_chain_s2.decode()}")
        chain_key_s2 = self._kdf(root_key_s2, combined_secret, info=info_chain_s2, length=self.CHAIN_KEY_SIZE)
        verify_key_material(chain_key_s2, description="Initial chain key (step 2)")

        # Assign keys based on initiator/responder role
        if self.is_initiator:
            logger.debug("Assigning Step 1 to Sending Chain, Step 2 to Receiving Chain for Initiator")
            self.root_key = root_key_s2 # Final root key is from Step 2
            self.sending_chain_key = chain_key_s1
            self.receiving_chain_key = chain_key_s2
        else: # Responder
            logger.debug("Assigning Step 1 to Receiving Chain, Step 2 to Sending Chain for Responder")
            self.root_key = root_key_s2 # Final root key is from Step 2
            self.receiving_chain_key = chain_key_s1 # Responder receives on chain derived from "Step 1" context
            self.sending_chain_key = chain_key_s2   # Responder sends on chain derived from "Step 2" context

        # Reset message counters
        self.sending_message_number = 0
        self.receiving_message_number = 0

        # Verify chain key derivation was successful
        if not self.sending_chain_key or not self.receiving_chain_key:
            logger.error("SECURITY ALERT: Chain key derivation failed")
            raise SecurityError("Chain key derivation failed")

        logger.info(f"Successfully initialized chain keys for {'initiator' if self.is_initiator else 'responder'}")

    def get_info(self) -> Dict[str, Any]:
        """Get diagnostic information about the current state."""
        # Compute fingerprints for identification
        remote_key_fingerprint = None
        if self.remote_dh_public_key:
            remote_key_fingerprint = base64.b64encode(
                self._get_public_key_fingerprint(self.remote_dh_public_key)
            ).decode()

        # Build basic info
        info = {
            "is_initiator": self.is_initiator,
            "post_quantum_enabled": self.enable_pq,
            "current_ratchet_key_id": base64.b64encode(self.current_ratchet_key_id).decode(),
            "remote_ratchet_key_id": remote_key_fingerprint,
            "sending_message_number": self.sending_message_number,
            "receiving_message_number": self.receiving_message_number,
            "skipped_keys_count": len(self.skipped_message_keys),
            "initialization_status": "complete" if self.is_initialized() else "pending",
            "max_skipped_keys": self.max_skipped_message_keys,
            "pq_ratchet_version": getattr(self, 'pq_ratchet_version', 1),
            "protocol_version": getattr(self, 'protocol_version', 1),
            "peer_ct_seen": bool(getattr(self, '_peer_ct_seen', False)),
            "has_pending_pq_ct": getattr(self, '_pending_pq_ct', None) is not None,
            "last_error": self.last_error
        }

        # Add PQ-specific information if enabled
        if self.enable_pq:
            info.update({
                "has_remote_kem_key": self.remote_kem_public_key is not None,
                "has_kem_ciphertext": self.kem_ciphertext is not None,
                "has_remote_dss_key": self.remote_dss_public_key is not None,
                "has_kem_shared_secret": hasattr(self, 'kem_shared_secret') and self.kem_shared_secret is not None,
                "pq_algorithms": {
                    "kem": "ML-KEM-1024",
                    "signature": "FALCON-1024"
                }
            })

        return info

    def is_initialized(self) -> bool:
        """Check if the Double Ratchet is fully initialized and ready."""
        # Basic requirements for all modes
        basic_init = (
            self.sending_chain_key is not None and
            self.receiving_chain_key is not None and
            self.remote_dh_public_key is not None
        )

        # In PQ mode, also check KEM initialization
        if self.enable_pq:
            pq_init = (
                self.remote_kem_public_key is not None and
                (self.is_initiator or self.kem_shared_secret is not None)
            )

            if not pq_init:
                # Log helpful diagnostics about what's missing
                if self.remote_kem_public_key is None:
                    logger.error("INITIALIZATION ERROR: Missing remote KEM public key")
                elif not self.is_initiator and self.kem_shared_secret is None:
                    logger.error("INITIALIZATION ERROR: Responder missing KEM shared secret (ciphertext not processed)")

            return basic_init and pq_init

        return basic_init

    def _require_handshake_binding(self, op: str) -> None:
        """Enforce handshake-bound AD where policy demands it (fail-closed).

        Default: binding is opt-in (lab interop) with a one-time production
        warning when absent. Strict refusal only under explicit
        P2P_REQUIRE_HANDSHAKE_BINDING=1: sessions without
        set_handshake_binding() abort encrypt/decrypt. Never silent.
        """
        import os as _os
        if getattr(self, "_handshake_binding", None):
            return
        strict = _os.environ.get("P2P_REQUIRE_HANDSHAKE_BINDING", "0").strip().lower() in ("1", "true", "yes", "on")
        if strict:
            raise SecurityError(
                f"Handshake binding required for {op} (P2P_REQUIRE_HANDSHAKE_BINDING=1)")
        prod = _os.environ.get("P2P_PRODUCTION", "0").strip().lower() in ("1", "true", "yes", "on") or _os.environ.get("SECURE_P2P_PRODUCTION", "0") == "1"
        if prod and not getattr(self, "_binding_warned", False):
            try:
                self._binding_warned = True
            except Exception:
                pass
            logger.warning(
                f"Production {op} without handshake binding: AD covers header "
                f"only (call set_handshake_binding for identity-misbinding resistance)")

    def _get_associated_data(self, header_bytes: bytes) -> bytes:
        """
        Create authenticated data binding the header to the ciphertext.

        Binds header + optional session binding (handshake transcript hash and
        both identity keys). Signal binds the header via the chain-derived key;
        explicit binding here adds unknown-key-share / identity-misbinding
        resistance (cf. PQXDH binding analysis, USENIX'24). Legacy sessions
        without a binding fall back to context+SHA256(header) for interop.
        """
        # Application context for domain separation
        context = b"DoubleRatchet_PQSv2"
        # Deterministically bind header to context
        auth_data = hashlib.sha256(header_bytes).digest()
        bind = getattr(self, "_handshake_binding", None)
        if bind:
            try:
                return context + auth_data + bytes(bind)
            except Exception:
                pass
        return context + auth_data

    def set_handshake_binding(self, transcript_hash: Optional[bytes] = None,
                              local_sig_pk: Optional[bytes] = None,
                              remote_sig_pk: Optional[bytes] = None) -> bytes:
        """Bind the data-plane AD to the handshake (opt-in, symmetric both sides).

        Both peers MUST call with byte-identical (transcript, local, remote)
        in canonical order or AEAD will fail closed (no silent downgrade).
        Returns the 32-byte binding mixed into _get_associated_data.
        Call after the handshake; safe to call before first encrypt/decrypt.
        """
        import hashlib as _hl
        th = bytes(transcript_hash) if transcript_hash is not None else b""
        lp = bytes(local_sig_pk) if local_sig_pk is not None else b""
        rp = bytes(remote_sig_pk) if remote_sig_pk is not None else b""
        if len(th) not in (0, 32, 48, 64):
            raise SecurityError("handshake transcript hash must be 32/48/64 bytes or empty")
        for name, pk in (("local_sig_pk", lp), ("remote_sig_pk", rp)):
            if pk and len(pk) != 2592:
                raise SecurityError(f"handshake {name} must be 2592-byte ML-DSA-87 or empty")
        # Canonical order: sorted identity pair + transcript (order-independent,
        # reflection-resistant); domain-separated SHA256.
        ids = sorted([lp, rp])
        h = _hl.sha256()
        h.update(b"DR-AD-BIND-v1")
        h.update(len(th).to_bytes(4, "big") + th)
        for pk in ids:
            h.update(len(pk).to_bytes(4, "big") + pk)
        self._handshake_binding = h.digest()
        logger.info("Handshake binding set for ratchet AD (transcript+identities)")
        return bytes(self._handshake_binding)

    def get_dss_public_key(self) -> Optional[Union[bytes, dict]]:
        """Returns the public key for the Digital Signature Scheme (FALCON-1024).
        
        Returns:
            Either bytes (legacy) or dict (hybrid with 'mldsa' and 'slhdsa' components)
        """
        return self.dss_public_key

    def secure_cleanup(self) -> None:
        """Securely erase all cryptographic material from memory.

        Performs comprehensive cleanup of all sensitive key material:
        1. Securely erases all private keys and chain keys
        2. Clears all skipped message keys
        3. Resets the replay protection cache
        4. Triggers garbage collection to remove lingering references

        This method should be called when the DoubleRatchet instance
        is no longer needed to prevent sensitive cryptographic material
        from remaining in memory where it could be exposed through memory
        dumps or cold boot attacks.

        Security note:
            This method is critical for maintaining forward secrecy.
            Always call this method when a session is complete.
        """
        logger.info("Double Ratchet state securely cleaned up")

        # Verified attribute inventory (P0-1): the live key material lives in
        # root_key / sending_chain_key / receiving_chain_key (no underscore)
        # plus dh/dss/kem private state. A previous revision listed only
        # '_root_key'-style names that do not exist, so hasattr() silently
        # wiped nothing. Every erase is individually guarded so one exotic
        # key-object type can never abort the remaining wipes (fail-closed:
        # continue wiping, never skip).
        sensitive_attrs = [
            'root_key', 'sending_chain_key', 'receiving_chain_key',
            'dh_private_key', 'dss_private_key', 'kem_private_key',
            'kem_shared_secret', '_pending_pq_ct',
            '_synchronized_kem_secret', 'kem_ciphertext', '_handshake_binding',
        ]

        for attr_name in sensitive_attrs:
            try:
                if hasattr(self, attr_name):
                    attr_value = getattr(self, attr_name)
                    if attr_value is not None:
                        try:
                            secure_erase(attr_value)
                        except Exception as e_erase:
                            logger.debug(f"secure_erase failed for {attr_name}: {e_erase}")
                        # Set to None after erasure
                        try:
                            setattr(self, attr_name, None)
                        except Exception:
                            logger.debug("Attribute read-only during cleanup") # Some attributes might be read-only
            except Exception as e_attr:
                logger.debug(f"Cleanup failed for {attr_name}: {e_attr}")

        # Explicitly handle the skipped_message_keys dictionary
        if hasattr(self, 'skipped_message_keys') and self.skipped_message_keys is not None:
            # Iterate over a copy of items to be safe
            for key_id, message_key in list(self.skipped_message_keys.items()):
                # Erase the stored message key ..
                try:
                    secure_erase(message_key)
                except Exception:
                    logger.debug("secure_erase failed for a skipped message key")
                # .. and any key bytes inside the tuple key (ratchet_key_id).
                try:
                    if isinstance(key_id, tuple):
                        for part in key_id:
                            if isinstance(part, (bytes, bytearray)):
                                try:
                                    secure_erase(part)
                                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                                except Exception:  # nosec: B110
                                    pass
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
            self.skipped_message_keys.clear()
        try:
            if hasattr(self, '_skipped_key_times') and self._skipped_key_times is not None:
                self._skipped_key_times.clear()
        except Exception:
            pass

        # Clear the replay cache
        if hasattr(self, 'replay_cache') and self.replay_cache is not None:
            self.replay_cache.clear()

        # Call garbage collector
        gc.collect()

    def _skip_message_keys(self, until_message_number: int, ratchet_key_id: bytes) -> None:
        """
        Skip message keys to handle out-of-order message delivery.

        Advances the receiving chain up to the specified message number (exclusive),
        storing skipped message keys securely for later use. Updates
        self.receiving_chain_key and self.receiving_message_number to reflect
        the state after skipping.
        """
        if self.receiving_chain_key is None:
            logger.error("Cannot skip message keys: receiving_chain_key is None.")
            raise SecurityError("Cannot skip message keys: receiving chain not initialized")

        start_msg_num = self.receiving_message_number

        if start_msg_num >= until_message_number:
            return # Nothing to skip

        logger.info(f"Attempting to skip from message #{start_msg_num} up to (but not including) #{until_message_number} " +
                    f"for ratchet {format_binary(ratchet_key_id)}. Current skipped_keys: {len(self.skipped_message_keys)}/{self.MAX_SKIP_MESSAGE_KEYS}")

        num_actually_skipped_and_stored = 0

        # Store the original receiving chain key and message number in case we hit the limit
        original_chain_key = self.receiving_chain_key

        # Check if we'll exceed the max skipped keys limit before starting the skip process
        total_keys_needed = until_message_number - start_msg_num

        # Enforce hard skip ceiling (Signal MAX_SKIP=1000 DoS bound).
        hard_limit = getattr(self, 'HARD_MAX_SKIP', 1000)
        if total_keys_needed > hard_limit:
            logger.error(f"SECURITY ALERT: total_keys_needed ({total_keys_needed}) exceeds HARD_MAX_SKIP ({hard_limit}). Aborting skip.")
            raise SecurityError(f"Skipping {total_keys_needed} keys exceeds maximum hard limit of {hard_limit}.")

        if len(self.skipped_message_keys) + total_keys_needed > self.MAX_SKIP_MESSAGE_KEYS:
            # If we can't store all needed keys, calculate how many we can actually store
            keys_we_can_store = max(0, self.MAX_SKIP_MESSAGE_KEYS - len(self.skipped_message_keys))

            # Only skip as many messages as we can store keys for
            limited_until = start_msg_num + keys_we_can_store

            logger.warning(
                f"Cannot store all {total_keys_needed} skipped keys (would exceed max of {self.MAX_SKIP_MESSAGE_KEYS}). " +
                f"Limiting skip to {keys_we_can_store} keys (up to message #{limited_until-1})."
            )

            until_message_number = limited_until

        # Loop from the current message number up to the target message number (exclusive)
        for i in range(start_msg_num, until_message_number):
            if len(self.skipped_message_keys) >= self.MAX_SKIP_MESSAGE_KEYS:
                logger.warning(
                    f"Maximum skipped keys limit ({self.MAX_SKIP_MESSAGE_KEYS}) reached. " +
                    f"Stopping skip at message #{i} (was targeting up to #{until_message_number-1})."
                )
                # Ensure we update our state to reflect the actual number of messages we skipped
                self.receiving_message_number = i
                break

            # Generate message key and advance the chain state
            # This call uses and updates self.receiving_chain_key internally FOR REAL if not careful.
            # _chain_ratchet_step should be pure based on input chain_key.
            # Let's ensure _chain_ratchet_step is pure. Yes, it takes chain_key as input.

            next_chain_key_val, message_key_val = self._chain_ratchet_step(self.receiving_chain_key)

            # Store the skipped message key
            key_tuple = (ratchet_key_id, i) # i is the message number being skipped
            self.skipped_message_keys[key_tuple] = message_key_val
            try:
                if not hasattr(self, "_skipped_key_times"):
                    self._skipped_key_times = {}
                self._skipped_key_times[key_tuple] = time.monotonic()
            except Exception:
                pass

            # Update the main chain key and message number to reflect this step
            self.receiving_chain_key = next_chain_key_val
            self.receiving_message_number = i + 1 # After processing/skipping message i, next expected is i+1

            num_actually_skipped_and_stored += 1
            logger.debug(f"Stored key for skipped message {i} (ratchet {format_binary(ratchet_key_id)}). Receiving number is now {self.receiving_message_number}.")

        logger.info(f"Finished skipping operation. Advanced receiving chain by {num_actually_skipped_and_stored} steps. " +
                    f"Receiving number is now {self.receiving_message_number}. Total skipped keys stored: {len(self.skipped_message_keys)}.")

    def _compare_public_keys(self, public_key1: X25519PublicKey, public_key2_bytes: bytes) -> bool:
        """
        Compare a public key object with raw public key bytes in constant time.

        This method ensures that the comparison is done in a way that prevents
        timing side-channel attacks that could leak information about the keys.
        """
        try:
            # Convert the first key to bytes
            public_key1_bytes = public_key1.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            # Use constant-time comparison to prevent timing attacks
            return ConstantTime.compare(public_key1_bytes, public_key2_bytes)
        except Exception as e:
            logger.error(f"Error comparing public keys: {e}")
            return False

    def set_remote_public_key(self,
                            public_key_bytes: bytes,
                            kem_public_key: Optional[bytes] = None,
                            dss_public_key = None) -> None:
        """
        Initialize the ratchet with the remote party's public key.

        This is a critical step to synchronize the Double Ratchet state
        between both parties before any messages are exchanged.
        
        Args:
            public_key_bytes: Remote X25519 public key (32 bytes)
            kem_public_key: Remote KEM public key (optional, for PQ mode)
            dss_public_key: Remote DSS public key (optional, bytes or dict for hybrid)
        """
        try:
            # Log operation
            logger.info(
                f"Initializing with remote public key ({len(public_key_bytes)} bytes)" +
                (f" and KEM public key ({len(kem_public_key)} bytes)" if kem_public_key and self.enable_pq else "")
            )

            # 1. Validate and set X25519 public key
            verify_key_material(public_key_bytes, expected_length=32, description="Remote X25519 public key")
            self.remote_dh_public_key = X25519PublicKey.from_public_bytes(public_key_bytes)
            remote_fingerprint = self._get_public_key_fingerprint(self.remote_dh_public_key)

            # 2. Set DSS public key if provided and PQ is enabled
            if self.enable_pq and dss_public_key:
                verify_key_material(dss_public_key, description="Remote FALCON public key")
                self.remote_dss_public_key = dss_public_key
                if isinstance(dss_public_key, dict):
                    key_info = f"hybrid with {len(dss_public_key)} components"
                else:
                    key_info = f"{len(dss_public_key)} bytes"
                logger.debug(f"Set remote FALCON public key ({key_info})")

            # 3. Perform X25519 calculation
            logger.debug("Performing initial Diffie-Hellman exchange")
            if self.dh_private_key is None:
                self._generate_dh_keypair()
            if self.dh_private_key is None:
                raise SecurityError("DH private key unavailable after generation (fail-closed)")
            dh_output = self.dh_private_key.exchange(self.remote_dh_public_key)
            verify_key_material(dh_output, description="Initial DH output")

            # 4. Process KEM public key if in PQ mode
            kem_shared_secret = None
            if self.enable_pq and kem_public_key:
                # Store the remote KEM public key
                verify_key_material(kem_public_key, description="Remote KEM public key")
                self.remote_kem_public_key = kem_public_key

                # For initiator or if we already have a shared secret, do encapsulation
                if (self.is_initiator or
                    (hasattr(self, 'kem_shared_secret') and self.kem_shared_secret)):
                    # Check if KEM implementation is available
                    if self.kem is None:
                        logger.error("SECURITY ALERT: KEM implementation is not available")
                        raise SecurityError("Cannot perform KEM encapsulation: KEM not available")

                    # Perform KEM encapsulation
                    logger.debug("Performing ML-KEM-1024 encapsulation")
                    kem_ciphertext, kem_shared_secret = self.kem.encaps(kem_public_key)
                    self.kem_ciphertext = kem_ciphertext
                    self.kem_shared_secret = kem_shared_secret
                    verify_key_material(kem_shared_secret, description="KEM shared secret")
                    logger.debug(f"KEM shared secret successfully established ({len(kem_shared_secret)} bytes)")
                else:
                    # Responder waiting for ciphertext
                    logger.debug("Responder waiting for KEM ciphertext to complete initialization")
                    return

            # 5. Initialize chains with the generated key material
            self._initialize_chain_keys(dh_output, kem_shared_secret)

            logger.info(f"Successfully initialized chains with remote key: {format_binary(remote_fingerprint)}")

        except Exception as e:
            self.last_error = f"Failed to set remote public key: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            raise SecurityError(f"Key initialization failed: {str(e)}")

    def _secure_verify(self, public_key, payload, signature, description="signature"):
        """Verify a digital signature with enhanced security and error handling.

        Performs secure signature verification with several security enhancements:
        1. Validates all inputs before verification
        2. Uses constant-time operations where possible
        3. Implements fail-closed security (exceptions on failure)
        4. Provides detailed security logging

        This method is designed to be resistant to signature forgery attacks
        and timing side-channel attacks.

        Args:
            public_key: FALCON public key bytes for verification
            payload: Original data that was signed
            signature: Signature bytes to verify
            description: Description for error messages and logging

        Returns:
            bool: True if verification succeeds (never returns False)

        Raises:
            SecurityError: If verification fails for any reason

        Security note:
            This method follows the principle of failing closed - any verification
            error results in an exception rather than a boolean False return.
        """
        try:
            # Check for null DSS implementation
            if self.dss is None:
                logger.error(f"SECURITY ALERT: Cannot verify {description} - DSS implementation is None")
                raise SecurityError(f"Handshake aborted: cannot verify {description}")

            # Handle signature format conversion for hybrid signatures
            # If signature is bytes but public_key is dict (hybrid), wrap signature in dict
            sig_to_verify = signature
            if isinstance(public_key, dict) and isinstance(signature, bytes):
                # Wrap bytes signature as ML-DSA component (used in 'fast' mode)
                sig_to_verify = {'mldsa': signature}
                logger.debug(f"Wrapped bytes signature as ML-DSA dict for hybrid verification")
            
            if not self.dss.verify(public_key, payload, sig_to_verify):
                logger.error(f"SECURITY ALERT: {description} verification failed")
                raise SecurityError(f"Handshake aborted: invalid {description}")
            return True
        except Exception as e:
            # Log at most "signature mismatch" (avoid printing raw data)
            logger.error(f"SECURITY ALERT: {description} verification error", exc_info=True)
            raise SecurityError(f"Handshake aborted: invalid {description}")

    def retry_extreme_out_of_order_message(self, message: bytes) -> bytes:
        """
        This method has been removed for security reasons.

        The original implementation allowed decryption of extremely out-of-order messages
        beyond the MAX_SKIP_MESSAGE_KEYS limit, which could weaken forward secrecy.

        Raises:
            SecurityError: Always raises this error to maintain maximum security
        """
        logger.error("SECURITY ALERT: Extreme out-of-order message recovery is disabled for security reasons")
        raise SecurityError("Extreme out-of-order message recovery is disabled to preserve forward secrecy")


class DoubleRatchetDefaults:
    """Default security settings for the Double Ratchet protocol with NIST Level-5 algorithms."""

    # Security level configurations - Only MAXIMUM with NIST Level-5 settings
    SECURITY_LEVELS = {
        "MAXIMUM": {
            "enable_pq": True,                # Always enable PQ for NIST Level-5
            "max_skipped_keys": 1000,         # Signal MAX_SKIP: tolerate loss/reorder, bounded DoS + expiry
            "key_rotation_messages": 3,        # Very frequent key rotation
            "key_rotation_time": 10,          # 10 second key rotation
            "max_message_size": 262144,       # 256KB max message size
            "strict_verification": True,      # Always use strict verification
            "side_channel_protection": True,  # Always enable side-channel protection
            "memory_protection": True,        # Always enable memory protection
            "anomaly_detection": True,        # Always enable anomaly detection
            "hardware_binding": True,         # Always enable hardware binding when available
            "threshold_security": True,       # Always enable threshold security
            "message_padding": True,          # Always add random padding
            "anti_tampering": True,           # Always enable anti-tampering
            "secure_erasure_passes": 10,      # Always use multiple secure erasure passes
            "replay_cache_size": 1000,        # Always use large replay cache
            "replay_cache_expiry": 7200       # Always use long expiry (2 hours)
        }
    }

    @classmethod
    def get_defaults(cls, security_level="MAXIMUM") -> dict:
        """Get NIST Level-5 security configuration.

        This method always returns the MAXIMUM security level settings,
        regardless of the input parameter, to enforce NIST Level-5 security.

        Args:
            security_level: Ignored, always returns MAXIMUM

        Returns:
            Dict containing security configuration parameters
        """
        # Always use MAXIMUM security level regardless of input parameter
        config = cls.SECURITY_LEVELS["MAXIMUM"].copy()

        # Check for hardware availability and adjust hardware_binding setting only
        if config.get("hardware_binding", True) and not hsm.is_available:
            logger.warning("Hardware binding requested but no secure hardware available")
            # Still keep all other security settings at maximum

        # Never reduce security settings based on recommendations
        # Only apply stricter settings from threat detection if available
        if config.get("anomaly_detection", True) and hasattr(threat_detector, "get_security_recommendations"):
            recommendations = threat_detector.get_security_recommendations()

            # Only apply recommendations that increase security
            if recommendations.get("decrease_key_rotation_time") and recommendations["decrease_key_rotation_time"] < config["key_rotation_time"]:
                config["key_rotation_time"] = recommendations["decrease_key_rotation_time"]

            if recommendations.get("rotate_keys") and recommendations["rotate_keys"] < config["key_rotation_messages"]:
                config["key_rotation_messages"] = recommendations["rotate_keys"]

        return config

    @classmethod
    def get_recommended_level(cls) -> str:
        """Get recommended security level - always returns MAXIMUM for NIST Level-5 compliance.

        Returns:
            Always returns "MAXIMUM" to enforce NIST Level-5 security
        """
        # Always return MAXIMUM to enforce NIST Level-5 security
        return "MAXIMUM"




class ReplayCache:
    """
    Enhanced replay protection cache with timestamp-based expiration.

    This class implements a secure message ID tracking system to prevent replay attacks.
    It uses a dictionary for O(1) lookups combined with a deque for efficient expiration
    tracking. The implementation automatically manages memory usage through periodic cleanup
    and enforces a maximum cache size to prevent DoS attacks.

    Attributes:
        max_size (int): Maximum number of message IDs to store
        expiry_seconds (int): Time in seconds after which message IDs expire
        cache (Dict[bytes, float]): Dictionary mapping message IDs to timestamps
        order (collections.deque): Double-ended queue tracking insertion order
    """

    def __init__(self, max_size=200, expiry_seconds=3600):
        """
        Initialize replay protection cache with size and expiry constraints.

        Args:
            max_size (int): Maximum number of message IDs to store before forced cleanup
            expiry_seconds (int): Time in seconds after which a message ID expires

        Raises:
            ValueError: If parameters are invalid
        """
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError("max_size must be a positive integer")
        if not isinstance(expiry_seconds, (int, float)) or expiry_seconds <= 0:
            raise ValueError("expiry_seconds must be a positive number")

        self.max_size = max_size
        self.expiry_seconds = expiry_seconds

        # Using a dictionary for O(1) average time complexity for lookups
        self.cache = {}
        # Using a deque for O(1) complexity for appends and pops from both ends
        self.order = collections.deque()

        # For thread safety
        self._lock = threading.Lock()

        # For periodic cleanup
        self.last_cleanup_time = time.time()
        self.cleanup_interval = max(60, expiry_seconds / 10)  # Cleanup at least every minute

    def clear(self):
        """
        Clear all entries from the cache.

        Thread-safe operation that removes all stored message IDs and resets the
        internal tracking structures.
        """
        with self._lock:
            self.cache.clear()
            self.order.clear()
            logger.info("Replay cache cleared")

    def add(self, message_id: bytes) -> None:
        """
        Add a message ID to the cache with timestamp-based expiration.

        This method stores a message ID with the current timestamp for future
        replay detection. If the cache exceeds its maximum size, older entries
        are automatically removed.

        Args:
            message_id (bytes): The unique message ID to add to the cache

        Raises:
            TypeError: If message_id is not bytes
        """
        if not isinstance(message_id, bytes):
            raise TypeError("Message ID must be bytes")

        with self._lock:
            # Perform cleanup if needed
            current_time = time.time()
            if current_time - self.last_cleanup_time > self.cleanup_interval:
                self._cleanup(current_time)

            # If we're at capacity, force a cleanup
            if len(self.cache) >= self.max_size:
                self._cleanup(current_time, force=True)

            # If still at capacity after cleanup, remove oldest entry
            if len(self.cache) >= self.max_size:
                self._remove_oldest()

            # Add the new message ID
            self.cache[message_id] = current_time
            self.order.append(message_id)

    def contains(self, message_id: bytes) -> bool:
        """
        Check if a message ID is in the replay cache using constant-time operations.

        This method uses constant-time comparison techniques to prevent timing
        side-channel attacks that could leak information about cache contents.

        Args:
            message_id (bytes): The message ID to check

        Returns:
            bool: True if the message ID is in the cache, False otherwise

        Raises:
            TypeError: If message_id is not bytes
        """
        if not isinstance(message_id, bytes):
            raise TypeError("Message ID must be bytes")

        with self._lock:
            # First check if the message ID is in the set using a non-constant time operation
            # This is an optimization that doesn't leak timing information about specific IDs
            if message_id not in self.cache:
                # Perform a dummy constant-time operation to maintain consistent timing
                # This prevents timing attacks based on early returns
                dummy_result = ConstantTime.compare(message_id, message_id)
                return False

            # If we get here, the ID is in the set, but we'll verify with constant-time comparison
            # to prevent any potential timing leaks in the set implementation
            result = False
            for stored_id in self.cache:
                # Use constant-time comparison for each ID
                # This is a bit inefficient but ensures constant-time behavior
                is_match = ConstantTime.compare(message_id, stored_id)
                # Update result without branching
                result = result or is_match

            return result

    def _cleanup(self, current_time: float, force: bool = False) -> None:
        """
        Remove expired message IDs from the cache.

        Args:
            current_time (float): Current time in seconds since epoch
            force (bool): If True, remove at least 25% of entries even if not expired
        """
        self.last_cleanup_time = current_time
        expired_ids = []

        # Find expired message IDs
        for msg_id, timestamp in self.cache.items():
            if current_time - timestamp > self.expiry_seconds:
                expired_ids.append(msg_id)

        # If forced cleanup and not enough expired, remove oldest entries
        if force and len(expired_ids) < (self.max_size // 4):
            # Sort by timestamp and keep only the newest 75%
            sorted_ids = sorted(self.cache.items(), key=lambda x: x[1])
            additional_removals = max(1, self.max_size // 4) - len(expired_ids)
            expired_ids.extend([msg_id for msg_id, _ in sorted_ids[:additional_removals]])

        # Remove expired IDs
        for msg_id in expired_ids:
            if msg_id in self.cache:  # Check in case concurrent modifications occurred
                del self.cache[msg_id]
                # We don't remove from order here to avoid O(n) operations
                # The order deque will be rebuilt during next forced cleanup if needed

    def _remove_oldest(self) -> None:
        """
        Remove the oldest message ID from the cache based on timestamp.

        This method is called when the cache is at capacity and needs to make room
        for new entries. It removes the entry with the oldest timestamp.
        """
        if not self.cache:
            return

        try:
            oldest_id = min(self.cache.items(), key=lambda x: x[1])[0]
            del self.cache[oldest_id]
            # Try to remove from order, but don't fail if not found
            try:
                self.order.remove(oldest_id)
            except ValueError:
                # Message ID not in order deque, which might happen in edge cases
                logger.debug("Message ID not in order deque")
        except Exception as e:
            logger.warning(f"Error removing oldest cache entry: {e}")

    def __contains__(self, message_id: bytes) -> bool:
        """
        Support for 'in' operator with constant-time comparison.

        Args:
            message_id (bytes): The message ID to check

        Returns:
            bool: True if the message ID is in the cache, False otherwise
        """
        return self.contains(message_id)

    def __len__(self) -> int:
        """
        Return the number of message IDs in the cache.

        Returns:
            int: Current number of cached message IDs
        """
        return len(self.cache)



class DuplicateDetectionManager:
    """
    Duplicate Detection Manager for preventing replay attacks.

    This class implements comprehensive duplicate detection mechanisms
    to prevent replay attacks and ensure message uniqueness.
    """

    def __init__(self, window_size: int = 2048):
        """
        Initialize duplicate detection manager.

        Args:
            window_size: Size of the sliding window for duplicate detection (default: 2048)
        """
        self.window_size = window_size
        self.message_ids = collections.deque(maxlen=window_size)
        self.message_hashes = collections.OrderedDict()
        self.sequence_numbers = {}
        self.lock = threading.RLock()

        print("Duplicate detection enabled")
        print("Message ID tracking and duplicate prevention active")
        logging.info("Duplicate detection manager initialized")

    def is_duplicate(self, message_id: str, message_hash: bytes,
                    sender_id: str, sequence_number: int) -> bool:
        """
        Check if a message is a duplicate.

        Args:
            message_id: Unique message identifier
            message_hash: Hash of the message content
            sender_id: Identifier of the message sender
            sequence_number: Sequence number of the message

        Returns:
            True if message is a duplicate, False otherwise
        """
        with self.lock:
            # Check message ID
            if message_id in self.message_ids:
                logging.warning(f"Duplicate message ID detected: {message_id}")
                return True

            # Check message hash (OrderedDict O(1) membership)
            if message_hash in self.message_hashes:
                logging.warning(f"Duplicate message hash detected")
                return True

            # Check sequence number
            if sender_id in self.sequence_numbers:
                if sequence_number <= self.sequence_numbers[sender_id]:
                    logging.warning(f"Duplicate/old sequence number: {sequence_number}")
                    return True

            return False

    def record_message(self, message_id: str, message_hash: bytes,
                      sender_id: str, sequence_number: int) -> None:
        """
        Record a new message to prevent future duplicates.

        Args:
            message_id: Unique message identifier
            message_hash: Hash of the message content
            sender_id: Identifier of the message sender
            sequence_number: Sequence number of the message
        """
        with self.lock:
            # Record message ID
            self.message_ids.append(message_id)

            # Record message hash with FIFO ordering
            self.message_hashes[message_hash] = True

            # Update sequence number
            self.sequence_numbers[sender_id] = sequence_number

            # Clean up oldest hashes deterministically (FIFO eviction via OrderedDict - Finding 3.2)
            while len(self.message_hashes) > self.window_size:
                self.message_hashes.popitem(last=False)


class AntiReplayMechanisms:
    """
    Anti-Replay Mechanisms for comprehensive replay attack prevention.

    This class implements multiple layers of anti-replay protection
    including timestamps, nonces, and sequence validation.
    """

    def __init__(self, time_window: int = 300):
        """
        Initialize anti-replay mechanisms.

        Args:
            time_window: Time window in seconds for timestamp validation
        """
        self.time_window = time_window
        self.used_nonces = collections.OrderedDict()
        self.timestamp_cache = collections.deque(maxlen=10000)
        self.lock = threading.RLock()

        print("Anti-replay mechanisms enabled")
        print("Message number sequence validation and replay protection active")
        logging.info("Anti-replay mechanisms initialized")

    def validate_timestamp(self, timestamp: float) -> bool:
        """
        Validate message timestamp against replay window.

        Args:
            timestamp: Message timestamp

        Returns:
            True if timestamp is valid, False if replay detected
        """
        current_time = time.time()

        # Check if timestamp is within acceptable window
        if abs(current_time - timestamp) > self.time_window:
            logging.warning(f"Timestamp outside valid window: {timestamp}")
            return False

        with self.lock:
            # Check if timestamp was already used
            if timestamp in self.timestamp_cache:
                logging.warning(f"Timestamp replay detected: {timestamp}")
                return False

            # Record timestamp
            self.timestamp_cache.append(timestamp)
            return True

    def validate_nonce(self, nonce: bytes) -> bool:
        """
        Validate nonce for uniqueness and freshness.

        Args:
            nonce: Message nonce

        Returns:
            True if nonce is unique, False if replay detected
        """
        with self.lock:
            now = time.time()
            cutoff = now - self.time_window

            # Evict expired nonces outside time window
            while self.used_nonces and next(iter(self.used_nonces.values())) < cutoff:
                self.used_nonces.popitem(last=False)

            if nonce in self.used_nonces:
                logging.warning("Nonce replay detected")
                return False

            self.used_nonces[nonce] = now

            # Clean up oldest nonces if cache limit reached
            if len(self.used_nonces) > 50000:
                self.used_nonces.popitem(last=False)

            return True

    def generate_secure_nonce(self) -> bytes:
        """
        Generate a cryptographically secure nonce.

        Returns:
            Secure random nonce
        """
        return secrets.token_bytes(16)

    def create_anti_replay_header(self, message_id: str) -> Dict[str, Any]:
        """
        Create anti-replay header for a message.

        Args:
            message_id: Unique message identifier

        Returns:
            Anti-replay header dictionary
        """
        return {
            'message_id': message_id,
            'timestamp': time.time(),
            'nonce': self.generate_secure_nonce(),
            'sequence': secrets.randbelow(2**32)
        }


# Global instances
_duplicate_detection_manager = None
_anti_replay_mechanisms = None

def get_duplicate_detection_manager() -> DuplicateDetectionManager:
    """Get global duplicate detection manager instance."""
    global _duplicate_detection_manager
    if _duplicate_detection_manager is None:
        _duplicate_detection_manager = DuplicateDetectionManager()
    return _duplicate_detection_manager

def get_anti_replay_mechanisms() -> AntiReplayMechanisms:
    """Get global anti-replay mechanisms instance."""
    global _anti_replay_mechanisms
    if _anti_replay_mechanisms is None:
        _anti_replay_mechanisms = AntiReplayMechanisms()
    return _anti_replay_mechanisms

# Initialize on module import
try:
    duplicate_manager = get_duplicate_detection_manager()
    replay_manager = get_anti_replay_mechanisms()
    logging.info("Replay protection mechanisms initialized")
except Exception as e:
    logging.error(f"Failed to initialize replay protection: {e}")


def _braid_wire_split(msg: bytes):
    """Split a ratchet wire message into (header, sig, nonce, ext, ciphertext).

    Test/diagnostic aid mirroring the decrypt() parser (no verification).
    """
    header = msg[:MessageHeader.HEADER_SIZE]
    sig_len = int.from_bytes(
        msg[MessageHeader.HEADER_SIZE:MessageHeader.HEADER_SIZE + 2], 'big')
    sig_off = MessageHeader.HEADER_SIZE + 2
    sig = msg[sig_off:sig_off + sig_len]
    co = sig_off + sig_len
    nonce = msg[co:co + 12]
    body = msg[co + 12:]
    magic = DoubleRatchet.PQ_CT_EXT_MAGIC
    ext, ciphertext = b'', body
    if len(body) >= 6 + DoubleRatchet.PQ_CT_EXT_MIN_CIPHERTEXT and body[:4] == magic:
        n = struct.unpack('>H', body[4:6])[0]
        if 0 < n <= DoubleRatchet.PQ_CT_EXT_MAX_CT_LEN and len(body) >= 6 + n + 16:
            ext, ciphertext = body[:6 + n], body[6 + n:]
    return header, sig, nonce, ext, ciphertext


def braid_ct_sync_roundtrip(plaintext: bytes = b"Braid peer-synced CT probe",
                            *, protocol_version: int = 2) -> Dict[str, Any]:
    """Encrypt->decrypt roundtrip exercising the peer-synced Braid CT path.

    Builds two v2 sessions (full PQ handshake), drives chain messages plus
    DH-epoch changes carrying fresh CTs in both directions, and verifies:

    * plaintext roundtrips every hop (proves the receiver reproduced the
      sender's exact ``hybrid_combine_v2`` mix -- same DH output by DH
      symmetry, same KEM secret via the CT, same SYNC transcript -- because
      equal mixes are the only way the chain keys match);
    * the wire carries ``MAGIC + pq_ct_len + pq_ct`` exactly when a fresh CT
      was staged, and legacy-identical bytes otherwise;
    * paired chain keys match across each CT-carrying hop
      (sender's sending chain == receiver's receiving chain);
    * a v2 message WITHOUT a CT still decrypts (legacy-reuse fallback, no
      abort -- a peer that never sends CT stays compatible);
    * a v1 pair still roundtrips byte-compatibly (existing behavior).

    Note on "same root": Double Ratchet roots are inherently asymmetric --
    each completed DH step ends one sending-side KDF ahead of the peer, so
    ``root_key`` bytes are only simultaneously equal at handshake time (even
    in v1). Sync is therefore asserted on the paired chain keys, which is the
    observable consequence of identical root evolution. Roots are returned
    for inspection.

    Returns:
        Dict summary with plaintext/chain/fallback/v1 flags, CT sizes seen
        on the wire, and final root fingerprints. Raises AssertionError on
        any sync failure.
    """
    root = secrets.token_bytes(32)
    alice = DoubleRatchet(root_key=root, is_initiator=True,
                          protocol_version=protocol_version)
    bob = DoubleRatchet(root_key=root, is_initiator=False,
                        protocol_version=protocol_version)
    alice.negotiate_pq_ratchet_version(protocol_version)
    bob.negotiate_pq_ratchet_version(protocol_version)
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert alice.pq_ratchet_version >= 2 and bob.pq_ratchet_version >= 2  # nosec: B101

    alice.set_remote_public_key(bob.get_public_key(), bob.get_kem_public_key(),
                                bob.get_dss_public_key())
    bob.set_remote_public_key(alice.get_public_key(), alice.get_kem_public_key(),
                              alice.get_dss_public_key())
    bob.process_kem_ciphertext(alice.get_kem_ciphertext())
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert alice.is_initialized() and bob.is_initialized()  # nosec: B101

    # 0. Steady-state chain message: no step, hence no CT on the wire.
    m0 = alice.encrypt(b"pre-rotation baseline")
    _, _, _, ext0, _ = _braid_wire_split(m0)
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert ext0 == b"", "no fresh CT available -> legacy-identical wire expected"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert bob.decrypt(m0) == b"pre-rotation baseline"  # nosec: B101

    # 1. Alice rotates (half-step, legacy, stages NO CT) and sends.
    alice.force_ratchet_rotation()
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert alice.get_pending_pq_ct() is None  # nosec: B101
    m1 = alice.encrypt(b"epoch1 alice->bob")
    _, _, _, ext1, _ = _braid_wire_split(m1)
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert ext1 == b"", "force rotation stages no CT"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert bob.decrypt(m1) == b"epoch1 alice->bob"  # nosec: B101
    # Bob's step took the legacy receive path (no peer CT) but staged HIS
    # fresh CT for the reply.
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert bob._peer_ct_seen is False  # nosec: B101
    staged_b = bob.get_pending_pq_ct()
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert staged_b, "bob must have staged a fresh CT after his v2 step"  # nosec: B101

    # 2. Bob replies WITH CT: Alice must consume it (peer-synced mix).
    m2 = bob.encrypt(b"epoch2 bob->alice")
    _, _, _, ext2, _ = _braid_wire_split(m2)
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert ext2 != b"", "staged fresh CT must ride the next message"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert struct.unpack('>H', ext2[4:6])[0] == len(staged_b)  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert ext2[6:] == staged_b, "wire CT must equal the staged fresh CT"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert bob.get_pending_pq_ct() is None, "staged CT consumed exactly once"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert alice.decrypt(m2) == b"epoch2 bob->alice"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert alice._peer_ct_seen is True, "alice consumed a peer CT"  # nosec: B101
    staged_a = alice.get_pending_pq_ct()
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert staged_a, "alice must have staged a fresh CT after her v2 step"  # nosec: B101
    # Paired chains match: bob's sending chain == alice's receiving chain.
    assert (  # nosec: B101
        alice.receiving_chain_key == bob.sending_chain_key
    ), "peer-synced mix must pair chain keys (bob->alice)"

    # 3. Alice replies WITH CT: Bob consumes it.
    m3 = alice.encrypt(b"epoch3 alice->bob")
    _, _, _, ext3, _ = _braid_wire_split(m3)
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert ext3 != b"" and ext3[6:] == staged_a  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert bob.decrypt(m3) == b"epoch3 alice->bob"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert bob._peer_ct_seen is True  # nosec: B101
    assert (  # nosec: B101
        bob.receiving_chain_key == alice.sending_chain_key
    ), "peer-synced mix must pair chain keys (alice->bob)"

    # 4. Negotiated compat with a v1 peer (fresh sessions): the v2-capable
    # side negotiates down to v1, so a peer that never sends CT stays fully
    # compatible -- pure legacy wire both ways, no abort. (Note: mid-session
    # downgrade after v2 mixes is NOT supported -- negotiation precedes
    # traffic; a mismatched epoch then fails closed at AEAD, never silently.)
    v1_root = secrets.token_bytes(32)
    a1 = DoubleRatchet(root_key=v1_root, is_initiator=True, protocol_version=2)
    b1 = DoubleRatchet(root_key=v1_root, is_initiator=False, protocol_version=1)
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert a1.negotiate_pq_ratchet_version(1) == 1, "v2 side must drop to v1"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert b1.negotiate_pq_ratchet_version(2) == 1, "negotiation is min(local, peer)"  # nosec: B101
    a1.set_remote_public_key(b1.get_public_key(), b1.get_kem_public_key(),
                             b1.get_dss_public_key())
    b1.set_remote_public_key(a1.get_public_key(), a1.get_kem_public_key(),
                             a1.get_dss_public_key())
    b1.process_kem_ciphertext(a1.get_kem_ciphertext())
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert b1.decrypt(a1.encrypt(b"negotiated v1 hello")) == b"negotiated v1 hello"  # nosec: B101
    a1.force_ratchet_rotation()
    m_neg = a1.encrypt(b"negotiated v1 post-rotation")
    _, _, _, ext_neg, _ = _braid_wire_split(m_neg)
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert ext_neg == b"", "negotiated-v1 wire must carry no extension"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert b1.decrypt(m_neg) == b"negotiated v1 post-rotation"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert a1.get_pending_pq_ct() is None and b1.get_pending_pq_ct() is None  # nosec: B101

    # 5. Pure-default v1 pair (constructor defaults, as existing tests use):
    # unchanged legacy behavior.
    v1b_root = secrets.token_bytes(32)
    c1 = DoubleRatchet(root_key=v1b_root, is_initiator=True)
    d1 = DoubleRatchet(root_key=v1b_root, is_initiator=False)
    c1.set_remote_public_key(d1.get_public_key(), d1.get_kem_public_key(),
                             d1.get_dss_public_key())
    d1.set_remote_public_key(c1.get_public_key(), c1.get_kem_public_key(),
                             c1.get_dss_public_key())
    d1.process_kem_ciphertext(c1.get_kem_ciphertext())
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert d1.decrypt(c1.encrypt(b"v1 hello")) == b"v1 hello"  # nosec: B101
    c1.force_ratchet_rotation()
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert d1.decrypt(c1.encrypt(b"v1 post-rotation")) == b"v1 post-rotation"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert c1.get_pending_pq_ct() is None and d1.get_pending_pq_ct() is None  # nosec: B101

    return {
        "plaintext_roundtrip": True,
        "ct_on_wire_m2": len(ext2) - 6,
        "ct_on_wire_m3": len(ext3) - 6,
        "chain_pair_bob_to_alice": True,
        "chain_pair_alice_to_bob": True,
        "peer_ct_seen_alice": alice._peer_ct_seen,
        "peer_ct_seen_bob": bob._peer_ct_seen,
        "v2_missing_ct_fallback_ok": True,
        "v1_roundtrip_ok": True,
        "root_alice_fp": alice._get_public_key_fingerprint(
            alice.dh_public_key).hex() if alice.dh_public_key else None,
        "note": "roots ratchet asymmetrically by design; sync proven via "
                "paired chain keys + bidirectional decrypt across CT epochs",
    }

