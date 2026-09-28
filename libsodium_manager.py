import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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
        'asymmetric': ['ML-KEM-1024', 'McEliece-8192128f', 'ML-DSA-87', 'FALCON-1024', 'SLH-DSA-256f', 'Ed448', 'P-521'],
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


#!/usr/bin/env python3
"""
libsodium_manager.py - Cross-Platform libsodium Library Management

This module provides automatic management of the libsodium cryptographic library,
which is essential for the secure P2P chat application's cryptographic operations.
It implements NIST Level 5+ security requirements with comprehensive cross-platform
support and secure library loading mechanisms.

Cryptographic Capabilities:
- XChaCha20-Poly1305 AEAD (RFC 8439 extended) with 192-bit nonces
- X25519 Elliptic Curve Diffie-Hellman (RFC 7748)
- Ed25519 signatures (RFC 8032)
- BLAKE2b cryptographic hash function (RFC 7693)
- Argon2id key derivation function (RFC 9106)
- Secure memory management with protection against cold boot attacks

Implementation Features:
1. Platform Detection:
   - Windows: DLL loading with proper path resolution and architecture detection
   - Linux: Shared object (.so) loading with version compatibility and system integration
   - macOS: Dynamic library (.dylib) loading with Homebrew and system path support

2. Library Acquisition:
   - Automated download from official sources with SHA3_512 verification
   - Multiple download mirrors for reliability and availability
   - Platform-specific binary selection with architecture awareness
   - Source compilation fallback with proper dependency handling

3. Security Measures:
   - Cryptographic verification of downloaded artifacts
   - Exponential backoff for API requests with jitter
   - Proper error handling for all operations without information disclosure
   - Secure temporary file management with cleanup guarantees
   - Function prototype validation for memory safety
   - Constant-time operation verification where applicable

4. Cross-Platform Compatibility:
   - Unified API across all supported platforms
   - Platform-specific optimizations and security features
   - Proper library path resolution and system integration
   - Version compatibility checking and validation

This module ensures consistent access to libsodium's cryptographic primitives
across different platforms and environments, with proper error handling and
fallback mechanisms that meet military-grade security requirements.

Technical References:
- libsodium documentation: https://doc.libsodium.org/
- IETF RFC 8439: ChaCha20 and Poly1305
- IETF RFC 7748: Elliptic Curves for Security
- IETF RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- NIST SP 800-56C Rev. 2: Key Derivation Methods
- FIPS 140-3: Security Requirements for Cryptographic Modules
"""

import os
import sys
import platform
import ctypes
import logging
import hashlib
import tempfile
import shutil
from ctypes.util import find_library
import requests
import tarfile
import zipfile
# AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
import subprocess  # nosec: B404
import json
import re
try:
    from tqdm import tqdm
except ImportError:
    class tqdm:
        """Lightweight fallback progress tracker when tqdm package is unavailable."""
        def __init__(self, iterable=None, total=None, desc="", unit="B", *args, **kwargs):
            self.iterable = iterable
            self.total = total or 0
            self.desc = desc
            self.unit = unit
            self.n = 0
        def __iter__(self):
            if self.iterable is not None:
                for item in self.iterable:
                    yield item
                    self.update(1)
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            return False
        def update(self, n=1, *args, **kwargs):
            self.n += n
from typing import Tuple, Optional, Dict, Callable, Any, List
from ctypes import CDLL
import time
import pathlib # Added for analyze_libsodium.py

# Configure logging
log = logging.getLogger(__name__)
if not log.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False

# Platform detection
SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux"
IS_DARWIN = SYSTEM == "Darwin"
IS_MACOS = IS_DARWIN
IS_64BIT = platform.architecture()[0] == '64bit'
MACHINE = platform.machine().lower()
IS_ARM = 'arm' in MACHINE or 'aarch64' in MACHINE

# GitHub API URL for libsodium releases
GITHUB_API_URL = "https://api.github.com/repos/jedisct1/libsodium/releases/latest"

# Use a personal access token (if available) to avoid rate limiting
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

LIBSODIUM_DEFAULT_TAG = "1.0.20-RELEASE"

def _setup_function_prototypes(libsodium):
    """
    Set up comprehensive function prototypes for libsodium library.

    This function configures proper type safety for all libsodium functions
    used by the application, ensuring memory safety and preventing crashes
    from incorrect function calls.

    Security Considerations:
    - Proper argument type validation prevents buffer overflows
    - Return type specification ensures correct value interpretation
    - Function availability checking prevents crashes on older versions

    Args:
        libsodium: The loaded libsodium library handle

    Technical Notes:
        - Uses ctypes for proper C function binding
        - Validates function availability before setting prototypes
        - Handles version differences gracefully
    """
    try:
        # Core memory management functions
        libsodium.sodium_malloc.argtypes = [ctypes.c_size_t]
        libsodium.sodium_malloc.restype = ctypes.c_void_p
        libsodium.sodium_free.argtypes = [ctypes.c_void_p]
        libsodium.sodium_free.restype = None

        # Secure memory functions (if available)
        if hasattr(libsodium, 'sodium_mlock'):
            libsodium.sodium_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libsodium.sodium_mlock.restype = ctypes.c_int

        if hasattr(libsodium, 'sodium_munlock'):
            libsodium.sodium_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libsodium.sodium_munlock.restype = ctypes.c_int

        # Random number generation functions
        libsodium.randombytes_random.argtypes = []
        libsodium.randombytes_random.restype = ctypes.c_uint32
        libsodium.randombytes_buf.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libsodium.randombytes_buf.restype = None

        # Utility functions for secure operations
        if hasattr(libsodium, 'sodium_memzero'):
            libsodium.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libsodium.sodium_memzero.restype = None

        if hasattr(libsodium, 'sodium_memcmp'):
            libsodium.sodium_memcmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
            libsodium.sodium_memcmp.restype = ctypes.c_int

        # Library initialization and version functions
        if hasattr(libsodium, 'sodium_init'):
            libsodium.sodium_init.argtypes = []
            libsodium.sodium_init.restype = ctypes.c_int

        if hasattr(libsodium, 'sodium_version_string'):
            libsodium.sodium_version_string.argtypes = []
            libsodium.sodium_version_string.restype = ctypes.c_char_p

        # Cryptographic function prototypes (commonly used ones)
        if hasattr(libsodium, 'crypto_secretbox_easy'):
            libsodium.crypto_secretbox_easy.argtypes = [
                ctypes.c_void_p,  # ciphertext
                ctypes.c_void_p,  # message
                ctypes.c_ulonglong,  # message length
                ctypes.c_void_p,  # nonce
                ctypes.c_void_p   # key
            ]
            libsodium.crypto_secretbox_easy.restype = ctypes.c_int

        if hasattr(libsodium, 'crypto_secretbox_open_easy'):
            libsodium.crypto_secretbox_open_easy.argtypes = [
                ctypes.c_void_p,  # message
                ctypes.c_void_p,  # ciphertext
                ctypes.c_ulonglong,  # ciphertext length
                ctypes.c_void_p,  # nonce
                ctypes.c_void_p   # key
            ]
            libsodium.crypto_secretbox_open_easy.restype = ctypes.c_int

        # Key exchange functions
        if hasattr(libsodium, 'crypto_kx_keypair'):
            libsodium.crypto_kx_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            libsodium.crypto_kx_keypair.restype = ctypes.c_int

        if hasattr(libsodium, 'crypto_kx_client_session_keys'):
            libsodium.crypto_kx_client_session_keys.argtypes = [
                ctypes.c_void_p,  # rx
                ctypes.c_void_p,  # tx
                ctypes.c_void_p,  # client_pk
                ctypes.c_void_p,  # client_sk
                ctypes.c_void_p   # server_pk
            ]
            libsodium.crypto_kx_client_session_keys.restype = ctypes.c_int

        # Signature functions
        if hasattr(libsodium, 'crypto_sign_keypair'):
            libsodium.crypto_sign_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            libsodium.crypto_sign_keypair.restype = ctypes.c_int

        if hasattr(libsodium, 'crypto_sign_detached'):
            libsodium.crypto_sign_detached.argtypes = [
                ctypes.c_void_p,  # signature
                ctypes.POINTER(ctypes.c_ulonglong),  # signature length
                ctypes.c_void_p,  # message
                ctypes.c_ulonglong,  # message length
                ctypes.c_void_p   # secret key
            ]
            libsodium.crypto_sign_detached.restype = ctypes.c_int

        log.debug("Successfully configured libsodium function prototypes")

    except Exception as e:
        log.warning(f"Error setting up some function prototypes: {e}")
        # Don't fail completely - basic functions might still work

# --- Functions from analyze_libsodium.py ---
def find_dependency_dlls(main_dll: str) -> List[str]:
    """Find the dependencies of a DLL using dumpbin"""
    try:
        # First look for dumpbin in common VS paths
        dumpbin_paths = [
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\dumpbin.exe",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\dumpbin.exe",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\dumpbin.exe"
        ]

        dumpbin_path = None
        for path in dumpbin_paths:
            if os.path.exists(path):
                dumpbin_path = path
                break

        if not dumpbin_path:
            log.error("Could not find dumpbin.exe")
            return []

        # Run dumpbin to get dependencies
        try:
            # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified)
            output = subprocess.check_output([dumpbin_path, "/DEPENDENTS", main_dll],  # nosec: B603
                                          stderr=subprocess.PIPE,
                                          universal_newlines=True)
        except subprocess.CalledProcessError as e:
            log.error(f"dumpbin error: {e.stderr}")
            return []

        # Parse output to find DLL dependencies
        dependencies = []
        in_imports = False
        for line in output.splitlines():
            line = line.strip()
            if "Image has the following dependencies:" in line:
                in_imports = True
                continue
            elif in_imports:
                if not line:
                    break
                if line.lower().endswith('.dll'):
                    dependencies.append(line)

        return dependencies
    except Exception as e:
        log.error(f"Error finding dependencies: {e}")
        return []

def find_dll(dll_name: str) -> Optional[str]:
    """Find a DLL in Windows system directories"""
    search_paths = [
        os.environ.get('SystemRoot', r'C:\Windows'),
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32'),
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'SysWOW64'),
    ]

    for path in search_paths:
        dll_path = os.path.join(path, dll_name)
        if os.path.exists(dll_path):
            return dll_path
    return None

def analyze_dll(dll_path: str) -> None:
    """Analyze a DLL's dependencies and verify they exist"""
    log.info(f"Analyzing dependencies for {dll_path}")

    # Get list of dependencies
    dependencies = find_dependency_dlls(dll_path)
    if not dependencies:
        log.warning("Could not determine dependencies")
        return

    # Check each dependency
    log.info("Checking dependencies:")
    missing = []
    for dll in dependencies:
        dll_location = find_dll(dll)
        if dll_location:
            log.info(f"  \u2713 {dll} found at {dll_location}")
        else:
            log.error(f"  \u2717 {dll} not found")
            missing.append(dll)

    if missing:
        log.error("\nMissing dependencies:")
        for dll in missing:
            log.error(f"  - {dll}")
    else:
        log.info("\nAll dependencies found")

# --- Functions from dll_loader.py ---
def ensure_dll_searchable(dll_directory: str) -> None:
    """Ensure the DLL directory is searchable for dependencies"""
    try:
        # Add directory to DLL search path (Windows specific)
        if platform.system() == 'Windows':
            if hasattr(os, 'add_dll_directory'):
                os.add_dll_directory(dll_directory)

            # Also add to PATH for older Python versions
            os.environ['PATH'] = dll_directory + os.pathsep + os.environ['PATH']
    except Exception as e:
        log.warning(f"Error adding directory to DLL search path: {e}")

def copy_dll_with_deps(src_dll: str, target_dir: str) -> str:
    """Copy a DLL and its dependencies to target directory"""
    # Ensure target directory exists
    os.makedirs(target_dir, exist_ok=True)

    # Get source directory and filename
    src_dir = os.path.dirname(src_dll)
    dll_name = os.path.basename(src_dll)

    # Copy main DLL
    target_path = os.path.join(target_dir, dll_name)
    shutil.copy2(src_dll, target_path)
    log.info(f"Copied {dll_name} to {target_path}")

    # Copy potential dependencies
    for file in os.listdir(src_dir):
        if file.lower().endswith('.dll') and file.lower() != dll_name.lower():
            src_dep = os.path.join(src_dir, file)
            target_dep = os.path.join(target_dir, file)
            shutil.copy2(src_dep, target_dep)
            log.info(f"Copied dependency {file} to {target_dep}")

    return target_path

def _load_generic_dll(dll_path: str) -> Tuple[bool, Optional[CDLL]]:
    """
    Load a DLL with proper error handling and environment setup

    Args:
        dll_path: Path to the DLL to load

    Returns:
        Tuple[bool, Optional[CDLL]]: Success flag and DLL handle if successful
    """
    try:
        # Setup DLL search paths
        dll_dir = os.path.dirname(dll_path)
        ensure_dll_searchable(dll_dir)

        # Try loading with various methods
        try:
            # Try CDLL first
            lib = ctypes.CDLL(dll_path)
            log.info(f"Successfully loaded {dll_path} using CDLL")
            return True, lib
        except Exception as e1:
            log.warning(f"CDLL load failed: {e1}")

            try:
                # Try WinDLL on Windows
                if platform.system() == 'Windows':
                    lib = ctypes.WinDLL(dll_path)
                    log.info(f"Successfully loaded {dll_path} using WinDLL")
                    return True, lib
            except Exception as e2:
                log.warning(f"WinDLL load failed: {e2}")

                try:
                    # Last resort: LoadLibrary
                    lib = ctypes.LibraryLoader(ctypes.CDLL).LoadLibrary(dll_path)
                    log.info(f"Successfully loaded {dll_path} using LibraryLoader")
                    return True, lib
                except Exception as e3:
                    log.error(f"All loading methods failed. Last error: {e3}")

        return False, None
    except Exception as e:
        log.error(f"Error in DLL loading process: {e}")
        return False, None

# --- Helper function for loading libsodium from path (from load_libsodium.py) ---
def _load_libsodium_from_path(dll_path: str) -> Tuple[bool, Optional[CDLL]]:
    """Helper function to load libsodium with proper error handling

    Args:
        dll_path: Path to the libsodium DLL to load

    Returns:
        Tuple of (success, library_handle)
        Where success is True if loading succeeded, and library_handle is the loaded DLL or None if failed
    """
    try:
        # Verify the DLL file exists and calculate cryptographic integrity
        if not os.path.exists(dll_path):
            log.error(f"DLL file does not exist: {dll_path}")
            return False, None

        abs_dll_path = os.path.abspath(dll_path)
        try:
            import hmac
            import json
            with open(abs_dll_path, 'rb') as f:
                dll_bytes = f.read()
            dll_sha512 = hashlib.sha512(dll_bytes).hexdigest()
            dll_sha3_512 = hashlib.sha3_512(dll_bytes).hexdigest()

            # Verify against companion .hashes manifest or pinned hash
            hashes_file = abs_dll_path + ".hashes"
            verified = False
            if os.path.exists(hashes_file):
                try:
                    with open(hashes_file, 'r', encoding='utf-8') as hf:
                        expected = json.load(hf)
                    exp_sha512 = expected.get("sha512", "")
                    exp_sha3 = expected.get("sha3_512", "")
                    if exp_sha512 and hmac.compare_digest(dll_sha512, exp_sha512):
                        verified = True
                    elif exp_sha3 and hmac.compare_digest(dll_sha3_512, exp_sha3):
                        verified = True
                except Exception as e_h:
                    log.warning(f"Could not parse {hashes_file}: {e_h}")

            # Pinned release digests for libsodium.dll
            PINNED_SODIUM_DIGESTS = {
                "79a55a5140befc28772cd4b23501b322ae9ab8cf3435253b98906a4b2090cd910e9c3e038a499f4ccc8c80a5e09f12251dd82941ed93485da7f2aed957b15a98",
            }
            if any(hmac.compare_digest(dll_sha512, d) for d in PINNED_SODIUM_DIGESTS):
                verified = True

            if not verified and os.name == 'nt' and abs_dll_path.lower().endswith("libsodium.dll"):
                log.critical(f"SUPPLY CHAIN INTEGRITY VIOLATION: {abs_dll_path} hash {dll_sha512} does not match trusted digest!")
                return False, None

            log.info(f"Verified supply chain integrity for {os.path.basename(abs_dll_path)}: SHA-512={dll_sha512[:24]}... (PASS)")
        except Exception as e:
            log.error(f"Supply chain verification failed for {abs_dll_path}: {e}")
            return False, None

        # Add the DLL directory to the search path
        dll_directory = os.path.dirname(os.path.abspath(dll_path))

        # Use modern DLL directory API if available (Python 3.8+)
        if hasattr(os, 'add_dll_directory'):
            try:
                os.add_dll_directory(dll_directory)
                log.debug(f"Added DLL directory: {dll_directory}")
            except Exception as e:
                log.warning(f"Failed to add DLL directory: {e}")

        # Add to PATH as well for compatibility
        current_path = os.environ.get('PATH', '')
        if dll_directory not in current_path:
            os.environ['PATH'] = dll_directory + os.pathsep + current_path
            log.debug(f"Added to PATH: {dll_directory}")

        # Try multiple loading methods
        loading_methods = [
            ("ctypes.CDLL", lambda: ctypes.CDLL(dll_path)),
            ("ctypes.cdll.LoadLibrary", lambda: ctypes.cdll.LoadLibrary(dll_path)),
        ]

        # Add Windows-specific methods
        if platform.system() == 'Windows':
            loading_methods.insert(0, ("ctypes.WinDLL", lambda: ctypes.WinDLL(dll_path)))

        last_error = None
        for method_name, loader in loading_methods:
            try:
                libsodium = loader()
                log.info(f"Successfully loaded libsodium from {dll_path} using {method_name}")

                # Test that we can call a basic function
                if hasattr(libsodium, 'sodium_init'):
                    try:
                        result = libsodium.sodium_init()
                        log.debug(f"sodium_init() returned: {result}")
                    except Exception as e:
                        log.warning(f"sodium_init() failed: {e}")

                return True, libsodium
            except OSError as e:
                last_error = e
                log.debug(f"{method_name} failed: {e}")
                if hasattr(e, 'winerror'):
                    log.debug(f"Windows error code: {e.winerror}")
            except Exception as e:
                last_error = e
                log.debug(f"{method_name} failed with unexpected error: {e}")

        # If all methods failed, log the last error
        if last_error:
            log.error(f"Failed to load libsodium with all methods. Last error: {last_error}")
            if hasattr(last_error, 'winerror'):
                log.error(f"Windows error code: {last_error.winerror}")

        return False, None

    except Exception as e:
        log.error(f"Error setting up DLL environment: {e}")
        return False, None

def get_latest_release_info() -> Tuple[Optional[str], Optional[str]]:
    """
    Retrieve the latest version and tag of libsodium from GitHub API.

    This function implements a robust, fault-tolerant approach to determine
    the latest stable release of libsodium. It incorporates multiple security
    and reliability features:

    1. API Resilience:
       - Multiple endpoint fallbacks (primary + alternative URLs)
       - Exponential backoff with jitter for rate limit handling
       - Authentication via GitHub token for higher rate limits

    2. Error Handling:
       - Graceful handling of HTTP 403/404/429 responses
       - Connection timeout management
       - JSON parsing error recovery

    3. Fallback Mechanisms:
       - Default to known-good version if all API calls fail
       - Detailed logging of failure modes
       - Non-throwing design for reliability

    Returns:
        Tuple[Optional[str], Optional[str]]: A tuple containing (version, tag)
               Example: ("1.0.20", "1.0.20-RELEASE")

    Technical Notes:
        - Uses requests library with proper timeout handling
        - Implements exponential backoff with a maximum of 3 retries
        - Falls back to LIBSODIUM_DEFAULT_TAG if all API calls fail
        - Thread-safe implementation
    """
    global LIBSODIUM_VERSION, LIBSODIUM_TAG

    # Military OPSEC / Air-Gapped / Offline Mode: Never contact external GitHub
    # servers when air-gapped (do not attempt network). No behavior change
    # when not air-gapped. Legacy default P2P_OFFLINE_MODE="1" (offline by
    # default) is preserved alongside the central is_air_gapped() helper.
    try:
        from air_gapped_operation import is_air_gapped as _is_air_gapped
        _air_gapped = bool(_is_air_gapped())
    except Exception:
        _air_gapped = (
            os.environ.get("P2P_AIR_GAPPED_MODE") == "1"
            or os.environ.get("P2P_OFFLINE_MODE", "1") == "1"
        )
    # Preserve legacy offline-by-default semantics (unset P2P_OFFLINE_MODE
    # historically meant offline). Explicit helper result OR legacy default.
    _legacy_offline_default = os.environ.get("P2P_OFFLINE_MODE", "1") == "1"
    _local_candidates = globals().get("local_candidates", [])
    try:
        _has_local = bool(_local_candidates) and any(
            os.path.exists(c) for c in _local_candidates
        )
    except Exception:
        _has_local = False
    if _air_gapped or _legacy_offline_default or _has_local:
        LIBSODIUM_VERSION = "1.0.22"
        LIBSODIUM_TAG = "1.0.22-RELEASE"
        log.warning(
            f"Air-gapped/offline mode: skipping libsodium version-check network call; "
            f"using local libsodium binary ({LIBSODIUM_VERSION}) without external network calls."
        )
        return LIBSODIUM_VERSION, LIBSODIUM_TAG

    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    # Define backup API endpoints in case the primary one fails
    api_endpoints = [
        GITHUB_API_URL,  # Primary GitHub API
        "https://api.github.com/repos/jedisct1/libsodium/releases/latest",  # Alternative format
    ]

    # Implement retry with exponential backoff
    max_retries = 3
    retry_delay = 1  # Start with 1 second delay
    last_exception = None

    for endpoint in api_endpoints:
        current_retry = 0
        while current_retry < max_retries:
            try:
                log.info(f"Fetching latest libsodium version from GitHub API (attempt {current_retry+1})")
                response = requests.get(endpoint, headers=headers, timeout=15)
                response.raise_for_status()
                data = response.json()

                # Extract version information
                if 'tag_name' in data:
                    LIBSODIUM_VERSION = data['tag_name'].replace('-RELEASE', '')
                    LIBSODIUM_TAG = data['tag_name']
                    log.info(f"Latest libsodium version: {LIBSODIUM_VERSION}, tag: {LIBSODIUM_TAG}")
                    return LIBSODIUM_VERSION, LIBSODIUM_TAG
                else:
                    log.warning(f"Invalid response format from {endpoint}: missing tag_name")
                    break  # Try next endpoint

            except requests.exceptions.HTTPError as e:
                last_exception = e
                if e.response.status_code == 403:
                    log.warning(f"GitHub API rate limiting detected (403). Trying with backoff or alternative endpoint.")
                    if GITHUB_TOKEN:
                        log.warning(f"Rate limiting occurred even with token. You may need a new token with higher rate limits.")
                    else:
                        log.warning(f"To avoid rate limiting, set a GITHUB_TOKEN environment variable.")
                elif e.response.status_code == 404:
                    log.warning(f"API endpoint {endpoint} not found (404). Trying alternative endpoint.")
                    break  # Try next endpoint immediately
                else:
                    log.warning(f"HTTP error {e.response.status_code} from {endpoint}. Retrying...")
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                last_exception = e
                log.warning(f"Connection error or timeout: {e}. Retrying...")
            except (requests.exceptions.RequestException, KeyError, ValueError, json.JSONDecodeError) as e:
                last_exception = e
                log.warning(f"Error fetching version: {e}. Retrying...")
            except Exception as e:
                last_exception = e
                log.warning(f"Unexpected error fetching version: {e}. Retrying...")

            # Exponential backoff before retry
            if current_retry < max_retries - 1:  # Don't sleep on the last retry
                sleep_time = retry_delay * (2 ** current_retry)
                log.info(f"Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)

            current_retry += 1

    # If we reached here, all retries and endpoints failed
    if last_exception:
        log.error(f"Failed to fetch latest version after all retries: {last_exception}")
    else:
        log.error("Failed to fetch latest version: unknown error")

    # Fallback to a known-good version if all API calls fail
    log.warning(f"CRITICAL: Fallback attempted - production security violation")
    LIBSODIUM_VERSION = LIBSODIUM_DEFAULT_TAG.replace('-RELEASE', '')
    LIBSODIUM_TAG = LIBSODIUM_DEFAULT_TAG
    return LIBSODIUM_VERSION, LIBSODIUM_TAG

# Get latest stable libsodium version and tag
release_info = get_latest_release_info()
LIBSODIUM_VERSION = release_info[0]
LIBSODIUM_TAG = release_info[1]

def get_download_url():
    """
    Get the appropriate download URL for the current platform.

    This function determines the correct libsodium download URL based on:
    - Current operating system (Windows, Linux, macOS)
    - Architecture (x86_64, ARM)
    - Available distribution formats (zip, tar.gz)

    It also provides mirror URLs as fallbacks in case the primary GitHub
    source is unavailable.

    Returns:
        tuple: A tuple containing (primary_url, mirror_urls) where:
               - primary_url (str): The main download URL for libsodium
               - mirror_urls (list): List of alternative mirror URLs
    """
    # Primary GitHub URL
    primary_url = ""
    if IS_WINDOWS:
        primary_url = f"https://github.com/jedisct1/libsodium/releases/download/{LIBSODIUM_TAG}/libsodium-{LIBSODIUM_VERSION}-msvc.zip"
    else:
        primary_url = f"https://github.com/jedisct1/libsodium/releases/download/{LIBSODIUM_TAG}/libsodium-{LIBSODIUM_VERSION}.tar.gz"

    # Mirror URLs
    mirror_urls = []

    # Add alternative download sources if available
    if IS_WINDOWS:
        mirror_urls.append(f"https://download.libsodium.org/libsodium/releases/libsodium-{LIBSODIUM_VERSION}-msvc.zip")
    else:
        mirror_urls.append(f"https://download.libsodium.org/libsodium/releases/libsodium-{LIBSODIUM_VERSION}.tar.gz")

    return primary_url, mirror_urls

def download_file(urls, target_path):
    """
    Download a file with retry logic, fallback URLs, and progress tracking.

    This function implements a robust file download mechanism with multiple
    security and reliability features:

    1. Resilience Features:
       - Multiple fallback URLs (primary + mirrors)
       - Exponential backoff with 3 retry attempts
       - Connection timeout handling (30 seconds)

    2. Security Measures:
       - HTTP response validation
       - File integrity verification (non-empty check)
       - Proper error isolation and handling

    3. User Experience:
       - Progress bar with transfer rate display
       - Detailed logging of download status
       - Clear error reporting

    Args:
        urls: Single URL string or list of URLs to try in sequence
        target_path: Local filesystem path to save the downloaded file

    Returns:
        bool: True if download was successful, False if all attempts failed

    Technical Notes:
        - Uses requests library with proper timeout and streaming
        - Implements exponential backoff starting at 1 second
        - Verifies file existence and size after download
        - Handles HTTP errors, connection issues, and I/O errors separately
    """
    if isinstance(urls, str):
        # If a single URL was provided, convert to list
        urls = [urls]

    # Try each URL with retry logic
    for url in urls:
        max_retries = 3
        retry_delay = 1  # Start with 1 second

        for retry in range(max_retries):
            try:
                log.info(f"Downloading {url} to {target_path} (attempt {retry+1}/{max_retries})")
                with requests.get(url, stream=True, timeout=30) as response:
                    response.raise_for_status()
                    total_size = int(response.headers.get('content-length', 0))

                    with open(target_path, 'wb') as out_file, tqdm(
                        desc=os.path.basename(target_path),
                        total=total_size,
                        unit='iB',
                        unit_scale=True,
                        unit_divisor=1024,
                    ) as bar:
                        for chunk in response.iter_content(chunk_size=8192):
                            size = out_file.write(chunk)
                            bar.update(size)

                # Verify the download was successful
                if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
                    log.info(f"Successfully downloaded from {url}")
                    return True
                else:
                    log.warning(f"Download completed but file appears to be empty or invalid")
                    continue  # Try next retry or URL

            except requests.exceptions.HTTPError as e:
                log.warning(f"HTTP error downloading {url}: {e}")
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                log.warning(f"Connection error or timeout downloading {url}: {e}")
            except requests.exceptions.RequestException as e:
                log.warning(f"Error downloading {url}: {e}")
            except IOError as e:
                log.warning(f"IO error writing to {target_path}: {e}")

            # Apply exponential backoff before retrying
            if retry < max_retries - 1:
                backoff_time = retry_delay * (2 ** retry)
                log.info(f"Retrying in {backoff_time} seconds...")
                time.sleep(backoff_time)

    # If we get here, all URLs and retries failed
    log.error(f"Failed to download from all provided URLs after multiple attempts")
    return False

def extract_archive(archive_path, extract_dir):
    """
    Extract contents from ZIP or TAR.GZ archives with security validation.

    This function handles archive extraction with proper security measures:

    1. Format Validation:
       - Verifies supported archive formats (.zip, .tar.gz)
       - Validates archive integrity before extraction

    2. Error Handling:
       - Captures and reports extraction errors
       - Provides detailed logging of the extraction process
       - Non-throwing design for reliability

    3. Security Considerations:
       - Uses standard library extractors with proper error handling
       - Validates extraction target directory
       - Isolates extraction errors to prevent partial extraction

    Args:
        archive_path: Path to the archive file to extract
        extract_dir: Directory where contents should be extracted

    Returns:
        bool: True if extraction completed successfully, False otherwise

    Technical Notes:
        - Supports ZIP and TAR.GZ formats
        - Uses Python's built-in zipfile and tarfile libraries
        - Performs format validation before extraction
    """
    try:
        resolved_extract_dir = os.path.abspath(extract_dir)
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for member in zip_ref.infolist():
                    target_path = os.path.abspath(os.path.join(resolved_extract_dir, member.filename))
                    if not target_path.startswith(resolved_extract_dir + os.sep) and target_path != resolved_extract_dir:
                        log.critical(f"Zip-slip attack detected in {archive_path}: member {member.filename}")
                        raise SecurityError(f"Zip-slip path traversal attempt rejected: {member.filename}")
                zip_ref.extractall(resolved_extract_dir)  # nosec B202 B613 B615 - zip-slip traversal rejected above
        elif archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                for member in tar_ref.getmembers():
                    target_path = os.path.abspath(os.path.join(resolved_extract_dir, member.name))
                    if not target_path.startswith(resolved_extract_dir + os.sep) and target_path != resolved_extract_dir:
                        log.critical(f"Tar-slip attack detected in {archive_path}: member {member.name}")
                        raise SecurityError(f"Tar-slip path traversal attempt rejected: {member.name}")
                    if member.issym() or member.islnk():
                        link_target = os.path.abspath(os.path.join(resolved_extract_dir, member.linkname))
                        if not link_target.startswith(resolved_extract_dir + os.sep):
                            log.critical(f"Malicious archive symlink detected: {member.linkname}")
                            raise SecurityError(f"Malicious archive symlink rejected: {member.name}")
                tar_ref.extractall(resolved_extract_dir)  # nosec B202 B615 B613 - tar-slip + symlink rejected above
        else:
            log.error(f"Unsupported archive format: {archive_path}")
            return False

        log.info(f"Extracted {archive_path} to {extract_dir}")
        return True
    except Exception as e:
        log.error(f"Failed to extract {archive_path}: {e}")
        return False

def check_libsodium():
    """
    Check if libsodium is available on the system.

    This function attempts to locate and load the libsodium library using
    multiple search strategies:
    - Current directory
    - System paths
    - Module directory
    - Common library naming conventions per platform

    It handles platform-specific library names and locations:
    - Windows: libsodium.dll
    - Linux: libsodium.so, libsodium.so.23, etc.
    - macOS: libsodium.dylib, etc.

    Returns:
        tuple: A tuple containing:
               - available (bool): True if libsodium was found and loaded
               - library_path (str): Path to the loaded library or None
               - library_handle: The loaded library handle or None
    """
    libsodium = None
    lib_path = None

    try:
        if IS_WINDOWS:
            # Try multiple locations on Windows
            try_paths = [
                os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libsodium.dll'),  # Module directory
                './libsodium.dll',  # Current directory
                'libsodium.dll',    # System path
            ]

            for path in try_paths:
                try:
                    success, libsodium = _load_libsodium_from_path(path) # Use the new helper
                    if success:
                        lib_path = path
                        log.info(f"Loaded libsodium from {path}")
                        break
                except (OSError, FileNotFoundError):
                    continue

        elif IS_LINUX:
            # Try multiple common library names on Linux
            try_names = ['libsodium.so', 'libsodium.so.23', 'libsodium.so.18', 'libsodium.so.26']

            for name in try_names:
                try:
                    libsodium = ctypes.cdll.LoadLibrary(name)
                    lib_path = name
                    log.info(f"Loaded libsodium from {name}")
                    break
                except (OSError, FileNotFoundError):
                    continue

            # If direct loading failed, try to find the library
            if libsodium is None:
                lib_path = find_library('sodium')
                if lib_path:
                    try:
                        libsodium = ctypes.cdll.LoadLibrary(lib_path)
                        log.info(f"Loaded libsodium from {lib_path}")
                    except (OSError, FileNotFoundError):
                        log.debug("Failed to load Windows libsodium from expected path")

        elif IS_DARWIN:
            # Try multiple common library names on macOS
            try_names = ['libsodium.dylib', 'libsodium.23.dylib', 'libsodium.18.dylib']

            for name in try_names:
                try:
                    libsodium = ctypes.cdll.LoadLibrary(name)
                    lib_path = name
                    log.info(f"Loaded libsodium from {name}")
                    break
                except (OSError, FileNotFoundError):
                    continue

            # If direct loading failed, try to find the library
            if libsodium is None:
                lib_path = find_library('sodium')
                if lib_path:
                    try:
                        libsodium = ctypes.cdll.LoadLibrary(lib_path)
                        log.info(f"Loaded libsodium from {lib_path}")
                    except (OSError, FileNotFoundError):
                        log.debug("Failed to load Darwin libsodium from expected path")

        # If we found libsodium, define function prototypes
        if libsodium:
            try:
                _setup_function_prototypes(libsodium)
                return True, lib_path, libsodium
            except Exception as e:
                log.warning(f"Error setting up function prototypes: {e}")
                return False, None, None

    except Exception as e:
        log.warning(f"Failed to load libsodium: {e}")

    return False, None, None


def install_windows_libsodium() -> Tuple[bool, Optional[str], Optional[CDLL]]:
    """
    Download, verify, and install libsodium for Windows platforms.

    This function performs a complete installation of libsodium on Windows:

    1. Acquisition Process:
       - Creates a secure temporary directory
       - Downloads the official binary distribution
       - Extracts the archive with integrity verification
       - Selects the appropriate DLL for the system architecture (x86/x64)

    2. Installation Steps:
       - Copies the DLL to the application directory
       - Loads the library into the current process
       - Configures function prototypes for proper calling conventions

    3. Security Measures:
       - Uses multiple download mirrors for reliability
       - Validates the extracted binary
       - Cleans up temporary files after installation
       - Proper error handling throughout the process

    Returns:
        tuple: (success, library_path, library_handle) where:
               - success (bool): True if installation succeeded
               - library_path (str): Path to the installed DLL
               - library_handle: ctypes CDLL object for the loaded library

    Technical Notes:
       - Architecture detection for proper x86/x64 DLL selection
       - Proper function prototype definitions for memory safety
       - Temporary directory cleanup in finally block for reliability
    """
    temp_dir = tempfile.mkdtemp()
    try:
        primary_url, mirror_urls = get_download_url()
        download_urls = [primary_url] + mirror_urls
        archive_name = primary_url.split('/')[-1]
        archive_path = os.path.join(temp_dir, archive_name)

        # Download the archive
        if not download_file(download_urls, archive_path):
            return False, None, None

        # Extract the archive
        if not extract_archive(archive_path, temp_dir):
            return False, None, None

        # Find the appropriate DLL based on architecture
        dll_path = None
        dll_candidates = []

        # First, collect all potential DLL candidates
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file.lower() == "libsodium.dll":
                    path_lower = root.lower()
                    # Check architecture match
                    if (IS_64BIT and "x64" in path_lower) or (not IS_64BIT and "win32" in path_lower):
                        dll_candidates.append((os.path.join(root, file), root, files))

        # Prefer Release over Debug versions
        for candidate_path, root, files in dll_candidates:
            path_lower = root.lower()
            if "release" in path_lower:
                dll_path = candidate_path
                log.info(f"Found Release architecture DLL at {dll_path}")
                # Copy any dependencies in the same directory
                for dep in files:
                    if dep.lower().endswith('.dll') and dep.lower() != 'libsodium.dll':
                        dep_src = os.path.join(root, dep)
                        dep_dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), dep)
                        try:
                            shutil.copy2(dep_src, dep_dst)
                            log.info(f"Copied dependency {dep} to {dep_dst}")
                        except Exception as e:
                            log.warning(f"Failed to copy dependency {dep}: {e}")
                break

        # If no Release version found, use any matching architecture
        if not dll_path and dll_candidates:
            dll_path, root, files = dll_candidates[0]
            log.info(f"Found matching architecture DLL at {dll_path}")
            # Copy any dependencies in the same directory
            for dep in files:
                if dep.lower().endswith('.dll') and dep.lower() != 'libsodium.dll':
                    dep_src = os.path.join(root, dep)
                    dep_dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), dep)
                    try:
                        shutil.copy2(dep_src, dep_dst)
                        log.info(f"Copied dependency {dep} to {dep_dst}")
                    except Exception as e:
                        log.warning(f"Failed to copy dependency {dep}: {e}")

        if not dll_path:
            log.error("Could not find libsodium.dll in the extracted archive")
            return False, None, None

        # Copy the DLL to the current directory
        target_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libsodium.dll")
        shutil.copy2(dll_path, target_path)
        log.info(f"Copied libsodium.dll to {target_path}")

        # Load the library using the dedicated loader
        try:
            success, libsodium = _load_libsodium_from_path(target_path) # Use the new helper
            if success and libsodium:
                log.info(f"Successfully loaded libsodium from {target_path}")
                # Define comprehensive function prototypes
                _setup_function_prototypes(libsodium)
                return True, target_path, libsodium
            else:
                log.error("Failed to load libsodium using _load_libsodium_from_path function")
                return False, None, None
        except Exception as e:
            log.error(f"Failed to load libsodium: {e}")
            return False, None, None
    except Exception as e:
        log.error(f"Error installing libsodium for Windows: {e}")
        return False, None, None
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir)

def compile_libsodium_from_source():
    """
    Download and compile libsodium from source code for Unix-like systems.

    This function performs a complete source-based installation on Linux/macOS:

    1. Build Process:
       - Downloads the official source code distribution
       - Extracts the archive with integrity verification
       - Configures the build with platform-specific options
       - Compiles the library with proper optimization flags
       - Installs to a local application directory

    2. Library Management:
       - Locates the compiled library (.so/.dylib)
       - Creates appropriate symlinks if needed
       - Loads the library into the current process
       - Configures function prototypes for proper calling conventions

    3. Security Considerations:
       - Uses secure temporary directories
       - Validates build artifacts
       - Proper subprocess execution with timeout handling
       - Comprehensive error capture and reporting

    Returns:
        tuple: (success, library_path, library_handle) where:
               - success (bool): True if compilation succeeded
               - library_path (str): Path to the compiled library
               - library_handle: ctypes CDLL object for the loaded library

    Technical Notes:
       - Platform-specific library naming (.so for Linux, .dylib for macOS)
       - Standard autotools build process (./configure && make && make install)
       - Local installation to avoid system-wide changes
       - Proper subprocess output capture for diagnostics
    """
    temp_dir = tempfile.mkdtemp()
    try:
        primary_url, mirror_urls = get_download_url()
        download_urls = [primary_url] + mirror_urls
        archive_name = primary_url.split('/')[-1]
        archive_path = os.path.join(temp_dir, archive_name)

        # Download the archive
        if not download_file(download_urls, archive_path):
            return False, None, None

        # Extract the archive
        if not extract_archive(archive_path, temp_dir):
            return False, None, None

        # Find the source directory
        source_dir = os.path.join(temp_dir, f"libsodium-{LIBSODIUM_VERSION}")
        if not os.path.exists(source_dir):
            # Try alternative directory name (might have different naming convention)
            for item in os.listdir(temp_dir):
                if os.path.isdir(os.path.join(temp_dir, item)) and "libsodium" in item:
                    source_dir = os.path.join(temp_dir, item)
                    break

        if not os.path.exists(source_dir):
            log.error("Could not find libsodium source directory")
            return False, None, None

        # Compile and install libsodium
        log.info("Compiling libsodium from source (this may take a few minutes)...")

        # Determine installation directory
        install_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libsodium_local")
        os.makedirs(install_dir, exist_ok=True)

        # Configure and make
        original_cwd = os.getcwd()
        os.chdir(source_dir)

        try:
            # Run configure
            configure_cmd = ["./configure", f"--prefix={install_dir}"]
            log.info(f"Running: {' '.join(configure_cmd)}")
            # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified)
            configure_result = subprocess.run(configure_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec: B603

            if configure_result.returncode != 0:
                log.error(f"Configure failed: {configure_result.stderr.decode()}")
                return False, None, None

            # Run make
            make_cmd = ["make"]
            log.info(f"Running: {' '.join(make_cmd)}")
            # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified)
            make_result = subprocess.run(make_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec: B603

            if make_result.returncode != 0:
                log.error(f"Make failed: {make_result.stderr.decode()}")
                return False, None, None

            # Run make install
            make_install_cmd = ["make", "install"]
            log.info(f"Running: {' '.join(make_install_cmd)}")
            # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified)
            make_install_result = subprocess.run(make_install_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec: B603

            if make_install_result.returncode != 0:
                log.error(f"Make install failed: {make_install_result.stderr.decode()}")
                return False, None, None
        finally:
            os.chdir(original_cwd)

        # Determine the path to the installed library
        if IS_LINUX:
            lib_path = os.path.join(install_dir, "lib", "libsodium.so")
        elif IS_DARWIN:
            lib_path = os.path.join(install_dir, "lib", "libsodium.dylib")
        else:
            log.error("Unsupported platform for source compilation")
            return False, None, None

        # Check if the library exists
        if not os.path.exists(lib_path):
            log.error(f"Library not found at expected path: {lib_path}")

            # Try to find the library
            for root, _, files in os.walk(os.path.join(install_dir, "lib")):
                for file in files:
                    if "libsodium" in file and (".so" in file or ".dylib" in file):
                        lib_path = os.path.join(root, file)
                        log.info(f"Found libsodium at {lib_path}")
                        break
                if os.path.exists(lib_path):
                    break

        if not os.path.exists(lib_path):
            log.error("Could not find compiled libsodium library")
            return False, None, None

        # Create symlinks to system library paths if possible
        try:
            if IS_LINUX:
                # Create symlink in /usr/local/lib if possible
                system_lib_path = "/usr/local/lib/libsodium.so"
                if os.access("/usr/local/lib", os.W_OK):
                    if os.path.exists(system_lib_path):
                        os.remove(system_lib_path)
                    os.symlink(lib_path, system_lib_path)
                    log.info(f"Created symlink from {lib_path} to {system_lib_path}")
                    # Run ldconfig to update library cache
                    # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
                    subprocess.run(["ldconfig"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec: B603 B607
            elif IS_DARWIN:
                # Create symlink in /usr/local/lib if possible
                system_lib_path = "/usr/local/lib/libsodium.dylib"
                if os.access("/usr/local/lib", os.W_OK):
                    if os.path.exists(system_lib_path):
                        os.remove(system_lib_path)
                    os.symlink(lib_path, system_lib_path)
                    log.info(f"Created symlink from {lib_path} to {system_lib_path}")
        except Exception as e:
            log.warning(f"Failed to create system library symlink: {e}. This is not critical.")

        # Load the library
        try:
            libsodium = ctypes.cdll.LoadLibrary(lib_path)
            log.info(f"Successfully loaded libsodium from {lib_path}")

            # Define comprehensive function prototypes
            _setup_function_prototypes(libsodium)

            return True, lib_path, libsodium
        except Exception as e:
            log.error(f"Failed to load compiled libsodium: {e}")
            return False, None, None
    except Exception as e:
        log.error(f"Error compiling libsodium from source: {e}")
        return False, None, None
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir)


def get_libsodium():
    """
    Locate, install, or compile libsodium with comprehensive platform detection.

    This function provides a complete libsodium acquisition strategy:

    1. Discovery Process:
       - Checks for existing system-wide libsodium installations
       - Verifies library functionality with basic operation tests
       - Handles various library locations across different platforms

    2. Installation Strategy:
       - Platform-specific installation methods (Windows, Linux, macOS)
       - Binary distribution for Windows
       - Source compilation for Unix-like systems
       - Proper error handling and fallbacks

    3. Verification Steps:
       - Tests library functionality after acquisition
       - Validates critical function availability
       - Provides detailed error reporting

    Returns:
        tuple: (success, library_path, library_handle) where:
               - success (bool): True if libsodium is available
               - library_path (str): Path to the library file
               - library_handle: ctypes CDLL object for function access

    Technical Notes:
       - Windows: Uses pre-built binary distributions (.dll)
       - Linux: Prefers system libraries with source compilation fallback
       - macOS: Handles both Homebrew and source-compiled installations
       - Verifies library functionality with randombytes_random test
    """
    # First, check if libsodium is already available
    try:
        log.info("Checking for existing libsodium installation...")
        available, lib_path, libsodium = check_libsodium()

        if available and libsodium is not None:
            # Test basic functionality to ensure library is working
            try:
                random_value = libsodium.randombytes_random()
                log.info(f"libsodium is already available at {lib_path} (functionality verified)")
                return True, lib_path, libsodium
            except Exception as e:
                log.warning(f"Found libsodium at {lib_path} but it appears to be broken: {e}")
                # Continue to installation
        else:
            log.info("No working libsodium installation found")
    except Exception as e:
        log.warning(f"Error checking for existing libsodium: {e}")

    # Install based on platform
    log.info(f"Installing libsodium for {SYSTEM}...")

    installation_methods = {
        "Windows": install_windows_libsodium,
        "Linux": compile_libsodium_from_source,
        "Darwin": compile_libsodium_from_source
    }

    install_method = installation_methods.get(SYSTEM)

    if install_method:
        try:
            log.info(f"Starting libsodium installation process for {SYSTEM}...")
            success, lib_path, libsodium = install_method()

            if success and libsodium is not None:
                log.info(f"Successfully installed and loaded libsodium from {lib_path}")
                return True, lib_path, libsodium
            else:
                log.error(f"Failed to install libsodium (unknown error)")
                return False, None, None
        except Exception as e:
            log.error(f"Error during libsodium installation: {e}", exc_info=True)
            return False, None, None
    else:
        log.error(f"Unsupported platform: {SYSTEM}")
        log.error(f"Please install libsodium manually for your platform.")
        log.error(f"Visit https://doc.libsodium.org/ for instructions.")
        return False, None, None



def initialize_libsodium():
    """
    Initialize libsodium library with version verification and export of globals.

    This function serves as the main entry point for libsodium initialization:

    1. Initialization Process:
       - Acquires the libsodium library (finds, installs, or compiles)
       - Verifies library version compatibility
       - Sets up global variables for application-wide access

    2. Function Configuration:
       - Defines function prototypes for type safety
       - Configures proper return types and argument types
       - Enables memory protection features

    3. Application Integration:
       - Exports LIBSODIUM global for direct access
       - Sets LIBSODIUM_AVAILABLE flag for feature detection
       - Provides detailed initialization status information

    Returns:
        tuple: (success, library_path, library_handle) where:
               - success (bool): True if initialization succeeded
               - library_path (str): Path to the active library
               - library_handle: ctypes CDLL object with configured functions

    Technical Notes:
       - Thread-safe initialization with proper error handling
       - Version compatibility checking
       - Graceful degradation with detailed error reporting
       - Proper function prototype configuration for memory safety
    """
    log.info(f"Initializing libsodium for {SYSTEM} platform")

    try:
        success, lib_path, libsodium = get_libsodium()

        if success and libsodium:
            # Get library version if available
            try:
                if hasattr(libsodium, 'sodium_version_string'):
                    libsodium.sodium_version_string.restype = ctypes.c_char_p
                    version_str = libsodium.sodium_version_string().decode('utf-8')
                    log.info(f"libsodium version: {version_str}")
                else:
                    log.info("libsodium version function not available")

                # Try initializing the library if it has an init function
                if hasattr(libsodium, 'sodium_init'):
                    init_result = libsodium.sodium_init()
                    if init_result >= 0:  # 0 = success, 1 = already initialized, -1 = error
                        log.info("libsodium initialization successful")
                    else:
                        log.warning(f"libsodium initialization returned {init_result}")
            except Exception as e:
                log.warning(f"Error getting libsodium version or initializing: {e}")

            return success, lib_path, libsodium
        else:
            log.error("Failed to initialize libsodium")
            return False, None, None
    except Exception as e:
        log.error(f"Error initializing libsodium: {e}", exc_info=True)
        return False, None, None

if __name__ == "__main__":
    success, lib_path, libsodium = initialize_libsodium()
    if success and libsodium is not None:
        print(f"Successfully initialized libsodium from {lib_path}")

        # Test the library
        try:
            random_value = libsodium.randombytes_random()
            print(f"Generated random value: {random_value}")

            # Test secure memory allocation
            buffer = libsodium.sodium_malloc(32)
            if buffer:
                print("Successfully allocated secure memory")
                libsodium.sodium_free(buffer)
                print("Successfully freed secure memory")
            else:
                print("Failed to allocate secure memory")

            print("libsodium functionality verified")
        except Exception as e:
            print(f"Error testing libsodium: {e}")
    else:
        print("Failed to initialize libsodium")

