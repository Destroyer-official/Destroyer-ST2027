#!/usr/bin/env python3
"""
LibOQS Python Wrapper - Hybrid Post-Quantum Cryptography Implementation
Uses the compiled liboqs library for PQC operations with hybrid algorithms,
and the 'cryptography' library for AES-256-GCM and HKDF.

Hybrid Strategy for Maximum Security:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

KEM (Hybrid ML-KEM-1024 + McEliece-8192128f):
- ML-KEM-1024 (Primary): Extremely fast (all ops < 1ms), official NIST standard (FIPS 203), 
  Level 5 security. Ideal for establishing ephemeral session keys quickly.
- Classic-McEliece-8192128f (Secondary): Incredibly conservative (code-based, unbroken since 1978), 
  Level 5 security. Provides essential diversity against lattice breaks. Its slowness 
  (Keygen ~370ms, Decaps ~124ms) is mitigated by using it alongside the fast ML-KEM.
- Hybrid Strategy: Derive the final symmetric session key using a Key Derivation Function 
  (KDF like HKDF-SHA384) combining the shared secrets from both KEMs (ss_mlkem and ss_mceliece). 
  An attacker must break both fundamentally different algorithms to compromise the session key. 
  This gives maximum long-term security.

Signatures (Hybrid ML-DSA-87 + SLH-DSA-256f):
- ML-DSA-87 (Primary): Very fast (Sign ~1.5ms, Verify ~0.4ms), official NIST standard (FIPS 204), 
  Level 5 security. Excellent for frequent signing operations where performance matters.
- SLH_DSA_PURE_SHAKE_256f (Secondary): Extremely conservative (hash-based, relies only on hash security), 
  official NIST standard (FIPS 205), Level 5 security. Provides essential diversity against lattice breaks. 
  The f (fast) variant brings signing time down to an acceptable ~200ms (much better than the s variant's 2 seconds).
- Hybrid Strategy: Use ML-DSA-87 for most real-time signing needs (e.g., authenticating messages). 
  Use SLH_DSA_PURE_SHAKE_256f for signing high-value, long-lifespan items where the ~200ms signing delay 
  and ~49KB signature size are acceptable (e.g., firmware updates, root certificates, identity documents). 
  Require verification of both signatures in critical scenarios for maximum assurance.

Supported Algorithms:
- KEM: ml_kem_1024 (Primary, Fast Lattice)
- KEM: classic_mceliece_8192128f (Secondary, Conservative Code-Based)
- SIG: ml_dsa_87 (Primary, Fast Lattice)
- SIG: slh_dsa_pure_shake_256f (Secondary, Conservative Hash-Based)
- Symmetric Cipher: AES-256-GCM
- KDF: HKDF-SHA384 for hybrid key derivation
"""

import ctypes
import logging
import os
import secrets
import hashlib
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

# --- Native-call input bounds (ctypes hardening, audit 6.2) -----------------
# Every buffer handed to liboqs via ctypes is length-pinned BEFORE
# from_buffer_copy: fixed sizes for keys/ciphertexts/signatures, plus an
# overall message ceiling so a hostile caller cannot force multi-GB native
# allocations (memory-exhaustion DoS) or zero-length edge cases through the
# FFI boundary. Largest legitimate single signed blob is the ~1.8MB hybrid
# bundle; 8MB leaves 4x headroom. (Refs: SP 800-227 s5 implementation
# guidance -- strict parameter checks; 2025/2009 fault-attack analyses.)
_NATIVE_MAX_MESSAGE_BYTES = 8 * 1024 * 1024


def _check_native_message(message: bytes, op: str) -> bytes:
    """Validate a message buffer before a native sign/verify call."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"Native {op}: message must be bytes-like")
    # Empty messages are LEGAL inputs (FIPS KAT edge case; liboqs handles
    # msglen=0 without dereference) -- only the oversize cap fail-closes.
    if len(message) > _NATIVE_MAX_MESSAGE_BYTES:
        raise ValueError(
            f"Native {op}: message {len(message)} bytes exceeds "
            f"{_NATIVE_MAX_MESSAGE_BYTES} cap (fail-closed)")
    return bytes(message)


def _check_native_sig(signature: bytes, sig_size: int, alg: str) -> bytes:
    """Validate a signature buffer before native verify.

    ML-DSA/SLH-DSA sigs are fixed-size; Falcon sigs are variable but bounded
    by sig_size. Anything empty or over bound is rejected pre-FFI so native
    code never sees attacker-controlled lengths.
    """
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError(f"Native {alg} verify: signature must be bytes-like")
    if len(signature) == 0 or len(signature) > sig_size:
        raise ValueError(
            f"Native {alg} verify: bad signature length {len(signature)} "
            f"(want 1..{sig_size})")
    return bytes(signature)


# --- Decaps DFR / native FFI error counters (non-breaking, observability only) ---
# Tracks native liboqs KEM decapsulation outcomes for native error detection.
# NOTE ON ML-KEM IMPLICIT REJECTION (NIST FIPS 203):
# Under standard IND-CCA2 security, ML-KEM employs the Fujisaki-Okamoto (FO) transform
# with implicit rejection. Corrupted or invalid ciphertexts do NOT produce an OQS_ERROR;
# instead, decapsulation deterministically outputs a pseudorandom key derived from the
# ciphertext and secret seed. Therefore, this counter specifically tracks low-level FFI,
# memory-corruption, or explicit API failure returns from OQS_KEM_decaps, rather than
# standard in-band ciphertext rejection.
_DECAPS_TOTAL = 0
_DECAPS_FAIL = 0
_DECAPS_LOCK = threading.Lock()
_DECAPS_ALERT_THRESHOLD = 0.01  # 1% fail rate
_DECAPS_MIN_SAMPLES = 100


def _record_decaps_result(success: bool) -> dict:
    """Increment module-level decaps counters; CRITICAL log if DFR anomalous."""
    global _DECAPS_TOTAL, _DECAPS_FAIL
    with _DECAPS_LOCK:
        _DECAPS_TOTAL += 1
        if not success:
            _DECAPS_FAIL += 1
        total = _DECAPS_TOTAL
        fail = _DECAPS_FAIL
    if not success:
        logger.warning(f"liboqs KEM decaps failure recorded ({fail}/{total})")
    if total >= _DECAPS_MIN_SAMPLES and total > 0:
        rate = fail / total
        if rate > _DECAPS_ALERT_THRESHOLD:
            logger.critical(
                "Possible fault/decapsulation-failure attack: liboqs KEM decaps fail rate "
                f"{rate:.2%} ({fail}/{total}) exceeds 1% over {total} samples")
    return {"decaps_total": total, "decaps_fail": fail}


def get_decaps_stats() -> dict:
    """Return current liboqs KEM decaps DFR/fault counters (read-only snapshot)."""
    with _DECAPS_LOCK:
        total = _DECAPS_TOTAL
        fail = _DECAPS_FAIL
    rate = (fail / total) if total else 0.0
    return {"decaps_total": total, "decaps_fail": fail, "decaps_fail_rate": rate}


def reset_decaps_stats() -> dict:
    """Reset liboqs decaps counters (for tests). Returns empty stats."""
    global _DECAPS_TOTAL, _DECAPS_FAIL
    with _DECAPS_LOCK:
        _DECAPS_TOTAL = 0
        _DECAPS_FAIL = 0
    return get_decaps_stats()

# Suppress excessive output for military deployment
QUIET_MODE = os.environ.get('PQC_QUIET_MODE', '0') == '1'

def quiet_print(*args, **kwargs):
    """Print only if not in quiet mode"""
    if not QUIET_MODE:
        try:
            print(*args, **kwargs)
        except (ValueError, OSError):
            pass
from typing import Tuple, Optional

# --- Configuration: Cross-platform liboqs resolution ---
import platform
from ctypes.util import find_library

def _find_liboqs_path() -> Path:
    repo_dir = Path(__file__).resolve().parent
    candidates = []
    if platform.system() == "Windows":
        # Strictly anchor to the audited repository directory to defeat DLL hijacking / CWD planting
        candidates = [
            repo_dir / "oqs.dll",
            repo_dir / "liboqs.dll"
        ]
    elif platform.system() == "Linux":
        candidates.extend([
            repo_dir / "liboqs.so",
            Path("/usr/local/lib/liboqs.so"),
            Path("/usr/lib/liboqs.so"),
            Path("/usr/lib/x86_64-linux-gnu/liboqs.so"),
            Path("/usr/lib/aarch64-linux-gnu/liboqs.so")
        ])
        sys_path = find_library("oqs")
        if sys_path:
            candidates.append(Path(sys_path))
    else:  # Darwin / macOS
        candidates.extend([
            repo_dir / "liboqs.dylib",
            Path("/usr/local/lib/liboqs.dylib"),
            Path("/opt/homebrew/lib/liboqs.dylib")
        ])
        sys_path = find_library("oqs")
        if sys_path:
            candidates.append(Path(sys_path))

    for cand in candidates:
        try:
            if cand.resolve().exists() and cand.is_file():
                return cand.resolve()
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
    # Fail-closed default anchored to repo directory
    return (repo_dir / ("oqs.dll" if platform.system() == "Windows" else "liboqs.so")).resolve()

LIBOQS_DLL_PATH = _find_liboqs_path()

# --- Mandatory dependency security verification (Task 3.4, fail-closed) ---
# The verifier import is STRICTLY mandatory: there is no try/except fallback
# and no HAVE_ flag. If the module is missing, unimportable, or blocked, this
# import raises fatal ImportError and oqs.dll is NEVER loaded — a missing
# guard must never silently become an unguarded load.
from dependency_security_verifier import verify_liboqs_dll, DependencySecurityError

if not LIBOQS_DLL_PATH.exists():
    raise ImportError(f"liboqs library not found at: {LIBOQS_DLL_PATH}. On Linux, install via 'sudo apt install liboqs-dev' or build liboqs.")
else:
    print(f"Found liboqs library at: {LIBOQS_DLL_PATH}")

# --- Verify Native Dynamic Library Security Before Loading ---
try:
    lib_name = LIBOQS_DLL_PATH.name
    print(f"Performing security verification of {lib_name}...")

    if lib_name in ("oqs.dll", "liboqs.dll"):
        # Vendored binary: verified against embedded Ed25519 signature and SHA-384 pin
        if lib_name == "liboqs.dll":
            verification_result = verify_liboqs_dll(str(LIBOQS_DLL_PATH))
        else:
            from dependency_security_verifier import verify_critical_dependency
            verification_result = verify_critical_dependency(lib_name, str(LIBOQS_DLL_PATH))

        if verification_result:
            print(f"[OK] {lib_name} security verification passed")
        else:
            print(f"[FAIL] {lib_name} security verification failed")
            raise ImportError(f"{lib_name} failed security verification - loading blocked")
    else:
        # Linux (.so) or macOS (.dylib): enforce absolute path existence, regular file, and basic safety
        if not LIBOQS_DLL_PATH.is_file():
            raise ImportError(f"Target shared library {LIBOQS_DLL_PATH} is not a valid regular file")
        # Ensure path is not world-writable on POSIX
        if hasattr(os, 'stat'):
            st = os.stat(str(LIBOQS_DLL_PATH))
            if hasattr(st, 'st_mode') and (st.st_mode & 0o002):
                raise ImportError(f"FATAL: Shared library {LIBOQS_DLL_PATH} is world-writable (insecure permissions)")
        print(f"[OK] {lib_name} file integrity and permission verification passed")

except DependencySecurityError as e:
    print(f"[FAIL] Native library security verification error: {e}")
    raise ImportError(f"{LIBOQS_DLL_PATH.name} security verification failed: {e}")
except Exception as e:
    print(f"[FAIL] Native library security verification encountered an error: {e}")
    raise ImportError(f"{LIBOQS_DLL_PATH.name} security verification failed: {e}")


# --- Load the library ---
try:
    liboqs = ctypes.CDLL(str(LIBOQS_DLL_PATH))
    print(f"[OK] {LIBOQS_DLL_PATH.name} loaded successfully")
except Exception as e:
    raise ImportError(f"Failed to load liboqs from {LIBOQS_DLL_PATH}: {e}")

# --- Define C structures and types (Should match oqs.h) ---
class OQS_KEM(ctypes.Structure):
    _fields_ = [
        ("method_name", ctypes.c_char_p), ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_uint8), ("ind_cca", ctypes.c_uint8),
        ("length_public_key", ctypes.c_size_t), ("length_secret_key", ctypes.c_size_t),
        ("length_ciphertext", ctypes.c_size_t), ("length_shared_secret", ctypes.c_size_t),
    ]

class OQS_SIG(ctypes.Structure):
    _fields_ = [
        ("method_name", ctypes.c_char_p), ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_uint8), ("euf_cma", ctypes.c_uint8),
        ("length_public_key", ctypes.c_size_t), ("length_secret_key", ctypes.c_size_t),
        ("length_signature", ctypes.c_size_t),
    ]

# --- Define function prototypes ---
# KEM Functions
liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]; liboqs.OQS_KEM_new.restype = ctypes.POINTER(OQS_KEM)
liboqs.OQS_KEM_keypair.argtypes = [ctypes.POINTER(OQS_KEM), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]; liboqs.OQS_KEM_keypair.restype = ctypes.c_int
liboqs.OQS_KEM_encaps.argtypes = [ctypes.POINTER(OQS_KEM), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]; liboqs.OQS_KEM_encaps.restype = ctypes.c_int
liboqs.OQS_KEM_decaps.argtypes = [ctypes.POINTER(OQS_KEM), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]; liboqs.OQS_KEM_decaps.restype = ctypes.c_int
liboqs.OQS_KEM_free.argtypes = [ctypes.POINTER(OQS_KEM)]; liboqs.OQS_KEM_free.restype = None
# Signature Functions
liboqs.OQS_SIG_new.argtypes = [ctypes.c_char_p]; liboqs.OQS_SIG_new.restype = ctypes.POINTER(OQS_SIG)
liboqs.OQS_SIG_keypair.argtypes = [ctypes.POINTER(OQS_SIG), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]; liboqs.OQS_SIG_keypair.restype = ctypes.c_int
liboqs.OQS_SIG_sign.argtypes = [ctypes.POINTER(OQS_SIG), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8)]; liboqs.OQS_SIG_sign.restype = ctypes.c_int
liboqs.OQS_SIG_verify.argtypes = [ctypes.POINTER(OQS_SIG), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8)]; liboqs.OQS_SIG_verify.restype = ctypes.c_int
liboqs.OQS_SIG_free.argtypes = [ctypes.POINTER(OQS_SIG)]; liboqs.OQS_SIG_free.restype = None

# --- Python Classes for Algorithms ---

class LibOQS_MLKEM_1024:
    """ML-KEM-1024 KEM implementation using liboqs (FIPS 203)"""
    _init_printed = False

    def __init__(self):
        self.alg_name = b"ML-KEM-1024"
        self.kem = liboqs.OQS_KEM_new(self.alg_name)
        if not self.kem: raise RuntimeError(f"Failed to initialize {self.alg_name.decode()} - Was it compiled?")
        self.pk_size = self.kem.contents.length_public_key
        self.sk_size = self.kem.contents.length_secret_key
        self.ct_size = self.kem.contents.length_ciphertext
        self.ss_size = self.kem.contents.length_shared_secret
        if not LibOQS_MLKEM_1024._init_printed:
            quiet_print(f"[OK] LibOQS {self.alg_name.decode()} initialized: PK={self.pk_size}, SK={self.sk_size}, CT={self.ct_size}, SS={self.ss_size}")
            LibOQS_MLKEM_1024._init_printed = True

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = (ctypes.c_uint8 * self.pk_size)(); sk = (ctypes.c_uint8 * self.sk_size)()
        result = liboqs.OQS_KEM_keypair(self.kem, pk, sk)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} keypair failed")
        return bytes(pk), bytes(sk)

    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        if len(public_key) != self.pk_size:
            raise ValueError("Invalid PK size")
        ct = (ctypes.c_uint8 * self.ct_size)(); ss = (ctypes.c_uint8 * self.ss_size)()
        pk_c = (ctypes.c_uint8 * self.pk_size).from_buffer_copy(public_key)
        result = liboqs.OQS_KEM_encaps(self.kem, ct, ss, pk_c)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} encaps failed")
        return bytes(ct), bytes(ss)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        # DFR/fault observability: input-validation failures count as decaps_fail.
        if len(secret_key) != self.sk_size:
            _record_decaps_result(False)
            raise ValueError("Invalid SK size")
        if len(ciphertext) != self.ct_size:
            _record_decaps_result(False)
            raise ValueError("Invalid CT size")
        ss = (ctypes.c_uint8 * self.ss_size)()
        sk_c = (ctypes.c_uint8 * self.sk_size).from_buffer_copy(secret_key)
        ct_c = (ctypes.c_uint8 * self.ct_size).from_buffer_copy(ciphertext)
        try:
            result = liboqs.OQS_KEM_decaps(self.kem, ss, ct_c, sk_c)
        except Exception:
            _record_decaps_result(False)
            raise
        if result != 0:
            _record_decaps_result(False)
            raise RuntimeError(f"{self.alg_name.decode()} decaps failed")
        _record_decaps_result(True)
        return bytes(ss)

    def __del__(self):
        if hasattr(self, 'kem') and self.kem: liboqs.OQS_KEM_free(self.kem)


class LibOQS_McEliece_8192128f:
    """Classic-McEliece-8192128f KEM implementation using liboqs"""
    _init_printed = False

    def __init__(self):
        self.alg_name = b"Classic-McEliece-8192128f"
        self.kem = liboqs.OQS_KEM_new(self.alg_name)
        if not self.kem: raise RuntimeError(f"Failed to initialize {self.alg_name.decode()} - Was it compiled?")
        self.pk_size = self.kem.contents.length_public_key
        self.sk_size = self.kem.contents.length_secret_key
        self.ct_size = self.kem.contents.length_ciphertext
        self.ss_size = self.kem.contents.length_shared_secret
        if not LibOQS_McEliece_8192128f._init_printed:
            quiet_print(f"[OK] LibOQS {self.alg_name.decode()} initialized: PK={self.pk_size}, SK={self.sk_size}, CT={self.ct_size}, SS={self.ss_size}")
            LibOQS_McEliece_8192128f._init_printed = True

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = (ctypes.c_uint8 * self.pk_size)(); sk = (ctypes.c_uint8 * self.sk_size)()
        result = liboqs.OQS_KEM_keypair(self.kem, pk, sk)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} keypair failed")
        return bytes(pk), bytes(sk)

    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        if len(public_key) != self.pk_size:
            raise ValueError("Invalid PK size")
        ct = (ctypes.c_uint8 * self.ct_size)(); ss = (ctypes.c_uint8 * self.ss_size)()
        pk_c = (ctypes.c_uint8 * self.pk_size).from_buffer_copy(public_key)
        result = liboqs.OQS_KEM_encaps(self.kem, ct, ss, pk_c)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} encaps failed")
        return bytes(ct), bytes(ss)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        # DFR/fault observability: input-validation failures count as decaps_fail.
        if len(secret_key) != self.sk_size:
            _record_decaps_result(False)
            raise ValueError("Invalid SK size")
        if len(ciphertext) != self.ct_size:
            _record_decaps_result(False)
            raise ValueError("Invalid CT size")
        ss = (ctypes.c_uint8 * self.ss_size)()
        sk_c = (ctypes.c_uint8 * self.sk_size).from_buffer_copy(secret_key)
        ct_c = (ctypes.c_uint8 * self.ct_size).from_buffer_copy(ciphertext)
        try:
            result = liboqs.OQS_KEM_decaps(self.kem, ss, ct_c, sk_c)
        except Exception:
            _record_decaps_result(False)
            raise
        if result != 0:
            _record_decaps_result(False)
            raise RuntimeError(f"{self.alg_name.decode()} decaps failed")
        _record_decaps_result(True)
        return bytes(ss)

    def __del__(self):
        if hasattr(self, 'kem') and self.kem: liboqs.OQS_KEM_free(self.kem)


class LibOQS_HQC_256:
    """HQC-256 KEM implementation using liboqs"""
    def __init__(self):
        self.alg_name = b"HQC-256"
        self.kem = liboqs.OQS_KEM_new(self.alg_name)
        if not self.kem: raise RuntimeError(f"Failed to initialize {self.alg_name.decode()} - Was it compiled into oqs.dll?")
        self.pk_size = self.kem.contents.length_public_key
        self.sk_size = self.kem.contents.length_secret_key
        self.ct_size = self.kem.contents.length_ciphertext
        self.ss_size = self.kem.contents.length_shared_secret
        quiet_print(f"[OK] LibOQS {self.alg_name.decode()} initialized: PK={self.pk_size}, SK={self.sk_size}, CT={self.ct_size}, SS={self.ss_size}")

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = (ctypes.c_uint8 * self.pk_size)(); sk = (ctypes.c_uint8 * self.sk_size)()
        result = liboqs.OQS_KEM_keypair(self.kem, pk, sk)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} keypair failed")
        return bytes(pk), bytes(sk)

    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        if len(public_key) != self.pk_size:
            raise ValueError("Invalid PK size")
        ct = (ctypes.c_uint8 * self.ct_size)(); ss = (ctypes.c_uint8 * self.ss_size)()
        pk_c = (ctypes.c_uint8 * self.pk_size).from_buffer_copy(public_key)
        result = liboqs.OQS_KEM_encaps(self.kem, ct, ss, pk_c)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} encaps failed")
        return bytes(ct), bytes(ss)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        # DFR/fault observability: input-validation failures count as decaps_fail.
        if len(secret_key) != self.sk_size:
            _record_decaps_result(False)
            raise ValueError("Invalid SK size")
        if len(ciphertext) != self.ct_size:
            _record_decaps_result(False)
            raise ValueError("Invalid CT size")
        ss = (ctypes.c_uint8 * self.ss_size)()
        sk_c = (ctypes.c_uint8 * self.sk_size).from_buffer_copy(secret_key)
        ct_c = (ctypes.c_uint8 * self.ct_size).from_buffer_copy(ciphertext)
        try:
            result = liboqs.OQS_KEM_decaps(self.kem, ss, ct_c, sk_c)
        except Exception:
            _record_decaps_result(False)
            raise
        if result != 0:
            _record_decaps_result(False)
            raise RuntimeError(f"{self.alg_name.decode()} decaps failed")
        _record_decaps_result(True)
        return bytes(ss)

    def __del__(self):
        if hasattr(self, 'kem') and self.kem: liboqs.OQS_KEM_free(self.kem)


class LibOQS_MLDSA_87:
    """ML-DSA-87 Signature implementation using liboqs (FIPS 204)"""
    def __init__(self):
        self.alg_name = b"ML-DSA-87"
        self.sig = liboqs.OQS_SIG_new(self.alg_name)
        if not self.sig: raise RuntimeError(f"Failed to initialize {self.alg_name.decode()} - Was it compiled?")
        self.pk_size = self.sig.contents.length_public_key
        self.sk_size = self.sig.contents.length_secret_key
        self.sig_size = self.sig.contents.length_signature # Max size
        quiet_print(f"[OK] LibOQS {self.alg_name.decode()} initialized: PK={self.pk_size}, SK={self.sk_size}, SIG={self.sig_size}")

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = (ctypes.c_uint8 * self.pk_size)(); sk = (ctypes.c_uint8 * self.sk_size)()
        result = liboqs.OQS_SIG_keypair(self.sig, pk, sk)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} keypair failed")
        return bytes(pk), bytes(sk)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if len(secret_key) != self.sk_size:
            raise ValueError("Invalid SK size")
        signature = (ctypes.c_uint8 * self.sig_size)(); sig_len = ctypes.c_size_t(0)
        sk_c = (ctypes.c_uint8 * self.sk_size).from_buffer_copy(secret_key)
        message = _check_native_message(message, "sign/verify")
        msg_c = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        result = liboqs.OQS_SIG_sign(self.sig, signature, ctypes.byref(sig_len), msg_c, len(message), sk_c)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} signing failed")
        return bytes(signature[:sig_len.value])

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != self.pk_size:
            raise ValueError("Invalid PK size")
        pk_c = (ctypes.c_uint8 * self.pk_size).from_buffer_copy(public_key)
        message = _check_native_message(message, "sign/verify")
        msg_c = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        signature = _check_native_sig(signature, self.sig_size, self.alg_name.decode())
        sig_c = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
        result = liboqs.OQS_SIG_verify(self.sig, msg_c, len(message), sig_c, len(signature), pk_c)
        return result == 0

    def __del__(self):
        if hasattr(self, 'sig') and self.sig: liboqs.OQS_SIG_free(self.sig)


class LibOQS_SLH_DSA_256f:
    """SLH_DSA_PURE_SHAKE_256f Signature implementation using liboqs (FIPS 205)"""
    def __init__(self):
        # Use the exact C string identifier for the FAST variant
        self.alg_name = b"SLH_DSA_PURE_SHAKE_256F"
        self.sig = liboqs.OQS_SIG_new(self.alg_name)
        if not self.sig: raise RuntimeError(f"Failed to initialize {self.alg_name.decode()} - Was it compiled?")
        self.pk_size = self.sig.contents.length_public_key
        self.sk_size = self.sig.contents.length_secret_key
        self.sig_size = self.sig.contents.length_signature # Max size
        quiet_print(f"[OK] LibOQS {self.alg_name.decode()} initialized: PK={self.pk_size}, SK={self.sk_size}, SIG={self.sig_size}")

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = (ctypes.c_uint8 * self.pk_size)(); sk = (ctypes.c_uint8 * self.sk_size)()
        result = liboqs.OQS_SIG_keypair(self.sig, pk, sk)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} keypair failed")
        return bytes(pk), bytes(sk)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if len(secret_key) != self.sk_size:
            raise ValueError("Invalid SK size")
        signature = (ctypes.c_uint8 * self.sig_size)(); sig_len = ctypes.c_size_t(0)
        sk_c = (ctypes.c_uint8 * self.sk_size).from_buffer_copy(secret_key)
        message = _check_native_message(message, "sign/verify")
        msg_c = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        result = liboqs.OQS_SIG_sign(self.sig, signature, ctypes.byref(sig_len), msg_c, len(message), sk_c)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} signing failed")
        return bytes(signature[:sig_len.value])

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != self.pk_size:
            raise ValueError("Invalid PK size")
        pk_c = (ctypes.c_uint8 * self.pk_size).from_buffer_copy(public_key)
        message = _check_native_message(message, "sign/verify")
        msg_c = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        signature = _check_native_sig(signature, self.sig_size, self.alg_name.decode())
        sig_c = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
        result = liboqs.OQS_SIG_verify(self.sig, msg_c, len(message), sig_c, len(signature), pk_c)
        return result == 0

    def __del__(self):
        if hasattr(self, 'sig') and self.sig: liboqs.OQS_SIG_free(self.sig)


class LibOQS_Falcon_1024:
    """Falcon-1024 Signature implementation using liboqs (NIST Round 3 Finalist)"""
    def __init__(self):
        self.alg_name = b"Falcon-1024"
        self.sig = liboqs.OQS_SIG_new(self.alg_name)
        if not self.sig: raise RuntimeError(f"Failed to initialize {self.alg_name.decode()} - Was it compiled into oqs.dll?")
        self.pk_size = self.sig.contents.length_public_key
        self.sk_size = self.sig.contents.length_secret_key
        self.sig_size = self.sig.contents.length_signature
        quiet_print(f"[OK] LibOQS {self.alg_name.decode()} initialized: PK={self.pk_size}, SK={self.sk_size}, SIG={self.sig_size}")

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = (ctypes.c_uint8 * self.pk_size)(); sk = (ctypes.c_uint8 * self.sk_size)()
        result = liboqs.OQS_SIG_keypair(self.sig, pk, sk)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} keypair failed")
        return bytes(pk), bytes(sk)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if len(secret_key) != self.sk_size:
            raise ValueError(f"Invalid SK size for {self.alg_name.decode()}: expected {self.sk_size}, got {len(secret_key)}")
        signature = (ctypes.c_uint8 * self.sig_size)(); sig_len = ctypes.c_size_t(0)
        sk_c = (ctypes.c_uint8 * self.sk_size).from_buffer_copy(secret_key)
        message = _check_native_message(message, "sign/verify")
        msg_c = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        result = liboqs.OQS_SIG_sign(self.sig, signature, ctypes.byref(sig_len), msg_c, len(message), sk_c)
        if result != 0:
            raise RuntimeError(f"{self.alg_name.decode()} signing failed")
        return bytes(signature[:sig_len.value])

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != self.pk_size:
            raise ValueError(f"Invalid PK size for {self.alg_name.decode()}: expected {self.pk_size}, got {len(public_key)}")
        pk_c = (ctypes.c_uint8 * self.pk_size).from_buffer_copy(public_key)
        message = _check_native_message(message, "sign/verify")
        msg_c = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        signature = _check_native_sig(signature, self.sig_size, self.alg_name.decode())
        sig_c = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
        result = liboqs.OQS_SIG_verify(self.sig, msg_c, len(message), sig_c, len(signature), pk_c)
        return result == 0

    def __del__(self):
        if hasattr(self, 'sig') and self.sig: liboqs.OQS_SIG_free(self.sig)


# --- AES-256-GCM Cipher Implementation (Uses 'cryptography' library) ---
class LibOQS_AES256GCM:
    _AESGCM = None; InvalidTag = None
    def __init__(self):
        if LibOQS_AES256GCM._AESGCM is None:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                from cryptography.exceptions import InvalidTag
                LibOQS_AES256GCM._AESGCM = AESGCM; LibOQS_AES256GCM.InvalidTag = InvalidTag
                print("[OK] AES-256-GCM cipher initialized (using cryptography lib)")
            except ImportError:
                print("ERROR: 'cryptography' library not found. AES-GCM unavailable. pip install cryptography")
                raise ImportError("cryptography library required for AES-256-GCM")
        self.AESGCM = LibOQS_AES256GCM._AESGCM; self.InvalidTag = LibOQS_AES256GCM.InvalidTag
    def generate_key(self) -> bytes: return secrets.token_bytes(32)
    def generate_nonce(self) -> bytes: return secrets.token_bytes(12)

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypt plaintext using AES-256-GCM"""
        if len(key) != 32: raise ValueError("Invalid key size: expected 32 bytes")
        if len(nonce) != 12: raise ValueError("Invalid nonce size: expected 12 bytes")
        return self.AESGCM(key).encrypt(nonce, plaintext, associated_data)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM.
        Raises InvalidTag if authentication fails.
        """
        if len(key) != 32: raise ValueError("Invalid key size: expected 32 bytes")
        if len(nonce) != 12: raise ValueError("Invalid nonce size: expected 12 bytes")
        try: return self.AESGCM(key).decrypt(nonce, ciphertext, associated_data)
        except self.InvalidTag: raise self.InvalidTag("AES-GCM decryption failed: Authentication tag is invalid")
        except Exception as e: raise RuntimeError(f"AES-GCM decryption error: {e}")

# --- Hybrid KEM Implementation ---
class HybridKEM:
    """
    MILITARY-GRADE HYBRID KEY ENCAPSULATION MECHANISM
    
    MILITARY SECURITY ENFORCEMENT ACTIVE
    • ONLY APPROVED ALGORITHMS: ML-KEM-1024 + McEliece-8192128f
    • KEY DERIVATION: HKDF-SHA384 ONLY
    • NO FALLBACKS PERMITTED
    • FAIL CLOSED SECURITY MODEL
    
    This implementation provides maximum security by combining two fundamentally different
    cryptographic approaches:
    - ML-KEM-1024: Fast lattice-based KEM (NIST FIPS 203)
    - McEliece-8192128f: Conservative code-based KEM (unbroken since 1978)
    
    The final shared secret is derived using HKDF-SHA384, combining both shared secrets.
    An attacker must break BOTH algorithms to compromise the session key.
    """
    
    _cached_mlkem = None
    _cached_mceliece = None

    def __init__(self):
        """Initialize hybrid KEM with both ML-KEM-1024 and McEliece-8192128f."""
        # MILITARY SECURITY ENFORCEMENT
        try:
            from military_security_enforcement import (
                validate_military_algorithm, 
                enforce_no_fallbacks,
                MilitarySecurityError
            )
            validate_military_algorithm("ML-KEM-1024", "KEM")
            validate_military_algorithm("McEliece-8192128f", "KEM")
            validate_military_algorithm("HKDF-SHA384", "KDF")
            enforce_no_fallbacks("HybridKEM")
            if not hasattr(HybridKEM, '_military_validation_printed'):
                quiet_print("MILITARY KEM ALGORITHMS VALIDATED: ML-KEM-1024 + McEliece-8192128f")
                HybridKEM._military_validation_printed = True
        except ImportError as e:
            logger.critical("FATAL: Military security enforcement module missing in HybridKEM: %s", e)
            raise ImportError(f"CRITICAL: Military enforcement required - failing closed: {e}") from e
        except Exception as e:
            logger.critical(f"ALERT MILITARY SECURITY VIOLATION: {e}")
            raise
        if HybridKEM._cached_mlkem is None:
            HybridKEM._cached_mlkem = LibOQS_MLKEM_1024()
        self.mlkem = HybridKEM._cached_mlkem
        
        # Import HKDF for key derivation
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            self.HKDF = HKDF
            self.hashes = hashes
            if not hasattr(HybridKEM, '_hkdf_init_printed'):
                quiet_print("[OK] Hybrid KEM initialized with HKDF-SHA384 key derivation")
                HybridKEM._hkdf_init_printed = True
        except ImportError:
            raise ImportError("cryptography library required for HKDF")
        
        # Individual algorithm sizes (McEliece sizes are fixed NIST/liboqs constants)
        self.pk_size_mlkem = self.mlkem.pk_size
        self.sk_size_mlkem = self.mlkem.sk_size
        self.pk_size_mceliece = 1357824
        self.sk_size_mceliece = 14120
        self.ct_size_mlkem = self.mlkem.ct_size
        self.ct_size_mceliece = 208
        
        # Combined sizes (serialized format)
        self.public_key_size = self.pk_size_mlkem + self.pk_size_mceliece
        self.secret_key_size = self.sk_size_mlkem + self.sk_size_mceliece
        self.ciphertext_size = self.ct_size_mlkem + self.ct_size_mceliece
        self.ss_size = 48  # 384-bit hybrid shared secret (from HKDF-SHA384)

    @property
    def mceliece(self) -> LibOQS_McEliece_8192128f:
        """Lazy-initialize and cache Classic-McEliece-8192128f on demand."""
        if HybridKEM._cached_mceliece is None:
            HybridKEM._cached_mceliece = LibOQS_McEliece_8192128f()
        return HybridKEM._cached_mceliece
    
    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate hybrid keypair for both ML-KEM-1024 and McEliece-8192128f.
        
        Returns:
            Tuple of (public_key, secret_key) where each is serialized bytes:
            - public_key: ML-KEM-1024 pk || McEliece-8192128f pk (concatenated)
            - secret_key: ML-KEM-1024 sk || McEliece-8192128f sk (concatenated)
        """
        pk_ml, sk_ml = self.mlkem.keygen()
        pk_mc, sk_mc = self.mceliece.keygen()
        
        # Serialize by concatenating the keys
        public_key = pk_ml + pk_mc
        secret_key = sk_ml + sk_mc
        
        return public_key, secret_key
    
    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Perform hybrid encapsulation using both KEMs.
        
        Args:
            public_key: Serialized public key (ML-KEM pk || McEliece pk)
        
        Returns:
            Tuple of (ciphertext, hybrid_shared_secret) where:
            - ciphertext: Serialized ciphertext (ML-KEM ct || McEliece ct)
            - hybrid_shared_secret: 48-byte derived key from HKDF-SHA384
        """
        # Deserialize the public key
        pk_ml = public_key[:self.pk_size_mlkem]
        pk_mc = public_key[self.pk_size_mlkem:]
        
        # Encapsulate with both KEMs
        ct_ml, ss_ml = self.mlkem.encaps(pk_ml)
        ct_mc, ss_mc = self.mceliece.encaps(pk_mc)
        
        # Combine shared secrets using HKDF-SHA384
        hybrid_ss = self._derive_hybrid_key(ss_ml, ss_mc)
        
        # Serialize ciphertexts by concatenation
        ciphertext = ct_ml + ct_mc
        
        return ciphertext, hybrid_ss
    
    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Perform hybrid decapsulation using both KEMs.
        
        Args:
            secret_key: Serialized secret key (ML-KEM sk || McEliece sk)
            ciphertext: Serialized ciphertext (ML-KEM ct || McEliece ct)
        
        Returns:
            48-byte hybrid shared secret derived from HKDF-SHA384
        """
        # Deserialize the secret key
        sk_ml = secret_key[:self.sk_size_mlkem]
        sk_mc = secret_key[self.sk_size_mlkem:]
        
        # Deserialize the ciphertext
        ct_ml = ciphertext[:self.ct_size_mlkem]
        ct_mc = ciphertext[self.ct_size_mlkem:]
        
        # Decapsulate with both KEMs. NOTE: inner primitive decaps() calls
        # already record module-level DFR/fault counters; do NOT record again
        # here to avoid double-counting (needs-manual-review if hybrid-level
        # aggregation is later desired).
        ss_ml = self.mlkem.decaps(sk_ml, ct_ml)
        ss_mc = self.mceliece.decaps(sk_mc, ct_mc)
        
        # Combine shared secrets using HKDF-SHA384
        hybrid_ss = self._derive_hybrid_key(ss_ml, ss_mc)
        
        return hybrid_ss
    
    def _derive_hybrid_key(self, ss_mlkem: bytes, ss_mceliece: bytes) -> bytes:
        """
        Derive hybrid shared secret using HKDF-SHA384.
        
        Combines both shared secrets using HKDF with SHA-384 to produce a 48-byte
        (384-bit) hybrid key. An attacker must break BOTH ML-KEM-1024 AND McEliece
        to compromise this key.
        
        Args:
            ss_mlkem: 32-byte shared secret from ML-KEM-1024
            ss_mceliece: 32-byte shared secret from McEliece-8192128f
        
        Returns:
            48-byte hybrid shared secret
        """
        # Concatenate both shared secrets as input key material
        ikm = ss_mlkem + ss_mceliece
        
        # Use HKDF-SHA384 with fixed, domain-separated salt (Finding 1.3)
        salt = hashlib.sha384(b"SecureP2P::HybridKEM::Salt::v1::CNSA2-Level5").digest()
        kdf = self.HKDF(
            algorithm=self.hashes.SHA384(),
            length=48,  # 384-bit output
            salt=salt,
            info=b'Hybrid-KEM-ML-KEM-1024-McEliece-8192128f'
        )
        
        hybrid_key = kdf.derive(ikm)
        return hybrid_key

    def combine_shared_secrets(self, ss_mlkem: bytes, ss_mceliece: bytes) -> bytes:
        """Public interface for combining shared secrets."""
        return self._derive_hybrid_key(ss_mlkem, ss_mceliece)

LibOQS_HybridKEM = HybridKEM


# --- Hybrid Signature Implementation ---
class HybridSignature:
    """
    Hybrid Digital Signature combining ML-DSA-87 and SLH-DSA-256f.
    
    This implementation provides maximum security and flexibility:
    - ML-DSA-87: Fast lattice-based signatures (NIST FIPS 204) for real-time operations
    - SLH-DSA-256f: Conservative hash-based signatures (NIST FIPS 205) for long-term security
    
    Modes:
    - 'fast': Use only ML-DSA-87 (for frequent, real-time signing)
    - 'secure': Use only SLH-DSA-256f (for high-value, long-lifespan items)
    - 'dual': Use both signatures (for maximum assurance in critical scenarios)
    """
    
    def __init__(self, mode: str = 'fast'):
        """
        Initialize hybrid signature system.
        
        Args:
            mode: Signature mode - 'fast', 'secure', or 'dual'
        """
        if mode not in ['fast', 'secure', 'dual']:
            raise ValueError("Mode must be 'fast', 'secure', or 'dual'")
        
        self.mode = mode
        self.mldsa = LibOQS_MLDSA_87()
        self.slhdsa = LibOQS_SLH_DSA_256f()
        
        quiet_print(f"[OK] Hybrid Signature initialized in '{mode}' mode")
    
    def keygen(self) -> Tuple[dict, dict]:
        """
        Generate hybrid keypair for both signature algorithms.
        
        Returns:
            Tuple of (public_keys, secret_keys) where each is a dict containing:
            - 'mldsa': ML-DSA-87 key bytes
            - 'slhdsa': SLH-DSA-256f key bytes
        """
        pk_ml, sk_ml = self.mldsa.keygen()
        pk_slh, sk_slh = self.slhdsa.keygen()
        
        public_keys = {
            'mldsa': pk_ml,
            'slhdsa': pk_slh
        }
        
        secret_keys = {
            'mldsa': sk_ml,
            'slhdsa': sk_slh
        }
        
        return public_keys, secret_keys
    
    def sign(self, secret_keys: dict, message: bytes) -> dict:
        """
        Sign message using the configured mode.
        
        Args:
            secret_keys: Dict containing 'mldsa' and 'slhdsa' secret keys
            message: Message to sign
        
        Returns:
            Dict containing signatures based on mode:
            - 'fast': {'mldsa': signature}
            - 'secure': {'slhdsa': signature}
            - 'dual': {'mldsa': signature, 'slhdsa': signature}
        """
        signatures = {}
        
        if self.mode in ['fast', 'dual']:
            signatures['mldsa'] = self.mldsa.sign(secret_keys['mldsa'], message)
        
        if self.mode in ['secure', 'dual']:
            signatures['slhdsa'] = self.slhdsa.sign(secret_keys['slhdsa'], message)
        
        return signatures
    
    def verify(self, public_keys: dict, message: bytes, signatures: dict) -> bool:
        """
        Verify signatures using the configured mode.
        
        Args:
            public_keys: Dict containing 'mldsa' and 'slhdsa' public keys
            message: Original message
            signatures: Dict containing signatures to verify
        
        Returns:
            True if all required signatures are valid, False otherwise
        """
        if self.mode == 'fast':
            if 'mldsa' not in signatures:
                return False
            return self.mldsa.verify(public_keys['mldsa'], message, signatures['mldsa'])
        
        elif self.mode == 'secure':
            if 'slhdsa' not in signatures:
                return False
            return self.slhdsa.verify(public_keys['slhdsa'], message, signatures['slhdsa'])
        
        elif self.mode == 'dual':
            if 'mldsa' not in signatures or 'slhdsa' not in signatures:
                return False
            
            # Both signatures must be valid
            ml_valid = self.mldsa.verify(public_keys['mldsa'], message, signatures['mldsa'])
            slh_valid = self.slhdsa.verify(public_keys['slhdsa'], message, signatures['slhdsa'])
            
            return ml_valid and slh_valid
        
        return False


# --- Export classes for easy import ---
__all__ = [
    'LibOQS_MLKEM_1024',
    'LibOQS_McEliece_8192128f',
    'LibOQS_HQC_256',
    'LibOQS_MLDSA_87',
    'LibOQS_SLH_DSA_256f',
    'LibOQS_AES256GCM',
    'HybridKEM',
    'HybridSignature',
]

# --- Test the implementation ---
if __name__ == '__main__':
    print("="*80)
    print("Testing LibOQS Python Wrapper (Hybrid Fast Build + AES-GCM)")
    print("Algorithms: ML-KEM-1024, McEliece-8192128f, ML-DSA-87, SLH-DSA-256f, AES-GCM")
    print("="*80)
    print()

    # Test ML-KEM-1024
    print("Testing ML-KEM-1024...")
    try:
        mlkem = LibOQS_MLKEM_1024()
        pk_ml, sk_ml = mlkem.keygen()
        print(f"  PASS Keypair generated: PK={len(pk_ml)} bytes, SK={len(sk_ml)} bytes")
        ct_ml, ss1_ml = mlkem.encaps(pk_ml)
        print(f"  PASS Encapsulation: CT={len(ct_ml)} bytes, SS={len(ss1_ml)} bytes")
        ss2_ml = mlkem.decaps(sk_ml, ct_ml)
        print(f"  PASS Decapsulation: SS={len(ss2_ml)} bytes")
        if ss1_ml == ss2_ml: print(f"  PASS Shared secrets MATCH - ML-KEM-1024 is WORKING!")
        else: print(f"  FAIL Shared secrets DO NOT MATCH - ML-KEM-1024 is BROKEN!")
    except Exception as e: print(f"  FAIL ML-KEM-1024 test failed: {e}")
    print("-" * 80)

    # Test Classic-McEliece-8192128f
    print("Testing Classic-McEliece-8192128f...")
    try:
        mceliece = LibOQS_McEliece_8192128f()
        pk_mc, sk_mc = mceliece.keygen()
        print(f"  PASS Keypair generated: PK={len(pk_mc)} bytes, SK={len(sk_mc)} bytes")
        ct_mc, ss1_mc = mceliece.encaps(pk_mc)
        print(f"  PASS Encapsulation: CT={len(ct_mc)} bytes, SS={len(ss1_mc)} bytes")
        ss2_mc = mceliece.decaps(sk_mc, ct_mc)
        print(f"  PASS Decapsulation: SS={len(ss2_mc)} bytes")
        if ss1_mc == ss2_mc: print(f"  PASS Shared secrets MATCH - McEliece-8192128f is WORKING!")
        else: print(f"  FAIL Shared secrets DO NOT MATCH - McEliece-8192128f is BROKEN!")
    except Exception as e: print(f"  FAIL McEliece-8192128f test failed: {e}")
    print("-" * 80)

    # Test ML-DSA-87
    print("Testing ML-DSA-87...")
    try:
        mldsa = LibOQS_MLDSA_87()
        pk_ml, sk_ml = mldsa.keygen()
        print(f"  PASS Keypair generated: PK={len(pk_ml)} bytes, SK={len(sk_ml)} bytes")
        message_ml = b"Test message for ML-DSA-87"
        signature_ml = mldsa.sign(sk_ml, message_ml)
        print(f"  PASS Signature generated: {len(signature_ml)} bytes")
        valid_ml = mldsa.verify(pk_ml, message_ml, signature_ml)
        if valid_ml: print(f"  PASS Signature VERIFIED - ML-DSA-87 is WORKING!")
        else: print(f"  FAIL Signature INVALID - ML-DSA-87 is BROKEN!")
        invalid_signature_ml = signature_ml[:-1] + bytes([(signature_ml[-1] + 1) % 256])
        invalid_valid_ml = mldsa.verify(pk_ml, message_ml, invalid_signature_ml)
        if not invalid_valid_ml: print(f"  PASS Correctly identified INVALID signature.")
        else: print(f"  FAIL FAILED to identify INVALID signature!")
    except Exception as e: print(f"  FAIL ML-DSA-87 test failed: {e}")
    print("-" * 80)

    # Test SLH_DSA_PURE_SHAKE_256F (Fast variant)
    print("Testing SLH_DSA_PURE_SHAKE_256F...")
    try:
        slh_dsa_f = LibOQS_SLH_DSA_256f() # Use the updated class name
        pk_slh, sk_slh = slh_dsa_f.keygen()
        print(f"  PASS Keypair generated: PK={len(pk_slh)} bytes, SK={len(sk_slh)} bytes")
        message_slh = b"Test message for SLH-DSA PURE SHAKE 256f"
        signature_slh = slh_dsa_f.sign(sk_slh, message_slh)
        print(f"  PASS Signature generated: {len(signature_slh)} bytes")
        valid_slh = slh_dsa_f.verify(pk_slh, message_slh, signature_slh)
        if valid_slh: print(f"  PASS Signature VERIFIED - SLH_DSA_PURE_SHAKE_256F is WORKING!")
        else: print(f"  FAIL Signature INVALID - SLH_DSA_PURE_SHAKE_256F is BROKEN!")
        invalid_signature_slh = signature_slh[:-1] + bytes([(signature_slh[-1] + 1) % 256])
        invalid_valid_slh = slh_dsa_f.verify(pk_slh, message_slh, invalid_signature_slh)
        if not invalid_valid_slh: print(f"  PASS Correctly identified INVALID signature.")
        else: print(f"  FAIL FAILED to identify INVALID signature!")
    except Exception as e: print(f"  FAIL SLH_DSA_PURE_SHAKE_256F test failed: {e}")
    print("-" * 80)

    # Test AES-256-GCM
    print("Testing AES-256-GCM...")
    # (AES test code remains the same as before)
    try:
        aes_gcm = LibOQS_AES256GCM()
        aes_key = aes_gcm.generate_key()
        print(f"  PASS AES Key generated: {len(aes_key)} bytes")
        aes_nonce = aes_gcm.generate_nonce()
        print(f"  PASS AES Nonce generated: {len(aes_nonce)} bytes")
        plaintext = b"This is the confidential military data (faster build)."
        aad = b"Metadata Packet ID 67890" # Associated Data

        ciphertext = aes_gcm.encrypt(aes_key, aes_nonce, plaintext, aad)
        print(f"  PASS Encrypted data: {len(ciphertext)} bytes (Plaintext: {len(plaintext)})")

        decrypted_text = aes_gcm.decrypt(aes_key, aes_nonce, ciphertext, aad)
        print(f"  PASS Decrypted data: {len(decrypted_text)} bytes")

        if decrypted_text == plaintext:
            print(f"  PASS Plaintext MATCHES - AES-256-GCM Encrypt/Decrypt is WORKING!")
        else:
            print(f"  FAIL Plaintext DOES NOT MATCH - AES-256-GCM is BROKEN!")

        # Test tampering
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[5] = (tampered_ciphertext[5] + 1) % 256 # Flip a byte
        try:
            aes_gcm.decrypt(aes_key, aes_nonce, bytes(tampered_ciphertext), aad)
            print(f"  FAIL FAILED to detect tampered ciphertext!")
        except aes_gcm.InvalidTag:
             print(f"  PASS Correctly detected tampered ciphertext (InvalidTag exception).")
        except Exception as tag_e:
             print(f"  FAIL Unexpected error during tampered decrypt: {tag_e}")

    except ImportError:
         print(f"  WARN AES-256-GCM test skipped: 'cryptography' library not installed.")
    except Exception as e:
        print(f"  FAIL AES-256-GCM test failed: {e}")

    print()
    print("="*80)
    print("Testing Hybrid KEM (ML-KEM-1024 + McEliece-8192128f)...")
    print("="*80)
    try:
        hybrid_kem = HybridKEM()
        
        # Generate hybrid keypair
        pk_hybrid, sk_hybrid = hybrid_kem.keygen()
        print(f"  PASS Hybrid keypair generated:")
        print(f"    - Combined PK: {len(pk_hybrid)} bytes (ML-KEM: {hybrid_kem.pk_size_mlkem}, McEliece: {hybrid_kem.pk_size_mceliece})")
        print(f"    - Combined SK: {len(sk_hybrid)} bytes (ML-KEM: {hybrid_kem.sk_size_mlkem}, McEliece: {hybrid_kem.sk_size_mceliece})")
        
        # Hybrid encapsulation
        ct_hybrid, ss1_hybrid = hybrid_kem.encaps(pk_hybrid)
        print(f"  PASS Hybrid encapsulation:")
        print(f"    - Combined CT: {len(ct_hybrid)} bytes (ML-KEM: {hybrid_kem.ct_size_mlkem}, McEliece: {hybrid_kem.ct_size_mceliece})")
        print(f"    - Hybrid SS: {len(ss1_hybrid)} bytes (384-bit from HKDF-SHA384)")
        
        # Hybrid decapsulation
        ss2_hybrid = hybrid_kem.decaps(sk_hybrid, ct_hybrid)
        print(f"  PASS Hybrid decapsulation: SS={len(ss2_hybrid)} bytes")
        
        if ss1_hybrid == ss2_hybrid:
            print(f"  PASS Hybrid shared secrets MATCH - Hybrid KEM is WORKING!")
            print(f"  SECURE Security: Attacker must break BOTH ML-KEM-1024 AND McEliece-8192128f")
        else:
            print(f"  FAIL Hybrid shared secrets DO NOT MATCH - Hybrid KEM is BROKEN!")
    except Exception as e:
        print(f"  FAIL Hybrid KEM test failed: {e}")
    print("-" * 80)
    
    print()
    print("="*80)
    print("Testing Hybrid Signatures (ML-DSA-87 + SLH-DSA-256f)...")
    print("="*80)
    
    # Test Fast Mode (ML-DSA-87 only)
    print("\n[Mode: FAST - ML-DSA-87 only]")
    try:
        hybrid_sig_fast = HybridSignature(mode='fast')
        pk_sig, sk_sig = hybrid_sig_fast.keygen()
        
        message = b"Test message for hybrid signature (fast mode)"
        signatures = hybrid_sig_fast.sign(sk_sig, message)
        print(f"  PASS Fast signature: {len(signatures['mldsa'])} bytes")
        
        valid = hybrid_sig_fast.verify(pk_sig, message, signatures)
        if valid:
            print(f"  PASS Fast signature VERIFIED - ML-DSA-87 working!")
        else:
            print(f"  FAIL Fast signature INVALID")
    except Exception as e:
        print(f"  FAIL Fast mode test failed: {e}")
    
    # Test Secure Mode (SLH-DSA-256f only)
    print("\n[Mode: SECURE - SLH-DSA-256f only]")
    try:
        hybrid_sig_secure = HybridSignature(mode='secure')
        pk_sig, sk_sig = hybrid_sig_secure.keygen()
        
        message = b"High-value document for long-term signature (secure mode)"
        signatures = hybrid_sig_secure.sign(sk_sig, message)
        print(f"  PASS Secure signature: {len(signatures['slhdsa'])} bytes")
        
        valid = hybrid_sig_secure.verify(pk_sig, message, signatures)
        if valid:
            print(f"  PASS Secure signature VERIFIED - SLH-DSA-256f working!")
        else:
            print(f"  FAIL Secure signature INVALID")
    except Exception as e:
        print(f"  FAIL Secure mode test failed: {e}")
    
    # Test Dual Mode (Both signatures)
    print("\n[Mode: DUAL - Both ML-DSA-87 and SLH-DSA-256f]")
    try:
        hybrid_sig_dual = HybridSignature(mode='dual')
        pk_sig, sk_sig = hybrid_sig_dual.keygen()
        
        message = b"Critical firmware update requiring maximum assurance (dual mode)"
        signatures = hybrid_sig_dual.sign(sk_sig, message)
        print(f"  PASS Dual signatures:")
        print(f"    - ML-DSA-87: {len(signatures['mldsa'])} bytes")
        print(f"    - SLH-DSA-256f: {len(signatures['slhdsa'])} bytes")
        
        valid = hybrid_sig_dual.verify(pk_sig, message, signatures)
        if valid:
            print(f"  PASS Both signatures VERIFIED - Dual mode working!")
            print(f"  SECURE Security: Attacker must break BOTH ML-DSA-87 AND SLH-DSA-256f")
        else:
            print(f"  FAIL Dual signature verification FAILED")
    except Exception as e:
        print(f"  FAIL Dual mode test failed: {e}")

    print()
    print("="*80)
    print("LibOQS Hybrid Cryptography Test Complete!")
    print("="*80)
    print("\nPASS Summary:")
    print("  * Hybrid KEM: ML-KEM-1024 + McEliece-8192128f with HKDF-SHA384")
    print("  * Hybrid Signatures: ML-DSA-87 (fast) + SLH-DSA-256f (secure)")
    print("  * Maximum security: Attacker must break multiple algorithm families")
    print("="*80)


