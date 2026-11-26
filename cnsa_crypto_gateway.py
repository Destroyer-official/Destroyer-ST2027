#!/usr/bin/env python3
"""
cnsa_crypto_gateway.py — Canonical Cryptographic Gateway for Sovereign ST2027.

Single Source of Truth (DRY) for symmetric AEAD encryption, deterministic nonces,
key derivation, and memory zeroization across all Python subsystems.

Mandates:
  1. CNSA Suite 2.0 purity: AES-256-GCM, HKDF-SHA384 / SHA512.
  2. NIST SP 800-38D Section 8.2.1: 96-bit deterministic composite IVs
     (32-bit fixed context || 64-bit atomic monotonic counter).
  3. Fail-closed error handling: zero silent fallback to unauthenticated or weak modes.
  4. DoD 5220.22-M memory zeroization for mutable buffers.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import struct
import threading
from typing import Iterator, Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecurityError(RuntimeError):
    """Base exception for cryptographic and security policy violations."""
    pass


class CryptographicIntegrityError(SecurityError):
    """Raised when AEAD tag verification, ciphertext integrity, or framing check fails."""
    pass


class KeyLengthError(ValueError):
    """Raised when a key does not satisfy CNSA 2.0 length requirements (e.g., 256 bits for AES)."""
    pass


class CounterExhaustionError(OverflowError):
    """Raised when the 64-bit monotonic counter reaches exhaustion requiring rekey."""
    pass


# ---------------------------------------------------------------------------
# NIST SP 800-38D Section 8.2.1 Durable + Key-Bound Deterministic IV Engine
# ---------------------------------------------------------------------------
_NONCE_STATE_MAGIC = b"ST2027IV"  # 8B magic + 4B u32 epoch + 32B durable seed = 44B
_NONCE_STATE_LEN = 44
_EPOCH_COUNTER_MAX = (1 << 32) - 1
_iv_lock = threading.Lock()
_iv_ctx_tls = threading.local()
_iv_pid = 0
_iv_boot_epoch = 0
_iv_node_seed = b""
_iv_proc_entropy = b""
_iv_counter = 0


def _is_production_posture() -> bool:
    import production_gate
    return production_gate.is_production()


def _resolve_nonce_state_path() -> Path:
    override = os.environ.get("ST2027_NONCE_STATE_DIR", "").strip()
    if override:
        base = Path(override)
    elif os.name == "nt":
        local_app = os.environ.get("LOCALAPPDATA", "").strip()
        base = (Path(local_app) if local_app else (Path.home() / "AppData" / "Local")) / "ST2027" / "state"
    else:
        xdg = os.environ.get("XDG_STATE_HOME", "").strip()
        base = (Path(xdg) if xdg else (Path.home() / ".local" / "state")) / "ST2027"
    return base / "gcm_nonce_epoch.bin"


def _file_lock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)


def _file_unlock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)


def _harden_private_path(path: Path, is_dir: bool) -> None:
    if os.name != "nt":
        try:
            os.chmod(path, 0o700 if is_dir else 0o600)
        except OSError:
            pass


def _allocate_persistent_boot_epoch() -> Tuple[int, bytes]:
    """Atomically reserve the next monotonic 32-bit boot epoch on durable storage."""
    state_path = _resolve_nonce_state_path()
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        _harden_private_path(state_path.parent, is_dir=True)
        if state_path.is_symlink():
            raise SecurityError(f"Refusing symlinked nonce state path: {state_path}")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(state_path), flags, 0o600)
        try:
            _file_lock(fd)
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                raw = os.read(fd, 128)
                if not raw:
                    next_epoch = 1
                    node_seed = secrets.token_bytes(32)
                elif len(raw) >= _NONCE_STATE_LEN and raw[:8] == _NONCE_STATE_MAGIC:
                    prev_epoch = struct.unpack(">I", raw[8:12])[0]
                    if prev_epoch >= _EPOCH_COUNTER_MAX:
                        raise CounterExhaustionError(
                            "NIST SP 800-38D persistent boot epoch exhausted: rekey master/node seed required"
                        )
                    next_epoch = prev_epoch + 1
                    node_seed = raw[12:_NONCE_STATE_LEN]
                else:
                    raise SecurityError(f"Corrupted durable nonce state file: {state_path}")

                new_blob = _NONCE_STATE_MAGIC + struct.pack(">I", next_epoch) + node_seed
                os.lseek(fd, 0, os.SEEK_SET)
                os.write(fd, new_blob)
                if hasattr(os, "ftruncate"):
                    os.ftruncate(fd, len(new_blob))
                os.fsync(fd)
                _harden_private_path(state_path, is_dir=False)
                return next_epoch, node_seed
            finally:
                try:
                    _file_unlock(fd)
                except OSError:
                    pass
        finally:
            os.close(fd)
    except CounterExhaustionError:
        raise
    except SecurityError:
        raise
    except Exception as exc:
        if _is_production_posture():
            raise SecurityError(
                f"Durable GCM nonce ledger unavailable in production ({state_path}): {exc}"
            ) from exc
        # Non-production fallback ONLY if primary state dir is unwritable
        return 1, secrets.token_bytes(32)


@contextmanager
def _bind_iv_key_context(key: Optional[bytes]) -> Iterator[None]:
    """Bind a cryptographic key digest into the current thread's IV context."""
    prev = getattr(_iv_ctx_tls, "key_digest", None)
    if key is not None:
        _iv_ctx_tls.key_digest = hashlib.sha384(b"ST2027-KEY-CTX-V2" + key).digest()[:16]
    else:
        _iv_ctx_tls.key_digest = None
    try:
        yield
    finally:
        _iv_ctx_tls.key_digest = prev


def _reseed_iv_state_locked() -> None:
    """Allocate a fresh durable epoch + per-process entropy on init or fork."""
    global _iv_pid, _iv_boot_epoch, _iv_node_seed, _iv_proc_entropy, _iv_counter
    epoch, node_seed = _allocate_persistent_boot_epoch()
    _iv_pid = os.getpid()
    _iv_boot_epoch = epoch
    _iv_node_seed = node_seed
    _iv_proc_entropy = secrets.token_bytes(32)
    _iv_counter = 0


def _on_fork_child() -> None:
    with _iv_lock:
        _reseed_iv_state_locked()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_on_fork_child)


def generate_deterministic_gcm_iv() -> bytes:
    """Generate a 96-bit durable, key-bound deterministic IV per NIST SP 800-38D Section 8.2.1.

    Format:
        Fixed Key-Bound Context (4 bytes) || Invocation Field (8 bytes: u32 durable_epoch || u32 seq)

    Guarantees:
      - Process restarts allocate a strictly monotonic persistent `durable_epoch` (fsynced ledger),
        preventing nonce reuse even if RNG state is replayed or processes restart frequently.
      - Forked children re-allocate a disjoint epoch via `os.register_at_fork` + PID check.
      - Distinct keys bound via `cnsa_aes_256_gcm_encrypt` derive distinct fixed context prefixes.
      - Counter overflow beyond 2^32 invocations atomically rotates to the next durable epoch or raises
        `CounterExhaustionError` on 32-bit epoch exhaustion.
    """
    global _iv_counter
    with _iv_lock:
        if os.getpid() != _iv_pid or _iv_boot_epoch == 0:
            _reseed_iv_state_locked()
        if _iv_counter >= _EPOCH_COUNTER_MAX:
            _reseed_iv_state_locked()
        _iv_counter += 1
        key_ctx = getattr(_iv_ctx_tls, "key_digest", None) or b"GLOBAL-CTX"
        fixed_prefix = hashlib.sha384(
            b"ST2027-SP800-38D-FIXED-V2"
            + _iv_node_seed
            + _iv_proc_entropy
            + key_ctx
            + struct.pack(">I", _iv_boot_epoch)
        ).digest()[:4]
        invocation = struct.pack(">II", _iv_boot_epoch, _iv_counter)
        return fixed_prefix + invocation


# ---------------------------------------------------------------------------
# CNSA 2.0 AES-256-GCM & XAES-256-GCM (NIST SP 800-108r1 + AES-256-GCM)
# ---------------------------------------------------------------------------

def _derive_xaes_subkey(key: bytes, nonce_prefix_12: bytes) -> bytes:
    """Derive 256-bit per-message subkey per c2sp.org/XAES-256-GCM using CMAC-AES-256 (SP 800-108r1)."""
    if len(key) != 32:
        raise KeyLengthError(f"XAES-256-GCM mandates 256-bit (32-byte) AES key, got {len(key)} bytes")
    if len(nonce_prefix_12) != 12:
        raise ValueError(f"XAES-256-GCM KDF expects 12-byte nonce prefix, got {len(nonce_prefix_12)} bytes")
    c1 = cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c1.update(b"\x00\x01X\x00" + nonce_prefix_12)
    c2 = cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c2.update(b"\x00\x02X\x00" + nonce_prefix_12)
    return c1.finalize() + c2.finalize()


def cnsa_xaes_256_gcm_encrypt(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
    nonce24: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt with c2sp.org/XAES-256-GCM (192-bit nonce, per-message SP 800-108r1 subkey).

    Safe for multi-host / stateless / VM-cloned workloads without global nonce coordination.
    Returns (ciphertext, nonce24, tag16).
    """
    if len(key) != 32:
        raise KeyLengthError(f"CNSA 2.0 mandates 256-bit (32-byte) AES key, got {len(key)} bytes")
    nonce = nonce24 if nonce24 is not None else secrets.token_bytes(24)
    if len(nonce) != 24:
        raise ValueError(f"XAES-256-GCM mandates exactly 24-byte (192-bit) nonce, got {len(nonce)} bytes")
    subkey_buf = bytearray(_derive_xaes_subkey(key, nonce[:12]))
    try:
        cipher = Cipher(algorithms.AES(bytes(subkey_buf)), modes.GCM(nonce[12:]), backend=default_backend())
        encryptor = cipher.encryptor()
        if associated_data is not None:
            encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, nonce, encryptor.tag
    finally:
        cnsa_zeroize_memory(subkey_buf)


def cnsa_xaes_256_gcm_decrypt(
    ciphertext: bytes,
    key: bytes,
    nonce24: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt and authenticate c2sp.org/XAES-256-GCM ciphertext."""
    if len(key) != 32:
        raise KeyLengthError(f"CNSA 2.0 mandates 256-bit (32-byte) AES key, got {len(key)} bytes")
    if len(nonce24) != 24:
        raise ValueError(f"XAES-256-GCM mandates exactly 24-byte (192-bit) nonce, got {len(nonce24)} bytes")
    if len(tag) != 16:
        raise CryptographicIntegrityError(f"AES-GCM mandates 16-byte authentication tag, got {len(tag)} bytes")
    subkey_buf = bytearray(_derive_xaes_subkey(key, nonce24[:12]))
    try:
        cipher = Cipher(algorithms.AES(bytes(subkey_buf)), modes.GCM(nonce24[12:], tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if associated_data is not None:
            decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise CryptographicIntegrityError(f"XAES-256-GCM authentication failed (tampering detected): {e}") from None
    finally:
        cnsa_zeroize_memory(subkey_buf)


def cnsa_aes_256_gcm_encrypt(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
    explicit_iv: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM with durable key-bound NIST SP 800-38D IV.

    Args:
        plaintext: Raw data to encrypt.
        key: Exactly 32 bytes (256-bit) AES key.
        associated_data: Optional authenticated associated data (AAD).
        explicit_iv: Optional explicit 12-byte IV (if omitted, generated monotonically).

    Returns:
        (ciphertext, iv, authentication_tag)
    """
    if len(key) != 32:
        raise KeyLengthError(f"CNSA 2.0 mandates 256-bit (32-byte) AES key, got {len(key)} bytes")

    if explicit_iv is not None:
        iv = explicit_iv
    else:
        with _bind_iv_key_context(key):
            iv = generate_deterministic_gcm_iv()
    if len(iv) != 12:
        raise ValueError(f"AES-GCM mandates exactly 12-byte (96-bit) IV, got {len(iv)} bytes")

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    if associated_data is not None:
        encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag


def cnsa_aes_256_gcm_decrypt(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt ciphertext and authenticate tag using AES-256-GCM.

    Args:
        ciphertext: Encrypted payload.
        key: Exactly 32 bytes (256-bit) AES key.
        iv: Exactly 12 bytes IV.
        tag: Exactly 16 bytes authentication tag.
        associated_data: Optional authenticated associated data (AAD).

    Returns:
        Plaintext bytes.

    Raises:
        CryptographicIntegrityError: If ciphertext, tag, or AAD has been tampered with.
    """
    if len(key) != 32:
        raise KeyLengthError(f"CNSA 2.0 mandates 256-bit (32-byte) AES key, got {len(key)} bytes")
    if len(iv) != 12:
        raise ValueError(f"AES-GCM mandates exactly 12-byte (96-bit) IV, got {len(iv)} bytes")
    if len(tag) != 16:
        raise CryptographicIntegrityError(f"AES-GCM mandates 16-byte authentication tag, got {len(tag)} bytes")

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if associated_data is not None:
            decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise CryptographicIntegrityError(f"AES-256-GCM authentication failed (tampering detected): {e}") from None


# ---------------------------------------------------------------------------
# Canonical Wire Envelope Framing (12-byte IV || Ciphertext || 16-byte Tag)
# ---------------------------------------------------------------------------

def cnsa_seal_payload(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Seal plaintext into canonical wire envelope: IV (12) || Ciphertext || Tag (16)."""
    ct, iv, tag = cnsa_aes_256_gcm_encrypt(plaintext, key, associated_data=associated_data)
    return iv + ct + tag


def cnsa_open_payload(
    sealed_bytes: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Open and authenticate canonical wire envelope: IV (12) || Ciphertext || Tag (16)."""
    if len(sealed_bytes) < 28:  # 12 (IV) + 16 (Tag) minimum for 0-byte payload
        raise CryptographicIntegrityError(f"Sealed envelope truncated (len={len(sealed_bytes)} < 28)")
    iv = sealed_bytes[:12]
    tag = sealed_bytes[-16:]
    ct = sealed_bytes[12:-16]
    return cnsa_aes_256_gcm_decrypt(ct, key, iv, tag, associated_data=associated_data)


# ---------------------------------------------------------------------------
# Standard Key Derivation (HKDF-SHA384 / SHA512)
# ---------------------------------------------------------------------------

def cnsa_hkdf_derive(
    master_secret: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
    algorithm: str = "sha384",
) -> bytes:
    """Derive keys using CNSA Suite 2.0 HKDF (SHA-384 or SHA-512)."""
    hash_algo = hashes.SHA384() if algorithm.lower() == "sha384" else hashes.SHA512()
    hkdf = HKDF(
        algorithm=hash_algo,
        length=length,
        salt=salt,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(master_secret)


# ---------------------------------------------------------------------------
# Memory Zeroization (DoD 5220.22-M 7-Pass)
# ---------------------------------------------------------------------------

def cnsa_zeroize_memory(*buffers: Optional[Union[bytearray, memoryview]]) -> None:
    """Perform deterministic DoD 5220.22-M 7-pass memory zeroization on mutable buffers."""
    for buf in buffers:
        if buf is None:
            continue
        if isinstance(buf, (bytearray, memoryview)):
            try:
                length = len(buf)
                # Pass 1: 0x00
                buf[:] = b"\x00" * length
                # Pass 2: 0xFF
                buf[:] = b"\xFF" * length
                # Pass 3: 0xAA (10101010)
                buf[:] = b"\xAA" * length
                # Pass 4: 0x55 (01010101)
                buf[:] = b"\x55" * length
                # Pass 5: 0x96 (10010110)
                buf[:] = b"\x96" * length
                # Pass 6: Cryptographic PRNG random bytes
                buf[:] = secrets.token_bytes(length)
                # Pass 7: Final zero flush
                buf[:] = b"\x00" * length
            except Exception:
                pass


__all__ = [
    "generate_deterministic_gcm_iv",
    "cnsa_aes_256_gcm_encrypt",
    "cnsa_aes_256_gcm_decrypt",
    "cnsa_xaes_256_gcm_encrypt",
    "cnsa_xaes_256_gcm_decrypt",
    "cnsa_seal_payload",
    "cnsa_open_payload",
    "cnsa_hkdf_derive",
    "cnsa_zeroize_memory",
    "SecurityError",
    "CryptographicIntegrityError",
    "KeyLengthError",
    "CounterExhaustionError",
]
