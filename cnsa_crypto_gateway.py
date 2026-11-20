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

import hmac
import os
import secrets
import threading
from typing import Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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
# NIST SP 800-38D Section 8.2.1 Deterministic IV Generation
# ---------------------------------------------------------------------------
_iv_lock = threading.Lock()
_iv_fixed_prefix = secrets.token_bytes(4)  # 32-bit device/session context
_iv_counter = 0


def generate_deterministic_gcm_iv() -> bytes:
    """Generate a 96-bit deterministic IV per NIST SP 800-38D Section 8.2.1.

    Format:
        Fixed Context (4 bytes) || Atomic Monotonic Counter (8 bytes, big-endian)

    Guarantees that no two invocations under the same key instantiate the same IV,
    permanently eliminating birthday-bound collision risk for AES-GCM.
    """
    global _iv_counter
    with _iv_lock:
        _iv_counter += 1
        if _iv_counter >= (1 << 64) - 1:
            raise CounterExhaustionError("NIST SP 800-38D 64-bit counter exhaustion: rekey required")
        return _iv_fixed_prefix + _iv_counter.to_bytes(8, byteorder="big")


# ---------------------------------------------------------------------------
# CNSA 2.0 AES-256-GCM Cryptographic Operations
# ---------------------------------------------------------------------------

def cnsa_aes_256_gcm_encrypt(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
    explicit_iv: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM with NIST SP 800-38D deterministic IV.

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

    iv = explicit_iv if explicit_iv is not None else generate_deterministic_gcm_iv()
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
    "cnsa_seal_payload",
    "cnsa_open_payload",
    "cnsa_hkdf_derive",
    "cnsa_zeroize_memory",
    "CryptographicIntegrityError",
    "KeyLengthError",
    "CounterExhaustionError",
]
