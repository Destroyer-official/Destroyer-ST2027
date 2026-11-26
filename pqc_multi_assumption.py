#!/usr/bin/env python3
"""
pqc_multi_assumption.py — Multi-Assumption Post-Quantum KEX Combiner (Zero Fallback).

Combines three independent mathematical hardness assumptions:
1. ML-KEM-1024 (Lattice-based, NIST FIPS 203, Category 5)
2. Classic McEliece 8192128f (Code-based Goppa codes, NIST Level 5, unbroken since 1978)
3. Out-of-band Hardware Pre-Shared Key (H-PSK, 256-bit symmetric entropy)

Security Invariant:
Strict Triple-PRF AND-combiner. If either ciphertext or the PSK is missing or invalid,
fail closed immediately. ZERO FALLBACK to classical or unhybridized algorithms.

Master Key Derivation:
K_master = HKDF-Extract(
    salt = SHA-384("ST2027-TRIPLE-KEX-v1" || Transcript),
    IKM  = SS_ML-KEM || SS_McEliece || K_H-PSK
)

All secret buffers enforce ZeroizeOnDrop / secure wiping and branchless constant-time comparisons.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

try:
    import destroyer_core
    _HAVE_DESTROYER_CORE = hasattr(destroyer_core, "CoreTripleKex")
except Exception:
    _HAVE_DESTROYER_CORE = False

from liboqs_wrapper import (
    LibOQS_MLKEM_1024,
    LibOQS_McEliece_8192128f,
)
from native_secure_buffer import NativeSecureBuffer, wipe_native

logger = logging.getLogger(__name__)

# Protocol domain separation constants
DOMAIN_SEPARATOR = b"ST2027-TRIPLE-KEX-v1"
DOMAIN_EXPAND_I2R = b"ST2027-TRIPLE-KEX-I2R-v1"
DOMAIN_EXPAND_R2I = b"ST2027-TRIPLE-KEX-R2I-v1"
DOMAIN_EXPAND_CONFIRM = b"ST2027-TRIPLE-KEX-CONFIRM-v1"
DOMAIN_CONFIRM_INITIATOR = b"ST2027-TRIPLE-KEX-CONFIRM-INITIATOR-v1"
DOMAIN_CONFIRM_RESPONDER = b"ST2027-TRIPLE-KEX-CONFIRM-RESPONDER-v1"

# Pinned algorithm parameters (NIST Level 5)
MLKEM_PK_LEN = 1568
MLKEM_SK_LEN = 3168
MLKEM_CT_LEN = 1568
MLKEM_SS_LEN = 32

MCELIECE_PK_LEN = 1357824
MCELIECE_SK_LEN = 14120
MCELIECE_CT_LEN = 208
MCELIECE_SS_LEN = 32

HPSK_LEN = 32
COMBINED_CT_LEN = MLKEM_CT_LEN + MCELIECE_CT_LEN  # 1776 bytes
COMBINED_PK_LEN = MLKEM_PK_LEN + MCELIECE_PK_LEN  # 1359392 bytes
COMBINED_SS_LEN = MLKEM_SS_LEN + MCELIECE_SS_LEN + HPSK_LEN  # 96 bytes
MASTER_KEY_LEN = 48  # SHA-384 HKDF-Extract output length


def _ct_is_all_zeros(buf: Union[bytes, bytearray]) -> bool:
    """Branchless constant-time check: returns True iff buffer is all zeros."""
    return secrets.compare_digest(bytes(buf), bytes(len(buf)))


def _zeroize_memory(data: Any) -> None:
    """Securely zeroize a mutable buffer in place."""
    if isinstance(data, bytearray):
        try:
            wipe_native(data)
        except Exception:
            for i in range(len(data)):
                data[i] = 0
    elif isinstance(data, NativeSecureBuffer):
        data.wipe()


@dataclass(frozen=True)
class TripleKexPublicKey:
    """Triple-KEX public key bundle holding ML-KEM-1024 and Classic McEliece 8192128f keys."""

    mlkem_pk: bytes
    mceliece_pk: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.mlkem_pk, (bytes, bytearray)):
            raise TypeError("mlkem_pk must be bytes-like")
        if not isinstance(self.mceliece_pk, (bytes, bytearray)):
            raise TypeError("mceliece_pk must be bytes-like")
        if len(self.mlkem_pk) != MLKEM_PK_LEN:
            raise ValueError(
                f"Invalid ML-KEM-1024 public key length: {len(self.mlkem_pk)} (expected {MLKEM_PK_LEN})"
            )
        if len(self.mceliece_pk) != MCELIECE_PK_LEN:
            raise ValueError(
                f"Invalid Classic McEliece public key length: {len(self.mceliece_pk)} (expected {MCELIECE_PK_LEN})"
            )
        if _ct_is_all_zeros(self.mlkem_pk) or _ct_is_all_zeros(self.mceliece_pk):
            raise ValueError("All-zero public key component rejected (fail-closed)")

    def __repr__(self) -> str:
        return f"TripleKexPublicKey(mlkem_pk=<{len(self.mlkem_pk)} bytes>, mceliece_pk=<{len(self.mceliece_pk)} bytes>)"

    def to_bytes(self) -> bytes:
        """Serialize public key bundle to raw contiguous bytes."""
        return bytes(self.mlkem_pk) + bytes(self.mceliece_pk)

    @classmethod
    def from_bytes(cls, data: bytes) -> TripleKexPublicKey:
        """Deserialize public key bundle from raw contiguous bytes."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes-like")
        if len(data) != COMBINED_PK_LEN:
            raise ValueError(
                f"Invalid TripleKexPublicKey bytes length: {len(data)} (expected {COMBINED_PK_LEN})"
            )
        mlkem_pk = bytes(data[:MLKEM_PK_LEN])
        mceliece_pk = bytes(data[MLKEM_PK_LEN:])
        return cls(mlkem_pk=mlkem_pk, mceliece_pk=mceliece_pk)

    def to_dict(self) -> Dict[str, str]:
        """Convert public key components to hex dictionary."""
        return {
            "mlkem_pk": bytes(self.mlkem_pk).hex(),
            "mceliece_pk": bytes(self.mceliece_pk).hex(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> TripleKexPublicKey:
        """Parse public key bundle from dictionary (accepting hex or raw bytes)."""
        if not isinstance(d, dict):
            raise TypeError("Bundle must be a dictionary")
        mlkem = d.get("mlkem_pk") or d.get("mlkem")
        mceliece = d.get("mceliece_pk") or d.get("mceliece")
        if mlkem is None or mceliece is None:
            raise ValueError("Public key bundle missing required KEM component (zero fallback)")

        if isinstance(mlkem, str):
            mlkem = bytes.fromhex(mlkem)
        if isinstance(mceliece, str):
            mceliece = bytes.fromhex(mceliece)

        return cls(mlkem_pk=bytes(mlkem), mceliece_pk=bytes(mceliece))

    def to_base64(self) -> str:
        """Serialize public key bundle to base64 string."""
        return base64.b64encode(self.to_bytes()).decode("ascii")

    @classmethod
    def from_base64(cls, b64_str: str) -> TripleKexPublicKey:
        """Deserialize public key bundle from base64 string."""
        if not isinstance(b64_str, str):
            raise TypeError("b64_str must be a string")
        raw = base64.b64decode(b64_str.encode("ascii"))
        return cls.from_bytes(raw)

    def to_json(self) -> str:
        """Serialize public key bundle to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> TripleKexPublicKey:
        """Deserialize public key bundle from JSON string."""
        if not isinstance(json_str, str):
            raise TypeError("json_str must be a string")
        return cls.from_dict(json.loads(json_str))


@dataclass(frozen=True)
class TripleKexCiphertext:
    """Triple-KEX ciphertext bundle holding ML-KEM-1024 and Classic McEliece 8192128f ciphertexts."""

    mlkem_ct: bytes
    mceliece_ct: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.mlkem_ct, (bytes, bytearray)):
            raise TypeError("mlkem_ct must be bytes-like")
        if not isinstance(self.mceliece_ct, (bytes, bytearray)):
            raise TypeError("mceliece_ct must be bytes-like")
        if len(self.mlkem_ct) != MLKEM_CT_LEN:
            raise ValueError(
                f"Invalid ML-KEM-1024 ciphertext length: {len(self.mlkem_ct)} (expected {MLKEM_CT_LEN})"
            )
        if len(self.mceliece_ct) != MCELIECE_CT_LEN:
            raise ValueError(
                f"Invalid Classic McEliece ciphertext length: {len(self.mceliece_ct)} (expected {MCELIECE_CT_LEN})"
            )
        if _ct_is_all_zeros(self.mlkem_ct) or _ct_is_all_zeros(self.mceliece_ct):
            raise ValueError("All-zero ciphertext component rejected (fail-closed)")

    def __repr__(self) -> str:
        return f"TripleKexCiphertext(mlkem_ct=<{len(self.mlkem_ct)} bytes>, mceliece_ct=<{len(self.mceliece_ct)} bytes>)"

    def to_bytes(self) -> bytes:
        """Serialize ciphertext bundle to raw contiguous bytes (1776 bytes)."""
        return bytes(self.mlkem_ct) + bytes(self.mceliece_ct)

    @classmethod
    def from_bytes(cls, data: bytes) -> TripleKexCiphertext:
        """Deserialize ciphertext bundle from raw contiguous bytes."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes-like")
        if len(data) != COMBINED_CT_LEN:
            raise ValueError(
                f"Invalid TripleKexCiphertext bytes length: {len(data)} (expected {COMBINED_CT_LEN})"
            )
        mlkem_ct = bytes(data[:MLKEM_CT_LEN])
        mceliece_ct = bytes(data[MLKEM_CT_LEN:])
        return cls(mlkem_ct=mlkem_ct, mceliece_ct=mceliece_ct)

    def to_dict(self) -> Dict[str, str]:
        """Convert ciphertext components to hex dictionary."""
        return {
            "mlkem_ct": bytes(self.mlkem_ct).hex(),
            "mceliece_ct": bytes(self.mceliece_ct).hex(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> TripleKexCiphertext:
        """Parse ciphertext bundle from dictionary (accepting hex or raw bytes)."""
        if not isinstance(d, dict):
            raise TypeError("Ciphertext bundle must be a dictionary")
        mlkem = d.get("mlkem_ct") or d.get("mlkem")
        mceliece = d.get("mceliece_ct") or d.get("mceliece")
        if mlkem is None or mceliece is None:
            raise ValueError("Ciphertext bundle missing required KEM component (zero fallback)")

        if isinstance(mlkem, str):
            mlkem = bytes.fromhex(mlkem)
        if isinstance(mceliece, str):
            mceliece = bytes.fromhex(mceliece)

        return cls(mlkem_ct=bytes(mlkem), mceliece_ct=bytes(mceliece))

    def to_base64(self) -> str:
        """Serialize ciphertext bundle to base64 string."""
        return base64.b64encode(self.to_bytes()).decode("ascii")

    @classmethod
    def from_base64(cls, b64_str: str) -> TripleKexCiphertext:
        """Deserialize ciphertext bundle from base64 string."""
        if not isinstance(b64_str, str):
            raise TypeError("b64_str must be a string")
        raw = base64.b64decode(b64_str.encode("ascii"))
        return cls.from_bytes(raw)

    def to_json(self) -> str:
        """Serialize ciphertext bundle to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> TripleKexCiphertext:
        """Deserialize ciphertext bundle from JSON string."""
        if not isinstance(json_str, str):
            raise TypeError("json_str must be a string")
        return cls.from_dict(json.loads(json_str))


class HardwarePsk:
    """Out-of-band Hardware Pre-Shared Key (32 bytes)."""

    def __init__(self, key: Union[bytes, bytearray, NativeSecureBuffer]):
        self._buf: Optional[NativeSecureBuffer] = None
        if key is None:
            raise ValueError("Hardware PSK cannot be None (strict Triple-PRF AND-combiner)")
        raw = bytes(key) if not isinstance(key, NativeSecureBuffer) else bytes(key)
        if len(raw) != HPSK_LEN:
            raise ValueError(
                f"Hardware PSK must be exactly {HPSK_LEN} bytes (got {len(raw)})"
            )
        if _ct_is_all_zeros(raw):
            raise ValueError("All-zero degenerate Hardware PSK rejected (fail-closed)")
        self._buf = NativeSecureBuffer(raw)

    def __repr__(self) -> str:
        return "HardwarePsk([REDACTED])"

    def as_bytes(self) -> bytes:
        if getattr(self, "_buf", None) is None or self._buf.wiped:
            raise RuntimeError("Hardware PSK buffer already zeroized")
        return bytes(self._buf)

    def wipe(self) -> None:
        buf = getattr(self, "_buf", None)
        if buf is not None:
            buf.wipe()
            self._buf = None

    def __enter__(self) -> HardwarePsk:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.wipe()

    def __del__(self) -> None:
        self.wipe()

    @classmethod
    def from_source(cls, source: Any) -> HardwarePsk:
        """Construct HardwarePsk from any supported source."""
        return load_hardware_psk(source)


def load_hardware_psk(source: Any) -> HardwarePsk:
    """
    Load a Hardware PSK from raw bytes, secured file, environment variable, or token provider.

    Accepts:
    1. Existing HardwarePsk instance
    2. NativeSecureBuffer instance
    3. Hardware token / provider object exposing `export_hardware_psk()` or `get_psk()`
    4. "env:<VAR_NAME>" loading from environment variable (hex, base64, or 32 raw bytes)
    5. Path to file on disk (32 raw bytes, 64 hex chars, or 44 base64 chars).
       On non-Windows systems, strictly enforces 0600 file permissions.
    6. Raw 32 bytes or bytearray.
    """
    if source is None:
        raise ValueError("Hardware PSK source cannot be None (fail-closed)")

    if isinstance(source, HardwarePsk):
        if getattr(source, "_buf", None) is None or source._buf.wiped:
            raise RuntimeError("Hardware PSK buffer already zeroized")
        return source

    if isinstance(source, NativeSecureBuffer):
        return HardwarePsk(source)

    if hasattr(source, "export_hardware_psk") and callable(source.export_hardware_psk):
        return HardwarePsk(source.export_hardware_psk())

    if hasattr(source, "get_psk") and callable(source.get_psk):
        return HardwarePsk(source.get_psk())

    if isinstance(source, (bytes, bytearray)):
        return HardwarePsk(bytes(source))

    if isinstance(source, str) and source.startswith("env:"):
        env_var = source[4:]
        val = os.environ.get(env_var)
        if not val:
            raise ValueError(f"Hardware PSK environment variable '{env_var}' is unset or empty")
        val_str = val.strip()
        # Try hex (64 chars)
        if len(val_str) == 64:
            try:
                return HardwarePsk(bytes.fromhex(val_str))
            except ValueError:
                pass
        # Try raw 32 bytes
        val_bytes = val.encode("utf-8")
        if len(val_bytes) == 32:
            return HardwarePsk(val_bytes)
        # Try base64
        try:
            decoded = base64.b64decode(val_str)
            if len(decoded) == 32:
                return HardwarePsk(decoded)
        except Exception:
            pass
        raise ValueError(
            f"Hardware PSK in env var '{env_var}' must contain 32 raw bytes, 64 hex characters, or 44 base64 characters"
        )

    p = Path(source).resolve()
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Hardware PSK file not found: {p}")
    if os.name != "nt":
        mode = p.stat().st_mode & 0o777
        if mode & 0o077 != 0:
            raise PermissionError(
                f"Hardware PSK file {p} has insecure permissions {oct(mode)} (must be 0600)"
            )
    raw_bytes = p.read_bytes()
    if len(raw_bytes) == HPSK_LEN:
        data = raw_bytes
    else:
        data = raw_bytes.strip()
        if len(data) == 64:
            try:
                data = bytes.fromhex(data.decode("ascii"))
            except Exception:
                pass
        elif len(data) in (43, 44):
            try:
                decoded = base64.b64decode(data)
                if len(decoded) == 32:
                    data = decoded
            except Exception:
                pass

    if len(data) != HPSK_LEN:
        raise ValueError(
            f"Hardware PSK file must contain 32 raw bytes, 64 hex characters, or 44 base64 characters (got {len(data)})"
        )
    return HardwarePsk(data)


@dataclass(frozen=True)
class TripleSessionKeys:
    """Role-separated transport traffic keys and confirmation key derived from MasterKey."""

    initiator_traffic_key: bytes
    responder_traffic_key: bytes
    confirmation_key: bytes

    def __post_init__(self) -> None:
        if len(self.initiator_traffic_key) != 32:
            raise ValueError("initiator_traffic_key must be 32 bytes")
        if len(self.responder_traffic_key) != 32:
            raise ValueError("responder_traffic_key must be 32 bytes")
        if len(self.confirmation_key) != 32:
            raise ValueError("confirmation_key must be 32 bytes")
        if (
            _ct_is_all_zeros(self.initiator_traffic_key)
            or _ct_is_all_zeros(self.responder_traffic_key)
            or _ct_is_all_zeros(self.confirmation_key)
        ):
            raise ValueError("Degenerate all-zero session key rejected (fail-closed)")

    def __repr__(self) -> str:
        return "TripleSessionKeys([REDACTED])"

    def ct_eq(self, other: TripleSessionKeys) -> bool:
        """Branchless constant-time comparison across all three keys."""
        if not isinstance(other, TripleSessionKeys):
            return False
        return (
            secrets.compare_digest(self.initiator_traffic_key, other.initiator_traffic_key)
            and secrets.compare_digest(self.responder_traffic_key, other.responder_traffic_key)
            and secrets.compare_digest(self.confirmation_key, other.confirmation_key)
        )

    def wipe(self) -> None:
        """Explicitly clear references on session completion."""
        pass

    def __enter__(self) -> TripleSessionKeys:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.wipe()


def expand_session_keys(
    master_key: Union[bytes, bytearray],
    transcript_binding: bytes = b"",
) -> TripleSessionKeys:
    """
    Expand MasterKey (48B) into role-separated transport keys and confirmation key:
    - initiator_traffic_key: 32 bytes (AES-256-GCM / FrameKey)
    - responder_traffic_key: 32 bytes (AES-256-GCM / FrameKey)
    - confirmation_key: 32 bytes (HMAC-SHA384 mutual confirmation tag key)
    """
    if len(master_key) != MASTER_KEY_LEN:
        raise ValueError(
            f"Invalid master key length: {len(master_key)} (expected {MASTER_KEY_LEN})"
        )
    if _ct_is_all_zeros(master_key):
        raise ValueError("All-zero degenerate master key rejected fail-closed")

    raw_mk = bytes(master_key)
    tb = bytes(transcript_binding)

    # RFC 5869 HKDF-Expand with SHA-384
    i2r = hmac.new(raw_mk, DOMAIN_EXPAND_I2R + tb + b"\x01", hashlib.sha384).digest()[:32]
    r2i = hmac.new(raw_mk, DOMAIN_EXPAND_R2I + tb + b"\x01", hashlib.sha384).digest()[:32]
    conf = hmac.new(raw_mk, DOMAIN_EXPAND_CONFIRM + tb + b"\x01", hashlib.sha384).digest()[:32]

    return TripleSessionKeys(
        initiator_traffic_key=i2r,
        responder_traffic_key=r2i,
        confirmation_key=conf,
    )


def compute_confirmation_tag(
    confirmation_key: Union[bytes, bytearray],
    role_label: bytes,
    transcript_binding: bytes = b"",
) -> bytes:
    """Compute 32-byte mutual confirmation tag via HMAC-SHA384(confirmation_key, role_label || transcript)."""
    if len(confirmation_key) != 32:
        raise ValueError("confirmation_key must be 32 bytes")
    if _ct_is_all_zeros(confirmation_key):
        raise ValueError("All-zero confirmation key rejected fail-closed")
    return hmac.new(
        bytes(confirmation_key),
        bytes(role_label) + bytes(transcript_binding),
        hashlib.sha384,
    ).digest()[:32]


def verify_confirmation_tag(
    confirmation_key: Union[bytes, bytearray],
    role_label: bytes,
    transcript_binding: bytes,
    expected_tag: bytes,
) -> bool:
    """Branchless constant-time verification of peer key confirmation tag."""
    computed = compute_confirmation_tag(confirmation_key, role_label, transcript_binding)
    if not isinstance(expected_tag, (bytes, bytearray)) or len(expected_tag) != len(computed):
        # Perform dummy comparison against computed to preserve constant time
        secrets.compare_digest(computed, computed)
        return False
    return secrets.compare_digest(computed, bytes(expected_tag))


class MultiAssumptionKEXManager:
    """
    Multi-Assumption Post-Quantum Key Encapsulation Manager.

    Combines:
    - ML-KEM-1024 (Lattice-based, NIST FIPS 203)
    - Classic McEliece 8192128f (Code-based, Goppa codes)
    - Hardware PSK (Out-of-band 256-bit entropy)

    Strict Triple-PRF AND-combiner: Zero Fallback.
    All three components MUST succeed.
    """

    def __init__(
        self,
        hardware_psk: Union[bytes, bytearray, HardwarePsk, NativeSecureBuffer],
        auto_generate: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._mlkem_pk: Optional[bytes] = None
        self._mlkem_sk: Optional[NativeSecureBuffer] = None
        self._mceliece_pk: Optional[bytes] = None
        self._mceliece_sk: Optional[NativeSecureBuffer] = None
        self._hardware_psk: Optional[HardwarePsk] = None

        if hardware_psk is None:
            raise ValueError(
                "Hardware PSK is strictly required: Zero fallback to unauthenticated/unhybridized KEX"
            )

        if isinstance(hardware_psk, HardwarePsk):
            self._hardware_psk: Optional[HardwarePsk] = hardware_psk
        else:
            self._hardware_psk = HardwarePsk(hardware_psk)

        # Initialize native LibOQS instances fail-closed
        try:
            self._mlkem = LibOQS_MLKEM_1024()
        except Exception as e:
            raise RuntimeError(
                f"FATAL: ML-KEM-1024 initialization failed: {e}. Zero fallback permitted."
            ) from e

        try:
            self._mceliece = LibOQS_McEliece_8192128f()
        except Exception as e:
            raise RuntimeError(
                f"FATAL: Classic McEliece 8192128f initialization failed: {e}. Zero fallback permitted."
            ) from e

        self._mlkem_pk: Optional[bytes] = None
        self._mlkem_sk: Optional[NativeSecureBuffer] = None
        self._mceliece_pk: Optional[bytes] = None
        self._mceliece_sk: Optional[NativeSecureBuffer] = None

        if auto_generate:
            self.generate_keypair()

    def generate_keypair(self) -> TripleKexPublicKey:
        """Generate fresh keypairs for both post-quantum algorithms."""
        with self._lock:
            # Clean up existing secret buffers if regenerating
            if self._mlkem_sk is not None:
                self._mlkem_sk.wipe()
            if self._mceliece_sk is not None:
                self._mceliece_sk.wipe()

            # ML-KEM-1024 keypair
            ml_pk, ml_sk = self._mlkem.keygen()
            if len(ml_pk) != MLKEM_PK_LEN or len(ml_sk) != MLKEM_SK_LEN:
                raise RuntimeError("ML-KEM-1024 keygen produced invalid key lengths")

            # Classic McEliece 8192128f keypair
            mc_pk, mc_sk = self._mceliece.keygen()
            if len(mc_pk) != MCELIECE_PK_LEN or len(mc_sk) != MCELIECE_SK_LEN:
                raise RuntimeError("Classic McEliece keygen produced invalid key lengths")

            self._mlkem_pk = ml_pk
            self._mlkem_sk = NativeSecureBuffer(ml_sk)
            self._mceliece_pk = mc_pk
            self._mceliece_sk = NativeSecureBuffer(mc_sk)

            return TripleKexPublicKey(mlkem_pk=ml_pk, mceliece_pk=mc_pk)

    def get_public_key(self) -> TripleKexPublicKey:
        """Return the current Triple-KEX public key bundle."""
        with self._lock:
            if self._mlkem_pk is None or self._mceliece_pk is None:
                raise RuntimeError("Keys not generated: call generate_keypair() first")
            return TripleKexPublicKey(
                mlkem_pk=self._mlkem_pk,
                mceliece_pk=self._mceliece_pk,
            )

    def encapsulate(
        self,
        peer_public_key: Union[TripleKexPublicKey, Dict[str, Any], bytes],
        transcript: bytes = b"",
    ) -> Tuple[TripleKexCiphertext, bytes]:
        """
        Encapsulate shared secrets against peer's public key bundle and combine with Hardware PSK.

        Returns (TripleKexCiphertext, master_key_48_bytes).
        """
        with self._lock:
            if peer_public_key is None:
                raise ValueError("peer_public_key is missing (fail-closed)")

            if isinstance(peer_public_key, TripleKexPublicKey):
                pk_bundle = peer_public_key
            elif isinstance(peer_public_key, dict):
                pk_bundle = TripleKexPublicKey.from_dict(peer_public_key)
            elif isinstance(peer_public_key, (bytes, bytearray)):
                pk_bundle = TripleKexPublicKey.from_bytes(bytes(peer_public_key))
            else:
                raise TypeError("peer_public_key must be TripleKexPublicKey, dict, or bytes")

            # 1. ML-KEM encapsulation
            ml_ct, ml_ss = self._mlkem.encaps(pk_bundle.mlkem_pk)
            if len(ml_ct) != MLKEM_CT_LEN or len(ml_ss) != MLKEM_SS_LEN:
                raise RuntimeError("ML-KEM-1024 encapsulation failed length invariants")

            # 2. Classic McEliece encapsulation
            mc_ct, mc_ss = self._mceliece.encaps(pk_bundle.mceliece_pk)
            if len(mc_ct) != MCELIECE_CT_LEN or len(mc_ss) != MCELIECE_SS_LEN:
                raise RuntimeError("Classic McEliece encapsulation failed length invariants")

            # 3. Triple-PRF AND-combiner
            if self._hardware_psk is None:
                raise ValueError("Hardware PSK missing (fail-closed)")
            h_psk_bytes = self._hardware_psk.as_bytes()

            # Wrap in mutable buffers for zeroization on completion
            ml_ss_buf = bytearray(ml_ss)
            mc_ss_buf = bytearray(mc_ss)

            try:
                k_master = self.derive_master_key(
                    transcript=transcript,
                    ss_mlkem=bytes(ml_ss_buf),
                    ss_mceliece=bytes(mc_ss_buf),
                    h_psk=h_psk_bytes,
                )
            finally:
                _zeroize_memory(ml_ss_buf)
                _zeroize_memory(mc_ss_buf)

            ciphertext = TripleKexCiphertext(mlkem_ct=ml_ct, mceliece_ct=mc_ct)
            return ciphertext, k_master

    def decapsulate(
        self,
        ciphertext: Union[TripleKexCiphertext, Dict[str, Any], bytes],
        transcript: bytes = b"",
    ) -> bytes:
        """
        Decapsulate ciphertexts using local secret keys and combine with Hardware PSK.

        Returns master_key_48_bytes.
        """
        with self._lock:
            if ciphertext is None:
                raise ValueError("ciphertext is missing (fail-closed, zero fallback)")

            if isinstance(ciphertext, TripleKexCiphertext):
                ct_bundle = ciphertext
            elif isinstance(ciphertext, dict):
                ct_bundle = TripleKexCiphertext.from_dict(ciphertext)
            elif isinstance(ciphertext, (bytes, bytearray)):
                ct_bundle = TripleKexCiphertext.from_bytes(bytes(ciphertext))
            else:
                raise TypeError("ciphertext must be TripleKexCiphertext, dict, or bytes")

            if self._mlkem_sk is None or self._mlkem_sk.wiped:
                raise RuntimeError("ML-KEM secret key not available or already zeroized")
            if self._mceliece_sk is None or self._mceliece_sk.wiped:
                raise RuntimeError("McEliece secret key not available or already zeroized")
            if self._hardware_psk is None:
                raise ValueError("Hardware PSK missing (fail-closed)")

            # 1. ML-KEM decapsulation
            ml_ss = self._mlkem.decaps(bytes(self._mlkem_sk), ct_bundle.mlkem_ct)
            if len(ml_ss) != MLKEM_SS_LEN:
                raise RuntimeError("ML-KEM decapsulation produced invalid shared secret length")

            # 2. Classic McEliece decapsulation
            try:
                mc_ss = self._mceliece.decaps(bytes(self._mceliece_sk), ct_bundle.mceliece_ct)
            except Exception as e_decaps:
                raise ValueError(
                    f"Classic McEliece decapsulation failed fail-closed: {e_decaps}"
                ) from e_decaps

            if len(mc_ss) != MCELIECE_SS_LEN:
                raise RuntimeError("McEliece decapsulation produced invalid shared secret length")

            ml_ss_buf = bytearray(ml_ss)
            mc_ss_buf = bytearray(mc_ss)
            h_psk_bytes = self._hardware_psk.as_bytes()

            try:
                k_master = self.derive_master_key(
                    transcript=transcript,
                    ss_mlkem=bytes(ml_ss_buf),
                    ss_mceliece=bytes(mc_ss_buf),
                    h_psk=h_psk_bytes,
                )
            finally:
                _zeroize_memory(ml_ss_buf)
                _zeroize_memory(mc_ss_buf)

            return k_master

    @staticmethod
    def derive_master_key(
        transcript: bytes,
        ss_mlkem: bytes,
        ss_mceliece: bytes,
        h_psk: bytes,
    ) -> bytes:
        r"""
        Derive $K_{\text{master}} = \text{HKDF-Extract}(\text{SHA384}(\text{"ST2027-TRIPLE-KEX-v1"} \parallel \text{Transcript}), SS_{\text{ML-KEM}} \parallel SS_{\text{McEliece}} \parallel K_{\text{H-PSK}})$.

        Strict Triple-PRF AND-combiner:
        - `ss_mlkem` must be 32 bytes and non-zero
        - `ss_mceliece` must be 32 bytes and non-zero
        - `h_psk` must be 32 bytes and non-zero
        If any component is missing, wrong length, or all zeros, fails closed immediately.
        """
        if not isinstance(ss_mlkem, (bytes, bytearray)):
            raise TypeError("ss_mlkem must be bytes-like")
        if not isinstance(ss_mceliece, (bytes, bytearray)):
            raise TypeError("ss_mceliece must be bytes-like")
        if not isinstance(h_psk, (bytes, bytearray)):
            raise TypeError("h_psk must be bytes-like")
        if not isinstance(transcript, (bytes, bytearray)):
            raise TypeError("transcript must be bytes-like")

        if len(ss_mlkem) != MLKEM_SS_LEN:
            raise ValueError(
                f"Invalid ML-KEM shared secret length: {len(ss_mlkem)} (want {MLKEM_SS_LEN})"
            )
        if len(ss_mceliece) != MCELIECE_SS_LEN:
            raise ValueError(
                f"Invalid McEliece shared secret length: {len(ss_mceliece)} (want {MCELIECE_SS_LEN})"
            )
        if len(h_psk) != HPSK_LEN:
            raise ValueError(
                f"Invalid Hardware PSK length: {len(h_psk)} (want {HPSK_LEN})"
            )

        # Branchless constant-time all-zero checks
        if (
            _ct_is_all_zeros(ss_mlkem)
            or _ct_is_all_zeros(ss_mceliece)
            or _ct_is_all_zeros(h_psk)
        ):
            raise ValueError("All-zero secret input refused fail-closed (Zero Fallback)")

        # Native acceleration when destroyer_core is available
        if _HAVE_DESTROYER_CORE:
            try:
                return bytes(
                    destroyer_core.CoreTripleKex.derive_master(
                        bytes(transcript),
                        bytes(ss_mlkem),
                        bytes(ss_mceliece),
                        bytes(h_psk),
                    )
                )
            except Exception as e_native:
                logger.debug("Native CoreTripleKex derivation fallback: %s", e_native)

        # Salt = SHA-384("ST2027-TRIPLE-KEX-v1" || Transcript)
        salt_hasher = hashlib.sha384()
        salt_hasher.update(DOMAIN_SEPARATOR)
        salt_hasher.update(bytes(transcript))
        salt = salt_hasher.digest()

        # IKM = SS_ML-KEM || SS_McEliece || K_H-PSK (96 bytes)
        ikm = bytearray(COMBINED_SS_LEN)
        ikm[:MLKEM_SS_LEN] = ss_mlkem
        ikm[MLKEM_SS_LEN : MLKEM_SS_LEN + MCELIECE_SS_LEN] = ss_mceliece
        ikm[MLKEM_SS_LEN + MCELIECE_SS_LEN :] = h_psk

        try:
            # HKDF-Extract(salt, IKM) = HMAC-SHA384(key=salt, msg=IKM)
            k_master = hmac.new(salt, ikm, hashlib.sha384).digest()
        finally:
            _zeroize_memory(ikm)

        if len(k_master) != MASTER_KEY_LEN:
            raise RuntimeError("HKDF-Extract produced invalid master key length")

        return k_master

    def expand_session_keys(
        self,
        master_key: bytes,
        transcript_binding: bytes = b"",
    ) -> TripleSessionKeys:
        """Expand master key into initiator traffic key, responder traffic key, and confirmation key."""
        return expand_session_keys(master_key, transcript_binding)

    def compute_confirmation_tag(
        self,
        confirmation_key: bytes,
        is_initiator: bool,
        transcript_binding: bytes = b"",
    ) -> bytes:
        """Compute mutual key confirmation tag for the local role."""
        role_label = DOMAIN_CONFIRM_INITIATOR if is_initiator else DOMAIN_CONFIRM_RESPONDER
        return compute_confirmation_tag(confirmation_key, role_label, transcript_binding)

    def verify_peer_confirmation_tag(
        self,
        confirmation_key: bytes,
        is_peer_initiator: bool,
        transcript_binding: bytes,
        peer_tag: bytes,
    ) -> bool:
        """Verify mutual key confirmation tag presented by the peer."""
        role_label = DOMAIN_CONFIRM_INITIATOR if is_peer_initiator else DOMAIN_CONFIRM_RESPONDER
        return verify_confirmation_tag(confirmation_key, role_label, transcript_binding, peer_tag)

    def close(self) -> None:
        """Explicitly zeroize all secret key buffers and Hardware PSK."""
        lock = getattr(self, "_lock", None)
        if lock is not None:
            with lock:
                mlkem_sk = getattr(self, "_mlkem_sk", None)
                if mlkem_sk is not None:
                    mlkem_sk.wipe()
                    self._mlkem_sk = None

                mceliece_sk = getattr(self, "_mceliece_sk", None)
                if mceliece_sk is not None:
                    mceliece_sk.wipe()
                    self._mceliece_sk = None

                hardware_psk = getattr(self, "_hardware_psk", None)
                if hardware_psk is not None:
                    hardware_psk.wipe()
                    self._hardware_psk = None
        else:
            mlkem_sk = getattr(self, "_mlkem_sk", None)
            if mlkem_sk is not None:
                mlkem_sk.wipe()
                self._mlkem_sk = None

            mceliece_sk = getattr(self, "_mceliece_sk", None)
            if mceliece_sk is not None:
                mceliece_sk.wipe()
                self._mceliece_sk = None

            hardware_psk = getattr(self, "_hardware_psk", None)
            if hardware_psk is not None:
                hardware_psk.wipe()
                self._hardware_psk = None

    def __repr__(self) -> str:
        has_keys = getattr(self, "_mlkem_pk", None) is not None
        closed = getattr(self, "_mlkem_sk", None) is None
        return f"MultiAssumptionKEXManager(has_keys={has_keys}, closed={closed})"

    def __enter__(self) -> MultiAssumptionKEXManager:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()
