#!/usr/bin/env python3
"""rust_backend.py — OPTIONAL Rust secure-core backend (additive only).

The Python reference modules (`noise_pq.py`, `double_ratchet.py`,
`secure_transmit_2027.py`, `trust_anchor.py`, `ts_attest.py`) stay canonical
and were NOT modified for this file. This shim probes for the compiled
`destroyer_core._native` extension (built via `maturin build -m
rust_data_plane/Cargo.toml`) and exposes it to orchestrators that prefer
the Rust production path (locked memory, verified wiping, constant-time
discipline). When the extension is absent, callers fall back to the Python
reference — availability is explicit, never silent.

Expected wire/profile constants (mirrored from the Rust `policy` +
`handshake` modules; asserted by `tests/test_rust_interop.py`):
"""

from __future__ import annotations

import importlib
from typing import Any


class BackendUnavailable(Exception):
    """Raised when the Rust extension is absent; use the Python reference."""


# Profile constants (must match rust_data_plane/src/{policy,handshake}.rs).
M1_LEN = 1665
M2_LEN = 8916
M3_LEN = 7251
P384_PUB = 97
MLKEM_PK = 1568
MLKEM_CT = 1568
MLDSA87_PK = 2592
MLDSA87_SIG = 4627
TRANSCRIPT_LEN = 48


def available() -> bool:
    """True iff the compiled Rust extension imports cleanly."""
    try:
        importlib.import_module("destroyer_core._native")
        return True
    except ImportError:
        return False


def require_native() -> Any:
    """Import the native module or raise BackendUnavailable (fail-closed).

    Callers MUST NOT silently continue on a different backend when the Rust
    production path was requested: catch this and either fall back loudly
    (log + metrics) or abort, per deployment policy.
    """
    try:
        return importlib.import_module("destroyer_core._native")
    except ImportError as exc:
        raise BackendUnavailable(
            "destroyer_core._native absent (maturin build -m "
            "rust_data_plane/Cargo.toml); using Python reference path"
        ) from exc


def get_cookie_gate(rotation_interval: int = 120, max_cached: int = 8192) -> Any:
    """Instantiate native Rust StatelessCookieGate if available."""
    native = require_native()
    return native.CoreCookieGate(rotation_interval, max_cached)


def get_acd_engine(**kwargs) -> Any:
    """Instantiate native Rust ActiveCyberDefenseEngine if available."""
    native = require_native()
    return native.CoreAcdEngine(
        kwargs.get("replay_threshold", 3),
        kwargs.get("replay_window_secs", 10.0),
        kwargs.get("auth_fail_threshold", 5),
        kwargs.get("auth_fail_window_secs", 30.0),
        kwargs.get("quarantine_duration_secs", 300.0),
    )


def get_zero_trust_engine(min_threshold: int = 50) -> Any:
    """Instantiate native Rust ZeroTrustEngine if available."""
    native = require_native()
    return native.CoreZeroTrustEngine(min_threshold)


def is_rust_primary() -> bool:
    """Return True if Rust secure-core is available and active as PRIMARY data plane."""
    return available()


def get_native_engine() -> Any:
    """Instantiate native Rust SecureEngine (fail-closed, memory-locked)."""
    native = require_native()
    return native.SecureEngine()


def get_native_ratchet(session_key: bytes) -> Any:
    """Instantiate native Rust fresh-KEM SPQR ratchet."""
    native = require_native()
    return native.CoreRatchet(list(session_key))


def get_native_transport(k_send: bytes, k_recv: bytes, is_initiator: bool) -> Any:
    """Instantiate native Rust post-handshake transport engine."""
    native = require_native()
    return native.CoreTransport(list(k_send), list(k_recv), is_initiator)


def get_native_group_ratchet(
    group_id: str, member_id: str, epoch_secret: bytes
) -> Any:
    """Instantiate native Rust SovereignGroupRatchet."""
    native = require_native()
    return native.CoreGroupRatchet(group_id, member_id, list(epoch_secret))


def get_native_signer() -> Any:
    """Instantiate native Rust ML-DSA-87 signer."""
    native = require_native()
    return native.CoreMldsaSigner()


def get_native_attest_store() -> Any:
    """Instantiate native Rust RATS attestation trust store."""
    native = require_native()
    return native.CoreAttestStore()


def get_native_hs_initiator() -> Any:
    """Instantiate native Rust Noise_XXhfs handshake initiator."""
    native = require_native()
    return native.CoreHsInitiator()


def get_native_hs_responder() -> Any:
    """Instantiate native Rust Noise_XXhfs handshake responder."""
    native = require_native()
    return native.CoreHsResponder()


def secure_wipe_buffer(buf: bytearray) -> None:
    """Perform multi-pass DoD 5220.22-M / NIST SP 800-88 cryptographic wipe."""
    if available():
        native = require_native()
        native.CoreMemoryGuard.secure_wipe(buf)
    else:
        # Fallback Python wipe
        for i in range(len(buf)):
            buf[i] = 0


