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
