#!/usr/bin/env python3
"""
DESTROYER STRATEGIC P2P: SOVEREIGN TOP SECRET COMMUNICATIONS NODE
Protocol: NSA CNSA Suite 2.0 / FIPS 203 ML-KEM-1024 / FIPS 204 ML-DSA-87
Data Plane: Hardware-Paced Wire Camouflage & Cauchy-RS Simplex Data Diode
Zero-Trust: Zero Central Servers, Zero Cloud Relays, Zero Metadata Leaks

Canonical implementation consolidated in secure_p2p.py.
This module re-exports the sovereign tactical node components from secure_p2p.
"""

# Re-exported for backwards compatibility with callers/tests that patch
# ``destroyer_tactical_p2p.subprocess``.  It is the same module object used by
# secure_p2p, so patching it here affects the canonical implementation.
import subprocess  # noqa: F401

from secure_p2p import (
    TacticalP2PNode,
    run_interactive_terminal,
    run_automated_two_terminal_drill,
    print_banner,
    _production,
    main,
    RESET,
    BOLD,
    GREEN,
    YELLOW,
    CYAN,
    RED,
    MAGENTA,
    DIM,
    NATIVE_BIN,
    ROOT,
)

if __name__ == "__main__":
    main()
