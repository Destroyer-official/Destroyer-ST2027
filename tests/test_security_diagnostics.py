#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""
Pytest wrapper for the full-project security diagnostics sweep.

Runs security_diagnostics.py end-to-end (all live probes) and fails if any
check reports FAIL or ERROR. SKIP results (absent pin store, unbuilt Rust
module, etc.) do not fail the suite.
"""

import os
import subprocess  # nosec: B404
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_full_project_security_diagnostics():
    clean_env = {k: v for k, v in os.environ.items() if not (k.upper().startswith("P2P_ALLOW_") or k.upper().startswith("P2P_DISABLE_"))}
    proc = subprocess.run(  # nosec: B603
        [sys.executable, os.path.join(REPO_ROOT, "security_diagnostics.py"), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        env=clean_env,
    )
    assert proc.returncode == 0, (  # nosec: B101
        "security diagnostics reported FAIL/ERROR.\n"
        f"--- stdout ---\n{proc.stdout[-4000:]}\n"
        f"--- stderr ---\n{proc.stderr[-2000:]}"
    )


def test_diagnostics_rejects_live_bypass_overrides():
    """Live ALLOW_* overrides must be refused (runs by default, not gated).

    This probe exercises the production diagnostics entry point in a
    subprocess, so a regression that lets P2P_ALLOW_* overrides through
    is caught in normal CI runs.
    """
    env = dict(os.environ, P2P_ALLOW_LOOPBACK="1")
    proc = subprocess.run(  # nosec: B603
        [sys.executable, os.path.join(REPO_ROOT, "security_diagnostics.py"),
         "--quiet", "--category", "CONFIG"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert proc.returncode == 1, "diagnostics must fail closed on live ALLOW_ overrides"  # nosec: B101

