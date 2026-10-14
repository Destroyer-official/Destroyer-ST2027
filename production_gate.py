"""
production_gate.py — Single source of truth for production/TS security posture.

AUDIT FINDING F-01 REMEDIATION (2026-10-14).
=============================================
Prior to this module, ~25 modules implemented *different* truthy checks for
the same conceptual "production mode"::

    config.py                          -> ('1','true','yes','on')  both vars
    double_ratchet.py:165              -> SECURE == "1" only, P2P in ("1","true")
    forward_secrecy_manager.py:474     -> SECURE == "true" only
    nc3_nuclear_command.py:174         -> == "true" only
    platform_hsm_interface.py:8736     -> SECURE == "1" only
    ... and ~20 more sites

The project's own CI comment (defense_ci.yml) admitted this as
"KNOWN GAP P1": an operator setting ``P2P_PRODUCTION=1`` could believe
every hardening gate was armed while individual modules silently stayed
in lab/TOFU/classical-permissive modes.

Design (production-grade, fail-closed):
--------------------------------------
1. **Canonical truthy set**: ``{'1','true','yes','on'}`` (case-insensitive,
   whitespace-stripped) for BOTH ``P2P_PRODUCTION`` and
   ``SECURE_P2P_PRODUCTION``. Any spelling that config.py accepted is
   accepted here; nothing else is.
2. **Sticky latch**: once True for the process lifetime, always True.
   Clearing the env after latch is detected, logged CRITICAL, and denied.
   (Mirrors config.py:23-52 but is the *only* latch in the codebase.)
3. **Eager re-eval**: each call re-reads the environment so a late
   ``os.environ['P2P_PRODUCTION']='1'`` still arms the gate (import-order
   independent). The sticky bit only ever moves False -> True.
4. **Audit trail**: first True observation and any unset-attempt are
   emitted to the ``audit`` logger.
5. **No third-party imports** at module scope (this module must be
   importable from every corner of the tree, including early bootstrap).

Every security decision that previously inlined ``os.environ.get(...)`` for
production mode MUST call :func:`is_production` instead.
"""

from __future__ import annotations

import logging
import os
import threading

__all__ = [
    "is_production",
    "is_ts_mode",
    "production_reason",
    "force_production",
    "TRUTHY",
    "PRODUCTION_VARS",
]

# Canonical truthy spellings. Keep in sync with config._env_wants_prod.
TRUTHY = frozenset({"1", "true", "yes", "on"})

# The two environment variables that request production posture.
PRODUCTION_VARS = ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION")

# Additional vars that imply TS / strict posture (subset of production
# semantics used by several modules; folded into is_production via
# is_ts_mode callers, NOT auto-promoted here to avoid surprising
# non-TS deployments).
TS_VARS = ("P2P_TS_MODE",)

_lock = threading.Lock()
_sticky: bool = False
_sticky_reason: str = ""
_unset_logged: bool = False
_log = logging.getLogger("production_gate")
_audit = logging.getLogger("audit")


def _truthy(name: str) -> bool:
    val = os.environ.get(name)
    if val is None:
        return False
    return val.strip().lower() in TRUTHY


def _wants() -> tuple[bool, str]:
    """Return (wants_production, reason)."""
    for var in PRODUCTION_VARS:
        raw = os.environ.get(var)
        if raw is None:
            continue
        norm = raw.strip().lower()
        if norm in TRUTHY:
            return True, f"{var}={norm!r}"
        # Explicit falsey values are fine (lab mode).
        if norm in ("0", "false", "no", "off", ""):
            continue
        # Unknown spelling: fail-closed toward lab, but scream — a typo
        # like "tru" must never be silently treated as production AND
        # must never be silently treated as safe either.
        _log.critical(
            "production_gate: %s has unrecognized value %r "
            "(accepted: 1/true/yes/on). Treating as NOT production. "
            "This is fail-open for hardening gates — fix the spelling.",
            var,
            raw,
        )
    return False, ""


def is_production() -> bool:
    """True when this process must enforce production/TS hardening.

    Sticky: once True, remains True for the process lifetime even if the
    operator (or malware) later clears the environment variables.
    """
    global _sticky, _sticky_reason, _unset_logged
    wants, reason = _wants()
    if wants:
        if not _sticky:
            _sticky = True
            _sticky_reason = reason
            msg = f"production_gate: production posture ARMED ({reason})"
            _log.critical(msg)
            try:
                _audit.warning(msg)
            except Exception:  # nosec B110 — audit must never break the gate
                pass
        return True
    if _sticky:
        if not _unset_logged:
            _unset_logged = True
            msg = (
                "production_gate: attempt to unset production mode detected "
                f"(latched by {_sticky_reason}; env no longer requests prod). "
                "Enforcing sticky production (fail-closed)."
            )
            _log.critical(msg)
            try:
                _audit.critical(msg)
            except Exception:  # nosec B110
                pass
        return True
    return False


def is_ts_mode() -> bool:
    """True when sovereign/TS posture is requested OR production is sticky."""
    if is_production():
        return True
    return any(_truthy(v) for v in TS_VARS)


def production_reason() -> str:
    """Human-readable reason production is armed ('' when lab)."""
    is_production()  # ensure latch side-effects ran
    return _sticky_reason


def force_production(reason: str = "forced") -> None:
    """Test/CI helper: latch production without env vars."""
    global _sticky, _sticky_reason
    with _lock:
        _sticky = True
        _sticky_reason = reason
        _log.critical("production_gate: FORCE-ARMED (%s)", reason)


def reset_for_tests() -> None:
    """TEST-ONLY: clear the sticky latch so pytest tests stay isolated.

    Never call this from production code. The test suite installs an
    autouse fixture that calls it around every test (see
    tests/conftest.py) so a test that arms production mode cannot leak
    sticky state into later tests. Production behavior is unaffected:
    without an explicit reset the latch only moves False -> True.
    """
    global _sticky, _sticky_reason, _unset_logged
    with _lock:
        _sticky = False
        _sticky_reason = ""
        _unset_logged = False


# Import-time arm: if the operator launched with production env set, the
# sticky bit is set immediately so import-order cannot create a lab window.
if _wants()[0]:
    is_production()
