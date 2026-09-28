#!/usr/bin/env python3
"""Two-person critical-release authority (nuclear-release discipline).

Technical enforcement of the two-person integrity rule for the CRITICAL
message class: no critical payload transmits unless TWO DISTINCT operators
independently authorize within one release ceremony. Verifiers live in RAM
only (never disk); failures fail closed with lockout.

Limits honestly stated: passphrases arrive as Python `str` (immutable —
wiped by dereference + GC, not guaranteed erasure); use getpass (no echo)
at call sites. This enforces procedure in code; it does not replace the
institutional ceremony (cleared operators, witnessed handling, ATO).
"""

import hashlib
import hmac
import logging
import os
import secrets

logger = logging.getLogger(__name__)

PBKDF2_ITERATIONS = 210_000  # OWASP 2023 floor for PBKDF2-SHA512
MAX_OPERATORS = 2
MAX_FAILURES = 5


class ReleaseAuthError(Exception):
    """Raised for any release-ceremony violation (fail closed)."""


class CriticalReleaseAuthority:
    """RAM-only two-operator authorization for critical releases."""

    def __init__(self):
        # operator_id -> (salt: bytes, verifier: bytes)
        self._verifiers = {}
        self._failures = 0
        self._locked = False

    @property
    def locked(self) -> bool:
        return self._locked

    @property
    def enrolled(self) -> int:
        return len(self._verifiers)

    def enroll(self, operator_id: str, passphrase: str) -> None:
        """Enroll one of exactly two distinct operators for this session."""
        if self._locked:
            raise ReleaseAuthError("authority locked after failures")
        if not operator_id or not passphrase:
            raise ReleaseAuthError("operator id and passphrase required")
        if operator_id in self._verifiers:
            raise ReleaseAuthError("operator already enrolled")
        if len(self._verifiers) >= MAX_OPERATORS:
            raise ReleaseAuthError("exactly two operators per session")
        salt = secrets.token_bytes(32)
        verifier = hashlib.pbkdf2_hmac(
            "sha512", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        self._verifiers[operator_id] = (salt, verifier)

    def _check(self, operator_id: str, passphrase: str) -> bool:
        entry = self._verifiers.get(operator_id)
        if entry is None:
            return False
        salt, expected = entry
        candidate = hashlib.pbkdf2_hmac(
            "sha512", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        ok = hmac.compare_digest(candidate, expected)
        del candidate
        return ok

    def _enforce_admin_rbac(self, *, requester_role=None,
                              requester_peer_id=None,
                              zero_trust_engine=None) -> None:
        """Require ADMIN for critical_release. Backward-compat allow unless strict."""
        # Engine-backed check (preferred when caller has a ZeroTrustEngine).
        if zero_trust_engine is not None and requester_peer_id is not None:
            try:
                check = getattr(zero_trust_engine, "check_permission", None)
                if callable(check):
                    check(requester_peer_id, "critical_release")
                    return
            except Exception as e:
                # check_permission raises AuthenticationFailure on deny in
                # strict mode; convert to ceremony error + lockout accounting.
                self._register_failure()
                raise ReleaseAuthError(f"RBAC denied critical_release: {e}") from e
            # Engine without check_permission API -> fall through to role logic.
        if requester_role is not None:
            role_val = getattr(requester_role, "value", requester_role)
            if str(role_val).lower() != "admin":
                self._register_failure()
                raise ReleaseAuthError(
                    f"RBAC denied critical_release: ADMIN required (got '{role_val}')"
                )
            return
        if os.environ.get("P2P_RBAC_STRICT") == "1":
            # Deny-by-default: no role proof supplied in strict mode.
            self._register_failure()
            raise ReleaseAuthError(
                "RBAC strict: ADMIN role required for critical_release "
                "(deny-by-default; pass requester_role='admin' or "
                "zero_trust_engine+requester_peer_id)"
            )
        # Non-strict (default): allow for backward compat with existing
        # tests/callers that do not pass role proof.
        logger.debug("RBAC non-strict: critical_release proceeding without role proof")

    def authorize(self, id1: str, pw1: str, id2: str, pw2: str, *,
                    requester_role=None, requester_peer_id=None,
                    zero_trust_engine=None) -> tuple:
        """Joint authorization by two DISTINCT enrolled operators.

        Returns (id1, id2) on success. Any failure increments the counter;
        5 failures lock the authority for the session. Fail closed always.

        Minimal-RBAC hardening (non-breaking):
          - Action guarded: ``critical_release`` requires ADMIN.
          - If ``zero_trust_engine`` + ``requester_peer_id`` are supplied,
            delegates to ``engine.check_permission(peer, "critical_release")``.
          - Else if ``requester_role`` is supplied, requires ADMIN
            (accepts "admin"/Role.ADMIN, case-insensitive).
          - Else backward-compat allow, unless P2P_RBAC_STRICT=1 which is
            deny-by-default (fail closed, no role proof -> deny).
        """
        self._enforce_admin_rbac(
            requester_role=requester_role,
            requester_peer_id=requester_peer_id,
            zero_trust_engine=zero_trust_engine,
        )
        if self._locked:
            raise ReleaseAuthError("authority locked after failures")
        if len(self._verifiers) != MAX_OPERATORS:
            raise ReleaseAuthError("two operators must be enrolled first")
        if not id1 or not id2 or id1 == id2:
            self._register_failure()
            raise ReleaseAuthError("two DISTINCT operators required")
        ok1 = self._check(id1, pw1)
        ok2 = self._check(id2, pw2)
        # Wipe caller-visible copies best-effort (strs are immutable; the
        # authoritative wipe happens when callers del + gc after return).
        del pw1, pw2
        if not (ok1 and ok2):
            self._register_failure()
            raise ReleaseAuthError("joint authorization failed")
        self._failures = 0
        return (id1, id2)

    def _register_failure(self) -> None:
        self._failures += 1
        if self._failures >= MAX_FAILURES:
            self._locked = True
            self._verifiers.clear()

    def reset(self) -> None:
        """Wipe all verifiers (session end / compromise response)."""
        for op_id in list(self._verifiers.keys()):
            salt, verifier = self._verifiers.pop(op_id)
            try:
                for i in range(len(salt)):
                    salt[i] = 0
            except TypeError:
                pass  # bytes immutable; drop reference
            del verifier
        self._failures = 0
        self._locked = False

    @staticmethod
    def session_environ_ready() -> bool:
        """Operational preconditions for a critical ceremony."""
        return (
            os.environ.get("P2P_REQUIRE_AUTH", "true").lower() == "true"
            and os.environ.get("P2P_DATA_PLANE", "python").lower() in ("rust", "rust_udp", "udp")
        )
