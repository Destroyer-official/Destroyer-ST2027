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
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from native_secure_buffer import NativeSecureBuffer, wipe_native

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

    def split_release_key(self, raw_key: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """Split a 32-byte release payload key into two sealed shares for enrolled operators.

        Neither operator alone can recover raw_key. Each share is encrypted under an
        operator-specific key derived from their PBKDF2 verifier using HKDF-SHA512.
        """
        if self._locked:
            raise ReleaseAuthError("authority locked after failures")
        if len(self._verifiers) != MAX_OPERATORS:
            raise ReleaseAuthError("two operators must be enrolled first")
        if len(raw_key) != 32:
            raise ValueError("raw_key must be exactly 32 bytes")

        op_ids = list(self._verifiers.keys())
        salt1, verifier1 = self._verifiers[op_ids[0]]
        salt2, verifier2 = self._verifiers[op_ids[1]]

        share1 = bytearray(secrets.token_bytes(32))
        share2 = bytearray(a ^ b for a, b in zip(raw_key, share1))

        # Derive share-encryption keys
        k1 = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt1,
            info=b"CRITICAL_RELEASE_OPERATOR_1_SHARE",
        ).derive(verifier1)
        k2 = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt2,
            info=b"CRITICAL_RELEASE_OPERATOR_2_SHARE",
        ).derive(verifier2)

        nonce1 = secrets.token_bytes(12)
        nonce2 = secrets.token_bytes(12)

        aes1 = AESGCM(k1)
        aes2 = AESGCM(k2)

        enc_share1 = aes1.encrypt(nonce1, bytes(share1), b"TPI_SHARE_1")
        enc_share2 = aes2.encrypt(nonce2, bytes(share2), b"TPI_SHARE_2")

        # Zeroize temporary secret buffers
        wipe_native(share1)
        wipe_native(share2)
        del k1, k2

        return (enc_share1, nonce1, enc_share2, nonce2)

    def combine_release_key(
        self,
        enc_share1: bytes,
        nonce1: bytes,
        enc_share2: bytes,
        nonce2: bytes,
        id1: str,
        pw1: str,
        id2: str,
        pw2: str,
        *,
        requester_role=None,
        requester_peer_id=None,
        zero_trust_engine=None,
    ) -> NativeSecureBuffer:
        """Jointly authorize and reconstruct release key into a protected NativeSecureBuffer.

        Reconstructs raw_key into locked, in-RAM encrypted memory via NativeSecureBuffer.protect().
        """
        self.authorize(
            id1,
            pw1,
            id2,
            pw2,
            requester_role=requester_role,
            requester_peer_id=requester_peer_id,
            zero_trust_engine=zero_trust_engine,
        )

        op_ids = list(self._verifiers.keys())
        salt1, verifier1 = self._verifiers[op_ids[0]]
        salt2, verifier2 = self._verifiers[op_ids[1]]

        k1 = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt1,
            info=b"CRITICAL_RELEASE_OPERATOR_1_SHARE",
        ).derive(verifier1)
        k2 = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt2,
            info=b"CRITICAL_RELEASE_OPERATOR_2_SHARE",
        ).derive(verifier2)

        try:
            aes1 = AESGCM(k1)
            aes2 = AESGCM(k2)
            share1 = bytearray(aes1.decrypt(nonce1, enc_share1, b"TPI_SHARE_1"))
            share2 = bytearray(aes2.decrypt(nonce2, enc_share2, b"TPI_SHARE_2"))
            raw_key = bytearray(a ^ b for a, b in zip(share1, share2))
        except Exception as e:
            self._register_failure()
            raise ReleaseAuthError(f"Share decryption failed: {e}") from e
        finally:
            del k1, k2

        buf = NativeSecureBuffer(raw_key)
        wipe_native(share1)
        wipe_native(share2)
        wipe_native(raw_key)

        buf.protect()
        return buf

    def encrypt_critical_payload(
        self,
        plaintext: bytes,
    ) -> Dict[str, Any]:
        """Encrypt payload with a fresh 256-bit key and generate two sealed shares."""
        raw_key = bytearray(secrets.token_bytes(32))
        enc_share1, nonce1, enc_share2, nonce2 = self.split_release_key(bytes(raw_key))

        payload_nonce = secrets.token_bytes(12)
        aes = AESGCM(bytes(raw_key))
        ciphertext = aes.encrypt(payload_nonce, plaintext, b"CRITICAL_RELEASE_PAYLOAD_V2")
        wipe_native(raw_key)

        return {
            "ciphertext": ciphertext,
            "payload_nonce": payload_nonce,
            "enc_share1": enc_share1,
            "share_nonce1": nonce1,
            "enc_share2": enc_share2,
            "share_nonce2": nonce2,
        }

    def decrypt_critical_payload(
        self,
        bundle: Dict[str, Any],
        id1: str,
        pw1: str,
        id2: str,
        pw2: str,
        *,
        requester_role=None,
        requester_peer_id=None,
        zero_trust_engine=None,
    ) -> bytes:
        """Authenticate both operators and decrypt payload using reconstructed key."""
        key_buf = self.combine_release_key(
            bundle["enc_share1"],
            bundle["share_nonce1"],
            bundle["enc_share2"],
            bundle["share_nonce2"],
            id1,
            pw1,
            id2,
            pw2,
            requester_role=requester_role,
            requester_peer_id=requester_peer_id,
            zero_trust_engine=zero_trust_engine,
        )

        try:
            with key_buf.expose() as key_bytes:
                aes = AESGCM(bytes(key_bytes))
                plaintext = aes.decrypt(
                    bundle["payload_nonce"],
                    bundle["ciphertext"],
                    b"CRITICAL_RELEASE_PAYLOAD_V2",
                )
            return plaintext
        except Exception as e:
            self._register_failure()
            raise ReleaseAuthError(f"Critical payload decryption failed: {e}") from e
        finally:
            key_buf.wipe()

    @staticmethod
    def session_environ_ready() -> bool:
        """Operational preconditions for a critical ceremony."""
        return (
            os.environ.get("P2P_REQUIRE_AUTH", "true").lower() == "true"
            and os.environ.get("P2P_DATA_PLANE", "python").lower() in ("rust", "rust_udp", "udp")
        )
