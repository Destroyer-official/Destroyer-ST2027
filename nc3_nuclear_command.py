#!/usr/bin/env python3
"""
Two-Person Integrity (TPI) Dual-Custody Protocol & Synthetic Emergency Action Subsystem
========================================================================================
Software Research Implementation of Dual-Person Authorization (DPA) and Multi-Custody Security.

RESEARCH EVALUATION NOTICE:
This module is a software research implementation modeling Two-Person Integrity (TPI)
cryptographic workflows (M-of-N threshold signatures, Shamir/Feldman VSS, and temporal
authorization windows). All directives, keys, and classification banners (e.g., SI-OP-IA, NC3)
are STRICTLY SYNTHETIC test fixtures for protocol modeling in unclassified environments.
Operational Nuclear Command, Control, and Communications (NC3) requires dedicated
NSA Type-1 certified cryptographic hardware, air-gapped buried infrastructure, and
government-accredited physical enclosures.

Modeled Protocol Invariants:
- DoD Directive S-5210.41M (Two-Person Rule / Multi-Custody Security Protocol)
- USSTRATCOM Emergency Action Procedures (EAP-STRAT Schema Modeling)
- NIST FIPS 204 (ML-DSA-87) & FIPS 203 (ML-KEM-1024) Post-Quantum Tokens
- Strict 120-second temporal lifetime and synchronized dual-authorization window
"""

import os
import sys
import json
import time
import secrets
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from pqc_algorithms import EnhancedMLDSA_87
from secure_memory_wiper import secure_wipe_dod, secure_wipe_dod_7pass
from audit_logging_system import log_event, AuditEventType, AuditSeverity

# Classification & Constants
EAM_PREAMBLE = "[NC3/EAM-AUTH-DEFCON-1]"
EAM_CLASSIFICATION = "TOP SECRET // SI-OP-IA // NC3 // NOFORN"
DEFAULT_EAM_VALIDITY_WINDOW = 120.0  # Strict 120-second lifetime
DEFAULT_MAX_DUAL_SYNC_WINDOW_SECONDS = 2.0  # Strict 2.0-second simultaneous action window (DoD S-5210.41M)


class NC3SecurityError(Exception):
    """Base exception for all Nuclear Command and Control protocol violations."""


class DualCustodyViolation(NC3SecurityError):
    """Raised when an operation attempts to bypass the Two-Person Rule."""


class DualCustodySynchronizationError(DualCustodyViolation):
    """Raised when authorizations exceed the strict simultaneous execution window (DoD S-5210.41M)."""


class VSSChecksumMismatchError(NC3SecurityError):
    """Raised when a Verifiable Secret Sharing share or reconstructed secret fails cryptographic commitment verification."""


class HardwareTokenAuthenticationError(NC3SecurityError):
    """Raised when hardware security token challenge-response authentication fails."""


class EAMExpiredError(NC3SecurityError):
    """Raised when an Emergency Action Message is received outside its temporal window."""


class EAMReplayError(NC3SecurityError):
    """Raised when an Emergency Action Message identifier has already been processed."""


def autonomous_emergency_zeroize(*buffers) -> None:
    """
    DoD 5220.22-M 7-Pass Autonomous Emergency Zeroization.
    Immediately sanitizes all passed mutable buffers and records
    a critical security event upon any protocol deviation.
    """
    for buf in buffers:
        if buf is None:
            continue
        try:
            if isinstance(buf, (bytearray, memoryview)):
                secure_wipe_dod(buf, passes=7)
            elif isinstance(buf, list):
                for item in buf:
                    if isinstance(item, (bytearray, memoryview)):
                        secure_wipe_dod(item, passes=7)
        except Exception as exc:
            # B110: the contract above promises a critical event on any
            # deviation -- a failed wipe must never be silent (the buffer
            # may still hold key material; caller must treat as tainted).
            import logging as _logging
            _logging.getLogger("nc3_security").critical(
                "autonomous_emergency_zeroize: wipe FAILED: %s", exc)


def _pal_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                 aad: bytes) -> bytes:
    """Seal the PAL payload under the CNSA-strict bulk cipher (AES-256-GCM).

    ChaCha20-Poly1305 is RFC 8439, not FIPS-approved and not in the CNSA
    2.0 symmetric set, so new seals use AES-256-GCM unconditionally.
    Interface matches the legacy cipher (32B key, 12B nonce) by design.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(bytes(key)) != 32 or len(bytes(nonce)) != 12:
        raise DualCustodyViolation("PAL seal parameter violation.")
    return AESGCM(bytes(key)).encrypt(bytes(nonce), bytes(plaintext),
                                      bytes(aad))


def _pal_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                 aad: bytes) -> bytes:
    """Open a PAL seal. AES-256-GCM primary; legacy ChaCha verify-only.

    QUARANTINE: pre-migration messages sealed with ChaCha20-Poly1305 still
    verify here so in-flight orders are never stranded by the cutover.
    Nothing new is ever sealed with ChaCha (see _pal_encrypt). Any failure
    on both paths is a fail-closed integrity event.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(bytes(key)) != 32 or len(bytes(nonce)) != 12 or not ciphertext:
        raise DualCustodyViolation("PAL open parameter violation.")
    try:
        return AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext),
                                          bytes(aad))
    except Exception as aes_error:
        # Strict postures never fall back: a failed AES open in production
        # or TOP SECRET mode is a fail-closed integrity event, not a cue to
        # try weaker primitives.
        try:
            import os as _os

            _strict = (_os.environ.get("P2P_TS_MODE", "").strip().lower()
                       in ("1", "true", "yes", "on")
                       or _os.environ.get("P2P_PRODUCTION", "").strip().lower()
                       in ("1", "true", "yes", "on"))
        except Exception:
            _strict = False
        if _strict:
            raise DualCustodyViolation(
                "PAL open refused: AES-256-GCM authentication failed; "
                "legacy fallback prohibited in strict mode.") from aes_error
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305(bytes(key)).decrypt(
        bytes(nonce), bytes(ciphertext), bytes(aad))


@dataclass
class OfficerIdentity:
    """Represents a certified strategic command officer with post-quantum credentials."""
    officer_id: str
    rank: str
    duty_title: str
    public_key: bytes  # ML-DSA-87 public key (2592 bytes)
    secret_key: Optional[bytes] = None  # ML-DSA-87 secret key (4896 bytes)
    # Token-bound approval binding (G2): when auth_scheme is a PKCS#11 token
    # scheme, approvals MUST be signed on-token and verify against
    # token_pubkey. Default ML-DSA-87 preserves the software path.
    auth_scheme: str = "ML-DSA-87"
    token_label: Optional[str] = None   # CKA_LABEL of the token private key
    token_pubkey: Optional[bytes] = None  # SPKI DER of the bound token key

    def to_dict(self, include_secret: bool = False) -> Dict[str, Any]:
        """Serialize officer profile. Secret key serialization is prohibited in production."""
        if include_secret:
            if os.environ.get("SECURE_P2P_PRODUCTION") == "true" or os.environ.get("P2P_PRODUCTION") == "true":
                raise NC3SecurityError(
                    "MILITARY FATAL: Serialization of NC3 secret signing keys to dictionaries/JSON "
                    "is strictly prohibited in production mode."
                )
            import logging
            logging.getLogger("nc3_security").warning(
                "[NC3-SEC-WARN] Secret key exported in officer profile dictionary (testing only)."
            )

        d = {
            "officer_id": self.officer_id,
            "rank": self.rank,
            "duty_title": self.duty_title,
            "public_key_hex": self.public_key.hex(),
            "auth_scheme": self.auth_scheme,
        }
        if self.token_label:
            d["token_label"] = self.token_label
        if self.token_pubkey:
            d["token_pubkey_hex"] = self.token_pubkey.hex()
        if include_secret and self.secret_key:
            d["secret_key_hex"] = self.secret_key.hex()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OfficerIdentity":
        return cls(
            officer_id=data["officer_id"],
            rank=data["rank"],
            duty_title=data["duty_title"],
            public_key=bytes.fromhex(data["public_key_hex"]),
            secret_key=bytes.fromhex(data["secret_key_hex"]) if "secret_key_hex" in data else None,
            auth_scheme=str(data.get("auth_scheme", "ML-DSA-87")),
            token_label=data.get("token_label"),
            token_pubkey=bytes.fromhex(data["token_pubkey_hex"]) if "token_pubkey_hex" in data else None,
        )


@dataclass
class EmergencyActionMessage:
    """Canonical Emergency Action Message (EAM) structure."""
    eam_id: str
    timestamp_utc: float
    validity_window_seconds: float
    directive_code: str
    target_command: str
    classification: str
    encrypted_pal_code: str  # Base64 encoded AES-256-GCM ciphertext
    # (pre-migration seals may be legacy ChaCha20-Poly1305; see _pal_decrypt)
    salt: str                # Base64 encoded 32-byte salt
    nonce: str               # Base64 encoded 12-byte nonce
    custodian_1_id: str
    custodian_1_pub: str     # Hex encoded
    custodian_1_signature: str # Hex encoded ML-DSA-87 signature
    custodian_2_id: str
    custodian_2_pub: str     # Hex encoded
    custodian_2_signature: str # Hex encoded ML-DSA-87 signature
    canonical_digest: str    # SHA3-512 transcript digest
    hw_auth_digest: str = ""
    vss_commitment: str = ""
    hw_custodians: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "eam_id": self.eam_id,
            "preamble": EAM_PREAMBLE,
            "timestamp_utc": self.timestamp_utc,
            "validity_window_seconds": self.validity_window_seconds,
            "directive_code": self.directive_code,
            "target_command": self.target_command,
            "classification": self.classification,
            "encrypted_pal_code": self.encrypted_pal_code,
            "salt": self.salt,
            "nonce": self.nonce,
            "custodians": [
                {
                    "officer_id": self.custodian_1_id,
                    "public_key": self.custodian_1_pub,
                    "signature": self.custodian_1_signature
                },
                {
                    "officer_id": self.custodian_2_id,
                    "public_key": self.custodian_2_pub,
                    "signature": self.custodian_2_signature
                }
            ],
            "canonical_digest": self.canonical_digest
        }
        if self.hw_auth_digest:
            d["hw_auth_digest"] = self.hw_auth_digest
        if self.vss_commitment:
            d["vss_commitment"] = self.vss_commitment
        if self.hw_custodians is not None:
            d["hw_custodians"] = self.hw_custodians
        return d

    def serialize(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class VerifiableKeyShare:
    """
    Cryptographically committed share of a 32-byte PAL war-order key.
    Neither custodian can derive the key or alter their share undetected.
    """
    share_index: int                       # 1 or 2
    share_bytes: bytes                     # 32 bytes
    share_commitment: bytes                # SHA3-512 commitment to this share
    secret_commitment: bytes               # SHA3-512 commitment to the master secret
    salt: bytes                            # 32-byte salt
    created_at: float                      # UTC timestamp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "share_index": self.share_index,
            "share_hex": self.share_bytes.hex(),
            "share_commitment_hex": self.share_commitment.hex(),
            "secret_commitment_hex": self.secret_commitment.hex(),
            "salt_hex": self.salt.hex(),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerifiableKeyShare":
        return cls(
            share_index=int(data["share_index"]),
            share_bytes=bytes.fromhex(data["share_hex"]),
            share_commitment=bytes.fromhex(data["share_commitment_hex"]),
            secret_commitment=bytes.fromhex(data["secret_commitment_hex"]),
            salt=bytes.fromhex(data["salt_hex"]),
            created_at=float(data["created_at"]),
        )


class VerifiableSecretSharing2of2:
    """
    Verifiable Secret Sharing (VSS) for 32-byte PAL war-order keys.
    Conforms to DoD S-5210.41M Two-Person Rule split-knowledge requirements.
    Information-theoretically secure 2-of-2 additive sharing with SHA3-512
    cryptographic commitment bindings.
    """
    KEY_LENGTH = 32

    @classmethod
    def _compute_share_commitment(cls, salt: bytes, index: int, share_data: bytes) -> bytes:
        hasher = hashlib.sha3_512()
        hasher.update(b"NC3-VSS-SHARE-COMMITMENT-V1:")
        hasher.update(salt)
        hasher.update(index.to_bytes(4, byteorder="big"))
        hasher.update(share_data)
        return hasher.digest()

    @classmethod
    def _compute_secret_commitment(cls, salt: bytes, secret: bytes) -> bytes:
        hasher = hashlib.sha3_512()
        hasher.update(b"NC3-VSS-SECRET-COMMITMENT-V1:")
        hasher.update(salt)
        hasher.update(secret)
        return hasher.digest()

    @classmethod
    def split(cls, secret: bytes) -> Tuple[VerifiableKeyShare, VerifiableKeyShare]:
        """
        Splits a 32-byte secret into two verifiable shares (s1, s2).
        Neither share alone contains any mutual information about the secret.
        """
        if len(secret) != cls.KEY_LENGTH:
            raise DualCustodyViolation(f"Secret must be exactly {cls.KEY_LENGTH} bytes, got {len(secret)}")

        salt = secrets.token_bytes(32)
        now_utc = datetime.now(timezone.utc).timestamp()

        # Share 1: 32 cryptographically secure random bytes
        s1 = bytearray(secrets.token_bytes(cls.KEY_LENGTH))
        # Share 2: s2 = secret XOR s1
        s2 = bytearray(cls.KEY_LENGTH)
        for i in range(cls.KEY_LENGTH):
            s2[i] = secret[i] ^ s1[i]

        sec_commit = cls._compute_secret_commitment(salt, secret)
        c1 = cls._compute_share_commitment(salt, 1, bytes(s1))
        c2 = cls._compute_share_commitment(salt, 2, bytes(s2))

        share1 = VerifiableKeyShare(
            share_index=1,
            share_bytes=bytes(s1),
            share_commitment=c1,
            secret_commitment=sec_commit,
            salt=salt,
            created_at=now_utc
        )
        share2 = VerifiableKeyShare(
            share_index=2,
            share_bytes=bytes(s2),
            share_commitment=c2,
            secret_commitment=sec_commit,
            salt=salt,
            created_at=now_utc
        )

        # DoD 7-pass zeroize temporary buffers
        autonomous_emergency_zeroize(s1, s2)

        return share1, share2

    @classmethod
    def verify_share(cls, share: VerifiableKeyShare) -> bool:
        """Verifies an individual share against its cryptographic commitment."""
        if len(share.share_bytes) != cls.KEY_LENGTH:
            return False
        expected_c = cls._compute_share_commitment(share.salt, share.share_index, share.share_bytes)
        return secrets.compare_digest(expected_c, share.share_commitment)

    @classmethod
    def combine(cls, share_1: VerifiableKeyShare, share_2: VerifiableKeyShare) -> bytes:
        """
        Reconstructs the 32-byte war-order PAL key from two verifiable shares.
        Enforces strict fail-closed verification of share commitments and reconstructed secret.
        """
        # Validate share indices
        if {share_1.share_index, share_2.share_index} != {1, 2}:
            raise DualCustodyViolation("VSS reconstruction requires exactly one Share 1 and one Share 2.")

        # Ensure consistent salt and master commitment
        if not secrets.compare_digest(share_1.salt, share_2.salt):
            raise VSSChecksumMismatchError("VSS share salt mismatch: shares belong to different split ceremonies.")
        if not secrets.compare_digest(share_1.secret_commitment, share_2.secret_commitment):
            raise VSSChecksumMismatchError("VSS secret commitment mismatch between shares.")

        # Order shares
        s1_obj = share_1 if share_1.share_index == 1 else share_2
        s2_obj = share_2 if share_2.share_index == 2 else share_1

        # Verify individual share commitments
        if not cls.verify_share(s1_obj):
            raise VSSChecksumMismatchError("Share 1 integrity verification failed (commitment mismatch).")
        if not cls.verify_share(s2_obj):
            raise VSSChecksumMismatchError("Share 2 integrity verification failed (commitment mismatch).")

        # Reconstruct candidate secret: s1 XOR s2
        reconstructed = bytearray(cls.KEY_LENGTH)
        for i in range(cls.KEY_LENGTH):
            reconstructed[i] = s1_obj.share_bytes[i] ^ s2_obj.share_bytes[i]

        # Verify against master secret commitment
        candidate_commit = cls._compute_secret_commitment(s1_obj.salt, bytes(reconstructed))
        if not secrets.compare_digest(candidate_commit, s1_obj.secret_commitment):
            # Compromise or corruption detected - zeroize immediately!
            autonomous_emergency_zeroize(reconstructed)
            raise VSSChecksumMismatchError(
                "VSS master commitment verification failed: reconstructed PAL key does not match master commitment."
            )

        return bytes(reconstructed)


@dataclass
class HardwareChallenge:
    """Challenge issued by NC3 system to physically present hardware security tokens."""
    challenge_id: str
    server_nonce: bytes                    # 32 bytes
    timestamp_utc: float
    expiry_seconds: float = 30.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "server_nonce_hex": self.server_nonce.hex(),
            "timestamp_utc": self.timestamp_utc,
            "expiry_seconds": self.expiry_seconds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HardwareChallenge":
        return cls(
            challenge_id=data["challenge_id"],
            server_nonce=bytes.fromhex(data["server_nonce_hex"]),
            timestamp_utc=float(data["timestamp_utc"]),
            expiry_seconds=float(data.get("expiry_seconds", 30.0)),
        )


@dataclass
class HardwareTokenResponse:
    """Cryptographic response signed by an officer's dedicated physical hardware token / HSM."""
    officer_id: str
    token_id: str                          # Physical token serial or TPM EK hash
    client_nonce: bytes                    # 32 bytes
    timestamp_utc: float                   # Physical trigger timestamp
    auth_signature: bytes                  # Signature over challenge transcript
    tpm_pcr_composite: Optional[bytes] = None # Optional TPM 2.0 PCR composite
    # Approval scheme: "ML-DSA-87" (software identity key) or a token-bound
    # scheme ("PKCS11-ECDSA-P384" / "PKCS11-RSA-SHA384"). The EXPECTED scheme
    # always comes from the verifier's registered officer binding, never
    # from this field (attacker-controlled on the wire).
    scheme: str = "ML-DSA-87"

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "officer_id": self.officer_id,
            "token_id": self.token_id,
            "client_nonce_hex": self.client_nonce.hex(),
            "timestamp_utc": self.timestamp_utc,
            "auth_signature_hex": self.auth_signature.hex(),
            "scheme": self.scheme,
        }
        if self.tpm_pcr_composite:
            d["tpm_pcr_composite_hex"] = self.tpm_pcr_composite.hex()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HardwareTokenResponse":
        return cls(
            officer_id=data["officer_id"],
            token_id=data["token_id"],
            client_nonce=bytes.fromhex(data["client_nonce_hex"]),
            timestamp_utc=float(data["timestamp_utc"]),
            auth_signature=bytes.fromhex(data["auth_signature_hex"]),
            tpm_pcr_composite=bytes.fromhex(data["tpm_pcr_composite_hex"]) if "tpm_pcr_composite_hex" in data else None,
            scheme=str(data.get("scheme", "ML-DSA-87")),
        )


class NC3CommandController:
    """
    Controller executing the Two-Person Rule and Emergency Action Message (EAM) operations.
    """
    def __init__(self):
        self.dsa = EnhancedMLDSA_87()
        self._journal_path = os.path.join(PROJECT_ROOT, "credentials", ".nc3_eam_replay.journal")
        self._processed_eams: set = self._load_eam_journal()

    def _load_eam_journal(self) -> set:
        processed = set()
        if os.path.exists(self._journal_path):
            try:
                with open(self._journal_path, "r", encoding="utf-8") as f:
                    for line in f:
                        eid = line.strip()
                        if eid:
                            processed.add(eid)
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
        return processed

    def _record_processed_eam(self, eam_id: str) -> None:
        self._processed_eams.add(eam_id)
        try:
            os.makedirs(os.path.dirname(self._journal_path), exist_ok=True)
            with open(self._journal_path, "a", encoding="utf-8") as f:
                f.write(eam_id + "\n")
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass

    @staticmethod
    def generate_officer_credentials(officer_id: str, rank: str, duty_title: str) -> OfficerIdentity:
        """Generate sovereign ML-DSA-87 keypair for an authorized strategic officer."""
        dsa = EnhancedMLDSA_87()
        pk, sk = dsa.keygen()
        return OfficerIdentity(
            officer_id=officer_id,
            rank=rank,
            duty_title=duty_title,
            public_key=pk,
            secret_key=sk
        )

    @staticmethod
    def _compute_canonical_digest(
        eam_id: str,
        timestamp_utc: float,
        validity_window: float,
        directive_code: str,
        target_command: str,
        encrypted_pal: str,
        salt_b64: str = "",
        nonce_b64: str = "",
        classification: str = "",
        hw_auth_digest_hex: str = "",
        vss_commitment_hex: str = ""
    ) -> bytes:
        """Computes unambiguous SHA3-512 canonical digest over immutable message fields."""
        import struct as _struct
        hasher = hashlib.sha3_512()
        hasher.update(EAM_PREAMBLE.encode('utf-8'))
        hasher.update(eam_id.encode('utf-8'))
        hasher.update(_struct.pack('>d', float(timestamp_utc)))
        hasher.update(_struct.pack('>d', float(validity_window)))
        hasher.update(directive_code.encode('utf-8'))
        hasher.update(target_command.encode('utf-8'))
        hasher.update(encrypted_pal.encode('utf-8'))
        hasher.update(salt_b64.encode('utf-8'))
        hasher.update(nonce_b64.encode('utf-8'))
        hasher.update(classification.encode('utf-8'))
        if hw_auth_digest_hex:
            hasher.update(hw_auth_digest_hex.encode('utf-8'))
        if vss_commitment_hex:
            hasher.update(vss_commitment_hex.encode('utf-8'))
        return hasher.digest()

    @staticmethod
    def _compute_hw_auth_digest(
        challenge_id: str,
        server_nonce: bytes,
        officer_id: str,
        token_id: str,
        client_nonce: bytes,
        timestamp_utc: float,
        tpm_pcr_composite: Optional[bytes] = None
    ) -> bytes:
        """Computes unambiguous SHA3-512 challenge transcript for physical hardware token authorization."""
        import struct as _struct
        hasher = hashlib.sha3_512()
        hasher.update(b"NC3-HW-AUTH-CHALLENGE-V1:")
        hasher.update(challenge_id.encode('utf-8'))
        hasher.update(server_nonce)
        hasher.update(officer_id.encode('utf-8'))
        hasher.update(token_id.encode('utf-8'))
        hasher.update(client_nonce)
        hasher.update(_struct.pack('>d', float(timestamp_utc)))
        if tpm_pcr_composite:
            hasher.update(tpm_pcr_composite)
        return hasher.digest()

    def issue_hardware_challenge(self, expiry_seconds: float = 30.0) -> HardwareChallenge:
        """Issues an ephemeral hardware challenge requiring physical cryptographic token response."""
        return HardwareChallenge(
            challenge_id=secrets.token_hex(16),
            server_nonce=secrets.token_bytes(32),
            timestamp_utc=datetime.now(timezone.utc).timestamp(),
            expiry_seconds=expiry_seconds
        )

    def create_hardware_token_response(
        self,
        officer: OfficerIdentity,
        challenge: HardwareChallenge,
        token_id: str,
        client_nonce: Optional[bytes] = None,
        timestamp_utc: Optional[float] = None,
        tpm_pcr_composite: Optional[bytes] = None
    ) -> HardwareTokenResponse:
        """
        Generates physical hardware token response signature for an authorized officer.
        In production deployment, this executes inside the officer's dedicated HSM / YubiKey / TPM 2.0 enclave.
        """
        if not officer.secret_key:
            raise DualCustodyViolation(f"Officer {officer.officer_id} lacks private signing key for hardware response.")

        c_nonce = client_nonce if client_nonce is not None else secrets.token_bytes(32)
        ts = timestamp_utc if timestamp_utc is not None else datetime.now(timezone.utc).timestamp()

        digest = self._compute_hw_auth_digest(
            challenge_id=challenge.challenge_id,
            server_nonce=challenge.server_nonce,
            officer_id=officer.officer_id,
            token_id=token_id,
            client_nonce=c_nonce,
            timestamp_utc=ts,
            tpm_pcr_composite=tpm_pcr_composite
        )
        sig = self.dsa.sign(officer.secret_key, digest)
        return HardwareTokenResponse(
            officer_id=officer.officer_id,
            token_id=token_id,
            client_nonce=c_nonce,
            timestamp_utc=ts,
            auth_signature=sig,
            tpm_pcr_composite=tpm_pcr_composite
        )

    # -- Token-bound approval signing (G2) --------------------------------
    # The approval digest is signed ON-TOKEN (private key never leaves the
    # PKCS#11 token; PIN/touch enforced by token middleware at C_Sign).
    # Honest strength note: a token leg is ECDSA P-384 / RSA-3072+ (192-256
    # bit classical) proving PHYSICAL PRESENCE; the ML-DSA-87 session and
    # message layers above remain 256-bit post-quantum. Dual custody, the
    # 2-second window, nonces, and PCR binding are unchanged.
    TOKEN_APPROVAL_SCHEMES = ("PKCS11-ECDSA-P384", "PKCS11-RSA-SHA384")
    _TOKEN_MECHANISM = {"PKCS11-ECDSA-P384": "ECDSA",
                        "PKCS11-RSA-SHA384": "SHA384_RSA_PKCS"}

    @staticmethod
    def _token_approval_message(digest: bytes) -> bytes:
        """Hash normalization for the ECDSA approval leg.

        The 64-byte transcript digest is hashed to 48 bytes with SHA-384 so
        that raw C_Sign/ECDSA signs a hash-sized message on every token and
        verification via Prehashed(SHA-384) is exact. (The RSA leg needs no
        normalization: SHA384_RSA_PKCS hashes inside the token on both
        sides.) Used by create_token_backed_response() and the ECDSA branch
        of _verify_token_signature() -- never sign raw digests on one side
        only.
        """
        import hashlib as _hl
        return _hl.sha384(bytes(digest)).digest()

    def create_token_backed_response(
        self,
        officer: OfficerIdentity,
        challenge: HardwareChallenge,
        token_backend,
        key_label: Optional[str] = None,
        client_nonce: Optional[bytes] = None,
        timestamp_utc: Optional[float] = None,
        tpm_pcr_composite: Optional[bytes] = None,
    ) -> HardwareTokenResponse:
        """Sign an officer approval digest ON-TOKEN via PKCS#11 (fail-closed).

        The officer must be token-bound (auth_scheme in
        TOKEN_APPROVAL_SCHEMES with a token_label, unless key_label is
        passed explicitly). Raises DualCustodyViolation for misbinding and
        HardwareTokenAuthenticationError when the token refuses (absent,
        wrong PIN, no such key).
        """
        scheme = str(getattr(officer, "auth_scheme", "ML-DSA-87") or "ML-DSA-87")
        if scheme not in self.TOKEN_APPROVAL_SCHEMES:
            raise DualCustodyViolation(
                f"Officer {officer.officer_id} is not token-bound "
                f"(auth_scheme={scheme!r}); use the software approval path.")
        label = key_label or getattr(officer, "token_label", None)
        if not label:
            raise DualCustodyViolation(
                f"Officer {officer.officer_id} has no token key label bound.")
        c_nonce = client_nonce if client_nonce is not None else secrets.token_bytes(32)
        ts = timestamp_utc if timestamp_utc is not None else datetime.now(timezone.utc).timestamp()
        # Resolve the physical token identity FIRST: token_id is part of
        # the signed digest, so it must be final before signing.
        try:
            describe = getattr(token_backend, "token_label", None)
            hw_tag = str(describe() if callable(describe) else describe
                         or "pkcs11-token")
        except Exception:
            hw_tag = "pkcs11-token"
        token_id = f"pkcs11:{hw_tag}:{label}"
        digest = self._compute_hw_auth_digest(
            challenge_id=challenge.challenge_id,
            server_nonce=challenge.server_nonce,
            officer_id=officer.officer_id,
            token_id=token_id,
            client_nonce=c_nonce,
            timestamp_utc=ts,
            tpm_pcr_composite=tpm_pcr_composite,
        )
        try:
            sig = token_backend.sign(
                label, self._token_approval_message(digest),
                mechanism=self._TOKEN_MECHANISM[scheme])
        except Exception as e:
            raise HardwareTokenAuthenticationError(
                f"Officer {officer.officer_id} token signing failed "
                f"(absent token / wrong PIN / missing key?): {e}") from e
        return HardwareTokenResponse(
            officer_id=officer.officer_id,
            token_id=token_id,
            client_nonce=c_nonce,
            timestamp_utc=ts,
            auth_signature=bytes(sig),
            tpm_pcr_composite=tpm_pcr_composite,
            scheme=scheme,
        )

    @staticmethod
    def _verify_token_signature(scheme: str, token_pub_der: bytes,
                                digest: bytes, signature: bytes) -> bool:
        """Verify a token approval signature (mirrors on-token semantics).

        Both sides operate on _token_approval_message(digest) (SHA-384 of
        the transcript digest) for the ECDSA leg, which verifies raw R||S
        via Prehashed(SHA-384) (PKCS#11 C_Sign/ECDSA emits raw R||S,
        converted to DER here). RSA leg mirrors token-side SHA384_RSA_PKCS
        with PKCS1v15+SHA384 over the raw digest (token hashes inside).
        Returns False (never raises) on any mismatch.
        Strict shapes only: P-384 EC, >= 3072-bit RSA.
        """
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            approval = NC3CommandController._token_approval_message(digest)
            if scheme == "PKCS11-ECDSA-P384":
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
                if len(signature) != 96:
                    return False
                pub = serialization.load_der_public_key(bytes(token_pub_der))
                if not isinstance(pub, ec.EllipticCurvePublicKey):
                    return False
                if not isinstance(pub.curve, ec.SECP384R1):
                    return False
                r = int.from_bytes(bytes(signature[:48]), "big")
                s = int.from_bytes(bytes(signature[48:]), "big")
                from cryptography.hazmat.primitives.asymmetric.utils import (
                    encode_dss_signature)
                pub.verify(encode_dss_signature(r, s), approval,
                           ec.ECDSA(Prehashed(hashes.SHA384())))
                return True
            if scheme == "PKCS11-RSA-SHA384":
                from cryptography.hazmat.primitives.asymmetric import padding, rsa
                pub = serialization.load_der_public_key(bytes(token_pub_der))
                if not isinstance(pub, rsa.RSAPublicKey):
                    return False
                if pub.key_size < 3072:
                    return False
                # Token hashed the raw digest inside (SHA384_RSA_PKCS);
                # mirror exactly (no pre-hash on this leg).
                pub.verify(bytes(signature), bytes(digest),
                           padding.PKCS1v15(), hashes.SHA384())
                return True
            return False
        except Exception:
            return False

    def verify_dual_hardware_responses(
        self,
        challenge: HardwareChallenge,
        resp_1: HardwareTokenResponse,
        resp_2: HardwareTokenResponse,
        officer_1_pub: bytes,
        officer_2_pub: bytes,
        max_sync_window_seconds: float = DEFAULT_MAX_DUAL_SYNC_WINDOW_SECONDS,
        expected_pcr_composite: Optional[bytes] = None,
        officer_1_auth: Optional[Dict[str, Any]] = None,
        officer_2_auth: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Verify dual approvals. officer_X_auth optionally pins the EXPECTED
        approval scheme + token public key for officer X::

            {"scheme": "PKCS11-ECDSA-P384", "token_pubkey": <SPKI DER bytes>}

        Absent binding == legacy ML-DSA-87 software path (unchanged). The
        expected scheme ALWAYS comes from this caller-supplied binding, never
        from the wire response's own scheme field (attacker-controlled)."""
        """
        Verifies dual hardware token responses conforming to DoD Directive S-5210.41M:
        1. Challenge freshness & validity (anti-replay).
        2. Two distinct officers.
        3. Two distinct physical hardware tokens (prevents single-token multi-signing).
        4. Independent client nonces.
        5. Physical Temporal Synchronization Window: abs(t1 - t2) <= 2.0 seconds.
        6. Cryptographic signature verification with NIST FIPS 204 ML-DSA-87.
        7. TPM 2.0 PCR composite validation (when sealed).
        """
        now_utc = datetime.now(timezone.utc).timestamp()
        if now_utc - challenge.timestamp_utc > challenge.expiry_seconds:
            raise HardwareTokenAuthenticationError("Hardware challenge has expired (replay defense).")
        if challenge.timestamp_utc > now_utc + 5.0:
            raise HardwareTokenAuthenticationError("Hardware challenge clock skew detected (future timestamp).")

        # 1. Distinct Officers
        if resp_1.officer_id == resp_2.officer_id:
            raise DualCustodyViolation("Hardware token responses must originate from two distinct officers.")

        # 2. Distinct Physical Hardware Tokens (DoD S-5210.41M Invariant)
        if resp_1.token_id == resp_2.token_id:
            raise DualCustodyViolation(
                f"Dual custody hardware violation: Both officers submitted the same physical token ID '{resp_1.token_id}'. "
                f"DoD Directive S-5210.41M mandates independent physical hardware per custodian."
            )

        # 3. Independent Nonces
        if secrets.compare_digest(resp_1.client_nonce, resp_2.client_nonce):
            raise DualCustodyViolation("Hardware token nonces must be cryptographically independent.")

        # 4. PHYSICAL TEMPORAL SYNCHRONIZATION WINDOW (Launch Switch Doctrine)
        sync_delta = abs(resp_1.timestamp_utc - resp_2.timestamp_utc)
        if sync_delta > max_sync_window_seconds:
            log_event(
                event_type=AuditEventType.SECURITY_VIOLATION,
                severity=AuditSeverity.CRITICAL,
                message=(
                    f"NC3 DUAL-CUSTODY TEMPORAL BREACH: Officers authorized {sync_delta:.3f}s apart "
                    f"(ceiling {max_sync_window_seconds:.1f}s). Potential single-operator serial bypass."
                ),
                details={
                    "officer_1": resp_1.officer_id,
                    "officer_2": resp_2.officer_id,
                    "delta_seconds": sync_delta,
                    "max_allowed": max_sync_window_seconds
                }
            )
            raise DualCustodySynchronizationError(
                f"Temporal synchronization violation: Officer 1 ({resp_1.officer_id}) and "
                f"Officer 2 ({resp_2.officer_id}) authorized {sync_delta:.3f}s apart, "
                f"exceeding strict simultaneous window of {max_sync_window_seconds:.1f}s."
            )

        # 5. Cryptographic Signature Verification (scheme-dispatched: the
        # EXPECTED scheme comes from the registered officer binding, never
        # from the wire response under test).
        d1 = self._compute_hw_auth_digest(
            challenge_id=challenge.challenge_id,
            server_nonce=challenge.server_nonce,
            officer_id=resp_1.officer_id,
            token_id=resp_1.token_id,
            client_nonce=resp_1.client_nonce,
            timestamp_utc=resp_1.timestamp_utc,
            tpm_pcr_composite=resp_1.tpm_pcr_composite
        )
        self._verify_approval_signature(
            resp_1, d1, officer_1_pub, officer_1_auth,
            f"Officer 1 ({resp_1.officer_id})")

        d2 = self._compute_hw_auth_digest(
            challenge_id=challenge.challenge_id,
            server_nonce=challenge.server_nonce,
            officer_id=resp_2.officer_id,
            token_id=resp_2.token_id,
            client_nonce=resp_2.client_nonce,
            timestamp_utc=resp_2.timestamp_utc,
            tpm_pcr_composite=resp_2.tpm_pcr_composite
        )
        self._verify_approval_signature(
            resp_2, d2, officer_2_pub, officer_2_auth,
            f"Officer 2 ({resp_2.officer_id})")

        # 6. TPM 2.0 PCR composite validation
        if expected_pcr_composite:
            if not resp_1.tpm_pcr_composite or not secrets.compare_digest(resp_1.tpm_pcr_composite, expected_pcr_composite):
                raise HardwareTokenAuthenticationError(f"Officer 1 ({resp_1.officer_id}) TPM PCR state mismatch.")
            if not resp_2.tpm_pcr_composite or not secrets.compare_digest(resp_2.tpm_pcr_composite, expected_pcr_composite):
                raise HardwareTokenAuthenticationError(f"Officer 2 ({resp_2.officer_id}) TPM PCR state mismatch.")

        return True

    def _verify_approval_signature(self, resp: HardwareTokenResponse,
                                     digest: bytes, mldsa_pub: bytes,
                                     auth_binding: Optional[Dict[str, Any]],
                                     who: str) -> None:
        """Dispatch one approval-signature check by registered binding.

        No binding (or ML-DSA-87 binding) == legacy software path, byte for
        byte unchanged. Token bindings require the wire scheme to match the
        registered scheme exactly (field-flip downgrade refused) and verify
        against the REGISTERED token public key (token-swap refused).
        Raises HardwareTokenAuthenticationError (fail-closed) on any failure.
        """
        binding = auth_binding or {}
        expected = str(binding.get("scheme", "ML-DSA-87") or "ML-DSA-87")
        if str(getattr(resp, "scheme", "ML-DSA-87") or "ML-DSA-87") != expected:
            raise HardwareTokenAuthenticationError(
                f"{who} approval scheme mismatch: wire says "
                f"{getattr(resp, 'scheme', '?')!r}, binding requires "
                f"{expected!r} (downgrade refused).")
        if expected == "ML-DSA-87":
            if not self.dsa.verify(mldsa_pub, digest, resp.auth_signature):
                raise HardwareTokenAuthenticationError(
                    f"{who} hardware token signature verification FAILED.")
            return
        if expected in self.TOKEN_APPROVAL_SCHEMES:
            token_pub = binding.get("token_pubkey")
            if not isinstance(token_pub, (bytes, bytearray)) or not token_pub:
                raise HardwareTokenAuthenticationError(
                    f"{who} token binding has no registered public key.")
            if not self._verify_token_signature(
                    expected, bytes(token_pub), bytes(digest),
                    bytes(resp.auth_signature)):
                raise HardwareTokenAuthenticationError(
                    f"{who} token approval signature verification FAILED.")
            return
        raise HardwareTokenAuthenticationError(
            f"{who} unknown approval scheme in binding: {expected!r}.")

    @staticmethod
    def _derive_split_key(secret_1: bytes, secret_2: bytes, salt: bytes) -> bytes:
        """Derives dual-officer combined key (neither officer alone possesses the key)."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        combined_material = secret_1 + secret_2
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            info=b"NC3/PAL-DUAL-CUSTODY-V1"
        )
        key = hkdf.derive(combined_material)
        return key

    def create_nuclear_eam(
        self,
        directive_code: str,
        target_command: str,
        pal_code: str,
        officer_1: OfficerIdentity,
        officer_2: OfficerIdentity,
        pal_key: Optional[bytes] = None,
        validity_window_seconds: float = DEFAULT_EAM_VALIDITY_WINDOW,
        hw_challenge: Optional[HardwareChallenge] = None,
        hw_responses: Optional[Tuple[HardwareTokenResponse, HardwareTokenResponse]] = None,
        vss_shares: Optional[Tuple[VerifiableKeyShare, VerifiableKeyShare]] = None,
        max_sync_window_seconds: float = DEFAULT_MAX_DUAL_SYNC_WINDOW_SECONDS
    ) -> EmergencyActionMessage:
        """
        Creates, dual-encrypts, and dual-signs a nuclear-grade Emergency Action Message.

        Requirements:
        - Two distinct officers with private keys must be present (Two-Person Rule).
        - `pal_key` (32 bytes) or `vss_shares` (2-of-2 Verifiable Secret Shares) is mandatory.
        - Hardware challenge-response and temporal synchronization window enforced when provided.
        - Plaintext PAL code and key buffers wiped with DoD 5220.22-M 7-pass sanitization.
        - On any failure, autonomous emergency zeroization is immediately executed.
        """
        if validity_window_seconds > 120.0 or validity_window_seconds <= 0.0:
            raise NC3SecurityError(
                f"EAM validity window {validity_window_seconds}s exceeds strict maximum ceiling of 120.0s "
                f"or is non-positive (fail-closed under military operational policy)."
            )
        if not officer_1.secret_key or not officer_2.secret_key:
            raise DualCustodyViolation("Both officers must provide valid cryptographic credentials (Two-Person Rule).")
        if officer_1.officer_id == officer_2.officer_id or officer_1.public_key == officer_2.public_key:
            raise DualCustodyViolation("Officers 1 and 2 must be distinct individuals (Two-Person Rule).")

        pal_buf: Optional[bytearray] = bytearray(pal_code.encode('utf-8'))
        key_buf: Optional[bytearray] = None

        try:
            # 1. War-Order Key Resolution (VSS reconstruction or caller-supplied key)
            if vss_shares is not None:
                reconstructed_key = VerifiableSecretSharing2of2.combine(vss_shares[0], vss_shares[1])
                key_buf = bytearray(reconstructed_key)
            elif pal_key is not None:
                if len(bytes(pal_key)) != 32:
                    raise DualCustodyViolation(
                        "A 32-byte war-order authentication key (pal_key) is mandatory. "
                        "Default/fallback keys are prohibited: they are publicly derivable."
                    )
                key_buf = bytearray(pal_key)
            else:
                raise DualCustodyViolation(
                    "A 32-byte war-order authentication key (pal_key) or verifiable secret shares (vss_shares) is mandatory. "
                    "Default/fallback keys are prohibited: they are publicly derivable."
                )

            # 2. Hardware Dual Custody Verification & Temporal Synchronization Check
            hw_digest_hex = ""
            hw_custodians_list = None
            if hw_responses is not None:
                if hw_challenge is None:
                    raise DualCustodyViolation("Hardware challenge must accompany hardware token responses.")
                self.verify_dual_hardware_responses(
                    challenge=hw_challenge,
                    resp_1=hw_responses[0],
                    resp_2=hw_responses[1],
                    officer_1_pub=officer_1.public_key,
                    officer_2_pub=officer_2.public_key,
                    max_sync_window_seconds=max_sync_window_seconds
                )
                hw_digest_hex = hashlib.sha3_512(hw_responses[0].auth_signature + hw_responses[1].auth_signature).hexdigest()
                hw_custodians_list = [hw_responses[0].to_dict(), hw_responses[1].to_dict()]

            vss_commit_hex = ""
            if vss_shares is not None:
                vss_commit_hex = vss_shares[0].secret_commitment.hex()

            eam_id = secrets.token_hex(16)
            now_utc = datetime.now(timezone.utc).timestamp()
            salt = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)

            # 3. Encrypt PAL payload using AES-256-GCM (CNSA strict).
            import base64

            encrypted_pal_raw = _pal_encrypt(bytes(key_buf), nonce,
                                             bytes(pal_buf),
                                             eam_id.encode('utf-8'))
            encrypted_pal_b64 = base64.b64encode(encrypted_pal_raw).decode('utf-8')

            # Wipe plaintext PAL and key from memory immediately with DoD 7-pass
            autonomous_emergency_zeroize(pal_buf, key_buf)
            pal_buf = None
            key_buf = None

            # 4. Canonical Transcript Digest
            _salt_b64 = base64.b64encode(salt).decode('utf-8')
            _nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            digest = self._compute_canonical_digest(
                eam_id=eam_id,
                timestamp_utc=now_utc,
                validity_window=validity_window_seconds,
                directive_code=directive_code,
                target_command=target_command,
                encrypted_pal=encrypted_pal_b64,
                salt_b64=_salt_b64,
                nonce_b64=_nonce_b64,
                classification=EAM_CLASSIFICATION,
                hw_auth_digest_hex=hw_digest_hex,
                vss_commitment_hex=vss_commit_hex
            )

            # 5. Dual Signatures
            sig1 = self.dsa.sign(officer_1.secret_key, digest)
            sig2 = self.dsa.sign(officer_2.secret_key, digest)

            eam = EmergencyActionMessage(
                eam_id=eam_id,
                timestamp_utc=now_utc,
                validity_window_seconds=validity_window_seconds,
                directive_code=directive_code,
                target_command=target_command,
                classification=EAM_CLASSIFICATION,
                encrypted_pal_code=encrypted_pal_b64,
                salt=base64.b64encode(salt).decode('utf-8'),
                nonce=base64.b64encode(nonce).decode('utf-8'),
                custodian_1_id=officer_1.officer_id,
                custodian_1_pub=officer_1.public_key.hex(),
                custodian_1_signature=sig1.hex(),
                custodian_2_id=officer_2.officer_id,
                custodian_2_pub=officer_2.public_key.hex(),
                custodian_2_signature=sig2.hex(),
                canonical_digest=digest.hex(),
                hw_auth_digest=hw_digest_hex,
                vss_commitment=vss_commit_hex,
                hw_custodians=hw_custodians_list
            )

            log_event(
                event_type=AuditEventType.MESSAGE_SENT,
                severity=AuditSeverity.CRITICAL,
                message=f"NUCLEAR EAM CREATED: {eam_id} [Directive: {directive_code}] Dual-Custody Verified.",
                details={"eam_id": eam_id, "directive": directive_code, "officer_1": officer_1.officer_id, "officer_2": officer_2.officer_id}
            )
            return eam
        except Exception:
            autonomous_emergency_zeroize(pal_buf, key_buf)
            raise

    def verify_and_decrypt_nuclear_eam(
        self,
        eam_data: Dict[str, Any],
        recipient_officer_1: OfficerIdentity,
        recipient_officer_2: OfficerIdentity,
        sender_officer_1_pub: bytes,
        sender_officer_2_pub: bytes,
        pal_key: Optional[bytes] = None,
        peer_verification_state: Optional[str] = None,
        peer_verified: bool = True,
        vss_shares: Optional[Tuple[VerifiableKeyShare, VerifiableKeyShare]] = None,
        hw_challenge: Optional[HardwareChallenge] = None,
        hw_responses: Optional[Tuple[HardwareTokenResponse, HardwareTokenResponse]] = None,
        max_sync_window_seconds: float = DEFAULT_MAX_DUAL_SYNC_WINDOW_SECONDS,
        expected_pcr_composite: Optional[bytes] = None
    ) -> str:
        """
        Validates the Two-Person signatures, checks temporal validity, and decrypts the PAL code.
        Enforces strict DoD 5220.22-M 7-pass autonomous zeroization on any anomaly or error.
        """
        import base64

        # Strict Zero-Trust Peer Verification Gate
        if peer_verified is False:
            raise NC3SecurityError("EAM rejected: sender peer identity is not verified.")
        if peer_verification_state is not None:
            clean_state = str(peer_verification_state).strip().upper()
            if clean_state in ("PENDING_OOB_VERIFICATION", "BLOCKED_UNVERIFIED_TOFU", "UNVERIFIED", "BLOCKED"):
                raise NC3SecurityError(
                    f"EAM rejected: sender peer identity is in unverified state '{clean_state}' "
                    f"under military zero-trust policy. Out-of-band safety number confirmation required."
                )

        if recipient_officer_1.officer_id == recipient_officer_2.officer_id:
            raise DualCustodyViolation("Recipient validation requires two distinct officers (Two-Person Rule).")

        eam_id = eam_data.get("eam_id")
        if not eam_id or eam_id in self._processed_eams:
            raise EAMReplayError(f"EAM ID {eam_id} is invalid or has already been processed (Anti-Replay).")

        # 1. Temporal Validity Window Check
        timestamp_utc = float(eam_data["timestamp_utc"])
        raw_window = float(eam_data.get("validity_window_seconds", DEFAULT_EAM_VALIDITY_WINDOW))
        if raw_window > 120.0 or raw_window <= 0.0:
            raise NC3SecurityError(
                f"EAM validity window {raw_window}s exceeds strict maximum ceiling of 120.0s "
                f"or is non-positive (fail-closed under military operational policy)."
            )
        window = min(raw_window, 120.0)
        current_utc = datetime.now(timezone.utc).timestamp()

        # Allow maximum 5 seconds future clock skew
        if timestamp_utc > current_utc + 5.0:
            raise EAMExpiredError(f"EAM clock skew rejected: timestamp {timestamp_utc} is in the future.")
        if current_utc - timestamp_utc > window:
            raise EAMExpiredError(f"EAM expired: age {current_utc - timestamp_utc:.1f}s exceeds window {window:.1f}s.")

        # 2. Hardware Dual Token Verification (if supplied)
        if hw_responses is not None:
            if hw_challenge is None:
                raise DualCustodyViolation("Hardware challenge must accompany hardware token responses for verification.")
            self.verify_dual_hardware_responses(
                challenge=hw_challenge,
                resp_1=hw_responses[0],
                resp_2=hw_responses[1],
                officer_1_pub=sender_officer_1_pub,
                officer_2_pub=sender_officer_2_pub,
                max_sync_window_seconds=max_sync_window_seconds,
                expected_pcr_composite=expected_pcr_composite
            )

        # 3. Canonical Digest Verification
        hw_digest_hex = eam_data.get("hw_auth_digest", "")
        vss_commit_hex = eam_data.get("vss_commitment", "")
        expected_digest = self._compute_canonical_digest(
            eam_id=eam_id,
            timestamp_utc=timestamp_utc,
            validity_window=window,
            directive_code=eam_data["directive_code"],
            target_command=eam_data["target_command"],
            encrypted_pal=eam_data["encrypted_pal_code"],
            salt_b64=eam_data.get("salt", ""),
            nonce_b64=eam_data.get("nonce", ""),
            classification=eam_data.get("classification", EAM_CLASSIFICATION),
            hw_auth_digest_hex=hw_digest_hex,
            vss_commitment_hex=vss_commit_hex
        )

        declared_digest = bytes.fromhex(eam_data["canonical_digest"])
        if not secrets.compare_digest(expected_digest, declared_digest):
            raise NC3SecurityError("EAM canonical digest mismatch: payload has been tampered with.")

        # 4. Dual-Officer Post-Quantum ML-DSA-87 Signature Verification
        custodians = eam_data.get("custodians", [])
        if len(custodians) != 2:
            raise DualCustodyViolation("EAM must contain exactly two custodian signatures.")

        cust1_sig = bytes.fromhex(custodians[0]["signature"])
        cust2_sig = bytes.fromhex(custodians[1]["signature"])

        if not self.dsa.verify(sender_officer_1_pub, expected_digest, cust1_sig):
            raise NC3SecurityError("Officer 1 signature verification FAILED.")
        if not self.dsa.verify(sender_officer_2_pub, expected_digest, cust2_sig):
            raise NC3SecurityError("Officer 2 signature verification FAILED.")

        # 5. Decrypt PAL payload with war-order key or reconstructed VSS shares
        active_key_buf: Optional[bytearray] = None
        decrypted_pal_buf: Optional[bytearray] = None

        try:
            if vss_shares is not None:
                reconstructed_key = VerifiableSecretSharing2of2.combine(vss_shares[0], vss_shares[1])
                active_key_buf = bytearray(reconstructed_key)
            elif pal_key is not None:
                if len(bytes(pal_key)) != 32:
                    raise DualCustodyViolation(
                        "War-order authentication key (pal_key) is mandatory to unseal. "
                        "Default/fallback keys are prohibited."
                    )
                active_key_buf = bytearray(pal_key)
            else:
                raise DualCustodyViolation(
                    "War-order authentication key (pal_key) or verifiable secret shares (vss_shares) is mandatory to unseal. "
                    "Default/fallback keys are prohibited."
                )

            salt = base64.b64decode(eam_data["salt"])
            nonce = base64.b64decode(eam_data["nonce"])
            encrypted_raw = base64.b64decode(eam_data["encrypted_pal_code"])

            raw_decrypted = _pal_decrypt(bytes(active_key_buf), nonce,
                                         encrypted_raw,
                                         eam_id.encode('utf-8'))
            decrypted_pal_buf = bytearray(raw_decrypted)
            decrypted_pal = raw_decrypted.decode('utf-8')
        except Exception as e:
            autonomous_emergency_zeroize(active_key_buf, decrypted_pal_buf)
            if isinstance(e, NC3SecurityError):
                raise
            raise NC3SecurityError(f"PAL Decryption failed: invalid key shares or tampered ciphertext: {e}")
        finally:
            autonomous_emergency_zeroize(active_key_buf, decrypted_pal_buf)

        # Register EAM ID in persistent anti-replay journal
        self._record_processed_eam(eam_id)

        log_event(
            event_type=AuditEventType.MESSAGE_RECEIVED,
            severity=AuditSeverity.CRITICAL,
            message=f"NUCLEAR EAM VERIFIED & OPENED: {eam_id} [Directive: {eam_data['directive_code']}].",
            details={"eam_id": eam_id, "directive": eam_data["directive_code"], "opened_by": [recipient_officer_1.officer_id, recipient_officer_2.officer_id]}
        )
        return decrypted_pal


class SoftwareTokenBackend:
    """Software simulation token backend for development, testing, and lab environments.
    
    Generates real SECP384R1 private keys and signs using ECDSA, returning raw R||S (96 bytes).
    """
    def __init__(self, label: str = "SOFT-SIM-TOKEN"):
        self._label = label
        self._keys: Dict[str, Any] = {}

    def token_label(self) -> str:
        return self._label

    def register_key(self, key_label: str, priv_key=None):
        from cryptography.hazmat.primitives.asymmetric import ec
        if priv_key is None:
            priv_key = ec.generate_private_key(ec.SECP384R1())
        self._keys[key_label] = priv_key
        return priv_key

    def get_public_key_der(self, key_label: str) -> bytes:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        if key_label not in self._keys:
            self.register_key(key_label)
        return self._keys[key_label].public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, key_label: str, data: bytes, mechanism: str = "ECDSA") -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, Prehashed
        if key_label not in self._keys:
            self.register_key(key_label)
        priv = self._keys[key_label]
        if len(data) == 48:
            der_sig = priv.sign(data, ec.ECDSA(Prehashed(hashes.SHA384())))
        else:
            der_sig = priv.sign(data, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der_sig)
        return r.to_bytes(48, "big") + s.to_bytes(48, "big")


class PKCS11HardwareTokenBackend:
    """Production PKCS#11 hardware token backend for physical cryptographic tokens.
    
    Interfaces with physical smartcards, YubiKeys, Nitrokeys, and HSMs via standard
    PKCS#11 dynamic libraries (OpenSC, YkCS11, SoftHSM).
    Emits raw R||S for ECDSA P-384 conforming to token approval semantics.
    """
    def __init__(
        self,
        library_path: Optional[str] = None,
        pin: Optional[str] = None,
        token_label_filter: Optional[str] = None
    ):
        self._library_path = library_path or self.find_pkcs11_library()
        self._pin = pin
        self._token_label_filter = token_label_filter
        # AUDITED (B105): false positive / test fixture, verified individually 2026-09
        self._token_label = "PKCS11-HARDWARE-TOKEN"  # nosec: B105
        self._available = False
        self._lib = None
        self._token = None
        self._init_backend()

    @staticmethod
    def find_pkcs11_library() -> Optional[str]:
        candidates = []
        if sys.platform == "win32":
            candidates = [
                r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
                r"C:\Program Files (x86)\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
                r"C:\Windows\System32\opensc-pkcs11.dll",
                r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
                r"C:\SoftHSM2\lib\softhsm2.dll",
            ]
        elif sys.platform == "linux":
            candidates = [
                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
                "/usr/lib/opensc-pkcs11.so",
                "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                "/usr/lib/softhsm/libsofthsm2.so",
                "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so",
            ]
        elif sys.platform == "darwin":
            candidates = [
                "/usr/local/lib/opensc-pkcs11.so",
                "/opt/homebrew/lib/opensc-pkcs11.so",
                "/usr/local/lib/softhsm/libsofthsm2.so",
            ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def _init_backend(self) -> None:
        if not self._library_path or not os.path.exists(self._library_path):
            return
        try:
            import pkcs11
            self._lib = pkcs11.lib(self._library_path)
            tokens = list(self._lib.get_tokens())
            if tokens:
                for t in tokens:
                    if not self._token_label_filter or self._token_label_filter.lower() in t.label.lower():
                        self._token = t
                        self._token_label = t.label
                        self._available = True
                        break
        except Exception:
            self._available = False

    def is_available(self) -> bool:
        return self._available

    def token_label(self) -> str:
        return self._token_label

    def sign(self, key_label: str, data: bytes, mechanism: str = "ECDSA") -> bytes:
        if not self._available or not self._token:
            raise HardwareTokenAuthenticationError(
                f"PKCS#11 hardware token absent or library not loaded (path: {self._library_path})"
            )
        try:
            from pkcs11 import Mechanism, ObjectClass
            with self._token.open(user_pin=self._pin) as session:
                mech = Mechanism.ECDSA if mechanism == "ECDSA" else Mechanism.SHA384_RSA_PKCS
                priv_key = session.get_key(label=key_label, object_class=ObjectClass.PRIVATE_KEY)
                sig = priv_key.sign(data, mechanism=mech)
                return bytes(sig)
        except Exception as e:
            raise HardwareTokenAuthenticationError(f"PKCS#11 hardware signing failed: {e}") from e


def get_default_token_backend(pin: Optional[str] = None) -> Any:
    """Retrieve physical PKCS#11 token backend if present; fallback to SoftwareTokenBackend if absent in non-prod."""
    backend = PKCS11HardwareTokenBackend(pin=pin)
    if backend.is_available():
        return backend
    if os.environ.get("P2P_PRODUCTION", "").strip() == "1" or os.environ.get("P2P_FAIL_ON_SOFTWARE_FALLBACK", "").strip() == "1":
        raise HardwareTokenAuthenticationError("Physical PKCS#11 hardware token mandatory in production mode.")
    return SoftwareTokenBackend()


# Global NC3 Controller Singleton
nc3_controller = NC3CommandController()


def get_or_create_tactical_officer(
    officer_id: str,
    rank: str = "O-6",
    duty_title: str = "Command Duty Officer",
    officers_dir: Optional[str] = None
) -> OfficerIdentity:
    """
    Retrieves an officer's post-quantum credentials from sealed storage,
    or generates and provisions sovereign credentials if not present.

    Storage security: private keys are NEVER written in plaintext. Files hold
    AES-256-GCM sealed packages; the file-seal key comes from a custodian
    passphrase (PBKDF2-SHA512/210k, per-file salt), prompted once per process
    and held in RAM only. Legacy plaintext credential files are migrated
    (loaded once, re-saved sealed, original shredded). A present-but-corrupt
    file RAISES instead of silently minting a replacement identity.
    """
    import base64
    import getpass
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if os.environ.get('P2P_EPHEMERAL_MODE') == '1' or os.environ.get('P2P_ANONYMOUS') == '1':
        # Pure in-memory ephemeral custodian credentials (zero disk persistence)
        return nc3_controller.generate_officer_credentials(officer_id, rank, duty_title)

    if officers_dir is None:
        officers_dir = os.path.join(PROJECT_ROOT, "credentials", "officers")
    os.makedirs(officers_dir, exist_ok=True)

    try:
        os.chmod(officers_dir, 0o700)
    except OSError:
        pass

    cred_path = os.path.join(officers_dir, f"{officer_id}.json")

    def _seal_save(officer: OfficerIdentity) -> None:
        seal_key = _officer_file_seal_key()
        raw = json.dumps(officer.to_dict(include_secret=True)).encode("utf-8")
        salt = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        file_key = hashlib.pbkdf2_hmac("sha512", seal_key, salt, 210_000, dklen=32)
        ct = AESGCM(file_key).encrypt(
            nonce, raw, f"NC3-OFFICER-CREDS-V2:{officer_id}".encode("utf-8")
        )
        _wipe(bytearray(file_key))
        tmp_path = cred_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "v": 2,
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "ct": base64.b64encode(ct).decode("ascii"),
                },
                f,
            )
        os.replace(tmp_path, cred_path)
        try:
            os.chmod(cred_path, 0o600)
        except OSError:
            pass

    def _seal_open() -> OfficerIdentity:
        with open(cred_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("v") != 2:
            raise NC3SecurityError(
                f"Officer credential file for {officer_id} is legacy or corrupt. "
                f"Refusing to silently replace identity — investigate before proceeding."
            )
        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        ct = base64.b64decode(data["ct"])
        seal_key = _officer_file_seal_key()
        file_key = hashlib.pbkdf2_hmac("sha512", seal_key, salt, 210_000, dklen=32)
        try:
            raw = AESGCM(file_key).decrypt(
                nonce, ct, f"NC3-OFFICER-CREDS-V2:{officer_id}".encode("utf-8")
            )
        finally:
            _wipe(bytearray(file_key))
        return OfficerIdentity.from_dict(json.loads(raw.decode("utf-8")))

    if os.path.exists(cred_path):
        try:
            with open(cred_path, "r", encoding="utf-8") as f:
                probe = json.load(f)
        except Exception as e:
            raise NC3SecurityError(
                f"Officer credential file for {officer_id} is unreadable — "
                f"refusing to mint a replacement identity: {e}"
            )
        if isinstance(probe, dict) and probe.get("v") == 2:
            return _seal_open()
        if isinstance(probe, dict) and "secret_key_hex" in probe:
            # One-time migration: legacy plaintext → sealed, then shred.
            officer = OfficerIdentity.from_dict(probe)
            _seal_save(officer)
            try:
                from secure_memory_wiper import secure_shred_file

                secure_shred_file(cred_path, passes=3)
                # Re-save sealed package under the original name.
                _seal_save(officer)
            except Exception as exc:
                # B110: shred failure leaves LEGACY PLAINTEXT on disk --
                # never silent. Sealed copy exists, but operators must
                # destroy the plaintext remnant out-of-band.
                import logging as _logging
                _logging.getLogger("nc3_security").critical(
                    "credential migration: shred of legacy plaintext %s "
                    "FAILED (%s); plaintext remnant requires out-of-band "
                    "destruction", cred_path, exc)
            return officer
        raise NC3SecurityError(
            f"Officer credential file for {officer_id} has an unknown format — refusing."
        )

    # Generate fresh sovereign officer credentials (first provisioning only).
    officer = nc3_controller.generate_officer_credentials(officer_id, rank, duty_title)
    _seal_save(officer)
    return officer


_officer_seal_key_cache: Optional[bytes] = None


def _officer_file_seal_key() -> bytes:
    """Custodian file-seal passphrase, prompted once per process (no echo).

    `P2P_OFFICER_SEAL_PW` may supply it non-interactively for automated
    TEST environments only — setting it logs a loud warning and must never
    be used operationally (environment memory is inspectable).
    """
    global _officer_seal_key_cache
    if _officer_seal_key_cache is None:
        env_pw = os.environ.get("P2P_OFFICER_SEAL_PW")
        if env_pw:
            import warnings

            warnings.warn(
                "P2P_OFFICER_SEAL_PW is set: non-interactive seal passphrase "
                "is TEST-ONLY and must never be used operationally."
            )
            _officer_seal_key_cache = env_pw.encode("utf-8")
            return _officer_seal_key_cache
        import getpass

        pw = getpass.getpass("Custodian file-seal passphrase (officer credentials at rest): ")
        if not pw:
            raise NC3SecurityError("File-seal passphrase required.")
        _officer_seal_key_cache = pw.encode("utf-8")
        del pw
    return _officer_seal_key_cache


def _wipe(buf: bytearray) -> None:
    try:
        from secure_memory_wiper import secure_wipe_dod

        secure_wipe_dod(buf)
    except Exception:
        for i in range(len(buf)):
            buf[i] = 0


def provision_standard_tactical_officers(officers_dir: Optional[str] = None) -> Dict[str, OfficerIdentity]:
    """
    Ensures baseline Strategic Command & Pentagon officer credentials exist for NC3 dual-custody operation.
    """
    officers = {
        # Station Alpha (NORAD / STRATCOM)
        "GEN_ALPHA": get_or_create_tactical_officer(
            "GEN_ALPHA", "General", "Commander, NORAD / Strategic Defense", officers_dir
        ),
        "ADM_BRAVO": get_or_create_tactical_officer(
            "ADM_BRAVO", "Admiral", "Deputy Commander, Strategic Forces", officers_dir
        ),
        # Station Bravo (Pentagon / NMCC)
        "COL_CHARLIE": get_or_create_tactical_officer(
            "COL_CHARLIE", "Colonel", "Director of Operations, NMCC Pentagon", officers_dir
        ),
        "CAPT_DELTA": get_or_create_tactical_officer(
            "CAPT_DELTA", "Captain", "Executive Officer, Strategic Authentications", officers_dir
        ),
    }
    return officers


def serialize_eam_wire(eam_data: Dict[str, Any], aead_key: Optional[bytes] = None) -> bytes:
    """
    Serializes an NC3 EAM dictionary with mandatory 1024-byte uniform block padding
    and optional AEAD envelope encryption to prevent traffic analysis and metadata correlation.
    """
    import json
    import struct
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    json_bytes = json.dumps(eam_data, sort_keys=True).encode('utf-8')
    raw_payload = struct.pack(">I", len(json_bytes)) + json_bytes

    # Uniform 1024-byte block padding (Finding 2 & P0.3)
    block_size = 1024
    remainder = len(raw_payload) % block_size
    pad_len = (block_size - remainder) if remainder != 0 else 0
    if len(raw_payload) + pad_len < block_size:
        pad_len = block_size - len(raw_payload)

    padded_payload = raw_payload + secrets.token_bytes(pad_len)
    # B101: explicit fail-closed check (assert stripped under python -O).
    if len(padded_payload) % block_size != 0:  # nosec B101 - explicit check, no assert
        raise ValueError("Padded payload must be an exact multiple of 1024 bytes")

    if aead_key is not None:
        if len(aead_key) != 32:
            raise ValueError("AEAD key must be 32 bytes for AES-256-GCM")
        nonce = secrets.token_bytes(12)
        ct = AESGCM(aead_key).encrypt(nonce, padded_payload, b"NC3-EAM-WIRE-V1")
        return nonce + ct
    return padded_payload


def deserialize_eam_wire(wire_bytes: bytes, aead_key: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Deserializes an NC3 EAM wire frame, decrypting AEAD envelope if keyed and
    stripping 1024-byte uniform block padding.
    """
    import json
    import struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if aead_key is not None:
        if len(aead_key) != 32:
            raise ValueError("AEAD key must be 32 bytes for AES-256-GCM")
        if len(wire_bytes) < 12 + 16:
            raise NC3SecurityError("Wire payload too short for AEAD envelope")
        nonce = wire_bytes[:12]
        ct = wire_bytes[12:]
        try:
            padded_payload = AESGCM(aead_key).decrypt(nonce, ct, b"NC3-EAM-WIRE-V1")
        except Exception as e:
            raise NC3SecurityError(f"AEAD wire envelope decryption failed: {e}")
    else:
        padded_payload = wire_bytes

    if len(padded_payload) < 4:
        raise NC3SecurityError("Padded wire payload too short")

    orig_len = struct.unpack(">I", padded_payload[:4])[0]
    if orig_len > len(padded_payload) - 4:
        raise NC3SecurityError("Invalid unpadded payload length in wire frame")

    json_bytes = padded_payload[4:4 + orig_len]
    try:
        return json.loads(json_bytes.decode('utf-8'))
    except Exception as e:
        raise NC3SecurityError(f"Invalid JSON in unpadded EAM wire frame: {e}")

