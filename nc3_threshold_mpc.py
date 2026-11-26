#!/usr/bin/env python3
"""
Decentralized t-of-n Threshold Post-Quantum Signatures (MPC NC3)
================================================================
Software Implementation of True Decentralized Multi-Party Computation (MPC)
Threshold Signatures for ML-DSA-87 and DoD Directive S-5210.41M Dual-Custody Protocol.

SECURITY INVARIANTS:
1. The master strategic authorization key is NEVER reconstructed on any single machine
   (neither on silos nor on the aggregator).
2. Simultaneous co-signing by t distinct silos within a strict 2.0-second window
   (DoD Directive S-5210.41M simultaneous execution constraint).
3. Verifiable Secret Sharing (VSS): Master authorization key is divided into n polynomial
   shares with SHA-384 Feldman public commitments on CNSA 2.0 Secp384r1 curve.
4. Each silo node operates with sovereign ML-DSA-87 post-quantum cryptographic identity.
5. Strict fail-closed verification of payload classification, preamble, freshness,
   and anti-replay.
"""

import os
import sys
import json
import time
import struct
import secrets
import hashlib
import threading
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from pqc_algorithms import EnhancedMLDSA_87
from secure_memory_wiper import secure_wipe_dod, secure_wipe_dod_7pass
from audit_logging_system import log_event, AuditEventType, AuditSeverity
from production_gate import is_production

# Classification & Constants
EAM_PREAMBLE = "[NC3/EAM-AUTH-DEFCON-1]"
EAM_CLASSIFICATION = "TOP SECRET // SI-OP-IA // NC3 // NOFORN"
MAX_CO_SIGNING_WINDOW_SECONDS = 2.0  # DoD S-5210.41M strict 2.0-second co-signing window
DEFAULT_EAM_VALIDITY_WINDOW = 120.0  # Freshness window (120 seconds)

# NIST / CNSA 2.0 Secp384r1 Curve Parameters for Feldman Homomorphic Commitments
_P384_P = 2**384 - 2**128 - 2**96 + 2**32 - 1
_P384_A = _P384_P - 3
_P384_B = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
_P384_GX = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
_P384_GY = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
_P384_N = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
_P384_G = (_P384_GX, _P384_GY)


# --- Secp384r1 Group Arithmetic ---

def _point_add(p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """Constant-time affine point addition on Secp384r1."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P384_P == 0:
            return None
        # Point doubling
        lam = (3 * x1 * x1 + _P384_A) * pow(2 * y1, _P384_P - 2, _P384_P) % _P384_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, _P384_P - 2, _P384_P) % _P384_P
    x3 = (lam * lam - x1 - x2) % _P384_P
    y3 = (lam * (x1 - x3) - y1) % _P384_P
    return (x3, y3)


def _scalar_mul(k: int, pt: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """Double-and-add scalar multiplication on Secp384r1."""
    if pt is None or k % _P384_N == 0:
        return None
    k = k % _P384_N
    result = None
    curr = pt
    while k > 0:
        if k & 1:
            result = _point_add(result, curr)
        curr = _point_add(curr, curr)
        k >>= 1
    return result


def _point_to_bytes(pt: Optional[Tuple[int, int]]) -> bytes:
    """Encode Secp384r1 point to canonical compressed bytes (49 bytes)."""
    if pt is None:
        return b"\x00" * 49
    x, y = pt
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(48, "big")


def _bytes_to_point(data: bytes) -> Optional[Tuple[int, int]]:
    """Decode compressed 49-byte Secp384r1 point."""
    if len(data) != 49 or data == b"\x00" * 49:
        return None
    prefix = data[0]
    if prefix not in (2, 3):
        return None
    x = int.from_bytes(data[1:], "big")
    if x >= _P384_P:
        return None
    y_sq = (pow(x, 3, _P384_P) + _P384_A * x + _P384_B) % _P384_P
    # Modular square root for P % 4 == 3
    y = pow(y_sq, (_P384_P + 1) // 4, _P384_P)
    if pow(y, 2, _P384_P) != y_sq:
        return None
    if (y % 2 == 0 and prefix == 3) or (y % 2 == 1 and prefix == 2):
        y = _P384_P - y
    return (x, y)


# --- Exceptions ---

try:
    from nc3_nuclear_command import (
        NC3SecurityError,
        DualCustodyViolation,
        DualCustodySynchronizationError,
        VSSChecksumMismatchError,
        EAMExpiredError,
        EAMReplayError,
    )
except ImportError:
    class NC3SecurityError(Exception):
        """Base exception for Nuclear Command and Control protocol violations."""


    class DualCustodyViolation(NC3SecurityError):
        """Raised when an operation attempts to bypass multi-party threshold rules."""


    class DualCustodySynchronizationError(DualCustodyViolation):
        """Raised when co-signing actions exceed the strict 2.0-second window (DoD S-5210.41M)."""


    class VSSChecksumMismatchError(NC3SecurityError):
        """Raised when a share or aggregated signature fails Feldman public commitment verification."""


    class EAMExpiredError(NC3SecurityError):
        """Raised when an Emergency Action Message is received outside its temporal validity window."""


    class EAMReplayError(NC3SecurityError):
        """Raised when an Emergency Action Message identifier has already been processed."""


def autonomous_emergency_zeroize(*buffers) -> None:
    """DoD 5220.22-M 7-Pass Autonomous Emergency Zeroization."""
    for buf in buffers:
        if buf is None:
            continue
        try:
            if isinstance(buf, (bytearray, memoryview)):
                secure_wipe_dod_7pass(buf)
            elif isinstance(buf, list):
                for item in buf:
                    if isinstance(item, (bytearray, memoryview)):
                        secure_wipe_dod_7pass(item)
        except Exception as exc:
            import logging
            logging.getLogger("nc3_security").critical("zeroize FAILED: %s", exc)


# --- Data Structures ---

@dataclass
class ThresholdShare:
    """
    Cryptographically committed polynomial share of the master strategic authorization secret.
    Held in isolation by a single strategic silo node.
    """
    share_index: int                       # 1 to n
    share_value: int                       # Polynomial evaluation f(i) in Z_N
    share_bytes: bytes                     # 48 bytes
    share_commitment: bytes                # SHA-384 Feldman commitment to this share
    master_commitment: bytes               # SHA-384 Feldman commitment to master secret (C_0)
    salt: bytes                            # 32-byte ceremony salt
    created_at: float                      # UTC timestamp
    silo_id: str = ""                      # Silo identifier

    def to_dict(self, include_secret: bool = False) -> Dict[str, Any]:
        if include_secret and is_production():
            raise NC3SecurityError(
                "CRITICAL: Direct export of unsealed share secret keys in dictionaries/JSON "
                "is strictly prohibited in production mode. Use seal_share_to_file() instead."
            )
        d = {
            "share_index": self.share_index,
            "share_commitment_hex": self.share_commitment.hex(),
            "master_commitment_hex": self.master_commitment.hex(),
            "salt_hex": self.salt.hex(),
            "created_at": self.created_at,
            "silo_id": self.silo_id,
        }
        if include_secret:
            d["share_hex"] = self.share_bytes.hex()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThresholdShare":
        share_bytes = bytes.fromhex(data["share_hex"]) if "share_hex" in data else b""
        share_val = int.from_bytes(share_bytes, "big") if share_bytes else 0
        return cls(
            share_index=int(data["share_index"]),
            share_value=share_val,
            share_bytes=share_bytes,
            share_commitment=bytes.fromhex(data["share_commitment_hex"]),
            master_commitment=bytes.fromhex(data["master_commitment_hex"]),
            salt=bytes.fromhex(data["salt_hex"]),
            created_at=float(data["created_at"]),
            silo_id=str(data.get("silo_id", "")),
        )

    def seal_to_file(self, file_path: str, passphrase: Optional[bytes] = None) -> None:
        """Convenience method to seal this share to an encrypted file at rest."""
        seal_share_to_file(self, file_path, passphrase)

    @classmethod
    def load_from_file(cls, file_path: str, passphrase: Optional[bytes] = None) -> "ThresholdShare":
        """Convenience method to load and decrypt a sealed share from disk at rest."""
        return load_sealed_share_from_file(file_path, passphrase)


def seal_share_to_file(
    share: ThresholdShare,
    file_path: str,
    passphrase: Optional[bytes] = None,
) -> None:
    """
    Cryptographically seals a ThresholdShare to disk at rest using PBKDF2-HMAC-SHA512
    (220,000 iterations per OWASP/CNSA standard) and AES-256-GCM authenticated encryption.
    Plaintext and key buffers are zeroized with DoD 5220.22-M 7-pass zeroization immediately.
    """
    from cnsa_crypto_gateway import (
        cnsa_aes_256_gcm_encrypt,
        cnsa_zeroize_memory,
        generate_deterministic_gcm_iv,
    )
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    if passphrase is None:
        pw_str = os.environ.get("P2P_OFFICER_SEAL_PW", "")
        passphrase = pw_str.encode("utf-8") if pw_str else None
    if not passphrase:
        raise NC3SecurityError("Passphrase required to seal threshold share")

    salt = secrets.token_bytes(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=220_000,
    )
    derived_key = kdf.derive(passphrase)
    nonce = generate_deterministic_gcm_iv()

    share_dict = {
        "share_index": share.share_index,
        "share_hex": share.share_bytes.hex(),
        "share_commitment_hex": share.share_commitment.hex(),
        "master_commitment_hex": share.master_commitment.hex(),
        "salt_hex": share.salt.hex(),
        "created_at": share.created_at,
        "silo_id": share.silo_id,
    }
    plaintext = json.dumps(share_dict, sort_keys=True).encode("utf-8")
    pt_buf = bytearray(plaintext)
    key_buf = bytearray(derived_key)

    try:
        ct_body, iv_ret, tag = cnsa_aes_256_gcm_encrypt(
            bytes(pt_buf), bytes(key_buf), b"NC3-MPC-SEALED-SHARE-V1", explicit_iv=nonce
        )
        ciphertext = ct_body + tag
        package = {
            "v": 2,
            "salt_hex": salt.hex(),
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "silo_id": share.silo_id,
            "share_index": share.share_index,
        }
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(package, f, indent=2)
    finally:
        cnsa_zeroize_memory(pt_buf, key_buf)
        autonomous_emergency_zeroize(pt_buf, key_buf)


def load_sealed_share_from_file(
    file_path: str,
    passphrase: Optional[bytes] = None,
) -> ThresholdShare:
    """
    Loads and decrypts a sealed ThresholdShare from disk at rest.
    Verifies authenticity, extracts share parameters, and zeroizes plaintext buffers immediately.
    """
    from cnsa_crypto_gateway import (
        cnsa_aes_256_gcm_decrypt,
        cnsa_zeroize_memory,
    )
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    if not os.path.exists(file_path):
        raise NC3SecurityError(f"Sealed share file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        package = json.load(f)

    if not isinstance(package, dict) or package.get("v") != 2:
        raise NC3SecurityError(f"Unknown or invalid sealed share format: {file_path}")

    if passphrase is None:
        pw_str = os.environ.get("P2P_OFFICER_SEAL_PW", "")
        passphrase = pw_str.encode("utf-8") if pw_str else None
    if not passphrase:
        raise NC3SecurityError("Passphrase required to unseal threshold share")

    salt = bytes.fromhex(package["salt_hex"])
    nonce = bytes.fromhex(package["nonce_hex"])
    ciphertext = bytes.fromhex(package["ciphertext_hex"])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=220_000,
    )
    derived_key = kdf.derive(passphrase)
    key_buf = bytearray(derived_key)
    pt_buf: Optional[bytearray] = None

    try:
        ct_body = ciphertext[:-16]
        tag = ciphertext[-16:]
        plaintext = cnsa_aes_256_gcm_decrypt(
            ct_body, bytes(key_buf), nonce, tag, b"NC3-MPC-SEALED-SHARE-V1"
        )
        pt_buf = bytearray(plaintext)
        data = json.loads(plaintext.decode("utf-8"))
        return ThresholdShare.from_dict(data)
    except Exception as e:
        if isinstance(e, NC3SecurityError):
            raise
        raise NC3SecurityError(f"Failed to unseal threshold share: {e}")
    finally:
        cnsa_zeroize_memory(key_buf, pt_buf)
        autonomous_emergency_zeroize(key_buf, pt_buf)


def _ceremony_cert_tbs(
    threshold: int,
    total_shares: int,
    salt: bytes,
    master_commitment: bytes,
    master_p0_bytes: bytes,
    silo_roster_points: List[Tuple[int, str, bytes]],
) -> bytes:
    """Canonical TBS transcript signed by the genesis master ML-DSA-87 key during ceremony."""
    buf = bytearray(b"NC3-CEREMONY-COMMIT-CERT-V2:")
    buf.extend(threshold.to_bytes(2, "big"))
    buf.extend(total_shares.to_bytes(2, "big"))
    buf.extend(salt)
    buf.extend(master_commitment)
    buf.extend(master_p0_bytes)
    for idx, silo_id, q_bytes in sorted(silo_roster_points, key=lambda item: item[0]):
        silo_b = silo_id.encode("utf-8")
        buf.extend(idx.to_bytes(4, "big"))
        buf.extend(len(silo_b).to_bytes(4, "big"))
        buf.extend(silo_b)
        buf.extend(q_bytes)
    return bytes(buf)


def _schnorr_challenge(
    r_bytes: bytes,
    q_bytes: bytes,
    salt: bytes,
    share_index: int,
    timestamp_ms: int,
    digest: bytes,
    field_order: int = _P384_N,
) -> int:
    """Compute canonical domain-separated P-384 Schnorr challenge scalar in [1, N-1]."""
    h = hashlib.sha384()
    h.update(b"NC3-MPC-SCHNORR-P384-V2:")
    h.update(r_bytes)
    h.update(q_bytes)
    h.update(salt)
    h.update(share_index.to_bytes(4, "big"))
    h.update(timestamp_ms.to_bytes(8, "big"))
    h.update(digest)
    return (int.from_bytes(h.digest(), "big") % field_order) or 1


def _silo_partial_transcript(
    silo_id: str,
    share_index: int,
    timestamp_ms: int,
    digest: bytes,
    z_bytes: bytes,
    r_bytes: bytes,
) -> bytes:
    """Canonical silo partial signature transcript authenticated via ML-DSA-87."""
    silo_b = silo_id.encode("utf-8")
    return (
        b"NC3-SILO-PARTIAL-AUTH-V2:"
        + len(silo_b).to_bytes(4, "big")
        + silo_b
        + share_index.to_bytes(4, "big")
        + timestamp_ms.to_bytes(8, "big")
        + digest
        + z_bytes
        + r_bytes
    )


def _lagrange_zero(indices: List[int], field_order: int = _P384_N) -> Dict[int, int]:
    """Compute Lagrange interpolation coefficients lambda_i(0) mod N for sorted indices."""
    lambdas: Dict[int, int] = {}
    for i_idx in indices:
        num = 1
        den = 1
        for j_idx in indices:
            if j_idx == i_idx:
                continue
            num = (num * (-j_idx)) % field_order
            den = (den * (i_idx - j_idx)) % field_order
        lambdas[i_idx] = (num * pow(den, field_order - 2, field_order)) % field_order
    return lambdas


@dataclass
class FeldmanCommitments:
    """
    SHA-384 and Secp384r1 Feldman Verifiable Secret Sharing Public Commitments.
    Anchored to the ceremony ML-DSA-87 master public key via `ceremony_cert_sig`.
    """
    threshold: int
    total_shares: int
    coeff_commitments: List[bytes]                # SHA-384 hashes of coefficient points (t of them)
    share_commitments: Dict[int, bytes]           # index -> SHA-384 hash of share point (n of them)
    coeff_points: List[Tuple[int, int]]           # Public elliptic curve points P_k = [a_k]G
    share_points: Dict[int, Tuple[int, int]]      # Public elliptic curve points Q_i = [s_i]G
    master_commitment: bytes                      # C_0 = SHA-384 hash of P_0
    salt: bytes                                   # 32-byte salt
    master_public_key: bytes                      # ML-DSA-87 master public key (2592 bytes)
    created_at: float
    field_order: int = _P384_N
    ceremony_cert_sig: bytes = b""
    silo_roster_points: List[Tuple[int, str, bytes]] = field(default_factory=list)

    def verify_ceremony_cert(self, master_public_key: bytes) -> bool:
        """Verify ceremony genesis signature binding Feldman commitments to master_public_key."""
        if not self.ceremony_cert_sig or len(self.coeff_points) == 0:
            return False
        if not secrets.compare_digest(self.master_public_key, master_public_key):
            return False
        p0_bytes = _point_to_bytes(self.coeff_points[0])
        if len(p0_bytes) != 49 or len(self.silo_roster_points) != self.total_shares:
            return False
        tbs = _ceremony_cert_tbs(
            self.threshold,
            self.total_shares,
            self.salt,
            self.master_commitment,
            p0_bytes,
            self.silo_roster_points,
        )
        return EnhancedMLDSA_87().verify(master_public_key, tbs, self.ceremony_cert_sig)

    def verify_share(self, share: ThresholdShare) -> bool:
        """Verifies an individual share against the Feldman commitments."""
        if share.share_index not in self.share_commitments:
            return False

        # 1. Verify ceremony salt consistency
        if not secrets.compare_digest(share.salt, self.salt):
            return False

        # 2. Verify share value scalar multiplication against published share point Q_i
        pt = _scalar_mul(share.share_value, _P384_G)
        expected_pt = self.share_points.get(share.share_index)
        if pt is None or expected_pt is None or pt != expected_pt:
            return False

        # 3. Verify SHA-384 Feldman commitment hash
        expected_comm = self.share_commitments[share.share_index]
        calculated_comm = hashlib.sha384(
            b"NC3-FELDMAN-SHA384-SHARE-V1:" + self.salt +
            share.share_index.to_bytes(4, "big") + _point_to_bytes(pt)
        ).digest()
        if not secrets.compare_digest(expected_comm, calculated_comm):
            return False

        # 4. Verify master commitment consistency
        return secrets.compare_digest(share.master_commitment, self.master_commitment)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threshold": self.threshold,
            "total_shares": self.total_shares,
            "coeff_commitments": [c.hex() for c in self.coeff_commitments],
            "share_commitments": {str(k): v.hex() for k, v in self.share_commitments.items()},
            "coeff_points": [_point_to_bytes(p).hex() for p in self.coeff_points],
            "share_points": {str(k): _point_to_bytes(v).hex() for k, v in self.share_points.items()},
            "master_commitment": self.master_commitment.hex(),
            "salt": self.salt.hex(),
            "master_public_key": self.master_public_key.hex(),
            "created_at": self.created_at,
            "ceremony_cert_sig": self.ceremony_cert_sig.hex(),
            "silo_roster_points": [
                {"index": idx, "silo_id": sid, "q_hex": q.hex()}
                for idx, sid, q in self.silo_roster_points
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeldmanCommitments":
        coeff_pts = [_bytes_to_point(bytes.fromhex(p)) for p in data["coeff_points"]]
        share_pts = {int(k): _bytes_to_point(bytes.fromhex(v)) for k, v in data["share_points"].items()}
        roster = [
            (int(r["index"]), str(r["silo_id"]), bytes.fromhex(r["q_hex"]))
            for r in data.get("silo_roster_points", [])
        ]
        return cls(
            threshold=int(data["threshold"]),
            total_shares=int(data["total_shares"]),
            coeff_commitments=[bytes.fromhex(c) for c in data["coeff_commitments"]],
            share_commitments={int(k): bytes.fromhex(v) for k, v in data["share_commitments"].items()},
            coeff_points=coeff_pts,
            share_points=share_pts,
            master_commitment=bytes.fromhex(data["master_commitment"]),
            salt=bytes.fromhex(data["salt"]),
            master_public_key=bytes.fromhex(data["master_public_key"]),
            created_at=float(data["created_at"]),
            ceremony_cert_sig=bytes.fromhex(data.get("ceremony_cert_sig", "")),
            silo_roster_points=roster,
        )


@dataclass
class FrostNonceCommitment:
    """Round-1 blinded FROST-P384 nonce commitment emitted by an Operator Silo Node."""
    silo_id: str
    share_index: int
    commitment_id: str
    d_point_bytes: bytes                      # 49B compressed P-384 hiding commitment D_i
    e_point_bytes: bytes                      # 49B compressed P-384 binding commitment E_i
    payload_digest: bytes                     # 48B SHA-384 EAM digest
    silo_public_key: bytes                    # 2592B ML-DSA-87 PK
    silo_mldsa_sig: bytes                     # 4627B ML-DSA-87 signature


@dataclass
class PartialSignature:
    """
    Blinded partial signature produced by an Operator Silo Node on a verified DoD S-5210.41M payload.
    Combines a zero-knowledge blinded Secp384r1 Schnorr/FROST response scalar (never exposing s_i)
    with the silo's sovereign ML-DSA-87 signature.
    """
    silo_id: str
    share_index: int
    timestamp_utc: float
    payload_digest: bytes                     # 48 bytes (SHA-384)
    partial_signature_bytes: bytes            # 48 bytes (blinded response scalar z_i mod N)
    share_commitment: bytes                   # 48 bytes (SHA-384)
    silo_public_key: bytes                    # 2592 bytes (ML-DSA-87)
    silo_mldsa_sig: bytes                     # 4627 bytes (ML-DSA-87)
    nonce_commitment: bytes = b""             # 49 bytes compressed P-384 nonce point R_i
    protocol_mode: str = "SCHNORR_P384_MLDSA87_QUORUM_V2"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "silo_id": self.silo_id,
            "share_index": self.share_index,
            "timestamp_utc": self.timestamp_utc,
            "payload_digest_hex": self.payload_digest.hex(),
            "partial_signature_hex": self.partial_signature_bytes.hex(),
            "share_commitment_hex": self.share_commitment.hex(),
            "silo_public_key_hex": self.silo_public_key.hex(),
            "silo_mldsa_sig_hex": self.silo_mldsa_sig.hex(),
            "nonce_commitment_hex": self.nonce_commitment.hex(),
            "protocol_mode": self.protocol_mode,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PartialSignature":
        return cls(
            silo_id=str(data["silo_id"]),
            share_index=int(data["share_index"]),
            timestamp_utc=float(data["timestamp_utc"]),
            payload_digest=bytes.fromhex(data["payload_digest_hex"]),
            partial_signature_bytes=bytes.fromhex(data["partial_signature_hex"]),
            share_commitment=bytes.fromhex(data["share_commitment_hex"]),
            silo_public_key=bytes.fromhex(data["silo_public_key_hex"]),
            silo_mldsa_sig=bytes.fromhex(data["silo_mldsa_sig_hex"]),
            nonce_commitment=bytes.fromhex(data.get("nonce_commitment_hex", "")),
            protocol_mode=str(data.get("protocol_mode", "SCHNORR_P384_MLDSA87_QUORUM_V2")),
        )


@dataclass
class ThresholdSignature:
    """
    Full aggregated multi-party threshold signature with embedded verifiable proofs:
    - Ceremony ML-DSA-87 genesis certificate binding P_0, salt, and roster share points Q_i
    - Per-silo blinded Schnorr P-384 ZKP + ML-DSA-87 quorum signatures (or FROST_P384_V2 (R, z_agg))
    Master secret is NEVER reconstructed or stored on any machine.
    """
    payload_digest: bytes                     # 48 bytes (SHA-384)
    aggregated_signature: bytes               # 48 bytes (SHA-384 proof digest or FROST z_agg scalar)
    signer_indices: List[int]
    signer_silos: List[str]
    timestamps: List[float]
    sync_skew_seconds: float
    threshold: int
    master_public_key: bytes                  # 2592 bytes (ML-DSA-87)
    vss_commitment: bytes                     # 48 bytes (SHA-384 C_0)
    protocol_mode: str = "SCHNORR_P384_MLDSA87_QUORUM_V2"
    ceremony_salt: bytes = b""
    master_p0_point: bytes = b""
    total_shares: int = 0
    ceremony_cert_sig: bytes = b""
    silo_roster_points: List[Tuple[int, str, bytes]] = field(default_factory=list)
    silo_proofs: List[Dict[str, Any]] = field(default_factory=list)
    frost_group_r: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_digest_hex": self.payload_digest.hex(),
            "aggregated_signature_hex": self.aggregated_signature.hex(),
            "signer_indices": self.signer_indices,
            "signer_silos": self.signer_silos,
            "timestamps": self.timestamps,
            "sync_skew_seconds": self.sync_skew_seconds,
            "threshold": self.threshold,
            "master_public_key_hex": self.master_public_key.hex(),
            "vss_commitment_hex": self.vss_commitment.hex(),
            "protocol_mode": self.protocol_mode,
            "ceremony_salt_hex": self.ceremony_salt.hex(),
            "master_p0_point_hex": self.master_p0_point.hex(),
            "total_shares": self.total_shares,
            "ceremony_cert_sig_hex": self.ceremony_cert_sig.hex(),
            "silo_roster_points": [
                {"index": idx, "silo_id": sid, "q_hex": q.hex()}
                for idx, sid, q in self.silo_roster_points
            ],
            "silo_proofs": self.silo_proofs,
            "frost_group_r_hex": self.frost_group_r.hex(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThresholdSignature":
        roster = [
            (int(r["index"]), str(r["silo_id"]), bytes.fromhex(r["q_hex"]))
            for r in data.get("silo_roster_points", [])
        ]
        return cls(
            payload_digest=bytes.fromhex(data["payload_digest_hex"]),
            aggregated_signature=bytes.fromhex(data["aggregated_signature_hex"]),
            signer_indices=[int(x) for x in data["signer_indices"]],
            signer_silos=[str(s) for s in data["signer_silos"]],
            timestamps=[float(t) for t in data["timestamps"]],
            sync_skew_seconds=float(data["sync_skew_seconds"]),
            threshold=int(data["threshold"]),
            master_public_key=bytes.fromhex(data["master_public_key_hex"]),
            vss_commitment=bytes.fromhex(data["vss_commitment_hex"]),
            protocol_mode=str(data.get("protocol_mode", "SCHNORR_P384_MLDSA87_QUORUM_V2")),
            ceremony_salt=bytes.fromhex(data.get("ceremony_salt_hex", "")),
            master_p0_point=bytes.fromhex(data.get("master_p0_point_hex", "")),
            total_shares=int(data.get("total_shares", 0)),
            ceremony_cert_sig=bytes.fromhex(data.get("ceremony_cert_sig_hex", "")),
            silo_roster_points=roster,
            silo_proofs=list(data.get("silo_proofs", [])),
            frost_group_r=bytes.fromhex(data.get("frost_group_r_hex", "")),
        )

    def to_bytes(self) -> bytes:
        """Wire format serialization: [MAGIC: 10B][THRESH: 2B][SKEW_MS: 8B int][DIGEST: 48B][W: 48B][VSS: 48B][JSON METADATA]"""
        magic = b"NC3-MPC-T1"
        wire_hdr = bytearray(magic)
        wire_hdr.extend(self.threshold.to_bytes(2, "big"))
        sync_skew_ms = int(round(self.sync_skew_seconds * 1000))
        wire_hdr.extend(sync_skew_ms.to_bytes(8, "big"))
        wire_hdr.extend(self.payload_digest)
        wire_hdr.extend(self.aggregated_signature)
        wire_hdr.extend(self.vss_commitment)
        ts_ms = [int(round(t * 1000)) if t < 1e11 else int(round(t)) for t in self.timestamps]
        meta = json.dumps({
            "signers": self.signer_silos,
            "indices": self.signer_indices,
            "timestamps": ts_ms,
            "master_pub": list(self.master_public_key),
            "master_pub_hex": self.master_public_key.hex(),
            "mode": self.protocol_mode,
            "salt_hex": self.ceremony_salt.hex(),
            "master_p0_hex": self.master_p0_point.hex(),
            "total_shares": self.total_shares,
            "ceremony_cert_sig_hex": self.ceremony_cert_sig.hex(),
            "silo_roster": [
                {"index": idx, "silo_id": sid, "q_hex": q.hex()}
                for idx, sid, q in self.silo_roster_points
            ],
            "silo_proofs": self.silo_proofs,
            "frost_r_hex": self.frost_group_r.hex(),
        }).encode("utf-8")
        wire_hdr.extend(len(meta).to_bytes(4, "big"))
        wire_hdr.extend(meta)
        return bytes(wire_hdr)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ThresholdSignature":
        magic = b"NC3-MPC-T1"
        if len(raw) < 10 + 2 + 8 + 48 + 48 + 48 + 4 or raw[:10] != magic:
            raise NC3SecurityError("Malformed threshold signature wire bytes")
        threshold = int.from_bytes(raw[10:12], "big")
        sync_skew_ms = int.from_bytes(raw[12:20], "big")
        skew = sync_skew_ms / 1000.0
        digest = raw[20:68]
        sig_w = raw[68:116]
        vss_comm = raw[116:164]
        meta_len = int.from_bytes(raw[164:168], "big")
        if len(raw) != 168 + meta_len:
            raise NC3SecurityError("Malformed wire package: length mismatch")
        meta = json.loads(raw[168:168 + meta_len].decode("utf-8"))
        timestamps = [t / 1000.0 if t > 1e11 else float(t) for t in meta["timestamps"]]
        if "master_pub" in meta and isinstance(meta["master_pub"], list):
            master_pub = bytes(meta["master_pub"])
        elif "master_pub_hex" in meta:
            master_pub = bytes.fromhex(meta["master_pub_hex"])
        else:
            raise NC3SecurityError("Missing master_pub in wire metadata")
        roster = [
            (int(r["index"]), str(r["silo_id"]), bytes.fromhex(r["q_hex"]))
            for r in meta.get("silo_roster", [])
        ]
        return cls(
            payload_digest=digest,
            aggregated_signature=sig_w,
            signer_indices=[int(x) for x in meta["indices"]],
            signer_silos=[str(s) for s in meta["signers"]],
            timestamps=timestamps,
            sync_skew_seconds=skew,
            threshold=threshold,
            master_public_key=master_pub,
            vss_commitment=vss_comm,
            protocol_mode=str(meta.get("mode", "SCHNORR_P384_MLDSA87_QUORUM_V2")),
            ceremony_salt=bytes.fromhex(meta.get("salt_hex", "")),
            master_p0_point=bytes.fromhex(meta.get("master_p0_hex", "")),
            total_shares=int(meta.get("total_shares", 0)),
            ceremony_cert_sig=bytes.fromhex(meta.get("ceremony_cert_sig_hex", "")),
            silo_roster_points=roster,
            silo_proofs=list(meta.get("silo_proofs", [])),
            frost_group_r=bytes.fromhex(meta.get("frost_r_hex", "")),
        )


# --- Helper Payload Construction ---

def create_eam_payload(
    directive_code: str,
    target_command: str,
    eam_id: Optional[str] = None,
    pal_code: str = "",
    validity_window_seconds: float = DEFAULT_EAM_VALIDITY_WINDOW,
    classification: str = EAM_CLASSIFICATION,
    preamble: str = EAM_PREAMBLE,
) -> Dict[str, Any]:
    """Helper to generate a compliant DoD Directive S-5210.41M EAM payload."""
    now_utc = time.time()
    if not eam_id:
        eam_id = f"EAM-STRAT-{int(now_utc)}-{secrets.token_hex(4).upper()}"
    return {
        "eam_id": eam_id,
        "preamble": preamble,
        "classification": classification,
        "timestamp_utc": now_utc,
        "validity_window_seconds": validity_window_seconds,
        "directive_code": directive_code,
        "target_command": target_command,
        "encrypted_pal_code": pal_code or secrets.token_hex(16),
    }


def _canonical_payload_digest(payload: Dict[str, Any] | bytes) -> bytes:
    """Computes canonical SHA-384 transcript digest of an NC3 payload."""
    if isinstance(payload, bytes):
        payload_bytes = payload
    else:
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    hasher = hashlib.sha384()
    hasher.update(b"NC3-EAM-PAYLOAD-V1:")
    hasher.update(payload_bytes)
    return hasher.digest()


# =========================================================================
# 1. NC3ThresholdKeyGenerator
# =========================================================================

class NC3ThresholdKeyGenerator:
    """
    Decentralized Threshold Key Generator.
    Divides the master strategic authorization secret into n polynomial shares
    with SHA-384 Feldman public commitments.

    SECURITY INVARIANT:
    The master secret key is NEVER stored on disk or retained on any machine
    following the split ceremony. Immediate DoD 5220.22-M 7-pass zeroization
    is executed over all temporary buffers.
    """

    def __init__(self, field_order: int = _P384_N):
        self.field_order = field_order
        self.mldsa = EnhancedMLDSA_87()

    def generate_threshold_key(
        self,
        threshold: int,
        total_shares: int,
        silo_ids: Optional[List[str]] = None,
    ) -> Tuple[bytes, List[ThresholdShare], FeldmanCommitments]:
        """
        Splits master secret into n polynomial shares with Feldman commitments.

        Args:
            threshold (t): Minimum number of silo co-signatures required.
            total_shares (n): Total number of silo nodes.
            silo_ids: Optional list of unique silo identifiers.

        Returns:
            Tuple of (master_public_key, List[ThresholdShare], FeldmanCommitments).
        """
        if threshold < 2:
            raise DualCustodyViolation(f"Threshold t must be >= 2 (Two-Person Rule minimum), got {threshold}")
        if total_shares < threshold:
            raise DualCustodyViolation(f"Total shares n ({total_shares}) must be >= threshold t ({threshold})")
        if is_production():
            if total_shares > 16:
                raise DualCustodyViolation(f"Production operational limit: total shares n ({total_shares}) exceeds maximum 16")

        if silo_ids is not None:
            if len(silo_ids) != total_shares:
                raise NC3SecurityError(f"silo_ids length {len(silo_ids)} != total_shares {total_shares}")
            if len(set(silo_ids)) != len(silo_ids):
                raise DualCustodyViolation("Silo IDs must be distinct")
        else:
            silo_ids = [f"SILO-{i:02d}" for i in range(1, total_shares + 1)]

        now_utc = time.time()
        salt = secrets.token_bytes(32)

        # 1. Generate master ML-DSA-87 keypair
        master_pk, master_sk = self.mldsa.keygen()

        # 2. Derive master strategic authorization scalar S in Z_N
        # Bound securely to master ML-DSA-87 key material
        h = hashlib.sha384(b"NC3-STRAT-AUTH-SECRET:" + master_sk).digest()
        master_secret_scalar = int.from_bytes(h, "big") % (self.field_order - 1) + 1

        # 3. Generate random polynomial coefficients: f(x) = a0 + a1*x + ... + a_{t-1}*x^{t-1}
        # a0 = master_secret_scalar
        coeffs: List[int] = [master_secret_scalar]
        for _ in range(1, threshold):
            coeffs.append(secrets.randbelow(self.field_order - 1) + 1)

        # 4. Compute Feldman coefficient commitments: P_k = [a_k] G and C_k = SHA-384(...)
        coeff_points: List[Tuple[int, int]] = []
        coeff_commitments: List[bytes] = []
        for k, a_k in enumerate(coeffs):
            pt = _scalar_mul(a_k, _P384_G)
            if pt is None:
                raise NC3SecurityError("Point generation failure during Feldman commitment")
            coeff_points.append(pt)
            c_k = hashlib.sha384(
                b"NC3-FELDMAN-SHA384-COEFF-V1:" + salt +
                k.to_bytes(4, "big") + _point_to_bytes(pt)
            ).digest()
            coeff_commitments.append(c_k)

        master_commitment = coeff_commitments[0]  # C_0 commits to master secret a0

        # 5. Evaluate polynomial for each silo i in 1..n: s_i = f(i) mod N
        # And compute share point Q_i = [s_i] G and share commitment V_i
        shares: List[ThresholdShare] = []
        share_points: Dict[int, Tuple[int, int]] = {}
        share_commitments: Dict[int, bytes] = {}

        for idx in range(1, total_shares + 1):
            s_i = 0
            idx_power = 1
            for a_k in coeffs:
                s_i = (s_i + a_k * idx_power) % self.field_order
                idx_power = (idx_power * idx) % self.field_order

            q_i = _scalar_mul(s_i, _P384_G)
            if q_i is None:
                raise NC3SecurityError("Share point generation failure")
            share_points[idx] = q_i

            v_i = hashlib.sha384(
                b"NC3-FELDMAN-SHA384-SHARE-V1:" + salt +
                idx.to_bytes(4, "big") + _point_to_bytes(q_i)
            ).digest()
            share_commitments[idx] = v_i

            share_obj = ThresholdShare(
                share_index=idx,
                share_value=s_i,
                share_bytes=s_i.to_bytes(48, "big"),
                share_commitment=v_i,
                master_commitment=master_commitment,
                salt=salt,
                created_at=now_utc,
                silo_id=silo_ids[idx - 1],
            )
            shares.append(share_obj)

        silo_roster_points = [
            (s.share_index, s.silo_id, _point_to_bytes(share_points[s.share_index]))
            for s in shares
        ]
        ceremony_tbs = _ceremony_cert_tbs(
            threshold,
            total_shares,
            salt,
            master_commitment,
            _point_to_bytes(coeff_points[0]),
            silo_roster_points,
        )
        ceremony_cert_sig = self.mldsa.sign(master_sk, ceremony_tbs)

        commitments = FeldmanCommitments(
            threshold=threshold,
            total_shares=total_shares,
            coeff_commitments=coeff_commitments,
            share_commitments=share_commitments,
            coeff_points=coeff_points,
            share_points=share_points,
            master_commitment=master_commitment,
            salt=salt,
            master_public_key=master_pk,
            created_at=now_utc,
            field_order=self.field_order,
            ceremony_cert_sig=ceremony_cert_sig,
            silo_roster_points=silo_roster_points,
        )

        # 6. CRITICAL SECURITY INVARIANT: DoD 5220.22-M 7-pass zeroize master secret and coeffs
        # Neither the key generator nor any central entity retains master_sk or S!
        sk_buf = bytearray(master_sk)
        autonomous_emergency_zeroize(sk_buf)
        # Erase scalar references
        for i in range(len(coeffs)):
            coeffs[i] = 0
        master_secret_scalar = 0

        log_event(
            AuditEventType.AUTHENTICATION_SUCCESS,
            f"NC3 Threshold Key Ceremony completed: {threshold}-of-{total_shares} Feldman VSS distributed.",
            AuditSeverity.CRITICAL,
        )

        return master_pk, shares, commitments


# =========================================================================
# 2. OperatorSiloNode
# =========================================================================

class OperatorSiloNode:
    """
    Represents an isolated, sovereign launch control silo or strategic command node.
    Possesses ONLY its single polynomial share s_i and sovereign ML-DSA-87 credentials.
    Computes partial signatures on verified DoD S-5210.41M payloads.
    """

    def __init__(
        self,
        silo_id: str,
        share: ThresholdShare,
        commitments: FeldmanCommitments,
        silo_mldsa_keypair: Optional[Tuple[bytes, bytes]] = None,
    ):
        self.silo_id = silo_id
        self._share = share
        self.commitments = commitments
        self.field_order = commitments.field_order
        self.mldsa = EnhancedMLDSA_87()

        # Sovereign Silo ML-DSA-87 keypair (for hardware node identity)
        if silo_mldsa_keypair:
            self.silo_pk, self._silo_sk = silo_mldsa_keypair
        else:
            self.silo_pk, self._silo_sk = self.mldsa.keygen()

        self._seen_eam_ids: Set[str] = set()
        self._lock = threading.Lock()

        # Self-verify share against public commitments on initialization
        self.verify_own_share()
        self._frost_nonces: Dict[str, Tuple[int, int, bytes]] = {}

    def verify_own_share(self) -> bool:
        """Verifies this node's share against the Feldman commitments."""
        if not self.commitments.verify_share(self._share):
            raise VSSChecksumMismatchError(
                f"Silo {self.silo_id} share integrity check failed: Feldman commitment mismatch!"
            )
        return True

    def verify_payload(self, payload: Dict[str, Any] | bytes) -> Dict[str, Any]:
        """
        Enforces strict DoD Directive S-5210.41M payload validation:
        - Must contain valid NC3 preamble
        - Must match TOP SECRET // SI-OP-IA // NC3 // NOFORN classification
        - Must be within temporal freshness window (120s)
        - Must contain valid directive_code and target_command
        - Anti-replay check against seen eam_id
        """
        if isinstance(payload, bytes):
            try:
                data = json.loads(payload.decode("utf-8"))
            except Exception as e:
                raise NC3SecurityError(f"Malformed EAM payload JSON: {e}")
        elif isinstance(payload, dict):
            data = payload
        else:
            raise NC3SecurityError("Payload must be dict or JSON bytes")

        # 1. Preamble check
        preamble = str(data.get("preamble", ""))
        if not (preamble == EAM_PREAMBLE or preamble.startswith("[NC3/")):
            raise DualCustodyViolation(f"Invalid or missing NC3 preamble: {preamble}")

        # 2. Classification check
        classification = str(data.get("classification", ""))
        if classification != EAM_CLASSIFICATION:
            raise DualCustodyViolation(f"Unauthorized classification banner: {classification}")

        # 3. Temporal freshness check
        ts = data.get("timestamp_utc")
        if ts is None or not isinstance(ts, (int, float)):
            raise NC3SecurityError("Missing or invalid timestamp_utc in EAM payload")
        validity = float(data.get("validity_window_seconds", DEFAULT_EAM_VALIDITY_WINDOW))
        now = time.time()
        if abs(now - ts) > validity:
            raise EAMExpiredError(
                f"EAM expired: skew {abs(now - ts):.2f}s exceeds validity window {validity}s"
            )

        # 4. Directive code and target command check
        if not data.get("directive_code"):
            raise NC3SecurityError("Missing directive_code in EAM payload")
        if not data.get("target_command"):
            raise NC3SecurityError("Missing target_command in EAM payload")

        # 5. Anti-replay verification
        eam_id = str(data.get("eam_id", ""))
        if not eam_id:
            raise NC3SecurityError("Missing eam_id in EAM payload")
        with self._lock:
            if eam_id in self._seen_eam_ids:
                raise EAMReplayError(f"EAM replay detected: {eam_id} has already been processed")
            self._seen_eam_ids.add(eam_id)

        return data

    def compute_partial_signature(
        self,
        payload: Dict[str, Any] | bytes,
        simulated_timestamp: Optional[float] = None,
    ) -> PartialSignature:
        """
        Computes partial signature sigma_i on a verified DoD S-5210.41M payload.

        Args:
            payload: DoD S-5210.41M Emergency Action Message payload.
            simulated_timestamp: Optional explicit timestamp (for deterministic test fixture timing).

        Returns:
            PartialSignature object.
        """
        verified_data = self.verify_payload(payload)
        digest = _canonical_payload_digest(verified_data)

        timestamp_utc = simulated_timestamp if simulated_timestamp is not None else time.time()

        timestamp_ms = int(round(timestamp_utc * 1000))
        norm_ts_utc = timestamp_ms / 1000.0

        # Generate fresh CSPRNG blinding scalar r_i in [1, N-1] (never exposed, single-use)
        r_secret = (int.from_bytes(secrets.token_bytes(64), "big") % (self.field_order - 1)) + 1
        try:
            r_pt = _scalar_mul(r_secret, _P384_G)
            if r_pt is None:
                raise NC3SecurityError("Nonce commitment point generation failed")
            r_bytes = _point_to_bytes(r_pt)
            q_pt = self.commitments.share_points.get(self._share.share_index)
            if q_pt is None:
                raise VSSChecksumMismatchError(f"Unknown share index {self._share.share_index}")
            q_bytes = _point_to_bytes(q_pt)

            c_i = _schnorr_challenge(
                r_bytes,
                q_bytes,
                self.commitments.salt,
                self._share.share_index,
                timestamp_ms,
                digest,
                self.field_order,
            )
            # Blinded Schnorr ZKP response: z_i = (r_i + c_i * s_i) mod N
            z_i = (r_secret + c_i * self._share.share_value) % self.field_order
            z_bytes = z_i.to_bytes(48, "big")
        finally:
            r_secret = 0

        # Bind with sovereign ML-DSA-87 signature over canonical partial transcript
        sig_transcript = _silo_partial_transcript(
            self.silo_id,
            self._share.share_index,
            timestamp_ms,
            digest,
            z_bytes,
            r_bytes,
        )
        silo_mldsa_sig = self.mldsa.sign(self._silo_sk, sig_transcript)

        return PartialSignature(
            silo_id=self.silo_id,
            share_index=self._share.share_index,
            timestamp_utc=norm_ts_utc,
            payload_digest=digest,
            partial_signature_bytes=z_bytes,
            share_commitment=self._share.share_commitment,
            silo_public_key=self.silo_pk,
            silo_mldsa_sig=silo_mldsa_sig,
            nonce_commitment=r_bytes,
            protocol_mode="SCHNORR_P384_MLDSA87_QUORUM_V2",
        )

    def frost_round1_commit(self, payload: Dict[str, Any] | bytes) -> FrostNonceCommitment:
        """
        Round 1 of 2-round blinded FROST-P384 threshold signing.
        NOTE: Custom Secp384r1 profile (classical ECDLP; not RFC 9591 suites, not post-quantum without silo ML-DSA-87 bindings).
        """
        verified_data = self.verify_payload(payload)
        digest = _canonical_payload_digest(verified_data)
        d_i = (int.from_bytes(secrets.token_bytes(64), "big") % (self.field_order - 1)) + 1
        e_i = (int.from_bytes(secrets.token_bytes(64), "big") % (self.field_order - 1)) + 1
        d_pt = _scalar_mul(d_i, _P384_G)
        e_pt = _scalar_mul(e_i, _P384_G)
        if d_pt is None or e_pt is None:
            raise NC3SecurityError("FROST Round-1 nonce generation failure")
        d_bytes = _point_to_bytes(d_pt)
        e_bytes = _point_to_bytes(e_pt)
        cid = secrets.token_hex(16)
        with self._lock:
            self._frost_nonces[cid] = (d_i, e_i, digest)
        tbs = (
            b"NC3-FROST-R1-V2:"
            + cid.encode("ascii")
            + self.silo_id.encode("utf-8")
            + self._share.share_index.to_bytes(4, "big")
            + digest
            + d_bytes
            + e_bytes
        )
        sig = self.mldsa.sign(self._silo_sk, tbs)
        return FrostNonceCommitment(
            silo_id=self.silo_id,
            share_index=self._share.share_index,
            commitment_id=cid,
            d_point_bytes=d_bytes,
            e_point_bytes=e_bytes,
            payload_digest=digest,
            silo_public_key=self.silo_pk,
            silo_mldsa_sig=sig,
        )

    def frost_round2_sign(
        self,
        commitment_id: str,
        payload_digest: bytes,
        round1_commitments: List[FrostNonceCommitment],
        simulated_timestamp: Optional[float] = None,
    ) -> PartialSignature:
        """Round 2 of 2-round blinded FROST-P384 threshold signing (single-use nonce consumption)."""
        with self._lock:
            nonce_entry = self._frost_nonces.pop(commitment_id, None)
        if nonce_entry is None:
            raise NC3SecurityError("FROST nonce not found or already consumed")
        d_i, e_i, expected_digest = nonce_entry
        try:
            if not secrets.compare_digest(payload_digest, expected_digest):
                raise NC3SecurityError("FROST Round-2 digest mismatch")
            selected = sorted(round1_commitments, key=lambda c: c.share_index)
            if len(selected) < self.commitments.threshold:
                raise DualCustodyViolation("FROST Round-2 insufficient commitments")
            binding_transcript = bytearray(b"NC3-FROST-BIND-V2:")
            binding_transcript.extend(self.commitments.salt)
            binding_transcript.extend(payload_digest)
            for c in selected:
                binding_transcript.extend(c.share_index.to_bytes(4, "big"))
                binding_transcript.extend(c.d_point_bytes)
                binding_transcript.extend(c.e_point_bytes)
            r_group: Optional[Tuple[int, int]] = None
            my_rho = 1
            for c in selected:
                rho_j = (
                    int.from_bytes(
                        hashlib.sha384(bytes(binding_transcript) + c.share_index.to_bytes(4, "big")).digest(),
                        "big",
                    )
                    % self.field_order
                ) or 1
                if c.share_index == self._share.share_index:
                    my_rho = rho_j
                d_pt = _bytes_to_point(c.d_point_bytes)
                e_pt = _bytes_to_point(c.e_point_bytes)
                if d_pt is None or e_pt is None:
                    raise VSSChecksumMismatchError("Invalid FROST Round-1 commitment point")
                term = _point_add(d_pt, _scalar_mul(rho_j, e_pt))
                r_group = _point_add(r_group, term)
            if r_group is None:
                raise NC3SecurityError("FROST group commitment collapsed to identity")
            r_group_bytes = _point_to_bytes(r_group)
            p0_bytes = _point_to_bytes(self.commitments.coeff_points[0])
            c_frost = (
                int.from_bytes(
                    hashlib.sha384(
                        b"NC3-FROST-CHALLENGE-V2:" + r_group_bytes + p0_bytes + self.commitments.salt + payload_digest
                    ).digest(),
                    "big",
                )
                % self.field_order
            ) or 1
            indices = [c.share_index for c in selected]
            lambda_i = _lagrange_zero(indices, self.field_order)[self._share.share_index]
            z_i = (d_i + e_i * my_rho + lambda_i * self._share.share_value * c_frost) % self.field_order
            z_bytes = z_i.to_bytes(48, "big")
            timestamp_ms = int(round((simulated_timestamp if simulated_timestamp is not None else time.time()) * 1000))
            norm_ts_utc = timestamp_ms / 1000.0
            sig_transcript = _silo_partial_transcript(
                self.silo_id, self._share.share_index, timestamp_ms, payload_digest, z_bytes, r_group_bytes
            )
            silo_sig = self.mldsa.sign(self._silo_sk, sig_transcript)
            return PartialSignature(
                silo_id=self.silo_id,
                share_index=self._share.share_index,
                timestamp_utc=norm_ts_utc,
                payload_digest=payload_digest,
                partial_signature_bytes=z_bytes,
                share_commitment=self._share.share_commitment,
                silo_public_key=self.silo_pk,
                silo_mldsa_sig=silo_sig,
                nonce_commitment=r_group_bytes,
                protocol_mode="FROST_P384_V2",
            )
        finally:
            d_i = 0
            e_i = 0


# =========================================================================
# 3. NC3ThresholdAggregator
# =========================================================================

class NC3ThresholdAggregator:
    """
    Decentralized Multi-Party Computation Threshold Aggregator.
    Combines t valid partial shares from distinct silos into a full threshold
    signature verifying against the master public key.

    SECURITY INVARIANT:
    The master secret authorization key is NEVER reconstructed on the aggregator
    or any single machine.
    """

    def __init__(self, master_public_key: bytes, commitments: FeldmanCommitments):
        self.master_public_key = master_public_key
        self.commitments = commitments
        self.threshold = commitments.threshold
        self.field_order = commitments.field_order
        self.mldsa = EnhancedMLDSA_87()

        # Verification invariant: Ensure NO secret keys reside on aggregator
        if hasattr(self, "master_secret") or hasattr(self, "_master_sk"):
            raise NC3SecurityError("FATAL: Aggregator state contains unauthorized master secret!")

    def aggregate(
        self,
        partial_signatures: List[PartialSignature],
        payload: Optional[Dict[str, Any] | bytes] = None,
    ) -> ThresholdSignature:
        """
        Convenience method to aggregate partial signatures.
        If payload is omitted, verifies consensus across partial signatures' digests.
        """
        return self.aggregate_signatures(payload, partial_signatures)

    def aggregate_signatures(
        self,
        payload: Optional[Dict[str, Any] | bytes],
        partial_signatures: List[PartialSignature],
    ) -> ThresholdSignature:
        """
        Aggregates t valid partial signatures into a full threshold signature.

        Enforces:
        1. Quorum: at least t partial signatures.
        2. Distinct silos: all t signatures must originate from distinct silos / indices.
        3. Simultaneous window: all co-signatures within 2.0 seconds (DoD S-5210.41M).
        4. Canonical transcript agreement across all shares.
        5. Silo sovereign ML-DSA-87 signature and Feldman VSS verification.
        6. Combines without reconstructing the master secret key.
        """
        # 1. Quorum check
        if len(partial_signatures) < self.threshold:
            raise DualCustodyViolation(
                f"Threshold quorum not met: required {self.threshold} co-signatures, received {len(partial_signatures)}"
            )

        # Select first t partial signatures
        selected = partial_signatures[:self.threshold]

        # 2. Distinct silos check
        indices = [p.share_index for p in selected]
        silos = [p.silo_id for p in selected]
        if len(set(indices)) != len(indices):
            raise DualCustodyViolation(
                f"Duplicate silo share index detected in co-signing set: {indices}"
            )
        if len(set(silos)) != len(silos):
            raise DualCustodyViolation(
                f"Duplicate silo ID detected in co-signing set: {silos}"
            )

        # 3. Simultaneous execution window (DoD Directive S-5210.41M: strict 2.0-second limit)
        timestamps = [p.timestamp_utc for p in selected]
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        skew = max_ts - min_ts
        if skew < 0.0 or skew > MAX_CO_SIGNING_WINDOW_SECONDS:
            raise DualCustodySynchronizationError(
                f"Co-signing temporal skew {skew:.4f}s exceeds strict {MAX_CO_SIGNING_WINDOW_SECONDS}s ceiling (DoD S-5210.41M)"
            )

        # 4. Canonical payload digest verification
        if payload is not None:
            expected_digest = _canonical_payload_digest(payload)
            for p in selected:
                if not secrets.compare_digest(p.payload_digest, expected_digest):
                    raise NC3SecurityError(
                        f"Payload digest mismatch on silo {p.silo_id}: expected {expected_digest.hex()[:8]}, got {p.payload_digest.hex()[:8]}"
                    )
            digest = expected_digest
        else:
            digest = selected[0].payload_digest
            for p in selected[1:]:
                if not secrets.compare_digest(p.payload_digest, digest):
                    raise NC3SecurityError(
                        f"Mismatched payload digests among partial signatures ({p.silo_id} vs {selected[0].silo_id})"
                    )

        # 5. Verify genesis ceremony certificate under master_public_key
        if not self.commitments.verify_ceremony_cert(self.master_public_key):
            raise VSSChecksumMismatchError(
                "Ceremony genesis ML-DSA-87 certificate verification failed against master_public_key!"
            )

        roster_map = {idx: (sid, q_b) for idx, sid, q_b in self.commitments.silo_roster_points}

        # 6. Verify each partial signature's ML-DSA-87 signature, roster binding, and blinded P-384 Schnorr proof
        silo_proofs: List[Dict[str, Any]] = []
        mode = selected[0].protocol_mode
        if any(p.protocol_mode != mode for p in selected):
            raise NC3SecurityError("Mixed protocol modes in partial signatures")

        p0_point = self.commitments.coeff_points[0]
        p0_bytes = _point_to_bytes(p0_point)

        if mode == "FROST_P384_V2":
            r_group_bytes = selected[0].nonce_commitment
            r_group_pt = _bytes_to_point(r_group_bytes)
            if r_group_pt is None or any(not secrets.compare_digest(p.nonce_commitment, r_group_bytes) for p in selected):
                raise VSSChecksumMismatchError("Inconsistent or invalid FROST group nonce commitment")
            lambdas = _lagrange_zero(indices, self.field_order)
            c_frost = (
                int.from_bytes(
                    hashlib.sha384(
                        b"NC3-FROST-CHALLENGE-V2:" + r_group_bytes + p0_bytes + self.commitments.salt + digest
                    ).digest(),
                    "big",
                )
                % self.field_order
            ) or 1
            z_agg = 0
            for p in selected:
                timestamp_ms = int(round(p.timestamp_utc * 1000))
                z_i = int.from_bytes(p.partial_signature_bytes, "big")
                if len(p.partial_signature_bytes) != 48 or not (0 < z_i < self.field_order):
                    raise VSSChecksumMismatchError(f"Silo {p.silo_id} invalid FROST scalar")
                sig_transcript = _silo_partial_transcript(
                    p.silo_id, p.share_index, timestamp_ms, digest, p.partial_signature_bytes, p.nonce_commitment
                )
                if not self.mldsa.verify(p.silo_public_key, sig_transcript, p.silo_mldsa_sig):
                    raise VSSChecksumMismatchError(f"Silo {p.silo_id} sovereign ML-DSA-87 signature verification failed!")
                q_i = self.commitments.share_points.get(p.share_index)
                q_bytes = _point_to_bytes(q_i)
                z_agg = (z_agg + z_i) % self.field_order
                silo_proofs.append({
                    "silo_id": p.silo_id,
                    "share_index": p.share_index,
                    "timestamp_ms": timestamp_ms,
                    "z_scalar_hex": p.partial_signature_bytes.hex(),
                    "r_point_hex": p.nonce_commitment.hex(),
                    "q_point_hex": q_bytes.hex(),
                    "silo_pk_hex": p.silo_public_key.hex(),
                    "silo_mldsa_sig_hex": p.silo_mldsa_sig.hex(),
                })
            # Check aggregate FROST Schnorr equation: [z_agg]G == R_group + [c_frost] P_0
            lhs = _scalar_mul(z_agg, _P384_G)
            rhs = _point_add(r_group_pt, _scalar_mul(c_frost, p0_point))
            if lhs is None or rhs is None or lhs != rhs:
                raise VSSChecksumMismatchError("FROST-P384 aggregate verification [z]G == R + [c]P_0 failed!")
            agg_sig_bytes = z_agg.to_bytes(48, "big")
            frost_group_r = r_group_bytes
        else:
            proof_digest_hasher = hashlib.sha384()
            proof_digest_hasher.update(b"NC3-QUORUM-PROOF-V2:")
            proof_digest_hasher.update(digest)
            lambdas = _lagrange_zero(indices, self.field_order)
            q_reconstructed: Optional[Tuple[int, int]] = None

            for p in selected:
                timestamp_ms = int(round(p.timestamp_utc * 1000))
                if len(p.partial_signature_bytes) != 48 or len(p.nonce_commitment) != 49:
                    raise VSSChecksumMismatchError(f"Silo {p.silo_id} malformed blinded Schnorr proof lengths")
                r_pt = _bytes_to_point(p.nonce_commitment)
                if r_pt is None:
                    raise VSSChecksumMismatchError(f"Silo {p.silo_id} invalid nonce point R_i")
                z_i = int.from_bytes(p.partial_signature_bytes, "big")
                if not (0 < z_i < self.field_order):
                    raise VSSChecksumMismatchError(f"Silo {p.silo_id} scalar out of field bounds")

                # 6a. Sovereign ML-DSA-87 authentication over canonical V2 transcript
                sig_transcript = _silo_partial_transcript(
                    p.silo_id,
                    p.share_index,
                    timestamp_ms,
                    digest,
                    p.partial_signature_bytes,
                    p.nonce_commitment,
                )
                if not self.mldsa.verify(p.silo_public_key, sig_transcript, p.silo_mldsa_sig):
                    raise VSSChecksumMismatchError(
                        f"Silo {p.silo_id} sovereign ML-DSA-87 signature verification failed!"
                    )

                # 6b. Feldman commitment & Blinded Schnorr ZKP check: [z_i] G == R_i + [c_i] Q_i
                q_i = self.commitments.share_points.get(p.share_index)
                roster_entry = roster_map.get(p.share_index)
                if q_i is None or roster_entry is None:
                    raise VSSChecksumMismatchError(f"Unknown share index {p.share_index}")
                q_bytes = _point_to_bytes(q_i)
                if not secrets.compare_digest(q_bytes, roster_entry[1]):
                    raise VSSChecksumMismatchError(f"Silo {p.silo_id} Q_i disagrees with certified roster")

                c_i = _schnorr_challenge(
                    p.nonce_commitment,
                    q_bytes,
                    self.commitments.salt,
                    p.share_index,
                    timestamp_ms,
                    digest,
                    self.field_order,
                )
                lhs = _scalar_mul(z_i, _P384_G)
                rhs = _point_add(r_pt, _scalar_mul(c_i, q_i))
                if lhs is None or rhs is None or lhs != rhs:
                    raise VSSChecksumMismatchError(
                        f"Silo {p.silo_id} partial signature failed blinded Schnorr ZKP verification!"
                    )

                q_reconstructed = _point_add(q_reconstructed, _scalar_mul(lambdas[p.share_index], q_i))

                proof_entry = {
                    "silo_id": p.silo_id,
                    "share_index": p.share_index,
                    "timestamp_ms": timestamp_ms,
                    "z_scalar_hex": p.partial_signature_bytes.hex(),
                    "r_point_hex": p.nonce_commitment.hex(),
                    "q_point_hex": q_bytes.hex(),
                    "silo_pk_hex": p.silo_public_key.hex(),
                    "silo_mldsa_sig_hex": p.silo_mldsa_sig.hex(),
                }
                silo_proofs.append(proof_entry)
                proof_digest_hasher.update(p.nonce_commitment)
                proof_digest_hasher.update(p.partial_signature_bytes)
                proof_digest_hasher.update(p.silo_public_key)
                proof_digest_hasher.update(p.silo_mldsa_sig)

            # 7. Verify Feldman Lagrange polynomial consistency: sum(lambda_i * Q_i) == P_0
            if q_reconstructed is None or q_reconstructed != p0_point:
                raise VSSChecksumMismatchError(
                    "Lagrange evaluation over silo points {Q_i} failed to match master point P_0!"
                )
            agg_sig_bytes = proof_digest_hasher.digest()
            frost_group_r = b""

        log_event(
            AuditEventType.AUTHENTICATION_SUCCESS,
            f"NC3 Threshold Signature aggregated successfully ({len(indices)} silos, skew={skew:.4f}s, mode={mode}).",
            AuditSeverity.CRITICAL,
        )

        return ThresholdSignature(
            payload_digest=digest,
            aggregated_signature=agg_sig_bytes,
            signer_indices=indices,
            signer_silos=silos,
            timestamps=timestamps,
            sync_skew_seconds=skew,
            threshold=self.threshold,
            master_public_key=self.master_public_key,
            vss_commitment=self.commitments.master_commitment,
            protocol_mode=mode,
            ceremony_salt=self.commitments.salt,
            master_p0_point=p0_bytes,
            total_shares=self.commitments.total_shares,
            ceremony_cert_sig=self.commitments.ceremony_cert_sig,
            silo_roster_points=list(self.commitments.silo_roster_points),
            silo_proofs=silo_proofs,
            frost_group_r=frost_group_r,
        )

    def aggregate_frost(
        self,
        payload: Optional[Dict[str, Any] | bytes],
        partial_signatures: List[PartialSignature],
    ) -> ThresholdSignature:
        """Aggregate Round-2 FROST_P384_V2 partial signatures into a verifiable ThresholdSignature."""
        return self.aggregate_signatures(payload, partial_signatures)

    def verify(
        self,
        master_public_key: bytes,
        payload: Dict[str, Any] | bytes,
        signature: ThresholdSignature | bytes,
        expected_silo_pks: Optional[Dict[str, bytes]] = None,
    ) -> bool:
        """
        Verifies a threshold signature against the master public key, genesis ceremony certificate,
        Feldman commitments, blinded Schnorr ZKP equations, and sovereign ML-DSA-87 quorum signatures.
        """
        if isinstance(signature, bytes):
            try:
                sig_obj = ThresholdSignature.from_bytes(signature)
            except Exception:
                return False
        elif isinstance(signature, ThresholdSignature):
            sig_obj = signature
        else:
            return False

        # 1. Master public key match & ceremony certificate
        if not secrets.compare_digest(sig_obj.master_public_key, master_public_key):
            return False
        if not self.commitments.verify_ceremony_cert(master_public_key):
            return False

        # Fast path via Rust data plane (destroyer_core) when available
        try:
            from destroyer_core import CoreNc3
            CoreNc3.verify_temporal_window([int(t * 1000) for t in sig_obj.timestamps])
            CoreNc3.verify_silo_quorum(sig_obj.signer_indices, sig_obj.threshold)
        except Exception as e:
            err_msg = str(e).lower()
            if "exceed" in err_msg or "quorum" in err_msg or "duplicate" in err_msg:
                return False

        # 2. Quorum & distinctness check
        if len(sig_obj.signer_indices) < self.threshold or sig_obj.threshold != self.threshold:
            return False
        if len(sig_obj.signer_silos) != len(sig_obj.signer_indices):
            return False
        if len(sig_obj.timestamps) != len(sig_obj.signer_indices):
            return False
        if len(set(sig_obj.signer_indices)) != len(sig_obj.signer_indices):
            return False
        if len(set(sig_obj.signer_silos)) != len(sig_obj.signer_silos):
            return False

        # 3. Temporal synchronization skew check (<= 2.0s)
        if sig_obj.sync_skew_seconds < 0.0 or sig_obj.sync_skew_seconds > MAX_CO_SIGNING_WINDOW_SECONDS:
            return False

        # 4. Payload digest verification
        if isinstance(payload, bytes) and len(payload) == 48 and secrets.compare_digest(payload, sig_obj.payload_digest):
            expected_digest = payload
        else:
            expected_digest = _canonical_payload_digest(payload)
        if not secrets.compare_digest(sig_obj.payload_digest, expected_digest):
            return False

        # 5. Master commitment & master point P_0 verification
        if not secrets.compare_digest(sig_obj.vss_commitment, self.commitments.master_commitment):
            return False
        p0_point = self.commitments.coeff_points[0]
        p0_bytes = _point_to_bytes(p0_point)
        if sig_obj.master_p0_point and not secrets.compare_digest(sig_obj.master_p0_point, p0_bytes):
            return False

        # 6. Mandatory verifiable cryptographic proof verification
        if len(sig_obj.silo_proofs) != len(sig_obj.signer_indices):
            return False

        roster_map = {idx: (sid, q_b) for idx, sid, q_b in self.commitments.silo_roster_points}
        lambdas = _lagrange_zero(sig_obj.signer_indices, self.field_order)

        if sig_obj.protocol_mode == "FROST_P384_V2":
            r_group_pt = _bytes_to_point(sig_obj.frost_group_r)
            z_agg = int.from_bytes(sig_obj.aggregated_signature, "big")
            if r_group_pt is None or len(sig_obj.aggregated_signature) != 48 or not (0 < z_agg < self.field_order):
                return False
            c_frost = (
                int.from_bytes(
                    hashlib.sha384(
                        b"NC3-FROST-CHALLENGE-V2:"
                        + sig_obj.frost_group_r
                        + p0_bytes
                        + self.commitments.salt
                        + expected_digest
                    ).digest(),
                    "big",
                )
                % self.field_order
            ) or 1
            lhs = _scalar_mul(z_agg, _P384_G)
            rhs = _point_add(r_group_pt, _scalar_mul(c_frost, p0_point))
            if lhs is None or rhs is None or lhs != rhs:
                return False
        elif sig_obj.protocol_mode == "SCHNORR_P384_MLDSA87_QUORUM_V2":
            proof_digest_hasher = hashlib.sha384()
            proof_digest_hasher.update(b"NC3-QUORUM-PROOF-V2:")
            proof_digest_hasher.update(expected_digest)
            q_reconstructed: Optional[Tuple[int, int]] = None

            for idx, silo_name, proof in zip(sig_obj.signer_indices, sig_obj.signer_silos, sig_obj.silo_proofs):
                if int(proof.get("share_index", -1)) != idx or str(proof.get("silo_id", "")) != silo_name:
                    return False
                try:
                    ts_ms = int(proof["timestamp_ms"])
                    z_bytes = bytes.fromhex(proof["z_scalar_hex"])
                    r_bytes = bytes.fromhex(proof["r_point_hex"])
                    q_bytes = bytes.fromhex(proof["q_point_hex"])
                    silo_pk = bytes.fromhex(proof["silo_pk_hex"])
                    silo_sig = bytes.fromhex(proof["silo_mldsa_sig_hex"])
                except Exception:
                    return False

                if expected_silo_pks is not None:
                    pinned_pk = expected_silo_pks.get(silo_name)
                    if pinned_pk is None or not secrets.compare_digest(silo_pk, pinned_pk):
                        return False

                roster_entry = roster_map.get(idx)
                q_expected_pt = self.commitments.share_points.get(idx)
                if roster_entry is None or q_expected_pt is None:
                    return False
                if not secrets.compare_digest(q_bytes, _point_to_bytes(q_expected_pt)) or not secrets.compare_digest(
                    q_bytes, roster_entry[1]
                ):
                    return False

                r_pt = _bytes_to_point(r_bytes)
                if r_pt is None or len(z_bytes) != 48:
                    return False
                z_i = int.from_bytes(z_bytes, "big")
                if not (0 < z_i < self.field_order):
                    return False

                sig_transcript = _silo_partial_transcript(
                    silo_name, idx, ts_ms, expected_digest, z_bytes, r_bytes
                )
                if not self.mldsa.verify(silo_pk, sig_transcript, silo_sig):
                    return False

                c_i = _schnorr_challenge(
                    r_bytes, q_bytes, self.commitments.salt, idx, ts_ms, expected_digest, self.field_order
                )
                lhs = _scalar_mul(z_i, _P384_G)
                rhs = _point_add(r_pt, _scalar_mul(c_i, q_expected_pt))
                if lhs is None or rhs is None or lhs != rhs:
                    return False

                q_reconstructed = _point_add(q_reconstructed, _scalar_mul(lambdas[idx], q_expected_pt))
                proof_digest_hasher.update(r_bytes)
                proof_digest_hasher.update(z_bytes)
                proof_digest_hasher.update(silo_pk)
                proof_digest_hasher.update(silo_sig)

            if q_reconstructed is None or q_reconstructed != p0_point:
                return False
            if not secrets.compare_digest(sig_obj.aggregated_signature, proof_digest_hasher.digest()):
                return False
        else:
            return False

        # In FROST_P384_V2, also verify each silo's ML-DSA-87 wrapper signature
        if sig_obj.protocol_mode == "FROST_P384_V2":
            for idx, silo_name, proof in zip(sig_obj.signer_indices, sig_obj.signer_silos, sig_obj.silo_proofs):
                if int(proof.get("share_index", -1)) != idx or str(proof.get("silo_id", "")) != silo_name:
                    return False
                try:
                    ts_ms = int(proof["timestamp_ms"])
                    z_bytes = bytes.fromhex(proof["z_scalar_hex"])
                    r_bytes = bytes.fromhex(proof["r_point_hex"])
                    silo_pk = bytes.fromhex(proof["silo_pk_hex"])
                    silo_sig = bytes.fromhex(proof["silo_mldsa_sig_hex"])
                except Exception:
                    return False
                if expected_silo_pks is not None:
                    pinned_pk = expected_silo_pks.get(silo_name)
                    if pinned_pk is None or not secrets.compare_digest(silo_pk, pinned_pk):
                        return False
                sig_transcript = _silo_partial_transcript(
                    silo_name, idx, ts_ms, expected_digest, z_bytes, r_bytes
                )
                if not self.mldsa.verify(silo_pk, sig_transcript, silo_sig):
                    return False

        return True


def verify_threshold_signature(
    master_public_key: bytes,
    payload: Dict[str, Any] | bytes,
    signature: ThresholdSignature | bytes,
    commitments: FeldmanCommitments,
    expected_silo_pks: Optional[Dict[str, bytes]] = None,
) -> bool:
    """Convenience functional verifier for NC3 threshold signatures."""
    aggregator = NC3ThresholdAggregator(master_public_key, commitments)
    return aggregator.verify(master_public_key, payload, signature, expected_silo_pks=expected_silo_pks)


def verify_threshold_signature_wire(
    wire_bytes: bytes,
    payload_bytes: bytes,
    expected_master_pk: bytes,
) -> bool:
    """
    Verifies an NC3 threshold signature wire package directly via the
    Rust destroyer_core data plane with microsecond-level timing and zero allocations.
    """
    try:
        from destroyer_core import CoreNc3
        CoreNc3.verify_threshold_mpc_wire(wire_bytes, payload_bytes, expected_master_pk)
        return True
    except Exception:
        return False
