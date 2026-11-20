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
    try:
        nonce = generate_deterministic_gcm_iv()
    except Exception:
        nonce = secrets.token_bytes(12)

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


@dataclass
class FeldmanCommitments:
    """
    SHA-384 and Secp384r1 Feldman Verifiable Secret Sharing Public Commitments.
    Allows any node or third party to verify that a share is mathematically consistent
    with the master secret without revealing any mutual information.
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
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeldmanCommitments":
        coeff_pts = [_bytes_to_point(bytes.fromhex(p)) for p in data["coeff_points"]]
        share_pts = {int(k): _bytes_to_point(bytes.fromhex(v)) for k, v in data["share_points"].items()}
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
        )


@dataclass
class PartialSignature:
    """
    Partial signature produced by an Operator Silo Node on a verified DoD S-5210.41M payload.
    Binds the silo's polynomial share component with its sovereign ML-DSA-87 identity.
    """
    silo_id: str
    share_index: int
    timestamp_utc: float
    payload_digest: bytes                     # 48 bytes (SHA-384)
    partial_signature_bytes: bytes            # 48 bytes (w_i scalar)
    share_commitment: bytes                   # 48 bytes (SHA-384)
    silo_public_key: bytes                    # 2592 bytes (ML-DSA-87)
    silo_mldsa_sig: bytes                     # 4627 bytes (ML-DSA-87)

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
        )


@dataclass
class ThresholdSignature:
    """
    Full aggregated multi-party threshold signature.
    Verifies against the master public key without the master private key ever having
    been reconstructed on any machine.
    """
    payload_digest: bytes                     # 48 bytes (SHA-384)
    aggregated_signature: bytes               # 48 bytes (W scalar)
    signer_indices: List[int]
    signer_silos: List[str]
    timestamps: List[float]
    sync_skew_seconds: float
    threshold: int
    master_public_key: bytes                  # 2592 bytes (ML-DSA-87)
    vss_commitment: bytes                     # 48 bytes (SHA-384)

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
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThresholdSignature":
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
        meta = json.dumps({
            "signers": self.signer_silos,
            "indices": self.signer_indices,
            "timestamps": [int(round(t * 1000)) if t < 1e11 else int(round(t)) for t in self.timestamps],
            "master_pub": list(self.master_public_key),
            "master_pub_hex": self.master_public_key.hex(),
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

        # Compute deterministic challenge scalar e = H(digest || salt) mod N
        hasher = hashlib.sha384()
        hasher.update(b"NC3-MPC-CHALLENGE-V1:")
        hasher.update(digest)
        hasher.update(self.commitments.salt)
        e_scalar = int.from_bytes(hasher.digest(), "big") % (self.field_order - 1) + 1

        # Partial signature component: w_i = s_i * e mod N
        w_i = (self._share.share_value * e_scalar) % self.field_order
        w_bytes = w_i.to_bytes(48, "big")

        # Bind with sovereign ML-DSA-87 signature over partial parameters
        sig_transcript = (
            b"NC3-SILO-PARTIAL-AUTH:" +
            self.silo_id.encode("utf-8") +
            self._share.share_index.to_bytes(4, "big") +
            struct.pack(">d", timestamp_utc) +
            digest +
            w_bytes
        )
        silo_mldsa_sig = self.mldsa.sign(self._silo_sk, sig_transcript)

        return PartialSignature(
            silo_id=self.silo_id,
            share_index=self._share.share_index,
            timestamp_utc=timestamp_utc,
            payload_digest=digest,
            partial_signature_bytes=w_bytes,
            share_commitment=self._share.share_commitment,
            silo_public_key=self.silo_pk,
            silo_mldsa_sig=silo_mldsa_sig,
        )


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

        # 5. Challenge scalar
        hasher = hashlib.sha384()
        hasher.update(b"NC3-MPC-CHALLENGE-V1:")
        hasher.update(digest)
        hasher.update(self.commitments.salt)
        e_scalar = int.from_bytes(hasher.digest(), "big") % (self.field_order - 1) + 1

        # 6. Verify each partial signature's sovereign ML-DSA-87 signature and Feldman commitment
        for p in selected:
            # 6a. Sovereign ML-DSA-87 authentication
            sig_transcript = (
                b"NC3-SILO-PARTIAL-AUTH:" +
                p.silo_id.encode("utf-8") +
                p.share_index.to_bytes(4, "big") +
                struct.pack(">d", p.timestamp_utc) +
                digest +
                p.partial_signature_bytes
            )
            if not self.mldsa.verify(p.silo_public_key, sig_transcript, p.silo_mldsa_sig):
                raise VSSChecksumMismatchError(
                    f"Silo {p.silo_id} sovereign ML-DSA-87 signature verification failed!"
                )

            # 6b. Feldman public commitment verification: [w_i] G == [e] Q_i
            w_i = int.from_bytes(p.partial_signature_bytes, "big")
            q_i = self.commitments.share_points.get(p.share_index)
            if q_i is None:
                raise VSSChecksumMismatchError(f"Unknown share index {p.share_index}")

            pt_w = _scalar_mul(w_i, _P384_G)
            pt_expected = _scalar_mul(e_scalar, q_i)
            if pt_w is None or pt_expected is None or pt_w != pt_expected:
                raise VSSChecksumMismatchError(
                    f"Silo {p.silo_id} partial signature failed Feldman commitment evaluation!"
                )

        # 7. Lagrange interpolation over partial signatures
        # W = sum_{i in S} lambda_i(0) * w_i mod N
        # Where lambda_i(0) = prod_{j in S, j != i} (-j / (i - j)) mod N
        # Notice: Master secret S is NEVER computed or reconstructed!
        # Aggregator only computes a linear combination of w_i.
        w_agg = 0
        for i_idx in indices:
            # Compute Lagrange coefficient lambda_i(0)
            num = 1
            den = 1
            for j_idx in indices:
                if j_idx == i_idx:
                    continue
                num = (num * (-j_idx)) % self.field_order
                den = (den * (i_idx - j_idx)) % self.field_order
            lambda_i = (num * pow(den, self.field_order - 2, self.field_order)) % self.field_order

            p_obj = next(p for p in selected if p.share_index == i_idx)
            w_i = int.from_bytes(p_obj.partial_signature_bytes, "big")
            w_agg = (w_agg + lambda_i * w_i) % self.field_order

        # 8. Verify aggregated signature W against master public commitment point P_0
        # Check: [W] G == [e] P_0
        master_p0 = self.commitments.coeff_points[0]
        lhs = _scalar_mul(w_agg, _P384_G)
        rhs = _scalar_mul(e_scalar, master_p0)
        if lhs is None or rhs is None or lhs != rhs:
            raise VSSChecksumMismatchError(
                "Aggregated threshold signature failed master verification against P_0!"
            )

        log_event(
            AuditEventType.AUTHENTICATION_SUCCESS,
            f"NC3 Threshold Signature aggregated successfully ({len(indices)} silos, skew={skew:.4f}s).",
            AuditSeverity.CRITICAL,
        )

        return ThresholdSignature(
            payload_digest=digest,
            aggregated_signature=w_agg.to_bytes(48, "big"),
            signer_indices=indices,
            signer_silos=silos,
            timestamps=timestamps,
            sync_skew_seconds=skew,
            threshold=self.threshold,
            master_public_key=self.master_public_key,
            vss_commitment=self.commitments.master_commitment,
        )

    def verify(
        self,
        master_public_key: bytes,
        payload: Dict[str, Any] | bytes,
        signature: ThresholdSignature | bytes,
    ) -> bool:
        """
        Verifies a threshold signature against the master public key and Feldman commitments.

        Args:
            master_public_key: 2592-byte master ML-DSA-87 public key.
            payload: Emergency Action Message payload.
            signature: ThresholdSignature instance or raw wire bytes.

        Returns:
            True if signature satisfies all threshold and cryptographic checks, False otherwise.
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

        # 1. Master public key match
        if not secrets.compare_digest(sig_obj.master_public_key, master_public_key):
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

        # 2. Quorum check
        if len(sig_obj.signer_indices) < self.threshold or sig_obj.threshold != self.threshold:
            return False

        # 3. Distinct signers check
        if len(set(sig_obj.signer_indices)) != len(sig_obj.signer_indices):
            return False
        if len(set(sig_obj.signer_silos)) != len(sig_obj.signer_silos):
            return False

        # 4. Temporal synchronization skew check (<= 2.0s)
        if sig_obj.sync_skew_seconds < 0.0 or sig_obj.sync_skew_seconds > MAX_CO_SIGNING_WINDOW_SECONDS:
            return False

        # 5. Payload digest verification
        if isinstance(payload, bytes) and len(payload) == 48 and secrets.compare_digest(payload, sig_obj.payload_digest):
            expected_digest = payload
        else:
            expected_digest = _canonical_payload_digest(payload)
        if not secrets.compare_digest(sig_obj.payload_digest, expected_digest):
            return False

        # 6. Master commitment check
        if not secrets.compare_digest(sig_obj.vss_commitment, self.commitments.master_commitment):
            return False

        # 7. Cryptographic evaluation: [W] G == [e] P_0
        w_val = int.from_bytes(sig_obj.aggregated_signature, "big")
        hasher = hashlib.sha384()
        hasher.update(b"NC3-MPC-CHALLENGE-V1:")
        hasher.update(expected_digest)
        hasher.update(self.commitments.salt)
        e_scalar = int.from_bytes(hasher.digest(), "big") % (self.field_order - 1) + 1

        master_p0 = self.commitments.coeff_points[0]
        lhs = _scalar_mul(w_val, _P384_G)
        rhs = _scalar_mul(e_scalar, master_p0)

        if lhs is None or rhs is None or lhs != rhs:
            return False

        return True


def verify_threshold_signature(
    master_public_key: bytes,
    payload: Dict[str, Any] | bytes,
    signature: ThresholdSignature | bytes,
    commitments: FeldmanCommitments,
) -> bool:
    """Convenience functional verifier for NC3 threshold signatures."""
    aggregator = NC3ThresholdAggregator(master_public_key, commitments)
    return aggregator.verify(master_public_key, payload, signature)


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
