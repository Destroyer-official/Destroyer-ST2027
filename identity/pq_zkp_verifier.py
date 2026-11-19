#!/usr/bin/env python3
"""
identity/pq_zkp_verifier.py
===========================
Post-Quantum Zero-Knowledge Identity Attestation (PQ-ZKP) Engine.

Protects tactical callsign and node identity metadata against wideband SIGINT:
- Anonymous Membership Attestation: Tactical units prove valid STRATCOM clearance
  without revealing their callsign, serial number, unit type, or public key.
- Merkle Accumulator & Constant-Time Verification via Rust Data Plane (`CorePqZkp`).
- Clearance Monotonicity: Top Secret units can attest to Secret without revealing Level 5.
- Epoch-Bound Sybil Nullifiers: Detects and rejects double-attestation in active epochs.
"""

import os
import sys
import time
import json
import struct
import secrets
import hashlib
import logging
import threading
from enum import IntEnum
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from audit_logging_system import log_event, AuditEventType, AuditSeverity
from destroyer_core import CorePqZkp, IS_NATIVE

logger = logging.getLogger("pq_zkp_identity")


class ClearanceLevel(IntEnum):
    """DoD / STRATCOM Security Clearance Hierarchy."""
    UNCLASSIFIED = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4
    TOP_SECRET_SCI_NC3 = 5


class PqZkpError(Exception):
    """Base exception for PQ-ZKP identity attestation failures."""


class InsufficientClearanceError(PqZkpError):
    """Raised when prover does not possess the required clearance level."""


class DoubleAttestationError(PqZkpError):
    """Raised when an epoch nullifier is reused (sybil / replay attack)."""


class ForgedProofError(PqZkpError):
    """Raised when cryptographic verification of a ZKP proof fails fail-closed."""


@dataclass
class TacticalIdentity:
    """Tactical node identity and clearance credential."""
    callsign: str
    serial_number: str
    clearance_level: ClearanceLevel
    public_key_fingerprint: bytes  # 32 bytes SHA3-256 of node ML-DSA-87 public key

    def leaf_hash(self) -> bytes:
        """Computes canonical leaf hash for the STRATCOM accumulator."""
        try:
            return bytes(CorePqZkp.compute_leaf_hash(
                self.callsign,
                self.serial_number,
                int(self.clearance_level),
                self.public_key_fingerprint,
            ))
        except Exception:
            # Fallback pure-Python calculation
            hasher = hashlib.sha3_256()
            hasher.update(b"STRATCOM-ID-LEAF-V1:")
            hasher.update(struct.pack(">H", len(self.callsign.encode("utf-8"))))
            hasher.update(self.callsign.encode("utf-8"))
            hasher.update(struct.pack(">H", len(self.serial_number.encode("utf-8"))))
            hasher.update(self.serial_number.encode("utf-8"))
            hasher.update(bytes([int(self.clearance_level)]))
            hasher.update(self.public_key_fingerprint)
            return hasher.digest()


class StratcomIdentityAccumulator:
    """
    STRATCOM Clearance Registry & Merkle Accumulator Authority.
    Publishes the trusted accumulator root and provides membership witnesses to units.
    """

    def __init__(self, identities: Optional[List[TacticalIdentity]] = None):
        self._identities: List[TacticalIdentity] = identities or []
        self._leaf_hashes: List[bytes] = []
        self.root: bytes = b""
        self._rebuild()

    def add_identity(self, identity: TacticalIdentity) -> int:
        """Registers a cleared tactical node and updates accumulator."""
        idx = len(self._identities)
        self._identities.append(identity)
        self._rebuild()
        return idx

    def _rebuild(self) -> None:
        """Reconstructs the 256-leaf Merkle accumulator tree."""
        self._leaf_hashes = [id_rec.leaf_hash() for id_rec in self._identities]
        if not self._leaf_hashes:
            self._leaf_hashes = [b"\x00" * 32]

        try:
            root_bytes, leaves_out = CorePqZkp.build_merkle_accumulator(self._leaf_hashes)
            self.root = bytes(root_bytes)
        except Exception as e:
            logger.warning(f"CorePqZkp accumulator build fallback: {e}")
            self.root = self._pure_python_build_root(self._leaf_hashes)

    @staticmethod
    def _pure_python_build_root(leaves: List[bytes]) -> bytes:
        """Fallback Merkle accumulator root calculation."""
        num_leaves = 256
        padded = list(leaves)
        while len(padded) < num_leaves:
            padded.append(b"\x00" * 32)

        curr = padded
        for _ in range(8):
            next_lvl = []
            for i in range(0, len(curr), 2):
                h = hashlib.sha3_256()
                h.update(b"STRATCOM-MERKLE-NODE-V1:")
                h.update(curr[i])
                h.update(curr[i + 1])
                next_lvl.append(h.digest())
            curr = next_lvl
        return curr[0]


class PqZkpIdentityProver:
    """
    Tactical Node Anonymous Attestation Engine.
    Generates zero-knowledge membership proofs for physical links, SDR transmissions,
    and cross-domain gateways without revealing callsign, serial number, or identity.
    """

    def __init__(
        self,
        identity: TacticalIdentity,
        accumulator: StratcomIdentityAccumulator,
        leaf_index: int,
    ):
        self.identity = identity
        self.accumulator = accumulator
        self.leaf_index = leaf_index

    def generate_attestation_proof(
        self,
        claimed_min_clearance: ClearanceLevel,
        epoch_id: bytes,
        session_nonce: bytes,
        blinding_salt: Optional[bytes] = None,
    ) -> bytes:
        """
        Generates an anonymous zero-knowledge attestation proof wire package.

        Args:
            claimed_min_clearance: Clearance level being proven (must be <= actual clearance).
            epoch_id: 16-byte operational epoch identifier (e.g. current 24-hour tactical key-epoch).
            session_nonce: 32-byte cryptographic challenge from verifier.
            blinding_salt: Optional 32-byte blinding secret (randomly generated if None).

        Returns:
            Serialized proof wire bytes.
        """
        if self.identity.clearance_level < claimed_min_clearance:
            raise InsufficientClearanceError(
                f"Node clearance {self.identity.clearance_level.name} is insufficient for claimed {claimed_min_clearance.name}"
            )

        if len(epoch_id) != 16:
            raise ValueError("epoch_id must be 16 bytes")
        if len(session_nonce) != 32:
            raise ValueError("session_nonce must be 32 bytes")

        if blinding_salt is None:
            blinding_salt = secrets.token_bytes(32)

        # Generate proof via Rust data plane CorePqZkp
        try:
            wire_bytes = CorePqZkp.prove_identity(
                self.identity.callsign,
                self.identity.serial_number,
                int(self.identity.clearance_level),
                self.identity.public_key_fingerprint,
                self.accumulator._leaf_hashes,
                self.leaf_index,
                int(claimed_min_clearance),
                epoch_id,
                session_nonce,
                blinding_salt,
            )
            return bytes(wire_bytes)
        except Exception as e:
            logger.error(f"CorePqZkp prove_identity error: {e}")
            raise ForgedProofError(f"Failed to generate ZKP proof: {e}")


class PqZkpIdentityVerifier:
    """
    Sovereign Zero-Knowledge Attestation Verifier.
    Verifies anonymous tactical node clearance membership in constant time.
    Prevents SIGINT correlation while strictly validating STRATCOM clearance.
    """

    def __init__(self, trusted_accumulator_root: bytes):
        if len(trusted_accumulator_root) != 32:
            raise ValueError("trusted_accumulator_root must be 32 bytes")
        self.trusted_root = trusted_accumulator_root
        self._epoch_nullifiers: Dict[bytes, Set[bytes]] = {}
        self._lock = threading.Lock()

    def verify_attestation(
        self,
        proof_wire: bytes,
        expected_session_nonce: bytes,
        expected_min_clearance: ClearanceLevel = ClearanceLevel.SECRET,
        epoch_id: Optional[bytes] = None,
    ) -> Tuple[bool, ClearanceLevel, str]:
        """
        Verifies an anonymous tactical node zero-knowledge attestation:
        1. Checks Merkle path consistency against trusted root.
        2. Validates session challenge-response.
        3. Enforces clearance hierarchy.
        4. Detects and rejects sybil double-attestation via nullifier cache.

        Returns:
            (is_valid, verified_clearance_level, nullifier_hex)
        """
        if len(expected_session_nonce) != 32:
            raise ValueError("expected_session_nonce must be 32 bytes")

        with self._lock:
            # Extract epoch_id from wire if not provided
            if epoch_id is None:
                if len(proof_wire) >= 73 and proof_wire[:6] == b"PQZKP1":
                    # offset 6 + 32 (root) + 32 (commit) + 1 (clearance) = 71
                    epoch_id = proof_wire[71:87]
                else:
                    epoch_id = b"\x00" * 16

            seen_nullifiers = list(self._epoch_nullifiers.setdefault(epoch_id, set()))

            try:
                verified_int, nullifier_bytes = CorePqZkp.verify_identity_wire(
                    proof_wire,
                    self.trusted_root,
                    expected_session_nonce,
                    int(expected_min_clearance),
                    seen_nullifiers,
                )
            except Exception as e:
                err_msg = str(e).lower()
                if "stale" in err_msg or "double" in err_msg:
                    log_event(
                        AuditEventType.SECURITY_VIOLATION,
                        "PQ-ZKP Double-attestation / Sybil replay detected in active epoch.",
                        AuditSeverity.CRITICAL,
                    )
                    raise DoubleAttestationError("Nullifier double-attestation in current epoch")
                if "auth" in err_msg or "clearance" in err_msg:
                    raise InsufficientClearanceError(f"Clearance verification failed: {e}")
                log_event(
                    AuditEventType.SECURITY_VIOLATION,
                    f"PQ-ZKP Identity attestation verification failed fail-closed: {e}",
                    AuditSeverity.HIGH,
                )
                raise ForgedProofError(f"Proof verification failed: {e}")

            # Record nullifier in this epoch
            nullifier_b = bytes(nullifier_bytes)
            self._epoch_nullifiers[epoch_id].add(nullifier_b)
            verified_level = ClearanceLevel(verified_int)

            log_event(
                AuditEventType.AUTHENTICATION_SUCCESS,
                f"PQ-ZKP Anonymous Attestation VERIFIED: Clearance {verified_level.name} (Nullifier: {nullifier_b.hex()[:12]}...).",
                AuditSeverity.HIGH,
            )

            return True, verified_level, nullifier_b.hex()
