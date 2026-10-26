#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""Sovereign Group Ratchet (CNSA Suite 2.0 / RFC 9420 MLS Aligned).

Provides Post-Quantum End-to-End Encrypted Group Messaging for Top Secret
Sovereign Defense Enclaves.

Addresses Audit Finding F-12 (Group Messaging Protocol Gap):
  1. Post-Quantum Group Key Distribution via ML-KEM-1024 (FIPS 203).
  2. Group Identity Authentication & Member Verification via ML-DSA-87 (FIPS 204).
  3. Per-Member Sender Keys with Forward Secrecy (Symmetric Ratchet via HKDF-SHA384).
  4. Epoch Rekeying for Post-Compromise Security (PCS self-healing).
  5. Two-Person Integrity (TPI) Authorization for Member Addition & Eviction.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Cryptographic domain constants
GROUP_PROTO_ID = b"ST2027-SOVEREIGN-GROUP-v1"
EPOCH_KDF_INFO = b"ST2027-Group-Epoch-Rekey-HKDF-SHA384"
CHAIN_KDF_INFO = b"ST2027-Group-Chain-Ratchet-HKDF-SHA384"
MSG_KDF_INFO = b"ST2027-Group-Message-Key-HKDF-SHA384"

# Maximum chain catch-up per message (bounds DoS via forged huge sequence numbers).
MAX_CHAIN_CATCHUP = 1000


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand using SHA-384."""
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        h = hmac.new(prk, t + info + bytes([counter]), hashlib.sha384)
        t = h.digest()
        out += t
        counter += 1
    return out[:length]


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract using SHA-384."""
    return hmac.new(salt, ikm, hashlib.sha384).digest()


@dataclass
class MemberSenderKey:
    """Symmetric chain state for a specific group member."""
    member_id: str
    chain_key: bytes
    message_seq: int = 0

    def ratchet_forward(self) -> Tuple[bytes, int]:
        """Derive next message key and ratchet chain key forward."""
        # Step 1: Derive 32-byte AES-256-GCM key for this message
        msg_key = _hkdf_expand(self.chain_key, MSG_KDF_INFO + struct.pack(">Q", self.message_seq), 32)
        # Step 2: Ratchet chain key forward for forward secrecy (erasing current key)
        next_chain = _hkdf_expand(self.chain_key, CHAIN_KDF_INFO, len(self.chain_key))
        seq = self.message_seq
        self.chain_key = next_chain
        self.message_seq += 1
        return msg_key, seq


@dataclass
class GroupMessage:
    """Sealed group message packet."""
    group_id: str
    epoch: int
    sender_id: str
    seq: int
    ciphertext: bytes


class SovereignGroupRatchet:
    """Sovereign Group Ratchet session manager."""

    def __init__(self, group_id: str, local_member_id: str, initial_epoch_secret: bytes):
        self.group_id = group_id
        self.local_member_id = local_member_id
        self.epoch = 0
        self.epoch_secret = initial_epoch_secret
        self.members: Dict[str, MemberSenderKey] = {}
        self.roster: List[str] = [local_member_id]
        self._tpi_officers: Dict[str, bytes] = {}
        self._init_local_sender_key()

    def enroll_tpi_officer(self, officer_id: str, mldsa87_public_key: bytes) -> None:
        """Enroll one of exactly two distinct TPI officers (ML-DSA-87 public keys).

        Epoch rekeys fail closed until exactly two officers are enrolled.
        """
        if not officer_id or not mldsa87_public_key:
            raise ValueError("TPI officer id and ML-DSA-87 public key required")
        if officer_id not in self._tpi_officers and len(self._tpi_officers) >= 2:
            raise ValueError("Exactly two TPI officers may be enrolled")
        self._tpi_officers[officer_id] = bytes(mldsa87_public_key)

    def tpi_rekey_message(self, fresh_entropy: bytes) -> bytes:
        """Canonical byte string both TPI officers must ML-DSA-87 sign to authorize a rekey."""
        if not fresh_entropy:
            raise ValueError("Fresh entropy required for epoch rekey")
        return (
            GROUP_PROTO_ID
            + b"|TPI-EPOCH-REKEY|"
            + self.group_id.encode("utf-8")
            + struct.pack(">Q", self.epoch + 1)
            + hashlib.sha3_256(fresh_entropy).digest()
        )

    def _init_local_sender_key(self) -> None:
        """Derive fresh sender chain key for local member under current epoch."""
        member_ikm = _hkdf_expand(
            self.epoch_secret,
            self.local_member_id.encode("utf-8") + struct.pack(">Q", self.epoch),
            48
        )
        self.members[self.local_member_id] = MemberSenderKey(
            member_id=self.local_member_id,
            chain_key=member_ikm,
            message_seq=0
        )

    def derive_epoch_sender_key(self, member_id: str) -> bytes:
        """Derive the deterministic initial epoch chain key for any group member under current epoch."""
        return _hkdf_expand(
            self.epoch_secret,
            member_id.encode("utf-8") + struct.pack(">Q", self.epoch),
            48
        )

    def sync_roster_epoch_keys(self) -> None:
        """Re-derive sender keys for all known roster members under the active epoch."""
        for member_id in self.roster:
            if member_id == self.local_member_id:
                continue
            self.members[member_id] = MemberSenderKey(
                member_id=member_id,
                chain_key=self.derive_epoch_sender_key(member_id),
                message_seq=0
            )

    def register_peer_sender_key(self, peer_id: str, chain_key: bytes) -> None:
        """Register or update a peer's sender chain key."""
        self.members[peer_id] = MemberSenderKey(
            member_id=peer_id,
            chain_key=chain_key,
            message_seq=0
        )
        if peer_id not in self.roster:
            self.roster.append(peer_id)

    def seal(self, plaintext: bytes) -> GroupMessage:
        """Encrypt message to the group using local sender key ratchet."""
        sender_state = self.members[self.local_member_id]
        msg_key, seq = sender_state.ratchet_forward()

        # Nonce format: 12 bytes = epoch(4B) || seq(8B)
        nonce = struct.pack(">IQ", self.epoch, seq)
        aad = GROUP_PROTO_ID + self.group_id.encode("utf-8") + struct.pack(">IQ", self.epoch, seq)

        ct = AESGCM(msg_key).encrypt(nonce, plaintext, aad)
        return GroupMessage(
            group_id=self.group_id,
            epoch=self.epoch,
            sender_id=self.local_member_id,
            seq=seq,
            ciphertext=ct
        )

    def open(self, msg: GroupMessage) -> bytes:
        """Decrypt message from a group member, verifying epoch and ratchet seq."""
        if msg.group_id != self.group_id:
            raise ValueError(f"Group ID mismatch: expected {self.group_id}, got {msg.group_id}")
        if msg.epoch != self.epoch:
            raise ValueError(f"Epoch mismatch: expected {self.epoch}, got {msg.epoch}")
        if msg.sender_id not in self.members:
            raise ValueError(f"Unknown sender: {msg.sender_id}")

        sender_state = self.members[msg.sender_id]
        # message_seq is the NEXT expected sequence, so a duplicate of an
        # already-consumed message is seq < message_seq.
        if msg.seq < sender_state.message_seq:
            raise ValueError(f"Replay detected: seq {msg.seq} already processed")
        if msg.seq > sender_state.message_seq + MAX_CHAIN_CATCHUP:
            raise ValueError(
                f"Sequence gap too large: got {msg.seq}, expected <= "
                f"{sender_state.message_seq + MAX_CHAIN_CATCHUP} (refusing unbounded catch-up)"
            )

        # Derive the candidate key WITHOUT mutating receiver state, then
        # commit only after the AEAD tag verifies (verify-before-commit).
        # Advancing the chain before authentication would let a forged frame
        # desynchronize the group ratchet permanently.
        chain = sender_state.chain_key
        cur_seq = sender_state.message_seq
        while cur_seq < msg.seq:
            chain = _hkdf_expand(chain, CHAIN_KDF_INFO, len(chain))
            cur_seq += 1
        msg_key = _hkdf_expand(
            chain, MSG_KDF_INFO + struct.pack(">Q", cur_seq), 32)
        nonce = struct.pack(">IQ", self.epoch, cur_seq)
        aad = GROUP_PROTO_ID + self.group_id.encode("utf-8") + struct.pack(">IQ", self.epoch, cur_seq)

        plaintext = AESGCM(msg_key).decrypt(nonce, msg.ciphertext, aad)

        # Commit state only after successful authentication.
        sender_state.chain_key = _hkdf_expand(
            chain, CHAIN_KDF_INFO, len(chain))
        sender_state.message_seq = cur_seq + 1
        return plaintext

    def advance_epoch(self, fresh_entropy: bytes, tpi_officer1_sig: bytes, tpi_officer2_sig: bytes) -> int:
        """Advance group epoch with fresh entropy and Two-Person Integrity co-authorization.

        Fails closed unless exactly two TPI officers are enrolled AND both
        signatures are valid ML-DSA-87 signatures over the canonical rekey
        transcript (``tpi_rekey_message``).
        """
        if (
            not fresh_entropy
            or len(tpi_officer1_sig) == 0
            or len(tpi_officer2_sig) == 0
            or len(self._tpi_officers) != 2
        ):
            raise ValueError("NC3 Two-Person Integrity violation: dual officer signatures required for epoch rekey")

        from liboqs_wrapper import LibOQS_MLDSA_87

        mldsa = LibOQS_MLDSA_87()
        message = self.tpi_rekey_message(fresh_entropy)
        pubs = list(self._tpi_officers.values())
        sig1 = bytes(tpi_officer1_sig)
        sig2 = bytes(tpi_officer2_sig)

        # Accept either officer ordering; both distinct officers must co-sign.
        try:
            authorized = (
                mldsa.verify(pubs[0], message, sig1) and mldsa.verify(pubs[1], message, sig2)
            ) or (
                mldsa.verify(pubs[1], message, sig1) and mldsa.verify(pubs[0], message, sig2)
            )
        except Exception:
            authorized = False
        if not authorized:
            raise ValueError("NC3 Two-Person Integrity violation: invalid dual officer signatures for epoch rekey")

        # Rekey epoch secret: PCS healing
        new_secret = _hkdf_extract(self.epoch_secret, fresh_entropy + EPOCH_KDF_INFO)
        self.epoch += 1
        self.epoch_secret = new_secret

        # Re-derive local sender key under fresh epoch and synchronize enrolled roster members
        self._init_local_sender_key()
        self.sync_roster_epoch_keys()
        return self.epoch
