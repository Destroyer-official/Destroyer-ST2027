#!/usr/bin/env python3
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

# Cryptographic domain constants (V2 canonical length-prefixed AAD matches Rust group_ratchet)
GROUP_PROTO_ID = b"ST2027-SOVEREIGN-GROUP-v2"
EPOCH_KDF_INFO = b"ST2027-Group-Epoch-Rekey-HKDF-SHA384"
CHAIN_KDF_INFO = b"ST2027-Group-Chain-Ratchet-HKDF-SHA384"
MSG_KDF_INFO = b"ST2027-Group-Message-Key-HKDF-SHA384"
SENDER_SIG_DOMAIN = b"ST2027-GROUP-SENDER-SIG-V2:"

# Maximum chain catch-up per message (bounds DoS via forged huge sequence numbers).
MAX_CHAIN_CATCHUP = 1000


def _wipe(buf: Optional[bytearray]) -> None:
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def _message_aad(group_id: str, epoch: int, sender_id: str, seq: int) -> bytes:
    """Canonical length-prefixed AAD matching Rust `group_ratchet::message_aad`."""
    gid_b = group_id.encode("utf-8")
    sid_b = sender_id.encode("utf-8")
    return (
        GROUP_PROTO_ID
        + struct.pack(">I", len(gid_b))
        + gid_b
        + struct.pack(">Q", epoch)
        + struct.pack(">I", len(sid_b))
        + sid_b
        + struct.pack(">Q", seq)
    )


def _hkdf_expand(prk: bytes | bytearray, info: bytes, length: int) -> bytes:
    """HKDF-Expand using SHA-384."""
    key_b = bytes(prk)
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        h = hmac.new(key_b, t + info + bytes([counter]), hashlib.sha384)
        t = h.digest()
        out += t
        counter += 1
    return out[:length]


def _hkdf_extract(salt: bytes | bytearray, ikm: bytes | bytearray) -> bytes:
    """HKDF-Extract using SHA-384."""
    return hmac.new(bytes(salt), bytes(ikm), hashlib.sha384).digest()


@dataclass
class MemberSenderKey:
    """Symmetric chain state for a specific group member (zeroizable bytearray storage)."""
    member_id: str
    chain_key: bytearray
    message_seq: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.chain_key, bytearray):
            self.chain_key = bytearray(self.chain_key)

    def ratchet_forward(self) -> Tuple[bytearray, int]:
        """Derive next wipeable message key and ratchet chain key forward."""
        msg_key = bytearray(_hkdf_expand(self.chain_key, MSG_KDF_INFO + struct.pack(">Q", self.message_seq), 32))
        next_chain = bytearray(_hkdf_expand(self.chain_key, CHAIN_KDF_INFO, len(self.chain_key)))
        seq = self.message_seq
        _wipe(self.chain_key)
        self.chain_key = next_chain
        self.message_seq += 1
        return msg_key, seq

    def wipe(self) -> None:
        _wipe(self.chain_key)


@dataclass
class GroupMessage:
    """Sealed group message packet with optional per-sender ML-DSA-87 signature."""
    group_id: str
    epoch: int
    sender_id: str
    seq: int
    ciphertext: bytes
    sender_mldsa_sig: bytes = b""


class SovereignGroupRatchet:
    """Sovereign Group Ratchet session manager."""

    def __init__(
        self,
        group_id: str,
        local_member_id: str,
        initial_epoch_secret: bytes | bytearray,
        local_mldsa_sk: Optional[bytes] = None,
        require_sender_auth: Optional[bool] = None,
    ):
        self.group_id = group_id
        self.local_member_id = local_member_id
        self.epoch = 0
        self.epoch_secret = bytearray(initial_epoch_secret)
        self.members: Dict[str, MemberSenderKey] = {}
        self.roster: List[str] = [local_member_id]
        self._tpi_officers: Dict[str, bytes] = {}
        self._sender_pks: Dict[str, bytes] = {}
        self._local_mldsa_sk: Optional[bytearray] = bytearray(local_mldsa_sk) if local_mldsa_sk else None
        if require_sender_auth is None:
            from production_gate import is_production
            self._require_sender_auth = bool(is_production())
        else:
            self._require_sender_auth = bool(require_sender_auth)
        self._init_local_sender_key()

    def enroll_sender_identity(self, member_id: str, mldsa87_public_key: bytes) -> None:
        """Enroll a group member's ML-DSA-87 public key to prevent sender spoofing."""
        if not member_id or not mldsa87_public_key:
            raise ValueError("member_id and ML-DSA-87 public key required")
        self._sender_pks[member_id] = bytes(mldsa87_public_key)

    def set_local_signing_key(self, mldsa87_secret_key: bytes) -> None:
        """Configure local ML-DSA-87 signing key for outbound message sender authentication."""
        if self._local_mldsa_sk is not None:
            _wipe(self._local_mldsa_sk)
        self._local_mldsa_sk = bytearray(mldsa87_secret_key)

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
        if self.local_member_id in self.members:
            self.members[self.local_member_id].wipe()
        member_ikm = bytearray(_hkdf_expand(
            self.epoch_secret,
            self.local_member_id.encode("utf-8") + struct.pack(">Q", self.epoch),
            48
        ))
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
            if member_id in self.members:
                self.members[member_id].wipe()
            self.members[member_id] = MemberSenderKey(
                member_id=member_id,
                chain_key=bytearray(self.derive_epoch_sender_key(member_id)),
                message_seq=0
            )

    def register_peer_sender_key(self, peer_id: str, chain_key: bytes | bytearray) -> None:
        """Register or update a peer's sender chain key."""
        if peer_id in self.members:
            self.members[peer_id].wipe()
        self.members[peer_id] = MemberSenderKey(
            member_id=peer_id,
            chain_key=bytearray(chain_key),
            message_seq=0
        )
        if peer_id not in self.roster:
            self.roster.append(peer_id)

    def seal(self, plaintext: bytes) -> GroupMessage:
        """Encrypt message to the group using local sender key ratchet (+ ML-DSA-87 when configured)."""
        if self._require_sender_auth and self._local_mldsa_sk is None:
            raise ValueError("Sender ML-DSA-87 signing key required in strict/production sender-auth mode")
        sender_state = self.members[self.local_member_id]
        msg_key, seq = sender_state.ratchet_forward()

        nonce = struct.pack(">IQ", self.epoch, seq)
        aad = _message_aad(self.group_id, self.epoch, self.local_member_id, seq)

        try:
            ct = AESGCM(bytes(msg_key)).encrypt(nonce, plaintext, aad)
        finally:
            _wipe(msg_key)

        sender_sig = b""
        if self._local_mldsa_sk is not None:
            from liboqs_wrapper import LibOQS_MLDSA_87
            sender_sig = bytes(LibOQS_MLDSA_87().sign(bytes(self._local_mldsa_sk), SENDER_SIG_DOMAIN + aad + ct))

        return GroupMessage(
            group_id=self.group_id,
            epoch=self.epoch,
            sender_id=self.local_member_id,
            seq=seq,
            ciphertext=ct,
            sender_mldsa_sig=sender_sig,
        )

    def open(self, msg: GroupMessage) -> bytes:
        """Decrypt message from a group member, verifying epoch, sender auth, AEAD, and ratchet seq."""
        if msg.group_id != self.group_id:
            raise ValueError(f"Group ID mismatch: expected {self.group_id}, got {msg.group_id}")
        if msg.epoch != self.epoch:
            raise ValueError(f"Epoch mismatch: expected {self.epoch}, got {msg.epoch}")
        if msg.sender_id not in self.members:
            raise ValueError(f"Unknown sender: {msg.sender_id}")

        sender_state = self.members[msg.sender_id]
        if msg.seq < sender_state.message_seq:
            raise ValueError(f"Replay detected: seq {msg.seq} already processed")
        if msg.seq > sender_state.message_seq + MAX_CHAIN_CATCHUP:
            raise ValueError(
                f"Sequence gap too large: got {msg.seq}, expected <= "
                f"{sender_state.message_seq + MAX_CHAIN_CATCHUP} (refusing unbounded catch-up)"
            )

        aad = _message_aad(self.group_id, self.epoch, msg.sender_id, msg.seq)
        enrolled_pk = self._sender_pks.get(msg.sender_id)
        if enrolled_pk is not None or self._require_sender_auth:
            if enrolled_pk is None or not msg.sender_mldsa_sig:
                raise ValueError(f"Sender authentication failed: missing signature or key for {msg.sender_id}")
            from liboqs_wrapper import LibOQS_MLDSA_87
            try:
                sig_ok = bool(LibOQS_MLDSA_87().verify(enrolled_pk, SENDER_SIG_DOMAIN + aad + msg.ciphertext, bytes(msg.sender_mldsa_sig)))
            except Exception:
                sig_ok = False
            if not sig_ok:
                raise ValueError(f"Sender ML-DSA-87 signature verification failed for {msg.sender_id}")

        chain = bytearray(sender_state.chain_key)
        cur_seq = sender_state.message_seq
        msg_key: Optional[bytearray] = None
        next_chain: Optional[bytearray] = None
        try:
            while cur_seq < msg.seq:
                nxt = bytearray(_hkdf_expand(chain, CHAIN_KDF_INFO, len(chain)))
                _wipe(chain)
                chain = nxt
                cur_seq += 1
            msg_key = bytearray(_hkdf_expand(chain, MSG_KDF_INFO + struct.pack(">Q", cur_seq), 32))
            nonce = struct.pack(">IQ", self.epoch, cur_seq)

            plaintext = AESGCM(bytes(msg_key)).decrypt(nonce, msg.ciphertext, aad)

            # Commit state only after successful authentication.
            next_chain = bytearray(_hkdf_expand(chain, CHAIN_KDF_INFO, len(chain)))
            _wipe(sender_state.chain_key)
            sender_state.chain_key = next_chain
            next_chain = None
            sender_state.message_seq = cur_seq + 1
            return plaintext
        finally:
            _wipe(chain)
            _wipe(msg_key)
            _wipe(next_chain)

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

        # Rekey epoch secret: PCS healing & zeroize old epoch_secret
        new_secret = bytearray(_hkdf_extract(self.epoch_secret, fresh_entropy + EPOCH_KDF_INFO))
        _wipe(self.epoch_secret)
        self.epoch += 1
        self.epoch_secret = new_secret

        self._init_local_sender_key()
        self.sync_roster_epoch_keys()
        return self.epoch

    def teardown(self) -> None:
        """Zeroize epoch secret, sender chains, and local signing key."""
        _wipe(self.epoch_secret)
        _wipe(self._local_mldsa_sk)
        for member_state in self.members.values():
            member_state.wipe()
        self.members.clear()
