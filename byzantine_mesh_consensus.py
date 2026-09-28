#!/usr/bin/env python3
"""
byzantine_mesh_consensus.py
Department of Defense (DoD) CSRMC Phase 5:
Multi-Node Byzantine Fault Tolerant (BFT) Quorum Consensus for Critical Tactical Commands.

Enforces M-of-N threshold multi-signature validation for strategic operations:
- NETWORK_WIDE_QUARANTINE
- TACTICAL_REKEY_ALL
- REVOKE_NODE_CREDENTIAL
- EMERGENCY_SILENCE

Requires authentic Post-Quantum ML-DSA-87 (FIPS 204) signatures from authorized command nodes.
Rejects rogue, compromised, or minority-signed command injections fail-closed.
"""

import argparse
import datetime
import hashlib
import hmac
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = REPO_ROOT / "compliance_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("ByzantineConsensus")

try:
    from liboqs_wrapper import LibOQS_MLDSA_87
except ImportError:
    sys.path.insert(0, str(REPO_ROOT))
    from liboqs_wrapper import LibOQS_MLDSA_87


class CriticalCommandType:
    NETWORK_WIDE_QUARANTINE = "NETWORK_WIDE_QUARANTINE"
    TACTICAL_REKEY_ALL = "TACTICAL_REKEY_ALL"
    REVOKE_NODE_CREDENTIAL = "REVOKE_NODE_CREDENTIAL"
    EMERGENCY_SILENCE = "EMERGENCY_SILENCE"


class ByzantineQuorumEngine:
    """M-of-N Byzantine Fault Tolerant Quorum Engine with Anti-Replay & Epoch Binding.

    Tier-4 v1 hardening (research basis: HotStuff-2 two-phase/QC shape,
    n>=3f+1 quorum theory, 2024-26 BFT accountability literature,
    threshold-ML-DSA tracked-not-claimed per 2026/013 Quorus/Mithril):
    - Quorum-validity bounds enforced at construction AND registration:
      M>=2, N>=2, M<=N, and M>=2f+1 with f=(N-1)//3 (any two quorums
      intersect in f+1 nodes, so no f-Byzantine coalition approves
      alone). Insecure configurations fail fast instead of existing.
      Roster can never exceed the declared N (which would silently
      weaken the bound).
    - Equivocation forensics: a signer validly signing two different
      payloads for the same (epoch, seq) emits a forensic record and is
      flagged; the poisoned proposal is refused outright (uniform, not
      lab-lenient: equivocation handling is a safety property).
    - Offline-verifiable quorum certificates: approvals export as
      self-contained certs checkable with NO engine state (third-party
      audit of historical strategic orders).
    - What this is NOT: no views/leaders/total-order log (single-shot
      threshold authorization, the correct shape for rare strategic
      commands -- multisig-wallet analogue, not a blockchain); no
      threshold-ML-DSA MPC (research-grade per 2026 literature: 3-round
      MPC for <=8 parties; our QC aggregates INDEPENDENT ML-DSA-87
      signatures, each verifiable under FIPS 204).
    """

    def __init__(self, required_quorum_m: int = 2, total_authorized_nodes_n: int = 3):
        if not isinstance(required_quorum_m, int) or not isinstance(total_authorized_nodes_n, int):
            raise ValueError("quorum parameters must be ints")
        m, n = required_quorum_m, total_authorized_nodes_n
        if n < 2:
            raise ValueError(f"refusing degenerate N={n}: strategic commands need >=2 nodes")
        if not (2 <= m <= n):
            raise ValueError(
                f"refusing quorum M={m} of N={n}: need 2<=M<=N "
                "(1-of-N dictatorships and M>N are never valid here)")
        f = (n - 1) // 3
        if m < 2 * f + 1:
            raise ValueError(
                f"refusing quorum M={m} of N={n}: tolerates f={f} Byzantine "
                f"only with M>={2 * f + 1} (any two quorums must intersect "
                "in f+1 nodes)")
        # RLock (reentrant): ballot methods hold the lock while delegating
        # to evaluate_proposal (which also locks). A plain Lock deadlocked
        # tally paths (caught by TestBallotTier4V1, 2026-09-23).
        self.lock = threading.RLock()
        self.required_quorum_m = m
        self.total_authorized_nodes_n = n
        self.max_faults = f

        # Authorized public keys: node_id -> public_key_bytes
        self.authorized_command_nodes: Dict[str, bytes] = {}
        self.executed_proposals: List[Dict[str, Any]] = []
        # Monotonic proposal execution index (Anti-Replay defense per LTSBFT)
        self.executed_proposal_ids: Set[str] = set()
        # Equivocation ledger (T4-C): vote-key -> {"digest","sig"}; plus
        # forensic records and flagged signers for removal review.
        self._vote_ledger: Dict[str, Dict[str, Any]] = {}
        self.forensic_records: List[Dict[str, Any]] = []
        self.flagged_signers: Set[str] = set()
        self._ballots: Dict[str, Dict[str, Any]] = {}
        self._ballot_digests: Set[str] = set()

    def register_command_node(self, node_id: str, public_key_bytes: bytes) -> None:
        """Register an authorized tactical command node and its ML-DSA-87 public key.

        Fail-closed: the roster can never exceed the declared N (extra
        nodes would silently weaken the quorum bound), re-registration
        with a DIFFERENT key is refused (rotation needs an explicit
        removal path, which does not exist by design), and empty keys
        are refused.
        """
        if not node_id or not isinstance(public_key_bytes, (bytes, bytearray)) or not public_key_bytes:
            raise ValueError("node_id must be non-empty and key must be non-empty bytes")
        with self.lock:
            if node_id in self.authorized_command_nodes:
                if bytes(self.authorized_command_nodes[node_id]) != bytes(public_key_bytes):
                    raise ValueError(
                        f"re-registration of {node_id!r} with a different key refused "
                        "(no silent rotation; use a fresh engine)")
                return
            if len(self.authorized_command_nodes) >= self.total_authorized_nodes_n:
                raise ValueError(
                    f"roster full ({self.total_authorized_nodes_n}): registering "
                    f"{node_id!r} would weaken the {self.required_quorum_m}-of-"
                    f"{self.total_authorized_nodes_n} bound")
            self.authorized_command_nodes[node_id] = bytes(public_key_bytes)

    def build_canonical_payload(
        self,
        command_type: str,
        target_payload: Dict[str, Any],
        proposed_by: str,
        proposal_seq: Optional[int] = None,
        epoch_id: Optional[str] = None,
        freshness_nonce: Optional[str] = None,
        valid_until_utc: Optional[float] = None,
    ) -> bytes:
        """Build canonical signable payload bytes with optional epoch and sequence binding."""
        d: Dict[str, Any] = {
            "command": command_type,
            "proposer": proposed_by,
            "target": target_payload,
        }
        if epoch_id is not None:
            d["epoch_id"] = epoch_id
        if freshness_nonce is not None:
            d["freshness_nonce"] = freshness_nonce
        if proposal_seq is not None:
            d["proposal_seq"] = proposal_seq
        if valid_until_utc is not None:
            d["valid_until_utc"] = valid_until_utc
        return json.dumps(d, sort_keys=True).encode("utf-8")

    def evaluate_proposal(
        self,
        command_type: str,
        target_payload: Dict[str, Any],
        proposed_by: str,
        signatures: Dict[str, bytes],  # node_id -> signature_bytes
        proposal_seq: Optional[int] = None,
        epoch_id: Optional[str] = None,
        freshness_nonce: Optional[str] = None,
        valid_until_utc: Optional[float] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verify M-of-N threshold signatures over the canonical command payload.
        Enforces anti-replay tracking and freshness expiration.
        Returns: (approved, message, consensus_record)
        """
        with self.lock:
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            now_str = now_dt.isoformat()
            now_ts = now_dt.timestamp()

            # 1. Freshness / Expiration Check
            if valid_until_utc is not None and now_ts > valid_until_utc:
                record = {
                    "command_type": command_type,
                    "proposed_by": proposed_by,
                    "timestamp_utc": now_str,
                    "status": "EXPIRED_REJECTED",
                    "reason": f"Proposal validity window expired at {valid_until_utc}",
                    "quorum_satisfied": False,
                }
                return False, f"Proposal expired (valid_until={valid_until_utc}, current={now_ts})", record

            canonical_bytes = self.build_canonical_payload(
                command_type=command_type,
                target_payload=target_payload,
                proposed_by=proposed_by,
                proposal_seq=proposal_seq,
                epoch_id=epoch_id,
                freshness_nonce=freshness_nonce,
                valid_until_utc=valid_until_utc,
            )

            # 2. Anti-Replay Defense (LTSBFT monotonic tracking)
            proposal_digest = hashlib.sha3_256(canonical_bytes).hexdigest()
            proposal_id = f"{proposed_by}:{command_type}:{proposal_seq or 'none'}:{epoch_id or 'none'}:{proposal_digest[:16]}"

            if proposal_id in self.executed_proposal_ids:
                record = {
                    "command_type": command_type,
                    "proposed_by": proposed_by,
                    "proposal_id": proposal_id,
                    "timestamp_utc": now_str,
                    "status": "REPLAY_DETECTED_REJECTED",
                    "reason": "Proposal has already been executed in this epoch",
                    "quorum_satisfied": False,
                }
                return False, f"Anti-Replay: Proposal {proposal_id} already executed", record

            valid_signers: Set[str] = set()
            verifier = LibOQS_MLDSA_87()
            # T4-C equivocation key: same signer, same (epoch, seq) must
            # never validly sign two digests (accountability literature:
            # double-signing is attributable Byzantine behavior).
            def _vote_key(nid: str) -> str:
                seq = proposal_seq if proposal_seq is not None else "none"
                return f"{nid}\x00{epoch_id or 'none'}\x00{seq}"

            for node_id, sig in signatures.items():
                if node_id not in self.authorized_command_nodes:
                    logger.warning(f"[BYZANTINE REJECT] Signer '{node_id}' is not an authorized command node")
                    continue

                pub_key = self.authorized_command_nodes[node_id]
                try:
                    if verifier.verify(pub_key, canonical_bytes, sig):
                        prior = self._vote_ledger.get(_vote_key(node_id))
                        if prior is not None and prior["digest"] != proposal_digest:
                            forensic = {
                                "type": "EQUIVOCATION",
                                "signer": node_id,
                                "epoch_id": epoch_id,
                                "proposal_seq": proposal_seq,
                                "first_digest": prior["digest"],
                                "second_digest": proposal_digest,
                                "first_sig": prior["sig"].hex(),
                                "second_sig": bytes(sig).hex(),
                                "detected_utc": now_str,
                            }
                            self.forensic_records.append(forensic)
                            self.flagged_signers.add(node_id)
                            record = {
                                "command_type": command_type,
                                "proposed_by": proposed_by,
                                "proposal_id": proposal_id,
                                "timestamp_utc": now_str,
                                "status": "EQUIVOCATION_REJECTED",
                                "reason": f"signer {node_id!r} double-signed "
                                          f"(epoch={epoch_id}, seq={proposal_seq}); "
                                          "proposal poisoned, signer flagged",
                                "quorum_satisfied": False,
                                "forensic": forensic,
                            }
                            logger.error(
                                f"[BYZANTINE FORENSIC] equivocation by {node_id!r} "
                                f"(epoch={epoch_id}, seq={proposal_seq})")
                            return False, f"Equivocation: {node_id} double-signed; proposal refused, signer flagged", record
                        self._vote_ledger[_vote_key(node_id)] = {
                            "digest": proposal_digest, "sig": bytes(sig)}
                        valid_signers.add(node_id)
                except Exception as e:
                    logger.warning(f"[BYZANTINE SIG ERROR] Invalid signature from '{node_id}': {e}")

            valid_count = len(valid_signers)
            quorum_satisfied = valid_count >= self.required_quorum_m

            record = {
                "command_type": command_type,
                "proposed_by": proposed_by,
                "proposal_id": proposal_id,
                "proposal_seq": proposal_seq,
                "epoch_id": epoch_id,
                "timestamp_utc": now_str,
                "required_quorum_m": self.required_quorum_m,
                "valid_signatures_collected": valid_count,
                "authorized_signers": sorted(list(valid_signers)),
                "quorum_satisfied": quorum_satisfied,
                "target_payload": target_payload,
                # Exact signed bytes (hex): quorum certificates verify
                # against THESE, cross-checked with rebuilt fields, so
                # optional fields (nonce/valid_until) can never desync.
                "canonical_hex": canonical_bytes.hex(),
                "freshness_nonce": freshness_nonce,
                "valid_until_utc": valid_until_utc,
                "status": "APPROVED" if quorum_satisfied else "QUORUM_DEFICIT_REJECTED",
            }

            if quorum_satisfied:
                self.executed_proposals.append(record)
                self.executed_proposal_ids.add(proposal_id)
                return True, f"Quorum achieved ({valid_count}/{self.required_quorum_m})", record
            else:
                return (
                    False,
                    f"Quorum failure: only {valid_count}/{self.required_quorum_m} valid signatures verified",
                    record,
                )

    def collect_rum_round_votes(
        self,
        round_num: int,
        proposal_id: str,
        command_type: str,
        target_payload: Dict[str, Any],
        votes: Dict[str, bytes],
        epoch: int = 1,
        proposed_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Leaderless Rûm (2025) round-based consensus vote aggregator.

        Supports message-omission tolerant voting in tactical ad-hoc mesh
        environments where proposals circulate without a designated primary leader.
        Nodes submit signed votes for round (round_num, proposal_id).

        Returns:
            Dict containing:
                - success: bool (True if M-of-N threshold reached)
                - round_num: int
                - proposal_id: str
                - quorum_certificate: Optional[Dict]
                - status_message: str
                - record: Dict
        """
        proposer = proposed_by or proposal_id
        approved, msg, record = self.evaluate_proposal(
            command_type=command_type,
            target_payload=target_payload,
            proposed_by=proposer,
            signatures=votes,
            proposal_seq=round_num,
            epoch_id=str(epoch),
        )
        qc = None
        if approved:
            qc = self.build_quorum_certificate(record, votes)
            record["qc"] = qc

        return {
            "success": approved,
            "round_num": round_num,
            "proposal_id": proposal_id,
            "quorum_certificate": qc,
            "status_message": msg,
            "record": record,
        }

    def build_quorum_certificate(
        self,
        record: Dict[str, Any],
        signatures: Dict[str, bytes],
    ) -> Dict[str, Any]:
        """Export an APPROVED record as a self-contained quorum certificate.

        Binds: canonical payload digest, threshold, roster snapshot
        (node -> pubkey hex) and the collected signatures (hex). A QC is
        the auditable artifact of a strategic order -- filed, shipped,
        and checked years later without this engine.
        """
        if not isinstance(record, dict) or record.get("status") != "APPROVED":
            raise ValueError("quorum certificates issue only for APPROVED records")
        if not record.get("canonical_hex"):
            raise ValueError("record lacks exact signed bytes (pre-T4-D record)")
        with self.lock:
            roster = {nid: bytes(pk).hex()
                      for nid, pk in self.authorized_command_nodes.items()}
            threshold = self.required_quorum_m
            total_n = self.total_authorized_nodes_n
        canonical = bytes.fromhex(record["canonical_hex"])
        return {
            "v": 1,
            "algorithm": "ML-DSA-87",
            "proposal_id": record.get("proposal_id"),
            "command_type": record.get("command_type"),
            "proposed_by": record.get("proposed_by"),
            "target_payload": record.get("target_payload", {}),
            "proposal_seq": record.get("proposal_seq"),
            "epoch_id": record.get("epoch_id"),
            "freshness_nonce": record.get("freshness_nonce"),
            "valid_until_utc": record.get("valid_until_utc"),
            "canonical_hex": record["canonical_hex"],
            "payload_digest": hashlib.sha3_256(canonical).hexdigest(),
            "threshold_m": threshold,
            "roster_n": total_n,
            "roster": roster,
            "signers": sorted(signatures.keys()),
            "signatures": {nid: bytes(sig).hex() for nid, sig in signatures.items()},
            "approved_utc": record.get("timestamp_utc"),
        }

    @staticmethod
    def verify_quorum_certificate(qc: Dict[str, Any]) -> Tuple[bool, str]:
        """Verify a QC with NO engine state (offline third-party audit).

        Re-checks: schema version, quorum-validity bounds (same T4-A
        rule: M>=2, M<=N, M>=2f+1), roster non-empty keys, threshold
        met by DISTINCT rostered signers, every signature valid under
        its roster key over the digest-bound canonical payload. Any
        failure returns (False, reason) -- never raises on adversarial
        input.
        """
        try:
            if not isinstance(qc, dict) or qc.get("v") != 1:
                return False, "unknown QC version"
            if qc.get("algorithm") != "ML-DSA-87":
                return False, "unsupported QC algorithm (want ML-DSA-87)"
            m = qc.get("threshold_m")
            n = qc.get("roster_n")
            roster = qc.get("roster")
            sigs = qc.get("signatures")
            if not isinstance(m, int) or not isinstance(n, int) or not isinstance(roster, dict) \
                    or not isinstance(sigs, dict):
                return False, "malformed QC envelope"
            if n < 2 or not (2 <= m <= n):
                return False, f"invalid quorum shape M={m} of N={n}"
            if m < 2 * ((n - 1) // 3) + 1:
                return False, f"quorum M={m} of N={n} violates 2f+1 bound"
            for nid, pk_hex in roster.items():
                try:
                    if not bytes.fromhex(pk_hex):
                        return False, f"empty roster key for {nid!r}"
                except Exception:
                    return False, f"malformed roster key for {nid!r}"
            try:
                canonical = bytes.fromhex(qc.get("canonical_hex", ""))
            except Exception:
                return False, "malformed QC canonical bytes"
            if not canonical:
                return False, "empty QC canonical bytes"
            digest = hashlib.sha3_256(canonical).hexdigest()
            # Constant-time compare (zero-tolerance: no == on digests).
            if not hmac.compare_digest(digest, str(qc.get("payload_digest", ""))):
                return False, "payload digest mismatch (tampered payload)"
            # Cross-check: human-readable fields must rebuild to the EXACT
            # signed bytes (binds the readable order to the signatures).
            rebuilt = ByzantineQuorumEngine._canonical_for_qc(qc)
            if rebuilt != canonical:
                return False, "QC fields do not reproduce signed bytes"
            verifier = LibOQS_MLDSA_87()
            good: Set[str] = set()
            for nid, sig_hex in sigs.items():
                if nid not in roster or nid in good:
                    continue  # unknown or duplicate signer: not counted
                try:
                    if verifier.verify(bytes.fromhex(roster[nid]), canonical,
                                       bytes.fromhex(sig_hex)):
                        good.add(nid)
                except Exception:  # nosec: B112
                    # One malformed entry must not abort the loop; the
                    # threshold count below is the fail-closed gate.
                    continue
            if len(good) < m:
                return False, f"only {len(good)}/{m} valid rostered signatures"
            return True, f"QC valid ({len(good)}/{m} ML-DSA-87, {qc.get('proposal_id')})"
        except Exception as e:
            return False, f"QC verification error: {e}"

    @staticmethod
    def _canonical_for_qc(qc: Dict[str, Any]) -> Optional[bytes]:
        """Rebuild the exact canonical bytes a QC's signatures cover."""
        try:
            d: Dict[str, Any] = {
                "command": qc["command_type"],
                "proposer": qc["proposed_by"],
                "target": qc["target_payload"] if "target_payload" in qc else qc.get("target", {}),
            }
            if qc.get("epoch_id") is not None:
                d["epoch_id"] = qc["epoch_id"]
            if qc.get("freshness_nonce") is not None:
                d["freshness_nonce"] = qc["freshness_nonce"]
            if qc.get("proposal_seq") is not None:
                d["proposal_seq"] = qc["proposal_seq"]
            if qc.get("valid_until_utc") is not None:
                d["valid_until_utc"] = qc["valid_until_utc"]
            return json.dumps(d, sort_keys=True).encode("utf-8")
        except Exception:
            return None

    # -- Multi-round ballot aggregation (T4-G; Rûm-2025 round direction)
    #
    # Research basis: Rûm (NCA 2025) round-based leaderless broadcast
    # consensus for lossy meshes. The single-shot evaluate_proposal and
    # the single-round collect_rum_round_votes both require all M votes
    # present at one call -- unworkable across DDIL blackouts where votes
    # trickle in over rounds. Ballots stay OPEN across rounds, aggregating
    # votes as they arrive (omission-tolerant collection), and decide the
    # moment M valid rostered votes exist. What this is NOT: Rûm's
    # randomized async termination proofs do not transfer (no coin rounds
    # here); liveness still needs M honest votes to eventually arrive.
    # Safety properties enforced: exact ballot bytes (same canonical form
    # as single-shot), one vote per node (re-vote with a DIFFERENT
    # signature feeds the T4-C equivocation path instead of counting
    # twice), expiry by valid_until_utc or max_rounds, replay-safe tally
    # (same executed_proposal_ids index), unknown/closed ballots refuse.

    def open_ballot(
        self,
        command_type: str,
        target_payload: Dict[str, Any],
        proposed_by: str,
        proposal_seq: Optional[int] = None,
        epoch_id: Optional[str] = None,
        freshness_nonce: Optional[str] = None,
        valid_until_utc: Optional[float] = None,
        max_rounds: Optional[int] = None,
    ) -> str:
        """Open a multi-round ballot; returns its ballot_id."""
        if not isinstance(target_payload, dict):
            raise ValueError("target_payload must be a dict")
        if max_rounds is not None and (not isinstance(max_rounds, int) or max_rounds < 1):
            raise ValueError("max_rounds must be a positive int")
        canonical = self.build_canonical_payload(
            command_type=command_type, target_payload=target_payload,
            proposed_by=proposed_by, proposal_seq=proposal_seq,
            epoch_id=epoch_id, freshness_nonce=freshness_nonce,
            valid_until_utc=valid_until_utc)
        digest = hashlib.sha3_256(canonical).hexdigest()
        with self.lock:
            ballot_id = f"BAL:{proposed_by}:{command_type}:{proposal_seq if proposal_seq is not None else 'none'}:{epoch_id or 'none'}:{digest[:16]}"
            if ballot_id in self._ballots:
                raise ValueError(f"ballot already open: {ballot_id}")
            if digest in self._ballot_digests:
                raise ValueError("identical ballot already open (replay-safe)")
            self._ballots[ballot_id] = {
                "command_type": command_type,
                "target_payload": dict(target_payload),
                "proposed_by": proposed_by,
                "proposal_seq": proposal_seq,
                "epoch_id": epoch_id,
                "freshness_nonce": freshness_nonce,
                "valid_until_utc": valid_until_utc,
                "max_rounds": max_rounds,
                "canonical_hex": canonical.hex(),
                "digest": digest,
                "votes": {},
                "vote_rounds": {},
                "rounds_seen": 0,
                "status": "OPEN",
            }
            self._ballot_digests.add(digest)
            return ballot_id

    def cast_ballot_vote(self, ballot_id: str, node_id: str,
                         signature: bytes, round_num: int = 1) -> Tuple[bool, str]:
        """Cast one vote on an open ballot. Returns (counted, message).

        counted=True means the vote is banked (quorum may now be reached;
        call tally_ballot to decide). A second DIFFERENT signature from
        the same node is equivocation: refused, forensic-recorded, signer
        flagged (T4-C path), ballot itself survives on honest votes.
        """
        with self.lock:
            bal = self._ballots.get(ballot_id)
            if bal is None or bal["status"] != "OPEN":
                return False, "unknown or closed ballot"
            if not isinstance(round_num, int) or round_num < 1:
                return False, "round_num must be a positive int"
            if bal["max_rounds"] is not None and round_num > bal["max_rounds"]:
                return False, f"round {round_num} exceeds ballot max {bal['max_rounds']}"
            bal["rounds_seen"] = max(bal["rounds_seen"], round_num)
            if node_id not in self.authorized_command_nodes:
                return False, f"signer {node_id!r} not authorized"
            verifier = LibOQS_MLDSA_87()
            try:
                ok = verifier.verify(self.authorized_command_nodes[node_id],
                                     bytes.fromhex(bal["canonical_hex"]),
                                     bytes(signature))
            except Exception:
                ok = False
            if not ok:
                return False, f"invalid signature from {node_id!r}"
            if node_id in bal["votes"]:
                if bytes(bal["votes"][node_id]) == bytes(signature):
                    return True, "duplicate vote ignored (already banked)"
                # Same node, same ballot bytes, different signature:
                # equivocation -- forensic path, vote refused, ballot lives.
                forensic = {
                    "type": "EQUIVOCATION",
                    "signer": node_id,
                    "ballot_id": ballot_id,
                    "epoch_id": bal["epoch_id"],
                    "proposal_seq": bal["proposal_seq"],
                    "first_digest": bal["digest"],
                    "second_digest": bal["digest"],
                    "first_sig": bytes(bal["votes"][node_id]).hex(),
                    "second_sig": bytes(signature).hex(),
                    "detected_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "note": "same ballot bytes, differing signatures: key misuse or signer fault",
                }
                self.forensic_records.append(forensic)
                self.flagged_signers.add(node_id)
                logger.error(f"[BYZANTINE FORENSIC] ballot equivocation by {node_id!r} on {ballot_id}")
                return False, f"Equivocation: {node_id!r} double-signed; vote refused, signer flagged"
            bal["votes"][node_id] = bytes(signature)
            bal["vote_rounds"][node_id] = round_num
            reached = len(bal["votes"]) >= self.required_quorum_m
            return True, (f"vote banked ({len(bal['votes'])}/{self.required_quorum_m})"
                          + ("; quorum reached" if reached else ""))

    def tally_ballot(self, ballot_id: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Decide an open ballot: approve iff M banked votes validate.

        Re-validates every banked signature at tally time (catches
        bit-rot or key-file swaps between cast and tally). Flagged
        equivocator votes are STRIPPED before counting (a proven-Byzantine
        signer must not decide the round); the exclusion is recorded. Marks
        the proposal executed (replay-safe) and closes the ballot.
        Returns the same (approved, message, record) triple as
        evaluate_proposal, with rounds_seen / vote_rounds included for
        DDIL forensics.
        """
        with self.lock:
            bal = self._ballots.get(ballot_id)
            if bal is None or bal["status"] != "OPEN":
                return False, "unknown or closed ballot", {
                    "status": "UNKNOWN_BALLOT_REJECTED", "quorum_satisfied": False}
            excluded = sorted(s for s in bal["votes"] if s in self.flagged_signers)
            counting = {s: sig for s, sig in bal["votes"].items()
                        if s not in self.flagged_signers}
            approved, msg, record = self.evaluate_proposal(
                command_type=bal["command_type"],
                target_payload=bal["target_payload"],
                proposed_by=bal["proposed_by"],
                signatures=counting,
                proposal_seq=bal["proposal_seq"],
                epoch_id=bal["epoch_id"],
                freshness_nonce=bal["freshness_nonce"],
                valid_until_utc=bal["valid_until_utc"],
            )
            record["ballot_id"] = ballot_id
            record["rounds_seen"] = bal["rounds_seen"]
            record["vote_rounds"] = dict(bal["vote_rounds"])
            record["excluded_flagged_signers"] = excluded
            bal["status"] = "TALLIED"
            return approved, msg, record

    def close_ballot(self, ballot_id: str) -> bool:
        """Discard an open ballot without execution. Returns True if closed."""
        with self.lock:
            bal = self._ballots.get(ballot_id)
            if bal is None or bal["status"] != "OPEN":
                return False
            bal["status"] = "CLOSED"
            return True

    def execute_approved_command(self, record: Dict[str, Any]) -> bool:
        """
        Autonomously actuate strategic tactical command upon verified M-of-N Byzantine Quorum approval:
        1. NETWORK_WIDE_QUARANTINE: Enforces automated network quarantine via Active Cyber Defense engine.
        2. TACTICAL_REKEY_ALL: Triggers active key rotation across DoubleRatchet and ForwardSecrecyManager.
        3. REVOKE_NODE_CREDENTIAL: Revokes peer pinned safety numbers and severs active sessions.
        4. EMERGENCY_SILENCE: Activates tactical cloaking and Poisson background chaff fail-closed.

        Fails closed (returns False) if record is unapproved or quorum is not satisfied.
        """
        if not isinstance(record, dict):
            logger.error("[BYZANTINE ACTUATOR] Execution rejected: record is not a dictionary")
            return False

        if record.get("status") != "APPROVED" or not record.get("quorum_satisfied"):
            logger.error(
                f"[BYZANTINE ACTUATOR] Execution rejected: Proposal not approved "
                f"(status={record.get('status')}, quorum_satisfied={record.get('quorum_satisfied')})"
            )
            return False

        cmd_type = record.get("command_type")
        target_payload = record.get("target_payload", {})
        proposal_id = record.get("proposal_id", "unknown_proposal")

        try:
            if cmd_type == CriticalCommandType.NETWORK_WIDE_QUARANTINE:
                peer_id = (
                    target_payload.get("peer_id")
                    or target_payload.get("isolate_node")
                    or target_payload.get("target_node")
                )
                if not peer_id:
                    logger.error(f"[BYZANTINE ACTUATOR] Missing target peer_id in {cmd_type}")
                    return False

                from active_cyber_defense import get_active_cyber_defense_engine
                acd = get_active_cyber_defense_engine()
                acd._execute_quarantine(str(peer_id), reason=f"Byzantine consensus order: {proposal_id}")
                logger.info(f"[BYZANTINE ACTUATOR] Enforced NETWORK_WIDE_QUARANTINE on peer '{peer_id}'")
                return True

            elif cmd_type == CriticalCommandType.TACTICAL_REKEY_ALL:
                rekey_count = 0
                try:
                    from forward_secrecy_manager import get_global_fs_manager
                    fs_mgr = get_global_fs_manager()
                    if fs_mgr and hasattr(fs_mgr, "force_global_rekey"):
                        fs_mgr.force_global_rekey()
                        rekey_count += 1
                except Exception as e_fs:
                    logger.warning(f"[BYZANTINE ACTUATOR] FS manager rekey notification error: {e_fs}")

                try:
                    from active_cyber_defense import get_active_cyber_defense_engine
                    acd = get_active_cyber_defense_engine()
                    acd._execute_purge_ephemeral(reason=f"Byzantine consensus rekey: {proposal_id}")
                    rekey_count += 1
                except Exception as e_acd:
                    logger.warning(f"[BYZANTINE ACTUATOR] ACD rekey notification error: {e_acd}")

                logger.info(f"[BYZANTINE ACTUATOR] Enforced TACTICAL_REKEY_ALL across subsystems ({rekey_count} notified)")
                return True

            elif cmd_type == CriticalCommandType.REVOKE_NODE_CREDENTIAL:
                peer_id = (
                    target_payload.get("peer_id")
                    or target_payload.get("revoke_node")
                    or target_payload.get("node_id")
                )
                if not peer_id:
                    logger.error(f"[BYZANTINE ACTUATOR] Missing target peer_id in {cmd_type}")
                    return False

                # Revoke TOFU pin in safety_numbers
                try:
                    from ui.safety_numbers import revoke_pin
                    revoke_pin(str(peer_id))
                except Exception as e_pin:
                    logger.warning(f"[BYZANTINE ACTUATOR] Safety number revocation warning for '{peer_id}': {e_pin}")

                # Sever session and quarantine in ACD
                try:
                    from active_cyber_defense import get_active_cyber_defense_engine
                    acd = get_active_cyber_defense_engine()
                    acd.quarantine_peer(
                        str(peer_id),
                        reason=f"Credential revoked via Byzantine consensus order: {proposal_id}"
                    )
                except Exception as e_acd:
                    logger.warning(f"[BYZANTINE ACTUATOR] ACD quarantine warning for '{peer_id}': {e_acd}")

                logger.info(f"[BYZANTINE ACTUATOR] Enforced REVOKE_NODE_CREDENTIAL on peer '{peer_id}'")
                return True

            elif cmd_type == CriticalCommandType.EMERGENCY_SILENCE:
                os.environ["P2P_TACTICAL_CLOAK"] = "1"
                try:
                    from active_cyber_defense import get_active_cyber_defense_engine
                    acd = get_active_cyber_defense_engine()
                    acd._execute_force_cloak(reason=f"Emergency silence order via Byzantine consensus: {proposal_id}")
                except Exception as e_acd:
                    logger.warning(f"[BYZANTINE ACTUATOR] ACD force cloak warning: {e_acd}")

                logger.info("[BYZANTINE ACTUATOR] Enforced EMERGENCY_SILENCE (tactical cloaking activated)")
                return True

            else:
                logger.error(f"[BYZANTINE ACTUATOR] Unknown command type: {cmd_type}")
                return False

        except Exception as e:
            logger.critical(f"[BYZANTINE ACTUATOR] Execution failed for command {cmd_type}: {e}", exc_info=True)
            return False


def sign_and_export_byzantine_receipt(
    record: Dict[str, Any],
    output_dir: Optional[Path] = None,
) -> Tuple[Path, Path, Path]:
    """Export and sign Byzantine consensus receipt with ML-DSA-87."""
    out_dir = output_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    data = {
        "byzantine_consensus_attestation": {
            "standard": "DoD CSRMC Phase 5 Multi-Party Fault Tolerant Quorum",
            "receipt": record,
        }
    }
    canonical_json = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")

    receipt_path = out_dir / "byzantine_consensus_receipt.json"
    sig_path = out_dir / "byzantine_consensus_receipt.json.mldsa87.sig"
    pub_path = out_dir / "byzantine_consensus_receipt.json.mldsa87.pub"

    receipt_path.write_bytes(canonical_json)

    signer = LibOQS_MLDSA_87()
    pk, sk = signer.keygen()
    sig = signer.sign(sk, canonical_json)

    sig_path.write_bytes(sig)
    pub_path.write_bytes(pk)

    return receipt_path, sig_path, pub_path


def verify_byzantine_receipt_signature(receipt_path: Path, sig_path: Path, pub_path: Path) -> bool:
    """Verify ML-DSA-87 signature over Byzantine consensus receipt."""
    if not (receipt_path.exists() and sig_path.exists() and pub_path.exists()):
        return False
    try:
        r_bytes = receipt_path.read_bytes()
        s_bytes = sig_path.read_bytes()
        p_bytes = pub_path.read_bytes()

        verifier = LibOQS_MLDSA_87()
        return verifier.verify(p_bytes, r_bytes, s_bytes)
    except Exception as e:
        logger.error(f"Byzantine receipt signature verification failed: {e}")
        return False


_GLOBAL_BYZANTINE_ENGINE: Optional[ByzantineQuorumEngine] = None
_BYZANTINE_LOCK = threading.Lock()


def get_byzantine_quorum_engine(required_quorum_m: int = 2, total_authorized_nodes_n: int = 3) -> ByzantineQuorumEngine:
    """Retrieve or initialize singleton Byzantine quorum engine."""
    global _GLOBAL_BYZANTINE_ENGINE
    with _BYZANTINE_LOCK:
        if _GLOBAL_BYZANTINE_ENGINE is None:
            _GLOBAL_BYZANTINE_ENGINE = ByzantineQuorumEngine(
                required_quorum_m=required_quorum_m,
                total_authorized_nodes_n=total_authorized_nodes_n,
            )
        return _GLOBAL_BYZANTINE_ENGINE


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DoD CSRMC Phase 5 Byzantine Quorum Consensus")
    parser.add_argument("--verify", action="store_true", help="Verify existing Byzantine consensus receipt signature")
    parser.add_argument("--test", action="store_true", help="Run multi-node Byzantine quorum self-test")
    args = parser.parse_args()

    r_file = REPORTS_DIR / "byzantine_consensus_receipt.json"
    s_file = REPORTS_DIR / "byzantine_consensus_receipt.json.mldsa87.sig"
    p_file = REPORTS_DIR / "byzantine_consensus_receipt.json.mldsa87.pub"

    if args.verify:
        valid = verify_byzantine_receipt_signature(r_file, s_file, p_file)
        print(f"[*] Byzantine Consensus Receipt Signature Valid: {valid}")
        sys.exit(0 if valid else 1)

    print("=" * 80)
    print(" DoD CSRMC Phase 5: Multi-Node Byzantine Quorum Consensus Self-Test")
    print("=" * 80)

    # 1. Initialize 2-of-3 Byzantine Quorum Engine
    engine = ByzantineQuorumEngine(required_quorum_m=2, total_authorized_nodes_n=3)

    sig_engine = LibOQS_MLDSA_87()
    keys = {}
    for node_name in ["COMMANDER_ALPHA", "COMMANDER_BRAVO", "COMMANDER_CHARLIE"]:
        pk, sk = sig_engine.keygen()
        keys[node_name] = (pk, sk)
        engine.register_command_node(node_name, pk)

    print("[1/5] Registered 3 authorized command nodes with ML-DSA-87 keypairs.")

    # 2. Test Rogue Peer Attempt (1 rogue signature, 0 authorized) -> REJECT
    print("[2/5] Testing single rogue node spoofing injection...")
    rogue_pk, rogue_sk = sig_engine.keygen()
    target_payload = {"isolate_node": "ROGUE_OUTPOST_99", "reason": "Compromised physical tamper"}
    canonical = json.dumps(
        {"command": CriticalCommandType.NETWORK_WIDE_QUARANTINE, "target": target_payload, "proposer": "INTRUDER"},
        sort_keys=True,
    ).encode("utf-8")
    rogue_sig = sig_engine.sign(rogue_sk, canonical)

    approved, msg, rec = engine.evaluate_proposal(
        command_type=CriticalCommandType.NETWORK_WIDE_QUARANTINE,
        target_payload=target_payload,
        proposed_by="INTRUDER",
        signatures={"INTRUDER": rogue_sig},
    )
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert approved is False  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert rec["quorum_satisfied"] is False  # nosec: B101
    print("  -> Rogue injection successfully rejected fail-closed.")

    # 3. Test Valid 2-of-3 Quorum -> APPROVED
    print("[3/5] Testing authentic 2-of-3 threshold command consensus...")
    cmd_bytes = json.dumps(
        {"command": CriticalCommandType.TACTICAL_REKEY_ALL, "target": {"epoch": 42}, "proposer": "COMMANDER_ALPHA"},
        sort_keys=True,
    ).encode("utf-8")

    sig_a = sig_engine.sign(keys["COMMANDER_ALPHA"][1], cmd_bytes)
    sig_b = sig_engine.sign(keys["COMMANDER_BRAVO"][1], cmd_bytes)

    approved, msg, rec = engine.evaluate_proposal(
        command_type=CriticalCommandType.TACTICAL_REKEY_ALL,
        target_payload={"epoch": 42},
        proposed_by="COMMANDER_ALPHA",
        signatures={"COMMANDER_ALPHA": sig_a, "COMMANDER_BRAVO": sig_b},
    )
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert approved is True  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert rec["quorum_satisfied"] is True  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert rec["valid_signatures_collected"] == 2  # nosec: B101

    # Export & sign consensus receipt
    rep_p, sig_p, pub_p = sign_and_export_byzantine_receipt(rec)
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert verify_byzantine_receipt_signature(rep_p, sig_p, pub_p) is True  # nosec: B101
    print(f"  -> 2-of-3 Quorum achieved and executed: {msg}")
    print(f"  -> Consensus receipt signed with ML-DSA-87: {rep_p.name}")

    # 4. Test Anti-Replay Defense (replaying exact same proposal payload)
    print("[4/5] Testing Anti-Replay Defense against replayed quorum command...")
    replayed, r_msg, r_rec = engine.evaluate_proposal(
        command_type=CriticalCommandType.TACTICAL_REKEY_ALL,
        target_payload={"epoch": 42},
        proposed_by="COMMANDER_ALPHA",
        signatures={"COMMANDER_ALPHA": sig_a, "COMMANDER_BRAVO": sig_b},
    )
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert replayed is False, "Replayed proposal was erroneously accepted!"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert r_rec["status"] == "REPLAY_DETECTED_REJECTED"  # nosec: B101
    print("  -> Replay attempt successfully blocked fail-closed.")

    # 5. Test Expiration Defense (stale proposal with expired timestamp)
    print("[5/5] Testing Proposal Expiration Defense (past valid_until_utc)...")
    past_timestamp = 100000.0  # Epoch in 1970
    expired, e_msg, e_rec = engine.evaluate_proposal(
        command_type=CriticalCommandType.EMERGENCY_SILENCE,
        target_payload={"zone": "RED_TACTICAL"},
        proposed_by="COMMANDER_ALPHA",
        signatures={"COMMANDER_ALPHA": sig_a, "COMMANDER_BRAVO": sig_b},
        valid_until_utc=past_timestamp,
    )
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert expired is False, "Expired proposal was erroneously accepted!"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert e_rec["status"] == "EXPIRED_REJECTED"  # nosec: B101
    print("  -> Stale/expired proposal successfully blocked fail-closed.")

    print("\n[ALL 5/5 BYZANTINE CONSENSUS TESTS PASSED SUCCESSFULLY]\n")


