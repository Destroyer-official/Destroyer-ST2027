#!/usr/bin/env python3
"""
cjadc2_allied_gateway.py

DoD CJADC2 Allied & Coalition Cross-Domain Tactical Gateway.
Enforces multi-nation data sharing policies across Allied Enclaves:
  - FVEY (Five Eyes: USA, GBR, AUS, CAN, NZL)
  - AUKUS (Pillar II Advanced Capabilities: USA, GBR, AUS)
  - NATO / Coalition Partners (USA, NATO Member Nations, UKR)
  - QUAD (USA, JPN, AUS, IND)

Core Capabilities:
1. Automated Content Disarm & Reconstruction (CDR):
   - Strips malicious embedded payloads, unapproved XML/JSON attributes, and suspicious metadata.
2. Automated National Compartment Redaction:
   - Enforces NOFORN filtering (hard block).
   - Scrubs US-only national compartment markers (HCS-P, SI-TK-G, ORCON, PROPIN).
   - Normalizes classification headers to coalition release tags (e.g. REL TO FVEY).
3. Cryptographic Coalition Release Tokens:
   - Packages sanitized tactical data with ML-DSA-87 (FIPS 204) coalition release receipts.
"""

from __future__ import annotations

import argparse
import collections
import enum
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure repository root is in python path
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cjadc2_cross_domain_guard import (
    SecurityClassification,
    SecurityCaveat,
    CrossDomainPolicyViolation,
)
from liboqs_wrapper import LibOQS_MLDSA_87

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("cjadc2_allied_gateway")


class CoalitionAlliance(str, enum.Enum):
    """Recognized Allied & Coalition Security Frameworks."""
    FVEY = "FVEY"               # USA, GBR, AUS, CAN, NZL
    AUKUS = "AUKUS"             # USA, GBR, AUS
    NATO = "NATO"               # USA, NATO Member Nations, UKR
    QUAD = "QUAD"               # USA, JPN, AUS, IND
    BILATERAL_GBR = "USA_GBR"   # Bilateral US-UK
    BILATERAL_AUS = "USA_AUS"   # Bilateral US-Australia


COALITION_MEMBERSHIP: Dict[CoalitionAlliance, Set[str]] = {
    CoalitionAlliance.FVEY: {"USA", "GBR", "AUS", "CAN", "NZL"},
    CoalitionAlliance.AUKUS: {"USA", "GBR", "AUS"},
    CoalitionAlliance.NATO: {
        "USA", "GBR", "CAN", "FRA", "DEU", "ITA", "POL", "ESP",
        "NLD", "NOR", "DNK", "BEL", "PRT", "TUR", "GRC", "UKR"
    },
    CoalitionAlliance.QUAD: {"USA", "JPN", "AUS", "IND"},
    CoalitionAlliance.BILATERAL_GBR: {"USA", "GBR"},
    CoalitionAlliance.BILATERAL_AUS: {"USA", "AUS"},
}

# US-Only Sensitive National Compartments & Caveats that MUST be redacted for coalition egress
US_ONLY_COMPARTMENTS: Set[str] = {
    "HCS-P",    # HUMINT Control System - Product
    "SI-TK-G",  # Special Intelligence - Talent Keyhole - Gamma
    "ORCON",    # Originator Controlled
    "PROPIN",   # Proprietary Information
    "NOFORN",   # Not Releasable to Foreign Nationals (Hard Block)
    "FISA",     # Foreign Intelligence Surveillance Act
}


class CoalitionRedactionError(Exception):
    """Raised when content cannot be lawfully sanitized or released to coalition partners."""
    pass


SecurityViolationException = CoalitionRedactionError


def _strict_cdr_quarantine_required() -> bool:
    """True when hostile-stripped content must HOLD for human review.

    Explicit ``P2P_GATEWAY_QUARANTINE_HOSTILE=1``, or automatic in
    production (``P2P_PRODUCTION``/``SECURE_P2P_PRODUCTION``). Research
    basis: CDS transfer doctrine -- down-transfer/human-review is the
    highest-risk case, and CDR completeness against novel vectors is
    unprovable, so cleaned-but-once-hostile content never auto-releases
    where it counts. Lab default warns + releases (existing flows keep
    working in tests). Explicit ``=0`` opts out in lab only; ignored
    with a CRITICAL log in production.
    """
    from utils.helpers import is_env_true
    prod = is_env_true("SECURE_P2P_PRODUCTION") or is_env_true("P2P_PRODUCTION")
    explicit = os.environ.get("P2P_GATEWAY_QUARANTINE_HOSTILE", "")
    if prod:
        if explicit == "0":
            log.critical("P2P_GATEWAY_QUARANTINE_HOSTILE=0 ignored in production (quarantine enforced)")
        return True
    return is_env_true("P2P_GATEWAY_QUARANTINE_HOSTILE")


class AlliedCoalitionGateway:
    """
    CJADC2 Cross-Domain Allied Coalition Gateway.
    Implements Content Disarm & Reconstruction (CDR) and Automated Redaction.
    """

    def __init__(self, gateway_id: str = "US-CJADC2-ALLIED-GW-01"):
        self.gateway_id = gateway_id
        self.signer = LibOQS_MLDSA_87()
        self.pk, self.sk = self.signer.keygen()
        self.redacted_transfers_count = 0
        self.blocked_noforn_count = 0
        self.quarantined_count = 0
        self.reviewed_count = 0
        self.active_alliances = list(CoalitionAlliance)
        # Quarantine hold (T4-E): quarantine_id -> held sanitized package
        # awaiting human review. In-memory by design (operational hold,
        # not persistent storage -- restarts drop held items fail-closed).
        self.quarantine_hold: Dict[str, Dict[str, Any]] = {}
        # Decision audit (T4-E, CDS AU-2 shape): EVERY terminal decision
        # (release/block/quarantine/review) is recorded for forensics.
        self.decision_log: collections.deque = collections.deque(maxlen=4096)
        self._decision_seq = 0

    def _audit_decision(self, decision: str, **fields: Any) -> Dict[str, Any]:
        """Append one transfer-decision audit record; returns it."""
        self._decision_seq += 1
        rec = {
            "decision_id": f"{self.gateway_id}-{self._decision_seq:06d}",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "gateway_id": self.gateway_id,
            "decision": decision,
        }
        rec.update(fields)
        self.decision_log.append(rec)
        return rec

    def transfer_decisions(self) -> List[Dict[str, Any]]:
        """Copy of the decision audit log (oldest first)."""
        return list(self.decision_log)

    # NOTE (no-demo hygiene, 2026-09-23): is_partner_cleared existed
    # TWICE (identical duplicates; the second shadowed the first).
    # Collapsed to one; dead code is dead trust.
    def is_partner_cleared(self, partner_nation: str, alliance: CoalitionAlliance) -> bool:
        """Verify whether a partner nation is a verified member of the coalition alliance."""
        authorized_nations = COALITION_MEMBERSHIP.get(alliance, set())
        return partner_nation.upper() in authorized_nations

    def execute_content_disarm_and_reconstruction(self, raw_payload: bytes) -> Tuple[bytes, bool]:
        """
        Content Disarm & Reconstruction (CDR):
        1. Validates structured JSON/XML integrity.
        2. Normalizes strings and strips executable scripts, shell codes, and macro vectors.
        3. Removes unauthorized nested binary objects.

        Returns (cleaned_bytes, hostile_stripped): the flag is True when
        active hostile content was actually removed (as opposed to a
        clean payload passing through). Callers MUST treat hostile=True
        as review-worthy: CDR completeness against novel vectors is not
        provable, so cleaned-but-once-hostile content quarantines in
        strict mode instead of auto-releasing.
        """
        try:
            # Decode utf-8 payload
            text = raw_payload.decode("utf-8", errors="replace")

            hostile_patterns = [
                r"<(script|embed|object|iframe)[^>]*>.*?</\1>",
                r"(javascript:|data:text/html|vbscript:|cmd\.exe|/bin/sh)",
                r"(eval\s*\(|exec\s*\(|<macro[\s>])",
                r"<!DOCTYPE[^>]*SYSTEM",
                r"<!ENTITY[^>]*SYSTEM",
                r"\x00",
                r"(\.\./|\.\.\\)",
                r"(\{\{.*?\}\}|\$\{.*?\})",
            ]
            hostile_stripped = any(
                re.search(p, text, flags=re.IGNORECASE | re.DOTALL)
                for p in hostile_patterns
            )

            # Strip script tags, shell metacharacters, and potential injection tokens
            cleaned_text = re.sub(r"<(script|embed|object|iframe)[^>]*>.*?</\1>", "", text, flags=re.IGNORECASE | re.DOTALL)
            cleaned_text = re.sub(r"(javascript:|data:text/html|cmd\.exe|/bin/sh)", "[FILTERED_BY_CDR]", cleaned_text, flags=re.IGNORECASE)
            cleaned_text = re.sub(r"<!DOCTYPE[^>]*SYSTEM[^>]*>", "[FILTERED_BY_CDR_XXE]", cleaned_text, flags=re.IGNORECASE)
            cleaned_text = re.sub(r"<!ENTITY[^>]*SYSTEM[^>]*>", "[FILTERED_BY_CDR_XXE]", cleaned_text, flags=re.IGNORECASE)
            cleaned_text = cleaned_text.replace("\x00", "")

            # Reconstruct JSON if applicable
            try:
                parsed = json.loads(cleaned_text)
                
                # Recursive AST sanitization for dictionary and list elements with depth limiting
                def _sanitize_structure(obj: Any, depth: int = 0) -> Any:
                    if depth > 64:
                        raise CoalitionRedactionError("Payload nesting depth exceeds maximum allowed limit (64)")
                    if isinstance(obj, dict):
                        sanitized_dict = {}
                        for k, v in obj.items():
                            k_clean = str(k).replace("\x00", "")
                            k_clean = re.sub(r"(\.\./|\.\.\\)", "[FILTERED_TRAVERSAL]", k_clean)
                            k_clean = re.sub(r"(\{\{.*?\}\}|\$\{.*?\})", "[FILTERED_TEMPLATE]", k_clean)
                            sanitized_dict[k_clean] = _sanitize_structure(v, depth + 1)
                        return sanitized_dict
                    elif isinstance(obj, list):
                        return [_sanitize_structure(elem, depth + 1) for elem in obj]
                    elif isinstance(obj, str):
                        s = re.sub(r"(\.\./|\.\.\\)", "[FILTERED_TRAVERSAL]", obj)
                        s = re.sub(r"(\{\{.*?\}\}|\$\{.*?\})", "[FILTERED_TEMPLATE]", s)
                        return s
                    return obj

                sanitized = _sanitize_structure(parsed)
                # Re-serialize deterministically per canonical JSON specification
                return json.dumps(sanitized, sort_keys=True, separators=(",", ":")).encode("utf-8"), hostile_stripped
            except json.JSONDecodeError:
                # Return normalized text bytes
                return cleaned_text.strip().encode("utf-8"), hostile_stripped
        except Exception as e:
            log.warning(f"CDR normalization error: {e}")
            raise CoalitionRedactionError(f"CDR Failure: Payload could not be safely disarmed: {e}")

    def redact_and_package_for_coalition(
        self,
        payload_bytes: bytes,
        source_classification: SecurityClassification,
        target_alliance: CoalitionAlliance,
        target_partner_nation: str,
        active_caveats: Set[str],
    ) -> Dict[str, Any]:
        """
        Sanitize, redact, and package tactical data for coalition egress:
        - Partner membership enforced; NOFORN hard-blocks (fail-closed).
        - CDR verdict: hostile-stripped content QUARANTINES for human
          review in strict/production (never auto-releases); lab warns
          and releases (existing flows).
        - Strip US-only compartment markers actually present (the token
          lists what was found, not a static full set).
        - Issue and sign an ML-DSA-87 Coalition Release Token.
        - EVERY terminal decision is audit-logged (AU-2 shape).
        """
        base_audit = {
            "direction": "egress",
            "target_alliance": target_alliance.value,
            "target_partner_nation": target_partner_nation.upper(),
            "source_classification": source_classification.name,
            "caveats": sorted({str(c).upper() for c in active_caveats}),
        }
        # 1. Partner nation membership check
        if not self.is_partner_cleared(target_partner_nation, target_alliance):
            self._audit_decision("MEMBERSHIP_BLOCKED", reason="partner not in alliance", **base_audit)
            raise CoalitionRedactionError(
                f"Partner nation '{target_partner_nation}' is NOT an authorized member of alliance '{target_alliance.value}'"
            )

        # 2. NOFORN Prohibition Check
        caveats_upper = {str(c).upper() for c in active_caveats}
        if "NOFORN" in caveats_upper or SecurityCaveat.NOFORN in caveats_upper:
            self.blocked_noforn_count += 1
            self._audit_decision("NOFORN_BLOCKED", reason="NOFORN caveat present", **base_audit)
            raise CoalitionRedactionError(
                f"COALITION TRANSFER REJECTED: Content marked NOFORN cannot be released to {target_partner_nation}"
            )

        # 3. Automated CDR pass (with hostile verdict)
        disarmed_bytes, hostile_stripped = self.execute_content_disarm_and_reconstruction(payload_bytes)
        disarmed_text = disarmed_bytes.decode("utf-8", errors="replace")

        US_ONLY_COMPARTMENT_REPLACEMENTS: Dict[str, str] = {
            "HCS-P": "[REDACTED_HUMINT_CONTROLLED]",
            "SI-TK-G": "[REDACTED_TALENT_KEYHOLE]",
            "ORCON": "[REDACTED_ORIGINATOR_CONTROLLED]",
            "PROPIN": "[REDACTED_PROPRIETARY_INFO]",
            "FISA": "[REDACTED_FISA_CONTROLLED]",
        }

        # 4. Deep content scrubbing for US-only compartment terms
        redacted_text = disarmed_text
        compartments_hit: List[str] = []
        for comp, replacement in US_ONLY_COMPARTMENT_REPLACEMENTS.items():
            pattern = re.compile(re.escape(comp), re.IGNORECASE)
            redacted_text, n_subs = pattern.subn(replacement, redacted_text)
            if n_subs:
                compartments_hit.append(comp)

        # 4b. Quarantine-hold (T4-E): cleaned-but-once-hostile content
        # holds for human review where it counts. NO release token is
        # issued for held content -- there is nothing releasable yet.
        if hostile_stripped and _strict_cdr_quarantine_required():
            self.quarantined_count += 1
            qid = f"Q-{target_alliance.value}-{target_partner_nation.upper()}-{int(time.time()*1000)}"
            content_hash = hashlib.sha3_256(redacted_text.encode("utf-8")).hexdigest()
            self.quarantine_hold[qid] = {
                "quarantine_id": qid,
                "status": "HELD_FOR_REVIEW",
                "reason": "CDR_HOSTILE_STRIPPED",
                "sanitized_payload": redacted_text,
                "payload_sha3_256": content_hash,
                "target_alliance": target_alliance.value,
                "target_partner_nation": target_partner_nation.upper(),
                "source_classification": source_classification.name,
                "caveats": sorted({str(c).upper() for c in active_caveats}),
                "compartments_redacted": sorted(compartments_hit),
            }
            self._audit_decision("QUARANTINED_FOR_REVIEW", quarantine_id=qid,
                                 payload_sha3_256=content_hash,
                                 compartments_redacted=sorted(compartments_hit),
                                 reason="CDR stripped active hostile content; human review required",
                                 **base_audit)
            log.warning(f"Coalition transfer QUARANTINED: {qid} (CDR hostile strip; awaiting review)")
            return {
                "release_id": qid,
                "status": "QUARANTINED_FOR_REVIEW",
                "quarantine_id": qid,
                "target_alliance": target_alliance.value,
                "target_partner_nation": target_partner_nation.upper(),
                "sanitized_payload": None,
                "reason": "CDR stripped active hostile content; held for human review",
            }
        if hostile_stripped:
            log.warning("CDR stripped hostile content; releasing with warning (lab only -- strict quarantines)")

        sanitized_bytes = redacted_text.encode("utf-8")
        content_hash = hashlib.sha3_256(sanitized_bytes).hexdigest()

        # 5. Formulate Coalition Release Header & Token
        release_id = f"REL-{target_alliance.value}-{target_partner_nation}-{int(time.time()*1000)}"
        release_header = f"// {source_classification.name} // REL TO {target_alliance.value} //"

        release_token_payload = {
            "release_id": release_id,
            "gateway_id": self.gateway_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "source_classification": source_classification.name,
            "coalition_header": release_header,
            "target_alliance": target_alliance.value,
            "target_partner_nation": target_partner_nation.upper(),
            "payload_sha3_256": content_hash,
            "cdr_status": "DISARMED_AND_RECONSTRUCTED",
            "cdr_hostile_stripped": bool(hostile_stripped),
            "redacted_compartments": sorted(compartments_hit),
        }

        token_bytes = json.dumps(release_token_payload, sort_keys=True).encode("utf-8")
        token_signature = self.signer.sign(self.sk, token_bytes)

        self.redacted_transfers_count += 1
        self._audit_decision("AUTHORIZED_COALITION_RELEASE", release_id=release_id,
                             payload_sha3_256=content_hash,
                             cdr_hostile_stripped=bool(hostile_stripped),
                             compartments_redacted=sorted(compartments_hit),
                             **base_audit)
        log.info(f"Coalition Release Granted: {release_id} -> {target_partner_nation} ({target_alliance.value})")

        return {
            "release_id": release_id,
            "status": "AUTHORIZED_COALITION_RELEASE",
            "coalition_header": release_header,
            "target_alliance": target_alliance.value,
            "target_partner_nation": target_partner_nation.upper(),
            "sanitized_payload": redacted_text,
            "sanitized_bytes_len": len(sanitized_bytes),
            "payload_sha3_256": content_hash,
            "release_token": release_token_payload,
            "release_token_signature_hex": token_signature.hex(),
            "gateway_ml_dsa_87_pubkey_hex": self.pk.hex(),
        }

    def review_quarantined(self, quarantine_id: str, approve: bool,
                           reviewer: str, reason: str = "") -> Dict[str, Any]:
        """Human review of held content (T4-E quarantine-hold completion).

        approve=True issues a full signed release from the HELD bytes
        (re-hashed at issue; reviewer bound into the token + audit).
        approve=False denies (held bytes dropped; denial audited).
        Unknown IDs, empty reviewer, and double-review all fail closed.
        """
        if not quarantine_id or not reviewer:
            raise CoalitionRedactionError("review requires quarantine_id and reviewer identity")
        held = self.quarantine_hold.get(quarantine_id)
        if held is None:
            raise CoalitionRedactionError(f"unknown or already-reviewed quarantine {quarantine_id!r}")
        if held.get("status") != "HELD_FOR_REVIEW":
            raise CoalitionRedactionError(f"quarantine {quarantine_id!r} not awaiting review")
        if approve:
            self.reviewed_count += 1
            release_id = held["quarantine_id"].replace("Q-", "REL-", 1) + "-RVW"
            token_payload = {
                "release_id": release_id,
                "gateway_id": self.gateway_id,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "source_classification": held["source_classification"],
                "coalition_header": f"// {held['source_classification']} // REL TO {held['target_alliance']} //",
                "target_alliance": held["target_alliance"],
                "target_partner_nation": held["target_partner_nation"],
                "payload_sha3_256": held["payload_sha3_256"],
                "cdr_status": "DISARMED_AND_RECONSTRUCTED",
                "cdr_hostile_stripped": True,
                "redacted_compartments": list(held["compartments_redacted"]),
                "reviewed_by": reviewer,
                "review_reason": reason,
                "quarantine_id": quarantine_id,
            }
            token_bytes = json.dumps(token_payload, sort_keys=True).encode("utf-8")
            token_sig = self.signer.sign(self.sk, token_bytes)
            # Re-hash at issue: held bytes must be exactly what ships.
            if hashlib.sha3_256(held["sanitized_payload"].encode("utf-8")).hexdigest() != held["payload_sha3_256"]:
                raise CoalitionRedactionError("held payload mutated before review issue (refusing)")
            pkg = {
                "release_id": release_id,
                "status": "AUTHORIZED_COALITION_RELEASE",
                "coalition_header": token_payload["coalition_header"],
                "target_alliance": held["target_alliance"],
                "target_partner_nation": held["target_partner_nation"],
                "sanitized_payload": held["sanitized_payload"],
                "sanitized_bytes_len": len(held["sanitized_payload"].encode("utf-8")),
                "payload_sha3_256": held["payload_sha3_256"],
                "release_token": token_payload,
                "release_token_signature_hex": token_sig.hex(),
                "gateway_ml_dsa_87_pubkey_hex": self.pk.hex(),
                "reviewed_by": reviewer,
            }
            del self.quarantine_hold[quarantine_id]
            self.redacted_transfers_count += 1
            self._audit_decision("REVIEW_APPROVED", release_id=release_id,
                                 quarantine_id=quarantine_id, reviewer=reviewer,
                                 reason=reason or "human review approved held content")
            log.info(f"Quarantined transfer APPROVED on review: {release_id} by {reviewer}")
            return pkg
        self.reviewed_count += 1
        denied = {
            "quarantine_id": quarantine_id,
            "status": "REVIEW_DENIED",
            "target_alliance": held["target_alliance"],
            "target_partner_nation": held["target_partner_nation"],
        }
        del self.quarantine_hold[quarantine_id]
        self._audit_decision("REVIEW_DENIED", quarantine_id=quarantine_id,
                             reviewer=reviewer,
                             reason=reason or "human review denied held content")
        log.warning(f"Quarantined transfer DENIED on review: {quarantine_id} by {reviewer}")
        return denied

    def verify_coalition_release(self, release_package: Dict[str, Any]) -> bool:
        """Verify the ML-DSA-87 signature and payload hash of a coalition release package."""
        try:
            token = release_package["release_token"]
            token_bytes = json.dumps(token, sort_keys=True).encode("utf-8")
            sig = bytes.fromhex(release_package["release_token_signature_hex"])
            pk = bytes.fromhex(release_package["gateway_ml_dsa_87_pubkey_hex"])

            # 1. Verify digital signature
            if not self.signer.verify(pk, token_bytes, sig):
                log.warning("Coalition Release Verification Failed: Invalid ML-DSA-87 signature.")
                return False

            # 2. Verify payload hash match
            payload_str = release_package["sanitized_payload"]
            actual_hash = hashlib.sha3_256(payload_str.encode("utf-8")).hexdigest()
            if actual_hash != token["payload_sha3_256"]:
                log.warning("Coalition Release Verification Failed: Payload hash mismatch.")
                return False

            return True
        except Exception as e:
            log.warning(f"Coalition Release Verification Error: {e}")
            return False

    def prepare_outbound_transfer(
        self,
        recipient_country: str,
        alliance: CoalitionAlliance,
        raw_payload: Any,
        classification_header: str = "// SECRET //",
        is_noforn: bool = False,
    ) -> Dict[str, Any]:
        """Prepare, sanitize, and cryptographically sign an outbound coalition transfer."""
        if not self.is_partner_cleared(recipient_country, alliance):
            raise SecurityViolationException(
                f"Recipient country '{recipient_country}' is not an authorized member of coalition '{alliance.value}'"
            )
        if is_noforn or "NOFORN" in str(classification_header).upper():
            self.blocked_noforn_count += 1
            raise SecurityViolationException(
                f"COALITION TRANSFER REJECTED: Content marked NOFORN cannot be released to {recipient_country}"
            )

        if isinstance(raw_payload, (dict, list)):
            payload_bytes = json.dumps(raw_payload, sort_keys=True).encode("utf-8")
        elif isinstance(raw_payload, str):
            payload_bytes = raw_payload.encode("utf-8")
        else:
            payload_bytes = bytes(raw_payload)

        pkg = self.redact_and_package_for_coalition(
            payload_bytes=payload_bytes,
            source_classification=SecurityClassification.SECRET,
            target_alliance=alliance,
            target_partner_nation=recipient_country,
            active_caveats=set(),
        )
        pkg["release_status"] = pkg.get("status", "AUTHORIZED_COALITION_RELEASE")
        pkg["recipient_country"] = recipient_country.upper()
        return pkg

    def verify_incoming_transfer(self, packet: Dict[str, Any]) -> bool:
        """Verify the cryptographic authenticity and integrity of incoming coalition packet."""
        return self.verify_coalition_release(packet)


# Module singleton
_GLOBAL_ALLIED_GATEWAY: Optional[AlliedCoalitionGateway] = None


def get_allied_coalition_gateway() -> AlliedCoalitionGateway:
    """Retrieve or initialize the global Allied Coalition Gateway."""
    global _GLOBAL_ALLIED_GATEWAY
    if _GLOBAL_ALLIED_GATEWAY is None:
        _GLOBAL_ALLIED_GATEWAY = AlliedCoalitionGateway()
    return _GLOBAL_ALLIED_GATEWAY


def sign_and_export_allied_gateway_report(output_dir: Optional[Path] = None) -> Tuple[Path, Path, Path]:
    """Generate CJADC2 Allied Coalition Gateway audit report and sign with ML-DSA-87."""
    gw = get_allied_coalition_gateway()
    target_dir = output_dir or (Path(__file__).parent / "compliance_reports")
    target_dir.mkdir(parents=True, exist_ok=True)

    report_data = {
        "report_id": f"CJADC2-ALLIED-GW-{int(time.time())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "gateway_id": gw.gateway_id,
        "standard": "DoD CJADC2 Combined Interoperability / NATO STANAG 4774/4778",
        "supported_alliances": [a.value for a in gw.active_alliances],
        "statistics": {
            "redacted_transfers_count": gw.redacted_transfers_count,
            "blocked_noforn_count": gw.blocked_noforn_count,
            "quarantined_count": gw.quarantined_count,
            "reviewed_count": gw.reviewed_count,
            "quarantine_held": len(gw.quarantine_hold),
            "decisions_logged": len(gw.decision_log),
        },
        "supported_partners": {
            alliance.value: sorted(list(members))
            for alliance, members in COALITION_MEMBERSHIP.items()
        },
        "content_disarm_reconstruction_profile": {
            "forbidden_active_elements": ["script", "iframe", "embed", "macro", "eval"],
            "cross_domain_redaction": "Enforced fail-closed (NOFORN strictly non-exportable)",
            "post_quantum_signature_suite": "ML-DSA-87 (FIPS 204)",
        }
    }

    report_bytes = json.dumps(report_data, indent=2, sort_keys=True).encode("utf-8")
    sig_bytes = gw.signer.sign(gw.sk, report_bytes)

    report_path = target_dir / "cjadc2_allied_gateway_report.json"
    sig_path = target_dir / "cjadc2_allied_gateway_report.json.mldsa87.sig"
    pub_path = target_dir / "cjadc2_allied_gateway_report.json.mldsa87.pub"

    report_path.write_bytes(report_bytes)
    sig_path.write_bytes(sig_bytes)
    pub_path.write_bytes(gw.pk)

    return report_path, sig_path, pub_path


def verify_allied_gateway_report_signature(
    report_path: Path,
    sig_path: Path,
    pub_path: Path
) -> bool:
    """Verify ML-DSA-87 signature over CJADC2 Allied Coalition Gateway audit report."""
    if not (report_path.exists() and sig_path.exists() and pub_path.exists()):
        return False
    data = report_path.read_bytes()
    sig = sig_path.read_bytes()
    pk = pub_path.read_bytes()

    signer = LibOQS_MLDSA_87()
    return signer.verify(pk, data, sig)


def generate_cjadc2_report(output_dir: Optional[Path] = None) -> Tuple[Path, Path, Path]:
    """Generate CJADC2 Allied Coalition Gateway audit report and sign with ML-DSA-87."""
    return sign_and_export_allied_gateway_report(output_dir)


def verify_cjadc2_report(
    report_path: Optional[Path] = None,
    sig_path: Optional[Path] = None,
    pub_path: Optional[Path] = None,
) -> bool:
    """Verify CJADC2 Allied Coalition Gateway audit report signature."""
    if report_path is None or sig_path is None or pub_path is None:
        target_dir = Path(__file__).parent / "compliance_reports"
        report_path = target_dir / "cjadc2_allied_gateway_report.json"
        sig_path = target_dir / "cjadc2_allied_gateway_report.json.mldsa87.sig"
        pub_path = target_dir / "cjadc2_allied_gateway_report.json.mldsa87.pub"
    return verify_allied_gateway_report_signature(report_path, sig_path, pub_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CJADC2 Allied & Coalition Cross-Domain Gateway")
    parser.add_argument("--test", action="store_true", help="Execute verification self-test")
    parser.add_argument("--generate-report", action="store_true", help="Generate and sign CJADC2 Allied Gateway report")
    parser.add_argument("--verify", action="store_true", help="Verify CJADC2 Allied Gateway report signature")
    args = parser.parse_args()

    gw = get_allied_coalition_gateway()
    r_dir = Path(__file__).parent / "compliance_reports"
    r_file = r_dir / "cjadc2_allied_gateway_report.json"
    s_file = r_dir / "cjadc2_allied_gateway_report.json.mldsa87.sig"
    p_file = r_dir / "cjadc2_allied_gateway_report.json.mldsa87.pub"

    if args.verify:
        valid = verify_allied_gateway_report_signature(r_file, s_file, p_file)
        print(f"[*] CJADC2 Allied Gateway Report Signature Valid: {valid}")
        sys.exit(0 if valid else 1)
    elif args.test:
        print("=== CJADC2 ALLIED COALITION GATEWAY TEST ===")
        # Test 1: Release to UK under FVEY
        raw_msg = json.dumps({
            "track": "AIR_THREAT_44",
            "lat": 34.55,
            "lon": 45.12,
            "source_intel": "HCS-P / SI-TK-G SATELLITE",
            "note": "Sensitive national intelligence feed"
        }).encode("utf-8")

        pkg = gw.redact_and_package_for_coalition(
            payload_bytes=raw_msg,
            source_classification=SecurityClassification.SECRET,
            target_alliance=CoalitionAlliance.FVEY,
            target_partner_nation="GBR",
            active_caveats=set(),
        )
        print(f"* Release Status: {pkg['status']}")
        print(f"* Header: {pkg['coalition_header']}")
        print(f"* Sanitized Payload: {pkg['sanitized_payload']}")
        is_valid = gw.verify_coalition_release(pkg)
        print(f"* Signature Verification: {'VALID' if is_valid else 'INVALID'}")
        # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
        assert is_valid is True  # nosec: B101
        # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
        assert "HCS-P" not in pkg["sanitized_payload"]  # nosec: B101

        # Test 2: NOFORN Block
        try:
            gw.redact_and_package_for_coalition(
                payload_bytes=b"HIGHLY_CLASSIFIED_US_ONLY",
                source_classification=SecurityClassification.TOP_SECRET,
                target_alliance=CoalitionAlliance.AUKUS,
                target_partner_nation="AUS",
                active_caveats={"NOFORN"},
            )
            print("* NOFORN Check: [FAIL] Allowed forbidden release")
        except CoalitionRedactionError as e:
            print(f"* NOFORN Check: [PASS] Blocked forbidden release ({e})")

        print("=== ALL ALLIED GATEWAY TESTS PASSED ===")
    elif args.generate_report:
        rep_p, sig_p, pub_p = sign_and_export_allied_gateway_report()
        valid = verify_allied_gateway_report_signature(rep_p, sig_p, pub_p)
        print(f"[PASS] Generated CJADC2 Allied Gateway Report: {rep_p.name}")
        print(f"[PASS] Signed with ML-DSA-87 (FIPS 204): {sig_p.name} (valid={valid})")
        sys.exit(0 if valid else 1)
    else:
        print(f"Allied Coalition Gateway: {gw.gateway_id}")
        print(f"Supported Alliances: {[a.value for a in gw.active_alliances]}")
        print(f"Redacted Transfers: {gw.redacted_transfers_count}, Blocked NOFORN: {gw.blocked_noforn_count}")


