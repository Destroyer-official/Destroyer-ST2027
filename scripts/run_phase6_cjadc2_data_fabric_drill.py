#!/usr/bin/env python3
"""
run_phase6_cjadc2_data_fabric_drill.py

Master Phase 6 CJADC2 Tactical Data Fabric & Dynamic PQC Crypto-Agility Mission Drill Harness.
Executes end-to-end operational verification across 5 mission-critical probes:
  Probe 1: Bell-LaPadula Multi-Level Security (MLS) & Dissemination Caveats (No Read Up, No Write Down)
  Probe 2: NSA NCDSMO "Raise the Bar" (RTB) Deep Content Inspection & Anti-Spillage Defense
  Probe 3: Cryptographic Compartment Isolation & Key Separation (HKDF-SHA3-512 + ChaCha20-Poly1305)
  Probe 4: NIST CSWP 39 Dynamic Post-Quantum Crypto-Agility State Machine & Anti-Downgrade Defense
  Probe 5: MIL-STD-6090 Cursor-on-Target (CoT) Situational Awareness, ML-DSA-87 Signing & DDIL Mesh

Generates and signs compliance_reports/cjadc2_data_fabric_drill_report.json with ML-DSA-87.
Supports --verify to independently audit signed mission drill receipts.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is in python path
_this_dir = Path(__file__).resolve().parent
REPO_ROOT = _this_dir.parent if _this_dir.name == "scripts" else _this_dir
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cjadc2_cross_domain_guard import (
    CrossDomainGuard,
    CrossDomainPolicyViolation,
    SecurityClassification,
    SecurityCaveat,
    sign_and_export_cross_domain_audit,
    verify_cross_domain_audit_signature,
)
from pqc_crypto_agility_engine import (
    CryptoAgilityEngine,
    AgilityState,
    ApprovedCNSA2Suite,
    sign_and_export_crypto_agility_audit,
    verify_crypto_agility_audit_signature,
)
from cjadc2_tactical_cot import (
    TacticalCoTEvent,
    CoTEventType,
)
from tactical_mesh_ddil import (
    DDILNodeMesh,
    DDILBundle,
    BundlePriority,
    get_ddil_node_mesh,
)
from liboqs_wrapper import LibOQS_MLDSA_87

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("cjadc2_phase6_drill")

COMPLIANCE_DIR = REPO_ROOT / "compliance_reports"
DRILL_REPORT_FILE = COMPLIANCE_DIR / "cjadc2_data_fabric_drill_report.json"
DRILL_SIG_FILE = COMPLIANCE_DIR / "cjadc2_data_fabric_drill_report.json.mldsa87.sig"
DRILL_PUB_FILE = COMPLIANCE_DIR / "cjadc2_data_fabric_drill_report.json.mldsa87.pub"


class Phase6DataFabricMissionDrill:
    """Orchestrates comprehensive DoD CJADC2 Phase 6 operational mission drills."""

    def __init__(self, drill_id: Optional[str] = None):
        self.drill_id = drill_id or f"CJADC2-PHASE6-DRILL-{int(time.time())}"
        self.results: Dict[str, Any] = {
            "drill_id": self.drill_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "standard_framework": "DoD CJADC2 Data Fabric / NSA NCDSMO Raise the Bar (RTB) v2.5 / NIST CSWP 39",
            "lifecycle_phase": "Phase 6: Tactical Data Fabric, Cross-Domain MLS & Dynamic PQC Crypto-Agility",
            "probes": [],
            "overall_status": "UNKNOWN",
            "signature_metadata": {},
        }
        self.signer = LibOQS_MLDSA_87()
        self.pk, self.sk = self.signer.keygen()

    def run_full_drill(self) -> Dict[str, Any]:
        """Execute all 5 Phase 6 mission probes sequentially."""
        log.info("=" * 80)
        log.info(f"STARTING DOD CJADC2 PHASE 6 DATA FABRIC MISSION DRILL: {self.drill_id}")
        log.info("=" * 80)

        probes_passed = 0
        total_probes = 5

        # Probe 1: Bell-LaPadula MLS & Dissemination Controls
        p1 = self._probe_1_bell_lapadula_mls()
        self.results["probes"].append(p1)
        if p1["status"] == "PASS":
            probes_passed += 1

        # Probe 2: NSA Raise the Bar Content Sanitization & Spillage Filter
        p2 = self._probe_2_rtb_content_inspection_spillage()
        self.results["probes"].append(p2)
        if p2["status"] == "PASS":
            probes_passed += 1

        # Probe 3: Cryptographic Compartment Isolation (HKDF-SHA3-512)
        p3 = self._probe_3_cryptographic_compartment_isolation()
        self.results["probes"].append(p3)
        if p3["status"] == "PASS":
            probes_passed += 1

        # Probe 4: NIST CSWP 39 Dynamic Crypto-Agility & Anti-Downgrade
        p4 = self._probe_4_crypto_agility_hotswap_and_anti_downgrade()
        self.results["probes"].append(p4)
        if p4["status"] == "PASS":
            probes_passed += 1

        # Probe 5: MIL-STD-6090 CoT Situational Awareness & DDIL Mesh Packaging
        p5 = self._probe_5_cot_situational_awareness_and_ddil()
        self.results["probes"].append(p5)
        if p5["status"] == "PASS":
            probes_passed += 1

        all_passed = (probes_passed == total_probes)
        self.results["overall_status"] = "PASS" if all_passed else "FAIL"
        self.results["summary"] = {
            "total_probes": total_probes,
            "probes_passed": probes_passed,
            "operational_verdict": "CJADC2_PHASE6_DATA_FABRIC_AUTHORIZATION_ACTIVE" if all_passed else "AUTHORIZATION_WITHHELD",
            "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        }

        self._sign_and_save_report()

        log.info("=" * 80)
        log.info(f"DRILL COMPLETE: {probes_passed}/{total_probes} PROBES PASSED ({self.results['summary']['operational_verdict']})")
        log.info(f"Signed Audit Report: {DRILL_REPORT_FILE}")
        log.info("=" * 80)
        return self.results

    def _probe_1_bell_lapadula_mls(self) -> Dict[str, Any]:
        """Probe 1: Bell-LaPadula Simple Security (No Read Up) & *-Property (No Write Down)."""
        log.info("--- [Probe 1/5] Bell-LaPadula MLS & Dissemination Caveat Enforcement ---")
        guard = CrossDomainGuard(node_clearance=SecurityClassification.SECRET,
                                 authorized_caveats={SecurityCaveat.REL_TO_FVEY, SecurityCaveat.NOFORN})

        # 1. No Read Up: SECRET node cannot read TOP_SECRET
        can_read_conf, _ = guard.evaluate_read_access(SecurityClassification.CONFIDENTIAL)
        can_read_sec, _ = guard.evaluate_read_access(SecurityClassification.SECRET)
        can_read_ts, reason_read_ts = guard.evaluate_read_access(SecurityClassification.TOP_SECRET)
        read_up_blocked = (not can_read_ts) and ("NO READ UP" in reason_read_ts)

        # 2. Caveat check: Cannot read object with unapproved caveat
        can_read_coalition, reason_caveat = guard.evaluate_read_access(
            SecurityClassification.SECRET, object_caveats={SecurityCaveat.REL_TO_COALITION}
        )
        caveat_blocked = (not can_read_coalition) and ("CAVEAT DISSEMINATION VIOLATION" in reason_caveat)

        # 3. No Write Down: SECRET node cannot write down to UNCLASSIFIED
        can_write_unclass, reason_write_unclass, _ = guard.evaluate_write_egress(
            source_classification=SecurityClassification.SECRET,
            target_classification=SecurityClassification.UNCLASSIFIED,
            payload_bytes=b"OPERATIONAL_PLAN_GAMMA"
        )
        write_down_blocked = (not can_write_unclass) and ("NO WRITE DOWN" in reason_write_unclass)

        # 4. Write Up is permitted
        can_write_ts, _, _ = guard.evaluate_write_egress(
            source_classification=SecurityClassification.SECRET,
            target_classification=SecurityClassification.TOP_SECRET,
            payload_bytes=b"OPERATIONAL_PLAN_GAMMA"
        )

        passed = can_read_conf and can_read_sec and read_up_blocked and caveat_blocked and write_down_blocked and can_write_ts
        probe_res = {
            "probe_id": "PROBE_1_BELL_LAPADULA_MLS",
            "title": "Bell-LaPadula MLS & Dissemination Caveat Enforcement",
            "status": "PASS" if passed else "FAIL",
            "details": {
                "node_clearance": guard.node_clearance.name,
                "read_up_blocked": read_up_blocked,
                "caveat_blocked": caveat_blocked,
                "write_down_blocked": write_down_blocked,
                "write_up_allowed": can_write_ts,
            }
        }
        log.info(f"  -> Probe 1 Status: {probe_res['status']} ({probe_res['details']})")
        return probe_res

    def _probe_2_rtb_content_inspection_spillage(self) -> Dict[str, Any]:
        """Probe 2: NSA NCDSMO 'Raise the Bar' (RTB) Deep Content Inspection & Anti-Spillage Defense."""
        log.info("--- [Probe 2/5] NSA NCDSMO 'Raise the Bar' (RTB) Content Inspection ---")
        guard = CrossDomainGuard(node_clearance=SecurityClassification.CONFIDENTIAL)

        # Vector 1: TOP SECRET dirty-word spillage into lower enclave
        spill_payload = b"TACTICAL UPDATE // TOP SECRET // SENSOR TRACK COORDINATES"
        ok_spill, reason_spill, _ = guard.evaluate_write_egress(
            source_classification=SecurityClassification.CONFIDENTIAL,
            target_classification=SecurityClassification.SECRET,
            payload_bytes=spill_payload
        )
        spill_blocked = (not ok_spill) and ("NSA RTB CONTENT INSPECTION FAILURE" in reason_spill)

        # Vector 2: Special Compartment indicator dirty-word
        sci_payload = b"INTEL BRIEF // SI-TK-G RESTRICTED // TARGET RECON"
        ok_sci, reason_sci, _ = guard.evaluate_write_egress(
            source_classification=SecurityClassification.CONFIDENTIAL,
            target_classification=SecurityClassification.SECRET,
            payload_bytes=sci_payload
        )
        sci_blocked = (not ok_sci) and ("NSA RTB CONTENT INSPECTION FAILURE" in reason_sci)

        # Vector 3: Clean sanitized payload passes CDR
        clean_payload = b"WEATHER OBSERVATION: VISIBILITY 10NM, CEILING 5000FT   \r\n"
        ok_clean, _, sanitized = guard.evaluate_write_egress(
            source_classification=SecurityClassification.CONFIDENTIAL,
            target_classification=SecurityClassification.SECRET,
            payload_bytes=clean_payload
        )
        cdr_clean = ok_clean and (sanitized == clean_payload.rstrip(b"\x00\r\n "))

        passed = spill_blocked and sci_blocked and cdr_clean
        probe_res = {
            "probe_id": "PROBE_2_RTB_CONTENT_INSPECTION",
            "title": "NSA NCDSMO Raise the Bar (RTB) Deep Content Inspection",
            "status": "PASS" if passed else "FAIL",
            "details": {
                "spill_blocked": spill_blocked,
                "sci_indicator_blocked": sci_blocked,
                "cdr_sanitization_verified": cdr_clean,
                "spillages_prevented_total": guard.spillage_events_blocked,
            }
        }
        log.info(f"  -> Probe 2 Status: {probe_res['status']} ({probe_res['details']})")
        return probe_res

    def _probe_3_cryptographic_compartment_isolation(self) -> Dict[str, Any]:
        """Probe 3: Cryptographic Compartment Isolation (HKDF-SHA3-512 + ChaCha20-Poly1305)."""
        log.info("--- [Probe 3/5] Cryptographic Compartment Isolation & Key Separation ---")
        guard = CrossDomainGuard()
        master_secret = secrets.token_bytes(64)
        secret_plaintext = b"TARGET_STRIKE_COORDINATES_ZONE_ZULU_34.12N_71.44E"

        # Encrypt inside TOP_SECRET:NOFORN compartment
        envelope = guard.encrypt_compartment_payload(
            master_secret=master_secret,
            classification=SecurityClassification.TOP_SECRET,
            caveat="NOFORN",
            plaintext_bytes=secret_plaintext
        )

        # 1. Unauthorized node (SECRET clearance) mathematically fails decryption
        unauthorized_blocked = False
        try:
            guard.decrypt_compartment_payload(
                master_secret=master_secret,
                compartment_envelope=envelope,
                node_clearance=SecurityClassification.SECRET,
                node_caveats={SecurityCaveat.NOFORN}
            )
        except CrossDomainPolicyViolation:
            unauthorized_blocked = True

        # 2. Unauthorized caveat (TOP_SECRET node without NOFORN caveat) fails
        caveat_blocked = False
        try:
            guard.decrypt_compartment_payload(
                master_secret=master_secret,
                compartment_envelope=envelope,
                node_clearance=SecurityClassification.TOP_SECRET,
                node_caveats={SecurityCaveat.REL_TO_FVEY}
            )
        except CrossDomainPolicyViolation:
            caveat_blocked = True

        # 3. Fully authorized node decrypts accurately
        decrypted = guard.decrypt_compartment_payload(
            master_secret=master_secret,
            compartment_envelope=envelope,
            node_clearance=SecurityClassification.TOP_SECRET,
            node_caveats={SecurityCaveat.NOFORN}
        )
        decryption_verified = (decrypted == secret_plaintext)

        passed = unauthorized_blocked and caveat_blocked and decryption_verified
        probe_res = {
            "probe_id": "PROBE_3_CRYPTOGRAPHIC_COMPARTMENTS",
            "title": "Cryptographic Compartment Isolation via HKDF-SHA3-512",
            "status": "PASS" if passed else "FAIL",
            "details": {
                "unauthorized_clearance_blocked": unauthorized_blocked,
                "unauthorized_caveat_blocked": caveat_blocked,
                "authorized_decryption_verified": decryption_verified,
                "kdf_derivation": "HKDF-SHA3-512 (256-bit isolated key)",
                "aead_cipher": "ChaCha20-Poly1305 (RFC 8439)",
            }
        }
        log.info(f"  -> Probe 3 Status: {probe_res['status']} ({probe_res['details']})")
        return probe_res

    def _probe_4_crypto_agility_hotswap_and_anti_downgrade(self) -> Dict[str, Any]:
        """Probe 4: NIST CSWP 39 Dynamic Crypto-Agility State Machine & Anti-Downgrade Defense."""
        log.info("--- [Probe 4/5] NIST CSWP 39 Dynamic Crypto-Agility & Anti-Downgrade ---")
        engine = CryptoAgilityEngine()

        # Step 1: Verify Initial State
        init_ok = (engine.current_state == AgilityState.ACTIVE_CNSA2_PRIMARY)
        init_kem = engine.active_kem
        init_dss = engine.active_dss

        # Step 2: In-flight hot-swap migration (Classic-McEliece-8192128f + SLH-DSA-256f)
        target_kem = "Classic-McEliece-8192128f"
        target_dss = "SLH-DSA-256f"
        hotswap_ok = engine.execute_live_migration(target_kem, target_dss)
        committed_ok = (engine.current_state == AgilityState.COMMITTED_MIGRATION)
        active_kem_ok = (engine.active_kem == target_kem)
        active_dss_ok = (engine.active_dss == target_dss)

        # Step 3: Anti-downgrade defense - attempt illegal migration to classical/sub-L5
        downgrades_blocked = 0
        forbidden_attempts = ["RSA-4096", "ECDH-P384", "Kyber-768", "Dilithium-3"]
        for bad_algo in forbidden_attempts:
            rejected = False
            try:
                engine.propose_migration(new_kem=bad_algo, new_dss=target_dss, reason="ILLEGAL_DOWNGRADE")
            except Exception:
                rejected = True
            if rejected or engine.downgrade_attempts_blocked > 0:
                downgrades_blocked += 1

        anti_downgrade_ok = (downgrades_blocked == len(forbidden_attempts))
        passed = init_ok and hotswap_ok and committed_ok and active_kem_ok and active_dss_ok and anti_downgrade_ok
        probe_res = {
            "probe_id": "PROBE_4_CRYPTO_AGILITY_HOTSWAP",
            "title": "NIST CSWP 39 Dynamic Crypto-Agility & Zero-Downtime Hot-Swap",
            "status": "PASS" if passed else "FAIL",
            "details": {
                "initial_suite": f"{init_kem} + {init_dss}",
                "migrated_suite": f"{engine.active_kem} + {engine.active_dss}",
                "zero_downtime_hotswap_success": hotswap_ok,
                "final_state": engine.current_state.value,
                "forbidden_downgrades_tested": len(forbidden_attempts),
                "forbidden_downgrades_blocked": downgrades_blocked,
            }
        }
        log.info(f"  -> Probe 4 Status: {probe_res['status']} ({probe_res['details']})")
        return probe_res

    def _probe_5_cot_situational_awareness_and_ddil(self) -> Dict[str, Any]:
        """Probe 5: MIL-STD-6090 Cursor-on-Target (CoT) Situational Awareness & DDIL Mesh."""
        log.info("--- [Probe 5/5] MIL-STD-6090 CoT Situational Awareness & DDIL Mesh ---")
        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()

        # 1. Generate MIL-STD-6090 CoT tactical event
        cot = TacticalCoTEvent(
            event_type=CoTEventType.HOSTILE_AIR_FIGHTER,
            lat=34.555,
            lon=43.123,
            callsign="BANDIT-01",
            speed_mps=450.0,
            course_deg=270.0,
            classification="SECRET"
        )
        cot.sign_event(sk, pk)
        xml_rep = cot.to_mil_std_6090_xml()
        xml_valid = ("<event" in xml_rep) and ("BANDIT-01" in xml_rep) and (cot.type in xml_rep)

        # 2. Verify ML-DSA-87 signature
        sig_valid = cot.verify_event_signature()

        # 3. Fail-closed geospatial tamper detection
        c_json = cot.to_compact_json()
        tampered_json = dict(c_json)
        tampered_json["pos"] = [34.999, 43.123, 0.0]
        tampered_cot = TacticalCoTEvent.from_compact_json(tampered_json)
        tamper_caught = (not tampered_cot.verify_event_signature())

        # 4. Package into DDIL Store-and-Forward bundle
        bundle = cot.to_ddil_bundle("RADAR_POST_01", "TACTICAL_TOC_HQ", seq=901)
        bundle_ok = (bundle.priority == BundlePriority.EMERGENCY) and (bundle.recipient_id == "TACTICAL_TOC_HQ")

        # 5. Ingest into DDIL mesh
        mesh = get_ddil_node_mesh(node_id="NODE-VIPER-11")
        ingest_ok = mesh.receive_reconciled_bundle(bundle)
        delivered = (bundle.bundle_id in mesh.delivered_bundles)

        passed = xml_valid and sig_valid and tamper_caught and bundle_ok and ingest_ok and delivered
        probe_res = {
            "probe_id": "PROBE_5_COT_TACTICAL_DATA_FABRIC",
            "title": "MIL-STD-6090 CoT Situational Awareness & DDIL Integration",
            "status": "PASS" if passed else "FAIL",
            "details": {
                "mil_std_6090_xml_valid": xml_valid,
                "pqc_mldsa87_signature_valid": sig_valid,
                "geospatial_tamper_defense_verified": tamper_caught,
                "ddil_bundle_priority": "EMERGENCY" if bundle.priority == BundlePriority.EMERGENCY else str(bundle.priority),
                "ddil_bundle_delivered": delivered,
            }
        }
        log.info(f"  -> Probe 5 Status: {probe_res['status']} ({probe_res['details']})")
        return probe_res

    def _sign_and_save_report(self) -> None:
        """Sign canonical drill JSON with ML-DSA-87 and persist to compliance_reports/."""
        COMPLIANCE_DIR.mkdir(parents=True, exist_ok=True)
        canonical_bytes = json.dumps(self.results, sort_keys=True, indent=2).encode("utf-8")
        sig = self.signer.sign(self.sk, canonical_bytes)

        self.results["signature_metadata"] = {
            "algorithm": "ML-DSA-87 (FIPS 204)",
            "public_key_hex": self.pk.hex(),
            "signature_hex": sig.hex(),
            "signed_at_utc": datetime.now(timezone.utc).isoformat(),
        }

        with open(DRILL_REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)
        with open(DRILL_SIG_FILE, "wb") as f:
            f.write(sig)
        with open(DRILL_PUB_FILE, "wb") as f:
            f.write(self.pk)


def verify_phase6_drill_report() -> bool:
    """Audit and verify cryptographic signature on compliance_reports/cjadc2_data_fabric_drill_report.json."""
    if not (DRILL_REPORT_FILE.exists() and DRILL_SIG_FILE.exists() and DRILL_PUB_FILE.exists()):
        print(f"[FAIL] Missing mission drill files in {COMPLIANCE_DIR}")
        return False

    with open(DRILL_REPORT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    with open(DRILL_SIG_FILE, "rb") as f:
        sig = f.read()
    with open(DRILL_PUB_FILE, "rb") as f:
        pk = f.read()

    # Reconstruct canonical data before signature_metadata injection
    data_for_verify = dict(data)
    data_for_verify["signature_metadata"] = {}
    canonical_bytes = json.dumps(data_for_verify, sort_keys=True, indent=2).encode("utf-8")

    signer = LibOQS_MLDSA_87()
    valid = signer.verify(pk, canonical_bytes, sig)
    print(f"[*] Phase 6 Mission Drill Audit Report: {DRILL_REPORT_FILE}")
    print(f"[*] ML-DSA-87 Digital Signature Valid: {valid}")
    print(f"[*] Operational Verdict: {data.get('summary', {}).get('operational_verdict', 'UNKNOWN')}")
    print(f"[*] Probes: {data.get('summary', {}).get('probes_passed', 0)}/{data.get('summary', {}).get('total_probes', 0)} Passed")
    return valid


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DoD CJADC2 Phase 6 Tactical Data Fabric Mission Drill")
    parser.add_argument("--verify", action="store_true", help="Verify signed drill audit report")
    args = parser.parse_args()

    if args.verify:
        success = verify_phase6_drill_report()
        sys.exit(0 if success else 1)
    else:
        drill = Phase6DataFabricMissionDrill()
        report = drill.run_full_drill()
        all_ok = (report.get("overall_status") == "PASS")
        sys.exit(0 if all_ok else 1)
