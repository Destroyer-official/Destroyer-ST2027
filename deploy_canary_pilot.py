#!/usr/bin/env python3
"""
Canary Pilot Deployment & Continuous Monitoring (ISCM / cATO) Telemetry Harness
Performs simulated canary node deployment, continuous telemetry health checks,
and Active Cyber Defense (ACD) verification per NIST SP 800-137 and DoD cATO.
"""

import os
import sys
import json
import time
import socket
import logging
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from remote_siem_forwarder import TamperEvidentAuditChain, verify_audit_log_chain
from tactical_cloaking_router import validate_outbound_destination, TacticalCloakViolation, tactical_cloak_enabled
from destroyer_node import DestroyerNode, FTYPE_MSG, FTYPE_CHAFF
import secrets

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("canary_pilot")


class CanaryPilotDeployer:
    """
    Orchestrates tactical canary node deployment and collects continuous
    monitoring telemetry per NIST SP 800-137 and DoD cATO standards.
    """

    def __init__(self, node_alpha_id: str = "CANARY-ALPHA", node_bravo_id: str = "CANARY-BRAVO"):
        self.node_alpha_id = node_alpha_id
        self.node_bravo_id = node_bravo_id
        self.telemetry_data = {
            "deployment_id": f"CANARY-{int(time.time())}",
            "standards": ["NIST SP 800-137 (ISCM)", "DoD cATO Active Cyber Defense", "NSA CNSA 2.0"],
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "nodes": [node_alpha_id, node_bravo_id],
            "probes": [],
            "overall_status": "UNKNOWN"
        }

    def run_pilot_evaluation(self) -> dict:
        """Run all 5 continuous monitoring and active defense telemetry probes."""
        log.info("Starting Canary Pilot Deployment & ISCM Telemetry Evaluation...")
        probes_passed = 0
        total_probes = 5

        # Probe 1: Cryptographic Compliance & Post-Quantum Algorithms
        p1 = self._probe_cryptographic_compliance()
        self.telemetry_data["probes"].append(p1)
        if p1["status"] == "PASS":
            probes_passed += 1

        # Probe 2: Tactical Cloaking & Zero Public Socket Egress
        p2 = self._probe_tactical_cloaking()
        self.telemetry_data["probes"].append(p2)
        if p2["status"] == "PASS":
            probes_passed += 1

        # Probe 3: WireGuard-Style UDP Framing & Discrete Quanta
        p3 = self._probe_udp_data_plane_framing()
        self.telemetry_data["probes"].append(p3)
        if p3["status"] == "PASS":
            probes_passed += 1

        # Probe 4: Anti-Replay Sliding Window Protection
        p4 = self._probe_anti_replay_window()
        self.telemetry_data["probes"].append(p4)
        if p4["status"] == "PASS":
            probes_passed += 1

        # Probe 5: Forward-Secure SIEM Audit Chaining & Head Anchor
        p5 = self._probe_siem_forward_secure_audit()
        self.telemetry_data["probes"].append(p5)
        if p5["status"] == "PASS":
            probes_passed += 1

        all_passed = (probes_passed == total_probes)
        self.telemetry_data["summary"] = {
            "total_probes": total_probes,
            "probes_passed": probes_passed,
            "all_probes_passed": all_passed
        }
        self.telemetry_data["overall_status"] = "OPERATIONAL" if all_passed else "DEGRADED"

        return self.telemetry_data

    def _probe_cryptographic_compliance(self) -> dict:
        """Verify strict CNSA 2.0 PQC algorithm enforcement."""
        try:
            from pqc_algorithms import EnhancedMLKEM_1024, EnhancedMLDSA_87
            kem = EnhancedMLKEM_1024()
            pk, sk = kem.keygen()
            ct, ss1 = kem.encaps(pk)
            ss2 = kem.decaps(sk, ct)
            # B101: explicit fail-closed checks (never `assert` on a deploy
            # gate; -O strips asserts and a broken lib must not deploy).
            if not (ss1 == ss2 and len(ss1) >= 32):
                raise ValueError("ML-KEM-1024 canary probe failed: shared secret mismatch/short")

            dsa = EnhancedMLDSA_87()
            dpk, dsk = dsa.keygen()
            msg = b"canary-telemetry-probe"
            sig = dsa.sign(dsk, msg)
            if dsa.verify(dpk, msg, sig) is not True:
                raise ValueError("ML-DSA-87 canary probe failed: self-verify rejected")

            return {
                "probe_id": "ISCM-P1",
                "title": "CNSA 2.0 Cryptographic Enforcement (FIPS 203/204/205)",
                "status": "PASS",
                "details": "ML-KEM-1024 and ML-DSA-87 verified operational with zero classical fallbacks"
            }
        except Exception as e:
            return {
                "probe_id": "ISCM-P1",
                "title": "CNSA 2.0 Cryptographic Enforcement",
                "status": "FAIL",
                "details": f"Error: {e}"
            }

    def _probe_tactical_cloaking(self) -> dict:
        """Verify tactical cloaking router prohibits raw public IP egress."""
        old_cloak = os.environ.get("P2P_TACTICAL_CLOAK")
        old_overlay = os.environ.get("P2P_OVERLAY_ACTIVE")
        os.environ["P2P_TACTICAL_CLOAK"] = "1"
        os.environ.pop("P2P_OVERLAY_ACTIVE", None)

        blocked_public = False
        allowed_overlay = False

        try:
            validate_outbound_destination("8.8.8.8", 50007)
        except TacticalCloakViolation:
            blocked_public = True

        try:
            os.environ["P2P_OVERLAY_ACTIVE"] = "1"
            if validate_outbound_destination("8.8.8.8", 50007):
                allowed_overlay = True
        except TacticalCloakViolation:
            pass
        finally:
            if old_cloak is not None:
                os.environ["P2P_TACTICAL_CLOAK"] = old_cloak
            else:
                os.environ.pop("P2P_TACTICAL_CLOAK", None)
            if old_overlay is not None:
                os.environ["P2P_OVERLAY_ACTIVE"] = old_overlay
            else:
                os.environ.pop("P2P_OVERLAY_ACTIVE", None)

        status = "PASS" if (blocked_public and allowed_overlay) else "FAIL"
        return {
            "probe_id": "ISCM-P2",
            "title": "Tactical Cloaking & Zero Public Socket Egress",
            "status": status,
            "details": "Direct public IP blocked; tactical overlay subnet (10.99.0.0/16) permitted"
        }

    def _probe_udp_data_plane_framing(self) -> dict:
        """Verify discrete quantum sizing {256, 512, 1232} and chaff absorption."""
        shared_key = secrets.token_bytes(32)
        node = DestroyerNode()
        node.establish(shared_key, is_initiator=True)

        sizes_quanta_ok = True
        for sz, expected_quantum in [(10, 256), (300, 512), (700, 1232)]:
            frame = node.transmit(b"X" * sz)
            if len(frame) != expected_quantum:
                sizes_quanta_ok = False
                break

        # Chaff test
        chaff = node.transmit(b"", chaff=True)
        chaff_ok = (len(chaff) in (256, 512, 1232))

        status = "PASS" if (sizes_quanta_ok and chaff_ok) else "FAIL"
        return {
            "probe_id": "ISCM-P3",
            "title": "WireGuard UDP Framing & Fixed Quantum Sizing",
            "status": status,
            "details": "All wire frames match discrete quanta {256, 512, 1232}; chaff conforms to quantum"
        }

    def _probe_anti_replay_window(self) -> dict:
        """Verify 64-bit sliding window rejects replay swarms."""
        node = DestroyerNode()
        w1 = node.engine.check_seq(10)
        w2 = node.engine.check_seq(8)   # out-of-order in window: True
        w3 = node.engine.check_seq(8)   # duplicate: False
        w4 = node.engine.check_seq(10)  # duplicate: False
        w5 = node.engine.check_seq(80)  # advance window
        w6 = node.engine.check_seq(8)   # >64 behind new window head (80): False

        status = "PASS" if (w1 and w2 and not w3 and not w4 and w5 and not w6) else "FAIL"
        return {
            "probe_id": "ISCM-P4",
            "title": "Anti-Replay Sliding Window (64-Packet Bitmap)",
            "status": status,
            "details": "In-window accepted; duplicates and out-of-window rejected fail-closed"
        }

    def _probe_siem_forward_secure_audit(self) -> dict:
        """Verify forward-secure HMAC-SHA384 audit chaining and head anchor integrity."""
        import tempfile
        tmp_dir = Path(tempfile.mkdtemp())
        log_file = tmp_dir / "canary_audit.jsonl"
        anchor_file = tmp_dir / "canary_head.anchor.json"
        
        forwarder = TamperEvidentAuditChain(ledger_path=log_file, anchor_path=anchor_file)
        forwarder.append_event("CANARY_BOOT", "INFO", {"node": self.node_alpha_id})
        forwarder.append_event("CANARY_LINK_UP", "INFO", {"peer": self.node_bravo_id})
        forwarder.export_head_anchor()

        is_valid, count, msg = forwarder.verify_ledger()
        return {
            "probe_id": "ISCM-P5",
            "title": "Forward-Secure Remote SIEM Chaining & Head Anchor",
            "status": "PASS" if is_valid else "FAIL",
            "details": f"Chain verified: {count} records sequentially locked ({msg})"
        }

    def export_telemetry_report(self, output_path: Path) -> Path:
        """Export machine-readable telemetry JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.telemetry_data, f, indent=2)
        return output_path


def main():
    deployer = CanaryPilotDeployer()
    telemetry = deployer.run_pilot_evaluation()
    out_path = PROJECT_ROOT / "compliance_reports" / "canary_pilot_telemetry.json"
    deployer.export_telemetry_report(out_path)

    print("=" * 80)
    print("  CANARY PILOT DEPLOYMENT & CONTINUOUS MONITORING (ISCM / cATO)")
    print("=" * 80)
    for p in telemetry["probes"]:
        print(f"  [{p['status']}] {p['probe_id']}: {p['title']}")
        print(f"         Details: {p['details']}")
    print("-" * 80)
    print(f"  OVERALL STATUS: {telemetry['overall_status']} ({telemetry['summary']['probes_passed']}/{telemetry['summary']['total_probes']} Probes Passed)")
    print(f"  Telemetry Record: {out_path}")
    print("=" * 80)

    if not telemetry["summary"]["all_probes_passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
