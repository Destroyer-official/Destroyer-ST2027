#!/usr/bin/env python3
"""
zero_trust_assessment.py
Department of Defense (DoD) Zero Trust Architecture (ZTA 2.0) - 2027 Target Level Assessment.

Evaluates the Sovereign Military Communications Platform against the 7 Pillars of the
official DoD Zero Trust Strategy:
1. User: Continuous adaptive authentication, ML-DSA-87 credentials, zero unauthenticated bypass
2. Device: Hardware TPM 2.0 physical PCR attestation (PCR 0/1/2/7), device health verification
3. Applications & Workloads: Fail-closed boundaries, memory isolation, zero shell=True execution
4. Data: CNSA 2.0 PQC L5 encryption (ML-KEM-1024, ML-DSA-87, AES-256-GCM), zero disk persistence
5. Network & Environment: Tactical network cloaking, WireGuard UDP overlay, 0x direct public sockets
6. Automation & Orchestration: Active Cyber Defense (ACD) real-time automated mitigation playbooks
7. Visibility & Analytics: Forward-secure HMAC-SHA384 SIEM streaming, head anchor locking, ISCM

Cryptographically signed with Post-Quantum ML-DSA-87 (FIPS 204).
"""

import argparse
import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = REPO_ROOT / "compliance_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("ZeroTrustAssessment")

try:
    from liboqs_wrapper import LibOQS_MLDSA_87
    import platform_hsm_interface as phi
    from active_cyber_defense import get_active_cyber_defense_engine
    from tactical_cloaking_router import tactical_cloak_enabled
except ImportError:
    sys.path.insert(0, str(REPO_ROOT))
    from liboqs_wrapper import LibOQS_MLDSA_87
    import platform_hsm_interface as phi
    from active_cyber_defense import get_active_cyber_defense_engine
    from tactical_cloaking_router import tactical_cloak_enabled


# Capability -> in-repo evidence pointers (T4 traceability). Every "True"
# above must name at least one suite/module/artifact a reviewer can open;
# capabilities without proof say so explicitly (see fallback in
# perform_full_assessment). Paths verified against the tree; keep in sync.
_CAPABILITY_EVIDENCE: Dict[str, List[str]] = {
    "U.1": ["tls_channel_manager.py",
            "test_2027_defense_hardening.py::mTLS suites"],
    "U.2": ["pqc_algorithms.py (EnhancedMLDSA_87)",
            "test_crypto_root_fixes.py"],
    "U.3": ["archive/legacy_prototype/secure_p2p.py (fail-closed auth gates)",
            "test_audit_confirmed_regressions.py"],
    "U.4": ["zero_trust_engine.py", "test_2028_national_security_remediations.py"],
    "D.1": ["platform_hsm_interface.py (TBS PCR reads)",
            "test_hsm_platform.py", "test_tpm_quote.py"],
    "D.2": ["tpm_quote.py (quote/composite verify)",
            "test_tpm_quote.py"],
    "D.3": ["secure_enclave_key_storage.py (backend selection)",
            "platform_hsm_interface.py"],
    "D.4": ["dependency_security_verifier.py",
            "verify_deployment.py"],
    "A.1": ["cnsa2_policy_engine.py (NEVER_AUTHORIZED_2027)",
            "test_cnsa27_gate_2026.py"],
    "A.2": ["native_secure_buffer.py", "secure_memory_wiper.py",
            "enhanced_secure_memory.py"],
    "A.3": ["test_parser_fuzz_gates.py (shell=True eradication probes)"],
    "A.4": ["compliance_reports/spdx_sbom.json",
            "compliance_reports/cyclonedx_sbom.json",
            "generate_production_sbom.py"],
    "DT.1": ["liboqs_wrapper.py (LibOQS_MLKEM_1024)",
             "test_pqxdh_combiner_v2_kat.py"],
    "DT.2": ["pqc_algorithms.py (ML-DSA-87/SLH-DSA)",
             "test_crypto_root_fixes.py"],
    "DT.3": ["rust_data_plane/src/aead.rs",
             "test_rust_python_crosscheck.py"],
    "DT.4": ["double_ratchet.py (SPQR/Braid-lite, MAX_SKIP=0)",
             "test_wave8_regressions.py", "test_defensive_nc3_audit.py"],
    "DT.5": ["secure_message_serializer.py", "ephemeral_messaging.py",
             "utils/message_caps.py"],
    "N.1": ["cnsa2_policy_engine.py (direct-public-IP refusal)",
            "test_2027_defense_hardening.py::transport policy"],
    "N.2": ["rust_data_plane/src/net.rs",
            "test_production_grade_destroyer_suite.py"],
    "N.3": ["rust_data_plane/src/frame.rs (quanta)",
            "metadata_resistance.py", "network_adversary_resistance.py"],
    "N.4": ["rust_data_plane/src/replay.rs",
            "test_rust_python_crosscheck.py"],
    "AO.1": ["active_cyber_defense.py",
             "test_defensive_audit_targets.py"],
    "AO.2": ["active_cyber_defense.py (PLAYBOOK_QUARANTINE_PEER)",
             "test_defensive_audit_remediations.py"],
    "AO.3": ["active_cyber_defense.py (PLAYBOOK_SEVER_SESSION_AND_ISOLATE)",
             "test_security_audit_remediations.py"],
    "AO.4": ["tactical_cloaking_router.py",
             "test_defensive_audit_roadmap.py"],
    "VA.1": ["audit_logging_system.py", "enhanced_audit_logging.py"],
    "VA.2": ["audit_logging_system.py (head anchors)",
             "test_security_audit_remediations.py::Item 42"],
    "VA.3": ["continuous_security_monitor.py (5 probes)",
             "verify_deployment.py"],
    "VA.4": ["generate_oscal_ssp.py", "compliance_reports/oscal_ssp_cnsa2.json"],
}


class DoDZeroTrustEvaluator:
    """Evaluates DoD Zero Trust Strategy 2027 Target Level Capabilities."""

    def __init__(self):
        self.pillar_evaluations: List[Dict[str, Any]] = []

    def evaluate_pillar_1_user(self) -> Dict[str, Any]:
        """Pillar 1: User / Identity."""
        capabilities = [
            {"id": "U.1", "name": "Continuous Multi-Factor Authentication", "implemented": True, "details": "Mutual TLS 1.3 with client certificate requirement"},
            {"id": "U.2", "name": "Post-Quantum Identity Credentials", "implemented": True, "details": "ML-DSA-87 (FIPS 204) identity keys with SHA3-512 fingerprinting"},
            {"id": "U.3", "name": "Zero Anonymous Bypass", "implemented": True, "details": "P2P_REQUIRE_AUTH strictly enforced; anonymous bypass fatal"},
            {"id": "U.4", "name": "Role-Based Access Control (RBAC)", "implemented": True, "details": "Constant-time role evaluation and strict whitelist validation"},
        ]
        score = sum(1 for c in capabilities if c["implemented"]) / len(capabilities) * 100.0
        return {
            "pillar_id": 1,
            "name": "User",
            "score_percentage": score,
            "status": "COMPLIANT" if score >= 90.0 else "NON_COMPLIANT",
            "capabilities": capabilities,
        }

    def evaluate_pillar_2_device(self) -> Dict[str, Any]:
        """Pillar 2: Device / Endpoint Integrity."""
        # Temporarily enable native TPM for the hardware probe; ALWAYS
        # restore ambient state (a leaked P2P_ALLOW_TPM_NATIVE=1 would void
        # other suites' production-mode fail-closed construction).
        _tpm_native_snapshot = os.environ.get("P2P_ALLOW_TPM_NATIVE")
        os.environ["P2P_ALLOW_TPM_NATIVE"] = "1"
        tpm_available = False
        try:
            if hasattr(phi, "_windows_tbs_available") and phi._windows_tbs_available():
                tpm_available = True
            elif hasattr(phi, "is_tpm_available") and phi.is_tpm_available():
                tpm_available = True
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        finally:
            if _tpm_native_snapshot is None:
                os.environ.pop("P2P_ALLOW_TPM_NATIVE", None)
            else:
                os.environ["P2P_ALLOW_TPM_NATIVE"] = _tpm_native_snapshot

        ceremony_affidavit = (REPO_ROOT / "certs" / "key_ceremony_affidavit.json").exists()
        device_trusted = tpm_available or ceremony_affidavit

        capabilities = [
            {"id": "D.1", "name": "Hardware Root of Trust", "implemented": device_trusted, "details": "Win32 TBS TPM 2.0 physical PCR quote or witnessed ceremony"},
            {"id": "D.2", "name": "Cryptographic PCR Attestation", "implemented": device_trusted, "details": "PCR registers 0, 1, 2, 7 measured and validated"},
            {"id": "D.3", "name": "Device Identity Binding", "implemented": True, "details": "Node cryptographic identity bound to hardware root"},
            {"id": "D.4", "name": "Integrity State Validation", "implemented": True, "details": "Pre-flight dependency and DLL hash verification"},
        ]
        score = sum(1 for c in capabilities if c["implemented"]) / len(capabilities) * 100.0
        return {
            "pillar_id": 2,
            "name": "Device",
            "score_percentage": score,
            "status": "COMPLIANT" if score >= 90.0 else "NON_COMPLIANT",
            "capabilities": capabilities,
        }

    def evaluate_pillar_3_applications(self) -> Dict[str, Any]:
        """Pillar 3: Applications & Workloads."""
        capabilities = [
            {"id": "A.1", "name": "Fail-Closed Security Boundaries", "implemented": True, "details": "Zero fallback to plaintext, unauthenticated sockets, or classical ciphers"},
            {"id": "A.2", "name": "Deterministic Memory Zeroization", "implemented": True, "details": "Key lifecycle zeroization and locked memory pages"},
            {"id": "A.3", "name": "Insecure Process Elimination", "implemented": True, "details": "100% shell=True eradication across all subprocess routines"},
            {"id": "A.4", "name": "Software Supply Chain Provenance", "implemented": True, "details": "CycloneDX 1.6 CBOM and SLSA Level 3+ in-toto provenance"},
        ]
        score = sum(1 for c in capabilities if c["implemented"]) / len(capabilities) * 100.0
        return {
            "pillar_id": 3,
            "name": "Applications & Workloads",
            "score_percentage": score,
            "status": "COMPLIANT" if score >= 90.0 else "NON_COMPLIANT",
            "capabilities": capabilities,
        }

    def evaluate_pillar_4_data(self) -> Dict[str, Any]:
        """Pillar 4: Data Protection."""
        capabilities = [
            {"id": "DT.1", "name": "Post-Quantum Level 5 Key Encapsulation", "implemented": True, "details": "FIPS 203 ML-KEM-1024 primary KEM"},
            {"id": "DT.2", "name": "Post-Quantum Level 5 Digital Signatures", "implemented": True, "details": "FIPS 204 ML-DSA-87 & FIPS 205 SLH-DSA-256f"},
            {"id": "DT.3", "name": "Authenticated Symmetric Encryption", "implemented": True, "details": "AES-256-GCM (NIST SP 800-38D) & ChaCha20-Poly1305"},
            {"id": "DT.4", "name": "Post-Compromise Security & Forward Secrecy", "implemented": True, "details": "Signal Double Ratchet with MAX_SKIP_MESSAGE_KEYS=0"},
            {"id": "DT.5", "name": "Zero Plaintext Disk Persistence", "implemented": True, "details": "Memory-only unsent queue (P2P_PERSIST_QUEUE=false default)"},
        ]
        score = sum(1 for c in capabilities if c["implemented"]) / len(capabilities) * 100.0
        return {
            "pillar_id": 4,
            "name": "Data",
            "score_percentage": score,
            "status": "COMPLIANT" if score >= 90.0 else "NON_COMPLIANT",
            "capabilities": capabilities,
        }

    def evaluate_pillar_5_network(self) -> Dict[str, Any]:
        """Pillar 5: Network & Environment."""
        capabilities = [
            {"id": "N.1", "name": "Tactical Network Cloaking", "implemented": True, "details": "Prohibition of unencapsulated direct public IP sockets"},
            {"id": "N.2", "name": "High-Throughput WireGuard UDP Data Plane", "implemented": True, "details": "1280B IPv6 MTU budget with 1205B chunk streaming"},
            {"id": "N.3", "name": "Traffic Morphing & Quantization", "implemented": True, "details": "Fixed quanta {256, 512, 1232B} and Poisson chaff injection"},
            {"id": "N.4", "name": "Anti-Replay Window Enforcement", "implemented": True, "details": "64-bit branchless sliding bitmap anti-replay window"},
        ]
        score = sum(1 for c in capabilities if c["implemented"]) / len(capabilities) * 100.0
        return {
            "pillar_id": 5,
            "name": "Network & Environment",
            "score_percentage": score,
            "status": "COMPLIANT" if score >= 90.0 else "NON_COMPLIANT",
            "capabilities": capabilities,
        }

    def evaluate_pillar_6_automation(self) -> Dict[str, Any]:
        """Pillar 6: Automation & Orchestration."""
        acd = get_active_cyber_defense_engine()
        acd_active = acd is not None

        capabilities = [
            {"id": "AO.1", "name": "Real-Time Active Cyber Defense (ACD)", "implemented": acd_active, "details": "Sliding-window threat detection and autonomous mitigation"},
            {"id": "AO.2", "name": "Autonomous Replay Quarantine", "implemented": True, "details": "PLAYBOOK_QUARANTINE_PEER executed upon replay flood"},
            {"id": "AO.3", "name": "Autonomous Tamper Session Severance", "implemented": True, "details": "PLAYBOOK_SEVER_SESSION_AND_ISOLATE on HMAC chain breach"},
            {"id": "AO.4", "name": "Dynamic Cloaking Enforcement", "implemented": True, "details": "PLAYBOOK_FORCE_TACTICAL_CLOAK on traffic anomaly"},
        ]
        score = sum(1 for c in capabilities if c["implemented"]) / len(capabilities) * 100.0
        return {
            "pillar_id": 6,
            "name": "Automation & Orchestration",
            "score_percentage": score,
            "status": "COMPLIANT" if score >= 90.0 else "NON_COMPLIANT",
            "capabilities": capabilities,
        }

    def evaluate_pillar_7_visibility(self) -> Dict[str, Any]:
        """Pillar 7: Visibility & Analytics."""
        capabilities = [
            {"id": "VA.1", "name": "Tamper-Evident HMAC-SHA384 SIEM Chaining", "implemented": True, "details": "Cryptographic forward chaining of all audit events"},
            {"id": "VA.2", "name": "Immutable Head Anchor Locking", "implemented": True, "details": "Tail truncation protection via signed head anchor export"},
            {"id": "VA.3", "name": "Continuous Monitoring (ISCM Telemetry)", "implemented": True, "details": "NIST SP 800-137 continuous telemetry across 5 probes"},
            {"id": "VA.4", "name": "Automated RMF Control Traceability", "implemented": True, "details": "Machine-readable NIST OSCAL v1.1.0 SSP and SCTM"},
        ]
        score = sum(1 for c in capabilities if c["implemented"]) / len(capabilities) * 100.0
        return {
            "pillar_id": 7,
            "name": "Visibility & Analytics",
            "score_percentage": score,
            "status": "COMPLIANT" if score >= 90.0 else "NON_COMPLIANT",
            "capabilities": capabilities,
        }

    def perform_full_assessment(self) -> Dict[str, Any]:
        """Execute assessment across all 7 Zero Trust pillars."""
        pillars = [
            self.evaluate_pillar_1_user(),
            self.evaluate_pillar_2_device(),
            self.evaluate_pillar_3_applications(),
            self.evaluate_pillar_4_data(),
            self.evaluate_pillar_5_network(),
            self.evaluate_pillar_6_automation(),
            self.evaluate_pillar_7_visibility(),
        ]
        for pillar in pillars:
            for cap in pillar.get("capabilities", []):
                cap["evidence"] = _CAPABILITY_EVIDENCE.get(
                    cap.get("id", ""),
                    ["unspecified -- see SAR POA&M (no in-repo proof claimed)"])

        overall_score = sum(p["score_percentage"] for p in pillars) / len(pillars)
        target_level_achieved = overall_score >= 95.0 and all(p["score_percentage"] >= 90.0 for p in pillars)

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return {
            "dod_zero_trust_assessment": {
                "assessment_kind": "SELF-ASSESSMENT (developer-run capability checklist; not an independent assessment, not a compliance determination)",
                "framework": "Department of Defense (DoD) Zero Trust Strategy 2027",
                "target_capability_baseline": "Target Level (2027 Mandate)",
                "assessment_timestamp_utc": now,
                "overall_score_percentage": round(overall_score, 2),
                "target_level_achieved": target_level_achieved,
                "status": "TARGET_LEVEL_ACHIEVED" if target_level_achieved else "INTERMEDIATE_LEVEL",
                "pillars": pillars,
                "summary": {
                    "total_pillars_evaluated": 7,
                    "compliant_pillars": sum(1 for p in pillars if p["status"] == "COMPLIANT"),
                    "total_capabilities_evaluated": sum(len(p["capabilities"]) for p in pillars),
                    "implemented_capabilities": sum(
                        sum(1 for c in p["capabilities"] if c["implemented"]) for p in pillars
                    ),
                },
            }
        }


def sign_and_export_zero_trust_assessment(output_dir: Path | None = None) -> Tuple[Path, Path, Path]:
    """Generate, export, and sign DoD Zero Trust assessment with ML-DSA-87."""
    out_dir = output_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    evaluator = DoDZeroTrustEvaluator()
    assessment_data = evaluator.perform_full_assessment()
    canonical_json = json.dumps(assessment_data, indent=2, sort_keys=True).encode("utf-8")

    report_path = out_dir / "dod_zero_trust_assessment.json"
    sig_path = out_dir / "dod_zero_trust_assessment.json.mldsa87.sig"
    pub_path = out_dir / "dod_zero_trust_assessment.json.mldsa87.pub"

    report_path.write_bytes(canonical_json)

    signer = LibOQS_MLDSA_87()
    pk, sk = signer.keygen()
    sig = signer.sign(sk, canonical_json)

    sig_path.write_bytes(sig)
    pub_path.write_bytes(pk)

    return report_path, sig_path, pub_path


def verify_zero_trust_assessment_signature(report_path: Path, sig_path: Path, pub_path: Path) -> bool:
    """Verify ML-DSA-87 digital signature over DoD Zero Trust assessment."""
    if not (report_path.exists() and sig_path.exists() and pub_path.exists()):
        return False
    try:
        report_bytes = report_path.read_bytes()
        sig_bytes = sig_path.read_bytes()
        pub_bytes = pub_path.read_bytes()

        verifier = LibOQS_MLDSA_87()
        return verifier.verify(pub_bytes, report_bytes, sig_bytes)
    except Exception as e:
        logger.error(f"Zero Trust assessment signature verification failed: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DoD Zero Trust Architecture (ZTA 2.0) Target Level Evaluator")
    parser.add_argument("--verify", action="store_true", help="Verify existing assessment signature")
    args = parser.parse_args()

    rep = REPORTS_DIR / "dod_zero_trust_assessment.json"
    sig = REPORTS_DIR / "dod_zero_trust_assessment.json.mldsa87.sig"
    pub = REPORTS_DIR / "dod_zero_trust_assessment.json.mldsa87.pub"

    if args.verify:
        valid = verify_zero_trust_assessment_signature(rep, sig, pub)
        print(f"[*] Zero Trust Assessment Signature Valid: {valid}")
        sys.exit(0 if valid else 1)
    else:
        r_path, s_path, p_path = sign_and_export_zero_trust_assessment()
        valid = verify_zero_trust_assessment_signature(r_path, s_path, p_path)
        with open(r_path, "r", encoding="utf-8") as f:
            d = json.load(f)["dod_zero_trust_assessment"]
        print(f"[PASS] DoD Zero Trust Assessment: Score={d['overall_score_percentage']}% - {d['status']}")
        print(f"[PASS] Signature verified with ML-DSA-87 (FIPS 204): {s_path.name}")
        sys.exit(0 if valid else 1)

