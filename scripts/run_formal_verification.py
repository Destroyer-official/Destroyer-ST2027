#!/usr/bin/env python3
"""
scripts/run_formal_verification.py

Automated Symbolic Formal Verification Engine for ST2027 Post-Quantum Protocol.
Verifies the machine-checked ProVerif models:
  - docs/formal/st2027_handshake.pv (Noise_XXhfs + ML-KEM-1024 + ML-DSA-87)
  - docs/formal/st2027_pcs.pv (Post-Compromise Security & Continuous Epoch Ratchet)
  - docs/formal/nc3_dual_custody.pv (NC3 Two-Person Rule EAM Verification)

Evaluates:
  1. Payload Secrecy vs Active Dolev-Yao Adversary: not attacker(secret_payload) is true
  2. Mutual Injective Identity Agreement: inj-event(S_Accepts) ==> inj-event(C_Accepts) is true
  3. Responder Authentication: event(C_VerifiedM2) ==> event(S_SentM2) is true
  4. Record Layer Anti-Replay: inj-event(R_Receives) ==> inj-event(C_Sends) is true
  5. Initiator Identity Privacy: not attacker(pk(sksC2)) is true

Outputs: compliance_reports/formal_verification_report.json (Signed with ML-DSA-87)
"""

import os
import sys
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from liboqs_wrapper import LibOQS_MLDSA_87


def run_formal_verification(output_dir: Optional[Path] = None) -> Dict[str, Any]:
    print("=" * 76)
    print("ST2027 FORMAL SYMBOLIC PROTOCOL VERIFICATION ENGINE (PROVERIF / PI-CALCULUS)")
    print("=" * 76)

    timestamp = datetime.now(timezone.utc).isoformat()
    report: Dict[str, Any] = {
        "engine": "ProVerif 2.05+ Automated Protocol Model Checker",
        "threat_model": "Dolev-Yao Active Network Attacker (Full Control over net)",
        "timestamp": timestamp,
        "models_evaluated": [],
        "overall_status": "PASS",
        "theorems_proven": 0,
        "theorems_total": 0
    }

    formal_dir = REPO_ROOT / "docs" / "formal"
    models = [
        ("st2027_handshake.pv", "Noise_XXhfs Hybrid KEX (P-384 + ML-KEM-1024 + ML-DSA-87)"),
        ("st2027_pcs.pv", "Continuous Epoch Ratchet (CER) Post-Compromise Security"),
        ("nc3_dual_custody.pv", "NC3 Strategic Two-Officer Rule Emergency Action Message")
    ]

    proverif_bin = shutil.which("proverif") or os.environ.get("P2P_PROVERIF")
    has_proverif = bool(proverif_bin and Path(proverif_bin).exists())

    if not has_proverif:
        report["overall_status"] = "NOT_VERIFIED_PROVERIF_MISSING"
        print("[!] FAIL-CLOSED: ProVerif binary not found in PATH or P2P_PROVERIF.")
        print("    Structural parsing is NOT a formal Dolev-Yao proof. Skipping synthetic PASS fabrication.")
    else:
        print(f"[*] ProVerif Binary Detected: YES ({proverif_bin})")

    for filename, description in models:
        pv_path = formal_dir / filename
        if not pv_path.exists():
            print(f"  [-] Model file missing: {filename}")
            report["overall_status"] = "FAIL"
            continue

        print(f"\n[*] Evaluating Formal Model: {filename}")
        print(f"    Description: {description}")

        model_entry: Dict[str, Any] = {
            "file": filename,
            "description": description,
            "verified_properties": [],
            "status": "FAIL" if not has_proverif else "PENDING",
        }

        if filename == "st2027_handshake.pv":
            properties = [
                ("Secrecy_Payload", "secret_payload", "PFS Confidentiality"),
                ("Mutual_Auth_Client", "inj-event(S_Accepts", "Mutual Identity Agreement"),
                ("Auth_Responder_M2", "event(C_VerifiedM2", "Responder Authenticity"),
                ("Record_Anti_Replay", "inj-event(R_Receives", "Injective Nonce Anti-Replay"),
                ("Initiator_Identity_Privacy", "sksC2", "Initiator Identity Confidentiality"),
            ]
        elif filename == "st2027_pcs.pv":
            properties = [
                ("Break_In_Recovery_PCS", "secret_payload2", "Post-Compromise Healing"),
            ]
        else:  # nc3_dual_custody.pv
            properties = [
                ("PAL_Confidentiality", "top_secret_pal_code", "PAL Secrecy Under Compromised Officer 1"),
                ("Dual_Officer_Authentication", "event(PALCodeReleased", "Two-Person Rule Authentication"),
                ("Dual_Officer_Injective_Binding", "inj-event(PALCodeReleased", "Two-Person Rule Injective Binding"),
            ]

        output = ""
        proverif_ok = False
        if has_proverif:
            try:
                proc = subprocess.run(
                    [proverif_bin, str(pv_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=str(pv_path.parent),
                )
                output = (proc.stdout or "") + "\n" + (proc.stderr or "")
                proverif_ok = proc.returncode == 0
                print(f"  [+] Native ProVerif execution complete (exit code: {proc.returncode})")
            except Exception as e:
                output = f"ProVerif execution error: {e}"
                proverif_ok = False

        import re
        result_lines = re.findall(r"^RESULT\s+(.*?)\s+is\s+(true|false)\b", output, re.MULTILINE) if output else []
        any_failed = False

        for prop_id, query_needle, sec_goal in properties:
            report["theorems_total"] += 1
            if not has_proverif:
                status = "NOT_VERIFIED_PROVERIF_MISSING"
                math_res = "ProVerif binary absent; theorem NOT proven"
                any_failed = True
            elif not proverif_ok or not result_lines:
                status = "FAIL"
                math_res = "ProVerif execution failed or produced no RESULT lines"
                any_failed = True
            else:
                matching = [(q, r) for (q, r) in result_lines if query_needle in q]
                prop_passed = bool(matching) and all(r == "true" for (_, r) in matching)
                status = "PASS" if prop_passed else "FAIL"
                math_res = "; ".join(f"{q} is {r}" for (q, r) in matching) if matching else "Query not found in ProVerif RESULT output"
                if prop_passed:
                    report["theorems_proven"] += 1
                else:
                    any_failed = True

            model_entry["verified_properties"].append({
                "property_id": prop_id,
                "formal_query_pattern": query_needle,
                "mathematical_result": math_res,
                "security_guarantee": sec_goal,
                "status": status,
            })
            print(f"  [*] Theorem [{prop_id}]: {sec_goal} -> {status}")

        model_entry["status"] = "PASS" if not any_failed else ("NOT_VERIFIED_PROVERIF_MISSING" if not has_proverif else "FAIL")
        if any_failed and has_proverif:
            report["overall_status"] = "FAIL"
        report["models_evaluated"].append(model_entry)

    out_dir = Path(output_dir) if output_dir is not None else (REPO_ROOT / "compliance_reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "formal_verification_report.json"

    signing_key_file = os.environ.get("ST2027_REPORT_SIGN_SK_FILE", "").strip()
    if signing_key_file and Path(signing_key_file).is_file() and report["overall_status"] == "PASS":
        sk_bytes = bytes.fromhex(Path(signing_key_file).read_text(encoding="utf-8").strip())
        mldsa = LibOQS_MLDSA_87()
        sig = mldsa.sign(sk_bytes, json.dumps(report, indent=2).encode("utf-8"))
        sig_path = out_dir / "formal_verification_report.json.mldsa87.sig"
        sig_path.write_bytes(sig)
        report["signature_status"] = f"SIGNED_AUTHORITY_KEY ({sig_path.name})"
    else:
        report["signature_status"] = "UNSIGNED_NO_EPHEMERAL_SELF_SIGNING"

    report_path.write_bytes(json.dumps(report, indent=2).encode("utf-8"))

    print("\n" + "=" * 76)
    print(f"[FORMAL VERIFICATION SUMMARY] Status: {report['overall_status']} | Proven: {report['theorems_proven']}/{report['theorems_total']}")
    print(f"[ARTIFACT] Report: {report_path.name} ({report['signature_status']})")
    print("=" * 76)

    return report


if __name__ == "__main__":
    report = run_formal_verification()
    sys.exit(0 if report["overall_status"] == "PASS" and report["theorems_proven"] == report["theorems_total"] else 1)
