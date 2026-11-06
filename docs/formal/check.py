#!/usr/bin/env python3
"""Cross-platform formal verification gate for ST2027.

Runs ProVerif 2.05 on the machine-checked models:
  1. docs/formal/st2027_handshake.pv (Noise_XXhfs handshake secrecy & mutual authentication)
  2. docs/formal/st2027_pcs.pv (Continuous Epoch Ratchet PCS healing)
  3. rust_data_plane property bounded model checking doubles
  4. DudeCT statistical timing analysis (|t| < 4.5)

Usage:
  python docs/formal/check.py            # Runs when proverif is in PATH or env
  python docs/formal/check.py --strict   # Mandatory blocking gate: fails if proverif missing or query fails
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.formal_verification_orchestrator import generate_certificate, find_proverif


def main() -> None:
    parser = argparse.ArgumentParser(description="ST2027 Machine-Checked Formal Gate")
    parser.add_argument("--strict", action="store_true",
                        help="Mandatory blocking: exit code 1 if verification fails")
    args = parser.parse_args()

    proverif_bin = find_proverif()
    is_ci = os.environ.get("CI", "").lower() == "true"
    must_block = args.strict or is_ci

    if not proverif_bin:
        print("[!] ProVerif binary not found on this system.")
        if must_block:
            print("[-] FAIL: ProVerif >= 2.05 required in strict/CI mode.", file=sys.stderr)
            sys.exit(1)
        else:
            print("[*] Falling back to structural AST formal verification test suite...")
            ret = subprocess.run([sys.executable, "-m", "unittest", str(ROOT / "tests" / "test_formal_proverif_models.py")])
            sys.exit(ret.returncode)

    print(f"[+] ProVerif binary detected: {proverif_bin}")
    cert = generate_certificate(ROOT / "docs" / "formal", strict=must_block)

    if cert.get("overall_status") == "VERIFIED":
        print("\n[+] ALL FORMAL VERIFICATION TARGETS VERIFIED.")
        sys.exit(0)
    else:
        print("\n[-] FORMAL VERIFICATION FAILED.", file=sys.stderr)
        sys.exit(1 if must_block else 0)


if __name__ == "__main__":
    main()
