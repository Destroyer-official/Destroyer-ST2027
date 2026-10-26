#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""
scripts/generate_pqc_pki.py
===========================
Generates the Post-Quantum PKI hierarchy using ML-DSA-87 and NIST P-521.
Standardized technical name for scripts/generate_sovereign_pki.py (NOM-08).
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.generate_sovereign_pki import main

if __name__ == "__main__":
    main()
