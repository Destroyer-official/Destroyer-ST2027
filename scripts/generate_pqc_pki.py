#!/usr/bin/env python3
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
