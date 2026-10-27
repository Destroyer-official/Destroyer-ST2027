#!/usr/bin/env python3
"""
scripts/verify_ratchet_performance.py
=====================================
Wrapper around internal ratchet and security vector performance benchmark drill.
Standardized technical name for scripts/verify_50x_sovereign_superiority.py (NOM-07).
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.verify_50x_sovereign_superiority import SovereignSuperiorityBenchmark

if __name__ == "__main__":
    benchmark = SovereignSuperiorityBenchmark()
    success = benchmark.run_all()
    sys.exit(0 if success else 1)
