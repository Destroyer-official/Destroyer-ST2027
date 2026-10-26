"""Deployment archive completeness and isolated lab self-test."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

from scripts import package_deployment as deployment


ROOT = Path(__file__).resolve().parent.parent


def test_clean_deployment_tree_runs_selftest():
    destination = ROOT / "out" / f"pytest-deployment-{os.getpid()}"
    try:
        deployment.build_deployment(destination)
        assert deployment.verify_deployment(destination)  # nosec: B101

        env = os.environ.copy()
        env["PYTHONPATH"] = ""
        env["PYTHONNOUSERSITE"] = "1"
        env["P2P_PRODUCTION"] = "0"
        env["SECURE_P2P_PRODUCTION"] = "0"
        env["P2P_TS_MODE"] = "0"
        result = subprocess.run(
            [sys.executable, "secure_transmit_2027.py", "selftest"],
            cwd=destination,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr  # nosec: B101
        assert "SELFTEST-OK" in result.stdout  # nosec: B101
    finally:
        shutil.rmtree(destination, ignore_errors=True)

