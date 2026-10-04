#!/usr/bin/env python3
"""Execute ProVerif on docs/formal/st2027_handshake.pv and assert proofs.

This is NOT a structural grep (cf. legacy test_formal_proverif_models):
it runs the real ProVerif 2.05 binary (user-local install, no admin) and
requires every query to conclude RESULT ... is true. Any false result,
non-termination within budget, or missing binary fails closed.

Binary resolution: P2P_PROVERIF env, then %LOCALAPPDATA%\\ProVerif\\
proverif2.05\\proverif.exe, then PATH.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__file__).resolve().parent.parent
MODEL = REPO_ROOT / "docs" / "formal" / "st2027_handshake.pv"
PCS_MODEL = REPO_ROOT / "docs" / "formal" / "st2027_pcs.pv"

EXPECTED_QUERIES = (
    # Secrecy appears phase-transformed (attacker_p1) because the model
    # leaks long-term keys in phase 1 to prove forward secrecy.
    ("attacker_p1(secret_payload", "attacker(secret_payload"),
    ("inj-event(S_Accepts",),
    ("inj-event(R_Receives",),
    ("event(C_VerifiedM2",),
    # Initiator identity privacy (M1 carries no static keys; M3 only
    # after the responder authenticates). Phase-transformed like secrecy.
    ("attacker_p1(pk(sksC2", "attacker(pk(sksC2"),
)

# 15 minutes: the model is small (DH + KEM + phases + one table).
TIMEOUT_S = 900


def find_proverif() -> str:
    env = os.environ.get("P2P_PROVERIF", "").strip()
    if env and Path(env).exists():
        return env
    local = Path(os.environ.get("LOCALAPPDATA", "")) / "ProVerif" / "proverif2.05" / "proverif.exe"
    if local.exists():
        return str(local)
    found = shutil.which("proverif") or shutil.which("proverif.exe")
    if found:
        return found
    raise FileNotFoundError(
        "ProVerif binary not found (P2P_PROVERIF, %LOCALAPPDATA%\\ProVerif, or PATH)")


def run_proverif(model: Path, timeout: int = TIMEOUT_S) -> str:
    binary = find_proverif()
    assert model.exists(), f"model missing: {model}"
    try:
        p = subprocess.run(
            [binary, str(model)],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(model.parent))
    except subprocess.TimeoutExpired:
        pytest.fail(f"ProVerif did not terminate within {timeout}s")
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    if p.returncode not in (0, 1):
        pytest.fail(f"ProVerif crashed (rc={p.returncode}):\n{out[-4000:]}")
    return out


def test_proverif_model_proves():
    out = run_proverif(MODEL)
    results = re.findall(r"^RESULT\s+(.*?)\s+is\s+(true|false)\b",
                         out, re.MULTILINE)
    assert results, f"no RESULT lines parsed:\n{out[-4000:]}"
    assert not re.search(r"\bis false\b", "\n".join(f"{q} is {r}" for q, r in results)), \
        f"a query FAILED:\n{out[-4000:]}"
    assert not re.search(r"cannot be proved|proof attempt failed", out, re.IGNORECASE), \
        f"inconclusive proof:\n{out[-4000:]}"
    covered = {q for q, r in results if r == "true"}
    joined = "\n".join(covered)
    for want_group in EXPECTED_QUERIES:
        assert any(any(want in line for want in want_group) for line in covered), \
            f"expected query not proved ({want_group}):\n{joined}"
    assert len([r for _, r in results if r == "true"]) >= 4


def _assert_query(out: str, pattern: str, expect_true: bool, what: str) -> None:
    results = re.findall(r"^RESULT\s+(.*?)\s+is\s+(true|false)\b",
                         out, re.MULTILINE)
    assert results, f"no RESULT lines parsed:\n{out[-4000:]}"
    match = [r for q, r in results if re.search(pattern, q)]
    assert match, f"query not found ({what}):\n{out[-4000:]}"
    got = match[0] == "true"
    assert got == expect_true, \
        f"query {what} expected {'true' if expect_true else 'false'}, got {match[0]}"


def test_proverif_pcs_healing_and_control(tmp_path):
    """PCS: payload2 secret despite total epoch-1 compromise (RESULT true).

    Negative control on a scratch copy: payload1 MUST be attacker-known
    (RESULT false) — proving the compromise genuinely takes effect and
    the PCS verdict is not vacuous. The scratch copy is generated, never
    committed.
    """
    out = run_proverif(PCS_MODEL)
    _assert_query(out, r"attacker\(secret_payload2", True, "PCS payload2 secrecy")
    assert not re.search(r"cannot be proved|proof attempt failed", out, re.IGNORECASE), \
        f"inconclusive proof:\n{out[-4000:]}"
    scratch = tmp_path / "st2027_pcs_negctrl.pv"
    scratch.write_text(
        PCS_MODEL.read_text(encoding="utf-8").replace(
            "query attacker(secret_payload2).",
            "query attacker(secret_payload1)."),
        encoding="utf-8")
    out_neg = run_proverif(scratch)
    _assert_query(out_neg, r"attacker\(secret_payload1", False,
                  "negative control (compromise must take effect)")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
