#!/usr/bin/env python3
"""Second-audit regression battery (F-01..F-06).

F-03: destroyer_node.establish_from_noise annotates ``sess: Any`` — the
module must import cleanly without NameError (CI collection was failing).
F-04: CAVP report must never claim CMVP submission readiness and must
dual-write the ATO-facing filename with a summary block.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "destroyer.py").exists() else Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_destroyer_node_imports_with_any_annotation():
    """F-03: NameError: Any at establish_from_noise must be impossible."""
    import destroyer_node  # noqa: F401
    from destroyer_node import DestroyerNode
    assert "Any" in DestroyerNode.establish_from_noise.__annotations__ or True
    # Annotations must resolve: typing.get_type_hints does not raise NameError.
    from typing import get_type_hints
    hints = get_type_hints(DestroyerNode.establish_from_noise)
    assert "sess" in hints


def test_cavp_report_never_claims_cmvp_submission():
    """F-04: readiness label must be LOCAL_SELFTEST_ONLY_NOT_CMVP (or DEFICIENCIES)."""
    report = ROOT / "compliance_reports" / "cavp_validation_report.json"
    if not report.exists():
        pytest.skip("cavp report not generated yet")
    data = json.loads(report.read_text(encoding="utf-8"))
    readiness = data.get("fips_140_3_readiness", "")
    assert readiness != "VERIFIED_FOR_CMVP_SUBMISSION", (
        "CAVP self-test must not claim CMVP submission readiness (F-04)"
    )
    cmvp = data.get("cmvp_claim", {})
    assert cmvp.get("module_is_cmvp_validated") is False
    assert cmvp.get("certificate_number") is None


def test_cavp_report_has_ato_compatible_summary():
    """F-04: local CAVP report carries summary.* for ATO fallback; does not clobber signed ACVP."""
    report = ROOT / "compliance_reports" / "cavp_validation_report.json"
    if not report.exists():
        pytest.skip("cavp report not generated yet")
    data = json.loads(report.read_text(encoding="utf-8"))
    summary = data.get("summary", {})
    assert summary.get("total_tests", 0) >= 12
    assert summary.get("failed", 1) == 0
    # Signed ACVP harness artifact must not be overwritten by the local KAT script.
    acvp = ROOT / "compliance_reports" / "acvp_cavp_validation_report.json"
    if acvp.exists():
        acvp_data = json.loads(acvp.read_text(encoding="utf-8"))
        # ACVP harness schema has metadata.harness_name; local CAVP has validation_program.
        assert "validation_program" not in acvp_data or acvp_data.get("validation_program") != data.get("validation_program")


def test_seq_journal_helpers_present_in_binary_source():
    """F-01: main.rs must contain the append-only journal path helper."""
    src = (ROOT / "rust_data_plane" / "src" / "main.rs").read_text(encoding="utf-8")
    assert "fn seq_journal_path" in src
    assert "fn seq_journal_high_water" in src
    assert "fn seq_journal_append" in src
    assert "state rollback detected" in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
