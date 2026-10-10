"""SSDF self-attestation + ZT evidence-map gates (Tier-1/2 package depth).

Covers:
  1. SSDF artifact: 14 practices across PO/PS/PW/RV, statuses honest
     (implemented/partial with gaps), every practice carries evidence.
  2. SSDF sign/verify roundtrip via detached ML-DSA-87 siblings.
  3. ZeroTrust evidence map: all 28 capabilities resolve to non-empty
     evidence; every named path exists on disk.
  4. No practice claims a status it cannot show evidence for
     (implemented => evidence non-empty).

Fast except ML-DSA keygen (~ms native). No network.
"""

import json

import pytest

import ssdf_attestation as ssdf
from ssdf_attestation import build_ssdf_practices


def test_practice_inventory_honest():
    practices = build_ssdf_practices()
    groups = {p["group"] for p in practices}
    assert groups == {"PO", "PS", "PW", "RV"}  # nosec: B101
    assert len(practices) == 14  # nosec: B101
    for p in practices:
        assert p["status"] in ("implemented", "partial", "planned", "na")  # nosec: B101
        assert isinstance(p["evidence"], list) and len(p["evidence"]) > 0  # nosec: B101
        if p["status"] in ("partial", "planned"):
            assert p.get("gap_and_plan"), f"{p['practice']} hides its gap"  # nosec: B101
    by_status = {}
    for p in practices:
        by_status[p["status"]] = by_status.get(p["status"], 0) + 1
    assert by_status.get("implemented", 0) >= 10  # nosec: B101
    assert "SECURITY.md" in " ".join(  # nosec: B101
        p.get("gap_and_plan", "") for p in practices), \
        "missing disclosure-contact gap must be tracked"


def test_ssdf_sign_verify_roundtrip(tmp_path):
    from ssdf_attestation import (
        sign_and_export_ssdf_attestation,
        verify_ssdf_attestation_signature,
    )
    r, s, p = sign_and_export_ssdf_attestation(output_dir=tmp_path)
    assert r.exists() and s.exists() and p.exists()  # nosec: B101
    assert verify_ssdf_attestation_signature(r, s, p) is True  # nosec: B101
    doc = json.loads(r.read_bytes())
    assert doc["framework"] == "NIST SP 800-218 SSDF v1.1"  # nosec: B101
    assert doc["summary"]["total"] == 14  # nosec: B101
    assert (  # nosec: B101
        "NOT" in doc["attestation_kind"].upper()
        or "not " in doc["attestation_kind"].lower()
    )


def test_zt_evidence_map_complete():
    import os
    from zero_trust_assessment import DoDZeroTrustEvaluator, _CAPABILITY_EVIDENCE
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assessment = DoDZeroTrustEvaluator().perform_full_assessment()[
        "dod_zero_trust_assessment"]
    seen = set()
    for pillar in assessment["pillars"]:
        for cap in pillar["capabilities"]:
            seen.add(cap["id"])
            ev = cap.get("evidence", [])
            assert (  # nosec: B101
                isinstance(ev, list) and len(ev) > 0
            ), f"capability {cap['id']} has no evidence"
            for item in ev:
                # Strip pytest node-id ("::...") and "(annotation)" suffixes.
                base = item.split("::")[0].split(" (")[0].strip()
                assert (  # nosec: B101
                    os.path.exists(os.path.join(repo, base))
                ), f"evidence path missing: {base} (cap {cap['id']})"
    assert len(seen) == 29  # nosec: B101
    assert set(_CAPABILITY_EVIDENCE.keys()) == seen  # nosec: B101

