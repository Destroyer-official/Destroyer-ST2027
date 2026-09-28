"""CNSA 2.0 January-2027 gate + 2026-27 research posture (E1/E2/E3).

2026-27 basis: FIPS 206 still draft (final late 2026/early 2027, wire
formats NOT compatible with pre-standard Falcon); IR 8610 round-3
candidates pre-standard (HAWK withdrawn after break); HashML-DSA
NSA-prohibited; Jan-1-2027 acquisition gate (ML-KEM-1024 + ML-DSA-87).

Covers:
  E1. NEVER_AUTHORIZED_2027 set exact + always enforced (fail-closed),
      2027 strict sets exact (no Falcon), strict rejects Falcon primary,
      non-strict keeps Falcon verify-legacy compat.
  E2. DeploymentVerifier.verify_cnsa27_readiness() passes on this host
      with native ML-KEM/ML-DSA roundtrip proof.
  E3. CBOM artifact: schema, ML-DSA-87 primary present, banned names
      absent from algorithm entries, live native sizes verified.

Fast except native PQ init (once). No network.
"""

import json

import pytest


def test_never_authorized_set_exact():
    from cnsa2_policy_engine import CNSA2PolicyEngine

    eng = CNSA2PolicyEngine()
    assert eng.NEVER_AUTHORIZED_2027 == frozenset({  # nosec: B101
        "FAEST", "HAWK", "MAYO", "MQOM", "QR-UOV", "SDITH", "SNOVA",
        "SQISIGN", "UOV",
        "HASHML-DSA", "HASHMLDSA", "HASH-ML-DSA", "HASHML-DSA-87",
        "HQC-128", "HQC-192",
        "FN-DSA-512", "FN-DSA-1024",
    })


def test_never_authorized_always_rejected():
    from cnsa2_policy_engine import CNSA2PolicyEngine, SecurityPolicyViolation

    eng = CNSA2PolicyEngine()
    for banned in ("HAWK", "MAYO", "HASHML-DSA-87", "FN-DSA-1024",
                   "HQC-128", "SQISIGN"):
        with pytest.raises(SecurityPolicyViolation):
            eng.validate_algorithm(banned)


def test_2027_strict_sets_and_falcon_quarantine(monkeypatch):
    from cnsa2_policy_engine import (
        AlgorithmCategory, CNSA2PolicyEngine, SecurityPolicyViolation)

    eng = CNSA2PolicyEngine()
    assert eng.CNSA_2027_APPROVED_SIG == frozenset({"ML-DSA-87", "SLH-DSA-256f"})  # nosec: B101
    assert "FALCON-1024" not in eng.CNSA_2027_APPROVED_SIG  # nosec: B101
    # Mandatory pair validates in any mode.
    assert eng.validate_algorithm("ML-KEM-1024", AlgorithmCategory.KEM) is True  # nosec: B101
    assert eng.validate_algorithm("ML-DSA-87", AlgorithmCategory.SIGNATURE) is True  # nosec: B101
    # Strict (2027 gate): Falcon primary refused...
    monkeypatch.setenv("CNSA_2027_STRICT", "1")
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    assert eng.is_cnsa_2027_strict is True  # nosec: B101
    with pytest.raises(SecurityPolicyViolation):
        eng.validate_algorithm("FALCON-1024", AlgorithmCategory.SIGNATURE)
    # ...while lab keeps verify-legacy compat (quarantine, not removal).
    monkeypatch.delenv("CNSA_2027_STRICT", raising=False)
    assert eng.is_cnsa_2027_strict is False  # nosec: B101
    assert eng.validate_algorithm("FALCON-1024", AlgorithmCategory.SIGNATURE) is True  # nosec: B101


def test_deployment_cnsa27_readiness_gate():
    from verify_deployment import DeploymentVerifier, VerificationStatus

    verifier = DeploymentVerifier()
    assert verifier.verify_cnsa27_readiness() is True  # nosec: B101
    kinds = {(r.status, r.check_name) for r in verifier.results}
    assert (VerificationStatus.PASS, "CNSA27: ML-KEM-1024 + ML-DSA-87 validate") in kinds  # nosec: B101
    assert (VerificationStatus.PASS, "CNSA27: native PQ roundtrip") in kinds  # nosec: B101
    assert (VerificationStatus.PASS, "CNSA27: HAWK refused") in kinds  # nosec: B101


def test_cbom_artifact_schema_and_policy(tmp_path):
    from generate_production_sbom import build_cbom_inventory, write_cbom

    out = write_cbom(tmp_path)
    assert out.exists()  # nosec: B101
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["cbom_version"] == "1.0"  # nosec: B101
    assert "CNSA 2.0" in doc["policy_basis"]  # nosec: B101
    assert isinstance(doc["components"], list) and len(doc["components"]) >= 5  # nosec: B101
    names = [a["name"] for c in doc["components"] for a in c["algorithms"]]
    assert "ML-DSA-87" in names and "ML-KEM-1024" in names  # nosec: B101
    banned = {"HAWK", "MAYO", "HASHML-DSA", "FN-DSA-512", "FN-DSA-1024",
              "FAEST", "MQOM", "QR-UOV", "SDITH", "SNOVA", "SQISIGN", "UOV"}
    assert not (set(names) & banned), "CBOM must not list unauthorized algorithms"  # nosec: B101
    live = doc["live_verification"]
    assert live["native_present"] is True  # nosec: B101
    assert live["native_sizes_ok"] is True  # nosec: B101
    assert live["policy_spotcheck_ok"] is True  # nosec: B101


def test_cbom_signs_and_verifies(tmp_path):
    from generate_production_sbom import _mldsa_sign_verified, write_cbom
    from liboqs_wrapper import LibOQS_MLDSA_87

    out = write_cbom(tmp_path)
    signer = LibOQS_MLDSA_87()
    pk, sk = signer.keygen()
    data = out.read_bytes()
    sig = _mldsa_sign_verified(signer, sk, pk, data, "cbom-probe")
    assert signer.verify(pk, data, sig) is True  # nosec: B101

