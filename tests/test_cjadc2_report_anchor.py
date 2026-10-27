#!/usr/bin/env python3
"""Compliance reports must verify against a pinned anchor, not their own .pub."""

import json

from cjadc2_allied_gateway import (
    generate_cjadc2_report,
    verify_allied_gateway_report_signature,
)
from liboqs_wrapper import LibOQS_MLDSA_87


def test_forged_self_anchored_report_is_rejected(tmp_path):
    report_p, sig_p, pub_p = generate_cjadc2_report(tmp_path)
    assert verify_allied_gateway_report_signature(report_p, sig_p, pub_p) is True  # nosec: B101

    signer = LibOQS_MLDSA_87()
    attacker_pk, attacker_sk = signer.keygen()
    forged_data = json.dumps({"forged": True}, sort_keys=True).encode("utf-8")
    report_p.write_bytes(forged_data)
    sig_p.write_bytes(signer.sign(attacker_sk, forged_data))
    pub_p.write_bytes(attacker_pk)

    assert verify_allied_gateway_report_signature(report_p, sig_p, pub_p) is False  # nosec: B101


def test_audit_signer_anchor_lengths():
    """Verify that audit signer keys match exact ML-DSA-87 parameter sizes (2592/4896)."""
    from pathlib import Path
    repo_root = Path(__file__).resolve().parent.parent
    pk_file = repo_root / "keys" / "audit_signer.mldsa87.pk"
    sk_file = repo_root / "keys" / "audit_signer.mldsa87.sk"
    assert pk_file.exists(), f"Audit signer public key missing: {pk_file}"
    assert pk_file.stat().st_size == 2592, f"Expected 2592 bytes for ML-DSA-87 PK, got {pk_file.stat().st_size}"
    if sk_file.exists():
        assert sk_file.stat().st_size == 4896, f"Expected 4896 bytes for ML-DSA-87 SK, got {sk_file.stat().st_size}"

