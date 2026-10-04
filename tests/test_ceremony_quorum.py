"""Ceremony cryptographic quorum (2-of-3 custodian approvals are real).

The old receipt "signatures" were sha512(id || root) -- computable by
anyone, proving nothing. Now each custodian holds an Ed25519 approval key;
receipt minting requires >= quorum_m VALID signatures over the FINAL
Merkle root, and auditors re-verify chain + quorum via verify_receipt().

Covers:
  1. Receipt without approvals fails closed (RuntimeError).
  2. Sub-quorum approvals (1-of-2) fail closed.
  3. Quorum (2-of-3) mints; verify_receipt() accepts.
  4. Forged/unknown-custodian approvals rejected (approve False).
  5. Tampered root / tampered chain step fails verify_receipt().
  6. Duplicate approvals from one custodian do not reach quorum.

Fast: no PQ keygen exercised (quorum logic only). No network.
"""

import copy
import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "witnessed_key_ceremony",
    str(Path(__file__).resolve().parent / "scripts" / "witnessed_key_ceremony.py"))
_cer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_cer)
WitnessedKeyCeremony = _cer.WitnessedKeyCeremony


def _fresh(tmp_path):
    # Redirect receipt output into tmp: generate_ceremony_receipt hardcodes
    # PROJECT_ROOT/compliance_reports, and other suites glob that dir for
    # the NEWEST receipt (a test receipt there would poison their assumptions).
    c = WitnessedKeyCeremony(ceremony_id="TEST-CEREMONY-QUORUM-001")
    c.output_dir = Path(tmp_path) / "ceremony_out"
    c.output_dir.mkdir(parents=True, exist_ok=True)
    assert c.register_custodians() is True  # nosec: B101
    c.log_ceremony_step("UNIT_PROBE", {"probe": True})
    return c


def _approve_all(c, ids=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    approved = 0
    for cid in (ids or [cu["id"] for cu in c.custodians]):
        priv = c._custodian_private[cid]
        sig = priv.sign(c._approval_message(cid, c.approval_challenge()))
        assert c.approve(cid, bytes(sig)) is True  # nosec: B101
        approved += 1
    return approved


def test_receipt_without_approvals_fails_closed(tmp_path):
    c = _fresh(tmp_path)
    with pytest.raises(RuntimeError):
        c.generate_ceremony_receipt()


def test_sub_quorum_fails_closed(tmp_path):
    c = _fresh(tmp_path)
    _approve_all(c, ids=["CUSTODIAN-01"])
    with pytest.raises(RuntimeError):
        c.generate_ceremony_receipt()


def test_quorum_mints_and_verifies(tmp_path):
    c = _fresh(tmp_path)
    _approve_all(c, ids=["CUSTODIAN-01", "CUSTODIAN-02"])
    path = c.generate_ceremony_receipt()
    assert path.exists()  # nosec: B101
    ok, msg = WitnessedKeyCeremony.verify_receipt(c.receipt, quorum_m=2)
    assert ok, msg  # nosec: B101
    # Higher threshold than met fails.
    ok, _ = WitnessedKeyCeremony.verify_receipt(c.receipt, quorum_m=3)
    assert not ok  # nosec: B101


def test_forged_and_unknown_approvals_rejected(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    c = _fresh(tmp_path)
    rogue = Ed25519PrivateKey.generate()
    root = c.approval_challenge()
    # Wrong key for a real custodian.
    assert c.approve("CUSTODIAN-01", bytes(rogue.sign(  # nosec: B101
        c._approval_message("CUSTODIAN-01", root)))) is False
    # Unknown custodian.
    assert c.approve("CUSTODIAN-99", b"\x00" * 64) is False  # nosec: B101
    # Garbage bytes.
    assert c.approve("CUSTODIAN-01", b"not-a-signature") is False  # nosec: B101
    with pytest.raises(RuntimeError):
        c.generate_ceremony_receipt()


def test_tampered_root_and_chain_fail_verify(tmp_path):
    c = _fresh(tmp_path)
    _approve_all(c, ids=["CUSTODIAN-01", "CUSTODIAN-02"])
    c.generate_ceremony_receipt()
    bad = copy.deepcopy(c.receipt)
    bad["merkle_root_hash"] = "00" * 64
    ok, _ = WitnessedKeyCeremony.verify_receipt(bad, quorum_m=2)
    assert not ok, "forged root must fail"  # nosec: B101
    bad2 = copy.deepcopy(c.receipt)
    bad2["merkle_audit_steps"][0]["details"] = {"probe": False}
    ok, _ = WitnessedKeyCeremony.verify_receipt(bad2, quorum_m=2)
    assert not ok, "tampered chain step must fail"  # nosec: B101


def test_single_custodian_cannot_reach_quorum(tmp_path):
    c = _fresh(tmp_path)
    # Same custodian approving twice still counts once.
    assert _approve_all(c, ids=["CUSTODIAN-01"]) == 1  # nosec: B101
    assert c.approve("CUSTODIAN-01", bytes(  # nosec: B101
        c._custodian_private["CUSTODIAN-01"].sign(
            c._approval_message("CUSTODIAN-01", c.approval_challenge())))) is True
    with pytest.raises(RuntimeError):
        c.generate_ceremony_receipt()
    ok, _ = WitnessedKeyCeremony.verify_receipt(
        {**c.receipt, "custodian_signatures": [], "merkle_root_hash": c.approval_challenge(),
         "merkle_audit_steps": c.merkle_steps, "ceremony_id": c.ceremony_id,
         "timestamp_utc": c.timestamp}, quorum_m=2)
    assert not ok  # nosec: B101

