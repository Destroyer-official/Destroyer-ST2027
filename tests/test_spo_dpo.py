#!/usr/bin/env python3
"""Production tests for spo_dpo — all REAL ML-DSA-87, no mocks of crypto."""

import hashlib
import os
import time
from pathlib import Path

import pytest

import spo_dpo as ceremony
import secure_transmit_2027 as st


def _lab_handles(monkeypatch, tmp_path):
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("P2P_REQUIRE_HARDWARE_IDENTITY", raising=False)
    monkeypatch.delenv("P2P_TS_MODE", raising=False)
    monkeypatch.setenv("P2P_SIEM_LEDGER", str(tmp_path / "audit.jsonl"))
    st._audit_chain = None
    st.PIN_DIR = tmp_path / "pins"
    h1 = st.generate_identity_hsm("officer-one")
    h2 = st.generate_identity_hsm("officer-two")
    # Lab software handles must have distinct labels and keys here.
    assert h1.label != h2.label
    assert h1.sig_pk != h2.sig_pk
    return h1, h2


def test_spo_success_secret(monkeypatch, tmp_path):
    h1, _ = _lab_handles(monkeypatch, tmp_path)
    payload = b"routine SECRET movement order 001"
    ch = ceremony.issue_challenge("op-001", "SECRET", payload)
    ap = ceremony.create_approval(h1, ch)
    receipt = ceremony.authorize_spo(ch, h1, ap)
    assert receipt["mode"] == "SPO"
    assert receipt["op"] == "op-001"


def test_spo_refused_top_secret(monkeypatch, tmp_path):
    h1, _ = _lab_handles(monkeypatch, tmp_path)
    payload = b"top secret payload"
    ch = ceremony.issue_challenge("op-ts-001", "TOP SECRET", payload)
    ap = ceremony.create_approval(h1, ch)
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.authorize_spo(ch, h1, ap)


def test_dpo_success_top_secret(monkeypatch, tmp_path):
    h1, h2 = _lab_handles(monkeypatch, tmp_path)
    payload = b"TOP SECRET launch authentication payload"
    ch = ceremony.issue_challenge("op-ts-002", "TOP SECRET", payload)
    a1 = ceremony.create_approval(h1, ch)
    time.sleep(0.05)
    a2 = ceremony.create_approval(h2, ch)
    receipt = ceremony.authorize_dpo(ch, h1, a1, h2, a2)
    assert receipt["mode"] == "DPO"
    assert receipt["delta"] <= 2.0
    # Stronger ceremony satisfies weaker policy via authorize_transmission
    # (fresh approvals: nonces are single-use by design).
    ch2 = ceremony.issue_challenge("op-ts-002b", "TOP SECRET", payload)
    b1 = ceremony.create_approval(h1, ch2)
    b2 = ceremony.create_approval(h2, ch2)
    receipt2 = ceremony.authorize_transmission(
        "TOP SECRET", payload, ch2, [(h1, b1), (h2, b2)]
    )
    assert receipt2["mode"] == "DPO"


def test_dpo_refuses_same_officer(monkeypatch, tmp_path):
    h1, _ = _lab_handles(monkeypatch, tmp_path)
    payload = b"TOP SECRET same officer attempt"
    ch = ceremony.issue_challenge("op-ts-003", "TOP SECRET", payload)
    a1 = ceremony.create_approval(h1, ch)
    a2 = ceremony.create_approval(h1, ch)
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.authorize_dpo(ch, h1, a1, h1, a2)


def test_dpo_refuses_replay(monkeypatch, tmp_path):
    h1, h2 = _lab_handles(monkeypatch, tmp_path)
    payload = b"TOP SECRET replay attempt"
    ch = ceremony.issue_challenge("op-ts-004", "TOP SECRET", payload)
    a1 = ceremony.create_approval(h1, ch)
    a2 = ceremony.create_approval(h2, ch)
    ceremony.authorize_dpo(ch, h1, a1, h2, a2)
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.authorize_dpo(ch, h1, a1, h2, a2)


def test_dpo_refuses_tampered_payload(monkeypatch, tmp_path):
    h1, h2 = _lab_handles(monkeypatch, tmp_path)
    payload = b"authentic payload"
    ch = ceremony.issue_challenge("op-ts-005", "TOP SECRET", payload)
    a1 = ceremony.create_approval(h1, ch)
    a2 = ceremony.create_approval(h2, ch)
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.authorize_transmission(
            "TOP SECRET", b"tampered payload", ch, [(h1, a1), (h2, a2)]
        )


def test_dpo_refuses_sync_breach(monkeypatch, tmp_path):
    h1, h2 = _lab_handles(monkeypatch, tmp_path)
    payload = b"TOP SECRET sync breach"
    ch = ceremony.issue_challenge("op-ts-006", "TOP SECRET", payload)
    a1 = ceremony.create_approval(h1, ch)
    a2 = ceremony.create_approval(h2, ch)
    # Force timestamps 3.2s apart to simulate serial single-operator bypass.
    a2.approved_at = a1.approved_at + 3.2
    # Re-sign is not done on purpose: timestamp is part of signed body, so
    # verification must fail closed either on signature or on window.
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.authorize_dpo(ch, h1, a1, h2, a2)


def test_hardware_required_refuses_lab_keys(monkeypatch, tmp_path):
    h1, _ = _lab_handles(monkeypatch, tmp_path)
    monkeypatch.setenv("P2P_REQUIRE_HARDWARE_IDENTITY", "1")
    payload = b"SECRET hardware gate"
    ch = ceremony.issue_challenge("op-hw-001", "SECRET", payload)
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.create_approval(h1, ch)


def test_purity_inventory_includes_spo_dpo():
    from cnsa_purity import TS_SESSION_FILES, scan_tree

    assert "spo_dpo.py" in TS_SESSION_FILES
    assert scan_tree() == {}


def test_f02_unsigned_dpo_receipt_refused(monkeypatch, tmp_path):
    """F-02: self-minted JSON blob (no approvals) must be refused, lab too."""
    _lab_handles(monkeypatch, tmp_path)
    payload = b"self-minted TOP SECRET attempt"
    digest = hashlib.sha3_512(payload).hexdigest()
    forged = {
        "mode": "DPO",
        "op": "op-forged",
        "class": "TOP SECRET",
        "payload_hex": digest,
        "ts": time.time(),
    }
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.require_spo_dpo_for_send("TOP SECRET", payload, forged)


def test_f02_signed_dpo_receipt_accepted_end_to_end(monkeypatch, tmp_path):
    """F-02: real DPO receipt passes the send gate and survives tamper checks."""
    h1, h2 = _lab_handles(monkeypatch, tmp_path)
    payload = b"legitimately dual-controlled TOP SECRET"
    ch = ceremony.issue_challenge("op-f02-ok", "TOP SECRET", payload)
    a1 = ceremony.create_approval(h1, ch)
    a2 = ceremony.create_approval(h2, ch)
    receipt = ceremony.authorize_dpo(ch, h1, a1, h2, a2)
    # Gate accepts the genuine receipt.
    out = ceremony.require_spo_dpo_for_send("TOP SECRET", payload, receipt)
    assert out["mode"] == "DPO"
    assert out.get("v") == 2
    assert len(out["approvals"]) == 2


def test_f02_tampered_receipt_refused(monkeypatch, tmp_path):
    """F-02: flipping any signed field (payload, sig, nonce) breaks verify."""
    h1, h2 = _lab_handles(monkeypatch, tmp_path)
    payload = b"payload that will be tampered in the receipt"
    ch = ceremony.issue_challenge("op-f02-tamper", "TOP SECRET", payload)
    a1 = ceremony.create_approval(h1, ch)
    a2 = ceremony.create_approval(h2, ch)
    receipt = ceremony.authorize_dpo(ch, h1, a1, h2, a2)

    # Tamper 1: swap payload_hex to another digest.
    bad = dict(receipt)
    bad["payload_hex"] = hashlib.sha3_512(b"other").hexdigest()
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.require_spo_dpo_for_send("TOP SECRET", payload, bad)

    # Tamper 2: flip one bit in an embedded signature.
    bad2 = dict(receipt)
    bad2["approvals"] = [dict(a) for a in receipt["approvals"]]
    sig_hex = bad2["approvals"][0]["sig"]
    bad2["approvals"][0]["sig"] = ("0" if sig_hex[0] != "0" else "1") + sig_hex[1:]
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.require_spo_dpo_for_send("TOP SECRET", payload, bad2)

    # Tamper 3: replace server_nonce (breaks the signed challenge binding).
    bad3 = dict(receipt)
    bad3["server_nonce"] = "00" * 32
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.require_spo_dpo_for_send("TOP SECRET", payload, bad3)


def test_f02_single_approval_dpo_receipt_refused(monkeypatch, tmp_path):
    """F-02: DPO receipt with only one approval must not satisfy the gate."""
    h1, h2 = _lab_handles(monkeypatch, tmp_path)
    payload = b"only one officer approved this"
    ch = ceremony.issue_challenge("op-f02-one", "TOP SECRET", payload)
    a1 = ceremony.create_approval(h1, ch)
    a2 = ceremony.create_approval(h2, ch)
    receipt = ceremony.authorize_dpo(ch, h1, a1, h2, a2)
    # Drop the second approval — gate must refuse.
    bad = dict(receipt)
    bad["approvals"] = receipt["approvals"][:1]
    with pytest.raises(ceremony.AuthorizationError):
        ceremony.require_spo_dpo_for_send("TOP SECRET", payload, bad)
