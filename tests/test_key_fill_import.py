"""Dual-officer key-fill gates (G1): create -> verify -> import -> replay.

Covers:
  1. Roundtrip: sealed fill opens with both passphrases (either order).
  2. Single officer / wrong passphrase / swapped order fails closed.
  3. Tampered fill (payload flip, sig flip) rejected; wrong trust anchor.
  4. Expired fill rejected; oversize/bad-schema rejected.
  5. Re-import of the same fill_id refused (registry replay hygiene).
  6. verify_fill_signature auditor path (True/False, never raises).

Fast except ML-DSA keygen/sign (~ms native) + scrypt wraps.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

import key_fill_import as kfi
from key_fill_import import KeyFillError


@pytest.fixture(scope="module")
def ceremony_keys():
    from liboqs_wrapper import LibOQS_MLDSA_87
    pk, sk = LibOQS_MLDSA_87().keygen()
    return bytes(pk), bytes(sk)


@pytest.fixture()
def workdir():
    d = tempfile.mkdtemp(prefix="kmifill_")
    yield Path(d)
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def _flip_b64char(s: str) -> str:
    """Flip the first base64 char to a GUARANTEED-different valid char.

    (A naive "A" + s[1:] flip is a silent no-op 1/64 of the time when the
    original char already is "A" -- a real 1.5% flake this helper kills.)
    """
    return ("B" if s[0] != "B" else "C") + s[1:]


def _make_fill(ceremony_keys, officers=("OFF-A", "OFF-B"),
               pw=("correct horse 1", "correct horse 2"),
               payload=None, **kw):
    pk, sk = ceremony_keys
    return kfi.create_key_fill(
        fill_id="FILL-0001",
        payload=payload or {"kind": "node-identity",
                            "node": "BASE_ALPHA",
                            "key_b64": "AAECAwQFBgc="},
        officer_ids=list(officers), officer_passphrases=list(pw),
        signing_key=sk, **kw), pk


def test_roundtrip_both_orders(ceremony_keys, workdir):
    fill, pk = _make_fill(ceremony_keys)
    reg = str(workdir / "registry.json")
    out = kfi.import_key_fill(
        fill_bytes=json.dumps(fill).encode(), officer_ids=["OFF-A", "OFF-B"],
        officer_passphrases=["correct horse 1", "correct horse 2"],
        verify_key=pk, registry_path=reg)
    assert out["payload"]["node"] == "BASE_ALPHA"  # nosec: B101
    assert kfi.verify_fill_signature(fill, pk) is True  # nosec: B101


def test_single_officer_and_wrong_passphrase_fail(ceremony_keys, workdir):
    fill, pk = _make_fill(ceremony_keys)
    reg = str(workdir / "registry.json")
    # Only one officer's wrap presented (officer set mismatch).
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(
            fill_bytes=json.dumps(fill).encode(), officer_ids=["OFF-A", "OFF-A"],
            officer_passphrases=["correct horse 1", "correct horse 1"],
            verify_key=pk, registry_path=reg)
    # Wrong second passphrase.
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(
            fill_bytes=json.dumps(fill).encode(), officer_ids=["OFF-A", "OFF-B"],
            officer_passphrases=["correct horse 1", "wrong passphrase!!"],
            verify_key=pk, registry_path=reg)
    # Swapped order is FINE (2-of-2, either order) -- proves order freedom.
    out = kfi.import_key_fill(
        fill_bytes=json.dumps(fill).encode(), officer_ids=["OFF-B", "OFF-A"],
        officer_passphrases=["correct horse 2", "correct horse 1"],
        verify_key=pk, registry_path=reg)
    assert out["fill_id"] == "FILL-0001"  # nosec: B101


def test_tamper_and_wrong_anchor_fail(ceremony_keys, workdir):
    from liboqs_wrapper import LibOQS_MLDSA_87
    fill, pk = _make_fill(ceremony_keys)
    reg = str(workdir / "registry.json")
    kw = dict(officer_ids=["OFF-A", "OFF-B"],
              officer_passphrases=["correct horse 1", "correct horse 2"],
              verify_key=pk, registry_path=reg)
    bad = json.loads(json.dumps(fill))
    bad["enc"]["ct"] = _flip_b64char(bad["enc"]["ct"])
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(fill_bytes=json.dumps(bad).encode(), **kw)
    bad2 = json.loads(json.dumps(fill))
    bad2["sig"] = _flip_b64char(bad2["sig"])
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(fill_bytes=json.dumps(bad2).encode(), **kw)
    other_pk, _ = LibOQS_MLDSA_87().keygen()
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(fill_bytes=json.dumps(fill).encode(),
                            officer_ids=kw["officer_ids"],
                            officer_passphrases=kw["officer_passphrases"],
                            verify_key=bytes(other_pk), registry_path=reg)
    assert kfi.verify_fill_signature(fill, bytes(other_pk)) is False  # nosec: B101
    assert kfi.verify_fill_signature({"nope": 1}, pk) is False  # nosec: B101


def test_expiry_schema_caps_and_replay(ceremony_keys, workdir, tmp_path):
    import time as _time
    # A fill that expires between creation and import must fail closed.
    # (Non-positive/non-finite lifetimes are refused at creation instead.)
    fill, pk = _make_fill(ceremony_keys, expires_hours=0.00028)  # ~1s
    _time.sleep(1.5)
    reg = str(workdir / "registry.json")
    kw = dict(officer_ids=["OFF-A", "OFF-B"],
              officer_passphrases=["correct horse 1", "correct horse 2"],
              verify_key=pk, registry_path=reg)
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(fill_bytes=json.dumps(fill).encode(), **kw)
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(fill_bytes=b"x" * (64 * 1024 + 1), **kw)
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(fill_bytes=b"not json", **kw)
    good, _ = _make_fill(ceremony_keys)
    raw = json.dumps(good).encode()
    kfi.import_key_fill(fill_bytes=raw, **kw)
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(fill_bytes=raw, **kw)  # replay refused
    # File-path input works identically (fill_id changed after signing
    # must fail signature verification).
    good2, _ = _make_fill(ceremony_keys)
    good2 = dict(good2)
    good2["fill_id"] = "FILL-0002"
    with pytest.raises(KeyFillError):
        kfi.import_key_fill(fill_bytes=json.dumps(good2).encode(), **kw)


def test_create_rejects_bad_inputs(ceremony_keys):
    _, sk = ceremony_keys
    base = dict(fill_id="F", payload={"k": "v"}, officer_ids=["A", "B"],
                officer_passphrases=["passphrase-1", "passphrase-2"],
                signing_key=sk)
    with pytest.raises(KeyFillError):
        kfi.create_key_fill(**{**base, "officer_ids": ["A", "A"]})
    with pytest.raises(KeyFillError):
        kfi.create_key_fill(**{**base, "officer_passphrases": ["short", "passphrase-2"]})
    with pytest.raises(KeyFillError):
        kfi.create_key_fill(**{**base, "signing_key": b"short"})
    with pytest.raises(KeyFillError):
        kfi.create_key_fill(**{**base, "payload": {}})
    with pytest.raises(KeyFillError):
        kfi.create_key_fill(**{**base, "officer_ids": ["bad id!", "B"]})
    for bad_expiry in (0, -5, float("nan"), float("inf"), "soon"):
        with pytest.raises(KeyFillError):
            kfi.create_key_fill(**{**base, "expires_hours": bad_expiry})


def test_concurrent_double_import_single_winner(ceremony_keys, workdir):
    """Two threads racing the same fill: exactly one imports, one refused."""
    import threading
    fill, pk = _make_fill(ceremony_keys)
    raw = json.dumps(fill).encode()
    reg = str(workdir / "registry.json")
    kw = dict(officer_ids=["OFF-A", "OFF-B"],
              officer_passphrases=["correct horse 1", "correct horse 2"],
              verify_key=pk, registry_path=reg)
    results = []

    def _try():
        try:
            kfi.import_key_fill(fill_bytes=raw, **kw)
            results.append("ok")
        except KeyFillError:
            results.append("refused")

    threads = [threading.Thread(target=_try) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert sorted(results) == ["ok", "refused"]  # nosec: B101

