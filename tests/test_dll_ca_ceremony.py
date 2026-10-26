# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""Ed25519 DLL CA ceremony (scripts/sign_dependencies.py) — rotation guard,
offline custody bootstrap, and receipt self-attestation.

The CA private key must live OUTSIDE the repo; replacing existing trust
anchors requires the explicit --rotate ceremony flag; a bare re-sign only
works with the already-custodied key.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from sign_dependencies import load_ca_key, main


def _mk_dll(tmp_path, name="fake.dll", data=b"FAKE-DLL-BYTES"):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _receipt_args(tmp_path):
    return ["--receipt", str(tmp_path / "receipt.json")]


def test_refuses_without_ca_key_and_no_rotate(tmp_path):
    dll = _mk_dll(tmp_path)
    ca = tmp_path / "ca.pem"
    rc = main(["--ca-key", str(ca), "--dll", str(dll)] + _receipt_args(tmp_path))
    assert rc == 2
    assert not ca.exists()
    assert not Path(str(dll) + ".sig").exists()


def test_rotate_bootstraps_offline_ca_and_signs(tmp_path):
    dll = _mk_dll(tmp_path)
    ca = tmp_path / "ca.pem"
    rc = main(["--ca-key", str(ca), "--dll", str(dll), "--rotate",
               "--reason", "unit-test"] + _receipt_args(tmp_path))
    assert rc == 0
    assert ca.exists()
    assert Path(str(ca) + ".passphrase").exists()

    pub = serialization.load_pem_public_key((Path(str(dll) + ".pub")).read_bytes())
    pub.verify(Path(str(dll) + ".sig").read_bytes(), dll.read_bytes())

    manifest = json.loads(Path(str(dll) + ".hashes").read_text(encoding="utf-8"))
    assert manifest["size"] == len(dll.read_bytes())
    assert manifest["sha512"] == hashlib.sha512(dll.read_bytes()).hexdigest()

    receipt = json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["action"] == "rotate"
    sig_b64 = receipt.pop("ed25519_signature_b64")
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    pub.verify(base64.b64decode(sig_b64), canonical)


def test_resign_with_same_custodied_key(tmp_path):
    dll = _mk_dll(tmp_path)
    ca = tmp_path / "ca.pem"
    assert main(["--ca-key", str(ca), "--dll", str(dll), "--rotate"] + _receipt_args(tmp_path)) == 0
    dll.write_bytes(b"NEW-DLL-BYTES")
    rc = main(["--ca-key", str(ca), "--dll", str(dll)] + _receipt_args(tmp_path))
    assert rc == 0
    pub = serialization.load_pem_public_key((Path(str(dll) + ".pub")).read_bytes())
    pub.verify(Path(str(dll) + ".sig").read_bytes(), dll.read_bytes())
    receipt = json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["action"] == "resign"


def test_refuses_silent_anchor_replacement(tmp_path):
    dll = _mk_dll(tmp_path)
    ca1 = tmp_path / "ca1.pem"
    assert main(["--ca-key", str(ca1), "--dll", str(dll), "--rotate"] + _receipt_args(tmp_path)) == 0
    anchor_before = Path(str(dll) + ".pub").read_bytes()

    other_ca = tmp_path / "ca2.pem"
    other_key = ed25519.Ed25519PrivateKey.generate()
    other_ca.write_bytes(other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    rc = main(["--ca-key", str(other_ca), "--dll", str(dll)] + _receipt_args(tmp_path))
    assert rc == 2
    assert Path(str(dll) + ".pub").read_bytes() == anchor_before


def test_rotate_replaces_anchor_with_explicit_flag(tmp_path):
    dll = _mk_dll(tmp_path)
    ca1 = tmp_path / "ca1.pem"
    assert main(["--ca-key", str(ca1), "--dll", str(dll), "--rotate"] + _receipt_args(tmp_path)) == 0
    anchor_before = Path(str(dll) + ".pub").read_bytes()

    ca2 = tmp_path / "ca2.pem"
    key2 = ed25519.Ed25519PrivateKey.generate()
    ca2.write_bytes(key2.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    rc = main(["--ca-key", str(ca2), "--dll", str(dll), "--rotate"] + _receipt_args(tmp_path))
    assert rc == 0
    anchor_after = Path(str(dll) + ".pub").read_bytes()
    assert anchor_after != anchor_before
    pub = serialization.load_pem_public_key(anchor_after)
    pub.verify(Path(str(dll) + ".sig").read_bytes(), dll.read_bytes())


def test_encrypted_ca_wrong_passphrase_fails_closed(tmp_path, monkeypatch):
    ca = tmp_path / "ca.pem"
    key = ed25519.Ed25519PrivateKey.generate()
    ca.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"correct-horse")))
    monkeypatch.delenv("P2P_CA_PASSPHRASE", raising=False)
    with pytest.raises(RuntimeError, match="cannot decrypt CA key"):
        load_ca_key(ca, None)
