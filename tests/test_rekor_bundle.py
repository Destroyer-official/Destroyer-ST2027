"""Unit tests for generate_production_sbom.verify_rekor_bundle (offline, no network)."""

import hashlib
import json

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from generate_production_sbom import verify_rekor_bundle


def _fresh_keypair():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return sk, bytes(pub)


def _write_bundle(path, sk, checkpoint=None, payload=b"sbom-payload"):
    checkpoint = checkpoint if checkpoint is not None else (
        "rekor checkpoint v1\n5\n6 abcdef=\n"
    )
    sig = sk.sign(checkpoint.encode("utf-8"))
    bundle = {
        "payload_sha512": hashlib.sha512(payload).hexdigest(),
        "inclusion_proof": {"log_index": 5, "tree_size": 6},
        "checkpoint": checkpoint,
        "sig": sig.hex(),
    }
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return bundle


def test_roundtrip_sign_verify_true(tmp_path):
    sk, pub = _fresh_keypair()
    bundle_path = tmp_path / "rekor.json"
    _write_bundle(bundle_path, sk)
    assert verify_rekor_bundle(bundle_path, pub) is True  # nosec: B101


def test_tampered_payload_returns_false(tmp_path):
    sk, pub = _fresh_keypair()
    bundle_path = tmp_path / "rekor.json"
    bundle = _write_bundle(bundle_path, sk)
    # Tamper the signed checkpoint payload; sig no longer verifies.
    bundle["checkpoint"] = bundle["checkpoint"] + "tampered"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    assert verify_rekor_bundle(bundle_path, pub) is False  # nosec: B101


def test_missing_file_raises(tmp_path):
    _sk, pub = _fresh_keypair()
    with pytest.raises(FileNotFoundError):
        verify_rekor_bundle(tmp_path / "does-not-exist.json", pub)

