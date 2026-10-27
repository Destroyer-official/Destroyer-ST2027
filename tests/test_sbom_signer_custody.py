"""SBOM signer custody resolution (F-04/A-01) — fail-closed anchor protection.

resolve_sbom_signing_material() must never signal a bootstrap (fresh lab
keypair) while ANY custody material exists: a present anchor .pub with a
relocated/missing .sk is the expected offline-custody production posture
and must refuse — signing then requires explicit key paths
(--signing-key/SBOM_SIGNING_KEY + SBOM_PUBKEY).
"""
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (_REPO_ROOT, _REPO_ROOT / "scripts"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from generate_production_sbom import resolve_sbom_signing_material


def _tmp_certs(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    return certs


def test_both_present_uses_local_anchor(tmp_path):
    certs = _tmp_certs(tmp_path)
    (certs / "sbom_mldsa87_signer.sk").write_bytes(b"SK-BYTES")
    (certs / "sbom_mldsa87_signer.pub").write_bytes(b"PK-BYTES")
    sk, pk, sk_src, pk_src, bootstrap = resolve_sbom_signing_material(certs_dir=certs)
    assert (sk, pk, bootstrap) == (b"SK-BYTES", b"PK-BYTES", False)
    assert Path(sk_src).name == "sbom_mldsa87_signer.sk"


def test_anchor_without_key_refused_never_bootstraps(tmp_path):
    certs = _tmp_certs(tmp_path)
    (certs / "sbom_mldsa87_signer.pub").write_bytes(b"PK-ANCHOR")
    with pytest.raises(RuntimeError, match="never silently replaced"):
        resolve_sbom_signing_material(certs_dir=certs)
    assert (certs / "sbom_mldsa87_signer.pub").read_bytes() == b"PK-ANCHOR"


def test_key_without_anchor_refused(tmp_path):
    certs = _tmp_certs(tmp_path)
    (certs / "sbom_mldsa87_signer.sk").write_bytes(b"SK-ONLY")
    with pytest.raises(RuntimeError, match="inconsistent custody"):
        resolve_sbom_signing_material(certs_dir=certs)


def test_neither_present_signals_bootstrap(tmp_path):
    certs = _tmp_certs(tmp_path)
    sk, pk, _, _, bootstrap = resolve_sbom_signing_material(certs_dir=certs)
    assert sk is None and pk is None and bootstrap is True


def test_explicit_key_missing_fails_closed(tmp_path):
    certs = _tmp_certs(tmp_path)
    with pytest.raises(RuntimeError, match="SBOM signing key not found"):
        resolve_sbom_signing_material(explicit_sk=str(tmp_path / "nope.sk"), certs_dir=certs)


def test_explicit_key_with_sibling_pub(tmp_path):
    certs = _tmp_certs(tmp_path)
    sk_path = tmp_path / "signer.sk"
    sk_path.write_bytes(b"SK")
    (tmp_path / "signer.pub").write_bytes(b"PK")
    sk, pk, _, pk_src, bootstrap = resolve_sbom_signing_material(
        explicit_sk=str(sk_path), certs_dir=certs)
    assert (sk, pk, bootstrap) == (b"SK", b"PK", False)
    assert Path(pk_src).name == "signer.pub"


def test_explicit_key_falls_back_to_certs_anchor(tmp_path):
    certs = _tmp_certs(tmp_path)
    (certs / "sbom_mldsa87_signer.pub").write_bytes(b"ANCHOR-PK")
    sk_path = tmp_path / "signer.sk"
    sk_path.write_bytes(b"SK")
    sk, pk, _, _, bootstrap = resolve_sbom_signing_material(
        explicit_sk=str(sk_path), certs_dir=certs)
    assert pk == b"ANCHOR-PK" and bootstrap is False


def test_explicit_key_without_any_pub_fails_closed(tmp_path):
    certs = _tmp_certs(tmp_path)
    sk_path = tmp_path / "signer.sk"
    sk_path.write_bytes(b"SK")
    with pytest.raises(RuntimeError, match="SBOM pubkey missing"):
        resolve_sbom_signing_material(explicit_sk=str(sk_path), certs_dir=certs)
