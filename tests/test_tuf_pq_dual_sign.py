"""TUF-lite post-quantum dual signatures (Fix B / audit 7.2, CNSA 2.0).

Both update paths dual-sign with ML-DSA-87 over the identical canonical
bytes alongside Ed25519:
  * live update path: manifest.json (+ .sig + .mldsa87.sig);
  * 4-role path: root/timestamp/snapshot/targets.json (+ .sig + .mldsa87.sig),
    with the ceremony PQ key published in root.json.

Policy enforced on verify (manifest + each role):
  * present-but-bad PQ sig  -> ALWAYS reject (no silent strip, even lab);
  * missing PQ sig           -> reject iff PQ required (production env or
    P2P_REQUIRE_PQ_CODE_SIG=1), else accept (migration window).

Covers:
  1. Manifest + roles dual-signed (.mldsa87.sig, 4627 bytes each).
  2. root.json publishes the ceremony ML-DSA-87 key (transparency).
  3. Dual-signed bundle verifies (both flows) and applies.
  4. Tampered PQ sig rejected even in lab (both flows).
  5. Missing PQ sig accepted in lab, rejected when required.
  6. Wrong ceremony passphrase cannot unseal the PQ private half.

Fast, deterministic, no network. Requires native liboqs (oqs.dll).
"""

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

# Ceremony secret is provisioned per-test (function fixture below), never at
# module scope: import-time env writes race with other suites' teardown in
# the same pytest process (they wiped test_2028's secret and broke its TUF
# tests -- root-caused 2026-09-21).


@pytest.fixture(autouse=True)
def _ceremony_secret(monkeypatch):
    """Self-sufficient ceremony secret: immune to other suites' env resets."""
    monkeypatch.setenv("P2P_SIGNING_PASSPHRASE", "test_tuf_pq_ceremony_secret_2028")

from supply_chain_security import CodeSigningError, TUFReleaseManager  # noqa: E402

ROLES = ("root", "timestamp", "snapshot", "targets")


@pytest.fixture()
def pkg():
    tmpdir = tempfile.mkdtemp()
    state_dir = Path(tmpdir) / "tuf_state"
    source_dir = Path(tmpdir) / "source"
    out_dir = Path(tmpdir) / "update_v1"
    dest_dir = Path(tmpdir) / "destination"
    roles_dir = Path(tmpdir) / "roles"
    source_dir.mkdir(parents=True)
    (source_dir / "core_update.py").write_text("# Core Update v1", encoding="utf-8")
    tuf = TUFReleaseManager(state_dir=str(state_dir))
    tuf.create_update_package(
        source_dir=str(source_dir), output_dir=str(out_dir), version_counter=1)
    roles_dir.mkdir(parents=True)
    tuf.create_role_metadata(output_dir=str(roles_dir), version=1,
                             source_dir=str(source_dir))
    yield tuf, out_dir, dest_dir, roles_dir
    shutil.rmtree(tmpdir, ignore_errors=True)


def _strip_pq(out_dir):
    for p in Path(out_dir).glob("*.mldsa87.sig"):
        p.unlink()


def test_manifest_dual_signed(pkg):
    _, out_dir, _, _ = pkg
    sig = out_dir / "manifest.json.mldsa87.sig"
    assert sig.exists(), "manifest PQ dual signature missing"  # nosec: B101
    assert len(sig.read_bytes()) == 4627, "ML-DSA-87 sig must be 4627 bytes"  # nosec: B101


def test_roles_dual_signed(pkg):
    _, _, _, roles_dir = pkg
    for r in ROLES:
        sig = roles_dir / f"{r}.json.mldsa87.sig"
        assert sig.exists(), f"missing PQ dual signature: {sig.name}"  # nosec: B101
        assert len(sig.read_bytes()) == 4627  # nosec: B101


def test_root_publishes_pq_key(pkg):
    _, _, _, roles_dir = pkg
    root = json.loads((roles_dir / "root.json").read_text(encoding="utf-8"))
    kinds = {(k.get("keytype"), k.get("scheme")) for k in root["keys"].values()}
    assert ("mldsa87", "mldsa87") in kinds, "root.json must publish the PQ key"  # nosec: B101
    assert ("ed25519", "ed25519") in kinds, "root.json must keep the Ed25519 key"  # nosec: B101


def test_dual_signed_bundle_verifies_and_applies(pkg):
    tuf, out_dir, dest_dir, roles_dir = pkg
    ok, msg = tuf.verify_update_package(str(out_dir))
    assert ok, f"dual-signed manifest bundle must verify: {msg}"  # nosec: B101
    ok, msg = tuf.verify_role_metadata(str(roles_dir))
    assert ok, f"dual-signed role bundle must verify: {msg}"  # nosec: B101
    assert tuf.apply_update(str(out_dir), str(dest_dir)) is True  # nosec: B101
    assert (dest_dir / "core_update.py").exists()  # nosec: B101


def test_tampered_pq_sig_rejected_even_in_lab(pkg):
    tuf, out_dir, _, roles_dir = pkg
    for target in (out_dir / "manifest.json.mldsa87.sig",
                   roles_dir / "targets.json.mldsa87.sig"):
        raw = bytearray(target.read_bytes())
        raw[0] ^= 0x01
        target.write_bytes(bytes(raw))
    ok, msg = tuf.verify_update_package(str(out_dir))
    assert not ok, "tampered manifest PQ signature must reject"  # nosec: B101
    assert "ML-DSA-87" in msg  # nosec: B101
    ok, msg = tuf.verify_role_metadata(str(roles_dir))
    assert not ok, "tampered role PQ signature must reject"  # nosec: B101
    assert "ML-DSA-87" in msg  # nosec: B101


def test_missing_pq_sig_lab_accepts_strict_rejects(pkg, monkeypatch):
    tuf, out_dir, _, roles_dir = pkg
    _strip_pq(out_dir)
    _strip_pq(roles_dir)
    monkeypatch.delenv("P2P_REQUIRE_PQ_CODE_SIG", raising=False)
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    ok, _ = tuf.verify_update_package(str(out_dir))
    assert ok, "lab must accept Ed25519-only manifest during migration"  # nosec: B101
    ok, _ = tuf.verify_role_metadata(str(roles_dir))
    assert ok, "lab must accept Ed25519-only roles during migration"  # nosec: B101
    monkeypatch.setenv("P2P_REQUIRE_PQ_CODE_SIG", "1")
    ok, msg = tuf.verify_update_package(str(out_dir))
    assert not ok, "strict mode must reject PQ-unsigned manifest"  # nosec: B101
    assert "ML-DSA-87" in msg  # nosec: B101
    ok, msg = tuf.verify_role_metadata(str(roles_dir))
    assert not ok, "strict mode must reject PQ-unsigned roles"  # nosec: B101
    assert "ML-DSA-87" in msg  # nosec: B101


def test_wrong_passphrase_cannot_unseal_pq_key(pkg):
    tuf, _, _, _ = pkg
    blob = tuf._pq_sk_path.read_bytes()
    with pytest.raises(CodeSigningError):
        tuf._pq_unseal(blob, b"wrong-ceremony-secret")
    sk = tuf._pq_unseal(blob, os.environ["P2P_SIGNING_PASSPHRASE"].encode())
    assert len(sk) == 4896  # nosec: B101

