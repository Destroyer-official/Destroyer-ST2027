#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""SP 800-208 stateful artifact-signing hook — behavioral proofs.

Covers, against the REAL module (no mocks of the signing logic):

  1. P2P_ENABLE_EXPERIMENTAL gate blocks sign AND verify.
  2. LMS round trip: detached signature + public-key sibling, durable
     one-time-key state advance, journal floor entry with the artifact
     digest (SP 800-208 Sec. 9.1 ordering: state durable before export).
  3. XMSS round trip.
  4. Tampered artifact / tampered signature fail verification.
  5. State-file rollback refused by the journal floor.
  6. FULL state+journal rollback (F-01 residual class) refused ONLY by the
     TPM NV seal, driven against fake tpm2-tools emitting authentic
     RC 0x18B / 0x14A responses.
  7. P2P_STATEFUL_NV_INDEX equal to the data-plane P2P_TPM_NV_INDEX is
     refused (separate NV domains).
  8. Lost state with public key/journal present requires explicit
     P2P_STATEFUL_REPROVISION=1; old signatures still verify against the
     retired public key.
  9. Key exhaustion fails closed BEFORE any signature file is released.
 10. Public-key substitution (key dir and artifact sibling) refused
     before release.
 11. Corrupt journal refused.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from pqc_algorithms import read_stateful_key, write_stateful_key
import stateful_artifact_signing as sas

FAKE_NV_PY = '''\
"""File-backed fake tpm2-tools for the SP 800-208 NV seal tests."""
import os
import sys
from pathlib import Path


def main() -> int:
    tool = sys.argv[1]
    d = Path(os.environ["FAKE_NV_DIR"])
    d.mkdir(parents=True, exist_ok=True)
    defined = d / "defined.flag"
    store = d / "seal.bin"

    if tool == "nvread":
        if not defined.exists():
            sys.stderr.write(
                "ERROR: tpm:handle(1):the handle is not correct for the use "
                "(0x18B)\\n")
            return 1
        if not store.exists():
            sys.stderr.write(
                "ERROR: tpm: an NV Index is used before being initialized "
                "(0x0000014a)\\n")
            return 1
        print(store.read_bytes().hex())
        return 0
    if tool == "nvwrite":
        if not defined.exists():
            sys.stderr.write(
                "ERROR: tpm:handle(1):the handle is not correct for the use "
                "(0x18B)\\n")
            return 1
        data = Path(sys.argv[sys.argv.index("-f") + 1]).read_bytes()
        if len(data) != 32:
            sys.stderr.write("ERROR: wrong seal size\\n")
            return 1
        store.write_bytes(data)
        return 0
    if tool == "nvdefine":
        if defined.exists():
            sys.stderr.write("ERROR: NV index already defined\\n")
            return 1
        defined.write_text("1", encoding="ascii")
        return 0
    sys.stderr.write(f"fake_tpm2: unknown tool {tool}\\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _setup(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("P2P_ENABLE_EXPERIMENTAL", "1")
    for name in ("P2P_STATEFUL_REPROVISION", "P2P_STATEFUL_NV_INDEX",
                 "P2P_TPM_NV_INDEX", "P2P_STATEFUL_KEY_DIR",
                 "P2P_TPM2_NVREAD", "P2P_TPM2_NVWRITE", "P2P_TPM2_NVDEFINE"):
        monkeypatch.delenv(name, raising=False)
    key_dir = tmp_path / "stateful-keys"
    artifact = tmp_path / "release-manifest.bin"
    artifact.write_bytes(b"DESTROYER-ST2027 SP 800-208 stateful signing "
                         b"test payload v1")
    return key_dir, artifact


def _install_fake_nv(monkeypatch, tmp_path: Path,
                     index: str = "0x1500018") -> None:
    wd = tmp_path / "fake-tpm2"
    wd.mkdir(parents=True, exist_ok=True)
    script = wd / "fake_tpm2.py"
    script.write_text(FAKE_NV_PY, encoding="utf-8")
    for tool in ("nvread", "nvwrite", "nvdefine"):
        if os.name == "nt":
            wrapper = wd / f"fake_{tool}.cmd"
            wrapper.write_text(
                f'@"{sys.executable}" "{script}" {tool} %*\r\n',
                encoding="utf-8")
        else:
            wrapper = wd / f"fake_{tool}"
            wrapper.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "{script}" {tool} "$@"\n',
                encoding="utf-8")
            wrapper.chmod(0o700)
        monkeypatch.setenv(f"P2P_TPM2_{tool.upper()}", str(wrapper))
    monkeypatch.setenv("FAKE_NV_DIR", str(wd / "nv"))
    monkeypatch.setenv("P2P_STATEFUL_NV_INDEX", index)


def test_gate_blocks_sign_and_verify_without_experimental(
        monkeypatch, tmp_path: Path):
    monkeypatch.delenv("P2P_ENABLE_EXPERIMENTAL", raising=False)
    key_dir, artifact = _setup(monkeypatch, tmp_path)
    monkeypatch.delenv("P2P_ENABLE_EXPERIMENTAL", raising=False)
    with pytest.raises(PermissionError, match="P2P_ENABLE_EXPERIMENTAL"):
        sas.sign_artifact(artifact, key_dir=key_dir)
    with pytest.raises(PermissionError, match="P2P_ENABLE_EXPERIMENTAL"):
        sas.verify_artifact(artifact, key_dir=key_dir)
    assert not key_dir.exists()


def test_lms_roundtrip_durable_advance_and_journal(
        monkeypatch, tmp_path: Path):
    key_dir, artifact = _setup(monkeypatch, tmp_path)
    out = sas.sign_artifact(artifact, alg="lms", key_dir=key_dir)
    sig_path = Path(str(artifact) + ".lms208.sig")
    pub_sibling = Path(str(artifact) + ".lms208.pub")
    assert sig_path.exists()
    assert pub_sibling.exists()
    assert out["index"] == 0
    assert out["signatures_remaining"] == 32767
    assert out["artifact_sha256"] == hashlib.sha256(
        artifact.read_bytes()).hexdigest()

    obj = sas._alg_obj("lms")
    sk = read_stateful_key(str(key_dir / "lms.stateful.key"))
    assert sas._state_index(obj, "lms", sk) == 1

    journal = (key_dir / "lms.stateful.journal").read_text(
        encoding="utf-8").strip().splitlines()
    assert len(journal) == 1
    entry = json.loads(journal[0])
    assert entry["i"] == 0
    assert entry["alg"] == "lms"
    assert entry["sha256"] == out["artifact_sha256"]
    assert entry["sig_sha256"] == hashlib.sha256(
        sig_path.read_bytes()).hexdigest()

    assert sas.verify_artifact(artifact, alg="lms", key_dir=key_dir) is True


def test_xmss_roundtrip(monkeypatch, tmp_path: Path):
    key_dir, artifact = _setup(monkeypatch, tmp_path)
    out = sas.sign_artifact(artifact, alg="xmss", key_dir=key_dir)
    assert Path(str(artifact) + ".xmss208.sig").exists()
    assert out["index"] == 0
    assert sas.verify_artifact(artifact, alg="xmss", key_dir=key_dir) is True


def test_tampered_artifact_and_signature_fail_verify(
        monkeypatch, tmp_path: Path):
    key_dir, artifact = _setup(monkeypatch, tmp_path)
    sas.sign_artifact(artifact, key_dir=key_dir)
    original = artifact.read_bytes()
    blob = bytearray(original)
    blob[3] ^= 0x01
    artifact.write_bytes(bytes(blob))
    assert sas.verify_artifact(artifact, key_dir=key_dir) is False
    artifact.write_bytes(original)
    assert sas.verify_artifact(artifact, key_dir=key_dir) is True

    sig_path = Path(str(artifact) + ".lms208.sig")
    sig = bytearray(sig_path.read_bytes())
    sig[-1] ^= 0x01
    sig_path.write_bytes(bytes(sig))
    assert sas.verify_artifact(artifact, key_dir=key_dir) is False


def test_state_file_rollback_refused_by_journal_floor(
        monkeypatch, tmp_path: Path):
    key_dir, artifact_a = _setup(monkeypatch, tmp_path)
    artifact_b = tmp_path / "second-manifest.bin"
    artifact_b.write_bytes(b"second artifact")
    artifact_c = tmp_path / "third-manifest.bin"
    artifact_c.write_bytes(b"third artifact")

    sas.sign_artifact(artifact_a, key_dir=key_dir)
    state_path = key_dir / "lms.stateful.key"
    state_after_first = state_path.read_bytes()
    sas.sign_artifact(artifact_b, key_dir=key_dir)

    state_path.write_bytes(state_after_first)
    with pytest.raises(sas.StateRollbackError, match="rollback"):
        sas.sign_artifact(artifact_c, key_dir=key_dir)
    assert not Path(str(artifact_c) + ".lms208.sig").exists()


def test_full_store_rollback_caught_by_nv_seal(
        monkeypatch, tmp_path: Path):
    key_dir, artifact_a = _setup(monkeypatch, tmp_path)
    _install_fake_nv(monkeypatch, tmp_path)
    artifact_b = tmp_path / "manifest-b.bin"
    artifact_b.write_bytes(b"artifact b")
    artifact_c = tmp_path / "manifest-c.bin"
    artifact_c.write_bytes(b"artifact c")

    out_a = sas.sign_artifact(artifact_a, key_dir=key_dir)
    assert out_a["nv_seal"] is not None
    state_path = key_dir / "lms.stateful.key"
    journal_path = key_dir / "lms.stateful.journal"
    state_after_first = state_path.read_bytes()
    journal_after_first = journal_path.read_bytes()

    out_b = sas.sign_artifact(artifact_b, key_dir=key_dir)
    assert out_b["index"] == 1
    assert out_b["nv_seal"] is not None
    assert sas.verify_artifact(artifact_b, key_dir=key_dir) is True

    state_path.write_bytes(state_after_first)
    journal_path.write_bytes(journal_after_first)

    with pytest.raises(sas.StateRollbackError, match="NV seal"):
        sas.sign_artifact(artifact_c, key_dir=key_dir)
    assert not Path(str(artifact_c) + ".lms208.sig").exists()


def test_nv_index_must_be_distinct_from_data_plane_guard(
        monkeypatch, tmp_path: Path):
    key_dir, artifact = _setup(monkeypatch, tmp_path)
    _install_fake_nv(monkeypatch, tmp_path, index="0x1500016")
    monkeypatch.setenv("P2P_TPM_NV_INDEX", "0x1500016")
    with pytest.raises(sas.StatefulSigningError, match="DISTINCT"):
        sas.sign_artifact(artifact, key_dir=key_dir)
    assert not Path(str(artifact) + ".lms208.sig").exists()


def test_lost_state_requires_explicit_reprovision_and_old_sigs_stay_valid(
        monkeypatch, tmp_path: Path):
    key_dir, artifact_old = _setup(monkeypatch, tmp_path)
    sas.sign_artifact(artifact_old, key_dir=key_dir)
    (key_dir / "lms.stateful.key").unlink()

    artifact_new = tmp_path / "post-rotation.bin"
    artifact_new.write_bytes(b"post rotation artifact")
    with pytest.raises(sas.StatefulSigningError, match="REPROVISION"):
        sas.sign_artifact(artifact_new, key_dir=key_dir)

    monkeypatch.setenv("P2P_STATEFUL_REPROVISION", "1")
    out = sas.sign_artifact(artifact_new, key_dir=key_dir)
    assert out["index"] == 0
    assert sas.verify_artifact(artifact_new, key_dir=key_dir) is True
    assert sas.verify_artifact(artifact_old, key_dir=key_dir) is True
    retired = list((key_dir / "retired").glob("*/lms.stateful.pub"))
    assert len(retired) == 1
    assert retired[0].read_bytes() == Path(
        str(artifact_old) + ".lms208.pub").read_bytes()


def test_exhaustion_fails_closed_before_signature_release(
        monkeypatch, tmp_path: Path):
    key_dir, artifact = _setup(monkeypatch, tmp_path)
    obj = sas._alg_obj("lms")
    pk, sk = obj.keygen()
    hdr = sas._sk_header(obj, "lms")
    q_off = len(hdr) + 16
    sk = (sk[:q_off] + (32767).to_bytes(4, byteorder="big") +
          sk[q_off + 4:])
    key_dir.mkdir(parents=True)
    write_stateful_key(str(key_dir / "lms.stateful.key"), sk)
    (key_dir / "lms.stateful.pub").write_bytes(pk)
    (key_dir / "lms.stateful.journal").write_bytes(b"")

    with pytest.raises(ValueError, match="exhausted"):
        sas.sign_artifact(artifact, key_dir=key_dir)
    assert not Path(str(artifact) + ".lms208.sig").exists()
    sk_after = read_stateful_key(str(key_dir / "lms.stateful.key"))
    assert sas._state_index(obj, "lms", sk_after) == 32767


def test_key_substitution_refused_before_release(
        monkeypatch, tmp_path: Path):
    key_dir, artifact_a = _setup(monkeypatch, tmp_path)
    artifact_b = tmp_path / "substitution-target.bin"
    artifact_b.write_bytes(b"target")
    sas.sign_artifact(artifact_a, key_dir=key_dir)

    (key_dir / "lms.stateful.pub").write_bytes(b"foreign-public-key")
    with pytest.raises(sas.KeySubstitutionError):
        sas.sign_artifact(artifact_b, key_dir=key_dir)
    assert not Path(str(artifact_b) + ".lms208.sig").exists()

    artifact_c = tmp_path / "sibling-substitution.bin"
    artifact_c.write_bytes(b"sibling substitution target")
    fresh_keys = tmp_path / "fresh-keys"
    sibling = Path(str(artifact_c) + ".lms208.pub")
    sibling.write_bytes(b"stale-sibling-key")
    with pytest.raises(sas.KeySubstitutionError):
        sas.sign_artifact(artifact_c, key_dir=fresh_keys)
    assert not Path(str(artifact_c) + ".lms208.sig").exists()


def test_corrupt_journal_refused(monkeypatch, tmp_path: Path):
    key_dir, artifact = _setup(monkeypatch, tmp_path)
    sas.sign_artifact(artifact, key_dir=key_dir)
    with (key_dir / "lms.stateful.journal").open("a", encoding="utf-8") as f:
        f.write("not-json-garbage\n")
    other = tmp_path / "after-corruption.bin"
    other.write_bytes(b"payload")
    with pytest.raises(sas.StatefulSigningError, match="corrupt"):
        sas.sign_artifact(other, key_dir=key_dir)
    assert not Path(str(other) + ".lms208.sig").exists()


def test_cli_sign_and_verify_roundtrip(monkeypatch, tmp_path: Path,
                                       capsys):
    key_dir, artifact = _setup(monkeypatch, tmp_path)
    rc = sas.main(["sign", str(artifact), "--key-dir", str(key_dir)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["alg"] == "lms"
    rc = sas.main(["verify", str(artifact), "--key-dir", str(key_dir)])
    assert rc == 0
    assert "[OK]" in capsys.readouterr().out
