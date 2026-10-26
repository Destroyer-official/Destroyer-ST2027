#!/usr/bin/env python3
"""Build a clean TOP SECRET deployment tree.

Includes only the CNSA-strict session path plus its native providers,
runbooks, and policy docs. Excludes the quarantined legacy monoliths,
databases, logs, caches, and virtualenvs so operators cannot deploy the
unhardened prototype by accident. Emits manifest.json with SHA-384 per
file. Fail-closed on any missing required file or hash mismatch.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED = [
    "production_gate.py",
    "secure_transmit_2027.py",
    "noise_pq.py",
    "crypto_selftest.py",
    "ts_hw_layer.py",
    "ts_runtime.py",
    "ts_attest.py",
    "cng_platform.py",
    "spo_dpo.py",
    "trust_anchor.py",
    "transport_anonymity.py",
    "cnsa_purity.py",
    "liboqs_wrapper.py",
    "dependency_security_verifier.py",
    "hw_readiness.py",
    "oqs.dll",
    "oqs.dll.sig",
    "libsodium.dll",
]

OPTIONAL = [
    "ts_rt/target/release/ts_rt.dll",
    "scripts/setup_tor_overlay.sh",
    "scripts/setup_wireguard.sh",
    "scripts/witnessed_key_ceremony.py",
    "docs/KEY_CEREMONY.md",
    "docs/FIREWALL_IPV6.md",
    "config_production.json",
]

EXCLUDE_NAMES = {
    "secure_p2.py",
    "secure_p2p.py",
    "secure_p2p_audit.db",
}
EXCLUDE_SUFFIXES = (".db", ".db-shm", ".db-wal", ".log", ".pyc")
EXCLUDE_DIRS = {"__pycache__", ".venv", ".git", "archive", "logs", "notupload",
                "downloads", "scratch", ".hypothesis", ".pytest_cache"}


def _sha384(path: Path) -> str:
    h = hashlib.sha384()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_dest(dest: Path) -> Path:
    """Resolve the destination and refuse anything outside a safe root.

    The destination is deleted recursively, so an operator typo (or a
    hostile argument) must never be able to remove a system directory.
    """
    dest = Path(dest).expanduser()
    try:
        resolved = dest.resolve()
    except OSError:
        raise SystemExit(f"DEPLOY-FAIL: destination not resolvable: {dest}")
    repo = REPO_ROOT.resolve()
    safe_roots = []
    for root in (repo / "out", repo / "deploy_st2027", repo / "build",
                 Path(tempfile.gettempdir()) / "st2027_deploy"):
        try:
            safe_roots.append(root.resolve())
        except OSError:
            continue
    # The repository root itself is a permitted target only for the
    # in-place build mode, and only when it is exactly the repo root.
    if resolved == repo:
        return resolved
    for root in safe_roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise SystemExit(
        f"DEPLOY-FAIL: destination {resolved} is outside the permitted "
        f"deployment roots ({', '.join(str(r) for r in safe_roots)})")


def _safe_rel(dest: Path, rel: str) -> Path:
    """Resolve a manifest entry and refuse traversal outside dest."""
    if not rel or rel.startswith(("/", "\\")) or ":" in rel:
        raise SystemExit(f"DEPLOY-FAIL: unsafe manifest path: {rel!r}")
    parts = Path(rel).parts
    if ".." in parts:
        raise SystemExit(f"DEPLOY-FAIL: traversal in manifest path: {rel!r}")
    candidate = (Path(dest) / rel).resolve()
    try:
        candidate.relative_to(Path(dest).resolve())
    except ValueError:
        raise SystemExit(f"DEPLOY-FAIL: manifest path escapes destination: {rel!r}")
    return candidate


def build_deployment(dest: Path) -> Path:
    dest = _safe_dest(dest)
    if dest.exists() and dest != REPO_ROOT.resolve():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    manifest = {"files": {}, "policy_basis": "CNSA 2.0 strict session path"}
    for name in REQUIRED:
        src = REPO_ROOT / name
        if not src.is_file():
            raise SystemExit(f"DEPLOY-FAIL: required file missing: {name}")
        out = dest / name
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)
        manifest["files"][name] = {"sha384": _sha384(out),
                                   "bytes": out.stat().st_size}
    for name in OPTIONAL:
        src = REPO_ROOT / name
        if src.is_file():
            out = dest / name
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, out)
            manifest["files"][name] = {"sha384": _sha384(out),
                                       "bytes": out.stat().st_size}
    # Refuse to carry quarantined or state artifacts even by accident.
    for rel in manifest["files"]:
        base = Path(rel).name
        if base in EXCLUDE_NAMES or base.endswith(EXCLUDE_SUFFIXES):
            raise SystemExit(f"DEPLOY-FAIL: excluded artifact listed: {rel}")
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2,
                                                   sort_keys=True),
                                        encoding="utf-8")
    return dest


def verify_deployment(dest: Path) -> bool:
    dest = Path(dest)
    manifest = json.loads((Path(dest) / "manifest.json").read_text(
        encoding="utf-8"))
    for rel, meta in manifest["files"].items():
        target = _safe_rel(dest, rel)
        data = target.read_bytes()
        if hashlib.sha384(data).hexdigest() != meta["sha384"]:
            raise SystemExit(f"DEPLOY-FAIL: hash mismatch: {rel}")
        if Path(rel).name in EXCLUDE_NAMES:
            raise SystemExit(f"DEPLOY-FAIL: quarantined file shipped: {rel}")
    return True


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "deploy_st2027"
    out = build_deployment(target)
    verify_deployment(out)
    print(f"deployment ready: {out} ({len(list(out.rglob('*')))} entries)")
