#!/usr/bin/env python3
"""Pinned trust anchor and custody policy for signed compliance/audit reports.

Self-anchored verification (trusting the ``.pub`` file shipped next to a
report) is forgeable: an attacker generates a keypair, signs a fake report,
and publishes the matching public key. Every report verifier must instead
check against a provisioned anchor. The default anchor is the persistent
``keys/audit_signer.mldsa87.pk`` keypair used by ``scripts/run_defense_audit.py``.

Production fails closed when the anchor is absent, when the signer key is not
under restrictive custody, or when a repository-local drill key is used without
an explicit deployment override. Labs may use local keys with a loud warning so
legacy drills keep working.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from utils.helpers import is_env_true

REPO_ROOT = Path(__file__).resolve().parent
log = logging.getLogger("report_trust")

_SK_NAME = "audit_signer.mldsa87.sk"
_PK_NAME = "audit_signer.mldsa87.pk"
_SK_LEN = 4896
_PK_LEN = 2592
_PROBE = b"st2027-audit-signer-keypair-probe"


def is_production() -> bool:
    from production_gate import is_production as _canonical_production
    return _canonical_production()


def audit_signer_paths() -> tuple[Path, Path]:
    key_dir = Path(os.environ.get("P2P_AUDIT_SIGNER_KEY_DIR", REPO_ROOT / "keys"))
    return (key_dir / _PK_NAME, key_dir / _SK_NAME)


def _within_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO_ROOT)
        return True
    except ValueError:
        return False


def _current_windows_principal() -> str | None:
    user = os.environ.get("USERNAME")
    if not user:
        return None
    domain = os.environ.get("USERDOMAIN")
    return f"{domain}\\{user}" if domain else user


def _icacls(path: Path, *args: str) -> bool:
    try:
        proc = subprocess.run(  # nosec: B603 B607 - fixed argv, no shell
            ["icacls.exe", str(path), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return proc.returncode == 0
    except Exception as exc:
        log.debug("icacls unavailable for %s: %s", path, exc)
        return False


def _harden_windows_acl(path: Path, *, directory: bool) -> bool:
    user = _current_windows_principal()
    if not user:
        return False
    inherit = ":(OI)(CI)F" if directory else ":F"
    ok = _icacls(
        path,
        "/inheritance:r",
        "/grant:r",
        f"{user}{inherit}",
        "/grant:r",
        f"SYSTEM{inherit}",
    )
    if not ok:
        return False
    proc = subprocess.run(  # nosec: B603 B607 - fixed argv, no shell
        ["icacls.exe", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if proc.returncode != 0:
        return False
    acl = proc.stdout.casefold()
    forbidden = (
        "everyone:",
        "builtin\\users:",
        "nt authority\\authenticated users:",
        "authenticated users:",
    )
    return not any(marker in acl for marker in forbidden)


def _harden_permissions(path: Path, *, directory: bool = False) -> bool:
    """Apply owner-only permissions; return True when hardening succeeded."""
    try:
        if os.name == "nt":
            return _harden_windows_acl(path, directory=directory)
        os.chmod(path, 0o700 if directory else 0o600)
        return True
    except Exception as exc:
        log.debug("permission hardening failed for %s: %s", path, exc)
        return False


def _assert_no_link(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"audit signer path is a symlink: {path} (fail-closed)")
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if st.st_nlink != 1:
        raise RuntimeError(
            f"audit signer path has {st.st_nlink} hard links: {path} (fail-closed)"
        )


def _assert_posix_custody(path: Path, *, directory: bool = False) -> None:
    st = path.stat()
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise RuntimeError(f"audit signer path is not owned by this user: {path}")
    forbidden = stat.S_IRWXG | stat.S_IRWXO
    if stat.S_IMODE(st.st_mode) & forbidden:
        raise RuntimeError(
            f"audit signer path grants group/other access: {path} "
            f"(mode {oct(stat.S_IMODE(st.st_mode))})"
        )


def _verify_private_custody(path: Path, *, directory: bool = False) -> None:
    _assert_no_link(path)
    if os.name != "nt":
        _assert_posix_custody(path, directory=directory)
        return
    if not _harden_windows_acl(path, directory=directory):
        if is_production():
            raise RuntimeError(
                f"audit signer ACL could not be verified/restricted: {path} "
                "(fail-closed)"
            )
        log.warning("audit signer ACL hardening/verification failed for %s (lab)", path)


def _prepare_key_dir(key_dir: Path) -> None:
    _assert_no_link(key_dir)
    key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    _assert_no_link(key_dir)
    if not _harden_permissions(key_dir, directory=True) and is_production():
        raise RuntimeError(
            f"audit signer key directory could not be restricted: {key_dir} "
            "(fail-closed)"
        )
    _verify_private_custody(key_dir, directory=True)
    if is_production() and _within_repo(key_dir):
        if not is_env_true("P2P_AUDIT_SIGNER_ALLOW_REPO_KEY_DIR"):
            raise RuntimeError(
                "audit signer key directory is inside the source repository; "
                "provision P2P_AUDIT_SIGNER_KEY_DIR outside the repo "
                "(set P2P_AUDIT_SIGNER_ALLOW_REPO_KEY_DIR=1 only for a "
                "documented drill) (fail-closed)"
            )


def _atomic_write(path: Path, data: bytes, *, secret: bool) -> None:
    """Write a key file atomically without following pre-existing links."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(str(tmp), flags, 0o600 if secret else 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if secret:
        _harden_permissions(path)
        _verify_private_custody(path)


def _repair_secret_key(path: Path, sk: bytes) -> bytes:
    repaired = sk.replace(b"\r\n", b"\n")
    if len(repaired) != _SK_LEN:
        raise RuntimeError(
            "audit signer secret key is malformed; restore from backup"
        )
    _verify_private_custody(path)
    _atomic_write(path, repaired, secret=True)
    return repaired


def load_or_create_audit_signer() -> tuple[bytes, bytes]:
    """Return the persistent audit signer keypair; bootstrap only outside prod."""
    from liboqs_wrapper import LibOQS_MLDSA_87

    pk_path, sk_path = audit_signer_paths()
    _prepare_key_dir(sk_path.parent)
    if sk_path.exists() != pk_path.exists():
        raise RuntimeError(
            "audit signer keypair is half-present; refusing to rotate (fail-closed)"
        )
    signer = LibOQS_MLDSA_87()
    if sk_path.exists():
        _verify_private_custody(sk_path)
        pk = pk_path.read_bytes()
        sk = sk_path.read_bytes()
        if len(pk) != _PK_LEN:
            raise RuntimeError("audit signer public key is malformed (fail-closed)")
        if len(sk) != _SK_LEN:
            sk = _repair_secret_key(sk_path, sk)
        probe = _PROBE
        if not signer.verify(pk, probe, signer.sign(sk, probe)):
            raise RuntimeError("audit signer keypair failed its probe (fail-closed)")
        return pk, sk
    if is_production():
        raise RuntimeError(
            "audit signer key is not provisioned; refusing an ephemeral report "
            "signing key in production (fail-closed)"
        )
    pk, sk = signer.keygen()
    _atomic_write(sk_path, sk, secret=True)
    _atomic_write(pk_path, pk, secret=False)
    log.warning("Bootstrapped audit signer key at %s (lab/drill only)", sk_path)
    return pk, sk


def audit_signer_fingerprint(pk: bytes) -> str:
    """Stable SHA3-256 identity for a report signer public key."""
    return hashlib.sha3_256(pk).hexdigest()


def rotate_audit_signer(*, confirm: bool = False) -> tuple[bytes, bytes]:
    """Retire the current signer and provision a new one under dual control.

    Rotation is intentionally not automatic. It requires ``confirm=True``,
    production approval when production mode is active, and two distinct named
    approvers. Retired keys are preserved under ``retired/`` with 0600 custody
    so existing signed reports can still be audited. Deployments must re-sign
    artifacts and redistribute the new pinned anchor after rotation.
    """
    if not confirm:
        raise RuntimeError("audit signer rotation requires explicit confirmation")
    approver1 = os.environ.get("P2P_AUDIT_ROTATION_APPROVER_1", "").strip()
    approver2 = os.environ.get("P2P_AUDIT_ROTATION_APPROVER_2", "").strip()
    if not approver1 or not approver2 or approver1 == approver2:
        raise RuntimeError(
            "audit signer rotation requires two distinct approvers "
            "(P2P_AUDIT_ROTATION_APPROVER_1/_2)"
        )
    if is_production() and not is_env_true("P2P_AUDIT_SIGNER_ROTATION_APPROVED"):
        raise RuntimeError(
            "audit signer rotation is not approved in production (fail-closed)"
        )

    from liboqs_wrapper import LibOQS_MLDSA_87

    pk_path, sk_path = audit_signer_paths()
    _prepare_key_dir(sk_path.parent)
    if not (pk_path.exists() and sk_path.exists()):
        raise RuntimeError("cannot rotate: audit signer keypair is not complete")
    _verify_private_custody(sk_path)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    retired = sk_path.parent / "retired"
    retired.mkdir(mode=0o700, exist_ok=True)
    _harden_permissions(retired, directory=True)
    for src, suffix in ((sk_path, ".sk"), (pk_path, ".pk")):
        dst = retired / f"audit_signer.{stamp}{suffix}"
        os.replace(src, dst)
        _harden_permissions(dst)
        _verify_private_custody(dst)

    signer = LibOQS_MLDSA_87()
    new_pk, new_sk = signer.keygen()
    _atomic_write(sk_path, new_sk, secret=True)
    _atomic_write(pk_path, new_pk, secret=False)
    log.critical(
        "AUDIT SIGNER ROTATED by %s and %s; redistribute the new pinned anchor "
        "and re-sign compliance artifacts",
        approver1,
        approver2,
    )
    return new_pk, new_sk


def verify_with_anchor(
    report_path: Path,
    sig_path: Path,
    pub_path: Path,
    verifier,
    anchor_path: Path | None = None,
) -> bool:
    """Verify a report against the pinned anchor (never its own ``.pub``)."""
    import hmac as _hmac

    report_path, sig_path, pub_path = Path(report_path), Path(sig_path), Path(pub_path)
    if not (report_path.exists() and sig_path.exists()):
        return False
    data = report_path.read_bytes()
    sig = sig_path.read_bytes()

    if anchor_path is None:
        anchor_path, _ = audit_signer_paths()
    anchor_path = Path(anchor_path)
    if anchor_path.exists():
        _assert_no_link(anchor_path)
        pk = anchor_path.read_bytes()
        if pub_path.exists() and not _hmac.compare_digest(pub_path.read_bytes(), pk):
            log.error("report embedded public key does not match the trust anchor")
            return False
    else:
        if is_production():
            log.error("report trust anchor missing in production (fail-closed)")
            return False
        if not pub_path.exists():
            return False
        log.warning(
            "report verified against an UNPINNED embedded public key (lab "
            "fallback); provision %s for trustworthy verification",
            anchor_path,
        )
        pk = pub_path.read_bytes()

    return bool(verifier.verify(pk, data, sig))


if __name__ == "__main__":  # pragma: no cover - operator utility
    pk_path, sk_path = audit_signer_paths()
    if len(sys.argv) > 1 and sys.argv[1] == "fingerprint":
        pk, _ = load_or_create_audit_signer()
        print(audit_signer_fingerprint(pk))
    else:
        print(f"public:  {pk_path}")
        print(f"secret:  {sk_path}")
        print(f"owner:   {'restricted' if sk_path.exists() else 'not provisioned'}")
