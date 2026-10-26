#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""
stateful_artifact_signing.py
NIST SP 800-208 stateful hash-based artifact signing hook (LMS / XMSS).

Complements the primary ML-DSA-87 (FIPS 204) release signatures with a
stateful hash-based signature for artifacts where software/firmware signing
guidance calls for one (NSA CNSA 2.0 direction: LMS/XMSS — not the
multi-tree HSS/XMSSMT variants).

SP 800-208 Sec. 9.1 obligations implemented by this hook:
  * the private-key state is advanced and made DURABLE (fsync + atomic
    replace) BEFORE the signature file is exported — a crash can burn one
    one-time key but can never release a signature whose state update was
    still only in the filesystem cache;
  * one-time key reuse is refused across processes via the append-only
    journal floor, and — when P2P_STATEFUL_NV_INDEX is set — across FULL
    file-store rollbacks via a TPM NV seal of the journal tail (the
    F-01 residual class: restoring state + journal + sidecars together);
  * exhaustion, corruption, key substitution and seal mismatches all fail
    closed before any signature bytes leave this process.

Honesty notes (never upgrade these claims):
  * Enabled only with P2P_ENABLE_EXPERIMENTAL=1. The underlying
    EnhancedLMS / EnhancedXMSS implementations in pqc_algorithms are
    custom, unaudited Python and are NOT RFC 8554 / RFC 8391
    byte-interoperable; signatures verify only inside this repository.
  * Not FIPS-validated, not CMVP-certified, no laboratory claim.
  * This hook adds a SECONDARY signature; it never replaces the primary
    .mldsa87.sig release signatures.
  * Without P2P_STATEFUL_NV_INDEX the rollback floor protects the local
    journal only; use a TPM NV index (distinct from the data plane's
    P2P_TPM_NV_INDEX guard) to anchor against whole-store restores.

Environment:
  P2P_ENABLE_EXPERIMENTAL=1      required gate (see pqc_algorithms)
  P2P_STATEFUL_KEY_DIR=DIR       key/state/journal directory
                                 (default: ./stateful_keys)
  P2P_STATEFUL_NV_INDEX=0x.....  optional TPM NV seal index
  P2P_TPM2_NVREAD/NVWRITE/NVDEFINE   optional tool path overrides
  P2P_STATEFUL_REPROVISION=1     explicit operator re-key (archives old
                                 material under <key_dir>/retired/)

Usage:
    python stateful_artifact_signing.py sign   FILE [--alg lms|xmss] [--key-dir DIR]
    python stateful_artifact_signing.py verify FILE [--alg lms|xmss] [--key-dir DIR]
    python stateful_artifact_signing.py keygen [--alg lms|xmss] [--key-dir DIR]
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pqc_algorithms import (
    EnhancedLMS,
    EnhancedXMSS,
    read_stateful_key,
    write_stateful_key,
)

logger = logging.getLogger("StatefulArtifactSigning")

STATEFUL_EXPERIMENTAL_ENV = "P2P_ENABLE_EXPERIMENTAL"
KEY_DIR_ENV = "P2P_STATEFUL_KEY_DIR"
REPROVISION_ENV = "P2P_STATEFUL_REPROVISION"
NV_INDEX_ENV = "P2P_STATEFUL_NV_INDEX"
NV_OWNER_ENV = "P2P_STATEFUL_NV_OWNER"
DATA_PLANE_NV_INDEX_ENV = "P2P_TPM_NV_INDEX"
NV_READ_TOOL_ENV = "P2P_TPM2_NVREAD"
NV_WRITE_TOOL_ENV = "P2P_TPM2_NVWRITE"
NV_DEFINE_TOOL_ENV = "P2P_TPM2_NVDEFINE"

_ALGS = {"lms": EnhancedLMS, "xmss": EnhancedXMSS}
_SUFFIX = {"lms": ".lms208", "xmss": ".xmss208"}


class StatefulSigningError(RuntimeError):
    """Base fail-closed error for the SP 800-208 artifact hook."""


class StateRollbackError(StatefulSigningError):
    """One-time key state appears rolled back; signing is refused."""


class KeySubstitutionError(StatefulSigningError):
    """Stored public key does not match the private-key state on disk."""


def _env_enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in (
        "1", "true", "yes", "enabled")


def _alg_obj(alg: str, parameter_set: Optional[str] = None):
    if alg not in _ALGS:
        raise StatefulSigningError(
            f"unknown algorithm {alg!r}; expected one of {sorted(_ALGS)}")
    cls = _ALGS[alg]
    return cls() if parameter_set is None else cls(parameter_set)


def _sk_header(obj, alg: str) -> bytes:
    return (f"{alg.upper()}-{obj.params['name']}-SK-").encode() + bytes(
        [obj.format_version])


def _pk_header(obj, alg: str) -> bytes:
    return (f"{alg.upper()}-{obj.params['name']}-PK-").encode() + bytes(
        [obj.format_version])


def _state_index(obj, alg: str, sk: bytes) -> int:
    hdr = _sk_header(obj, alg)
    if not sk.startswith(hdr):
        raise StatefulSigningError(
            "private-key state format mismatch (parameter set changed or "
            "corrupt state file)")
    offset = len(hdr)
    if alg == "lms":
        offset += 16
    return int.from_bytes(sk[offset:offset + 4], byteorder="big")


def _derive_public_key(obj, alg: str, sk: bytes) -> bytes:
    hdr = _sk_header(obj, alg)
    if not sk.startswith(hdr):
        raise StatefulSigningError(
            "private-key state format mismatch (parameter set changed or "
            "corrupt state file)")
    n = obj.params["n"]
    offset = len(hdr)
    if alg == "xmss":
        need = 4 + 3 * n
        if len(sk) < offset + need:
            raise StatefulSigningError("private-key state truncated")
        pub_seed = sk[offset + 4 + n:offset + 4 + 2 * n]
        root = sk[offset + 4 + 2 * n:offset + 4 + 3 * n]
        return _pk_header(obj, alg) + root + pub_seed
    if len(sk) < offset + 16 + 4 + 4 + 4 + 2 * n:
        raise StatefulSigningError("private-key state truncated")
    ident = sk[offset:offset + 16]
    lms_tc = sk[offset + 20:offset + 24]
    ots_tc = sk[offset + 24:offset + 28]
    root = sk[offset + 28 + n:offset + 28 + 2 * n]
    return _pk_header(obj, alg) + ident + lms_tc + ots_tc + root


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    d = str(path.parent)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".sfs-tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _key_paths(key_dir: Path, alg: str) -> Dict[str, Path]:
    return {
        "state": key_dir / f"{alg}.stateful.key",
        "journal": key_dir / f"{alg}.stateful.journal",
        "pub": key_dir / f"{alg}.stateful.pub",
    }


def _journal_read(path: Path) -> Tuple[List[str], List[dict]]:
    if not path.exists():
        return [], []
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    parts = text.split("\n")
    lines: List[str] = []
    entries: List[dict] = []
    for i, part in enumerate(parts):
        if part == "":
            continue
        if i == len(parts) - 1 and parts[i] != "":
            if text.endswith("\n"):
                raise StatefulSigningError(f"corrupt journal (trailing data) in {path}")
            continue
        lines.append(part + "\n")
        try:
            entry = json.loads(part)
        except ValueError as exc:
            raise StatefulSigningError(
                f"corrupt journal entry in {path}: {exc}") from exc
        entries.append(entry)
    _validate_journal(path, entries)
    return lines, entries


def _validate_journal(path: Path, entries: List[dict]) -> None:
    last = -1
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("i"), int):
            raise StatefulSigningError(f"corrupt journal entry in {path}")
        if entry["i"] <= last:
            raise StatefulSigningError(
                f"journal indices not strictly increasing in {path} "
                "(reuse or tampering suspected)")
        last = entry["i"]


def _journal_append(path: Path, entry: dict) -> bytes:
    line = (json.dumps(entry, sort_keys=True, separators=(",", ":")) +
            "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path),
                 os.O_WRONLY | os.O_CREAT | os.O_APPEND |
                 getattr(os, "O_BINARY", 0), 0o600)
    try:
        written = os.write(fd, line)
        if written != len(line):
            raise StatefulSigningError(
                f"short write appending journal {path}")
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(path.parent)
    return line


def _parse_nv_index() -> Optional[int]:
    raw = os.environ.get(NV_INDEX_ENV, "").strip()
    if not raw:
        return None
    try:
        index = int(raw, 0)
    except ValueError as exc:
        raise StatefulSigningError(
            f"{NV_INDEX_ENV}={raw!r} is not an integer") from exc
    data_plane = os.environ.get(DATA_PLANE_NV_INDEX_ENV, "").strip()
    if data_plane:
        try:
            if int(data_plane, 0) == index:
                raise StatefulSigningError(
                    f"{NV_INDEX_ENV} must be DISTINCT from "
                    f"{DATA_PLANE_NV_INDEX_ENV} ({data_plane}); the data-plane "
                    "guard and the artifact seal own separate NV domains")
        except ValueError:
            pass
    if index < 0x01000000:
        raise StatefulSigningError(
            f"{NV_INDEX_ENV}={hex(index)} outside the NV index range")
    return index


def _nv_tool(env_name: str, default: str) -> str:
    return os.environ.get(env_name, "").strip() or default


def _nv_owner() -> str:
    return os.environ.get(NV_OWNER_ENV, "").strip() or "o"


def _run_tool(argv: List[str]) -> subprocess.CompletedProcess:
    command: "str | List[str]" = argv
    if os.name == "nt" and argv[0].lower().endswith((".cmd", ".bat")):
        command = " ".join(
            '"' + a.replace('"', "") + '"' for a in argv)
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StatefulSigningError(
            f"TPM NV tool failed to run: {argv[0]}: {exc}") from exc


def _nv_read(index: int) -> Optional[bytes]:
    proc = _run_tool([
        _nv_tool(NV_READ_TOOL_ENV, "tpm2_nvread"),
        hex(index), "-C", _nv_owner(), "-s", "32",
    ])
    if proc.returncode != 0:
        low = (proc.stderr or "").lower()
        if ("0x18b" in low or "0x0000018b" in low or
                "not correct for the use" in low):
            return None
        if ("0x14a" in low or "0x0000014a" in low or
                "used before being initialized" in low):
            return None
        raise StatefulSigningError(
            f"tpm2_nvread failed for index {hex(index)}: "
            f"{(proc.stderr or proc.stdout).strip()[:400]}")
    hexs = "".join((proc.stdout or "").split())
    try:
        data = bytes.fromhex(hexs)
    except ValueError as exc:
        raise StatefulSigningError(
            f"tpm2_nvread returned non-hex data for {hex(index)}") from exc
    if len(data) != 32:
        raise StatefulSigningError(
            f"tpm2_nvread returned {len(data)} bytes for {hex(index)}, "
            "expected 32")
    return data


def _nv_ensure_defined(index: int) -> None:
    proc = _run_tool([
        _nv_tool(NV_DEFINE_TOOL_ENV, "tpm2_nvdefine"),
        hex(index), "-C", _nv_owner(), "-s", "32",
        "-a", "ownerread|ownerwrite",
    ])
    if proc.returncode != 0:
        existing = _nv_read(index)
        if existing is None and "already defined" not in (
                proc.stderr or "").lower():
            raise StatefulSigningError(
                f"tpm2_nvdefine failed for index {hex(index)}: "
                f"{(proc.stderr or proc.stdout).strip()[:400]}")


def _nv_write(index: int, data: bytes) -> None:
    if len(data) != 32:
        raise StatefulSigningError("NV seal payload must be exactly 32 bytes")
    fd, tmp = tempfile.mkstemp(prefix=".sfs-nv-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        proc = _run_tool([
            _nv_tool(NV_WRITE_TOOL_ENV, "tpm2_nvwrite"),
            hex(index), "-C", _nv_owner(), "-f", tmp,
        ])
        if proc.returncode != 0:
            raise StatefulSigningError(
                f"tpm2_nvwrite failed for index {hex(index)}: "
                f"{(proc.stderr or proc.stdout).strip()[:400]}")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    readback = _nv_read(index)
    if readback != data:
        raise StatefulSigningError(
            f"TPM NV seal read-back mismatch for {hex(index)} "
            "(write not durable or index is not writable)")


def _nv_seal(index: int, line: bytes) -> str:
    _nv_ensure_defined(index)
    digest = hashlib.sha256(line).digest()
    _nv_write(index, digest)
    return digest.hex()


def _nv_check_seal(index: int, lines: List[str]) -> None:
    current = _nv_read(index)
    if current is None:
        return
    candidates = [hashlib.sha256(l.encode("utf-8")).digest()
                  for l in lines[-2:]]
    if current not in candidates:
        raise StateRollbackError(
            "TPM NV seal mismatch: the journal tail no longer matches the "
            "hardware-anchored seal (whole-store rollback or journal "
            "tampering detected). Restore an authentic file store or "
            f"re-key explicitly with {REPROVISION_ENV}=1 after proving "
            "custody.")


def _default_key_dir() -> Path:
    override = os.environ.get(KEY_DIR_ENV, "").strip()
    if override:
        return Path(override)
    return Path.cwd() / "stateful_keys"


def _retire(paths: Dict[str, Path]) -> Optional[Path]:
    present = [p for p in paths.values() if p.exists()]
    if not present:
        return None
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ")
    target = paths["state"].parent / "retired" / stamp
    target.mkdir(parents=True, exist_ok=True)
    for p in present:
        os.replace(str(p), str(target / p.name))
    _fsync_dir(target)
    return target


def provision_signing_key(alg: str = "lms",
                          key_dir: Optional[Path] = None,
                          parameter_set: Optional[str] = None,
                          force_rotate: bool = False) -> Dict[str, Path]:
    """Create the stateful key, public key and empty journal."""
    obj = _alg_obj(alg, parameter_set)
    kdir = Path(key_dir) if key_dir else _default_key_dir()
    kdir.mkdir(parents=True, exist_ok=True)
    paths = _key_paths(kdir, alg)
    if any(p.exists() for p in paths.values()):
        if not force_rotate:
            raise StatefulSigningError(
                f"stateful key already provisioned under {kdir} "
                f"(set {REPROVISION_ENV}=1 to archive and re-key)")
        retired = _retire(paths)
        logger.warning("stateful key material retired to %s", retired)
    pk, sk = obj.keygen()
    _atomic_write_bytes(paths["journal"], b"")
    _atomic_write_bytes(paths["pub"], pk)
    write_stateful_key(str(paths["state"]), sk)
    return paths


def sign_artifact(path: "str | os.PathLike",
                  alg: str = "lms",
                  key_dir: "str | os.PathLike | None" = None,
                  parameter_set: Optional[str] = None) -> Dict[str, object]:
    """SP 800-208-compliant detached stateful signature over an artifact.

    Writes ``<path>.lms208.sig`` (+ ``.lms208.pub`` sibling) and advances
    the one-time-key state durably BEFORE the signature file is released.
    Raises PermissionError without P2P_ENABLE_EXPERIMENTAL=1 and
    StatefulSigningError / StateRollbackError / KeySubstitutionError on
    any fail-closed condition.
    """
    obj = _alg_obj(alg, parameter_set)
    artifact = Path(path)
    message = artifact.read_bytes()
    kdir = Path(key_dir) if key_dir else _default_key_dir()
    kdir.mkdir(parents=True, exist_ok=True)
    paths = _key_paths(kdir, alg)

    reprovision = _env_enabled(REPROVISION_ENV)
    if paths["state"].exists():
        if not paths["journal"].exists():
            probe = read_stateful_key(str(paths["state"]))
            probe_index = _state_index(obj, alg, probe)
            if probe_index > 0:
                raise StatefulSigningError(
                    f"journal missing under {kdir} while one-time keys were "
                    "already used (custody breach or partial restore); "
                    f"restore the authentic journal or re-key with "
                    f"{REPROVISION_ENV}=1.")
            _atomic_write_bytes(paths["journal"], b"")
        sk = read_stateful_key(str(paths["state"]))
        lines, entries = _journal_read(paths["journal"])
    elif paths["pub"].exists() or paths["journal"].exists():
        if not reprovision:
            raise StatefulSigningError(
                f"stateful key state missing under {kdir} while public key/"
                "journal exist (possible restore of a partial store). "
                f"Restore the authentic state file or re-key with "
                f"{REPROVISION_ENV}=1.")
        provision_signing_key(alg, kdir, parameter_set, force_rotate=True)
        sk = read_stateful_key(str(paths["state"]))
        lines, entries = _journal_read(paths["journal"])
    else:
        provision_signing_key(alg, kdir, parameter_set)
        sk = read_stateful_key(str(paths["state"]))
        lines, entries = _journal_read(paths["journal"])

    index = _state_index(obj, alg, sk)
    max_used = entries[-1]["i"] if entries else -1
    if index <= max_used:
        raise StateRollbackError(
            f"one-time key state index {index} is not ahead of the journal "
            f"floor {max_used} (state rollback detected). Restore the "
            f"authentic state file or re-key with {REPROVISION_ENV}=1.")
    derived_pk = _derive_public_key(obj, alg, sk)
    stored_pk = paths["pub"].read_bytes() if paths["pub"].exists() else None
    if stored_pk is None:
        _atomic_write_bytes(paths["pub"], derived_pk)
    elif stored_pk != derived_pk:
        raise KeySubstitutionError(
            f"stored public key under {kdir} does not match the private-key "
            "state (key substitution or mixed-up key directory)")

    suffix = _SUFFIX[alg]
    sig_path = Path(str(artifact) + suffix + ".sig")
    sibling_pub = Path(str(artifact) + suffix + ".pub")
    if sibling_pub.exists() and sibling_pub.read_bytes() != derived_pk:
        raise KeySubstitutionError(
            f"stale foreign public key at {sibling_pub}; after an explicit "
            f"re-key ({REPROVISION_ENV}=1) remove superseded sibling "
            "public keys before re-signing")

    nv_index = _parse_nv_index()
    if nv_index is not None:
        _nv_check_seal(nv_index, lines)

    new_sk, signature = obj.sign_and_advance(sk, message)
    write_stateful_key(str(paths["state"]), new_sk)

    entry = {
        "alg": alg,
        "artifact": artifact.name,
        "i": index,
        "sha256": hashlib.sha256(message).hexdigest(),
        "sig_sha256": hashlib.sha256(signature).hexdigest(),
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    line = _journal_append(paths["journal"], entry)

    nv_hex: Optional[str] = None
    if nv_index is not None:
        nv_hex = _nv_seal(nv_index, line)

    _atomic_write_bytes(sig_path, signature)
    if not sibling_pub.exists():
        _atomic_write_bytes(sibling_pub, derived_pk)

    remaining = obj.params["max_signatures"] - (index + 1)
    logger.info("stateful %s signature released for %s (index=%d, %d left)",
                alg, artifact.name, index, remaining)
    return {
        "alg": alg,
        "artifact": str(artifact),
        "artifact_sha256": entry["sha256"],
        "index": index,
        "journal": str(paths["journal"]),
        "nv_seal": nv_hex,
        "parameter_set": obj.params["name"],
        "pub_path": str(paths["pub"]),
        "signatures_remaining": remaining,
        "sig_path": str(sig_path),
        "state": str(paths["state"]),
    }


def verify_artifact(path: "str | os.PathLike",
                    alg: str = "lms",
                    key_dir: "str | os.PathLike | None" = None,
                    pub_path: "str | os.PathLike | None" = None,
                    parameter_set: Optional[str] = None) -> bool:
    """Verify the detached stateful signature for an artifact."""
    obj = _alg_obj(alg, parameter_set)
    artifact = Path(path)
    message = artifact.read_bytes()
    suffix = _SUFFIX[alg]
    sig_file = Path(str(artifact) + suffix + ".sig")
    if not sig_file.exists():
        raise StatefulSigningError(f"missing stateful signature {sig_file}")
    if pub_path is not None:
        pub_file = Path(pub_path)
    else:
        sibling = Path(str(artifact) + suffix + ".pub")
        kdir = Path(key_dir) if key_dir else _default_key_dir()
        fallback = _key_paths(kdir, alg)["pub"]
        pub_file = sibling if sibling.exists() else fallback
    if not pub_file.exists():
        raise StatefulSigningError(f"missing stateful public key {pub_file}")
    ok = obj.verify(pub_file.read_bytes(), message, sig_file.read_bytes())
    return bool(ok)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="SP 800-208 stateful (LMS/XMSS) artifact signing hook")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
            ("sign", "produce <FILE>.lms208.sig (state advanced durably "
                     "before release)"),
            ("verify", "verify the detached stateful signature"),
            ("keygen", "provision stateful key material")):
        p = sub.add_parser(name, help=help_text)
        if name != "keygen":
            p.add_argument("file")
        p.add_argument("--alg", choices=sorted(_ALGS), default="lms")
        p.add_argument("--key-dir", default=None)
        p.add_argument("--parameter-set", default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "sign":
            print(json.dumps(sign_artifact(
                args.file, alg=args.alg, key_dir=args.key_dir,
                parameter_set=args.parameter_set), indent=2, sort_keys=True))
            return 0
        if args.command == "verify":
            ok = verify_artifact(
                args.file, alg=args.alg, key_dir=args.key_dir,
                parameter_set=args.parameter_set)
            print("[OK] stateful signature valid" if ok else
                  "[FAIL] stateful signature INVALID")
            return 0 if ok else 1
        paths = provision_signing_key(
            args.alg, args.key_dir, args.parameter_set,
            force_rotate=_env_enabled(REPROVISION_ENV))
        print(json.dumps({k: str(v) for k, v in paths.items()},
                         indent=2, sort_keys=True))
        return 0
    except PermissionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    except StatefulSigningError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
