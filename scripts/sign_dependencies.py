#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""DLL supply-chain signing for oqs.dll / libsodium.dll (Ed25519 CA).

Ceremony rules (military posture, F-04/A-02):
  * The Ed25519 CA private key NEVER lives in the repo tree. Default
    custody path: ~/.destroyer-st2027/offline-keys/military_root_ca.pem
    (override: --ca-key or P2P_CA_KEY_PATH).
  * Replacing the trust anchors (oqs.dll.pub / libsodium.dll.pub) with a
    DIFFERENT public key requires the explicit --rotate ceremony flag.
    A bare re-sign (same key, new DLL bytes) does not.
  * Generating a new CA key also requires --rotate.
  * Every run emits docs/dll_ca_ceremony_receipt.json (hashes, anchor
    fingerprints, Ed25519 self-signature). Lab-grade self-attestation
    until external (Rekor) anchoring exists — say so when citing.

Usage:
  python scripts/sign_dependencies.py                # re-sign with custodied key
  python scripts/sign_dependencies.py --rotate       # generate/rotate CA + anchors
  python scripts/sign_dependencies.py --ca-key D:\\offline\\ca.pem
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

DEFAULT_CA_DIR = Path.home() / ".destroyer-st2027" / "offline-keys"
DEFAULT_CA_KEY = DEFAULT_CA_DIR / "military_root_ca.pem"
ANCHOR_DLLS = ("oqs.dll", "libsodium.dll")
RECEIPT_PATH = Path("docs") / "dll_ca_ceremony_receipt.json"


def _write_new_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create a new file with restrictive mode from the first byte (no chmod race)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
    except BaseException:
        try:
            os.unlink(str(path))
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        raise


def _resolve_passphrase(ca_key_path: Path, passphrase_file: Optional[Path]) -> bytes:
    """Passphrase precedence: --passphrase-file > sibling sidecar > env > generated.

    Returns bytes; callers generating a NEW key must persist the generated
    secret themselves (see _bootstrap_ca_key).
    """
    env_pass = os.environ.get("P2P_CA_PASSPHRASE", "")
    if env_pass:
        return env_pass.encode("utf-8")
    if passphrase_file and passphrase_file.is_file():
        return passphrase_file.read_bytes().strip()
    sidecar = Path(str(ca_key_path) + ".passphrase")
    if sidecar.is_file():
        return sidecar.read_bytes().strip()
    return b""


def load_ca_key(ca_key_path: Path, passphrase_file: Optional[Path]) -> ed25519.Ed25519PrivateKey:
    if not ca_key_path.is_file():
        raise RuntimeError(
            f"FAIL-CLOSED: CA key not found at {ca_key_path}. "
            "Pass --rotate to generate a new anchor (documented ceremony) "
            "or provide --ca-key/P2P_CA_KEY_PATH."
        )
    data = ca_key_path.read_bytes()
    if not data:
        raise RuntimeError(f"FAIL-CLOSED: CA key empty/unreadable: {ca_key_path}")
    passphrase = _resolve_passphrase(ca_key_path, passphrase_file)
    try:
        return serialization.load_pem_private_key(data, password=passphrase or None)
    except Exception as e:
        raise RuntimeError(
            f"FAIL-CLOSED: cannot decrypt CA key {ca_key_path}: {e}. "
            "Provide P2P_CA_PASSPHRASE or --passphrase-file."
        ) from e


def bootstrap_ca_key(ca_key_path: Path, passphrase_file: Optional[Path]) -> ed25519.Ed25519PrivateKey:
    """Generate a new Ed25519 CA key OUTSIDE the repo with encrypted-at-rest custody."""
    if ca_key_path.exists():
        raise RuntimeError(
            f"Refusing to overwrite existing CA key at {ca_key_path} "
            "(rotation must be an explicit, reviewed action)."
        )
    passphrase = _resolve_passphrase(ca_key_path, passphrase_file)
    if not passphrase:
        generated_secret = secrets.token_urlsafe(32)
        sidecar = Path(str(ca_key_path) + ".passphrase")
        _write_new_private(sidecar, generated_secret.encode("utf-8"), mode=0o400)
        print(f"[CEREMONY] Generated custodian passphrase stored at {sidecar} "
              "(mode 0400). It is NOT printed.")
        passphrase = generated_secret.encode("utf-8")

    private_key = ed25519.Ed25519PrivateKey.generate()
    _write_new_private(ca_key_path, private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    ))
    print(f"[CEREMONY] New Ed25519 CA key written to {ca_key_path} (0600, offline custody).")
    return private_key


def _pub_pem(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def ensure_anchor_consistency(dlls: List[Path], pub_pem: bytes, rotate: bool) -> bool:
    """Return True when anchors changed (rotation). Refuse silent anchor replacement."""
    changed = False
    for dll in dlls:
        anchor = Path(str(dll) + ".pub")
        if anchor.exists():
            existing = anchor.read_bytes()
            if existing != pub_pem:
                if not rotate:
                    raise RuntimeError(
                        f"Refusing to replace trust anchor {anchor} with a different "
                        "public key without the explicit --rotate ceremony flag."
                    )
                print(f"[CEREMONY] Rotating anchor {anchor} (old sha256 "
                      f"{hashlib.sha256(existing).hexdigest()[:16]}... -> new)")
                changed = True
    return changed


def sign_dll(dll_path: Path, private_key: ed25519.Ed25519PrivateKey) -> dict:
    """Sign one DLL, write .sig + .hashes + .pub anchor; return receipt entry."""
    data = dll_path.read_bytes()
    signature = private_key.sign(data)
    Path(str(dll_path) + ".sig").write_bytes(signature)

    manifest = {
        "sha512": hashlib.sha512(data).hexdigest(),
        "sha3_512": hashlib.sha3_512(data).hexdigest(),  # NIST FIPS 202
        "size": len(data),
    }
    Path(str(dll_path) + ".hashes").write_text(json.dumps(manifest, indent=4), encoding="utf-8")
    Path(str(dll_path) + ".pub").write_bytes(_pub_pem(private_key))

    print(f"[OK] Signed {dll_path.name} ({manifest['size']} bytes, "
          f"sha256 {hashlib.sha256(data).hexdigest()[:16]}...)")
    return {
        "dll": str(dll_path),
        "size": manifest["size"],
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": manifest["sha512"],
        "sha3_512": manifest["sha3_512"],
    }


def write_receipt(entries: List[dict], private_key: ed25519.Ed25519PrivateKey,
                  action: str, reason: str,
                  receipt_path: Optional[Path] = None) -> Path:
    pub_pem = _pub_pem(private_key)
    record = {
        "ceremony": "dll-ca-signing",
        "action": action,
        "reason": reason,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ca_algorithm": "Ed25519",
        "anchor_pub_sha256": hashlib.sha256(pub_pem).hexdigest(),
        "anchor_pub_sha512": hashlib.sha512(pub_pem).hexdigest(),
        "dlls": entries,
        "attestation_grade": "LAB-GRADE self-attestation until Rekor anchoring "
                             "(see docs/liboqs_pin.md external anchoring plan)",
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record["ed25519_signature_b64"] = base64.b64encode(private_key.sign(canonical)).decode("ascii")
    receipt = Path(receipt_path) if receipt_path is not None else Path(RECEIPT_PATH)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"[OK] Ceremony receipt written to {receipt}")
    return receipt


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ca-key", default=os.environ.get("P2P_CA_KEY_PATH") or str(DEFAULT_CA_KEY))
    ap.add_argument("--passphrase-file", default=None)
    ap.add_argument("--rotate", action="store_true",
                    help="Explicit ceremony: generate a new CA key and/or replace existing anchors.")
    ap.add_argument("--dll", action="append", default=None,
                    help="DLL to sign (repeatable). Default: oqs.dll + libsodium.dll when present.")
    ap.add_argument("--reason", default="manual run of scripts/sign_dependencies.py")
    ap.add_argument("--receipt", default=os.environ.get("P2P_DLL_CEREMONY_RECEIPT") or str(RECEIPT_PATH),
                    help="Where to write the ceremony receipt JSON.")
    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    ca_key_path = Path(args.ca_key)
    passphrase_file = Path(args.passphrase_file) if args.passphrase_file else None

    if args.dll:
        dlls = [Path(d) for d in args.dll]
    else:
        dlls = [Path(d) for d in ANCHOR_DLLS]
    missing = [str(d) for d in dlls if not d.is_file()]
    if missing:
        print(f"[ERROR] DLL(s) not found: {', '.join(missing)}", file=sys.stderr)
        return 1

    try:
        bootstrapped = False
        if ca_key_path.is_file():
            private_key = load_ca_key(ca_key_path, passphrase_file)
        elif args.rotate:
            private_key = bootstrap_ca_key(ca_key_path, passphrase_file)
            bootstrapped = True
        else:
            raise RuntimeError(
                f"FAIL-CLOSED: CA key not found at {ca_key_path} and --rotate "
                "not given (a bare re-sign cannot create the root of trust)."
            )

        rotated = ensure_anchor_consistency(dlls, _pub_pem(private_key), args.rotate)
        entries = [sign_dll(dll, private_key) for dll in dlls]
        write_receipt(entries, private_key,
                      action="rotate" if (rotated or bootstrapped) else "resign",
                      reason=args.reason, receipt_path=Path(args.receipt))
        print("\n[SUCCESS] DLL supply-chain signatures and anchors are consistent.")
        return 0
    except RuntimeError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
