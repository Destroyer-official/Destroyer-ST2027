#!/usr/bin/env python3
"""Offline CRL bundle CLI for air-gapped operation (no network).

USB / sneakernet flow::

    # On online/signing host (or revoking device):
    python scripts/crl_bundle.py export --out bundle.json --user alice --issuer alice
    sha256sum / sha3sum bundle.json  # record hash for runbook

    # Carry bundle.json via USB to air-gapped host, verify hash, then:
    python scripts/crl_bundle.py import --in bundle.json

Reuses :class:`MultiDeviceManager` ``export_crl_bundle`` /
``import_crl_bundle`` when importable; otherwise falls back to a pure-JSON
passthrough with schema + version checks. Never performs network I/O.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

CRL_BUNDLE_VERSION = 1
REQUIRED_KEYS = ("issuer", "version", "revoked_serials", "timestamp")


def bundle_hash(bundle: dict) -> str:
    """SHA3-512 hex of canonical bundle JSON (for runbook hash check)."""
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha3_512(canonical).hexdigest()


def validate_bundle_schema(bundle: dict) -> list[str]:
    """Return list of schema errors (empty when valid). Fail-closed caller decides."""
    errors: list[str] = []
    if not isinstance(bundle, dict):
        return ["bundle must be a JSON object"]
    for key in REQUIRED_KEYS:
        if key not in bundle:
            errors.append(f"missing required key: {key}")
    issuer = bundle.get("issuer")
    if "issuer" in bundle and (not isinstance(issuer, str) or not issuer):
        errors.append("issuer must be a non-empty string")
    version = bundle.get("version")
    if "version" in bundle:
        try:
            v = int(version)  # type: ignore[arg-type]
            if v < 0:
                errors.append("version must be >= 0")
        except Exception:
            errors.append("version must be an integer")
    serials = bundle.get("revoked_serials")
    if "revoked_serials" in bundle:
        if not isinstance(serials, list):
            errors.append("revoked_serials must be a list")
        else:
            for s in serials:
                if not isinstance(s, str):
                    errors.append("revoked_serials entries must be hex strings")
                    break
                try:
                    bytes.fromhex(s)
                except Exception:
                    errors.append(f"revoked_serials entry not hex: {s[:32]}")
                    break
    ts = bundle.get("timestamp")
    if "timestamp" in bundle and not isinstance(ts, str):
        errors.append("timestamp must be an ISO-8601 string")
    return errors


def _try_load_manager(in_memory_only_default: bool = True):
    """Import MultiDeviceManager when available, else return (None, error)."""
    try:
        from multi_device_manager import MultiDeviceManager  # noqa: E402

        return MultiDeviceManager, None
    except Exception as e:  # pragma: no cover - fallback path
        return None, e


def _load_manager_from_file(manager_cls, devices_file: str | None, in_memory: bool):
    if devices_file:
        mgr = manager_cls(storage_path=str(Path(devices_file).parent), in_memory_only=False)
        # Canonical devices.json layout: <dir>/devices.json
        p = Path(devices_file)
        candidate = p if p.is_file() else p.parent / "devices.json" if p.suffix != ".json" else p
        # If user passed a directory, resolve inside it.
        if p.is_dir():
            candidate = p / "devices.json"
        try:
            if candidate.is_file():
                mgr.load_from_file(str(candidate))
        except Exception as e:
            print(f"WARN: could not load devices file {candidate}: {e}", file=sys.stderr)
        # Remember resolved path for later save.
        mgr._cli_devices_file = str(candidate)  # type: ignore[attr-defined]
        return mgr
    return manager_cls(in_memory_only=in_memory)


def do_export(args: argparse.Namespace) -> int:
    out_path = Path(args.out)
    if args.signing_key:
        # MultiDeviceManager.export_crl_bundle resolves this env + file anchors.
        os.environ["P2P_CRL_SIGNING_KEY"] = str(args.signing_key)
    user_id = args.user or args.issuer or "local-user"
    issuer = args.issuer or user_id
    version = args.version  # None => manager picks max(stored+1, now_ms)

    manager_cls, import_err = _try_load_manager()
    if manager_cls is not None:
        mgr = _load_manager_from_file(manager_cls, args.devices_file, in_memory=True)
        try:
            bundle = mgr.export_crl_bundle(user_id, issuer=issuer, version=version)
        except TypeError:
            # Older manager without issuer/version kwargs.
            bundle = mgr.export_crl_bundle(user_id)
    else:
        print(
            f"WARN: MultiDeviceManager unavailable ({import_err}); "
            "using JSON passthrough (unsigned, empty revocation list).",
            file=sys.stderr,
        )
        import time as _time

        bundle = {
            "issuer": issuer,
            "version": int(version) if version is not None else int(_time.time() * 1000),
            "revoked_serials": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alg": "none",
            "kid": None,
            "sig": None,
        }

    errors = validate_bundle_schema(bundle)
    if errors:
        print(f"ERROR: exported bundle failed schema check: {errors}", file=sys.stderr)
        return 2

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass
    print(f"exported CRL bundle: issuer={bundle.get('issuer')} version={bundle.get('version')} "
          f"revoked={len(bundle.get('revoked_serials', []))} alg={bundle.get('alg')}")
    print(f"  -> {out_path}")
    print(f"  sha3-512: {bundle_hash(bundle)}")
    print("  (record this hash in the air-gap runbook; verify after USB copy)")
    if not bundle.get("sig"):
        print("  NOTE: bundle is UNSIGNED (lab fail-open). Set --signing-key for production.",
              file=sys.stderr)
    return 0


def do_import(args: argparse.Namespace) -> int:
    in_path = Path(getattr(args, "input"))
    if args.verify_key:
        os.environ["P2P_CRL_VERIFY_KEY"] = str(args.verify_key)
    enforce = bool(args.enforce_sig) or os.environ.get("P2P_CRL_REQUIRE_SIG") == "1"

    try:
        bundle = json.loads(in_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"ERROR: input file not found: {in_path}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: could not parse {in_path}: {e}", file=sys.stderr)
        return 2

    errors = validate_bundle_schema(bundle)
    if errors:
        print(f"ERROR: bundle schema check failed: {errors}", file=sys.stderr)
        return 2
    try:
        version = int(bundle.get("version", 0) or 0)
        if version <= 0:
            print("ERROR: bundle version must be a positive integer (downgrade protection).",
                  file=sys.stderr)
            return 2
    except Exception:
        print("ERROR: bundle version must be an integer.", file=sys.stderr)
        return 2

    print(f"bundle: issuer={bundle.get('issuer')} version={version} "
          f"revoked={len(bundle.get('revoked_serials', []))} alg={bundle.get('alg')}")
    print(f"  sha3-512: {bundle_hash(bundle)}")

    manager_cls, import_err = _try_load_manager()
    if manager_cls is None:
        print(
            f"WARN: MultiDeviceManager unavailable ({import_err}); "
            "passthrough validation only (no local revocation list updated).",
            file=sys.stderr,
        )
        if bundle.get("sig"):
            print("  signed bundle present; signature NOT verified in passthrough mode "
                  "(import on a full host to verify).", file=sys.stderr)
        elif enforce:
            print("ERROR: unsigned bundle rejected (--enforce-sig).", file=sys.stderr)
            return 3
        else:
            print("  unsigned bundle accepted in passthrough mode (lab fail-open).",
                  file=sys.stderr)
        print("passthrough check: OK (schema + version)")
        return 0

    mgr = _load_manager_from_file(manager_cls, args.devices_file, in_memory=True)
    verify_pubkey = None
    if args.verify_key and Path(str(args.verify_key)).is_file():
        try:
            raw = Path(str(args.verify_key)).read_bytes()
            # Support raw bytes or base64-encoded key files.
            try:
                verify_pubkey = base64.b64decode(raw, validate=True)
                if len(verify_pubkey) not in (1952, 2592):
                    verify_pubkey = raw
            except Exception:
                verify_pubkey = raw
        except Exception as e:
            print(f"WARN: could not read --verify-key: {e}", file=sys.stderr)
    try:
        added = mgr.import_crl_bundle(bundle, verify_pubkey=verify_pubkey, enforce_sig=enforce)
    except TypeError:
        added = mgr.import_crl_bundle(bundle)
    print(f"merged {added} new revocation(s) from {bundle.get('issuer')} (v{version})")
    # Persist when a devices file was given.
    save_target = getattr(mgr, "_cli_devices_file", None) or args.devices_file
    if save_target:
        try:
            mgr.save_to_file(str(save_target))
            print(f"  saved device registry -> {save_target}")
        except Exception as e:
            print(f"WARN: could not save devices file {save_target}: {e}", file=sys.stderr)
    if added == 0:
        print("  (0 may mean stale version, already-merged, or rejected signature - see log)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crl_bundle",
        description="Offline CRL bundle export/import for air-gapped hosts. No network I/O.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("export", help="Export local revocation list to a bundle file.")
    pe.add_argument("--out", required=True, help="Output bundle path (e.g. bundle.json).")
    pe.add_argument("--user", default=None, help="User identity id (defaults to --issuer).")
    pe.add_argument("--issuer", default=None, help="Bundle issuer id (defaults to --user).")
    pe.add_argument("--version", type=int, default=None, help="Monotonic version (default: auto).")
    pe.add_argument("--devices-file", default=None,
                    help="devices.json path (or dir containing it) to export from.")
    pe.add_argument("--signing-key", default=None,
                    help="ML-DSA-87 signing key path (sets P2P_CRL_SIGNING_KEY).")
    pe.set_defaults(func=do_export)

    pi = sub.add_parser("import", help="Validate + merge a bundle file (USB import).")
    pi.add_argument("--in", dest="input", required=True, help="Input bundle path (e.g. bundle.json).")
    pi.add_argument("--devices-file", default=None,
                    help="devices.json path to merge into (and save).")
    pi.add_argument("--verify-key", default=None,
                    help="ML-DSA-87 verify key path (sets P2P_CRL_VERIFY_KEY).")
    pi.add_argument("--enforce-sig", action="store_true",
                    help="Reject unsigned/invalid bundles (fail-closed).")
    pi.set_defaults(func=do_import)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
