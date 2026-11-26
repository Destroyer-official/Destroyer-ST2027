#!/usr/bin/env python3
"""Pin-scoped OSV audit for 2028 hardening (fail-closed online & offline).

Queries https://api.osv.dev/v1/query for each pinned package in
requirements.txt + requirements-test.txt and fails on any known
vulnerability. Supports verified, fresh, ML-DSA-87-signed offline mirrors
with full pin coverage so air-gapped verification cannot pass on stale,
unsigned, incomplete, or unreachable data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

PIN_FILES = [REPO / "requirements.txt", REPO / "requirements-test.txt"]
DEFAULT_MIRROR = REPO / "compliance_reports" / "cve_scan_offline.json"
OSV_URL = "https://api.osv.dev/v1/query"
TIMEOUT = 30
MAX_MIRROR_AGE_DAYS = 30


def parse_pins() -> list[tuple[str, str]]:
    pins = []
    for fn in PIN_FILES:
        if not fn.exists():
            continue
        buf = ""
        for line in fn.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.endswith("\\"):
                buf += s[:-1].strip() + " "
                continue
            buf += s
            m = re.match(r"([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-+]+)", buf)
            if m:
                pins.append((m.group(1), m.group(2)))
            buf = ""
    seen = {}
    for n, v in pins:
        seen[n.lower()] = (n, v)
    return sorted(seen.values())


def osv_query(name: str, version: str) -> dict:
    import ssl

    payload = json.dumps({"package": {"name": name, "ecosystem": "PyPI"}, "version": version}).encode()
    req = urllib.request.Request(OSV_URL, data=payload, headers={"Content-Type": "application/json"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    with urllib.request.urlopen(req, context=ctx, timeout=TIMEOUT) as r:  # nosec B310 - https-only + verified ctx + timeout
        return json.loads(r.read().decode())


def _is_production_posture() -> bool:
    try:
        from production_gate import is_production
        return bool(is_production())
    except Exception:
        return False


def _verify_mirror_signature(mirror_file: Path, *, require_signature: bool) -> None:
    sig_path = mirror_file.with_name(mirror_file.name + ".mldsa87.sig")
    if not sig_path.exists():
        if require_signature:
            raise RuntimeError(f"Offline mirror signature missing (fail-closed): {sig_path}")
        return
    from liboqs_wrapper import LibOQS_MLDSA_87
    from report_trust import verify_with_anchor

    pub_path = REPO / "certs" / "audit_signer.mldsa87.pub"
    verifier = LibOQS_MLDSA_87()
    if not verify_with_anchor(mirror_file, sig_path, pub_path, verifier):
        raise RuntimeError(
            f"Offline mirror ML-DSA-87 signature verification FAILED for {mirror_file} (fail-closed)"
        )


def load_and_validate_mirror(
    mirror_file: Path,
    pins: list[tuple[str, str]],
    *,
    require_signature: bool = False,
) -> dict[tuple[str, str], list]:
    """Load, verify freshness/signature/coverage, and return {(pkg_lower, ver): vulns}."""
    if not mirror_file.exists():
        raise RuntimeError(f"Offline mirror file missing: {mirror_file} (fail-closed)")

    _verify_mirror_signature(mirror_file, require_signature=require_signature)

    try:
        db = json.loads(mirror_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Invalid offline mirror JSON {mirror_file}: {exc}") from exc

    now = datetime.now(timezone.utc)
    if isinstance(db, dict):
        if db.get("skipped_offline"):
            raise RuntimeError(
                "Offline mirror is marked 'skipped_offline' instead of verified clean (fail-closed)"
            )
        gen_raw = db.get("generated_utc")
        if not isinstance(gen_raw, str) or not gen_raw.strip():
            raise RuntimeError("Offline mirror missing required 'generated_utc' timestamp (fail-closed)")
        try:
            gen_dt = datetime.fromisoformat(gen_raw.replace("Z", "+00:00"))
            if gen_dt.tzinfo is None:
                gen_dt = gen_dt.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise RuntimeError(f"Invalid offline mirror timestamp {gen_raw!r}: {exc}") from exc

        max_age = min(int(db.get("max_age_days", MAX_MIRROR_AGE_DAYS)), MAX_MIRROR_AGE_DAYS)
        if gen_dt > now + timedelta(days=1):
            raise RuntimeError(f"Offline mirror timestamp is far in the future ({gen_raw}) (fail-closed)")
        if (now - gen_dt) > timedelta(days=max_age):
            raise RuntimeError(
                f"Offline mirror expired (generated {gen_raw}, max_age_days={max_age}) (fail-closed)"
            )
        items = db.get("packages")
        if not isinstance(items, list):
            raise RuntimeError("Offline mirror missing 'packages' list (fail-closed)")
    elif isinstance(db, list):
        items = db
    else:
        raise RuntimeError("Offline mirror JSON must be an object or array (fail-closed)")

    index: dict[tuple[str, str], list] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        pkg = str(item.get("package", "")).strip().lower()
        ver = str(item.get("version", "")).strip()
        if not pkg or not ver:
            continue
        if item.get("skipped_offline"):
            raise RuntimeError(
                f"Offline mirror marks {pkg}=={ver} as 'skipped_offline' instead of verified clean (fail-closed)"
            )
        vulns = item.get("vulns")
        if vulns is None:
            vulns = item.get("osv_ids", [])
        index[(pkg, ver)] = list(vulns)

    missing = [(n, v) for n, v in pins if (n.lower(), v) not in index]
    if missing:
        raise RuntimeError(
            f"Offline mirror omits {len(missing)} pinned package(s): "
            f"{', '.join(f'{n}=={v}' for n, v in missing[:5])} (fail-closed)"
        )
    return index


def generate_mirror(mirror_file: Path, pins: list[tuple[str, str]]) -> int:
    """Query live OSV for every pin, write compliance mirror JSON, and sign with audit_signer."""
    from liboqs_wrapper import LibOQS_MLDSA_87
    from report_trust import load_or_create_audit_signer

    packages = []
    vulns_found = 0
    print(f"Generating signed OSV offline mirror for {len(pins)} pinned packages -> {mirror_file}")
    for name, ver in pins:
        data = osv_query(name, ver)
        vulns = data.get("vulns", [])
        vuln_ids = [v.get("id", str(v)) if isinstance(v, dict) else str(v) for v in vulns]
        if vuln_ids:
            vulns_found += 1
        packages.append(
            {
                "package": name,
                "version": ver,
                "osv_ids": vuln_ids,
                "status": "vulnerable" if vuln_ids else "clean",
            }
        )

    payload = {
        "schema_version": "2.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "max_age_days": MAX_MIRROR_AGE_DAYS,
        "source": OSV_URL,
        "pin_count": len(packages),
        "packages": packages,
    }
    raw_bytes = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    mirror_file.parent.mkdir(parents=True, exist_ok=True)
    mirror_file.write_bytes(raw_bytes)

    _pk, sk = load_or_create_audit_signer()
    sig = LibOQS_MLDSA_87().sign(sk, raw_bytes)
    sig_path = mirror_file.with_name(mirror_file.name + ".mldsa87.sig")
    sig_path.write_bytes(sig)
    print(
        f"Wrote {mirror_file} (sha384={hashlib.sha384(raw_bytes).hexdigest()[:16]}...) "
        f"and signature {sig_path.name} ({len(sig)}B ML-DSA-87)"
    )
    if vulns_found:
        print(f"FAIL: {vulns_found} package(s) reported known vulnerabilities")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Pin-scoped vulnerability auditor (supports online OSV and air-gapped signed mirror)"
    )
    parser.add_argument("--offline", action="store_true", help="Air-gapped operation: use local vulnerability mirror")
    parser.add_argument("--mirror", default=None, help="Path to local vulnerability mirror JSON file")
    parser.add_argument("--require-signature", action="store_true", help="Require ML-DSA-87 mirror signature")
    parser.add_argument(
        "--generate-mirror",
        action="store_true",
        help="Query live OSV and write a fresh ML-DSA-87-signed offline mirror JSON",
    )
    args = parser.parse_args(argv)

    pins = parse_pins()
    mirror_file = Path(args.mirror) if args.mirror else DEFAULT_MIRROR
    if args.generate_mirror:
        return generate_mirror(mirror_file, pins)

    prod_mode = _is_production_posture()
    offline_mode = args.offline or (os.environ.get("P2P_AIRGAP_MODE", "").strip().lower() in ("1", "true", "yes"))
    require_sig = bool(args.require_signature or prod_mode or (mirror_file.resolve() == DEFAULT_MIRROR.resolve()))

    if offline_mode:
        print(f"Auditing {len(pins)} pinned packages against offline mirror: {mirror_file}...")
        try:
            mirror_index = load_and_validate_mirror(mirror_file, pins, require_signature=require_sig)
        except Exception as exc:
            print(f"FAIL: offline mirror validation failed: {exc}", file=sys.stderr)
            return 1
    else:
        print(f"Auditing {len(pins)} pinned packages against OSV...")
        mirror_index = None

    failures = []
    query_errors = []
    for name, ver in pins:
        try:
            if offline_mode:
                data = {"vulns": mirror_index[(name.lower(), ver)]}
            else:
                data = osv_query(name, ver)
        except Exception as e:
            if not prod_mode and mirror_file.exists():
                try:
                    if mirror_index is None:
                        mirror_index = load_and_validate_mirror(
                            mirror_file, pins, require_signature=require_sig
                        )
                    print(f"  WARN {name}=={ver}: OSV unreachable ({e}), using verified offline mirror")
                    data = {"vulns": mirror_index[(name.lower(), ver)]}
                except Exception as mirror_exc:
                    print(f"  ERROR {name}=={ver}: OSV unreachable ({e}) and offline mirror invalid ({mirror_exc})")
                    query_errors.append((name, ver))
                    continue
            else:
                print(f"  ERROR {name}=={ver}: OSV query failed ({e})")
                query_errors.append((name, ver))
                continue

        vulns = data.get("vulns", [])
        if vulns:
            for v in vulns:
                if isinstance(v, dict):
                    vid = v.get("id", "?")
                    sev = "".join(f" {s.get('type')}:{s.get('score', '')}" for s in v.get("severity", []))
                else:
                    vid = str(v)
                    sev = ""
                print(f"  FAIL {name}=={ver}: {vid}{sev}")
            failures.append((name, ver, len(vulns)))
        else:
            print(f"  OK   {name}=={ver}: no known vulns")

    if failures:
        print(f"\n{len(failures)} pinned package(s) with known vulns - FAIL")
        return 1
    if query_errors:
        print(f"\n{len(query_errors)} pinned package(s) could not be audited - FAIL (fail-closed)")
        return 1
    print("\nAll pinned packages clean - PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
