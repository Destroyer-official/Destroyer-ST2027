#!/usr/bin/env python3
"""Offline-first CVE scan over pinned requirements (additive, non-breaking).

Default (offline, no network):
  - parses requirements pins (``pkg==ver`` + ``--hash=``),
  - checks pins exist + hashes present,
  - warns on unpinned / hash-missing lines (stderr, exit 0),
  - emits JSON ``[{package, version, skipped_offline, ...}]`` (no network).

Online (only with ``--online``):
  - queries OSV API ``https://api.osv.dev/v1/query`` per pin via stdlib
    ``urllib`` only, collects ``osv_ids``.
  - exits 1 on confirmed vulns when ``--fail-on-vuln`` (default True
    when ``--online``); network errors warn and continue (never fail
    the scan on transport errors; the finding is recorded with
    ``osv_query_error`` and empty ``osv_ids``).

Examples:
  python scripts/cve_scan.py                     # offline, JSON to stdout
  python scripts/cve_scan.py --output cve.json   # offline + file
  python scripts/cve_scan.py --online --fail-on-vuln
  python scripts/cve_scan.py --online --no-fail-on-vuln --output cve.json
"""

import argparse
import json
import re
import ssl
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_REQUIREMENTS = REPO / "requirements.txt"
OSV_URL = "https://api.osv.dev/v1/query"

PIN_RE = re.compile(r"([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-+]+)")
HASH_RE = re.compile(r"--hash=\s*sha256:([0-9a-fA-F]{64})")
NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<|===)?")


def _parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Offline-first CVE scan of pinned requirements (OSV only with --online)."
    )
    p.add_argument(
        "--requirements",
        dest="requirements",
        default=str(DEFAULT_REQUIREMENTS),
        help="Path to requirements file (default: requirements.txt).",
    )
    p.add_argument(
        "--output",
        dest="output",
        default=None,
        help="Optional path to write JSON results (else stdout only).",
    )
    p.add_argument(
        "--online",
        action="store_true",
        default=False,
        help="Query OSV API. Without this flag no network is performed.",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="OSV HTTPS timeout in seconds (online only, default 30).",
    )
    p.add_argument(
        "--fail-on-vuln",
        dest="fail_on_vuln",
        action="store_true",
        default=True,
        help="Exit 1 when online scan finds vulns (default True).",
    )
    p.add_argument(
        "--no-fail-on-vuln",
        dest="fail_on_vuln",
        action="store_false",
        help="Exit 0 even when vulns are found (report only).",
    )
    return p.parse_args(argv)


def _warn(msg):
    print(f"[WARN] {msg}", file=sys.stderr)


def parse_requirements(path):
    """Return (pins, warnings).

    pins: list of {name, version, hashes, line}
    warnings: list of str for unpinned / hash-missing lines.
    """
    pins = []
    warnings = []
    text = Path(path).read_text(encoding="utf-8")
    buf = ""
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        # Inside a "\" continuation, every line (incl. "--hash=...") belongs
        # to the pending requirement; only treat "-" / "#" as special when
        # starting a fresh logical line.
        if buf:
            if s.startswith("#"):
                continue
            if s.endswith("\\"):
                buf += s[:-1].strip() + " "
                continue
            buf += s
        else:
            if s.startswith("#"):
                continue
            # pip options / include lines we do not audit as pins
            # (only when not inside a continuation).
            if s.startswith("-"):
                continue
            if s.endswith("\\"):
                buf += s[:-1].strip() + " "
                continue
            buf += s
        logical = buf.strip()
        buf = ""
        if not logical or logical.startswith("#"):
            continue
        m = PIN_RE.search(logical)
        if m:
            name, ver = m.group(1), m.group(2)
            hashes = HASH_RE.findall(logical)
            pins.append(
                {"name": name, "version": ver, "hashes": hashes, "line": logical}
            )
            if not hashes:
                warnings.append(
                    f"{name}=={ver}: pinned but no --hash present "
                    f"(install with --require-hashes needs hashes)"
                )
        else:
            nm = NAME_RE.match(logical)
            label = nm.group(1) if nm else logical[:60]
            warnings.append(
                f"{label}: unpinned or non-== specifier skipped "
                f"(line: {logical[:120]})"
            )
    if buf.strip():
        logical = buf.strip()
        m = PIN_RE.search(logical)
        if m:
            pins.append(
                {
                    "name": m.group(1),
                    "version": m.group(2),
                    "hashes": HASH_RE.findall(logical),
                    "line": logical,
                }
            )
        else:
            warnings.append(f"unpinned trailing line skipped: {logical[:120]}")
    # dedupe, keep last occurrence per lowercase name
    seen = {}
    for pin in pins:
        seen[pin["name"].lower()] = pin
    return sorted(seen.values(), key=lambda d: d["name"].lower()), warnings


def osv_query(name, version, timeout=30):
    """Query OSV, return list of vuln IDs. Raises on transport/parse error."""
    payload = json.dumps(
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    ).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    # B310: https-only constant URL + verified TLS ctx + timeout.
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:  # nosec B310 - https-only + verified ctx + timeout
        data = json.loads(r.read().decode("utf-8"))
    return [v.get("id", "?") for v in data.get("vulns", [])]


def main(argv=None):
    args = _parse_args(argv)
    req_path = Path(args.requirements)
    if not req_path.is_file():
        # fall back to repo-root requirements.txt when a bare name was given
        alt = REPO / Path(args.requirements).name
        if alt.is_file():
            req_path = alt
        else:
            print(f"[ERROR] requirements file not found: {args.requirements}",
                  file=sys.stderr)
            return 2

    pins, warnings = parse_requirements(req_path)
    for w in warnings:
        _warn(w)
    if not pins:
        _warn(f"no pinned (==) packages found in {req_path}")

    results = []
    vuln_count = 0
    if not args.online:
        # Offline: no network by design. Never fail on network error
        # (no request is made at all); warn only.
        for pin in pins:
            results.append(
                {
                    "package": pin["name"],
                    "version": pin["version"],
                    "skipped_offline": True,
                    "osv_ids": [],
                    "hashes_present": bool(pin["hashes"]),
                    "hash_count": len(pin["hashes"]),
                }
            )
        print(f"[INFO] offline scan: {len(pins)} pins checked, "
              f"{len(warnings)} warning(s), no network used.",
              file=sys.stderr)
    else:
        for pin in pins:
            entry = {
                "package": pin["name"],
                "version": pin["version"],
                "skipped_offline": False,
                "hashes_present": bool(pin["hashes"]),
                "hash_count": len(pin["hashes"]),
            }
            try:
                ids = osv_query(pin["name"], pin["version"], timeout=args.timeout)
                entry["osv_ids"] = ids
                if ids:
                    vuln_count += 1
                    print(f"  FAIL {pin['name']}=={pin['version']}: "
                          f"{', '.join(ids)}", file=sys.stderr)
                else:
                    print(f"  OK   {pin['name']}=={pin['version']}: no known vulns",
                          file=sys.stderr)
            except Exception as e:
                # Never fail the scan on transport errors; record + warn.
                entry["osv_ids"] = []
                entry["osv_query_error"] = str(e)[:200]
                _warn(f"{pin['name']}=={pin['version']}: OSV query failed "
                      f"({e}); treated as unknown, not a failure")
            results.append(entry)
        print(f"[INFO] online scan: {len(pins)} pins, {vuln_count} with vulns, "
              f"{len(warnings)} warning(s).", file=sys.stderr)

    out_json = json.dumps(results, indent=2)
    if args.output:
        Path(args.output).write_text(out_json + "\n", encoding="utf-8")
        print(f"[OK] CVE scan wrote {len(results)} result(s) -> {args.output}",
              file=sys.stderr)
    # JSON to stdout for automation (warnings/info stay on stderr).
    print(out_json)

    if args.online and args.fail_on_vuln and vuln_count:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
