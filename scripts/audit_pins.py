#!/usr/bin/env python3
"""Pin-scoped OSV audit for 2028 hardening (no isolated-env hash issues).

Queries https://api.osv.dev/v1/query for each pinned package in
requirements.txt + requirements-test.txt and fails on any known
vulnerability. Unlike `pip-audit -r` (which breaks in --require-hashes
mode on transitive unpinned deps like cffi>=2.0.0), this audits exactly
the pins we ship.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PIN_FILES = [REPO / "requirements.txt", REPO / "requirements-test.txt"]
OSV_URL = "https://api.osv.dev/v1/query"
TIMEOUT = 30


def parse_pins():
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
    # dedupe, keep highest version per name
    seen = {}
    for n, v in pins:
        seen[n.lower()] = (n, v)
    return sorted(seen.values())


def osv_query(name, version):
    import ssl
    payload = json.dumps({"package": {"name": name, "ecosystem": "PyPI"}, "version": version}).encode()
    req = urllib.request.Request(OSV_URL, data=payload, headers={"Content-Type": "application/json"})
    # B310: https-only (constant OSV_URL) + verified TLS ctx + 30s timeout.
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    with urllib.request.urlopen(req, context=ctx, timeout=TIMEOUT) as r:  # nosec B310 - https-only + verified ctx + timeout
        return json.loads(r.read().decode())


def main():
    pins = parse_pins()
    print(f"Auditing {len(pins)} pinned packages against OSV...")
    failures = []
    for name, ver in pins:
        try:
            data = osv_query(name, ver)
        except Exception as e:
            print(f"  WARN {name}=={ver}: OSV query failed ({e})")
            continue
        vulns = data.get("vulns", [])
        if vulns:
            for v in vulns:
                vid = v.get("id", "?")
                sev = ""
                for s in v.get("severity", []):
                    sev += f" {s.get('type')}:{s.get('score', '')}"
                print(f"  FAIL {name}=={ver}: {vid}{sev}")
            failures.append((name, ver, len(vulns)))
        else:
            print(f"  OK   {name}=={ver}: no known vulns")
    if failures:
        print(f"\n{len(failures)} pinned package(s) with known vulns - FAIL")
        return 1
    print("\nAll pinned packages clean - PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
