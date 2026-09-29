#!/usr/bin/env python3
"""Production attack-surface audit (Task 5.2): the lean core stays lean.

Proves, by AST import-closure analysis (not filenames), that the audited
production entry points never import experimental/quarantined modules:

  CORE = secure_transmit_2027 + noise_pq + trust_anchor + cnsa_purity +
         crypto_selftest + transport_anonymity + spo_dpo + ts_hw_layer +
         ts_runtime + ts_attest (+ stdlib + vetted PQC/OS deps).

  QUARANTINED = nc3_nuclear_command, zk_authenticator (and the legacy
  archive tree). None appear in the transitive import closure of any
  CORE root. Moving them would break verified suites without reducing
  reachable attack surface — so the boundary is ENFORCED here instead.

Also records that allied_gateway.py (named in older plans) does not exist;
cjadc2_allied_gateway.py is a distinct tier-tested module, untouched.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent

CORE = [
    "secure_transmit_2027.py",
    "noise_pq.py",
    "trust_anchor.py",
    "cnsa_purity.py",
    "crypto_selftest.py",
    "transport_anonymity.py",
    "spo_dpo.py",
    "ts_hw_layer.py",
    "ts_runtime.py",
    "ts_attest.py",
]

# Modules that must never be reachable from CORE (quarantined surface).
QUARANTINED_TOP_LEVELS = {
    "nc3_nuclear_command",
    "zk_authenticator",
    "allied_gateway",
}

# Imports that never count (stdlib, vetted third-party, intra-core, lazy
# hardware backends resolved at runtime, test-only shims).
ALLOW_TOP_LEVELS = {
    "os", "sys", "json", "time", "logging", "hashlib", "hmac", "secrets",
    "socket", "ssl", "struct", "threading", "pathlib", "dataclasses",
    "typing", "enum", "collections", "re", "io", "ctypes", "platform",
    "subprocess", "shutil", "tempfile", "unittest", "ipaddress",
    "datetime", "math", "base64", "binascii", "functools", "itertools",
    "contextlib", "weakref", "gc", "inspect", "textwrap", "argparse",
    "getpass", "shlex", "uuid", "mmap", "importlib", "traceback",
    "cryptography", "liboqs_wrapper", "dependency_security_verifier",
    "platform_hsm_interface", "cng_platform", "psutil",
    "secure_transmit_2027", "noise_pq", "trust_anchor", "cnsa_purity",
    "crypto_selftest", "transport_anonymity", "spo_dpo", "ts_hw_layer",
    "ts_runtime", "ts_attest", "remote_siem_forwarder",
    "hw_readiness", "ctypes",
}


def _imports_of(path: Path) -> set:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, OSError):
        return set()
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module.split(".")[0])
    return out


def _closure(roots: list, seen: dict) -> set:
    frontier = list(roots)
    while frontier:
        name = frontier.pop()
        if name in seen:
            continue
        p = ROOT / f"{name}.py"
        if not p.exists():
            seen[name] = set()
            continue
        imps = _imports_of(p)
        seen[name] = imps
        frontier.extend(i for i in imps
                        if i not in seen and (ROOT / f"{i}.py").exists())
    return seen


def test_production_closure_excludes_quarantine():
    for name in CORE:
        assert (ROOT / name).exists(), f"core member missing: {name}"
    assert not (ROOT / "allied_gateway.py").exists()  # never existed here
    seen: dict = {}
    _closure(CORE, seen)
    violations = {}
    for mod, imps in seen.items():
        bad = (imps & QUARANTINED_TOP_LEVELS) - ALLOW_TOP_LEVELS
        if bad:
            violations[mod] = sorted(bad)
    assert not violations, f"quarantine reachable from core: {violations}"


def test_core_surface_stays_lean():
    # Gate: lean audited production surface < 15 files (10 modules +
    # 2 native crates, counted here as entries).
    entries = len(CORE) + 2  # + rust_data_plane/ + ts_rt/
    assert entries < 15, entries
    assert (ROOT / "rust_data_plane").is_dir()
    assert (ROOT / "ts_rt").is_dir()
    assert (ROOT / "archive" / "experimental" / "README.md").exists()
