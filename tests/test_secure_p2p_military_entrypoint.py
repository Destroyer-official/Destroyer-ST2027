#!/usr/bin/env python3
"""Entrypoint hardening tests for secure_p2p.py."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PY = sys.executable


def _run(args, *, env=None, timeout=120):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run(
        [PY, str(REPO / "secure_p2p.py")] + args,
        cwd=str(REPO),
        env=merged,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )


def test_help_exposes_production_and_lab_surfaces():
    res = _run(["--help"])
    assert res.returncode == 0
    for token in ("node", "selftest", "audit", "demo", "chat", "monolith", "web"):
        assert token in res.stdout


def test_production_refuses_implicit_command():
    res = _run([], env={"P2P_PRODUCTION": "1"})
    assert res.returncode == 2
    assert "PRODUCTION GATE" in res.stdout or "No command" in res.stdout


def test_production_refuses_demo_without_lab():
    res = _run(["demo"], env={"P2P_PRODUCTION": "1"})
    assert res.returncode == 2
    assert "PRODUCTION REFUSAL" in res.stdout or "lab" in res.stdout.lower()


def test_production_refuses_chat_and_web():
    for cmd in (["chat"], ["web"]):
        res = _run(cmd, env={"P2P_PRODUCTION": "1"})
        assert res.returncode == 2


def test_production_node_requires_psk():
    res = _run(["node", "--role", "responder"], env={"P2P_PRODUCTION": "1"})
    assert res.returncode == 2
    assert "No PSK" in res.stdout or "PSK" in res.stdout


def test_lab_mode_required_for_demo_even_outside_production():
    res = _run(["demo"])
    assert res.returncode == 2
    assert "LAB GATE" in res.stdout or "lab" in res.stdout.lower()


def test_production_node_requires_mutual_auth_material():
    """PSK alone is not enough on the production path."""
    with tempfile.TemporaryDirectory() as td:
        psk = Path(td) / "shared.psk"
        psk.write_text("ab" * 32 + "\n", encoding="utf-8")
        res = _run(
            ["node", "--role", "responder", "--psk-file", str(psk)],
            env={"P2P_PRODUCTION": "1"},
        )
    assert res.returncode == 2
    assert "Mutual ML-DSA-87" in res.stdout or "auth-sk-file" in res.stdout


def test_production_node_rejects_malformed_auth_material():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        psk = td / "shared.psk"
        psk.write_text("ab" * 32 + "\n", encoding="utf-8")
        sk = td / "local.sk"
        pk = td / "peer.pk"
        sk.write_text("00" * 32 + "\n", encoding="utf-8")
        pk.write_text("00" * 32 + "\n", encoding="utf-8")  # too short
        res = _run(
            ["node", "--role", "responder", "--psk-file", str(psk),
             "--auth-sk-file", str(sk), "--peer-auth-pk-file", str(pk)],
            env={"P2P_PRODUCTION": "1"},
        )
    assert res.returncode == 2
    assert "Invalid authentication material" in res.stdout or "expected exactly" in res.stdout


def test_production_refuses_weak_crypto_env_overrides():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        psk = td / "shared.psk"
        psk.write_text("ab" * 32 + "\n", encoding="utf-8")
        sk = td / "local.sk"
        pk = td / "peer.pk"
        sk.write_text("11" * 32 + "\n", encoding="utf-8")
        pk.write_text("22" * 2592 + "\n", encoding="utf-8")
        res = _run(
            ["node", "--role", "responder", "--psk-file", str(psk),
             "--auth-sk-file", str(sk), "--peer-auth-pk-file", str(pk)],
            env={"P2P_PRODUCTION": "1", "P2P_ALLOW_CLASSICAL": "1"},
        )
    assert res.returncode == 2
    assert "crypto-policy self-check failed" in res.stdout
    assert "P2P_ALLOW_CLASSICAL" in res.stdout


def test_help_lists_mutual_auth_flags():
    res = _run(["node", "--help"])
    assert res.returncode == 0
    for token in ("--auth-sk-file", "--peer-auth-pk-file", "--require-mutual-auth"):
        assert token in res.stdout


def test_selftest_passes():
    res = _run(["selftest"], timeout=300)
    assert res.returncode == 0, res.stdout[-1000:]
    assert "8/8 passed" in res.stdout or "passed" in res.stdout


def test_weak_tokens_absent_from_active_rust_code():
    src_dir = REPO / "rust_data_plane" / "src"
    import re
    forbidden = re.compile(r"\b(x25519|curve25519|chacha20|p-256|secp256r1)\b", re.I)
    for path in src_dir.glob("*.rs"):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            code = line.split("//", 1)[0]
            assert not forbidden.search(code), f"weak token in {path.name}: {line.strip()}"


def test_production_node_with_require_hardware_fails_closed():
    """Operational mode must fail closed on standard workstation lacking physical HSM/FIPS provider."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        psk = td / "shared.psk"
        psk.write_text("ab" * 32 + "\n", encoding="utf-8")
        sk = td / "local.sk"
        pk = td / "peer.pk"
        sk.write_text("11" * 32 + "\n", encoding="utf-8")
        pk.write_text("22" * 2592 + "\n", encoding="utf-8")
        res = _run(
            ["node", "--role", "responder", "--psk-file", str(psk),
             "--auth-sk-file", str(sk), "--peer-auth-pk-file", str(pk),
             "--require-hardware"],
        )
    assert res.returncode in (1, 2)
    assert "Hardware readiness not compliant" in res.stdout or "Refusing under strict hardware policy" in res.stdout

