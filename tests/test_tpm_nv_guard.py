#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""TPM NV monotonic-counter guard — end-to-end proof of the F-01 residual.

The Rust data plane can bind send-seq reservations to a TPM 2.0 NV counter
(`P2P_TPM_NV_INDEX`, see `destroyer_core::tpm_nv`). This suite drives the
REAL secure-transmit binary against fake tpm2-tools (file-backed counter
emitting authentic RC 0x18B / RC 0x14A / already-defined responses) and
proves:

1. Disabled (env unset): unchanged behavior — no `.nvck` sidecar is created.
2. Enabled: consecutive sends succeed, the counter advances, and an
   authenticated `<state>.nvck` checkpoint chain is written.
3. State-only rollback is refused by the NV checkpoint (send_seq behind).
4. The full F-01 residual — restoring state + `.seqlog` + `.nvck` to an old
   consistent triple — is refused because the counter generation cannot be
   rolled back in software.
5. `P2P_TPM_NV_REPROVISION=1` is the explicit operator recovery from 4.

No real TPM is touched: tool paths are overridden per subprocess via
P2P_TPM2_NVREAD / P2P_TPM2_NVINCREMENT / P2P_TPM2_NVDEFINE.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__file__).resolve().parent.parent
CRATE = ROOT / "rust_data_plane"
BIN = CRATE / "target" / "debug" / (
    "secure-transmit.exe" if os.name == "nt" else "secure-transmit")

FAKE_TPM2_PY = '''\
"""File-backed fake tpm2-tools for the NV guard e2e tests.

Semantics mirror the real tools:
  nvread       -> 16 hex chars on stdout; RC 0x18B if index undefined,
                  RC 0x14A if defined but never incremented.
  nvincrement  -> silent success; first increment initializes to 1.
  nvdefine     -> fails "already defined" on the second call (exercises
                  the idempotent-define path in ToolsTransport).
"""
import os
import struct
import sys
from pathlib import Path


def main() -> int:
    tool = sys.argv[1]
    d = Path(os.environ["FAKE_TPM_DIR"])
    d.mkdir(parents=True, exist_ok=True)
    cfile = d / "counter.bin"
    wfile = d / "written.flag"

    def not_defined() -> int:
        sys.stderr.write(
            "ERROR:esys: Failed to read NVRAM area at index\\n"
            "ERROR: tpm:handle(1):the handle is not correct for the use (0x18B)\\n")
        return 1

    if tool == "nvread":
        if not cfile.exists():
            return not_defined()
        if not wfile.exists():
            sys.stderr.write(
                "ERROR: tpm: an NV Index is used before being initialized "
                "(0x0000014a)\\n")
            return 1
        value = struct.unpack(">Q", cfile.read_bytes())[0]
        print(format(value, "016x"))
        return 0
    if tool == "nvincrement":
        if not cfile.exists():
            return not_defined()
        if wfile.exists():
            value = struct.unpack(">Q", cfile.read_bytes())[0] + 1
        else:
            value = 1
        cfile.write_bytes(struct.pack(">Q", value))
        wfile.write_text("1", encoding="ascii")
        return 0
    if tool == "nvdefine":
        if cfile.exists():
            sys.stderr.write("ERROR: NV index already defined\\n")
            return 1
        cfile.write_bytes(b"")  # defined, TPMA_NV_WRITTEN still clear
        return 0
    sys.stderr.write(f"fake_tpm2: unknown tool {tool}\\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


@pytest.fixture(scope="module", autouse=True)
def _built_binary():
    if shutil.which("cargo") is None:
        pytest.skip("cargo toolchain absent")
    built = subprocess.run(
        ["cargo", "build", "--offline", "--bin", "secure-transmit"],
        capture_output=True, text=True, timeout=600, cwd=str(CRATE))
    assert built.returncode == 0, built.stderr[-2000:]
    assert BIN.exists()


def _install_fake_tools(wd: Path) -> dict:
    """Create per-tool wrappers + return the tool-path env overrides."""
    wd.mkdir(parents=True, exist_ok=True)
    script = wd / "fake_tpm2.py"
    script.write_text(FAKE_TPM2_PY, encoding="utf-8")
    env = {}
    for tool in ("nvread", "nvincrement", "nvdefine"):
        if os.name == "nt":
            wrapper = wd / f"fake_{tool}.cmd"
            wrapper.write_text(
                f'@"{sys.executable}" "{script}" {tool} %*\r\n',
                encoding="utf-8")
        else:
            wrapper = wd / f"fake_{tool}"
            wrapper.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "{script}" {tool} "$@"\n',
                encoding="utf-8")
            os.chmod(wrapper, 0o700)
        env[f"P2P_TPM2_{tool.upper()}"] = str(wrapper)
    return env


def _run_bin(*argv, env_extra=None, timeout=60):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run([str(BIN), *argv], capture_output=True, text=True,
                          timeout=timeout, cwd=str(CRATE), env=env)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _seq_of(proc) -> int:
    m = re.search(r"sent seq=(\d+)", proc.stderr)
    assert m, proc.stderr[-800:]
    return int(m.group(1))


def _keyfile(tmp: Path, key_hex: str) -> str:
    p = tmp / "frame.key"
    p.write_text(key_hex.strip() + "\n", encoding="ascii")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return str(p)


def _send(key_file: str, state: str, port: int, msg: str, env_extra=None):
    r = _run_bin("send", "--key-file", key_file, "--state", state,
                 "--to", f"127.0.0.1:{port}", "--msg", msg,
                 env_extra=env_extra)
    return r, (_seq_of(r) if r.returncode == 0 else None)


def _counter(env_extra) -> int:
    """-1 = undefined, -2 = defined but uninitialized, else counter value."""
    p = Path(env_extra["FAKE_TPM_DIR"]) / "counter.bin"
    if not p.exists():
        return -1
    data = p.read_bytes()
    if not data:
        return -2
    return int.from_bytes(data, "big")


def _nv_env(tmp_path: Path) -> dict:
    env = _install_fake_tools(tmp_path / "tools")
    env["FAKE_TPM_DIR"] = str(tmp_path / "faketpm")
    env["P2P_TPM_NV_INDEX"] = "0x1500016"
    return env


def test_disabled_env_creates_no_sidecar(tmp_path):
    """Guard off (P2P_TPM_NV_INDEX unset): identical behavior, no .nvck."""
    key_hex = _run_bin("keygen").stdout.strip()
    kf = _keyfile(tmp_path, key_hex)
    state = str(tmp_path / "send.state")
    port = _free_port()
    r1, n1 = _send(kf, state, port, "ALFA-1")
    assert r1.returncode == 0, r1.stderr[-800:]
    r2, n2 = _send(kf, state, port, "ALFA-2")
    assert r2.returncode == 0, r2.stderr[-800:]
    assert n2 == n1 + 1
    assert not Path(state + ".nvck").exists(), (
        "NV checkpoint sidecar must not appear while the guard is disabled")


def test_enabled_guard_checkpoints_and_advances(tmp_path):
    """Two sends succeed; counter advances; authenticated chain exists."""
    env = _nv_env(tmp_path)
    key_hex = _run_bin("keygen").stdout.strip()
    kf = _keyfile(tmp_path, key_hex)
    state = str(tmp_path / "send.state")
    port = _free_port()
    r1, n1 = _send(kf, state, port, "BRAVO-1", env)
    assert r1.returncode == 0, r1.stderr[-800:]
    r2, n2 = _send(kf, state, port, "BRAVO-2", env)
    assert r2.returncode == 0, r2.stderr[-800:]
    assert n2 == n1 + 1
    assert _counter(env) == 2, "NV counter must advance once per reservation"
    sidecar = Path(state + ".nvck")
    assert sidecar.exists(), "checkpoint sidecar missing"
    lines = [x for x in sidecar.read_text().splitlines() if x.strip()]
    assert len(lines) == 2, lines
    gen1, seq1, tag1 = lines[0].split()
    gen2, seq2, tag2 = lines[1].split()
    assert (int(gen1), int(gen2)) == (1, 2)
    assert (int(seq1), int(seq2)) == (n1 + 1, n2 + 1)
    assert len(tag1) == len(tag2) == 64


def test_state_only_rollback_refused_by_nv_checkpoint(tmp_path):
    """Restore only the state file: send_seq is behind the NV checkpoint."""
    env = _nv_env(tmp_path)
    key_hex = _run_bin("keygen").stdout.strip()
    kf = _keyfile(tmp_path, key_hex)
    state = str(tmp_path / "send.state")
    port = _free_port()
    r1, n1 = _send(kf, state, port, "CHARLIE-1", env)
    assert r1.returncode == 0, r1.stderr[-800:]
    snap = Path(state).read_bytes()
    r2, n2 = _send(kf, state, port, "CHARLIE-2", env)
    assert r2.returncode == 0, r2.stderr[-800:]

    Path(state).write_bytes(snap)  # ATTACK: roll back the state only
    r3, _ = _send(kf, state, port, "CHARLIE-DUP", env)
    assert r3.returncode != 0, "state rollback was re-accepted"
    assert "behind NV checkpoint" in r3.stderr, r3.stderr[-800:]
    assert "sent seq=" not in r3.stderr


def test_full_triple_rollback_refused_by_hardware_counter(tmp_path):
    """THE F-01 residual: state + .seqlog + .nvck all restored to an old
    consistent triple — only the (un-rollbackable) counter generation
    distinguishes it, and the guard must refuse."""
    env = _nv_env(tmp_path)
    key_hex = _run_bin("keygen").stdout.strip()
    kf = _keyfile(tmp_path, key_hex)
    state = str(tmp_path / "send.state")
    port = _free_port()
    r1, n1 = _send(kf, state, port, "DELTA-1", env)
    assert r1.returncode == 0, r1.stderr[-800:]
    triple = {
        name: Path(state + suffix).read_bytes()
        for name, suffix in (("state", ""), ("seqlog", ".seqlog"),
                             ("nvck", ".nvck"))
    }
    r2, n2 = _send(kf, state, port, "DELTA-2", env)
    assert r2.returncode == 0, r2.stderr[-800:]
    assert _counter(env) == 2

    # ATTACK: rewind every software artifact to the first-send snapshot.
    Path(state).write_bytes(triple["state"])
    Path(state + ".seqlog").write_bytes(triple["seqlog"])
    Path(state + ".nvck").write_bytes(triple["nvck"])
    r3, _ = _send(kf, state, port, "DELTA-DUP", env)
    assert r3.returncode != 0, (
        "state+seqlog+nvck rollback re-accepted — hardware residual not closed")
    assert "ahead of sidecar" in r3.stderr, r3.stderr[-800:]
    assert "sent seq=" not in r3.stderr
    assert _counter(env) == 2, "counter itself must be untouched by rollback"


def test_reprovision_env_is_explicit_recovery(tmp_path):
    """P2P_TPM_NV_REPROVISION=1 re-anchors the chain after operator ack."""
    env = _nv_env(tmp_path)
    key_hex = _run_bin("keygen").stdout.strip()
    kf = _keyfile(tmp_path, key_hex)
    state = str(tmp_path / "send.state")
    port = _free_port()
    r1, n1 = _send(kf, state, port, "ECHO-1", env)
    assert r1.returncode == 0, r1.stderr[-800:]
    snap = {
        name: Path(state + suffix).read_bytes()
        for name, suffix in (("state", ""), ("seqlog", ".seqlog"),
                             ("nvck", ".nvck"))
    }
    r2, _ = _send(kf, state, port, "ECHO-2", env)
    assert r2.returncode == 0, r2.stderr[-800:]

    Path(state).write_bytes(snap["state"])
    Path(state + ".seqlog").write_bytes(snap["seqlog"])
    Path(state + ".nvck").write_bytes(snap["nvck"])

    # Without the flag: refused (fail-closed).
    r3, _ = _send(kf, state, port, "ECHO-DUP", env)
    assert r3.returncode != 0
    assert "P2P_TPM_NV_REPROVISION" in r3.stderr, r3.stderr[-800:]

    # With the explicit operator acknowledgment: chain re-anchored, send works.
    env_ack = dict(env)
    env_ack["P2P_TPM_NV_REPROVISION"] = "1"
    r4, _ = _send(kf, state, port, "ECHO-ACK", env_ack)
    assert r4.returncode == 0, r4.stderr[-800:]


def test_invalid_index_env_is_fail_closed(tmp_path):
    """A malformed P2P_TPM_NV_INDEX must refuse, not silently disable."""
    env = _nv_env(tmp_path)
    env["P2P_TPM_NV_INDEX"] = "not-a-number"
    key_hex = _run_bin("keygen").stdout.strip()
    kf = _keyfile(tmp_path, key_hex)
    state = str(tmp_path / "send.state")
    r, _ = _send(kf, state, _free_port(), "FOXTROT", env)
    assert r.returncode != 0
    assert "P2P_TPM_NV_INDEX" in r.stderr, r.stderr[-800:]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
