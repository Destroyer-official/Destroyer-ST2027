"""End-to-end non-mocked verification for ST2027 stream transport,
privilege-separated Tor bridge (`secure-transmit-tor`), Tamaraw 496B Tor cell
quantization, and `--zero-footprint` fail-closed host security gates.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUST_BIN = ROOT / "rust_data_plane" / "target" / "release" / (
    "secure-transmit.exe" if sys.platform == "win32" else "secure-transmit"
)
TOR_BIN = ROOT / "tor_transport" / "target" / "release" / (
    "secure-transmit-tor.exe" if sys.platform == "win32" else "secure-transmit-tor"
)


def _clean_lab_env() -> dict[str, str]:
    env = os.environ.copy()
    for k in ("SECURE_P2P_PRODUCTION", "P2P_PRODUCTION", "P2P_STRICT_SECURITY", "CNSA_2027_STRICT"):
        env.pop(k, None)
    env["P2P_LAB_MODE"] = "1"
    return env


def _provision_identity_and_psk(tmp_path: Path, env: dict[str, str]):
    psk_path = tmp_path / "psk.hex"
    psk_path.write_text("42" * 32, encoding="utf-8")
    os.chmod(psk_path, 0o600)

    i_sk = tmp_path / "init.sk"
    i_pk = tmp_path / "init.pk"
    r_sk = tmp_path / "resp.sk"
    r_pk = tmp_path / "resp.pk"

    for sk, pk in ((i_sk, i_pk), (r_sk, r_pk)):
        subprocess.run(
            [str(RUST_BIN), "auth-keygen", "--out-sk", str(sk), "--out-pk", str(pk)],
            check=True,
            env=env,
            capture_output=True,
            text=True,
        )
    return psk_path, i_sk, i_pk, r_sk, r_pk


@pytest.mark.skipif(not RUST_BIN.exists(), reason="release secure-transmit binary not built")
def test_stream_zero_footprint_roundtrip_and_no_disk_artifacts(tmp_path: Path):
    """Real loopback stream session: in-stream Noise_XXhfs + 496B Tor-aligned
    Tamaraw cells + zero `.state` or temp `.key` artifacts left on disk.
    """
    env = _clean_lab_env()
    psk_path, i_sk, i_pk, r_sk, r_pk = _provision_identity_and_psk(tmp_path, env)

    work_a = tmp_path / "node_resp"
    work_b = tmp_path / "node_init"
    work_a.mkdir()
    work_b.mkdir()

    resp_cmd = [
        str(RUST_BIN),
        "node",
        "--role", "responder",
        "--transport", "stream",
        "--zero-footprint",
        "--bind", "127.0.0.1:0",
        "--psk-file", str(psk_path),
        "--auth-sk-file", str(r_sk),
        "--peer-auth-pk-file", str(i_pk),
        "--quantum", "496",
        "--interval-ms", "20",
        "--tamaraw-l", "8",
        "--recv-count", "1",
        "--drain-ticks", "4",
        "--timeout-ms", "15000",
        "--headless",
    ]
    resp = subprocess.Popen(
        resp_cmd,
        cwd=work_a,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        listen_addr = None
        resp_lines: list[str] = []
        deadline = time.monotonic() + 10.0
        assert resp.stdout is not None
        while time.monotonic() < deadline:
            line = resp.stdout.readline()
            if not line:
                break
            resp_lines.append(line.strip())
            m = re.search(r"stream:\s+LISTENING\s+addr=(\S+)", line)
            if m:
                listen_addr = m.group(1)
                break

        assert listen_addr is not None, f"Responder failed to bind stream: {resp_lines}"

        def _drain_resp():
            assert resp.stdout is not None
            for extra in resp.stdout:
                resp_lines.append(extra.strip())

        t = threading.Thread(target=_drain_resp, daemon=True)
        t.start()

        init_res = subprocess.run(
            [
                str(RUST_BIN),
                "node",
                "--role", "initiator",
                "--transport", "stream",
                "--zero-footprint",
                "--to", listen_addr,
                "--psk-file", str(psk_path),
                "--auth-sk-file", str(i_sk),
                "--peer-auth-pk-file", str(r_pk),
                "--quantum", "496",
                "--interval-ms", "20",
                "--tamaraw-l", "8",
                "--msg", "MILITARY-STREAM-TOR-QUANTUM-496",
                "--count", "12",
                "--timeout-ms", "15000",
                "--headless",
            ],
            cwd=work_b,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert init_res.returncode == 0, init_res.stdout + init_res.stderr
        assert "quantum=496B" in init_res.stdout
        assert "zero_footprint=true" in init_res.stdout
        if sys.platform == "win32":
            assert "dumps_suppressed=true" in init_res.stdout

        resp.wait(timeout=15)
        t.join(timeout=5)
        joined_resp = "\n".join(resp_lines)
        assert resp.returncode == 0, joined_resp
        assert "MILITARY-STREAM-TOR-QUANTUM-496" in joined_resp
        assert "ZEROIZE_AND_TERMINATED" in joined_resp

        # Verify zero .state / key artifacts leaked in either node's CWD.
        assert list(work_a.iterdir()) == []
        assert list(work_b.iterdir()) == []
    finally:
        if resp.poll() is None:
            resp.kill()
            resp.wait(timeout=5)


@pytest.mark.skipif(not RUST_BIN.exists(), reason="release secure-transmit binary not built")
def test_zero_footprint_refuses_static_key_fail_closed(tmp_path: Path):
    """--zero-footprint must fail closed when combined with --key-file."""
    env = _clean_lab_env()
    kf = tmp_path / "raw.key"
    kf.write_text("11" * 32, encoding="utf-8")
    res = subprocess.run(
        [
            str(RUST_BIN),
            "node",
            "--role", "responder",
            "--transport", "stream",
            "--zero-footprint",
            "--bind", "127.0.0.1:0",
            "--key-file", str(kf),
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
    assert "refuses static --key-file" in (res.stderr + res.stdout)


@pytest.mark.skipif(not RUST_BIN.exists(), reason="release secure-transmit binary not built")
def test_tor_production_requires_client_auth_v3_fail_closed(tmp_path: Path):
    """In production posture, Tor nodes must refuse launching without ClientAuthV3."""
    env = os.environ.copy()
    env["SECURE_P2P_PRODUCTION"] = "1"
    env.pop("P2P_LAB_MODE", None)
    psk = tmp_path / "psk.hex"
    psk.write_text("33" * 32, encoding="utf-8")
    os.chmod(psk, 0o600)
    sk = tmp_path / "r.sk"
    pk = tmp_path / "p.pk"
    subprocess.run(
        [str(RUST_BIN), "auth-keygen", "--out-sk", str(sk), "--out-pk", str(pk)],
        check=True,
        env=_clean_lab_env(),
        capture_output=True,
    )

    resp = subprocess.run(
        [
            str(RUST_BIN),
            "node",
            "--role", "responder",
            "--tor",
            "--zero-footprint",
            "--psk-file", str(psk),
            "--auth-sk-file", str(sk),
            "--peer-auth-pk-file", str(pk),
            "--headless",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert resp.returncode != 0
    err = resp.stderr + resp.stdout
    assert ("--onion-client-auth-pk" in err) or ("plaintext disk --auth-sk-file" in err)


@pytest.mark.skipif(not TOR_BIN.exists(), reason="release secure-transmit-tor binary not built")
def test_tor_bridge_client_auth_keygen_and_clearnet_refusal():
    """Verify embedded Arti bridge generates valid ClientAuthV3 keys and refuses clearnet/IP targets."""
    gen = subprocess.run(
        [str(TOR_BIN), "--mode", "client-auth-keygen"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert re.search(r"CLIENT_AUTH_PK=descriptor:x25519:[A-Z2-7]{52}", gen.stdout)
    assert re.search(r"CLIENT_AUTH_SK_HEX=[0-9a-f]{64}", gen.stdout)

    bad = subprocess.run(
        [str(TOR_BIN), "--mode", "initiator", "--to", "example.com:443"],
        capture_output=True,
        text=True,
    )
    assert bad.returncode != 0
    assert ".onion" in (bad.stderr + bad.stdout)


@pytest.mark.skipif(
    not (RUST_BIN.exists() and TOR_BIN.exists()),
    reason="release binaries not built",
)
def test_tor_bridge_bad_sha384_pin_refused_fail_closed(tmp_path: Path):
    """--tor-bridge-sha384 must verify the exact SHA-384 of secure-transmit-tor before spawning."""
    env = _clean_lab_env()
    psk_path, i_sk, _i_pk, _r_sk, r_pk = _provision_identity_and_psk(tmp_path, env)
    gen = subprocess.run(
        [str(TOR_BIN), "--mode", "client-auth-keygen"],
        check=True,
        capture_output=True,
        text=True,
    )
    m_sk = re.search(r"CLIENT_AUTH_SK_HEX=([0-9a-f]{64})", gen.stdout)
    assert m_sk is not None
    cauth_sk = tmp_path / "client_auth.sk"
    cauth_sk.write_text(m_sk.group(1), encoding="utf-8")

    # Wrong 96-hex SHA-384 pin must fail closed before spawning Tor.
    wrong_pin = "00" * 48
    res = subprocess.run(
        [
            str(RUST_BIN),
            "node",
            "--role", "initiator",
            "--tor",
            "--zero-footprint",
            "--to", "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:443",
            "--psk-file", str(psk_path),
            "--auth-sk-file", str(i_sk),
            "--peer-auth-pk-file", str(r_pk),
            "--onion-auth-sk-file", str(cauth_sk),
            "--tor-bridge-bin", str(TOR_BIN),
            "--tor-bridge-sha384", wrong_pin,
            "--headless",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert res.returncode != 0
    assert "SHA-384 mismatch" in (res.stderr + res.stdout)


@pytest.mark.skipif(not RUST_BIN.exists(), reason="release secure-transmit binary not built")
def test_pt_binary_bad_sha384_pin_refused_fail_closed(tmp_path: Path):
    """--pt-binary with mismatched --pt-sha384 must fail closed before spawning Tor."""
    env = _clean_lab_env()
    psk_path, i_sk, _i_pk, _r_sk, r_pk = _provision_identity_and_psk(tmp_path, env)
    dummy_pt = tmp_path / ("lyrebird.exe" if sys.platform == "win32" else "lyrebird")
    dummy_pt.write_bytes(b"not-a-real-lyrebird-binary")

    res = subprocess.run(
        [
            str(RUST_BIN),
            "node",
            "--role", "initiator",
            "--tor",
            "--zero-footprint",
            "--to", "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:443",
            "--psk-file", str(psk_path),
            "--auth-sk-file", str(i_sk),
            "--peer-auth-pk-file", str(r_pk),
            "--pt-binary", str(dummy_pt),
            "--pt-type", "webtunnel",
            "--pt-bridge", "webtunnel 127.0.0.1:443 0000000000000000000000000000000000000000 url=https://example.com/",
            "--pt-sha384", "ff" * 48,
            "--headless",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert res.returncode != 0
    assert "SHA-384 mismatch" in (res.stderr + res.stdout)


def test_secure_p2p_cli_node_tor_gates_and_stream_roundtrip(tmp_path: Path):
    """secure_p2p.py node enforces Tor ClientAuthV3/PT gates in prod and forwards stream/zero-footprint."""
    prod_env = os.environ.copy()
    for weak_var in (
        "P2P_LAB_MODE",
        "P2P_ALLOW_CLASSICAL",
        "P2P_ALLOW_INSECURE_PLAINTEXT",
        "P2P_ALLOW_UNVERIFIED_TOFU",
        "P2P_ALLOW_INSECURE_DANE_BYPASS",
        "P2P_ALLOW_UNKEYED_CHUNKS",
        "P2P_ALLOW_LEGACY_CERTS",
        "P2P_ALLOW_LEGACY_KEY_MIGRATION",
        "P2P_ALLOW_LEGACY_AUDIT_CHAIN",
        "P2P_ALLOW_LEGACY_WORM_CHAIN",
        "P2P_ALLOW_SOFTWARE_FALLBACK",
        "P2P_REQUIRE_AUTH",
    ):
        prod_env.pop(weak_var, None)
    prod_env["P2P_PRODUCTION"] = "1"

    psk = tmp_path / "psk.hex"
    psk.write_text("77" * 32, encoding="utf-8")
    os.chmod(psk, 0o600)
    pk = tmp_path / "peer.pk"
    pk.write_text("01" * 2592, encoding="utf-8")
    os.chmod(pk, 0o600)

    # 1. Production --tor responder without --onion-client-auth-pk fails closed.
    r1 = subprocess.run(
        [
            sys.executable, str(ROOT / "secure_p2p.py"), "node",
            "--role", "responder",
            "--tor",
            "--zero-footprint",
            "--psk-file", str(psk),
            "--auth-pkcs11-label", "HSM_KEY",
            "--auth-pk-file", str(pk),
            "--peer-auth-pk-file", str(pk),
        ],
        env=prod_env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r1.returncode != 0
    assert "ClientAuthV3" in (r1.stdout + r1.stderr)

    # 2. Production --pt-binary without --pt-sha384 fails closed.
    dummy_pt = tmp_path / "lyrebird"
    dummy_pt.write_bytes(b"pt")
    r2 = subprocess.run(
        [
            sys.executable, str(ROOT / "secure_p2p.py"), "node",
            "--role", "responder",
            "--tor",
            "--onion-client-auth-pk", "descriptor:x25519:" + ("A" * 52),
            "--pt-binary", str(dummy_pt),
            "--psk-file", str(psk),
            "--auth-pkcs11-label", "HSM_KEY",
            "--auth-pk-file", str(pk),
            "--peer-auth-pk-file", str(pk),
        ],
        env=prod_env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r2.returncode != 0
    assert "--pt-sha384" in (r2.stdout + r2.stderr)

    # 3. Real stream loopback launch via secure_p2p.py node --transport stream --zero-footprint + /rekey
    if not RUST_BIN.exists():
        return
    env = _clean_lab_env()
    psk_path, i_sk, i_pk, r_sk, r_pk = _provision_identity_and_psk(tmp_path, env)
    resp = subprocess.Popen(
        [
            sys.executable, "-u", str(ROOT / "secure_p2p.py"), "node",
            "--role", "responder",
            "--transport", "stream",
            "--zero-footprint",
            "--bind", "127.0.0.1:0",
            "--psk-file", str(psk_path),
            "--auth-sk-file", str(r_sk),
            "--peer-auth-pk-file", str(i_pk),
            "--quantum", "496",
            "--interval-ms", "20",
            "--tamaraw-l", "8",
            "--recv-count", "1",
            "--drain-ticks", "40",
            "--timeout-ms", "25000",
            "--headless",
        ],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        listen_addr = None
        lines: list[str] = []
        deadline = time.monotonic() + 20.0
        assert resp.stdout is not None
        while time.monotonic() < deadline:
            ln = resp.stdout.readline()
            if not ln:
                break
            lines.append(ln.strip())
            m = re.search(r"stream:\s+LISTENING\s+addr=(\S+)", ln)
            if m:
                listen_addr = m.group(1)
                break
        assert listen_addr is not None, "\n".join(lines)

        t = threading.Thread(
            target=lambda: lines.extend(x.strip() for x in resp.stdout),  # type: ignore[union-attr]
            daemon=True,
        )
        t.start()

        # Initiator sends /rekey then payload via stdin to exercise interactive PQ epoch rotation + dispatch
        init_res = subprocess.run(
            [
                sys.executable, str(ROOT / "secure_p2p.py"), "node",
                "--role", "initiator",
                "--transport", "stream",
                "--zero-footprint",
                "--to", listen_addr,
                "--psk-file", str(psk_path),
                "--auth-sk-file", str(i_sk),
                "--peer-auth-pk-file", str(r_pk),
                "--quantum", "496",
                "--interval-ms", "20",
                "--tamaraw-l", "8",
                "--stdin",
                "--headless",
                "--count", "80",
                "--timeout-ms", "25000",
            ],
            input="/rekey\nDISPATCHER-STREAM-REKEY-OK\n",
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert init_res.returncode == 0, init_res.stdout + init_res.stderr
        resp.wait(timeout=15)
        t.join(timeout=5)
        joined = "\n".join(lines)
        assert resp.returncode == 0, joined
        assert "DISPATCHER-STREAM-REKEY-OK" in joined
        assert "Stream epoch advanced to 1" in joined, joined
    finally:
        if resp.poll() is None:
            resp.kill()
            resp.wait(timeout=5)


def test_stream_zero_footprint_doc_transfer_and_sha384_verification(tmp_path: Path):
    """Multi-fragment /doc transfer over 496B Tor-aligned stream with SHA-384 + safe filename checks."""
    if not RUST_BIN.exists():
        pytest.skip("rust release binary not built")
    env = _clean_lab_env()
    psk_path, i_sk, i_pk, r_sk, r_pk = _provision_identity_and_psk(tmp_path, env)

    src_doc = tmp_path / "sitrep_alpha.txt"
    doc_payload = (b"CLASSIFIED-TEST-SITREP-CELL-001 " * 64) + b"END"
    src_doc.write_bytes(doc_payload)
    expected_sha384 = hashlib.sha384(doc_payload).hexdigest()

    recv_dir = tmp_path / "received_docs"
    recv_dir.mkdir()

    resp = subprocess.Popen(
        [
            sys.executable, "-u", str(ROOT / "secure_p2p.py"), "node",
            "--role", "responder",
            "--transport", "stream",
            "--zero-footprint",
            "--bind", "127.0.0.1:0",
            "--psk-file", str(psk_path),
            "--auth-sk-file", str(r_sk),
            "--peer-auth-pk-file", str(i_pk),
            "--recv-dir", str(recv_dir),
            "--quantum", "496",
            "--interval-ms", "15",
            "--tamaraw-l", "8",
            "--recv-count", "1",
            "--drain-ticks", "24",
            "--timeout-ms", "25000",
            "--headless",
        ],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        listen_addr = None
        lines: list[str] = []
        deadline = time.monotonic() + 20.0
        assert resp.stdout is not None
        while time.monotonic() < deadline:
            ln = resp.stdout.readline()
            if not ln:
                break
            lines.append(ln.strip())
            m = re.search(r"stream:\s+LISTENING\s+addr=(\S+)", ln)
            if m:
                listen_addr = m.group(1)
                break
        assert listen_addr is not None, "\n".join(lines)

        t = threading.Thread(
            target=lambda: lines.extend(x.strip() for x in resp.stdout),  # type: ignore[union-attr]
            daemon=True,
        )
        t.start()

        init_res = subprocess.run(
            [
                sys.executable, str(ROOT / "secure_p2p.py"), "node",
                "--role", "initiator",
                "--transport", "stream",
                "--zero-footprint",
                "--to", listen_addr,
                "--psk-file", str(psk_path),
                "--auth-sk-file", str(i_sk),
                "--peer-auth-pk-file", str(r_pk),
                "--quantum", "496",
                "--interval-ms", "15",
                "--tamaraw-l", "8",
                "--stdin",
                "--headless",
                "--count", "60",
                "--timeout-ms", "25000",
            ],
            input=f"/doc {src_doc}\n",
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=25,
        )
        assert init_res.returncode == 0, init_res.stdout + init_res.stderr
        assert "[DOC_TRANSFER] Queued file=sitrep_alpha.txt" in init_res.stdout
        resp.wait(timeout=15)
        t.join(timeout=5)
        joined = "\n".join(lines)
        assert resp.returncode == 0, joined
        assert f"RECV_DOC" in joined and f"sha384={expected_sha384}" in joined, joined
        out_doc = recv_dir / "sitrep_alpha.txt"
        assert out_doc.is_file()
        assert out_doc.read_bytes() == doc_payload
    finally:
        if resp.poll() is None:
            resp.kill()
            resp.wait(timeout=5)
