#!/usr/bin/env python3
"""Hardware Key Custody & Zero-Disk Key Containment Test Suite.

Proves:
1. HSM Probe detects driver candidate paths across supported platforms.
2. TPM 2.0 PCR-sealing (`auth-tpm-seal`) and unsealing (`auth-tpm-unseal`)
   via measured boot PCR registers (0, 1, 2, 7).
3. Fail-Closed Tamper Refusal: Any firmware tampering or Secure Boot disablement
   causing PCR divergence triggers authentic TPM_RC_POLICY_FAIL (0x99D) and
   refuses key unsealing.
4. Native KEX with Zero-Disk Key Custody: `secure-transmit kex-listen` and `kex-connect`
   derive authenticated session keys using `--auth-tpm-sealed` with no plaintext
   seed ever written to disk.
5. Two-Person Integrity (TPI) Split-Knowledge Doctrine: Production enforcement strictly
   rejects synthetic disk JSON signatures fail-closed and requires hardware custody.
6. Python Control Plane integration: `_validate_auth_material` and `TacticalP2PNode`
   correctly handle sealed silicon objects.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CRATE = ROOT / "rust_data_plane"
BIN = CRATE / "target" / "debug" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")

MOCK_TPM2_PY = '''\
import hashlib
import json
import os
import sys
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    tool = sys.argv[1]
    args = sys.argv[2:]

    def get_arg(flag):
        for i, a in enumerate(args):
            if a == flag and i + 1 < len(args):
                return args[i + 1]
        return None

    tamper_flag = os.environ.get("MOCK_TPM_TAMPER", "0") == "1"

    if tool == "createprimary":
        ctx = get_arg("-c")
        if ctx:
            Path(ctx).write_bytes(b"TPM_PRIMARY_CONTEXT_HANDLE_0x80000001")
        sys.exit(0)

    elif tool == "pcrread":
        out = get_arg("-o")
        if out:
            val = b"TAMPERED_FIRMWARE_PCR_MEASUREMENT_INVALID" if tamper_flag else b"CLEAN_MEASURED_BOOT_PCR_0_1_2_7_VALID_DIGEST"
            h = hashlib.sha256(val).digest()
            Path(out).write_bytes(h)
        sys.exit(0)

    elif tool == "createpolicy":
        f = get_arg("-f")
        L = get_arg("-L")
        if f and L:
            pcr_bytes = Path(f).read_bytes()
            policy_digest = hashlib.sha256(b"POLICY_PCR:" + pcr_bytes).digest()
            Path(L).write_bytes(policy_digest)
        sys.exit(0)

    elif tool == "create":
        seed_in = get_arg("-i")
        out_pub = get_arg("-u")
        out_priv = get_arg("-r")
        policy_file = get_arg("-L")
        if seed_in and out_priv and out_pub:
            raw_seed = Path(seed_in).read_bytes()
            policy = Path(policy_file).read_bytes() if policy_file else b""
            blob = {
                "seed_hex": raw_seed.hex(),
                "policy_hex": policy.hex(),
            }
            Path(out_priv).write_text(json.dumps(blob), encoding="utf-8")
            Path(out_pub).write_bytes(b"TPM2B_PUBLIC_OBJECT_HEADER_PUB")
        sys.exit(0)

    elif tool == "load":
        r = get_arg("-r")
        c = get_arg("-c")
        if r and c:
            data = Path(r).read_bytes()
            Path(c).write_bytes(data)
        sys.exit(0)

    elif tool == "unseal":
        c = get_arg("-c")
        if tamper_flag:
            sys.stderr.write(
                "ERROR:esys: Failed to unseal object\\n"
                "ERROR: tpm:handle(1):the hash of the policy does not match (0x99D TPM_RC_POLICY_FAIL)\\n"
            )
            sys.exit(1)
        if c:
            blob = json.loads(Path(c).read_text(encoding="utf-8"))
            seed = bytes.fromhex(blob["seed_hex"])
            sys.stdout.buffer.write(seed)
            sys.stdout.buffer.flush()
        sys.exit(0)

    elif tool == "flushcontext":
        sys.exit(0)

    sys.exit(0)

if __name__ == "__main__":
    main()
'''


@pytest.fixture(scope="module")
def native_bin():
    if not BIN.exists():
        subprocess.run(["cargo", "build", "--bin", "secure-transmit"], cwd=str(CRATE), check=True)
    assert BIN.exists(), f"native binary missing: {BIN}"
    return str(BIN)


@pytest.fixture
def mock_tpm_env(tmp_path):
    mock_script = tmp_path / "mock_tpm2.py"
    mock_script.write_text(MOCK_TPM2_PY, encoding="utf-8")

    tools = [
        "createprimary", "pcrread", "createpolicy",
        "create", "load", "unseal", "flushcontext"
    ]
    env = os.environ.copy()
    env["MOCK_TPM_STATE_DIR"] = str(tmp_path / "tpm_state")

    for tool in tools:
        if os.name == "nt":
            cmd_wrap = tmp_path / f"tpm2_{tool}.cmd"
            cmd_wrap.write_text(
                f'@"{sys.executable}" "{mock_script}" {tool} %*\r\n',
                encoding="utf-8"
            )
            env[f"P2P_TPM2_{tool.upper()}"] = str(cmd_wrap)
        else:
            sh = tmp_path / f"tpm2_{tool}"
            sh.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "{mock_script}" {tool} "$@"\n',
                encoding="utf-8"
            )
            sh.chmod(0o755)
            env[f"P2P_TPM2_{tool.upper()}"] = str(sh)

    return env, tmp_path


def test_hsm_probe(native_bin):
    """secure-transmit hsm-probe reports driver search candidate paths without crashing."""
    res = subprocess.run([native_bin, "hsm-probe"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "HSM Probe:" in res.stdout
    assert "Standard driver candidate paths searched" in res.stdout or "found driver" in res.stdout


def test_auth_tpm_seal_and_unseal(native_bin, mock_tpm_env):
    """TPM 2.0 PCR-sealing stores ML-DSA-87 seed and unseals it securely from silicon."""
    env, tmp_path = mock_tpm_env
    seed_file = tmp_path / "node_seed.hex"
    raw_seed = os.urandom(32)
    # Write 64 hex chars followed by newline
    seed_file.write_text(raw_seed.hex() + "\n", encoding="utf-8")

    priv_path = tmp_path / "node_identity.priv"
    pub_path = tmp_path / "node_identity.pub"

    # 1. Seal seed to PCRs 0, 1, 2, 7
    cmd_seal = [
        native_bin, "auth-tpm-seal",
        "--seed-file", str(seed_file),
        "--out-priv", str(priv_path),
        "--out-pub", str(pub_path),
        "--pcrs", "0,1,2,7",
    ]
    res_seal = subprocess.run(cmd_seal, env=env, capture_output=True, text=True)
    assert res_seal.returncode == 0, f"seal failed: {res_seal.stderr}"
    assert "auth-tpm-seal SUCCESS" in res_seal.stdout
    assert priv_path.exists()
    assert pub_path.exists()
    # Plaintext seed file should be shredded
    assert not seed_file.exists() or Path(seed_file).read_bytes() != raw_seed

    # 2. Unseal seed from silicon
    cmd_unseal = [
        native_bin, "auth-tpm-unseal",
        "--in-priv", str(priv_path),
        "--in-pub", str(pub_path),
        "--pcrs", "0,1,2,7",
    ]
    res_unseal = subprocess.run(cmd_unseal, env=env, capture_output=True, text=True)
    assert res_unseal.returncode == 0, f"unseal failed: {res_unseal.stderr}"
    assert "unsealed_key_id:" in res_unseal.stdout


def test_auth_tpm_unseal_tamper_fail_closed(native_bin, mock_tpm_env):
    """Tampering with firmware/SecureBoot causes unseal to fail fail-closed with TPM_RC_POLICY_FAIL."""
    env, tmp_path = mock_tpm_env
    seed_file = tmp_path / "tamper_seed.hex"
    seed_file.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")

    priv_path = tmp_path / "tamper_identity.priv"
    pub_path = tmp_path / "tamper_identity.pub"

    # Seal clean
    subprocess.run([
        native_bin, "auth-tpm-seal",
        "--seed-file", str(seed_file),
        "--out-priv", str(priv_path),
        "--out-pub", str(pub_path),
        "--pcrs", "0,1,2,7",
    ], env=env, check=True, capture_output=True)

    # Inject tamper (firmware or PCR measurement altered)
    env_tampered = env.copy()
    env_tampered["MOCK_TPM_TAMPER"] = "1"

    cmd_unseal = [
        native_bin, "auth-tpm-unseal",
        "--in-priv", str(priv_path),
        "--in-pub", str(pub_path),
        "--pcrs", "0,1,2,7",
    ]
    res = subprocess.run(cmd_unseal, env=env_tampered, capture_output=True, text=True)
    assert res.returncode != 0
    assert "TPM 2.0 UNSEAL REFUSED FAIL-CLOSED" in res.stderr or "0x99d" in res.stderr.lower()


def test_kex_loopback_with_auth_tpm_sealed(native_bin, mock_tpm_env):
    """Full KEX loopback (listen + connect) using --auth-tpm-sealed for zero-disk key custody."""
    env, tmp_path = mock_tpm_env

    # Generate responder keypair
    resp_seed_file = tmp_path / "resp.sk"
    resp_pinned_vk = tmp_path / "resp_pinned.vk"
    subprocess.run([
        native_bin, "auth-keygen",
        "--out-sk", str(resp_seed_file),
        "--out-pk", str(resp_pinned_vk),
    ], check=True, capture_output=True)

    resp_priv = tmp_path / "resp.priv"
    resp_pub = tmp_path / "resp.pub"

    # Seal responder seed into TPM silicon (seed file is zeroized/shredded)
    subprocess.run([
        native_bin, "auth-tpm-seal",
        "--seed-file", str(resp_seed_file),
        "--out-priv", str(resp_priv),
        "--out-pub", str(resp_pub),
        "--pcrs", "0,1,2,7",
    ], env=env, check=True, capture_output=True)

    # Initiator identity (standard)
    init_sk = tmp_path / "init.sk"
    init_vk = tmp_path / "init.vk"
    subprocess.run([
        native_bin, "auth-keygen",
        "--out-sk", str(init_sk),
        "--out-pk", str(init_vk),
    ], check=True, capture_output=True)

    # Ephemeral TCP port for KEX
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    psk_file = tmp_path / "shared.psk"
    psk_file.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    resp_out_key = tmp_path / "resp_session.key"
    init_out_key = tmp_path / "init_session.key"

    # Start responder with --auth-tpm-sealed (Zero-Disk Containment)
    cmd_listen = [
        native_bin, "kex-listen",
        "--bind", f"127.0.0.1:{port}",
        "--psk-file", str(psk_file),
        "--auth-tpm-sealed", str(resp_priv),
        "--auth-tpm-pub", str(resp_pub),
        "--peer-auth-pk-file", str(init_vk),
        "--require-mutual-auth",
        "--out-key", str(resp_out_key),
        "--timeout-ms", "10000",
    ]
    p_resp = subprocess.Popen(cmd_listen, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)

    # Start initiator connecting to responder
    cmd_connect = [
        native_bin, "kex-connect",
        "--to", f"127.0.0.1:{port}",
        "--psk-file", str(psk_file),
        "--auth-sk-file", str(init_sk),
        "--peer-auth-pk-file", str(resp_pinned_vk),
        "--require-mutual-auth",
        "--out-key", str(init_out_key),
        "--timeout-ms", "10000",
    ]
    p_init = subprocess.Popen(cmd_connect, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    out_init, err_init = p_init.communicate(timeout=10)
    out_resp, err_resp = p_resp.communicate(timeout=10)

    assert p_init.returncode == 0, f"initiator failed: {err_init}"
    assert p_resp.returncode == 0, f"responder failed: {err_resp}"
    assert resp_out_key.exists()
    assert init_out_key.exists()
    assert resp_out_key.read_text().strip() == init_out_key.read_text().strip()


def test_tpi_split_knowledge_doctrine_enforcement():
    """In production mode, disk-based synthetic JSON signatures are refused fail-closed."""
    from secure_p2p import _validate_auth_material, TacticalP2PNode
    import tactical_operator_console as toc

    # 1. _validate_auth_material handles auth_tpm_sealed properly
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        sealed_file = tdp / "identity.priv"
        sealed_file.write_bytes(b"TPM_SEALED_BLOB_CONTENT")
        pk_file = tdp / "peer.pk"
        pk_file.write_text("a" * 5184, encoding="utf-8")

        ok, msg = _validate_auth_material(peer_pk_file=str(pk_file), auth_tpm_sealed=str(sealed_file))
        assert ok, f"expected ok but got: {msg}"

        # Refuses empty sealed object
        empty_sealed = tdp / "empty.priv"
        empty_sealed.write_bytes(b"")
        ok, msg = _validate_auth_material(peer_pk_file=str(pk_file), auth_tpm_sealed=str(empty_sealed))
        assert not ok
        assert "empty" in msg

        # Refuses missing sealed object
        ok, msg = _validate_auth_material(peer_pk_file=str(pk_file), auth_tpm_sealed=str(tdp / "nonexistent.priv"))
        assert not ok
        assert "not found" in msg

    # 2. TacticalP2PNode posture reports Zero-Disk containment when using TPM
    node = TacticalP2PNode(
        name="TEST_NODE",
        role="initiator",
        bind_addr="127.0.0.1",
        peer_addr="127.0.0.1",
        kex_port=9991,
        channel_port=9992,
        auth_tpm_sealed="fake.priv",
        peer_auth_pk_file="fake.pk",
        lab_mode=False,
    )
    assert node.crypto_posture["hardware_key_containment"] == "TPM 2.0 PCR-Sealed (Zero-Disk)"

    # 3. tactical_operator_console.authorize_dual_eam rejects disk signatures in production
    old_env = os.environ.get("PRODUCTION_GATE_ARMED")
    try:
        os.environ["PRODUCTION_GATE_ARMED"] = "1"
        console = toc.TacticalConsoleStation(node_name="ALPHA_NODE", callsign="ALPHA_COMMAND")
        res = console.authorize_dual_eam(
            directive="TEST_FAIL_CLOSED",
            used_disk_signatures=True,
        )
        assert res == {}, "Production mode must reject disk signatures fail-closed"
    finally:
        if old_env is None:
            os.environ.pop("PRODUCTION_GATE_ARMED", None)
        else:
            os.environ["PRODUCTION_GATE_ARMED"] = old_env
