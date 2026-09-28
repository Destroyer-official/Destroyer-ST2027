"""Hardware-provider gates (F1-F7): use the on-desk hardware for real.

Covers with mocked natives (deterministic, no TPM required):
  F1. TBS TPM2_GetRandom framing/chunking/fail-closed (mocked _tbs_lib).
  F2. Linux sysfs PCR reads from a fake sysfs tree (no exec).
  F3. EK DER trimming (synthetic cert + padding) + mocked tpm2_nvread.
  F4. DPAPI scope flags + real user/machine roundtrips (Windows only).
  F5. Host posture shape (never raises; typed fields).
  F6. tpm2-tools seal/unseal argv shapes + fail-closed (mocked tools).
  F7. keyctl trusted attempt (mocked keyctl success + absent paths).

No network. Real TPM never touched (all native boundaries mocked).
"""

import base64
import os
import secrets
import struct

import pytest

import platform_hsm_interface as phi

IS_WINDOWS = phi.IS_WINDOWS
IS_LINUX = phi.IS_LINUX


# ---------------------------------------------------------------------------
# F1. TBS TPM2_GetRandom
# ---------------------------------------------------------------------------

class _FakeTBS:
    """Minimal tbs.dll double speaking TPM2_GetRandom."""

    def __init__(self, rc=0, truncate=False):
        self.submits = []
        self.rc = rc
        self.truncate = truncate
        self.closed = 0

    def Tbsi_Context_Create(self, params, h_ctx):
        import ctypes
        h_ctx._obj.value = 0x1234
        return 0

    def Tbsip_Submit_Command(self, h_ctx, _loc, _pri, cmd, cmd_len,
                             out_buf, out_len):
        import ctypes
        self.submits.append(bytes(cmd[:cmd_len]))
        want = int.from_bytes(bytes(cmd[:cmd_len])[10:12], "big")
        payload = bytes((i % 251 for i in range(want)))
        body = struct.pack(">H", want) + payload
        resp = (b"\x80\x01" + struct.pack(">I", 10 + len(body))
                + struct.pack(">I", self.rc) + body)
        if self.truncate:
            resp = resp[:8]
        n = min(len(resp), out_len._obj.value)
        ctypes.memmove(out_buf, resp, n)
        out_len._obj.value = n
        return 0

    def Tbsip_Context_Close(self, _h_ctx):
        self.closed += 1
        return 0


@pytest.mark.skipif(not IS_WINDOWS, reason="TBS is Windows-only")
def test_tbs_getrandom_framing_and_chunking(monkeypatch):
    fake = _FakeTBS()
    monkeypatch.setattr(phi, "_tbs_lib", fake)
    out = phi._windows_tbs_get_random(70)
    assert len(out) == 70  # nosec: B101
    assert len(fake.submits) == 3  # 32 + 32 + 6  # nosec: B101
    first = fake.submits[0]
    assert first[:2] == b"\x80\x01"  # nosec: B101
    assert int.from_bytes(first[2:6], "big") == 12  # nosec: B101
    assert int.from_bytes(first[6:10], "big") == 0x17B  # nosec: B101
    assert int.from_bytes(first[10:12], "big") == 32  # nosec: B101
    assert fake.closed == 1  # nosec: B101


@pytest.mark.skipif(not IS_WINDOWS, reason="TBS is Windows-only")
def test_tbs_getrandom_tpm_error_fail_closed(monkeypatch):
    monkeypatch.setattr(phi, "_tbs_lib", _FakeTBS(rc=0x14B))
    with pytest.raises(RuntimeError):
        phi._windows_tbs_get_random(32)


@pytest.mark.skipif(not IS_WINDOWS, reason="TBS is Windows-only")
def test_tbs_getrandom_truncated_fail_closed(monkeypatch):
    monkeypatch.setattr(phi, "_tbs_lib", _FakeTBS(truncate=True))
    with pytest.raises(RuntimeError):
        phi._windows_tbs_get_random(32)


def test_tbs_getrandom_bad_size_rejected():
    if not IS_WINDOWS:
        with pytest.raises(RuntimeError):
            phi._windows_tbs_get_random(32)
        return
    with pytest.raises(ValueError):
        phi._windows_tbs_get_random(0)
    with pytest.raises(ValueError):
        phi._windows_tbs_get_random(2048)


# ---------------------------------------------------------------------------
# F2. sysfs PCR reads
# ---------------------------------------------------------------------------

def test_sysfs_pcr_reads(tmp_path):
    bank = tmp_path / "tpm0" / "pcr-sha256"
    bank.mkdir(parents=True)
    (bank / "0").write_text("00" * 32 + "\n", encoding="utf-8")
    (bank / "7").write_text("ab" * 32 + "\n", encoding="utf-8")
    (bank / "9").write_text("not-hex\n", encoding="utf-8")
    out = phi._read_linux_pcr_sysfs(sysfs_base=str(tmp_path))
    assert out == {"0": "0x" + "00" * 32, "7": "0x" + "ab" * 32}  # nosec: B101


def test_sysfs_pcr_absent_is_empty(tmp_path):
    assert phi._read_linux_pcr_sysfs(sysfs_base=str(tmp_path)) == {}  # nosec: B101


# ---------------------------------------------------------------------------
# F3. EK certificate reads
# ---------------------------------------------------------------------------

def _make_synthetic_cert():
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime
    key = ec.generate_private_key(ec.SECP256R1())
    name = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "TEST-EK")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (_x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.DER)


def test_der_trim_handles_nv_padding():
    der = _make_synthetic_cert()
    padded = der + b"\x00" * 256 + b"\xff" * 16
    assert phi._der_trim_certificate(padded) == der  # nosec: B101
    assert phi._der_trim_certificate(b"garbage") is None  # nosec: B101
    assert phi._der_trim_certificate(b"") is None  # nosec: B101


def test_ek_nvread_mocked(monkeypatch):
    if IS_WINDOWS:
        pytest.skip("Linux NV path (mocked subprocess runs anywhere)")
    der = _make_synthetic_cert()
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)

    class _Proc:
        returncode = 0
        stdout = der + b"\x00" * 64
        stderr = b""

    monkeypatch.setattr("subprocess.run", lambda *a, **k: _Proc())
    out = phi.read_ek_certificate_linux()
    assert out is not None  # nosec: B101
    assert out["subject"] == "CN=TEST-EK"  # nosec: B101
    assert out["source"] == "tpm-nv"  # nosec: B101
    assert len(out["sha256_fp"]) == 64  # nosec: B101


def test_ek_nvread_tools_absent(monkeypatch):
    if IS_WINDOWS:
        pytest.skip("Linux NV path")
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert phi.read_ek_certificate_linux() is None  # nosec: B101


# ---------------------------------------------------------------------------
# F4. DPAPI scope
# ---------------------------------------------------------------------------

def test_dpapi_scope_flags(monkeypatch):
    import air_gapped_operation as ago
    monkeypatch.delenv("P2P_DPAPI_MACHINE_SCOPE", raising=False)
    assert ago._dpapi_scope_flags() == 0x1  # nosec: B101
    monkeypatch.setenv("P2P_DPAPI_MACHINE_SCOPE", "1")
    assert ago._dpapi_scope_flags() == 0x5  # nosec: B101


@pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows-only")
def test_dpapi_roundtrips_both_scopes(monkeypatch):
    import air_gapped_operation as ago
    secret = secrets.token_bytes(32)
    monkeypatch.delenv("P2P_DPAPI_MACHINE_SCOPE", raising=False)
    assert ago.win_dpapi_unprotect(ago.win_dpapi_protect(secret)) == secret  # nosec: B101
    monkeypatch.setenv("P2P_DPAPI_MACHINE_SCOPE", "1")
    assert ago.win_dpapi_unprotect(ago.win_dpapi_protect(secret)) == secret  # nosec: B101


# ---------------------------------------------------------------------------
# F5. Posture shape
# ---------------------------------------------------------------------------

def test_host_posture_shape():
    p = phi.get_host_security_posture()
    for key in ("os", "secure_boot", "tpm_present", "tpm_tools", "vbs",
                "hvci", "cred_guard", "kernel_lockdown", "tbs_available",
                "detail"):
        assert key in p, f"missing posture key {key}"  # nosec: B101
    assert p["secure_boot"] in (True, False, None)  # nosec: B101
    assert isinstance(p["tpm_present"], bool)  # nosec: B101
    assert isinstance(p["detail"], dict)  # nosec: B101


# ---------------------------------------------------------------------------
# F6. tpm2-tools seal/unseal (mocked tools)
# ---------------------------------------------------------------------------

class _ToolProc:
    def __init__(self, rc=0, stdout=b"", stderr=b""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr


def _mock_tools(monkeypatch, fail_on=()):
    calls = []

    def _run(argv, **kwargs):
        calls.append(list(argv))
        name = argv[0]
        if name in fail_on:
            return _ToolProc(rc=1, stderr=b"mocked tool failure")
        if name == "tpm2_createpolicy":
            Path = __import__("pathlib").Path
            for i, a in enumerate(argv):
                if a == "-L":
                    Path(argv[i + 1]).write_bytes(b"POLICY" * 8)
            return _ToolProc()
        if name == "tpm2_create":
            Path = __import__("pathlib").Path
            for i, a in enumerate(argv):
                if a == "-u":
                    Path(argv[i + 1]).write_bytes(b"PUB" * 16)
                if a == "-r":
                    Path(argv[i + 1]).write_bytes(b"PRIV" * 16)
            return _ToolProc()
        if name == "tpm2_load":
            return _ToolProc()
        if name == "tpm2_unseal":
            Path = __import__("pathlib").Path
            for i, a in enumerate(argv):
                if a == "-o":
                    Path(argv[i + 1]).write_bytes(_mock_tools.secret)
            return _ToolProc()
        raise AssertionError(f"unexpected tool {name}")

    _mock_tools.secret = b""
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr("subprocess.run", _run)
    return calls


def test_tpm2_seal_unseal_roundtrip_mocked(monkeypatch, tmp_path):
    import tpm_quote
    calls = _mock_tools(monkeypatch)
    _mock_tools.secret = b"sixteen-bytes!!" + b"pad-to-32-bytes........"
    env = tpm_quote.seal_secret_tpm2_tools(_mock_tools.secret)
    assert env["v"] == 2 and env["sealed_by"] == "tpm2-tools-sealed"  # nosec: B101
    assert env["pcr_selector"] == "sha256:0,1,2,3,7"  # nosec: B101
    names = [c[0] for c in calls]
    assert names == ["tpm2_createpolicy", "tpm2_create"]  # nosec: B101
    policy_call = calls[0]
    assert "--policy-pcr" in policy_call  # nosec: B101
    assert "sha256:0,1,2,3,7" in policy_call  # nosec: B101
    create_call = calls[1]
    assert "-G" in create_call and "keyedhash" in create_call  # nosec: B101
    assert "-C" in create_call and "o" in create_call  # nosec: B101
    calls.clear()
    out = tpm_quote.unseal_secret_tpm2_tools(env)
    assert out == _mock_tools.secret  # nosec: B101
    unseal_call = [c for c in calls if c[0] == "tpm2_unseal"][0]
    assert "pcr:sha256:0,1,2,3,7" in unseal_call  # nosec: B101


def test_tpm2_seal_rejects_bad_inputs():
    import tpm_quote
    with pytest.raises(ValueError):
        tpm_quote.seal_secret_tpm2_tools(b"x" * 16, pcr_selector="sha1:0")
    with pytest.raises(ValueError):
        tpm_quote.seal_secret_tpm2_tools(b"x" * 16, pcr_selector="sha256:24")
    with pytest.raises(ValueError):
        tpm_quote.seal_secret_tpm2_tools(b"x" * 129)
    with pytest.raises(TypeError):
        tpm_quote.seal_secret_tpm2_tools(b"")
    with pytest.raises(ValueError):
        tpm_quote.unseal_secret_tpm2_tools({"v": 1})


def test_tpm2_unseal_tool_failure_is_pcr_mismatch(monkeypatch):
    import tpm_quote
    from tpm_quote import PCRMismatchError
    calls = _mock_tools(monkeypatch, fail_on=("tpm2_unseal",))
    _mock_tools.secret = b"0123456789abcdef"
    env = tpm_quote.seal_secret_tpm2_tools(_mock_tools.secret)
    with pytest.raises(PCRMismatchError):
        tpm_quote.unseal_secret_tpm2_tools(env)


def test_software_envelope_labeled():
    import tpm_quote
    pcrs = {0: "00" * 64, 7: "11" * 64}
    env = tpm_quote.seal_secret_to_pcrs(b"secret", pcrs)
    assert env["sealed_by"] == "software-pcr-bound"  # nosec: B101
    assert tpm_quote.unseal_secret_from_pcrs(env, pcrs) == b"secret"  # nosec: B101


# ---------------------------------------------------------------------------
# F7. keyctl trusted attempt (mocked)
# ---------------------------------------------------------------------------

def test_keyctl_absent_graceful(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    out = phi.store_key_kernel_keyring("p2p_test", b"x" * 16)
    assert out["ok"] is False  # nosec: B101
    # Platform gate fires before tool detection on non-Linux hosts.
    assert out["reason"] in ("keyctl not installed", "non-Linux host")  # nosec: B101


def test_keyctl_label_and_size_gates():
    assert phi.store_key_kernel_keyring("bad label!", b"x")["ok"] is False  # nosec: B101
    assert phi.store_key_kernel_keyring("ok", b"")["ok"] is False  # nosec: B101
    assert "128" in phi.store_key_kernel_keyring("ok", b"x" * 129)["reason"]  # nosec: B101


def test_keyctl_trusted_roundtrip_mocked(monkeypatch):
    state = {}

    class _Proc:
        def __init__(self, rc=0, stdout="", stderr=""):
            self.returncode = rc
            self.stdout = stdout
            self.stderr = stderr

    def _run(argv, **kwargs):
        if argv[1] == "add":
            state["id"] = "123456"
            state["hex"] = None
            return _Proc(stdout="123456\n")
        if argv[1] == "padd":
            state["hex"] = argv[2]
            return _Proc()
        if argv[1] == "pipe":
            return _Proc(stdout=(state.get("hex") or "") + "\n")
        if argv[1] == "revoke":
            return _Proc()
        raise AssertionError(argv)

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/keyctl")
    monkeypatch.setattr("subprocess.run", _run)
    if not IS_LINUX:
        out = phi.store_key_kernel_keyring("p2p_test", b"y" * 16)
        assert out["ok"] is False  # honest non-Linux refusal  # nosec: B101
        return
    out = phi.store_key_kernel_keyring("p2p_test", b"y" * 16)
    assert out == {"ok": True, "backend": "kernel-trusted", "id": "123456"}  # nosec: B101
    back = phi.retrieve_key_kernel_keyring("123456")
    assert back == {"ok": True, "secret": b"y" * 16}  # nosec: B101


# ---------------------------------------------------------------------------
# Deployment posture gate
# ---------------------------------------------------------------------------

def test_deployment_host_posture_gate():
    from verify_deployment import DeploymentVerifier, VerificationStatus
    v = DeploymentVerifier()
    assert v.verify_host_posture() is True  # lab: WARN at most, never FAIL  # nosec: B101
    names = [r.check_name for r in v.results]
    assert "Host Posture: SecureBoot" in names  # nosec: B101
    assert "Host Posture: TPM" in names  # nosec: B101

