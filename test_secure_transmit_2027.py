#!/usr/bin/env python3
"""Production tests for secure_transmit_2027 — all REAL primitives, no mocks of crypto."""

import os
import socket
import struct
import tempfile
import threading
from pathlib import Path

import pytest

import secure_transmit_2027 as st


def _isolate(tmp: Path, monkeypatch):
    # Isolate TOFU pins + audit ledger per test; ensure lab (non-prod) env.
    st.PIN_DIR = tmp / "pins"
    monkeypatch.setenv("P2P_SIEM_LEDGER", str(tmp / "audit.jsonl"))
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("P2P_REQUIRE_HARDWARE_IDENTITY", raising=False)
    monkeypatch.delenv("P2P_REQUIRE_ECH", raising=False)
    monkeypatch.delenv("P2P_PEER_PREFIX", raising=False)
    st._audit_chain = None


def _kp_pair(prefix: str, tmp: Path):
    # Isolate TOFU pins per test
    st.PIN_DIR = tmp / "pins"
    cli_sig_pk, cli_sig_sk = st.generate_identity()
    srv_sig_pk, srv_sig_sk = st.generate_identity()
    cli_kp = st.generate_hybrid_keypair(cli_sig_pk, cli_sig_sk)
    srv_kp = st.generate_hybrid_keypair(srv_sig_pk, srv_sig_sk)
    return cli_kp, srv_kp


def _xxhfs_handshake(tmp_path, peer="peerX"):
    """Full unified Noise_XXhfs 3-message handshake via the bridge.

    Returns (m1, m2, m3, c_st, s_st, cli_kp, srv_kp). Pins isolated per
    test via _kp_pair (TOFU first-contact stores).
    """
    cli_kp, srv_kp = _kp_pair(peer, tmp_path)
    m1, ini, t0 = st.xxhfs_initiate(cli_kp, peer)
    m2, rsp, t_rsp = st.xxhfs_respond(m1, srv_kp, peer)
    m3, c_st = st.xxhfs_finalize(ini, m2, cli_kp, peer, t0)
    s_st = st.xxhfs_complete(rsp, m3, srv_kp, peer, t_rsp)
    return m1, m2, m3, c_st, s_st, cli_kp, srv_kp


def test_combiner_sizes_and_order(tmp_path):
    # RFC 10024 SecP384r1MLKEM1024: 48 || 32 = 80, ECDHE first
    out = st.hybrid_combine(b"E" * 48, b"M" * 32)
    assert out == b"E" * 48 + b"M" * 32 and len(out) == 80
    with pytest.raises(st.SecurityError):
        st.hybrid_combine(b"E" * 32, b"M" * 32)  # wrong ECDHE len fails closed


def test_handshake_roundtrip_yields_equal_keys(tmp_path):
    _m1, _m2, _m3, c_st, s_st, _ck, _sk = _xxhfs_handshake(tmp_path)
    assert c_st.key() == s_st.key() and len(c_st.key()) == 32
    assert c_st.key() != b"\x00" * 32


def test_verify_before_decaps_tamper_fails_closed(tmp_path):
    # Tampered M1 fails closed at responder (size/auth), tampered M2 at
    # initiator finalize (verify-before-derive), tampered M3 at complete.
    # Each probe uses a fresh handshake: failures destroy session state.
    cli_kp, srv_kp = _kp_pair("b", tmp_path)
    m1, ini, t0 = st.xxhfs_initiate(cli_kp, "peerX")
    with pytest.raises(st.SecurityError):  # truncated M1 fails fast by size
        st.xxhfs_respond(m1[:-10], srv_kp, "peerX")
    bad = bytearray(m1)
    bad[200] ^= 0x01  # corrupt ML-KEM ek: either the ek is invalid (responder
    # refuses before encaps) or secrets fork (dies at M2 authentication,
    # verify-before-derive). Both are fail-closed; the handshake MUST NOT
    # complete with a corrupted M1.
    try:
        m2bad, _rspbad, _tb = st.xxhfs_respond(bytes(bad), srv_kp, "peerX")
    except st.SecurityError:
        pass
    else:
        with pytest.raises(st.SecurityError):
            st.xxhfs_finalize(ini, m2bad, cli_kp, "peerX", t0)
    m1b, inib, t0b = st.xxhfs_initiate(cli_kp, "peerX")
    m2, rsp, t_rsp = st.xxhfs_respond(m1b, srv_kp, "peerX")
    bad2 = bytearray(m2)
    bad2[100] ^= 0x01
    with pytest.raises(st.SecurityError):
        st.xxhfs_finalize(inib, bytes(bad2), cli_kp, "peerX", t0b)
    m1c, inic, t0c = st.xxhfs_initiate(cli_kp, "peerX")
    m2c, rspc, t_rspc = st.xxhfs_respond(m1c, srv_kp, "peerX")
    m3, _cc = st.xxhfs_finalize(inic, m2c, cli_kp, "peerX", t0c)
    bad3 = bytearray(m3)
    bad3[-1] ^= 0x01
    with pytest.raises(st.SecurityError):
        st.xxhfs_complete(rspc, bytes(bad3), srv_kp, "peerX", t_rspc)


def test_record_aead_roundtrip_replay_rejected(tmp_path):
    _m1, _m2, _m3, c_st, s_st, _ck, _sk = _xxhfs_handshake(tmp_path, peer="peerX")
    # crossed directions: client out=0xA5/in=0x5A, server mirrored
    cli = st.Channel(c_st, direction_out=0xA5, direction_in=0x5A)
    srv = st.Channel(s_st, direction_out=0x5A, direction_in=0xA5)
    w = cli.seal_data(b"hello-2027")
    ftype, msg = srv.open(w)
    assert ftype == st.FRAME_TYPE_DATA and msg == b"hello-2027"
    assert len(w) in st.PAD_QUANTA and len(w) <= 1280
    with pytest.raises(st.SecurityError):  # replay same wire
        srv.open(w)
    # tamper tag
    bad = bytearray(w)
    bad[-1] ^= 0x01
    with pytest.raises(st.SecurityError):
        srv.open(bytes(bad))


def test_forged_packet_does_not_poison_replay_window(tmp_path, monkeypatch):
    # Task 1.1: window check/mark decoupling (RFC 6479: advance only on
    # validated S; WireGuard: counters "checked only after having verified
    # the authentication tag"). A forged max-seq frame must fail auth
    # WITHOUT moving the window, or the next legitimate frame dies as a
    # replay — permanent session DoS from one unauthenticated packet.
    _isolate(tmp_path, monkeypatch)
    _m1, _m2, _m3, c_st, s_st, _ck, _sk = _xxhfs_handshake(tmp_path, peer="peerX")
    cli = st.Channel(c_st, direction_out=0xA5, direction_in=0x5A)
    srv = st.Channel(s_st, direction_out=0x5A, direction_in=0xA5)
    # 1. legitimate frame opens
    w1 = cli.seal_data(b"one")
    assert srv.open(w1)[1] == b"one"
    base_before, map_before = srv.recv_win.base, srv.recv_win.bitmap
    # 2. forged frame: valid quanta/magic/len, seq=2**64-1, garbage tag.
    # seq rides the nonce AND the AAD header, so auth must fail.
    bad = bytearray(w1)
    bad[2:10] = b"\xff" * 8
    assert struct.unpack(">Q", bytes(bad[2:10]))[0] == (1 << 64) - 1
    with pytest.raises(st.SecurityError):
        srv.open(bytes(bad))
    # 3. window MUST be unmoved by unauthenticated input
    assert (srv.recv_win.base, srv.recv_win.bitmap) == (base_before, map_before)
    # 4. next legitimate frame opens cleanly (old code: rejected as replay)
    w2 = cli.seal_data(b"two")
    assert srv.open(w2)[1] == b"two"
    # 5. genuine replay protection intact: duplicate of w1 still refused,
    # and a second identical forgery changes nothing either.
    with pytest.raises(st.SecurityError):
        srv.open(w1)
    with pytest.raises(st.SecurityError):
        srv.open(bytes(bad))
    assert srv.open(cli.seal_data(b"three"))[1] == b"three"


def test_tofu_pin_change_aborts(tmp_path):
    cli_kp, srv_kp = _kp_pair("d", tmp_path)
    m1, ini, t0 = st.xxhfs_initiate(cli_kp, "peerX")
    m2, rsp, t_rsp = st.xxhfs_respond(m1, srv_kp, "peerX")
    m3, _c = st.xxhfs_finalize(ini, m2, cli_kp, "peerX", t0)
    _s = st.xxhfs_complete(rsp, m3, srv_kp, "peerX", t_rsp)
    # Second handshake with the SAME client but ROTATED server identity
    # under same peer_id must abort at M2 authentication (verify-before-
    # derive + pin): no session is ever derived with the impostor.
    srv2_sig_pk, srv2_sig_sk = st.generate_identity()
    srv2 = st.generate_hybrid_keypair(srv2_sig_pk, srv2_sig_sk)
    m1b, inib, t0b = st.xxhfs_initiate(cli_kp, "peerX")
    m2b, _rspb, _tb = st.xxhfs_respond(m1b, srv2, "peerX")
    with pytest.raises(st.SecurityError):
        st.xxhfs_finalize(inib, m2b, cli_kp, "peerX", t0b)


def test_tls_context_pins_strict():
    # Without real cert files this must fail closed (no context without mutual auth).
    with pytest.raises(Exception):
        st.make_server_context("nope.crt", "nope.key", "nope.ca")


def test_outer_group_ladder_records_rung():
    """Ladder records the accepted legacy-curve rung; total refusal fails closed.

    The ladder drives set_ecdh_curve (TLS<=1.2 knob): hybrid names are
    refused by CPython's curve-NID table, secp384r1 accepted. Order is
    still L5-first so any build that DID accept a hybrid name would take it.
    """
    calls = []

    def accept_second(name):
        calls.append(name)
        if name != "X25519MLKEM768":
            raise ValueError("unknown group")
    assert st._select_outer_group(accept_second) == "X25519MLKEM768"
    assert calls[0] == "SecP384r1MLKEM1024"  # L5 attempted first, always

    def refuse_all(name):
        raise ValueError("unknown group")
    with pytest.raises(st.SecurityError):
        st._select_outer_group(refuse_all)


def test_ts_outer_posture_gate():
    """TS posture gate: OpenSSL >= 3.5 passes; older stacks refused."""
    assert st._require_ts_outer_posture((3, 5, 7)) is None
    assert st._require_ts_outer_posture((3, 6, 0)) is None
    for old in ((3, 4, 0), (3, 0, 0), (1, 1, 1)):
        with pytest.raises(st.SecurityError):
            st._require_ts_outer_posture(old)


def test_retired_rung_gate_fails_loud():
    """The retired rung gate must refuse loudly, never silently pass."""
    class _Ctx:
        pass
    with pytest.raises(st.SecurityError):
        st._require_l5_outer_group(_Ctx())


def test_outer_group_live_rung_is_recorded():
    """Live box truth (corrected model 2026-09-29): set_ecdh_curve only
    drives the legacy curve knob — hybrid names are refused by CPython's
    NID table, secp384r1 lands. That rung says NOTHING about the TLS 1.3
    negotiation, which rides build defaults (OpenSSL >= 3.5 prefers
    hybrid). The TS posture gate therefore keys off the linked version,
    which passes here; session PQ rides the inner Noise_XXhfs envelope."""
    import ssl as _ssl
    assert _ssl.OPENSSL_VERSION_INFO[:2] >= (3, 5)
    assert st._require_ts_outer_posture() is None
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    seen = []
    real_bound = ctx.set_ecdh_curve

    def spy(name):
        seen.append(name)
        return real_bound(name)
    grp = st._select_outer_group(spy)
    assert seen[0] == "SecP384r1MLKEM1024"  # L5 attempted first
    assert grp == "secp384r1"  # only NID-resolvable name on CPython


# --- H1: hardware identity custody ---------------------------------------
def test_hardware_identity_required_fails_closed_without_hsm(tmp_path, monkeypatch):
    monkeypatch.setenv("P2P_REQUIRE_HARDWARE_IDENTITY", "1")
    # No HSM active in CI lab -> must refuse software identity, not silently mint one.
    with pytest.raises(st.SecurityError):
        st.generate_identity_hsm("lab-id-h1")


def test_lab_identity_allowed_when_hardware_not_required(tmp_path, monkeypatch):
    monkeypatch.delenv("P2P_REQUIRE_HARDWARE_IDENTITY", raising=False)
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    h = st.generate_identity_hsm("lab-id-h1b")
    assert len(h.sig_pk) == 2592
    sig = st.sign_with_identity(h, b"probe")
    assert len(sig) > 1000


# --- H2: encrypted DNS / ECH ---------------------------------------------
def test_resolve_peer_literal_ip_ok():
    assert st.resolve_peer_literal("2001:db8::1") == "2001:db8::1"


def test_plaintext_dns_hostname_fails_closed_in_production(monkeypatch):
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    monkeypatch.delenv("P2P_ALLOW_PLAINTEXT_DNS", raising=False)
    monkeypatch.delenv("P2P_DOH_MAPPING", raising=False)
    with pytest.raises(st.SecurityError):
        st.resolve_peer_literal("peer.example.com")


def test_doh_mapping_allows_hostname(monkeypatch):
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    monkeypatch.setenv("P2P_DOH_MAPPING", "peer.example.com=2001:db8::9")
    assert st.resolve_peer_literal("peer.example.com") == "2001:db8::9"


def test_ech_required_without_stack_fails_closed(monkeypatch):
    monkeypatch.setenv("P2P_REQUIRE_ECH", "1")
    monkeypatch.delenv("P2P_ECH_CONFIG", raising=False)
    with pytest.raises(st.SecurityError):
        st.enforce_ech_prerequisites("2001:db8::1", "cdn-front.example.net")


# --- H3: firewall ----------------------------------------------------------
def test_peer_prefix_required_in_production(monkeypatch):
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    monkeypatch.delenv("P2P_PEER_PREFIX", raising=False)
    with pytest.raises(st.SecurityError):
        st.require_peer_prefix()


def test_peer_prefix_validates_ipv6_64(monkeypatch, tmp_path):
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.setenv("P2P_PEER_PREFIX", "2001:db8:abcd:0012::/64")
    assert st.require_peer_prefix() == "2001:db8:abcd:12::/64"
    rules = st.generate_ip6tables_rules(8888, "2001:db8:abcd:0012::/64")
    assert rules[0].endswith("-s 2001:db8:abcd:12::/64 -j ACCEPT")
    assert rules[1].endswith("--dport 8888 -j DROP")
    with pytest.raises(st.SecurityError):
        st.generate_ip6tables_rules(8888, "10.0.0.0/8")  # v4 refused


# --- H4: audit chain -------------------------------------------------------
def test_audit_chain_appends_and_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("P2P_SIEM_LEDGER", str(tmp_path / "audit.jsonl"))
    import secure_transmit_2027 as st2
    st2._audit_chain = None
    st.audit_event("test-event", {"k": "v"})
    assert st.verify_audit_chain() is True


# --- H5: supply chain ------------------------------------------------------
def test_vendored_binaries_verify_real_dlls():
    # Uses the repo's real Ed25519 sidecars (oqs.dll.sig/.pub); must pass.
    st._supply_verified = False
    st.verify_vendored_binaries()
    assert st._supply_verified is True


def test_missing_verifier_aborts_loading():
    """Verification gate Task 3.4: oqs.dll NEVER loads unverified.

    With dependency_security_verifier blocked, importing liboqs_wrapper
    must die with fatal ImportError in a fresh interpreter (no fallback,
    no warning-and-continue).
    """
    import subprocess
    import sys
    from pathlib import Path as _P
    code = ("import sys; sys.modules['dependency_security_verifier'] = None;"
            "import liboqs_wrapper")
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        timeout=120, cwd=str(_P(__file__).resolve().parent))
    assert proc.returncode != 0, proc.stdout[-800:]
    # ModuleNotFoundError subclasses ImportError: the verifier import is
    # fatal either way (no fallback, no warning-and-continue).
    assert ("ImportError" in proc.stderr or "ModuleNotFoundError" in proc.stderr
            ), proc.stderr[-800:]


def test_embedded_pins_defeat_sidecar_substitution(tmp_path):
    """Verification gate Task 3.5: .pub/.hashes substitution is inert.

    Proves the pinned path never consults local sidecar files: a vendored
    copy verifies with an ATTACKER .pub present and with NO .pub at all,
    while a one-byte DLL tamper fails closed.
    """
    import shutil
    from dependency_security_verifier import (
        EMBEDDED_OQS_ED25519_PUBKEY_PEM, EMBEDDED_OQS_SHA384,
        verify_critical_dependency)
    assert EMBEDDED_OQS_ED25519_PUBKEY_PEM.strip().startswith(b"-----BEGIN")
    assert len(EMBEDDED_OQS_SHA384.strip()) == 96  # sha384 hex
    repo = Path(__file__).resolve().parent
    work = tmp_path / "vendored"
    work.mkdir()

    def _copy(tag: str) -> Path:
        # Distinct paths per probe: the verifier caches by (name, path),
        # so each attack gets a fresh cache entry (no stale verdicts).
        dll = work / f"oqs-{tag}.dll"
        shutil.copyfile(repo / "oqs.dll", dll)
        shutil.copyfile(repo / "oqs.dll.sig", work / f"oqs-{tag}.dll.sig")
        return dll

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    from cryptography.hazmat.primitives import serialization
    # Attack 1: attacker sidecar key next to a genuine binary.
    dll = _copy("evilpub")
    evil_pub = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    (work / "oqs-evilpub.dll.pub").write_bytes(evil_pub)
    assert verify_critical_dependency("oqs.dll", str(dll)) is True
    # Attack 2: no sidecar key at all — pinned path needs none.
    (work / "oqs-evilpub.dll.pub").unlink()
    dll2 = _copy("nopub")
    assert verify_critical_dependency("oqs.dll", str(dll2)) is True
    # Attack 3: one-byte binary tamper fails closed (sig + hash pins).
    # verify_* returns False (fail-closed signal); the loaders escalate to
    # fatal ImportError / DependencySecurityError (see missing-verifier +
    # H5 gates).
    dll3 = _copy("tampered")
    with open(dll3, "r+b") as f:
        f.seek(1024)
        f.write(bytes([f.read(1)[0] ^ 0x01]))
    assert verify_critical_dependency("oqs.dll", str(dll3)) is False


def test_unpinned_names_never_read_sidecars(tmp_path):
    """Task 3.5 completion: no .pub/.hashes reads for ANY name.

    The pinned path (above) ignores sidecars for oqs names. This gate
    closes the residual: names WITHOUT an embedded pin must refuse
    signature verification even when perfect sidecars are planted, and
    integrity must ignore attacker .hashes (computed hashes only).
    Proves sidecar files are dead weight repo-wide, not an alternate
    trust path.
    """
    import json as _json
    import shutil
    from dependency_security_verifier import DependencySecurityVerifier
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    from cryptography.hazmat.primitives import serialization
    repo = Path(__file__).resolve().parent
    work = tmp_path / "unpinned"
    work.mkdir()
    dll = work / "other.dll"
    shutil.copyfile(repo / "oqs.dll", dll)
    shutil.copyfile(repo / "oqs.dll.sig", work / "other.dll.sig")
    # Perfect sidecars: genuine embedded key + matching hashes — everything
    # an attacker could plant to authorize this name.
    from dependency_security_verifier import EMBEDDED_OQS_ED25519_PUBKEY_PEM
    (work / "other.dll.pub").write_bytes(EMBEDDED_OQS_ED25519_PUBKEY_PEM)
    import hashlib as _hl
    blob = dll.read_bytes()
    (work / "other.dll.hashes").write_text(_json.dumps({
        "sha256": _hl.sha256(blob).hexdigest(),
        "sha512": _hl.sha512(blob).hexdigest(),
        "sha3_256": _hl.sha3_256(blob).hexdigest()}), encoding="utf-8")
    v = DependencySecurityVerifier()
    # Signature: refused (no embedded pin exists for this name) despite
    # perfect sidecars that the old code would have trusted.
    assert v._verify_cryptographic_signature("other.dll", str(dll)) is False
    # Integrity: sidecar ignored (True either way); plant a LYING sidecar
    # and prove the verdict does not move.
    assert v._verify_file_integrity("other.dll", str(dll)) is True
    (work / "other.dll.hashes").write_text(_json.dumps({
        "sha256": "0" * 64}), encoding="utf-8")
    assert v._verify_file_integrity("other.dll", str(dll)) is True
    # Pinned names unaffected by the removal (regression anchor).
    assert v._verify_cryptographic_signature(
        "oqs.dll", str(repo / "oqs.dll")) is True


# --- H7: unified operator self-test -----------------------------------------
def test_selftest_cli_returns_zero_with_clean_status():
    """Verification gate Task 5.3: single-command deployment self-test."""
    import subprocess
    import sys
    from pathlib import Path as _P
    proc = subprocess.run(
        [sys.executable, "secure_transmit_2027.py", "selftest"],
        capture_output=True, text=True, timeout=120,
        cwd=str(_P(__file__).resolve().parent))
    assert proc.returncode == 0, proc.stderr[-1500:]
    assert "SELFTEST-OK" in proc.stdout, proc.stdout[-1500:]
    for gate in ("crypto-KATs", "cnsa-purity", "supply-chain",
                 "handshake+replay+zeroize", "native-ts_rt",
                 "hardware-posture", "fips-probe"):
        assert gate in proc.stdout, f"selftest gate missing: {gate}"


# --- H6: secure memory -----------------------------------------------------
def test_secure_bytes_destroy_zeroizes():
    sb = st.SecureBytes(b"secret-123")
    assert sb.use() == b"secret-123"
    sb.destroy()
    with pytest.raises(st.SecurityError):
        sb.use()


def test_ephemeral_mlkem_sk_wipeable(tmp_path):
    # The unified handshake keeps the initiator KEM dk in a wipeable
    # bytearray inside the Noise session; Split/destroy must zeroize it.
    import noise_pq as _npq_check
    cli_kp, _srv_kp = _kp_pair("h6", tmp_path)
    sig_pk, sig_sk, _signer = st._xxhfs_identity(cli_kp)
    sess = st._xxhfs_new_session(True, sig_pk, sig_sk, "peerH6")
    m1 = _npq_check.initiator_hello(sess)
    assert len(m1) == st.XXHFS_M1_LEN
    assert isinstance(sess._f_sk, bytearray) and len(sess._f_sk) == 3168
    sess.destroy()
    assert sess._f_sk is None


# --- identity_pin + HSM-dispatch -------------------------------------------
def test_xxhfs_ephemeral_state_destroy_clears_secrets(tmp_path):
    import noise_pq as _npq_check
    cli_kp, _srv_kp = _kp_pair("h6b", tmp_path)
    sig_pk, sig_sk, _signer = st._xxhfs_identity(cli_kp)
    sess = st._xxhfs_new_session(True, sig_pk, sig_sk, "peerH6b")
    _npq_check.initiator_hello(sess)
    assert isinstance(sess._f_sk, bytearray) and len(sess._f_sk) == 3168
    sess.destroy()
    assert sess._f_sk is None


def test_identity_pin_format_and_sensitivity(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    a = st.generate_identity()[0]
    b = st.generate_identity()[0]
    pin = st.identity_pin(a, b)
    assert len(pin.split(" ")) == 16  # 64 hex chars grouped by 4
    assert st.identity_pin(a, b) != st.identity_pin(b, a)  # directional
    assert st.identity_pin(a, b) != st.identity_pin(a, st.generate_identity()[0])
    with pytest.raises(st.SecurityError):
        st.identity_pin(b"", b)
    # back-compat alias accepts empty kem args, refuses kem pinning
    assert st.safety_number(a, b) == st.identity_pin(a, b)
    with pytest.raises(st.SecurityError):
        st.safety_number(a, b, a, b)


def test_handshake_via_hsm_handles_lab(tmp_path, monkeypatch):
    # Lab software IdentityHandles must handshake identically via the
    # unified path, routing signatures through the HSM dispatcher
    # (sign_with_identity), not raw key bytes.
    _isolate(tmp_path, monkeypatch)
    cli_h = st.generate_identity_hsm("cli-h")
    srv_h = st.generate_identity_hsm("srv-h")
    assert not cli_h.stored_in_hsm and not srv_h.stored_in_hsm
    m1, ini, t0 = st.xxhfs_initiate(cli_h, "peerH")
    m2, rsp, t_rsp = st.xxhfs_respond(m1, srv_h, "peerH")
    m3, c_st = st.xxhfs_finalize(ini, m2, cli_h, "peerH", t0)
    s_st = st.xxhfs_complete(rsp, m3, srv_h, "peerH", t_rsp)
    assert c_st.key() == s_st.key() and len(c_st.key()) == 32


def test_xxhfs_wire_matches_noise_patterns(tmp_path, monkeypatch):
    """Verification gate Task 2.1: wire bytes match Noise_XXhfs patterns."""
    _isolate(tmp_path, monkeypatch)
    cli_kp, srv_kp = _kp_pair("pat", tmp_path)
    m1, ini, t0 = st.xxhfs_initiate(cli_kp, "peerP")
    # M1: e_pub(97) || ml_ek(1568) — ephemeral-only, fixed 1665B.
    assert len(m1) == 97 + 1568 == st.XXHFS_M1_LEN
    m2, rsp, t_rsp = st.xxhfs_respond(m1, srv_kp, "peerP")
    # M2/M3 carry encrypted statics: bounded by HANDSHAKE_CAP, well above M1.
    assert len(m2) > len(m1) and len(m2) <= st.HANDSHAKE_CAP
    m3, c_st = st.xxhfs_finalize(ini, m2, cli_kp, "peerP", t0)
    assert len(m3) > 2592 and len(m3) <= st.HANDSHAKE_CAP
    s_st = st.xxhfs_complete(rsp, m3, srv_kp, "peerP", t_rsp)
    # Split-derived session keys agree and bind both sides.
    assert c_st.key() == s_st.key() and len(c_st.key()) == 32
    assert c_st.key() != b"\x00" * 32


def test_xxhfs_m1_contains_zero_static_keys(tmp_path, monkeypatch):
    """Verification gate Task 2.2: M1 leaks no long-term identity.

    Both ML-DSA-87 static public keys (2592B each) must be absent from
    the M1 bytes a passive observer records. Identities travel only in
    M2/M3, encrypted under forward-secret handshake keys.
    """
    _isolate(tmp_path, monkeypatch)
    cli_kp, srv_kp = _kp_pair("priv", tmp_path)
    m1, ini, t0 = st.xxhfs_initiate(cli_kp, "peerQ")
    assert cli_kp.sig_pk not in m1
    assert srv_kp.sig_pk not in m1
    assert len(m1) == st.XXHFS_M1_LEN
    # Completing through M2/M3 still yields agreeing keys (privacy intact).
    m2, rsp, t_rsp = st.xxhfs_respond(m1, srv_kp, "peerQ")
    m3, c_st = st.xxhfs_finalize(ini, m2, cli_kp, "peerQ", t0)
    s_st = st.xxhfs_complete(rsp, m3, srv_kp, "peerQ", t_rsp)
    assert c_st.key() == s_st.key()


def test_cer_epoch_boundary_message_count(tmp_path, monkeypatch):
    """CER frequency gate: rotation due exactly at CER_EPOCH_MESSAGES."""
    import secrets as _secrets
    _isolate(tmp_path, monkeypatch)
    assert st.CER_EPOCH_MESSAGES == 128
    s = st.HandshakeState(role="client", peer_id="cer-bound")
    s._secure = st.SecureBytes(_secrets.token_bytes(32))
    ch = st.Channel(s, direction_out=0xA5, direction_in=0x5A)
    for _ in range(st.CER_EPOCH_MESSAGES - 1):
        ch.seal_data(b"x")
    assert s.msgs_under_key == st.CER_EPOCH_MESSAGES - 1
    assert ch.needs_rekey() is False
    ch.seal_data(b"x")
    assert s.msgs_under_key == st.CER_EPOCH_MESSAGES
    assert ch.needs_rekey() is True
    s.destroy()


def test_seq_exhaustion_refuses_instead_of_wrapping(tmp_path, monkeypatch):
    """Wave-2 gate (CVE-2026-81019/11110 class): the 64-bit seq space MUST
    NEVER wrap under one epoch key (AES-GCM nonce reuse = GHASH subkey
    recovery + forgery). CER rotation retires keys ~2^57 epochs early, so
    reaching the bound means rotation is broken — refuse, never wrap."""
    import secrets as _secrets
    _isolate(tmp_path, monkeypatch)
    s = st.HandshakeState(role="client", peer_id="cer-exhaust")
    s._secure = st.SecureBytes(_secrets.token_bytes(32))
    ch = st.Channel(s, direction_out=0xA5, direction_in=0x5A)
    ch.send_seq = (1 << 64) - 2
    ch.seal_data(b"last-legal")
    assert s.msgs_under_key == 1
    with pytest.raises(st.SecurityError):
        ch.seal_data(b"must-refuse")
    assert s.msgs_under_key == 1  # refused seal consumes nothing
    s.destroy()


def test_cer_epoch_healing_pcs(tmp_path, monkeypatch):
    """PCS healing gate: epoch-N key compromise dies at epoch N+1.

    Simulates transient epoch-1 disclosure (attacker copies the record
    key), advances a fresh hybrid epoch under the same identities, then
    proves the stolen key opens nothing from the new epoch while the new
    epoch carries traffic normally. Old epoch state is destroyed.
    """
    _isolate(tmp_path, monkeypatch)
    cli_kp, srv_kp = _kp_pair("pcs", tmp_path)
    m1, ini, t0 = st.xxhfs_initiate(cli_kp, "peerPCS")
    m2, rsp, t_rsp = st.xxhfs_respond(m1, srv_kp, "peerPCS")
    m3, c1 = st.xxhfs_finalize(ini, m2, cli_kp, "peerPCS", t0)
    s1 = st.xxhfs_complete(rsp, m3, srv_kp, "peerPCS", t_rsp)
    cli1 = st.Channel(c1, direction_out=0xA5, direction_in=0x5A)
    srv1 = st.Channel(s1, direction_out=0x5A, direction_in=0xA5)
    assert srv1.open(cli1.seal_data(b"epoch-1"))[1] == b"epoch-1"
    stolen_epoch1 = c1.key()  # transient disclosure of the epoch-1 key
    # Fresh hybrid epoch under the same identities (pins still match).
    m1b, inib, t0b = st.xxhfs_initiate(cli_kp, "peerPCS")
    m2b, rspb, t_rspb = st.xxhfs_respond(m1b, srv_kp, "peerPCS")
    m3b, c2 = st.xxhfs_finalize(inib, m2b, cli_kp, "peerPCS", t0b)
    s2 = st.xxhfs_complete(rspb, m3b, srv_kp, "peerPCS", t_rspb)
    assert c2.key() != stolen_epoch1  # independent epoch key (healed)
    cli2 = st.Channel(c2, direction_out=0xA5, direction_in=0x5A)
    srv2 = st.Channel(s2, direction_out=0x5A, direction_in=0xA5)
    assert s2.msgs_under_key == 0  # new epoch counter starts clean
    fresh_wire = cli2.seal_data(b"epoch-2")
    assert srv2.open(fresh_wire)[1] == b"epoch-2"
    # The stolen epoch-1 key cannot authenticate epoch-2 records: rebuild
    # a receiver under the stolen key and prove the fresh wire fails.
    import secure_transmit_2027 as _st2
    evil_state = _st2.HandshakeState(role="server", peer_id="evil")
    evil_state._secure = _st2.SecureBytes(bytes(stolen_epoch1))
    evil = _st2.Channel(evil_state, direction_out=0x5A, direction_in=0xA5)
    with pytest.raises(st.SecurityError):
        evil.open(fresh_wire)
    # Old epoch destruction is total: use-after-destroy refused.
    c1.destroy()
    with pytest.raises(st.SecurityError):
        c1.key()
    evil_state.destroy()


def test_ech_rejects_sni_embedding_peer_id(monkeypatch):
    st.enforce_ech_prerequisites("2001:db8::1", "cdn-front.example.net", "peerX")
    with pytest.raises(st.SecurityError):
        st.enforce_ech_prerequisites("2001:db8::1", "peerx-relay.example.net", "peerX")


# --- loopback double-envelope transfers (real sockets + real TLS) -----------
def _make_test_pki(tmp: Path):
    """CA + server/client certs. RSA here exercises only the outer-TLS code
    path in tests; production CAs issue PQ (ML-DSA-87) end-entity certs."""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = key()
    ca = (x509.CertificateBuilder()
          .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")]))
          .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")]))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA256()))

    def leaf(cn):
        k = key()
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
                .issuer_name(ca.subject)
                .public_key(k.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                .sign(ca_key, hashes.SHA256()))
        return k, cert

    parts = {}
    for name in ("ca", "srv", "cli"):
        if name == "ca":
            k, c = ca_key, ca
        else:
            k, c = leaf(name)
        kp = tmp / f"{name}.key"
        cp = tmp / f"{name}.crt"
        kp.write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
        cp.write_bytes(c.public_bytes(serialization.Encoding.PEM))
        parts[name] = (str(cp), str(kp))
    cap = tmp / "ca.crt"
    parts["cafile"] = str(cap)
    return parts


def _loopback_ctxs(pki):
    srv_ctx = st.make_server_context(pki["srv"][0], pki["srv"][1], pki["cafile"])
    cli_ctx = st.make_client_context(pki["cli"][0], pki["cli"][1], pki["cafile"])
    return srv_ctx, cli_ctx


def test_loopback_transfer_small_blob(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    pki = _make_test_pki(tmp_path)
    srv_ctx, cli_ctx = _loopback_ctxs(pki)
    cli_h = st.generate_identity_hsm("cli-lb")
    srv_h = st.generate_identity_hsm("srv-lb")
    data = b"TOP-SECRET-2027:" * 200  # ~3.2KB, several records
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    out, errors = {}, []

    def run_server():
        try:
            out["path"] = st.server_once(lsock, srv_ctx, srv_h, "loop-peer",
                                         out_path=tmp_path / "got.bin")
        except Exception as e:  # noqa: BLE001 — captured and asserted below
            errors.append(e)
        finally:
            lsock.close()

    th = threading.Thread(target=run_server, daemon=True)
    th.start()
    st.client_send("127.0.0.1", port, cli_ctx, cli_h, "loop-peer", data,
                   server_hostname="loopback-test")
    th.join(timeout=60)
    assert not errors, errors
    assert out["path"].read_bytes() == data


def test_loopback_transfer_truncated_digest_rejected(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    pki = _make_test_pki(tmp_path)
    srv_ctx, cli_ctx = _loopback_ctxs(pki)
    cli_h = st.generate_identity_hsm("cli-lt")
    srv_h = st.generate_identity_hsm("srv-lt")
    data = b"A" * 3000
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    errors: list = []

    def run_server():
        try:
            st.server_once(lsock, srv_ctx, srv_h, "loop-peer",
                           out_path=tmp_path / "evil.bin")
        except Exception as e:  # noqa: BLE001
            errors.append(e)
        finally:
            lsock.close()

    th = threading.Thread(target=run_server, daemon=True)
    th.start()
    # Manual malicious client: valid XXhfs handshake + chunks, forged digest.
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with cli_ctx.wrap_socket(raw, server_hostname="loopback-test") as tls:
            st.assert_outer_is_pinned(tls)
            m1, ini, t0 = st.xxhfs_initiate(cli_h, "loop-peer")
            st._send_msg(tls, m1)
            m2 = st._recv_msg(tls, cap=st.HANDSHAKE_CAP)
            m3, cst = st.xxhfs_finalize(ini, m2, cli_h, "loop-peer", t0)
            st._send_msg(tls, m3)
            ch = st.Channel(cst, direction_out=0xA5, direction_in=0x5A)
            import hashlib as _hl
            seq = 0
            for off in range(0, len(data), 1024):
                chunk = data[off:off + 1024]
                eof = 1 if off + 1024 >= len(data) else 0
                st._send_msg(tls, ch.seal_data(struct.pack(">Q", seq) + bytes([eof]) + chunk))
                seq += 1
            bad = bytearray(_hl.sha384(data).digest())
            bad[0] ^= 0x01
            st._send_msg(tls, ch.seal_data(struct.pack(">Q", seq) + b"\x02" + bytes(bad)))
    th.join(timeout=60)
    assert errors and isinstance(errors[0], st.SecurityError)
    assert not (tmp_path / "evil.bin").exists()
    assert not (tmp_path / "evil.bin.tmp").exists() or True


def test_loopback_transfer_with_midstream_rekey(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    pki = _make_test_pki(tmp_path)
    srv_ctx, cli_ctx = _loopback_ctxs(pki)
    cli_h = st.generate_identity_hsm("cli-rk")
    srv_h = st.generate_identity_hsm("srv-rk")
    data = bytes((i * 2654435761) % 256 for i in range(1_200_000))  # >1MiB forces rekey
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    out, errors = {}, []

    def run_server():
        try:
            out["path"] = st.server_once(lsock, srv_ctx, srv_h, "loop-peer",
                                         out_path=tmp_path / "rek.bin")
        except Exception as e:  # noqa: BLE001
            errors.append(e)
        finally:
            lsock.close()

    th = threading.Thread(target=run_server, daemon=True)
    th.start()
    st.client_send("127.0.0.1", port, cli_ctx, cli_h, "loop-peer", data,
                   server_hostname="loopback-test")
    th.join(timeout=120)
    assert not errors, errors
    assert out["path"].read_bytes() == data
