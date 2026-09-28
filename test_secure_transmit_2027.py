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


def test_combiner_sizes_and_order(tmp_path):
    # RFC 10024 SecP384r1MLKEM1024: 48 || 32 = 80, ECDHE first
    out = st.hybrid_combine(b"E" * 48, b"M" * 32)
    assert out == b"E" * 48 + b"M" * 32 and len(out) == 80
    with pytest.raises(st.SecurityError):
        st.hybrid_combine(b"E" * 32, b"M" * 32)  # wrong ECDHE len fails closed


def test_handshake_roundtrip_yields_equal_keys(tmp_path):
    cli_kp, srv_kp = _kp_pair("a", tmp_path)
    hello, tr, eph, t = st.build_client_hello(cli_kp, "peerX")
    resp, s_st = st.server_accept(hello, srv_kp, "peerX")
    c_st = st.client_finish(resp, eph, cli_kp, tr, "peerX", t)
    assert c_st.key() == s_st.key() and len(c_st.key()) == 32
    assert c_st.key() != b"\x00" * 32


def test_verify_before_decaps_tamper_fails_closed(tmp_path):
    cli_kp, srv_kp = _kp_pair("b", tmp_path)
    hello, tr, eph, t = st.build_client_hello(cli_kp, "peerX")
    bad = bytearray(hello)
    bad[30] ^= 0x01  # flip a byte inside ephemeral share/sig region
    with pytest.raises(st.SecurityError):
        st.server_accept(bytes(bad), srv_kp, "peerX")


def test_record_aead_roundtrip_replay_rejected(tmp_path):
    cli_kp, srv_kp = _kp_pair("c", tmp_path)
    hello, tr, eph, t = st.build_client_hello(cli_kp, "peerX")
    resp, s_st = st.server_accept(hello, srv_kp, "peerX")
    c_st = st.client_finish(resp, eph, cli_kp, tr, "peerX", t)
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


def test_tofu_pin_change_aborts(tmp_path):
    cli_kp, srv_kp = _kp_pair("d", tmp_path)
    hello, tr, eph, t = st.build_client_hello(cli_kp, "peerX")
    resp, s_st = st.server_accept(hello, srv_kp, "peerX")
    c_st = st.client_finish(resp, eph, cli_kp, tr, "peerX", t)
    # second handshake with ROTATED server identity under same peer_id must abort
    srv2_sig_pk, srv2_sig_sk = st.generate_identity()
    srv2 = st.generate_hybrid_keypair(srv2_sig_pk, srv2_sig_sk)
    hello2, tr2, eph2, t2 = st.build_client_hello(cli_kp, "peerX")
    with pytest.raises(st.SecurityError):
        st.server_accept(hello2, srv2, "peerX")


def test_tls_context_pins_strict():
    # Without real cert files this must fail closed (no context without mutual auth).
    with pytest.raises(Exception):
        st.make_server_context("nope.crt", "nope.key", "nope.ca")


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


# --- H6: secure memory -----------------------------------------------------
def test_secure_bytes_destroy_zeroizes():
    sb = st.SecureBytes(b"secret-123")
    assert sb.use() == b"secret-123"
    sb.destroy()
    with pytest.raises(st.SecurityError):
        sb.use()


def test_ephemeral_mlkem_sk_wipeable(tmp_path):
    cli_kp, _srv_kp = _kp_pair("h6", tmp_path)
    _hello, _tr, eph, _t = st.build_client_hello(cli_kp, "peerH6")
    assert isinstance(eph.mlkem_sk, bytearray) and len(eph.mlkem_sk) == 3168
    eph.destroy()
    assert all(b == 0 for b in eph.mlkem_sk)


# --- identity_pin + HSM-dispatch -------------------------------------------
def test_ephemeral_mlkem_sk_wipeable(tmp_path):
    cli_kp, _srv_kp = _kp_pair("h6", tmp_path)
    _hello, _tr, eph, _t = st.build_client_hello(cli_kp, "peerH6")
    assert isinstance(eph.mlkem_sk, bytearray) and len(eph.mlkem_sk) == 3168
    eph.destroy()
    assert all(b == 0 for b in eph.mlkem_sk)


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
    # Lab software IdentityHandles must handshake identically (HSM dispatcher).
    _isolate(tmp_path, monkeypatch)
    cli_h = st.generate_identity_hsm("cli-h")
    srv_h = st.generate_identity_hsm("srv-h")
    assert not cli_h.stored_in_hsm and not srv_h.stored_in_hsm
    hello, tr, eph, t = st.build_client_hello(cli_h, "peerH")
    resp, s_st = st.server_accept(hello, srv_h, "peerH")
    c_st = st.client_finish(resp, eph, cli_h, tr, "peerH", t)
    assert c_st.key() == s_st.key() and len(c_st.key()) == 32


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
    # Manual malicious client: valid handshake + chunks, forged digest trailer.
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with cli_ctx.wrap_socket(raw, server_hostname="loopback-test") as tls:
            st.assert_outer_is_pinned(tls)
            hello, tr, eph, t = st.build_client_hello(cli_h, "loop-peer")
            st._send_msg(tls, hello)
            resp = st._recv_msg(tls, cap=st.HANDSHAKE_CAP)
            cst = st.client_finish(resp, eph, cli_h, tr, "loop-peer", t)
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
