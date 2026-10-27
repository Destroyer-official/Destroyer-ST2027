#!/usr/bin/env python3
"""Production tests for trust_anchor — real ML-DSA-87 threshold, no mocks."""

import os
import secrets
import time

import pytest

import trust_anchor as ta
import secure_transmit_2027 as st


def _handles(monkeypatch, tmp_path, labels):
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("P2P_TS_MODE", raising=False)
    monkeypatch.delenv("P2P_REQUIRE_PKI", raising=False)
    monkeypatch.delenv("P2P_EPHEMERAL", raising=False)
    monkeypatch.setenv("P2P_SIEM_LEDGER", str(tmp_path / "audit.jsonl"))
    st._audit_chain = None
    st.PIN_DIR = tmp_path / "pins"
    ta.clear_registry()
    handles = [st.generate_identity_hsm(label) for label in labels]
    return handles


def _custodians(handles):
    return [ta.Custodian(label=h.label, mldsa_pk=bytes(h.sig_pk))
            for h in handles]


def _tbs(subject, subject_pk):
    now = int(time.time())
    return ta.CertTBS(serial=secrets.token_bytes(16), subject=subject,
                      subject_pk=bytes(subject_pk),
                      not_before=now - 60, not_after=now + 3600)


def test_threshold_issue_verify_3of5(tmp_path, monkeypatch):
    cust = _handles(monkeypatch, tmp_path,
                    [f"custodian-{i}" for i in range(1, 6)])
    subject = _handles(monkeypatch, tmp_path, ["officer-alpha"])[0]
    # NOTE: second _handles call cleared the registry; re-register below.
    ta.clear_registry()
    custodians = _custodians(cust)
    ta.configure(custodians, ta.RevocationCache(custodians))
    cert = ta.issue_certificate(_tbs("officer-alpha", subject.sig_pk), cust[:3])
    assert len(cert.sigs) == 3
    ta.verify_certificate(cert, custodians)
    ta.register_certificate(cert)
    assert ta.peer_certificate_for("officer-alpha") is not None


def test_threshold_quorum_refused(tmp_path, monkeypatch):
    cust = _handles(monkeypatch, tmp_path,
                    [f"custodian-{i}" for i in range(1, 6)])
    subject = st.generate_identity_hsm("officer-quorum")
    ta.clear_registry()
    custodians = _custodians(cust)
    ta.configure(custodians, ta.RevocationCache(custodians))
    with pytest.raises(ta.TrustError):
        ta.issue_certificate(_tbs("officer-quorum", subject.sig_pk), cust[:2])
    cert = ta.issue_certificate(_tbs("officer-quorum", subject.sig_pk),
                                cust[:3])
    # Drop one signature below quorum.
    cert.sigs = cert.sigs[:2]
    with pytest.raises(ta.TrustError):
        ta.verify_certificate(cert, custodians)


def test_threshold_wrong_custodian_and_expiry(tmp_path, monkeypatch):
    cust = _handles(monkeypatch, tmp_path,
                    [f"custodian-{i}" for i in range(1, 6)])
    outsider = _handles(monkeypatch, tmp_path, ["outsider"])[0]
    subject = st.generate_identity_hsm("officer-exp")
    ta.clear_registry()
    custodians = _custodians(cust)
    ta.configure(custodians, ta.RevocationCache(custodians))
    with pytest.raises(ta.TrustError):
        ta.issue_certificate(_tbs("officer-exp", subject.sig_pk),
                             cust[:2] + [outsider], authorized=custodians)
    rogue = ta.issue_certificate(_tbs("officer-exp", subject.sig_pk),
                                 cust[:2] + [outsider])
    with pytest.raises(ta.TrustError):
        ta.verify_certificate(rogue, custodians)
    now = int(__import__("time").time())
    long_tbs = ta.CertTBS(serial=__import__("secrets").token_bytes(16),
                          subject="officer-exp",
                          subject_pk=bytes(subject.sig_pk),
                          not_before=now - 60, not_after=now + 30 * 24 * 3600)
    with pytest.raises(ta.TrustError):
        ta.issue_certificate(long_tbs, cust[:3], authorized=custodians)
    now = int(time.time())
    stale = ta.CertTBS(serial=secrets.token_bytes(16), subject="officer-exp",
                       subject_pk=bytes(subject.sig_pk),
                       not_before=now - 7200, not_after=now - 3600)
    cert = ta.issue_certificate(stale, cust[:3])
    with pytest.raises(ta.TrustError):
        ta.verify_certificate(cert, custodians)


def test_revocation_quorum_replay_and_gate(tmp_path, monkeypatch):
    cust = _handles(monkeypatch, tmp_path,
                    [f"custodian-{i}" for i in range(1, 6)])
    subject = st.generate_identity_hsm("officer-rev")
    ta.clear_registry()
    custodians = _custodians(cust)
    cache = ta.RevocationCache(custodians)
    ta.configure(custodians, cache)
    cert = ta.issue_certificate(_tbs("officer-rev", subject.sig_pk), cust[:3])
    ta.register_certificate(cert)
    rev = ta.Revocation(serial=bytes(cert.tbs.serial), reason="COMPROMISED",
                        ts=time.time(), seq=1)
    with pytest.raises(ta.TrustError):
        ta.sign_revocation(rev, cust[:2])
    ta.sign_revocation(rev, cust[:3])
    cache.add(rev)
    assert cache.is_revoked(bytes(cert.tbs.serial)) is True
    replay = ta.Revocation(serial=bytes(cert.tbs.serial), reason="COMPROMISED",
                           ts=time.time(), seq=1)
    ta.sign_revocation(replay, cust[2:])
    with pytest.raises(ta.TrustError):
        cache.add(replay)
    # Gate refuses the revoked certificate for the bound key.
    with pytest.raises(ta.TrustError):
        ta.require_cert_for_remote(bytes(subject.sig_pk),
                                   ta.cert_to_json(cert), "officer-rev")


def test_strict_refuses_tofu_without_cert(tmp_path, monkeypatch):
    _handles(monkeypatch, tmp_path, ["custodian-x"])
    monkeypatch.setenv("P2P_REQUIRE_PKI", "1")
    with pytest.raises(ta.TrustError):
        ta.require_cert_for_remote(os.urandom(2592), None, "officer-ghost")


def test_strict_handshake_with_certs_no_tofu(tmp_path, monkeypatch):
    cust = _handles(monkeypatch, tmp_path,
                    [f"custodian-{i}" for i in range(1, 6)])
    alpha = st.generate_identity_hsm("officer-alpha")
    bravo = st.generate_identity_hsm("officer-bravo")
    ta.clear_registry()
    custodians = _custodians(cust)
    cache = ta.RevocationCache(custodians)
    ta.configure(custodians, cache)
    cert_a = ta.issue_certificate(_tbs("officer-alpha", alpha.sig_pk),
                                  cust[:3])
    cert_b = ta.issue_certificate(_tbs("officer-bravo", bravo.sig_pk),
                                  cust[2:])
    monkeypatch.setenv("P2P_REQUIRE_PKI", "1")
    monkeypatch.setenv("P2P_EPHEMERAL", "1")
    kp_a = st.generate_hybrid_keypair(alpha.sig_pk,
                                      alpha.sig_sk or os.urandom(4896))
    kp_b = st.generate_hybrid_keypair(bravo.sig_pk,
                                      bravo.sig_sk or os.urandom(4896))
    # Software lab handles carry sk for the handshake KEX path below.
    if kp_a.sig_sk is None:
        kp_a.sig_sk = alpha.sig_sk
    if kp_b.sig_sk is None:
        kp_b.sig_sk = bravo.sig_sk
    m1, ini, t0 = st.xxhfs_initiate(kp_a, "sess-pki")
    m2, rsp, t_rsp = st.xxhfs_respond(
        m1, kp_b, "sess-pki")
    m3, c_st = st.xxhfs_finalize(
        ini, m2, kp_a, "sess-pki", t0,
        peer_cert=ta.cert_to_json(cert_b), peer_subject="officer-bravo")
    s_st = st.xxhfs_complete(
        rsp, m3, kp_b, "sess-pki", t_rsp,
        peer_cert=ta.cert_to_json(cert_a), peer_subject="officer-alpha")
    assert c_st.key() == s_st.key()
    # Revoked peer aborts the next handshake.
    rev = ta.Revocation(serial=bytes(cert_a.tbs.serial), reason="COMPROMISED",
                        ts=__import__("time").time(), seq=1)
    ta.sign_revocation(rev, cust[:3])
    cache.add(rev)
    m1b, inib, t0b = st.xxhfs_initiate(kp_a, "sess-pki2")
    m2b, rspb, t_rspb = st.xxhfs_respond(m1b, kp_b, "sess-pki2")
    m3b, _cb = st.xxhfs_finalize(inib, m2b, kp_a, "sess-pki2", t0b,
                                 peer_cert=ta.cert_to_json(cert_b),
                                 peer_subject="officer-bravo")
    # The responder gates the revoked initiator certificate at M3.
    with pytest.raises(st.SecurityError):
        st.xxhfs_complete(rspb, m3b, kp_b, "sess-pki2", t_rspb,
                          peer_cert=ta.cert_to_json(cert_a),
                          peer_subject="officer-alpha")
    # Strict without any certificate refuses (no TOFU fallback).
    m1c, inic, t0c = st.xxhfs_initiate(kp_a, "sess-pki3")
    m2c, rspc, t_rspc = st.xxhfs_respond(m1c, kp_b, "sess-pki3")
    m3c, _cc = st.xxhfs_finalize(inic, m2c, kp_a, "sess-pki3", t0c,
                                 peer_cert=ta.cert_to_json(cert_b),
                                 peer_subject="officer-bravo")
    with pytest.raises(st.SecurityError):
        st.xxhfs_complete(rspc, m3c, kp_b, "sess-pki3", t_rspc)


def test_serial_uniqueness_and_revocation_persists(tmp_path, monkeypatch):
    cust = _handles(monkeypatch, tmp_path,
                    [f"custodian-{i}" for i in range(1, 6)])
    subject = st.generate_identity_hsm("officer-serial")
    other = st.generate_identity_hsm("officer-other")
    ta.clear_registry()
    custodians = _custodians(cust)
    cache = ta.RevocationCache(custodians)
    ta.configure(custodians, cache)
    tbs = _tbs("officer-serial", subject.sig_pk)
    ta.register_certificate(ta.issue_certificate(tbs, cust[:3]))
    clash = ta.CertTBS(serial=bytes(tbs.serial), subject="officer-other",
                        subject_pk=bytes(other.sig_pk),
                        not_before=tbs.not_before, not_after=tbs.not_after)
    with pytest.raises(ta.TrustError):
        ta.register_certificate(ta.issue_certificate(clash, cust[2:]))
    old = ta.Revocation(serial=bytes(tbs.serial), reason="COMPROMISED",
                        ts=__import__("time").time() - 30 * 24 * 3600, seq=1)
    ta.sign_revocation(old, cust[:3])
    cache.add(old)
    assert cache.is_revoked(bytes(tbs.serial)) is True


def test_pki_loopback_transfer_over_sockets(tmp_path, monkeypatch):
    import socket as _socket
    import threading as _threading

    import test_secure_transmit_2027 as harness

    harness._isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("P2P_REQUIRE_PKI", "1")
    pki = harness._make_test_pki(tmp_path)
    srv_ctx, cli_ctx = harness._loopback_ctxs(pki)
    cust = [st.generate_identity_hsm(f"custodian-{i}") for i in range(1, 6)]
    alpha = st.generate_identity_hsm("officer-alpha")
    bravo = st.generate_identity_hsm("officer-bravo")
    ta.clear_registry()
    custodians = _custodians(cust)
    ta.configure(custodians, ta.RevocationCache(custodians))
    cert_a = ta.issue_certificate(_tbs("officer-alpha", alpha.sig_pk),
                                  cust[:3])
    cert_b = ta.issue_certificate(_tbs("officer-bravo", bravo.sig_pk),
                                  cust[2:])
    kp_a = st.generate_hybrid_keypair(alpha.sig_pk, alpha.sig_sk)
    kp_b = st.generate_hybrid_keypair(bravo.sig_pk, bravo.sig_sk)
    data = b"PKI-LOOPBACK:" * 80
    lsock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    out, errors = {}, []

    def run_server():
        try:
            out["path"] = st.server_once(
                lsock, srv_ctx, kp_b, "sess-pki-loop",
                out_path=tmp_path / "pki.bin",
                peer_cert=ta.cert_to_json(cert_a),
                peer_subject="officer-alpha")
        except Exception as e:  # noqa: BLE001
            errors.append(e)
        finally:
            try:
                lsock.close()
            except OSError:
                pass

    th = _threading.Thread(target=run_server, daemon=True)
    th.start()
    st.client_send("127.0.0.1", port, cli_ctx, kp_a, "sess-pki-loop", data,
                   server_hostname="loopback-test",
                   peer_cert=ta.cert_to_json(cert_b),
                   peer_subject="officer-bravo")
    th.join(timeout=60)
    assert not errors, errors
    assert out["path"].read_bytes() == data


def test_torrc_pt_gate(tmp_path, monkeypatch):
    import transport_anonymity as _ta

    monkeypatch.setenv("P2P_TOR_PT", "required")
    monkeypatch.setenv("P2P_TORRC", str(tmp_path / "missing-torrc"))
    assert _ta.torrc_enforces_pt() is False
    (tmp_path / "torrc").write_text(
        "# comment only\nUseBridges 1\n"
        "ClientTransportPlugin obfs4 exec /usr/bin/lyrebird\n",
        encoding="utf-8")
    monkeypatch.setenv("P2P_TORRC", str(tmp_path / "torrc"))
    assert _ta.torrc_enforces_pt() is True
    monkeypatch.delenv("P2P_TOR_PT")


def test_ephemeral_memory_pins_no_files(tmp_path, monkeypatch):
    _handles(monkeypatch, tmp_path, ["custodian-e"])
    monkeypatch.setenv("P2P_EPHEMERAL", "1")
    local = os.urandom(2592)
    remote = os.urandom(2592)
    ta.verify_peer_identity("sess:1", local, remote)
    ta.verify_peer_identity("sess:1", local, remote)
    pin_dir = st.PIN_DIR
    assert not pin_dir.exists() or list(pin_dir.glob("*.pin")) == []
    with pytest.raises(ta.TrustError):
        ta.verify_peer_identity("sess:1", local, os.urandom(2592))
    with pytest.raises(ta.TrustError):
        ta.forbid_plaintext_disk(tmp_path / "pins_2027" / "x.pin")
