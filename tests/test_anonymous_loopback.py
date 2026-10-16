#!/usr/bin/env python3
"""End-to-end anonymous transfer over loopback: overlay + TLS + ST2027
handshake + constant-rate uniform cells + dual control. First execution
of the full #4 path on real sockets; fail-closed on any deviation."""

import socket
import threading

import test_secure_transmit_2027 as harness

import secure_transmit_2027 as st
import spo_dpo as ceremony
import transport_anonymity as ta


def _lab(tmp_path, monkeypatch):
    harness._isolate(tmp_path, monkeypatch)


def test_anonymous_loopback_top_secret(tmp_path, monkeypatch):
    _lab(tmp_path, monkeypatch)
    pki = harness._make_test_pki(tmp_path)
    srv_ctx, cli_ctx = harness._loopback_ctxs(pki)
    cli_h = st.generate_identity_hsm("cli-anon")
    srv_h = st.generate_identity_hsm("srv-anon")
    data = b"ANON-TOP-SECRET:" * 64  # ~1KB through uniform cells
    ch = ceremony.issue_challenge("op-anon-loop", "TOP SECRET", data)
    a1 = ceremony.create_approval(cli_h, ch)
    # NOTE: dual control binds the two endpoint identities that authorize
    # this movement; either handle order is accepted by authorize_dpo.
    receipt = ceremony.authorize_dpo(ch, cli_h, a1, srv_h,
                                     ceremony.create_approval(srv_h, ch))
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    out, errors = {}, []

    def run_server():
        try:
            out["path"] = ta.anonymous_recv(
                lsock, srv_ctx, srv_h, "loop-peer", tmp_path / "anon.bin",
                classification="TOP SECRET", receipt=receipt)
        except Exception as e:  # noqa: BLE001 — asserted below
            errors.append(e)
        finally:
            try:
                lsock.close()
            except OSError:
                pass

    th = threading.Thread(target=run_server, daemon=True)
    th.start()
    ta.anonymous_send("127.0.0.1", port, cli_ctx, cli_h, "loop-peer", data,
                      classification="TOP SECRET", receipt=receipt,
                      server_hostname="loopback-test")
    # A-12: under full-suite CPU load the server side has occasionally been
    # observed not to finish (flake ~1 in 3 full runs, never in isolation).
    # Wait with a hard bound, then fail with an explicit diagnostic instead
    # of the misleading KeyError('path') a bare join+index would produce.
    th.join(timeout=300)
    if errors:
        import traceback
        for err in errors:
            traceback.print_exception(type(err), err, err.__traceback__)
    assert not errors, errors
    assert not th.is_alive(), (
        "server thread did not finish within 300s (no, or empty, error was"
        " recorded; likely a scheduling stall under load)")
    assert out.get("path") is not None, "server completed without a result"
    assert out["path"].read_bytes() == data
