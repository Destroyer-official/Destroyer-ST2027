"""Diode interface binding + direction enforcement (G3).

Covers:
  1. Transmitter rejects invalid target host/port, unbindable egress
     source, and ifname pinning off Linux (fail-closed).
  2. Egress-pinned transmitter still delivers end-to-end (loopback).
  3. Receiver rejects wildcard binds by default and invalid hosts/ports.
  4. Direction proofs: AST-level -- DiodeTransmitter methods contain no
     recv/recvfrom/listen/accept; DiodeReceiver methods contain no
     send/sendto/connect. (Static guarantee behind the runtime simplex.)
  5. Honesty: module no longer claims physical impossibility (assert the
     corrected docstring).

Fast, loopback only. No network beyond localhost UDP.
"""

import ast
import inspect

import pytest

import tactical_data_diode as diode
from tactical_data_diode import DiodeReceiver, DiodeTransmitter


def test_transmitter_rejects_bad_config():
    with pytest.raises(ValueError):
        DiodeTransmitter(target_host="not an ip!!")
    with pytest.raises(ValueError):
        DiodeTransmitter(target_port=99999)
    with pytest.raises(ValueError):
        DiodeTransmitter(egress_source_ip="999.1.1.1")
    import os
    if os.name != "posix":
        with pytest.raises(ValueError):
            DiodeTransmitter(egress_ifname="eth0")


def test_transmitter_egress_pinned_roundtrip():
    rx = DiodeReceiver(bind_host="127.0.0.1", bind_port=55231)
    tx = DiodeTransmitter(target_host="127.0.0.1", target_port=55231,
                          chunk_payload_size=64, egress_source_ip="127.0.0.1")
    try:
        assert tx._explicit_bind is True  # nosec: B101
        assert tx._sock.getsockname()[0] == "127.0.0.1"  # nosec: B101
        tx_id = tx.send_payload(b"diode-binding-probe-payload", k=4, m=2,
                                burst_interpacket_delay_ms=0)
        assert isinstance(tx_id, bytes) and len(tx_id) == 16  # nosec: B101
        out = rx.receive_payload(timeout_seconds=5.0)
        assert out == b"diode-binding-probe-payload"  # nosec: B101
    finally:
        tx.close()
        rx.close()


def test_transmitter_unpinned_by_default():
    tx = DiodeTransmitter(target_host="127.0.0.1", target_port=55232)
    try:
        assert tx._explicit_bind is False  # nosec: B101
    finally:
        tx.close()


def test_receiver_rejects_wildcard_and_bad_config():
    # nosec B104 (both lines): wildcard literals below are NEGATIVE test
    # vectors asserting the constructor REFUSES them (fail-closed proof).
    with pytest.raises(ValueError):
        DiodeReceiver(bind_host="0.0.0.0", bind_port=55233)  # nosec B104
    with pytest.raises(ValueError):
        DiodeReceiver(bind_host="::", bind_port=55233)  # nosec B104
    with pytest.raises(ValueError):
        DiodeReceiver(bind_host="not an ip", bind_port=55233)
    with pytest.raises(ValueError):
        DiodeReceiver(bind_host="127.0.0.1", bind_port=0)
    # Explicit opt-in still constructs (logged loudly by the module).
    rx = DiodeReceiver(bind_host="127.0.0.1", bind_port=55234,
                       allow_wildcard=True)
    rx.close()


def _class_source(cls):
    return inspect.getsource(cls)


def test_direction_enforced_statically():
    tx_src = _class_source(DiodeTransmitter)
    tx_tree = ast.parse(tx_src)
    tx_calls = {n.func.attr for n in ast.walk(tx_tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert (  # nosec: B101
        not ({"recv", "recvfrom", "listen", "accept"} & tx_calls)
    ), f"transmitter must never receive: {tx_calls}"
    rx_src = _class_source(DiodeReceiver)
    rx_tree = ast.parse(rx_src)
    rx_calls = {n.func.attr for n in ast.walk(rx_tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert (  # nosec: B101
        not ({"send", "sendto", "connect"} & rx_calls)
    ), f"receiver must never transmit: {rx_calls}"


def test_no_physical_impossibility_claim():
    import tactical_data_diode as mod
    doc = (mod.__doc__ or "").lower()
    assert "absolute physical impossibility" not in doc  # nosec: B101
    assert "optical diode hardware" in doc or "hardware" in doc  # nosec: B101

