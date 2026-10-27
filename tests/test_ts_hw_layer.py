#!/usr/bin/env python3
"""Production tests for ts_hw_layer — REAL probes, REAL crypto, REAL sockets.

Fail-closed assertions are environment-aware: where this dev box lacks
hardware (no FIPS provider, no HSM), tests assert the layer REFUSES TOP
SECRET operation — documenting the box as unqualified, which is the
correct secure behavior.
"""

import json
import os
import socket
import struct
import threading
from pathlib import Path

import pytest

import ts_hw_layer as ts


def _clean_env(monkeypatch):
    for v in ("P2P_TS_MODE", "P2P_PRODUCTION", "P2P_FIPS_RECORD",
              "P2P_TEMPEST_REGISTRY", "P2P_DIODE_REGISTRY", "TS_MESH_TEST_ARM"):
        monkeypatch.delenv(v, raising=False)


# --- TS-1: FIPS provider gate ------------------------------------------------
@pytest.mark.live
def test_fips_probe_is_real_and_fail_closed_without_record(monkeypatch):
    _clean_env(monkeypatch)
    st = ts.check_fips_provider()
    assert isinstance(st.provider_loaded, bool)
    assert st.openssl_info >= (3, 0)
    # No CMVP record provisioned -> TOP SECRET refused regardless of provider.
    with pytest.raises(ts.TSRequiredError):
        ts.require_fips_module()


@pytest.mark.hermetic
def test_cmvp_record_validation(tmp_path, monkeypatch):
    import ts_runtime as _rt
    from liboqs_wrapper import LibOQS_MLDSA_87
    pk, sk = LibOQS_MLDSA_87().keygen()
    monkeypatch.setattr(_rt, "PLATFORM_ROOT_PK_HEX", pk.hex())

    def _signed(record: dict, name: str) -> Path:
        from liboqs_wrapper import LibOQS_MLDSA_87 as _S
        raw = json.dumps(record).encode("utf-8")
        p = tmp_path / name
        p.write_bytes(raw)
        (tmp_path / (name + ".sig")).write_text(
            _S().sign(sk, raw).hex(), encoding="utf-8")
        return p

    good = {"module": "OpenSSL FIPS Provider", "version": "3.1.2",
            "cmvp_cert": "4985", "valid_through": "2030-03-10"}
    p = _signed(good, "fips.json")
    rec = ts.check_cmvp_record(p)
    assert rec["ok"] and rec["known_good"]
    bad = dict(good, valid_through="2020-01-01")
    p.write_bytes(json.dumps(bad).encode("utf-8"))
    (tmp_path / "fips.json.sig").write_text(
        LibOQS_MLDSA_87().sign(sk, p.read_bytes()).hex(), encoding="utf-8")
    assert not ts.check_cmvp_record(p)["ok"]
    assert not ts.check_cmvp_record(tmp_path / "missing.json")["ok"]


@pytest.mark.live
def test_unsigned_cmvp_fails_closed(tmp_path, monkeypatch):
    """Verification gate Task 3.2: unsigned CMVP records never authorize."""
    import ts_runtime as _rt
    from liboqs_wrapper import LibOQS_MLDSA_87
    pk, sk = LibOQS_MLDSA_87().keygen()
    monkeypatch.setattr(_rt, "PLATFORM_ROOT_PK_HEX", pk.hex())
    good = {"module": "OpenSSL FIPS Provider", "version": "3.1.2",
            "cmvp_cert": "4985", "valid_through": "2030-03-10"}
    # Valid record, no sidecar: refused.
    p = tmp_path / "nosig.json"
    p.write_text(json.dumps(good), encoding="utf-8")
    r = ts.check_cmvp_record(p)
    assert not r["ok"] and "signature missing" in r["reason"]
    # Valid record, stale signature over different bytes: refused.
    q = tmp_path / "stale.json"
    q.write_bytes(json.dumps(good).encode("utf-8"))
    (tmp_path / "stale.json.sig").write_text(
        LibOQS_MLDSA_87().sign(sk, b"other bytes").hex(), encoding="utf-8")
    assert not ts.check_cmvp_record(q)["ok"]
    # Wrong-key signature: refused.
    evil_pk, evil_sk = LibOQS_MLDSA_87().keygen()
    assert evil_pk != pk
    w = tmp_path / "wrongkey.json"
    w.write_bytes(json.dumps(good).encode("utf-8"))
    (tmp_path / "wrongkey.json.sig").write_text(
        LibOQS_MLDSA_87().sign(evil_sk, w.read_bytes()).hex(), encoding="utf-8")
    assert not ts.check_cmvp_record(w)["ok"]
    with pytest.raises(ts.TSRequiredError):
        ts.require_fips_module(p)


@pytest.mark.live
def test_fips_cipher_probe_is_real(monkeypatch):
    """Task 3.3 gate: ?fips=yes fetch resolves (or refuses) via live C API."""
    _clean_env(monkeypatch)
    res = ts.check_fips_cipher()
    assert isinstance(res.get("ok"), bool)
    assert "provider" in res or "reason" in res
    # This dev box has no FIPS provider: the probe must report refusal,
    # never raise, and the TS gate must refuse on top of it.
    prov = ts.check_fips_provider()
    if not prov.provider_loaded:
        assert res["ok"] is False
        with pytest.raises(ts.TSRequiredError):
            ts.require_fips_module()
    else:
        # On a provisioned host the cipher MUST resolve to fips itself
        # (the name check is what makes ?fips=yes enforcing).
        assert res == {"ok": True, "provider": "fips"}


# --- TS-1b: hardware custody --------------------------------------------------
@pytest.mark.live
def test_custody_probe_and_gate_are_honest(monkeypatch):
    _clean_env(monkeypatch)
    att = ts.probe_hardware_custody()
    assert isinstance(att.hardware, bool)
    if not att.hardware:
        with pytest.raises(ts.TSRequiredError):
            ts.require_hardware_custody("test keys")
    else:
        assert ts.require_hardware_custody("test keys").hardware


# --- TS-2: RED/BLACK ----------------------------------------------------------
def _black_ip():
    import psutil
    for ifname, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                return a.address, ifname
    return None, None


@pytest.mark.live
def test_red_black_valid_separation():
    black, _if = _black_ip()
    if black is None:
        pytest.skip("no non-loopback NIC on this box")
    cfg = ts.RedBlackConfig(red_bind="127.0.0.1", black_bind=black)
    rep = ts.verify_red_black(cfg)
    assert rep["ok"] and rep["red_iface"] != rep["black_iface"]


@pytest.mark.live
def test_red_black_refusals():
    black, _if = _black_ip()
    with pytest.raises(ts.TSError):  # RED on external/wildcard
        ts.verify_red_black(ts.RedBlackConfig(red_bind="0.0.0.0", black_bind=black or "10.0.0.5"))  # nosec B104 - negative test verifying refusal of wildcard
    with pytest.raises(ts.TSError):  # BLACK on loopback in separated operation
        ts.verify_red_black(ts.RedBlackConfig(red_bind="127.0.0.1", black_bind="127.0.0.1"))
    with pytest.raises(ts.TSError):  # wildcard BLACK
        ts.enforce_bind("BLACK", "0.0.0.0")  # nosec B104 - negative test verifying refusal of wildcard
    assert ts.enforce_bind("BLACK", "127.0.0.1", strict_black_loopback=False) == "127.0.0.1"
    with pytest.raises(ts.TSError):
        ts.enforce_bind("RED", "8.8.8.8")


# --- TS-3: TEMPEST registry ---------------------------------------------------
def _write_tempest(tmp: Path, certs) -> Path:
    p = tmp / "tempest.json"
    p.write_text(json.dumps({"certs": certs}))
    return p


def _cert(**kw):
    base = {"facility": "SCIF-1", "zone": 1, "level": "B", "standard": "SDIP-27/3",
            "nta_ref": "NTA-2025-001", "vendor_niapc_ref": "NIAPC-V-88",
            "issued": "2025-01-15", "expires": "2028-01-15",
            "zone_report_ref": "SDIP-28-RPT-7", "install_ref": "SDIP-29-INST-7",
            "classifications": ["SECRET", "TOP SECRET"]}
    base.update(kw)
    return base


@pytest.mark.hermetic
def test_tempest_approval_and_level_mapping(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    reg = _write_tempest(tmp_path, [_cert()])
    cert = ts.require_tempest_approval(1, "SECRET", reg)
    assert cert.level == "B"
    # TOP SECRET in Zone 1 needs Level A under this gate's TOP_SECRET rule.
    with pytest.raises(ts.TSRequiredError):
        ts.require_tempest_approval(1, "TOP SECRET", reg)
    reg_a = _write_tempest(tmp_path, [_cert(zone=0, level="A")])
    assert ts.require_tempest_approval(0, "TOP SECRET", reg_a).level == "A"
    # Zone 0 with only Level B -> refused.
    reg_b = _write_tempest(tmp_path, [_cert(zone=0, level="B")])
    with pytest.raises(ts.TSRequiredError):
        ts.require_tempest_approval(0, "TOP SECRET", reg_b)


@pytest.mark.hermetic
def test_tempest_expiry_and_missing_refs_refused(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    reg = _write_tempest(tmp_path, [_cert(expires="2020-01-01")])
    with pytest.raises(ts.TSRequiredError):
        ts.require_tempest_approval(1, "SECRET", reg)
    reg2 = _write_tempest(tmp_path, [_cert(zone_report_ref="", install_ref="")])
    with pytest.raises(ts.TSRequiredError):
        ts.require_tempest_approval(1, "SECRET", reg2)
    with pytest.raises((ts.TSRequiredError, ts.TSError)):
        ts.require_tempest_approval(1, "SECRET", tmp_path / "absent.json")


@pytest.mark.hermetic
def test_emission_hygiene_never_claims_shielding():
    notes = {n["id"]: n for n in ts.emission_hygiene()}
    assert notes["SHIELDING"]["status"] == "FACILITY-REQUIRED"


# --- TS-4: zeroize mesh ---------------------------------------------------------
@pytest.mark.hermetic
def test_mesh_zeroizes_real_buffers_and_callbacks(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("TS_MESH_TEST_ARM", "1")
    mesh = ts.ZeroizeMesh(audit_dir=tmp_path)
    mesh.arm()
    assert mesh.armed and not mesh.zeroized
    buf = bytearray(b"TOP-SECRET-KEY-MATERIAL-0123456789")
    ran = []
    mesh.register_buffer(buf)
    mesh.register_callback(lambda: ran.append(1))
    mesh.note_heartbeat()
    rep = ts.inject_test_tamper(mesh)
    assert mesh.zeroized and ran == [1]
    assert all(b == 0 for b in buf)  # real shredding, read-back verified inside
    assert (tmp_path / "emergency_zeroization_audit.json").exists()
    assert rep["emergency_zeroization_audit"]["status"] == "SANITIZATION_COMPLETE"


@pytest.mark.hermetic
def test_test_injector_refused_in_production(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    monkeypatch.setenv("TS_MESH_TEST_ARM", "1")
    from emergency_anti_tamper import EmergencyZeroizationEngine
    mesh = ts.ZeroizeMesh(audit_dir=tmp_path,
                          engine=EmergencyZeroizationEngine(audit_dir=tmp_path))
    mesh.arm()
    with pytest.raises(ts.TSError):
        ts.inject_test_tamper(mesh)
    assert not mesh.zeroized


@pytest.mark.hermetic
def test_tamper_order_verify_replay_and_forgery(monkeypatch):
    _clean_env(monkeypatch)
    from liboqs_wrapper import LibOQS_MLDSA_87
    pk, sk = LibOQS_MLDSA_87().keygen()
    import time as _t
    body_nonce = os.urandom(8).hex()
    body = b"TS-TAMPER-v1" + ts.TamperSource.OPERATOR_DURESS.encode() + body_nonce.encode() \
        + struct.pack(">Q", int(_t.time() * 1000))
    order = {"action": ts.TamperSource.OPERATOR_DURESS, "nonce": body_nonce,
             "ts": _t.time(), "sig": LibOQS_MLDSA_87().sign(sk, body).hex()}
    ok = ts.verify_tamper_order(order, pk.hex())
    assert ok.action == ts.TamperSource.OPERATOR_DURESS
    with pytest.raises(ts.TSError):  # replay
        ts.verify_tamper_order(order, pk.hex())
    pk2, _ = LibOQS_MLDSA_87().keygen()
    order2 = dict(order, nonce=os.urandom(8).hex())
    with pytest.raises(ts.TSError):  # wrong authority key
        ts.verify_tamper_order(order2, pk2.hex())


@pytest.mark.hermetic
def test_heartbeat_loss_triggers_mesh(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("TS_MESH_TEST_ARM", "1")
    mesh = ts.ZeroizeMesh(audit_dir=tmp_path)
    mesh.arm()
    mesh._last_heartbeat -= 3600.0
    mesh.check_heartbeat(max_age_s=60.0)
    assert mesh.zeroized


# --- TS-5: diode gate + simplex transfer --------------------------------------
def _write_diode(tmp: Path, devs) -> Path:
    p = tmp / "diodes.json"
    p.write_text(json.dumps({"devices": devs}))
    return p


def _dev(**kw):
    base = {"device_id": "DIODE-01", "vendor": "ACME", "model": "UGW-200",
            "cc_cert": "EAL4+AVA_VAN.5", "cc_id": "NSCIB-CC-000",
            "tx_only_attested": True, "install_ref": "OE.NETWORK-SOLO-1",
            "valid_through": "2028-01-01", "direction": "low-to-high"}
    base.update(kw)
    return base


@pytest.mark.hermetic
def test_diode_registry_gate(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    reg = _write_diode(tmp_path, [_dev()])
    assert ts.require_diode("DIODE-01", reg).cc_cert == "EAL4+AVA_VAN.5"
    reg_exp = _write_diode(tmp_path, [_dev(valid_through="2020-01-01")])
    with pytest.raises(ts.TSRequiredError):
        ts.require_diode("DIODE-01", reg_exp)
    reg_notx = _write_diode(tmp_path, [_dev(tx_only_attested=False)])
    with pytest.raises(ts.TSRequiredError):
        ts.require_diode("DIODE-01", reg_notx)
    with pytest.raises(ts.TSRequiredError):
        ts.require_diode("DIODE-01", None)


@pytest.mark.live
def test_diode_simplex_transfer_loopback(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    from liboqs_wrapper import LibOQS_MLDSA_87
    pk, sk = LibOQS_MLDSA_87().keygen()
    blob = b"STRATEGIC-PAYLOAD:" * 64
    port = 55431
    got = {}

    def rx():
        got["blob"] = ts.diode_receive("127.0.0.1", port, pk, timeout_seconds=20.0)

    th = threading.Thread(target=rx, daemon=True)
    th.start()
    import time as _t
    _t.sleep(0.3)
    tx_id = ts.diode_send(blob, sk, "kid-1", "127.0.0.1", port,
                          egress_source_ip="127.0.0.1", k=8, m=4)
    th.join(timeout=30)
    assert isinstance(tx_id, bytes) and got.get("blob") == blob


@pytest.mark.live
def test_diode_send_via_identity_handle_and_prod_refusal(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    import secure_transmit_2027 as s
    s.PIN_DIR = tmp_path / "pins"
    s._audit_chain = None
    monkeypatch.setenv("P2P_SIEM_LEDGER", str(tmp_path / "audit.jsonl"))
    handle = s.generate_identity_hsm("diode-handle")
    assert not handle.stored_in_hsm  # lab software handle on this box
    blob = b"HANDLE-SIGNED:" * 32
    port = 55432
    got = {}

    def rx():
        got["blob"] = ts.diode_receive("127.0.0.1", port, handle.sig_pk,
                                       timeout_seconds=20.0)

    th = threading.Thread(target=rx, daemon=True)
    th.start()
    import time as _t
    _t.sleep(0.3)
    ts.diode_send(blob, handle, "kid-h", "127.0.0.1", port,
                  egress_source_ip="127.0.0.1", k=8, m=4)
    th.join(timeout=30)
    assert got.get("blob") == blob
    # Raw-key signing is refused the moment production/TS custody applies.
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    from liboqs_wrapper import LibOQS_MLDSA_87
    _, raw_sk = LibOQS_MLDSA_87().keygen()
    with pytest.raises(ts.TSRequiredError):
        ts.diode_send(b"x", raw_sk, "kid-1", "127.0.0.1", port)


@pytest.mark.hermetic
def test_diode_tamper_and_wrong_key_refused(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    from liboqs_wrapper import LibOQS_MLDSA_87
    pk, sk = LibOQS_MLDSA_87().keygen()
    pkg = ts._diode_package(b"secret", sk, "kid-1")
    bad = bytearray(pkg)
    bad[-1] ^= 0x01
    with pytest.raises(ts.TSError):
        ts._diode_open(bytes(bad), pk)
    pk2, _ = LibOQS_MLDSA_87().keygen()
    with pytest.raises(ts.TSError):
        ts._diode_open(pkg, pk2)


# --- TPM PCR path ---------------------------------------------------------------
@pytest.mark.live
def test_tpm_pcr_read_unknown_on_tpm_less_box(monkeypatch):
    _clean_env(monkeypatch)
    r = ts.read_tpm_pcrs((0, 1))
    # This dev box exposes no TPM: UNKNOWN (None), never trusted.
    # On TPM-equipped hosts this returns real SHA-256 PCR digests.
    assert r is None or (isinstance(r, dict) and all(len(v) == 64 for v in r.values()))
    c = ts.check_tpm_pcr({0: "00" * 32})
    assert c is None or isinstance(c, bool)
    with pytest.raises(ts.TSError):
        ts.check_tpm_pcr({})


@pytest.mark.live
def test_mesh_pcr_poll_ignores_unknown(monkeypatch, tmp_path):
    _clean_env(monkeypatch)
    monkeypatch.setenv("TS_MESH_TEST_ARM", "1")
    from emergency_anti_tamper import EmergencyZeroizationEngine
    if ts.read_tpm_pcrs((0,)) is not None:
        pytest.skip("TPM present: live-PCR test needs pinned policy")
    mesh = ts.ZeroizeMesh(audit_dir=tmp_path,
                          engine=EmergencyZeroizationEngine(audit_dir=tmp_path),
                          pcr_expected={0: "00" * 32})
    mesh.arm()
    mesh.poll_sensors()  # UNKNOWN must never trigger
    assert not mesh.zeroized


@pytest.mark.hermetic
def test_unarmed_mesh_dispatch_refused(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    from emergency_anti_tamper import EmergencyZeroizationEngine
    mesh = ts.ZeroizeMesh(audit_dir=tmp_path,
                          engine=EmergencyZeroizationEngine(audit_dir=tmp_path))
    assert not mesh.armed
    with pytest.raises(ts.TSError):
        mesh.dispatch(ts.TamperEvent(ts.TamperSource.CHASSIS_INTRUSION, "x"))


# --- hardening: registries, nonces, params, roles --------------------------------
@pytest.mark.hermetic
def test_registry_shape_violations_refused(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    bad_list = tmp_path / "list.json"
    bad_list.write_text(json.dumps([1, 2, 3]))
    with pytest.raises(ts.TSError):
        ts.load_tempest_registry(bad_list)
    with pytest.raises(ts.TSError):
        ts.load_diode_registry(bad_list)
    bad_entry = tmp_path / "entry.json"
    bad_entry.write_text(json.dumps({"certs": ["not-an-object"]}))
    with pytest.raises(ts.TSError):
        ts.load_tempest_registry(bad_entry)
    bad_zone = tmp_path / "zone.json"
    bad_zone.write_text(json.dumps({"certs": [{
        "facility": "F", "zone": True, "level": "A", "expires": "2028-01-01",
        "zone_report_ref": "R", "install_ref": "I",
        "classifications": ["TOP SECRET"]}]}))
    with pytest.raises(ts.TSError):
        ts.load_tempest_registry(bad_zone)
    bad_dev = tmp_path / "dev.json"
    bad_dev.write_text(json.dumps({"devices": [{"vendor": "V"}]}))
    with pytest.raises(ts.TSError):
        ts.load_diode_registry(bad_dev)
    assert not ts.check_cmvp_record(bad_list)["ok"]


@pytest.mark.hermetic
def test_tamper_order_nonce_cap_evicts_fifo(monkeypatch):
    _clean_env(monkeypatch)
    from liboqs_wrapper import LibOQS_MLDSA_87
    import time as _t
    pk, sk = LibOQS_MLDSA_87().keygen()

    def order(nonce):
        now = _t.time()
        body = b"TS-TAMPER-v1" + ts.TamperSource.OPERATOR_DURESS.encode() + nonce.encode() \
            + struct.pack(">Q", int(now * 1000))
        return {"action": ts.TamperSource.OPERATOR_DURESS, "nonce": nonce,
                "ts": now, "sig": LibOQS_MLDSA_87().sign(sk, body).hex()}

    # Pre-fill to cap-1 with synthetic entries, then two real orders:
    # size must stay bounded at cap (FIFO eviction, still verifies).
    ts._USED_ORDER_NONCES.clear()
    ts._ORDER_NONCE_FIFO.clear()
    for i in range(ts.ORDER_NONCE_CAP - 1):
        ts._USED_ORDER_NONCES.add(f"fill-{i}")
        ts._ORDER_NONCE_FIFO.append(f"fill-{i}")
    ts.verify_tamper_order(order("real-1"), pk.hex())
    assert len(ts._USED_ORDER_NONCES) == ts.ORDER_NONCE_CAP
    ts.verify_tamper_order(order("real-2"), pk.hex())
    assert len(ts._USED_ORDER_NONCES) == ts.ORDER_NONCE_CAP
    assert "fill-0" not in ts._USED_ORDER_NONCES  # oldest evicted
    ts._USED_ORDER_NONCES.clear()
    ts._ORDER_NONCE_FIFO.clear()


@pytest.mark.hermetic
def test_injector_refused_in_ts_mode(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("P2P_TS_MODE", "1")
    monkeypatch.setenv("TS_MESH_TEST_ARM", "1")
    from emergency_anti_tamper import EmergencyZeroizationEngine
    mesh = ts.ZeroizeMesh(audit_dir=tmp_path,
                          engine=EmergencyZeroizationEngine(audit_dir=tmp_path))
    mesh.arm()
    with pytest.raises(ts.TSError):
        ts.inject_test_tamper(mesh)
    assert not mesh.zeroized


@pytest.mark.hermetic
def test_register_buffer_rejects_immutable(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    from emergency_anti_tamper import EmergencyZeroizationEngine
    mesh = ts.ZeroizeMesh(audit_dir=tmp_path,
                          engine=EmergencyZeroizationEngine(audit_dir=tmp_path))
    with pytest.raises(ts.TSError):
        mesh.register_buffer(b"immutable-bytes")


@pytest.mark.hermetic
def test_enforce_bind_unknown_role_refused():
    with pytest.raises(ts.TSError):
        ts.enforce_bind("GREEN", "127.0.0.1")


@pytest.mark.hermetic
def test_diode_parameter_violations():
    from liboqs_wrapper import LibOQS_MLDSA_87
    _, sk = LibOQS_MLDSA_87().keygen()
    for kw in ({"k": 0}, {"m": -1}, {"k": True}, {"k": 65}):
        with pytest.raises(ts.TSError):
            ts.diode_send(b"data", sk, "kid", "127.0.0.1", 55433, **kw)
    with pytest.raises(ts.TSError):
        ts.diode_send(b"data", sk, "x" * 129, "127.0.0.1", 55433)
    with pytest.raises(ts.TSError):
        ts.diode_send(b"", sk, "kid", "127.0.0.1", 55433)
    with pytest.raises(ts.TSError):
        ts.diode_receive("127.0.0.1", 0, b"pk")
    with pytest.raises(ts.TSError):
        ts.diode_receive("127.0.0.1", 55433, b"pk", timeout_seconds=-1.0)
    with pytest.raises(ts.TSError):
        ts.check_tpm_pcr({True: "00" * 64})
    with pytest.raises(ts.TSError):
        ts.check_tpm_pcr("not-a-dict")


@pytest.mark.hermetic
def test_profile_from_env_strictness(monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("P2P_TS_ZONE", "5")
    with pytest.raises(ts.TSError):
        ts.profile_from_env()
    monkeypatch.setenv("P2P_TS_ZONE", "1")
    monkeypatch.setenv("P2P_BLACK_PORT", "never")
    with pytest.raises(ts.TSError):
        ts.profile_from_env()


@pytest.mark.live
def test_red_black_nets_and_port_types():
    with pytest.raises(ts.TSError):
        ts.verify_red_black(ts.RedBlackConfig(
            red_bind="127.0.0.1", black_bind="10.9.9.9",
            red_allow_nets=("not-a-net",)))
    black, _if = None, None
    import socket as _s
    import psutil as _ps
    for ifname, addrs in _ps.net_if_addrs().items():
        for a in addrs:
            if a.family == _s.AF_INET and not a.address.startswith("127."):
                black = a.address
                break
    if black is None:
        pytest.skip("no non-loopback NIC on this box")
    cfg = ts.RedBlackConfig(red_bind="127.0.0.1", black_bind=black)
    cfg.black_port = True
    with pytest.raises(ts.TSError):
        ts.verify_red_black(cfg)


@pytest.mark.live
def test_cli_recv_ts_mode_refused_without_hardware(monkeypatch, tmp_path):
    _clean_env(monkeypatch)
    monkeypatch.setenv("P2P_TS_MODE", "1")
    import secure_transmit_2027 as s
    with pytest.raises(Exception):
        s.main(["recv", "--port", "18888", "--cert", "c", "--key", "k",
                "--ca", "ca", "--peer-id", "p", "--out", str(tmp_path / "o"),
                "--label", "lab-cli-ts"])


@pytest.mark.hermetic
def test_ts_prefix_required_in_ts_mode_only(monkeypatch):
    _clean_env(monkeypatch)
    import secure_transmit_2027 as s
    monkeypatch.delenv("P2P_PEER_PREFIX", raising=False)
    assert s.require_peer_prefix() == ""  # lab: open
    monkeypatch.setenv("P2P_TS_MODE", "1")
    with pytest.raises(s.SecurityError):
        s.require_peer_prefix()
    monkeypatch.delenv("P2P_TS_MODE", raising=False)
    monkeypatch.setenv("P2P_PEER_PREFIX", "10.0.0.0/8")
    with pytest.raises(s.SecurityError):  # IPv4 refused (IPv6 L5 fabric only)
        s.require_peer_prefix()


# --- CNG TPM-backed device custody (REAL hardware ops) ------------------------------
def _cng_or_skip():
    import cng_platform
    try:
        h = cng_platform.open_platform_provider()
    except Exception:
        pytest.skip("no CNG platform provider on this host")
        return None
    cng_platform.close_handle(h)
    return cng_platform


@pytest.mark.live
def test_cng_tpm_roundtrip_with_non_export_proof():
    cng = _cng_or_skip()
    import hashlib as _hl
    name = f"TS-TEST-{os.getpid()}-RT"
    h = cng.open_platform_provider()
    k = None
    try:
        if cng.device_key_exists(h, name):
            raise AssertionError("stale test key present")
        k = cng.create_device_key(h, name)
        pub = cng.export_pubkey_blob(k)
        assert len(pub) == 72  # P-256 ECCPUBLICBLOB
        cng.prove_non_exportable(k)  # private half must NOT leave the TPM
        dgst = _hl.sha256(b"TS-DEVICE-PROOF").digest()
        sig = cng.sign_digest(k, dgst)
        assert len(sig) == 64  # raw R||S
        cng.verify_with_key(k, dgst, sig)  # must not raise
        with pytest.raises(cng.CngError):
            cng.verify_with_key(k, dgst, bytes(b ^ 0x01 for b in sig))
        with pytest.raises(cng.CngError):
            cng.sign_digest(k, b"short")
        cng.delete_key(k)
        k = None
        assert not cng.device_key_exists(h, name)  # deletion proven by absence
    finally:
        try:
            if k is not None:
                cng.delete_key(k)
        except Exception:
            pass
        try:
            if cng.device_key_exists(h, name):
                kk = cng.open_device_key(h, name)
                cng.delete_key(kk)
        except Exception:
            pass
        cng.close_handle(h)


@pytest.mark.live
def test_cng_attest_and_labels():
    cng = _cng_or_skip()
    import hashlib as _hl
    name = f"TS-TEST-{os.getpid()}-AT"
    h = cng.open_platform_provider()
    k = None
    try:
        k = cng.create_device_key(h, name)
        nonce = os.urandom(32)
        sig, pub = cng.tpm_device_attest(k, nonce)
        body = _hl.sha256(cng.DEVICE_ATTEST_DOMAIN + nonce).digest()
        cng.verify_with_key(k, body, sig)
        with pytest.raises(cng.CngError):
            cng.tpm_device_attest(k, b"bad-nonce")
        with pytest.raises(cng.CngError):
            cng.create_device_key(h, "bad label!")
        cng.delete_key(k)
        k = None
    finally:
        try:
            if k is not None:
                cng.delete_key(k)
        except Exception:
            pass
        cng.close_handle(h)


@pytest.mark.live
def test_custody_tiers_honest_on_this_box(monkeypatch):
    _clean_env(monkeypatch)
    assert ts.probe_pqc_token() is None      # no PQC token present
    assert ts.probe_kek_wrap() is None       # no HW AES/KEK present
    dev = ts.probe_tpm_device()
    import sys as _sys
    if _sys.platform != "win32":
        assert dev is None
    else:
        assert dev is not None and dev.tier == "TPM-DEVICE"
    # Data-plane custody still correctly refused: DEV tier is auth-only.
    with pytest.raises(ts.TSRequiredError) as ei:
        ts.require_hardware_custody("TOP SECRET session keys")
    assert "TPM device anchor" in str(ei.value) or "no hardware" in str(ei.value)


# --- Aggregator + session hook --------------------------------------------------
@pytest.mark.live
def test_ts_layer_fail_closed_without_provisioning(monkeypatch, tmp_path):
    _clean_env(monkeypatch)
    with pytest.raises((ts.TSRequiredError, ts.TSError)):
        ts.require_ts_layer(ts.TSLayerProfile(zone=1))


@pytest.mark.live
def test_ts_mode_hook_blocks_session_without_hardware(monkeypatch, tmp_path):
    _clean_env(monkeypatch)
    import secure_transmit_2027 as s
    monkeypatch.setenv("P2P_TS_MODE", "1")
    monkeypatch.setenv("P2P_SIEM_LEDGER", str(tmp_path / "audit.jsonl"))
    s._audit_chain = None
    s.PIN_DIR = tmp_path / "pins"
    with pytest.raises(Exception):
        s._production_preflight("127.0.0.1", "cdn-front.example.net", 8888, "peerX")


# --- Mock audit & live/hermetic separation gate (Task 4.4) --------------------
# This suite uses NO standard-library mock-framework fakes: hermetic tests
# run pure logic over synthetic tmp inputs (monkeypatch env only); live
# tests probe real host state (libcrypto, TPM/CNG, NICs, loopback sockets)
# and adapt with environment-aware refusal assertions. Every test carries
# exactly one marker (@pytest.mark.live / @pytest.mark.hermetic); the gate
# below enforces the separation mechanically (it scans for mock-framework
# imports and mock-object constructors, then audits marker coverage).
def test_suite_mock_live_separation():
    """Verification gate Task 4.4: mock audit + marker separation."""
    import ast
    from pathlib import Path as _P
    src = _P(__file__).read_text(encoding="utf-8")
    # Needles constructed dynamically: a literal here would match itself.
    _um = "unittest" + ".mock"
    _fuim = "from " + "unittest" + " import " + "mock"
    _mo = "Mock" + "("
    _mmo = "MagicMock" + "("
    assert _um not in src and _fuim not in src
    assert _mo not in src and _mmo not in src
    tree = ast.parse(src)
    multi, unmarked = [], []
    n_live = n_hermetic = 0
    for node in ast.walk(tree):
        if not (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test_")):
            continue
        if node.name == "test_suite_mock_live_separation":
            continue
        marks = set()
        for d in node.decorator_list:
            f = d.func if isinstance(d, ast.Call) else d
            parts = []
            while isinstance(f, ast.Attribute):
                parts.append(f.attr)
                f = f.value
            if parts and parts[-1] == "mark":
                marks.add(parts[0])
        has_live = "live" in marks
        has_her = "hermetic" in marks
        if has_live and has_her:
            multi.append(node.name)
        elif has_live:
            n_live += 1
        elif has_her:
            n_hermetic += 1
        else:
            unmarked.append(node.name)
    assert not multi, f"dual-marked: {multi}"
    assert not unmarked, f"unmarked tests (separation violated): {unmarked}"
    assert n_live >= 1 and n_hermetic >= 1
