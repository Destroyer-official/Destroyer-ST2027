#!/usr/bin/env python3
"""Production tests for ts_runtime — REAL posture reads, REAL native core.

Fail-closed assertions are environment-aware: this dev box runs an
unenforced consumer OS (Secure Boot off, VBS/HVCI off, x86-64), so TS-mode
gates must REFUSE it — asserting the refusal documents the box as
unqualified, which is the correct secure behavior.
"""

import json
import os
import random
import struct
from pathlib import Path

import pytest

import ts_runtime as rt


def _clean_env(monkeypatch):
    for v in ("P2P_TS_MODE", "P2P_PRODUCTION", "P2P_SEL4_RECORD",
              "P2P_PLATFORM_WAIVER", "P2P_TS_RT_LIB"):
        monkeypatch.delenv(v, raising=False)


# --- native deterministic core -------------------------------------------------
def test_native_loads_selftest_version():
    import re
    ver = rt.native_version()
    # Exact NUL-terminated shape: no over-read garbage allowed.
    assert re.fullmatch(r"ts_rt 1\.0\.0 \[rustc [^]]+\]", ver), ver


def test_locked_buffer_lifecycle():
    with rt.LockedBuffer(64) as b:
        assert b.size == 64
        b.fill(0xA5)
        assert b.compare(b"\xA5" * 64) is True
        assert b.compare(b"\xA5" * 63 + b"\x00") is False
        assert b.compare(b"\xA5" * 32) is False  # length mismatch, no oracle
        assert b.compare("not-bytes") is False
        assert b.compare(bytearray(b"\xA5" * 64)) is True
    with pytest.raises(rt.TSError):
        b.compare(b"\xA5" * 64)  # use-after-destroy refused
    with pytest.raises(rt.TSError):
        rt.LockedBuffer(0)
    with pytest.raises(rt.TSError):
        rt.LockedBuffer((64 << 20) + 1)


def test_native_binding_guards(monkeypatch, tmp_path):
    monkeypatch.setenv("P2P_TS_RT_LIB", str(tmp_path / "absent.dll"))
    rt._native_lib = None
    try:
        with pytest.raises(rt.TSRequiredError):
            rt.load_native()
    finally:
        monkeypatch.delenv("P2P_TS_RT_LIB", raising=False)
        rt._native_lib = None
    n = rt.NativeReplay(9000)
    try:
        with pytest.raises(rt.TSError):
            n.check_and_mark(-1)
        with pytest.raises(rt.TSError):
            n.check_and_mark(1 << 64)
    finally:
        n.close()


def test_native_replay_crosscheck_with_python():
    import secure_transmit_2027 as s
    lib = rt.load_native()
    n = rt.NativeReplay(5000)
    p = s.ReplayWindow()
    p.check_and_mark(5000)  # identical initial state: base=5000, {5000} seen
    rng = random.Random(20260925)
    seqs = [5000 + rng.randrange(0, 200) for _ in range(400)]
    for seq in seqs:
        try:
            n.check_and_mark(seq)
            n_ok = True
        except rt.TSError:
            n_ok = False
        try:
            p.check_and_mark(seq)
            p_ok = True
        except s.SecurityError:
            p_ok = False
        assert n_ok == p_ok, f"divergence at seq {seq}"
    n.close()
    with pytest.raises(rt.TSError):
        n.check_and_mark(5001)  # use-after-close refused


# --- live posture ----------------------------------------------------------------
def test_posture_reads_are_real_and_sane():
    post = rt.read_platform_posture()
    assert post["os"] == "Windows"
    assert post["arch"] in ("x86_64", "amd64", "arm64", "aarch64")
    assert post["secure_boot"] in (True, False, None)
    assert post["vbs_status"] in (None, 0, 1, 2)
    assert post["hvci_running"] in (True, False, None)
    assert post["dma_capable"] in (True, False, None)
    assert post["measured_boot_log"] in (True, False, None, "present-unreadable")
    # Observed on THIS dev box during implementation (informational, and the
    # reason its TS gates refuse it): Secure Boot off, VBS/HVCI unenforced.
    # Asserted structurally above so these tests also pass on hardened hosts.


# --- seL4 record validation ----------------------------------------------------------
def _sel4_record(tmp: Path, **kw) -> Path:
    base = {"board": "QEMU-AArch64-virt", "arch": "aarch64",
            "sel4_version": "16.0.0", "config": "AARCH64_verified",
            "verification_report_ref": "NTA-SEL4-2026-001",
            "measured_boot_binding": {"tpm_quote": "required-at-deploy"}}
    base.update(kw)
    p = tmp / "sel4.json"
    p.write_text(json.dumps(base))
    return p


def test_sel4_record_validation(tmp_path):
    good = rt.load_sel4_record(_sel4_record(tmp_path))
    assert good["tier"] == "SEL4-VERIFIED"
    with pytest.raises(rt.TSError):  # x86_64 never verified
        rt.load_sel4_record(_sel4_record(tmp_path, arch="x86_64",
                                         config="X86_64_verified"))
    with pytest.raises(rt.TSError):  # MCS proved on RISC-V only
        rt.load_sel4_record(_sel4_record(tmp_path, arch="aarch64",
                                         config="AARCH64_MCS_verified"))
    with pytest.raises(rt.TSError):  # predates 16.0.0 critical fixes
        rt.load_sel4_record(_sel4_record(tmp_path, sel4_version="14.0.0",
                                         config="AARCH64_verified"))
    with pytest.raises(rt.TSError):  # unknown config family
        rt.load_sel4_record(_sel4_record(tmp_path, config="AARCH64_custom"))
    with pytest.raises(rt.TSError):  # missing measured-boot binding
        p = tmp_path / "nobind.json"
        rec = json.loads(_sel4_record(tmp_path).read_text())
        del rec["measured_boot_binding"]
        p.write_text(json.dumps(rec))
        rt.load_sel4_record(p)
    # RISC-V MCS is the proved MCS configuration -> accepted.
    riscv = rt.load_sel4_record(_sel4_record(tmp_path, arch="riscv64",
                                             board="QEMU-RISC-V-virt",
                                             config="RISCV64_MCS_verified"))
    assert riscv["tier"] == "SEL4-VERIFIED"
    with pytest.raises(rt.TSError):  # unreadable record
        rt.load_sel4_record(tmp_path / "absent.json")
    with pytest.raises(rt.TSError):  # non-object record
        p2 = tmp_path / "list.json"
        p2.write_text(json.dumps([1, 2]))
        rt.load_sel4_record(p2)


def test_sel4_record_bound_to_live_arch(tmp_path, monkeypatch):
    import platform as _plat
    _clean_env(monkeypatch)
    rec = _sel4_record(tmp_path)  # aarch64 record
    # Live host is x86_64/amd64 here: an aarch64 record must refuse it.
    with pytest.raises(rt.TSRequiredError):
        monkeypatch.setenv("P2P_SEL4_RECORD", str(rec))
        rt.require_verified_platform()
    # Simulated aarch64 host: matching record passes arch binding.
    monkeypatch.setattr(_plat, "machine", lambda: "aarch64")
    got = rt.require_verified_platform()
    assert got["tier"] == "SEL4-VERIFIED"
    # ...but an x86_64 record is still refused (no verified x86_64 config).
    rec_x86 = _sel4_record(tmp_path, arch="x86_64", config="X86_64_verified")
    monkeypatch.setenv("P2P_SEL4_RECORD", str(rec_x86))
    with pytest.raises(rt.TSError):
        rt.require_verified_platform()
    assert rt._live_arch_family() == "aarch64"
    monkeypatch.setattr(_plat, "machine", lambda: "AMD64")
    assert rt._live_arch_family() == "x86_64"


def test_platform_gate_records_and_waiver(monkeypatch, tmp_path):
    _clean_env(monkeypatch)
    with pytest.raises(rt.TSRequiredError):
        rt.require_verified_platform()
    # Hermetic waiver-accept branch: synthetic fully-enforced posture +
    # real waiver file passes on any host (no live state asserted).
    w = tmp_path / "waiver.json"
    w.write_text(json.dumps({"justification": "synthetic accept-path test",
                             "ao": "AO-TEST", "expires": "2028-01-01",
                             "mitigations": ["VBS", "HVCI", "SecureBoot"]}))
    monkeypatch.setenv("P2P_PLATFORM_WAIVER", str(w))
    good_post = {"secure_boot": True, "vbs_status": 2, "hvci_running": True,
                 "dma_capable": True, "measured_boot_log": True}
    rep = rt.require_verified_platform(good_post)
    assert rep["tier"] == "VBS-WAIVER" and "NOT equivalent" in rep["note"]


def test_waiver_insufficient_on_unenforced_box(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    w = tmp_path / "waiver.json"
    w.write_text(json.dumps({"justification": "lab", "ao": "AO-1",
                             "expires": "2028-01-01",
                             "mitigations": ["VBS", "HVCI", "SecureBoot"]}))
    monkeypatch.setenv("P2P_PLATFORM_WAIVER", str(w))
    # Hermetic refusal: synthetic unenforced posture fails even with a
    # facially valid waiver (mirrors this box's live state).
    bad_post = {"secure_boot": False, "vbs_status": 0, "hvci_running": False,
                "dma_capable": True, "measured_boot_log": True}
    with pytest.raises(rt.TSRequiredError):
        rt.require_verified_platform(bad_post)
    w.write_text(json.dumps({"justification": "lab", "ao": "AO-1",
                             "expires": "2020-01-01", "mitigations": []}))
    with pytest.raises(rt.TSError):
        rt.load_waiver(w)
    with pytest.raises(rt.TSError):  # non-object waiver
        w.write_text(json.dumps(["x"]))
        rt.load_waiver(w)


def test_waiver_must_cover_required_mitigations(tmp_path, monkeypatch):
    _clean_env(monkeypatch)
    good_post = {"secure_boot": True, "vbs_status": 2, "hvci_running": True,
                 "dma_capable": True, "measured_boot_log": True}
    w = tmp_path / "thin.json"
    w.write_text(json.dumps({"justification": "thin", "ao": "AO-1",
                             "expires": "2028-01-01",
                             "mitigations": ["VBS"]}))  # hvci/secure_boot missing
    monkeypatch.setenv("P2P_PLATFORM_WAIVER", str(w))
    with pytest.raises(rt.TSError):
        rt.require_verified_platform(good_post)


# --- boot chain + anti-DMA ---------------------------------------------------------------
def test_boot_chain_refuses_unqualified_posture(monkeypatch):
    _clean_env(monkeypatch)
    # Hermetic: every degraded posture refused, on any host.
    base = {"secure_boot": True, "vbs_status": 2, "hvci_running": True,
            "measured_boot_log": True}
    assert rt.require_boot_chain(dict(base))["ok"] is True
    for bad_key, bad_val in (("secure_boot", False), ("secure_boot", None),
                             ("vbs_status", 0), ("hvci_running", False),
                             ("measured_boot_log", False),
                             ("measured_boot_log", "present-unreadable"),
                             ("measured_boot_log", None)):
        bad = dict(base)
        bad[bad_key] = bad_val
        with pytest.raises(rt.TSRequiredError):
            rt.require_boot_chain(bad)
    # Live box state must agree with itself: gate passes live IFF the live
    # posture is fully qualified (this dev box is not -> refuses).
    live = rt.read_platform_posture()
    qualified = (live.get("secure_boot") is True and live.get("vbs_status") == 2
                 and live.get("hvci_running") is True
                 and live.get("measured_boot_log") is True)
    if qualified:
        assert rt.require_boot_chain(live)["ok"] is True
    else:
        with pytest.raises(rt.TSRequiredError):
            rt.require_boot_chain(live)


def test_dma_enumeration_real_and_empty_here(monkeypatch):
    _clean_env(monkeypatch)
    scan = rt.enumerate_external_dma()
    assert scan.get("scan_ok") is True  # live scan must succeed, not just look empty
    devs = scan["devices"]
    assert isinstance(devs, list)
    assert all(rt.is_external_dma_device(d) for d in devs)  # no benign leaks in
    rep = rt.require_dma_posture()
    assert rep["ok"] is True and rep["devices_scanned"] >= 0
    hostile = [{"name": "Evil Thunderbolt Dock", "status": "OK",
                "class": "System", "device_id": r"PCI\VEN_8086&DEV_15D2&FOO"}]
    hostile_pnp = [{"FriendlyName": "Evil Thunderbolt Dock", "Status": "OK",
                    "Class": "System", "DeviceID": r"PCI\VEN_8086&DEV_15D2&FOO",
                    "InstanceId": r"PCI\VEN_8086&DEV_15D2&FOO\0"}]
    # Both record shapes (normalized + raw PnP) must classify hostile.
    assert rt.is_external_dma_device(hostile[0]) is True
    assert rt.is_external_dma_device(hostile_pnp[0]) is True
    with pytest.raises(rt.TSRequiredError):
        rt.require_dma_posture(devices=hostile)
    with pytest.raises(rt.TSRequiredError):
        rt.require_dma_posture(devices=hostile_pnp)
    # AMD numeric collision (VEN_1022 DEV_15E8/15D3 are bridges, not
    # Thunderbolt) must NOT refuse: proven live regression test.
    amd_bridges = [
        {"name": "PCI standard host CPU bridge", "status": "OK",
         "class": "System",
         "device_id": r"PCI\VEN_1022&DEV_15E8&SUBSYS_00000000&REV_00\3&11583659&0&C0"},
        {"name": "PCI Express Root Port", "status": "OK",
         "class": "System",
         "device_id": r"PCI\VEN_1022&DEV_15D3&SUBSYS_14531022&REV_00\3&11583659&0&0A"},
    ]
    assert rt.require_dma_posture(devices=amd_bridges)["ok"] is True
    # Named acceptance in waiver + capability (present here) passes.
    post = rt.read_platform_posture()
    assert post.get("dma_capable") is True
    rep2 = rt.require_dma_posture(
        post, hostile, waiver_dma_accepted=[r"PCI\VEN_8086&DEV_15D2&FOO"])
    assert rep2["accepted"] is True
    # Failed scans refuse even with an empty device list (absence of
    # evidence is not evidence of absence).
    with pytest.raises(rt.TSRequiredError):
        rt.require_dma_posture(devices={"devices": [], "scan_ok": False})
    with pytest.raises(rt.TSError):
        rt.require_dma_posture(devices={"devices": "not-a-list", "scan_ok": True})
    with pytest.raises(rt.TSError):
        rt.require_dma_posture(devices=42)


def test_ts_runtime_aggregator_refuses_this_box(monkeypatch):
    _clean_env(monkeypatch)
    with pytest.raises((rt.TSRequiredError, rt.TSError)):
        rt.require_ts_runtime()


def test_ts_mode_hook_blocks_session_without_runtime(monkeypatch, tmp_path):
    _clean_env(monkeypatch)
    import secure_transmit_2027 as s
    monkeypatch.setenv("P2P_TS_MODE", "1")
    monkeypatch.setenv("P2P_SIEM_LEDGER", str(tmp_path / "audit.jsonl"))
    s._audit_chain = None
    s.PIN_DIR = tmp_path / "pins"
    with pytest.raises(Exception):
        s._production_preflight("127.0.0.1", "cdn-front.example.net", 8888, "peerX")
