#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""liboqs runtime version-floor gate — behavioral proofs (docs/liboqs_pin.md).

Covers:
  1. parse_oqs_version: official releases, -dev snapshots, garbage.
  2. liboqs_version_floor: single-sourced from the oqs.dll min_version pin;
     unreadable pin falls back fail-closed to (0, 16, 0) — never lower.
  3. verify_liboqs_native_version (mocked native probe):
       - load failure / missing OQS_version export / probe raise / empty
         string -> (None, False)  [unverifiable => fail closed]
       - below floor -> (raw, False)
       - OFFICIAL-RELEASE rule: "0.16.0-dev"/"0.17.0-dev" are NOT
         acceptance even at/above floor (raw, False)
       - official releases at/above floor -> (raw, True)
  4. liboqs_wrapper._liboqs_strict_mode():4-value env truthiness.
  5. Load gate in a FRESH interpreter (subprocess — no in-process module
     mutation): production/TS + below-floor => refused ("production/TS
     load refused"); production/TS + healthy => loads; inconclusive probe
     fails closed in production and continues LAB-ONLY in lab mode.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

import dependency_security_verifier as dsv
import liboqs_wrapper

REPO_ROOT = Path(__file__).resolve().parents[1]
STRICT_VARS = ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION", "P2P_TS_MODE", "P2P_STRICT_PIN")

_CHILD_BELOW_FLOOR = '''\
import dependency_security_verifier as dsv
dsv.verify_liboqs_native_version = lambda _p: ("0.14.1-dev", False)
import liboqs_wrapper
print("FLAG=%s" % liboqs_wrapper.LIBOQS_BELOW_FLOOR)
print("RAW=%s" % liboqs_wrapper.LIBOQS_NATIVE_VERSION)
'''

_CHILD_HEALTHY = '''\
import dependency_security_verifier as dsv
dsv.verify_liboqs_native_version = lambda _p: ("0.16.0", True)
import liboqs_wrapper
print("FLAG=%s" % liboqs_wrapper.LIBOQS_BELOW_FLOOR)
'''

_CHILD_INCONCLUSIVE = '''\
import dependency_security_verifier as dsv
def _boom(_p):
    raise RuntimeError("simulated version probe failure")
dsv.verify_liboqs_native_version = _boom
import liboqs_wrapper
print("FLAG=%s" % liboqs_wrapper.LIBOQS_BELOW_FLOOR)
'''


def _run_child(script: str, strict: bool) -> "subprocess.CompletedProcess[str]":
    env = os.environ.copy()
    for var in STRICT_VARS:
        env.pop(var, None)
    if strict:
        env["P2P_PRODUCTION"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO_ROOT)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=120,
        cwd=str(REPO_ROOT), env=env)


class TestParseOqsVersion:
    @pytest.mark.parametrize("raw,expected", [
        ("0.16.0", (0, 16, 0)),
        ("0.14.1-dev", (0, 14, 1)),
        ("0.17.0", (0, 17, 0)),
        (" 0.15.2 ", (0, 15, 2)),
        ("0.16", None),
        ("garbage", None),
        ("", None),
        (None, None),
    ])
    def test_parse(self, raw, expected):
        assert dsv.parse_oqs_version(raw) == expected


class TestFloorSingleSource:
    def test_floor_matches_pin(self):
        floor = dsv.liboqs_version_floor()
        pinned = dsv.DependencySecurityVerifier().critical_dependencies[
            "oqs.dll"]["min_version"]
        assert floor == (0, 16, 0)
        assert dsv.parse_oqs_version(pinned) == floor

    @pytest.mark.parametrize("deps", [
        {},
        {"oqs.dll": {}},
        {"oqs.dll": {"min_version": "garbage"}},
        {"oqs.dll": {"min_version": None}},
    ])
    def test_unreadable_pin_falls_back_fail_closed(self, deps):
        stub = mock.MagicMock()
        stub.return_value.critical_dependencies = deps
        with mock.patch.object(dsv, "DependencySecurityVerifier", stub):
            assert dsv.liboqs_version_floor() == (0, 16, 0)


class TestVerifyNativeVersion:
    def test_load_failure_returns_unverifiable(self):
        with mock.patch.object(dsv.ctypes, "CDLL", side_effect=OSError("missing")):
            assert dsv.verify_liboqs_native_version("nope.dll") == (None, False)

    def test_missing_export_returns_unverifiable(self):
        fake = mock.MagicMock(spec=[])
        with mock.patch.object(dsv.ctypes, "CDLL", return_value=fake):
            assert dsv.verify_liboqs_native_version("x.dll") == (None, False)

    def test_probe_raise_returns_unverifiable(self):
        fake = mock.MagicMock()
        fake.OQS_version = mock.MagicMock(side_effect=OSError("probe boom"))
        with mock.patch.object(dsv.ctypes, "CDLL", return_value=fake):
            assert dsv.verify_liboqs_native_version("x.dll") == (None, False)

    def test_empty_raw_returns_unverifiable(self):
        fake = mock.MagicMock()
        fake.OQS_version = mock.MagicMock(return_value=b"")
        with mock.patch.object(dsv.ctypes, "CDLL", return_value=fake):
            assert dsv.verify_liboqs_native_version("x.dll") == (None, False)

    @pytest.mark.parametrize("raw,meets", [
        ("0.16.0", True),
        ("0.17.0", True),
        ("0.14.1", False),
        ("0.14.1-dev", False),
        ("0.16.0-dev", False),
        ("0.17.0-dev", False),
        ("0.16", False),
        ("0.16.0.1", False),
        ("0.16.0+build.1", False),
        ("not-a-version", False),
    ])
    def test_floor_and_official_release_rule(self, raw, meets):
        fake = mock.MagicMock()
        fake.OQS_version = mock.MagicMock(return_value=raw.encode("ascii"))
        with mock.patch.object(dsv.ctypes, "CDLL", return_value=fake):
            got_raw, ok = dsv.verify_liboqs_native_version("x.dll")
        assert got_raw == raw
        assert ok is meets

    def test_real_dll_smoke(self):
        raw, ok = dsv.verify_liboqs_native_version(str(liboqs_wrapper.LIBOQS_DLL_PATH))
        assert isinstance(ok, bool)
        if ok:
            assert raw is not None
            assert dsv.parse_oqs_version(raw) >= dsv.liboqs_version_floor()


class TestStrictModeEnv:
    @pytest.mark.parametrize("env,expected", [
        ({}, False),
        ({"P2P_PRODUCTION": "1"}, True),
        ({"P2P_PRODUCTION": "true"}, True),
        ({"SECURE_P2P_PRODUCTION": "YES"}, True),
        ({"P2P_TS_MODE": "on"}, True),
        ({"P2P_STRICT_PIN": "1"}, True),
        ({"P2P_PRODUCTION": "0"}, False),
        ({"P2P_PRODUCTION": "false"}, False),
        ({"P2P_PRODUCTION": ""}, False),
        ({"P2P_PRODUCTION": " "}, False),
        ({"UNRELATED_VAR": "1"}, False),
    ])
    def test_strict_mode(self, env, expected, monkeypatch):
        for var in STRICT_VARS:
            monkeypatch.delenv(var, raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        assert liboqs_wrapper._liboqs_strict_mode() is expected


class TestLoadGateFreshInterpreter:
    def test_production_refuses_below_floor(self):
        proc = _run_child(_CHILD_BELOW_FLOOR, strict=True)
        combined = proc.stdout + proc.stderr
        assert proc.returncode != 0, combined
        assert "production/TS load refused" in combined

    def test_lab_continues_below_floor(self):
        proc = _run_child(_CHILD_BELOW_FLOOR, strict=False)
        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert "FLAG=True" in proc.stdout
        assert "RAW=0.14.1-dev" in proc.stdout
        assert "LAB-ONLY" in combined

    def test_production_accepts_healthy_release(self):
        proc = _run_child(_CHILD_HEALTHY, strict=True)
        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert "FLAG=False" in proc.stdout
        assert "meets floor" in combined

    def test_production_refuses_inconclusive_probe(self):
        proc = _run_child(_CHILD_INCONCLUSIVE, strict=True)
        combined = proc.stdout + proc.stderr
        assert proc.returncode != 0, combined
        assert "gate failed closed" in combined

    def test_lab_continues_inconclusive_probe(self):
        proc = _run_child(_CHILD_INCONCLUSIVE, strict=False)
        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert "FLAG=True" in proc.stdout
        assert "LAB-ONLY" in combined
