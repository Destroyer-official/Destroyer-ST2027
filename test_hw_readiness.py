#!/usr/bin/env python3
"""hw_readiness: HAVE/MISSING verdicts, strict refusal, admin elevation.

All hardware is mocked (monkeypatched module attrs); no test touches real
TPM/HSM/firmware or spawns UAC. Live behavior is proven by operators via
`secure_transmit_2027 check-hw` on provisioned endpoints.
"""
import sys

import pytest

import hw_readiness as hw


def _v(status, ts_required=True, vid="x"):
    return hw.Verdict(vid, "label", status, "detail", "action", ts_required)


class TestVerdicts:
    def test_headline_names_missing_hardware_plainly(self):
        v = hw.Verdict("hsm", "Hardware key custody", hw.MISSING,
                       "no backend answered", "attach HSM", True)
        assert "YOU DON'T HAVE THIS" in v.headline()
        assert "attach HSM" in v.headline()

    def test_headline_have_and_unknown(self):
        assert "[HAVE]" in _v(hw.HAVE).headline()
        u = hw.Verdict("tpm", "TPM", hw.UNKNOWN, "unreadable", "elevate", True)
        assert "[UNKNOWN]" in u.headline()

    def test_strict_ok_requires_all_ts_required_have(self):
        assert hw.strict_ok([_v(hw.HAVE), _v(hw.HAVE, False)]) is True
        assert hw.strict_ok([_v(hw.HAVE), _v(hw.MISSING)]) is False
        assert hw.strict_ok([_v(hw.HAVE), _v(hw.UNKNOWN)]) is False
        # Non-required MISSING never blocks strict.
        assert hw.strict_ok([_v(hw.HAVE), _v(hw.MISSING, False)]) is True

    def test_collect_never_raises_crashing_probe_to_caller(self, monkeypatch):
        def boom():
            raise RuntimeError("probe exploded")
        monkeypatch.setattr(hw, "check_fips", boom)
        out = hw.collect()
        assert len(out) == len(hw.ALL_CHECKS)
        assert all(isinstance(v, hw.Verdict) for v in out)


class TestProbesMocked:
    def test_secure_boot_maps_true_false_none(self, monkeypatch):
        import types
        for value, want in ((True, hw.HAVE), (False, hw.MISSING),
                            (None, hw.UNKNOWN)):
            fake = types.SimpleNamespace(
                read_platform_posture=lambda v=value: {"secure_boot": v})
            monkeypatch.setitem(sys.modules, "ts_runtime", fake)
            assert hw.check_secure_boot().status == want

    def test_vbs_hvci_requires_both_enforcing(self, monkeypatch):
        import types
        good = types.SimpleNamespace(
            read_platform_posture=lambda: {"vbs_status": 2,
                                           "hvci_running": True})
        monkeypatch.setitem(sys.modules, "ts_runtime", good)
        assert hw.check_vbs_hvci().status == hw.HAVE
        bad = types.SimpleNamespace(
            read_platform_posture=lambda: {"vbs_status": 2,
                                           "hvci_running": False})
        monkeypatch.setitem(sys.modules, "ts_runtime", bad)
        assert hw.check_vbs_hvci().status == hw.MISSING

    def test_tpm_absent_reports_missing_with_action(self, monkeypatch):
        import types
        fake = types.SimpleNamespace(probe_tpm_device=lambda: None)
        monkeypatch.setitem(sys.modules, "ts_hw_layer", fake)
        v = hw.check_tpm()
        assert v.status == hw.MISSING
        assert "YOU DON'T HAVE THIS" in v.headline()

    def test_hsm_uses_hardware_when_present(self, monkeypatch):
        import types
        att = types.SimpleNamespace(hardware=True, provider_type="CNG",
                                    tier="TPM-DEVICE", detail="tpm key")
        fake = types.SimpleNamespace(probe_hardware_custody=lambda: att,
                                     probe_pqc_token=lambda: None)
        monkeypatch.setitem(sys.modules, "ts_hw_layer", fake)
        v = hw.check_hsm_token()
        assert v.status == hw.HAVE
        assert "in use" in v.headline()


class TestAdminElevation:
    def test_already_admin_short_circuits(self, monkeypatch, capsys):
        monkeypatch.setattr(hw, "is_admin", lambda: True)
        assert hw.ensure_admin() == "already"
        assert "[HAVE]" in capsys.readouterr().out

    def test_no_elevate_flag_skips(self, monkeypatch, capsys):
        monkeypatch.setattr(hw, "is_admin", lambda: False)
        assert hw.ensure_admin(no_elevate=True) == "skipped"

    def test_non_interactive_never_prompts(self, monkeypatch, capsys):
        monkeypatch.setattr(hw, "is_admin", lambda: False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        called = []
        monkeypatch.setattr("builtins.input",
                            lambda *a: called.append(a) or "y")
        assert hw.ensure_admin() == "skipped"
        assert called == []  # no prompt issued

    def test_declined_consent_returns_declined(self, monkeypatch):
        monkeypatch.setattr(hw, "is_admin", lambda: False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda *a: "n")
        assert hw.ensure_admin() == "declined"

    def test_consent_relaunches_and_propagates_exit_code(self, monkeypatch):
        import os as _os
        if _os.name != "nt":
            pytest.skip("windows relaunch path")
        monkeypatch.setattr(hw, "is_admin", lambda: False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda *a: "y")
        seen = {}

        def fake_relaunch(argv, timeout_s):
            seen["argv"] = argv
            return 7
        monkeypatch.setattr(hw, "_relaunch_elevated_windows", fake_relaunch)
        with pytest.raises(SystemExit) as ei:
            hw.ensure_admin()
        assert ei.value.code == 7
        assert seen["argv"][0].lower().endswith("python.exe")

    def test_failed_relaunch_is_fail_closed(self, monkeypatch):
        import os as _os
        if _os.name != "nt":
            pytest.skip("windows relaunch path")
        monkeypatch.setattr(hw, "is_admin", lambda: False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda *a: "y")

        def boom(argv, timeout_s):
            raise OSError("UAC denied")
        monkeypatch.setattr(hw, "_relaunch_elevated_windows", boom)
        with pytest.raises(SystemExit) as ei:
            hw.ensure_admin()
        assert ei.value.code == hw.ELEVATED_EXIT_SPAWN_FAILED


class TestMain:
    def test_strict_refuses_on_missing(self, monkeypatch):
        monkeypatch.setattr(hw, "collect",
                            lambda: [_v(hw.HAVE),
                                     _v(hw.MISSING, True, "hsm")])
        assert hw.main(["--strict"]) == 1

    def test_report_only_exits_zero(self, monkeypatch, capsys):
        monkeypatch.setattr(hw, "collect",
                            lambda: [_v(hw.MISSING, True, "hsm")])
        assert hw.main([]) == 0
        assert "YOU DON'T HAVE THIS" in capsys.readouterr().err

    def test_json_shape(self, monkeypatch, capsys):
        import json as _json
        monkeypatch.setattr(hw, "collect", lambda: [_v(hw.HAVE, True, "tpm")])
        monkeypatch.setattr(hw, "is_admin", lambda: True)
        assert hw.main(["--json"]) == 0
        doc = _json.loads(capsys.readouterr().out)
        assert doc["strict_ok"] is True and doc["items"][0]["id"] == "tpm"


class TestCliWiring:
    def test_check_hw_subcommand_forwards_strict(self, monkeypatch):
        import types
        import secure_transmit_2027 as st
        seen = {}

        def fake_main(argv):
            seen["argv"] = argv
            return 1
        fake = types.SimpleNamespace(main=fake_main,
                                     ensure_admin=lambda **k: "already")
        monkeypatch.setitem(sys.modules, "hw_readiness", fake)
        assert st.main(["check-hw", "--strict"]) == 1
        assert seen["argv"] == ["--strict"]

    def test_gate_lab_path_is_zero_behavior_change(self, monkeypatch, capsys):
        import types
        import secure_transmit_2027 as st
        monkeypatch.delenv("P2P_TS_MODE", raising=False)
        ns = types.SimpleNamespace(require_admin=False, no_elevate=False)
        assert st._gate_hw_admin(ns) is None
        assert capsys.readouterr().out == ""

    def test_gate_require_admin_declined_refuses(self, monkeypatch):
        import types
        import secure_transmit_2027 as st
        fake = types.SimpleNamespace(
            collect=lambda: [],
            ensure_admin=lambda **k: "declined")
        monkeypatch.setitem(sys.modules, "hw_readiness", fake)
        ns = types.SimpleNamespace(require_admin=True, no_elevate=False)
        with pytest.raises(st.SecurityError):
            st._gate_hw_admin(ns)

    def test_gate_ts_advisory_prints_and_continues(self, monkeypatch, capsys):
        import types
        import secure_transmit_2027 as st
        v = hw.Verdict("tpm", "TPM 2.0 device", hw.HAVE, "cng key",
                       "none", True)
        fake = types.SimpleNamespace(
            collect=lambda: [v],
            ensure_admin=lambda **k: "skipped")
        monkeypatch.setitem(sys.modules, "hw_readiness", fake)
        monkeypatch.setenv("P2P_TS_MODE", "1")
        ns = types.SimpleNamespace(require_admin=False, no_elevate=False)
        assert st._gate_hw_admin(ns) is None  # advisory only: no refusal
        assert "TPM 2.0 device" in capsys.readouterr().out


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
