"""F-01 production-gate consistency matrix.

Verifies that EVERY production-mode gate flips under ALL four accepted
truthy spellings (1/true/yes/on) for BOTH P2P_PRODUCTION and
SECURE_P2P_PRODUCTION, that falsey values never arm it, that the latch is
sticky, and that the canonical detector imports cleanly at process start
in a fresh interpreter (import-order independence).

Regression guard for the CI "KNOWN GAP P1" (defense_ci.yml): the gates that
previously accepted only ==\"1\" or only ==\"true\" (forward_secrecy_manager,
nc3_nuclear_command, platform_hsm_interface, double_ratchet, hybrid_kex ...)
are covered here through production_gate plus direct module-function probes.
"""

import os
import subprocess
import sys

import pytest

import production_gate as pg

TRUTHY = ("1", "true", "TRUE", "Yes", "on", " ON ")
FALSEY = ("", "0", "false", "no", "off", "FALSE")
BOTH_VARS = ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION")


@pytest.fixture(autouse=True)
def _clean_gate():
    pg.reset_for_tests()
    saved = {k: os.environ.get(k) for k in BOTH_VARS + ("P2P_TS_MODE",)}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    pg.reset_for_tests()


@pytest.mark.parametrize("var", BOTH_VARS)
@pytest.mark.parametrize("value", TRUTHY)
def test_gate_true_for_all_truthy_spellings(var, value, monkeypatch):
    monkeypatch.setenv(var, value)
    assert pg.is_production() is True, f"{var}={value!r} must arm production gate"
    assert pg.is_ts_mode() is True


@pytest.mark.parametrize("var", BOTH_VARS)
@pytest.mark.parametrize("value", FALSEY)
def test_gate_false_for_falsey_values(var, value, monkeypatch):
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    monkeypatch.setenv(var, value)
    assert pg.is_production() is False, f"{var}={value!r} must NOT arm production gate"


def test_gate_false_when_unset(monkeypatch):
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    assert pg.is_production() is False


def test_sticky_latch_survives_env_clear(monkeypatch):
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    assert pg.is_production() is True
    monkeypatch.delenv("P2P_PRODUCTION")
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    # Latched: clearing the env mid-process must not disarm hardening gates.
    assert pg.is_production() is True
    assert pg.production_reason() != ""


def test_reset_for_tests_clears_latch(monkeypatch):
    monkeypatch.setenv("P2P_PRODUCTION", "true")
    assert pg.is_production() is True
    monkeypatch.delenv("P2P_PRODUCTION")
    pg.reset_for_tests()
    assert pg.is_production() is False


def test_unknown_spelling_fails_open_but_logs(monkeypatch, caplog):
    # Typo like "tru" must NOT arm the gate (and must be loudly reported).
    monkeypatch.setenv("P2P_PRODUCTION", "tru")
    with caplog.at_level("CRITICAL", logger="production_gate"):
        assert pg.is_production() is False
    assert any("unrecognized value" in r.message for r in caplog.records)


# --- direct module-gate probes (the sites named in the audit) -------------

def _module_gates():
    """(label, zero-arg callable) pairs for gates callable without I/O."""
    probes = []
    try:
        import double_ratchet
        probes.append(("double_ratchet._pq_ratchet_production_mode",
                       double_ratchet._pq_ratchet_production_mode))
    except Exception as exc:  # pragma: no cover
        probes.append(("double_ratchet IMPORT FAILED", lambda: (_ for _ in ()).throw(exc)))
    try:
        import platform_hsm_interface
        probes.append(("platform_hsm_interface._softhsm_prod_strict",
                       platform_hsm_interface._softhsm_prod_strict))
    except Exception as exc:  # pragma: no cover
        probes.append(("platform_hsm_interface IMPORT FAILED", lambda: (_ for _ in ()).throw(exc)))
    try:
        from security import hardening, monitor, graceful_degradation
        probes.append(("security.hardening._is_production", hardening._is_production))
        probes.append(("security.monitor._is_production", monitor._is_production))
        probes.append(("security.graceful_degradation._is_production",
                       graceful_degradation._is_production))
    except Exception as exc:  # pragma: no cover
        probes.append(("security.* IMPORT FAILED", lambda: (_ for _ in ()).throw(exc)))
    try:
        import liboqs_wrapper
        if hasattr(liboqs_wrapper, "_liboqs_strict_mode"):
            probes.append(("liboqs_wrapper._liboqs_strict_mode",
                           liboqs_wrapper._liboqs_strict_mode))
    except Exception as exc:  # pragma: no cover
        probes.append(("liboqs_wrapper IMPORT FAILED", lambda: (_ for _ in ()).throw(exc)))
    return probes


@pytest.mark.parametrize("label,fn", _module_gates())
@pytest.mark.parametrize("var", BOTH_VARS)
@pytest.mark.parametrize("value", TRUTHY)
def test_module_gates_flip_on_all_spellings(label, fn, var, value, monkeypatch):
    pg.reset_for_tests()
    monkeypatch.setenv(var, value)
    assert fn() is True, f"{label} must be True for {var}={value!r}"


@pytest.mark.parametrize("label,fn", _module_gates())
def test_module_gates_false_when_unset(label, fn, monkeypatch):
    pg.reset_for_tests()
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("P2P_TS_MODE", raising=False)
    assert fn() is False, f"{label} must be False when unset"


@pytest.mark.parametrize("var", BOTH_VARS)
@pytest.mark.parametrize("value", ("1", "true", "yes", "on"))
def test_fresh_interpreter_arms_import_time(var, value):
    """Import-order independence: a fresh process started with the env var
    armed at import of production_gate (no explicit call required)."""
    env = dict(os.environ)
    env.pop("P2P_PRODUCTION", None)
    env.pop("SECURE_P2P_PRODUCTION", None)
    env[var] = value
    env["PYTHONPATH"] = os.pathsep.join(
        [os.getcwd()] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    code = (
        "import production_gate;"
        "print(1 if production_gate.is_production() else 0)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "1", (
        f"fresh interpreter with {var}={value!r} must report production: "
        f"stderr={out.stderr[-500:]}"
    )
