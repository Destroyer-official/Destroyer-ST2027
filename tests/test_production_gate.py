# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
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

import ast
import os
from pathlib import Path
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


@pytest.mark.parametrize("var", BOTH_VARS)
def test_unknown_spelling_fails_closed_and_latches(var, monkeypatch, caplog):
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    monkeypatch.setenv(var, "tru")
    with caplog.at_level("CRITICAL", logger="production_gate"):
        assert pg.is_production() is True
    assert any("unrecognized value" in r.message for r in caplog.records)
    monkeypatch.delenv(var)
    assert pg.is_production() is True
    assert "unrecognized" in pg.production_reason()


@pytest.mark.parametrize("unknown_var", BOTH_VARS)
@pytest.mark.parametrize("false_value", FALSEY)
def test_unknown_value_wins_over_other_variable_falsey(
    unknown_var, false_value, monkeypatch
):
    other_var = next(v for v in BOTH_VARS if v != unknown_var)
    monkeypatch.setenv(unknown_var, "tru")
    monkeypatch.setenv(other_var, false_value)
    assert pg.is_production() is True


@pytest.mark.parametrize("truthy_var", BOTH_VARS)
def test_truthy_value_wins_over_other_variable_falsey(truthy_var, monkeypatch):
    other_var = next(v for v in BOTH_VARS if v != truthy_var)
    monkeypatch.setenv(truthy_var, "1")
    monkeypatch.setenv(other_var, "0")
    assert pg.is_production() is True


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
@pytest.mark.parametrize("value", ("1", "true", "yes", "on", "tru"))
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


def test_no_direct_production_environment_parsers():
    """Security gates must not reintroduce independent production parsing.

    Environment save/restore belongs in tests; production modules must use the
    canonical gate (directly or through an audited adapter) instead of reading
    either production variable from ``os.environ``/``os.getenv`` themselves.
    """
    root = Path(__file__).resolve().parents[1]
    excluded = {".venv", "notupload", "target", "node_modules", "tests"}
    violations = []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if any(
            part in excluded or part.startswith(".audit-") or part == "site-packages"
            for part in relative.parts[:-1]
        ):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError) as exc:
            violations.append(f"{relative}: source could not be audited: {exc}")
            continue
        for node in ast.walk(tree):
            names = ()
            if isinstance(node, ast.Call) and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and arg.value in BOTH_VARS:
                    func = node.func
                    if isinstance(func, ast.Name) and func.id == "getenv":
                        names = (arg.value,)
                    elif isinstance(func, ast.Attribute) and func.attr == "get":
                        owner = func.value
                        if (
                            isinstance(owner, ast.Name)
                            and owner.id in {"environ", "os"}
                        ) or (
                            isinstance(owner, ast.Attribute)
                            and owner.attr == "environ"
                        ):
                            names = (arg.value,)
                    elif isinstance(func, ast.Attribute) and func.attr == "getenv":
                        names = (arg.value,)
            elif isinstance(node, ast.Subscript):
                key = node.slice
                if isinstance(key, ast.Constant) and key.value in BOTH_VARS:
                    owner = node.value
                    if (
                        isinstance(owner, ast.Name) and owner.id == "environ"
                    ) or (
                        isinstance(owner, ast.Attribute) and owner.attr == "environ"
                    ):
                        names = (key.value,)
            for name in names:
                violations.append(f"{relative}:{node.lineno}: direct read of {name}")
    assert not violations, "\n".join(violations)
