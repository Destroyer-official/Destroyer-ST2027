"""Shared pytest fixtures.

F-01 test isolation: production_gate.is_production() is process-sticky by
design (fail-closed). Without an explicit reset, any test that arms
production mode would leak sticky state into every later test and turn the
suite order-dependent (F-06). This autouse fixture clears the latch before
AND after every test; production code never calls reset_for_tests().

F-06 process-scope env isolation: SecureP2PChat(anonymous=True) ->
create_ephemeral_user() sets P2P_EPHEMERAL_MODE=1 process-wide (secure_p2p.py
-- intentional production signal: an ephemeral process must keep ALL
subsystems, incl. NC3 officer storage, off disk). Tests that construct an
anonymous chat would otherwise leak the flag and silently divert later
tests onto the in-memory path (nc3 sealed-credential roundtrip never
writes its file). Snapshot + restore the two process-wide mode flags
around every test.
"""

import os

import pytest

# Pre-load hypothesis (and its _native extension) at session start, BEFORE
# any test module can install process-wide import hooks
# (dependency_security_verifier.monitored_import). Late/lazy loading at
# pytest teardown intermittently fails the native DLL signature check
# through the hook and crashes the interpreter before the summary line.
try:
    import hypothesis  # noqa: F401
except Exception:
    pass

_PROCESS_MODE_VARS = ("P2P_EPHEMERAL_MODE", "P2P_ANONYMOUS")


@pytest.fixture(autouse=True)
def _isolate_production_gate():
    try:
        import production_gate
    except Exception:
        production_gate = None
    if production_gate is not None:
        production_gate.reset_for_tests()
    saved_env = {k: os.environ.get(k) for k in _PROCESS_MODE_VARS}
    yield
    for _k, _v in saved_env.items():
        if _v is None:
            os.environ.pop(_k, None)
        else:
            os.environ[_k] = _v
    if production_gate is not None:
        production_gate.reset_for_tests()
