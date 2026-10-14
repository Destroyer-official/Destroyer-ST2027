"""Shared pytest fixtures.

F-01 test isolation: production_gate.is_production() is process-sticky by
design (fail-closed). Without an explicit reset, any test that arms
production mode would leak sticky state into every later test and turn the
suite order-dependent (F-06). This autouse fixture clears the latch before
AND after every test; production code never calls reset_for_tests().
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_production_gate():
    try:
        import production_gate
    except Exception:
        production_gate = None
    if production_gate is not None:
        production_gate.reset_for_tests()
    yield
    if production_gate is not None:
        production_gate.reset_for_tests()
