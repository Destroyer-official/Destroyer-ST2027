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

_PROCESS_MODE_VARS = (
    "P2P_EPHEMERAL_MODE",
    "P2P_ANONYMOUS",
    "P2P_PRODUCTION",
    "SECURE_P2P_PRODUCTION",
    "P2P_TOP_SECRET",
    "P2P_TS_MODE",
)


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


import os
import sys
import shutil
import subprocess
from pathlib import Path


def pytest_sessionstart(session):
    repo_root = Path(__file__).resolve().parent.parent

    # 1. Add rust_data_plane/python to sys.path so destroyer_core package is importable
    rdp_py = str(repo_root / "rust_data_plane" / "python")
    if rdp_py not in sys.path:
        sys.path.insert(0, rdp_py)

    # 2. Locate cargo
    cargo = shutil.which("cargo")
    if not cargo:
        cand = Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo")
        if cand.exists():
            cargo = str(cand)
            os.environ["PATH"] = str(cand.parent) + os.pathsep + os.environ.get("PATH", "")

    if cargo:
        # 3. Build ts_rt
        ts_rt_bin = repo_root / "ts_rt" / "target" / "release" / ("ts_rt.dll" if os.name == "nt" else "libts_rt.so")
        if not ts_rt_bin.exists():
            try:
                subprocess.run([cargo, "build", "--manifest-path", str(repo_root / "ts_rt" / "Cargo.toml"), "--release"],
                               check=True, timeout=90, capture_output=True)
            except Exception:
                pass

        # 4. Build rust_data_plane (secure-transmit and cdylib)
        data_plane_debug = repo_root / "rust_data_plane" / "target" / "debug" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
        if not data_plane_debug.exists():
            try:
                subprocess.run([cargo, "build", "--manifest-path", str(repo_root / "rust_data_plane" / "Cargo.toml")],
                               check=True, timeout=120, capture_output=True)
            except Exception:
                pass

        # 5. Build and install destroyer_core via maturin or provide _native extension
        try:
            import destroyer_core  # noqa: F401
        except ImportError:
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "maturin"],
                    check=False,
                    timeout=60,
                    capture_output=True,
                )
                subprocess.run(
                    [sys.executable, "-m", "maturin", "develop", "-r", "-m", str(repo_root / "rust_data_plane" / "Cargo.toml")],
                    check=False,
                    timeout=180,
                    capture_output=True,
                )
            except Exception:
                pass
            native_ext = repo_root / "rust_data_plane" / "python" / "destroyer_core" / ("_native.pyd" if os.name == "nt" else "_native.so")
            if not native_ext.exists():
                for cand_dir in ("release", "debug"):
                    cdylib = repo_root / "rust_data_plane" / "target" / cand_dir / ("destroyer_core.dll" if os.name == "nt" else "libdestroyer_core.so")
                    if cdylib.exists():
                        try:
                            native_ext.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(cdylib, native_ext)
                            break
                        except Exception:
                            pass
