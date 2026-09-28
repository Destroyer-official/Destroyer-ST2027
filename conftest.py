"""Repo-wide test hermeticity: leave-no-trace process environment.

Root cause of an entire class of order-dependent suite failures
(P2P_ALLOW_TPM_NATIVE / P2P_ENABLE_EXPERIMENTAL / ceremony secrets /
production flags leaking between suites in one pytest process, then
tripping other suites' fail-closed construction): snapshot os.environ
around EVERY test and restore afterwards.

Semantics (deliberate):
- Snapshot is taken at per-test FIXTURE SETUP, so module-scoped opt-in
  fixtures and import-time lab defaults are honored DURING the test.
- Restore happens at teardown, so nothing a test sets can pollute the
  next test, whatever file it lives in.
- Product code untouched. Shell-provided lab flags (P2P_ALLOW_LOOPBACK)
  survive because they exist before every snapshot.

Any suite that relied on inheriting another suite's runtime env mutation
was order-fragile by construction; such coupling now fails loudly at the
dependent test instead of silently passing in lucky orders.
"""

import os

import pytest

import faulthandler

# Crash diagnostics 2026-09-24: full-suite runs die in interpreter teardown
# (a dozen all-daemon monitor threads per constructed chat, times hundreds
# of chats, plus native McEliece-scale load) AFTER the last test passes, so
# pytest never prints its summary. Enabling faulthandler dumps every
# thread's stack on a fatal signal instead of dying silent. Diagnostic only:
# no product code, scheduling, or assertion behavior changes.
faulthandler.enable(all_threads=True)


@pytest.fixture(autouse=True)
def _p2p_env_hermetic(request):
    snapshot = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(snapshot)


@pytest.fixture(scope="session", autouse=True)
def _p2p_warm_native_kat_oracles():
    """Pre-load lazy native KAT-oracle DLLs before OS binary lockdown.

    Root cause of test_selftests_green_and_cached failing ONLY in full-suite
    order (OSError WinError 577 on Crypto.Cipher._raw_ecb): EnhancedDEP
    enables PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY/MicrosoftSignedOnly
    at first chat construction (dep_impl.set_binary_signature_policy_flags).
    That mitigation is process-global and IRREVERSIBLE. crypto_selftest
    imports PyCryptodome (unsigned native .pyd oracles: AES-GCM KAT, SHA384,
    HMAC, HKDF, ECC) lazily, so in full-suite order the oracle LoadLibrary
    lands after lockdown and the OS refuses it. Warm every native dep here,
    in the session fixture that runs before any test, mirroring production
    where all native modules (oqs/libsodium/ts_rt) load pre-lockdown.
    Deliberately loud on failure: a broken oracle must fail the session,
    never one test in lucky orders.
    """
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA384, HMAC
    from Crypto.Protocol.KDF import HKDF
    from Crypto.PublicKey import ECC

    _k = b"\x00" * 32
    _n = b"\x00" * 12
    _c = AES.new(_k, AES.MODE_GCM, nonce=_n)
    _ct, _tag = _c.encrypt_and_digest(b"warm")
    _d = AES.new(_k, AES.MODE_GCM, nonce=_n)
    assert _d.decrypt_and_verify(_ct, _tag) == b"warm"
    assert SHA384.new(b"warm").digest()
    assert HMAC.new(_k, b"warm", digestmod=SHA384).digest()
    assert len(HKDF(b"warm", 32, salt=b"warm", hashmod=SHA384)) == 32
    assert ECC.generate(curve="P-384").public_key()
    # ts_rt.dll is OUR OWN unsigned Rust core, loaded lazily by
    # ts_runtime.load_native() on first use. Same lockdown wall killed
    # test_ts_runtime (4 tests, WinError 577) in full-suite order.
    # Production 2027 path is safe by construction (ts_hw_layer never
    # enables the binary-signature policy; legacy prod loads all native
    # modules at import, pre-lockdown), so warming here changes no
    # security posture -- it only fixes suite ordering.
    import ts_runtime
    ts_runtime.load_native()
    yield


def pytest_sessionfinish(session, exitstatus):
    """Drain cyclic garbage while the interpreter is fully alive.

    Bisect-proven (readiness-style runs crash identically with this body
    disabled): the post-session teardown AV is NOT caused here. It fires
    only after multi-chat pytest sessions, during interpreter GC teardown
    (daemon monitor threads x COM apartment release x native DLL unload),
    always AFTER junit XML is complete. Collecting here — GIL-held,
    apartments alive, DLLs loaded — narrows that race window to the minimum
    achievable without touching live shutdown paths (joining
    security-monitor threads or rebalancing COM refcounts from the harness
    would risk hangs/regressions in production teardown behavior for zero
    test-result benefit). Results remain certified via junit XML counts,
    never via the OS exit code alone.
    """
    import gc

    gc.collect()
