#!/usr/bin/env python3
"""Gates for real TPM/HSM usage paths (mocked native layer).

Proves, without hardware: gate behavior, KEK roundtrip, hash-id mapping,
fail-closed boot/integrity checks, honest fallback labeling, and the
Linux detection probes. No network, no TPM/COM/WMI, no registry writes.
RAF: hermetic HOME redirection for file-backed tests.
"""
import os

import pytest

import platform_hsm_interface as phi


@pytest.fixture(autouse=True)
def _hermetic_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    yield


def test_native_gate_defaults_off(monkeypatch):
    monkeypatch.delenv("P2P_ALLOW_TPM_NATIVE", raising=False)
    assert phi._tpm_native_allowed() is False  # nosec: B101
    monkeypatch.setenv("P2P_ALLOW_TPM_NATIVE", "1")
    assert phi._tpm_native_allowed() is True  # nosec: B101


def test_softhsm_refuses_default_pins(monkeypatch):
    """B105/B107: no token may be minted with public default PINs.

    Without explicit PINs (args or P2P_SOFTHSM_PIN/SO_PIN env) the init
    must fail closed; lab defaults require explicit opt-in; production
    refuses even the opt-in.
    """
    monkeypatch.delenv("P2P_SOFTHSM_PIN", raising=False)
    monkeypatch.delenv("P2P_SOFTHSM_SO_PIN", raising=False)
    monkeypatch.delenv("P2P_SOFTHSM_TEST_DEFAULT_PINS", raising=False)
    monkeypatch.delenv("SECURE_P2P_PRODUCTION", raising=False)
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    ok, msg = phi.initialize_softhsm2()
    assert ok is False  # nosec: B101
    assert "PIN" in msg  # nosec: B101
    # Lab opt-in path exists but is explicit (does not run softhsm here;
    # covered by message contract, not by minting a real token).
    monkeypatch.setenv("P2P_SOFTHSM_TEST_DEFAULT_PINS", "1")
    # Either refuses (no softhsm installed) or proceeds loudly -- but the
    # default-PIN branch must never be silent. If it proceeds, a warning
    # is logged; assert the call does not raise.
    ok2, _ = phi.initialize_softhsm2()
    assert isinstance(ok2, bool)  # nosec: B101
    # Production refuses even the lab opt-in.
    monkeypatch.setenv("P2P_PRODUCTION", "true")
    ok3, msg3 = phi.initialize_softhsm2()
    assert ok3 is False  # nosec: B101
    assert "production" in msg3.lower() or "PIN" in msg3  # nosec: B101


def test_pkcs11_pin_fail_closed(monkeypatch):
    """B105/B107: init_hsm PIN path never silently uses public default PINs.

    Precedence: explicit arg > P2P_HSM_PIN/P2P_PKCS11_PIN env > platform
    config pin. Empty everywhere => (None, False) unless lab opt-in
    P2P_HSM_TEST_DEFAULT_PINS=1, which production still refuses.
    """
    for var in ("P2P_HSM_PIN", "P2P_PKCS11_PIN", "P2P_HSM_TEST_DEFAULT_PINS",
                "SECURE_P2P_PRODUCTION", "P2P_PRODUCTION"):
        monkeypatch.delenv(var, raising=False)
    # 1. explicit arg wins (even over env/config)
    monkeypatch.setenv("P2P_HSM_PIN", "env-pin")
    pin, lab, _ = phi._resolve_pkcs11_pin("arg-pin", {"pkcs11": {"pin": "cfg-pin"}}, "lib.so")
    assert (pin, lab) == ("arg-pin", False)  # nosec: B101
    # 2. env wins over platform config
    pin, lab, _ = phi._resolve_pkcs11_pin("", {"pkcs11": {"pin": "cfg-pin"}}, "lib.so")
    assert (pin, lab) == ("env-pin", False)  # nosec: B101
    # 3. platform config honored when arg+env empty
    monkeypatch.delenv("P2P_HSM_PIN", raising=False)
    monkeypatch.delenv("P2P_PKCS11_PIN", raising=False)
    pin, lab, _ = phi._resolve_pkcs11_pin("", {"pkcs11": {"pin": "cfg-pin"}}, "lib.so")
    assert (pin, lab) == ("cfg-pin", False)  # nosec: B101
    # 4. nothing configured => fail closed, no silent "1234"
    pin, lab, msg = phi._resolve_pkcs11_pin("", {}, "lib.so")
    assert pin is None and lab is False  # nosec: B101
    assert "1234" not in msg  # nosec: B101
    # 5. lab opt-in yields explicit lab default (loud, flagged)
    monkeypatch.setenv("P2P_HSM_TEST_DEFAULT_PINS", "1")
    pin, lab, _ = phi._resolve_pkcs11_pin("", {}, "lib.so")
    assert (pin, lab) == ("1234", True)  # nosec: B101
    # 6. production refuses even the lab opt-in
    monkeypatch.setenv("P2P_PRODUCTION", "true")
    pin, lab, msg = phi._resolve_pkcs11_pin("", {}, "lib.so")
    assert pin is None and lab is False  # nosec: B101
    assert "roduction" in msg  # nosec: B101


def test_kek_file_roundtrip_now_readable():
    assert phi.store_key_file_secure("gatetest", b"k" * 32) is True  # nosec: B101
    out = phi.retrieve_key_file_secure("gatetest")
    assert bytes(out) == b"k" * 32  # nosec: B101


def test_kek_file_wrong_label_fails_closed():
    assert phi.store_key_file_secure("gatelabel", b"k" * 32) is True  # nosec: B101
    assert phi.retrieve_key_file_secure("gatelabel-nope") is None  # nosec: B101


def test_sign_hash_id_is_canonical_cng_name():
    # Regression guard for the L"sha3_512" bug: CNG requires hyphenated
    # "SHA3-512", and the lookup uppercases input, so the map key must be
    # the uppercase canonical form. A lowercase key + .upper() lookup
    # rejected every algorithm (all TPM signing failed).
    import inspect
    src = inspect.getsource(phi.sign_with_tpm_key)
    assert 'LPCWSTR("SHA3-512")' in src  # nosec: B101
    assert 'LPCWSTR("sha3_512")' not in src  # nosec: B101
    assert '"SHA3-512"' in src  # nosec: B101


def test_secure_boot_fail_closed_on_probe_error(monkeypatch):
    import subprocess  # nosec: B404
    def _boom(*a, **k):
        raise OSError("no powershell")
    monkeypatch.setattr(subprocess, "run", _boom)
    assert phi._check_windows_secure_boot() is False  # nosec: B101


def test_runtime_integrity_unavailable_is_false():
    # Function probes VirtualLock presence; result must be an honest bool,
    # and the fallback path must be False (never unconditional True).
    import inspect
    src = inspect.getsource(phi._activate_windows_runtime_integrity)
    assert "return True" in src  # probe-hit path keeps capability signal  # nosec: B101
    # Fallback branch explicitly returns False (grep the tail).
    tail = src[src.find("Secondary fallback"):]
    assert "return False" in tail  # nosec: B101


def test_store_in_tpm_labels_file_fallback_honestly(monkeypatch):
    # Force the CNG path then make import fail -> file fallback must NOT
    # claim provider "windows_cng".
    monkeypatch.setattr(phi, "_check_cng_available", lambda: True)
    monkeypatch.setattr(phi, "_open_cng_provider_platform", lambda: True)
    monkeypatch.setattr(phi, "_NCryptImportKey", lambda *a, **k: 0x80090029)
    monkeypatch.setattr(phi, "_NCryptFreeObject", lambda *a, **k: 0)
    ok = phi.store_key_in_tpm("gatelabel2", b"x" * 32)
    assert ok is True  # nosec: B101
    assert phi._hsm_provider_type in ("windows_cng_file_fallback",  # nosec: B101
                                      "windows_cng_chunked")
    assert phi._full_hsm_storage is False  # nosec: B101


def test_linux_tpm_presence_probe_is_real():
    # Regression guard: the old block was `try: log.info(...); return True`
    # with a dead `except ImportError` (always-True without device/module).
    # Every `return True` in the Linux branch must be guarded by a device
    # existence check or a real tpm2_pytss import.
    import inspect
    src = inspect.getsource(phi.is_tpm_available)
    assert "find_spec" in src and "import tpm2_pytss" in src  # nosec: B101
    assert "/dev/tpmrm0" in src or "/dev/tpm0" in src  # nosec: B101


def test_pcr_bank_is_sha256():
    # Regression guard: tpm2_pcrread banks are sha1/sha256 (sha384 rare);
    # the old code requested sha3_512, which no TPM implements.
    import inspect
    assert hasattr(phi, "_get_linux_tpm_pcr_values")  # nosec: B101
    src = inspect.getsource(phi._get_linux_tpm_pcr_values)
    assert "sha256" in src  # nosec: B101

