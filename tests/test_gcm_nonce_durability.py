#!/usr/bin/env python3
"""Regression tests for F-03: Durable, key-bound GCM IV & XAES-256-GCM."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import cjadc2_cross_domain_guard as cdg
import cnsa_crypto_gateway as gw
import platform_hsm_interface as phi


def test_platform_hsm_shares_single_iv_engine():
    """F-03 consolidation: platform_hsm_interface delegates to cnsa_crypto_gateway."""
    assert phi.generate_deterministic_gcm_iv is gw.generate_deterministic_gcm_iv  # nosec: B101


def test_cross_process_restart_unique_iv_even_with_fixed_rng(tmp_path):
    """Even if secrets.token_bytes returns all zeros, consecutive process restarts emit distinct IVs."""
    state_dir = tmp_path / "nonce_state"
    env = os.environ.copy()
    env["ST2027_NONCE_STATE_DIR"] = str(state_dir)

    script = (
        "import secrets\n"
        "secrets.token_bytes = lambda n: b'\\x00' * n\n"
        "import cnsa_crypto_gateway as gw\n"
        "ct, iv, tag = gw.cnsa_aes_256_gcm_encrypt(b'hello', b'\\x11' * 32)\n"
        "print(iv.hex())\n"
    )
    out1 = subprocess.check_output([sys.executable, "-c", script], env=env, text=True).strip()
    out2 = subprocess.check_output([sys.executable, "-c", script], env=env, text=True).strip()

    assert len(out1) == 24 and len(out2) == 24  # nosec: B101
    assert out1 != out2, "Process restarts must allocate disjoint durable epochs"  # nosec: B101
    assert out1[8:16] == "00000001" and out2[8:16] == "00000002"  # nosec: B101


def test_distinct_keys_get_distinct_iv_prefix(monkeypatch, tmp_path):
    """Different symmetric keys derive distinct key-bound fixed fields even at identical epoch/seq."""
    monkeypatch.setenv("ST2027_NONCE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(gw, "_iv_pid", 0)
    _, iv1, _ = gw.cnsa_aes_256_gcm_encrypt(b"msg", b"\x11" * 32)
    monkeypatch.setattr(gw, "_iv_counter", 0)
    _, iv2, _ = gw.cnsa_aes_256_gcm_encrypt(b"msg", b"\x22" * 32)
    assert iv1[:4] != iv2[:4]  # nosec: B101


def test_production_unwritable_state_dir_fails_closed(monkeypatch, tmp_path):
    """In production, a symlinked or corrupted nonce state file must fail closed."""
    state_dir = tmp_path / "bad_state"
    state_dir.mkdir(parents=True)
    state_file = state_dir / "gcm_nonce_epoch.bin"
    state_file.write_bytes(b"CORRUPTED")
    monkeypatch.setenv("ST2027_NONCE_STATE_DIR", str(state_dir))
    monkeypatch.setenv("P2P_PRODUCTION", "1")
    monkeypatch.setattr(gw, "_iv_pid", 0)

    with pytest.raises(gw.SecurityError):
        gw.generate_deterministic_gcm_iv()

    # Restore clean state for later tests in this worker
    monkeypatch.setenv("ST2027_NONCE_STATE_DIR", str(tmp_path / "clean_state"))
    monkeypatch.delenv("P2P_PRODUCTION", raising=False)
    monkeypatch.setattr(gw, "_iv_pid", 0)


def test_xaes_256_gcm_known_vector_and_roundtrip():
    """Verify exact c2sp.org/XAES-256-GCM test vector (SP 800-108r1 CMAC-AES-256 + AES-256-GCM)."""
    # Official test vector #1 from c2sp.org/XAES-256-GCM
    key = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
    nonce = b"ABCDEFGHIJKLMNOPQRSTUVWX"
    pt = b"XAES-256-GCM"
    ct, used_nonce, tag = gw.cnsa_xaes_256_gcm_encrypt(pt, key, nonce24=nonce)
    expected = bytes.fromhex("ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271")
    assert used_nonce == nonce  # nosec: B101
    assert ct + tag == expected  # nosec: B101
    assert gw.cnsa_xaes_256_gcm_decrypt(ct, key, nonce, tag) == pt  # nosec: B101

    with pytest.raises(gw.CryptographicIntegrityError):
        gw.cnsa_xaes_256_gcm_decrypt(ct, key, nonce, bytes([tag[0] ^ 0xFF]) + tag[1:])


def test_cjadc2_compartment_derives_distinct_per_message_subkeys(tmp_path, monkeypatch):
    """CJADC2 compartment encryption must use durable nonces and unique per-message subkeys."""
    monkeypatch.setenv("ST2027_NONCE_STATE_DIR", str(tmp_path / "cjadc2_state"))
    monkeypatch.setattr(gw, "_iv_pid", 0)
    guard = cdg.CrossDomainGuard(audit_dir=tmp_path)
    master = b"\x44" * 64
    e1 = guard.encrypt_compartment_payload(master, cdg.SecurityClassification.TOP_SECRET, "NOFORN", b"PAYLOAD")
    e2 = guard.encrypt_compartment_payload(master, cdg.SecurityClassification.TOP_SECRET, "NOFORN", b"PAYLOAD")

    assert e1["kdf_version"] == 2  # nosec: B101
    assert e1["nonce_hex"] != e2["nonce_hex"]  # nosec: B101
    assert e1["ciphertext_hex"] != e2["ciphertext_hex"]  # nosec: B101
    pt1 = guard.decrypt_compartment_payload(master, e1, cdg.SecurityClassification.TOP_SECRET, {"NOFORN"})
    pt2 = guard.decrypt_compartment_payload(master, e2, cdg.SecurityClassification.TOP_SECRET, {"NOFORN"})
    assert pt1 == b"PAYLOAD" and pt2 == b"PAYLOAD"  # nosec: B101
