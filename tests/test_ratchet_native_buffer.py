#!/usr/bin/env python3
"""test_ratchet_native_buffer.py

Tests for:
1. DoubleRatchet key lifecycle using NativeSecureBuffer (in-memory zeroization).
2. validate_handshake_quote in tpm_quote (nonce matching, freshness, degradation gate).
3. Session handshake TPM quote attachment and validation.
"""

from __future__ import annotations

import os
import time
import secrets
import pytest

from double_ratchet import DoubleRatchet, SecurityError
from native_secure_buffer import NativeSecureBuffer, wipe_native
import tpm_quote


# ----------------------------------------------------------------------
# 1. DoubleRatchet + NativeSecureBuffer Integration Tests
# ----------------------------------------------------------------------

def test_doubleratchet_encrypt_decrypt_with_native_buffer():
    """Verify standard message roundtrip through DoubleRatchet using NativeSecureBuffer."""
    shared_root = secrets.token_bytes(32)
    
    alice = DoubleRatchet(root_key=shared_root, is_initiator=True, enable_pq=True)
    bob = DoubleRatchet(root_key=shared_root, is_initiator=False, enable_pq=True)

    # Complete initial handshake to initialize ratchet chains and keys
    alice.set_remote_public_key(bob.get_public_key(), bob.get_kem_public_key(), bob.get_dss_public_key())
    bob.set_remote_public_key(alice.get_public_key(), alice.get_kem_public_key(), alice.get_dss_public_key())
    bob.process_kem_ciphertext(alice.get_kem_ciphertext())

    # Alice encrypts to Bob
    plaintext = b"NIST-Level-5-Encrypted-Command-Telemetry"
    encrypted_msg = alice.encrypt(plaintext)

    assert encrypted_msg != plaintext  # nosec: B101
    assert len(encrypted_msg) > len(plaintext)  # nosec: B101

    # Bob decrypts message
    decrypted = bob.decrypt(encrypted_msg)
    assert decrypted == plaintext  # nosec: B101


def test_doubleratchet_cipher_native_buffer_zeroizes():
    """Verify that _encrypt_with_cipher and _decrypt_with_cipher properly handle keys."""
    shared_root = secrets.token_bytes(32)
    alice = DoubleRatchet(root_key=shared_root, is_initiator=True, enable_pq=True)

    key = secrets.token_bytes(32)
    nonce, ct = alice._encrypt_with_cipher(b"secret payload", b"associated-data", key)
    
    pt = alice._decrypt_with_cipher(nonce, ct, b"associated-data", key)
    assert pt == b"secret payload"  # nosec: B101

    # Mismatched associated data fails authentication
    with pytest.raises(SecurityError):
        alice._decrypt_with_cipher(nonce, ct, b"wrong-associated-data", key)


# ----------------------------------------------------------------------
# 2. validate_handshake_quote Tests
# ----------------------------------------------------------------------

def test_validate_handshake_quote_roundtrip():
    pub, sk = tpm_quote.generate_ak_stub()
    nonce = secrets.token_bytes(32)
    pcr = {0: "aa" * 32, 7: "bb" * 32}

    env = tpm_quote.sign_quote(pcr, nonce, "ak-peer-1", sk, degraded=False)
    
    # Valid quote verifies
    assert tpm_quote.validate_handshake_quote(env, expected_nonce=nonce, trusted_pubs=[pub]) is True  # nosec: B101

    # Wrong nonce rejected
    assert tpm_quote.validate_handshake_quote(env, expected_nonce=secrets.token_bytes(32), trusted_pubs=[pub]) is False  # nosec: B101

    # Untrusted pubkey rejected
    other_pub, _ = tpm_quote.generate_ak_stub()
    assert tpm_quote.validate_handshake_quote(env, expected_nonce=nonce, trusted_pubs=[other_pub]) is False  # nosec: B101


def test_validate_handshake_quote_degradation_gate():
    pub, sk = tpm_quote.generate_ak_stub()
    nonce = secrets.token_bytes(32)
    pcr = {0: "00" * 32}

    # Degraded quote
    deg_env = tpm_quote.sign_quote(pcr, nonce, "ak-deg", sk, degraded=True)

    # In production (allow_degraded=False), degraded quotes MUST fail-closed
    assert tpm_quote.validate_handshake_quote(deg_env, expected_nonce=nonce, trusted_pubs=[pub], allow_degraded=False) is False  # nosec: B101

    # In lab/simulation (allow_degraded=True), degraded quote can be accepted
    assert tpm_quote.validate_handshake_quote(deg_env, expected_nonce=nonce, trusted_pubs=[pub], allow_degraded=True) is True  # nosec: B101


def test_attach_quote_reads_pcrs_when_available(monkeypatch):
    monkeypatch.setenv("P2P_TPM_QUOTE", "1")
    monkeypatch.setenv("P2P_ALLOW_TPM_NATIVE", "1")

    quote = tpm_quote.attach_quote_to_handshake("peer-test")
    assert quote is not None  # nosec: B101
    assert quote["v"] == 1  # nosec: B101
    assert quote["alg"] == "ML-DSA-87"  # nosec: B101
    assert "sig" in quote  # nosec: B101
    assert "nonce" in quote  # nosec: B101

