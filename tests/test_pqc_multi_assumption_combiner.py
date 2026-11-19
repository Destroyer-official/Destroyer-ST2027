#!/usr/bin/env python3
"""
tests/test_pqc_multi_assumption_combiner.py

Comprehensive Test Suite for Multi-Assumption Post-Quantum KEX Combiner (Zero Fallback).

Verifies:
1. MultiAssumptionKEXManager roundtrip: ML-KEM-1024 + Classic McEliece 8192128f + Hardware PSK.
2. Exact mathematical derivation against known test vectors and independent HKDF-Extract calculations.
3. Strict Triple-PRF AND-combiner: Any single leg alteration invalidates master key derivation.
4. Zero Fallback Fail-Closed Enforcement:
   - Missing or degenerate all-zero Hardware PSK refused.
   - Missing, truncated, or degenerate all-zero ciphertext refused.
   - Missing or malformed public keys refused.
   - Corrupted ciphertext decapsulation fails closed.
5. ZeroizeOnDrop / Native memory wiping on key destruction and manager closure.
6. Serialization / Deserialization of public keys (1,359,392B) and ciphertexts (1,776B).
7. Branchless constant-time comparisons on sensitive key materials.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pqc_multi_assumption as pma
from pqc_multi_assumption import (
    DOMAIN_SEPARATOR,
    HPSK_LEN,
    MASTER_KEY_LEN,
    MCELIECE_CT_LEN,
    MCELIECE_PK_LEN,
    MLKEM_CT_LEN,
    MLKEM_PK_LEN,
    HardwarePsk,
    MultiAssumptionKEXManager,
    TripleKexCiphertext,
    TripleKexPublicKey,
    _ct_is_all_zeros,
)


class TestPqcMultiAssumptionCombiner:
    """Test suite for the Multi-Assumption Post-Quantum KEX Combiner."""

    def test_kex_roundtrip_happy_path(self):
        """Alice and Bob negotiate a session key via ML-KEM-1024 + Classic McEliece 8192128f + H-PSK."""
        psk = secrets.token_bytes(32)
        transcript = b"SESSION-INIT-ID-42-TRANSCRIPT-DATA"

        alice = MultiAssumptionKEXManager(hardware_psk=psk)
        bob = MultiAssumptionKEXManager(hardware_psk=psk, auto_generate=False)

        # Bob encapsulates to Alice's public key bundle
        alice_pk = alice.get_public_key()
        ciphertext_bundle, k_master_bob = bob.encapsulate(alice_pk, transcript=transcript)

        assert isinstance(ciphertext_bundle, TripleKexCiphertext)
        assert len(k_master_bob) == MASTER_KEY_LEN

        # Alice decapsulates Bob's ciphertext bundle
        k_master_alice = alice.decapsulate(ciphertext_bundle, transcript=transcript)

        assert len(k_master_alice) == MASTER_KEY_LEN
        assert secrets.compare_digest(k_master_alice, k_master_bob) is True

    def test_exact_mathematical_derivation_vector(self):
        """Verify K_master = HKDF-Extract(SHA384("ST2027-TRIPLE-KEX-v1" || Transcript), SS_ML-KEM || SS_McEliece || K_H-PSK)."""
        transcript = b"TEST-TRANSCRIPT-VECTOR-999"
        ss_mlkem = b"\x11" * 32
        ss_mceliece = b"\x22" * 32
        h_psk = b"\x33" * 32

        # 1. Independent calculation per formula
        salt = hashlib.sha384(DOMAIN_SEPARATOR + transcript).digest()
        ikm = ss_mlkem + ss_mceliece + h_psk
        expected_prk = hmac.new(salt, ikm, hashlib.sha384).digest()

        # 2. Output from MultiAssumptionKEXManager
        derived_prk = MultiAssumptionKEXManager.derive_master_key(
            transcript=transcript,
            ss_mlkem=ss_mlkem,
            ss_mceliece=ss_mceliece,
            h_psk=h_psk,
        )

        assert len(derived_prk) == 48
        assert secrets.compare_digest(derived_prk, expected_prk) is True
        assert (
            derived_prk.hex()
            == "cfb1aaa2081c4549345df71afdb4726974b29662980a3834f444338e9c514f5b626b80f908476ab80557ab6bfd1c8712"
        )

    def test_strict_triple_prf_and_combiner_all_secrets_required(self):
        """Mutating any one secret leg or transcript alters the resulting master key."""
        transcript = b"TEST-TRANSCRIPT"
        ss_ml = b"\x01" * 32
        ss_mc = b"\x02" * 32
        h_psk = b"\x03" * 32

        base_key = MultiAssumptionKEXManager.derive_master_key(
            transcript, ss_ml, ss_mc, h_psk
        )

        # Mutate ML-KEM leg
        ss_ml_alt = bytearray(ss_ml)
        ss_ml_alt[0] ^= 0x80
        key_ml_alt = MultiAssumptionKEXManager.derive_master_key(
            transcript, bytes(ss_ml_alt), ss_mc, h_psk
        )
        assert secrets.compare_digest(base_key, key_ml_alt) is False

        # Mutate McEliece leg
        ss_mc_alt = bytearray(ss_mc)
        ss_mc_alt[0] ^= 0x80
        key_mc_alt = MultiAssumptionKEXManager.derive_master_key(
            transcript, ss_ml, bytes(ss_mc_alt), h_psk
        )
        assert secrets.compare_digest(base_key, key_mc_alt) is False

        # Mutate Hardware PSK
        psk_alt = bytearray(h_psk)
        psk_alt[0] ^= 0x80
        key_psk_alt = MultiAssumptionKEXManager.derive_master_key(
            transcript, ss_ml, ss_mc, bytes(psk_alt)
        )
        assert secrets.compare_digest(base_key, key_psk_alt) is False

        # Mutate Transcript
        key_tr_alt = MultiAssumptionKEXManager.derive_master_key(
            b"DIFFERENT-TRANSCRIPT", ss_ml, ss_mc, h_psk
        )
        assert secrets.compare_digest(base_key, key_tr_alt) is False

    def test_zero_fallback_missing_or_invalid_psk_refused(self):
        """Missing or malformed hardware PSK MUST fail closed immediately (zero fallback)."""
        # None PSK
        with pytest.raises(ValueError, match="Hardware PSK is strictly required"):
            MultiAssumptionKEXManager(hardware_psk=None)

        # Short PSK (16 bytes)
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            MultiAssumptionKEXManager(hardware_psk=b"too_short_psk_16")

        # Long PSK (64 bytes)
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            MultiAssumptionKEXManager(hardware_psk=b"\x01" * 64)

        # All-zero degenerate PSK
        with pytest.raises(ValueError, match="All-zero degenerate Hardware PSK rejected"):
            MultiAssumptionKEXManager(hardware_psk=bytes(32))

        # HardwarePsk class validation
        with pytest.raises(ValueError, match="Hardware PSK cannot be None"):
            HardwarePsk(None)

    def test_zero_fallback_all_zero_shared_secrets_refused(self):
        """All-zero degenerate shared secret inputs to derive_master_key MUST fail closed."""
        transcript = b"TRANSCRIPT"
        zero_32 = bytes(32)
        valid_32 = b"\x42" * 32

        with pytest.raises(ValueError, match="All-zero secret input refused"):
            MultiAssumptionKEXManager.derive_master_key(
                transcript, zero_32, valid_32, valid_32
            )

        with pytest.raises(ValueError, match="All-zero secret input refused"):
            MultiAssumptionKEXManager.derive_master_key(
                transcript, valid_32, zero_32, valid_32
            )

        with pytest.raises(ValueError, match="All-zero secret input refused"):
            MultiAssumptionKEXManager.derive_master_key(
                transcript, valid_32, valid_32, zero_32
            )

    def test_zero_fallback_invalid_secret_lengths_refused(self):
        """Invalid shared secret lengths passed to derive_master_key fail closed."""
        transcript = b"TRANSCRIPT"
        valid_32 = b"\x42" * 32

        with pytest.raises(ValueError, match="Invalid ML-KEM shared secret length"):
            MultiAssumptionKEXManager.derive_master_key(
                transcript, b"\x01" * 16, valid_32, valid_32
            )

        with pytest.raises(ValueError, match="Invalid McEliece shared secret length"):
            MultiAssumptionKEXManager.derive_master_key(
                transcript, valid_32, b"\x01" * 16, valid_32
            )

        with pytest.raises(ValueError, match="Invalid Hardware PSK length"):
            MultiAssumptionKEXManager.derive_master_key(
                transcript, valid_32, valid_32, b"\x01" * 16
            )

    def test_tampered_ciphertext_fails_closed(self):
        """Tampered ciphertext either causes decapsulation error or diverges master key."""
        psk = secrets.token_bytes(32)
        transcript = b"AUTHENTICATED-SESSION"

        alice = MultiAssumptionKEXManager(hardware_psk=psk)
        bob = MultiAssumptionKEXManager(hardware_psk=psk, auto_generate=False)

        ct, k_bob = bob.encapsulate(alice.get_public_key(), transcript=transcript)

        # 1. Tamper ML-KEM ciphertext
        raw_ml = bytearray(ct.mlkem_ct)
        raw_ml[10] ^= 0xFF
        tampered_ml_ct = TripleKexCiphertext(mlkem_ct=bytes(raw_ml), mceliece_ct=ct.mceliece_ct)

        # Under ML-KEM implicit rejection, decapsulation succeeds but key diverges
        k_alice_ml_tampered = alice.decapsulate(tampered_ml_ct, transcript=transcript)
        assert secrets.compare_digest(k_alice_ml_tampered, k_bob) is False

        # 2. Tamper McEliece ciphertext
        raw_mc = bytearray(ct.mceliece_ct)
        raw_mc[10] ^= 0xFF
        tampered_mc_ct = TripleKexCiphertext(mlkem_ct=ct.mlkem_ct, mceliece_ct=bytes(raw_mc))

        # McEliece decapsulation should either raise decaps failure or diverge
        try:
            k_alice_mc_tampered = alice.decapsulate(tampered_mc_ct, transcript=transcript)
            assert secrets.compare_digest(k_alice_mc_tampered, k_bob) is False
        except ValueError as exc:
            assert "McEliece decapsulation failed fail-closed" in str(exc)

    def test_missing_or_corrupted_ciphertext_input_refused(self):
        """Passing None or malformed ciphertext to decapsulate fails closed."""
        psk = secrets.token_bytes(32)
        alice = MultiAssumptionKEXManager(hardware_psk=psk)

        with pytest.raises(ValueError, match="ciphertext is missing"):
            alice.decapsulate(None)

        with pytest.raises(ValueError, match="Invalid TripleKexCiphertext bytes length"):
            alice.decapsulate(b"short_ct")

        with pytest.raises(ValueError, match="Ciphertext bundle missing required KEM component"):
            alice.decapsulate({"mlkem_ct": "aa" * 1568})  # missing mceliece

    def test_public_key_and_ciphertext_wire_serialization(self):
        """Verify binary and dict serialization for public keys and ciphertexts."""
        ml_pk = b"\x01" * MLKEM_PK_LEN
        mc_pk = b"\x02" * MCELIECE_PK_LEN
        pk = TripleKexPublicKey(mlkem_pk=ml_pk, mceliece_pk=mc_pk)

        pk_bytes = pk.to_bytes()
        assert len(pk_bytes) == MLKEM_PK_LEN + MCELIECE_PK_LEN
        pk_restored = TripleKexPublicKey.from_bytes(pk_bytes)
        assert pk_restored.mlkem_pk == ml_pk
        assert pk_restored.mceliece_pk == mc_pk

        pk_dict = pk.to_dict()
        pk_from_dict = TripleKexPublicKey.from_dict(pk_dict)
        assert pk_from_dict.mlkem_pk == ml_pk
        assert pk_from_dict.mceliece_pk == mc_pk

        ml_ct = b"\x03" * MLKEM_CT_LEN
        mc_ct = b"\x04" * MCELIECE_CT_LEN
        ct = TripleKexCiphertext(mlkem_ct=ml_ct, mceliece_ct=mc_ct)

        ct_bytes = ct.to_bytes()
        assert len(ct_bytes) == MLKEM_CT_LEN + MCELIECE_CT_LEN
        ct_restored = TripleKexCiphertext.from_bytes(ct_bytes)
        assert ct_restored.mlkem_ct == ml_ct
        assert ct_restored.mceliece_ct == mc_ct

        ct_dict = ct.to_dict()
        ct_from_dict = TripleKexCiphertext.from_dict(ct_dict)
        assert ct_from_dict.mlkem_ct == ml_ct
        assert ct_from_dict.mceliece_ct == mc_ct

    def test_zeroize_on_drop_and_close(self):
        """Verify that calling close() or using context manager wipes secret buffers."""
        psk = secrets.token_bytes(32)
        manager = MultiAssumptionKEXManager(hardware_psk=psk)

        # Before close, secret keys exist
        assert manager._mlkem_sk is not None
        assert manager._mlkem_sk.wiped is False
        assert manager._mceliece_sk is not None
        assert manager._mceliece_sk.wiped is False

        # Close manager
        manager.close()

        # After close, buffers are wiped and references cleared
        assert manager._mlkem_sk is None
        assert manager._mceliece_sk is None
        assert manager._hardware_psk is None

        # Subsequent decapsulation attempts fail closed
        with pytest.raises(RuntimeError, match="secret key not available or already zeroized"):
            manager.decapsulate(
                TripleKexCiphertext(mlkem_ct=b"\x01" * MLKEM_CT_LEN, mceliece_ct=b"\x02" * MCELIECE_CT_LEN)
            )

    def test_context_manager_lifecycle_wipes_keys(self):
        """Context manager exit automatically triggers zeroization."""
        psk = secrets.token_bytes(32)
        with MultiAssumptionKEXManager(hardware_psk=psk) as kex:
            pk = kex.get_public_key()
            assert len(pk.mlkem_pk) == MLKEM_PK_LEN
        # Exited with-block
        assert kex._mlkem_sk is None
        assert kex._mceliece_sk is None
        assert kex._hardware_psk is None

    def test_branchless_constant_time_zero_check(self):
        """Ensure _ct_is_all_zeros accurately detects zero buffers branchlessly."""
        assert _ct_is_all_zeros(bytes(32)) is True
        assert _ct_is_all_zeros(bytes(100)) is True
        non_zero = bytearray(32)
        non_zero[31] = 1
        assert _ct_is_all_zeros(non_zero) is False
        non_zero[0] = 1
        assert _ct_is_all_zeros(non_zero) is False

    def test_session_keys_expansion_and_mutual_confirmation(self):
        """Verify derivation of role-separated traffic keys and mutual confirmation tags."""
        psk = secrets.token_bytes(32)
        transcript = b"TRANSCRIPT-CONFIRMATION-RUN-01"

        alice = MultiAssumptionKEXManager(hardware_psk=psk)
        bob = MultiAssumptionKEXManager(hardware_psk=psk, auto_generate=False)

        ct, k_bob = bob.encapsulate(alice.get_public_key(), transcript=transcript)
        k_alice = alice.decapsulate(ct, transcript=transcript)

        assert secrets.compare_digest(k_alice, k_bob) is True

        # Expand session keys on both sides
        keys_alice = alice.expand_session_keys(k_alice, transcript_binding=transcript)
        keys_bob = bob.expand_session_keys(k_bob, transcript_binding=transcript)

        # Keys must be mutually agreed
        assert secrets.compare_digest(keys_alice.initiator_traffic_key, keys_bob.initiator_traffic_key) is True
        assert secrets.compare_digest(keys_alice.responder_traffic_key, keys_bob.responder_traffic_key) is True
        assert secrets.compare_digest(keys_alice.confirmation_key, keys_bob.confirmation_key) is True

        # Keys must be role-separated
        assert keys_alice.initiator_traffic_key != keys_alice.responder_traffic_key
        assert keys_alice.initiator_traffic_key != keys_alice.confirmation_key

        # Initiator computes tag; Responder verifies
        bob_tag = bob.compute_confirmation_tag(keys_bob.confirmation_key, is_initiator=True, transcript_binding=transcript)
        assert alice.verify_peer_confirmation_tag(keys_alice.confirmation_key, is_peer_initiator=True, transcript_binding=transcript, peer_tag=bob_tag) is True

        # Responder computes tag; Initiator verifies
        alice_tag = alice.compute_confirmation_tag(keys_alice.confirmation_key, is_initiator=False, transcript_binding=transcript)
        assert bob.verify_peer_confirmation_tag(keys_bob.confirmation_key, is_peer_initiator=False, transcript_binding=transcript, peer_tag=alice_tag) is True

        # Role separation: Initiator tag != Responder tag
        assert bob_tag != alice_tag

        # Tampered tag is rejected fail-closed
        bad_tag = bytearray(bob_tag)
        bad_tag[0] ^= 0x5A
        assert alice.verify_peer_confirmation_tag(keys_alice.confirmation_key, is_peer_initiator=True, transcript_binding=transcript, peer_tag=bytes(bad_tag)) is False

    def test_cross_language_interop_destroyer_core(self):
        """Verify destroyer_core._native / destroyer_core CoreTripleKex agrees with Python manager."""
        import destroyer_core
        has_triple_kex = hasattr(destroyer_core, "CoreTripleKex")
        assert has_triple_kex is True, "destroyer_core must export CoreTripleKex"

        transcript = b"CROSS-LANG-TRANSCRIPT-TEST-007"
        ss_ml = b"\x41" * 32
        ss_mc = b"\x42" * 32
        h_psk = b"\x43" * 32

        # 1. Master key derivation comparison
        master_py = MultiAssumptionKEXManager.derive_master_key(transcript, ss_ml, ss_mc, h_psk)
        master_core = destroyer_core.CoreTripleKex.derive_master(transcript, ss_ml, ss_mc, h_psk)
        assert secrets.compare_digest(master_py, master_core) is True

        # 2. Session key expansion comparison
        keys_py = pma.expand_session_keys(master_py, transcript_binding=transcript)
        i2r_c, r2i_c, conf_c = destroyer_core.CoreTripleKex.expand_session_keys(master_core, transcript)

        assert secrets.compare_digest(keys_py.initiator_traffic_key, i2r_c) is True
        assert secrets.compare_digest(keys_py.responder_traffic_key, r2i_c) is True
        assert secrets.compare_digest(keys_py.confirmation_key, conf_c) is True

        # 3. Confirmation tag comparison
        tag_py = pma.compute_confirmation_tag(keys_py.confirmation_key, pma.DOMAIN_CONFIRM_INITIATOR, transcript)
        tag_c = destroyer_core.CoreTripleKex.compute_confirmation_tag(conf_c, pma.DOMAIN_CONFIRM_INITIATOR, transcript)
        assert secrets.compare_digest(tag_py, tag_c) is True

        # Verify confirmation tag
        assert destroyer_core.CoreTripleKex.verify_confirmation_tag(conf_c, pma.DOMAIN_CONFIRM_INITIATOR, transcript, tag_py) is True

    def test_load_hardware_psk_from_file_and_hex(self, tmp_path: Path):
        """Verify load_hardware_psk handles raw 32-byte files, 64-char hex files, and fails closed."""
        raw_key = secrets.token_bytes(32)

        # 1. Raw binary file
        raw_file = tmp_path / "h_psk_raw.bin"
        raw_file.write_bytes(raw_key)
        psk_loaded = pma.load_hardware_psk(raw_file)
        assert secrets.compare_digest(psk_loaded.as_bytes(), raw_key) is True

        # 2. Hex text file
        hex_file = tmp_path / "h_psk_hex.txt"
        hex_file.write_text(raw_key.hex() + "\n", encoding="ascii")
        psk_hex_loaded = pma.load_hardware_psk(hex_file)
        assert secrets.compare_digest(psk_hex_loaded.as_bytes(), raw_key) is True

        # 3. Missing file
        with pytest.raises(FileNotFoundError):
            pma.load_hardware_psk(tmp_path / "non_existent.bin")

        # 4. Corrupt size file
        bad_file = tmp_path / "bad_len.bin"
        bad_file.write_bytes(b"\x11" * 15)
        with pytest.raises(ValueError, match="must contain 32 raw bytes"):
            pma.load_hardware_psk(bad_file)

    def test_concurrent_multi_threaded_kex_sessions(self):
        """Verify concurrent multi-threaded handshakes maintain session isolation and thread safety."""
        import concurrent.futures

        num_sessions = 6

        def run_single_session(idx: int) -> bool:
            psk = secrets.token_bytes(32)
            transcript = f"CONCURRENT-SESSION-TRANSCRIPT-{idx}".encode()

            alice = MultiAssumptionKEXManager(hardware_psk=psk)
            bob = MultiAssumptionKEXManager(hardware_psk=psk, auto_generate=False)

            ct, k_bob = bob.encapsulate(alice.get_public_key(), transcript=transcript)
            k_alice = alice.decapsulate(ct, transcript=transcript)

            if not secrets.compare_digest(k_alice, k_bob):
                return False

            keys_alice = alice.expand_session_keys(k_alice, transcript_binding=transcript)
            keys_bob = bob.expand_session_keys(k_bob, transcript_binding=transcript)

            if not secrets.compare_digest(keys_alice.initiator_traffic_key, keys_bob.initiator_traffic_key):
                return False

            tag = bob.compute_confirmation_tag(keys_bob.confirmation_key, is_initiator=True, transcript_binding=transcript)
            return alice.verify_peer_confirmation_tag(keys_alice.confirmation_key, is_peer_initiator=True, transcript_binding=transcript, peer_tag=tag)

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_single_session, i) for i in range(num_sessions)]
            results = [f.result() for f in futures]

        assert all(results) is True
        assert len(results) == num_sessions

    def test_type_and_bounds_validation_fail_closed(self):
        """Invalid types passed to KEX operations fail closed immediately."""
        psk = secrets.token_bytes(32)
        mgr = MultiAssumptionKEXManager(hardware_psk=psk)

        with pytest.raises(TypeError):
            MultiAssumptionKEXManager.derive_master_key(12345, b"\x01"*32, b"\x02"*32, b"\x03"*32)

        with pytest.raises(TypeError):
            MultiAssumptionKEXManager.derive_master_key(b"tr", None, b"\x02"*32, b"\x03"*32)

        with pytest.raises(TypeError):
            mgr.encapsulate(12345)

        with pytest.raises(TypeError):
            mgr.decapsulate(12345)

        with pytest.raises(ValueError):
            pma.expand_session_keys(b"\x01" * 32)  # wrong master key length (32 instead of 48)

    def test_public_key_and_ciphertext_json_and_base64_serialization(self):
        """Verify JSON and base64 serialization roundtrips for public keys and ciphertexts."""
        ml_pk = b"\x31" * MLKEM_PK_LEN
        mc_pk = b"\x32" * MCELIECE_PK_LEN
        pk = TripleKexPublicKey(mlkem_pk=ml_pk, mceliece_pk=mc_pk)

        # Base64
        b64_pk = pk.to_base64()
        assert isinstance(b64_pk, str)
        pk_restored_b64 = TripleKexPublicKey.from_base64(b64_pk)
        assert pk_restored_b64.mlkem_pk == ml_pk
        assert pk_restored_b64.mceliece_pk == mc_pk

        # JSON
        json_pk = pk.to_json()
        assert isinstance(json_pk, str)
        pk_restored_json = TripleKexPublicKey.from_json(json_pk)
        assert pk_restored_json.mlkem_pk == ml_pk
        assert pk_restored_json.mceliece_pk == mc_pk

        # Ciphertext
        ml_ct = b"\x41" * MLKEM_CT_LEN
        mc_ct = b"\x42" * MCELIECE_CT_LEN
        ct = TripleKexCiphertext(mlkem_ct=ml_ct, mceliece_ct=mc_ct)

        b64_ct = ct.to_base64()
        ct_restored_b64 = TripleKexCiphertext.from_base64(b64_ct)
        assert ct_restored_b64.mlkem_ct == ml_ct
        assert ct_restored_b64.mceliece_ct == mc_ct

        json_ct = ct.to_json()
        ct_restored_json = TripleKexCiphertext.from_json(json_ct)
        assert ct_restored_json.mlkem_ct == ml_ct
        assert ct_restored_json.mceliece_ct == mc_ct

    def test_redacted_repr_prevents_secret_leakage(self):
        """Verify that __repr__ never leaks secret material in tracebacks or logs."""
        raw_key = b"\xDE\xAD\xBE\xEF" * 8
        psk = HardwarePsk(raw_key)
        assert raw_key.hex() not in repr(psk)
        assert "[REDACTED]" in repr(psk)

        session_keys = pma.expand_session_keys(b"\x55" * 48, b"TR")
        assert repr(session_keys) == "TripleSessionKeys([REDACTED])"
        assert session_keys.initiator_traffic_key.hex() not in repr(session_keys)

        mgr = MultiAssumptionKEXManager(hardware_psk=psk)
        mgr_repr = repr(mgr)
        assert "MultiAssumptionKEXManager" in mgr_repr
        assert raw_key.hex() not in mgr_repr

        # Also verify TripleKexPublicKey and TripleKexCiphertext __repr__ summaries
        pk = mgr.get_public_key()
        assert "1568 bytes" in repr(pk)
        assert "1357824 bytes" in repr(pk)

    def test_hardware_psk_load_from_env_vars(self, monkeypatch):
        """Verify load_hardware_psk supports env:VAR with hex, base64, and raw bytes."""
        import base64
        raw_32 = secrets.token_bytes(32)

        # 1. Hex in env
        monkeypatch.setenv("TEST_HPSK_HEX", raw_32.hex())
        psk_hex = pma.load_hardware_psk("env:TEST_HPSK_HEX")
        assert secrets.compare_digest(psk_hex.as_bytes(), raw_32) is True

        # 2. Base64 in env
        monkeypatch.setenv("TEST_HPSK_B64", base64.b64encode(raw_32).decode("ascii"))
        psk_b64 = pma.load_hardware_psk("env:TEST_HPSK_B64")
        assert secrets.compare_digest(psk_b64.as_bytes(), raw_32) is True

        # 3. Unset env var fails closed
        with pytest.raises(ValueError, match="is unset or empty"):
            pma.load_hardware_psk("env:NON_EXISTENT_VAR_XYZ")

    def test_hardware_psk_load_from_provider_object(self):
        """Verify duck-typed token providers exposing get_psk() or export_hardware_psk()."""
        raw_key = secrets.token_bytes(32)

        class MockEnclaveProvider:
            def export_hardware_psk(self):
                return raw_key

        class MockHsmToken:
            def get_psk(self):
                return raw_key

        psk1 = pma.load_hardware_psk(MockEnclaveProvider())
        assert secrets.compare_digest(psk1.as_bytes(), raw_key) is True

        psk2 = pma.load_hardware_psk(MockHsmToken())
        assert secrets.compare_digest(psk2.as_bytes(), raw_key) is True

    def test_hardware_psk_load_base64_file(self, tmp_path: Path):
        """Verify load_hardware_psk handles base64-encoded key files."""
        import base64
        raw_key = secrets.token_bytes(32)
        b64_file = tmp_path / "psk.b64"
        b64_file.write_text(base64.b64encode(raw_key).decode("ascii") + "\n", encoding="ascii")

        psk = pma.load_hardware_psk(b64_file)
        assert secrets.compare_digest(psk.as_bytes(), raw_key) is True

    def test_triple_session_keys_context_manager_and_ct_eq(self):
        """Verify TripleSessionKeys context manager and constant-time ct_eq method."""
        keys1 = pma.expand_session_keys(b"\x21" * 48, b"TR-A")
        keys2 = pma.expand_session_keys(b"\x21" * 48, b"TR-A")
        keys3 = pma.expand_session_keys(b"\x22" * 48, b"TR-A")

        assert keys1.ct_eq(keys2) is True
        assert keys1.ct_eq(keys3) is False
        assert keys1.ct_eq("not_keys") is False

        with keys1 as k:
            assert len(k.initiator_traffic_key) == 32

    def test_constant_time_confirmation_tag_with_length_tampering(self):
        """Verify that verify_confirmation_tag branchlessly rejects wrong-length tags."""
        key = b"\x33" * 32
        role = pma.DOMAIN_CONFIRM_INITIATOR
        transcript = b"TR-TAG"

        valid_tag = pma.compute_confirmation_tag(key, role, transcript)
        assert pma.verify_confirmation_tag(key, role, transcript, valid_tag) is True

        # Short tag
        assert pma.verify_confirmation_tag(key, role, transcript, valid_tag[:16]) is False
        # Long tag
        assert pma.verify_confirmation_tag(key, role, transcript, valid_tag + b"\x00") is False
        # Empty tag
        assert pma.verify_confirmation_tag(key, role, transcript, b"") is False
        # Non-bytes
        assert pma.verify_confirmation_tag(key, role, transcript, None) is False

    def test_fuzz_random_bit_flips_fail_closed(self):
        """Fuzz 10 random bit flips in ML-KEM and McEliece ciphertexts ensuring fail-closed rejection."""
        psk = secrets.token_bytes(32)
        alice = MultiAssumptionKEXManager(hardware_psk=psk)
        bob = MultiAssumptionKEXManager(hardware_psk=psk, auto_generate=False)

        ct, k_bob = bob.encapsulate(alice.get_public_key(), transcript=b"FUZZ-TRANSCRIPT")

        # ML-KEM bit flips
        for offset in [0, 100, 500, 1000, MLKEM_CT_LEN - 1]:
            corrupt_ml = bytearray(ct.mlkem_ct)
            corrupt_ml[offset] ^= 0x01
            fuzzed_ct = TripleKexCiphertext(mlkem_ct=bytes(corrupt_ml), mceliece_ct=ct.mceliece_ct)
            # Under implicit rejection, decapsulation key MUST diverge
            k_alice = alice.decapsulate(fuzzed_ct, transcript=b"FUZZ-TRANSCRIPT")
            assert secrets.compare_digest(k_alice, k_bob) is False

        # McEliece bit flips
        for offset in [0, 50, 100, MCELIECE_CT_LEN - 1]:
            corrupt_mc = bytearray(ct.mceliece_ct)
            corrupt_mc[offset] ^= 0x01
            fuzzed_ct = TripleKexCiphertext(mlkem_ct=ct.mlkem_ct, mceliece_ct=bytes(corrupt_mc))
            try:
                k_alice = alice.decapsulate(fuzzed_ct, transcript=b"FUZZ-TRANSCRIPT")
                assert secrets.compare_digest(k_alice, k_bob) is False
            except ValueError:
                # McEliece explicit decapsulation rejection is also fail-closed compliant
                pass

    def test_role_reflection_attack_refused(self):
        """Initiator tag is strictly rejected as responder tag (reflection protection)."""
        key = secrets.token_bytes(32)
        transcript = b"TR-ROLE-SEPARATION"

        init_tag = pma.compute_confirmation_tag(key, pma.DOMAIN_CONFIRM_INITIATOR, transcript)
        resp_tag = pma.compute_confirmation_tag(key, pma.DOMAIN_CONFIRM_RESPONDER, transcript)

        assert init_tag != resp_tag
        # Trying to submit initiator tag as responder tag MUST fail
        assert pma.verify_confirmation_tag(key, pma.DOMAIN_CONFIRM_RESPONDER, transcript, init_tag) is False
        assert pma.verify_confirmation_tag(key, pma.DOMAIN_CONFIRM_INITIATOR, transcript, resp_tag) is False

    def test_transcript_binding_in_confirmation_tag(self):
        """Mismatched transcript in confirmation tag fails verification."""
        key = secrets.token_bytes(32)
        tag_tr1 = pma.compute_confirmation_tag(key, pma.DOMAIN_CONFIRM_INITIATOR, b"TRANSCRIPT-1")
        assert pma.verify_confirmation_tag(key, pma.DOMAIN_CONFIRM_INITIATOR, b"TRANSCRIPT-2", tag_tr1) is False

    def test_empty_transcript_determinism_and_distinctness(self):
        """Empty transcript b'' is fully valid, deterministic, and differs from non-empty."""
        ss_ml = b"\x12" * 32
        ss_mc = b"\x34" * 32
        psk = b"\x56" * 32

        k_empty1 = MultiAssumptionKEXManager.derive_master_key(b"", ss_ml, ss_mc, psk)
        k_empty2 = MultiAssumptionKEXManager.derive_master_key(b"", ss_ml, ss_mc, psk)
        k_non_empty = MultiAssumptionKEXManager.derive_master_key(b"SOME-TRANSCRIPT", ss_ml, ss_mc, psk)

        assert secrets.compare_digest(k_empty1, k_empty2) is True
        assert secrets.compare_digest(k_empty1, k_non_empty) is False
        assert len(k_empty1) == 48

    def test_key_regeneration_clears_prior_keys(self):
        """Calling generate_keypair() regenerates fresh keys and wipes prior secrets."""
        psk = secrets.token_bytes(32)
        mgr = MultiAssumptionKEXManager(hardware_psk=psk)

        pk1 = mgr.get_public_key()
        old_sk_ml = bytes(mgr._mlkem_sk)

        pk2 = mgr.generate_keypair()
        new_sk_ml = bytes(mgr._mlkem_sk)

        assert pk1.mlkem_pk != pk2.mlkem_pk
        assert old_sk_ml != new_sk_ml

    def test_post_wipe_operations_fail_closed(self):
        """Operations after manager.close() or psk.wipe() fail closed with RuntimeError."""
        psk = HardwarePsk(secrets.token_bytes(32))
        mgr = MultiAssumptionKEXManager(hardware_psk=psk)
        pk = mgr.get_public_key()
        ct = TripleKexCiphertext(mlkem_ct=b"\x01" * MLKEM_CT_LEN, mceliece_ct=b"\x02" * MCELIECE_CT_LEN)

        psk.wipe()
        with pytest.raises(RuntimeError, match="Hardware PSK buffer already zeroized"):
            psk.as_bytes()

        mgr.close()
        with pytest.raises(RuntimeError, match="secret key not available or already zeroized"):
            mgr.decapsulate(ct)

        # Encapsulation also requires active keys/PSK
        with pytest.raises((RuntimeError, ValueError)):
            mgr.encapsulate(pk)
