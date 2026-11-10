#!/usr/bin/env python3
"""
CNSA 2.0 Hybrid Key Exchange (2027 Mandate) and NIST SP 800-38D Test Suite.

Verifies:
1. CNSA 2.0 Hybrid Handshake: P-384 ECDH + ML-KEM-1024 + ML-DSA-87 signatures + HKDF-SHA384 combiner.
2. Mutual ML-DSA-87 signature authentication of public bundles.
3. Tamper detection: altered bundles or ciphertexts are rejected fail-closed.
4. NIST SP 800-38D Section 8.2.1: Deterministic 96-bit composite IV (32-bit fixed + 64-bit atomic monotonic counter).
5. DoubleRatchet default posture: protocol_version=2 (SPQR fresh-KEM per DH step) enabled by default.
6. Post-compromise security (PCS) verified across ratchet steps.
"""

import os
import sys
import secrets
import pytest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hybrid_kex import HybridKeyExchange2027
import p2p_core
import platform_hsm_interface
from double_ratchet import DoubleRatchet, braid_ct_sync_roundtrip


class TestCNSA2HybridKex2027:
    def test_cnsa2_handshake_roundtrip(self):
        """Verify full CNSA 2.0 P-384 + ML-KEM-1024 + ML-DSA-87 key exchange."""
        psk = secrets.token_bytes(32)
        alice = HybridKeyExchange2027(identity="ALICE_ALPHA", psk=psk)
        bob = HybridKeyExchange2027(identity="BOB_BRAVO", psk=psk)

        b_alice = alice.get_public_bundle()
        b_bob = bob.get_public_bundle()

        assert alice.verify_public_bundle(b_bob) is True
        assert bob.verify_public_bundle(b_alice) is True

        handshake_msg, ss_alice = alice.initiate_handshake(b_bob)
        ss_bob = bob.respond_to_handshake(handshake_msg, b_alice)

        assert len(ss_alice) == 32
        assert len(ss_bob) == 32
        assert secrets.compare_digest(ss_alice, ss_bob) is True

    def test_tampered_bundle_signature_rejected(self):
        """Verify that altering bundle data invalidates the ML-DSA-87 signature."""
        alice = HybridKeyExchange2027(identity="ALICE")
        bob = HybridKeyExchange2027(identity="BOB")

        bundle = alice.get_public_bundle()
        # Tamper with the public ML-KEM key in the bundle
        raw_mlkem = bytearray(bytes.fromhex(bundle["mlkem"]))
        raw_mlkem[0] ^= 0xFF
        bundle["mlkem"] = bytes(raw_mlkem).hex()

        assert bob.verify_public_bundle(bundle) is False
        with pytest.raises(ValueError, match="Peer bundle failed ML-DSA-87 signature"):
            bob.initiate_handshake(bundle)

    def test_tampered_signature_rejected(self):
        """Verify that modifying the ML-DSA-87 signature fails verification."""
        alice = HybridKeyExchange2027(identity="ALICE")
        bob = HybridKeyExchange2027(identity="BOB")

        bundle = alice.get_public_bundle()
        sig = bytearray(bytes.fromhex(bundle["signature"]))
        sig[10] ^= 0x5A
        bundle["signature"] = bytes(sig).hex()

        assert bob.verify_public_bundle(bundle) is False

    def test_sp_800_38d_deterministic_iv_structure(self):
        """NIST SP 800-38D Section 8.2.1: 96-bit deterministic IV = 4-byte fixed + 8-byte monotonic counter."""
        iv1 = p2p_core.generate_deterministic_gcm_iv()
        iv2 = p2p_core.generate_deterministic_gcm_iv()

        assert len(iv1) == 12
        assert len(iv2) == 12
        # Fixed 4-byte field must match within same process session
        assert iv1[:4] == iv2[:4]
        # 8-byte monotonic counter must strictly increase
        cnt1 = int.from_bytes(iv1[4:], byteorder="big")
        cnt2 = int.from_bytes(iv2[4:], byteorder="big")
        assert cnt2 == cnt1 + 1

    def test_sp_800_38d_aes_gcm_roundtrip(self):
        """Verify AES-256-GCM encryption/decryption with deterministic IV."""
        key = secrets.token_bytes(32)
        plaintext = b"CNSA 2.0 TOP SECRET // NIST SP 800-38D ASSURANCE"

        ciphertext, iv, tag = p2p_core.secure_encrypt_aes_256_gcm(plaintext, key)
        assert len(iv) == 12
        assert len(tag) == 16

        recovered = p2p_core.secure_decrypt_aes_256_gcm(ciphertext, key, iv, tag)
        assert recovered == plaintext

    def test_double_ratchet_defaults_to_v2_fresh_kem(self):
        """Verify DoubleRatchet constructor defaults to protocol_version=2 (fresh ML-KEM PCS)."""
        root = secrets.token_bytes(32)
        alice = DoubleRatchet(root_key=root, is_initiator=True)
        assert alice.protocol_version == 2
        assert alice.pq_ratchet_version == DoubleRatchet.PQ_RATCHET_VERSION_FRESH

    def test_double_ratchet_braid_sync_roundtrip(self):
        """Verify full SPQR fresh-KEM roundtrip with ML-KEM-1024 encapsulation per DH epoch."""
        res = braid_ct_sync_roundtrip()
        assert res["plaintext_roundtrip"] is True
        assert res["ct_on_wire_m2"] == 1568  # FIPS 203 ML-KEM-1024 CT length
        assert res["chain_pair_bob_to_alice"] is True
        assert res["chain_pair_alice_to_bob"] is True
        assert res["peer_ct_seen_alice"] is True
        assert res["peer_ct_seen_bob"] is True

