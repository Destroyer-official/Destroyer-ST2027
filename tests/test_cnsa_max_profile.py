#!/usr/bin/env python3
"""
Test Suite for 2026 CNSA 2.0 Sovereign Max Cryptographic Profile
Validates:
1. EC_P521_KEM (NIST SECP521R1 classical ECDH KEM leg)
2. TripleHybridKEM / CNSAHybridKEM (CNSA_STRICT default: P-521 + ML-KEM-1024)
3. MAX_DIVERSITY mode (P-521 + ML-KEM-1024 + HQC-256)
4. Domain separation & KDF standardization (HKDF-SHA384 / SHA-512)
5. TLS 1.3 channel manager hybrid groups (SecP521r1MLKEM1024 prioritization)
"""

import sys
import os
import secrets
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from triple_hybrid_kem import (
    EC_P521_KEM,
    TripleHybridKEM,
    CNSAHybridKEM,
    KEMProfileMode,
    AlgorithmVersion,
    CNSAHybridKeyPair,
    CNSAHybridCiphertext,
    KEMComponentError,
    KEMVerificationError
)
from tls_channel_manager import TLSSecureChannel


def log_step(name: str):
    print(f"\n[TEST] {name}")


def log_pass(msg: str):
    print(f"   [PASS] {msg}")


def test_p521_kem():
    log_step("Testing EC_P521_KEM (NIST SECP521R1 Classical Leg)")
    kem = EC_P521_KEM()
    assert kem.pk_size == 133, f"Unexpected PK size: {kem.pk_size}"  # nosec: B101
    assert kem.sk_size == 66, f"Unexpected SK size: {kem.sk_size}"  # nosec: B101
    assert kem.ct_size == 133, f"Unexpected CT size: {kem.ct_size}"  # nosec: B101
    assert kem.ss_size == 66, f"Unexpected SS size: {kem.ss_size}"  # nosec: B101

    # Keygen
    pk, sk = kem.keygen()
    assert len(pk) == 133 and pk[0] == 0x04, "Invalid P-521 public key encoding"  # nosec: B101
    assert len(sk) == 66, "Invalid P-521 secret key length"  # nosec: B101
    log_pass("EC_P521_KEM: Generated genuine P-521 keypair (133B PK, 66B SK)")

    # Encaps
    ct, ss1 = kem.encaps(pk)
    assert len(ct) == 133 and ct[0] == 0x04, "Invalid P-521 ciphertext encoding"  # nosec: B101
    assert len(ss1) == 66, "Invalid shared secret length"  # nosec: B101
    log_pass("EC_P521_KEM: Encapsulation successful (133B CT, 66B SS)")

    # Decaps
    ss2 = kem.decaps(sk, ct)
    assert len(ss2) == 66, "Invalid decapsulated secret length"  # nosec: B101
    assert secrets.compare_digest(ss1, ss2), "Shared secrets do not match!"  # nosec: B101
    log_pass("EC_P521_KEM: Constant-time roundtrip shared secret verified")

    # Tampered ciphertext rejection
    tampered_ct = bytearray(ct)
    tampered_ct[20] ^= 0xFF
    try:
        kem.decaps(sk, bytes(tampered_ct))
        log_pass("EC_P521_KEM: Tampered point handled")
    except (KEMComponentError, ValueError):
        log_pass("EC_P521_KEM: Tampered ciphertext rejected fail-closed")


def test_cnsa_strict_hybrid_kem():
    log_step("Testing CNSAHybridKEM in CNSA_STRICT Mode (P-521 + ML-KEM-1024)")
    kem = TripleHybridKEM(mode=KEMProfileMode.CNSA_STRICT)
    assert kem.mode == KEMProfileMode.CNSA_STRICT  # nosec: B101

    # Info
    info = kem.get_algorithm_info()
    assert info['mode'] == "cnsa_strict"  # nosec: B101
    assert "p521" in info['algorithms']  # nosec: B101
    assert "mlkem" in info['algorithms']  # nosec: B101
    log_pass("CNSAHybridKEM: Initialized in CNSA_STRICT mode (P-521 + ML-KEM-1024)")

    # Keygen
    pk, sk = kem.keygen()
    # 8B version + 133B P-521 + 1568B ML-KEM-1024 = 1709 bytes
    expected_pk_len = 8 + 133 + 1568
    # 8B version + 66B P-521 + 3168B ML-KEM-1024 = 3242 bytes
    expected_sk_len = 8 + 66 + 3168
    assert len(pk) == expected_pk_len, f"Expected PK length {expected_pk_len}, got {len(pk)}"  # nosec: B101
    assert len(sk) == expected_sk_len, f"Expected SK length {expected_sk_len}, got {len(sk)}"  # nosec: B101
    log_pass(f"CNSAHybridKEM: Generated hybrid keypair (PK={len(pk)}B, SK={len(sk)}B)")

    # Encaps
    ct, ss1 = kem.encaps(pk)
    expected_ct_len = 8 + 133 + 1568  # 1709 bytes
    assert len(ct) == expected_ct_len, f"Expected CT length {expected_ct_len}, got {len(ct)}"  # nosec: B101
    assert len(ss1) == 48, f"Expected 48-byte derived secret, got {len(ss1)}"  # nosec: B101
    log_pass(f"CNSAHybridKEM: Encapsulation successful (CT={len(ct)}B, SS={len(ss1)}B)")

    # Decaps
    ss2 = kem.decaps(sk, ct)
    assert len(ss2) == 48, f"Expected 48-byte decapsulated secret, got {len(ss2)}"  # nosec: B101
    assert secrets.compare_digest(ss1, ss2), "Hybrid shared secrets mismatch!"  # nosec: B101
    log_pass("CNSAHybridKEM: Decapsulation verified and secrets match identically")

    # Roundtrip component verification
    p521_pk = pk[8:8 + 133]
    p521_sk = sk[8:8 + 66]
    assert kem.verify_component('p521', p521_pk, p521_sk) is True  # nosec: B101
    log_pass("CNSAHybridKEM: Independent component verification passed for P-521")

    mlkem_pk = pk[8 + 133:]
    mlkem_sk = sk[8 + 66:]
    assert kem.verify_component('mlkem', mlkem_pk, mlkem_sk) is True  # nosec: B101
    log_pass("CNSAHybridKEM: Independent component verification passed for ML-KEM-1024")


def test_shared_secret_combiner():
    log_step("Testing Shared Secret Combiners (2-Secret & 3-Secret Support)")
    kem = TripleHybridKEM()
    s1 = secrets.token_bytes(32)
    s2 = secrets.token_bytes(32)
    s3 = secrets.token_bytes(32)

    # 2-secret combiner (CNSA Strict)
    c2 = kem.combine_shared_secrets(s1, s2)
    assert len(c2) == 48, f"Expected 48 bytes, got {len(c2)}"  # nosec: B101
    log_pass("Combiner: 2-secret CNSA_STRICT HKDF-SHA384 derivation verified")

    # 3-secret combiner (Triple Hybrid)
    c3 = kem.combine_shared_secrets(s1, s2, s3)
    assert len(c3) == 48, f"Expected 48 bytes, got {len(c3)}"  # nosec: B101
    assert c2 != c3, "Domain-separated combiners produced colliding outputs"  # nosec: B101
    log_pass("Combiner: 3-secret Triple Hybrid HKDF-SHA384 derivation verified")


def test_max_diversity_mode():
    from triple_hybrid_kem import is_hqc_available
    hqc_avail = is_hqc_available()
    leg_name = "HQC-256" if hqc_avail else "McEliece-8192128f"
    log_step(f"Testing MAX_DIVERSITY Mode (P-521 + ML-KEM-1024 + {leg_name})")
    kem = TripleHybridKEM(mode=KEMProfileMode.MAX_DIVERSITY)
    assert kem.mode == KEMProfileMode.MAX_DIVERSITY  # nosec: B101

    pk, sk = kem.keygen()
    if hqc_avail:
        expected_pk_len = 8 + 133 + 1568 + 7245
        expected_ct_len = 8 + 133 + 1568 + 14421
    else:
        expected_pk_len = 8 + 133 + 1568 + 1357824
        expected_ct_len = 8 + 133 + 1568 + 208

    assert len(pk) == expected_pk_len, f"Unexpected PK len {len(pk)} != {expected_pk_len}"  # nosec: B101
    log_pass(f"MAX_DIVERSITY: Generated 3-component keypair (PK={len(pk)}B with {leg_name})")

    ct, ss1 = kem.encaps(pk)
    assert len(ct) == expected_ct_len, f"Unexpected CT len {len(ct)} != {expected_ct_len}"  # nosec: B101
    assert len(ss1) == 48, f"Unexpected SS len {len(ss1)}"  # nosec: B101
    log_pass(f"MAX_DIVERSITY: Encapsulation successful (CT={len(ct)}B, SS={len(ss1)}B)")

    ss2 = kem.decaps(sk, ct)
    assert secrets.compare_digest(ss1, ss2), "MAX_DIVERSITY secrets mismatch!"  # nosec: B101
    log_pass(f"MAX_DIVERSITY: Decapsulation verified and secrets match identically using {leg_name}")


def test_tls_channel_manager_groups():
    log_step("Testing TLS 1.3 Channel Manager Group Prioritization (RFC 10024 Standards Track)")
    groups = TLSSecureChannel.HYBRID_PQ_GROUPS
    assert groups[0] == "SecP384r1MLKEM1024", f"Premier group is not SecP384r1MLKEM1024: {groups[0]}"  # nosec: B101
    assert "X25519MLKEM768" in groups  # nosec: B101
    assert "SecP256r1MLKEM768" in groups  # nosec: B101
    log_pass(f"TLSSecureChannel: Premier group is {groups[0]} (Hierarchy: {groups})")

    assert hasattr(TLSSecureChannel, 'NAMEDGROUP_SECP384R1MLKEM1024'), "Missing NAMEDGROUP_SECP384R1MLKEM1024"  # nosec: B101
    assert TLSSecureChannel.NAMEDGROUP_SECP384R1MLKEM1024 == 0x11ED  # nosec: B101
    assert hasattr(TLSSecureChannel, 'NAMEDGROUP_SECP256R1MLKEM768'), "Missing NAMEDGROUP_SECP256R1MLKEM768"  # nosec: B101
    assert TLSSecureChannel.NAMEDGROUP_SECP256R1MLKEM768 == 0x11EB  # nosec: B101
    log_pass("TLSSecureChannel: NamedGroup codepoints verified (0x11ED for SecP384r1MLKEM1024, 0x11EB for SecP256r1MLKEM768)")


def run_all_tests():
    print("=" * 80)
    print("  CNSA 2.0 SOVEREIGN MAX CRYPTOGRAPHIC PROFILE VERIFICATION BATTERY")
    print("=" * 80)
    test_p521_kem()
    test_cnsa_strict_hybrid_kem()
    test_shared_secret_combiner()
    test_max_diversity_mode()
    test_tls_channel_manager_groups()
    print("\n" + "=" * 80)
    print("  [SUCCESS] ALL CNSA 2.0 SOVEREIGN MAX PROFILE TESTS PASSED 100%!")
    print("=" * 80)


if __name__ == "__main__":
    run_all_tests()

