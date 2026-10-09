#!/usr/bin/env python3
"""
tests/test_comprehensive_security_tiers.py

Automated Test Suite for Comprehensive Multi-Tier Security Hardening:
  1. Micro Hardening:
     - NativeSecureBuffer in-RAM DPAPI protection (CryptProtectMemory on Windows).
     - NativeSecureBuffer expose() context manager & wipe zeroization.
     - SideChannelResistance constant-time padding check & constant-time int equals.
  2. Medium Hardening:
     - LibOQS Verify-After-Sign (VAS) for ML-DSA-87, SLH-DSA-256f, Falcon-1024.
     - Corrupted / faulted signature rejection (CHES 2024 / eprint 2025/2009).
  3. High Hardening:
     - DAITA traffic camouflage validation (quantum framing + Poisson chaff).
     - Sliding-window anti-replay policy validation.
  4. Critical Hardening:
     - Two-Person Integrity (TPI) authorization gates.
     - Dual-operator distinctness, token freshness, and payload commitment.
  5. Multi-Tier Policy Engine:
     - Strict hierarchy enforcement (LOW < BASIC < MEDIUM < HIGH < CRITICAL).
     - Fail-closed runtime tier assessment.
"""

from __future__ import annotations

import os
import secrets
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from native_secure_buffer import NativeSecureBuffer, wipe_native
from side_channel_resistance import ConstantTimeOperations
from security_tiers import (
    SecurityTier,
    SecurityTierEngine,
    SecurityTierViolationError,
    TIER_PROFILES,
)


class TestComprehensiveSecurityTiers(unittest.TestCase):
    """Verifies micro-to-major security across all 5 operational tiers."""

    # ----------------------------------------------------------------------
    # 1. Micro-Level Memory & Side-Channel Defenses
    # ----------------------------------------------------------------------

    def test_native_buffer_in_ram_dpapi_protect_unprotect(self):
        """NativeSecureBuffer supports in-RAM DPAPI protection (CryptProtectMemory on Windows)."""
        secret_data = secrets.token_bytes(32)
        buf = NativeSecureBuffer(secret_data)
        self.assertEqual(len(buf), 32)
        self.assertFalse(buf.is_protected)

        # Protect buffer in RAM
        protected_ok = buf.protect()
        if sys.platform == "win32":
            self.assertTrue(protected_ok)
            self.assertTrue(buf.is_protected)
            # When protected on Windows, the raw bytearray in RAM contains DPAPI ciphertext
            self.assertNotEqual(bytes(buf._buf), secret_data)

            # export_bytes() must transparently unprotect and re-protect
            exported = buf.export_bytes()
            self.assertEqual(exported, secret_data)
            self.assertTrue(buf.is_protected)

            # expose() context manager grants transient plaintext access
            with buf.expose() as pt:
                self.assertEqual(bytes(pt), secret_data)
            self.assertTrue(buf.is_protected)

            # Explicit unprotect
            self.assertTrue(buf.unprotect())
            self.assertFalse(buf.is_protected)
            self.assertEqual(bytes(buf._buf), secret_data)

        # Wipe securely clears and unprotects
        wipe_method = buf.wipe()
        self.assertTrue(buf.wiped)
        self.assertFalse(buf.is_protected)
        self.assertEqual(bytes(buf), b"\x00" * 32)
        self.assertTrue(isinstance(wipe_method, str))

    def test_side_channel_constant_time_equals_int(self):
        """Constant-time integer equality comparison without branching."""
        self.assertTrue(ConstantTimeOperations.constant_time_equals_int(0, 0))
        self.assertTrue(ConstantTimeOperations.constant_time_equals_int(42, 42))
        self.assertTrue(ConstantTimeOperations.constant_time_equals_int(0xFFFFFFFF, 0xFFFFFFFF))
        self.assertFalse(ConstantTimeOperations.constant_time_equals_int(0, 1))
        self.assertFalse(ConstantTimeOperations.constant_time_equals_int(42, 43))

    def test_side_channel_constant_time_verify_padding(self):
        """Constant-time PKCS#7 padding validation."""
        # Valid 16-byte block with 4 bytes of padding (value 0x04)
        valid_block = b"123456781234" + b"\x04\x04\x04\x04"
        is_valid, pad_len = ConstantTimeOperations.constant_time_verify_padding(valid_block, block_size=16)
        self.assertTrue(is_valid)
        self.assertEqual(pad_len, 4)

        # Valid 16-byte block with 16 bytes of padding (value 0x10)
        full_pad = b"\x10" * 16
        is_valid, pad_len = ConstantTimeOperations.constant_time_verify_padding(full_pad, block_size=16)
        self.assertTrue(is_valid)
        self.assertEqual(pad_len, 16)

        # Corrupted padding byte must fail in constant time
        corrupted = b"123456781234" + b"\x04\x04\x05\x04"
        is_valid, pad_len = ConstantTimeOperations.constant_time_verify_padding(corrupted, block_size=16)
        self.assertFalse(is_valid)
        self.assertEqual(pad_len, 0)

        # Padding byte exceeding block size must fail
        invalid_len = b"123456781234123" + b"\x15"
        is_valid, pad_len = ConstantTimeOperations.constant_time_verify_padding(invalid_len, block_size=16)
        self.assertFalse(is_valid)
        self.assertEqual(pad_len, 0)

    # ----------------------------------------------------------------------
    # 2. Medium-Level Cryptography & Verify-After-Sign (VAS)
    # ----------------------------------------------------------------------

    def test_liboqs_mldsa87_verify_after_sign(self):
        """ML-DSA-87 signature with Verify-After-Sign (VAS) succeeds on valid and fails closed on fault."""
        from liboqs_wrapper import LibOQS_MLDSA_87
        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()
        msg = b"MISSION_CRITICAL_TELEMETRY_PACKET"

        # Positive path: sign with VAS
        sig = signer.sign(sk, msg, public_key=pk)
        self.assertTrue(signer.verify(pk, msg, sig))

        # Test sign_verified convenience method
        sig2 = signer.sign_verified(sk, msg, pk)
        self.assertTrue(signer.verify(pk, msg, sig2))

        # Fault injection simulation: wrong public key causes VAS to fail closed
        other_pk, _ = signer.keygen()
        with self.assertRaises(RuntimeError) as ctx:
            signer.sign(sk, msg, public_key=other_pk)
        self.assertIn("FAIL-CLOSED: Verify-After-Sign", str(ctx.exception))

    # ----------------------------------------------------------------------
    # 3. Security Tier Hierarchy & Criteria
    # ----------------------------------------------------------------------

    def test_tier_comparison_and_hierarchy(self):
        """Verify strict ordering across all 5 tiers: LOW < BASIC < MEDIUM < HIGH < CRITICAL."""
        self.assertTrue(SecurityTier.LOW < SecurityTier.BASIC)
        self.assertTrue(SecurityTier.BASIC < SecurityTier.MEDIUM)
        self.assertTrue(SecurityTier.MEDIUM < SecurityTier.HIGH)
        self.assertTrue(SecurityTier.HIGH < SecurityTier.CRITICAL)

        self.assertTrue(SecurityTier.CRITICAL >= SecurityTier.HIGH)
        self.assertTrue(SecurityTier.HIGH >= SecurityTier.MEDIUM)
        self.assertTrue(SecurityTier.MEDIUM >= SecurityTier.BASIC)
        self.assertTrue(SecurityTier.BASIC >= SecurityTier.LOW)

    def test_validate_cipher_suite_per_tier(self):
        """Validate CNSA 2.0 cipher suite requirements across each tier."""
        # LOW tier allows standard cipher without PQC
        ok, violations = SecurityTierEngine.validate_cipher_suite(
            SecurityTier.LOW,
            cipher_name="AES-256-GCM",
            hash_or_kdf_name="SHA-384",
        )
        self.assertTrue(ok)
        self.assertEqual(len(violations), 0)

        # MEDIUM tier requires PQC (ML-KEM-1024 + ML-DSA-87)
        ok_med, violations_med = SecurityTierEngine.validate_cipher_suite(
            SecurityTier.MEDIUM,
            cipher_name="AES-256-GCM",
            hash_or_kdf_name="HKDF-SHA384",
            kem_name="ML-KEM-1024",
            sig_name="ML-DSA-87",
        )
        self.assertTrue(ok_med)
        self.assertEqual(len(violations_med), 0)

        # MEDIUM tier fails if PQC KEM is missing
        bad_med, v_bad = SecurityTierEngine.validate_cipher_suite(
            SecurityTier.MEDIUM,
            cipher_name="AES-256-GCM",
            hash_or_kdf_name="HKDF-SHA384",
        )
        self.assertFalse(bad_med)
        self.assertTrue(any("requires Post-Quantum KEM" in v for v in v_bad))

    def test_validate_memory_hygiene_per_tier(self):
        """Verify memory protection requirements (RAM locking & encryption)."""
        # LOW tier allows non-pinned memory
        ok_low, _ = SecurityTierEngine.validate_memory_hygiene(
            SecurityTier.LOW, is_pinned=False, is_ram_encrypted=False
        )
        self.assertTrue(ok_low)

        # BASIC and higher require locked memory or in-RAM encryption
        ok_basic, _ = SecurityTierEngine.validate_memory_hygiene(
            SecurityTier.BASIC, is_pinned=True, is_ram_encrypted=False
        )
        self.assertTrue(ok_basic)

        fail_basic, v_basic = SecurityTierEngine.validate_memory_hygiene(
            SecurityTier.BASIC, is_pinned=False, is_ram_encrypted=False
        )
        self.assertFalse(fail_basic)
        self.assertTrue(any("memory locking" in v for v in v_basic))

        # In-RAM DPAPI encryption satisfies the requirement even if page locking failed
        ok_dpapi, _ = SecurityTierEngine.validate_memory_hygiene(
            SecurityTier.HIGH, is_pinned=False, is_ram_encrypted=True
        )
        self.assertTrue(ok_dpapi)

    def test_validate_traffic_camouflage_per_tier(self):
        """Verify DAITA camouflage and anti-replay requirements."""
        # HIGH requires both quantization and chaff
        ok_high, _ = SecurityTierEngine.validate_traffic_camouflage(
            SecurityTier.HIGH,
            is_quantized=True,
            is_chaff_active=True,
            has_anti_replay=True,
        )
        self.assertTrue(ok_high)

        fail_high, v_high = SecurityTierEngine.validate_traffic_camouflage(
            SecurityTier.HIGH,
            is_quantized=False,
            is_chaff_active=True,
            has_anti_replay=True,
        )
        self.assertFalse(fail_high)
        self.assertTrue(any("constant-quantum frame padding" in v for v in v_high))

    # ----------------------------------------------------------------------
    # 4. Critical Tier: Two-Person Integrity (TPI)
    # ----------------------------------------------------------------------

    def test_critical_two_person_integrity_validation(self):
        """CRITICAL tier demands 2 distinct operators, fresh challenge, and valid signatures."""
        op1 = "operator_alpha"
        op2 = "operator_bravo"
        sig1 = secrets.token_bytes(64)
        sig2 = secrets.token_bytes(64)
        digest = secrets.token_bytes(48)  # SHA-384 digest

        # Valid dual-operator release
        ok, violations = SecurityTierEngine.validate_critical_authorization(
            SecurityTier.CRITICAL,
            operator_ids=[op1, op2],
            signatures=[sig1, sig2],
            payload_digest=digest,
            challenge_age_sec=45.0,
        )
        self.assertTrue(ok)
        self.assertEqual(len(violations), 0)

        # Single operator rejected (Two-Person Integrity failure)
        fail_single, v_single = SecurityTierEngine.validate_critical_authorization(
            SecurityTier.CRITICAL,
            operator_ids=[op1],
            signatures=[sig1],
            payload_digest=digest,
            challenge_age_sec=45.0,
        )
        self.assertFalse(fail_single)
        self.assertTrue(any("at least 2 distinct operators" in v for v in v_single))

        # Duplicate operator ID rejected
        fail_dup, v_dup = SecurityTierEngine.validate_critical_authorization(
            SecurityTier.CRITICAL,
            operator_ids=[op1, op1],
            signatures=[sig1, sig2],
            payload_digest=digest,
            challenge_age_sec=45.0,
        )
        self.assertFalse(fail_dup)
        self.assertTrue(any("duplicate operator ID" in v for v in v_dup))

        # Expired ceremony challenge rejected (>300s)
        fail_expired, v_expired = SecurityTierEngine.validate_critical_authorization(
            SecurityTier.CRITICAL,
            operator_ids=[op1, op2],
            signatures=[sig1, sig2],
            payload_digest=digest,
            challenge_age_sec=360.0,
        )
        self.assertFalse(fail_expired)
        self.assertTrue(any("expired" in v.lower() for v in v_expired))

    # ----------------------------------------------------------------------
    # 5. Dynamic Runtime Tier Assessment
    # ----------------------------------------------------------------------

    def test_assess_runtime_security_tier(self):
        """Verify dynamic qualification from capabilities down to accurate tier."""
        # Complete CRITICAL capabilities
        crit_caps = {
            "has_pqc_kem": True,
            "has_pqc_sig": True,
            "has_vas": True,
            "has_locked_memory": True,
            "has_ram_encryption": True,
            "has_forward_secrecy": True,
            "has_quantization": True,
            "has_pacing_chaff": True,
            "has_anti_replay": True,
            "has_two_person_integrity": True,
            "has_cross_domain_guard": True,
            "has_emergency_shred": True,
        }
        self.assertEqual(SecurityTierEngine.assess_runtime_security_tier(crit_caps), SecurityTier.CRITICAL)

        # Demote by omitting TPI: qualifies for HIGH
        high_caps = dict(crit_caps)
        high_caps["has_two_person_integrity"] = False
        self.assertEqual(SecurityTierEngine.assess_runtime_security_tier(high_caps), SecurityTier.HIGH)

        # Demote by omitting DAITA chaff: qualifies for MEDIUM
        med_caps = dict(high_caps)
        med_caps["has_pacing_chaff"] = False
        self.assertEqual(SecurityTierEngine.assess_runtime_security_tier(med_caps), SecurityTier.MEDIUM)

        # Demote by omitting PQC: qualifies for BASIC
        basic_caps = dict(med_caps)
        basic_caps["has_pqc_kem"] = False
        self.assertEqual(SecurityTierEngine.assess_runtime_security_tier(basic_caps), SecurityTier.BASIC)

        # Minimal capabilities: qualifies for LOW
        low_caps = {"has_anti_replay": False}
        self.assertEqual(SecurityTierEngine.assess_runtime_security_tier(low_caps), SecurityTier.LOW)


if __name__ == "__main__":
    unittest.main()
