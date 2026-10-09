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
    TelemetryScrubber,
    DiagnosticAccessControl,
    DeterministicNonceGenerator,
    AntiReplaySlidingWindow,
    MonotonicStatePersister,
    TranscriptBoundHybridKEM,
    VASLatchingAuthority,
    TripleRatchetMessage,
    TripleRatchetEngine,
    DAITAFrameShaper,
    PoissonCoverTrafficScheduler,
    TrafficAction,
    TrafficState,
    MaybenotTrafficFSM,
    SP800_208_LMS,
    EmergencyMultiPassShredder,
    AntiDowngradePolicyEnforcer,
    EmergencyPurgeCeremony,
)
from critical_release import CriticalReleaseAuthority, ReleaseAuthError


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

    def test_critical_release_threshold_key_split_and_combine(self):
        """CriticalReleaseAuthority splits key into dual-sealed shares and reconstructs into NativeSecureBuffer."""
        auth = CriticalReleaseAuthority()
        auth.enroll("alice", "passphrase_alpha_secure_99")
        auth.enroll("bob", "passphrase_bravo_secure_88")

        raw_key = secrets.token_bytes(32)
        enc_s1, n1, enc_s2, n2 = auth.split_release_key(raw_key)

        # Neither share alone equals raw_key
        self.assertNotEqual(enc_s1, raw_key)
        self.assertNotEqual(enc_s2, raw_key)

        # Joint authorization combines into protected NativeSecureBuffer
        buf = auth.combine_release_key(
            enc_s1, n1, enc_s2, n2,
            "alice", "passphrase_alpha_secure_99",
            "bob", "passphrase_bravo_secure_88",
        )
        self.assertTrue(buf.is_protected)
        self.assertEqual(buf.export_bytes(), raw_key)
        buf.wipe()
        self.assertTrue(buf.wiped)

    def test_critical_release_payload_encrypt_decrypt_roundtrip(self):
        """End-to-end critical payload encryption and dual-operator ceremony decryption."""
        auth = CriticalReleaseAuthority()
        auth.enroll("alice", "passphrase_alpha_secure_99")
        auth.enroll("bob", "passphrase_bravo_secure_88")

        payload = b"EXECUTE_STRATEGIC_PAYLOAD_COMMAND_ALPHA_2027"
        bundle = auth.encrypt_critical_payload(payload)

        # Decrypt with both authorized operators
        plaintext = auth.decrypt_critical_payload(
            bundle,
            "alice", "passphrase_alpha_secure_99",
            "bob", "passphrase_bravo_secure_88",
        )
        self.assertEqual(plaintext, payload)

    def test_critical_release_wrong_passphrase_fails_closed(self):
        """Critical payload decryption fails closed on incorrect passphrase or missing operator."""
        auth = CriticalReleaseAuthority()
        auth.enroll("alice", "passphrase_alpha_secure_99")
        auth.enroll("bob", "passphrase_bravo_secure_88")

        payload = b"CRITICAL_PROTECTED_COMMAND"
        bundle = auth.encrypt_critical_payload(payload)

        # Wrong passphrase for bob
        with self.assertRaises(ReleaseAuthError):
            auth.decrypt_critical_payload(
                bundle,
                "alice", "passphrase_alpha_secure_99",
                "bob", "wrong_passphrase",
            )

        # Same operator twice rejected
        with self.assertRaises(ReleaseAuthError):
            auth.decrypt_critical_payload(
                bundle,
                "alice", "passphrase_alpha_secure_99",
                "alice", "passphrase_alpha_secure_99",
            )

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

    # ----------------------------------------------------------------------
    # 6. Advanced Micro-to-Major Primitives Across All Tiers
    # ----------------------------------------------------------------------

    def test_side_channel_constant_time_select(self):
        """Constant-time selection between two byte strings without branching."""
        a = b"FIRST_SECRET_KEY_1234567890ABC"
        b = b"SECOND_SECRET_KEY_1234567890AB"
        # Lengths must match
        res_true = ConstantTimeOperations.constant_time_select(True, a, b)
        self.assertEqual(res_true, a)

        res_false = ConstantTimeOperations.constant_time_select(False, a, b)
        self.assertEqual(res_false, b)

        with self.assertRaises(ValueError):
            ConstantTimeOperations.constant_time_select(True, b"short", b"longer_string")

    def test_side_channel_constant_time_wipe(self):
        """Multi-pass memory zeroization for mutable buffers and NativeSecureBuffers."""
        data = bytearray(b"SENSITIVE_CRYPTOGRAPHIC_MATERIAL")
        ConstantTimeOperations.constant_time_wipe(data)
        self.assertEqual(bytes(data), b"\x00" * len(data))

        buf = NativeSecureBuffer(secrets.token_bytes(32))
        ConstantTimeOperations.constant_time_wipe(buf)
        self.assertTrue(buf.wiped)

    def test_tier_low_telemetry_scrubber(self):
        """LOW Tier: Sanitizes internal addresses, paths, IP addresses, and tokens."""
        raw_trace = (
            "Exception at 0x7ffeefbff560 in D:\\code\\Main_projects\\p2p\\key.pem "
            "from node 192.168.1.105 with token a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        )
        scrubbed = TelemetryScrubber.scrub(raw_trace)
        self.assertNotIn("0x7ffeefbff560", scrubbed)
        self.assertNotIn("D:\\code\\Main_projects", scrubbed)
        self.assertNotIn("192.168.1.105", scrubbed)
        self.assertNotIn("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", scrubbed)
        self.assertIn("[ADDR_MASKED]", scrubbed)
        self.assertIn("[PATH_MASKED]", scrubbed)
        self.assertIn("[IP_MASKED]", scrubbed)
        self.assertIn("[SECRET_MASKED]", scrubbed)

        # Constant-time token verification
        self.assertTrue(TelemetryScrubber.verify_auth_token("ADMIN_TOKEN_999", "ADMIN_TOKEN_999"))
        self.assertFalse(TelemetryScrubber.verify_auth_token("ADMIN_TOKEN_999", "INVALID_TOKEN"))

    def test_tier_basic_deterministic_nonce_generator(self):
        """BASIC Tier: Deterministic 96-bit nonce generation prevents GCM nonce reuse."""
        salt = secrets.token_bytes(4)
        gen = DeterministicNonceGenerator(session_salt=salt)
        self.assertEqual(gen.salt, salt)

        seq0, nonce0 = gen.next_nonce()
        seq1, nonce1 = gen.next_nonce()
        self.assertEqual(seq0, 0)
        self.assertEqual(seq1, 1)
        self.assertEqual(len(nonce0), 12)
        self.assertEqual(len(nonce1), 12)
        self.assertEqual(nonce0[:4], salt)
        self.assertEqual(nonce1[:4], salt)
        self.assertNotEqual(nonce0, nonce1)

    def test_tier_basic_anti_replay_sliding_window(self):
        """BASIC Tier: RFC 6479 decoupled sliding window detects in-order, out-of-order, and replays."""
        window = AntiReplaySlidingWindow(window_size=64)

        # In-order packet
        self.assertTrue(window.check(1))
        window.mark(1)
        self.assertEqual(window.last_seq, 1)

        # Repeated packet rejected (replay attack)
        self.assertFalse(window.check(1))

        # Check-only does not advance or mutate state
        self.assertTrue(window.check(5))
        self.assertEqual(window.last_seq, 1)

        # Out-of-order packet accepted
        self.assertTrue(window.check_and_update(5))
        self.assertEqual(window.last_seq, 5)

        # Packet 2 accepted (within window)
        self.assertTrue(window.check_and_update(2))

        # Duplicate packet 2 rejected
        self.assertFalse(window.check_and_update(2))

        # Packet far behind window rejected
        self.assertTrue(window.check_and_update(100))
        self.assertFalse(window.check_and_update(10))  # 100 - 10 = 90 >= 64
        self.assertGreater(window.drops, 0)

    def test_tier_medium_transcript_bound_kem(self):
        """MEDIUM Tier: NIST SP 800-227 / RFC 10024 Transcript-Bound Hybrid KEM derivation."""
        client_id = "TACTICAL_NODE_ALPHA"
        server_id = "GATEWAY_NODE_BRAVO"
        suite_id = "TLS_AES_256_GCM_SHA384_MLKEM1024"
        c_pk = secrets.token_bytes(1568)
        s_pk = secrets.token_bytes(1568)
        ct = secrets.token_bytes(1568)
        ss1 = secrets.token_bytes(32)
        ss2 = secrets.token_bytes(32)

        # Client and server derive identical key given matching transcripts
        k_client = TranscriptBoundHybridKEM.derive_bound_session_key(
            client_id, server_id, suite_id, c_pk, s_pk, ct, [ss1, ss2]
        )
        k_server = TranscriptBoundHybridKEM.derive_bound_session_key(
            client_id, server_id, suite_id, c_pk, s_pk, ct, [ss1, ss2]
        )
        self.assertEqual(k_client, k_server)
        self.assertEqual(len(k_client), 32)

        # Any transcript modification completely alters the derived key (anti-downgrade)
        k_tampered = TranscriptBoundHybridKEM.derive_bound_session_key(
            client_id, server_id, suite_id, c_pk + b"\x01", s_pk, ct, [ss1, ss2]
        )
        self.assertNotEqual(k_client, k_tampered)

    def test_tier_medium_vas_latching_quarantine(self):
        """MEDIUM Tier: Verify-After-Sign (VAS) with fail-closed latching quarantine."""
        auth = VASLatchingAuthority(key_id="ENCLAVE_KEY_87")
        self.assertFalse(auth.is_quarantined)

        # Normal valid sign-and-verify succeeds
        msg = b"VALID_TACTICAL_COMMAND"
        sig = auth.sign_with_vas(
            sign_fn=lambda m: b"SIG:" + m,
            verify_fn=lambda m, s: s == b"SIG:" + m,
            message=msg,
        )
        self.assertEqual(sig, b"SIG:" + msg)

        # Simulated fault injection (corrupted signature)
        secret_buf = NativeSecureBuffer(secrets.token_bytes(32))
        with self.assertRaises(SecurityTierViolationError) as ctx:
            auth.sign_with_vas(
                sign_fn=lambda m: b"CORRUPTED_SIGNATURE",
                verify_fn=lambda m, s: s == b"SIG:" + m,
                message=msg,
                secret_buffer=secret_buf,
            )
        self.assertIn("FAIL-CLOSED: Verify-After-Sign", str(ctx.exception))
        # Secret buffer was wiped and authority latched into quarantine
        self.assertTrue(secret_buf.wiped)
        self.assertTrue(auth.is_quarantined)

        # Subsequent sign attempts immediately fail closed without executing sign_fn
        with self.assertRaises(SecurityTierViolationError) as ctx2:
            auth.sign_with_vas(
                sign_fn=lambda m: b"ANOTHER_SIG",
                verify_fn=lambda m, s: True,
                message=msg,
            )
        self.assertIn("permanently quarantined", str(ctx2.exception))

    def test_tier_high_daita_frame_shaper(self):
        """HIGH Tier: DAITA frame size quantization to discrete buckets."""
        # 50-byte payload padded to 256 bucket
        p50 = secrets.token_bytes(50)
        shaped50 = DAITAFrameShaper.shape_frame(p50)
        self.assertEqual(len(shaped50), 256)
        self.assertEqual(DAITAFrameShaper.unshape_frame(shaped50), p50)

        # 300-byte payload padded to 512 bucket
        p300 = secrets.token_bytes(300)
        shaped300 = DAITAFrameShaper.shape_frame(p300)
        self.assertEqual(len(shaped300), 512)
        self.assertEqual(DAITAFrameShaper.unshape_frame(shaped300), p300)

        # 800-byte payload padded to 1024 bucket
        p800 = secrets.token_bytes(800)
        shaped800 = DAITAFrameShaper.shape_frame(p800)
        self.assertEqual(len(shaped800), 1024)
        self.assertEqual(DAITAFrameShaper.unshape_frame(shaped800), p800)

        # Malformed frame rejected
        with self.assertRaises(ValueError):
            DAITAFrameShaper.unshape_frame(b"x")

    def test_tier_high_poisson_cover_traffic_scheduler(self):
        """HIGH Tier: Memoryless Poisson interval sampling and synthetic chaff detection."""
        delays = [PoissonCoverTrafficScheduler.sample_delay(interval_sec=0.05) for _ in range(20)]
        for d in delays:
            self.assertGreaterEqual(d, 0.005)
            self.assertLessEqual(d, 1.0)

        chaff = PoissonCoverTrafficScheduler.generate_chaff_frame(bucket_size=256)
        self.assertEqual(len(chaff), 256)
        self.assertTrue(PoissonCoverTrafficScheduler.is_chaff_frame(chaff))

        real_payload = b"\x01\x02\x03\x04" + secrets.token_bytes(252)
        self.assertFalse(PoissonCoverTrafficScheduler.is_chaff_frame(real_payload))

    def test_tier_critical_sp800_208_lms_signature(self):
        """CRITICAL Tier: NIST SP 800-208 / RFC 8554 LMS stateful hash-based signature and verification."""
        lms = SP800_208_LMS(tree_height=2)  # 2^2 = 4 signatures
        pk = lms.public_key_bytes
        self.assertEqual(len(pk), 56)

        msg = b"SOVEREIGN_CRITICAL_COMMAND_AUTHORIZATION"
        sig = lms.sign(msg)
        self.assertTrue(SP800_208_LMS.verify(pk, msg, sig, tree_height=2))

        # Tampered message fails verification
        self.assertFalse(SP800_208_LMS.verify(pk, msg + b"\x00", sig, tree_height=2))

        # Sign until all 4 one-time keys exhausted (1 signed above)
        for i in range(3):
            lms.sign(f"MESSAGE_{i}".encode("utf-8"))

        # 5th signature must fail closed due to key exhaustion
        with self.assertRaises(SecurityTierViolationError) as ctx:
            lms.sign(b"EXHAUSTED_SIGNATURE_ATTEMPT")
        self.assertIn("LMS tree exhausted", str(ctx.exception))

    def test_tier_critical_anti_downgrade_enforcer(self):
        """CRITICAL Tier: AntiDowngradePolicyEnforcer fails closed on downgrade proposals."""
        enforcer = AntiDowngradePolicyEnforcer(minimum_enforced_tier=SecurityTier.CRITICAL)
        self.assertEqual(enforcer.minimum_tier, SecurityTier.CRITICAL)

        # Equal tier permitted
        enforcer.assert_tier_permitted(SecurityTier.CRITICAL)

        # Lower tiers strictly rejected
        for lower in [SecurityTier.HIGH, SecurityTier.MEDIUM, SecurityTier.BASIC, SecurityTier.LOW]:
            with self.assertRaises(SecurityTierViolationError) as ctx:
                enforcer.assert_tier_permitted(lower)
            self.assertIn("Downgrade attack prevented", str(ctx.exception))

    def test_tier_critical_emergency_multipass_shredder(self):
        """CRITICAL Tier: Emergency 4-pass memory overwrite securely wipes secrets."""
        mem = bytearray(secrets.token_bytes(64))
        bytes_shredded = EmergencyMultiPassShredder.shred(mem)
        self.assertEqual(bytes_shredded, 64)
        self.assertEqual(bytes(mem), b"\x00" * 64)

        buf = NativeSecureBuffer(secrets.token_bytes(32))
        buf_shredded = EmergencyMultiPassShredder.shred(buf)
        self.assertEqual(buf_shredded, 32)
        self.assertTrue(buf.wiped)

    def test_tier_low_diagnostic_access_control(self):
        """LOW Tier: DiagnosticAccessControl enforces ring buffer memory bounds and rate limits."""
        ctrl = DiagnosticAccessControl(max_buffer_size=5, max_requests_per_min=10)

        # Record messages
        for i in range(10):
            ctrl.record_telemetry(f"Log {i} pointer 0x7ffeefbff000 from 10.0.0.1")

        # Buffer bounded to 5 items
        items = ctrl.get_recent_telemetry("client_alpha")
        self.assertEqual(len(items), 5)
        for item in items:
            self.assertIn("[ADDR_MASKED]", item)
            self.assertNotIn("0x7ffeefbff000", item)

        # Rate limit exhaustion
        for _ in range(9):
            ctrl.get_recent_telemetry("client_alpha")

        # 11th request exceeds limit
        with self.assertRaises(SecurityTierViolationError) as ctx:
            ctrl.get_recent_telemetry("client_alpha")
        self.assertIn("Rate limit exceeded", str(ctx.exception))

    def test_tier_basic_monotonic_state_persister(self):
        """BASIC Tier: MonotonicStatePersister atomic crash-consistent write and load."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "anti_replay_state.json"
            persister = MonotonicStatePersister(state_file)

            # Initial load non-existent file
            seq, bmap, drops = persister.load_state()
            self.assertEqual((seq, bmap, drops), (0, 0, 0))

            # Persist state
            persister.persist_state(last_seq=42, bitmap=0x0F, drops=2)
            self.assertTrue(state_file.exists())

            # Load state
            s2, b2, d2 = persister.load_state()
            self.assertEqual((s2, b2, d2), (42, 0x0F, 2))

            # Corrupted state file fails closed
            state_file.write_text("CORRUPTED_JSON_DATA", encoding="utf-8")
            with self.assertRaises(SecurityTierViolationError) as ctx:
                persister.load_state()
            self.assertIn("FAIL-CLOSED: Monotonic state corruption", str(ctx.exception))

    def test_tier_medium_triple_ratchet_conversation_and_spqr(self):
        """MEDIUM Tier: October 2025 Signal Triple Ratchet (SPQR) conversation roundtrip."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
        from liboqs_wrapper import LibOQS_MLKEM_1024

        kem = LibOQS_MLKEM_1024()
        alice_kem_pk, alice_kem_sk = kem.keygen()
        bob_kem_pk, bob_kem_sk = kem.keygen()

        alice_dh = x25519.X25519PrivateKey.generate()
        bob_dh = x25519.X25519PrivateKey.generate()
        alice_dh_pub = alice_dh.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        bob_dh_pub = bob_dh.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        shared_rk = secrets.token_bytes(48)

        alice = TripleRatchetEngine(
            local_id="alice",
            remote_id="bob",
            shared_root_key=shared_rk,
            is_initiator=True,
            remote_dh_pub=bob_dh_pub,
            remote_kem_pub=bob_kem_pk,
            local_dh_keypair=alice_dh,
            local_kem_keypair=(alice_kem_pk, alice_kem_sk),
        )

        bob = TripleRatchetEngine(
            local_id="bob",
            remote_id="alice",
            shared_root_key=shared_rk,
            is_initiator=False,
            remote_dh_pub=alice_dh_pub,
            remote_kem_pub=alice_kem_pk,
            local_dh_keypair=bob_dh,
            local_kem_keypair=(bob_kem_pk, bob_kem_sk),
        )

        # Alice -> Bob
        msg1 = alice.encrypt(b"MESSAGE_1_ALICE_TO_BOB")
        plain1 = bob.decrypt(msg1)
        self.assertEqual(plain1, b"MESSAGE_1_ALICE_TO_BOB")

        # Alice -> Bob (second in same chain)
        msg2 = alice.encrypt(b"MESSAGE_2_ALICE_TO_BOB")
        plain2 = bob.decrypt(msg2)
        self.assertEqual(plain2, b"MESSAGE_2_ALICE_TO_BOB")

        # Bob -> Alice (turnaround with SPQR advancement)
        msg3 = bob.encrypt(b"MESSAGE_3_BOB_TO_ALICE_REPLY")
        plain3 = alice.decrypt(msg3)
        self.assertEqual(plain3, b"MESSAGE_3_BOB_TO_ALICE_REPLY")

    def test_tier_medium_triple_ratchet_out_of_order_delivery(self):
        """MEDIUM Tier: Triple Ratchet correctly buffers skipped keys for out-of-order packets."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
        from liboqs_wrapper import LibOQS_MLKEM_1024

        kem = LibOQS_MLKEM_1024()
        alice_kem_pk, alice_kem_sk = kem.keygen()
        bob_kem_pk, bob_kem_sk = kem.keygen()

        alice_dh = x25519.X25519PrivateKey.generate()
        bob_dh = x25519.X25519PrivateKey.generate()
        alice_dh_pub = alice_dh.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        bob_dh_pub = bob_dh.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        shared_rk = secrets.token_bytes(48)

        alice = TripleRatchetEngine(
            local_id="alice",
            remote_id="bob",
            shared_root_key=shared_rk,
            is_initiator=True,
            remote_dh_pub=bob_dh_pub,
            remote_kem_pub=bob_kem_pk,
            local_dh_keypair=alice_dh,
            local_kem_keypair=(alice_kem_pk, alice_kem_sk),
        )

        bob = TripleRatchetEngine(
            local_id="bob",
            remote_id="alice",
            shared_root_key=shared_rk,
            is_initiator=False,
            remote_dh_pub=alice_dh_pub,
            remote_kem_pub=alice_kem_pk,
            local_dh_keypair=bob_dh,
            local_kem_keypair=(bob_kem_pk, bob_kem_sk),
        )

        pkt0 = alice.encrypt(b"PACKET_ZERO")
        pkt1 = alice.encrypt(b"PACKET_ONE")
        pkt2 = alice.encrypt(b"PACKET_TWO")

        # Bob receives pkt2 first (out-of-order)
        plain2 = bob.decrypt(pkt2)
        self.assertEqual(plain2, b"PACKET_TWO")

        # Bob then receives pkt0, then pkt1
        plain0 = bob.decrypt(pkt0)
        self.assertEqual(plain0, b"PACKET_ZERO")

        plain1 = bob.decrypt(pkt1)
        self.assertEqual(plain1, b"PACKET_ONE")

    def test_tier_high_maybenot_traffic_fsm(self):
        """HIGH Tier: Maybenot v2 / DAITA traffic finite state machine bursts and transitions."""
        fsm = MaybenotTrafficFSM(burst_threshold_pkts=3, burst_window_sec=0.1, target_quantum_size=256)
        self.assertEqual(fsm.state, TrafficState.STATE_PASSIVE_MONITORING)

        # Send 1 packet: passive
        s1, a1, _ = fsm.on_packet_sent(100)
        self.assertEqual(s1, TrafficState.STATE_PASSIVE_MONITORING)
        self.assertEqual(a1, TrafficAction.ACTION_NONE)

        # Send 2nd packet: passive
        s2, a2, _ = fsm.on_packet_sent(120)
        self.assertEqual(s2, TrafficState.STATE_PASSIVE_MONITORING)

        # Send 3rd packet: triggers burst mitigation and chaff injection
        s3, a3, meta3 = fsm.on_packet_sent(150)
        self.assertEqual(s3, TrafficState.STATE_BURST_MITIGATION)
        self.assertEqual(a3, TrafficAction.ACTION_INJECT_CHAFF)
        self.assertEqual(meta3["chaff_size"], 256)

        # Idle timer tick triggers scheduled padding
        import time
        time.sleep(0.06)
        s_tick, a_tick, meta_tick = fsm.on_timer_tick(idle_threshold_sec=0.05)
        self.assertEqual(s_tick, TrafficState.STATE_SCHEDULED_PADDING)
        self.assertEqual(a_tick, TrafficAction.ACTION_INJECT_CHAFF)

    def test_tier_critical_emergency_purge_ceremony(self):
        """CRITICAL Tier: Dual-Operator EmergencyPurgeCeremony securely destroys in-RAM and disk keys."""
        import tempfile
        auth = CriticalReleaseAuthority()
        auth.enroll("commander_1", "secure_passphrase_alpha_77")
        auth.enroll("commander_2", "secure_passphrase_bravo_88")

        ceremony = EmergencyPurgeCeremony(authority=auth)
        self.assertFalse(ceremony.is_purged)

        buf1 = NativeSecureBuffer(secrets.token_bytes(32))
        buf2 = bytearray(secrets.token_bytes(64))

        with tempfile.TemporaryDirectory() as tmpdir:
            test_key_file = Path(tmpdir) / ".sealed_kek_test.sealed"
            test_key_file.write_bytes(secrets.token_bytes(48))
            self.assertTrue(test_key_file.exists())

            # Same operator twice rejected (TPI failure)
            with self.assertRaises(SecurityTierViolationError):
                ceremony.execute_purge(
                    "commander_1", "secure_passphrase_alpha_77",
                    "commander_1", "secure_passphrase_alpha_77",
                    sensitive_buffers=[buf1],
                    sealed_key_paths=[test_key_file],
                )

            # Valid dual-operator purge
            receipt = ceremony.execute_purge(
                "commander_1", "secure_passphrase_alpha_77",
                "commander_2", "secure_passphrase_bravo_88",
                sensitive_buffers=[buf1, buf2],
                sealed_key_paths=[test_key_file],
            )

            self.assertTrue(ceremony.is_purged)
            self.assertTrue(buf1.wiped)
            self.assertEqual(bytes(buf2), b"\x00" * 64)
            self.assertFalse(test_key_file.exists())
            self.assertEqual(receipt["status"], "PURGE_COMPLETE_ZEROIZATION_ENFORCED")

            # Second execution fails closed
            with self.assertRaises(SecurityTierViolationError) as ctx:
                ceremony.execute_purge(
                    "commander_1", "secure_passphrase_alpha_77",
                    "commander_2", "secure_passphrase_bravo_88",
                    sensitive_buffers=[],
                )
            self.assertIn("already executed", str(ctx.exception))

    def test_tier_low_shannon_entropy_scrubbing_and_audit_chain(self):
        """LOW Tier: High-entropy secret scrubbing and SHA-384 diagnostic audit chaining."""
        raw_token = secrets.token_hex(32)
        raw_msg = f"Diagnostic state dump secret: {raw_token} complete."
        scrubbed = TelemetryScrubber.scrub(raw_msg)
        self.assertNotIn(raw_token, scrubbed)

        ctrl = DiagnosticAccessControl(max_buffer_size=10, max_requests_per_min=30)
        initial_chain = ctrl.current_audit_chain_hash
        self.assertEqual(len(initial_chain), 96)  # SHA-384 hex length

        ctrl.record_telemetry("Diagnostic event 1")
        chain1 = ctrl.current_audit_chain_hash
        self.assertNotEqual(initial_chain, chain1)

        ctrl.record_telemetry("Diagnostic event 2")
        chain2 = ctrl.current_audit_chain_hash
        self.assertNotEqual(chain1, chain2)

    def test_tier_basic_rekey_boundary_and_hmac_persister(self):
        """BASIC Tier: Rekey threshold guard and HMAC authenticated state persister."""
        salt = secrets.token_bytes(4)
        gen = DeterministicNonceGenerator(session_salt=salt, rekey_threshold=3, strict_rekey=True)
        self.assertFalse(gen.is_rekey_required)

        gen.next_nonce()  # seq 0
        gen.next_nonce()  # seq 1
        gen.next_nonce()  # seq 2
        self.assertTrue(gen.is_rekey_required)

        # Exceeding threshold in strict mode raises error
        with self.assertRaises(SecurityTierViolationError) as ctx:
            gen.next_nonce()
        self.assertIn("re-key threshold reached", str(ctx.exception))

        # HMAC authenticated monotonic persistence
        import tempfile
        import json
        key = secrets.token_bytes(32)
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "authenticated_seq.json"
            persister = MonotonicStatePersister(fpath, integrity_key=key)
            persister.persist_state(last_seq=100, bitmap=0xFF, drops=0)

            seq, bmap, _ = persister.load_state()
            self.assertEqual(seq, 100)

            # Tampered state file is rejected fail-closed
            tampered_data = json.loads(fpath.read_text(encoding="utf-8"))
            tampered_data["last_seq"] = 200
            fpath.write_text(json.dumps(tampered_data), encoding="utf-8")

            with self.assertRaises(SecurityTierViolationError) as ctx2:
                persister.load_state()
            self.assertIn("integrity verification failed", str(ctx2.exception))

    def test_tier_medium_triple_ratchet_destroy_lifecycle(self):
        """MEDIUM Tier: TripleRatchetEngine destroy securely zeroes all keys and rejects subsequent crypto ops."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
        from liboqs_wrapper import LibOQS_MLKEM_1024

        kem = LibOQS_MLKEM_1024()
        alice_kem_pk, alice_kem_sk = kem.keygen()
        bob_kem_pk, bob_kem_sk = kem.keygen()

        alice_dh = x25519.X25519PrivateKey.generate()
        bob_dh = x25519.X25519PrivateKey.generate()
        alice_dh_pub = alice_dh.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        bob_dh_pub = bob_dh.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        alice = TripleRatchetEngine(
            local_id="alice",
            remote_id="bob",
            shared_root_key=secrets.token_bytes(48),
            is_initiator=True,
            remote_dh_pub=bob_dh_pub,
            remote_kem_pub=bob_kem_pk,
            local_dh_keypair=alice_dh,
            local_kem_keypair=(alice_kem_pk, alice_kem_sk),
        )

        msg = alice.encrypt(b"PRE_DESTRUCTION_DATA")
        self.assertIsNotNone(msg)

        wiped_bytes = alice.destroy()
        self.assertGreater(wiped_bytes, 0)
        self.assertTrue(alice.is_destroyed)

        # Subsequent encryption and decryption fail closed
        with self.assertRaises(SecurityTierViolationError) as ctx:
            alice.encrypt(b"POST_DESTRUCTION_DATA")
        self.assertIn("Triple ratchet engine destroyed", str(ctx.exception))

    def test_tier_high_front_defense_and_chaff_stripping(self):
        """HIGH Tier: FRONT defense model bursts and DAITA constant-time chaff stripping."""
        fsm = MaybenotTrafficFSM(
            burst_threshold_pkts=10,
            burst_window_sec=0.1,
            target_quantum_size=256,
            front_window_pkts=3,
            front_chaff_budget=2,
        )

        # First packet: FRONT algorithm triggers chaff
        state1, action1, meta1 = fsm.on_packet_sent(100)
        self.assertEqual(action1, TrafficAction.ACTION_INJECT_CHAFF)
        self.assertEqual(meta1.get("reason"), "FRONT_DEFENSE_INITIAL_FLOW_CAMOUFLAGE")

        # Second packet: FRONT algorithm triggers chaff
        state2, action2, meta2 = fsm.on_packet_sent(100)
        self.assertEqual(action2, TrafficAction.ACTION_INJECT_CHAFF)

        # Third packet: FRONT budget exhausted, returns NONE
        state3, action3, _ = fsm.on_packet_sent(100)
        self.assertEqual(action3, TrafficAction.ACTION_NONE)

        # DAITA frame shaping and chaff stripping
        real_payload = b"CRITICAL_PAYLOAD_ABC"
        shaped = DAITAFrameShaper.shape_frame(real_payload)
        is_chaff, extracted = DAITAFrameShaper.strip_chaff_or_unshape(shaped)
        self.assertFalse(is_chaff)
        self.assertEqual(extracted, real_payload)

        chaff_frame = PoissonCoverTrafficScheduler.generate_chaff_frame(256)
        is_chaff2, extracted2 = DAITAFrameShaper.strip_chaff_or_unshape(chaff_frame)
        self.assertTrue(is_chaff2)
        self.assertEqual(extracted2, b"")

    def test_tier_critical_lms_crash_consistent_state_persistence(self):
        """CRITICAL Tier: SP800_208_LMS monotonic state persistence across restarts."""
        import tempfile
        master_seed = secrets.token_bytes(32)
        with tempfile.TemporaryDirectory() as tmpdir:
            seq_file = Path(tmpdir) / "lms_leaf_state.json"
            persister = MonotonicStatePersister(seq_file)

            lms1 = SP800_208_LMS(tree_height=2, state_persister=persister, seed=master_seed)
            pk = lms1.public_key_bytes

            sig1 = lms1.sign(b"COMMAND_1")
            self.assertTrue(SP800_208_LMS.verify(pk, b"COMMAND_1", sig1, tree_height=2))

            # Simulate restart: create new instance with same persister and seed
            lms2 = SP800_208_LMS(tree_height=2, state_persister=persister, seed=master_seed)
            self.assertEqual(lms2._next_q, 1)  # Resumed at leaf 1, leaf 0 not reused!
            self.assertEqual(lms2.public_key_bytes, pk)

            sig2 = lms2.sign(b"COMMAND_2")
            self.assertTrue(SP800_208_LMS.verify(pk, b"COMMAND_2", sig2, tree_height=2))
            self.assertEqual(lms2._next_q, 2)


if __name__ == "__main__":
    unittest.main()
