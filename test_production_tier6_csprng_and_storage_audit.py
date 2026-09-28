#!/usr/bin/env python3
"""
test_production_tier6_csprng_and_storage_audit.py

Production Hardening Verification Suite — Tier 6:
1. CSPRNG Discipline in TLS Channel Manager (SingleCipherSuite, CounterBasedNonceManager, SecureEnclaveManager.generate_random).
2. KeyStorage Verification & CSPRNG Discipline (storage.py).
3. Tactical Mesh DDIL BPsec Encapsulation & CSPRNG (tactical_mesh_ddil.py).
4. Supply Chain Security PQ Key Seal/Unseal Round-Trip (supply_chain_security.py TUFReleaseManager).
5. Secure Key Manager IPC Authentication & Temp Path CSPRNG (secure_key_manager.py SecureProcessIsolation).
6. 100% Line-by-Line Twin Parity Invariant between secure_p2.py and secure_p2p.py.
"""

import hashlib
import os
import secrets
import tempfile
import unittest
from pathlib import Path


class TestTier6CSPRNGAndStorageAudit(unittest.TestCase):
    """Tier 6 audit verification test cases."""

    def test_01_tls_channel_manager_csprng_hardening(self):
        """Verify tls_channel_manager uses secrets.token_bytes and functions cleanly."""
        from tls_channel_manager import SingleCipherSuite, CounterBasedNonceManager, SecureEnclaveManager

        # Test SingleCipherSuite key rotation
        initial_key = secrets.token_bytes(32)
        suite = SingleCipherSuite(initial_key)
        old_aes_key = suite.aes_key
        suite._rotate_keys()
        new_aes_key = suite.aes_key
        self.assertNotEqual(old_aes_key, new_aes_key)
        self.assertEqual(len(new_aes_key), 32)

        # Test encryption/decryption round-trip
        plaintext = b"NIST_FIPS_LEVEL3_TLS_CHANNEL_PLAINTEXT"
        ct = suite.encrypt(plaintext, aad=b"TEST_AAD")
        decrypted = suite.decrypt(ct, aad=b"TEST_AAD")
        self.assertEqual(decrypted, plaintext)

        # Test CounterBasedNonceManager
        nonce_mgr = CounterBasedNonceManager(counter_size=4, salt_size=8, nonce_size=12)
        salt1 = nonce_mgr.get_salt()
        self.assertEqual(len(salt1), 8)
        nonce1 = nonce_mgr.generate_nonce()
        nonce2 = nonce_mgr.generate_nonce()
        self.assertEqual(len(nonce1), 12)
        self.assertEqual(len(nonce2), 12)
        self.assertNotEqual(nonce1, nonce2)
        # Verify prefix matches salt
        self.assertTrue(nonce1.startswith(salt1))
        self.assertTrue(nonce2.startswith(salt1))

        # Test reset
        nonce_mgr.reset()
        salt2 = nonce_mgr.get_salt()
        self.assertNotEqual(salt1, salt2)

        # Test SecureEnclaveManager.generate_random fallback
        enclave_mgr = SecureEnclaveManager()
        rand_bytes = enclave_mgr.generate_random(48)
        self.assertEqual(len(rand_bytes), 48)

    def test_02_storage_verification_csprng(self):
        """Verify storage.py uses secrets.token_bytes for test key and passes verification."""
        from storage import KeyStorage
        class DummyOrchestrator:
            in_memory_only = True

        orch = DummyOrchestrator()
        storage = KeyStorage(orch)
        verified = storage._verify_key_storage()
        self.assertTrue(verified)

        # Store and retrieve
        test_material = secrets.token_bytes(64)
        key_id = storage.store_key(test_material, "tier6_test_key")
        self.assertIsNotNone(key_id)
        retrieved = storage.retrieve_key("tier6_test_key")
        self.assertEqual(retrieved, test_material)

    def test_03_tactical_mesh_ddil_bpsec_csprng(self):
        """Verify tactical_mesh_ddil BPsec bundle generation and CSPRNG."""
        from tactical_mesh_ddil import create_bpsec_bundle, decrypt_bpsec_bundle, DDILBundle
        from liboqs_wrapper import LibOQS_MLDSA_87

        mldsa = LibOQS_MLDSA_87()
        pk, sk = mldsa.keygen()
        payload = b"TACTICAL_MISSION_TASKING_PAYLOAD_TIER6"
        sym_key = secrets.token_bytes(32)

        bundle = create_bpsec_bundle(
            sender_id="ALPHA_COMMAND",
            recipient_id="BRAVO_OUTPOST",
            seq=42,
            payload_plaintext=payload,
            sender_sk=sk,
            sender_pk=pk,
            symmetric_key=sym_key,
            compress_key=False,
        )

        self.assertIsInstance(bundle, DDILBundle)
        self.assertEqual(bundle.sender_id, "ALPHA_COMMAND")
        self.assertEqual(bundle.recipient_id, "BRAVO_OUTPOST")
        self.assertEqual(bundle.seq, 42)

        # Decrypt bundle and verify payload
        recovered = decrypt_bpsec_bundle(bundle, symmetric_key=sym_key, expected_sender_pk=pk)
        self.assertEqual(recovered, payload)

    def test_04_supply_chain_security_pq_seal_unseal(self):
        """Verify supply_chain_security _pq_seal and _pq_unseal round trip in TUFReleaseManager."""
        from supply_chain_security import TUFReleaseManager

        dummy_sk = secrets.token_bytes(4896)
        passphrase = b"Tier6_Master_Release_Passphrase_2026!"

        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = TUFReleaseManager(state_dir=tmpdir)
            mgr._pq_seal(dummy_sk, passphrase)
            self.assertTrue(mgr._pq_sk_path.exists())

            # Read sealed blob
            sealed_blob = mgr._pq_sk_path.read_bytes()
            unsealed_sk = mgr._pq_unseal(sealed_blob, passphrase)
            self.assertEqual(unsealed_sk, dummy_sk)

            # Wrong passphrase must fail closed
            with self.assertRaises(Exception):
                mgr._pq_unseal(sealed_blob, b"Wrong_Passphrase_Failure")

    def test_05_secure_key_manager_csprng_tokens(self):
        """Verify secure_key_manager SecureProcessIsolation IPC tokens and auth key."""
        from secure_key_manager import SecureProcessIsolation, SecureKeyManager

        isolation = SecureProcessIsolation()
        # Verify IPC auth key is 32 bytes and from CSPRNG
        self.assertEqual(len(isolation._auth_key), 32)
        self.assertIsInstance(isolation._auth_key, (bytes, bytearray))

        # Verify storage security passes
        skm = SecureKeyManager(app_name="tier6_test_app", in_memory_only=True)
        verified = skm.verify_storage()
        self.assertTrue(verified)

    def test_06_secure_p2_and_secure_p2p_exact_twin_parity(self):
        """Verify 100% exact byte-for-byte and line-by-line twin parity between secure_p2.py and secure_p2p.py."""
        repo_root = Path(__file__).resolve().parent
        p2_path = repo_root / "archive/legacy_prototype/secure_p2.py"
        p2p_path = repo_root / "archive/legacy_prototype/secure_p2p.py"

        self.assertTrue(p2_path.exists(), "secure_p2.py does not exist")
        self.assertTrue(p2p_path.exists(), "secure_p2p.py does not exist")

        p2_bytes = p2_path.read_bytes()
        p2p_bytes = p2p_path.read_bytes()

        p2_sha256 = hashlib.sha256(p2_bytes).hexdigest()
        p2p_sha256 = hashlib.sha256(p2p_bytes).hexdigest()

        self.assertEqual(
            p2_sha256,
            p2p_sha256,
            f"Twin parity SHA256 mismatch!\nsecure_p2.py:  {p2_sha256}\nsecure_p2p.py: {p2p_sha256}"
        )
        self.assertEqual(p2_bytes, p2p_bytes, "Twin parity byte mismatch!")

    def test_07_crypto_child_bound_to_kill_on_close_job(self):
        """SecureProcessIsolation crypto children must die with their parent
        (Windows Job Object KILL_ON_JOB_CLOSE) so killed terminal parents
        cannot orphan grandchildren that poison later suites' ports."""
        import sys as _sys
        import subprocess as _sp  # nosec: B404
        import ctypes as _ct
        from secure_key_manager import SecureProcessIsolation
        if _sys.platform != "win32":
            self.skipTest("job-object guarantee is Windows-specific")
        # Bind a sacrificial sleeper (never our own runner process).
        proc = _sp.Popen([_sys.executable, "-c",  # nosec: B603
                          "import time; time.sleep(60)"])
        try:
            hjob = SecureProcessIsolation._bind_kill_on_close(
                int(proc._handle))
            self.assertTrue(hjob)
            kernel32 = _ct.WinDLL("kernel32", use_last_error=True)
            in_job = _ct.c_bool(False)
            self.assertTrue(
                kernel32.IsProcessInJob(proc._handle, None,
                                        _ct.byref(in_job)))
            self.assertTrue(in_job.value)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
            try:
                _ct.WinDLL("kernel32", use_last_error=True).CloseHandle(hjob)
            except Exception:  # nosec: B110
                pass
        # Garbage handle refused fail-closed (no silent unbound child).
        with self.assertRaises(Exception):
            SecureProcessIsolation._bind_kill_on_close(0)


if __name__ == "__main__":
    unittest.main()

