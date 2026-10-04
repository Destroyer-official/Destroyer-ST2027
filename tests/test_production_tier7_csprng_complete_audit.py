#!/usr/bin/env python3
"""
Test Suite: Production Tier 7 CSPRNG Complete Hardening & Parity Audit
Validates complete migration from os.urandom to secrets.token_bytes across:
1. LibOQS Wrapper (AES-GCM key/nonce generation)
2. PlatformHSMInterface fallback software entropy generation & diagnostic tracking
3. QuantumRNG system entropy replenishment and pooling
4. NC3 Nuclear Command uniform 1024-byte block padding & AEAD wire nonce
5. CJADC2 Cross-Domain Guard compartment encryption & secret isolation
6. EmergencyAntiTamper DoD 5220.22-M Pass 3 memory overwriting
7. secure_p2p_core / utils / helpers parity (CSPRNG, hmac.compare_digest, bounded FIFO)
8. User profile management (data/user_mgmt.py & secure_p2p_core/data/user_mgmt.py)
9. Key storage verification test keys (keys/storage.py & secure_p2p_core/keys/storage.py)
10. CA services (ca_services.py) XChaCha20Poly1305 storage, ephemeral keys, and secure wipe rotation
11. Twin file parity verification (secure_p2p.py == secure_p2.py)
"""

import inspect
import os
import secrets
import sys
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class TestProductionTier7CSPRNGCompleteAudit(unittest.TestCase):
    """Tier 7 CSPRNG and Entropy Hardening Verification."""

    def test_01_liboqs_wrapper_csprng(self):
        """Verify LibOQS_AES256GCM key and nonce generation use secrets without os.urandom."""
        import liboqs_wrapper as low
        src = inspect.getsource(low.LibOQS_AES256GCM)
        self.assertNotIn("os.urandom", src, "LibOQS_AES256GCM must not contain os.urandom")
        self.assertIn("secrets.token_bytes", src, "LibOQS_AES256GCM must use secrets.token_bytes")

        aes = low.LibOQS_AES256GCM()
        key = aes.generate_key()
        nonce = aes.generate_nonce()
        self.assertEqual(len(key), 32)
        self.assertEqual(len(nonce), 12)

    def test_02_platform_hsm_software_entropy(self):
        """Verify PlatformHSMInterface fallback entropy uses secrets.token_bytes and labels correctly."""
        import platform_hsm_interface as phi
        func_src = inspect.getsource(phi.enhanced_secure_random)
        self.assertNotIn("os.urandom", func_src, "enhanced_secure_random must not use os.urandom")
        self.assertIn("secrets.token_bytes", func_src, "enhanced_secure_random must use secrets.token_bytes")

        # Deterministically test software fallback entropy path
        with unittest.mock.patch.object(phi, 'enhanced_tpm_detection', return_value={"tpm_available": False}):
            res = phi.enhanced_secure_random(32)
            self.assertIn("random_bytes", res)
            self.assertIn("sources_used", res)
            self.assertTrue(any("secrets" in s.lower() for s in res["sources_used"]), f"Expected secrets source in {res['sources_used']}")
            self.assertEqual(len(res["random_bytes"]), 32)

    def test_03_quantum_rng_entropy_replenish(self):
        """Verify QuantumRNG uses secrets.token_bytes for pool replenishment."""
        import quantum_rng
        src = inspect.getsource(quantum_rng.EntropyPool)
        self.assertNotIn("os.urandom", src, "EntropyPool must not call os.urandom")
        self.assertIn("secrets.token_bytes", src, "EntropyPool must call secrets.token_bytes")

        pool = quantum_rng.EntropyPool()
        initial_entropy = pool.get_estimated_entropy()
        self.assertGreaterEqual(initial_entropy, 0.0)

    def test_04_nc3_wire_padding_and_nonce(self):
        """Verify NC3 wire payload padding and AEAD nonce derive from secrets."""
        import nc3_nuclear_command as nc3
        src = inspect.getsource(nc3.serialize_eam_wire)
        self.assertNotIn("os.urandom", src, "serialize_eam_wire must not use os.urandom")
        self.assertIn("secrets.token_bytes", src, "serialize_eam_wire must use secrets.token_bytes")

        test_payload = {"command": "EXECUTE_STRAT_SIOP_OMEGA", "timestamp": 1718000000}
        key = secrets.token_bytes(32)
        wire_data = nc3.serialize_eam_wire(test_payload, aead_key=key)
        # 12-byte nonce + 1024-byte padded ciphertext + 16-byte tag = 1052 bytes
        self.assertEqual(len(wire_data), 12 + 1024 + 16)

    def test_05_cjadc2_guard_compartment(self):
        """Verify CJADC2 CrossDomainGuard uses secrets for compartment payloads."""
        import cjadc2_cross_domain_guard as cdg
        src = inspect.getsource(cdg.CrossDomainGuard.encrypt_compartment_payload)
        self.assertNotIn("os.urandom", src, "encrypt_compartment_payload must not use os.urandom")
        self.assertIn("secrets.token_bytes", src, "encrypt_compartment_payload must use secrets.token_bytes")

        guard = cdg.CrossDomainGuard()
        master_secret = secrets.token_bytes(64)
        plaintext = b"STRIKE_COORDINATES_32N_44E"
        envelope = guard.encrypt_compartment_payload(
            master_secret=master_secret,
            classification=cdg.SecurityClassification.TOP_SECRET,
            caveat="NOFORN",
            plaintext_bytes=plaintext
        )
        self.assertIn("ciphertext_hex", envelope)
        self.assertIn("nonce_hex", envelope)
        self.assertEqual(len(bytes.fromhex(envelope["nonce_hex"])), 12)

    def test_06_emergency_anti_tamper_wiping(self):
        """Verify EmergencyZeroizationEngine DoD 5220.22-M Pass 3 memory scrubbing uses secrets."""
        import emergency_anti_tamper as eat
        src = inspect.getsource(eat.EmergencyZeroizationEngine.shred_bytes)
        self.assertNotIn("os.urandom", src, "shred_bytes must not call os.urandom")
        self.assertIn("secrets.token_bytes", src, "shred_bytes must call secrets.token_bytes")

        buf = bytearray(b"SENSITIVE_KEY_MATERIAL_FOR_PURGE_00000000")
        method = eat.EmergencyZeroizationEngine.shred_bytes(buf)
        self.assertIn(method, ["ctypes-memset", "python-loop", "zeroized"])
        self.assertEqual(bytes(buf), b"\x00" * len(buf))

    def test_07_secure_p2p_core_helpers_hardening(self):
        """Verify secure_p2p_core/utils/helpers.py matches root utils/helpers.py invariants."""
        import secure_p2p_core.utils.helpers as core_helpers
        import utils.helpers as root_helpers

        # Nonce generation
        n1 = core_helpers.generate_nonce(16)
        n2 = root_helpers.generate_nonce(16)
        self.assertEqual(len(n1), 16)
        self.assertEqual(len(n2), 16)

        # Constant time compare
        self.assertTrue(core_helpers.constant_time_compare(b"secret_key_1234", b"secret_key_1234"))
        self.assertFalse(core_helpers.constant_time_compare(b"secret_key_1234", b"secret_key_5678"))
        self.assertFalse(core_helpers.constant_time_compare(b"secret", b"secret_long"))
        self.assertFalse(core_helpers.constant_time_compare("not_bytes", b"secret"))

        # NonceManager bounded FIFO eviction
        nm = core_helpers.NonceManager(nonce_size=12, max_nonce_uses=10, max_history=5)
        nonces = [nm.generate_nonce() for _ in range(8)]
        self.assertEqual(len(nonces), 8)
        self.assertLessEqual(len(nm.used_nonces), 5)
        self.assertLessEqual(len(nm._nonce_fifo), 5)

    def test_08_user_mgmt_and_storage_parity(self):
        """Verify user_mgmt and keys/storage across root and secure_p2p_core use secrets."""
        import data.user_mgmt as root_um
        import secure_p2p_core.data.user_mgmt as core_um
        import keys.storage as root_ks
        import secure_p2p_core.keys.storage as core_ks

        # Check source for no os.urandom
        for mod, name in [(root_um, "root user_mgmt"), (core_um, "core user_mgmt")]:
            src = inspect.getsource(mod)
            self.assertNotIn("os.urandom", src, f"{name} must not contain os.urandom")
            self.assertIn("secrets.token_bytes", src, f"{name} must contain secrets.token_bytes")

        for mod, name in [(root_ks, "root keys/storage"), (core_ks, "core keys/storage")]:
            src = inspect.getsource(mod)
            self.assertNotIn("os.urandom", src, f"{name} must not contain os.urandom")
            self.assertIn("secrets.token_bytes", src, f"{name} must contain secrets.token_bytes")

    def test_09_ca_services_csprng(self):
        """Verify ca_services.py uses secrets for storage, ephemeral key agreement, and wipe."""
        import ca_services
        src = inspect.getsource(ca_services)
        self.assertNotIn("os.urandom", src, "ca_services must not contain os.urandom")
        self.assertIn("secrets.token_bytes", src, "ca_services must use secrets.token_bytes")

    def test_10_memory_and_dep_impl_csprng(self):
        """Verify memory_manager.py and dep_impl.py use secrets for barriers and region IDs."""
        import memory_manager
        import dep_impl

        src_mm = inspect.getsource(memory_manager)
        self.assertNotIn("os.urandom", src_mm, "memory_manager must not contain os.urandom")
        self.assertIn("secrets.token_bytes", src_mm, "memory_manager must use secrets.token_bytes")

        src_dep = inspect.getsource(dep_impl)
        self.assertNotIn("os.urandom", src_dep, "dep_impl must not contain os.urandom")
        self.assertIn("secrets.token_hex", src_dep, "dep_impl must use secrets.token_hex")

    def test_11_twin_parity_sha256_invariant(self):
        """Verify 100% exact byte-for-byte SHA256 parity between secure_p2p.py and secure_p2.py."""
        import hashlib
        p2p_path = REPO_ROOT / "archive/legacy_prototype/secure_p2p.py"
        p2_path = REPO_ROOT / "archive/legacy_prototype/secure_p2.py"

        with open(p2p_path, "rb") as f:
            h_p2p = hashlib.sha256(f.read()).hexdigest()
        with open(p2_path, "rb") as f:
            h_p2 = hashlib.sha256(f.read()).hexdigest()

        self.assertEqual(h_p2p, h_p2, "secure_p2p.py and secure_p2.py MUST have identical SHA256 hashes")


if __name__ == "__main__":
    unittest.main()
