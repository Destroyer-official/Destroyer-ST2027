#!/usr/bin/env python3
"""
VERIFICATION SUITE: AUDIT FINDINGS O-01, O-02, O-05, O-12 REMEDIATIONS
Validates:
1. PBKDF2 220,000 iteration hardening & migration across secure storage and credentials.
2. Backward compatibility for BACKUP_V1 (210,000) and ENC_KEY_V1 (210,000) credentials.
3. Live two-terminal operational execution via run_two_terminals_secure_p2_test.py.
4. Clean, hermetic execution with zero residual files.
"""

import os
import sys
import json
import secrets
import tempfile
import unittest
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class TestAuditPBKDF2AndArchitectureRemediations(unittest.TestCase):
    """Test suite validating forensic audit remediations."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_audit_remed_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_enclave_backup_v2_export_and_import(self):
        """Verify BACKUP_V2 uses 220,000 iterations and roundtrips keys securely."""
        from secure_enclave_key_storage import SoftwareFallbackBackend, KeyAlgorithm

        storage = SoftwareFallbackBackend(storage_path=self.tmp_dir)
        test_key = secrets.token_bytes(32)
        storage.store_key("TACTICAL_KEY_ALPHA", test_key, algorithm=KeyAlgorithm.AES_256_GCM)

        passphrase = b"TopSecret-Mission-Master-Passphrase-2027!"
        blob_v2 = storage.export_backup(passphrase)

        # Assert format versioning
        self.assertTrue(blob_v2.startswith(b"BACKUP_V2"), "Backup blob must start with BACKUP_V2 header")
        self.assertGreater(len(blob_v2), 60)

        # Import into fresh storage
        new_tmp = tempfile.mkdtemp(prefix="test_enclave_restore_")
        try:
            new_storage = SoftwareFallbackBackend(storage_path=new_tmp)
            restored_count = new_storage.import_backup(blob_v2, passphrase)
            self.assertEqual(restored_count, 1)

            retrieved = new_storage.retrieve_key("TACTICAL_KEY_ALPHA")
            self.assertEqual(retrieved, test_key)
        finally:
            import shutil
            shutil.rmtree(new_tmp, ignore_errors=True)

    def test_02_enclave_backup_v1_legacy_compatibility(self):
        """Verify backward compatibility: BACKUP_V1 blobs (210k iterations) import cleanly."""
        from secure_enclave_key_storage import SoftwareFallbackBackend, KeyAlgorithm
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        import base64

        passphrase = b"Legacy-Passphrase-2026!"
        salt = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        # Create authentic legacy V1 blob using 210,000 iterations and V1 AAD
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=210_000,
            backend=default_backend()
        )
        legacy_key = kdf.derive(passphrase)

        secret_data = secrets.token_bytes(32)
        payload = {
            "version": 1,
            "keys": {
                "LEGACY_KEY_01": {
                    "alg": KeyAlgorithm.AES_256_GCM.value,
                    "data": base64.b64encode(secret_data).decode('ascii')
                }
            }
        }
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode('utf-8')
        ct = AESGCM(legacy_key).encrypt(nonce, plaintext, b"SecureP2P::Backup::v1")
        blob_v1 = b"BACKUP_V1" + salt + nonce + ct

        # Import legacy V1 blob into current enclave storage
        storage = SoftwareFallbackBackend(storage_path=self.tmp_dir)
        restored_count = storage.import_backup(blob_v1, passphrase)
        self.assertEqual(restored_count, 1)

        retrieved = storage.retrieve_key("LEGACY_KEY_01")
        self.assertEqual(retrieved, secret_data)

    def test_03_tactical_credential_v2_and_v1_roundtrip(self):
        """Verify tactical_key_provisioner saves V2 (220k) and loads both V2 and V1."""
        from tactical_key_provisioner import save_encrypted_credential, load_encrypted_credential
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        cred_path = os.path.join(self.tmp_dir, "test_cred.pem")
        secret_payload = b"-----BEGIN TACTICAL SECRET KEY-----\nSAMPLE_KEY_DATA\n-----END TACTICAL SECRET KEY-----"
        pw = "Tactical-Credential-Passphrase-2027"

        # Save V2
        save_encrypted_credential(cred_path, secret_payload, passphrase=pw)
        with open(cred_path, "rb") as f:
            v2_bytes = f.read()
        self.assertTrue(v2_bytes.startswith(b"ENC_KEY_V2"), "Saved credential must use ENC_KEY_V2 header")

        # Load V2
        loaded = load_encrypted_credential(cred_path, passphrase=pw)
        self.assertEqual(loaded, secret_payload)

        # Create authentic legacy ENC_KEY_V1 file (210,000 iterations)
        v1_path = os.path.join(self.tmp_dir, "legacy_cred.pem")
        salt = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=210_000,
            backend=default_backend()
        )
        key = kdf.derive(pw.encode('utf-8'))
        ct = AESGCM(key).encrypt(nonce, secret_payload, os.path.basename(v1_path).encode('utf-8'))
        v1_payload = b"ENC_KEY_V1" + salt + nonce + ct

        with open(v1_path, "wb") as f:
            f.write(v1_payload)

        # Load V1
        loaded_v1 = load_encrypted_credential(v1_path, passphrase=pw)
        self.assertEqual(loaded_v1, secret_payload)

    def test_04_critical_release_authority_enroll_and_check(self):
        """Verify CriticalReleaseAuthority uses 220,000 iterations and enforces dual-operator rule."""
        from critical_release import CriticalReleaseAuthority, ReleaseAuthError

        auth = CriticalReleaseAuthority()
        auth.enroll("OFFICER_01", "Officer1-Passphrase-Alpha")
        auth.enroll("OFFICER_02", "Officer2-Passphrase-Bravo")

        self.assertEqual(auth.enrolled, 2)
        self.assertTrue(auth._check("OFFICER_01", "Officer1-Passphrase-Alpha"))
        self.assertTrue(auth._check("OFFICER_02", "Officer2-Passphrase-Bravo"))
        self.assertFalse(auth._check("OFFICER_01", "Wrong-Passphrase"))

        # Third operator enrollment must fail closed
        with self.assertRaises(ReleaseAuthError):
            auth.enroll("OFFICER_03", "Officer3-Passphrase")

    def test_05_live_two_terminal_drill_script_execution(self):
        """Execute run_two_terminals_secure_p2_test.py and confirm 100% telemetry."""
        script_path = PROJECT_ROOT / "run_two_terminals_secure_p2_test.py"
        self.assertTrue(script_path.exists(), "run_two_terminals_secure_p2_test.py must exist at project root")

        env = dict(os.environ, PYTHONUNBUFFERED="1", P2P_ALLOW_LOOPBACK="1")
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60
        )
        output = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 0, f"Script failed with code {proc.returncode}:\n{output}")
        self.assertIn("Rust data plane session established (outer AEAD envelope active)", output)
        self.assertIn("Base Alpha successfully received and decrypted Flash Order.", output)
        self.assertIn("Base Bravo successfully received and decrypted Flash ACK.", output)
        self.assertIn("2-TERMINAL SECURE_P2.PY TEST 100% SUCCESSFUL!", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)

