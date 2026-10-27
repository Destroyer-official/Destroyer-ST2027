#!/usr/bin/env python3
"""
Test Suite: Multi-Device Registry Thread Safety, Memory Deallocation, & Hardening Audit

Verifies:
1. MultiDeviceManager thread-safety under concurrent multi-threaded enrollments and revocations.
2. MultiDeviceManager strict enforcement of the 5-device limit under concurrent race conditions.
3. MultiDeviceManager atomic persistence using temporary file replacement (zero corruption).
4. SecureMemoryManager deallocation unlocks locked memory via VirtualUnlock/munlock, preventing quota leaks.
5. SecurityHardening emergency wipe cascades to orchestrator sessions and cryptographic state.
6. MultiDeviceManager CRL gossip import/export thread-safety.
"""

import os
import sys
import json
import base64
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from multi_device_manager import (
    MultiDeviceManager,
    DeviceInfo,
    DeviceStatus,
    DeviceEnrollmentError,
    DeviceLimitExceededError,
)
from memory_manager import (
    SecureMemoryManager,
    SecurityLevel,
)
import security.hardening as sh


class TestMultiDeviceThreadSafety(unittest.TestCase):
    """Verify thread-safety and concurrency controls in MultiDeviceManager."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.manager = MultiDeviceManager(
            storage_path=self.temp_dir.name,
            in_memory_only=True
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_concurrent_device_enrollment_limit_enforcement(self):
        """Under concurrent enrollment attempts, max 5 devices limit must be strictly enforced."""
        user_id = "user_concurrent_test_1"
        # Enroll root device first
        root_dev, root_sk = self.manager.enroll_root_device(
            user_identity_id=user_id,
            device_name="RootStation"
        )
        self.assertIsNotNone(root_dev)
        self.assertEqual(self.manager.get_active_device_count(user_id), 1)

        # Attempt to enroll 10 devices simultaneously from 10 threads (limit is 5)
        successes = []
        failures = []
        threads = []

        def _worker(thread_idx):
            try:
                dev, sk = self.manager.enroll_device(
                    user_identity_id=user_id,
                    device_name=f"SubDevice_{thread_idx}",
                    device_type="mobile",
                    authorizing_device_id=root_dev.device_id,
                    authorizing_private_key=root_sk
                )
                successes.append(dev.device_id)
            except DeviceLimitExceededError:
                failures.append("limit_exceeded")
            except Exception as e:
                failures.append(f"unexpected_err: {e}")

        for i in range(10):
            t = threading.Thread(target=_worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Root + enrolled active devices must be exactly 5 (4 children + 1 root)
        active_count = self.manager.get_active_device_count(user_id)
        self.assertEqual(active_count, 5, f"Expected exactly 5 devices, got {active_count}")
        self.assertEqual(len(successes), 4, f"Expected exactly 4 successful child enrollments, got {len(successes)}")
        self.assertEqual(len(failures), 6, f"Expected 6 threads to fail with limit exceeded, got {len(failures)}")
        for f in failures:
            self.assertEqual(f, "limit_exceeded")

    def test_concurrent_revocation_and_cascade(self):
        """Revoking devices concurrently must safely update revocation lists without race conditions."""
        user_id = "user_revocation_cascade_test"
        root_dev, root_sk = self.manager.enroll_root_device(
            user_identity_id=user_id,
            device_name="RootHub"
        )

        # Enroll child device A
        child_a, child_a_sk = self.manager.enroll_device(
            user_identity_id=user_id,
            device_name="ChildA",
            device_type="desktop",
            authorizing_device_id=root_dev.device_id,
            authorizing_private_key=root_sk
        )

        # Enroll child device B
        child_b, child_b_sk = self.manager.enroll_device(
            user_identity_id=user_id,
            device_name="ChildB",
            device_type="mobile",
            authorizing_device_id=root_dev.device_id,
            authorizing_private_key=root_sk
        )

        self.assertEqual(self.manager.get_active_device_count(user_id), 3)

        # Run concurrent revocations from separate threads
        threads = []
        errors = []

        def _revoker(dev_id, reason):
            try:
                self.manager.revoke_device(user_id, dev_id, reason=reason)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=_revoker, args=(child_a.device_id, "Compromise child A"))
        t2 = threading.Thread(target=_revoker, args=(child_b.device_id, "Compromise child B"))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(errors), 0, f"Unexpected errors during concurrent revocation: {errors}")
        self.assertTrue(self.manager.is_device_revoked(user_id, child_a.device_id))
        self.assertTrue(self.manager.is_device_revoked(user_id, child_b.device_id))
        self.assertEqual(self.manager.get_active_device_count(user_id), 1)  # Only root remains


class TestMultiDeviceAtomicPersistence(unittest.TestCase):
    """Verify atomic persistence of devices.json to prevent corruption."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_atomic_persistence_sealed_envelope(self):
        """Registry saved under P2P_STORAGE_PASSPHRASE must write atomically and reload intact."""
        passphrase = "TacticalUnit789Passphrase!Secure"  # nosec: B105
        with patch.dict(os.environ, {"P2P_STORAGE_PASSPHRASE": passphrase}):
            mgr = MultiDeviceManager(storage_path=str(self.storage_path), in_memory_only=False)
            user_id = "user_sealed_persist"
            root_dev, root_sk = mgr.enroll_root_device(
                user_identity_id=user_id,
                device_name="PrimaryStation"
            )
            child_dev, child_sk = mgr.enroll_device(
                user_identity_id=user_id,
                device_name="TacticalTablet",
                device_type="tablet",
                authorizing_device_id=root_dev.device_id,
                authorizing_private_key=root_sk
            )

            # Persist
            mgr.save_to_file()
            devices_file = self.storage_path / "devices.json"
            self.assertTrue(devices_file.exists())
            raw_bytes = devices_file.read_bytes()
            self.assertTrue(raw_bytes.startswith(b"DEVENC_V1:"), "File must be sealed with DEVENC_V1 envelope")

            # Check that no temporary files were left behind
            tmp_files = list(self.storage_path.glob("devices.json.tmp.*"))
            self.assertEqual(len(tmp_files), 0, "No temporary files must linger after atomic save")

            # Reload into a fresh manager
            mgr2 = MultiDeviceManager(storage_path=str(self.storage_path), in_memory_only=False)
            mgr2.load_from_file()
            self.assertEqual(mgr2.get_active_device_count(user_id), 2)
            loaded_root = mgr2.get_device(user_id, root_dev.device_id)
            self.assertIsNotNone(loaded_root)
            self.assertEqual(loaded_root.device_name, "PrimaryStation")

    def test_atomic_persistence_unsealed_lab_mode(self):
        """Registry saved without passphrase in non-production mode must write atomically and be valid JSON."""
        with patch.dict(os.environ, {"P2P_STORAGE_PASSPHRASE": "", "P2P_PRODUCTION": "0", "SECURE_P2P_PRODUCTION": "0"}):  # nosec: B105
            mgr = MultiDeviceManager(storage_path=str(self.storage_path), in_memory_only=False)
            user_id = "user_unsealed_lab"
            root_dev, root_sk = mgr.enroll_root_device(
                user_identity_id=user_id,
                device_name="LabNode"
            )

            mgr.save_to_file()
            devices_file = self.storage_path / "devices.json"
            self.assertTrue(devices_file.exists())

            # Verify valid JSON
            with open(devices_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("user_devices", data)
            self.assertIn(user_id, data["user_devices"])

            # Reload
            mgr2 = MultiDeviceManager(storage_path=str(self.storage_path), in_memory_only=False)
            mgr2.load_from_file()
            self.assertEqual(mgr2.get_active_device_count(user_id), 1)


class TestSecureMemoryDeallocation(unittest.TestCase):
    """Verify that memory deallocation unlocks locked memory pages without quota leaks."""

    def test_deallocate_unlocks_locked_buffer(self):
        """deallocate_secure_buffer must invoke OS unlock when buffer was locked."""
        mgr = SecureMemoryManager()
        is_win = sys.platform.startswith("win")
        unlock_attr = "_virtual_unlock" if is_win else "_munlock"

        # Mock the unlock function to verify it gets called with correct parameters
        mock_unlock = MagicMock(return_value=True if is_win else 0)
        setattr(mgr, unlock_attr, mock_unlock)

        # Allocate buffer and mock it as locked
        buf = mgr.allocate_secure_buffer(1024, security_level=SecurityLevel.CRYPTOGRAPHIC_MATERIAL, use_guard_pages=True)
        buf_id = id(buf)
        self.assertIn(buf_id, mgr._buffers)
        mgr._buffers[buf_id].locked = True  # Mark as locked

        # Deallocate buffer
        mgr.deallocate_secure_buffer(buf)

        # Buffer must be removed from manager tracking
        self.assertNotIn(buf_id, mgr._buffers)

        # OS unlock must have been called exactly once
        mock_unlock.assert_called_once()
        args, _ = mock_unlock.call_args
        unlock_size = args[1].value if hasattr(args[1], "value") else int(args[1])
        self.assertGreater(unlock_size, 1024, "Unlock size must include page alignment and guard pages")


class TestHardeningEmergencyWipeCascading(unittest.TestCase):
    """Verify that SecurityHardening._emergency_wipe cascades to orchestrators."""

    def test_emergency_wipe_cascades_to_orchestrator(self):
        """When emergency wipe occurs, orchestrator's cleanup or emergency_wipe must be triggered."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.cleanup = MagicMock()

        hardening = sh.SecurityHardening(orchestrator=mock_orchestrator)
        self.assertIsNotNone(hardening.orchestrator)

        # Trigger emergency wipe
        hardening._emergency_wipe()

        # Verify orchestrator was cleaned up and reference cleared
        mock_orchestrator.cleanup.assert_called_once()
        self.assertIsNone(hardening.orchestrator)
        self.assertEqual(len(hardening.security_hardening), 0)


class TestCRLGossipThreadSafety(unittest.TestCase):
    """CRL gossip import/export thread-safety (fulfills this suite's item 6).

    N threads concurrently import versioned bundles for one issuer: no
    exceptions, no deadlock, no lost updates (sum of per-import added
    counts equals final set size), shared serial always present,
    per-issuer version monotonicity enforced (stale replay rejected),
    and enforce_sig rejects unsigned bundles deterministically.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        for var in ("P2P_CRL_SIGNING_KEY", "SBOM_SIGNING_KEY",
                    "P2P_CRL_VERIFY_KEY", "SBOM_PUBKEY",
                    "P2P_CRL_REQUIRE_SIG", "P2P_CRL_SIGNING_KEY"):
            os.environ.pop(var, None)
        from multi_device_manager import MultiDeviceManager
        self.mgr = MultiDeviceManager(storage_path=self.temp_dir.name,
                                      in_memory_only=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _bundle(self, version, serials):
        import datetime
        return {"issuer": "CMD_AG", "version": version,
                "revoked_serials": list(serials),
                "timestamp": datetime.datetime.now().isoformat(),
                "alg": "none", "kid": None, "sig": None}

    def test_concurrent_import_no_lost_updates(self):
        import threading
        shared = "aa" * 32
        versions = list(range(1, 17))
        added = []
        errors = []
        lock = threading.Lock()

        def _worker(v):
            try:
                n = self.mgr.import_crl_bundle(
                    self._bundle(v, [shared, f"{v:064x}"]))
                with lock:
                    added.append(n)
            except Exception as e:  # noqa: BLE001 -- collected, asserted empty
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=_worker, args=(v,))
                   for v in versions]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertTrue(all(not t.is_alive() for t in threads),
                        "CRL import deadlocked under concurrency")
        self.assertEqual(errors, [])
        final = set(self.mgr.get_revocation_list("CMD_AG"))
        final_hex = {b.hex() if isinstance(b, (bytes, bytearray)) else b
                     for b in final}
        # Shared serial survives every interleaving; accounting is exact.
        self.assertIn(shared, final_hex)
        self.assertEqual(sum(added), len(final_hex))
        self.assertLessEqual(final_hex,
                             {shared} | {f"{v:064x}" for v in versions})

    def test_stale_version_rejected_and_sig_enforced(self):
        fresh = self._bundle(50, ["bb" * 32])
        self.assertGreater(self.mgr.import_crl_bundle(fresh), 0)
        stale = self._bundle(49, ["cc" * 32])
        self.assertEqual(self.mgr.import_crl_bundle(stale), 0)
        serials = {b.hex() if isinstance(b, (bytes, bytearray)) else b
                   for b in self.mgr.get_revocation_list("CMD_AG")}
        self.assertNotIn("cc" * 32, serials)
        # Unsigned bundles refused (return 0, never raise) when enforced.
        self.assertEqual(
            self.mgr.import_crl_bundle(self._bundle(51, ["dd" * 32]),
                                       enforce_sig=True), 0)
        serials2 = {b.hex() if isinstance(b, (bytes, bytearray)) else b
                    for b in self.mgr.get_revocation_list("CMD_AG")}
        self.assertNotIn("dd" * 32, serials2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

