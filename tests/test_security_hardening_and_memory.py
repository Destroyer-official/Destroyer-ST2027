#!/usr/bin/env python3
"""
Test Security Hardening, Graceful Degradation Fail-Closed, and Memory Pinning.

Verifies:
1. memory_manager.py fails closed with MemoryError when P2P_REQUIRE_PINNED_KEYS=1 and lock fails.
2. security/hardening.py strictly prohibits DISABLE_ANTI_DEBUGGING in production mode.
3. security/hardening.py strictly prohibits fallback security components in production mode.
4. security/graceful_degradation.py strictly prohibits un-Merkle-chained logging in production mode.
5. security/monitor.py fails closed with MonitoringError in production mode if monitoring fails to start.
6. forward_secrecy_manager.py invokes force_ratchet_rotation() on DoubleRatchet during rotation.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


class TestSecurityHardeningAndMemory(unittest.TestCase):

    def test_memory_manager_pinned_keys_fail_closed(self):
        """Verify that memory_manager raises MemoryError when P2P_REQUIRE_PINNED_KEYS=1 and lock fails."""
        import memory_manager
        from memory_manager import SecureMemoryManager, SecurityLevel

        mgr = SecureMemoryManager()
        lock_attr = "_virtual_lock" if hasattr(mgr, "_virtual_lock") else "_mlock"
        fail_val = False if hasattr(mgr, "_virtual_lock") else -1
        with patch.dict(os.environ, {"P2P_REQUIRE_PINNED_KEYS": "1"}):
            with patch.object(mgr, lock_attr, return_value=fail_val):
                with self.assertRaises(MemoryError) as ctx:
                    mgr.allocate_secure_buffer(1024, security_level=SecurityLevel.CRYPTOGRAPHIC_MATERIAL)
                self.assertIn("P2P_REQUIRE_PINNED_KEYS", str(ctx.exception))

    def test_anti_debugging_bypass_prohibited_in_production(self):
        """Verify that DISABLE_ANTI_DEBUGGING raises SecurityError when P2P_PRODUCTION=1."""
        import security.hardening as sh

        hardening = sh.SecurityHardening()
        with patch.dict(os.environ, {"P2P_PRODUCTION": "1", "DISABLE_ANTI_DEBUGGING": "true"}):
            with self.assertRaises(sh.SecurityError) as ctx:
                hardening.enable_anti_debugging()
            self.assertIn("prohibited in production", str(ctx.exception).lower())

    def test_fallback_security_components_prohibited_in_production(self):
        """Verify that fallback security components raise SecurityError when in production mode."""
        import security.hardening as sh

        hardening = sh.SecurityHardening()
        with patch.dict(os.environ, {"SECURE_P2P_PRODUCTION": "true"}):
            with self.assertRaises(sh.SecurityError) as ctx:
                hardening._initialize_fallback_security_components()
            self.assertIn("prohibited in production", str(ctx.exception).lower())

    def test_audit_logging_degradation_prohibited_in_production(self):
        """Verify that graceful degradation of audit logging raises RuntimeError in production mode."""
        import security.graceful_degradation as gd

        mgr = gd.SecurityDegradationManager()
        with patch.dict(os.environ, {"P2P_PRODUCTION": "1"}):
            with patch.object(mgr, "is_module_available", return_value=False):
                with self.assertRaises(RuntimeError) as ctx:
                    mgr.get_audit_logging_fallback()
                self.assertIn("AuditLogger is strictly required in production mode", str(ctx.exception))

    def test_security_monitor_fail_closed_in_production(self):
        """Verify that SecurityMonitor raises MonitoringError in production mode if monitoring fails."""
        import security.monitor as sm

        monitor = sm.SecurityMonitor()
        with patch.dict(os.environ, {"P2P_PRODUCTION": "1"}):
            with patch("threading.Thread", side_effect=RuntimeError("Thread creation denied")):
                with self.assertRaises(sm.MonitoringError) as ctx:
                    monitor.start_security_monitoring()
                self.assertIn("production", str(ctx.exception).lower())

    def test_forward_secrecy_enhanced_double_ratchet_invokes_force_rotation(self):
        """Verify EnhancedDoubleRatchetRotation invokes force_ratchet_rotation() during rotation."""
        from forward_secrecy_manager import EnhancedDoubleRatchetRotation, RotationTrigger

        mock_ratchet = MagicMock()
        mock_ratchet.KEY_ROTATION_MESSAGES = 100
        mock_ratchet.KEY_ROTATION_TIME = 900
        mock_ratchet.force_ratchet_rotation = MagicMock(return_value=b"new_dh_pk")

        enhanced = EnhancedDoubleRatchetRotation(double_ratchet=mock_ratchet)
        enhanced._on_rotation(RotationTrigger.TIME_THRESHOLD)

        mock_ratchet.force_ratchet_rotation.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
