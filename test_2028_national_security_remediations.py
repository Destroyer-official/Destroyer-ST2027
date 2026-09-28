#!/usr/bin/env python3
"""
Test Suite: 2028+ National-Security Level Hardening & Remediation Battery
Validates:
1. Zero-Trust RBAC & Fine-Grained Authorization
2. Cryptographically Signed Boot Configuration & Anti-Downgrade Invariants
3. TUF-Style Secure Updater with Monotonic Rollback Protection
4. Persistent SBOM Trust Anchor & Cryptographic Receipt Verification
5. Strict Air-Gapped Mode Enforcement & Network Isolation
6. Shamir M-of-N Key Backup & Tested Dual-Witness Restore Ceremony
7. At-Rest AES-256-GCM Sealed Storage for pins.json
"""

import os
import secrets
import json
import time
import shutil
import tempfile
import unittest
from pathlib import Path

# Set test environment defaults (snapshot first so tearDownClass can
# restore the ambient process env instead of blind-popping keys that
# later suites in the same pytest process may need).
_ENV_KEYS = ("P2P_ALLOW_LOOPBACK", "P2P_OFFLINE_MODE",
             "P2P_SIGNING_PASSPHRASE", "P2P_ENABLE_CUSTOM_THRESHOLD")
_ENV_SNAPSHOT = {k: os.environ.get(k) for k in _ENV_KEYS}
os.environ["P2P_ALLOW_LOOPBACK"] = "1"
os.environ["P2P_OFFLINE_MODE"] = "1"
os.environ["P2P_SIGNING_PASSPHRASE"] = "test_tuf_ceremony_secret_2028"  # nosec: B105
os.environ["P2P_ENABLE_CUSTOM_THRESHOLD"] = "1"

from data_models import SecurityRole, SecurityPermission, RoleAssignment, UserProfile, PeerInfo
from zero_trust_engine import (
    ZeroTrustEngine,
    RBACPolicyEngine,
    AuthorizationFailure,
    AuthenticationFailure,
    SessionTerminated,
    SessionState
)
from utils.config_manager import ConfigManager, ConfigurationError
from config import ConfigManager as CoreConfigManager
from supply_chain_security import (
    TUFReleaseManager,
    CodeSigningManager,
    RollbackAttackError,
    ExpiredMetadataError
)
from security_recovery_manager import SecurityRecoveryManager, SecurityRecoveryError
from ui import safety_numbers


class TestZeroTrustRBAC(unittest.TestCase):
    """Test 1: Zero-Trust Role-Based Access Control and Granular Authorization."""

    def setUp(self):
        self.rbac = RBACPolicyEngine()

    def test_operator_least_privilege(self):
        """Operators can send chat and files, but never NC3 or emergency release."""
        peer_id = "operator_node_alpha"
        self.rbac.assign_role(peer_id, SecurityRole.OPERATOR)

        self.assertTrue(self.rbac.check_permission(peer_id, SecurityPermission.SEND_CHAT))
        self.assertTrue(self.rbac.check_permission(peer_id, SecurityPermission.SEND_FILE))

        self.assertFalse(self.rbac.check_permission(peer_id, SecurityPermission.SEND_NC3))
        self.assertFalse(self.rbac.check_permission(peer_id, SecurityPermission.EMERGENCY_RELEASE))
        self.assertFalse(self.rbac.check_permission(peer_id, SecurityPermission.UPDATE_CONFIG))

        with self.assertRaises(AuthorizationFailure):
            self.rbac.enforce_permission(peer_id, SecurityPermission.SEND_NC3)

    def test_commander_privileges(self):
        """Commanders hold NC3 launch and emergency release authorization."""
        commander_id = "commander_supreme"
        self.rbac.assign_role(commander_id, SecurityRole.COMMANDER)

        self.assertTrue(self.rbac.check_permission(commander_id, SecurityPermission.SEND_NC3))
        self.assertTrue(self.rbac.check_permission(commander_id, SecurityPermission.EMERGENCY_RELEASE))
        self.assertTrue(self.rbac.check_permission(commander_id, SecurityPermission.SEND_CHAT))

    def test_anonymous_default_deny(self):
        """Unregistered principals are assigned ANONYMOUS and denied all actions."""
        unknown_id = "adversary_impostor"
        self.assertEqual(self.rbac.get_role(unknown_id), SecurityRole.ANONYMOUS)
        for perm in SecurityPermission:
            self.assertFalse(self.rbac.check_permission(unknown_id, perm))
            with self.assertRaises(AuthorizationFailure):
                self.rbac.enforce_permission(unknown_id, perm)

    def test_zero_trust_engine_authorization_wiring(self):
        """ZeroTrustEngine enforces session active state AND RBAC permission."""
        from liboqs_wrapper import LibOQS_MLDSA_87
        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()
        engine = ZeroTrustEngine(identity_key=pk, signing_key=sk)

        peer_id = "tactical_peer_007"
        engine.assign_peer_role(peer_id, SecurityRole.OPERATOR)

        # Unauthenticated session -> authorize fails
        self.assertFalse(engine.authorize(peer_id, SecurityPermission.SEND_CHAT))

        # Manually mark session authenticated
        engine._sessions[peer_id] = SessionState.AUTHENTICATED

        # Authenticated operator -> SEND_CHAT authorized, SEND_NC3 denied
        self.assertTrue(engine.authorize(peer_id, SecurityPermission.SEND_CHAT))
        self.assertFalse(engine.authorize(peer_id, SecurityPermission.SEND_NC3))

        with self.assertRaises(AuthorizationFailure):
            engine.enforce_authorization(peer_id, SecurityPermission.SEND_NC3)


class TestSignedBootConfig(unittest.TestCase):
    """Test 2: Cryptographically Signed Boot Configuration & Anti-Downgrade Invariants."""

    def test_production_config_signature_valid(self):
        """Production boot config signature verifies with root anchor."""
        self.assertTrue(ConfigManager.verify_config_signature("config_production.json"))

    def test_tampered_production_config_fails_closed(self):
        """Any tampering with config_production.json fails signature check and raises ConfigurationError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_cfg = Path(tmpdir) / "config_production.json"
            tmp_sig = Path(tmpdir) / "config_production.json.sig"

            shutil.copy("config_production.json", tmp_cfg)
            shutil.copy("config_production.json.sig", tmp_sig)

            # Valid initially
            self.assertTrue(ConfigManager.verify_config_signature(str(tmp_cfg)))

            # Tamper with config file (e.g. attacker attempts to disable HSM or air-gap)
            content = json.loads(tmp_cfg.read_text(encoding='utf-8'))
            content["enable_hsm"] = False
            tmp_cfg.write_text(json.dumps(content), encoding='utf-8')

            # Verification MUST fail
            self.assertFalse(ConfigManager.verify_config_signature(str(tmp_cfg)))

            # ConfigManager load MUST fail-closed with ConfigurationError
            with self.assertRaises(ConfigurationError):
                ConfigManager(config_path=str(tmp_cfg))

    def test_config_py_anti_downgrade_env_overrides(self):
        """Anti-downgrade prevents overriding critical security settings via env in MAXIMUM mode."""
        old_level = os.environ.get("P2P_SECURITY_LEVEL")
        try:
            os.environ["P2P_SECURITY_LEVEL"] = "LOW"
            mgr = CoreConfigManager("config_production.json")
            # In MAXIMUM mode, P2P_SECURITY_LEVEL=LOW is ignored
            self.assertEqual(mgr.get("security_level"), "MAXIMUM")
        finally:
            if old_level is not None:
                os.environ["P2P_SECURITY_LEVEL"] = old_level
            else:
                os.environ.pop("P2P_SECURITY_LEVEL", None)


class TestTUFUpdaterRollbackProtection(unittest.TestCase):
    """Test 3: TUF-Style Secure Updater with Monotonic Rollback Protection."""

    def setUp(self):
        os.environ["P2P_SIGNING_PASSPHRASE"] = "test_tuf_ceremony_secret_2028"  # nosec: B105
        self.tmpdir = tempfile.mkdtemp()
        self.state_dir = Path(self.tmpdir) / "tuf_state"
        self.source_dir = Path(self.tmpdir) / "source"
        self.update_pkg_dir = Path(self.tmpdir) / "update_v1"
        self.dest_dir = Path(self.tmpdir) / "destination"

        self.source_dir.mkdir(parents=True)
        (self.source_dir / "core_update.py").write_text("# Core Update v1", encoding='utf-8')

        self.tuf = TUFReleaseManager(state_dir=str(self.state_dir))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_and_apply_update_v1(self):
        """Update package v1 can be created and applied, advancing monotonic counter."""
        self.assertEqual(self.tuf.get_current_version_counter(), 0)

        self.tuf.create_update_package(
            source_dir=str(self.source_dir),
            output_dir=str(self.update_pkg_dir),
            version_counter=1
        )

        ok = self.tuf.apply_update(str(self.update_pkg_dir), str(self.dest_dir))
        self.assertTrue(ok)
        self.assertEqual(self.tuf.get_current_version_counter(), 1)
        self.assertTrue((self.dest_dir / "core_update.py").exists())

    def test_rollback_attack_rejected(self):
        """Applying or creating an update with version <= current counter raises RollbackAttackError."""
        # Advance to version 5
        self.tuf._save_state(5)
        self.assertEqual(self.tuf.get_current_version_counter(), 5)

        # Attacker replays version 3 update
        with self.assertRaises(RollbackAttackError):
            self.tuf.create_update_package(
                source_dir=str(self.source_dir),
                output_dir=str(self.update_pkg_dir),
                version_counter=3
            )

    def test_tampered_update_target_fails_verification(self):
        """Tampering with an update file after package creation causes verification failure."""
        self.tuf.create_update_package(
            source_dir=str(self.source_dir),
            output_dir=str(self.update_pkg_dir),
            version_counter=2
        )

        # Tamper with packaged file
        (self.update_pkg_dir / "core_update.py").write_text("# Injected Backdoor", encoding='utf-8')

        ok, msg = self.tuf.verify_update_package(str(self.update_pkg_dir))
        self.assertFalse(ok)
        self.assertIn("mismatch", msg)


class TestAirGappedModeEnforcement(unittest.TestCase):
    """Test 4: Air-Gapped Mode Hardening & Outbound Network Isolation."""

    def test_air_gapped_mode_suppresses_siem_network_calls(self):
        """In air-gapped mode, continuous security monitor never makes external HTTP requests."""
        from datetime import datetime
        from continuous_security_monitor import SecurityMonitor, SecurityAlert, AlertSeverity
        monitor = SecurityMonitor()

        old_mode = os.environ.get("P2P_AIR_GAPPED_MODE")
        try:
            os.environ["P2P_AIR_GAPPED_MODE"] = "1"
            monitor._siem_endpoint = "https://unreachable.invalid:8443/alerts"
            monitor._siem_api_key = "test_key"

            alert = SecurityAlert(
                alert_id="alert_001",
                severity=AlertSeverity.HIGH,
                title="Airgap Isolation Test",
                description="Test description",
                timestamp=datetime.now(),
                source="test",
                alert_type="intrusion_attempt"
            )

            # In air-gapped mode, should return True immediately without network call
            success = monitor._send_to_siem(alert)
            self.assertTrue(success)
        finally:
            if old_mode is not None:
                os.environ["P2P_AIR_GAPPED_MODE"] = old_mode
            else:
                os.environ.pop("P2P_AIR_GAPPED_MODE", None)

    def test_siem_alert_cryptographic_signature_and_retry_queue(self):
        """SIEM alerts generate cryptographic HMAC signatures and queue retries on delivery failure."""
        from datetime import datetime
        from continuous_security_monitor import SecurityMonitor, SecurityAlert, AlertSeverity
        monitor = SecurityMonitor(siem_endpoint="https://siem.soc.mil:8443/alerts", siem_api_key="TopSecretDefenseKey")

        alert = SecurityAlert(
            alert_id="alert_tactical_999",
            severity=AlertSeverity.CRITICAL,
            title="Intrusion Alert",
            description="Signature Test",
            timestamp=datetime.now(),
            source="ids_node",
            alert_type="intrusion_attempt"
        )

        # Signing generates deterministic hex signature
        sig = monitor.sign_alert(alert)
        self.assertIsInstance(sig, str)
        self.assertEqual(len(sig), 64)  # SHA3-256 hex length

        # When network fails, export queues to _siem_retry_queue
        old_mode = os.environ.get("P2P_AIR_GAPPED_MODE")
        try:
            os.environ.pop("P2P_AIR_GAPPED_MODE", None)
            monitor._alerts.append(alert)
            monitor._export_alerts_to_siem()
            # Delivery failure queues into retry queue
            self.assertEqual(len(monitor._siem_retry_queue), 1)
            self.assertEqual(monitor._siem_retry_queue[0].retry_count, 1)
            self.assertIsNotNone(monitor._siem_retry_queue[0].signature)
        finally:
            if old_mode is not None:
                os.environ["P2P_AIR_GAPPED_MODE"] = old_mode


class TestKeyBackupAndRestoreCeremony(unittest.TestCase):
    """Test 5: M-of-N Shamir Key Backup & Tested Dual-Witness Restore Ceremony."""

    def setUp(self):
        self.recovery_mgr = SecurityRecoveryManager()
        self.master_secret = secrets.token_bytes(32)

    def test_shamir_3_of_5_roundtrip(self):
        """Master key can be split into 5 shares and restored from any 3."""
        manifest = self.recovery_mgr.backup_master_key(
            key_id="tactical_master_key_1",
            key_bytes=self.master_secret,
            threshold=3,
            total_shares=5
        )

        self.assertEqual(len(manifest["shares"]), 5)
        expected_hash = manifest["sha3_512"]

        # 3 shares: success
        restored = self.recovery_mgr.restore_master_key(
            key_id="tactical_master_key_1",
            shares_data=manifest["shares"][:3],
            expected_hash=expected_hash
        )
        self.assertEqual(restored, self.master_secret)

    def test_insufficient_shares_fail_closed(self):
        """Providing fewer than threshold shares fails closed."""
        manifest = self.recovery_mgr.backup_master_key(
            key_id="tactical_master_key_2",
            key_bytes=self.master_secret,
            threshold=3,
            total_shares=5
        )
        from threshold_cryptography import InsufficientSharesError
        with self.assertRaises(InsufficientSharesError):
            self.recovery_mgr.restore_master_key(
                key_id="tactical_master_key_2",
                shares_data=manifest["shares"][:2]
            )

    def test_dual_witness_restore_ceremony(self):
        """Restore ceremony succeeds with 2 witnesses and verified shares."""
        manifest = self.recovery_mgr.backup_master_key(
            key_id="nuclear_auth_key",
            key_bytes=self.master_secret,
            threshold=3,
            total_shares=5
        )

        ok, key = self.recovery_mgr.execute_key_restore_ceremony(
            ceremony_id="ceremony_alpha_2028",
            witness_ids=["Officer_Alpha_1", "Officer_Bravo_2"],
            shares_data=manifest["shares"][:3],
            expected_hash=manifest["sha3_512"]
        )
        self.assertTrue(ok)
        self.assertEqual(key, self.master_secret)

        # Rejects with only 1 witness
        ok_single, _ = self.recovery_mgr.execute_key_restore_ceremony(
            ceremony_id="ceremony_alpha_2028",
            witness_ids=["Officer_Alpha_1"],
            shares_data=manifest["shares"][:3],
            expected_hash=manifest["sha3_512"]
        )
        self.assertFalse(ok_single)


class TestAtRestSealedStoragePins(unittest.TestCase):
    """Test 6: AES-256-GCM Sealed Envelope for pins.json."""

    def test_pins_sealed_envelope_roundtrip(self):
        """Storing pins with P2P_PIN_KEK encrypts pins.json with PINENC_V1: envelope."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_pin_store = Path(tmpdir) / "pins.json"
            orig_store = safety_numbers.PIN_STORE
            orig_kek = safety_numbers._PIN_KEK

            try:
                safety_numbers.PIN_STORE = test_pin_store
                safety_numbers._PIN_KEK = b"TestTacticalPassphrase2028!#$"

                safety_numbers.store_pin("peer_charlie_888", "sha3_fingerprint_sample_data_xyz")

                # Verify file starts with PINENC_V1: magic bytes
                raw = test_pin_store.read_bytes()
                self.assertTrue(raw.startswith(b"PINENC_V1:"))

                # Load pins decrypts cleanly
                loaded = safety_numbers.load_pins()
                self.assertIn("peer_charlie_888", loaded)
                self.assertEqual(safety_numbers.check_pin("peer_charlie_888", "sha3_fingerprint_sample_data_xyz"), "match")
            finally:
                safety_numbers.PIN_STORE = orig_store
                safety_numbers._PIN_KEK = orig_kek


class TestCertificateRevocationEnforcement(unittest.TestCase):
    """Test 7: Post-Quantum Certificate Revocation & Fail-Closed Enforcement."""

    def test_revoked_certificate_rejected(self):
        from pq_certificate_authority import PQCertificateAuthority, CertificateRevokedError
        from liboqs_wrapper import LibOQS_MLDSA_87

        ca = PQCertificateAuthority(ca_name="US_DEFENSE_PQC_CA_ROOT")
        signer = LibOQS_MLDSA_87()
        pk, _ = signer.keygen()

        cert = ca.issue_certificate(
            subject="defense_terminal_bravo",
            public_key=pk,
            validity_days=30
        )

        # Valid initially
        self.assertTrue(ca.verify_certificate(cert))

        # Revoke certificate
        ca.revoke_certificate(cert.serial)
        self.assertTrue(ca.is_revoked(cert.serial))

        # Verification must raise CertificateRevokedError
        with self.assertRaises(CertificateRevokedError):
            ca.verify_certificate(cert)


class TestFaultInjectionAndRedundancy(unittest.TestCase):
    """Test 8: Software-Level Fault Injection Resistance & Redundant Majority Consensus."""

    def test_fault_resistant_computation_consensus(self):
        from enhanced_security_features import MilitaryFaultInjectionResistance
        fir = MilitaryFaultInjectionResistance(redundancy_factor=4)

        # Consistent computation
        result = fir.fault_resistant_computation(lambda x, y: x * y + 10, 5, 7)
        self.assertEqual(result, 45)

    def test_fault_injection_divergence_fails_closed(self):
        from enhanced_security_features import MilitaryFaultInjectionResistance
        fir = MilitaryFaultInjectionResistance(redundancy_factor=4)

        call_count = 0
        def unstable_computation():
            nonlocal call_count
            call_count += 1
            # Injects divergence on each call
            return f"divergent_output_{call_count}"

        # Divergent results must raise RuntimeError fail-closed
        with self.assertRaises(RuntimeError) as ctx:
            fir.fault_resistant_computation(unstable_computation)
        self.assertIn("Fault injection detected", str(ctx.exception))


class TestRealHardwareAndNonSilentFallback(unittest.TestCase):
    """Test 9: Real Hardware Probing, Non-Silent Fallback Warnings, and NC3 Key Isolation."""

    def test_windows_hardware_integrity_monitoring(self):
        """Windows runtime integrity monitoring checks real Win32 VirtualLock capability."""
        from platform_hsm_interface import _activate_windows_runtime_integrity
        result = _activate_windows_runtime_integrity()
        # On Windows, must return bool without crashing or unhandled exception
        self.assertIsInstance(result, bool)

    def test_ceremony_degraded_simulation_branding_when_hardware_absent(self):
        """Witnessed key ceremony branding is always self-consistent.

        No-demo rule (fixed 2026-09-23): an earlier revision assumed
        tpm_available and hardware_mode always agree. They legitimately
        do NOT: TPM present but unattestable (attestation guard fails)
        correctly reports tpm_available=True WITH degraded branding.
        The invariant that must hold in EVERY state: mode/tamper-flag
        agreement + exact degraded strings (never a silent mismatch).
        """
        from scripts.witnessed_key_ceremony import WitnessedKeyCeremony
        ceremony = WitnessedKeyCeremony(quorum_m=2, total_n=3)
        status = ceremony.check_hardware_root_of_trust()
        self.assertIn("hardware_mode", status)
        self.assertIn("hardware_id", status)
        if status["hardware_mode"] == "DEGRADED_SECONDARY_SIMULATION":
            self.assertEqual(status["hardware_id"], "DEGRADED_SECONDARY_SIMULATION_ROOT")
            self.assertFalse(status["hardware_tamper_resistant"])
        else:
            self.assertEqual(status["hardware_mode"], "HARDWARE_ROOT_ENFORCED")
            self.assertTrue(status["hardware_tamper_resistant"])
            self.assertTrue(status["tpm_available"])

        # Also verify secondary fallback path explicitly via patch
        from unittest.mock import patch
        with patch("scripts.witnessed_key_ceremony.is_tpm_available", return_value=False):
            ceremony_fallback = WitnessedKeyCeremony(quorum_m=2, total_n=3)
            fallback_status = ceremony_fallback.check_hardware_root_of_trust()
            self.assertEqual(fallback_status["hardware_mode"], "DEGRADED_SECONDARY_SIMULATION")
            self.assertEqual(fallback_status["hardware_id"], "DEGRADED_SECONDARY_SIMULATION_ROOT")
            self.assertFalse(fallback_status["hardware_tamper_resistant"])

    def test_nc3_secret_key_serialization_rejected_in_production(self):
        """NC3 OfficerIdentity rejects secret key dictionary serialization in production mode."""
        from nc3_nuclear_command import OfficerIdentity, NC3SecurityError
        officer = OfficerIdentity(
            officer_id="Gen_Vance_01",
            rank="General",
            duty_title="STRATCOM Commander",
            public_key=secrets.token_bytes(2592),
            secret_key=secrets.token_bytes(4896)
        )

        # Default serialization never includes secret key
        safe_dict = officer.to_dict()
        self.assertNotIn("secret_key_hex", safe_dict)

        # In production mode, include_secret=True raises NC3SecurityError fail-closed
        old_prod = os.environ.get("SECURE_P2P_PRODUCTION")
        try:
            os.environ["SECURE_P2P_PRODUCTION"] = "true"
            with self.assertRaises(NC3SecurityError):
                officer.to_dict(include_secret=True)
        finally:
            if old_prod is not None:
                os.environ["SECURE_P2P_PRODUCTION"] = old_prod
            else:
                os.environ.pop("SECURE_P2P_PRODUCTION", None)


def tearDownModule():
    # Restore (not blind-pop): later suites in the same pytest process
    # may rely on ambient values (e.g. shell-provided P2P_ALLOW_LOOPBACK
    # or another suite's ceremony secret).
    for k in ("P2P_ALLOW_LOOPBACK", "P2P_OFFLINE_MODE", "P2P_SIGNING_PASSPHRASE", "P2P_ENABLE_CUSTOM_THRESHOLD"):
        old = _ENV_SNAPSHOT.get(k)
        if old is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = old


if __name__ == "__main__":
    unittest.main()



