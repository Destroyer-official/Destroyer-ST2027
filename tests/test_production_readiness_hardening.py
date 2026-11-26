"""Regression tests for production-readiness security hardening across
threshold_cryptography, tactical_mesh_ddil, verify_deployment, and CI/report honesty.
"""

import secrets
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class TestThresholdCryptographyHardening:
    """Verify fail-closed boundaries in threshold_cryptography.py."""

    def test_custom_threshold_refused_in_production_even_with_override_env(self, monkeypatch):
        import threshold_cryptography as tc

        monkeypatch.setenv("P2P_ENABLE_CUSTOM_THRESHOLD", "1")
        monkeypatch.setenv("P2P_ENABLE_EXPERIMENTAL", "1")
        monkeypatch.setattr("production_gate.is_production", lambda: True)
        assert tc.is_custom_threshold_enabled() is False  # nosec: B101

        with pytest.raises(PermissionError):
            tc.ThresholdKeyManager(threshold=2, total_shares=3)

    def test_reconstruct_rejects_inconsistent_redundant_shares(self, monkeypatch):
        from threshold_cryptography import (
            ReconstructionError,
            ThresholdKeyManager,
            ThresholdShare,
        )

        monkeypatch.setattr("production_gate.is_production", lambda: False)
        monkeypatch.setenv("P2P_ENABLE_CUSTOM_THRESHOLD", "1")
        mgr = ThresholdKeyManager(threshold=2, total_shares=4)
        secret = secrets.token_bytes(32)
        shares = mgr.split_key(secret)

        # Flip 1 bit in share[2] (beyond threshold k=2) to simulate Byzantine share injection
        corrupted_val = bytearray(shares[2].value)
        corrupted_val[0] ^= 0x01
        poisoned = ThresholdShare(
            index=shares[2].index,
            value=bytes(corrupted_val),
            commitment=shares[2].commitment,
            threshold=shares[2].threshold,
            total_shares=shares[2].total_shares,
        )

        with pytest.raises(ReconstructionError, match="Inconsistent share"):
            mgr.reconstruct_key([shares[0], shares[1], poisoned], key_length=32)

    def test_verify_share_enforces_prime_field_and_length_bounds(self, monkeypatch):
        from threshold_cryptography import (
            ReconstructionError,
            ThresholdKeyManager,
            ThresholdShare,
        )

        monkeypatch.setattr("production_gate.is_production", lambda: False)
        monkeypatch.setenv("P2P_ENABLE_CUSTOM_THRESHOLD", "1")
        mgr = ThresholdKeyManager(threshold=2, total_shares=3)
        shares = mgr.split_key(secrets.token_bytes(32))
        oversized = ThresholdShare(
            index=1,
            value=ThresholdKeyManager.PRIME.to_bytes(32, "big"),
            commitment=shares[0].commitment,
            threshold=2,
            total_shares=3,
        )
        assert mgr.verify_share(oversized, commitment=mgr._last_combined_commitment) is False  # nosec: B101

        with pytest.raises(ReconstructionError, match="Invalid key_length"):
            mgr.reconstruct_key(shares[:2], key_length=33)

    def test_distributed_key_storage_refuses_random_iv_and_unsafe_key_id(self, tmp_path, monkeypatch):
        from threshold_cryptography import (
            DistributedKeyStorage,
            ThresholdError,
            ThresholdKeyManager,
        )

        monkeypatch.setattr("production_gate.is_production", lambda: False)
        monkeypatch.setenv("P2P_ENABLE_CUSTOM_THRESHOLD", "1")
        monkeypatch.setenv("P2P_THRESHOLD_STORAGE_KEY", "test_passphrase_2027_strong")

        mgr = ThresholdKeyManager(threshold=2, total_shares=3)
        locs = [tmp_path / "s1", tmp_path / "s2", tmp_path / "s3"]
        storage = DistributedKeyStorage(storage_locations=locs, threshold_manager=mgr)

        # Path traversal key_id must fail closed
        with pytest.raises(ThresholdError, match="Unsafe threshold key_id"):
            storage.store_key("../etc/passwd", secrets.token_bytes(32))

        # Block deterministic IV gateways -> must fail closed (never fallback to os.urandom)
        monkeypatch.setitem(sys.modules, "cnsa_crypto_gateway", None)
        monkeypatch.setitem(sys.modules, "p2p_core", None)
        with pytest.raises(ImportError):
            storage.store_key("k_test_1", secrets.token_bytes(32))


class TestTacticalMeshDDILHardening:
    """Verify key pinning, auth, replay, and bounded queue hardening in tactical_mesh_ddil.py."""

    def test_keyring_refuses_silent_peer_key_overwrite(self):
        from tactical_mesh_ddil import TacticalKeyring

        ring = TacticalKeyring()
        pk1 = b"pk-node-alpha-1"
        pk2 = b"pk-node-alpha-2"
        ring.register_peer_key("ALPHA", pk1)
        assert ring.register_peer_key("ALPHA", pk1) == ring.register_peer_key("ALPHA", pk1)  # nosec: B101

        with pytest.raises(ValueError, match="already pinned"):
            ring.register_peer_key("ALPHA", pk2)

        # Explicit allow_rotation=True rotates cleanly
        new_id = ring.register_peer_key("ALPHA", pk2, allow_rotation=True)
        assert ring.get_key_by_node("ALPHA") == pk2  # nosec: B101
        assert ring.get_key_by_id(new_id) == pk2  # nosec: B101

    def test_verify_signature_refuses_unpinned_self_asserted_sender_pubkey(self):
        from liboqs_wrapper import LibOQS_MLDSA_87
        from tactical_mesh_ddil import DDILBundle, TacticalKeyring

        signer = LibOQS_MLDSA_87()
        pk_att, sk_att = signer.keygen()
        ring = TacticalKeyring()  # Empty keyring — attacker's key is NOT pinned

        forged = DDILBundle(
            bundle_id="FORGED-1",
            sender_id="COMMAND_HQ",
            recipient_id="OUTPOST",
            seq=1,
            ciphertext_bytes=b"\x00" * 16,
            auth_tag=b"\x01" * 16,
            timestamp_utc=time.time(),
            sender_pubkey=pk_att,
            key_epoch=1,
        )
        forged.sign_bundle(signer, sk_att, pk_att)

        assert forged.verify_signature(keyring=ring) is False  # nosec: B101

    def test_ttl_and_legacy_epoch_and_nonce_tampering_rejected(self, monkeypatch):
        from liboqs_wrapper import LibOQS_MLDSA_87
        from tactical_mesh_ddil import TacticalKeyring, create_bpsec_bundle, decrypt_bpsec_bundle

        signer = LibOQS_MLDSA_87()
        pk, sk = signer.keygen()
        sym = secrets.token_bytes(32)
        ring = TacticalKeyring()

        bundle = create_bpsec_bundle(
            sender_id="ALPHA",
            recipient_id="BRAVO",
            seq=7,
            payload_plaintext=b"MISSION_ORDER",
            sender_sk=sk,
            sender_pk=pk,
            symmetric_key=sym,
            keyring=ring,
        )

        # Tampering ttl_sec must invalidate ML-DSA-87 signature
        bundle.ttl_sec = 9999999.0
        with pytest.raises(ValueError, match="signature"):
            decrypt_bpsec_bundle(bundle, sym, expected_sender_pk=pk, keyring=ring)

        # Production mode rejects legacy epoch <= 0
        monkeypatch.setattr("production_gate.is_production", lambda: True)
        bundle.key_epoch = 0
        with pytest.raises(ValueError, match="key_epoch=0 rejected"):
            decrypt_bpsec_bundle(bundle, sym, expected_sender_pk=pk, keyring=ring)

    def test_mesh_replay_queue_cap_and_distinct_governance_signers(self, monkeypatch):
        from liboqs_wrapper import LibOQS_MLDSA_87
        from tactical_mesh_ddil import (
            BundlePriority,
            DDILBundle,
            DDILNodeMesh,
            GovernanceEnvelope,
            TacticalKeyring,
            create_bpsec_bundle,
        )

        signer = LibOQS_MLDSA_87()
        ring = TacticalKeyring()
        pk, sk = signer.keygen()
        sym = secrets.token_bytes(32)

        # Duplicate key aliased under two signer IDs cannot satisfy required_signatures=2
        ring.register_peer_key("CMD_1", pk)
        ring.register_peer_key("CMD_1_ALIAS", pk)
        env = GovernanceEnvelope(
            envelope_id="ENV-ALIAS-TEST",
            authorized_action="REKEY_NETWORK",
            target_parameters={},
            valid_until_utc=time.time() + 300.0,
            required_signatures=2,
        )
        env.sign("CMD_1", sk, signer)
        env.sign("CMD_1_ALIAS", sk, signer)
        assert env.verify(ring) is False  # nosec: B101

        # Bounded queue eviction/saturation (~251B + ~451B > 550B cap)
        mesh = DDILNodeMesh("NODE_A", max_queue_bytes=550, keyring=ring)
        b1 = mesh.enqueue_bundle("NODE_B", seq=1, ciphertext_bytes=b"A" * 200, auth_tag=b"\x00" * 16, priority=BundlePriority.STANDARD)
        assert b1 is not None  # nosec: B101
        with pytest.raises(ValueError, match="saturated"):
            mesh.enqueue_bundle("NODE_B", seq=2, ciphertext_bytes=b"B" * 400, auth_tag=b"\x00" * 16, priority=BundlePriority.STANDARD)

        # Higher priority EMERGENCY evicts STANDARD (~351B <= 550B)
        b_emg = mesh.enqueue_bundle("NODE_B", seq=3, ciphertext_bytes=b"E" * 300, auth_tag=b"\x00" * 16, priority=BundlePriority.EMERGENCY)
        assert b_emg.priority == BundlePriority.EMERGENCY  # nosec: B101
        assert len(mesh.outbound_store["NODE_B"]) == 1  # nosec: B101

        # Signed bundle replay with modified bundle_id rejected by receive_reconciled_bundle
        ring2 = TacticalKeyring()
        pk_s, sk_s = signer.keygen()
        signed_b = create_bpsec_bundle(
            sender_id="ALPHA_S",
            recipient_id="BRAVO_R",
            seq=42,
            payload_plaintext=b"ORDERS",
            sender_sk=sk_s,
            sender_pk=pk_s,
            symmetric_key=sym,
            keyring=ring2,
        )
        rx_mesh = DDILNodeMesh("BRAVO_R", keyring=ring2)
        assert rx_mesh.receive_reconciled_bundle(signed_b) is True  # nosec: B101

        rewrapped = DDILBundle(
            bundle_id="REWRAPPED-NEW-ID",
            sender_id=signed_b.sender_id,
            recipient_id=signed_b.recipient_id,
            seq=signed_b.seq,
            ciphertext_bytes=signed_b.ciphertext_bytes,
            auth_tag=signed_b.auth_tag,
            timestamp_utc=signed_b.timestamp_utc,
            ttl_sec=signed_b.ttl_sec,
            signature=signed_b.signature,
            sender_pubkey=signed_b.sender_pubkey,
            sender_key_id=signed_b.sender_key_id,
            priority=signed_b.priority,
            key_epoch=signed_b.key_epoch,
            encryption_key_id=signed_b.encryption_key_id,
        )
        assert rx_mesh.receive_reconciled_bundle(rewrapped) is False  # nosec: B101

        # Production rejects unsigned reconciled bundles
        unsigned_b = DDILBundle(
            bundle_id="UNSIGNED-1",
            sender_id="ALPHA_S",
            recipient_id="BRAVO_R",
            seq=99,
            ciphertext_bytes=b"C" * 32,
            auth_tag=b"\x00" * 16,
            timestamp_utc=time.time(),
            key_epoch=1,
        )
        monkeypatch.setattr("production_gate.is_production", lambda: True)
        assert rx_mesh.receive_reconciled_bundle(unsigned_b) is False  # nosec: B101


class TestVerifyDeploymentTruthfulness:
    """Verify simulated / waived hardware controls never stamp fake PASS."""

    def test_waived_secureboot_and_simulated_hardware_warn_not_pass(self, monkeypatch):
        import verify_deployment as vd

        monkeypatch.setattr("production_gate.is_production", lambda: False)
        monkeypatch.setenv("P2P_SECUREBOOT_WAIVED", "1")
        with patch(
            "platform_hsm_interface.get_host_security_posture",
            return_value={
                "os": "Linux",
                "secure_boot": False,
                "tpm_present": False,
                "dma_capable": False,
            },
        ):
            v = vd.DeploymentVerifier()
            assert v.verify_host_posture() is True  # nosec: B101
            sb_res = [r for r in v.results if r.check_name == "Host Posture: SecureBoot"][0]
            assert sb_res.status == vd.VerificationStatus.WARN  # nosec: B101

        # In production, P2P_SECUREBOOT_WAIVED=1 MUST still FAIL CLOSED
        monkeypatch.setattr("production_gate.is_production", lambda: True)
        with patch(
            "platform_hsm_interface.get_host_security_posture",
            return_value={
                "os": "Linux",
                "secure_boot": False,
                "tpm_present": True,
                "dma_capable": True,
            },
        ):
            v_prod = vd.DeploymentVerifier()
            assert v_prod.verify_host_posture() is False  # nosec: B101
            sb_prod = [r for r in v_prod.results if r.check_name == "Host Posture: SecureBoot"][0]
            assert sb_prod.status == vd.VerificationStatus.FAIL  # nosec: B101

    def test_simulated_tpm_and_tokens_emit_warn(self, monkeypatch, capsys):
        import verify_deployment as vd
        import scripts.verify_hardware_tokens as vht
        import scripts.provision_tpm2_nv_counter as tpm_prov

        monkeypatch.setattr("production_gate.is_production", lambda: False)
        monkeypatch.setattr(vht.HardwareTokenVerifier, "probe_readers", lambda self: [])
        monkeypatch.setattr(
            tpm_prov.TPM2NvCounterProvisioner,
            "check_tpm_prerequisites",
            lambda self: {
                "tpm_tools_installed": False,
                "tpm_device_present": True,
                "index_hex": "0x01800001",
            },
        )
        monkeypatch.setattr(
            tpm_prov.TPM2NvCounterProvisioner,
            "verify_monotonic_assurance",
            lambda self: {
                "verified": True,
                "simulated": True,
                "strictly_monotonic": True,
                "message": "Simulated increment 1 -> 2",
            },
        )

        v = vd.DeploymentVerifier()
        assert v.verify_hardware_tokens_posture() is True  # nosec: B101
        assert v.verify_tpm_monotonic_counter_posture() is True  # nosec: B101
        statuses = {r.check_name: r.status for r in v.results}
        assert statuses["Hardware Tokens: Two-Person Integrity"] == vd.VerificationStatus.WARN  # nosec: B101
        assert statuses["TPM Monotonic Counter: 0x01800001"] == vd.VerificationStatus.WARN  # nosec: B101
        capsys.readouterr()


class TestTacticalWebUiAndConsoleHardening:
    """Verify tactical_web CSP/DOM-XSS/API fixes and tactical_web_console fail-closed guards."""

    def test_web_assets_csp_compliant_no_innerhtml_and_valid_js(self):
        import re
        import shutil
        import subprocess

        app_js = (REPO_ROOT / "tactical_web" / "app.js").read_text(encoding="utf-8")
        index_html = (REPO_ROOT / "tactical_web" / "index.html").read_text(encoding="utf-8")

        assert not re.findall(r"\bon(?:click|submit|change)=", index_html), (  # nosec: B101
            "Inline HTML event handlers violate CSP script-src 'self'"
        )
        assert "X25519" not in index_html  # nosec: B101
        assert "P-384" in index_html  # nosec: B101
        assert ".innerHTML" not in app_js  # nosec: B101
        assert "fido2-l3-token-primary-001" not in app_js  # nosec: B101
        for endpoint in ("/api/send", "/api/eam", "/api/zgdp", "/api/cot", "/api/diode/send", "/api/zeroize", "/api/drill"):
            assert endpoint in app_js  # nosec: B101

        node = shutil.which("node")
        if node:
            res = subprocess.run([node, "--check", str(REPO_ROOT / "tactical_web" / "app.js")], capture_output=True, text=True)
            assert res.returncode == 0, f"app.js syntax error: {res.stderr}"  # nosec: B101

    def test_web_console_enforces_prod_mtls_and_webauthn_and_drill_errors(self, monkeypatch, tmp_path):
        import json
        from io import BytesIO
        import tactical_web_console as twc

        creds = twc.ensure_cac_piv_mtls_credentials(tmp_path)
        monkeypatch.setattr("production_gate.is_production", lambda: True)

        with pytest.raises(RuntimeError, match="mTLS client certificate"):
            twc.create_mtls_server_context(
                cafile=creds["ca_cert"],
                certfile=creds["server_cert"],
                keyfile=creds["server_key"],
                require_client_cert=False,
            )

        with patch.object(twc.TacticalWebHandler, "setup"), patch.object(twc.TacticalWebHandler, "finish"):
            handler = twc.TacticalWebHandler.__new__(twc.TacticalWebHandler)
            handler.rfile = BytesIO(b"{}")
            handler.wfile = BytesIO()
            handler.command = "POST"
            handler.path = "/api/send"
            handler.requestline = "POST /api/send HTTP/1.1"
            handler.request_version = "HTTP/1.1"
            handler.client_address = ("127.0.0.1", 12345)
            handler.headers = {"Content-Length": "2", "Content-Type": "application/json", "Origin": "https://127.0.0.1:8443"}
            handler.server = type("Srv", (), {"require_webauthn": False})()
            handler._handle_api_send({"sender": "NORAD_ALPHA", "message": "TEST"})
            raw = handler.wfile.getvalue().decode("utf-8")
            head, body_s = raw.split("\r\n\r\n", 1)
            assert "403" in head.splitlines()[0]  # nosec: B101
            assert "Access-Control-Allow-Origin: https://127.0.0.1:8443" in head  # nosec: B101
            assert json.loads(body_s)["status"] == "WEBAUTHN_L3_VERIFICATION_REQUIRED"  # nosec: B101


class TestFormalVerificationAndLauncherHardening:
    """Verify ProVerif query alignment and destroyer production launcher gates."""

    def test_formal_verifier_queries_match_pv_models_and_isolate_output(self, tmp_path, monkeypatch):
        from scripts.run_formal_verification import run_formal_verification

        hs_pv = (REPO_ROOT / "docs" / "formal" / "st2027_handshake.pv").read_text(encoding="utf-8")
        pcs_pv = (REPO_ROOT / "docs" / "formal" / "st2027_pcs.pv").read_text(encoding="utf-8")
        nc3_pv = (REPO_ROOT / "docs" / "formal" / "nc3_dual_custody.pv").read_text(encoding="utf-8")

        # Simulate ProVerif absent so no external binary needed; check recorded patterns against real .pv files
        monkeypatch.setattr("shutil.which", lambda _name: None)
        monkeypatch.delenv("P2P_PROVERIF", raising=False)
        report = run_formal_verification(output_dir=tmp_path)
        assert (tmp_path / "formal_verification_report.json").exists()  # nosec: B101
        by_file = {m["file"]: m for m in report["models_evaluated"]}

        for prop in by_file["st2027_handshake.pv"]["verified_properties"]:
            assert prop["formal_query_pattern"] in hs_pv  # nosec: B101
        for prop in by_file["st2027_pcs.pv"]["verified_properties"]:
            assert prop["formal_query_pattern"] in pcs_pv  # nosec: B101
        for prop in by_file["nc3_dual_custody.pv"]["verified_properties"]:
            assert prop["formal_query_pattern"] in nc3_pv  # nosec: B101

    def test_destroyer_diode_and_batch_launchers_enforce_production_keys(self, monkeypatch, tmp_path):
        import destroyer

        monkeypatch.delenv("P2P_DIODE_PSK", raising=False)
        monkeypatch.setenv("P2P_DIODE_DIR", str(tmp_path / "diode"))
        monkeypatch.setattr("production_gate.is_production", lambda: True)
        with pytest.raises(SystemExit) as exc:
            destroyer._provision_diode_key_material()
        assert exc.value.code == 2  # nosec: B101

        for bat_name in (
            "start_tactical_alpha.bat",
            "start_tactical_bravo.bat",
            "start_native_terminal_alpha.bat",
            "start_native_terminal_bravo.bat",
        ):
            content = (REPO_ROOT / bat_name).read_text(encoding="utf-8")
            assert "--auth-sk-file" in content  # nosec: B101
            assert "--peer-auth-pk-file" in content  # nosec: B101
            assert "--require-mutual-auth" in content  # nosec: B101

    def test_witnessed_key_ceremony_output_dir_isolates_compliance_reports(self, tmp_path):
        import json
        from scripts.witnessed_key_ceremony import WitnessedKeyCeremony

        comp_dir = REPO_ROOT / "compliance_reports"
        before = sorted(p.name for p in comp_dir.iterdir()) if comp_dir.exists() else []
        ceremony = WitnessedKeyCeremony(ceremony_id="TEST-ISOLATED-CEREMONY", output_dir=tmp_path)
        ceremony.register_custodians()
        ceremony.check_hardware_root_of_trust()
        ceremony.generate_cnsa2_root_keys()
        ceremony._lab_self_approve()
        receipt_path = ceremony.generate_ceremony_receipt()

        assert receipt_path.parent == tmp_path  # nosec: B101
        assert receipt_path.exists()  # nosec: B101
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        ok, msg = WitnessedKeyCeremony.verify_receipt(receipt, quorum_m=2)
        assert ok, msg  # nosec: B101
        after = sorted(p.name for p in comp_dir.iterdir()) if comp_dir.exists() else []
        assert after == before  # nosec: B101

    def test_reproducible_build_output_dir_and_dynamic_rust_count(self, tmp_path):
        import json
        from scripts.verify_reproducible_build import run_reproducible_build_verification

        comp_dir = REPO_ROOT / "compliance_reports"
        before = {p.name: p.stat().st_mtime_ns for p in comp_dir.iterdir()} if comp_dir.exists() else {}
        rc = run_reproducible_build_verification(output_dir=tmp_path)
        receipt_path = tmp_path / "signed_reproducible_build_receipt.json"
        assert rc == 0  # nosec: B101
        assert receipt_path.exists()  # nosec: B101
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        expected_rust = len(list((REPO_ROOT / "rust_data_plane" / "src").glob("*.rs")))
        assert f"({expected_rust} pure Rust modules)" in receipt["full_source_scope_description"]  # nosec: B101
        assert receipt["sbom_status"]["cyclonedx_mldsa87_signature_verified"] is True  # nosec: B101
        assert receipt["sbom_status"]["spdx_mldsa87_signature_verified"] is True  # nosec: B101
        after = {p.name: p.stat().st_mtime_ns for p in comp_dir.iterdir()} if comp_dir.exists() else {}
        assert after == before  # nosec: B101

    def test_deterministic_gcm_iv_enforced_fail_closed_without_random_fallback(self, monkeypatch, tmp_path):
        import cnsa_crypto_gateway
        import libsodium_manager
        import nc3_nuclear_command
        from cjadc2_cross_domain_guard import CrossDomainGuard, SecurityClassification

        def _fail_counter():
            raise cnsa_crypto_gateway.CounterExhaustionError("exhausted")

        monkeypatch.setattr(cnsa_crypto_gateway, "generate_deterministic_gcm_iv", _fail_counter)

        with pytest.raises(cnsa_crypto_gateway.CounterExhaustionError):
            libsodium_manager.secure_encrypt_aes_256_gcm(b"payload", b"\x11" * 32)
        with pytest.raises(cnsa_crypto_gateway.CounterExhaustionError):
            nc3_nuclear_command.serialize_eam_wire({"eam": "test"}, aead_key=b"\x22" * 32)
        guard = CrossDomainGuard(audit_dir=tmp_path)
        with pytest.raises(cnsa_crypto_gateway.CounterExhaustionError):
            guard.encrypt_compartment_payload(b"\x33" * 32, SecurityClassification.TOP_SECRET, "NOFORN", b"pt")

        for mod_name in (
            "cjadc2_cross_domain_guard.py",
            "libsodium_manager.py",
            "nc3_nuclear_command.py",
            "nc3_threshold_mpc.py",
            "platform_hsm_interface.py",
            "pqc_algorithms.py",
            "secure_enclave_key_storage.py",
            "secure_key_manager.py",
            "security_tiers.py",
            "supply_chain_security.py",
        ):
            src = (REPO_ROOT / mod_name).read_text(encoding="utf-8")
            assert "from p2p_core import generate_deterministic_gcm_iv" not in src, mod_name  # nosec: B101


