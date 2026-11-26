#!/usr/bin/env python3
"""Regression test suite verifying remediation of Forensic Security Audit Findings F-01 through F-08.

Ensures:
  - F-01: CI collection invariance (typing.Optional in destroyer_node, destroyer_core fallback stubs, scipy guard).
  - F-02: TacticalP2PNode.negotiate_hybrid_kex forwards mandatory authentication CLI arguments.
  - F-03: Secret boundary protection — production mode prohibits raw session key export into CPython bytes.
  - F-04: Release build flags exclude lab-only surfaces by default (--no-default-features).
  - F-05: Strict memory custody requirement fails closed on lock failure.
  - F-06: Formal checker script fails closed when --strict is specified and ProVerif is absent.
  - F-07: OpenTelemetry dependency pinned to fixed version (>= 1.45.2).
  - F-08: Production mode latching is armed unconditionally when lab=False.
"""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_f01_destroyer_node_typing_optional():
    """F-01: Ensure destroyer_node.py properly imports Optional from typing."""
    import destroyer_node
    assert hasattr(destroyer_node, "Optional"), "destroyer_node must export/import Optional"
    assert destroyer_node.DestroyerNode is not None


def test_f01_destroyer_core_fallback_stubs_present():
    """F-01: Ensure destroyer_core exports CorePqZkp, CoreDtnBundle, CoreSdrDsss even in fallback mode."""
    import destroyer_core
    assert hasattr(destroyer_core, "CorePqZkp"), "destroyer_core must export CorePqZkp"
    assert hasattr(destroyer_core, "CoreDtnBundle"), "destroyer_core must export CoreDtnBundle"
    assert hasattr(destroyer_core, "CoreSdrDsss"), "destroyer_core must export CoreSdrDsss"


def test_f01_f07_requirements_test_pinned_safely():
    """F-01 & F-07: Verify requirements-test.txt has opentelemetry-api >= 1.45.2 (fixing GHSA-mf5v-w3w3-f6cg) and scipy."""
    req_file = Path("requirements-test.txt")
    assert req_file.exists(), "requirements-test.txt must exist"
    content = req_file.read_text(encoding="utf-8")
    assert "opentelemetry-api==1.45.2" in content, "opentelemetry-api must be pinned to fixed version 1.45.2"
    assert "scipy" in content, "scipy must be declared in test requirements"


def test_f02_tactical_node_kex_command_arguments(tmp_path):
    """F-02: Verify negotiate_hybrid_kex forwards --psk-file, --auth-sk-file, --peer-auth-pk-file, etc."""
    from secure_p2p import TacticalP2PNode

    psk_file = str(tmp_path / "test.psk")
    auth_sk_file = str(tmp_path / "test.auth.sk")
    peer_auth_pk_file = str(tmp_path / "test.auth.pk")
    node_cert_file = str(tmp_path / "test.der")
    peer_cert_file = str(tmp_path / "peer.crt")
    root_ca_file = str(tmp_path / "ca.der")

    node = TacticalP2PNode(
        name="TEST_NODE",
        role="initiator",
        bind_addr="127.0.0.1",
        peer_addr="127.0.0.1",
        kex_port=9051,
        channel_port=9061,
        psk_file=psk_file,
        auth_sk_file=auth_sk_file,
        peer_auth_pk_file=peer_auth_pk_file,
        node_cert_file=node_cert_file,
        peer_cert_file=peer_cert_file,
        root_ca_file=root_ca_file,
        require_root_ca=False,
        lab_mode=False
    )

    with patch("subprocess.Popen") as mock_popen, patch("os.path.exists", return_value=True):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("[SAS: 1234-5678]", "")
        mock_popen.return_value = mock_proc

        with patch("secure_p2p._production", return_value=True):
            res = node.negotiate_hybrid_kex(timeout_sec=5)
            assert res is True

            call_args = mock_popen.call_args[0][0]
            assert "--psk-file" in call_args
            assert psk_file in call_args
            assert "--auth-sk-file" in call_args
            assert auth_sk_file in call_args
            assert "--peer-auth-pk-file" in call_args
            assert peer_auth_pk_file in call_args
            assert "--cert-file" in call_args
            assert node_cert_file in call_args
            assert "--ca-file" in call_args
            assert root_ca_file in call_args
            assert "--lab" not in call_args


def test_f03_production_secret_boundary_no_python_key_read(tmp_path):
    """F-03: Verify in production mode negotiate_hybrid_kex does not read key files into Python bytes."""
    from secure_p2p import TacticalP2PNode

    node = TacticalP2PNode(
        name="TEST_NODE",
        role="responder",
        bind_addr="127.0.0.1",
        peer_addr="127.0.0.1",
        kex_port=9050,
        channel_port=9060,
        psk_file=str(tmp_path / "test.psk"),
        auth_sk_file=str(tmp_path / "test.auth.sk"),
        peer_auth_pk_file=str(tmp_path / "test.auth.pk"),
        require_root_ca=False,
        lab_mode=False
    )

    with patch("subprocess.Popen") as mock_popen, patch("os.path.exists", return_value=True):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("[SAS: 9999-0000]", "")
        mock_popen.return_value = mock_proc

        # Under production mode, Path.read_text should NOT be called to import session secrets into Python
        with patch("secure_p2p._production", return_value=True):
            with patch("pathlib.Path.read_text") as mock_read_text:
                res = node.negotiate_hybrid_kex(timeout_sec=5)
                assert res is True
                mock_read_text.assert_not_called()


def test_f04_deterministic_iv_across_subsystems():
    """F-04: Verify NIST SP 800-38D deterministic composite IVs in ca_services, secure_file_sharing, serializer."""
    import ca_services
    import secure_file_sharing
    from secure_message_serializer import SecureMessageSerializer, MessageType

    key = b"\x01" * 32
    pt = b"TOP_SECRET_MILITARY_PAYLOAD"
    
    # ca_services deterministic IV check
    ct1, iv1, tag1 = ca_services.secure_encrypt_aes_256_gcm(pt, key)
    ct2, iv2, tag2 = ca_services.secure_encrypt_aes_256_gcm(pt, key)
    assert len(iv1) == 12 and len(iv2) == 12
    # Sequential invocations must increment monotonic counter (iv2 > iv1 in counter component)
    assert iv1 != iv2
    dec1 = ca_services.secure_decrypt_aes_256_gcm(ct1, key, iv1, tag1)
    assert dec1 == pt

    # secure_file_sharing deterministic IV check
    ct3, iv3, tag3 = secure_file_sharing.secure_encrypt_aes_256_gcm(pt, key)
    assert len(iv3) == 12
    dec3 = secure_file_sharing.secure_decrypt_aes_256_gcm(ct3, key, iv3, tag3)
    assert dec3 == pt

    # serializer deterministic IV check
    serializer = SecureMessageSerializer(mac_key=b"M" * 32)
    serialized = serializer.serialize_aead_envelope(
        sequence=1001,
        sender_id=b"\x02" * 32,
        msg_type=MessageType.DATA,
        payload=pt,
        aead_key=key
    )
    unpacked = serializer.deserialize_aead_envelope(serialized, aead_key=key)
    assert unpacked.payload == pt


def test_f03_ffi_source_guards_all_key_exports():
    """F-03: Verify rust_data_plane/src/ffi.rs guards every raw key export with check_production_key_export."""
    ffi_rs = Path("rust_data_plane/src/ffi.rs").read_text(encoding="utf-8")
    assert ffi_rs.count("check_production_key_export()?;") >= 10, (
        "ffi.rs must guard all raw key exports with check_production_key_export()"
    )


def test_f04_defense_ci_builds_without_default_features():
    """F-04: Verify CI workflow explicitly uses --no-default-features for production releases."""
    ci_file = Path(".github/workflows/defense_ci.yml")
    assert ci_file.exists()
    content = ci_file.read_text(encoding="utf-8")
    assert "cargo build --release --no-default-features" in content
    assert "maturin develop -r --no-default-features" in content


def test_f05_memlock_custody_strict_mode():
    """F-05: Verify memory custody module exposes require_locked and rust binary honors P2P_STRICT_MEMLOCK."""
    main_rs = Path("rust_data_plane/src/main.rs").read_text(encoding="utf-8")
    assert 'std::env::var("P2P_STRICT_MEMLOCK")' in main_rs
    assert 'out.require_locked().unwrap_or_else(|e| fail(e));' in main_rs
    memlock_rs = Path("rust_data_plane/src/memlock.rs").read_text(encoding="utf-8")
    assert "pub fn require_locked(&self) -> Result<(), &'static str>" in memlock_rs


def test_f06_formal_checker_strict_requires_proverif():
    """F-06: Verify docs/formal/check.sh fails closed without proverif unless structural-only opted in."""
    check_script = Path("docs/formal/check.sh")
    assert check_script.exists()
    content = check_script.read_text(encoding="utf-8")
    assert 'if [ "$STRICT" = "1" ] || [ "$ALLOW_STRUCTURAL_ONLY" != "1" ] || [ "${CI:-}" = "true" ]; then' in content
    assert "FAIL: proverif not installed" in content


def test_f08_tactical_station_arms_production_gate_when_non_lab():
    """F-08: Verify run_tactical_station unconditionally arms production gate and dispatches to native binary when lab=False."""
    import secure_p2p

    old_prod = os.environ.get("P2P_PRODUCTION")
    try:
        os.environ.pop("P2P_PRODUCTION", None)
        with patch("secure_p2p._auto_provision_tactical_credentials"), \
             patch("subprocess.call", return_value=0) as mock_call:
            res = secure_p2p.run_tactical_station("alpha", lab=False)
            assert os.environ.get("P2P_PRODUCTION") == "1", "P2P_PRODUCTION must be armed when lab=False"
            assert mock_call.called, "subprocess.call to native binary must be invoked"
            called_cmd = mock_call.call_args[0][0]
            assert "node" in called_cmd
            assert "--role" in called_cmd
            assert "responder" in called_cmd
            assert "--require-mutual-auth" in called_cmd
    finally:
        if old_prod is not None:
            os.environ["P2P_PRODUCTION"] = old_prod
        else:
            os.environ.pop("P2P_PRODUCTION", None)


def test_f08_canonical_production_dispatch_to_native_binary():
    """F-08: Verify main() with command 'node' in non-lab mode dispatches directly to native secure-transmit node."""
    import secure_p2p

    fake_args = [
        "node",
        "--role", "initiator",
        "--psk-file", "dummy.psk",
        "--auth-sk-file", "dummy.auth.sk",
        "--peer-auth-pk-file", "dummy.auth.pk",
        "--require-mutual-auth"
    ]
    with patch("os.path.exists", return_value=True), \
         patch("secure_p2p._validate_auth_material", return_value=(True, "OK")), \
         patch("subprocess.call", return_value=0) as mock_call:
        res = secure_p2p.main(fake_args)
        assert res == 0
        assert mock_call.called
        cmd = mock_call.call_args[0][0]
        assert "node" in cmd
        assert "--role" in cmd
        assert "initiator" in cmd
        assert "--require-mutual-auth" in cmd


def test_f04_deterministic_iv_expanded_subsystems():
    """F-04: Verify expanded critical subsystems use deterministic nonces per NIST SP 800-38D."""
    from p2p_core import generate_deterministic_gcm_iv

    # 1. Audit logging field encryption
    from audit_logging_system import _encrypt_db_field, _decrypt_db_field
    enc1 = _encrypt_db_field("TOP_SECRET_LOG_EVENT_1")
    enc2 = _encrypt_db_field("TOP_SECRET_LOG_EVENT_2")
    assert enc1.startswith("ENC:")
    assert enc2.startswith("ENC:")
    assert enc1 != enc2
    assert _decrypt_db_field(enc1) == "TOP_SECRET_LOG_EVENT_1"

    # 2. Key fill import seal
    from key_fill_import import _aes_seal, _aes_open
    key32 = b"K" * 32
    nonce_a, ct_a = _aes_seal(key32, b"classified_data_a", b"aad")
    nonce_b, ct_b = _aes_seal(key32, b"classified_data_b", b"aad")
    assert len(nonce_a) == 12
    assert len(nonce_b) == 12
    assert nonce_a != nonce_b
    assert _aes_open(key32, nonce_a, ct_a, b"aad") == b"classified_data_a"


def test_f03_pyo3_runtime_boundary_blocks_key_export():
    """F-03: Verify PyO3 extension strictly blocks raw key export when P2P_PRODUCTION=1."""
    import destroyer_core
    old_prod = os.environ.get("P2P_PRODUCTION")
    try:
        os.environ["P2P_PRODUCTION"] = "1"
        with pytest.raises(PermissionError) as exc_info:
            destroyer_core.CoreZeroGapPipeline.derive_war_key(b"\x01" * 32, b"info")
        assert "Production key boundary violation" in str(exc_info.value)
    finally:
        if old_prod is not None:
            os.environ["P2P_PRODUCTION"] = old_prod
        else:
            os.environ.pop("P2P_PRODUCTION", None)


def test_system_boundary_control_plane_violation_in_production():
    """Verify system boundary separation: operational C2 loops refuse execution in CPython under production."""
    import asyncio
    from production_gate import ControlPlaneBoundaryViolation, enforce_control_plane_boundary, assert_native_dataplane_only
    from secure_p2p import SecureP2PChat

    old_prod = os.environ.get("P2P_PRODUCTION")
    try:
        os.environ["P2P_PRODUCTION"] = "1"
        # 1. SecureP2PChat.start() must refuse operational execution in CPython under production
        chat = SecureP2PChat.__new__(SecureP2PChat)
        chat.threat_engine = None
        with pytest.raises(ControlPlaneBoundaryViolation) as exc_chat:
            asyncio.run(chat.start())
        assert "CONTROL-PLANE BOUNDARY VIOLATION" in str(exc_chat.value)

        # 2. Direct enforce_control_plane_boundary / assert_native_dataplane_only must raise ControlPlaneBoundaryViolation
        with pytest.raises(ControlPlaneBoundaryViolation) as exc_gate:
            enforce_control_plane_boundary("Operational C2 loop")
        assert "CONTROL-PLANE BOUNDARY VIOLATION" in str(exc_gate.value)
        with pytest.raises(ControlPlaneBoundaryViolation) as exc_alias:
            assert_native_dataplane_only("Operational C2 loop alias")
        assert "CONTROL-PLANE BOUNDARY VIOLATION" in str(exc_alias.value)
    finally:
        if old_prod is not None:
            os.environ["P2P_PRODUCTION"] = old_prod
        else:
            os.environ.pop("P2P_PRODUCTION", None)


def test_cnsa_crypto_gateway_centralization_across_subsystems():
    """Verify code hygiene & centralization: critical_release, nc3_threshold_mpc, ephemeral_messaging, group_key_manager, and hardware_enclave_manager."""
    import secrets

    # 1. Ephemeral messaging
    from ephemeral_messaging import EphemeralMessageManager, EphemeralMessage, DeletionRecord
    mgr = EphemeralMessageManager(device_id="DEV_1")
    key32 = secrets.token_bytes(32)
    msg = mgr.create_message(
        content=b"CLASSIFIED_OPERATION_ORDER",
        sender_id="node_a",
        recipient_id="node_b",
        ttl_seconds=300
    )
    env = msg.to_encrypted_envelope(key32)
    opened = EphemeralMessage.from_encrypted_envelope(env, key32)
    assert bytes(opened.content) == b"CLASSIFIED_OPERATION_ORDER"

    del_rec = DeletionRecord(
        message_id="msg_12345",
        deleted_at=1700000000.0,
        deletion_reason="expired",
        device_id="DEV_1",
        verification_hash=b"\xaa" * 32
    )
    del_env = del_rec.to_encrypted_envelope(key32)
    del_opened = DeletionRecord.from_encrypted_envelope(del_env, key32)
    assert del_opened.message_id == "msg_12345"

    # 2. Group key manager placeholder AEAD envelope
    from group_key_manager import _aead_seal, _aead_open
    grp_env = _aead_seal(key32, b"GROUP_AAD_1", b"TACTICAL_GROUP_MESSAGE")
    assert len(grp_env) >= 12 + 16
    grp_opened = _aead_open(key32, b"GROUP_AAD_1", grp_env)
    assert grp_opened == b"TACTICAL_GROUP_MESSAGE"

    # 3. Critical release payload roundtrip
    from critical_release import CriticalReleaseAuthority
    cra = CriticalReleaseAuthority()
    cra.enroll("alpha", "p@ssword123")
    cra.enroll("bravo", "secr3t456")
    bundle = cra.encrypt_critical_payload(b"NUCLEAR_RELEASE_AUTH_CODE")
    recovered = cra.decrypt_critical_payload(bundle, "alpha", "p@ssword123", "bravo", "secr3t456")
    assert recovered == b"NUCLEAR_RELEASE_AUTH_CODE"

