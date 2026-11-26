#!/usr/bin/env python3
"""
Comprehensive Unit & Integration Test Suite for:
1. Runtime Memory Sanitization & Control-Plane Boundaries (CPython Immutable Bytes vs Native Rust)
2. Tactical Web Console Hardening (mTLS 1.3 CAC/PIV Smartcard, WebAuthn FIDO2 Level 3, CSP Level 3, Zero CDNs)
"""

import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import patch, MagicMock

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import production_gate
from production_gate import (
    ControlPlaneBoundaryViolation,
    enforce_control_plane_boundary,
    prohibit_python_key_transit,
)
import cnsa2_policy_engine
import secure_p2p
from tactical_web_console import (
    TacticalWebHandler,
    WebAuthnL3Manager,
    parse_and_validate_cac_piv_cert,
    ensure_cac_piv_mtls_credentials,
    create_mtls_server_context,
    PIV_AUTH_OID,
    _webauthn_manager,
)


class TestRuntimeMemoryBoundary(unittest.TestCase):
    """Test Suite for CPython Immutable Bytes Object Retention & Control-Plane Boundaries."""

    def setUp(self):
        production_gate.reset_for_tests()

    def tearDown(self):
        production_gate.reset_for_tests()

    def test_enforce_control_plane_boundary_production_rejection(self):
        """Verify enforce_control_plane_boundary raises in production."""
        with patch.dict(os.environ, {"P2P_PRODUCTION": "1"}):
            with self.assertRaises(ControlPlaneBoundaryViolation) as ctx:
                enforce_control_plane_boundary("test_transit")
            self.assertIn("CONTROL-PLANE BOUNDARY VIOLATION", str(ctx.exception))
            self.assertIn("secure-transmit node", str(ctx.exception))

    def test_enforce_control_plane_boundary_lab_permitted(self):
        """Verify enforce_control_plane_boundary permits lab execution when production is unset."""
        with patch.dict(os.environ, {"P2P_PRODUCTION": "0"}):
            # Should not raise
            enforce_control_plane_boundary("test_lab_transit")

    def test_prohibit_python_key_transit_production(self):
        """Verify prohibit_python_key_transit raises in production."""
        with patch.dict(os.environ, {"P2P_PRODUCTION": "1"}):
            with self.assertRaises(ControlPlaneBoundaryViolation) as ctx:
                prohibit_python_key_transit(b"\x00" * 32, "symmetric_key")
            self.assertIn("RUNTIME MEMORY BOUNDARY VIOLATION", str(ctx.exception))

    def test_prohibit_python_key_transit_lab(self):
        """Verify prohibit_python_key_transit permits lab execution when production is unset."""
        with patch.dict(os.environ, {"P2P_PRODUCTION": "0"}):
            # Should not raise
            prohibit_python_key_transit(b"\x00" * 32, "lab_key")

    def test_cnsa2_policy_engine_validate_control_plane_boundary(self):
        """Verify policy engine enforces control plane boundary."""
        engine = cnsa2_policy_engine.CNSA2PolicyEngine()
        with patch.dict(os.environ, {"P2P_PRODUCTION": "0"}):
            self.assertTrue(engine.validate_control_plane_boundary("lab_eval"))

        with patch.dict(os.environ, {"P2P_PRODUCTION": "1"}):
            with self.assertRaises(cnsa2_policy_engine.SecurityPolicyViolation):
                engine.validate_control_plane_boundary("operational_c2")

    def test_secure_p2p_terminal_production_refusal(self):
        """Verify secure_p2p.run_interactive_terminal returns 2 and refuses in production."""
        mock_args = MagicMock()
        mock_args.bind = "127.0.0.1"
        mock_args.peer = "127.0.0.1"
        mock_args.name = "ALPHA"
        with patch("secure_p2p._production", return_value=True):
            with self.assertRaises(SystemExit) as ctx:
                secure_p2p.run_interactive_terminal(mock_args, bind="127.0.0.1", peer="127.0.0.1", name="ALPHA")
            self.assertEqual(ctx.exception.code, 2)

    def test_secure_p2p_web_production_refusal(self):
        """Verify secure_p2p refuses web command when production gate is armed."""
        with patch("secure_p2p._production", return_value=True):
            code = secure_p2p.main(["web", "--lab"])
            self.assertEqual(code, 2)

    def test_native_rust_node_binary_exists_and_selftests(self):
        """Verify native Rust binary secure-transmit runs selftest cleanly."""
        bin_name = "secure-transmit.exe" if os.name == "nt" else "secure-transmit"
        exe_path = Path(f"rust_data_plane/target/debug/{bin_name}")
        if not exe_path.exists():
            exe_path = Path(f"rust_data_plane/target/release/{bin_name}")
        self.assertTrue(exe_path.exists(), f"Compiled binary not found: {exe_path}")

        res = subprocess.run(
            [str(exe_path), "selftest"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = res.stdout + res.stderr
        self.assertEqual(res.returncode, 0, f"Selftest failed: {output}")
        self.assertIn("selftest: aead-roundtrip ok", output)
        self.assertIn("zeroize-sp800-88 ok", output)

    def test_native_rust_node_help_and_argument_parsing(self):
        """Verify native Rust binary secure-transmit node subcommand argument handling."""
        bin_name = "secure-transmit.exe" if os.name == "nt" else "secure-transmit"
        exe_path = Path(f"rust_data_plane/target/debug/{bin_name}")
        if not exe_path.exists():
            exe_path = Path(f"rust_data_plane/target/release/{bin_name}")

        res = subprocess.run(
            [str(exe_path), "node", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = res.stdout + res.stderr
        self.assertEqual(res.returncode, 0)
        self.assertIn("secure-transmit node", output)
        self.assertIn("--role <initiator|responder>", output)
        self.assertIn("--psk-file", output)
        self.assertIn("--auth-sk-file", output)
        self.assertIn("--peer-auth-pk-file", output)


class TestCacPivMtls(unittest.TestCase):
    """Test Suite for CAC / PIV Smartcard Client Certificate Parsing & Validation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cert_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_credential_generation_and_validation(self):
        """Verify ensure_cac_piv_mtls_credentials generates valid DoD/PIV certs."""
        creds = ensure_cac_piv_mtls_credentials(self.cert_dir)
        ca_pem = Path(creds["ca_cert"])
        srv_cert = Path(creds["server_cert"])
        cli_cert = Path(creds["client_cert"])

        self.assertTrue(ca_pem.exists())
        self.assertTrue(srv_cert.exists())
        self.assertTrue(cli_cert.exists())

        # Read client cert DER and validate
        cli_obj = x509.load_pem_x509_certificate(cli_cert.read_bytes(), default_backend())
        cli_der = cli_obj.public_bytes(serialization.Encoding.DER)

        res = parse_and_validate_cac_piv_cert(cli_der)
        self.assertTrue(res["valid"])
        self.assertTrue(res["has_client_auth"])
        self.assertTrue(res["has_digital_signature"])
        self.assertTrue(res["has_piv_auth"])
        self.assertEqual(res["edipi"], "1098765432")
        self.assertIn("PIV Authentication", res["extensions"])

    def test_missing_piv_auth_oid_rejection(self):
        """Verify certificate lacking PIV Auth OID is flagged."""
        priv = ec.generate_private_key(ec.SECP384R1())
        pub = priv.public_key()
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "OPERATOR.WITHOUT.PIV.OID.1234567890"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(priv, hashes.SHA384(), default_backend())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        res = parse_and_validate_cac_piv_cert(der)
        self.assertFalse(res["valid"])
        self.assertIn("PIV Authentication", res["error"])

    def test_missing_digital_signature_rejection(self):
        """Verify certificate lacking digitalSignature key usage is flagged."""
        priv = ec.generate_private_key(ec.SECP384R1())
        pub = priv.public_key()
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "OPERATOR.NO.SIG.1234567890"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(
                x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(PIV_AUTH_OID), None)]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(priv, hashes.SHA384(), default_backend())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        res = parse_and_validate_cac_piv_cert(der)
        self.assertFalse(res["valid"])
        self.assertIn("digitalSignature", res["error"])

    def test_expired_certificate_rejection(self):
        """Verify expired certificate is flagged as invalid."""
        priv = ec.generate_private_key(ec.SECP384R1())
        pub = priv.public_key()
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "EXPIRED.OPERATOR.1234567890"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=10))
            .not_valid_after(datetime.now(timezone.utc) - timedelta(days=2))
            .add_extension(
                x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(PIV_AUTH_OID), None)]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(priv, hashes.SHA384(), default_backend())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        res = parse_and_validate_cac_piv_cert(der)
        self.assertFalse(res["valid"])
        self.assertIn("expired", res["error"].lower())

    def test_create_mtls_server_context(self):
        """Verify create_mtls_server_context enforces TLS 1.3 only and client auth."""
        creds = ensure_cac_piv_mtls_credentials(self.cert_dir)
        ctx = create_mtls_server_context(
            cafile=creds["ca_cert"],
            certfile=creds["server_cert"],
            keyfile=creds["server_key"],
        )
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(ctx.maximum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)


class TestWebAuthnL3Presence(unittest.TestCase):
    """Test Suite for W3C WebAuthn Level 3 / FIDO2 Hardware Presence & Verification."""

    def setUp(self):
        self.mgr = WebAuthnL3Manager()

    def test_challenge_issuance_and_single_use(self):
        """Verify challenge is URL-safe CSPRNG token (>=32 bytes) and single-use."""
        c = self.mgr.issue_challenge()
        self.assertTrue(len(c) >= 32)

        # Consume challenge
        assertion = self.mgr.create_mock_assertion(c, user_presence=True, user_verification=True)
        ok, reason, meta = self.mgr.verify_assertion(assertion)
        self.assertTrue(ok, f"Verification failed: {reason}")
        self.assertEqual(meta["tier"], "FIDO2_LEVEL_3_LAB_SIMULATED")

        # Second attempt with same challenge must be rejected (replay suppression)
        ok2, reason2, _ = self.mgr.verify_assertion(assertion)
        self.assertFalse(ok2)
        self.assertIn("Challenge not found", reason2)

    def test_missing_user_presence_rejected(self):
        """Verify assertion with UP=0 is rejected."""
        c = self.mgr.issue_challenge()
        assertion = self.mgr.create_mock_assertion(c, user_presence=False, user_verification=True)
        ok, reason, _ = self.mgr.verify_assertion(assertion)
        self.assertFalse(ok)
        self.assertIn("User Presence", reason)

    def test_missing_user_verification_rejected(self):
        """Verify assertion with UV=0 is rejected."""
        c = self.mgr.issue_challenge()
        assertion = self.mgr.create_mock_assertion(c, user_presence=True, user_verification=False)
        ok, reason, _ = self.mgr.verify_assertion(assertion)
        self.assertFalse(ok)
        self.assertIn("User Verification", reason)

    def test_monotonic_sign_count_authenticator_cloning_defense(self):
        """Verify non-increasing sign_count is detected as cloning attack and rejected."""
        c1 = self.mgr.issue_challenge()
        assertion1 = self.mgr.create_mock_assertion(c1, user_presence=True, user_verification=True, sign_count=10)
        ok1, _, meta1 = self.mgr.verify_assertion(assertion1)
        self.assertTrue(ok1)
        self.assertEqual(meta1["sign_count"], 10)

        # Subsequent assertion with same or lower sign_count must fail
        c2 = self.mgr.issue_challenge()
        assertion2 = self.mgr.create_mock_assertion(c2, user_presence=True, user_verification=True, sign_count=10)
        ok2, reason2, _ = self.mgr.verify_assertion(assertion2)
        self.assertFalse(ok2)
        self.assertIn("cloned token", reason2)

    def test_tampered_signature_rejected(self):
        """Verify signature verification detects tampered bytes."""
        c = self.mgr.issue_challenge()
        assertion = self.mgr.create_mock_assertion(c, user_presence=True, user_verification=True)

        # Corrupt signatures
        sig_raw = bytearray(base64.b64decode(assertion["signature"]))
        sig_raw[5] ^= 0xFF
        tampered_b64 = base64.b64encode(bytes(sig_raw)).decode("ascii")
        assertion["signature"] = tampered_b64
        assertion["signature_b64"] = tampered_b64

        ok, reason, _ = self.mgr.verify_assertion(assertion)
        self.assertFalse(ok)
        self.assertIn("verification failed", reason.lower())


class TestWebConsoleSecurityHeadersAndEndpoints(unittest.TestCase):
    """Test Suite for Content Security Policy Level 3 & Mutating Endpoint Auth Gates."""

    def _create_handler(self, method: str, path: str, body: dict = None, require_webauthn: bool = False):
        body_bytes = json.dumps(body or {}).encode("utf-8")
        rfile = BytesIO(body_bytes)
        wfile = BytesIO()

        with patch.object(TacticalWebHandler, "setup"), patch.object(TacticalWebHandler, "finish"):
            handler = TacticalWebHandler.__new__(TacticalWebHandler)
            handler.rfile = rfile
            handler.wfile = wfile
            handler.command = method
            handler.path = path
            handler.requestline = f"{method} {path} HTTP/1.1"
            handler.request_version = "HTTP/1.1"
            handler.client_address = ("127.0.0.1", 12345)
            handler.log_request = lambda *args, **kwargs: None
            handler.log_error = lambda *args, **kwargs: None
            handler.headers = {
                "Content-Length": str(len(body_bytes)),
                "Content-Type": "application/json"
            }
            # mock server attribute
            mock_server = MagicMock()
            mock_server.require_webauthn = require_webauthn
            handler.server = mock_server
            return handler, wfile

    def _parse_response(self, wfile: BytesIO) -> tuple[int, dict, str]:
        wfile.seek(0)
        raw = wfile.getvalue().decode("utf-8")
        parts = raw.split("\r\n\r\n", 1)
        headers = parts[0]
        body = json.loads(parts[1]) if len(parts) > 1 and parts[1] else {}
        status_line = headers.split("\r\n")[0]
        status_code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 200
        return status_code, body, headers

    def test_strict_csp_level_3_headers(self):
        """Verify strict Content Security Policy Level 3 is emitted on responses."""
        handler, wfile = self._create_handler("GET", "/api/status")
        handler._handle_api_status()
        _, _, headers = self._parse_response(wfile)
        self.assertIn("Content-Security-Policy", headers)
        self.assertIn("object-src 'none'", headers)
        self.assertIn("default-src 'self'", headers)
        self.assertIn("frame-ancestors 'none'", headers)

    def test_api_status_profiles(self):
        """Verify GET /api/status exposes mTLS, WebAuthn L3, and CSP profiles."""
        handler, wfile = self._create_handler("GET", "/api/status")
        handler._handle_api_status()
        _, body, _ = self._parse_response(wfile)
        self.assertIn("mtls_profile", body)
        self.assertEqual(body["mtls_profile"]["tls_version"], "TLSv1.3")
        self.assertIn("webauthn_profile", body)
        self.assertIn("FIDO2 Level 3", body["webauthn_profile"]["level"])
        self.assertIn("csp_profile", body)
        self.assertIn("object-src 'none'", body["csp_profile"]["policy"])

    def test_mutating_endpoints_refuse_unauthenticated_in_strict_mode(self):
        """Verify mutating endpoints return 403 when WebAuthn is required and missing."""
        endpoints = [
            ("send", {"sender": "NORAD_ALPHA", "message": "TEST"}),
            ("zgdp", {"message": "DIAGNOSTIC"}),
            ("cot", {"callsign": "VIPER"}),
            ("diode_send", {"fileName": "DATA.BIN"}),
            ("zeroize", {"confirm": "CONFIRM_TACTICAL_ZEROIZE_NOW"}),
        ]
        for name, payload in endpoints:
            handler, wfile = self._create_handler("POST", f"/api/{name}", payload, require_webauthn=True)
            method = getattr(handler, f"_handle_api_{name}")
            method(payload)
            code, body, _ = self._parse_response(wfile)
            self.assertEqual(code, 403, f"Endpoint {name} did not return 403: {body}")
            self.assertEqual(body.get("status"), "WEBAUTHN_L3_VERIFICATION_REQUIRED")

    def test_mutating_endpoints_accept_valid_webauthn_assertion(self):
        """Verify mutating endpoints succeed when valid WebAuthn L3 assertion is attached."""
        c = _webauthn_manager.issue_challenge()
        assertion = _webauthn_manager.create_mock_assertion(c, user_presence=True, user_verification=True)

        payload = {
            "sender": "NORAD_ALPHA",
            "message": "DEFCON-1 AUTHENTICATED",
            "webauthn_assertion": assertion,
        }
        handler, wfile = self._create_handler("POST", "/api/send", payload, require_webauthn=True)
        handler._handle_api_send(payload)
        code, body, _ = self._parse_response(wfile)
        self.assertEqual(code, 200)
        self.assertEqual(body.get("status"), "TRANSMITTED_SIMULATED")
        self.assertTrue(body.get("webauthn_l3_verified"))

    def test_zero_external_cdns_audit(self):
        """Verify that tactical_web/index.html contains zero external CDN dependencies."""
        index_html_path = Path("tactical_web/index.html")
        self.assertTrue(index_html_path.exists())
        content = index_html_path.read_text(encoding="utf-8")

        prohibited_cdns = [
            "cdnjs.cloudflare.com",
            "cdn.jsdelivr.net",
            "unpkg.com",
            "fonts.googleapis.com",
            "ajax.googleapis.com",
            "code.jquery.com",
            "cdn.tailwindcss.com",
            "stackpath.bootstrapcdn.com",
        ]
        for cdn in prohibited_cdns:
            self.assertNotIn(cdn, content, f"External CDN dependency detected: {cdn}")

    def test_ensure_cac_piv_mtls_credentials_with_string_path(self):
        """Verify ensure_cac_piv_mtls_credentials functions with string paths."""
        with tempfile.TemporaryDirectory() as td:
            creds = ensure_cac_piv_mtls_credentials(td)
            for k in ["ca_cert", "server_cert", "server_key", "client_cert", "client_key"]:
                self.assertIn(k, creds)
                self.assertTrue(os.path.exists(creds[k]), f"Missing credential file: {creds[k]}")

    def test_native_rust_node_loopback_e2e_communication(self):
        """Verify two standalone native secure-transmit node processes communicate via UDP."""
        bin_name = "secure-transmit.exe" if os.name == "nt" else "secure-transmit"
        exe_path = Path(f"rust_data_plane/target/release/{bin_name}")
        if not exe_path.exists():
            exe_path = Path(f"rust_data_plane/target/debug/{bin_name}")
        self.assertTrue(exe_path.exists(), f"Compiled binary not found: {exe_path}")

        with tempfile.TemporaryDirectory() as td:
            psk_path = os.path.join(td, "shared.key")
            with open(psk_path, "wb") as f:
                f.write(b"42" * 32 + b"\n")
            try:
                os.chmod(psk_path, 0o600)
            except OSError:
                pass
            resp_sk = os.path.join(td, "resp.sk")
            resp_pk = os.path.join(td, "resp.pk")
            init_sk = os.path.join(td, "init.sk")
            init_pk = os.path.join(td, "init.pk")
            subprocess.run([str(exe_path), "auth-keygen", "--out-sk", resp_sk, "--out-pk", resp_pk], check=True, capture_output=True)
            subprocess.run([str(exe_path), "auth-keygen", "--out-sk", init_sk, "--out-pk", init_pk], check=True, capture_output=True)

            # Responder: listen on free ports (mutual ML-DSA-87 auth)
            import socket as _sock, threading as _thr
            def _free_port():
                for _ in range(50):
                    with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as st:
                        st.bind(("127.0.0.1", 0))
                        p = st.getsockname()[1]
                    try:
                        with _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM) as su:
                            su.bind(("127.0.0.1", p))
                        return p
                    except OSError:
                        continue
                raise RuntimeError("No free dual TCP/UDP port found")
            p_r = _free_port()
            p_i = _free_port()
            while p_i == p_r:
                p_i = _free_port()

            cmd_resp = [
                str(exe_path), "node", "--role", "responder",
                "--bind", f"127.0.0.1:{p_r}", "--to", f"127.0.0.1:{p_i}",
                "--psk-file", psk_path,
                "--auth-sk-file", resp_sk, "--peer-auth-pk-file", init_pk,
                "--require-mutual-auth",
                "--state", os.path.join(td, "resp.state"),
                "--headless", "--recv-count", "1", "--interval-ms", "20", "--timeout-ms", "15000"
            ]

            # Initiator: connect and send payload only once both UDP channels are ACTIVE
            cmd_init = [
                str(exe_path), "node", "--role", "initiator",
                "--bind", f"127.0.0.1:{p_i}", "--to", f"127.0.0.1:{p_r}",
                "--psk-file", psk_path,
                "--auth-sk-file", init_sk, "--peer-auth-pk-file", resp_pk,
                "--require-mutual-auth",
                "--state", os.path.join(td, "init.state"),
                "--headless", "--stdin", "--interval-ms", "20", "--timeout-ms", "15000"
            ]

            p_resp = subprocess.Popen(cmd_resp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            resp_lines: list[str] = []
            resp_listening = _thr.Event()
            resp_active = _thr.Event()
            resp_got_msg = _thr.Event()

            def _pump_resp():
                for line in p_resp.stdout:
                    resp_lines.append(line)
                    if "[KEX] Listening" in line:
                        resp_listening.set()
                    if "channel: ACTIVE" in line:
                        resp_active.set()
                    if "RECV_MSG" in line:
                        resp_got_msg.set()

            tr = _thr.Thread(target=_pump_resp, daemon=True)
            tr.start()
            self.assertTrue(resp_listening.wait(timeout=10.0), f"Responder KEX did not start listening: {''.join(resp_lines)}")
            time.sleep(0.25)

            p_init = subprocess.Popen(cmd_init, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            init_lines: list[str] = []
            init_active = _thr.Event()

            def _pump_init():
                for line in p_init.stdout:
                    init_lines.append(line)
                    if "channel: ACTIVE" in line:
                        init_active.set()

            ti = _thr.Thread(target=_pump_init, daemon=True)
            ti.start()

            if not resp_active.wait(timeout=15.0):
                p_init.kill()
                p_resp.kill()
                _, e_i = p_init.communicate(timeout=5)
                _, e_r = p_resp.communicate(timeout=5)
                self.fail(f"Responder channel did not become ACTIVE\nRESP OUT: {''.join(resp_lines)}\nRESP ERR: {e_r}\nINIT OUT: {''.join(init_lines)}\nINIT ERR: {e_i}")
            if not init_active.wait(timeout=15.0):
                p_init.kill()
                p_resp.kill()
                _, e_i = p_init.communicate(timeout=5)
                _, e_r = p_resp.communicate(timeout=5)
                self.fail(f"Initiator channel did not become ACTIVE\nINIT OUT: {''.join(init_lines)}\nINIT ERR: {e_i}")
            p_init.stdin.write("ALPHA-BRAVO-VERIFIED\n")
            p_init.stdin.flush()
            self.assertTrue(resp_got_msg.wait(timeout=10.0), f"Responder did not receive message: {''.join(resp_lines)}")
            p_init.stdin.write("/zeroize\n")
            p_init.stdin.flush()

            _, err_i = p_init.communicate(timeout=15)
            _, err_r = p_resp.communicate(timeout=15)
            tr.join(timeout=2)
            ti.join(timeout=2)
            out_i = "".join(init_lines)
            out_r = "".join(resp_lines)

            self.assertEqual(p_init.returncode, 0, f"Initiator failed: {err_i}")
            self.assertEqual(p_resp.returncode, 0, f"Responder failed: {err_r}")
            self.assertIn("EMIT_MSG", out_i)
            self.assertIn("RECV_MSG", out_r)
            self.assertIn("ALPHA-BRAVO-VERIFIED", out_r)


if __name__ == "__main__":
    unittest.main()
