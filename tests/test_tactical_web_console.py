#!/usr/bin/env python3
"""
Unit tests for Tactical Web Command Center API handlers.
Verifies /api/status, /api/eam, /api/zgdp, /api/cot, and simplex diode endpoints.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
from io import BytesIO
from tactical_web_console import TacticalWebHandler


class DummyRequest:
    def makefile(self, *args, **kwargs):
        return BytesIO(b"")


class TestTacticalWebConsole(unittest.TestCase):
    """Test suite for TacticalWebHandler REST endpoints."""

    def _create_handler(self, method: str, path: str, body: dict = None):
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
            return handler, wfile

    def _parse_response(self, wfile: BytesIO) -> dict:
        wfile.seek(0)
        raw = wfile.getvalue().decode("utf-8")
        # Split HTTP headers and body
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) > 1:
            return json.loads(parts[1])
        return json.loads(raw)

    def test_api_status_endpoint(self):
        """Verify GET /api/status returns valid telemetry and PCR measurements."""
        handler, wfile = self._create_handler("GET", "/api/status")
        handler._handle_api_status()
        data = self._parse_response(wfile)
        self.assertEqual(data.get("status"), "ARMED_PACED")
        self.assertIn("pcr_0", data)
        self.assertIn("cnsa_suite", data)

    def test_api_sovereignty_endpoint(self):
        """Verify GET /api/sovereignty returns zero-trust matrix."""
        handler, wfile = self._create_handler("GET", "/api/sovereignty")
        handler._handle_api_sovereignty()
        data = self._parse_response(wfile)
        self.assertIn("vectors", data)
        self.assertTrue(len(data["vectors"]) >= 4)

    def test_api_send_endpoint(self):
        """Verify POST /api/send formats classified chat cell."""
        handler, wfile = self._create_handler("POST", "/api/send", {
            "sender": "NORAD_ALPHA",
            "message": "DEFCON-1 STATUS CONFIRMED"
        })
        handler._handle_api_send({"sender": "NORAD_ALPHA", "message": "DEFCON-1 STATUS CONFIRMED"})
        data = self._parse_response(wfile)
        self.assertEqual(data.get("status"), "TRANSMITTED_SIMULATED")
        self.assertTrue(data.get("simulated"))
        self.assertIn("PENTAGON_BRAVO", data.get("reply", ""))

    def test_api_eam_rejects_bare_signature_strings(self):
        """A4-09: mere signature strings must NOT be claimed as verified 2-of-2.

        The old handler marked any two string fields '2-OF-2_VERIFIED'. The
        hardened handler reports an explicit simulated fixture unless a
        complete, cryptographically valid ML-DSA-87 custody package is given.
        """
        directive = "DEFCON-1 AUTHORIZE STRATCOM STRIKE PACKAGE CHARLIE"
        payload = {
            "originator": "NORAD_ALPHA",
            "directive": directive,
            "officer_1_sig": "SIG_OFFICER_ALPHA_TEST",
            "officer_2_sig": "SIG_OFFICER_BRAVO_TEST"
        }
        handler, wfile = self._create_handler("POST", "/api/eam", payload)
        handler._handle_api_eam(payload)
        data = self._parse_response(wfile)
        self.assertEqual(data.get("status"), "EAM_SIMULATED_DEMO_FIXTURE")
        self.assertTrue(data.get("simulated"))
        self.assertFalse(data.get("dual_custody", "").startswith("2-OF-2"))
        self.assertEqual(
            data.get("dual_custody"), "UNVERIFIED_NO_CUSTODY_PACKAGE_SUPPLIED"
        )
        self.assertTrue(len(data.get("authenticator_sha3_512", "")) == 128)

    def test_api_eam_rejects_incomplete_custody_package(self):
        """A4-09: partial custody packages are rejected, not silently verified."""
        payload = {
            "originator": "NORAD_ALPHA",
            "directive": "DEFCON-2 ORDER",
            "officer_1_id": "OFFICER_ALPHA",
            "officer_1_sig_b64": "AAAA",
        }
        handler, wfile = self._create_handler("POST", "/api/eam", payload)
        handler._handle_api_eam(payload)
        data = self._parse_response(wfile)
        self.assertEqual(data.get("status"), "EAM_REJECTED_INCOMPLETE_CUSTODY_PACKAGE")
        self.assertEqual(data.get("dual_custody"), "REJECTED_INCOMPLETE")

    def test_api_zgdp_telemetry_endpoint(self):
        """Verify POST /api/zgdp executes live pipeline roundtrip."""
        handler, wfile = self._create_handler("POST", "/api/zgdp", {
            "message": "TACTICAL_TELEMETRY_SAMPLE"
        })
        handler._handle_api_zgdp({"message": "TACTICAL_TELEMETRY_SAMPLE"})
        data = self._parse_response(wfile)
        self.assertEqual(data.get("status"), "ZGDP_ROUNDTRIP_VERIFIED")
        self.assertTrue(data.get("decrypted_matches"))
        self.assertEqual(data.get("cadence_ms"), 15)

    def test_api_cot_beacon_endpoint(self):
        """Verify POST /api/cot generates signed CoT event."""
        handler, wfile = self._create_handler("POST", "/api/cot", {
            "callsign": "RAPTOR_01",
            "lat": 38.8719,
            "lon": -77.0563
        })
        handler._handle_api_cot({"callsign": "RAPTOR_01", "lat": 38.8719, "lon": -77.0563})
        data = self._parse_response(wfile)
        self.assertEqual(data.get("status"), "COT_EMITTED")
        self.assertEqual(data.get("callsign"), "RAPTOR_01")

    def test_disa_stig_security_headers(self):
        """Verify that DISA ASD STIG compliant security headers are emitted on responses."""
        handler, wfile = self._create_handler("GET", "/api/status")
        handler._handle_api_status()
        raw = wfile.getvalue().decode("utf-8")
        headers_raw = raw.split("\r\n\r\n", 1)[0]
        
        self.assertIn("Content-Security-Policy: default-src 'self'", headers_raw)
        self.assertIn("frame-ancestors 'none'", headers_raw)
        self.assertIn("X-Frame-Options: DENY", headers_raw)
        self.assertIn("X-Content-Type-Options: nosniff", headers_raw)
        self.assertIn("Strict-Transport-Security: max-age=63072000; includeSubDomains; preload", headers_raw)
        self.assertIn("Referrer-Policy: strict-origin-when-cross-origin", headers_raw)
        self.assertIn("Cache-Control: no-store, no-cache, must-revalidate, private", headers_raw)

    def test_webauthn_register_requires_auth_and_csrf_referer_and_drill_gated(self):
        """Unauthenticated WebAuthn registration fails closed (403); CSRF Referer rejected; /api/drill gated."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import tactical_web_console as twc

        pub_pem = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("utf-8")
        )
        # Missing bootstrap token / admin assertion -> 403
        handler, wfile = self._create_handler(
            "POST",
            "/api/auth/webauthn/register",
            {"credential_id": "rogue-cred", "public_key_pem": pub_pem},
        )
        handler._handle_api_webauthn_register({"credential_id": "rogue-cred", "public_key_pem": pub_pem})
        data = self._parse_response(wfile)
        self.assertEqual(data.get("status"), "WEBAUTHN_ENROLLMENT_UNAUTHORIZED")

        # Valid registration_token succeeds
        handler_ok, wfile_ok = self._create_handler("POST", "/api/auth/webauthn/register", {})
        handler_ok._handle_api_webauthn_register({
            "credential_id": f"auth-cred-{hash(pub_pem)}",
            "public_key_pem": pub_pem,
            "registration_token": twc._webauthn_manager._registration_token,
        })
        self.assertEqual(self._parse_response(wfile_ok).get("status"), "KEY_REGISTERED")

        # Cross-origin Referer blocked on do_POST
        handler_csrf, wfile_csrf = self._create_handler("POST", "/api/cot", {"callsign": "X"})
        handler_csrf.headers["Referer"] = "https://attacker.invalid/csrf.html"
        handler_csrf.do_POST()
        self.assertIn("Cross-origin Referer", self._parse_response(wfile_csrf).get("error", ""))

        # /api/drill enforces WebAuthn gate when server.require_webauthn=True
        handler_drill, wfile_drill = self._create_handler("POST", "/api/drill", {})
        handler_drill.server = MagicMock(require_webauthn=True)
        handler_drill._handle_api_drill({})
        self.assertEqual(self._parse_response(wfile_drill).get("status"), "WEBAUTHN_L3_VERIFICATION_REQUIRED")



if __name__ == "__main__":
    unittest.main()

