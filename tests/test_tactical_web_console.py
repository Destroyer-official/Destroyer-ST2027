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
        self.assertEqual(data.get("status"), "TRANSMITTED")
        self.assertIn("PENTAGON_BRAVO", data.get("reply", ""))

    def test_api_eam_nuclear_directive_endpoint(self):
        """Verify POST /api/eam seals emergency directive under Two-Person Integrity."""
        directive = "DEFCON-1 AUTHORIZE STRATCOM STRIKE PACKAGE CHARLIE"
        handler, wfile = self._create_handler("POST", "/api/eam", {
            "originator": "NORAD_ALPHA",
            "directive": directive
        })
        handler._handle_api_eam({"originator": "NORAD_ALPHA", "directive": directive})
        data = self._parse_response(wfile)
        self.assertEqual(data.get("status"), "EAM_RELEASED_AND_SEALED")
        self.assertEqual(data.get("dual_custody"), "2-OF-2_VERIFIED")
        self.assertEqual(data.get("validity_seconds"), 120.0)
        self.assertTrue(len(data.get("authenticator_sha3_512", "")) == 128)

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


if __name__ == "__main__":
    unittest.main()
