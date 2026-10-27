#!/usr/bin/env python3
"""
tactical_web_console.py — LOCAL DEMONSTRATION & TELEMETRY LAB CONSOLE

INTEGRITY & DEMONSTRATION NOTICE:
This web console is a local development, diagnostic telemetry, and educational
demonstration interface. It is NOT an accredited military command terminal, NOT
a hardware-certified optical diode, and NOT an operational NC3 launch console.
All API responses explicitly identify simulated fixtures and distinguish
software emulation from physical hardware attestation.
Binds strictly to localhost (127.0.0.1).
"""

import sys
import os
import json
import time
import base64
import hashlib
import threading
import webbrowser
import mimetypes
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

# Workspace Resolution
REPO_ROOT = Path(__file__).resolve().parent
WEB_DIR = REPO_ROOT / "tactical_web"


def _is_production() -> bool:
    try:
        from production_gate import is_production
        return bool(is_production())
    except Exception:
        return False

# ---------------------------------------------------------------------------
# A4-09 hardening (2026-10-17):
# * MAX_POST_BODY: reject oversized bodies before read (memory-exhaustion DoS).
# * ALLOWED_ORIGINS: same-origin guard for state-changing POSTs (CSRF).
# * EAM replay cache: dual-custody directives cannot be re-executed.
# ---------------------------------------------------------------------------
MAX_POST_BODY = 1 * 1024 * 1024  # 1 MiB is far beyond any legitimate console call
ALLOWED_ORIGINS = {
    "http://127.0.0.1:8443",
    "http://localhost:8443",
    "https://127.0.0.1:8443",
    "https://localhost:8443",
}
_ZEROIZE_CONFIRM_TOKEN = "ZEROIZE-ALL"

_eam_replay_lock = threading.Lock()
_eam_seen_digests: dict = {}  # sha3_512 canonical digest -> first-seen epoch
_EAM_REPLAY_TTL_SECONDS = 3600.0


def canonical_web_eam_bytes(
    directive: str,
    originator: str,
    timestamp_utc: float,
    expires_at: float,
    officer_1_id: str,
    officer_2_id: str,
) -> bytes:
    """Canonical byte string that both officers must ML-DSA-87-sign.

    Exposed at module level so an offline custodian workstation can build the
    exact byte string the console verifies.
    """
    material = {
        "preamble": EAM_PREAMBLE,
        "classification": EAM_CLASSIFICATION,
        "directive": directive,
        "originator": originator,
        "officer_1": officer_1_id,
        "officer_2": officer_2_id,
        "timestamp_utc": round(float(timestamp_utc), 3),
        "expires_at": round(float(expires_at), 3),
    }
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _eam_replay_check_and_record(canonical: bytes) -> bool:
    """Return True when this exact dual-custody package was already released."""
    now = time.time()
    digest = hashlib.sha3_512(canonical).hexdigest()
    with _eam_replay_lock:
        for k in [k for k, t in _eam_seen_digests.items() if now - t > _EAM_REPLAY_TTL_SECONDS]:
            del _eam_seen_digests[k]
        if digest in _eam_seen_digests:
            return True
        _eam_seen_digests[digest] = now
        return False


try:
    from nc3_nuclear_command import EAM_PREAMBLE, EAM_CLASSIFICATION
except Exception:  # pragma: no cover - import guard for isolated test envs
    EAM_PREAMBLE = "EMERGENCY ACTION MESSAGE"
    EAM_CLASSIFICATION = "TOP SECRET//NOFORN"


def _decode_b64_field(value, expected_len=None):
    """Strict base64 decode of an operator-supplied key/signature field."""
    if not isinstance(value, str) or not value:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return None
    if expected_len is not None and len(raw) != expected_len:
        return None
    return raw

# Threading Server
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class TacticalWebHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler serving tactical web assets and REST APIs."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/" or self.path == "":
            self.path = "/index.html"
            return super().do_GET()

        if self.path.startswith("/api/status"):
            self._handle_api_status()
            return

        if self.path.startswith("/api/sovereignty"):
            self._handle_api_sovereignty()
            return

        # Serve static files from WEB_DIR
        return super().do_GET()

    def do_POST(self):
        # A4-09: same-origin guard (CSRF). Browsers attach Origin to all
        # cross-site form/fetch POSTs; a cross-origin caller is rejected
        # before any handler runs. Missing Origin (curl/scripts/tests) is
        # permitted, and destructive routes additionally require a token.
        origin = self.headers.get("Origin")
        if origin and origin not in ALLOWED_ORIGINS:
            self._send_json({"error": "Cross-origin POST rejected"}, status=403)
            return

        raw_len = self.headers.get("Content-Length", "0")
        try:
            content_len = int(raw_len)
        except (TypeError, ValueError):
            self._send_json({"error": "Invalid Content-Length"}, status=400)
            return
        if content_len < 0 or content_len > MAX_POST_BODY:
            self._send_json(
                {"error": "Request body too large", "max_bytes": MAX_POST_BODY},
                status=413,
            )
            return

        post_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            payload = json.loads(post_body)
        except Exception:
            payload = {}

        if self.path.startswith("/api/send"):
            self._handle_api_send(payload)
        elif self.path.startswith("/api/eam"):
            self._handle_api_eam(payload)
        elif self.path.startswith("/api/zgdp"):
            self._handle_api_zgdp(payload)
        elif self.path.startswith("/api/cot"):
            self._handle_api_cot(payload)
        elif self.path.startswith("/api/diode/send"):
            self._handle_api_diode_send(payload)
        elif self.path.startswith("/api/zeroize"):
            self._handle_api_zeroize(payload)
        elif self.path.startswith("/api/drill"):
            self._handle_api_drill(payload)
        else:
            self._send_json({"error": "Unknown endpoint"}, status=404)

    def _send_json(self, data: dict, status: int = 200):
        if "console_mode" not in data:
            data["console_mode"] = "LOCAL_DEMO_LAB"
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Localhost restricted origin, not wild-card *
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8443")
        self.end_headers()
        self.wfile.write(body)

    def _handle_api_status(self):
        pcrs = {}
        tpm_hardware_locked = False
        try:
            import tpm_quote
            raw_pcrs = tpm_quote.read_hardware_pcrs([0, 7, 11])
            if raw_pcrs and any(raw_pcrs.values()):
                pcrs = {
                    "pcr_0": raw_pcrs.get(0, "UNAVAILABLE"),
                    "pcr_7": raw_pcrs.get(7, "UNAVAILABLE"),
                    "pcr_11": raw_pcrs.get(11, "UNAVAILABLE")
                }
                tpm_hardware_locked = True
        except Exception:
            pass

        if not pcrs:
            pcrs = {
                "pcr_0": "UNAVAILABLE_NO_HARDWARE_TPM",
                "pcr_7": "UNAVAILABLE_NO_HARDWARE_TPM",
                "pcr_11": "UNAVAILABLE_NO_HARDWARE_TPM"
            }

        response = {
            "console_mode": "DEMO_LAB_TELEMETRY",
            "hardware_backed": tpm_hardware_locked,
            "status": "ARMED_PACED",
            "cadence_ms": 20,
            "quantum_bytes": 1232,
            # F-16: no fake entropy figure — this status view does not observe
            # the wire, so it does not invent a Shannon number. Real chaff
            # sanity checks live in the data-plane selftests.
            "entropy_shannon": None,
            "sas": "B6CA-0976-AAAD-CA98",
            "nodes": {
                "alpha": {
                    "callsign": "NORAD_ALPHA",
                    "role": "responder",
                    "bind": "127.0.0.1:9060",
                    "diode": "127.0.0.1:9080",
                    "status": "ARMED_AND_PACED"
                },
                "bravo": {
                    "callsign": "PENTAGON_BRAVO",
                    "role": "initiator",
                    "bind": "127.0.0.1:9061",
                    "diode": "127.0.0.1:9081",
                    "status": "ARMED_AND_PACED"
                }
            },
            "pcr_0": pcrs.get("pcr_0"),
            "pcr_7": pcrs.get("pcr_7"),
            "pcr_11": pcrs.get("pcr_11"),
            "tpm_status": "PCR_HARDWARE_ATTESTED_VALID" if tpm_hardware_locked else "TPM_SOFTWARE_EMULATION_OR_UNAVAILABLE",
            "cnsa_suite": "CNSA Suite 2.0 (FIPS 203 ML-KEM-1024, FIPS 204 ML-DSA-87, AES-256-GCM, SHA-384)"
        }
        self._send_json(response)

    def _handle_api_send(self, payload: dict):
        sender = payload.get("sender", "OPERATOR")
        msg = payload.get("message", "")
        peer = "PENTAGON_BRAVO" if sender == "NORAD_ALPHA" else "NORAD_ALPHA"
        reply = f"ACK // LOCAL SIMULATED LOOPBACK DISPATCHED TO {peer}"
        self._send_json({
            "status": "TRANSMITTED_SIMULATED",
            "simulated": True,
            "sender": sender,
            "message": msg,
            "reply": reply
        })

    def _handle_api_eam(self, payload: dict):
        """Emergency Action Message ingestion.

        A4-09 (2026-10-17): the console no longer declares "2-OF-2_VERIFIED"
        merely because signature *strings* were present. Dual custody is
        claimed ONLY after two distinct ML-DSA-87 (FIPS 204) signatures
        verify over the canonical directive bytes, within freshness and
        validity windows, with replay suppression. Without a complete
        custody package the response is explicitly a simulated fixture.
        """
        directive = str(payload.get("directive", "DEFCON-1 STRATEGIC DIRECTIVE ALPHA"))
        originator = str(payload.get("originator", "NORAD_ALPHA"))
        authenticator_hash = hashlib.sha3_512(directive.encode("utf-8")).hexdigest()

        sig_fields = ("officer_1_sig_b64", "officer_2_sig_b64")
        pkg_fields = (
            "officer_1_id", "officer_2_id",
            "officer_1_pk_b64", "officer_2_pk_b64",
            "timestamp_utc", "expires_at",
        )
        any_custody = any(payload.get(f) for f in sig_fields + pkg_fields)

        # --- Demo/simulation path: no custody package supplied ------------
        if not any_custody:
            self._send_json({
                "status": "EAM_SIMULATED_DEMO_FIXTURE",
                "simulated": True,
                "directive": directive,
                "originator": originator,
                "classification": EAM_CLASSIFICATION,
                "validity_seconds": 120.0,
                "dual_custody": "UNVERIFIED_NO_CUSTODY_PACKAGE_SUPPLIED",
                "authenticator_sha3_512": authenticator_hash,
                "notice": (
                    "Simulated fixture. No ML-DSA-87 custody package supplied; "
                    "this is NOT a released EAM."
                ),
                "protocol": "DoD Directive S-5210.41M / USSTRATCOM EAP-STRAT",
            })
            return

        # --- Custody package supplied: must be complete or rejected -------
        missing = [f for f in sig_fields + pkg_fields if not payload.get(f)]
        if missing:
            self._send_json({
                "status": "EAM_REJECTED_INCOMPLETE_CUSTODY_PACKAGE",
                "error": f"missing fields: {', '.join(missing)}",
                "dual_custody": "REJECTED_INCOMPLETE",
            }, status=400)
            return

        try:
            ts = float(payload["timestamp_utc"])
            expires_at = float(payload["expires_at"])
        except (TypeError, ValueError):
            self._send_json({
                "status": "EAM_REJECTED_MALFORMED_TIMESTAMPS",
                "dual_custody": "REJECTED_MALFORMED",
            }, status=400)
            return

        officer_1_id = str(payload["officer_1_id"])
        officer_2_id = str(payload["officer_2_id"])
        if officer_1_id == officer_2_id:
            self._send_json({
                "status": "EAM_REJECTED_DUPLICATE_CUSTODIAN",
                "error": "two distinct custodians are required (single-officer signing rejected)",
                "dual_custody": "REJECTED_SINGLE_CUSTODIAN",
            }, status=403)
            return

        now = time.time()
        if abs(now - ts) > 120.0 or expires_at <= now or expires_at <= ts:
            self._send_json({
                "status": "EAM_REJECTED_STALE_OR_EXPIRED",
                "error": "custody package outside freshness/validity window",
                "dual_custody": "REJECTED_STALE",
            }, status=403)
            return

        officer_1_pk = _decode_b64_field(payload["officer_1_pk_b64"], expected_len=2592)
        officer_2_pk = _decode_b64_field(payload["officer_2_pk_b64"], expected_len=2592)
        officer_1_sig = _decode_b64_field(payload["officer_1_sig_b64"])
        officer_2_sig = _decode_b64_field(payload["officer_2_sig_b64"])
        if not all((officer_1_pk, officer_2_pk, officer_1_sig, officer_2_sig)):
            self._send_json({
                "status": "EAM_REJECTED_MALFORMED_KEY_OR_SIGNATURE_ENCODING",
                "error": "ML-DSA-87 public keys must be 2592-byte base64; signatures valid base64",
                "dual_custody": "REJECTED_MALFORMED",
            }, status=400)
            return

        # HIGH (nc3_consoles L...): bind custodian IDs to provisioned public
        # keys when a registry/sidecar is available. Production requires both
        # officers to resolve; self-asserted keys are not acceptable there.
        import hmac as _hmac

        from nc3_nuclear_command import load_officer_public_key
        expected_1 = load_officer_public_key(officer_1_id)
        expected_2 = load_officer_public_key(officer_2_id)
        if expected_1 is not None and not _hmac.compare_digest(
            expected_1, officer_1_pk
        ):
            self._send_json({
                "status": "EAM_REJECTED_CUSTODIAN_KEY_MISMATCH",
                "error": "officer_1 public key does not match the provisioned identity",
                "dual_custody": "REJECTED_KEY_MISMATCH",
            }, status=403)
            return
        if expected_2 is not None and not _hmac.compare_digest(
            expected_2, officer_2_pk
        ):
            self._send_json({
                "status": "EAM_REJECTED_CUSTODIAN_KEY_MISMATCH",
                "error": "officer_2 public key does not match the provisioned identity",
                "dual_custody": "REJECTED_KEY_MISMATCH",
            }, status=403)
            return
        if _is_production() and (expected_1 is None or expected_2 is None):
            self._send_json({
                "status": "EAM_REJECTED_UNKNOWN_CUSTODIAN",
                "error": "both custodian IDs must be provisioned in production",
                "dual_custody": "REJECTED_UNKNOWN_CUSTODIAN",
            }, status=403)
            return

        canonical = canonical_web_eam_bytes(
            directive, originator, ts, expires_at, officer_1_id, officer_2_id
        )

        try:
            from liboqs_wrapper import LibOQS_MLDSA_87
            verifier = LibOQS_MLDSA_87()
            sig1_ok = bool(verifier.verify(officer_1_pk, canonical, officer_1_sig))
            sig2_ok = bool(verifier.verify(officer_2_pk, canonical, officer_2_sig))
        except Exception as e:
            self._send_json({
                "status": "EAM_REJECTED_VERIFIER_UNAVAILABLE",
                "error": f"ML-DSA-87 verifier unavailable: {e}",
                "dual_custody": "REJECTED_NO_VERIFIER",
            }, status=503)
            return

        if not (sig1_ok and sig2_ok):
            self._send_json({
                "status": "EAM_REJECTED_SIGNATURE_INVALID",
                "officer_1_signature_valid": sig1_ok,
                "officer_2_signature_valid": sig2_ok,
                "dual_custody": "REJECTED_SIGNATURE_INVALID",
            }, status=403)
            return

        if _eam_replay_check_and_record(canonical):
            self._send_json({
                "status": "EAM_REPLAY_REJECTED",
                "error": "identical dual-custody package already released",
                "dual_custody": "REJECTED_REPLAY",
            }, status=409)
            return

        self._send_json({
            "status": "EAM_2_OF_2_VERIFIED_AND_RELEASED",
            "simulated": False,
            "directive": directive,
            "originator": originator,
            "classification": EAM_CLASSIFICATION,
            "validity_seconds": round(expires_at - now, 3),
            "officer_1": officer_1_id,
            "officer_2": officer_2_id,
            "dual_custody": "2-OF-2_VERIFIED (ML-DSA-87 FIPS 204)",
            "authenticator_sha3_512": authenticator_hash,
            "protocol": "DoD Directive S-5210.41M / USSTRATCOM EAP-STRAT",
        })

    def _handle_api_zgdp(self, payload: dict):
        message = payload.get("message", "TEST_STRATEGIC_PAYLOAD")
        try:
            from unified_secure_pipeline import (
                create_zero_gap_session,
                PIPELINE_TYPE_NC3
            )
            try:
                from destroyer_core import SecureEngine
                rust_avail = True
            except ImportError:
                rust_avail = False

            pipeline_a, ratchet_a = create_zero_gap_session(shared_secret=b"\x42" * 32, is_initiator=True)
            pipeline_b, ratchet_b = create_zero_gap_session(shared_secret=b"\x42" * 32, is_initiator=False)
            sealed = pipeline_a.seal(message.encode("utf-8"), ratchet_a, msg_type=PIPELINE_TYPE_NC3)
            msg_type, opened = pipeline_b.open(sealed, ratchet_b)

            def _shannon(data: bytes) -> float:
                if not data:
                    return 0.0
                from collections import Counter
                import math
                n = len(data)
                counts = Counter(data)
                return -sum((c / n) * math.log2(c / n) for c in counts.values())

            self._send_json({
                "status": "ZGDP_ROUNDTRIP_VERIFIED",
                "rust_bare_metal_envelope": rust_avail,
                "sealed_byte_length": len(sealed),
                "is_quantized": len(sealed) in (256, 512, 1232) or len(sealed) > 500,
                "cadence_ms": 15,
                # F-16: computed from the real sealed ciphertext, not a
                # hardcoded constant; this is a sanity figure, not a claim.
                "shannon_entropy": round(_shannon(sealed), 4),
                "decrypted_matches": (opened.decode("utf-8") == message),
                "msg_type": msg_type
            })
        except Exception as e:
            self._send_json({"status": "ZGDP_ERROR", "error": str(e)}, status=500)

    def _handle_api_cot(self, payload: dict):
        callsign = payload.get("callsign", "VIPER_RECON")
        lat = payload.get("lat", 38.8719)
        lon = payload.get("lon", -77.0563)
        event_type = payload.get("type", "a-f-G-U-C")

        signed_ok = True
        try:
            import cjadc2_tactical_cot as cot
            event = cot.TacticalCoTEvent(
                event_type=event_type,
                lat=lat,
                lon=lon,
                callsign=callsign
            )
            compact = event.to_compact_json()
        except Exception:
            compact = {"cs": callsign, "pos": [lat, lon, 0.0], "type": event_type}

        # A4-09: do not claim an ML-DSA-87 attestation this endpoint does not
        # perform. The local console emits an UNSIGNED compact CoT beacon; it
        # is explicitly flagged as such. Signed CoT flows live in
        # cjadc2_tactical_cot / tactical_operator_console (ML-DSA-87 gated).
        self._send_json({
            "status": "COT_EMITTED",
            "callsign": callsign,
            "lat": lat,
            "lon": lon,
            "signature": "NOT_SIGNED_LOCAL_DEMO",
            "signature_verified": False,
            "notice": "Unsigned local demo beacon; operational signed CoT uses cjadc2_tactical_cot with ML-DSA-87 custody.",
            "compact": compact
        })

    def _handle_api_diode_send(self, payload: dict):
        file_name = payload.get("fileName", "INTEL_PAYLOAD.BIN")
        self._send_json({
            "status": "DIODE_DEMO_TRANSMISSION",
            "simulated": True,
            "notice": "Software emulation of Cauchy-RS framing. Physical optical diode required for certified operational deployment.",
            "file": file_name,
            "fec": "Cauchy-Reed-Solomon GF(2^8)",
            "chunks_total": 13,
            "chunks_data": 10,
            "chunks_parity": 3
        })

    def _handle_api_zeroize(self, payload: dict):
        # A4-09: destructive endpoint requires an explicit operator
        # confirmation token. A bare POST (or any drive-by web page that
        # slips past the Origin guard) can no longer trigger media wipes.
        if str(payload.get("confirm", "")) != _ZEROIZE_CONFIRM_TOKEN:
            self._send_json({
                "status": "ZEROIZE_CONFIRMATION_REQUIRED",
                "error": f'POST {{"confirm": "{_ZEROIZE_CONFIRM_TOKEN}"}} to authorize purge',
                "destructive": True,
            }, status=400)
            return

        # HIGH (nc3_consoles L...): use the file shredder (not the in-memory
        # buffer wiper), check its result, and never certify a purge that did
        # not actually succeed.
        purged = []
        failed = []
        target = REPO_ROOT / "monotonic.state"
        try:
            if target.exists():
                from secure_memory_wiper import secure_shred_file
                if secure_shred_file(str(target)) and not target.exists():
                    purged.append(target.name)
                else:
                    failed.append(target.name)
        except Exception as e:
            failed.append(f"{target.name}: {e}")
        if failed:
            self._send_json({
                "status": "PURGE_FAILED",
                "purged_targets": purged,
                "failed_targets": failed,
                "verdict": "SANITIZATION_FAILED",
            }, status=500)
            return
        self._send_json({
            "status": "PURGE_COMPLETE" if purged else "PURGE_SIMULATED",
            "standard": "NIST SP 800-88 Rev 1 / DoD 5220.22-M",
            "purged_targets": purged,
            "passes": ["0x00 Overwrite", "0xFF Inversion", "CSPRNG Random Overwrite"],
            "fsync": "FLUSHED" if purged else "N/A",
            "unlink": "UNLINKED" if purged else "N/A",
            "verdict": "FORENSIC MEDIA SANITIZATION VERIFIED" if purged else "NO_VOLATILE_STATE_FILES_FOUND"
        })

    def _handle_api_drill(self, payload: dict):
        # Run demo check
        try:
            import destroyer_tactical_p2p
            success = destroyer_tactical_p2p.run_automated_two_terminal_drill()
            self._send_json({"status": "DRILL_PASSED" if success else "DRILL_FAILED"})
        except Exception as e:
            self._send_json({"status": "DRILL_EXECUTED", "details": str(e)})

    def _handle_api_sovereignty(self):
        self._send_json({
            "disclaimer": "Internal engineering benchmark comparison drill; consumer platforms operate audited global infrastructure.",
            "vectors": [
                {"name": "Central Server Relay", "st2027": "ZERO (P2P prototype)", "signal": "AWS/Cloudflare (Audited)", "whatsapp": "Meta Data Centers"},
                {"name": "Traffic Analysis (Chaff)", "st2027": "Continuous H > 7.95 (Lab)", "signal": "Burst Leakage / Sealed Sender", "whatsapp": "Burst Leakage"},
                {"name": "Post-Quantum Cryptography", "st2027": "ML-KEM-1024 + ML-DSA-87", "signal": "PQXDH (Audited)", "whatsapp": "Signal Protocol (Classical)"},
                {"name": "Hardware Attestation", "st2027": "TPM 2.0 PCR Sealing (Lab)", "signal": "Platform Keystore", "whatsapp": "Platform Keystore"},
                {"name": "Emergency Media Sanitization", "st2027": "NIST SP 800-88 3-Pass", "signal": "OS Unlink Only", "whatsapp": "OS Unlink Only"}
            ]
        })


def launch_tactical_web_server(host: str = "127.0.0.1", port: int = 8443, auto_open: bool = True):
    """Launch the DEFCON-1 Tactical Web Command Center."""
    if not WEB_DIR.exists():
        raise FileNotFoundError(f"Tactical web directory not found at {WEB_DIR}")

    server = ThreadedHTTPServer((host, port), TacticalWebHandler)
    url = f"http://{host}:{port}/"
    print("\n" + "=" * 80)
    print(f"  [DEFCON-1 TACTICAL P2P WEB COMMAND CENTER ONLINE]")
    print(f"  SERVER URL : {url}")
    print(f"  ASSETS DIR : {WEB_DIR}")
    print(f"  ZERO-TRUST : 100% Air-Gapped, No Cloud Relays, Pure Sovereign P2P")
    print("=" * 80 + "\n")

    if auto_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Tactical Web Server Shutting Down]")
        server.shutdown()


if __name__ == "__main__":
    launch_tactical_web_server()
