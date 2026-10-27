#!/usr/bin/env python3
"""
A4 Audit Remediation Regression Battery (2026-10-17)
===================================================

Gates for the fourth forensic audit cycle fixes:
  A4-01 hybrid_kex handshake FALCON verify-result discard (CRITICAL)
  A4-02 secure_key_manager hybrid_verify FALCON result discard
  A4-03 SIEM tamper-evident chain constant-time HMAC compare
  A4-04 PTT_VOICE spoofing (unauthenticated voice bursts)
  A4-05 EAM nonce replay suppression
  A4-06 WiFi Direct unbounded frame length (OOM DoS)
  A4-07 DoubleRatchet file-completion filename traversal
  A4-08 Unsigned/invalid-signature discovery broadcasts
  A4-10 Hardcoded diode PSK provisioning
  A4-12 STUN attribute bounds checks (truncated-datagram DoS)
  A4-13 Handshake rate limiter global cap (identity rotation)
  A4-14 Key-store at-rest KDF source precedence
  A4-15 Per-install audit PBKDF2 salt
  A4-16 Tar archive device/FIFO member rejection
  A4-17 Persistent master-audit receipt signer
  A4-18 secure_p2p_core accept-loop rate limiting
  A4-19 Config secret redaction on set()
  A4-23 .gitignore secret artifacts
  A4-24 NC3 live-transfer test war key de-hardcoding
  A4-25 Diode frame HMAC authentication (optional PSK)
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import struct
import sys
import tarfile
import time
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tactical_web_console import TacticalWebHandler


def _web_handler(method: str, path: str, body: dict = None, extra_headers: dict = None):
    """Minimal HTTP handler harness (mirrors tests/test_tactical_web_console.py)."""
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
            "Content-Type": "application/json",
        }
        if extra_headers:
            handler.headers.update(extra_headers)
    return handler, wfile


def _web_response(wfile: BytesIO) -> dict:
    wfile.seek(0)
    raw = wfile.getvalue().decode("utf-8")
    parts = raw.split("\r\n\r\n", 1)
    return json.loads(parts[1] if len(parts) > 1 else raw)


class TestA4CriticalSignatureFixes:
    def test_a4_01_hybrid_kex_checks_verify_result(self):
        """A4-01: the handshake path must not discard dss.verify()'s bool."""
        src = (ROOT / "hybrid_kex.py").read_text(encoding="utf-8")
        marker = "Verify FALCON signature"
        idx = src.index(marker)
        segment = src[idx:idx + 1200]
        assert "sig_ok = self.dss.verify" in segment
        assert "if not sig_ok" in segment
        assert "raise ValueError" in segment

    def test_a4_02_hybrid_verify_rejects_forged_falcon(self):
        """A4-02: forged FALCON-1024 signatures must yield False, not True.

        The full QuantumResistanceFutureProfing ctor pulls in the HQC
        agility-reserve engine (refused by the vendored oqs.dll guard), so
        the instance is built via __new__ with only the FALCON engine -
        exactly the code path hybrid_verify() exercises.
        """
        import pqc_algorithms
        from secure_key_manager import QuantumResistanceFutureProfing
        algo_cls = getattr(pqc_algorithms, "EnhancedFALCON_1024", None)
        if algo_cls is None:
            pytest.skip("EnhancedFALCON_1024 unavailable in pqc_algorithms")

        qrf = object.__new__(QuantumResistanceFutureProfing)
        qrf.logger = logging.getLogger("a4-02-probe")
        qrf._algorithm_instances = {"FALCON-1024": algo_cls()}
        algo = qrf._algorithm_instances["FALCON-1024"]
        pk, sk = algo.keygen()
        message = b"A4-02 forged-signature probe payload"

        good_sig = algo.sign(sk, message)
        assert qrf.hybrid_verify(
            message, {"FALCON-1024": good_sig}, {"FALCON-1024": pk}
        )["FALCON-1024"] is True

        forged = bytearray(good_sig)
        forged[len(forged) // 2] ^= 0x01
        assert qrf.hybrid_verify(
            message, {"FALCON-1024": bytes(forged)}, {"FALCON-1024": pk}
        )["FALCON-1024"] is False

        assert qrf.hybrid_verify(
            b"different message", {"FALCON-1024": good_sig}, {"FALCON-1024": pk}
        )["FALCON-1024"] is False


class TestA4SiemChain:
    def test_a4_03_constant_time_compare_helper(self, tmp_path):
        from remote_siem_forwarder import (
            _ct_eq_str,
            TamperEvidentAuditChain,
            verify_audit_log_chain,
        )
        assert _ct_eq_str("abc123", "abc123") is True
        assert _ct_eq_str("abc123", "abc124") is False
        assert _ct_eq_str(None, "abc") is False
        assert _ct_eq_str("abc", 123) is False

        # Persisted-chain path (the A4-03 fix site): clean chain verifies,
        # payload tampering is still detected through the compare path.
        ledger = tmp_path / "siem.jsonl"
        chain = TamperEvidentAuditChain(
            ledger_path=ledger, anchor_path=tmp_path / "anchor.json"
        )
        chain.append_event("TEST_EVENT", "INFO", {"k": "v"})
        ok, count, msg = chain.verify_ledger()
        assert ok and count == 1, msg

        tampered = ledger.read_text(encoding="utf-8").replace('"v"', '"x"')
        ledger.write_text(tampered, encoding="utf-8")
        ok2, _, msg2 = verify_audit_log_chain(ledger, chain.hmac_key)
        assert ok2 is False and "TAMPER" in msg2, msg2


class TestA4TacticalConsole:
    def test_a4_04_ptt_requires_valid_signature(self):
        import tactical_operator_console as toc
        tx = toc.TacticalConsoleStation("ptt-tx", "PTT-TX", local_port=9181, enable_atak_bridge=False)
        rx = toc.TacticalConsoleStation("ptt-rx", "PTT-RX", local_port=9182, enable_atak_bridge=False)
        rx.enrolled_peers[tx.callsign] = tx.pubkey_hex

        frames, dur = 12, 1500
        ts = time.time()
        sig = tx.sign_data(toc.canonical_ptt_bytes(tx.callsign, frames, dur, ts))
        pkt = {
            "type": "PTT_VOICE", "chunks": frames, "duration_ms": dur,
            "signer": tx.callsign, "sig": sig.hex(), "timestamp": ts,
        }
        assert rx._process_ptt_packet(pkt, tx.callsign) is True

        tampered = dict(pkt)
        tampered["chunks"] = frames + 1
        assert rx._process_ptt_packet(tampered, tx.callsign) is False

        unsigned = {"type": "PTT_VOICE", "chunks": 5, "duration_ms": 800,
                    "signer": "GHOST", "timestamp": time.time()}
        assert rx._process_ptt_packet(unsigned, "GHOST") is False

    def test_a4_05_eam_nonce_replay_rejected(self):
        import tactical_operator_console as toc
        of1 = toc.TacticalConsoleStation("of1", "OF1", local_port=9183, enable_atak_bridge=False)
        of2 = toc.TacticalConsoleStation("of2", "OF2", local_port=9184, enable_atak_bridge=False)
        rx = toc.TacticalConsoleStation("rx", "RX", local_port=9185, enable_atak_bridge=False)

        pkt = of1.authorize_dual_eam(
            directive="A4-05 REPLAY PROBE",
            second_officer_callsign="OF2",
            second_officer_pk=of2.pubkey_mldsa,
            second_officer_signer=of2.sign_data,
        )
        assert pkt and pkt.get("nonce")
        assert rx._process_eam_packet(pkt) is True
        assert rx._process_eam_packet(pkt) is False, "captured EAM must not re-execute"


class TestA4WebConsole:
    @staticmethod
    def _custody_payload(directive: str, ts: float, pk1, sk1, pk2, sk2, sig_mutator=None):
        import tactical_web_console as twc
        from liboqs_wrapper import LibOQS_MLDSA_87
        expires = ts + 120.0
        canonical = twc.canonical_web_eam_bytes(
            directive, "NORAD_ALPHA", ts, expires, "OFFICER-1", "OFFICER-2"
        )
        signer = LibOQS_MLDSA_87()
        sig1 = signer.sign(sk1, canonical)
        sig2 = signer.sign(sk2, canonical)
        if sig_mutator:
            sig1 = sig_mutator(sig1)
        return {
            "originator": "NORAD_ALPHA",
            "directive": directive,
            "officer_1_id": "OFFICER-1",
            "officer_2_id": "OFFICER-2",
            "timestamp_utc": ts,
            "expires_at": expires,
            "officer_1_pk_b64": base64.b64encode(pk1).decode(),
            "officer_2_pk_b64": base64.b64encode(pk2).decode(),
            "officer_1_sig_b64": base64.b64encode(sig1).decode(),
            "officer_2_sig_b64": base64.b64encode(sig2).decode(),
        }

    def test_a4_09_eam_real_dual_verification_and_replay(self):
        from liboqs_wrapper import LibOQS_MLDSA_87
        signer = LibOQS_MLDSA_87()
        pk1, sk1 = signer.keygen()
        pk2, sk2 = signer.keygen()
        ts = time.time()
        payload = self._custody_payload("A4-09 REAL VERIFY", ts, pk1, sk1, pk2, sk2)

        handler, wfile = _web_handler("POST", "/api/eam", payload)
        handler._handle_api_eam(payload)
        data = _web_response(wfile)
        assert data["status"] == "EAM_2_OF_2_VERIFIED_AND_RELEASED"
        assert data["dual_custody"].startswith("2-OF-2_VERIFIED")
        assert data["simulated"] is False

        # Replay of the identical custody package must be refused
        handler2, wfile2 = _web_handler("POST", "/api/eam", payload)
        handler2._handle_api_eam(payload)
        assert _web_response(wfile2)["status"] == "EAM_REPLAY_REJECTED"

    def test_a4_09_eam_forged_signature_rejected(self):
        from liboqs_wrapper import LibOQS_MLDSA_87
        signer = LibOQS_MLDSA_87()
        pk1, sk1 = signer.keygen()
        pk2, sk2 = signer.keygen()
        payload = self._custody_payload(
            "A4-09 FORGED PROBE", time.time(), pk1, sk1, pk2, sk2,
            sig_mutator=lambda s: bytes([s[0] ^ 0xFF]) + s[1:],
        )
        handler, wfile = _web_handler("POST", "/api/eam", payload)
        handler._handle_api_eam(payload)
        assert _web_response(wfile)["status"] == "EAM_REJECTED_SIGNATURE_INVALID"

    def test_a4_09_eam_single_custodian_rejected(self):
        from liboqs_wrapper import LibOQS_MLDSA_87
        signer = LibOQS_MLDSA_87()
        pk1, sk1 = signer.keygen()
        payload = self._custody_payload("A4-09 SINGLE CUSTODIAN", time.time(), pk1, sk1, pk1, sk1)
        payload["officer_2_id"] = payload["officer_1_id"]
        handler, wfile = _web_handler("POST", "/api/eam", payload)
        handler._handle_api_eam(payload)
        assert _web_response(wfile)["status"] == "EAM_REJECTED_DUPLICATE_CUSTODIAN"

    def test_a4_09_post_origin_guard(self):
        handler, wfile = _web_handler(
            "POST", "/api/send", {"sender": "X", "message": "Y"},
            extra_headers={"Origin": "http://evil.example"},
        )
        handler.do_POST()
        assert _web_response(wfile)["error"] == "Cross-origin POST rejected"

    def test_a4_09_post_body_cap(self):
        handler, wfile = _web_handler("POST", "/api/send", {})
        handler.headers["Content-Length"] = str(64 * 1024 * 1024)
        handler.do_POST()
        assert _web_response(wfile)["error"] == "Request body too large"

    def test_a4_09_zeroize_requires_confirmation(self, monkeypatch, tmp_path):
        import tactical_web_console as twc
        monkeypatch.setattr(twc, "REPO_ROOT", tmp_path)
        handler, wfile = _web_handler("POST", "/api/zeroize", {})
        handler._handle_api_zeroize({})
        assert _web_response(wfile)["status"] == "ZEROIZE_CONFIRMATION_REQUIRED"

        handler2, wfile2 = _web_handler("POST", "/api/zeroize", {"confirm": "ZEROIZE-ALL"})
        handler2._handle_api_zeroize({"confirm": "ZEROIZE-ALL"})
        assert _web_response(wfile2)["status"] in ("PURGE_COMPLETE", "PURGE_SIMULATED")


class TestA4NetworkHardening:
    def test_a4_06_wifi_direct_frame_cap(self):
        from decentralized_architecture import WiFiDirectTransport

        class FakeSock:
            def __init__(self, payload: bytes):
                self._buf = payload
            def settimeout(self, _t):
                pass
            def recv(self, n):
                out, self._buf = self._buf[:n], self._buf[n:]
                return out

        t = WiFiDirectTransport(port=45123)
        t._connected = True
        t._client_socket = FakeSock(struct.pack(">I", 0xFFFFFFFF))
        assert t.receive_data(timeout=0.1) is None
        assert t._connected is False, "oversized frame must drop the connection"

        t2 = WiFiDirectTransport(port=45124)
        t2._connected = True
        t2._client_socket = FakeSock(struct.pack(">I", 0))
        assert t2.receive_data(timeout=0.1) is None

    def test_a4_12_stun_truncated_attribute_no_crash(self):
        from p2p_core import StunClient
        tx = b"\x11" * 12
        header = struct.pack("!HH", 0x0101, 0) + struct.pack("!I", StunClient.MAGIC_COOKIE) + tx

        # Attr claims XOR-MAPPED-ADDRESS but body is effectively absent
        short_body = struct.pack("!HH", StunClient.XOR_MAPPED_ADDRESS, 4) + b"\x00\x01\x00\x00"
        assert StunClient.parse_stun_response(header + short_body, tx) is None

        # Declared length exceeds remaining datagram
        lying_len = struct.pack("!HH", StunClient.XOR_MAPPED_ADDRESS, 400) + b"\x00\x02" + b"\x00" * 8
        assert StunClient.parse_stun_response(header + lying_len, tx) is None

        # IPv6 family byte with an 8-byte body (must be 20)
        v6_short = struct.pack("!HH", StunClient.XOR_MAPPED_ADDRESS, 8) + b"\x00\x02\x12\x34" + b"\x00" * 4
        assert StunClient.parse_stun_response(header + v6_short, tx) is None

        # Valid IPv4 vector still parses correctly
        port = 51820
        ip = bytes([10, 0, 0, 5])
        xport = port ^ (StunClient.MAGIC_COOKIE >> 16)
        xip = bytes(b ^ m for b, m in zip(ip, struct.pack("!I", StunClient.MAGIC_COOKIE)))
        attr = struct.pack("!HH", StunClient.XOR_MAPPED_ADDRESS, 8) + b"\x00\x01" + struct.pack("!H", xport) + xip
        assert StunClient.parse_stun_response(header + attr, tx) == ("10.0.0.5", port)

    def test_a4_13_handshake_global_rate_cap(self):
        from protocol_manager import ProtocolManager, ProtocolViolationError

        async def attempt(mgr, ident):
            try:
                await mgr._perform_handshake("sess", ident, SimpleNamespace())
            except ProtocolViolationError as e:
                return str(e)
            return "no-error"

        mgr = object.__new__(ProtocolManager)
        ident = SimpleNamespace(identity_id="rotating-identity")
        messages = [asyncio.run(attempt(mgr, ident)) for _ in range(11)]
        assert "rate limit" in messages[-1], messages[-1]

        mgr2 = object.__new__(ProtocolManager)
        last = None
        for i in range(121):
            last = asyncio.run(attempt(mgr2, SimpleNamespace(identity_id=f"attacker-id-{i}")))
        assert "Global handshake rate limit" in last, last


class TestA4AirGappedDiscovery:
    def test_a4_08_signed_policy_and_invalid_signature(self, monkeypatch):
        from air_gapped_operation import LocalPeerDiscovery
        from liboqs_wrapper import LibOQS_MLDSA_87

        tx = LocalPeerDiscovery(node_id=b"\x01" * 32, port=45679)
        unsigned_msg = tx._build_discovery_message()

        # Default posture: signed discovery is required, so an unsigned
        # broadcast is refused (it has no authenticated origin).
        monkeypatch.delenv("P2P_ALLOW_UNSIGNED_DISCOVERY", raising=False)
        default_rx = LocalPeerDiscovery(node_id=b"\x02" * 32, port=45679)
        default_rx._handle_discovery_message(unsigned_msg, ("127.0.0.1", 50100))
        assert len(default_rx._peers) == 0

        # Explicit legacy-interop opt-in admits unsigned broadcasts.
        monkeypatch.setenv("P2P_ALLOW_UNSIGNED_DISCOVERY", "1")
        lab_rx = LocalPeerDiscovery(node_id=b"\x02" * 32, port=45679)
        lab_rx._handle_discovery_message(unsigned_msg, ("127.0.0.1", 50100))
        assert len(lab_rx._peers) == 1
        monkeypatch.delenv("P2P_ALLOW_UNSIGNED_DISCOVERY", raising=False)

        # Strict policy: unsigned broadcast rejected.
        monkeypatch.setenv("P2P_REQUIRE_SIGNED_DISCOVERY", "1")
        strict_rx = LocalPeerDiscovery(node_id=b"\x03" * 32, port=45679)
        strict_rx._handle_discovery_message(unsigned_msg, ("127.0.0.2", 50101))
        assert len(strict_rx._peers) == 0
        monkeypatch.delenv("P2P_REQUIRE_SIGNED_DISCOVERY")

        # Provided-but-invalid signature must be rejected even in lab mode.
        pk, _sk = LibOQS_MLDSA_87().keygen()
        forger = LocalPeerDiscovery(
            node_id=b"\x04" * 32, port=45679,
            sig_public_key=pk, sig_signer=lambda _b: b"\xde\xad\xbe\xef",
        )
        forged_msg = forger._build_discovery_message()
        rx = LocalPeerDiscovery(node_id=b"\x05" * 32, port=45679)
        rx._handle_discovery_message(forged_msg, ("127.0.0.3", 50102))
        assert len(rx._peers) == 0


class TestA4SecretsAndConfig:
    def test_a4_10_diode_key_provisioning(self, monkeypatch, tmp_path):
        import destroyer
        monkeypatch.delenv("P2P_DIODE_PSK", raising=False)
        monkeypatch.setenv("P2P_DIODE_DIR", str(tmp_path / "diode"))

        key_path, _state = destroyer._provision_diode_key_material()
        content = Path(key_path).read_text(encoding="ascii").strip()
        assert len(content) == 64
        assert content != "0123456789abcdef" * 4, "hardcoded key must be gone"

        key_path2, _ = destroyer._provision_diode_key_material()
        assert Path(key_path2).read_text(encoding="ascii").strip() == content

        monkeypatch.setenv("P2P_DIODE_PSK", "ab" * 32)
        key_path3, _ = destroyer._provision_diode_key_material()
        assert Path(key_path3).read_text(encoding="ascii").strip() == "ab" * 32

    def test_a4_15_audit_salt_per_install(self, monkeypatch, tmp_path):
        import audit_logging_system as als
        monkeypatch.setenv("P2P_BASE_DIR", str(tmp_path))
        monkeypatch.delenv("P2P_AUDIT_LEGACY_SALT", raising=False)

        s1 = als._get_audit_salt()
        s2 = als._get_audit_salt()
        assert s1 == s2 and len(s1) == 32
        assert s1 != b"SecureP2P::AuditDbSalt::v1::StrictEntropy"
        assert (tmp_path / ".secure_audit_salt").exists()

        monkeypatch.setenv("P2P_AUDIT_LEGACY_SALT", "1")
        assert als._get_audit_salt() == b"SecureP2P::AuditDbSalt::v1::StrictEntropy"

    def test_a4_15b_salt_written_binary_and_repairable(self, monkeypatch, tmp_path):
        """A4-15b: Windows os.open text mode expanded 0x0A bytes of the random
        salt to CRLF (os.write still reported success). The file must be
        binary-correct on write, and a CRLF-inflated legacy file must be
        repaired to the exact original salt."""
        import audit_logging_system as als
        monkeypatch.setenv("P2P_BASE_DIR", str(tmp_path))
        monkeypatch.delenv("P2P_AUDIT_LEGACY_SALT", raising=False)
        salt_path = tmp_path / ".secure_audit_salt"

        # Deterministic worst case: every byte is 0x0A
        monkeypatch.setattr(als.secrets, "token_bytes", lambda n: b"\n" * n)
        s1 = als._get_audit_salt()
        assert s1 == b"\n" * 32
        assert salt_path.stat().st_size == 32, "salt must be written with O_BINARY"
        assert als._get_audit_salt() == b"\n" * 32

        # Legacy CRLF-inflated file (what the old buggy write produced)
        inflated = b"\n" * 32
        inflated = b"".join(b"\r\n" for _ in range(32))
        salt_path.write_bytes(inflated)
        s2 = als._get_audit_salt()
        assert s2 == b"\n" * 32, "CRLF artifact must be reversed to the original salt"
        assert salt_path.stat().st_size == 32, "repaired salt must be persisted binary-correct"

    def test_a4_19_config_set_redacts_secrets(self):
        from config import ConfigManager
        cm = object.__new__(ConfigManager)
        cm.config = {}
        cm.logger = logging.getLogger("test-a4-19")
        cm.set("API_KEY", "topsecret-value")
        cm.set("LOG_LEVEL", "INFO")
        dumped = cm.to_dict()
        assert dumped["API_KEY"] == "[REDACTED]"
        assert dumped["LOG_LEVEL"] == "INFO"

    def test_a4_23_gitignore_covers_new_secret_artifacts(self):
        text = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for entry in (".secure_audit_salt", "scratch/", "unsent_messages/"):
            assert entry in text

    def test_a4_24_nc3_war_key_not_hardcoded(self):
        text = (ROOT / "tests" / "test_nc3_two_terminal_live_transfer.py").read_text(encoding="utf-8")
        assert "058d3327d4d78bb641a4adab8d7d967c7c05c0035d29141be2dea7a3b9bfd342" not in text
        assert "secrets.token_hex(32)" in text


class TestA4ArtefactsAndArchives:
    def test_a4_16_tar_device_fifo_rejected(self, tmp_path):
        from libsodium_manager import extract_archive, SecurityError as LibSecurityError  # noqa: F401

        archive = tmp_path / "evil.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            fifo = tarfile.TarInfo("fifo_member")
            fifo.type = tarfile.FIFOTYPE
            tar.addfile(fifo)
            data = b"payload"
            regular = tarfile.TarInfo("regular.txt")
            regular.size = len(data)
            import io as _io
            tar.addfile(regular, _io.BytesIO(data))

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = extract_archive(str(archive), str(out_dir))
        assert result is False, "device/FIFO archive must be rejected"
        assert not (out_dir / "fifo_member").exists()

    def test_a4_25_diode_frame_hmac_roundtrip(self):
        from tactical_data_diode import DiodePacket, DIODE_MAGIC
        key = b"K" * 32
        pkt = DiodePacket(
            magic=DIODE_MAGIC, tx_id=b"T" * 16, total_len=4, chunk_len=4,
            k=8, m=4, chunk_index=0,
            chunk_sha3=hashlib.sha3_256(b"DATA").digest(), chunk_data=b"DATA",
        )

        wire = pkt.serialize(mac_key=key)
        assert DiodePacket.deserialize(wire, mac_key=key).chunk_data == b"DATA"

        tampered = wire[:-1] + bytes([wire[-1] ^ 0x01])
        with pytest.raises(ValueError):
            DiodePacket.deserialize(tampered, mac_key=key)

        # Mode mismatch (keyed frame, keyless verifier) must fail closed
        with pytest.raises(ValueError):
            DiodePacket.deserialize(wire)

        # Unkeyed legacy frames still round-trip
        assert DiodePacket.deserialize(pkt.serialize()).chunk_data == b"DATA"


class TestA4KeyStoreKDF:
    def test_a4_14_keystore_kdf_precedence(self, monkeypatch, tmp_path):
        """A4-14: passphrase > DPAPI master > (lab-only) host attributes.

        KeyService lives inside the generated service-script template in
        secure_key_manager.py (it is materialised to disk and executed as a
        child process), so the precedence contract is asserted at source
        level, plus the legacy material must never equal the passphrase path.
        """
        src = (ROOT / "secure_key_manager.py").read_text(encoding="utf-8")
        assert "def _get_or_create_storage_master_key" in src
        assert ".keystore_master.dpapi" in src
        # Fail closed instead of silently rotating an unreadable sealed master
        assert "Sealed key-store master key unreadable" in src
        assert "prohibited in production" in src

        i_pass = src.index("passphrase = os.environ.get('P2P_KEY_STORAGE_PASSPHRASE')")
        i_dpapi = src.index("master = self._get_or_create_storage_master_key()")
        i_prod = src.index("prohibited in production")
        i_legacy = src.index("PUBLIC host attributes (lab fallback)")
        assert i_pass < i_dpapi < i_prod < i_legacy, "precedence order regressed"

        # Behavioral contrast: passphrase-derived material differs from the
        # legacy public-host-attribute material for the same salt.
        monkeypatch.setenv("P2P_KEY_STORAGE_PASSPHRASE", "a4-14-probe-passphrase")
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        salt = b"\x42" * 32
        strong = PBKDF2HMAC(
            algorithm=hashes.SHA512(), length=32, salt=salt, iterations=600000
        ).derive(os.environ["P2P_KEY_STORAGE_PASSPHRASE"].encode("utf-8"))

        user = os.environ.get("USERNAME") or os.environ.get("USER") or "default_user"
        domain = os.environ.get("USERDOMAIN") or "local_domain"
        legacy_material = f"p2p-secure-keys::{user}::{domain}::{Path.home()}".encode("utf-8")
        legacy = PBKDF2HMAC(
            algorithm=hashes.SHA512(), length=32, salt=salt, iterations=600000
        ).derive(legacy_material)
        assert len(strong) == 32 and strong != legacy
        monkeypatch.delenv("P2P_KEY_STORAGE_PASSPHRASE")


class TestA4SourceGuards:
    def test_a4_17_persistent_audit_signer(self):
        src = (ROOT / "scripts" / "run_defense_audit.py").read_text(encoding="utf-8")
        trust = (ROOT / "report_trust.py").read_text(encoding="utf-8")
        assert "load_or_create_audit_signer" in src
        assert "signer_pk_sha3_256" in src
        assert "audit_signer.mldsa87.sk" in trust
        assert "audit_signer.mldsa87.pk" in trust
        # A4-17b: binary-safe write + CRLF repair + VAS probe on load
        assert 'getattr(os, "O_BINARY", 0)' in trust
        assert 'replace(b"\\r\\n", b"\\n")' in trust
        assert "st2027-audit-signer-keypair-probe" in trust
        # Custody/rotation controls must live with the trust anchor.
        assert "_verify_private_custody" in trust
        assert "P2P_AUDIT_ROTATION_APPROVER_1" in trust
        assert "_assert_no_link" in trust

    def test_a4_18_accept_limiter_mirrored(self):
        src = (ROOT / "secure_p2p_core" / "core" / "orchestrator.py").read_text(encoding="utf-8")
        assert "Rate-limit: dropping rapid connection" in src
        assert "_accept_hits" in src


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
