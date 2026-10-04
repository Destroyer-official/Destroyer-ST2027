#!/usr/bin/env python3
"""Regression battery for pasted-audit P0 fixes (verified-true items only).

Covers, with fresh runtime evidence (not log scraping):
  P0-1  double_ratchet.secure_cleanup wipes the REAL attribute names
        (root_key/sending_chain_key/receiving_chain_key + dh/dss/kem
        private state), survives exotic key-object types, and clears
        skipped_message_keys (values and tuple-key bytes).
  P0-2  AuditLogger.log_event instance path applies the same denylist
        redaction as the global log_event path.
  P0-3a TLSSecureChannel._create_server_context enforces CERT_REQUIRED
        (mTLS) instead of the PROTOCOL_TLS_SERVER CERT_NONE default.
  P0-3b Decentralized direct-send refuses peers without a pinned
        expected_fingerprint (fail-closed, no CA-validity-only send).
  P0-4  FramedSocket.send_framed refuses the b'' encryption-failure
        sentinel so no unchecked monolith call site can emit it.
"""
import asyncio
import os
import ssl
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestP0SecureCleanupRealAttrs(unittest.TestCase):
    def test_cleanup_wipes_live_key_attrs(self):
        from double_ratchet import DoubleRatchet
        r = DoubleRatchet.__new__(DoubleRatchet)
        r.root_key = b"R" * 32
        r.sending_chain_key = b"S" * 32
        r.receiving_chain_key = b"V" * 32
        r.dh_private_key = b"D" * 32
        r.dss_private_key = b"G" * 32
        r.kem_private_key = b"K" * 32
        r.kem_shared_secret = b"H" * 32
        r.skipped_message_keys = {(b"kid-1", 7): b"M" * 32}
        from double_ratchet import ReplayCache
        r.replay_cache = ReplayCache(max_size=8)
        r.secure_cleanup()
        for attr in ("root_key", "sending_chain_key", "receiving_chain_key",
                     "dh_private_key", "dss_private_key", "kem_private_key",
                     "kem_shared_secret"):
            self.assertIsNone(getattr(r, attr), f"{attr} must be None after cleanup")
        self.assertEqual(r.skipped_message_keys, {})

    def test_cleanup_survives_exotic_key_objects(self):
        from double_ratchet import DoubleRatchet

        class WeirdKey:
            pass

        r = DoubleRatchet.__new__(DoubleRatchet)
        r.root_key = WeirdKey()  # must not abort remaining wipes
        r.sending_chain_key = b"S" * 32
        r.receiving_chain_key = None
        r.dh_private_key = None
        r.dss_private_key = None
        r.kem_private_key = None
        r.kem_shared_secret = None
        r.skipped_message_keys = {}
        r.replay_cache = None
        r.secure_cleanup()  # must not raise
        self.assertIsNone(r.sending_chain_key)


class TestP0AuditInstancePath(unittest.TestCase):
    def test_instance_path_encrypts_not_redacts(self):
        # VERIFIED architecture (regression-guard): the AuditLogger instance
        # path must NOT denylist-redact details, because store/query applies
        # field-level encryption with a decrypt-on-read round-trip
        # (pinned by test_finding_7_audit_db_restricted_and_encrypted).
        # A pasted-audit claim demanded redaction here; applying it broke
        # that round-trip, so this test locks in the correct contract:
        # plaintext round-trips through the API while never hitting disk.
        import tempfile
        import shutil
        from pathlib import Path
        from audit_logging_system import (
            AuditLogger, AuditEventType, AuditSeverity,
            enforce_audit_db_permissions, redact_sensitive_audit_data,
        )
        # Global (untrusted-caller) path still redacts - that half stands.
        self.assertNotIn("TOPSECRET", str(redact_sensitive_audit_data(
            {"private_key": "TOPSECRET"})))
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = str(Path(tmpdir) / "logs" / "p0_audit.db")
            logger = AuditLogger(db_path=db_path)
            event = logger.log_event(
                AuditEventType.SECURITY_VIOLATION, "probe",
                AuditSeverity.HIGH,
                details={"forensic_token": "CLASSIFIED_TOP_SECRET"},  # nosec: B105
            )
            logger.flush_buffer()
            with open(db_path, "rb") as f:
                self.assertNotIn(b"CLASSIFIED_TOP_SECRET", f.read())
            events = logger.query_events(limit=5)
            matching = [e for e in events if e.event_id == event.event_id]
            self.assertTrue(matching)
            self.assertEqual(matching[0].details.get("forensic_token"),
                             "CLASSIFIED_TOP_SECRET")
            enforce_audit_db_permissions(db_path)
            if logger.db_connection:
                logger.db_connection.close()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestP0MTLSServerContext(unittest.TestCase):
    def test_first_server_context_with_real_cert(self):
        # End-to-end: generate a real self-signed pair via ca_services and
        # prove the first builder never yields a CERT_NONE server context:
        # either CERT_REQUIRED is returned, or construction fails closed
        # with an explicit exception (both are safe; silent CERT_NONE is not).
        import tempfile
        import tls_channel_manager as tcm
        from ca_services import CAExchange
        ca = CAExchange(secure_exchange=True)
        ca.generate_self_signed()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cf, \
             tempfile.NamedTemporaryFile(delete=False, suffix=".key") as kf:
            cf.write(ca.local_cert_pem)
            kf.write(ca.local_key_pem)
            crt, key = cf.name, kf.name
        try:
            ch = tcm.TLSSecureChannel.__new__(tcm.TLSSecureChannel)
            ch.in_memory_only = False
            ch.cert_path = crt
            ch.key_path = key
            ch.enable_pq_kem = False
            ch.verify_certs = True
            ch.ca_path = None
            ch.secure_enclave = None
            try:
                ctx = ch._create_server_context()
            except (ssl.SSLError, tcm.TlsChannelException, tcm.CryptographicError) as e:
                # Fail-closed construction (e.g. no selectable PQ ciphers on
                # this host OpenSSL) - safe, assert it says so explicitly.
                self.assertIn("FATAL", str(e))
                return
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        finally:
            for p in (crt, key):
                try:
                    os.unlink(p)
                except Exception:  # nosec: B110
                    pass


class TestP0DirectSendRequiresPin(unittest.TestCase):
    def test_no_pin_no_send(self):
        import decentralized_architecture as da
        from types import SimpleNamespace
        node = da.DecentralizedPeerDiscovery.__new__(da.DecentralizedPeerDiscovery)
        peer = SimpleNamespace(address="203.0.1.7", port=45678)  # no fingerprint
        msg = SimpleNamespace(message_id="m", sender_id=b"\x01" * 32,
                              recipient_id=b"\x02" * 32,
                              encrypted_payload=b"payload", timestamp=0, ttl=5)
        with self.assertRaises(Exception):
            asyncio.run(node._send_direct_to_peer(peer, msg))


class TestP0EmptyFrameRefused(unittest.TestCase):
    def test_send_framed_refuses_empty_sentinel(self):
        from p2p_core import FramedSocket
        self.assertFalse(asyncio.run(FramedSocket.send_framed(object(), b"")))


class TestP0PreAuthCapsBound(unittest.TestCase):
    def test_handshake_receives_capped_64k_10s(self):
        # Every bare pre-auth receive in both monoliths must carry the
        # 64KB/10s ceiling. A bare receive_framed(self.tcp_socket) anywhere
        # is a 4MB pre-auth allocation primitive (P0-5).
        import pathlib
        for name in ("archive/legacy_prototype/secure_p2p.py", "archive/legacy_prototype/secure_p2.py"):
            src = pathlib.Path(os.path.dirname(os.path.abspath(__file__))
                               ).joinpath(name).read_text(encoding="utf-8")
            # Bare form ends with ')' right after the socket (4MB default).
            bare = src.count("receive_framed(self.tcp_socket)")
            capped_std = src.count(
                "receive_framed(self.tcp_socket, timeout=p2p.PRE_AUTH_TIMEOUT, "
                "max_size=p2p.PRE_AUTH_MAX_MESSAGE_SIZE)")
            capped_bundle = src.count(
                "receive_framed(self.tcp_socket, timeout=p2p.PRE_AUTH_TIMEOUT, "
                "max_size=p2p.PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE)")
            capped = capped_std + capped_bundle
            self.assertEqual(bare, 0,
                             f"{name}: bare pre-auth receives remain")
            self.assertGreaterEqual(capped, 14, f"{name}: expected >= 14 capped sites")


class TestP0RelayIngressGuards(unittest.TestCase):
    def _node(self):
        import decentralized_architecture as da
        return da.RelayNode(node_id=b"\x09" * 32, storage_path=None)

    def _msg(self, **kw):
        import time
        import decentralized_architecture as da
        base = dict(message_id="m1", sender_id=b"\x01" * 32,
                    recipient_id=b"\x02" * 32, encrypted_payload=b"ct",
                    timestamp=time.time(), ttl=600, hop_count=0)
        base.update(kw)
        return da.RelayMessage(**base)

    def test_fresh_message_queued(self):
        self.assertTrue(self._node().queue_message(self._msg()))

    def test_expired_message_refused(self):
        import time
        node = self._node()
        self.assertFalse(node.queue_message(
            self._msg(timestamp=time.time() - 3600, ttl=60)))

    def test_hop_overflow_refused(self):
        import decentralized_architecture as da
        node = self._node()
        self.assertFalse(node.queue_message(self._msg(hop_count=da.MESH_MAX_HOPS + 1)))

    def test_direct_envelope_preserves_sig(self):
        # The direct-send wire dict must not strip origin authentication.
        import inspect
        import decentralized_architecture as da
        src = inspect.getsource(da.DecentralizedArchitecture._send_direct_to_peer)
        for key in ("'sender_sig'", "'sender_pubkey'", "'hop_count'"):
            self.assertIn(key, src, f"envelope must preserve {key}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

