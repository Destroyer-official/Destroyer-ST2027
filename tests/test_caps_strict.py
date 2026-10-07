"""Caps unification + encrypt-sentinel strict mode (pure asserts, no network)."""
import asyncio
import os
import unittest


class TestCapsConsistency(unittest.TestCase):
    def test_canonical_values_and_layering(self):
        from utils.message_caps import (
            MAX_MESSAGE_PAYLOAD, MAX_FILE_PAYLOAD, MAX_FRAME,
            PRE_AUTH_MAX, POST_AUTH_MAX,
            validate_payload_size, validate_frame_size,
            is_strict_encrypt,
        )
        self.assertEqual(MAX_MESSAGE_PAYLOAD, 65536)
        self.assertEqual(MAX_FRAME, 4 * 1024 * 1024)
        self.assertEqual(PRE_AUTH_MAX, 64 * 1024)
        self.assertEqual(POST_AUTH_MAX, 512 * 1024)
        self.assertEqual(MAX_FILE_PAYLOAD, 512 * 1024)
        # Layered: frame > post-auth >= pre-auth == chat payload
        self.assertGreater(MAX_FRAME, POST_AUTH_MAX)
        self.assertGreaterEqual(POST_AUTH_MAX, PRE_AUTH_MAX)
        self.assertEqual(PRE_AUTH_MAX, MAX_MESSAGE_PAYLOAD)
        self.assertGreater(MAX_FRAME, MAX_MESSAGE_PAYLOAD)
        # Helpers exist and are callable
        self.assertTrue(callable(validate_payload_size))
        self.assertTrue(callable(validate_frame_size))
        self.assertTrue(callable(is_strict_encrypt))

    def test_validate_payload_sizes(self):
        from utils.message_caps import validate_payload_size
        # Chat MSG within 64KB passes
        self.assertEqual(validate_payload_size(0), 0)
        self.assertEqual(validate_payload_size(65536), 65536)
        self.assertEqual(validate_payload_size(b"x" * 100), 100)
        # Chat MSG over 64KB raises
        with self.assertRaises(ValueError):
            validate_payload_size(65537)
        with self.assertRaises(ValueError):
            validate_payload_size(b"x" * (64 * 1024 + 1))
        # FILE chunks with explicit flag allow up to 512KB
        self.assertEqual(validate_payload_size(512 * 1024, is_file=True), 512 * 1024)
        self.assertEqual(validate_payload_size(b"x" * 70000, is_file=True), 70000)
        with self.assertRaises(ValueError):
            validate_payload_size(512 * 1024 + 1, is_file=True)
        # Absolute frame ceiling always applies
        with self.assertRaises(ValueError):
            validate_payload_size(4 * 1024 * 1024 + 1, is_file=True)

    def test_cross_module_consistency(self):
        from utils import message_caps as caps
        # p2p_core frame caps mirror central caps
        import p2p_core
        self.assertEqual(p2p_core.FramedSocket.MAX_MESSAGE_SIZE, caps.MAX_FRAME)
        self.assertEqual(p2p_core.FramedSocket.PRE_AUTH_MAX_MESSAGE_SIZE, caps.PRE_AUTH_MAX)
        self.assertEqual(p2p_core.FramedSocket.POST_AUTH_MAX_MESSAGE_SIZE, caps.POST_AUTH_MAX)
        # security/validation chat cap mirrors central caps
        from security.validation import InputValidator
        self.assertEqual(InputValidator.MAX_MESSAGE_SIZE, caps.MAX_MESSAGE_PAYLOAD)
        # serializer per-type caps mirror central caps
        from secure_message_serializer import SecureMessageSerializer
        self.assertEqual(SecureMessageSerializer.MAX_MSG_PAYLOAD, caps.MAX_MESSAGE_PAYLOAD)
        self.assertEqual(SecureMessageSerializer.MAX_FILE_PAYLOAD, caps.MAX_FILE_PAYLOAD)
        # messaging/handler uses same 64KB bound (literal kept, value-checked)
        self.assertEqual(caps.MAX_MESSAGE_PAYLOAD, 65536)
        # config_manager defaults mirror central caps (discoverability)
        from utils.config_manager import ConfigManager
        d = ConfigManager.DEFAULT_SECURITY_SETTINGS
        mc = d["security"]["message_caps"]
        self.assertEqual(mc["max_message_payload"], caps.MAX_MESSAGE_PAYLOAD)
        self.assertEqual(mc["max_frame"], caps.MAX_FRAME)
        self.assertEqual(mc["pre_auth_max"], caps.PRE_AUTH_MAX)
        self.assertEqual(mc["post_auth_max"], caps.POST_AUTH_MAX)

    def test_serializer_enforces_unified_chat_cap(self):
        from secure_message_serializer import SecureMessageSerializer, MessageType
        s = SecureMessageSerializer(mac_key=b"k" * 32)
        sender = b"s" * 32
        # 64KB chat payload serializes
        m_ok = s.create_message(MessageType.DATA, b"x" * 65536, sender, sequence=1)
        wire = s.serialize(m_ok)
        self.assertTrue(len(wire) > 65536)
        # >64KB chat payload rejected on serialize
        m_big = s.create_message(MessageType.DATA, b"x" * 65537, sender, sequence=2)
        with self.assertRaises(ValueError):
            s.serialize(m_big)
        # FILE_TRANSFER with explicit type allows >64KB up to 512KB
        m_file = s.create_message(MessageType.FILE_TRANSFER, b"y" * 70000, sender, sequence=3)
        wire_f = s.serialize(m_file)
        self.assertTrue(len(wire_f) > 70000)
        # FILE over 512KB rejected
        m_file_big = s.create_message(MessageType.FILE_TRANSFER, b"z" * (512 * 1024 + 1), sender, sequence=4)
        with self.assertRaises(ValueError):
            s.serialize(m_file_big)


class TestStrictEncryptSentinel(unittest.TestCase):
    def test_lab_default_is_permissive(self):
        # Ensure lab env (no strict, no prod) -> not strict
        old = dict(os.environ)
        try:
            for k in ("P2P_STRICT_ENCRYPT", "P2P_PRODUCTION", "SECURE_P2P_PRODUCTION"):
                os.environ.pop(k, None)
            os.environ.pop("P2P_ENV", None)
            from utils.message_caps import is_strict_encrypt
            # Re-import to re-evaluate env (function reads env live)
            self.assertFalse(is_strict_encrypt())
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_strict_env_flag_enables(self):
        old = os.environ.get("P2P_STRICT_ENCRYPT")
        try:
            os.environ["P2P_STRICT_ENCRYPT"] = "1"
            from utils.message_caps import is_strict_encrypt
            self.assertTrue(is_strict_encrypt())
        finally:
            if old is None:
                os.environ.pop("P2P_STRICT_ENCRYPT", None)
            else:
                os.environ["P2P_STRICT_ENCRYPT"] = old

    def test_production_auto_enables_strict(self):
        old = os.environ.get("P2P_PRODUCTION")
        try:
            os.environ["P2P_PRODUCTION"] = "1"
            # Ensure explicit flag cleared so auto-on path is exercised
            old2 = os.environ.pop("P2P_STRICT_ENCRYPT", None)
            try:
                from utils.message_caps import is_strict_encrypt
                self.assertTrue(is_strict_encrypt())
            finally:
                if old2 is not None:
                    os.environ["P2P_STRICT_ENCRYPT"] = old2
        finally:
            if old is None:
                os.environ.pop("P2P_PRODUCTION", None)
            else:
                os.environ["P2P_PRODUCTION"] = old

    def test_require_encrypted_raises_on_empty(self):
        # Pure: no network, bypass __init__ via __new__
        from secure_p2p import SecureP2PChat, SecurityError
        inst = SecureP2PChat.__new__(SecureP2PChat)
        with self.assertRaises(SecurityError):
            inst._require_encrypted(b"", "test:empty")
        with self.assertRaises(SecurityError):
            inst._require_encrypted(None, "test:none")
        # Non-empty passes through
        self.assertEqual(inst._require_encrypted(b"ct", "test:ok"), b"ct")

    def test_encrypt_message_strict_raises_instead_of_sentinel(self):
        # Pure: not connected -> lab returns b'', strict raises SecurityError.
        # No sockets touched (early return before any I/O).
        from secure_p2p import SecureP2PChat, SecurityError
        old_strict = os.environ.get("P2P_STRICT_ENCRYPT")
        old_prod = os.environ.get("P2P_PRODUCTION")
        old_sprod = os.environ.get("SECURE_P2P_PRODUCTION")
        old_env = os.environ.get("P2P_ENV")
        try:
            inst = SecureP2PChat.__new__(SecureP2PChat)
            # Minimal attrs needed before TLS/ratchet checks
            inst.is_connected = False
            inst.tcp_socket = None
            inst.tls_channel = None
            inst.ratchet = None
            # Stub NIST enforcement to pass through to is_connected check
            inst.enforce_nist_level5_for_operation = lambda *a, **k: None

            # Lab default: returns b'' sentinel (compat)
            for k in ("P2P_STRICT_ENCRYPT", "P2P_PRODUCTION", "SECURE_P2P_PRODUCTION"):
                os.environ.pop(k, None)
            os.environ.pop("P2P_ENV", None)
            # Control frame bypasses InputValidator; hits not-connected path
            lab_res = asyncio.run(inst._encrypt_message("HEARTBEAT"))
            self.assertEqual(lab_res, b"")

            # Strict mode: raises instead of b''
            os.environ["P2P_STRICT_ENCRYPT"] = "1"
            with self.assertRaises(SecurityError):
                asyncio.run(inst._encrypt_message("HEARTBEAT"))
        finally:
            for k, v in (("P2P_STRICT_ENCRYPT", old_strict), ("P2P_PRODUCTION", old_prod),
                         ("SECURE_P2P_PRODUCTION", old_sprod), ("P2P_ENV", old_env)):
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


    def test_p2p_core_module_aliases_match_framed_socket(self):
        # 2026-09-18 regression: secure_p2.py/secure_p2p.py call
        # p2p.PRE_AUTH_TIMEOUT etc. at module scope (14 sites each); the
        # constants live on FramedSocket. Module aliases must exist and
        # equal the class values or every live handshake AttributeErrors.
        import p2p_core
        for name in ("PRE_AUTH_TIMEOUT", "PRE_AUTH_MAX_MESSAGE_SIZE",
                     "POST_AUTH_MAX_MESSAGE_SIZE", "MAX_MESSAGE_SIZE",
                     "MAX_CHAT_PAYLOAD", "DEFAULT_RECV_TIMEOUT",
                     "DEFAULT_SEND_TIMEOUT"):
            self.assertTrue(hasattr(p2p_core, name), f"missing p2p_core.{name}")
            self.assertEqual(getattr(p2p_core, name),
                             getattr(p2p_core.FramedSocket, name))

    def test_p2p_core_receive_framed_forwards_max_size(self):
        # 2026-09-18 regression: module wrapper dropped the max_size kwarg
        # all 28 live-handshake sites pass (TypeError before any exchange).
        import inspect
        import p2p_core
        params = inspect.signature(p2p_core.receive_framed).parameters
        self.assertIn("max_size", params)

    def test_hybrid_bundle_ceiling_fits_measured_bundle(self):
        # 2026-09-19 regression: hybrid bundle measures ~1.8MB (McEliece pk
        # base64 + ML-KEM pk + sigs); 64KB pre-auth cap rejected it, killing
        # every live handshake at bundle exchange. The 2MB bundle-only
        # ceiling must fit it while staying under the 4MB frame ceiling.
        import p2p_core
        from utils import message_caps as caps
        self.assertEqual(p2p_core.PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE, 2 * 1024 * 1024)
        self.assertEqual(caps.PRE_AUTH_HYBRID_BUNDLE_MAX, 2 * 1024 * 1024)
        self.assertEqual(p2p_core.PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE,
                         p2p_core.FramedSocket.PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE)
        self.assertGreater(p2p_core.PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE,
                           p2p_core.PRE_AUTH_MAX_MESSAGE_SIZE)
        self.assertLessEqual(p2p_core.PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE,
                             p2p_core.MAX_MESSAGE_SIZE)


if __name__ == "__main__":
    unittest.main()
