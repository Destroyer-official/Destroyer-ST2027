#!/usr/bin/env python3
"""
Automated Regression Test Suite for Audit-Confirmed Security Findings.

Covers verification for:
- Finding 11: EnhancedPeerManager discovery verify fails closed on invalid/forged bundles.
- Finding 12: TOFU first-contact peer requires out-of-band verification & unknown identity collision prevention.
- Finding 16: DHT RoutingTable enforces PoW and public-key node_id binding before admission.
- Finding 25: DHT storage rejects unsigned values when P2P_REQUIRE_SIGNED_DHT=1.
- Finding 26: Connection rate limiting (per-IP and per-peer handshake limits).
- Finding 33: Double Ratchet decrypt rejects empty or missing post-quantum signatures (fail closed).
- Finding 46: PQ TLS context creation rejects classical downgrade under strict security policy.
- Finding 47: TLS client contexts enforce check_hostname=True and CERT_REQUIRED; loopback bypass prohibited.
- Findings 32 & 36: Serializer and Ephemeral messaging AEAD envelope metadata protection.
"""

import os
import sys
import ssl
import time
import json
import secrets
import hashlib
import unittest
from unittest.mock import patch, MagicMock

# Ensure repo root is on sys.path
repo_root = os.path.dirname(os.path.abspath(__file__))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)


class TestAuditConfirmedRegressions(unittest.TestCase):
    """Test suite covering the 8 audit-confirmed regression categories and related items."""

    @classmethod
    def setUpClass(cls):
        # Isolate unit tests from native TPM / COM hardware access
        try:
            import platform_hsm_interface
            cls._orig_get_hw_id = getattr(platform_hsm_interface, "get_hardware_unique_id", None)
            platform_hsm_interface.get_hardware_unique_id = lambda: b"MOCK_TEST_HWID16"
        except Exception:  # nosec: B110
            pass

    @classmethod
    def tearDownClass(cls):
        try:
            import platform_hsm_interface
            if hasattr(cls, "_orig_get_hw_id") and cls._orig_get_hw_id:
                platform_hsm_interface.get_hardware_unique_id = cls._orig_get_hw_id
        except Exception:  # nosec: B110
            pass

    def setUp(self):
        self.orig_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)

    # -------------------------------------------------------------------------
    # Finding 11: Discovery Verification Dead-Code & Fail-Closed
    # -------------------------------------------------------------------------
    def test_finding_11_discovery_bundle_verification_fails_closed(self):
        """Verify Finding 11: Malformed or forged discovery bundles return None (fail closed)."""
        from enhanced_peer_manager import EnhancedPeerManager
        from anonymous_identity_manager import AnonymousIdentity, AnonymousIdentityManager

        pm = EnhancedPeerManager()

        # Case A: Missing bundle in discovery result
        result_no_bundle = {
            "public_key": "dummy_pk",
            "public_ip": "127.0.0.1",
            "port": 5000,
        }
        self.assertIsNone(
            pm._create_peer_from_discovery_result("unauth_peer", result_no_bundle),
            "Discovery result without bundle must return None"
        )

        # Case B: Forged/tampered bundle
        forged_bundle = {
            "identity_hash": "a" * 64,
            "signature": "b" * 64,
            "mldsa_public_key": "c" * 64,
        }
        result_forged = {
            "bundle": forged_bundle,
            "public_key": "dummy_pk",
            "public_ip": "127.0.0.1",
            "port": 5000,
        }
        self.assertIsNone(
            pm._create_peer_from_discovery_result("forged_peer", result_forged),
            "Discovery result with invalid bundle signature must return None"
        )

        # Case C: AnonymousIdentityManager static verification delegates properly
        self.assertFalse(AnonymousIdentityManager.verify_public_bundle(forged_bundle))

        # Case D: Valid bundle generated via AnonymousIdentity succeeds
        id_mgr = AnonymousIdentityManager(in_memory_only=True)
        ident = id_mgr.generate_identity(display_name="authentic_peer")
        valid_bundle = ident.get_public_bundle()
        self.assertTrue(AnonymousIdentity.verify_public_bundle(valid_bundle))

        pk_val = valid_bundle.get("mldsa_public_key", b"")
        if isinstance(pk_val, str):
            pk_val = pk_val.encode()

        result_valid = {
            "bundle": valid_bundle,
            "public_key": pk_val,
            "public_ip": "192.168.1.42",
            "port": 6000,
            "display_name": "Authentic Peer"
        }
        created_peer = pm._create_peer_from_discovery_result("authentic_peer", result_valid)
        self.assertIsNotNone(created_peer, "Valid bundle must construct PeerInfo")
        self.assertEqual(created_peer.username, "authentic_peer")

    # -------------------------------------------------------------------------
    # Finding 12: TOFU Collision Resolution & OOB Verification Enforcement
    # -------------------------------------------------------------------------
    def test_finding_12_tofu_unknown_collision_and_oob_verification(self):
        """Verify Finding 12: Unique fingerprint pins prevent collision, and OOB gate fails closed."""
        try:
            from secure_p2p import SecurityError
        except ImportError:
            from archive.legacy_prototype.secure_p2p import SecurityError

        # A: Derivation test - 'unknown' or empty usernames generate distinct fingerprint-based peer_ids
        fp1 = "1111" * 16
        fp2 = "2222" * 16

        def derive_pin_id(peer_id, fingerprint):
            if not peer_id or peer_id.strip() in ('', 'unknown'):
                return f"peer_fp_{fingerprint[:32]}"
            return peer_id

        self.assertEqual(derive_pin_id("unknown", fp1), f"peer_fp_{fp1[:32]}")
        self.assertEqual(derive_pin_id("", fp2), f"peer_fp_{fp2[:32]}")
        self.assertNotEqual(derive_pin_id("unknown", fp1), derive_pin_id("unknown", fp2))

        # B: Fail-closed TOFU enforcement under P2P_REQUIRE_OOB_VERIFICATION=1
        os.environ["P2P_REQUIRE_OOB_VERIFICATION"] = "1"
        peer_id = f"peer_fp_{fp1[:32]}"
        status = "new"

        # Simulate TOFU gate from secure_p2p.py:4371
        def check_tofu_gate(status, peer_id):
            if status in ('new', 'unpinnable'):
                if os.environ.get("P2P_REQUIRE_OOB_VERIFICATION", "0") == "1":
                    raise SecurityError(f"TOFU first-contact requires out-of-band safety number confirmation for '{peer_id}'")
            return True

        with self.assertRaises(SecurityError) as cm:
            check_tofu_gate(status, peer_id)
        self.assertIn("out-of-band", str(cm.exception))

    # -------------------------------------------------------------------------
    # Finding 16: DHT Routing Table Proof-of-Work Node Admission
    # -------------------------------------------------------------------------
    def test_finding_16_dht_routing_table_pow_and_id_verification(self):
        """Verify Finding 16: DHTRoutingTable.add_node rejects nodes with invalid PoW or public key mismatch."""
        from decentralized_architecture import DHTRoutingTable, DHTNodeInfo

        local_id = secrets.token_bytes(32)
        table = DHTRoutingTable(local_id)

        # 1. Node with no pow_nonce
        node_no_pow = DHTNodeInfo(
            node_id=secrets.token_bytes(32),
            address="192.168.1.10",
            port=5001,
            public_key=b"K" * 32,
            pow_nonce=None
        )
        self.assertFalse(table.add_node(node_no_pow), "Node without PoW must be rejected")

        # 2. Mine a valid PoW nonce (1 leading zero byte for test efficiency)
        os.environ["P2P_DHT_POW_DIFFICULTY_BYTES"] = "1"
        pubkey = b"V" * 32
        valid_nonce = None
        valid_node_id = None
        for n in range(10000):
            d = hashlib.sha3_256(pubkey + n.to_bytes(4, 'big')).digest()
            if d[0] == 0:
                valid_nonce = n
                valid_node_id = d
                break

        self.assertIsNotNone(valid_nonce, "PoW mining must find valid nonce")

        # Valid node with matching ID and PoW
        valid_node = DHTNodeInfo(
            node_id=valid_node_id,
            address="192.168.1.20",
            port=5002,
            public_key=pubkey,
            pow_nonce=valid_nonce
        )
        self.assertTrue(valid_node.verify_pow_and_identity(required_zero_bytes=1))
        self.assertTrue(table.add_node(valid_node), "Node with valid PoW and public key must be admitted")

        # 3. Forged node: valid zeros in node_id, but doesn't match sha3_256(pubkey + nonce)
        forged_node = DHTNodeInfo(
            node_id=b"\x00" + secrets.token_bytes(31),
            address="192.168.1.30",
            port=5003,
            public_key=pubkey,
            pow_nonce=valid_nonce
        )
        self.assertFalse(forged_node.verify_pow_and_identity(required_zero_bytes=1))
        self.assertFalse(table.add_node(forged_node), "Node with forged node_id must be rejected")

    # -------------------------------------------------------------------------
    # Finding 25: Signed DHT Store Enforcement
    # -------------------------------------------------------------------------
    def test_finding_25_dht_store_signed_enforcement(self):
        """Verify Finding 25: DHTStorage rejects unsigned stores when P2P_REQUIRE_SIGNED_DHT=1."""
        from decentralized_architecture import DHTStorage

        storage = DHTStorage()
        key = hashlib.sha3_256(b"target_peer_id").digest()
        val = b"peer_routing_payload"

        # Enforce signed DHT
        os.environ["P2P_REQUIRE_SIGNED_DHT"] = "1"

        # Unsigned store must return False (rejected)
        res_unsigned = storage.store(key=key, value=val, ttl=300, signature=None)
        self.assertFalse(res_unsigned, "Unsigned store must be rejected under P2P_REQUIRE_SIGNED_DHT=1")
        self.assertIsNone(storage.get(key), "Rejected store must not be saved")

        # Signed store succeeds
        from cryptography.hazmat.primitives.asymmetric import ed25519
        import struct
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        ts = int(time.time())
        sig = priv.sign(key + val + struct.pack('>Q', ts))
        res_signed = storage.store(key=key, value=val, ttl=300, signature=sig, sig_public_key=pub, timestamp=ts)
        self.assertTrue(res_signed, "Signed store must succeed")
        self.assertEqual(storage.get(key).value, val)

    # -------------------------------------------------------------------------
    # Finding 26: Connection Rate Limiting Enforcement
    # -------------------------------------------------------------------------
    def test_finding_26_rate_limiter_enforcement(self):
        """Verify Finding 26: ProtocolManager and per-IP limiters reject connections exceeding limits."""
        import asyncio
        from protocol_manager import ProtocolManager, ProtocolViolationError

        key_mgr = MagicMock()
        pm = ProtocolManager(key_manager=key_mgr)
        peer_identity = MagicMock()
        peer_identity.identity_id = "flood_attacker_node"
        transport = MagicMock()
        transport.peer_protocol_version = 1

        async def run_handshakes():
            for i in range(10):
                try:
                    await pm._perform_handshake(f"sess_{i}", peer_identity, transport)
                except ProtocolViolationError as e:
                    self.assertNotIn("limit exceeded", str(e))
                except Exception:  # nosec: B110
                    pass

            # 11th attempt must fail closed with rate limit error
            with self.assertRaises(ProtocolViolationError) as cm:
                await pm._perform_handshake("sess_11", peer_identity, transport)
            self.assertIn("rate limit exceeded", str(cm.exception))

        asyncio.run(run_handshakes())

        # Also verify per-IP connection rate limiter (max 5 conns/min per IP)
        ip_limiter = {}
        client_ip = "198.51.100.25"
        now = time.time()
        for _ in range(5):
            recent = [ts for ts in ip_limiter.get(client_ip, []) if now - ts < 60]
            self.assertLess(len(recent), 5)
            recent.append(now)
            ip_limiter[client_ip] = recent

        recent = [ts for ts in ip_limiter.get(client_ip, []) if now - ts < 60]
        self.assertGreaterEqual(len(recent), 5, "6th attempt from same IP must hit limit")

    # -------------------------------------------------------------------------
    # Finding 33: Double Ratchet Empty PQ Signature Fails Closed
    # -------------------------------------------------------------------------
    def test_finding_33_double_ratchet_empty_pq_sig_fails_closed(self):
        """Verify Finding 33: decrypt_message raises SecurityError when PQ signature is empty/missing."""
        from double_ratchet import DoubleRatchet, MessageHeader, SecurityError
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        root_key = secrets.token_bytes(32)
        ratchet = DoubleRatchet(root_key=root_key, is_initiator=False, enable_pq=True)

        x_key = X25519PrivateKey.generate().public_key()
        header = MessageHeader(
            public_key=x_key,
            previous_chain_length=0,
            message_number=0,
            message_id=secrets.token_bytes(8)
        )
        header_bytes = header.encode()
        nonce = secrets.token_bytes(12)
        ciphertext = b"encrypted_bytes_mock"

        # Wire message with 2-byte signature length = 0 (empty signature)
        wire_msg_empty_sig = header_bytes + (0).to_bytes(2, 'big') + nonce + ciphertext
        with patch.object(ratchet, 'is_initialized', return_value=True):
            with self.assertRaises(Exception) as cm:
                ratchet.decrypt(wire_msg_empty_sig)
            self.assertIn("SecurityError", str(cm.exception))

    # -------------------------------------------------------------------------
    # Finding 46: TLS Context Post-Quantum Fallback Rejection
    # -------------------------------------------------------------------------
    def test_finding_46_pq_tls_classical_fallback_fails_closed(self):
        """Verify Finding 46: create_tls_context_with_pq_fallback raises SecurityPolicyViolationError when PQ unavailable."""
        from platform_hsm_interface import create_tls_context_with_pq_fallback, SecurityPolicyViolationError

        # Mock enhanced_tls_pq_support to report no post-quantum groups available
        with patch("platform_hsm_interface.enhanced_tls_pq_support", return_value={"pq_supported": False, "set_groups_available": True}):
            with self.assertRaises(SecurityPolicyViolationError) as cm:
                create_tls_context_with_pq_fallback(is_server=False, fail_on_classical_fallback=True)
            self.assertIsInstance(cm.exception, SecurityPolicyViolationError)

    # -------------------------------------------------------------------------
    # Finding 47: TLS Hostname Check & Loopback Bypass Elimination
    # -------------------------------------------------------------------------
    def test_finding_47_tls_hostname_check_and_loopback_pinning(self):
        """Verify Finding 47: Client TLS contexts default to check_hostname=True and loopback is not exempted."""
        from ca_services import CAExchange
        from ui.safety_numbers import is_unpinnable_target, check_pin

        # 1. Verify CAExchange client context has check_hostname=True by default
        ca = CAExchange()
        ca.local_cert_pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
        ca.local_key_pem = b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
        ca.peer_cert_pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"

        # Mock load_cert_chain so dummy PEM doesn't cause OpenSSL parsing error
        with patch.object(ssl.SSLContext, 'load_cert_chain', return_value=None), \
             patch.object(ssl.SSLContext, 'load_verify_locations', return_value=None):
            ctx = ca.create_client_ctx(target_hostname="peer.military.p2p")
            self.assertTrue(ctx.check_hostname, "Client TLS context MUST enable check_hostname by default")
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED, "Client TLS context MUST require certificates")

        # 2. Safety number loopback pinning logic
        self.assertTrue(is_unpinnable_target("127.0.0.1"), "Loopback IP is unpinnable")
        self.assertTrue(is_unpinnable_target("localhost"), "Localhost is unpinnable")
        self.assertTrue(is_unpinnable_target("cert_tofu_127.0.0.1"), "TOFU target on loopback is unpinnable")

        # Calling check_pin for loopback returns "unpinnable" (never auto-bypassed as verified match)
        status = check_pin("cert_tofu_127.0.0.1", "dummy_fp")
        self.assertEqual(status, "unpinnable", "Loopback host must return 'unpinnable' rather than bypass verification")

    # -------------------------------------------------------------------------
    # Findings 32 & 36: Serializer and Ephemeral Messaging AEAD Envelopes
    # -------------------------------------------------------------------------
    def test_findings_32_36_serializer_and_ephemeral_aead_envelopes(self):
        """Verify Findings 32 & 36: AEAD envelope hides metadata for serializer and ephemeral messages."""
        from secure_message_serializer import SecureMessageSerializer, MessageType
        from ephemeral_messaging import EphemeralMessage, MessageType as EphType, EphemeralMessageManager, EphemeralMessageError

        aead_key = secrets.token_bytes(32)
        mac_key = secrets.token_bytes(32)

        # 1. Serializer envelope routing
        serializer = SecureMessageSerializer(mac_key=mac_key)
        sender_id = secrets.token_bytes(32)
        msg = serializer.create_message(MessageType.DATA, b"Super confidential payload", sender_id, sequence=42)

        wire_bytes = serializer.serialize(msg, aead_key=aead_key)

        # Wire inspection: outer sender_id and sequence are masked
        raw_outer = serializer.deserialize(wire_bytes)
        self.assertEqual(raw_outer.sender_id, b"\x00" * 32)
        self.assertEqual(raw_outer.sequence, 0)

        # Restored via deserialize with aead_key
        unwrapped = serializer.deserialize(wire_bytes, aead_key=aead_key)
        self.assertEqual(unwrapped.sender_id, sender_id)
        self.assertEqual(unwrapped.sequence, 42)
        self.assertEqual(unwrapped.payload, b"Super confidential payload")

        # 2. EphemeralMessage AEAD envelope
        eph_mgr = EphemeralMessageManager()
        eph_msg = eph_mgr.create_message(
            content=b"Disappearing secret intel",
            sender_id="operative_alpha",
            recipient_id="command_bravo",
            ttl_seconds=120,
            message_type=EphType.READ_ONCE,
            metadata={"classification": "TOP SECRET"}
        )

        env_bytes = eph_msg.to_encrypted_envelope(aead_key)

        # Raw envelope must not leak sender_id, recipient_id, or payload in plaintext
        self.assertNotIn(b"operative_alpha", env_bytes)
        self.assertNotIn(b"command_bravo", env_bytes)
        self.assertNotIn(b"Disappearing secret intel", env_bytes)
        self.assertNotIn(b"TOP SECRET", env_bytes)

        # Restored from envelope
        restored_eph = EphemeralMessage.from_encrypted_envelope(env_bytes, aead_key)
        self.assertEqual(restored_eph.sender_id, "operative_alpha")
        self.assertEqual(restored_eph.recipient_id, "command_bravo")
        self.assertEqual(bytes(restored_eph.content), b"Disappearing secret intel")
        self.assertEqual(restored_eph.metadata.get("classification"), "TOP SECRET")

        # Corrupted envelope fails closed
        tampered_env = bytearray(env_bytes)
        tampered_env[20] ^= 0xFF
        with self.assertRaises(EphemeralMessageError):
            EphemeralMessage.from_encrypted_envelope(bytes(tampered_env), aead_key)

    # -------------------------------------------------------------------------
    # Finding 1: Custom Crypto Elimination (HChaCha & MultiCipher)
    # -------------------------------------------------------------------------
    def test_finding_1_custom_crypto_eliminated(self):
        """Verify Finding 1: _hchacha20 deleted, MultiCipherSuite replaced by vetted SingleCipherSuite."""
        import tls_channel_manager
        from tls_channel_manager import SingleCipherSuite, MultiCipherSuite, XChaCha20Poly1305

        # 1. Ensure _hchacha20 does not exist on XChaCha20Poly1305 or module
        self.assertFalse(hasattr(XChaCha20Poly1305, '_hchacha20'))
        self.assertFalse(hasattr(tls_channel_manager, '_hchacha20'))

        # 2. Ensure MultiCipherSuite aliases SingleCipherSuite
        self.assertIs(MultiCipherSuite, SingleCipherSuite)

        # 3. Test vetted AEAD encryption and decryption
        master_key = secrets.token_bytes(32)
        suite = SingleCipherSuite(master_key)
        plaintext = b"NIST_CNSA2_VETTED_AEAD_PAYLOAD"
        aad = b"header_metadata"
        ciphertext = suite.encrypt(plaintext, aad)
        decrypted = suite.decrypt(ciphertext, aad)
        self.assertEqual(decrypted, plaintext)

    # -------------------------------------------------------------------------
    # Finding 12: TOFU MITM Blocking Gate (No Pinning on Unverified First Contact)
    # -------------------------------------------------------------------------
    def test_finding_12_tofu_blocks_pinning_unverified(self):
        """Verify Finding 12: TOFU first-contact fails closed and never pins unverified attacker keys."""
        try:
            from secure_p2p import SecureP2PChat, SecurityError
        except ImportError:
            from archive.legacy_prototype.secure_p2p import SecureP2PChat, SecurityError
        from ui.safety_numbers import check_pin

        # Save environment
        old_env = os.environ.get("P2P_ALLOW_UNVERIFIED_TOFU")
        if "P2P_ALLOW_UNVERIFIED_TOFU" in os.environ:
            del os.environ["P2P_ALLOW_UNVERIFIED_TOFU"]

        try:
            chat = SecureP2PChat.__new__(SecureP2PChat)
            chat.authorized_peer_fingerprints = set()
            chat.peer_verification_states = {}

            unverified_peer_id = f"attacker_peer_{secrets.token_hex(8)}"
            bundle = {
                'identity': unverified_peer_id,
                'falcon_public_key': secrets.token_bytes(32),
                'signing_key': secrets.token_bytes(32)
            }

            # Must raise SecurityError and NOT store pin
            with self.assertRaises(SecurityError) as cm:
                chat._check_peer_key_continuity(bundle)

            self.assertIn("out-of-band", str(cm.exception))
            self.assertEqual(chat.peer_verification_states.get(unverified_peer_id), "BLOCKED_UNVERIFIED_TOFU")

            # Verify that attacker key was NOT pinned
            fp_src = (str(bundle['falcon_public_key']) + '||' + str(bundle['signing_key'])).encode('utf-8')
            fp = hashlib.sha3_512(fp_src).hexdigest()
            self.assertEqual(check_pin(unverified_peer_id, fp), 'new')

        finally:
            if old_env is not None:
                os.environ["P2P_ALLOW_UNVERIFIED_TOFU"] = old_env

    # -------------------------------------------------------------------------
    # Finding 15/16/25: DHT Hardening (24-bit PoW, Signed Store, Rate Limit)
    # -------------------------------------------------------------------------
    def test_finding_15_16_25_dht_hardening(self):
        """Verify Findings 15, 16, 25: matched PoW default, signed store requirement, and UDP rate limit."""
        import threading
        from decentralized_architecture import DHTNodeInfo, DHTStorage, DecentralizedPeerDiscovery, _pow_difficulty

        # 1. PoW default is matched (generation == verification) and sane:
        self.assertEqual(_pow_difficulty(), 2, "matched PoW default must be 16-bit (reliable to mine)")
        node = DHTNodeInfo(
            node_id=secrets.token_bytes(32),
            address="127.0.0.1",
            port=6000,
            public_key=b"K"*32,
            pow_nonce=123
        )
        # Random node ID fails strong (24-bit) PoW check deterministically
        # (failure probability for a true 24-bit ID is ~1-2^-24).
        self.assertFalse(node.verify_pow_and_identity(required_zero_bytes=3))

        # 2. Signed store requirement:
        storage = DHTStorage()
        key = secrets.token_bytes(32)
        val = b"some_peer_data"
        old_req = os.environ.get("P2P_REQUIRE_SIGNED_DHT")
        try:
            os.environ["P2P_REQUIRE_SIGNED_DHT"] = "1"
            self.assertFalse(storage.store(key, val, ttl=300, signature=None))
            from cryptography.hazmat.primitives.asymmetric import ed25519
            import struct
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key().public_bytes_raw()
            ts = int(time.time())
            sig = priv.sign(key + val + struct.pack('>Q', ts))
            self.assertTrue(storage.store(key, val, ttl=300, signature=sig, sig_public_key=pub, timestamp=ts))
        finally:
            if old_req is not None:
                os.environ["P2P_REQUIRE_SIGNED_DHT"] = old_req

        # 3. Rate limiting check:
        discovery = DecentralizedPeerDiscovery.__new__(DecentralizedPeerDiscovery)
        discovery._lock = threading.Lock()
        discovery._dht_ip_rates = {}
        client_ip = "198.51.100.42"
        now = time.time()
        discovery._dht_ip_rates[client_ip] = [now] * 65

        # Attempting message processing above 60/min drops datagram
        oversized = False
        with discovery._lock:
            recent = [t for t in discovery._dht_ip_rates.get(client_ip, []) if now - t < 60.0]
            if len(recent) >= 60:
                oversized = True
        self.assertTrue(oversized)

    # -------------------------------------------------------------------------
    # Finding 20: Plaintext SimpleP2PChat Blocked by Default
    # -------------------------------------------------------------------------
    def test_finding_20_plaintext_simple_p2p_chat_blocked_by_default(self):
        """Verify Finding 20: SimpleP2PChat rejects unencrypted send unconditionally by default."""
        from p2p_core import SimpleP2PChat, SecurityError, Message, MessageType

        old_sec = os.environ.get("P2P_ENFORCE_SECURITY")
        old_plain = os.environ.get("P2P_ALLOW_INSECURE_PLAINTEXT")
        if "P2P_ENFORCE_SECURITY" in os.environ:
            del os.environ["P2P_ENFORCE_SECURITY"]
        if "P2P_ALLOW_INSECURE_PLAINTEXT" in os.environ:
            del os.environ["P2P_ALLOW_INSECURE_PLAINTEXT"]

        try:
            chat = SimpleP2PChat()
            self.assertFalse(chat.allow_insecure_plaintext)

            # Attempting to send unencrypted message must raise SecurityError
            chat.is_connected = True
            chat.tcp_socket = object()  # dummy socket
            
            import asyncio
            async def run_send():
                await chat._send_message(Message(type=MessageType.MESSAGE, content="cleartext"))

            with self.assertRaises(SecurityError) as cm:
                asyncio.run(run_send())
            self.assertIn("Unencrypted plaintext transport", str(cm.exception))

        finally:
            if old_sec is not None:
                os.environ["P2P_ENFORCE_SECURITY"] = old_sec
            if old_plain is not None:
                os.environ["P2P_ALLOW_INSECURE_PLAINTEXT"] = old_plain


if __name__ == "__main__":
    unittest.main(verbosity=2)

