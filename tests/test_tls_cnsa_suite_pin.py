"""TLS 1.3 CNSA suite pin + SecurityError definition (audit 2026-10-15).

Pre-fix: tls_channel_manager raised SecurityError at 7+ fail-closed sites
(CERT_NONE prohibition, CA-load failure) but never defined/imported it —
those raises surfaced as NameError at runtime, defeating callers catching
SecurityError specifically. Also, Python's SSLContext.set_ciphers cannot
constrain the TLS 1.3 ciphersuite offer, so OpenSSL defaults left
TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_GCM_SHA256 negotiable on the
live secure_p2p path (ca_services context) with no post-handshake pin.

Post-fix: SecurityError defined in-module; do_handshake() pins the
negotiated suite to TLS_AES_256_GCM_SHA384 (CNSA 2.0) post-handshake,
closing + raising SecurityError on any mismatch (mirrors
secure_transmit_2027.assert_outer_is_pinned).
"""

import pytest


def test_securityerror_defined_in_module():
    import tls_channel_manager
    assert hasattr(tls_channel_manager, "SecurityError")
    with pytest.raises(tls_channel_manager.SecurityError):
        raise tls_channel_manager.SecurityError("test")


def test_do_handshake_pins_cnsa_suite(monkeypatch):
    """do_handshake must accept TLS_AES_256_GCM_SHA384 and refuse others."""
    import tls_channel_manager as t

    class FakeSSLSocket:
        def __init__(self, cipher_name, version):
            self._cipher = (cipher_name, "TLSv1.3", 512)
            self._version = version
            self.closed = False
            self.context = type("Ctx", (), {"_pq_enabled": False})()

        def do_handshake(self):
            pass

        def cipher(self):
            return self._cipher

        def version(self):
            return self._version

        def close(self):
            self.closed = True

    def make_channel(cipher_name, version):
        ch = t.TLSSecureChannel.__new__(t.TLSSecureChannel)
        ch.ssl_socket = FakeSSLSocket(cipher_name, version)
        ch.handshake_complete = False
        ch.enable_pq_kem = False
        ch.is_server = True  # server side skips client-only DANE branch
        ch.dane_tlsa_records = None
        ch.certificate_pinning = None
        ch.pq_shared_secret = None
        ch.connected = True
        # shadow methods that would touch uninitialized instance state
        ch.is_standalone_mode = lambda: False
        ch._verify_security_parameters = lambda ctx: None
        return ch

    # CNSA suite passes the pin
    ch = make_channel("TLS_AES_256_GCM_SHA384", "TLSv1.3")
    assert ch.do_handshake() is True
    assert ch.handshake_complete is True
    assert ch.ssl_socket.closed is False

    # Non-CNSA TLS 1.3 suite refused + socket closed
    ch = make_channel("TLS_CHACHA20_POLY1305_SHA256", "TLSv1.3")
    with pytest.raises(t.SecurityError, match="suite pin violated"):
        ch.do_handshake()
    assert ch.handshake_complete is False
    assert ch.ssl_socket.closed is True

    # AES-128-GCM refused
    ch = make_channel("TLS_AES_128_GCM_SHA256", "TLSv1.3")
    with pytest.raises(t.SecurityError, match="suite pin violated"):
        ch.do_handshake()
    assert ch.ssl_socket.closed is True

    # Non-TLS1.3 version refused even with CNSA suite name
    ch = make_channel("TLS_AES_256_GCM_SHA384", "TLSv1.2")
    with pytest.raises(t.SecurityError, match="suite pin violated"):
        ch.do_handshake()
    assert ch.ssl_socket.closed is True
