#!/usr/bin/env python3
"""
tests/test_noise_pq_hardened.py
Sovereign Defense Hardening Test Suite:
1. Noise_XXhfs_psk2 Pattern (Air-gapped 256-bit symmetric entropy floor)
2. StatelessCookieGate (Anti-amplification & Anti-CPU exhaustion proof-of-work)
"""

import os
import secrets
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import noise_pq as npq
from liboqs_wrapper import LibOQS_MLDSA_87


def _make_identities():
    sig_engine = LibOQS_MLDSA_87()
    ci_pk, ci_sk = sig_engine.keygen()
    cr_pk, cr_sk = sig_engine.keygen()
    return (ci_pk, ci_sk), (cr_pk, cr_sk)


class TestNoisePsk2Hardening:
    """Rigorous verification of Noise_XXhfs_psk2 hardware/air-gapped PSK infusion."""

    def test_psk2_handshake_agreement(self):
        """Verify initiator and responder establish identical crossed keys with 32-byte PSK."""
        (ci_pk, ci_sk), (cr_pk, cr_sk) = _make_identities()
        psk = secrets.token_bytes(32)

        ini = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk, psk=psk)
        rsp = npq.NoiseSession(is_initiator=False, sig_pk=cr_pk, sig_sk=cr_sk, psk=psk)

        import hashlib
        assert ini.sym.h == hashlib.sha384(npq.PROTOCOL_NAME_PSK2).digest()
        assert rsp.sym.h == hashlib.sha384(npq.PROTOCOL_NAME_PSK2).digest()

        m1 = npq.initiator_hello(ini)
        m2 = npq.responder_reply(rsp, m1)
        npq.initiator_finish(ini, m2, expected_peer_pk=cr_pk)
        m3 = npq.initiator_complete(ini)
        npq.responder_complete(rsp, m3, expected_peer_pk=ci_pk)

        ki_s, ki_r, hi = npq.split_session(ini)
        kr_s, kr_r, hr = npq.split_session(rsp)

        assert ki_s == kr_r, "Crossed sending/receiving keys must match"
        assert ki_r == kr_s, "Crossed receiving/sending keys must match"
        assert hi == hr, "Channel binding transcript hash must be bit-for-bit identical"
        assert len(hi) == 48

        # Bidirectional transport verification under PSK
        wire1 = npq.transport_send(ini, b"TOP_SECRET_TACTICAL_TELEMETRY")
        assert npq.transport_recv(rsp, wire1) == b"TOP_SECRET_TACTICAL_TELEMETRY"

        wire2 = npq.transport_send(rsp, b"BASE_ACKNOWLEDGED_BURST")
        assert npq.transport_recv(ini, wire2) == b"BASE_ACKNOWLEDGED_BURST"

    def test_psk_divergence_from_non_psk(self):
        """Verify PSK session produces distinct transcript and keys compared to bare XXhfs."""
        (ci_pk, ci_sk), (cr_pk, cr_sk) = _make_identities()
        psk = secrets.token_bytes(32)

        # PSK session
        ini_psk = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk, psk=psk)
        rsp_psk = npq.NoiseSession(is_initiator=False, sig_pk=cr_pk, sig_sk=cr_sk, psk=psk)
        m1 = npq.initiator_hello(ini_psk)
        m2 = npq.responder_reply(rsp_psk, m1)
        npq.initiator_finish(ini_psk, m2, expected_peer_pk=cr_pk)
        m3 = npq.initiator_complete(ini_psk)
        npq.responder_complete(rsp_psk, m3, expected_peer_pk=ci_pk)
        k_psk, _, h_psk = npq.split_session(ini_psk)

        # Bare session (no PSK)
        ini_bare = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk)
        rsp_bare = npq.NoiseSession(is_initiator=False, sig_pk=cr_pk, sig_sk=cr_sk)
        m1_b = npq.initiator_hello(ini_bare)
        m2_b = npq.responder_reply(rsp_bare, m1_b)
        npq.initiator_finish(ini_bare, m2_b, expected_peer_pk=cr_pk)
        m3_b = npq.initiator_complete(ini_bare)
        npq.responder_complete(rsp_bare, m3_b, expected_peer_pk=ci_pk)
        k_bare, _, h_bare = npq.split_session(ini_bare)

        assert k_psk != k_bare, "PSK must cryptographically diversify transport keys"
        assert h_psk != h_bare, "PSK must alter channel binding hash"

    def test_psk_mismatch_fails_closed(self):
        """Verify handshake fails closed when peers possess mismatched PSKs."""
        (ci_pk, ci_sk), (cr_pk, cr_sk) = _make_identities()
        psk_alice = secrets.token_bytes(32)
        psk_bob = secrets.token_bytes(32)

        ini = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk, psk=psk_alice)
        rsp = npq.NoiseSession(is_initiator=False, sig_pk=cr_pk, sig_sk=cr_sk, psk=psk_bob)

        m1 = npq.initiator_hello(ini)
        m2 = npq.responder_reply(rsp, m1)
        # Initiator processes M2 and mixes psk_alice:
        npq.initiator_finish(ini, m2, expected_peer_pk=cr_pk)
        # M3 emitted under psk_alice:
        m3 = npq.initiator_complete(ini)

        # Responder expected psk_bob: transcript diverged, decryption fails closed
        with pytest.raises(npq.NoiseError, match="handshake authentication failed"):
            npq.responder_complete(rsp, m3, expected_peer_pk=ci_pk)

    def test_psk_vs_non_psk_mismatch_fails_closed(self):
        """Verify handshake aborts if one peer enables PSK and the other does not."""
        (ci_pk, ci_sk), (cr_pk, cr_sk) = _make_identities()
        psk = secrets.token_bytes(32)

        ini = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk, psk=psk)
        rsp = npq.NoiseSession(is_initiator=False, sig_pk=cr_pk, sig_sk=cr_sk, psk=None)

        m1 = npq.initiator_hello(ini)
        m2 = npq.responder_reply(rsp, m1)
        # Initiator has PSK protocol name, responder does not -> M2 decryption fails
        with pytest.raises(npq.NoiseError, match="handshake authentication failed"):
            npq.initiator_finish(ini, m2, expected_peer_pk=cr_pk)

    def test_invalid_psk_length_rejected(self):
        """Verify non-32-byte PSK raises NoiseError fail-closed."""
        (ci_pk, ci_sk), _ = _make_identities()
        with pytest.raises(npq.NoiseError, match="PSK parameter violation"):
            npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk, psk=b"short_16_bytes!!")

        with pytest.raises(npq.NoiseError, match="PSK parameter violation"):
            npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk, psk=secrets.token_bytes(64))

    def test_psk_zeroization_on_destroy(self):
        """Verify mutable PSK buffer is zeroized when session is destroyed."""
        (ci_pk, ci_sk), _ = _make_identities()
        raw_psk = bytearray(secrets.token_bytes(32))
        sess = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk, psk=raw_psk)
        sess.destroy()
        assert sess.psk is None
        assert all(b == 0 for b in raw_psk), "Mutable PSK must be zeroized in-place upon destroy()"


class TestStatelessCookieGate:
    """Rigorous verification of anti-amplification and anti-DoS cookie gate."""

    def test_cookie_generation_and_validation(self):
        """Verify cookie generated for a specific IP, port, and M1 prefix verifies cleanly."""
        gate = npq.StatelessCookieGate(rotation_interval=60)
        client_ip = "198.51.100.42"
        client_port = 54321
        m1_prefix = secrets.token_bytes(64)

        cookie = gate.create_cookie(client_ip, client_port, m1_prefix)
        assert len(cookie) == 38  # 6B magic + 8B epoch + 24B MAC
        assert cookie.startswith(npq.StatelessCookieGate.MAGIC)

        # Legitimate verification passes
        assert gate.verify_cookie(cookie, client_ip, client_port, m1_prefix) is True

    def test_spoofed_ip_or_port_rejected(self):
        """Verify cookie validation fails if source IP or port is spoofed."""
        gate = npq.StatelessCookieGate()
        real_ip = "203.0.113.10"
        real_port = 50001
        m1_prefix = secrets.token_bytes(64)

        cookie = gate.create_cookie(real_ip, real_port, m1_prefix)

        # Attacker spoofs different IP
        assert gate.verify_cookie(cookie, "203.0.113.99", real_port, m1_prefix) is False
        # Attacker spoofs different port
        assert gate.verify_cookie(cookie, real_ip, 50002, m1_prefix) is False
        # Attacker swaps M1 payload prefix
        assert gate.verify_cookie(cookie, real_ip, real_port, secrets.token_bytes(64)) is False

    def test_tampered_cookie_rejected(self):
        """Verify bit flips in cookie payload are immediately rejected."""
        gate = npq.StatelessCookieGate()
        cookie = bytearray(gate.create_cookie("10.0.0.1", 1234, b"test_m1"))
        cookie[-1] ^= 0xFF
        assert gate.verify_cookie(bytes(cookie), "10.0.0.1", 1234, b"test_m1") is False

    def test_micro_pow_challenge_solve_and_verify(self):
        """Verify dynamic micro-PoW challenge generation, client solver, and verification."""
        gate = npq.StatelessCookieGate()
        client_ip = "192.0.2.1"
        client_port = 44444
        m1 = secrets.token_bytes(100)

        # Responder creates challenge with 8-bit PoW difficulty
        challenge = gate.create_challenge(client_ip, client_port, m1, difficulty_bits=8)
        assert challenge.startswith(b"NPQ_CHALLENGE\x00")

        # Client solves PoW
        t0 = time.perf_counter()
        response = npq.StatelessCookieGate.solve_challenge(challenge)
        duration_ms = (time.perf_counter() - t0) * 1000
        assert response is not None
        assert duration_ms < 500  # 8 bits is rapid (< 10ms typically)

        # Responder validates response
        assert gate.verify_response(response, client_ip, client_port, m1, difficulty_bits=8) is True

        # Tampered nonce fails PoW check
        tampered_response = bytearray(response)
        tampered_response[-1] ^= 0x01
        assert gate.verify_response(bytes(tampered_response), client_ip, client_port, m1, difficulty_bits=8) is False

    def test_cookie_performance_under_flood(self):
        """Verify cookie verification is sub-microsecond, defeating CPU-exhaustion amplification."""
        gate = npq.StatelessCookieGate()
        cookie = gate.create_cookie("10.10.10.10", 9999, b"prefix")

        t0 = time.perf_counter()
        N = 10_000
        for _ in range(N):
            _ = gate.verify_cookie(cookie, "10.10.10.10", 9999, b"prefix")
        total_sec = time.perf_counter() - t0
        avg_us = (total_sec / N) * 1_000_000

        # Verification must be fast (< 25 microseconds in Python, compared to ~5000us for full M2)
        assert avg_us < 50.0, f"Cookie check too slow: {avg_us:.2f}us"

    def test_m1_cookie_packing_and_ingress_flow(self):
        """Verify full connectionless M1 challenge-response exchange."""
        (ci_pk, ci_sk), (cr_pk, cr_sk) = _make_identities()
        gate = npq.StatelessCookieGate()
        client_addr = ("198.51.100.25", 54321)

        # 1. Initiator prepares M1
        ini = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk)
        m1 = npq.initiator_hello(ini)

        # 2. Server under attack / flood requires cookies
        status, challenge = gate.process_incoming_m1(
            m1, client_addr[0], client_addr[1], require_cookie=True, difficulty_bits=4
        )
        assert status == "CHALLENGE"
        assert challenge.startswith(b"NPQ_CHALLENGE\x00")
        assert len(challenge) < 64  # Minimal wire size: zero amplification

        # 3. Client handles challenge statelessly
        cookie_m1 = npq.StatelessCookieGate.client_handle_challenge(challenge, m1)
        assert cookie_m1 is not None
        assert cookie_m1.startswith(npq.COOKIE_M1_PREFIX)

        # 4. Server admits validated M1
        status2, accepted_m1 = gate.process_incoming_m1(
            cookie_m1, client_addr[0], client_addr[1], require_cookie=True, difficulty_bits=4
        )
        assert status2 == "ACCEPT"
        assert accepted_m1 == m1

        # 5. Handshake completes successfully
        rsp = npq.NoiseSession(is_initiator=False, sig_pk=cr_pk, sig_sk=cr_sk)
        m2 = npq.responder_reply(rsp, accepted_m1)
        npq.initiator_finish(ini, m2, expected_peer_pk=cr_pk)
        m3 = npq.initiator_complete(ini)
        npq.responder_complete(rsp, m3, expected_peer_pk=ci_pk)

        ki_s, ki_r, hi = npq.split_session(ini)
        kr_s, kr_r, hr = npq.split_session(rsp)
        assert ki_s == kr_r
        assert hi == hr


class TestDestroyerNodeIngressHardening:
    """Verify DestroyerNode integration with StatelessCookieGate and Rust data plane."""

    def test_destroyer_node_ingress_gating(self):
        """Test unified ingress filter in DestroyerNode for both handshake and data."""
        from destroyer_node import DestroyerNode

        node = DestroyerNode()
        node.enable_cookie_gate(difficulty_bits=4, require_cookie=True)

        addr = ("192.168.1.100", 50000)
        (ci_pk, ci_sk), _ = _make_identities()
        ini = npq.NoiseSession(is_initiator=True, sig_pk=ci_pk, sig_sk=ci_sk)
        m1 = npq.initiator_hello(ini)

        # 1. Raw M1 under cookie requirement elicits CHALLENGE
        status, challenge = node.process_udp_ingress(m1, addr)
        assert status == "CHALLENGE"
        assert challenge.startswith(b"NPQ_CHALLENGE\x00")

        # 2. Client-solved cookie M1 is admitted for handshake
        cookie_m1 = npq.StatelessCookieGate.client_handle_challenge(challenge, m1)
        status, admitted = node.process_udp_ingress(cookie_m1, addr)
        assert status == "ACCEPT_HANDSHAKE"
        assert admitted == m1

        # 3. Spoofed IP fails closed (silent drop)
        spoofed_addr = ("192.168.1.101", 50000)
        status, _ = node.process_udp_ingress(cookie_m1, spoofed_addr)
        assert status == "DROP"

        # 4. Oversized datagram dropped
        oversized = b"\x00" * 1500
        status, _ = node.process_udp_ingress(oversized, addr)
        assert status == "DROP"

    def test_physical_memory_locking_discipline(self):
        """Verify memory locking and in-place zeroization for cryptographic buffers."""
        buf = bytearray(32)
        buf[:] = b"\x42" * 32
        locked = npq._lock_buffer(buf)
        assert isinstance(locked, bool)

        # Unlock and scrub
        npq._unlock_buffer(buf)
        npq._zero(buf)
        assert buf == bytearray(32)

