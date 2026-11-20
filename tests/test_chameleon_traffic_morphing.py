#!/usr/bin/env python3
"""
tests/test_chameleon_traffic_morphing.py
Comprehensive Verification Suite for Chameleon Traffic Morphing & LPI/LPD Waveform Abstraction.

Verifies:
1. WebRtcMorpher: RFC 3550 RTP formatting, Opus payload headers (RFC 7587), sequence/timestamp progression.
2. QuicMorpher: RFC 9000 / RFC 9369 QUIC v2 1-RTT short-header framing with fake TLS 1.3 padding.
3. Security Invariant: Statistical match to legitimate civilian WebRTC / QUIC v2 traffic (p > 0.95 KS-score).
4. Zero Bit Corruption: Seamless demorphing recovering 100% identical plaintext/ciphertext cells.
5. End-to-end integration with ST2027 SecureEngine AEAD framing.
6. Fail-closed rejection of tampered, truncated, or malformed packets.
"""

import math
import os
import secrets
import struct
import pytest
try:
    from scipy.stats import kstest, norm
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    kstest = None
    norm = None

from network.traffic_morpher import (
    WebRtcTrafficMorpher,
    QuicTrafficMorpher,
    ChameleonTrafficMorpher,
    verify_ks_score,
    compute_shannon_entropy,
    generate_gaussian_pacing,
    is_valid_rtp,
    is_valid_quic_short_header,
    DEFAULT_OPUS_PAYLOAD_TYPE,
    OPUS_TIMESTAMP_INCREMENT_20MS,
    DEFAULT_OPUS_TOC,
    RTP_FIXED_HEADER_LEN,
    WEBRTC_MORPH_OVERHEAD,
    QUIC_V2_VERSION,
)

try:
    import destroyer_core
    from destroyer_core import (
        SecureEngine,
        CoreWebRtcMorpher,
        CoreQuicMorpher,
        CoreChameleonEngine,
    )
    HAVE_DESTROYER_CORE = True
except ImportError:
    HAVE_DESTROYER_CORE = False


# =====================================================================
# Pillar 1: WebRTC Morpher (RFC 3550 RTP & RFC 7587 Opus Framing)
# =====================================================================

class TestWebRtcTrafficMorphing:
    """Tests for WebRtcMorpher embedding cells into RFC 3550 RTP packets with Opus payload headers."""

    def test_webrtc_rtp_morphing_and_demorphing_roundtrip(self):
        """Verify WebRTC morphing and demorphing preserves data byte-for-byte with zero corruption."""
        morpher = WebRtcTrafficMorpher(payload_type=111, ssrc=0xCAFE1234)

        test_payloads = [
            b"",
            b"X",
            b"TACTICAL_CELL_COORDINATES_ALPHA",
            os.urandom(64),
            os.urandom(256),
            os.urandom(512),
            os.urandom(1024),
            os.urandom(1205),
        ]

        for payload in test_payloads:
            packet = morpher.morph(payload)

            # 1. Verify RFC 3550 RTP Header Structure (12 bytes)
            assert len(packet) >= WEBRTC_MORPH_OVERHEAD + len(payload)
            assert is_valid_rtp(packet, payload_type=111)

            # Byte 0: V=2 (0x80)
            assert (packet[0] >> 6) == 2, "RTP version must be 2"
            assert (packet[0] & 0x20) == 0, "RTP padding bit should be 0 in fixed header"
            assert (packet[0] & 0x10) == 0, "RTP extension bit should be 0"
            assert (packet[0] & 0x0F) == 0, "RTP CC must be 0"

            # Byte 1: PT=111 (Opus dynamic payload type)
            assert (packet[1] & 0x7F) == 111, "Payload type must be 111 (Opus)"

            # SSRC check
            ssrc_val = struct.unpack(">I", packet[8:12])[0]
            assert ssrc_val == 0xCAFE1234, "SSRC must match configured stream source"

            # 2. Verify RFC 7587 Opus Payload Header
            assert packet[12] == DEFAULT_OPUS_TOC, "TOC byte must match Opus configuration"
            cell_len = struct.unpack(">H", packet[13:15])[0]
            assert cell_len == len(payload), "Embedded cell length must match exact payload length"

            # 3. Demorph and verify ZERO bit corruption
            recovered = morpher.demorph(packet)
            assert recovered == payload, "Demorphed cell suffered bit corruption!"

    def test_webrtc_sequence_and_timestamp_progression(self):
        """Verify monotonic sequence number increment and 48 kHz / 20ms timestamp advancement."""
        morpher = WebRtcTrafficMorpher(ssrc=0x11223344)
        p1 = morpher.morph(b"cell_alpha")
        p2 = morpher.morph(b"cell_bravo")
        p3 = morpher.morph(b"cell_charlie")

        seq1 = struct.unpack(">H", p1[2:4])[0]
        seq2 = struct.unpack(">H", p2[2:4])[0]
        seq3 = struct.unpack(">H", p3[2:4])[0]

        assert (seq2 - seq1) & 0xFFFF == 1, "RTP sequence number must advance by 1"
        assert (seq3 - seq2) & 0xFFFF == 1, "RTP sequence number must advance by 1"

        ts1 = struct.unpack(">I", p1[4:8])[0]
        ts2 = struct.unpack(">I", p2[4:8])[0]
        ts3 = struct.unpack(">I", p3[4:8])[0]

        assert (ts2 - ts1) & 0xFFFFFFFF == OPUS_TIMESTAMP_INCREMENT_20MS, \
            "RTP timestamp must advance by exactly 960 (20ms at 48000 Hz)"
        assert (ts3 - ts2) & 0xFFFFFFFF == OPUS_TIMESTAMP_INCREMENT_20MS

    def test_webrtc_target_quantum_padding_roundtrip(self):
        """Verify target quantum padding (e.g. 256, 512, 1232B) demorphs cleanly."""
        for quantum in [256, 512, 1232]:
            morpher = WebRtcTrafficMorpher(target_quantum=quantum)
            cell = os.urandom(100)
            packet = morpher.morph(cell)

            assert len(packet) == quantum, f"Packet length must match quantum {quantum}"
            recovered = morpher.demorph(packet)
            assert recovered == cell, "Quantum padding leaked into demorphed payload!"


# =====================================================================
# Pillar 2: Security Invariant: Statistical Match & Kolmogorov-Smirnov Test
# =====================================================================

class TestChameleonStatisticalPacing:
    """
    Security Invariant Test:
    ST2027 traffic pacing is dynamically shaped to statistically match legitimate
    civilian WebRTC audio packet intervals (p > 0.95 Kolmogorov-Smirnov score).
    """

    def test_gaussian_jitter_pacing_kolmogorov_smirnov_score(self):
        """
        Verify synthetic 20ms Gaussian jitter pacing achieves p > 0.95 KS-score
        against the reference civilian distribution N(20.0ms, 2.0ms).
        """
        morpher = WebRtcTrafficMorpher(pacing_mean_ms=20.0, pacing_std_ms=2.0)

        # Test across multiple batch sizes
        for n_samples in [50, 100, 200]:
            intervals = morpher.generate_pacing_intervals(n_samples)
            assert len(intervals) == n_samples

            # Run Kolmogorov-Smirnov test against civilian WebRTC Opus inter-arrival timing
            stat, p_val, passed = verify_ks_score(intervals, mean=20.0, std=2.0)

            # Security Invariant Assertion
            assert passed, (
                f"Kolmogorov-Smirnov score p={p_val:.4f} failed invariant p > 0.95 (D={stat:.4f}) "
                f"for N={n_samples}"
            )
            assert p_val > 0.95, f"Expected p > 0.95, got {p_val}"

            # Verify mean and standard deviation boundaries
            mean_sample = sum(intervals) / len(intervals)
            var_sample = sum((x - mean_sample) ** 2 for x in intervals) / len(intervals)
            std_sample = math.sqrt(var_sample)

            assert abs(mean_sample - 20.0) < 0.2, f"Sample mean {mean_sample} drifted from 20.0ms"
            assert abs(std_sample - 2.0) < 0.3, f"Sample std {std_sample} drifted from 2.0ms"

    def test_sequential_pacing_delay_progression(self):
        """Verify sequential next_pacing_delay_ms() calls yield high-fit Gaussian pacing."""
        morpher = WebRtcTrafficMorpher(pacing_mean_ms=20.0, pacing_std_ms=2.0)
        delays = [morpher.next_pacing_delay_ms() for _ in range(100)]

        stat, p_val, passed = verify_ks_score(delays, mean=20.0, std=2.0)
        assert passed, f"Sequential delay KS-test failed: p={p_val:.4f}, D={stat:.4f}"
        assert p_val > 0.95

        # Verify next_pacing_delay() returns seconds
        delay_sec = morpher.next_pacing_delay()
        assert 0.010 <= delay_sec <= 0.035, f"Delay {delay_sec}s outside realistic 20ms pacing window"


# =====================================================================
# Pillar 3: QUIC Morpher (RFC 9000 & RFC 9369 QUIC v2 Short Header Framing)
# =====================================================================

class TestQuicTrafficMorphing:
    """Tests for QuicMorpher encapsulating cells into valid QUIC v2 1-RTT short headers with fake TLS 1.3 padding."""

    def test_quic_v2_1rtt_short_header_morphing_and_demorphing(self):
        """Verify QUIC v2 1-RTT short header encapsulation and demorphing with zero bit corruption."""
        dcid = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11])
        morpher = QuicTrafficMorpher(dcid=dcid, target_size=1200)

        test_payloads = [
            b"",
            b"QUIC_V2_ENCRYPTED_TACTICAL_FRAME",
            os.urandom(32),
            os.urandom(128),
            os.urandom(512),
            os.urandom(1000),
            os.urandom(1100),
        ]

        for payload in test_payloads:
            packet = morpher.morph(payload)

            # 1. Verify QUIC Short Header
            assert len(packet) == 1200, "Packet must be padded to target MTU size (1200B)"
            assert is_valid_quic_short_header(packet, dcid_len=8)

            first_byte = packet[0]
            assert (first_byte & 0x80) == 0, "Bit 7 must be 0 for Short Header"
            assert (first_byte & 0x40) != 0, "Bit 6 (Fixed Bit) must be 1 in RFC 9000"
            assert (first_byte & 0x03) == 3, "Packet number length bits must indicate 4-byte PN"

            # Verify DCID
            assert packet[1:9] == dcid, "Destination Connection ID mismatch"

            # 2. Demorph and verify ZERO bit corruption
            recovered = morpher.demorph(packet)
            assert recovered == payload, "Demorphed QUIC cell suffered bit corruption!"

    def test_quic_v2_packet_number_monotonicity(self):
        """Verify QUIC short header packet numbers increment monotonically."""
        morpher = QuicTrafficMorpher()
        p1 = morpher.morph(b"pkt1")
        p2 = morpher.morph(b"pkt2")
        p3 = morpher.morph(b"pkt3")

        pn1 = struct.unpack(">I", p1[9:13])[0]
        pn2 = struct.unpack(">I", p2[9:13])[0]
        pn3 = struct.unpack(">I", p3[9:13])[0]

        assert pn2 == pn1 + 1, "QUIC packet number must increment by 1"
        assert pn3 == pn2 + 1

    def test_quic_fake_tls13_padding_integrity(self):
        """Verify fake TLS 1.3 / QUIC PADDING frames expand packet without altering payload."""
        morpher = QuicTrafficMorpher(target_size=1232)
        payload = b"CRITICAL_INTELLIGENCE_BURST"
        packet = morpher.morph(payload)

        assert len(packet) == 1232
        # Verify padding frames: trailing bytes must be 0x00 (RFC 9000 PADDING frame type)
        # Check last 100 bytes are all zeros
        assert all(b == 0 for b in packet[-100:]), "QUIC padding frames must be 0x00"

        recovered = morpher.demorph(packet)
        assert recovered == payload


# =====================================================================
# Pillar 4: Chameleon Unified Engine & Dynamic Profile Switching
# =====================================================================

class TestChameleonUnifiedEngine:
    """Tests for ChameleonTrafficMorpher unified API and dynamic profile switching."""

    def test_dynamic_profile_switching_and_auto_demorph(self):
        """Verify switching between WebRTC and QUIC profiles with seamless auto-demorphing."""
        engine = ChameleonTrafficMorpher(default_profile="webrtc")
        assert engine.profile == "webrtc"

        # 1. Morph under WebRTC
        cell_webrtc = b"TACTICAL_DATA_OVER_WEBRTC"
        pkt_webrtc = engine.morph(cell_webrtc)
        assert is_valid_rtp(pkt_webrtc)

        # Demorph auto-detects WebRTC
        rec_webrtc = engine.demorph(pkt_webrtc)
        assert rec_webrtc == cell_webrtc

        # 2. Switch to QUIC v2
        engine.set_profile("quic")
        assert engine.profile == "quic"

        cell_quic = b"TACTICAL_DATA_OVER_QUIC_V2"
        pkt_quic = engine.morph(cell_quic)
        assert is_valid_quic_short_header(pkt_quic)

        # Demorph auto-detects QUIC
        rec_quic = engine.demorph(pkt_quic)
        assert rec_quic == cell_quic

        # 3. Interleaved demorphing (mixed traffic reception)
        engine.set_profile("webrtc")
        pkt_webrtc2 = engine.morph(cell_webrtc)
        engine.set_profile("quic")
        pkt_quic2 = engine.morph(cell_quic)
        assert engine.demorph(pkt_webrtc2) == cell_webrtc
        assert engine.demorph(pkt_quic2) == cell_quic

    def test_invalid_profile_name_raises(self):
        """Verify unrecognized profile raises ValueError."""
        engine = ChameleonTrafficMorpher()
        with pytest.raises(ValueError, match="Unknown traffic morphing profile"):
            engine.set_profile("carrier_pigeon")


# =====================================================================
# Pillar 5: Deep Packet Inspection (DPI) & Shannon Entropy Evasion
# =====================================================================

class TestDpiAndEntropyInvariance:
    """Verifies morphed packets evade DPI heuristic scanners and entropy checks."""

    def test_shannon_entropy_invariance(self):
        """Encrypted ST2027 cells morphed into WebRTC/QUIC retain high entropy (>= 7.80 bits/byte)."""
        webrtc = WebRtcTrafficMorpher(target_quantum=1232)
        encrypted_cell = os.urandom(1200)  # Simulated AEAD ciphertext
        packet = webrtc.morph(encrypted_cell)

        entropy = compute_shannon_entropy(packet)
        # Encrypted ciphertext + Opus audio headers should exhibit high entropy
        assert entropy >= 7.80, f"Entropy {entropy} bits/byte too low; vulnerable to heuristic detection"


# =====================================================================
# Pillar 6: End-to-End ST2027 Crypto Pipeline Integration
# =====================================================================

class TestSt2027CryptoIntegration:
    """Integration test verifying ST2027 sealed frames morph, demorph, and unseal cleanly."""

    def test_st2027_secure_engine_frame_morph_demorph_roundtrip(self):
        """Verify an ST2027 AEAD frame survives morphing and demorphing with zero bit corruption."""
        if not HAVE_DESTROYER_CORE or SecureEngine is None:
            pytest.skip("destroyer_core.SecureEngine not available")

        # Set up transmitter and receiver engines
        tx_engine = SecureEngine()
        rx_engine = SecureEngine()

        shared_key = bytes([0x5A] * 32)
        tx_engine.establish_session(list(shared_key), start_seq=1000, is_initiator=True)
        rx_engine.establish_session(list(shared_key), start_seq=1000, is_initiator=False)

        # Seal application message into ST2027 frame
        raw_msg = b"CRITICAL_STRATEGIC_DIRECTIVE_ST2027_VERIFIED"
        quantum, sealed_frame = tx_engine.seal_msg(0x01, list(raw_msg))
        assert len(sealed_frame) == quantum

        # Morph via WebRTC
        webrtc = WebRtcTrafficMorpher()
        morphed_rtp = webrtc.morph(bytes(sealed_frame))

        # Demorph from WebRTC
        demorphed_frame = webrtc.demorph(morphed_rtp)
        assert demorphed_frame == bytes(sealed_frame), "Demorphed frame mismatch!"

        # Open frame in receiving engine
        opened = rx_engine.open_msg(list(demorphed_frame))
        assert opened is not None
        rec_type, rec_msg = opened
        assert bytes(rec_msg) == raw_msg, "Decrypted message mismatch after WebRTC morphing pipeline!"

        # Repeat for QUIC v2
        quic = QuicTrafficMorpher(target_size=1232)
        morphed_quic = quic.morph(bytes(sealed_frame))
        demorphed_quic = quic.demorph(morphed_quic)
        assert demorphed_quic == bytes(sealed_frame)

        # Re-seal a second message for QUIC
        raw_msg2 = b"SECOND_COMMAND_BURST_ST2027_AUTHENTICATED"
        _, sealed_frame2 = tx_engine.seal_msg(0x01, list(raw_msg2))
        morphed_quic2 = quic.morph(bytes(sealed_frame2))
        demorphed_quic2 = quic.demorph(morphed_quic2)
        assert demorphed_quic2 == bytes(sealed_frame2)

        opened_quic = rx_engine.open_msg(list(demorphed_quic2))
        assert opened_quic is not None
        _, rec_msg_quic = opened_quic
        assert bytes(rec_msg_quic) == raw_msg2, "Decrypted message mismatch after QUIC v2 morphing pipeline!"


# =====================================================================
# Pillar 7: Native Rust Accelerator & Fallback Cross-Check
# =====================================================================

class TestNativeRustCoreMorpher:
    """Direct tests for native destroyer_core Rust data plane morphing implementation."""

    def test_native_webrtc_morpher_direct(self):
        """Verify native CoreWebRtcMorpher if present."""
        if not HAVE_DESTROYER_CORE or CoreWebRtcMorpher is None:
            pytest.skip("Native CoreWebRtcMorpher not built")

        native_w = CoreWebRtcMorpher(payload_type=111, ssrc=0xFEEDBEEF, target_quantum=512)
        cell = b"TACTICAL_NATIVE_RUST_CORE_PAYLOAD"
        packet = bytes(native_w.morph(list(cell)))

        assert len(packet) == 512
        assert is_valid_rtp(packet, payload_type=111)

        recovered = bytes(native_w.demorph(list(packet)))
        assert recovered == cell

        intervals = list(native_w.generate_pacing_intervals(100))
        stat, pval, passed = verify_ks_score(intervals)
        assert passed, f"Native pacing failed KS test: p={pval:.4f}"
        assert pval > 0.95

    def test_native_quic_morpher_direct(self):
        """Verify native CoreQuicMorpher if present."""
        if not HAVE_DESTROYER_CORE or CoreQuicMorpher is None:
            pytest.skip("Native CoreQuicMorpher not built")

        native_q = CoreQuicMorpher(dcid=list(b"\x01\x02\x03\x04\x05\x06\x07\x08"), target_size=1200)
        cell = b"QUIC_NATIVE_RUST_CORE_PAYLOAD"
        packet = bytes(native_q.morph(list(cell)))

        assert len(packet) == 1200
        assert is_valid_quic_short_header(packet, dcid_len=8)

        recovered = bytes(native_q.demorph(list(packet)))
        assert recovered == cell


# =====================================================================
# Pillar 8: Robustness & Fail-Closed Malformed Input Rejection
# =====================================================================

class TestChameleonFailClosedRejection:
    """Verifies malformed, truncated, or tampered packets fail closed gracefully without panics."""

    def test_webrtc_malformed_packets_rejected(self):
        """Malformed RTP packets raise ValueError."""
        morpher = WebRtcTrafficMorpher()

        # Truncated packets
        with pytest.raises(ValueError):
            morpher.demorph(b"")

        with pytest.raises(ValueError):
            morpher.demorph(b"\x80\x6f\x00\x01\x00\x00\x03\xc0")  # Only 8 bytes

        # Wrong RTP version (0 instead of 2)
        fake_v0 = bytearray(20)
        fake_v0[0] = 0x00
        fake_v0[1] = 111
        with pytest.raises(ValueError, match=r"(?i)invalid rtp version"):
            morpher.demorph(bytes(fake_v0))

        # Wrong payload type (e.g. 96 instead of 111)
        fake_pt = bytearray(20)
        fake_pt[0] = 0x80
        fake_pt[1] = 96
        with pytest.raises(ValueError, match=r"(?i)payload type"):
            morpher.demorph(bytes(fake_pt))

        # Corrupted cell length field exceeding packet size
        corrupt_len = bytearray(20)
        corrupt_len[0] = 0x80
        corrupt_len[1] = 111
        corrupt_len[12] = 0x78  # Standard Opus CELT 20ms TOC (not 0x00 Comfort Noise chaff)
        struct.pack_into(">H", corrupt_len, 13, 10000)  # Claims 10000B, but packet is 20B
        with pytest.raises(ValueError, match=r"(?i)exceeds packet"):
            morpher.demorph(bytes(corrupt_len))

    def test_quic_malformed_packets_rejected(self):
        """Malformed QUIC packets raise ValueError."""
        morpher = QuicTrafficMorpher()

        with pytest.raises(ValueError):
            morpher.demorph(b"")

        # Fixed bit not set (Bit 6 == 0)
        invalid_fixed_bit = bytearray(30)
        invalid_fixed_bit[0] = 0x03  # Bit 7 is 0, but Bit 6 is 0
        with pytest.raises(ValueError, match=r"(?i)fixed bit"):
            morpher.demorph(bytes(invalid_fixed_bit))

        # Truncated packet
        short_pkt = bytearray([0x43]) + b"\x00" * 8  # Missing PN and payload
        with pytest.raises(ValueError, match=r"(?i)truncated|too short"):
            morpher.demorph(bytes(short_pkt))


# =====================================================================
# Pillar 9: Canonical Aliases, Async Pacing, and Framing Detection
# =====================================================================

class TestChameleonProductionAliasesAndPacing:
    """Verifies production aliases, framing auto-detection, and async pacing utilities."""

    def test_canonical_class_aliases(self):
        """Verify WebRtcMorpher, QuicMorpher, ChameleonEngine, and TrafficMorpher aliases."""
        from network.traffic_morpher import (
            WebRtcMorpher,
            QuicMorpher,
            ChameleonEngine,
            TrafficMorpher,
        )

        wm = WebRtcMorpher(payload_type=111)
        qm = QuicMorpher(target_size=1200)
        ce = ChameleonEngine(default_profile="webrtc")
        tm = TrafficMorpher(default_profile="quic")

        # WebRTC alias test
        data = b"ALIAS_TEST_PAYLOAD_WEBRTC"
        pkt = wm.morph(data)
        assert wm.demorph(pkt) == data

        # QUIC alias test
        pkt_q = qm.morph(data)
        assert qm.demorph(pkt_q) == data

        # ChameleonEngine alias test
        pkt_ce = ce.morph(data)
        assert ce.demorph(pkt_ce) == data

        # TrafficMorpher alias test
        pkt_tm = tm.morph(data)
        assert tm.demorph(pkt_tm) == data

    def test_detect_framing(self):
        """Verify detect_framing correctly identifies WebRTC vs QUIC v2 packets."""
        engine = ChameleonTrafficMorpher()
        wm = WebRtcTrafficMorpher()
        qm = QuicTrafficMorpher()

        pkt_rtp = wm.morph(b"detect_me_rtp")
        pkt_quic = qm.morph(b"detect_me_quic")

        assert engine.detect_framing(pkt_rtp) == "webrtc"
        assert engine.detect_framing(pkt_quic) == "quic"

        with pytest.raises(ValueError, match="Empty packet"):
            engine.detect_framing(b"")

        with pytest.raises(ValueError, match="Unrecognized packet framing"):
            engine.detect_framing(b"\x00" * 20)

    def test_async_pacing_delay(self):
        """Verify async pace() / pace_next() functions return realistic pacing intervals."""
        import asyncio
        engine = ChameleonTrafficMorpher()
        delay_s = asyncio.run(engine.pace())
        assert 0.010 <= delay_s <= 0.035, f"Async delay {delay_s}s out of expected bounds"

    def test_engine_verify_ks_score_helper(self):
        """Verify engine.verify_ks_score() returns valid KS statistics with p > 0.95."""
        engine = ChameleonTrafficMorpher()
        stat, p_val, passed = engine.verify_ks_score(count=100)
        assert passed, f"engine.verify_ks_score failed: p={p_val:.4f}, D={stat:.4f}"
        assert p_val > 0.95

    def test_quic_varint_boundary_encodings(self):
        """Verify QUIC variable-length integer encoding and decoding at 1, 2, 4, 8-byte boundaries."""
        morpher = QuicTrafficMorpher()
        test_values = [0, 1, 25, 63, 64, 150, 1232, 16383, 16384, 100000, 1073741823, 1073741824]
        for val in test_values:
            buf = bytearray()
            morpher._encode_varint(val, buf)
            decoded, new_off = morpher._decode_varint(bytes(buf), 0)
            assert decoded == val, f"Varint mismatch for {val}: got {decoded}"
            assert new_off == len(buf)


# =====================================================================
# Pillar 10: ChameleonSocketWrapper Live UDP Loopback & Cover Pacing
# =====================================================================

class TestChameleonSocketWrapperLiveLoopback:
    """Live UDP loopback tests for ChameleonSocketWrapper with automatic demorphing and chaff absorption."""

    def test_webrtc_socket_loopback_and_chaff_absorption(self):
        """Verify WebRTC socket wrapper bidirectional transmission and background cover chaff absorption."""
        from network.traffic_morpher import ChameleonSocketWrapper
        import socket
        import time

        sock_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        rx_wrapper = ChameleonSocketWrapper(sock_rx, profile="webrtc", target_size=1200)
        tx_wrapper = ChameleonSocketWrapper(sock_tx, profile="webrtc", target_size=1200)

        rx_addr = rx_wrapper.bind(("127.0.0.1", 0))

        # 1. Direct message morph and demorph over real UDP socket
        msg1 = b"TACTICAL_TELEMETRY_ALPHA_OVER_WEBRTC"
        tx_wrapper.send_morphed(msg1, rx_addr)
        received1, from_addr = rx_wrapper.recv_demorph(timeout=2.0)
        assert received1 == msg1
        assert from_addr[0] == "127.0.0.1"

        # 2. Start background pacing cover traffic thread emitting synthetic Opus DTX chaff
        tx_wrapper.start_pacing(rx_addr)
        time.sleep(0.06)  # Allow ~3 chaff packets to be sent and absorbed

        # 3. Transmit real data amidst active cover traffic
        msg2 = b"CRITICAL_COORDINATE_TRANSMISSION_42"
        tx_wrapper.send_morphed(msg2, rx_addr)

        # rx_wrapper.recv_demorph silently absorbs the chaff packets and returns only the genuine message
        received2, _ = rx_wrapper.recv_demorph(timeout=2.0)
        assert received2 == msg2

        # 4. Clean shutdown
        tx_wrapper.stop_pacing()
        tx_wrapper.close()
        rx_wrapper.close()

    def test_quic_socket_loopback(self):
        """Verify QUIC v2 socket wrapper transmission and demorphing."""
        from network.traffic_morpher import ChameleonSocketWrapper
        import socket

        sock_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        rx_wrapper = ChameleonSocketWrapper(sock_rx, profile="quic", target_size=1200)
        tx_wrapper = ChameleonSocketWrapper(sock_tx, profile="quic", target_size=1200)

        rx_addr = rx_wrapper.bind(("127.0.0.1", 0))

        msg = b"QUIC_V2_TACTICAL_CELL_ST2027"
        tx_wrapper.send_morphed(msg, rx_addr)
        received, _ = rx_wrapper.recv_demorph(timeout=2.0)
        assert received == msg

        tx_wrapper.close()
        rx_wrapper.close()


# =====================================================================
# Pillar 11: DestroyerNode Live End-to-End Encrypted Chameleon Morphing
# =====================================================================

class TestDestroyerNodeChameleonLiveUdpIntegration:
    """Verifies DestroyerNode full-stack ST2027 encryption + Chameleon WebRTC/QUIC morphing over UDP."""

    def test_destroyer_node_live_udp_morphing_roundtrip(self):
        """Full end-to-end integration: DestroyerNode encrypted frames morphed over real UDP."""
        from destroyer_node import DestroyerNode

        node_a = DestroyerNode()
        node_b = DestroyerNode()

        # Shared 32-byte key derived from simulated PQ handshake
        session_key = os.urandom(32)

        # Establish ST2027 crypto sessions
        node_a.establish(session_key, start_seq=100, is_initiator=True)
        node_b.establish(session_key, start_seq=100, is_initiator=False)

        # Bind UDP sockets to loopback ephemeral ports
        addr_a = node_a.bind_udp(("127.0.0.1", 0))
        addr_b = node_b.bind_udp(("127.0.0.1", 0))

        # Enable Chameleon WebRTC morphing on both nodes
        node_a.enable_chameleon_morphing(profile="webrtc", target_size=1232)
        node_b.enable_chameleon_morphing(profile="webrtc", target_size=1232)

        assert node_a.is_chameleon_morphing()
        assert node_b.is_chameleon_morphing()

        # 1. Transmit authenticated, encrypted ST2027 message from Node A to Node B
        tactical_msg = b"ALPHA_DRONE_GRID_STRIKE_COORDINATES_37.2431_115.7930"
        bytes_sent = node_a.send_udp_msg(tactical_msg, addr_b)
        assert bytes_sent == 1232  # Fixed target quantum

        received_payload, from_peer = node_b.recv_udp_msg(timeout=2.0)
        assert received_payload == tactical_msg
        assert from_peer[1] == addr_a[1]

        # 2. Transmit chaff datagram: Node B should silently absorb it, and receive next msg
        node_a.send_chaff(addr_b)
        post_chaff_msg = b"TACTICAL_CONFIRMATION_AFTER_COVER_CHAFF"
        node_a.send_udp_msg(post_chaff_msg, addr_b)

        received_post_chaff, _ = node_b.recv_udp_msg(timeout=2.0)
        assert received_post_chaff == post_chaff_msg

        # 3. Dynamic Profile Switch to QUIC v2
        node_a.chameleon_morpher.set_profile("quic")
        node_b.chameleon_morpher.set_profile("quic")

        quic_reply = b"NODE_B_QUIC_V2_ACKNOWLEDGEMENT_STATUS_GREEN"
        node_b.send_udp_msg(quic_reply, addr_a)

        received_quic, _ = node_a.recv_udp_msg(timeout=2.0)
        assert received_quic == quic_reply

        # 4. Verify telemetry tracking on both nodes
        telemetry_a = node_a.get_chameleon_telemetry()
        assert telemetry_a["active"] is True
        assert telemetry_a["packets_morphed"] >= 2
        assert telemetry_a["packets_demorphed"] >= 1

        # 5. Disable morphing and cleanup sockets
        node_a.disable_chameleon_morphing()
        node_b.disable_chameleon_morphing()
        assert not node_a.is_chameleon_morphing()

        node_a.close()
        node_b.close()


