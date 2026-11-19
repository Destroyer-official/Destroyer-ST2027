#!/usr/bin/env python3
"""
tactical_sdr_controller.py
==========================
Tactical SDR DSSS LPI/LPD Physical Waveform Engine.

Provides low-probability-of-intercept / low-probability-of-detection (LPI/LPD)
physical layer baseband waveform synthesis for Software Defined Radios (USRP, HackRF):
- Direct Sequence Spread Spectrum (DSSS) with processing gains up to 30.1 dB (N=1023).
- Deep Sub-Thermal-Noise Communication: Transmits and decodes below ambient noise floor (SNR < -15 dB).
- Root-Raised-Cosine (RRC) pulse shaping (alpha = 0.35) for spectral confinement.
- Direct synthesis into complex baseband I/Q (cf32) and interleaved signed 16-bit PCM (cs16).
- Packet framing with synchronized Barker/Gold preambles and CRC-32 integrity.
"""

import os
import sys
import struct
import zlib
import math
import logging
from typing import List, Tuple, Optional, Dict, Any

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from audit_logging_system import log_event, AuditEventType, AuditSeverity
from destroyer_core import CoreSdrDsss, IS_NATIVE

logger = logging.getLogger("tactical_sdr")

# Default Barker Sync Preamble (13-bit optimal aperiodic autocorrelation)
BARKER_13 = [1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1]


def bytes_to_bits(data: bytes) -> List[int]:
    """Converts bytes to list of bits (MSB first)."""
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    """Converts list of bits to bytes (MSB first)."""
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | (bits[i + bit_idx] & 1)
        out.append(byte_val)
    return bytes(out)


class TacticalSdrController:
    """
    High-level controller for Tactical SDR DSSS Physical Waveforms.
    Manages packet encapsulation, spreading, baseband I/Q synthesis, and despreading.
    """

    def __init__(self, spreading_factor: int = 511, sample_rate_hz: float = 2_048_000.0):
        if spreading_factor not in (127, 255, 511, 1023):
            raise ValueError(f"Spreading factor must be in (127, 255, 511, 1023), got {spreading_factor}")
        self.spreading_factor = spreading_factor
        self.sample_rate_hz = sample_rate_hz
        self.processing_gain_db = 10.0 * math.log10(spreading_factor)

    def frame_packet(self, payload: bytes) -> List[int]:
        """
        Frames raw payload into physical DSSS bitstream:
        [ Preamble (13b) | Length (16b) | Payload (Nb) | CRC-32 (32b) ]
        """
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        header = struct.pack(">H", len(payload))
        footer = struct.pack(">I", crc)

        packet_bytes = header + payload + footer
        payload_bits = bytes_to_bits(packet_bytes)
        return BARKER_13 + payload_bits

    def deframe_packet(self, bits: List[int]) -> Optional[bytes]:
        """
        Locates Barker preamble, extracts length and CRC, and recovers payload.
        """
        if len(bits) < len(BARKER_13) + 48:
            return None

        # Correlate for Barker sync preamble
        best_offset = -1
        max_corr = -999

        for offset in range(min(128, len(bits) - len(BARKER_13) - 48)):
            corr = 0
            for i, expected in enumerate(BARKER_13):
                corr += 1 if bits[offset + i] == expected else -1
            if corr > max_corr:
                max_corr = corr
                best_offset = offset

        # Threshold: allow at most 2 bit flips in 13-bit preamble
        if max_corr < 9 or best_offset < 0:
            return None

        payload_start = best_offset + len(BARKER_13)
        raw_bytes = bits_to_bytes(bits[payload_start:])
        if len(raw_bytes) < 6:
            return None

        payload_len = struct.unpack(">H", raw_bytes[:2])[0]
        if len(raw_bytes) < 2 + payload_len + 4:
            return None

        payload = raw_bytes[2:2 + payload_len]
        crc_received = struct.unpack(">I", raw_bytes[2 + payload_len:2 + payload_len + 4])[0]
        crc_calculated = zlib.crc32(payload) & 0xFFFFFFFF

        if crc_received != crc_calculated:
            logger.warning(f"CRC mismatch on deframed packet: {crc_received:#x} vs {crc_calculated:#x}")
            return None

        return payload

    def transmit_baseband(self, payload: bytes) -> Tuple[List[float], List[float]]:
        """
        Synthesizes baseband I/Q samples for physical SDR transmission.
        Returns:
            (i_samples, q_samples)
        """
        packet_bits = self.frame_packet(payload)
        i_chan, q_chan = CoreSdrDsss.modulate_dsss_bits(packet_bits, self.spreading_factor)

        log_event(
            AuditEventType.MESSAGE_SENT,
            f"Tactical SDR DSSS Frame Synthesized ({len(payload)}B, PG={self.processing_gain_db:.1f} dB, {len(i_chan)} samples).",
            AuditSeverity.HIGH,
        )

        return i_chan, q_chan

    def receive_baseband(self, i_channel: List[float]) -> Optional[bytes]:
        """
        Despreads received I/Q stream and deframes payload.
        Operates below the thermal noise floor (SNR < -15 dB).
        """
        recovered_bits = CoreSdrDsss.demodulate_dsss_bits(i_channel, self.spreading_factor)
        payload = self.deframe_packet(recovered_bits)

        if payload is not None:
            log_event(
                AuditEventType.MESSAGE_RECEIVED,
                f"Tactical SDR DSSS Frame Successfully Decoded ({len(payload)}B recovered below noise floor).",
                AuditSeverity.CRITICAL,
            )

        return payload

    def export_cs16_file(self, file_path: str, i_channel: List[float], q_channel: List[float], amplitude: float = 0.8) -> None:
        """Exports complex baseband to raw interleaved 16-bit PCM file for USRP/HackRF."""
        pcm_samples = CoreSdrDsss.to_cs16_pcm(i_channel, q_channel, amplitude)
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "wb") as f:
            f.write(struct.pack(f"<{len(pcm_samples)}h", *pcm_samples))
