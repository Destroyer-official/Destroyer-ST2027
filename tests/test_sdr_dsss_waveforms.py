#!/usr/bin/env python3
"""
tests/test_sdr_dsss_waveforms.py
================================
Verification suite for Phase I: Tactical SDR DSSS LPI/LPD Physical Waveform Engine.
Validates direct baseband I/Q synthesis, processing gain, and negative SNR recovery.
"""

import os
import sys
import tempfile
import unittest
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tactical_sdr_controller import (
    TacticalSdrController,
    bytes_to_bits,
    bits_to_bytes,
)
from destroyer_core import CoreSdrDsss, IS_NATIVE


class TestSdrDsssWaveforms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdr_511 = TacticalSdrController(spreading_factor=511)
        cls.sdr_127 = TacticalSdrController(spreading_factor=127)

    # =========================================================================
    # 1. Framing & Bit Conversion Tests
    # =========================================================================

    def test_01_dsss_framing_and_deframing_roundtrip(self):
        """Verify packet framing with Barker sync and CRC-32 integrity."""
        payload = b"TACTICAL-DIRECTIVE-9912"
        bits = self.sdr_511.frame_packet(payload)
        self.assertEqual(len(bits), 13 + 16 + len(payload) * 8 + 32)

        recovered = self.sdr_511.deframe_packet(bits)
        self.assertEqual(recovered, payload)

    def test_02_clean_baseband_synthesis_and_recovery(self):
        """Verify end-to-end baseband synthesis and demodulation without channel noise."""
        payload = b"HIGH-PRIORITY-EAM-RETALIATE-ALPHA"
        i_chan, q_chan = self.sdr_511.transmit_baseband(payload)

        self.assertEqual(len(i_chan), len(q_chan))
        self.assertTrue(len(i_chan) > 0)

        # Receiver decodes I-channel
        decoded = self.sdr_511.receive_baseband(i_chan)
        self.assertEqual(decoded, payload)

    # =========================================================================
    # 2. Sub-Thermal Noise LPI/LPD Channel Recovery Tests (SNR < -15 dB)
    # =========================================================================

    def test_03_deep_sub_noise_reception_at_minus_15db_snr(self):
        """
        Verify reliable packet recovery below ambient thermal noise floor (SNR = -15 dB).
        Noise power is ~31.6 times greater than signal power.
        """
        payload = b"LPI-LPD-COVERT-SUB-NOISE-EAM"
        i_chan, _ = self.sdr_511.transmit_baseband(payload)

        # Inject extreme AWGN noise via native Rust engine: SNR = -15 dB
        noisy_i = CoreSdrDsss.simulate_awgn_channel(i_chan, snr_db=-15.0)

        # Despread and recover
        recovered = self.sdr_511.receive_baseband(noisy_i)
        self.assertEqual(recovered, payload)

    def test_04_processing_gain_scaling_with_spreading_factor(self):
        """Verify processing gain matches theoretical 10*log10(N_chips)."""
        sdr_127 = TacticalSdrController(spreading_factor=127)
        sdr_1023 = TacticalSdrController(spreading_factor=1023)

        self.assertAlmostEqual(sdr_127.processing_gain_db, 21.038, places=2)
        self.assertAlmostEqual(sdr_1023.processing_gain_db, 30.099, places=2)

    # =========================================================================
    # 3. Anti-Tamper & Error Detection Tests
    # =========================================================================

    def test_05_corrupted_crc_packet_refusal_fail_closed(self):
        """Verify that any payload bit flip invalidating CRC is refused fail-closed."""
        payload = b"TAMPER-TEST-DATA"
        bits = self.sdr_511.frame_packet(payload)

        # Corrupt one payload bit
        bits[50] ^= 1

        # Deframing must refuse corrupted packet
        self.assertIsNone(self.sdr_511.deframe_packet(bits))

    def test_06_corrupted_barker_preamble_refusal(self):
        """Verify that heavily damaged sync preambles fail sync detection."""
        payload = b"SYNC-TEST"
        bits = self.sdr_511.frame_packet(payload)

        # Corrupt 8 bits of the 13-bit preamble
        for i in range(8):
            bits[i] ^= 1

        self.assertIsNone(self.sdr_511.deframe_packet(bits))

    def test_07_cs16_raw_pcm_export_and_file_structure(self):
        """Verify export to signed 16-bit interleaved PCM file for USRP / HackRF."""
        payload = b"PCM-EXPORT-TEST"
        i_chan, q_chan = self.sdr_127.transmit_baseband(payload)

        with tempfile.NamedTemporaryFile(suffix=".cs16", delete=False) as f:
            tmp_path = f.name

        try:
            self.sdr_127.export_cs16_file(tmp_path, i_chan, q_chan, amplitude=0.7)
            self.assertTrue(os.path.exists(tmp_path))
            file_size = os.path.getsize(tmp_path)
            # Each complex sample has 2 int16 (4 bytes)
            self.assertEqual(file_size, len(i_chan) * 4)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_08_native_rust_core_sdr_dsss_fast_path(self):
        """Verify native Rust CoreSdrDsss functions execute cleanly."""
        self.assertTrue(IS_NATIVE)

        bits = [1, 0, 1, 1, 0, 0, 1]
        i_chan, q_chan = CoreSdrDsss.modulate_dsss_bits(bits, spreading_factor=127)
        self.assertTrue(len(i_chan) > 0)
        self.assertEqual(len(i_chan), len(q_chan))

        recovered = CoreSdrDsss.demodulate_dsss_bits(i_chan, spreading_factor=127)
        self.assertEqual(list(recovered), bits)


if __name__ == "__main__":
    unittest.main()
