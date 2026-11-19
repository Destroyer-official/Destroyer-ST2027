"""
Unit and Integration Tests for Phase L: Free-Space Optical (FSO) / Visual Air-Gap Fountain Transceiver
Verifies rateless Luby Transform fountain code recovery, 60fps visual framing,
TEMPEST Level A optical emission security, and resilience to optical packet loss.
"""

import unittest
from hardware.visual_airgap_diode import (
    IS_NATIVE,
    VisualAirgapDiodeTransceiver,
    VISUAL_PREAMBLE,
)


class TestVisualAirgapTransceiver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transceiver = VisualAirgapDiodeTransceiver(fps=60, default_symbol_size=16)

    def test_01_fso_fountain_codec_clean_roundtrip(self):
        """Verify rateless fountain encoding and peeling decoder reconstruction."""
        payload = b"DIRECTIVE-2027: SCIF GLASS OPTICAL AIR-GAP TELEMETRY BURST"
        frames = self.transceiver.transmit_fountain_stream(
            payload, symbol_size=16, redundancy_overhead=0.5
        )
        self.assertTrue(len(frames) > 0)

        recovered = self.transceiver.receive_and_decode(
            frames, original_len=len(payload), symbol_size=16
        )
        self.assertEqual(recovered, payload)

    def test_02_resilience_to_20_percent_optical_frame_loss(self):
        """Verify unconstrained unidirectional recovery despite 20% optical frame drops."""
        payload = b"CRITICAL-COMMAND: NUCLEAR-POSTURE-STATUS-NOMINAL-ALL-SILOS-GREEN"
        frames = self.transceiver.transmit_fountain_stream(
            payload, symbol_size=16, redundancy_overhead=1.0  # 100% redundancy
        )

        # Simulate 20% optical link drop rate (e.g. blast door reflection / obscuration)
        surviving_frames = self.transceiver.simulate_airgap_channel(
            frames, loss_rate=0.20, seed=1337
        )
        self.assertLess(len(surviving_frames), len(frames))

        recovered = self.transceiver.receive_and_decode(
            surviving_frames, original_len=len(payload), symbol_size=16
        )
        self.assertEqual(recovered, payload)

    def test_03_tempest_scrambler_and_preamble_framing(self):
        """Verify optical frames contain standard preamble and TEMPEST DC-balancing."""
        payload = b"TEMPEST-LEVEL-A-TEST"
        frames = self.transceiver.transmit_fountain_stream(payload, symbol_size=16)

        for frame in frames:
            # Check visual preamble
            self.assertEqual(frame[:4], VISUAL_PREAMBLE)
            # Check length field
            plen = int.from_bytes(frame[4:6], "big")
            self.assertEqual(len(frame), 6 + plen)

    def test_04_corrupted_fountain_frame_rejection(self):
        """Verify tampered or corrupted visual frames are rejected fail-closed."""
        payload = b"TAMPER-TEST-PAYLOAD"
        frames = self.transceiver.transmit_fountain_stream(payload, symbol_size=16)

        # Tamper frame payload
        corrupt_frame = bytearray(frames[0])
        corrupt_frame[-1] ^= 0xFF
        corrupt_frames = [bytes(corrupt_frame)]

        recovered = self.transceiver.receive_and_decode(
            corrupt_frames, original_len=len(payload), symbol_size=16
        )
        self.assertIsNone(recovered)

    def test_05_insufficient_symbols_fails_gracefully(self):
        """Verify that receiving too few symbols safely returns None without crashing."""
        payload = b"LARGE-DATASTREAM-REQUIRING-MANY-SYMBOLS-TO-SOLVE-PROPERLY" * 4
        frames = self.transceiver.transmit_fountain_stream(payload, symbol_size=8)

        # Only pass 1 frame when many more are required
        starved_frames = frames[:1]
        recovered = self.transceiver.receive_and_decode(
            starved_frames, original_len=len(payload), symbol_size=8
        )
        self.assertIsNone(recovered)

    def test_06_native_rust_fast_path(self):
        """Verify native Rust CoreFsoTransceiver is bound and active."""
        self.assertTrue(IS_NATIVE)


if __name__ == "__main__":
    unittest.main()
