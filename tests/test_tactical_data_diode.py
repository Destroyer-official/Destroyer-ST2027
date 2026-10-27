#!/usr/bin/env python3
"""
Test Suite: Simplex Tactical Data Diode & Forward Error Correction
==================================================================
Validates:
1. Galois Field GF(2^8) field arithmetic invariants.
2. Cauchy Reed-Solomon Erasure Coding (K=8, M=4) under 0%, 25%, and 33% packet drop.
3. Diode Packet Serialization, magic headers, and SHA3-256 integrity checks.
4. Cursor-on-Target (CoT) tactical telemetry generation and serialization.
5. End-to-end live UDP simplex transmission with ZERO reverse channel (pure diode).
"""

import os
import sys
import time
import secrets
import threading
import unittest

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tactical_data_diode import (
    GF256,
    CauchyErasureCoder,
    DiodePacket,
    DiodeTransmitter,
    DiodeReceiver,
    CursorOnTargetEvent,
    DIODE_MAGIC,
    DIODE_HEADER_SIZE
)


class TestTacticalDataDiode(unittest.TestCase):
    # =========================================================================
    # 1. GALOIS FIELD GF(2^8) MATHEMATICAL INVARIANTS
    # =========================================================================

    def test_01_gf256_arithmetic(self):
        """Verify GF(2^8) field axioms: commutativity, inversion, division."""
        gf = GF256()

        # Addition / Subtraction (XOR)
        self.assertEqual(gf.add(42, 42), 0)
        self.assertEqual(gf.sub(100, 20), 100 ^ 20)

        # Inversion and Multiplication
        for a in range(1, 256):
            inv_a = gf.inv(a)
            prod = gf.mul(a, inv_a)
            self.assertEqual(prod, 1, f"Failed for a={a}: inv={inv_a}, prod={prod}")

        # Multiplication with zero
        self.assertEqual(gf.mul(0, 123), 0)
        self.assertEqual(gf.mul(123, 0), 0)

        # Division
        self.assertEqual(gf.div(42, 42), 1)
        self.assertEqual(gf.div(0, 42), 0)
        with self.assertRaises(ZeroDivisionError):
            gf.div(42, 0)

    # =========================================================================
    # 2. CAUCHY REED-SOLOMON ERASURE CODING
    # =========================================================================

    def test_02_erasure_coding_no_loss(self):
        """Verify K=8, M=4 coding reconstructs perfectly with all chunks."""
        k, m = 8, 4
        coder = CauchyErasureCoder(k=k, m=m)
        chunk_len = 128

        data_chunks = [secrets.token_bytes(chunk_len) for _ in range(k)]
        encoded = coder.encode(data_chunks)
        self.assertEqual(len(encoded), k + m)

        # Reconstruct with all 8 data chunks (indices 0..7)
        received = {i: encoded[i] for i in range(k)}
        decoded = coder.decode(received, chunk_len)
        self.assertEqual(decoded, data_chunks)

    def test_03_erasure_coding_maximum_drop_recovery(self):
        """
        Verify K=8, M=4 coding reconstructs perfectly when ANY M (4) packets are dropped.
        We drop the first 4 data chunks entirely (severe burst loss).
        """
        k, m = 8, 4
        coder = CauchyErasureCoder(k=k, m=m)
        chunk_len = 256

        data_chunks = [secrets.token_bytes(chunk_len) for _ in range(k)]
        encoded = coder.encode(data_chunks)

        # Drop chunks 0, 1, 2, 3!
        # Receiver gets data chunks 4, 5, 6, 7 and parity chunks 8, 9, 10, 11 (total 8)
        received = {i: encoded[i] for i in range(4, 12)}
        self.assertEqual(len(received), k)

        decoded = coder.decode(received, chunk_len)
        self.assertEqual(decoded, data_chunks)

    def test_04_erasure_coding_interleaved_packet_drop(self):
        """Verify recovery under scattered / interleaved packet loss pattern."""
        k, m = 6, 3
        coder = CauchyErasureCoder(k=k, m=m)
        chunk_len = 64

        data_chunks = [secrets.token_bytes(chunk_len) for _ in range(k)]
        encoded = coder.encode(data_chunks)

        # Drop indices 0, 3, 5 (3 packets dropped out of 9)
        received = {i: encoded[i] for i in [1, 2, 4, 6, 7, 8]}
        self.assertEqual(len(received), k)

        decoded = coder.decode(received, chunk_len)
        self.assertEqual(decoded, data_chunks)

    def test_05_erasure_coding_insufficient_packets_fails_closed(self):
        """Verify that receiving fewer than K packets fails closed with an error."""
        k, m = 8, 4
        coder = CauchyErasureCoder(k=k, m=m)
        data_chunks = [secrets.token_bytes(64) for _ in range(k)]
        encoded = coder.encode(data_chunks)

        # Receive only 7 chunks (need 8)
        received = {i: encoded[i] for i in range(7)}
        with self.assertRaises(ValueError) as ctx:
            coder.decode(received, 64)
        self.assertIn("Insufficient chunks", str(ctx.exception))

    # =========================================================================
    # 3. DIODE PACKET SERIALIZATION & INTEGRITY
    # =========================================================================

    def test_06_packet_serialization_roundtrip(self):
        """Verify packet header serialization, deserialization, and SHA3 integrity check."""
        tx_id = secrets.token_bytes(16)
        chunk_data = b"CLASSIFIED-DIODE-PAYLOAD-BYTES-TEST"
        sha3 = __import__("hashlib").sha3_256(chunk_data).digest()

        pkt = DiodePacket(
            magic=DIODE_MAGIC,
            tx_id=tx_id,
            total_len=len(chunk_data),
            chunk_len=len(chunk_data),
            k=4,
            m=2,
            chunk_index=1,
            chunk_sha3=sha3,
            chunk_data=chunk_data
        )

        wire = pkt.serialize()
        self.assertEqual(len(wire), DIODE_HEADER_SIZE + len(chunk_data))

        restored = DiodePacket.deserialize(wire)
        self.assertEqual(restored.magic, DIODE_MAGIC)
        self.assertEqual(restored.tx_id, tx_id)
        self.assertEqual(restored.chunk_index, 1)
        self.assertEqual(restored.chunk_data, chunk_data)

    def test_07_tampered_packet_fails_closed(self):
        """Verify that tampering with packet payload triggers fail-closed integrity check."""
        tx_id = secrets.token_bytes(16)
        chunk_data = b"GENUINE-PAYLOAD"
        sha3 = __import__("hashlib").sha3_256(chunk_data).digest()

        pkt = DiodePacket(
            magic=DIODE_MAGIC,
            tx_id=tx_id,
            total_len=len(chunk_data),
            chunk_len=len(chunk_data),
            k=4,
            m=2,
            chunk_index=0,
            chunk_sha3=sha3,
            chunk_data=chunk_data
        )

        wire = bytearray(pkt.serialize())
        # Tamper with the last byte
        wire[-1] ^= 0xFF

        with self.assertRaises(ValueError) as ctx:
            DiodePacket.deserialize(bytes(wire))
        self.assertIn("integrity check failed", str(ctx.exception))

    # =========================================================================
    # 4. CURSOR-ON-TARGET (CoT) TACTICAL TELEMETRY
    # =========================================================================

    def test_08_cursor_on_target_xml_generation(self):
        """Verify MIL-STD Cursor-on-Target XML structure."""
        cot = CursorOnTargetEvent.create_tactical(
            callsign="VIPER-ONE-LEADER",
            event_type="a-f-G-U-C",
            lat=34.0522,
            lon=-118.2437,
            status="DEFCON-1"
        )
        xml = cot.to_xml()

        self.assertIn('<?xml version="1.0"', xml)
        self.assertIn('type="a-f-G-U-C"', xml)
        self.assertIn('callsign="VIPER-ONE-LEADER"', xml)
        self.assertIn('readiness="DEFCON-1"', xml)
        self.assertIn('lat="34.052200"', xml)
        self.assertIn('lon="-118.243700"', xml)

    # =========================================================================
    # 5. END-TO-END LIVE SIMPLEX DIODE TRANSMISSION OVER UDP
    # =========================================================================

    def test_09_e2e_simplex_diode_transmission(self):
        """
        Verify live end-to-end transmission across simplex diode boundary
        with 3000-byte payload using K=8, M=4 Cauchy Forward Error Correction.
        """
        port = 55199
        receiver = DiodeReceiver(bind_host="127.0.0.1", bind_port=port)
        transmitter = DiodeTransmitter(target_host="127.0.0.1", target_port=port, chunk_payload_size=256)

        test_payload = secrets.token_bytes(3000)
        received_result = [None]

        def receive_worker():
            received_result[0] = receiver.receive_payload(timeout_seconds=4.0)

        t = threading.Thread(target=receive_worker)
        t.start()

        time.sleep(0.1)  # Allow receiver to bind
        transmitter.send_payload(test_payload, k=8, m=4, burst_interpacket_delay_ms=0.1)

        t.join(timeout=5.0)
        receiver.close()
        transmitter.close()

        self.assertIsNotNone(received_result[0], "Receiver timed out without recovering payload")
        self.assertEqual(received_result[0], test_payload)

    def test_10_e2e_simplex_cot_telemetry_transmission(self):
        """Verify tactical telemetry streaming across the diode."""
        port = 55198
        receiver = DiodeReceiver(bind_host="127.0.0.1", bind_port=port)
        transmitter = DiodeTransmitter(target_host="127.0.0.1", target_port=port, chunk_payload_size=128)

        cot = CursorOnTargetEvent.create_tactical(
            callsign="COMMAND-DUTY-OFFICER-STRATCOM",
            status="DEFCON-1"
        )
        cot_bytes = cot.to_xml().encode("utf-8")

        received_result = [None]

        def receive_worker():
            received_result[0] = receiver.receive_payload(timeout_seconds=4.0)

        t = threading.Thread(target=receive_worker)
        t.start()

        time.sleep(0.1)
        transmitter.send_payload(cot_bytes, k=6, m=3, burst_interpacket_delay_ms=0.1)

        t.join(timeout=5.0)
        receiver.close()
        transmitter.close()

        self.assertIsNotNone(received_result[0])
        self.assertEqual(received_result[0], cot_bytes)
        self.assertIn(b"COMMAND-DUTY-OFFICER-STRATCOM", received_result[0])


if __name__ == "__main__":
    unittest.main()
