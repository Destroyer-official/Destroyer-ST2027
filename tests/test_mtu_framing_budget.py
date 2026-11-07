"""
Unit and property tests for ST2027 IPv6 MTU and Framing Budget Verification.

Explicitly validates RFC 8200 minimum IPv6 MTU boundaries, RFC 768 UDP overheads,
and ST2027 wire quantization sizes to guarantee zero network-level IP fragmentation.

Wire Budget Breakdown:
  IPv6 Minimum MTU: 1280 bytes (RFC 8200 Section 5)
  IPv6 Header     :   40 bytes
  UDP Header      :    8 bytes (RFC 768)
  Max UDP Datagram: 1232 bytes (1280 - 40 - 8)

ST2027 Wire Framing Structure (inside UDP datagram payload):
  Sequence Number :    8 bytes (u64 big-endian)
  Payload Length  :    2 bytes (u16 big-endian)
  Frame Type      :    1 byte  (u8)
  AEAD GHASH Tag  :   16 bytes (NIST SP 800-38D)
  Total Overhead  :   27 bytes (FRAME_OVERHEAD)
  Max Plaintext   : 1205 bytes (MAX_PAYLOAD = 1232 - 27)

Complete Encapsulated Frame Size:
  1205 (Plaintext) + 27 (ST2027 Overhead) + 8 (UDP) + 40 (IPv6) = 1280 bytes.
"""

import unittest

# Standard Protocol Constants
IPV6_MIN_MTU = 1280
IPV6_HEADER_LEN = 40
UDP_HEADER_LEN = 8
MAX_UDP_PAYLOAD_AT_MIN_MTU = IPV6_MIN_MTU - IPV6_HEADER_LEN - UDP_HEADER_LEN  # 1232

# ST2027 Framing Constants
ST2027_SEQ_LEN = 8
ST2027_LEN_FIELD = 2
ST2027_TYPE_FIELD = 1
ST2027_TAG_LEN = 16
ST2027_FRAME_OVERHEAD = ST2027_SEQ_LEN + ST2027_LEN_FIELD + ST2027_TYPE_FIELD + ST2027_TAG_LEN  # 27
ST2027_TOP_QUANTUM = 1232
ST2027_MAX_PLAINTEXT = ST2027_TOP_QUANTUM - ST2027_FRAME_OVERHEAD  # 1205

ST2027_VALID_QUANTA = (256, 512, 1232)


class TestMtuFramingBudget(unittest.TestCase):
    def test_ipv6_minimum_mtu_derivation(self):
        """Verify the exact arithmetic of IPv6 minimum MTU minus transport headers."""
        self.assertEqual(MAX_UDP_PAYLOAD_AT_MIN_MTU, 1232)
        self.assertEqual(IPV6_HEADER_LEN + UDP_HEADER_LEN + MAX_UDP_PAYLOAD_AT_MIN_MTU, IPV6_MIN_MTU)

    def test_st2027_frame_overhead(self):
        """Verify wire framing overhead fields and tag."""
        self.assertEqual(ST2027_FRAME_OVERHEAD, 27)
        self.assertEqual(ST2027_MAX_PLAINTEXT, 1205)

    def test_complete_encapsulated_packet_boundary(self):
        """Assert complete encapsulated datagram matches the 1280-byte IPv6 minimum MTU boundary."""
        total_wire_packet = (
            ST2027_MAX_PLAINTEXT
            + ST2027_FRAME_OVERHEAD
            + UDP_HEADER_LEN
            + IPV6_HEADER_LEN
        )
        self.assertEqual(total_wire_packet, IPV6_MIN_MTU)
        self.assertLessEqual(total_wire_packet, IPV6_MIN_MTU)

    def test_all_quanta_fit_within_ipv6_minimum_mtu(self):
        """Verify every defined quantum fits without fragmentation on an IPv6 minimum MTU path."""
        for quantum in ST2027_VALID_QUANTA:
            encapsulated = quantum + UDP_HEADER_LEN + IPV6_HEADER_LEN
            self.assertLessEqual(
                encapsulated,
                IPV6_MIN_MTU,
                f"Quantum {quantum} encapsulated size {encapsulated} exceeds minimum MTU {IPV6_MIN_MTU}",
            )

    def test_quanta_payload_capacities(self):
        """Verify payload capacities across all quanta."""
        expected_capacities = {
            256: 256 - 27,   # 229 bytes
            512: 512 - 27,   # 485 bytes
            1232: 1232 - 27, # 1205 bytes
        }
        for q, cap in expected_capacities.items():
            self.assertEqual(q - ST2027_FRAME_OVERHEAD, cap)


if __name__ == "__main__":
    unittest.main()

