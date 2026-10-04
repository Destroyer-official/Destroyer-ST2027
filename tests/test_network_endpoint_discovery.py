#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite: Military Network Endpoint Discovery Engine
=====================================================
Validates:
1. Local Global Unicast IPv6 (GUA) classification and extraction.
2. Kernel-routed zero-egress source IP selection.
3. RFC 5389 / RFC 8489 STUN XOR-MAPPED-ADDRESS vector parsing for IPv4 and IPv6.
4. Anti-spoofing: Transaction ID and Magic Cookie validation.
5. Fuzz / malformed packet resilience (fail-closed, zero unhandled crashes).
6. Tactical cloak / air-gapped zero-egress policy enforcement.
7. End-to-end performance and latency budgets (< 100ms local).
"""

import asyncio
import ipaddress
import json
import os
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

import pytest

from network_endpoint_discovery import (
    DEFAULT_P2P_PORT,
    NetworkEndpoint,
    NetworkEndpointDiscovery,
    NetworkPosture,
    parse_endpoint,
)


class TestNetworkEndpointDiscovery(unittest.TestCase):
    """Unit and property test suite for NetworkEndpointDiscovery."""

    def setUp(self):
        self.engine = NetworkEndpointDiscovery(custom_port=50007)

    def test_ipv6_endpoint_formatting(self):
        """Verify IPv6 endpoints include brackets and strip zone indices."""
        ep_v6 = NetworkEndpoint(
            ip="2409:4091:10a2:7a01:6169:e7ee:60ad:b5f8%4",
            family="IPv6",
            scope="global",
            interface="Ethernet",
            is_public=True,
            port=50007,
        )
        assert ep_v6.formatted_endpoint == "[2409:4091:10a2:7a01:6169:e7ee:60ad:b5f8]:50007"

    def test_ipv4_endpoint_formatting(self):
        """Verify IPv4 endpoints format cleanly without brackets."""
        ep_v4 = NetworkEndpoint(
            ip="192.168.31.182",
            family="IPv4",
            scope="private",
            interface="Ethernet",
            is_public=False,
            port=50007,
        )
        assert ep_v4.formatted_endpoint == "192.168.31.182:50007"

    def test_kernel_routed_ipv6_is_global_if_present(self):
        """If host has IPv6 connectivity, kernel-routed IP must be valid Global Unicast."""
        kernel_v6 = self.engine.get_kernel_routed_ipv6()
        if kernel_v6 is not None:
            ip = ipaddress.ip_address(kernel_v6)
            assert ip.version == 6
            assert ip.is_global is True
            assert ip.is_link_local is False
            assert ip.is_loopback is False
            assert ip.is_multicast is False

    def test_kernel_routed_ipv4_is_valid_if_present(self):
        """If host has IPv4 connectivity, kernel-routed IP must be a valid non-loopback IPv4."""
        kernel_v4 = self.engine.get_kernel_routed_ipv4()
        if kernel_v4 is not None:
            ip = ipaddress.ip_address(kernel_v4)
            assert ip.version == 4
            assert ip.is_loopback is False

    def test_local_interface_scanning_categorization(self):
        """Verify local interfaces classify into public IPv6, local IPv4, and link-local IPv6."""
        pub_v6, loc_v4, link_v6 = self.engine.scan_local_interfaces()

        # All items in pub_v6 must be global IPv6
        for ep in pub_v6:
            assert ep.family == "IPv6"
            assert ep.scope == "global"
            ip = ipaddress.ip_address(ep.ip)
            assert ip.is_global is True

        # All items in loc_v4 must be IPv4
        for ep in loc_v4:
            assert ep.family == "IPv4"
            ip = ipaddress.ip_address(ep.ip)
            assert ip.version == 4
            assert ip.is_loopback is False

        # All items in link_v6 must be link-local IPv6
        for ep in link_v6:
            assert ep.family == "IPv6"
            assert ep.scope == "link-local"
            ip = ipaddress.ip_address(ep.ip.split("%")[0])
            assert ip.is_link_local is True

    def test_air_gap_mode_suppresses_stun(self):
        """In air-gap or tactical cloak mode, STUN queries must be completely bypassed."""
        with patch.dict(os.environ, {"P2P_AIR_GAPPED": "1"}):
            posture = asyncio.run(self.engine.discover_endpoints(allow_stun=True))
            assert posture.air_gap_mode is True
            assert posture.stun_queried is False
            assert posture.primary_public_ipv4 is None

        with patch.dict(os.environ, {"P2P_TACTICAL_CLOAK": "1", "P2P_AIR_GAPPED": "0"}):
            posture = asyncio.run(self.engine.discover_endpoints(allow_stun=True))
            assert posture.air_gap_mode is True
            assert posture.stun_queried is False
            assert posture.primary_public_ipv4 is None

    def test_offline_discovery_latency_budget(self):
        """Local zero-egress discovery must execute under 100 milliseconds."""
        posture = asyncio.run(self.engine.discover_endpoints(allow_stun=False))
        assert posture.discovery_duration_ms < 100.0, f"Too slow: {posture.discovery_duration_ms}ms"

    def test_rfc5389_stun_xor_mapped_ipv4_parsing(self):
        """Test RFC 5389 XOR-MAPPED-ADDRESS IPv4 attribute decoding with known test vector."""
        magic_cookie = 0x2112A442
        tx_id = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"

        # Response Header: 0x0101 (Success), length 12, magic, tx_id
        attr_type = 0x0020  # XOR-MAPPED-ADDRESS
        attr_len = 8
        family = 0x01       # IPv4

        # Real IP: 198.51.100.1, Port: 32853
        test_ip = "198.51.100.1"
        test_port = 32853

        x_port = test_port ^ (magic_cookie >> 16)
        x_ip = int(ipaddress.IPv4Address(test_ip)) ^ magic_cookie

        attr_payload = struct.pack("!BBHI", 0, family, x_port, x_ip)
        attr = struct.pack("!HH", attr_type, attr_len) + attr_payload

        resp_header = struct.pack("!HHI", 0x0101, len(attr), magic_cookie) + tx_id
        mock_packet = resp_header + attr

        # Mock the socket loop
        async def mock_query():
            with patch("asyncio.get_running_loop") as mock_get_loop:
                mock_loop = MagicMock()
                mock_get_loop.return_value = mock_loop
                mock_loop.getaddrinfo = unittest.mock.AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 3478))])
                mock_loop.sock_connect = unittest.mock.AsyncMock(return_value=None)
                mock_loop.sock_sendall = unittest.mock.AsyncMock(return_value=None)
                mock_loop.sock_recv = unittest.mock.AsyncMock(return_value=mock_packet)

                with patch("os.urandom", return_value=tx_id):
                    return await self.engine.query_stun_server("dummy.stun.com", 3478)

        res = asyncio.run(mock_query())
        assert res is not None
        assert res[0] == test_ip
        assert res[1] == test_port

    def test_rfc5389_stun_xor_mapped_ipv6_parsing(self):
        """Test RFC 5389 XOR-MAPPED-ADDRESS IPv6 attribute decoding with known test vector."""
        magic_cookie = 0x2112A442
        tx_id = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"

        attr_type = 0x0020
        attr_len = 20
        family = 0x02  # IPv6

        test_ip = "2001:db8:85a3::8a2e:370:7334"
        test_port = 49152

        x_port = test_port ^ (magic_cookie >> 16)
        raw_ip_bytes = ipaddress.IPv6Address(test_ip).packed
        xor_key = struct.pack("!I", magic_cookie) + tx_id
        x_ip_bytes = bytes(a ^ b for a, b in zip(raw_ip_bytes, xor_key))

        attr_payload = struct.pack("!BBH", 0, family, x_port) + x_ip_bytes
        attr = struct.pack("!HH", attr_type, attr_len) + attr_payload

        resp_header = struct.pack("!HHI", 0x0101, len(attr), magic_cookie) + tx_id
        mock_packet = resp_header + attr

        async def mock_query():
            with patch("asyncio.get_running_loop") as mock_get_loop:
                mock_loop = MagicMock()
                mock_get_loop.return_value = mock_loop
                mock_loop.getaddrinfo = unittest.mock.AsyncMock(return_value=[(None, None, None, None, ("::1", 3478))])
                mock_loop.sock_connect = unittest.mock.AsyncMock(return_value=None)
                mock_loop.sock_sendall = unittest.mock.AsyncMock(return_value=None)
                mock_loop.sock_recv = unittest.mock.AsyncMock(return_value=mock_packet)

                with patch("os.urandom", return_value=tx_id):
                    return await self.engine.query_stun_server("dummy.stun.com", 3478, family=socket.AF_INET6)

        res = asyncio.run(mock_query())
        assert res is not None
        assert res[0] == test_ip
        assert res[1] == test_port

    def test_stun_malformed_packet_fails_closed(self):
        """Malformed, truncated, or random bytes must return None and never raise."""
        garbage_packets = [
            b"",
            b"too_short",
            b"\x00" * 19,
            b"\x01\x01\x00\x00\x00\x00\x00\x00" + b"\x00" * 12,  # wrong magic
            b"\x01\x01\x00\x10\x21\x12\xa4\x42" + b"\xff" * 12,  # wrong tx_id
            b"\x01\x01\x00\x08\x21\x12\xa4\x42" + b"\x00" * 12 + b"\x00\x20\x00\x02\x00\x00",  # truncated attr
        ]

        for pkt in garbage_packets:
            async def run_bad_pkt():
                with patch("asyncio.get_running_loop") as mock_get_loop:
                    mock_loop = MagicMock()
                    mock_get_loop.return_value = mock_loop
                    mock_loop.getaddrinfo = unittest.mock.AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 3478))])
                    mock_loop.sock_connect = unittest.mock.AsyncMock(return_value=None)
                    mock_loop.sock_sendall = unittest.mock.AsyncMock(return_value=None)
                    mock_loop.sock_recv = unittest.mock.AsyncMock(return_value=pkt)
                    with patch("os.urandom", return_value=b"\x00" * 12):
                        return await self.engine.query_stun_server("dummy", 3478)

            result = asyncio.run(run_bad_pkt())
            assert result is None, f"Expected None on malformed packet {pkt!r}, got {result}"

    def test_json_serialization_roundtrip(self):
        """Verify NetworkPosture serializes to valid JSON matching data schema."""
        posture = asyncio.run(self.engine.discover_endpoints(allow_stun=False))
        json_str = posture.to_json()
        data = json.loads(json_str)

        assert "primary_public_ipv6" in data
        assert "primary_public_ipv4" in data
        assert "primary_local_ipv4" in data
        assert "all_public_ipv6" in data
        assert "all_local_ipv4" in data
        assert "discovery_duration_ms" in data
        assert isinstance(data["all_public_ipv6"], list)

    def test_parse_endpoint_bracketed_ipv6_with_port(self):
        """Verify [ipv6]:port parses host and port correctly."""
        host, port = parse_endpoint("[2409:4091:10a2:7a01:6169:e7ee:60ad:b5f8]:50007")
        assert host == "2409:4091:10a2:7a01:6169:e7ee:60ad:b5f8"
        assert port == 50007

    def test_parse_endpoint_bracketed_ipv6_without_port(self):
        """Verify [ipv6] parses host and applies default port."""
        host, port = parse_endpoint("[2409:4091:10a2:7a01:6169:e7ee:60ad:b5f8]", default_port=50007)
        assert host == "2409:4091:10a2:7a01:6169:e7ee:60ad:b5f8"
        assert port == 50007

    def test_parse_endpoint_bare_ipv6(self):
        """Verify bare unbracketed IPv6 parses host without misinterpreting colons as port."""
        host, port = parse_endpoint("2409:4091:10a2:7a01:6169:e7ee:60ad:b5f8", default_port=50007)
        assert host == "2409:4091:10a2:7a01:6169:e7ee:60ad:b5f8"
        assert port == 50007

    def test_parse_endpoint_ipv4_with_port(self):
        """Verify ipv4:port parses host and port correctly."""
        host, port = parse_endpoint("192.168.31.182:50009")
        assert host == "192.168.31.182"
        assert port == 50009

    def test_parse_endpoint_bare_ipv4(self):
        """Verify bare ipv4 applies default port."""
        host, port = parse_endpoint("192.168.31.182", default_port=50007)
        assert host == "192.168.31.182"
        assert port == 50007

    def test_parse_endpoint_hostname_with_port(self):
        """Verify hostname:port parses cleanly."""
        host, port = parse_endpoint("peer.defense.mil:8443")
        assert host == "peer.defense.mil"
        assert port == 8443

    def test_parse_endpoint_malformed_inputs(self):
        """Verify malformed endpoints raise ValueError and fail-closed."""
        bad_inputs = [
            "",
            "   ",
            "[2409:1234",  # Missing closing bracket
            "[2409:1234]:notaport",
            "192.168.1.1:99999",  # Port out of range
            "192.168.1.1:-5",
            None,
        ]
        for bad in bad_inputs:
            with pytest.raises(ValueError):
                parse_endpoint(bad)


if __name__ == "__main__":
    unittest.main()
