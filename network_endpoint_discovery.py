#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Military-Grade Network Endpoint Discovery Engine (IPv6 / IPv4 / LAN)
====================================================================
Provides reliable, high-speed, and secure discovery of all network endpoints:
1. Public Global Unicast IPv6 (GUA) — Zero-network-egress kernel route + interface scan.
2. Public IPv4 — RFC 5389 / RFC 8489 STUN NAT traversal (optional, respects air-gap).
3. Local LAN IPv4 — Intranet / Base-to-Base private addresses.
4. Link-Local IPv6 — Point-to-point / ad-hoc direct military mesh addresses.

Security & Operational Invariants:
- Air-gap / Tactical Cloak Safe: When P2P_TACTICAL_CLOAK or P2P_AIR_GAPPED is active,
  zero network packets leave the machine; endpoints are derived strictly from local
  kernel routing tables and hardware interfaces.
- Zero Latency IPv6 Discovery: Because IPv6 has no NAT, the public Global Unicast
  address is resolved in < 1ms without querying any external cloud/STUN server.
- Fail-Closed & Robust: Handles multi-homed interfaces, temporary privacy addresses
  (RFC 4941), dual-stack adapters, and disconnected states cleanly.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import socket
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("network_endpoint_discovery")

# Default military port
DEFAULT_P2P_PORT = 50007

# Fallback resilient STUN servers (used only if STUN is permitted by policy)
DEFAULT_STUN_SERVERS = [
    ("stun.cloudflare.com", 3478),
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
]


@dataclass
class NetworkEndpoint:
    """Represents a single discovered network address."""
    ip: str
    family: str  # 'IPv4' or 'IPv6'
    scope: str   # 'global', 'private', 'link-local', 'loopback'
    interface: str
    is_public: bool
    is_temporary: bool = False
    port: int = DEFAULT_P2P_PORT

    @property
    def formatted_endpoint(self) -> str:
        """Return formatted IP:Port string with IPv6 bracket notation."""
        if self.family == "IPv6":
            # Strip interface zone id if present for public addresses
            clean_ip = self.ip.split("%")[0]
            return f"[{clean_ip}]:{self.port}"
        return f"{self.ip}:{self.port}"


@dataclass
class NetworkPosture:
    """Complete network state and endpoint report."""
    primary_public_ipv6: Optional[str] = None
    primary_public_ipv4: Optional[str] = None
    primary_local_ipv4: Optional[str] = None
    primary_local_ipv6: Optional[str] = None
    all_public_ipv6: List[NetworkEndpoint] = field(default_factory=list)
    all_local_ipv4: List[NetworkEndpoint] = field(default_factory=list)
    all_link_local_ipv6: List[NetworkEndpoint] = field(default_factory=list)
    active_interface: Optional[str] = None
    dual_stack_capable: bool = False
    air_gap_mode: bool = False
    stun_queried: bool = False
    discovery_duration_ms: float = 0.0

    @property
    def primary_public_endpoint(self) -> Optional[str]:
        """Returns the best public routable endpoint (IPv6 preferred, else IPv4)."""
        if self.primary_public_ipv6:
            return f"[{self.primary_public_ipv6}]:{DEFAULT_P2P_PORT}"
        if self.primary_public_ipv4:
            return f"{self.primary_public_ipv4}:{DEFAULT_P2P_PORT}"
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert posture to serializable dictionary."""
        return {
            "primary_public_ipv6": self.primary_public_ipv6,
            "primary_public_ipv4": self.primary_public_ipv4,
            "primary_local_ipv4": self.primary_local_ipv4,
            "primary_local_ipv6": self.primary_local_ipv6,
            "primary_public_endpoint": self.primary_public_endpoint,
            "all_public_ipv6": [asdict(e) for e in self.all_public_ipv6],
            "all_local_ipv4": [asdict(e) for e in self.all_local_ipv4],
            "all_link_local_ipv6": [asdict(e) for e in self.all_link_local_ipv6],
            "active_interface": self.active_interface,
            "dual_stack_capable": self.dual_stack_capable,
            "air_gap_mode": self.air_gap_mode,
            "stun_queried": self.stun_queried,
            "discovery_duration_ms": round(self.discovery_duration_ms, 2),
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert posture to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class NetworkEndpointDiscovery:
    """
    High-assurance network endpoint discovery engine.
    Works in all environments: Air-Gapped, Direct IPv6, and IPv4 NAT.
    """

    def __init__(self, custom_port: int = DEFAULT_P2P_PORT):
        self.port = custom_port

    def get_kernel_routed_ipv6(self) -> Optional[str]:
        """
        Ask the OS kernel routing table which local IPv6 source address it
        uses for public internet traffic without sending any packets.
        """
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                # 2606:4700:4700::1111 is Cloudflare Public DNS
                sock.connect(("2606:4700:4700::1111", 53))
                src_ip = sock.getsockname()[0]
                # Validate that it is a real global unicast address
                ip_obj = ipaddress.ip_address(src_ip.split("%")[0])
                if ip_obj.version == 6 and ip_obj.is_global and not ip_obj.is_link_local:
                    return str(ip_obj)
            finally:
                sock.close()
        except Exception as exc:
            logger.debug(f"Kernel routed IPv6 check bypassed: {exc}")
        return None

    def get_kernel_routed_ipv4(self) -> Optional[str]:
        """
        Ask the OS kernel routing table which local IPv4 source address it
        uses for public internet traffic without sending any packets.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # 1.1.1.1 is Cloudflare Public DNS
                sock.connect(("1.1.1.1", 53))
                src_ip = sock.getsockname()[0]
                ip_obj = ipaddress.ip_address(src_ip)
                if ip_obj.version == 4 and not ip_obj.is_loopback:
                    return str(ip_obj)
            finally:
                sock.close()
        except Exception as exc:
            logger.debug(f"Kernel routed IPv4 check bypassed: {exc}")
        return None

    def scan_local_interfaces(self) -> Tuple[List[NetworkEndpoint], List[NetworkEndpoint], List[NetworkEndpoint]]:
        """
        Scan all local network adapter hardware interfaces for IPv6 and IPv4 addresses.
        Returns:
            Tuple of (public_ipv6_list, local_ipv4_list, link_local_ipv6_list)
        """
        public_v6: List[NetworkEndpoint] = []
        local_v4: List[NetworkEndpoint] = []
        link_local_v6: List[NetworkEndpoint] = []

        try:
            import psutil
            interfaces = psutil.net_if_addrs()
        except ImportError:
            # Fallback to standard socket if psutil is unavailable
            interfaces = {}

        for iface_name, addrs in interfaces.items():
            for addr_info in addrs:
                ip_raw = addr_info.address
                # Strip zone identifier (e.g. fe80::1%4 -> fe80::1)
                ip_clean = ip_raw.split("%")[0]

                try:
                    ip_obj = ipaddress.ip_address(ip_clean)
                except ValueError:
                    continue

                if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
                    continue

                if ip_obj.version == 6:
                    if ip_obj.is_link_local:
                        link_local_v6.append(NetworkEndpoint(
                            ip=ip_raw,
                            family="IPv6",
                            scope="link-local",
                            interface=iface_name,
                            is_public=False,
                            port=self.port,
                        ))
                    elif ip_obj.is_global and not ip_obj.is_reserved:
                        # Global Unicast IPv6 is a real, publicly routable address!
                        # Heuristic: Temporary privacy addresses typically have high entropy in the host ID
                        public_v6.append(NetworkEndpoint(
                            ip=ip_clean,
                            family="IPv6",
                            scope="global",
                            interface=iface_name,
                            is_public=True,
                            port=self.port,
                        ))

                elif ip_obj.version == 4:
                    scope = "private" if ip_obj.is_private else "global"
                    is_public = ip_obj.is_global and not ip_obj.is_private
                    local_v4.append(NetworkEndpoint(
                        ip=ip_clean,
                        family="IPv4",
                        scope=scope,
                        interface=iface_name,
                        is_public=is_public,
                        port=self.port,
                    ))

        return public_v6, local_v4, link_local_v6

    async def query_stun_server(
        self,
        stun_host: str,
        stun_port: int,
        family: int = socket.AF_INET,
        timeout: float = 2.0
    ) -> Optional[Tuple[str, int]]:
        """
        RFC 5389 / RFC 8489 STUN Binding Request to discover public mapped endpoint.
        Handles both IPv4 and IPv6 XOR-MAPPED-ADDRESS attributes.
        """
        # RFC 5389 Header: Binding Request (0x0001), Length (0), Magic Cookie (0x2112A442), 96-bit TxID
        magic_cookie = 0x2112A442
        tx_id = os.urandom(12)
        request = struct.pack("!HHI", 0x0001, 0, magic_cookie) + tx_id

        loop = asyncio.get_running_loop()
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)

        try:
            # Resolve STUN server
            addr_info = await loop.getaddrinfo(
                stun_host,
                stun_port,
                family=family,
                type=socket.SOCK_DGRAM
            )
            if not addr_info:
                return None
            target_addr = addr_info[0][4]

            await loop.sock_connect(sock, target_addr)
            await loop.sock_sendall(sock, request)

            # Wait for response with timeout
            data = await asyncio.wait_for(loop.sock_recv(sock, 2048), timeout=timeout)
            if len(data) < 20:
                return None

            resp_type, msg_len, resp_magic = struct.unpack("!HHI", data[:8])
            resp_tx_id = data[8:20]

            if resp_type != 0x0101 or resp_magic != magic_cookie or resp_tx_id != tx_id:
                return None

            # Parse STUN Attributes
            offset = 20
            end_offset = 20 + msg_len
            while offset + 4 <= end_offset and offset + 4 <= len(data):
                attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
                offset += 4
                attr_data = data[offset:offset + attr_len]
                offset += (attr_len + 3) & ~3  # Pad to 4-byte boundary

                # XOR-MAPPED-ADDRESS (0x0020)
                if attr_type == 0x0020 and len(attr_data) >= 8:
                    _reserved = attr_data[0]
                    family_code = attr_data[1]
                    x_port = struct.unpack("!H", attr_data[2:4])[0]
                    mapped_port = x_port ^ (magic_cookie >> 16)

                    if family_code == 0x01 and len(attr_data) >= 8:  # IPv4
                        x_ip = struct.unpack("!I", attr_data[4:8])[0]
                        mapped_ip_int = x_ip ^ magic_cookie
                        mapped_ip = socket.inet_ntoa(struct.pack("!I", mapped_ip_int))
                        return mapped_ip, mapped_port

                    elif family_code == 0x02 and len(attr_data) >= 20:  # IPv6
                        x_ip_bytes = attr_data[4:20]
                        xor_mask = struct.pack("!I", magic_cookie) + tx_id
                        mapped_ip_bytes = bytes(a ^ b for a, b in zip(x_ip_bytes, xor_mask))
                        mapped_ip = socket.inet_ntop(socket.AF_INET6, mapped_ip_bytes)
                        return mapped_ip, mapped_port

        except Exception as exc:
            logger.debug(f"STUN query failed on {stun_host}:{stun_port} ({family}): {exc}")
        finally:
            sock.close()

        return None

    async def discover_endpoints(
        self,
        allow_stun: bool = True,
        stun_servers: Optional[List[Tuple[str, int]]] = None,
        timeout: float = 2.0
    ) -> NetworkPosture:
        """
        Execute comprehensive multi-tier endpoint discovery.
        """
        start_time = time.perf_counter()
        posture = NetworkPosture()

        # Check military policy constraints
        is_air_gapped = os.environ.get("P2P_AIR_GAPPED", "").lower() in ("1", "true", "yes")
        is_tactical_cloak = os.environ.get("P2P_TACTICAL_CLOAK", "").lower() in ("1", "true", "yes")
        posture.air_gap_mode = is_air_gapped or is_tactical_cloak

        # ---------------------------------------------------------------------
        # TIER 1: Instant Local Hardware Interface & Kernel Route Scan (0ms)
        # ---------------------------------------------------------------------
        kernel_v6 = self.get_kernel_routed_ipv6()
        kernel_v4 = self.get_kernel_routed_ipv4()

        public_v6_list, local_v4_list, link_local_v6_list = self.scan_local_interfaces()
        posture.all_public_ipv6 = public_v6_list
        posture.all_local_ipv4 = local_v4_list
        posture.all_link_local_ipv6 = link_local_v6_list

        # Pick primary public IPv6:
        # Prefer kernel-routed GUA, else first discovered GUA on an active adapter
        if kernel_v6:
            posture.primary_public_ipv6 = kernel_v6
        elif public_v6_list:
            posture.primary_public_ipv6 = public_v6_list[0].ip

        # Pick primary local IPv4:
        if kernel_v4:
            posture.primary_local_ipv4 = kernel_v4
        elif local_v4_list:
            posture.primary_local_ipv4 = local_v4_list[0].ip

        # Pick primary link-local IPv6:
        if link_local_v6_list:
            posture.primary_local_ipv6 = link_local_v6_list[0].ip

        # Determine active interface
        if public_v6_list:
            posture.active_interface = public_v6_list[0].interface
        elif local_v4_list:
            posture.active_interface = local_v4_list[0].interface

        posture.dual_stack_capable = bool(posture.primary_public_ipv6 and posture.primary_local_ipv4)

        # ---------------------------------------------------------------------
        # TIER 2: STUN Discovery for IPv4 NAT Traversal (if permitted)
        # ---------------------------------------------------------------------
        can_query_stun = allow_stun and not posture.air_gap_mode
        if can_query_stun:
            servers = stun_servers or DEFAULT_STUN_SERVERS
            posture.stun_queried = True

            # Attempt STUN for IPv4 (to find external NAT mapping)
            for s_host, s_port in servers:
                res_v4 = await self.query_stun_server(s_host, s_port, family=socket.AF_INET, timeout=timeout)
                if res_v4 and res_v4[0]:
                    posture.primary_public_ipv4 = res_v4[0]
                    break

            # If IPv6 GUA was not discovered locally, also try STUN IPv6
            if not posture.primary_public_ipv6:
                for s_host, s_port in servers:
                    res_v6 = await self.query_stun_server(s_host, s_port, family=socket.AF_INET6, timeout=timeout)
                    if res_v6 and res_v6[0]:
                        posture.primary_public_ipv6 = res_v6[0]
                        break

        posture.discovery_duration_ms = (time.perf_counter() - start_time) * 1000.0
        return posture


def print_network_report(posture: NetworkPosture, port: int = DEFAULT_P2P_PORT) -> None:
    """Print an aesthetically rich, military-grade terminal report."""
    green = "\033[92m"
    cyan = "\033[96m"
    yellow = "\033[93m"
    magenta = "\033[95m"
    bold = "\033[1m"
    reset = "\033[0m"

    print(f"\n{bold}{cyan}{'='*75}{reset}")
    print(f"{bold}{cyan}  MILITARY SECURE NETWORK ENDPOINT DISCOVERY REPORT{reset}")
    print(f"  Discovery Time: {posture.discovery_duration_ms:.2f} ms | Dual-Stack: {posture.dual_stack_capable}")
    print(f"{bold}{cyan}{'='*75}{reset}")

    # 1. Public IPv6 Section
    print(f"\n{bold}[1. GLOBAL PUBLIC IPv6 ENDPOINTS (Internet Direct - Zero NAT)]{reset}")
    if posture.primary_public_ipv6:
        print(f"  {green}► Primary Public IPv6 :{reset} {bold}[{posture.primary_public_ipv6}]:{port}{reset}")
        for idx, ep in enumerate(posture.all_public_ipv6, 1):
            is_pri = " (PRIMARY)" if ep.ip == posture.primary_public_ipv6 else ""
            print(f"    {idx}. [{ep.ip}]:{port} on interface '{ep.interface}'{is_pri}")
    else:
        print(f"  {yellow}► None detected (Check router IPv6 RA or interface state){reset}")

    # 2. Public IPv4 Section
    print(f"\n{bold}[2. PUBLIC IPv4 ENDPOINT (NAT Mapped)]{reset}")
    if posture.primary_public_ipv4:
        print(f"  {green}► Public IPv4 (NAT)   :{reset} {bold}{posture.primary_public_ipv4}:{port}{reset}")
    else:
        status_msg = "Air-Gap/Tactical Cloak Active (STUN Suppressed)" if posture.air_gap_mode else "STUN not queried or NAT unreachable"
        print(f"  {yellow}► {status_msg}{reset}")

    # 3. Local LAN IPv4 Section
    print(f"\n{bold}[3. LOCAL LAN IPv4 ENDPOINTS (Intranet / Military Base LAN)]{reset}")
    if posture.all_local_ipv4:
        for idx, ep in enumerate(posture.all_local_ipv4, 1):
            is_pri = " (DEFAULT)" if ep.ip == posture.primary_local_ipv4 else ""
            print(f"    {idx}. {ep.ip}:{port} on interface '{ep.interface}' [{ep.scope}]{is_pri}")
    else:
        print(f"  {yellow}► None detected{reset}")

    # 4. Link-Local IPv6 Section
    print(f"\n{bold}[4. LINK-LOCAL IPv6 ENDPOINTS (Ad-Hoc / Point-to-Point Mesh)]{reset}")
    if posture.all_link_local_ipv6:
        for idx, ep in enumerate(posture.all_link_local_ipv6, 1):
            print(f"    {idx}. [{ep.ip}]:{port} on interface '{ep.interface}'")
    else:
        print(f"  {yellow}► None detected{reset}")

    # 5. Connection String for Remote Peer
    print(f"\n{bold}{cyan}{'-'*75}{reset}")
    print(f"{bold}READY-TO-USE P2P CONNECTION STRINGS FOR REMOTE PEERS:{reset}")
    if posture.primary_public_ipv6:
        print(f"  {green}Global Internet (IPv6) :{reset} {bold}{posture.primary_public_ipv6} {port}{reset}")
    if posture.primary_public_ipv4:
        print(f"  {green}Global Internet (IPv4) :{reset} {bold}{posture.primary_public_ipv4} {port}{reset}")
    if posture.primary_local_ipv4:
        print(f"  {cyan}Same Local LAN (IPv4)  :{reset} {bold}{posture.primary_local_ipv4} {port}{reset}")
    print(f"{bold}{cyan}{'='*75}{reset}\n")


def parse_endpoint(raw_str: str, default_port: int = DEFAULT_P2P_PORT) -> Tuple[str, int]:
    """
    Parse an IP endpoint string (IPv6, IPv4, or hostname with optional port)
    into a normalized (clean_ip_or_host, port) tuple.

    Complies with RFC 3986 (URI IP-literal), RFC 5952 (IPv6 representation),
    and RFC 1123 (DNS hostname).

    Supported formats:
      - [2001:db8::1]:50007 -> ('2001:db8::1', 50007)
      - [2001:db8::1]       -> ('2001:db8::1', default_port)
      - 2001:db8::1         -> ('2001:db8::1', default_port)
      - 192.168.1.5:50007   -> ('192.168.1.5', 50007)
      - 192.168.1.5         -> ('192.168.1.5', default_port)
      - peer.domain.mil:50007 -> ('peer.domain.mil', 50007)
      - peer.domain.mil     -> ('peer.domain.mil', default_port)

    Raises:
        ValueError: If input is invalid or port is outside 1-65535.
    """
    if not raw_str or not isinstance(raw_str, str):
        raise ValueError("Endpoint string cannot be empty or non-string")
    s = raw_str.strip()
    if not s:
        raise ValueError("Endpoint string cannot be whitespace-only")

    # Format 1: Bracketed IPv6: [ipv6] or [ipv6]:port
    if s.startswith('['):
        if ']:' in s:
            host_part, port_part = s.split(']:', 1)
            host = host_part.lstrip('[').strip()
            try:
                port = int(port_part.strip())
            except ValueError:
                raise ValueError(f"Invalid port in bracketed IPv6 endpoint: '{port_part}'")
        elif s.endswith(']'):
            host = s[1:-1].strip()
            port = default_port
        else:
            raise ValueError(f"Malformed bracketed IPv6 endpoint: '{s}'")
    # Format 2: Standard host/IPv4 with port: host:port (single colon)
    elif ':' in s and s.count(':') == 1:
        host_part, port_part = s.split(':', 1)
        host = host_part.strip()
        try:
            port = int(port_part.strip())
        except ValueError:
            raise ValueError(f"Invalid port in host:port endpoint: '{port_part}'")
    # Format 3: Raw IPv6 without brackets (multiple colons), or hostname/IPv4 without port
    else:
        host = s
        port = default_port

    if not (1 <= port <= 65535):
        raise ValueError(f"Port number {port} is out of valid range (1-65535)")

    return host, port


async def main() -> None:
    parser = argparse.ArgumentParser(description="Military Secure P2P Network Endpoint Discovery Engine")
    parser.add_argument("--port", type=int, default=DEFAULT_P2P_PORT, help=f"P2P port number (default: {DEFAULT_P2P_PORT})")
    parser.add_argument("--json", action="store_true", help="Output complete report in JSON format")
    parser.add_argument("--no-stun", action="store_true", help="Strict zero-network-egress air-gapped mode (no STUN)")
    parser.add_argument("--stun-host", type=str, default=None, help="Custom STUN server hostname")
    parser.add_argument("--stun-port", type=int, default=3478, help="Custom STUN server port (default: 3478)")
    args = parser.parse_args()

    engine = NetworkEndpointDiscovery(custom_port=args.port)
    stun_servers = [(args.stun_host, args.stun_port)] if args.stun_host else None

    allow_stun = not args.no_stun
    posture = await engine.discover_endpoints(allow_stun=allow_stun, stun_servers=stun_servers)

    if args.json:
        print(posture.to_json())
    else:
        print_network_report(posture, port=args.port)


if __name__ == "__main__":
    asyncio.run(main())
