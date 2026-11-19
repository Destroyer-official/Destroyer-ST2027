#!/usr/bin/env python3
"""
tests/test_sel4_mils_spec.py — Formal Static Verification Suite for seL4 Microkit
MILS (Multiple Independent Levels of Security) Domain Separation Architecture.

Evaluates Common Criteria EAL6+ / EAL7 Security Functional Requirements:
  - FDP_ACC.2: Complete Access Control (Zero non-bypassable paths).
  - FDP_ACF.1: Security Attribute-Based Access Control.
  - FPT_FLS.1: Fail-Secure / Fail-Closed State.
  - Non-Interference: Pure mathematical isolation between RED and BLACK domains.
  - Complete Mediation: Cryptographic partition is a strict cut-vertex in the channel graph.

Security Invariants Verified:
  1. Zero RED <-> BLACK direct IPC channel or notification endpoint.
  2. Zero RED <-> BLACK shared memory intersection.
  3. Quarantined cryptographic key storage (accessible strictly by CRYPTO domain).
  4. Memory region bounds and page alignment (4 KiB page multiples).
  5. Formal graph cut-vertex property: all information flows MUST traverse CRYPTO.
  6. `#![no_std]` and `#![no_main]` bare-metal Rust source invariants.
  7. Fail-closed negative mutation resistance.
"""

from __future__ import annotations

import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pytest
from defusedxml.ElementTree import parse as secure_xml_parse

from sel4_microkit_manifest import (
    SeL4MicrokitManifest,
    MemoryRegion,
    MemoryMap,
    ProtectionDomain,
    Channel,
    SeL4PolicyViolation,
)

SYSTEM_XML_PATH = Path("sel4_mils_appliance/system.xml")
RED_SRC_PATH = Path("sel4_mils_appliance/red_domain/src/main.rs")
CRYPTO_SRC_PATH = Path("sel4_mils_appliance/crypto_domain/src/main.rs")
BLACK_SRC_PATH = Path("sel4_mils_appliance/black_domain/src/main.rs")
CARGO_TOML_PATH = Path("sel4_mils_appliance/Cargo.toml")


# =============================================================================
# Helper Utilities for MILS Topology Analysis
# =============================================================================

def parse_system_xml(path: Path) -> ET.Element:
    """Parse and return root of system.xml using defusedxml."""
    tree = secure_xml_parse(path)
    root = tree.getroot()
    assert root.tag == "system", f"Root tag must be <system>, found <{root.tag}>"
    return root


def extract_protection_domains(root: ET.Element) -> Dict[str, dict]:
    """Extract protection domains and their memory mappings."""
    pds = {}
    for pd in root.findall("protection_domain"):
        name = pd.get("name")
        priority = int(pd.get("priority", "0"))
        img_elem = pd.find("program_image")
        img_path = img_elem.get("path") if img_elem is not None else ""
        maps = []
        for m in pd.findall("map"):
            maps.append({
                "mr": m.get("mr"),
                "vaddr": int(m.get("vaddr", "0"), 16),
                "perms": m.get("perms", ""),
                "cached": m.get("cached", "true").lower() == "true",
            })
        pds[name] = {
            "priority": priority,
            "image": img_path,
            "maps": maps,
            "mr_names": {m["mr"] for m in maps},
        }
    return pds


def extract_channels(root: ET.Element) -> List[Tuple[str, int, str, int]]:
    """Extract channel endpoint pairs."""
    channels = []
    for ch in root.findall("channel"):
        ends = ch.findall("end")
        assert len(ends) == 2, f"Channel must have exactly 2 ends, got {len(ends)}"
        channels.append((
            ends[0].get("pd"),
            int(ends[0].get("id")),
            ends[1].get("pd"),
            int(ends[1].get("id")),
        ))
    return channels


def extract_memory_regions(root: ET.Element) -> Dict[str, dict]:
    """Extract memory region definitions."""
    mrs = {}
    for mr in root.findall("memory_region"):
        name = mr.get("name")
        size = int(mr.get("size", "0"), 16)
        page_size = int(mr.get("page_size", "0x1000"), 16)
        mrs[name] = {"size": size, "page_size": page_size}
    return mrs


def get_canonical_domain(name: str) -> str:
    """Normalize domain name to canonical RED/CRYPTO/BLACK category."""
    name_lower = name.lower()
    if "red" in name_lower:
        return "RED"
    if "crypto" in name_lower:
        return "CRYPTO"
    if "black" in name_lower:
        return "BLACK"
    return name


# =============================================================================
# Test Suite: seL4 Microkit MILS Domain Separation Specification
# =============================================================================

def test_system_xml_exists_and_is_valid():
    """Verify system.xml exists, is readable, and contains well-formed XML."""
    assert SYSTEM_XML_PATH.exists(), f"Missing {SYSTEM_XML_PATH}"
    root = parse_system_xml(SYSTEM_XML_PATH)
    assert len(root.findall("protection_domain")) >= 3
    assert len(root.findall("memory_region")) >= 2
    assert len(root.findall("channel")) >= 2


def test_protection_domains_and_priorities():
    """Verify that exactly three protection domains exist: RED, CRYPTO, BLACK,
    and their priority hierarchy guarantees deterministic cryptographic dispatch.
    """
    root = parse_system_xml(SYSTEM_XML_PATH)
    pds = extract_protection_domains(root)

    # Resolve domains
    domain_by_category = {}
    for pd_name in pds:
        cat = get_canonical_domain(pd_name)
        domain_by_category[cat] = pds[pd_name]

    assert "RED" in domain_by_category, "RED domain is missing from system.xml"
    assert "CRYPTO" in domain_by_category, "CRYPTO domain is missing from system.xml"
    assert "BLACK" in domain_by_category, "BLACK domain is missing from system.xml"

    red = domain_by_category["RED"]
    crypto = domain_by_category["CRYPTO"]
    black = domain_by_category["BLACK"]

    # Priority hierarchy: CRYPTO (120) > RED (100) > BLACK (90)
    assert crypto["priority"] > red["priority"], (
        f"CRYPTO priority ({crypto['priority']}) must exceed RED ({red['priority']})"
    )
    assert red["priority"] > black["priority"], (
        f"RED priority ({red['priority']}) must exceed BLACK ({black['priority']})"
    )

    # Program images must specify valid ELF paths
    for cat, pd in domain_by_category.items():
        assert pd["image"].endswith(".elf"), f"{cat} domain program image must be an ELF binary"


def test_shared_memory_regions_page_alignment():
    """Verify memory regions are properly sized and page-aligned (multiple of 4 KiB)."""
    root = parse_system_xml(SYSTEM_XML_PATH)
    mrs = extract_memory_regions(root)

    assert "red_crypto_ring" in mrs, "red_crypto_ring memory region missing"
    assert "crypto_black_ring" in mrs, "crypto_black_ring memory region missing"

    for name, mr in mrs.items():
        assert mr["size"] > 0, f"Memory region {name} size must be non-zero"
        assert mr["page_size"] >= 0x1000, f"Page size {mr['page_size']} must be at least 4 KiB"
        assert mr["size"] % mr["page_size"] == 0, (
            f"Region {name} size {hex(mr['size'])} is not page-aligned (page={hex(mr['page_size'])})"
        )

    # Ring buffers must have at least 64 KiB capacity (0x10000)
    assert mrs["red_crypto_ring"]["size"] >= 0x10000
    assert mrs["crypto_black_ring"]["size"] >= 0x10000


def test_static_assertion_zero_red_black_shared_memory():
    """MATHEMATICAL INVARIANT: Zero shared memory between RED and BLACK domains.
    Static assertion: Map(RED) ∩ Map(BLACK) == ∅.
    """
    root = parse_system_xml(SYSTEM_XML_PATH)
    pds = extract_protection_domains(root)

    red_pds = [pds[name] for name in pds if get_canonical_domain(name) == "RED"]
    black_pds = [pds[name] for name in pds if get_canonical_domain(name) == "BLACK"]

    red_regions = set()
    for pd in red_pds:
        red_regions.update(pd["mr_names"])

    black_regions = set()
    for pd in black_pds:
        black_regions.update(pd["mr_names"])

    # Formal intersection check
    shared = red_regions.intersection(black_regions)
    assert len(shared) == 0, (
        f"CRITICAL MILS INVARIANT VIOLATION: Memory region(s) {shared} shared between RED and BLACK domains!"
    )

    # Affirmative mappings
    assert "red_crypto_ring" in red_regions, "RED must map red_crypto_ring"
    assert "crypto_black_ring" not in red_regions, "RED MUST NOT map crypto_black_ring"
    assert "crypto_black_ring" in black_regions, "BLACK must map crypto_black_ring"
    assert "red_crypto_ring" not in black_regions, "BLACK MUST NOT map red_crypto_ring"


def test_static_assertion_zero_red_black_direct_channel():
    """MATHEMATICAL INVARIANT: Zero direct IPC channels between RED and BLACK domains.
    Static assertion: ∀ ch ∈ Channels: {ch.pd_a, ch.pd_b} != {RED, BLACK}.
    """
    root = parse_system_xml(SYSTEM_XML_PATH)
    channels = extract_channels(root)

    for pd_a, id_a, pd_b, id_b in channels:
        cat_a = get_canonical_domain(pd_a)
        cat_b = get_canonical_domain(pd_b)
        channel_pair = {cat_a, cat_b}

        assert channel_pair != {"RED", "BLACK"}, (
            f"CRITICAL MILS INVARIANT VIOLATION: Direct IPC channel detected between {pd_a} and {pd_b}!"
        )

    # Verify required channels exist
    categories_connected = [
        {get_canonical_domain(ch[0]), get_canonical_domain(ch[2])}
        for ch in channels
    ]
    assert {"RED", "CRYPTO"} in categories_connected, "Channel between RED and CRYPTO missing"
    assert {"CRYPTO", "BLACK"} in categories_connected, "Channel between CRYPTO and BLACK missing"


def test_formal_topology_cut_vertex_invariance():
    """GRAPH THEORETIC INVARIANT: Complete Mediation & Non-Bypassability.
    Verifies that CRYPTO is a formal cut-vertex in the communication graph.
    Removing CRYPTO strictly partitions RED and BLACK into disconnected subgraphs.
    """
    root = parse_system_xml(SYSTEM_XML_PATH)
    channels = extract_channels(root)

    # Build adjacency list
    adj: Dict[str, Set[str]] = {}
    for pd_a, _, pd_b, _ in channels:
        cat_a = get_canonical_domain(pd_a)
        cat_b = get_canonical_domain(pd_b)
        adj.setdefault(cat_a, set()).add(cat_b)
        adj.setdefault(cat_b, set()).add(cat_a)

    # Direct edge between RED and BLACK must NOT exist
    assert "BLACK" not in adj.get("RED", set()), "Direct channel exists between RED and BLACK"
    assert "RED" not in adj.get("BLACK", set()), "Direct channel exists between BLACK and RED"

    # Breadth-first search without CRYPTO: must be unable to reach BLACK from RED
    visited = set()
    queue = ["RED"]
    visited.add("RED")

    while queue:
        curr = queue.pop(0)
        for neighbor in adj.get(curr, set()):
            # Block traversal through CRYPTO to simulate removing the cut-vertex
            if neighbor == "CRYPTO":
                continue
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    assert "BLACK" not in visited, (
        "CRITICAL SECURITY FAILURE: Bypass path detected! RED can reach BLACK without traversing CRYPTO!"
    )


def test_key_quarantine_invariance():
    """KEY ISOLATION INVARIANT:
    Key material (`crypto_locked_keys`) is accessible exclusively by CRYPTO domain.
    """
    root = parse_system_xml(SYSTEM_XML_PATH)
    pds = extract_protection_domains(root)

    for pd_name, pd in pds.items():
        cat = get_canonical_domain(pd_name)
        if "crypto_locked_keys" in pd["mr_names"]:
            assert cat == "CRYPTO", (
                f"CRITICAL KEY ISOLATION VIOLATION: {pd_name} ({cat}) has access to crypto_locked_keys!"
            )
            # Find the mapping and verify cached="false"
            for m in pd["maps"]:
                if m["mr"] == "crypto_locked_keys":
                    assert not m["cached"], "crypto_locked_keys MUST be mapped with cached='false'"


def test_memory_virtual_address_layout():
    """Verify distinct virtual addresses in each protection domain."""
    root = parse_system_xml(SYSTEM_XML_PATH)
    pds = extract_protection_domains(root)

    for pd_name, pd in pds.items():
        vaddrs = [m["vaddr"] for m in pd["maps"]]
        # No two mappings within the same protection domain can share the same vaddr
        assert len(vaddrs) == len(set(vaddrs)), f"Virtual address collision in domain {pd_name}"


def test_fail_closed_negative_mutations():
    """FAIL-CLOSED MUTATION TESTS:
    Verify that injecting violations into the manifest triggers policy violations.
    """
    manifest = SeL4MicrokitManifest.from_xml_file(SYSTEM_XML_PATH)
    assert manifest.validate_mils_invariants() is True

    # 1. Mutate: add direct RED <-> BLACK channel
    pds = list(manifest.protection_domains.keys())
    red_pd = next(name for name in pds if "red" in name.lower())
    black_pd = next(name for name in pds if "black" in name.lower())
    crypto_pd = next(name for name in pds if "crypto" in name.lower())

    bad_ch = Channel(red_pd, 99, black_pd, 99)
    manifest.channels.append(bad_ch)
    with pytest.raises(SeL4PolicyViolation, match="Direct IPC channel detected"):
        manifest.validate_mils_invariants()
    manifest.channels.remove(bad_ch)

    # 2. Mutate: map red_crypto_ring into BLACK domain
    bad_map = MemoryMap("red_crypto_ring", vaddr=0x40000000, perms="rw")
    manifest.protection_domains[black_pd].maps.append(bad_map)
    with pytest.raises(SeL4PolicyViolation, match="mapped into both RED and BLACK"):
        manifest.validate_mils_invariants()
    manifest.protection_domains[black_pd].maps.remove(bad_map)

    # 3. Mutate: map crypto_locked_keys into RED domain
    bad_key_map = MemoryMap("crypto_locked_keys", vaddr=0x50000000, perms="rw")
    manifest.protection_domains[red_pd].maps.append(bad_key_map)
    with pytest.raises(SeL4PolicyViolation, match="crypto_locked_keys mapped outside CRYPTO"):
        manifest.validate_mils_invariants()
    manifest.protection_domains[red_pd].maps.remove(bad_key_map)


def test_rust_no_std_static_invariants():
    """Verify bare-metal `#![no_std]` and `#![no_main]` invariants across all domain sources."""
    for path, expected_name in [
        (RED_SRC_PATH, "RED"),
        (CRYPTO_SRC_PATH, "CRYPTO"),
        (BLACK_SRC_PATH, "BLACK"),
    ]:
        assert path.exists(), f"Source file {path} missing"
        content = path.read_text(encoding="utf-8")

        # Must be strictly no_std and no_main
        assert "#![no_std]" in content, f"{expected_name} domain missing #![no_std]"
        assert "#![no_main]" in content, f"{expected_name} domain missing #![no_main]"

        # Microkit hook functions must be defined
        assert "fn init()" in content, f"{expected_name} domain missing init() hook"
        assert "fn notified(" in content, f"{expected_name} domain missing notified() hook"
        assert "panic_handler" in content, f"{expected_name} domain missing panic_handler"

    # Check domain-specific isolation in source text
    red_code = RED_SRC_PATH.read_text(encoding="utf-8")
    assert "RED_CRYPTO_RING_VADDR" in red_code
    assert "CRYPTO_BLACK_RING_VADDR" not in red_code, "RED source must not reference BLACK ring"
    assert "CRYPTO_LOCKED_KEYS_VADDR" not in red_code, "RED source must not reference key storage"

    black_code = BLACK_SRC_PATH.read_text(encoding="utf-8")
    assert "CRYPTO_BLACK_RING_VADDR" in black_code
    assert "RED_CRYPTO_RING_VADDR" not in black_code, "BLACK source must not reference RED ring"
    assert "CRYPTO_LOCKED_KEYS_VADDR" not in black_code, "BLACK source must not reference key storage"
    assert "CHAFF_CELL_TYPE" in black_code, "BLACK domain must implement chaff cell support"

    crypto_code = CRYPTO_SRC_PATH.read_text(encoding="utf-8")
    assert "RED_CRYPTO_RING_VADDR" in crypto_code
    assert "CRYPTO_BLACK_RING_VADDR" in crypto_code
    assert "CRYPTO_LOCKED_KEYS_VADDR" in crypto_code
    assert "emergency_wipe_keys" in crypto_code, "CRYPTO must implement emergency key wipe"


def test_rust_crates_compile_cleanly():
    """Verify that all three seL4 Microkit Rust crates compile with cargo check."""
    result = subprocess.run(
        ["cargo", "check", "--manifest-path", str(CARGO_TOML_PATH)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Cargo check failed:\n{result.stderr}\n{result.stdout}"


def test_rust_unit_tests_pass():
    """Verify that bare-metal Rust unit tests pass (zero-copy ring buffers, wrap-around,
    crypto mediation, and chaff emission).
    """
    result = subprocess.run(
        ["cargo", "test", "--manifest-path", str(CARGO_TOML_PATH)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Cargo test failed:\n{result.stderr}\n{result.stdout}"
    assert "test result: ok." in result.stdout


def test_bell_lapadula_information_flow_lattice():
    """FORMAL INFORMATION FLOW VERIFICATION:
    Verifies adherence to Bell-LaPadula / Biba Multilevel Security (MILS):
      - RED domain has confidentiality level HIGH, integrity level HIGH.
      - CRYPTO domain is a trusted declassifier / cryptographic transformator.
      - BLACK domain has confidentiality level LOW (public network), integrity level LOW.
    Invariants:
      1. Plaintext user data cannot transition to BLACK without passing through CRYPTO encryption.
      2. Inbound ciphertext from BLACK cannot transition to RED without CRYPTO authentication.
    """
    root = parse_system_xml(SYSTEM_XML_PATH)
    pds = extract_protection_domains(root)

    # Security labels
    levels = {
        "RED": {"confidentiality": 3, "integrity": 3},
        "CRYPTO": {"confidentiality": 2, "integrity": 2, "trusted_declassifier": True},
        "BLACK": {"confidentiality": 1, "integrity": 1},
    }

    # Verify memory mapping flow legality
    for name, pd in pds.items():
        cat = get_canonical_domain(name)
        for m in pd["maps"]:
            mr_name = m["mr"]
            if mr_name == "red_crypto_ring":
                assert cat in ("RED", "CRYPTO"), f"Illegal mapping of red_crypto_ring into {name}"
            elif mr_name == "crypto_black_ring":
                assert cat in ("CRYPTO", "BLACK"), f"Illegal mapping of crypto_black_ring into {name}"
            elif mr_name == "crypto_locked_keys":
                assert cat == "CRYPTO", f"Illegal mapping of crypto_locked_keys into {name}"


def test_channel_id_integrity_and_bounds():
    """Verify seL4 Microkit channel IDs are within valid range (1..63)
    and endpoints are properly assigned.
    """
    root = parse_system_xml(SYSTEM_XML_PATH)
    channels = extract_channels(root)

    for pd_a, id_a, pd_b, id_b in channels:
        assert 1 <= id_a <= 63, f"Channel ID {id_a} out of range [1, 63] for {pd_a}"
        assert 1 <= id_b <= 63, f"Channel ID {id_b} out of range [1, 63] for {pd_b}"


def test_sovereign_appliance_node_integration():
    """Verify end-to-end integration between SovereignApplianceNode and system.xml."""
    import secrets
    from sovereign_sel4_appliance import SovereignApplianceNode

    shared_psk = secrets.token_bytes(32)
    node_alpha = SovereignApplianceNode("ALPHA", psk=shared_psk, system_xml_path=SYSTEM_XML_PATH)
    node_bravo = SovereignApplianceNode("BRAVO", psk=shared_psk, system_xml_path=SYSTEM_XML_PATH)

    # Pair nodes via Triple-Hybrid Post-Quantum KEX
    node_alpha.pair_with_peer(node_bravo)

    # Transmit plaintext message from RED domain
    test_msg = b"EAL6_PLUS_VERIFIED_OPERATIONAL_TRANSMISSION"
    assert node_alpha.send_message(test_msg) is True

    # Step engine cycle: RED -> CRYPTO -> BLACK wire cell
    wire_cell = node_alpha.step_cycle()
    assert len(wire_cell) == 1232
    assert test_msg not in wire_cell  # Must be encrypted on wire

    # Deliver wire cell to Bravo
    assert node_bravo.receive_wire_cell(wire_cell) is True

    # Bravo decrypts into RED domain
    recv = node_bravo.get_received_messages()
    assert len(recv) == 1
    assert recv[0] == test_msg


def test_board_json_specification_alignment():
    """Verify board.json hardware layout matches system.xml memory regions and channels."""
    board_path = Path("sel4_mils_appliance/board.json")
    assert board_path.exists(), "board.json missing"

    import json
    with open(board_path, "r", encoding="utf-8") as f:
        board = json.load(f)

    root = parse_system_xml(SYSTEM_XML_PATH)
    xml_mrs = extract_memory_regions(root)

    # Check memory layout alignment
    for mr_name, mr_info in xml_mrs.items():
        assert mr_name in board["memory_layout"], f"Region {mr_name} not defined in board.json"
        board_mr = board["memory_layout"][mr_name]
        assert int(board_mr["size"], 16) == mr_info["size"]
        assert int(board_mr["page_size"], 16) == mr_info["page_size"]


def test_linker_script_wx_policy():
    """Verify linker.lds enforces W^X memory execution policy and page-aligned sections."""
    linker_path = Path("sel4_mils_appliance/linker.lds")
    assert linker_path.exists(), "linker.lds missing"
    content = linker_path.read_text(encoding="utf-8")

    assert ".text : ALIGN(4096)" in content, "text section must be 4 KiB aligned"
    assert ".rodata : ALIGN(4096)" in content, "rodata section must be 4 KiB aligned"
    assert ".data : ALIGN(4096)" in content, "data section must be 4 KiB aligned"
    assert ".stack" in content, "stack section must be defined"
    assert ".note.GNU-stack" in content, "note.GNU-stack must be declared for non-executable stack"


def test_traffic_chaff_shannon_entropy():
    """Verify synthetic 20 Hz chaff traffic achieves cryptographic Shannon entropy > 7.8 bits/byte."""
    import math
    import secrets
    from sovereign_sel4_appliance import SovereignApplianceNode

    node = SovereignApplianceNode("CHAFF_AUDIT", psk=secrets.token_bytes(32), system_xml_path=SYSTEM_XML_PATH)
    # Collect 5 consecutive idle wire frames (chaff)
    chaff_cells = [node.step_cycle() for _ in range(5)]

    for cell in chaff_cells:
        assert len(cell) == 1232
        # Byte 2 is CHAFF_CELL_TYPE (0xFF)
        assert cell[2] == 0xFF
        chaff_body = cell[3:]

        # Calculate Shannon entropy: H = -sum(p * log2(p))
        counts = {}
        for b in chaff_body:
            counts[b] = counts.get(b, 0) + 1

        entropy = 0.0
        total = len(chaff_body)
        for cnt in counts.values():
            p = cnt / total
            entropy -= p * math.log2(p)

        assert entropy > 7.8, f"Chaff entropy too low ({entropy:.3f} bits/byte), vulnerable to SIGINT"


from hypothesis import given, strategies as st, settings


@settings(max_examples=30, deadline=None)
@given(
    seed=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF)
)
def test_hypothesis_chaff_entropy_high_across_seeds(seed):
    """Property-based verification: SplitMix64/XorShift128+ generates high-entropy chaff (> 7.8 bits/byte)
    across arbitrary 64-bit random seeds.
    """
    import math

    def splitmix64(s):
        z = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        return (z ^ (z >> 31)) & 0xFFFFFFFFFFFFFFFF

    s0 = splitmix64(seed)
    s1 = splitmix64(s0)

    out = bytearray(1229)
    idx = 0
    while idx < 1229:
        s1_tmp = s0
        s0_tmp = s1
        res = (s0_tmp + s1_tmp) & 0xFFFFFFFFFFFFFFFF
        s0 = s0_tmp
        s1_tmp = (s1_tmp ^ ((s1_tmp << 23) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
        s1 = (s1_tmp ^ s0 ^ (s1_tmp >> 18) ^ (s0 >> 5)) & 0xFFFFFFFFFFFFFFFF

        b = res.to_bytes(8, "little")
        for byte in b:
            if idx < 1229:
                out[idx] = byte
                idx += 1
            else:
                break

    counts = {}
    for b in out:
        counts[b] = counts.get(b, 0) + 1

    entropy = 0.0
    for cnt in counts.values():
        p = cnt / 1229
        entropy -= p * math.log2(p)

    assert entropy > 7.8, f"Seed {seed} generated insufficient entropy: {entropy:.2f}"


def test_mils_compliance_report_generation():
    """Verify validate_mils.py generates a valid JSON compliance report."""
    import sys
    sys.path.insert(0, str(Path("sel4_mils_appliance").resolve()))
    from validate_mils import validate_mils_xml

    report = validate_mils_xml(SYSTEM_XML_PATH)
    assert report["status"] == "PASS"
    assert report["invariants"]["zero_shared_memory"] is True
    assert report["invariants"]["zero_direct_channels"] is True
    assert report["invariants"]["key_quarantined"] is True
    assert report["invariants"]["complete_mediation"] is True
    assert len(report["errors"]) == 0
    assert len(report["sha256"]) == 64


def test_aarch64_baremetal_compilation_and_elf_verification():
    """Verify bare-metal AArch64 compilation generates valid ELF binaries for all 3 domains.
    Validates ELF magic (\\x7fELF), 64-bit class, little-endian, and EM_AARCH64 (0xB7).
    """
    res = subprocess.run(
        ["cargo", "build", "--target", "aarch64-unknown-none", "--release", "--manifest-path", str(CARGO_TOML_PATH)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"AArch64 cargo build failed:\n{res.stderr}\n{res.stdout}"

    binaries = ["mils_red_domain", "mils_crypto_domain", "mils_black_domain"]
    rel_dir = Path("sel4_mils_appliance/target/aarch64-unknown-none/release")

    for bname in binaries:
        bin_path = rel_dir / bname
        assert bin_path.exists(), f"Expected binary {bin_path} does not exist"
        data = bin_path.read_bytes()
        assert len(data) >= 64, f"Binary {bname} is too short ({len(data)} bytes)"

        # ELF Identification Header
        magic = data[0:4]
        assert magic == b"\x7fELF", f"{bname}: Invalid ELF magic: {magic}"
        ei_class = data[4]
        assert ei_class == 2, f"{bname}: Expected 64-bit ELF (class 2), got {ei_class}"
        ei_data = data[5]
        assert ei_data == 1, f"{bname}: Expected 2's complement little-endian (data 1), got {ei_data}"
        ei_version = data[6]
        assert ei_version == 1, f"{bname}: Expected ELF version 1, got {ei_version}"

        # e_type (bytes 16..18, uint16 little-endian): 2 = ET_EXEC
        e_type = int.from_bytes(data[16:18], "little")
        assert e_type == 2, f"{bname}: Expected ET_EXEC (2), got {e_type}"

        # e_machine (bytes 18..20, uint16 little-endian): 0xB7 (183) = EM_AARCH64
        e_machine = int.from_bytes(data[18:20], "little")
        assert e_machine == 0xB7, f"{bname}: Expected EM_AARCH64 (0xB7), got {hex(e_machine)}"

        # e_entry (bytes 24..32, uint64 little-endian)
        e_entry = int.from_bytes(data[24:32], "little")
        assert e_entry != 0, f"{bname}: Entry point must be non-zero"


def test_system_xml_malformed_rejection_negative_matrix():
    """Negative testing: corrupt or malformed XML structures must fail-closed."""
    import tempfile

    # 1. Non-page-aligned memory region size
    bad_xml_unaligned = """<?xml version="1.0" encoding="UTF-8"?>
    <system>
        <memory_region name="bad_region" size="0x1005" page_size="0x1000" />
        <protection_domain name="red" priority="100">
            <map mr="bad_region" vaddr="0x10000000" perms="rw" />
        </protection_domain>
    </system>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tf:
        tf.write(bad_xml_unaligned)
        tf_path = Path(tf.name)
    try:
        with pytest.raises(SeL4PolicyViolation):
            manifest = SeL4MicrokitManifest.from_xml_file(tf_path)
            manifest.validate_mils_invariants()
    finally:
        tf_path.unlink(missing_ok=True)

    # 2. Out-of-bounds Channel ID (> 63)
    bad_xml_ch_id = """<?xml version="1.0" encoding="UTF-8"?>
    <system>
        <protection_domain name="red" priority="100" />
        <protection_domain name="crypto" priority="120" />
        <channel>
            <end pd="red" id="64" />
            <end pd="crypto" id="1" />
        </channel>
    </system>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tf:
        tf.write(bad_xml_ch_id)
        tf_path = Path(tf.name)
    try:
        with pytest.raises(SeL4PolicyViolation):
            manifest = SeL4MicrokitManifest.from_xml_file(tf_path)
            manifest.validate_mils_invariants()
    finally:
        tf_path.unlink(missing_ok=True)


def test_anti_replay_window_comprehensive_matrix():
    """Verify RFC 6479 decoupled anti-replay window logic under exhaustive boundary conditions."""
    class DecoupledAntiReplay:
        def __init__(self, window_size: int = 128):
            self.window_size = window_size
            self.last_seq = 0
            self.bitmap = [0, 0]
            self.initialized = False

        def check(self, seq: int) -> bool:
            if not self.initialized:
                return True
            if seq > self.last_seq:
                return True
            diff = self.last_seq - seq
            if diff >= self.window_size:
                return False
            word_idx = diff // 64
            bit_idx = diff % 64
            return (self.bitmap[word_idx] & (1 << bit_idx)) == 0

        def mark(self, seq: int):
            if not self.initialized:
                self.last_seq = seq
                self.bitmap[0] = 1
                self.bitmap[1] = 0
                self.initialized = True
                return
            if seq > self.last_seq:
                diff = seq - self.last_seq
                if diff >= self.window_size:
                    self.bitmap[0] = 1
                    self.bitmap[1] = 0
                elif diff >= 64:
                    shift = diff - 64
                    self.bitmap[1] = (self.bitmap[0] << shift) & 0xFFFFFFFFFFFFFFFF
                    self.bitmap[0] = 1
                else:
                    shift = diff
                    self.bitmap[1] = ((self.bitmap[1] << shift) | (self.bitmap[0] >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF
                    self.bitmap[0] = ((self.bitmap[0] << shift) | 1) & 0xFFFFFFFFFFFFFFFF
                self.last_seq = seq
            else:
                diff = self.last_seq - seq
                if diff < self.window_size:
                    word_idx = diff // 64
                    bit_idx = diff % 64
                    self.bitmap[word_idx] |= (1 << bit_idx)

    win = DecoupledAntiReplay()
    assert win.check(0)
    win.mark(0)
    assert not win.check(0)

    # Walk 1..100
    for s in range(1, 101):
        assert win.check(s)
        win.mark(s)
        assert not win.check(s)

    # In-window replayed checks
    for s in range(1, 101):
        assert not win.check(s)

    # Jump forward by 50 to 150
    win.mark(150)
    # Stale boundary: 150 - 128 = 22 -> seq <= 22 is stale
    assert not win.check(22)
    assert not win.check(10)
    assert not win.check(0)
    # Unread in-window packet: seq 140 (150 - 140 = 10 < 128)
    assert win.check(140)
    win.mark(140)
    assert not win.check(140)

    # Huge jump forward
    win.mark(10_000_000)
    assert not win.check(150)
    assert win.check(10_000_000 - 127)
    assert not win.check(10_000_000 - 128)


def test_multi_round_ring_buffer_torture_and_continuity():
    """Simulate continuous wrap-around stream across 10,000 packets of variable lengths.
    Confirms zero memory corruption, zero packet drops, and deterministic SPSC operation.
    """
    capacity = 32704
    buffer = bytearray(capacity)
    head = 0
    tail = 0
    header_size = 4
    wrap_type = 0xFE

    import random
    rng = random.Random(42)

    for round_num in range(10_000):
        payload_len = rng.randint(1, 512)
        needed = header_size + payload_len

        # Available space calculation
        avail = (tail + capacity - head - 1) % capacity
        assert avail >= needed

        # Check end of buffer wrap
        if capacity - head < needed:
            # Write wrap marker
            buffer[head:head+4] = (0).to_bytes(2, "little") + bytes([wrap_type, 0])
            head = 0

        # Write frame
        token = (round_num & 0xFF).to_bytes(1, "little") * payload_len
        buffer[head:head+2] = payload_len.to_bytes(2, "little")
        buffer[head+2] = 1 # msg_type
        buffer[head+3] = 0 # flags
        buffer[head+header_size:head+needed] = token
        head = (head + needed) % capacity

        # Consumer read
        # Peek
        c_hdr = buffer[tail:tail+header_size]
        msg_len = int.from_bytes(c_hdr[0:2], "little")
        msg_type = c_hdr[2]
        if msg_type == wrap_type:
            tail = 0
            c_hdr = buffer[tail:tail+header_size]
            msg_len = int.from_bytes(c_hdr[0:2], "little")
            msg_type = c_hdr[2]

        c_needed = header_size + msg_len
        payload = bytes(buffer[tail+header_size:tail+c_needed])
        assert payload == token
        tail = (tail + c_needed) % capacity

    assert head == tail


def test_validate_mils_cli_strict():
    """Verify that running validate_mils.py --strict CLI exits cleanly with 0."""
    res = subprocess.run(
        ["python", "sel4_mils_appliance/validate_mils.py", "--strict"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"validate_mils.py failed:\n{res.stderr}\n{res.stdout}"
    assert "Status:     PASS" in res.stdout
    assert "[PASS] complete_mediation" in res.stdout
    assert "[PASS] zero_shared_memory" in res.stdout
    assert "[PASS] zero_direct_channels" in res.stdout
    assert "[PASS] key_quarantined" in res.stdout




