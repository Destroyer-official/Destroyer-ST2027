#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
"""
sovereign_sel4_appliance.py — Unified seL4 Sovereign Hardware Appliance Runtime
for Sovereign Transmit 2027 (ST2027).

Orchestrates the three MILS seL4 Microkit Protection Domains:
  - RED Domain: Air-gapped plaintext operator console
  - CRYPTO Domain: Sovereign PQC Triple-Hybrid engine with dual-rail verification
  - BLACK Domain: Constant-rate 20 Hz paced wire transport with 0xFF chaff

Enforces fail-closed isolation invariants, measured boot chain verification,
and active anti-tamper zeroization.
"""

from __future__ import annotations

import logging
import secrets
from typing import Optional, List, Dict, Any

from sel4_microkit_manifest import SeL4MicrokitManifest
from sovereign_crypto_domain import (
    SeL4SharedRingBuffer,
    SovereignCryptoDomain,
    CryptoDomainError,
    TamperZeroizedError,
)
from sovereign_red_domain import SovereignRedDomain
from sovereign_black_domain import SovereignBlackDomain, ST2027_CELL_SIZE

logger = logging.getLogger("sovereign_sel4_appliance")


class SovereignApplianceNode:
    """An integrated seL4 Sovereign Appliance Node executing MILS separation."""

    def __init__(self, node_id: str, psk: Optional[bytes] = None):
        self.node_id = node_id

        # 1. Formal Manifest & Invariant Check
        self.manifest = SeL4MicrokitManifest.create_st2027_sovereign_system()
        self.manifest.validate_mils_invariants()

        # 2. Inter-Domain Shared Memory Rings
        self.ring_red_to_crypto = SeL4SharedRingBuffer(f"{node_id}_red_to_crypto")
        self.ring_crypto_to_red = SeL4SharedRingBuffer(f"{node_id}_crypto_to_red")
        self.ring_crypto_to_black = SeL4SharedRingBuffer(f"{node_id}_crypto_to_black")
        self.ring_black_to_crypto = SeL4SharedRingBuffer(f"{node_id}_black_to_crypto")

        # 3. Instantiate the 3 Isolated Protection Domains
        self.red = SovereignRedDomain(
            red_to_crypto_ring=self.ring_red_to_crypto,
            crypto_to_red_ring=self.ring_crypto_to_red,
        )

        self.crypto = SovereignCryptoDomain(
            red_in=self.ring_red_to_crypto,
            red_out=self.ring_crypto_to_red,
            black_in=self.ring_black_to_crypto,
            black_out=self.ring_crypto_to_black,
            psk=psk,
        )

        self.black = SovereignBlackDomain(
            crypto_to_black_ring=self.ring_crypto_to_black,
            black_to_crypto_ring=self.ring_black_to_crypto,
            pacing_interval_sec=0.05,
        )

        self._zeroized = False
        logger.info("Initialized seL4 Sovereign Appliance Node [%s] with MILS separation.", node_id)

    def pair_with_peer(self, peer: "SovereignApplianceNode") -> None:
        """Execute Triple-Hybrid KEX session agreement with peer node."""
        self.crypto.establish_session_as_initiator(peer.crypto)

    def send_message(self, plaintext: bytes) -> bool:
        """Send message from the isolated RED operator console."""
        return self.red.send_plaintext_message(plaintext)

    def step_cycle(self) -> bytes:
        """Step one engine execution cycle:
        1. Encrypt outbound plaintext from RED -> BLACK.
        2. Decrypt inbound ciphertext from BLACK -> RED.
        3. Emit the next 1232-byte wire frame (real payload or chaff).
        """
        if self._zeroized:
            raise TamperZeroizedError("Appliance is zeroized")

        # Crypto processing
        self.crypto.process_red_to_black_step()
        self.crypto.process_black_to_red_step()

        # Emit wire cell (guaranteed exactly 1232 bytes)
        return self.black.emit_next_wire_cell()

    def receive_wire_cell(self, cell: bytes) -> bool:
        """Receive a 1232-byte wire cell from physical network and process."""
        if self._zeroized:
            raise TamperZeroizedError("Appliance is zeroized")
        accepted = self.black.ingest_wire_cell(cell)
        if accepted:
            self.crypto.process_black_to_red_step()
        return accepted

    def get_received_messages(self) -> List[bytes]:
        """Poll decrypted messages from the RED domain."""
        return self.red.poll_received_messages()

    def emergency_scorched_earth_zeroize(self) -> None:
        """Trigger scorched-earth zeroization across all domains."""
        self._zeroized = True
        self.red.trigger_duress_zeroization(self.crypto)
        self.black.emergency_zeroize()
        logger.critical("EMERGENCY ZEROIZATION EXECUTED ON NODE [%s]", self.node_id)
