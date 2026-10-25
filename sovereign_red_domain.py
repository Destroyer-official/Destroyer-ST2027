#!/usr/bin/env python3
"""
sovereign_red_domain.py — High-Assurance Reference Implementation of the
seL4 RED Protection Domain for Sovereign Transmit 2027 (ST2027).

Core Architectural Invariants:
  1. Complete Network Air-Gap: This module contains ZERO network socket imports,
     binds, or connection capabilities. Direct internet/LAN connectivity is
     architecturally impossible.
  2. Isolated Plaintext Handling: Operates strictly on plaintext message buffers,
     keypads, display sinks, or tactical audio interfaces.
  3. Controlled Crypto Gateway: Plaintext data leaves the domain ONLY through the
     seL4 shared-memory ring buffer (`red_crypto_ring`) connected to the
     CRYPTO domain.
"""

from __future__ import annotations

import logging
from typing import Optional, List, Tuple
from sovereign_crypto_domain import SeL4SharedRingBuffer, TamperZeroizedError

logger = logging.getLogger("sovereign_red_domain")

# Max plaintext payload size per ST2027 quantized cell (1232 bytes total wire - framing/AEAD overhead)
MAX_PLAINTEXT_PAYLOAD_BYTES = 1024


class RedDomainError(Exception):
    """Base error for RED protection domain operations."""


class SovereignRedDomain:
    """The seL4 RED Protection Domain:
    Handles operator UI, plaintext input queue, and decrypted output sink.
    Strictly isolated from network PHY.
    """

    def __init__(self, red_to_crypto_ring: SeL4SharedRingBuffer, crypto_to_red_ring: SeL4SharedRingBuffer):
        self.to_crypto = red_to_crypto_ring
        self.from_crypto = crypto_to_red_ring
        self._received_messages: List[bytes] = []
        self._zeroized = False

    def send_plaintext_message(self, message: bytes) -> bool:
        """Enqueue an operator message for transmission.
        Packages message and pushes into the red-to-crypto shared ring buffer.
        """
        if self._zeroized:
            raise RedDomainError("RED domain has been zeroized")
        if not message:
            return False
        if len(message) > MAX_PLAINTEXT_PAYLOAD_BYTES:
            raise RedDomainError(
                f"Message size {len(message)} exceeds maximum ST2027 payload limit {MAX_PLAINTEXT_PAYLOAD_BYTES}"
            )

        success = self.to_crypto.push(message)
        if not success:
            logger.warning("RED-to-CRYPTO shared ring buffer full; message dropped")
        return success

    def poll_received_messages(self) -> List[bytes]:
        """Poll decrypted messages delivered from the CRYPTO domain."""
        if self._zeroized:
            raise RedDomainError("RED domain has been zeroized")
        new_msgs: List[bytes] = []
        while True:
            msg = self.from_crypto.pop()
            if msg is None:
                break
            new_msgs.append(msg)
            self._received_messages.append(msg)
        return new_msgs

    def get_message_history(self) -> List[bytes]:
        """Retrieve copy of all messages received in this session."""
        return list(self._received_messages)

    def trigger_duress_zeroization(self, crypto_domain) -> None:
        """Operator duress signal: immediately scorches RED domain and triggers CRYPTO zeroize."""
        self._zeroized = True
        self._received_messages.clear()
        self.to_crypto.zeroize()
        self.from_crypto.zeroize()
        crypto_domain.emergency_zeroize()
        logger.critical("RED DOMAIN ZEROIZATION EXECUTED: All plaintext wiped.")
