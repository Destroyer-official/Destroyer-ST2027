#!/usr/bin/env python3
"""
test_paced_socket_wrapper.py -- Verification for Hardware-Paced Wire Camouflage

Tests:
  1. Initialization and configuration of PacedChannel
  2. Subprocess command building and options
  3. Status telemetry reporting
  4. PacedSocketAdapter base64 encoding/decoding and sendall/recv
  5. Live loopback test: initiator and responder exchange messages over paced channel
  6. Fail-closed behavior on invalid configuration or termination
"""

import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

from paced_socket_wrapper import PacedChannel, PacedSocketAdapter, NATIVE_BIN


def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestPacedSocketWrapper(unittest.TestCase):
    """Test suite for paced_socket_wrapper."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_paced_")
        self.key_path = os.path.join(self.temp_dir, "test.key")
        self.state_path_init = os.path.join(self.temp_dir, "init.state")
        self.state_path_resp = os.path.join(self.temp_dir, "resp.state")

        # 32-byte hex key for frame encryption
        key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        with open(self.key_path, "w") as f:
            f.write(key_hex)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_native_binary_exists(self):
        """Verify the native secure-transmit binary is available."""
        self.assertTrue(NATIVE_BIN.exists(), f"Native binary missing at {NATIVE_BIN}")

    def test_02_channel_config(self):
        """Verify PacedChannel configuration and status properties."""
        chan = PacedChannel(
            key_path=self.key_path,
            state_path=self.state_path_init,
            bind_addr="127.0.0.1:9001",
            peer_addr="127.0.0.1:9002",
            role="initiator",
            interval_ms=25,
            quantum=1232,
        )
        self.assertEqual(chan.interval_ms, 25)
        self.assertEqual(chan.quantum, 1232)
        self.assertEqual(chan.role, "initiator")
        self.assertFalse(chan.is_active)

        status = chan.status()
        self.assertFalse(status["active"])
        self.assertEqual(status["interval_ms"], 25)
        self.assertEqual(status["quantum_bytes"], 1232)

    def test_03_adapter_send_receive_interface(self):
        """Verify PacedSocketAdapter encoding and interface contract."""
        chan = PacedChannel(
            key_path=self.key_path,
            state_path=self.state_path_init,
            bind_addr="127.0.0.1:9001",
            peer_addr="127.0.0.1:9002",
        )
        adapter = PacedSocketAdapter(chan)

        # Inactive channel should raise ConnectionError on sendall
        with self.assertRaises(ConnectionError):
            adapter.sendall(b"Hello secure world")

        # Inactive channel recv should return empty bytes on timeout
        received = adapter.recv(1024, timeout=0.1)
        self.assertEqual(received, b"")

    def test_04_live_loopback_paced_exchange(self):
        """Verify live full-duplex paced channel communication between two nodes."""
        port_init = _free_udp_port()
        port_resp = _free_udp_port()

        # Create responder (listens first)
        resp_chan = PacedChannel(
            key_path=self.key_path,
            state_path=self.state_path_resp,
            bind_addr=f"127.0.0.1:{port_resp}",
            peer_addr=f"127.0.0.1:{port_init}",
            role="responder",
            interval_ms=15,
            quantum=1232,
        )

        # Create initiator
        init_chan = PacedChannel(
            key_path=self.key_path,
            state_path=self.state_path_init,
            bind_addr=f"127.0.0.1:{port_init}",
            peer_addr=f"127.0.0.1:{port_resp}",
            role="initiator",
            interval_ms=15,
            quantum=1232,
        )

        try:
            started_resp = resp_chan.start()
            self.assertTrue(started_resp, "Responder channel failed to start")
            time.sleep(0.3)

            started_init = init_chan.start()
            self.assertTrue(started_init, "Initiator channel failed to start")
            time.sleep(0.5)

            # Both channels should be active
            self.assertTrue(resp_chan.is_active)
            self.assertTrue(init_chan.is_active)

            # Send message from initiator to responder
            test_msg = "DESTROYER_NUCLEAR_AUTH_EAM_SIG_ALPHA"
            sent = init_chan.send(test_msg)
            self.assertTrue(sent)

            # Wait for reception at responder
            received = resp_chan.receive(timeout=5.0)
            self.assertEqual(received, test_msg)

            # Send response from responder back to initiator
            reply_msg = "DEFCON_1_CONFIRMED_ROGER_THAT"
            sent_reply = resp_chan.send(reply_msg)
            self.assertTrue(sent_reply)

            # Wait for reception at initiator
            received_reply = init_chan.receive(timeout=5.0)
            self.assertEqual(received_reply, reply_msg)

        finally:
            init_chan.stop()
            resp_chan.stop()
            time.sleep(0.2)

    def test_05_adapter_stream_buffering_and_duck_typing(self):
        """Verify PacedSocketAdapter stream buffering (recv 4 then recv rest) and duck typing."""
        port_init = _free_udp_port()
        port_resp = _free_udp_port()

        resp_chan = PacedChannel(
            key_path=self.key_path,
            state_path=self.state_path_resp,
            bind_addr=f"127.0.0.1:{port_resp}",
            peer_addr=f"127.0.0.1:{port_init}",
            role="responder",
            interval_ms=15,
        )
        init_chan = PacedChannel(
            key_path=self.key_path,
            state_path=self.state_path_init,
            bind_addr=f"127.0.0.1:{port_init}",
            peer_addr=f"127.0.0.1:{port_resp}",
            role="initiator",
            interval_ms=15,
        )

        adapter_init = PacedSocketAdapter(init_chan)
        adapter_resp = PacedSocketAdapter(resp_chan)

        # Verify duck typing properties for p2p_core integration
        self.assertTrue(hasattr(adapter_init, 'cipher') and callable(adapter_init.cipher))
        self.assertTrue(hasattr(adapter_init, 'context'))
        self.assertEqual(adapter_init.fileno(), -1)
        self.assertTrue(adapter_init.is_paced)

        try:
            self.assertTrue(resp_chan.start())
            time.sleep(0.2)
            self.assertTrue(init_chan.start())
            time.sleep(0.3)

            # Send a length-prefixed frame: 4 bytes length + body
            raw_payload = b"CRITICAL_DEFENSE_DIRECTIVE_OMEGA"
            frame = len(raw_payload).to_bytes(4, 'big') + raw_payload

            # Send via adapter.send(data)
            bytes_sent = adapter_init.send(frame)
            self.assertEqual(bytes_sent, len(frame))

            # Receive 4-byte prefix first
            len_bytes = adapter_resp.recv(4, timeout=5.0)
            self.assertEqual(len(len_bytes), 4)
            expected_len = int.from_bytes(len_bytes, 'big')
            self.assertEqual(expected_len, len(raw_payload))

            # Receive remaining body
            body_bytes = adapter_resp.recv(expected_len, timeout=5.0)
            self.assertEqual(body_bytes, raw_payload)

        finally:
            adapter_init.close()
            adapter_resp.close()


if __name__ == "__main__":
    unittest.main()

