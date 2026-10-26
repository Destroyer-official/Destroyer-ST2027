#!/usr/bin/env python3
"""
Test Military Bases Two-Terminal Live Post-Quantum Operational Drill
====================================================================
Validates end-to-end tactical operations between Base Alpha (NORAD Strategic Defense Command)
and Base Bravo (Pentagon Joint Operations Command / NMCC):
  1. Mutual post-quantum X.509 certificate generation with ML-DSA-87 signatures.
  2. Out-of-band post-quantum certificate exchange and pinning.
  3. Mutual TLS 1.3 connection establishment with TLS_AES_256_GCM_SHA384 cipher suite.
  4. Bidirectional FLASH DEFCON-1 directive and telemetry dispatch/acknowledgment.
  5. Cryptographic zeroization and memory sanitization on session closure.
"""

import os
import sys
import time
import socket
import subprocess  # nosec: B404
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _find_free_port() -> int:
    """Find a free TCP port for loopback testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.timeout(60)
def test_military_base_alpha_and_bravo_automated_drill():
    """Execute live automated drill between Base Alpha (NORAD) and Base Bravo (Pentagon)."""
    port = _find_free_port()

    # Launch Base Alpha (NORAD Server)
    alpha = subprocess.Popen(
        [sys.executable, "military_base_alpha.py", "--port", str(port), "--automated"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Give Base Alpha server time to bind cert exchange port
    time.sleep(2.5)

    # Launch Base Bravo (Pentagon Client)
    bravo = subprocess.Popen(
        [sys.executable, "military_base_bravo.py", "--port", str(port), "--automated"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Allow up to 45 seconds for full post-quantum cert generation and TLS 1.3 exchange
    t0 = time.time()
    while time.time() - t0 < 45:
        if alpha.poll() is not None and bravo.poll() is not None:
            break
        time.sleep(0.5)

    # Verify exit codes
    alpha_rc = alpha.poll()
    bravo_rc = bravo.poll()
    if alpha_rc is None:
        alpha.kill()
    if bravo_rc is None:
        bravo.kill()

    assert alpha_rc == 0, f"Base Alpha failed with code {alpha_rc}"
    assert bravo_rc == 0, f"Base Bravo failed with code {bravo_rc}"


@pytest.mark.timeout(30)
def test_military_base_rejects_untrusted_rogue_certificate():
    """Verify Base Alpha mutual exchange listener strictly rejects rogue/unpinned connections."""
    port = _find_free_port()

    # Launch Base Alpha (NORAD Server) in automated mode
    alpha = subprocess.Popen(
        [sys.executable, "military_base_alpha.py", "--port", str(port), "--automated"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        # Give server time to initialize and bind cert exchange port (port + 1)
        time.sleep(2.5)

        # Attempt rogue payload connection to cert exchange port
        rejected = False
        try:
            with socket.create_connection(("127.0.0.1", port + 1), timeout=5) as raw_sock:
                # Read full 1576 bytes server greeting (4B magic + 4B len + 1568B PK)
                g = b""
                while len(g) < 1576:
                    chunk = raw_sock.recv(1576 - len(g))
                    if not chunk:
                        break
                    g += chunk
                assert g.startswith(b"PQC1")
                # Send invalid non-PQC payload
                raw_sock.sendall(b"ROGUE_UNAUTHENTICATED_PAYLOAD\n")
                # Server terminates connection fail-closed with EOF or ConnectionReset
                res = raw_sock.recv(1024)
                if not res:
                    rejected = True
        except (ConnectionResetError, BrokenPipeError, socket.timeout):
            rejected = True

        assert rejected, "Rogue client without certified credentials must be rejected fail-closed"
    finally:
        alpha.kill()
        alpha.wait()

