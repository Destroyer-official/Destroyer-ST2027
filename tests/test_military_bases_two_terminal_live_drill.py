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
import tempfile
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _find_free_port_pair() -> int:
    """Find two consecutive free TCP ports for loopback testing."""
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
            s1.bind(("127.0.0.1", 0))
            p = s1.getsockname()[1]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                s2.bind(("127.0.0.1", p + 1))
            return p
        except OSError:
            continue
    raise RuntimeError("Could not find free consecutive port pair")


@pytest.mark.timeout(90)
def test_military_base_alpha_and_bravo_automated_drill():
    """Execute live automated drill between Base Alpha (NORAD) and Base Bravo (Pentagon)."""
    port = _find_free_port_pair()

    alpha_out_f = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
    alpha_err_f = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
    bravo_out_f = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
    bravo_err_f = tempfile.TemporaryFile(mode="w+", encoding="utf-8")

    try:
        # Launch Base Alpha (NORAD Server)
        alpha = subprocess.Popen(
            [sys.executable, "military_base_alpha.py", "--port", str(port), "--automated"],
            cwd=REPO_ROOT,
            stdout=alpha_out_f,
            stderr=alpha_err_f,
        )

        # Give Base Alpha server time to bind cert exchange port
        time.sleep(3.0)

        # Launch Base Bravo (Pentagon Client)
        bravo = subprocess.Popen(
            [sys.executable, "military_base_bravo.py", "--port", str(port), "--automated"],
            cwd=REPO_ROOT,
            stdout=bravo_out_f,
            stderr=bravo_err_f,
        )

        # Allow up to 75 seconds for full post-quantum cert generation and TLS 1.3 exchange
        t0 = time.time()
        while time.time() - t0 < 75:
            if alpha.poll() is not None and bravo.poll() is not None:
                break
            time.sleep(0.5)

        # Ensure termination if still running
        if alpha.poll() is None:
            alpha.kill()
        if bravo.poll() is None:
            bravo.kill()

        alpha_rc = alpha.poll()
        bravo_rc = bravo.poll()

        alpha_out_f.seek(0)
        alpha_err_f.seek(0)
        bravo_out_f.seek(0)
        bravo_err_f.seek(0)

        alpha_out = alpha_out_f.read()
        alpha_err = alpha_err_f.read()
        bravo_out = bravo_out_f.read()
        bravo_err = bravo_err_f.read()

        assert alpha_rc == 0, f"Base Alpha failed with code {alpha_rc}\nSTDOUT:\n{alpha_out}\nSTDERR:\n{alpha_err}"
        assert bravo_rc == 0, f"Base Bravo failed with code {bravo_rc}\nSTDOUT:\n{bravo_out}\nSTDERR:\n{bravo_err}"
    finally:
        alpha_out_f.close()
        alpha_err_f.close()
        bravo_out_f.close()
        bravo_err_f.close()


@pytest.mark.timeout(30)
def test_military_base_rejects_untrusted_rogue_certificate():
    """Verify Base Alpha mutual exchange listener strictly rejects rogue/unpinned connections."""
    port = _find_free_port_pair()

    # Launch Base Alpha (NORAD Server) in automated mode
    alpha = subprocess.Popen(
        [sys.executable, "military_base_alpha.py", "--port", str(port), "--automated"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        # Wait up to 12s for server to initialize and bind cert exchange port (port + 1)
        raw_sock = None
        for _ in range(24):
            try:
                raw_sock = socket.create_connection(("127.0.0.1", port + 1), timeout=1)
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.5)

        assert raw_sock is not None, f"Base Alpha did not bind port {port + 1} within 12s"

        # Attempt rogue payload connection to cert exchange port
        rejected = False
        try:
            with raw_sock:
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

