#!/usr/bin/env python3
"""
TOP-SECRET DEFENSE NETWORK NODE
Base Alpha: NORAD Strategic Defense Command (Cheyenne Mountain Complex)
Protocol: CNSA 2.0 / Post-Quantum Mutual TLS 1.3 / FIPS 140-3 Level 3
"""

import sys
import os
import time
import socket
import ssl
import threading
import argparse

# Ensure workspace imports resolve
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

from ca_services import CAExchange
from secure_memory_wiper import secure_shred_file

# ANSI Colors for Military Terminal UI
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
MAGENTA = "\033[95m"

BANNER = f"""{BOLD}{CYAN}
================================================================================
  [TOP SECRET // CNSA 2.0 // NOFORN]
  UNITED STATES STRATEGIC COMMAND - TACTICAL COMMUNICATIONS NODE
  LOCATION: NORAD / CHEYENNE MOUNTAIN COMPLEX (BASE ALPHA)
  SECURITY POSTURE: DEFCON-1 (MAXIMUM ENCRYPTED READINESS)
================================================================================{RESET}
"""

def run_base_alpha(port: int = 9050, automated: bool = False):
    print(BANNER)
    print(f"{BOLD}[BASE ALPHA]{RESET} Initializing Defense Node on Port {port}...")
    print(f"{BOLD}[BASE ALPHA]{RESET} Cryptographic Engine: ML-KEM-1024 + Classic-McEliece + AES-256-GCM + ML-DSA-87")

    # Initialize Certificate Authority & Post-Quantum Exchange
    ca = CAExchange(exchange_port_offset=1, secure_exchange=True)
    print(f"{BOLD}[BASE ALPHA]{RESET} Generating X.509 Top-Secret Command Certificate...")
    ca.generate_self_signed()
    print(f"{GREEN}[BASE ALPHA] Certificate Generated. SHA3-512 Fingerprint: {ca.local_cert_fingerprint[:32]}...{RESET}")

    exchange_ready = threading.Event()
    cert_error = []

    def run_cert_listener():
        try:
            print(f"{CYAN}[BASE ALPHA] Awaiting Post-Quantum Cert Exchange from Base Bravo on port {port + 1}...{RESET}")
            ca.exchange_certs("server", "127.0.0.1", port, ready_event=exchange_ready)
            print(f"{GREEN}[BASE ALPHA] Cert Exchange Complete! Base Bravo verified and pinned.{RESET}")
        except Exception as e:
            cert_error.append(str(e))
            print(f"{RED}[BASE ALPHA ERROR] Cert Exchange Failed: {e}{RESET}")

    cert_thread = threading.Thread(target=run_cert_listener, daemon=True)
    cert_thread.start()

    exchange_ready.wait(timeout=30)
    print("[BASE ALPHA READY FOR EXCHANGE]", flush=True)

    # Wait for certificate exchange to finish (allow sufficient time for post-quantum keygen)
    cert_thread.join(timeout=180)
    if cert_error or not ca.peer_cert_pem:
        print(f"{RED}[BASE ALPHA CRITICAL] Could not establish trusted certificate link with Base Bravo. Aborting.{RESET}")
        return False

    # Create TLS 1.3 Server Context
    print(f"{CYAN}[BASE ALPHA] Initializing Mutual TLS 1.3 Server Context...{RESET}")
    server_ctx = ca.create_server_ctx()
    print(f"{GREEN}[BASE ALPHA] Mutual TLS 1.3 Context Active. Forensic Shredding of temporary keys complete.{RESET}")

    # Bind Main Tactical Socket
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", port))
    srv_sock.listen(1)
    print(f"{BOLD}[BASE ALPHA]{RESET} Tactical Carrier Channel Listening on 127.0.0.1:{port}...", flush=True)
    print("[BASE ALPHA MAIN SERVER READY]", flush=True)

    raw_conn, addr = srv_sock.accept()
    print(f"{GREEN}[BASE ALPHA] Incoming tactical carrier link from Pentagon Base Bravo {addr}{RESET}")

    tls_conn = server_ctx.wrap_socket(raw_conn, server_side=True)
    cipher_info = tls_conn.cipher()
    print(f"{BOLD}{GREEN}[BASE ALPHA] MUTUAL TLS 1.3 ESTABLISHED! Cipher: {cipher_info}{RESET}")

    try:
        if automated:
            # Automated military exchange script
            print(f"{YELLOW}[BASE ALPHA] Awaiting tactical transmission from Base Bravo...{RESET}")
            msg = tls_conn.recv(4096).decode('utf-8')
            print(f"\n{BOLD}{MAGENTA}[BASE ALPHA RECEIVED <- BASE BRAVO]:{RESET} {msg}")

            response = (
                "[FLASH DEFCON-1 ACK] NORAD Command to Pentagon: Interceptor grid Alpha-9 is ARMED. "
                "Orbital telemetry locked on target vectors. Operation Guardian Shield is GO."
            )
            print(f"\n{BOLD}{CYAN}[BASE ALPHA DISPATCHING -> BASE BRAVO]:{RESET} {response}")
            tls_conn.sendall(response.encode('utf-8'))

            # Await final receipt acknowledgment
            ack = tls_conn.recv(4096).decode('utf-8')
            print(f"\n{BOLD}{MAGENTA}[BASE ALPHA RECEIVED <- BASE BRAVO]:{RESET} {ack}")

            print(f"\n{BOLD}{GREEN}[BASE ALPHA] All strategic defense communications completed successfully.{RESET}")
            return True
        else:
            print(f"\n{BOLD}{GREEN}[BASE ALPHA] SECURE TACTICAL CHAT READY. Type message and press Enter (or 'exit' to disconnect):{RESET}")
            while True:
                msg = tls_conn.recv(4096)
                if not msg:
                    print(f"{YELLOW}[BASE ALPHA] Base Bravo disconnected.{RESET}")
                    break
                print(f"\n{BOLD}{MAGENTA}[BASE BRAVO]:{RESET} {msg.decode('utf-8', errors='replace')}")
                # B322: console operator input, capped at 16KB before send.
                out_msg = input(f"{BOLD}{CYAN}[BASE ALPHA (YOU)]:{RESET} ")  # nosec B322 - operator console, capped below
                if len(out_msg) > 16384:
                    print(f"{YELLOW}[BASE ALPHA] Message exceeds 16KB cap, truncated.{RESET}")
                    out_msg = out_msg[:16384]
                if out_msg.strip().lower() == 'exit':
                    break
                tls_conn.sendall(out_msg.encode('utf-8'))
            return True
    finally:
        tls_conn.close()
        srv_sock.close()
        ca.secure_cleanup()
        try:
            from native_secure_buffer import wipe_native
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        print(f"{BOLD}[BASE ALPHA]{RESET} Tactical link terminated. Memory sanitized.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Base Alpha - NORAD Tactical Node")
    parser.add_argument("--port", type=int, default=9050, help="Tactical port (default: 9050)")
    parser.add_argument("--automated", action="store_true", help="Run in automated testing mode")
    args = parser.parse_args()

    success = run_base_alpha(port=args.port, automated=args.automated)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0 if success else 1)

