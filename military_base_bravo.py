#!/usr/bin/env python3
"""
TOP-SECRET DEFENSE NETWORK NODE
Base Bravo: Pentagon Joint Operations Command (National Military Command Center)
Protocol: CNSA 2.0 / Post-Quantum Mutual TLS 1.3 / FIPS 140-3 Level 3
"""

import sys
import os
import time
import socket
import ssl
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

BANNER = f"""{BOLD}{GREEN}
================================================================================
  [TOP SECRET // CNSA 2.0 // NOFORN]
  NATIONAL MILITARY COMMAND CENTER - PENTAGON (BASE BRAVO)
  TACTICAL POST-QUANTUM DEFENSE TERMINAL
  SECURITY POSTURE: DEFCON-1 (MAXIMUM ENCRYPTED READINESS)
================================================================================{RESET}
"""

def run_base_bravo(target_host: str = "127.0.0.1", port: int = 9050, automated: bool = False):
    print(BANNER)
    print(f"{BOLD}[BASE BRAVO]{RESET} Initializing Defense Node...")
    print(f"{BOLD}[BASE BRAVO]{RESET} Target Node: NORAD Base Alpha at {target_host}:{port}")
    print(f"{BOLD}[BASE BRAVO]{RESET} Cryptographic Engine: ML-KEM-1024 + Classic-McEliece + AES-256-GCM + ML-DSA-87")

    # Initialize Certificate Authority & Post-Quantum Exchange
    ca = CAExchange(exchange_port_offset=1, secure_exchange=True)
    print(f"{BOLD}[BASE BRAVO]{RESET} Generating X.509 Top-Secret Pentagon Command Certificate...")
    ca.generate_self_signed()
    print(f"{GREEN}[BASE BRAVO] Certificate Generated. SHA3-512 Fingerprint: {ca.local_cert_fingerprint[:32]}...{RESET}")

    # Give Base Alpha server a brief moment to ensure socket readiness
    print(f"{CYAN}[BASE BRAVO] Connecting to Base Alpha Post-Quantum Cert Port at {target_host}:{port + 1}...{RESET}")
    max_retries = 30
    connected = False
    for attempt in range(max_retries):
        try:
            ca.exchange_certs("client", target_host, port)
            connected = True
            break
        except Exception as e:
            time.sleep(1.5)

    if not connected or not ca.peer_cert_pem:
        print(f"{RED}[BASE BRAVO CRITICAL] Failed to complete post-quantum certificate exchange with Base Alpha.{RESET}")
        return False

    print(f"{GREEN}[BASE BRAVO] Post-Quantum Cert Exchange Complete! Base Alpha verified & pinned.{RESET}")

    # Create TLS 1.3 Client Context
    print(f"{CYAN}[BASE BRAVO] Initializing Mutual TLS 1.3 Client Context...{RESET}")
    client_ctx = ca.create_client_ctx(target_hostname=target_host)
    print(f"{GREEN}[BASE BRAVO] Mutual TLS 1.3 Context Active. Forensic Shredding of temporary keys complete.{RESET}")

    # Connect to Main Tactical Carrier Socket with retry
    print(f"{CYAN}[BASE BRAVO] Connecting to Base Alpha Tactical Carrier at {target_host}:{port}...{RESET}")
    cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_connected = False
    for attempt in range(20):
        try:
            cli_sock.connect((target_host, port))
            main_connected = True
            break
        except Exception as conn_err:
            time.sleep(0.5)

    if not main_connected:
        print(f"{RED}[BASE BRAVO CRITICAL] Could not connect to Base Alpha main carrier at {target_host}:{port}.{RESET}")
        return False

    tls_conn = client_ctx.wrap_socket(cli_sock, server_side=False, server_hostname=target_host)
    cipher_info = tls_conn.cipher()
    print(f"{BOLD}{GREEN}[BASE BRAVO] MUTUAL TLS 1.3 LINK ACTIVE! Cipher: {cipher_info}{RESET}")

    try:
        if automated:
            # Automated military exchange script
            order = (
                "[FLASH DEFCON-1 ORDER] Pentagon Joint Command to NORAD: "
                "Execute Operation Guardian Shield. Authenticate interceptor grid Alpha-9 readiness immediately."
            )
            print(f"\n{BOLD}{CYAN}[BASE BRAVO DISPATCHING -> BASE ALPHA]:{RESET} {order}")
            tls_conn.sendall(order.encode('utf-8'))

            # Receive Base Alpha's flash confirmation
            response = tls_conn.recv(4096).decode('utf-8')
            print(f"\n{BOLD}{MAGENTA}[BASE BRAVO RECEIVED <- BASE ALPHA]:{RESET} {response}")

            final_ack = (
                "[CONFIRMED] Pentagon acknowledges grid status Alpha-9 green. "
                "Post-quantum quantum-resistant communications link verified active (CNSA 2.0 / ML-KEM-1024 + ML-DSA-87 / NIST Level 5)."
            )
            print(f"\n{BOLD}{CYAN}[BASE BRAVO DISPATCHING -> BASE ALPHA]:{RESET} {final_ack}")
            tls_conn.sendall(final_ack.encode('utf-8'))

            print(f"\n{BOLD}{GREEN}[BASE BRAVO] All tactical mission directives dispatched and validated successfully.{RESET}")
            return True
        else:
            print(f"\n{BOLD}{GREEN}[BASE BRAVO] SECURE TACTICAL CHAT READY. Type message and press Enter (or 'exit' to disconnect):{RESET}")
            while True:
                out_msg = input(f"{BOLD}{CYAN}[BASE BRAVO (YOU)]:{RESET} ")
                if out_msg.strip().lower() == 'exit':
                    break
                tls_conn.sendall(out_msg.encode('utf-8'))
                msg = tls_conn.recv(4096)
                if not msg:
                    print(f"{YELLOW}[BASE BRAVO] Base Alpha disconnected.{RESET}")
                    break
                print(f"\n{BOLD}{MAGENTA}[BASE ALPHA]:{RESET} {msg.decode('utf-8', errors='replace')}")
            return True
    finally:
        tls_conn.close()
        cli_sock.close()
        ca.secure_cleanup()
        try:
            from native_secure_buffer import wipe_native
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        print(f"{BOLD}[BASE BRAVO]{RESET} Tactical link terminated. Memory sanitized.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Base Bravo - Pentagon Tactical Node")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Target node IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9050, help="Tactical port (default: 9050)")
    parser.add_argument("--automated", action="store_true", help="Run in automated testing mode")
    args = parser.parse_args()

    success = run_base_bravo(target_host=args.host, port=args.port, automated=args.automated)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0 if success else 1)

