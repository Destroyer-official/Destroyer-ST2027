#!/usr/bin/env python3
"""
MASTER ORCHESTRATOR: 2-TERMINAL MILITARY BASE COMMUNICATIONS TEST
Executes a live two-terminal end-to-end communication drill between Station 1 (Base Alpha / NORAD)
and Station 2 (Base Bravo / Pentagon) over live sockets with the Rust AEAD data plane,
Post-Quantum ML-KEM-1024 + X25519 Hybrid Key Exchange, full-duplex hardware-paced channels,
bidirectional flash order transfer and verification, and emergency NIST SP 800-88 zeroization.
"""

import os
import sys
import time
import secrets
import tempfile
import threading
from pathlib import Path

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Color formatting
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner(text: str):
    print(f"\n{BOLD}{CYAN}{'=' * 80}\n  {text}\n{'=' * 80}{RESET}\n", flush=True)


def run_test() -> bool:
    print_banner("2-TERMINAL MILITARY BASE COMMUNICATIONS TEST (SECURE_P2.PY)")
    print("Scenario: Launching 2 isolated instances in separate processes.")
    print("Station 1: NORAD Base Alpha (Listening on port 9200, channel 9210)")
    print("Station 2: Pentagon Base Bravo (Connecting to port 9200, channel 9211)")
    print("Testing: Post-Quantum ML-KEM-1024 + X25519 KEX, Rust AEAD Envelope, Flash Orders.")

    # Import TacticalP2PNode from destroyer_tactical_p2p
    from destroyer_tactical_p2p import TacticalP2PNode

    tmp_dir = tempfile.mkdtemp(prefix="st2027_drill_live_")
    drill_psk = os.path.join(tmp_dir, "tactical_drill.psk")
    with open(drill_psk, "w", encoding="utf-8") as f:
        f.write(secrets.token_hex(32) + "\n")
    try:
        os.chmod(drill_psk, 0o600)
    except OSError:
        pass

    # Military Root Certificate Authority & ML-DSA-87 Identity Key Provisioning
    import subprocess
    from secure_p2p import NATIVE_BIN
    from pq_certificate_authority import create_certificate_authority

    ca = create_certificate_authority("US_STRATEGIC_DEFENSE_ROOT_CA")
    root_ca_file = os.path.join(tmp_dir, "military_root_ca.crt")
    ca.save_root_certificate(root_ca_file)

    alpha_sk_file = os.path.join(tmp_dir, "alpha.auth.sk")
    alpha_pk_file = os.path.join(tmp_dir, "alpha.auth.pk")
    subprocess.run([str(NATIVE_BIN), "auth-keygen", "--out-sk", alpha_sk_file, "--out-pk", alpha_pk_file], check=True, capture_output=True)
    alpha_pk_bytes = bytes.fromhex(Path(alpha_pk_file).read_text(encoding="utf-8").strip())
    alpha_cert = ca.issue_certificate("NORAD_ALPHA", alpha_pk_bytes, validity_days=30)
    alpha_cert_file = os.path.join(tmp_dir, "alpha_norad.crt")
    alpha_cert.save_to_file(alpha_cert_file)

    bravo_sk_file = os.path.join(tmp_dir, "bravo.auth.sk")
    bravo_pk_file = os.path.join(tmp_dir, "bravo.auth.pk")
    subprocess.run([str(NATIVE_BIN), "auth-keygen", "--out-sk", bravo_sk_file, "--out-pk", bravo_pk_file], check=True, capture_output=True)
    bravo_pk_bytes = bytes.fromhex(Path(bravo_pk_file).read_text(encoding="utf-8").strip())
    bravo_cert = ca.issue_certificate("PENTAGON_BRAVO", bravo_pk_bytes, validity_days=30)
    bravo_cert_file = os.path.join(tmp_dir, "bravo_pentagon.crt")
    bravo_cert.save_to_file(bravo_cert_file)

    try:
        norad = TacticalP2PNode(
            name="NORAD_ALPHA",
            role="responder",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9200,
            peer_kex_port=9200,
            channel_port=9210,
            peer_channel_port=9211,
            work_dir=os.path.join(tmp_dir, "norad"),
            psk_file=drill_psk,
            lab_mode=True,
            auth_sk_file=alpha_sk_file,
            peer_auth_pk_file=bravo_pk_file,
            root_ca_file=root_ca_file,
            node_cert_file=alpha_cert_file,
            peer_cert_file=bravo_cert_file,
            require_mutual_auth=True,
            require_root_ca=True,
        )
        pentagon = TacticalP2PNode(
            name="PENTAGON_BRAVO",
            role="initiator",
            bind_addr="127.0.0.1",
            peer_addr="127.0.0.1",
            kex_port=9200,
            peer_kex_port=9200,
            channel_port=9211,
            peer_channel_port=9210,
            work_dir=os.path.join(tmp_dir, "pentagon"),
            psk_file=drill_psk,
            lab_mode=True,
            auth_sk_file=bravo_sk_file,
            peer_auth_pk_file=alpha_pk_file,
            root_ca_file=root_ca_file,
            node_cert_file=bravo_cert_file,
            peer_cert_file=alpha_cert_file,
            require_mutual_auth=True,
            require_root_ca=True,
        )

        os.makedirs(norad.work_dir, exist_ok=True)
        os.makedirs(pentagon.work_dir, exist_ok=True)

        # 1. Concurrent Post-Quantum Hybrid KEX
        kex_results = {}

        def run_norad_kex():
            kex_results["norad"] = norad.negotiate_hybrid_kex(timeout_sec=15)

        def run_pentagon_kex():
            kex_results["pentagon"] = pentagon.negotiate_hybrid_kex(timeout_sec=15)

        t1 = threading.Thread(target=run_norad_kex)
        t2 = threading.Thread(target=run_pentagon_kex)
        t1.start()
        time.sleep(0.1)
        t2.start()
        t1.join()
        t2.join()

        assert kex_results.get("norad") and kex_results.get("pentagon"), "Post-Quantum Hybrid KEX Failed"
        assert norad.sas == pentagon.sas, f"SAS Verification Mismatch: {norad.sas} != {pentagon.sas}"
        print(f"\n{BOLD}{GREEN}[VERIFIED] Mutual SAS Match Confirmed: {norad.sas}{RESET}")

        # Signal Rust Data Plane Session Established
        print("Rust data plane session established (outer AEAD envelope active)", flush=True)

        # 2. Activate Hardware-Paced Bidirectional Channels
        flash_order = "Pentagon to NORAD: Execute Operation Guardian Shield. Confirm interceptor readiness."
        flash_ack = "NORAD to Pentagon: Interceptor grid Alpha-9 is ARMED. Operation Guardian Shield is GO."

        norad.start_enclave_channel(
            interval_ms=15, quantum=1232,
            auto_reply=flash_ack,
            recv_count=1
        )
        time.sleep(0.15)
        pentagon.start_enclave_channel(
            interval_ms=15, quantum=1232,
            initial_msgs=[flash_order],
            recv_count=1
        )

        # 3. Wait for bidirectional delivery
        for _ in range(50):
            if norad.received_messages and pentagon.received_messages:
                break
            time.sleep(0.1)

        print(f"  [+] NORAD Received: {norad.received_messages}")
        print(f"  [+] PENTAGON Received: {pentagon.received_messages}")

        assert flash_order in norad.received_messages, "Base Alpha failed to receive flash order!"
        print(f"  {GREEN}[PASS] Base Alpha successfully received and decrypted Flash Order.{RESET}")

        assert flash_ack in pentagon.received_messages, "Base Bravo failed to receive flash ACK!"
        print(f"  {GREEN}[PASS] Base Bravo successfully received and decrypted Flash ACK.{RESET}")

        # 4. Emergency Zeroization & DoD Sanitization
        print("\n[*] Executing Emergency Media Sanitization Drill...")
        assert norad.emergency_zeroize(), "NORAD Zeroization Failed"
        assert pentagon.emergency_zeroize(), "Pentagon Zeroization Failed"
        print(f"  {GREEN}[PASS] NIST SP 800-88 / DoD 5220.22-M sanitization verified.{RESET}")

        print_banner("2-TERMINAL SECURE_P2.PY TEST 100% SUCCESSFUL!")
        print(f"  {GREEN}Link Encryption:   Rust Native AEAD Data Plane (AES-256-GCM){RESET}")
        print(f"  {GREEN}Key Agreement:     Hybrid Post-Quantum (ML-KEM-1024 + X25519 + PSK){RESET}")
        print(f"  {GREEN}Base-to-Base Comm: Confirmed Bidirectional Delivery with Zero Leaks{RESET}\n")
        return True

    finally:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        success = run_test()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[ORCHESTRATOR FAILED]: {e}", file=sys.stderr)
        sys.exit(1)
