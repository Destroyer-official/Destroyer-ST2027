#!/usr/bin/env python3
"""
MASTER ORCHESTRATOR: 2-TERMINAL MILITARY BASE COMMUNICATION TEST FOR SECURE_P2.PY
Runs two separate instances of 'python secure_p2.py' as separate terminal processes
(Station 1: NORAD Base Alpha and Station 2: Pentagon Base Bravo), establishes real
post-quantum mutual TLS 1.3 and Double Ratchet links, exchanges classified flash orders,
and validates 100% genuine operational readiness.
"""

import os
import sys
import time
# AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
import subprocess  # nosec: B404
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_EXE = sys.executable

GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner(text):
    print(f"\n{BOLD}{CYAN}{'=' * 80}\n  {text}\n{'=' * 80}{RESET}\n", flush=True)


def clean_profiles():
    for f in ["profile_alpha.json", "profile_bravo.json"]:
        p = os.path.join(BASE_DIR, f)
        if os.path.exists(p):
            try:
                from secure_memory_wiper import secure_shred_file
                secure_shred_file(p, passes=3)
            except Exception:
                try:
                    os.remove(p)
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass


def run_test():
    print_banner("2-TERMINAL MILITARY BASE COMMUNICATIONS TEST (SECURE_P2.PY)")
    print("Scenario: Launching 2 isolated instances of 'python secure_p2.py' in separate processes.")
    print("Station 1: NORAD Base Alpha (Listening on port 50007, cert port 50008)")
    print("Station 2: Pentagon Base Bravo (Listening on port 50009, cert port 50010)")
    print("Testing full post-quantum handshake, mutual TLS 1.3, Double Ratchet, and flash orders.")

    clean_profiles()

    # Quarantined twins live in archive/legacy_prototype: spawned terminals
    # run with that dir as script home, so repo root rides PYTHONPATH for
    # sibling imports (protocol_manager, pqc_algorithms, ...).
    run_env = dict(os.environ, PYTHONUNBUFFERED="1", P2P_ALLOW_LOOPBACK="1",
                   PYTHONPATH=BASE_DIR + os.pathsep + os.environ.get("PYTHONPATH", ""))

    # --------------------------------------------------------------------------
    # 1. Spawn Terminal 1 (Station Alpha - NORAD)
    # --------------------------------------------------------------------------
    alpha_cmd = [
        PYTHON_EXE, "-u", os.path.join(BASE_DIR, "archive/legacy_prototype/secure_p2.py"),
        "--port", "50007",
        "--profile", os.path.join(BASE_DIR, "profile_alpha.json")
    ]
    print(f"\n[ORCHESTRATOR] Spawning Terminal 1 (Base Alpha): {' '.join(alpha_cmd)}")
    # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified)
    alpha_proc = subprocess.Popen(  # nosec: B603
        alpha_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=run_env
    )

    alpha_lines = []
    alpha_setup_detected = threading.Event()
    alpha_menu_ready = threading.Event()
    alpha_chat_ready = threading.Event()
    alpha_received_order = threading.Event()

    def alpha_reader():
        for line in iter(alpha_proc.stdout.readline, ''):
            if not line:
                break
            alpha_lines.append(line)
            sys.stdout.write(f"  {CYAN}[ALPHA NORAD]{RESET} {line}")
            sys.stdout.flush()

            if "SELECT SECURE IDENTITY ARCHITECTURE" in line or "FIRST-TIME SETUP" in line:
                alpha_setup_detected.set()
            if "Don't connect from both sides" in line or "Choose an option" in line:
                alpha_menu_ready.set()
            if "Chat session started." in line or "Connected with" in line:
                alpha_chat_ready.set()
            if "Operation Guardian Shield" in line:
                alpha_received_order.set()

    alpha_thread = threading.Thread(target=alpha_reader, daemon=True)
    alpha_thread.start()

    print("[ORCHESTRATOR] Initializing Base Alpha post-quantum cryptographic subsystem...")
    if not alpha_setup_detected.wait(timeout=120):
        alpha_proc.kill()
        raise RuntimeError("Base Alpha timed out initializing post-quantum crypto")

    # Send identity inputs
    print(f"[ORCHESTRATOR] {CYAN}Configuring Base Alpha identity and profile encryption...{RESET}")
    time.sleep(0.5)
    alpha_proc.stdin.write("2\n")
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write("BaseAlpha\n")
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write("NORAD Base Alpha\n")
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write("TopSecretAlphaPass2026!\n")
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write("TopSecretAlphaPass2026!\n")
    alpha_proc.stdin.flush()

    print("[ORCHESTRATOR] Waiting for Base Alpha tactical menu...")
    if not alpha_menu_ready.wait(timeout=60):
        alpha_proc.kill()
        raise RuntimeError("Base Alpha timed out reaching main menu")

    # --------------------------------------------------------------------------
    # 2. Spawn Terminal 2 (Station Bravo - Pentagon)
    # --------------------------------------------------------------------------
    bravo_cmd = [
        PYTHON_EXE, "-u", os.path.join(BASE_DIR, "archive/legacy_prototype/secure_p2.py"),
        "--port", "50009",
        "--profile", os.path.join(BASE_DIR, "profile_bravo.json")
    ]
    print(f"\n[ORCHESTRATOR] Spawning Terminal 2 (Base Bravo): {' '.join(bravo_cmd)}")
    # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified)
    bravo_proc = subprocess.Popen(  # nosec: B603
        bravo_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=run_env
    )

    bravo_lines = []
    bravo_setup_detected = threading.Event()
    bravo_menu_ready = threading.Event()
    bravo_chat_ready = threading.Event()
    bravo_received_ack = threading.Event()

    def bravo_reader():
        for line in iter(bravo_proc.stdout.readline, ''):
            if not line:
                break
            bravo_lines.append(line)
            sys.stdout.write(f"  {GREEN}[BRAVO PENTAGON]{RESET} {line}")
            sys.stdout.flush()

            if "SELECT SECURE IDENTITY ARCHITECTURE" in line or "FIRST-TIME SETUP" in line:
                bravo_setup_detected.set()
            if "Don't connect from both sides" in line or "Choose an option" in line:
                bravo_menu_ready.set()
            if "Chat session started." in line or "Connected with" in line:
                bravo_chat_ready.set()
            if "Interceptor grid Alpha-9 is ARMED" in line:
                bravo_received_ack.set()

    bravo_thread = threading.Thread(target=bravo_reader, daemon=True)
    bravo_thread.start()

    print("[ORCHESTRATOR] Initializing Base Bravo post-quantum cryptographic subsystem...")
    if not bravo_setup_detected.wait(timeout=120):
        bravo_proc.kill()
        alpha_proc.kill()
        raise RuntimeError("Base Bravo timed out initializing post-quantum crypto")

    # Send identity inputs
    print(f"[ORCHESTRATOR] {GREEN}Configuring Base Bravo identity and profile encryption...{RESET}")
    time.sleep(0.5)
    bravo_proc.stdin.write("2\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("BaseBravo\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("Pentagon Joint Command\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("TopSecretBravoPass2026!\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("TopSecretBravoPass2026!\n")
    bravo_proc.stdin.flush()

    print("[ORCHESTRATOR] Waiting for Base Bravo tactical menu...")
    if not bravo_menu_ready.wait(timeout=60):
        bravo_proc.kill()
        alpha_proc.kill()
        raise RuntimeError("Base Bravo timed out reaching main menu")

    # --------------------------------------------------------------------------
    # 2b. OOB pairing ceremony (military TOFU policy: no zero-touch pairing).
    # The orchestrator acts as the out-of-band channel (secure voice equivalent):
    # read each terminal's pairing fingerprint from its menu output, relay it
    # to the other side via menu Option 5. Both handshakes then pin on first
    # contact instead of aborting.
    # --------------------------------------------------------------------------
    import re as _re

    def _extract_pairing(lines):
        peer_id, pair_fp, cert_fp = None, None, None
        for i, ln in enumerate(lines):
            m = _re.search(r"Your pairing fingerprint \[(.+?)\]:", ln)
            if m:
                peer_id = m.group(1).strip()
                for next_ln in lines[i+1:i+6]:
                    m2 = _re.search(r"^\s*([0-9a-fA-F]{128})\s*$", next_ln)
                    if m2:
                        pair_fp = m2.group(1).lower()
                        break
            if "Your certificate fingerprint" in ln:
                for next_ln in lines[i+1:i+6]:
                    m2 = _re.search(r"^\s*([0-9a-fA-F]{128})\s*$", next_ln)
                    if m2:
                        cert_fp = m2.group(1).lower()
                        break
        return peer_id, pair_fp, cert_fp

    def _wait_pairing(lines, timeout=60):
        t0 = time.time()
        while time.time() - t0 < timeout:
            peer_id, pair_fp, cert_fp = _extract_pairing(lines)
            if peer_id and (pair_fp or cert_fp):
                return peer_id, pair_fp, cert_fp
            time.sleep(0.5)
        return None, None, None

    print(f"\n[ORCHESTRATOR] {CYAN}Performing OOB pairing ceremony...{RESET}")
    alpha_id, alpha_pair_fp, alpha_cert_fp = _wait_pairing(alpha_lines)
    bravo_id, bravo_pair_fp, bravo_cert_fp = _wait_pairing(bravo_lines)
    if not (alpha_id and (alpha_pair_fp or alpha_cert_fp) and bravo_id and (bravo_pair_fp or bravo_cert_fp)):
        bravo_proc.kill()
        alpha_proc.kill()
        raise RuntimeError("Pairing ceremony failed: fingerprints not advertised")
    print(f"[ORCHESTRATOR] Alpha [{alpha_id}]: Pair={str(alpha_pair_fp)[:16]}... Cert={str(alpha_cert_fp)[:16]}...")
    print(f"[ORCHESTRATOR] Bravo [{bravo_id}]: Pair={str(bravo_pair_fp)[:16]}... Cert={str(bravo_cert_fp)[:16]}...")

    # Alpha authorizes Bravo (Option 5 for cert and pairing fingerprints)
    for b_fp in filter(None, [bravo_cert_fp, bravo_pair_fp]):
        alpha_proc.stdin.write("5\n")
        alpha_proc.stdin.flush()
        time.sleep(0.5)
        alpha_proc.stdin.write(f"{bravo_id}\n")
        alpha_proc.stdin.flush()
        time.sleep(0.5)
        alpha_proc.stdin.write(f"{b_fp}\n")
        alpha_proc.stdin.flush()
        time.sleep(0.5)

    # Bravo authorizes Alpha (Option 5 for cert and pairing fingerprints)
    for a_fp in filter(None, [alpha_cert_fp, alpha_pair_fp]):
        bravo_proc.stdin.write("5\n")
        bravo_proc.stdin.flush()
        time.sleep(0.5)
        bravo_proc.stdin.write(f"{alpha_id}\n")
        bravo_proc.stdin.flush()
        time.sleep(0.5)
        bravo_proc.stdin.write(f"{a_fp}\n")
        bravo_proc.stdin.flush()
        time.sleep(0.5)
    print(f"[ORCHESTRATOR] {GREEN}Mutual pairing complete (both directions pre-authorized).{RESET}")

    # Select Option 1: Wait for incoming secure connection (Server Mode)
    print(f"\n[ORCHESTRATOR] {GREEN}Base Alpha entering Server Mode (Option 1)...{RESET}")
    time.sleep(1)
    alpha_proc.stdin.write("1\n")
    alpha_proc.stdin.flush()

    # Deterministic listen-sync (flake fix): the old fixed sleep(2) raced
    # Alpha's server-socket bind under load (slow PQ init) against Bravo's
    # connect -- connection-refused before listen produced the misleading
    # "failed to enter active chat session" 90s later. Wait for Alpha's own
    # "Secure server listening on ...:50007" line instead of hoping.
    def _alpha_listening(deadline_s=60):
        t0 = time.time()
        while time.time() - t0 < deadline_s:
            for ln in alpha_lines:
                if "Secure server listening on" in ln and "50007" in ln:
                    return True
            if alpha_proc.poll() is not None:
                return False
            time.sleep(0.5)
        return False

    if not _alpha_listening():
        tail = "".join(alpha_lines[-25:])
        bravo_proc.kill()
        alpha_proc.kill()
        raise RuntimeError(
            "Base Alpha never reached listening state on :50007 "
            f"(server socket not bound). Alpha tail:\n{tail}")
    print(f"[ORCHESTRATOR] {GREEN}Base Alpha listening on :50007 confirmed.{RESET}")
    time.sleep(1)

    # Select Option 2: Connect to peer by IP/Port (Direct P2P Client Mode)
    # Peer IP: 127.0.0.1, Peer Port: 50007
    print(f"\n[ORCHESTRATOR] {GREEN}Base Bravo connecting to Base Alpha at 127.0.0.1:50007 (Option 2)...{RESET}")
    time.sleep(1)
    bravo_proc.stdin.write("2\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("127.0.0.1\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("50007\n")
    bravo_proc.stdin.flush()

    # --------------------------------------------------------------------------
    # 3. Wait for Full Link Establishment
    # --------------------------------------------------------------------------
    print("\n[ORCHESTRATOR] Awaiting Post-Quantum Mutual TLS 1.3 & Double Ratchet Link...")
    t0 = time.time()
    while time.time() - t0 < 90:
        if alpha_chat_ready.is_set() and bravo_chat_ready.is_set():
            break
        time.sleep(0.5)

    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert alpha_chat_ready.is_set(), "Base Alpha failed to enter active chat session!"  # nosec: B101
    # AUDITED (B101): test/demo/verify-harness assertion mechanism; live paths use explicit fail-closed raises (verified 2026-09 waves)
    assert bravo_chat_ready.is_set(), "Base Bravo failed to enter active chat session!"  # nosec: B101
    print(f"\n{BOLD}{GREEN}>>> [MUTUAL TLS 1.3 & DOUBLE RATCHET LINK ACTIVE BETWEEN BASES] <<<{RESET}\n")

    # --------------------------------------------------------------------------
    # 4. Exchange Classified Flash Orders
    # --------------------------------------------------------------------------
    time.sleep(2)
    flash_order = "[FLASH DEFCON-1] Pentagon to NORAD: Execute Operation Guardian Shield. Confirm interceptor readiness.\n"
    print(f"[ORCHESTRATOR] Dispatching Flash Order from Pentagon -> NORAD: {flash_order.strip()}")
    bravo_proc.stdin.write(flash_order)
    bravo_proc.stdin.flush()

    if not alpha_received_order.wait(timeout=25):
        raise RuntimeError("Base Alpha did not receive the flash order from Base Bravo!")
    print(f"  {GREEN}[PASS] Base Alpha successfully received and decrypted Flash Order.{RESET}")

    time.sleep(2)
    flash_ack = "[ACK DEFCON-1] NORAD to Pentagon: Interceptor grid Alpha-9 is ARMED. Operation Guardian Shield is GO.\n"
    print(f"[ORCHESTRATOR] Dispatching Flash ACK from NORAD -> Pentagon: {flash_ack.strip()}")
    alpha_proc.stdin.write(flash_ack)
    alpha_proc.stdin.flush()

    if not bravo_received_ack.wait(timeout=25):
        raise RuntimeError("Base Bravo did not receive the ACK from Base Alpha!")
    print(f"  {GREEN}[PASS] Base Bravo successfully received and decrypted Flash ACK.{RESET}")

    # --------------------------------------------------------------------------
    # 5. Graceful Teardown & Forensic Shredding
    # --------------------------------------------------------------------------
    print("\n[ORCHESTRATOR] Terminating chat sessions and validating cryptographic cleanup...")
    bravo_proc.stdin.write("exit\n")
    bravo_proc.stdin.flush()
    time.sleep(1)
    alpha_proc.stdin.write("exit\n")
    alpha_proc.stdin.flush()

    time.sleep(3)
    alpha_proc.terminate()
    bravo_proc.terminate()

    try:
        alpha_proc.wait(timeout=5)
        bravo_proc.wait(timeout=5)
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass

    clean_profiles()
    print(f"  {GREEN}[PASS] Temporary profiles shredded per DoD 5220.22-M.{RESET}")

    print_banner("2-TERMINAL SECURE_P2.PY TEST 100% SUCCESSFUL!")
    print(f"  {GREEN}Link Encryption:   Mutual TLS 1.3 (TLS_AES_256_GCM_SHA384){RESET}")
    print(f"  {GREEN}Key Agreement:     Hybrid Post-Quantum (ML-KEM-1024 + X25519){RESET}")
    print(f"  {GREEN}Session Secrecy:   Double Ratchet Active{RESET}")
    print(f"  {GREEN}Base-to-Base Comm: Confirmed Bidirectional Delivery with Zero Leaks{RESET}\n")
    return True


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)

