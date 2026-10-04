#!/usr/bin/env python3
"""
NC3 TWO-TERMINAL LIVE INTEGRATION TEST (SECURE_P2.PY)
=====================================================
Spawns two independent processes running 'python secure_p2.py' (Station 1: NORAD Base Alpha,
Station 2: Pentagon Base Bravo), conducts post-quantum TLS 1.3 handshake and Double Ratchet,
executes /nc3-send under Two-Person Rule, receives EAM, authenticates and unseals PAL code
with /nc3-verify under Dual-Custody, tests /zeroize, and validates 100% operational readiness.
"""

import os
import sys
import time
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
    for f in ["profile_nc3_alpha.json", "profile_nc3_bravo.json"]:
        p = os.path.join(BASE_DIR, f)
        if os.path.exists(p):
            try:
                from secure_memory_wiper import secure_shred_file
                secure_shred_file(p, passes=3)
            except Exception:
                try:
                    os.remove(p)
                except Exception:  # nosec: B110
                    pass


def run_live_nc3_test():
    print_banner("NC3 TWO-TERMINAL LIVE EAM TRANSFER & VERIFICATION TEST")
    print("Scenario: Launching Station Alpha (NORAD) and Station Bravo (Pentagon) using secure_p2.py.")
    print("Testing: Two-Person Rule /nc3-send, EAM reception alert, /nc3-verify unsealing, and /zeroize.")

    clean_profiles()

    # TEST-ONLY shared secrets: the war-order key and officer file-seal
    # passphrase are injected via environment so scripted stations never
    # block on getpass prompts. NEVER set these operationally — custodians
    # type them interactively (no echo) in production.
    run_env = dict(
        os.environ,
        PYTHONUNBUFFERED="1",
        P2P_ALLOW_LOOPBACK="1",
        # Quarantined twins live in archive/legacy_prototype: spawned
        # terminals run with that dir as script home, so repo root rides
        # PYTHONPATH for sibling imports (protocol_manager, ...).
        PYTHONPATH=BASE_DIR + os.pathsep + os.environ.get("PYTHONPATH", ""),
        P2P_NC3_WAR_KEY="058d3327d4d78bb641a4adab8d7d967c7c05c0035d29141be2dea7a3b9bfd342",
        P2P_OFFICER_SEAL_PW="nc3-live-transfer-test-seal-only",
    )

    # 1. Spawn Station Alpha (NORAD) on port 50021
    alpha_cmd = [
        PYTHON_EXE, "-u", os.path.join(BASE_DIR, "archive/legacy_prototype/secure_p2.py"),
        "--port", "50021",
        "--profile", os.path.join(BASE_DIR, "profile_nc3_alpha.json")
    ]
    print(f"[ORCHESTRATOR] Spawning Station Alpha: {' '.join(alpha_cmd)}")
    alpha_proc = subprocess.Popen(  # nosec: B603
        alpha_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=run_env
    )

    alpha_setup_detected = threading.Event()
    alpha_menu_ready = threading.Event()
    alpha_chat_ready = threading.Event()
    alpha_eam_dispatched = threading.Event()

    alpha_lines = []
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
            if "EMERGENCY ACTION MESSAGE BROADCAST" in line:
                alpha_eam_dispatched.set()

    alpha_thread = threading.Thread(target=alpha_reader, daemon=True)
    alpha_thread.start()

    if not alpha_setup_detected.wait(timeout=120):
        alpha_proc.kill()
        raise RuntimeError("Station Alpha timed out during crypto init")

    # Alpha first-time setup input
    time.sleep(0.5)
    alpha_proc.stdin.write("2\n")  # Setup option 2 (direct custom identity)
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write("BaseAlphaNC3\n")
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write("NORAD Strategic Defense Command\n")
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write("TopSecretNC3Alpha2026!\n")
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write("TopSecretNC3Alpha2026!\n")
    alpha_proc.stdin.flush()

    if not alpha_menu_ready.wait(timeout=60):
        alpha_proc.kill()
        raise RuntimeError("Station Alpha timed out reaching main menu")

    # 2. Spawn Station Bravo (Pentagon) on port 50023
    bravo_cmd = [
        PYTHON_EXE, "-u", os.path.join(BASE_DIR, "archive/legacy_prototype/secure_p2.py"),
        "--port", "50023",
        "--profile", os.path.join(BASE_DIR, "profile_nc3_bravo.json")
    ]
    print(f"[ORCHESTRATOR] Spawning Station Bravo: {' '.join(bravo_cmd)}")
    bravo_proc = subprocess.Popen(  # nosec: B603
        bravo_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=run_env
    )

    bravo_setup_detected = threading.Event()
    bravo_menu_ready = threading.Event()
    bravo_chat_ready = threading.Event()
    bravo_eam_alert_detected = threading.Event()
    bravo_pal_unsealed = threading.Event()
    bravo_zeroized = threading.Event()

    bravo_lines = []
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
            if "INCOMING EMERGENCY ACTION MESSAGE (EAM) DETECTED" in line:
                bravo_eam_alert_detected.set()
            if "9941-8823-ALPHA-ZULU-7711" in line:
                bravo_pal_unsealed.set()
            if "All volatile session buffers and EAM memory zeroized" in line:
                bravo_zeroized.set()

    bravo_thread = threading.Thread(target=bravo_reader, daemon=True)
    bravo_thread.start()

    if not bravo_setup_detected.wait(timeout=120):
        bravo_proc.kill()
        alpha_proc.kill()
        raise RuntimeError("Station Bravo timed out during crypto init")

    # Bravo first-time setup input
    time.sleep(0.5)
    bravo_proc.stdin.write("2\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("BaseBravoNC3\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("Pentagon NMCC Operations\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("TopSecretNC3Bravo2026!\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("TopSecretNC3Bravo2026!\n")
    bravo_proc.stdin.flush()

    if not bravo_menu_ready.wait(timeout=60):
        bravo_proc.kill()
        alpha_proc.kill()
        raise RuntimeError("Station Bravo timed out reaching main menu")

    # 2b. OOB pairing ceremony (military TOFU policy)
    import re as _re

    def _extract_pairing(lines):
        peer_id, fp = None, None
        for ln in lines:
            m = _re.search(r"Your pairing fingerprint \[(.+?)\]:", ln)
            if m:
                peer_id = m.group(1).strip()
            m = _re.search(r"^\s*([0-9a-fA-F]{128})\s*$", ln)
            if m:
                fp = m.group(1).lower()
        return peer_id, fp

    def _wait_pairing(lines, timeout=60):
        t0 = time.time()
        while time.time() - t0 < timeout:
            peer_id, fp = _extract_pairing(lines)
            if peer_id and fp:
                return peer_id, fp
            time.sleep(0.5)
        return None, None

    print(f"\n[ORCHESTRATOR] {CYAN}Performing OOB pairing ceremony...{RESET}")
    alpha_id, alpha_fp = _wait_pairing(alpha_lines)
    bravo_id, bravo_fp = _wait_pairing(bravo_lines)
    if not (alpha_id and alpha_fp and bravo_id and bravo_fp):
        bravo_proc.kill()
        alpha_proc.kill()
        raise RuntimeError("Pairing ceremony failed: fingerprints not advertised")

    alpha_proc.stdin.write("5\n")
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write(f"{bravo_id}\n")
    alpha_proc.stdin.flush()
    time.sleep(0.5)
    alpha_proc.stdin.write(f"{bravo_fp}\n")
    alpha_proc.stdin.flush()
    time.sleep(1.0)

    bravo_proc.stdin.write("5\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write(f"{alpha_id}\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write(f"{alpha_fp}\n")
    bravo_proc.stdin.flush()
    time.sleep(1.0)
    print(f"[ORCHESTRATOR] {GREEN}Mutual pairing complete (both directions pre-authorized).{RESET}")

    # Alpha enters Server Mode (Option 1)
    time.sleep(1)
    alpha_proc.stdin.write("1\n")
    alpha_proc.stdin.flush()

    # Deterministic listen-sync (same flake class as
    # run_two_terminals_secure_p2_test.py): never let Bravo connect before
    # Alpha's server socket is bound+listening; fail fast with Alpha's tail
    # instead of a misleading chat-session assert 90s later.
    def _alpha_listening(deadline_s=60):
        t0 = time.time()
        while time.time() - t0 < deadline_s:
            for ln in alpha_lines:
                if "Secure server listening on" in ln and "50021" in ln:
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
            "Station Alpha never reached listening state on :50021. "
            f"Alpha tail:\n{tail}")
    print(f"[ORCHESTRATOR] {GREEN}Station Alpha listening on :50021 confirmed.{RESET}")
    time.sleep(1)

    # Bravo connects to Alpha (Option 2 -> 127.0.0.1 -> 50021)
    time.sleep(1)
    bravo_proc.stdin.write("2\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("127.0.0.1\n")
    bravo_proc.stdin.flush()
    time.sleep(0.5)
    bravo_proc.stdin.write("50021\n")
    bravo_proc.stdin.flush()

    # 3. Wait for Link Establishment
    print("\n[ORCHESTRATOR] Awaiting Mutual TLS 1.3 & Post-Quantum Double Ratchet link...")
    t0 = time.time()
    while time.time() - t0 < 90:
        if alpha_chat_ready.is_set() and bravo_chat_ready.is_set():
            break
        time.sleep(0.5)

    assert alpha_chat_ready.is_set(), "Station Alpha failed to enter active chat session!"  # nosec: B101
    assert bravo_chat_ready.is_set(), "Station Bravo failed to enter active chat session!"  # nosec: B101
    print(f"\n{BOLD}{GREEN}>>> [MUTUAL POST-QUANTUM LINK ESTABLISHED BETWEEN BASES] <<<{RESET}\n")

    # 4. Dispatch Nuclear EAM from NORAD (Station Alpha)
    time.sleep(2)
    eam_command = "/nc3-send FLASH-DEFCON1-STRIKE-PLAN TARGET-VECTOR-OMNI 9941-8823-ALPHA-ZULU-7711\n"
    print(f"[ORCHESTRATOR] Dispatching NC3 EAM from NORAD: {eam_command.strip()}")
    alpha_proc.stdin.write(eam_command)
    alpha_proc.stdin.flush()

    if not alpha_eam_dispatched.wait(timeout=30):
        raise RuntimeError("Station Alpha failed to broadcast NC3 Emergency Action Message!")
    print(f"  {GREEN}[PASS] Station Alpha successfully sealed and broadcasted EAM under Two-Person Rule.{RESET}")

    # 5. Verify EAM Reception Alert at Station Bravo
    if not bravo_eam_alert_detected.wait(timeout=30):
        raise RuntimeError("Station Bravo did not detect incoming NC3 EAM alert!")
    print(f"  {GREEN}[PASS] Station Bravo triggered High-Priority DEFCON-1 EAM alert banner.{RESET}")

    # 6. Execute Dual-Officer Verification at Station Bravo
    time.sleep(2)
    verify_command = "/nc3-verify COL_CHARLIE CAPT_DELTA\n"
    print(f"[ORCHESTRATOR] Station Bravo executing Dual-Officer verification: {verify_command.strip()}")
    bravo_proc.stdin.write(verify_command)
    bravo_proc.stdin.flush()

    if not bravo_pal_unsealed.wait(timeout=30):
        raise RuntimeError("Station Bravo failed to verify and unseal PAL code!")
    print(f"  {GREEN}[PASS] Station Bravo successfully authenticated ML-DSA-87 signatures and unsealed PAL code!{RESET}")

    # 7. Execute Emergency Zeroization
    time.sleep(2)
    zero_command = "/zeroize\n"
    print(f"[ORCHESTRATOR] Station Bravo triggering DoD 5220.22-M zeroization: {zero_command.strip()}")
    bravo_proc.stdin.write(zero_command)
    bravo_proc.stdin.flush()

    if not bravo_zeroized.wait(timeout=20):
        raise RuntimeError("Station Bravo failed to zeroize volatile buffers!")
    print(f"  {GREEN}[PASS] DoD 5220.22-M 3-pass memory zeroization successfully confirmed.{RESET}")

    # 8. Clean Teardown
    print("\n[ORCHESTRATOR] Shutting down stations...")
    bravo_proc.stdin.write("exit\n")
    bravo_proc.stdin.flush()
    time.sleep(1)
    alpha_proc.stdin.write("exit\n")
    alpha_proc.stdin.flush()

    try:
        bravo_proc.wait(timeout=15)
    except Exception:
        bravo_proc.kill()
    try:
        alpha_proc.wait(timeout=15)
    except Exception:
        alpha_proc.kill()

    clean_profiles()
    print(f"\n{BOLD}{GREEN}================================================================================")
    print("  [ALL NC3 TWO-TERMINAL LIVE VERIFICATION CHECKS PASSED 100%]")
    print(f"================================================================================{RESET}\n")
    return True


def test_nc3_two_terminal_live_eam_transfer():
    """Pytest gate: full NC3 two-terminal live run (Two-Person Rule
    /nc3-send, EAM alert, dual-officer /nc3-verify unseal, /zeroize).
    ~3-5 min, loopback lab only. Ports 50021+ fixed: do not run two
    instances concurrently."""
    assert run_live_nc3_test() is True  # nosec: B101


if __name__ == "__main__":
    success = run_live_nc3_test()
    sys.exit(0 if success else 1)

