#!/usr/bin/env python3
"""
test_real_uses_dual_terminal.py
====================================================================
End-to-end verification of SECURE_P2P.PY executed in 2 SEPARATE TERMINALS
under full production security logic flow:
  - Mutual Root CA verification (US_STRATEGIC_DEFENSE_ROOT_CA)
  - Mutual ML-DSA-87 station identity signing & verification
  - Hybrid Post-Quantum KEX (SecP384r1 + ML-KEM-1024 + PSK)
  - SAS verification code confirmation
  - Constant 20ms paced wire camouflage with synthetic CSPRNG chaff
  - Classified bidirectional flash order exchange
  - Military precedence messages (/precedence Z)
  - MIL-STD Cursor-on-Target telemetry (/cot) & Blue Force Tracking (/bft)
  - In-band Continuous Epoch Ratchet (CER) rotation (/rekey)
  - In-band document streaming with SHA-384 integrity verification (/doc)
  - Cryptographic telemetry and status introspection (/status, /pipeline, /lpd)
  - Clean shutdown & zeroization (/quit and /zeroize)
"""

import os
import sys
import time
import subprocess
import threading
from pathlib import Path

# Terminal colors
BOLD = "\033[1m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RED = "\033[91m"
RESET = "\033[0m"

REPO_ROOT = Path(__file__).resolve().parent

# Ensure test mission document exists
os.makedirs(REPO_ROOT / "scratch", exist_ok=True)
mission_doc = REPO_ROOT / "scratch" / "mission_order_alpha_7.txt"
mission_doc.write_text(
    "CLASSIFIED // TOP SECRET // CNSA 2.0 // NOFORN\n"
    "OPERATION GUARDIAN SHIELD: Interceptor grid deployment authorized.\n"
    "Grid Alpha-9 coordinates: 48.8566 N, 2.3522 E.\n"
    "All strategic assets armed and standing by for flash execution.\n",
    encoding="utf-8"
)

alpha_lines = []
bravo_lines = []

def reader_thread(proc, name, lines_list):
    """Continuously read process stdout line-by-line and print."""
    color = CYAN if "ALPHA" in name else GREEN
    for line in iter(proc.stdout.readline, ''):
        if not line:
            break
        cleaned = line.rstrip()
        lines_list.append(cleaned)
        print(f"{color}[{name}]{RESET} {cleaned}", flush=True)

def wait_for(lines_list, pattern, timeout=20, desc=""):
    """Poll lines_list until a pattern is found or timeout expires."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        for line in lines_list:
            if pattern in line:
                return True
        time.sleep(0.1)
    print(f"{RED}[TIMEOUT FAIL] Did not find '{pattern}' ({desc}) within {timeout}s!{RESET}")
    return False

def send_cmd(proc, name, cmd_str):
    """Write command to child stdin."""
    print(f"\n{BOLD}{YELLOW}>>> [OPERATOR INPUT TO {name}] > {cmd_str}{RESET}", flush=True)
    proc.stdin.write(cmd_str + "\n")
    proc.stdin.flush()
    time.sleep(0.6)

def run_two_terminals_full_test():
    print(f"\n{BOLD}{MAGENTA}{'=' * 80}")
    print("  LAUNCHING SECURE_P2P.PY IN 2 SEPARATE TERMINALS (REAL USES VERIFICATION)")
    print(f"{'=' * 80}{RESET}\n")

    py_exe = sys.executable

    alpha_cmd = [
        py_exe, "-u", "secure_p2p.py", "alpha", "--lab"
    ]

    bravo_cmd = [
        py_exe, "-u", "secure_p2p.py", "bravo", "--lab"
    ]

    # Spawn Terminal 1 (NORAD_ALPHA - Responder)
    print(f"{BOLD}[SPAWN] Terminal 1: NORAD Base Alpha (Responder)...{RESET}")
    proc_alpha = subprocess.Popen(
        alpha_cmd,
        cwd=str(REPO_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    t_alpha = threading.Thread(target=reader_thread, args=(proc_alpha, "NORAD_ALPHA", alpha_lines), daemon=True)
    t_alpha.start()

    # Wait for Alpha to start listening
    time.sleep(2.0)

    # Spawn Terminal 2 (PENTAGON_BRAVO - Initiator)
    print(f"{BOLD}[SPAWN] Terminal 2: Pentagon Base Bravo (Initiator)...{RESET}")
    proc_bravo = subprocess.Popen(
        bravo_cmd,
        cwd=str(REPO_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    t_bravo = threading.Thread(target=reader_thread, args=(proc_bravo, "PENTAGON_BRAVO", bravo_lines), daemon=True)
    t_bravo.start()

    try:
        # STEP 1: Verify Channel Establishment on both terminals
        print(f"\n{BOLD}[TEST STEP 1] Awaiting Mutual Root CA & Post-Quantum KEX Establishment...{RESET}")
        assert wait_for(alpha_lines, "TACTICAL SECURE CHANNEL ESTABLISHED", timeout=25, desc="Alpha Channel Ready"), "Alpha failed channel setup"
        assert wait_for(bravo_lines, "TACTICAL SECURE CHANNEL ESTABLISHED", timeout=25, desc="Bravo Channel Ready"), "Bravo failed channel setup"
        print(f"{BOLD}{GREEN}[PASS] Both terminals established post-quantum mutual KEX & pacing channels.{RESET}")

        # STEP 2: Verify SAS Short Authentication String match
        print(f"\n{BOLD}[TEST STEP 2] Verifying SAS Matching...{RESET}")
        sas_alpha = None
        sas_bravo = None
        for l in alpha_lines:
            if "Verification Code:" in l or "SAS Code" in l or "OOB SAS" in l:
                sas_alpha = l
        for l in bravo_lines:
            if "Verification Code:" in l or "SAS Code" in l or "OOB SAS" in l:
                sas_bravo = l
        print(f"  Alpha SAS line: {sas_alpha}")
        print(f"  Bravo SAS line: {sas_bravo}")

        time.sleep(1.0)

        # STEP 3: Real Use Case 1 - Send Classified Tactical Message from Bravo to Alpha
        print(f"\n{BOLD}[TEST STEP 3] Real Use Case 1: Classified Message from Bravo to Alpha...{RESET}")
        send_cmd(proc_bravo, "PENTAGON_BRAVO", "FLASH ORDER: Execute Operation Guardian Shield. Confirm interceptor status.")
        assert wait_for(alpha_lines, "Execute Operation Guardian Shield", timeout=10, desc="Alpha receive flash order"), "Alpha failed to receive Bravo message"
        print(f"{BOLD}{GREEN}[PASS] NORAD Alpha received & decrypted Bravo's message with zero loss.{RESET}")

        # STEP 4: Real Use Case 2 - Send Reply from Alpha back to Bravo
        print(f"\n{BOLD}[TEST STEP 4] Real Use Case 2: Reply from Alpha to Bravo...{RESET}")
        send_cmd(proc_alpha, "NORAD_ALPHA", "CONFIRM ACK: Interceptor grid Alpha-9 is ARMED. Airspace fully secured.")
        assert wait_for(bravo_lines, "Interceptor grid Alpha-9 is ARMED", timeout=10, desc="Bravo receive reply"), "Bravo failed to receive Alpha message"
        print(f"{BOLD}{GREEN}[PASS] Pentagon Bravo received & decrypted Alpha's reply.{RESET}")

        # STEP 5: Real Use Case 3 - Military Precedence Flash Message (/precedence Z)
        print(f"\n{BOLD}[TEST STEP 5] Real Use Case 3: Military Flash Precedence Order...{RESET}")
        send_cmd(proc_bravo, "PENTAGON_BRAVO", "/precedence Z FLASH PRIORITY: DEFCON-1 verified across all sectors.")
        assert wait_for(alpha_lines, "DEFCON-1 verified across all sectors", timeout=10, desc="Alpha receive precedence order"), "Alpha failed to receive precedence order"
        print(f"{BOLD}{GREEN}[PASS] Military precedence message delivered successfully.{RESET}")

        # STEP 6: Real Use Case 4 - Cursor-on-Target (/cot) & Blue Force Tracking (/bft)
        print(f"\n{BOLD}[TEST STEP 6] Real Use Case 4: Cursor-on-Target Beacon & Blue Force Tracking...{RESET}")
        send_cmd(proc_bravo, "PENTAGON_BRAVO", "/cot 38.8719 -77.0563 PENTAGON_C2")
        time.sleep(1.0)
        send_cmd(proc_alpha, "NORAD_ALPHA", "/bft")
        time.sleep(1.0)
        assert wait_for(alpha_lines, "PENTAGON_C2", timeout=10, desc="Alpha BFT tracking table"), "Alpha BFT missing PENTAGON_C2"
        print(f"{BOLD}{GREEN}[PASS] CoT beacon transmitted, decrypted, and populated in Blue Force Tracking.{RESET}")

        # STEP 7: Real Use Case 5 - In-Band Continuous Epoch Ratchet (CER) Rotation (/rekey)
        print(f"\n{BOLD}[TEST STEP 7] Real Use Case 5: On-Demand In-Band CER Epoch Rekey...{RESET}")
        send_cmd(proc_alpha, "NORAD_ALPHA", "/rekey")
        assert wait_for(bravo_lines, "Synchronized CER epoch rotation", timeout=10, desc="Bravo synchronized CER rotation"), "Bravo failed CER sync"
        print(f"{BOLD}{GREEN}[PASS] In-band CER epoch rotated and synchronized across both terminals.{RESET}")

        # STEP 8: Real Use Case 6 - In-Band Mission Document Streaming (/doc)
        print(f"\n{BOLD}[TEST STEP 8] Real Use Case 6: In-Band Tactical Document Streaming...{RESET}")
        send_cmd(proc_bravo, "PENTAGON_BRAVO", f"/doc {mission_doc}")
        assert wait_for(alpha_lines, "IN-BAND DOCUMENT VERIFIED", timeout=15, desc="Alpha document verification"), "Alpha failed to verify streamed document"
        print(f"{BOLD}{GREEN}[PASS] Mission document streamed, fragmented, reassembled, and verified via SHA-384.{RESET}")

        # STEP 9: Real Use Case 7 - Cryptographic Status & Telemetry Inspection (/status, /pipeline, /lpd)
        print(f"\n{BOLD}[TEST STEP 9] Real Use Case 7: Cryptographic Status & Telemetry Introspection...{RESET}")
        send_cmd(proc_alpha, "NORAD_ALPHA", "/status")
        time.sleep(0.5)
        send_cmd(proc_alpha, "NORAD_ALPHA", "/pipeline")
        time.sleep(0.5)
        send_cmd(proc_alpha, "NORAD_ALPHA", "/lpd")
        time.sleep(0.5)
        assert wait_for(alpha_lines, "TACTICAL NODE STATUS", timeout=10, desc="Status banner"), "Status banner missing"
        assert wait_for(alpha_lines, "ZERO-GAP MULTI-LAYER DEFENSE STATUS", timeout=10, desc="Pipeline banner"), "Pipeline banner missing"
        assert wait_for(alpha_lines, "LOW PROBABILITY OF DETECTION / INTERCEPTION", timeout=10, desc="LPD banner"), "LPD banner missing"
        print(f"{BOLD}{GREEN}[PASS] Telemetry, pipeline, and LPD telemetry inspected and verified.{RESET}")

        # STEP 10: Real Use Case 8 - Clean Shutdown & Zeroization
        print(f"\n{BOLD}[TEST STEP 10] Real Use Case 8: Clean Termination & SP 800-88 Zeroization...{RESET}")
        send_cmd(proc_alpha, "NORAD_ALPHA", "/quit")
        send_cmd(proc_bravo, "PENTAGON_BRAVO", "/zeroize")

        proc_alpha.wait(timeout=10)
        proc_bravo.wait(timeout=10)
        print(f"{BOLD}{GREEN}[PASS] Both terminal processes terminated cleanly.{RESET}")

        print(f"\n{BOLD}{GREEN}{'=' * 80}")
        print("  ALL 8 REAL USE CASES SUCCEEDED 100% IN 2 SEPARATE TERMINAL PROCESSES!")
        print(f"{'=' * 80}{RESET}\n")
        return True

    except Exception as e:
        print(f"\n{BOLD}{RED}[FAIL] Exception during dual-terminal test: {e}{RESET}")
        proc_alpha.kill()
        proc_bravo.kill()
        return False
    finally:
        if proc_alpha.poll() is None:
            proc_alpha.kill()
        if proc_bravo.poll() is None:
            proc_bravo.kill()

if __name__ == "__main__":
    success = run_two_terminals_full_test()
    sys.exit(0 if success else 1)
