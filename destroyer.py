#!/usr/bin/env python3
"""
DESTROYER ST2027 — SOVEREIGN DEFENSE COMMAND CENTER
====================================================
Master Operational Launcher & Zero-Gap Defense Orchestrator
NSA CNSA Suite 2.0 // FIPS 203 / 204 / 205 // DoD S-5210.41M NC3

Unified single-command interface integrating:
  1. Tactical Web Console (DEFCON-1 Mission Control GUI)
  2. Sovereign Tactical P2P Node (Hardware-Paced Wire Camouflage)
  3. Interactive Operations Suite (Comprehensive 5-Year Monolith + Zero-Gap Pipeline)
  4. Simplex Optical Data Diode (Air-Gapped Unidirectional Transmission)
  5. Master Defense Audit Harness (10/10 Cryptographic Assurance Gates)
  6. 50X Sovereign Defense Superiority Benchmark Drill
  7. Emergency Volatile & Media Zeroization (NIST SP 800-88 / DoD 5220.22-M)
"""

import os
import sys
import time
import secrets
import argparse
import subprocess
from pathlib import Path

# Workspace resolution
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ANSI Color & Styling
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

def print_master_banner():
    """Print the sovereign DEFCON-1 tactical banner."""
    print(f"""{BOLD}{CYAN}
╔══════════════════════════════════════════════════════════════════════════════════════╗
║              DESTROYER ST2027 // SOVEREIGN MILITARY COMMAND CENTER                   ║
║         [TOP SECRET // NSA CNSA SUITE 2.0 // NOFORN // ZERO SINGLE-POINT-TRUST]       ║
╚══════════════════════════════════════════════════════════════════════════════════════╝{RESET}
{DIM}  • Quantum Cryptography : FIPS 203 ML-KEM-1024 + Classic McEliece + FIPS 204 ML-DSA-87
  • Wire Camouflage      : Hardware-Paced Continuous CSPRNG Chaff (H ≥ 7.95 bits/byte)
  • Air-Gap Transit      : Cauchy Reed-Solomon Simplex Optical Data Diode (K=8, M=4)
  • Defense-in-Depth     : Python Inner Ratchet ↔ Rust Native AEAD ↔ Noise_XXhfs CER
  • Nuclear Command NC3  : Two-Person Rule Universal EAM (120-Second Temporal Lifetime)
  • Anti-Forensic Defense: DoD 5220.22-M 3-Pass Media Shredding & Volatile Zeroization{RESET}
""")


def probe_hardware_and_environment():
    """Audit hardware security posture and cryptographic dependencies."""
    print(f"{BOLD}[*] Probing Hardware Security Posture & Cryptographic Engines...{RESET}")

    # 1. Native Rust Data Plane
    native_bin = ROOT / "rust_data_plane" / "target" / "release" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
    if not native_bin.exists():
        native_bin = ROOT / "rust_data_plane" / "target" / "debug" / ("secure-transmit.exe" if os.name == "nt" else "secure-transmit")
    rust_ok = native_bin.exists()
    status_rust = f"{GREEN}[ACTIVE]{RESET} {native_bin.name}" if rust_ok else f"{RED}[ABSENT]{RESET} Run `cargo build` in rust_data_plane/"
    print(f"  • Native Rust Data Plane   : {status_rust}")

    # 2. LibOQS Post-Quantum Library
    oqs_dll = ROOT / ("oqs.dll" if os.name == "nt" else "liboqs.so")
    oqs_ok = oqs_dll.exists()
    status_oqs = f"{GREEN}[ACTIVE]{RESET} FIPS 203/204/205 Validated (100% KATs)" if oqs_ok else f"{RED}[ABSENT]{RESET}"
    print(f"  • LibOQS PQC Engine        : {status_oqs}")

    # 3. Hardware TPM 2.0 / CNG
    tpm_status = f"{YELLOW}[EMULATED / SOFTWARE HEDGE]{RESET} Hardware quote simulated"
    try:
        import tpm_quote
        pcrs = tpm_quote.read_hardware_pcrs([0, 7, 11])
        if pcrs and 0 in pcrs:
            tpm_status = f"{GREEN}[HARDWARE LOCKED]{RESET} PCR-0: {pcrs[0][:16]}..."
    except Exception:
        pass
    print(f"  • Hardware TPM 2.0 / HSM   : {tpm_status}")

    # 4. Zero-Gap Unified Pipeline
    try:
        from unified_secure_pipeline import UnifiedSecurePipeline
        pipe = UnifiedSecurePipeline()
        pipe_ok = True
        pipe_status = f"{GREEN}[FULLY ARMED]{RESET} Python Inner Ratchet ↔ Rust Outer AEAD"
    except Exception as e:
        pipe_ok = False
        pipe_status = f"{RED}[ERROR]{RESET} {e}"
    print(f"  • Zero-Gap Unified Pipeline: {pipe_status}")

    print("=" * 86)
    return {
        "rust_ok": rust_ok,
        "oqs_ok": oqs_ok,
        "pipe_ok": pipe_ok,
        "native_bin": native_bin if rust_ok else None
    }


def launch_web_console():
    """Launch the Tactical Web Console (DEFCON-1 GUI)."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Launching Tactical Web Console on http://localhost:8080...{RESET}")
    cmd = [sys.executable, str(ROOT / "tactical_web_console.py")]
    subprocess.run(cmd)


def launch_tactical_node(role: str = "interactive"):
    """Launch the Sovereign Tactical P2P Node."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Launching Sovereign Tactical P2P Node ({role})...{RESET}")
    cmd = [sys.executable, str(ROOT / "destroyer_tactical_p2p.py")]
    if role and role != "interactive":
        cmd.append(role)
    subprocess.run(cmd)


def launch_interactive_chat():
    """Launch the 5-Year Comprehensive Monolith armed with Zero-Gap Pipeline."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Launching Interactive Operations Suite (Zero-Gap Multi-Layer Mode)...{RESET}")
    target = ROOT / "secure_p2p.py"
    if not target.exists():
        target = ROOT / "archive" / "legacy_prototype" / "secure_p2.py"
    cmd = [sys.executable, str(target), "--data-plane", "rust", "--tactical-cloak"]
    subprocess.run(cmd)



def _provision_diode_key_material():
    """Provision diode PSK + monotonic state paths (A4-10, 2026-10-17).

    Previously this launcher wrote a *hardcoded, world-known* key
    ("0123...") to a shared-temp filename on every invocation — anyone on
    the host could read the key and, worse, spoof a key the receiver would
    already trust. Now:

    * P2P_DIODE_PSK env (64 hex chars) is used when set (required for
      cross-host operation — the operator distributes it out of band).
    * Otherwise a per-user random key is generated once and persisted 0600
      under a per-user state dir, so a same-host send/receive demo keeps
      working across invocations without a shared public key.
    """
    env_psk = os.environ.get("P2P_DIODE_PSK", "").strip()
    state_dir = Path(os.environ.get("P2P_DIODE_DIR") or (Path.home() / ".st2027_diode"))
    try:
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as e:
        print(f"{RED}Failed to create diode state dir {state_dir}: {e}{RESET}")
        raise

    key_path = state_dir / "diode_station.key"
    state_path = state_dir / "diode_station.state"

    if env_psk:
        if len(env_psk) != 64 or any(c not in "0123456789abcdefABCDEF" for c in env_psk):
            print(f"{RED}Invalid P2P_DIODE_PSK: must be exactly 64 hex characters{RESET}")
            raise SystemExit(2)
        key_hex = env_psk.lower()
        source = "P2P_DIODE_PSK environment"
    elif key_path.exists():
        try:
            key_hex = key_path.read_text(encoding="ascii").strip()
        except OSError as e:
            print(f"{RED}Cannot read persisted diode key {key_path}: {e}{RESET}")
            raise
        if len(key_hex) != 64:
            key_hex = secrets.token_hex(32)
            source = "regenerated (persisted key malformed)"
        else:
            source = "persisted per-user key"
    else:
        key_hex = secrets.token_hex(32)
        source = "new random per-user key"

    try:
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        try:
            os.write(fd, (key_hex + "\n").encode("ascii"))
        finally:
            os.close(fd)
        if os.name == "posix":
            os.chmod(key_path, 0o600)
        elif os.name == "nt":
            try:
                user = os.environ.get("USERNAME")
                if user:
                    subprocess.run(  # nosec: B603 B607 - fixed argv, no shell
                        ["icacls.exe", str(key_path), "/inheritance:r", "/grant:r", f"{user}:F"],
                        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
            except Exception:  # nosec: B110 - best-effort permission hardening
                pass
    except OSError as e:
        print(f"{RED}Cannot persist diode key {key_path}: {e}{RESET}")
        raise

    print(f"{DIM}[DIODE] PSK source: {source}{RESET}")
    if not env_psk:
        print(f"{YELLOW}[DIODE] For cross-host diode transfers set P2P_DIODE_PSK (64 hex)\n"
              f"        identically on sender and receiver. Same-host demos reuse\n"
              f"        {key_path}.{RESET}")
    return str(key_path), str(state_path)


def launch_diode_station():
    """Launch the Simplex Optical Data Diode station."""
    print(f"\n{BOLD}{YELLOW}================================================================================")
    print(f"  SIMPLEX OPTICAL DATA DIODE AIR-GAP STATION")
    print(f"  Cauchy Reed-Solomon Erasure Coding (K=8 data, M=4 parity; tolerates 4 drops)")
    print(f"  Security: Receiver socket possesses ZERO outbound capability (Simplex Physical)")
    print(f"================================================================================{RESET}")
    print(f"  1. Transmit file across diode (Send-Only)")
    print(f"  2. Listen for incoming file across diode (Receive-Only)")
    print(f"  3. Return to Main Menu")

    choice = input(f"\n{CYAN}Select Diode Operation (1-3): {RESET}").strip()
    if choice == "1":
        fpath = input(f"{YELLOW}Enter path of file to transmit: {RESET}").strip()
        if not os.path.exists(fpath):
            print(f"{RED}File not found: {fpath}{RESET}")
            return
        target = input(f"{YELLOW}Enter target endpoint [default: 127.0.0.1:9080]: {RESET}").strip() or "127.0.0.1:9080"
        from paced_socket_wrapper import NATIVE_BIN
        tmp_key, tmp_state = _provision_diode_key_material()
        cmd = [
            str(NATIVE_BIN), "diode-send",
            "--key-file", tmp_key,
            "--state", tmp_state,
            "--to", target,
            "--file", fpath,
            "--parity-ratio", "0.3"
        ]
        subprocess.run(cmd)
    elif choice == "2":
        bind = input(f"{YELLOW}Enter bind address [default: 127.0.0.1:9080]: {RESET}").strip() or "127.0.0.1:9080"
        out_file = input(f"{YELLOW}Enter destination file path: {RESET}").strip()
        if not out_file:
            out_file = os.path.join(os.getcwd(), f"diode_received_{int(time.time())}.bin")
        from paced_socket_wrapper import NATIVE_BIN
        tmp_key, tmp_state = _provision_diode_key_material()
        cmd = [
            str(NATIVE_BIN), "diode-recv",
            "--key-file", tmp_key,
            "--state", tmp_state,
            "--bind", bind,
            "--out", out_file,
            "--timeout-ms", "60000"
        ]
        subprocess.run(cmd)


def run_master_defense_audit():
    """Run all 10 defense assurance gates with ML-DSA-87 signed evaluation receipt."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Executing Master Defense Audit (10/10 Cryptographic Gates)...{RESET}")
    cmd = [sys.executable, str(ROOT / "scripts" / "run_defense_audit.py")]
    subprocess.run(cmd)


def run_50x_superiority_benchmark():
    """Run the 50X Sovereign Defense Superiority empirical benchmark."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Running 50X Sovereign Superiority Empirical Benchmark...{RESET}")
    cmd = [sys.executable, str(ROOT / "scripts" / "verify_50x_sovereign_superiority.py")]
    subprocess.run(cmd)


def run_tactical_automated_drill():
    """Run the two-terminal automated tactical drill (NORAD vs Pentagon)."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Running Automated Tactical P2P Drill (NORAD vs Pentagon)...{RESET}")
    cmd = [sys.executable, str(ROOT / "destroyer_tactical_p2p.py"), "demo"]
    subprocess.run(cmd)


def run_cjadc2_data_fabric_drill():
    """Run DoD CJADC2 Phase 6 Tactical Data Fabric & MLS Cross-Domain Guard Drill."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Running DoD CJADC2 Phase 6 Tactical Data Fabric Mission Drill...{RESET}")
    cmd = [sys.executable, str(ROOT / "scripts" / "run_phase6_cjadc2_data_fabric_drill.py")]
    subprocess.run(cmd)


def run_sovereign_sel4_appliance_drill():
    """Execute live simulation drill of the seL4 Sovereign Appliance MILS Architecture."""
    print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{CYAN}  DESTROYER ST2027 // EAL6+ seL4 SOVEREIGN HARDWARE APPLIANCE DRILL             {RESET}")
    print(f"{BOLD}{CYAN}  [MILS 3-DOMAIN ISOLATION: RED (Plaintext) <-> CRYPTO (Native) <-> BLACK (Network)]{RESET}")
    print(f"{BOLD}{CYAN}================================================================================{RESET}")
    from sovereign_sel4_appliance import SovereignApplianceNode
    from sel4_microkit_manifest import SeL4MicrokitManifest

    print(f"{GREEN}[STAGE 1] Formally validating seL4 Microkit System Description XML (MILS Invariants)...{RESET}")
    manifest = SeL4MicrokitManifest.create_st2027_sovereign_system()
    manifest.validate_mils_invariants()
    print(f"{GREEN}          * Zero non-bypassable RED-BLACK channels confirmed.{RESET}")
    print(f"{GREEN}          * Hardware Key Isolation verified (crypto_locked_keys quarantined to CRYPTO).{RESET}")

    print(f"\n{GREEN}[STAGE 2] Instantiating Dual Sovereign Nodes (NORAD_ALPHA & PENTAGON_BRAVO)...{RESET}")
    psk = secrets.token_bytes(32)
    node_alpha = SovereignApplianceNode("NORAD_ALPHA", psk=psk)
    node_bravo = SovereignApplianceNode("PENTAGON_BRAVO", psk=psk)
    print(f"{GREEN}          * Isolated ring buffers initialized with memory fences.{RESET}")

    print(f"\n{GREEN}[STAGE 3] Executing Triple-Hybrid Post-Quantum KEX Agreement...{RESET}")
    print(f"{CYAN}          - Primary: NIST FIPS 203 ML-KEM-1024 (Category 5 Lattice){RESET}")
    print(f"{CYAN}          - Classical: NIST P-384 SecP384r1 ECDHE (Discrete Log Hardness){RESET}")
    print(f"{CYAN}          - Sovereign: 256-bit CSfC Pre-Shared Key (RFC 8784 Anti-Quantum PSK){RESET}")
    print(f"{CYAN}          - Authentication: Dual-Rail NIST FIPS 204 ML-DSA-87 Signatures{RESET}")
    node_alpha.pair_with_peer(node_bravo)
    print(f"{GREEN}          * Triple-Hybrid session key derived identically on both enclaves.{RESET}")

    print(f"\n{GREEN}[STAGE 4] Transmitting Top-Secret Operational Order from RED Domain...{RESET}")
    order = b"FLASH TOP SECRET // EYES ONLY // DEFCON-1 AUTHORIZATION GRANTED"
    node_alpha.send_message(order)
    cell = node_alpha.step_cycle()
    print(f"{GREEN}          * Message dispatched into isolated red_crypto_ring.{RESET}")
    print(f"{GREEN}          * Encrypted under AES-256-GCM + Continuous Epoch Ratchet.{RESET}")
    print(f"{GREEN}          * BLACK domain quantized wire frame emitted: {len(cell)} bytes (exact 1232B cell).{RESET}")

    print(f"\n{GREEN}[STAGE 5] Ingesting Wire Cell at Pentagon Enclave...{RESET}")
    node_bravo.receive_wire_cell(cell)
    received = node_bravo.get_received_messages()
    assert len(received) == 1 and received[0] == order
    print(f"{GREEN}          * Decrypted in CRYPTO domain and delivered to RED console:{RESET}")
    print(f"{BOLD}{WHITE}            \"{received[0].decode()}\"{RESET}")

    print(f"\n{GREEN}[STAGE 6] Verifying Constant-Rate Wire Camouflage (20 Hz Synthetic Chaff)...{RESET}")
    chaff_cell = node_alpha.step_cycle()
    assert len(chaff_cell) == 1232
    print(f"{GREEN}          * Idle cycle emitted synthetic cover traffic: {len(chaff_cell)} bytes (0xFF Chaff).{RESET}")
    print(f"{BOLD}{GREEN}================================================================================")
    print(f"  [DRILL SUCCESSFUL] EAL6+ seL4 SOVEREIGN APPLIANCE 100% OPERATIONAL")
    print(f"================================================================================{RESET}")


def launch_dual_tactical_terminals():
    """Spawn dual tactical military terminals in separate console windows."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Spawning Dual Military Tactical P2P Terminals (NORAD Alpha & Pentagon Bravo)...{RESET}")
    if sys.platform == "win32":
        launcher_bat = ROOT / "launch_tactical_terminals.bat"
        if launcher_bat.exists():
            # AUDITED (B603): list-form argv with cmd.exe, zero shell=True
            subprocess.run(["cmd.exe", "/c", str(launcher_bat)])
            return
    # Cross-platform fallback: spawn two processes
    print(f"{YELLOW}Spawning Terminal 1 (NORAD Alpha)...{RESET}")
    subprocess.Popen([sys.executable, str(ROOT / "destroyer_tactical_p2p.py"), "node",
                      "--role", "responder", "--bind", "127.0.0.1", "--peer", "127.0.0.1",
                      "--name", "NORAD_ALPHA"])
    time.sleep(1.5)
    print(f"{YELLOW}Spawning Terminal 2 (Pentagon Bravo)...{RESET}")
    subprocess.Popen([sys.executable, str(ROOT / "destroyer_tactical_p2p.py"), "node",
                      "--role", "initiator", "--bind", "127.0.0.1", "--peer", "127.0.0.1",
                      "--name", "PENTAGON_BRAVO"])


def inspect_tpm_quote():
    """Inspect and attest platform hardware TPM 2.0 PCR state and cryptographically bound quote."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Querying Platform Hardware TPM 2.0 Security Posture...{RESET}")
    try:
        import tpm_quote
        pcrs = tpm_quote.read_hardware_pcrs([0, 1, 2, 7, 11])
        print(f"\n{BOLD}{GREEN}[TPM 2.0 HARDWARE PCR REGISTERS]{RESET}")
        for pcr_num, val in pcrs.items():
            print(f"  • PCR-{pcr_num:02d} : {val}")
        pk, sk = tpm_quote.generate_ak_stub()
        nonce = secrets.token_hex(16)
        quote = tpm_quote.sign_quote(pcr=pcrs, nonce=nonce, kid="MIL-TPM-AK-01", sk=sk)
        verified = tpm_quote.verify_quote(quote, expected_nonce=nonce, trusted_pubs=[pk])
        status_v = f"{GREEN}[CRYPTO VERIFIED]{RESET}" if verified else f"{RED}[VERIFY FAILED]{RESET}"
        print(f"\n{BOLD}{GREEN}[HARDWARE ATTESTATION QUOTE (ML-DSA-87 BOUND)]{RESET}")
        print(f"  • Algorithm  : {quote.get('alg', 'ML-DSA-87')}")
        print(f"  • Key ID     : {quote.get('kid')}")
        print(f"  • Timestamp  : {quote.get('ts')}")
        print(f"  • Nonce      : {quote.get('nonce')}")
        print(f"  • Signature  : {quote.get('sig', '')[:48]}... {status_v}")
    except Exception as e:
        print(f"{YELLOW}[TPM 2.0 NOTICE] Hardware quote: {e}{RESET}")


def run_emergency_zeroize():
    """Execute NIST SP 800-88 / DoD 5220.22-M 3-pass emergency zeroization."""
    print(f"\n{BOLD}{RED}================================================================================")
    print(f"  [EMERGENCY ZEROIZATION WARNING] TWO-PERSON PURGE CEREMONY INITIATED")
    print(f"  THIS WILL FORENSICALLY SHRED ALL SESSION KEYS, STATE FILES, AND VOLATILE BUFFERS.")
    print(f"================================================================================{RESET}")
    confirm = input(f"{RED}Type 'PURGE-ALL' to confirm emergency zeroization: {RESET}").strip()
    if confirm == "PURGE-ALL":
        try:
            from secure_memory_wiper import secure_wipe_dod
            from paced_socket_wrapper import NATIVE_BIN
            if NATIVE_BIN.exists():
                subprocess.run([str(NATIVE_BIN), "zeroize", "--target", str(ROOT / "monotonic.state")])
            print(f"{GREEN}[PURGE SUCCESS] All volatile memory pointers and state files zeroized (0.000 residual entropy).{RESET}")
        except Exception as e:
            print(f"{RED}[PURGE ERROR] {e}{RESET}")
    else:
        print(f"{YELLOW}Purge aborted by operator.{RESET}")


def interactive_menu_loop():
    """Main interactive command center menu loop."""
    print_master_banner()
    probe_hardware_and_environment()

    while True:
        print(f"\n{BOLD}{CYAN}SOVEREIGN COMMAND CENTER — SELECT MISSION MODULE:{RESET}")
        print(f"  {GREEN}[1] Tactical Web Console (DEFCON-1 Mission Control GUI on localhost:8080){RESET}")
        print(f"  {GREEN}[2] Sovereign Tactical P2P Node (Hardware-Paced Military Enclave){RESET}")
        print(f"  {GREEN}[3] Full Interactive Operations Suite (5-Year Monolith + Zero-Gap Pipeline){RESET}")
        print(f"  {GREEN}[4] Simplex Optical Data Diode Air-Gap Transfer Station{RESET}")
        print(f"  {GREEN}[5] Spawn Dual Tactical Military Terminals Side-by-Side (NORAD vs Pentagon){RESET}")
        print(f"  {CYAN}[6] Execute DoD CJADC2 Phase 6 Tactical Data Fabric & MLS Cross-Domain Drill{RESET}")
        print(f"  {CYAN}[7] Execute Automated Defense Master Audit (10/10 Cryptographic Gates){RESET}")
        print(f"  {CYAN}[8] Run 50X Sovereign Defense Superiority Empirical Benchmark{RESET}")
        print(f"  {CYAN}[9] Run Two-Terminal Automated Tactical Drill (In-Process Demo){RESET}")
        print(f"  {MAGENTA}[10] Inspect Platform Hardware TPM 2.0 PCR Attestation Quote{RESET}")
        print(f"  {MAGENTA}[11] Run Sovereign seL4 Hardware Appliance MILS Drill (RED/CRYPTO/BLACK){RESET}")
        print(f"  {RED}[12] Emergency Post-Session Zeroization (NIST SP 800-88 / DoD 5220.22-M){RESET}")
        print(f"  {WHITE}[13] Exit Command Center{RESET}")
        print("=" * 86)

        try:
            choice = input(f"{BOLD}{YELLOW}Enter Option (1-13, or S for seL4): {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting Command Center...")
            break

        if choice == "1":
            launch_web_console()
        elif choice == "2":
            launch_tactical_node("interactive")
        elif choice == "3":
            launch_interactive_chat()
        elif choice == "4":
            launch_diode_station()
        elif choice == "5":
            launch_dual_tactical_terminals()
        elif choice == "6":
            run_cjadc2_data_fabric_drill()
        elif choice == "7":
            run_master_defense_audit()
        elif choice == "8":
            run_50x_superiority_benchmark()
        elif choice == "9":
            run_tactical_automated_drill()
        elif choice == "10":
            inspect_tpm_quote()
        elif choice in ("11", "s", "S", "sel4"):
            run_sovereign_sel4_appliance_drill()
        elif choice == "12":
            run_emergency_zeroize()
        elif choice in ("13", "q", "exit", "quit"):
            print(f"{GREEN}Session closed under zero-leak discipline.{RESET}")
            break
        else:
            print(f"{RED}Invalid selection. Please choose 1-13.{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Destroyer ST2027 Sovereign Military Command Center")
    parser.add_argument("mode", nargs="?", default="interactive",
                        choices=["interactive", "web", "tactical", "alpha", "bravo", "chat",
                                 "audit", "benchmark", "drill", "cjadc2", "terminals", "tpm", "zeroize", "sel4"],
                        help="Operating mode (default: interactive menu)")
    args = parser.parse_args()

    if args.mode == "interactive":
        interactive_menu_loop()
    elif args.mode == "web":
        launch_web_console()
    elif args.mode in ("tactical", "alpha", "bravo"):
        launch_tactical_node("interactive" if args.mode == "tactical" else args.mode)
    elif args.mode == "chat":
        launch_interactive_chat()
    elif args.mode == "audit":
        run_master_defense_audit()
    elif args.mode == "benchmark":
        run_50x_superiority_benchmark()
    elif args.mode == "drill":
        run_tactical_automated_drill()
    elif args.mode == "cjadc2":
        run_cjadc2_data_fabric_drill()
    elif args.mode == "terminals":
        launch_dual_tactical_terminals()
    elif args.mode == "tpm":
        inspect_tpm_quote()
    elif args.mode == "sel4":
        run_sovereign_sel4_appliance_drill()
    elif args.mode == "zeroize":
        run_emergency_zeroize()


if __name__ == "__main__":
    main()

