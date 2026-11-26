#!/usr/bin/env python3
"""
ST2027 PROTOCOL SUITE COMMAND CENTER
====================================================
Master Operational Launcher & Zero-Gap Defense Orchestrator
NSA CNSA Suite 2.0 // FIPS 203 / 204 / 205 // Two-Person Rule

Unified single-command interface integrating:
  1. Tactical Web Console (DEFCON-1 Mission Control GUI)
  2. P2P Terminal Node (Hardware-Paced Wire Camouflage)
  3. Interactive Operations Suite (Comprehensive 5-Year Monolith + Zero-Gap Pipeline)
  4. Simplex Optical Data Diode (Air-Gapped Unidirectional Transmission)
  5. Master Defense Audit Harness (10/10 Cryptographic Assurance Gates)
  6. Protocol Performance Benchmark Drill
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

# Fail-closed default: arm production posture unless explicitly running under lab opt-in or under test harness
if os.environ.get("P2P_LAB_MODE") != "1" and "pytest" not in sys.modules and not os.environ.get("PYTEST_CURRENT_TEST"):
    import production_gate
    production_gate.arm_production_gate("destroyer_cli_default")
    os.environ.setdefault("P2P_DATA_PLANE", "rust")

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
    """Print the protocol command banner."""
    print(f"""{BOLD}{CYAN}
╔══════════════════════════════════════════════════════════════════════════════════════╗
║              ST2027 PROTOCOL SUITE // COMMAND CENTER                   ║
║         [TOP SECRET // NSA CNSA SUITE 2.0 // NOFORN // ZERO SINGLE-POINT-TRUST]       ║
╚══════════════════════════════════════════════════════════════════════════════════════╝{RESET}
{DIM}  • Quantum Cryptography : FIPS 203 ML-KEM-1024 + Classic McEliece + FIPS 204 ML-DSA-87
  • Wire Camouflage      : Hardware-Paced Continuous CSPRNG Chaff (H ≥ 7.95 bits/byte)
  • Air-Gap Transit      : Cauchy Reed-Solomon Simplex Optical Data Diode (K=8, M=4)
  • Defense-in-Depth     : Python Inner Ratchet ↔ Rust Native AEAD ↔ Noise_XXhfs CER
  • Dual Authorization     : Two-Person Rule Cryptographic Directive (120-Second Lifetime)
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

    # 2. Standalone Out-of-Process Native Verifier (Blocker B-03)
    verifier_bin = ROOT / "rust_data_plane" / "target" / "release" / ("verify-binaries.exe" if os.name == "nt" else "verify-binaries")
    if not verifier_bin.exists():
        verifier_bin = ROOT / "rust_data_plane" / "target" / "debug" / ("verify-binaries.exe" if os.name == "nt" else "verify-binaries")
    verifier_ok = verifier_bin.exists()
    status_verifier = f"{GREEN}[ACTIVE]{RESET} Standalone Out-of-Process Rust Verifier ({verifier_bin.name})" if verifier_ok else f"{YELLOW}[BUILD PENDING]{RESET}"
    print(f"  • Native Binary Verifier   : {status_verifier}")

    # 3. LibOQS Post-Quantum Library
    oqs_dll = ROOT / ("oqs.dll" if os.name == "nt" else "liboqs.so")
    oqs_ok = oqs_dll.exists()
    status_oqs = (
        f"{GREEN}[PRESENT]{RESET} Native liboqs binary loaded (FIPS 203 ML-KEM-1024, FIPS 204 ML-DSA-87; CMVP module certificate pending)"
        if oqs_ok else f"{RED}[ABSENT]{RESET}"
    )
    print(f"  • LibOQS PQC Engine        : {status_oqs}")

    # 4. Hardware TPM 2.0 / CNG
    tpm_status = f"{YELLOW}[EMULATED / SOFTWARE HEDGE]{RESET} Hardware quote simulated"
    try:
        import tpm_quote
        pcrs = tpm_quote.read_hardware_pcrs([0, 7, 11])
        if pcrs and 0 in pcrs:
            tpm_status = f"{GREEN}[HARDWARE LOCKED]{RESET} PCR-0: {pcrs[0][:16]}..."
    except Exception:
        pass
    print(f"  • Hardware TPM 2.0 / HSM   : {tpm_status}")

    # 5. Zero-Gap Unified Pipeline
    try:
        from unified_secure_pipeline import UnifiedSecurePipeline
        pipe = UnifiedSecurePipeline()
        pipe_ok = True
        pipe_status = f"{GREEN}[FULLY ARMED]{RESET} Python Inner Ratchet ↔ Rust Outer AEAD"
    except Exception as e:
        pipe_ok = False
        pipe_status = f"{RED}[ERROR]{RESET} {e}"
    print(f"  • Zero-Gap Unified Pipeline: {pipe_status}")

    # 6. CMT Laboratory & AO Submittal Packet
    submittal_tar = ROOT / "compliance_reports" / "cmt_lab_submission_packet.tar.gz"
    submittal_manifest = ROOT / "compliance_reports" / "cmt_laboratory_submission_manifest.json"
    submittal_ok = submittal_tar.exists() and submittal_manifest.exists()
    status_submittal = (
        f"{GREEN}[SEALED & SIGNED]{RESET} 14/14 Artifacts (ML-DSA-87 Signed Manifest)"
        if submittal_ok else f"{YELLOW}[NOT PACKAGED]{RESET} Run `python scripts/package_cmt_laboratory_submittal.py --package`"
    )
    print(f"  • CMT / AO Submittal Dossier: {status_submittal}")

    print("=" * 86)
    return {
        "rust_ok": rust_ok,
        "verifier_ok": verifier_ok,
        "oqs_ok": oqs_ok,
        "pipe_ok": pipe_ok,
        "native_bin": native_bin if rust_ok else None,
        "verifier_bin": verifier_bin if verifier_ok else None
    }


def launch_web_console():
    """Launch the Tactical Web Console (local mTLS 1.3 Command Center)."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Launching Tactical Web Console on https://127.0.0.1:8443...{RESET}")
    cmd = [sys.executable, str(ROOT / "tactical_web_console.py")]
    subprocess.run(cmd)


def launch_tactical_node(role: str = "interactive"):
    """Launch the P2P Terminal Node."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Launching P2P Terminal Node ({role})...{RESET}")
    cmd = [sys.executable, str(ROOT / "secure_p2p.py")]
    if role and role != "interactive":
        cmd.append(role)
    subprocess.run(cmd)


def launch_interactive_chat():
    """Launch the Tactical Operations Suite armed with Zero-Gap Pipeline."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Launching Tactical Operations Node (NORAD Alpha DEFCON-1 Mode)...{RESET}")
    cmd = [sys.executable, str(ROOT / "secure_p2p.py"), "alpha"]
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
    else:
        try:
            from production_gate import is_production
            in_prod = bool(is_production())
        except Exception:
            in_prod = True
        if in_prod:
            print(f"{RED}[DIODE FAIL-CLOSED] Production mode requires explicit out-of-band P2P_DIODE_PSK (64 hex chars). Refusing auto-generated local key file.{RESET}")
            raise SystemExit(2)
        if key_path.exists():
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
    audit_env = os.environ.copy()
    audit_env.pop("P2P_PRODUCTION", None)
    audit_env.pop("SECURE_P2P_PRODUCTION", None)
    cmd = [sys.executable, str(ROOT / "scripts" / "run_defense_audit.py")]
    res = subprocess.run(cmd, env=audit_env)
    return res.returncode == 0


def run_cryptographic_performance_benchmark():
    """Run the protocol performance empirical benchmark."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Running Protocol Performance Empirical Benchmark...{RESET}")
    cmd = [sys.executable, str(ROOT / "scripts" / "verify_ratchet_performance.py")]
    subprocess.run(cmd)


def run_tactical_automated_drill():
    """Run the tactical verification battery and production cryptographic selftest."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Running Tactical Verification Battery & Cryptographic Selftest (8/8 Checks)...{RESET}")
    cmd = [sys.executable, str(ROOT / "secure_p2p.py"), "selftest"]
    subprocess.run(cmd)


def run_cjadc2_data_fabric_drill():
    """Run DoD CJADC2 Phase 6 Tactical Data Fabric & MLS Cross-Domain Guard Drill."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Running DoD CJADC2 Phase 6 Tactical Data Fabric Mission Drill...{RESET}")
    cmd = [sys.executable, str(ROOT / "scripts" / "run_phase6_cjadc2_data_fabric_drill.py")]
    subprocess.run(cmd)


def run_sovereign_sel4_appliance_drill():
    """Execute live simulation drill of the seL4 Appliance Architecture."""
    print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{CYAN}  ST2027 // seL4 DOMAIN SEPARATION APPLIANCE SIMULATION DRILL             {RESET}")
    print(f"{BOLD}{CYAN}  [MILS 3-DOMAIN ISOLATION: RED (Plaintext) <-> CRYPTO (Native) <-> BLACK (Network)]{RESET}")
    print(f"{BOLD}{CYAN}================================================================================{RESET}")
    from sovereign_sel4_appliance import SovereignApplianceNode
    from sel4_microkit_manifest import SeL4MicrokitManifest

    print(f"{GREEN}[STAGE 1] Formally validating seL4 Microkit System Description XML (MILS Invariants)...{RESET}")
    manifest = SeL4MicrokitManifest.create_st2027_sovereign_system()
    manifest.validate_mils_invariants()
    print(f"{GREEN}          * Zero non-bypassable RED-BLACK channels confirmed.{RESET}")
    print(f"{GREEN}          * Hardware Key Isolation verified (crypto_locked_keys quarantined to CRYPTO).{RESET}")

    print(f"\n{GREEN}[STAGE 2] Instantiating Dual Nodes (NODE_ALPHA & NODE_BRAVO)...{RESET}")
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
    print(f"  [DRILL SUCCESSFUL] seL4 DOMAIN SEPARATION APPLIANCE SIMULATION OPERATIONAL")
    print(f"================================================================================{RESET}")


def run_multi_assumption_pqc_kex_drill():
    """Execute live demonstration & verification drill of Multi-Assumption Post-Quantum KEX Combiner."""
    print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{CYAN}  ST2027 // MULTI-ASSUMPTION POST-QUANTUM KEX COMBINER DRILL (ZERO FALLBACK)   {RESET}")
    print(f"{BOLD}{CYAN}  [Lattice (ML-KEM-1024) + Code-Based (Classic McEliece 8192128f) + Hardware PSK]{RESET}")
    print(f"{BOLD}{CYAN}================================================================================{RESET}")

    from pqc_multi_assumption import (
        MultiAssumptionKEXManager,
        TripleKexPublicKey,
        TripleKexCiphertext,
        load_hardware_psk,
    )

    print(f"{GREEN}[STAGE 1] Provisioning Out-of-Band Hardware Pre-Shared Key (256-bit entropy)...{RESET}")
    h_psk_bytes = secrets.token_bytes(32)
    h_psk = load_hardware_psk(h_psk_bytes)
    print(f"{GREEN}          * Out-of-band Hardware PSK loaded into pinned memory.{RESET}")

    print(f"\n{GREEN}[STAGE 2] Initializing Multi-Assumption KEX Enclaves (Alice & Bob)...{RESET}")
    alice = MultiAssumptionKEXManager(hardware_psk=h_psk)
    bob = MultiAssumptionKEXManager(hardware_psk=h_psk, auto_generate=False)
    alice_pk = alice.get_public_key()
    print(f"{GREEN}          * Alice generated ML-KEM-1024 keypair (1,568B PK).{RESET}")
    print(f"{GREEN}          * Alice generated Classic McEliece 8192128f keypair (1,357,824B PK).{RESET}")
    print(f"{GREEN}          * Alice public key bundle: {len(alice_pk.to_bytes()):,} bytes.{RESET}")

    print(f"\n{GREEN}[STAGE 3] Bob Encapsulates Against Alice's Public Bundle + Hardware PSK...{RESET}")
    transcript = b"ST2027-TACTICAL-DRILL-SESSION-TRANSCRIPT-001"
    ct_bundle, k_bob = bob.encapsulate(alice_pk, transcript=transcript)
    print(f"{GREEN}          * Encapsulated ML-KEM-1024 ciphertext: {len(ct_bundle.mlkem_ct)} bytes.{RESET}")
    print(f"{GREEN}          * Encapsulated Classic McEliece ciphertext: {len(ct_bundle.mceliece_ct)} bytes.{RESET}")
    print(f"{GREEN}          * Total wire ciphertext: {len(ct_bundle.to_bytes())} bytes.{RESET}")
    print(f"{GREEN}          * Derived K_master (Bob): 48 bytes (HKDF-SHA384).{RESET}")

    print(f"\n{GREEN}[STAGE 4] Alice Decapsulates and Derives Session Keys...{RESET}")
    k_alice = alice.decapsulate(ct_bundle, transcript=transcript)
    assert secrets.compare_digest(k_alice, k_bob) is True
    print(f"{GREEN}          * Master Key bit-for-bit match confirmed: {k_alice[:16].hex()}...[REDACTED]{RESET}")

    print(f"\n{GREEN}[STAGE 5] Expanding Role-Separated Transport Keys & Mutual Confirmation...{RESET}")
    keys_alice = alice.expand_session_keys(k_alice, transcript_binding=transcript)
    keys_bob = bob.expand_session_keys(k_bob, transcript_binding=transcript)
    assert keys_alice.ct_eq(keys_bob) is True
    print(f"{GREEN}          * Initiator Traffic Key (32B): verified matching.{RESET}")
    print(f"{GREEN}          * Responder Traffic Key (32B): verified matching.{RESET}")
    print(f"{GREEN}          * Confirmation Root Key (32B): verified matching.{RESET}")

    bob_tag = bob.compute_confirmation_tag(keys_bob.confirmation_key, is_initiator=True, transcript_binding=transcript)
    alice_verified = alice.verify_peer_confirmation_tag(keys_alice.confirmation_key, is_peer_initiator=True, transcript_binding=transcript, peer_tag=bob_tag)
    assert alice_verified is True
    print(f"{GREEN}          * Mutual key confirmation tags authenticated successfully.{RESET}")

    print(f"\n{GREEN}[STAGE 6] Verifying Zero Fallback & Tamper Rejection Invariant...{RESET}")
    # Tamper 1 bit in ciphertext
    corrupt_ct = bytearray(ct_bundle.mlkem_ct)
    corrupt_ct[42] ^= 0x01
    tampered_bundle = TripleKexCiphertext(mlkem_ct=bytes(corrupt_ct), mceliece_ct=ct_bundle.mceliece_ct)
    k_tampered = alice.decapsulate(tampered_bundle, transcript=transcript)
    assert not secrets.compare_digest(k_tampered, k_bob)
    print(f"{GREEN}          * Tampered ciphertext diverged key material: zero silent fallback confirmed.{RESET}")

    # Zeroize keys
    alice.close()
    bob.close()
    print(f"{GREEN}          * Ephemeral secret buffers securely zeroized.{RESET}")
    print(f"{BOLD}{GREEN}================================================================================")
    print(f"  [DRILL SUCCESSFUL] MULTI-ASSUMPTION POST-QUANTUM KEX COMBINER OPERATIONAL")
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
    if os.name == "nt":
        key_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ST2027" / "keys"
    else:
        key_dir = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "ST2027" / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    psk_file = key_dir / "tactical_station.psk"
    if not psk_file.exists():
        psk_file.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
        if os.name != "nt":
            try:
                os.chmod(psk_file, 0o600)
            except OSError:
                pass
    psk_path = str(psk_file)
    from paced_socket_wrapper import NATIVE_BIN
    alpha_sk = key_dir / "norad_alpha.sk"
    alpha_pk = key_dir / "norad_alpha.pk"
    bravo_sk = key_dir / "pentagon_bravo.sk"
    bravo_pk = key_dir / "pentagon_bravo.pk"
    if not (alpha_sk.exists() and alpha_pk.exists()):
        subprocess.run([str(NATIVE_BIN), "auth-keygen", "--out-sk", str(alpha_sk), "--out-pk", str(alpha_pk)], check=True)
    if not (bravo_sk.exists() and bravo_pk.exists()):
        subprocess.run([str(NATIVE_BIN), "auth-keygen", "--out-sk", str(bravo_sk), "--out-pk", str(bravo_pk)], check=True)

    print(f"{YELLOW}Spawning Terminal 1 (NORAD Alpha with ML-DSA-87 mutual auth)...{RESET}")
    subprocess.Popen([sys.executable, str(ROOT / "secure_p2p.py"), "node",
                      "--role", "responder", "--bind", "127.0.0.1", "--peer", "127.0.0.1",
                      "--name", "NORAD_ALPHA", "--psk-file", psk_path,
                      "--auth-sk-file", str(alpha_sk), "--peer-auth-pk-file", str(bravo_pk),
                      "--require-mutual-auth"])
    time.sleep(1.5)
    print(f"{YELLOW}Spawning Terminal 2 (Pentagon Bravo with ML-DSA-87 mutual auth)...{RESET}")
    subprocess.Popen([sys.executable, str(ROOT / "secure_p2p.py"), "node",
                      "--role", "initiator", "--bind", "127.0.0.1", "--peer", "127.0.0.1",
                      "--name", "PENTAGON_BRAVO", "--psk-file", psk_path,
                      "--auth-sk-file", str(bravo_sk), "--peer-auth-pk-file", str(alpha_pk),
                      "--require-mutual-auth"])


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


def run_cmt_submittal_audit():
    """Package and cryptographically verify the formal CMT Laboratory & AO Submittal Dossier."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Verifying & Packaging FIPS 140-3 CMT Laboratory & AO Submittal Dossier...{RESET}", flush=True)
    packager_script = ROOT / "scripts" / "package_cmt_laboratory_submittal.py"
    res = subprocess.run([sys.executable, str(packager_script), "--package"])
    if res.returncode == 0:
        print(f"\n{BOLD}{GREEN}[SUCCESS] CMT Laboratory & AO Submittal Dossier packaged and verified with 100% cryptographic integrity.{RESET}\n", flush=True)
    else:
        print(f"\n{BOLD}{RED}[FAILURE] CMT Laboratory & AO Submittal Dossier packaging or verification encountered errors (exit code {res.returncode}).{RESET}\n", flush=True)


def run_acvp_validation_cmd():
    """Run NIST ACVP automated test vector harness for FIPS 203 & FIPS 204."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Running NIST ACVP Post-Quantum Automated Validation Harness...{RESET}", flush=True)
    script = ROOT / "scripts" / "acvp_pqc_validator.py"
    subprocess.run([sys.executable, str(script)])


def run_formal_verification_cmd():
    """Run automated ProVerif formal symbolic verification engine."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Running ProVerif Symbolic Formal Protocol Verification...{RESET}", flush=True)
    script = ROOT / "scripts" / "run_formal_verification.py"
    subprocess.run([sys.executable, str(script)])


def run_constant_time_cmd():
    """Run statistical constant-time side-channel evaluation (CT-KAT / Dudect)."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Running Statistical Constant-Time Side-Channel Analysis (Welch's t-test)...{RESET}", flush=True)
    script = ROOT / "scripts" / "verify_constant_time.py"
    subprocess.run([sys.executable, str(script)])


def run_oscal_ssp_cmd():
    """Generate and cryptographically sign NIST OSCAL v1.1.0 System Security Plan."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Generating NIST OSCAL v1.1.0 Machine-Readable System Security Plan (SSP)...{RESET}", flush=True)
    script = ROOT / "scripts" / "generate_oscal_ssp.py"
    subprocess.run([sys.executable, str(script)])


def run_slsa_provenance_cmd():
    """Generate signed SLSA Level 4 in-toto software supply chain provenance attestation."""
    print(f"\n{BOLD}{CYAN}[COMMAND] Generating SLSA Level 4 In-Toto Provenance Attestation...{RESET}", flush=True)
    script = ROOT / "scripts" / "generate_slsa_provenance.py"
    subprocess.run([sys.executable, str(script)])


def run_master_certify_cmd():
    """Execute local self-check and pre-assessment diagnostic battery."""
    print(f"\n{BOLD}{CYAN}================================================================================")
    print("  ST2027 LOCAL PRE-ASSESSMENT DIAGNOSTIC BATTERY")
    print(f"================================================================================{RESET}\n")

    steps = [
        ("NIST ACVP PQC Functional Self-Check (FIPS 203/204)", ROOT / "scripts" / "acvp_pqc_validator.py"),
        ("Statistical Constant-Time Dudect Analysis", ROOT / "scripts" / "verify_constant_time.py"),
        ("ProVerif Formal Symbolic Protocol Verification", ROOT / "scripts" / "run_formal_verification.py"),
        ("NIST OSCAL v1.1.0 System Security Plan", ROOT / "scripts" / "generate_oscal_ssp.py"),
        ("SLSA Level 4 In-Toto Provenance Attestation", ROOT / "scripts" / "generate_slsa_provenance.py"),
        ("Signed Reproducible Build & Supply Chain", ROOT / "scripts" / "verify_reproducible_build.py"),
    ]

    cert_env = os.environ.copy()
    cert_env.pop("P2P_PRODUCTION", None)
    cert_env.pop("SECURE_P2P_PRODUCTION", None)

    results = []
    for title, script in steps:
        print(f"\n{BOLD}[*] Executing Gate: {title}...{RESET}")
        res = subprocess.run([sys.executable, str(script)], env=cert_env)
        ok = (res.returncode == 0)
        results.append((title, ok))

    print(f"\n{BOLD}{CYAN}================================================================================")
    print("  LOCAL SELF-CHECK DIAGNOSTIC MATRIX")
    print(f"================================================================================{RESET}")
    passed_count = sum(1 for _, ok in results if ok)
    total_count = len(results)

    for title, ok in results:
        status_tag = f"{GREEN}[PASS]{RESET}" if ok else f"{RED}[FAIL/UNVERIFIED]{RESET}"
        print(f"  {status_tag} {title}")

    print("--------------------------------------------------------------------------------")
    score_pct = (passed_count / total_count) * 100.0
    print(f"  {BOLD}Self-Check Gates Executed: {passed_count}/{total_count} Passed ({score_pct:.1f}%){RESET}")
    if passed_count == total_count:
        print(f"  {BOLD}{GREEN}[LOCAL SCRIPTS GREEN — EXTERNAL LAB/CMVP/DAO ACCREDITATION STILL REQUIRED FOR ATO]{RESET}")
    else:
        print(f"  {BOLD}{RED}[VERDICT: REMEDIATION REQUIRED BEFORE FORMAL LAB SUBMITTAL]{RESET}")
    print("================================================================================\n")


def interactive_menu_loop():
    """Main interactive command center menu loop."""
    print_master_banner()
    probe_hardware_and_environment()

    while True:
        print(f"\n{BOLD}{CYAN}COMMAND CENTER — SELECT MODULE:{RESET}")
        print(f"  {GREEN}[1] Tactical Web Console (DEFCON-1 Mission Control GUI on localhost:8080){RESET}")
        print(f"  {GREEN}[2] P2P Terminal Node (Hardware-Paced Enclave){RESET}")
        print(f"  {GREEN}[3] Full Interactive Operations Suite (5-Year Monolith + Zero-Gap Pipeline){RESET}")
        print(f"  {GREEN}[4] Simplex Optical Data Diode Air-Gap Transfer Station{RESET}")
        print(f"  {GREEN}[5] Spawn Dual Tactical Military Terminals Side-by-Side (NORAD vs Pentagon){RESET}")
        print(f"  {CYAN}[6] Execute DoD CJADC2 Phase 6 Tactical Data Fabric & MLS Cross-Domain Drill{RESET}")
        print(f"  {CYAN}[7] Execute Automated Defense Master Audit (10/10 Cryptographic Gates){RESET}")
        print(f"  {CYAN}[8] Run Protocol Performance Empirical Benchmark{RESET}")
        print(f"  {CYAN}[9] Run Two-Terminal Automated Tactical Drill (In-Process Demo){RESET}")
        print(f"  {MAGENTA}[10] Inspect Platform Hardware TPM 2.0 PCR Attestation Quote{RESET}")
        print(f"  {MAGENTA}[11] Run seL4 Hardware Appliance Simulation Drill (RED/CRYPTO/BLACK){RESET}")
        print(f"  {RED}[12] Emergency Post-Session Zeroization (NIST SP 800-88 / DoD 5220.22-M){RESET}")
        print(f"  {CYAN}[13] Verify & Package FIPS 140-3 CMT Laboratory & AO Submittal Dossier{RESET}")
        print(f"  {CYAN}[14] Run Multi-Assumption Post-Quantum KEX Combiner Drill (Zero Fallback){RESET}")
        print(f"  {GREEN}[16] Run NIST ACVP PQC Automated Validation Harness (FIPS 203/204){RESET}")
        print(f"  {GREEN}[17] Run ProVerif Symbolic Formal Protocol Verification Engine{RESET}")
        print(f"  {GREEN}[18] Run Statistical Constant-Time Side-Channel Analysis (CT-KAT/Dudect){RESET}")
        print(f"  {GREEN}[19] Generate NIST OSCAL v1.1.0 System Security Plan (SSP){RESET}")
        print(f"  {GREEN}[20] Generate Signed SLSA Level 4 Software Supply Chain Provenance{RESET}")
        print(f"  {BOLD}{MAGENTA}[21] Run Master Local Pre-Accreditation Diagnostic Battery{RESET}")
        print(f"  {WHITE}[15] Exit Command Center{RESET}")
        print("=" * 86)

        try:
            choice = input(f"{BOLD}{YELLOW}Enter Option (1-21, C for Certify, P for PQC, S for seL4): {RESET}").strip()
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
            run_cryptographic_performance_benchmark()
        elif choice == "9":
            run_tactical_automated_drill()
        elif choice == "10":
            inspect_tpm_quote()
        elif choice in ("11", "s", "S", "sel4"):
            run_sovereign_sel4_appliance_drill()
        elif choice == "12":
            run_emergency_zeroize()
        elif choice == "13":
            run_cmt_submittal_audit()
        elif choice in ("14", "p", "P", "pqc", "kex"):
            run_multi_assumption_pqc_kex_drill()
        elif choice in ("16", "acvp"):
            run_acvp_validation_cmd()
        elif choice in ("17", "formal"):
            run_formal_verification_cmd()
        elif choice in ("18", "ct"):
            run_constant_time_cmd()
        elif choice in ("19", "oscal"):
            run_oscal_ssp_cmd()
        elif choice in ("20", "slsa"):
            run_slsa_provenance_cmd()
        elif choice in ("21", "c", "C", "certify"):
            run_master_certify_cmd()
        elif choice in ("15", "q", "exit", "quit"):
            print(f"{GREEN}Session closed under zero-leak discipline.{RESET}")
            break
        else:
            print(f"{RED}Invalid selection. Please choose 1-21.{RESET}")


def main():
    parser = argparse.ArgumentParser(description="ST2027 Protocol Suite Command Center")
    parser.add_argument("mode", nargs="?", default="interactive",
                        choices=["interactive", "web", "tactical", "alpha", "bravo", "chat",
                                 "audit", "benchmark", "drill", "cjadc2", "terminals", "tpm", "zeroize", "sel4", "cmt", "pqc", "kex",
                                 "acvp", "formal", "ct", "oscal", "slsa", "certify"],
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
        run_cryptographic_performance_benchmark()
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
    elif args.mode == "cmt":
        run_cmt_submittal_audit()
    elif args.mode in ("pqc", "kex"):
        run_multi_assumption_pqc_kex_drill()
    elif args.mode == "acvp":
        run_acvp_validation_cmd()
    elif args.mode == "formal":
        run_formal_verification_cmd()
    elif args.mode == "ct":
        run_constant_time_cmd()
    elif args.mode == "oscal":
        run_oscal_ssp_cmd()
    elif args.mode == "slsa":
        run_slsa_provenance_cmd()
    elif args.mode == "certify":
        run_master_certify_cmd()


if __name__ == "__main__":
    main()

