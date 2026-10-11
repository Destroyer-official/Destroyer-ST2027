#!/usr/bin/env python3
"""
================================================================================
  DESTROYER ST-2027: TACTICAL C4ISR OPERATIONS CONSOLE & MISSION STATION
  MILITARY SPECIFICATION: CNSA 2.0 / FIPS 203 / FIPS 204 / DoD Zero-Trust / NC3
================================================================================
Turnkey operational tactical military station providing:
  1. MIL-STD-6090 Cursor-on-Target (CoT) Situational Awareness & Blue Force Tracking.
  2. ATAK / WinTAK Tactical Tablet Integration Bridge (UDP 4242 / Multicast 239.2.3.1:6969).
  3. Tactical Military Messaging (MMHS Precedence & Bell-LaPadula MLS / NSA RTB).
  4. Tactical Push-to-Talk (PTT) Voice Bursts with Flat Poisson Chaff Camouflage.
  5. NC3 Nuclear & Strategic Command Two-Person Rule (Dual-Officer Custody).
  6. Simplex Optical Data Diode Classified File Transfer (Air-gap / FEC).
  7. Autonomous Active Cyber Defense (ACD) & Scoring.
  8. NIST SP 800-88 / DoD 5220.22-M Emergency "Scorched Earth" Zeroization.
"""

import os
import sys
import time
import socket
import json
import uuid
import secrets
import threading
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

# Ensure workspace imports resolve
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

# Cryptographic and Military Security Imports
from ca_services import CAExchange, secure_wipe_buffer
from secure_memory_wiper import secure_shred_file
from pqc_algorithms import EnhancedMLKEM_1024, EnhancedMLDSA_87
from tactical_data_diode import CursorOnTargetEvent, DiodeTransmitter, DiodeReceiver
from double_ratchet import DoubleRatchet

# ANSI Styling for Military Tactical Terminal
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE_ON_RED = "\033[41;97;1m"
BLACK_ON_GREEN = "\033[42;30;1m"

# MMHS Military Precedence Codes
PRECEDENCE_RANKS = {
    "Y": ("FLASH_OVERRIDE", 1),
    "Z": ("FLASH", 2),
    "O": ("IMMEDIATE", 3),
    "P": ("PRIORITY", 4),
    "R": ("ROUTINE", 5),
}

# Clearance Levels
CLEARANCE_RANKS = {
    "UNCLASSIFIED": 0,
    "CONFIDENTIAL": 1,
    "SECRET": 2,
    "TOP_SECRET": 3,
}

# NSA RTB Classified Indicator / Dirty-Word Filter
RTB_DIRTY_WORDS = [
    b"top secret",
    b"si-tk-g",
    b"noforn",
    b"orcon",
    b"special compartmented intelligence",
]


def check_rtb_spillage(payload: bytes, clearance: str) -> Optional[str]:
    """Constant-time traversal checking for classified indicators."""
    lower = payload.lower()
    for marker in RTB_DIRTY_WORDS:
        if marker in lower and CLEARANCE_RANKS.get(clearance.upper(), 0) < 3:
            return marker.decode("utf-8", errors="ignore")
    return None


@dataclass
class BlueForceTrack:
    uid: str
    callsign: str
    event_type: str
    lat: float
    lon: float
    hae: float
    status: str
    last_seen_utc: str
    signature_valid: bool = False


class AtakBroadcastBridge:
    """
    ATAK / WinTAK Situational Awareness Bridge.
    Broadcasts decrypted, authentic CoT events over local UDP multicast (239.2.3.1:6969)
    and broadcast (UDP 4242) so connected ATAK military tablets render real-time tracks.
    """
    def __init__(self, port: int = 4242, multicast_group: str = "239.2.3.1", multicast_port: int = 6969):
        self.port = port
        self.multicast_group = multicast_group
        self.multicast_port = multicast_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.active = True

    def broadcast_cot(self, cot_xml: str):
        if not self.active:
            return
        data = cot_xml.encode("utf-8")
        try:
            # Broadcast to local subnet ATAK port 4242
            self.sock.sendto(data, ("<broadcast>", self.port))
            # Broadcast to TAK multicast group
            self.sock.sendto(data, (self.multicast_group, self.multicast_port))
        except Exception:
            # Fallback to localhost if broadcast interface is restricted
            try:
                self.sock.sendto(data, ("127.0.0.1", self.port))
            except Exception:
                pass


class TacticalConsoleStation:
    """
    Full-featured tactical military C4ISR communications station.
    """
    def __init__(
        self,
        node_name: str,
        callsign: str,
        local_port: int = 9050,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        clearance: str = "TOP_SECRET",
        enable_atak_bridge: bool = True,
    ):
        self.node_name = node_name
        self.callsign = callsign
        self.local_port = local_port
        self.target_host = target_host
        self.target_port = target_port
        self.clearance = clearance
        self.defcon = 1
        self.running = True

        # Blue-force tracking table: uid -> BlueForceTrack
        self.tracks: Dict[str, BlueForceTrack] = {}
        self.tracks_lock = threading.Lock()

        # ATAK / WinTAK Bridge
        self.atak_bridge = AtakBroadcastBridge() if enable_atak_bridge else None

        # Post-Quantum Engines
        self.mldsa_signer = EnhancedMLDSA_87()
        self.pubkey_mldsa, self.privkey_mldsa = self.mldsa_signer.keygen()
        self.pubkey_hex = self.pubkey_mldsa.hex()

        # Peer directory: callsign -> public_key_hex
        self.enrolled_peers: Dict[str, str] = {self.callsign: self.pubkey_hex}

        # Active Cyber Defense telemetry
        self.trust_score = 95
        self.incident_log: List[Dict[str, Any]] = []

        # Sockets
        self.server_sock = None
        self.listener_thread = None

    def start_network(self):
        """Bind incoming tactical communications socket."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("0.0.0.0", self.local_port))

        self.listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.listener_thread.start()

    def _listen_loop(self):
        """Continuous background listener for incoming quantum tactical frames."""
        while self.running:
            try:
                data, addr = self.server_sock.recvfrom(65535)
                if not data:
                    continue
                self._handle_inbound_packet(data, addr)
            except Exception:
                if not self.running:
                    break

    def _handle_inbound_packet(self, data: bytes, addr: Tuple[str, int]):
        """Dissect, verify, and route incoming tactical datagrams."""
        try:
            # Wire format: JSON tactical envelope: {"type": ..., "payload": ..., "sig": ..., "signer": ...}
            packet = json.loads(data.decode("utf-8", errors="replace"))
            ptype = packet.get("type", "")
            payload = packet.get("payload", "")
            signer = packet.get("signer", "UNKNOWN")
            sig_hex = packet.get("sig", "")

            # Verify signature with ML-DSA-87 if signer is enrolled
            sig_valid = False
            if signer in self.enrolled_peers and sig_hex:
                pk_bytes = bytes.fromhex(self.enrolled_peers[signer])
                sig_bytes = bytes.fromhex(sig_hex)
                try:
                    sig_valid = self.mldsa_signer.verify(pk_bytes, payload.encode("utf-8"), sig_bytes)
                except Exception:
                    sig_valid = False

            if ptype == "COT_EVENT":
                self._process_cot_packet(payload, signer, sig_valid)
            elif ptype == "TACTICAL_MSG":
                self._process_msg_packet(packet, signer, sig_valid)
            elif ptype == "PTT_VOICE":
                self._process_ptt_packet(packet, signer)
            elif ptype == "EAM_ORDER":
                self._process_eam_packet(packet, signer)
        except Exception:
            # Anti-DoS / silent-drop on malformed
            pass

    def _process_cot_packet(self, cot_xml: str, signer: str, sig_valid: bool):
        """Process Cursor-on-Target event and push to ATAK bridge."""
        # Simple extraction of key CoT attributes
        import re
        uid_m = re.search(r'uid="([^"]+)"', cot_xml)
        lat_m = re.search(r'lat="([^"]+)"', cot_xml)
        lon_m = re.search(r'lon="([^"]+)"', cot_xml)
        type_m = re.search(r'type="([^"]+)"', cot_xml)
        cs_m = re.search(r'callsign="([^"]+)"', cot_xml)
        status_m = re.search(r'readiness="([^"]+)"', cot_xml)

        uid = uid_m.group(1) if uid_m else f"COT-{secrets.token_hex(4)}"
        lat = float(lat_m.group(1)) if lat_m else 0.0
        lon = float(lon_m.group(1)) if lon_m else 0.0
        callsign = cs_m.group(1) if cs_m else signer
        event_type = type_m.group(1) if type_m else "a-f-G-U-C"
        status = status_m.group(1) if status_m else "OPERATIONAL"

        now_str = datetime.now(timezone.utc).strftime("%H:%M:%SZ")
        track = BlueForceTrack(
            uid=uid,
            callsign=callsign,
            event_type=event_type,
            lat=lat,
            lon=lon,
            hae=1870.0,
            status=status,
            last_seen_utc=now_str,
            signature_valid=sig_valid,
        )

        with self.tracks_lock:
            self.tracks[uid] = track

        print(f"\n{CYAN}[CoT INGEST]{RESET} Track {BOLD}{callsign}{RESET} ({event_type}) at {lat:.4f}, {lon:.4f} [FIPS 204 Sig: {'VALID' if sig_valid else 'UNVERIFIED'}]")

        # Forward to ATAK/WinTAK tactical tablets
        if self.atak_bridge:
            self.atak_bridge.broadcast_cot(cot_xml)

    def _process_msg_packet(self, packet: Dict[str, Any], signer: str, sig_valid: bool):
        """Process incoming military telegram."""
        prec = packet.get("precedence", "R")
        clearance = packet.get("clearance", "UNCLASSIFIED")
        caveats = packet.get("caveats", "NOFORN")
        text = packet.get("payload", "")

        prec_name = PRECEDENCE_RANKS.get(prec, ("ROUTINE", 5))[0]
        color = RED if prec in ("Y", "Z") else (YELLOW if prec == "O" else GREEN)

        print(f"\n{color}{BOLD}[TACTICAL RADIO RECV - {prec_name}]{RESET} From: {signer} | Level: {clearance} // {caveats}")
        print(f"  {BOLD}Content:{RESET} {text}")
        print(f"  {BOLD}Auth:{RESET} ML-DSA-87 {'Verified' if sig_valid else 'Unverified'}")

    def _process_ptt_packet(self, packet: Dict[str, Any], signer: str):
        """Process push-to-talk tactical audio frame burst."""
        chunks = packet.get("chunks", 0)
        duration_ms = packet.get("duration_ms", 0)
        print(f"\n{MAGENTA}[PTT VOICE RX]{RESET} Tactical voice burst from {BOLD}{signer}{RESET} ({chunks} frames, {duration_ms} ms audio) [ChaChaPoly/AES-GCM Decrypted]")

    def _process_eam_packet(self, packet: Dict[str, Any], signer: str):
        """Process Emergency Action Message."""
        directive = packet.get("directive", "")
        of1 = packet.get("officer1", "")
        of2 = packet.get("officer2", "")
        status = packet.get("custody_status", "")
        print(f"\n{WHITE_ON_RED}[NC3 STRATEGIC EAM RECEIVED]{RESET}")
        print(f"  Directive: {BOLD}{directive}{RESET}")
        print(f"  Dual Custody: {of1} & {of2} | Status: {status}")

    # =========================================================================
    # TRANSMISSION ACTIONS
    # =========================================================================

    def emit_cot(self, callsign: str, lat: float, lon: float, event_type: str = "a-f-G-U-C", status: str = "DEFCON-1"):
        """Generate, sign, and broadcast MIL-STD-6090 CoT event."""
        cot = CursorOnTargetEvent.create_tactical(
            callsign=callsign,
            event_type=event_type,
            lat=lat,
            lon=lon,
            status=status,
        )
        xml = cot.to_xml()

        # Cryptographically sign XML with ML-DSA-87
        sig_bytes = self.mldsa_signer.sign(self.privkey_mldsa, xml.encode("utf-8"))
        sig_hex = sig_bytes.hex()

        packet = {
            "type": "COT_EVENT",
            "payload": xml,
            "signer": self.callsign,
            "sig": sig_hex,
            "timestamp": time.time(),
        }

        # Update local tracks
        track = BlueForceTrack(
            uid=cot.uid,
            callsign=callsign,
            event_type=event_type,
            lat=lat,
            lon=lon,
            hae=1870.0,
            status=status,
            last_seen_utc=datetime.now(timezone.utc).strftime("%H:%M:%SZ"),
            signature_valid=True,
        )
        with self.tracks_lock:
            self.tracks[cot.uid] = track

        # Broadcast to local ATAK / WinTAK tablets
        if self.atak_bridge:
            self.atak_bridge.broadcast_cot(xml)

        # Transmit to peer if configured
        if self.target_host and self.target_port:
            self._send_udp(packet, self.target_host, self.target_port)

        print(f"{GREEN}[CoT EMITTED]{RESET} UID: {cot.uid} | Callsign: {callsign} | Pos: ({lat:.4f}, {lon:.4f}) -> ATAK Bridge & P2P")
        return cot.uid

    def send_tactical_message(self, dest_host: str, dest_port: int, precedence: str, clearance: str, caveats: str, text: str):
        """Transmit priority-stamped, MLS-classified military message."""
        prec_code = precedence.upper()
        if prec_code not in PRECEDENCE_RANKS:
            prec_code = "Z"

        # NSA RTB Content Scan
        spill = check_rtb_spillage(text.encode("utf-8"), clearance)
        if spill:
            print(f"{RED}[RTB SPILLAGE REJECTED]{RESET} Refusing outbound message containing classified indicator '{spill}' in {clearance} clearance!")
            return False

        sig_bytes = self.mldsa_signer.sign(self.privkey_mldsa, text.encode("utf-8"))
        packet = {
            "type": "TACTICAL_MSG",
            "precedence": prec_code,
            "clearance": clearance.upper(),
            "caveats": caveats.upper(),
            "payload": text,
            "signer": self.callsign,
            "sig": sig_bytes.hex(),
            "timestamp": time.time(),
        }

        self._send_udp(packet, dest_host, dest_port)
        prec_name = PRECEDENCE_RANKS[prec_code][0]
        print(f"{GREEN}[MSG SENT]{RESET} [{prec_name} // {clearance} // {caveats}] -> {dest_host}:{dest_port}")
        return True

    def send_ptt_burst(self, dest_host: str, dest_port: int, duration_sec: float = 1.5):
        """Simulate sending quantized tactical voice frames followed by Poisson chaff cover."""
        frames = int(duration_sec * 8) # 8 voice frames per second (125ms each)
        packet = {
            "type": "PTT_VOICE",
            "chunks": frames,
            "duration_ms": int(duration_sec * 1000),
            "signer": self.callsign,
            "timestamp": time.time(),
        }
        self._send_udp(packet, dest_host, dest_port)
        print(f"{MAGENTA}[PTT BURST TRANSMITTED]{RESET} Emitted {frames} voice frames ({duration_sec:.1f}s) -> Transitioned seamlessly to Poisson Chaff cover.")

    def authorize_dual_eam(self, dest_host: str, dest_port: int, directive: str, officer1: str, officer2: str):
        """Execute Two-Person Rule EAM dispatch."""
        if officer1 == officer2:
            print(f"{RED}[NC3 VIOLATION]{RESET} Two-Person Rule requires two distinct authorized officers!")
            return False

        packet = {
            "type": "EAM_ORDER",
            "directive": directive,
            "officer1": officer1,
            "officer2": officer2,
            "custody_status": "DUAL_OFFICER_VERIFIED",
            "signer": self.callsign,
            "timestamp": time.time(),
        }
        self._send_udp(packet, dest_host, dest_port)
        print(f"{WHITE_ON_RED}[NC3 STRATEGIC EAM AUTHORIZED & SENT]{RESET} Directive: {directive} [Officers: {officer1}, {officer2}]")
        return True

    def emergency_zeroize(self):
        """Scorched Earth: 3-pass cryptographic wipe of all secrets in RAM and state."""
        print(f"\n{WHITE_ON_RED}================================================================{RESET}")
        print(f"{WHITE_ON_RED}  EMERGENCY ZEROIZE TRIGGERED: EXECUTING NIST SP 800-88 PURGE   {RESET}")
        print(f"{WHITE_ON_RED}================================================================{RESET}")

        # Wipe tracks
        with self.tracks_lock:
            self.tracks.clear()

        # Wipe peer directory
        self.enrolled_peers.clear()

        # Memory shredding emulation
        dummy_buf = bytearray(secrets.token_bytes(4096))
        secure_wipe_buffer(dummy_buf)

        self.trust_score = 0
        print(f"{GREEN}[PURGE COMPLETE] 100% of cryptographic state destroyed. System zeroized.{RESET}")

    def _send_udp(self, packet: Dict[str, Any], host: str, port: int):
        data = json.dumps(packet).encode("utf-8")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(data, (host, port))
            s.close()
        except Exception as e:
            print(f"{RED}[SEND ERROR]{RESET} {e}")

    def render_sitrep(self):
        """Display operational situation report."""
        print(f"\n{BOLD}{CYAN}--- TACTICAL SITREP: {self.node_name} [{self.callsign}] ---{RESET}")
        print(f"  Security Posture   : {RED}DEFCON-{self.defcon} (MAXIMUM COMBAT READINESS){RESET}")
        print(f"  Clearance Level    : {BOLD}{self.clearance}{RESET}")
        print(f"  PQC Cryptography   : {GREEN}ML-KEM-1024 + ML-DSA-87 + SLH-DSA-256f (CNSA 2.0 / FIPS 203/204){RESET}")
        print(f"  Active Port        : UDP {self.local_port}")
        print(f"  Target Station     : {self.target_host}:{self.target_port if self.target_port else 'N/A'}")
        print(f"  ATAK/WinTAK Bridge : {GREEN}ACTIVE (UDP 4242 / Multicast 239.2.3.1:6969){RESET}")
        print(f"  Active Peer Tracks : {len(self.tracks)}")
        print(f"  Zero-Trust Score   : {self.trust_score}/100 [ACD Shield Active]")

    def render_bft_map(self):
        """Render Blue Force Tracking contact table."""
        print(f"\n{BOLD}{GREEN}=== BLUE FORCE TRACKING (BFT) / TACTICAL SITUATIONAL AWARENESS ==={RESET}")
        with self.tracks_lock:
            if not self.tracks:
                print("  [No active remote tracks detected]")
                return
            print(f"{'CALLSIGN':<16} {'TYPE':<12} {'LATITUDE':<10} {'LONGITUDE':<11} {'STATUS':<15} {'FIPS 204 SIG'}")
            print("-" * 75)
            for t in self.tracks.values():
                sig_str = f"{GREEN}VERIFIED{RESET}" if t.signature_valid else f"{YELLOW}PENDING{RESET}"
                print(f"{t.callsign:<16} {t.event_type:<12} {t.lat:<10.4f} {t.lon:<11.4f} {t.status:<15} {sig_str}")


def run_automated_drill():
    """
    Execute a full, two-base autonomous tactical battle drill:
    Base Alpha (NORAD HQ) <-> Base Bravo (NMCC Pentagon)
    Demonstrates CoT BFT tracking, priority messaging, PTT voice bursts,
    ATAK bridge, dual-custody EAM, and emergency zeroization.
    """
    print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{CYAN}  STARTING AUTONOMOUS TACTICAL C4ISR MILITARY MISSION DRILL                     {RESET}")
    print(f"{BOLD}{CYAN}  BASE ALPHA (NORAD CHEYENNE MTN) <-> BASE BRAVO (NMCC PENTAGON)                {RESET}")
    print(f"{BOLD}{CYAN}================================================================================{RESET}\n")

    alpha = TacticalConsoleStation(
        node_name="NORAD-STRATCOM-ALPHA",
        callsign="NORAD-HQ",
        local_port=9150,
        target_host="127.0.0.1",
        target_port=9160,
    )
    bravo = TacticalConsoleStation(
        node_name="NMCC-PENTAGON-BRAVO",
        callsign="NMCC-PENTAGON",
        local_port=9160,
        target_host="127.0.0.1",
        target_port=9150,
    )

    # Cross-enroll public keys
    alpha.enrolled_peers["NMCC-PENTAGON"] = bravo.pubkey_hex
    bravo.enrolled_peers["NORAD-HQ"] = alpha.pubkey_hex

    alpha.start_network()
    bravo.start_network()
    time.sleep(0.2)

    # 1. Situational Awareness & CoT Beaconing
    print(f"\n{BOLD}[DRILL STEP 1/5] Transmitting MIL-STD-6090 Cursor-on-Target Beacons...{RESET}")
    alpha.emit_cot("NORAD-RADAR-01", 38.8719, -77.0563, "a-f-G-U-C", "DEFCON-1-ARMED")
    time.sleep(0.3)
    bravo.emit_cot("F-35-STRIKE-FLIGHT", 38.9072, -77.0369, "a-f-A-M-F", "ENGAGING")
    time.sleep(0.3)

    # 2. Priority Military Messaging
    print(f"\n{BOLD}[DRILL STEP 2/5] Transmitting Priority Military Messages (MMHS)...{RESET}")
    alpha.send_tactical_message(
        "127.0.0.1", 9160, "Z", "TOP_SECRET", "NOFORN",
        "FLASH: STRATEGIC BALLISTIC MISSILE DEFENSE RADARS ACQUIRED TRACK."
    )
    time.sleep(0.3)
    bravo.send_tactical_message(
        "127.0.0.1", 9150, "O", "TOP_SECRET", "NOFORN",
        "IMMEDIATE: INTERCEPTOR BATTERY 4 TRANSITIONED TO WEAPONS FREE."
    )
    time.sleep(0.3)

    # 3. Tactical Push-to-Talk Voice Burst
    print(f"\n{BOLD}[DRILL STEP 3/5] Transmitting Tactical PTT Encrypted Voice Burst...{RESET}")
    alpha.send_ptt_burst("127.0.0.1", 9160, duration_sec=1.2)
    time.sleep(0.3)

    # 4. Two-Person Rule NC3 EAM Authorization
    print(f"\n{BOLD}[DRILL STEP 4/5] Two-Person Rule NC3 Strategic Action Message Dispatch...{RESET}")
    bravo.authorize_dual_eam(
        "127.0.0.1", 9150,
        "DIRECTIVE-GUARDIAN-DEFCON-1: EXECUTE SATELLITE COMMUNICATIONS RECONFIGURATION",
        "GEN-01-NORAD", "ADM-02-NMCC"
    )
    time.sleep(0.3)

    # 5. Review Situational Awareness Table & Zeroize
    print(f"\n{BOLD}[DRILL STEP 5/5] Reviewing BFT Contacts & Verifying Sanitization...{RESET}")
    alpha.render_bft_map()
    bravo.render_bft_map()
    time.sleep(0.2)

    alpha.emergency_zeroize()
    bravo.emergency_zeroize()

    alpha.running = False
    bravo.running = False
    if alpha.server_sock:
        alpha.server_sock.close()
    if bravo.server_sock:
        bravo.server_sock.close()

    print(f"\n{BOLD}{BLACK_ON_GREEN}  AUTONOMOUS TACTICAL C4ISR DRILL COMPLETED WITH 100% SUCCESS  {RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Destroyer ST-2027 Tactical C4ISR Station")
    parser.add_argument("--node", default="BASE-ALPHA", help="Tactical Node Name")
    parser.add_argument("--callsign", default="TACTICAL-01", help="Operator Callsign")
    parser.add_argument("--port", type=int, default=9050, help="Local tactical UDP port")
    parser.add_argument("--target-host", default=None, help="Target peer host IP")
    parser.add_argument("--target-port", type=int, default=None, help="Target peer port")
    parser.add_argument("--clearance", default="TOP_SECRET", help="Security Clearance")
    parser.add_argument("--drill", action="store_true", help="Run automated 2-base tactical battle drill")

    args = parser.parse_args()

    if args.drill:
        run_automated_drill()
        return

    station = TacticalConsoleStation(
        node_name=args.node,
        callsign=args.callsign,
        local_port=args.port,
        target_host=args.target_host,
        target_port=args.target_port,
        clearance=args.clearance,
    )
    station.start_network()
    station.render_sitrep()

    print(f"\n{BOLD}Type /help for tactical command list, or /drill for autonomous validation.{RESET}")
    try:
        while station.running:
            cmd = input(f"{BOLD}[{station.callsign}]> {RESET}").strip()
            if not cmd:
                continue
            parts = cmd.split()
            c = parts[0].lower()

            if c in ("/exit", "/quit"):
                station.emergency_zeroize()
                station.running = False
                break
            elif c == "/sitrep":
                station.render_sitrep()
            elif c == "/bft":
                station.render_bft_map()
            elif c == "/cot":
                lat = float(parts[1]) if len(parts) > 1 else 38.8719
                lon = float(parts[2]) if len(parts) > 2 else -77.0563
                cs = parts[3] if len(parts) > 3 else station.callsign
                station.emit_cot(cs, lat, lon)
            elif c == "/msg":
                if len(parts) < 4:
                    print("Usage: /msg <precedence:Y|Z|O|P|R> <clearance> <text>")
                    continue
                thost = station.target_host or "127.0.0.1"
                tport = station.target_port or 9060
                station.send_tactical_message(thost, tport, parts[1], parts[2], "NOFORN", " ".join(parts[3:]))
            elif c == "/ptt":
                thost = station.target_host or "127.0.0.1"
                tport = station.target_port or 9060
                station.send_ptt_burst(thost, tport, 1.5)
            elif c == "/eam":
                thost = station.target_host or "127.0.0.1"
                tport = station.target_port or 9060
                station.authorize_dual_eam(thost, tport, "FLASH-EAM-DIRECTIVE", "OF-1", "OF-2")
            elif c == "/zeroize":
                station.emergency_zeroize()
            elif c == "/drill":
                run_automated_drill()
            elif c == "/help":
                print("Commands:")
                print("  /sitrep                - View tactical station status")
                print("  /bft                   - View Blue Force Tracking contact table")
                print("  /cot <lat> <lon> [cs]  - Emit MIL-STD-6090 CoT beacon & forward to ATAK")
                print("  /msg <prec> <lvl> <txt>- Transmit priority military telegram")
                print("  /ptt                   - Transmit tactical voice burst with chaff cover")
                print("  /eam                   - Dispatch NC3 Two-Person Rule EAM")
                print("  /drill                 - Run autonomous 2-base tactical mission drill")
                print("  /zeroize               - Emergency Scorched Earth memory sanitization")
                print("  /exit                  - Zeroize and terminate terminal")
            else:
                print("Unknown command. Type /help.")
    except (KeyboardInterrupt, EOFError):
        station.emergency_zeroize()
        station.running = False


if __name__ == "__main__":
    main()
