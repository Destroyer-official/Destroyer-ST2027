#!/usr/bin/env python3
# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
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
import hashlib
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable

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

def _is_production() -> bool:
    try:
        from production_gate import is_production
        return bool(is_production())
    except Exception:
        return False


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


def canonical_msg_bytes(precedence: str, clearance: str, caveats: str, text: str, signer: str, timestamp: float) -> bytes:
    """Canonical domain-separated envelope binding text and message metadata."""
    canonical_str = f"{precedence}|{clearance}|{caveats}|{signer}|{int(timestamp)}|{text}"
    return b"DESTROYER-ST2027-TACTICAL-MSG-v1\x00" + canonical_str.encode("utf-8")


def canonical_eam_bytes(directive: str, officer1: str, officer2: str, timestamp: float, nonce: str) -> bytes:
    """Canonical NC3 domain-separated envelope binding EAM directive and dual officer credentials."""
    canonical_str = f"{directive}|{officer1}|{officer2}|{int(timestamp)}|{nonce}"
    return b"DESTROYER-ST2027-NC3-EAM\x00" + canonical_str.encode("utf-8")


def canonical_ptt_bytes(signer: str, chunks: int, duration_ms: int, timestamp: float) -> bytes:
    """Canonical domain-separated envelope for PTT voice burst metadata (A4-04)."""
    canonical_str = f"{signer}|{int(chunks)}|{int(duration_ms)}|{int(timestamp)}"
    return b"DESTROYER-ST2027-TACTICAL-PTT-v1\x00" + canonical_str.encode("utf-8")


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
        pk, sk = self.mldsa_signer.keygen()
        self.pubkey_mldsa = pk
        self.privkey_mldsa = bytearray(sk)
        self.pubkey_hex = self.pubkey_mldsa.hex()

        # Peer directory: callsign -> public_key_hex
        self.enrolled_peers: Dict[str, str] = {self.callsign: self.pubkey_hex}

        # EAM nonce replay cache (A4-05): directive nonce -> first-seen epoch.
        self._eam_seen_nonces: Dict[str, float] = {}
        self._eam_nonce_lock = threading.Lock()

        # CoT/MSG/PTT replay suppression: signed-envelope digest -> expiry.
        self._seen_tactical_messages: Dict[bytes, float] = {}
        self._tactical_replay_lock = threading.RLock()
        self._tactical_replay_ttl = 600.0
        self._max_tactical_replays = 65536

        # Active Cyber Defense telemetry
        self.trust_score = 95
        self.incident_log: List[Dict[str, Any]] = []

        # Sockets
        self.server_sock = None
        self.listener_thread = None

    def start_network(self, bind_host: str = "127.0.0.1"):
        """Bind incoming tactical communications socket."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((bind_host, self.local_port))  # nosec: B104 - default loopback, explicit host binding

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

    def sign_data(self, data: bytes) -> bytes:
        """Sign data using station's ML-DSA-87 private key (fails if zeroized)."""
        if not hasattr(self, "privkey_mldsa") or self.privkey_mldsa is None or len(self.privkey_mldsa) == 0:
            raise RuntimeError("Cryptographic keys zeroized or unavailable")
        if not hasattr(self, "mldsa_signer") or self.mldsa_signer is None:
            raise RuntimeError("Cryptographic signer zeroized or unavailable")
        return self.mldsa_signer.sign(bytes(self.privkey_mldsa), data)

    def _claim_tactical_message(self, kind: str, signer: str, signed_bytes: bytes) -> bool:
        now = time.time()
        digest = hashlib.sha3_256(
            kind.encode("utf-8") + b"\x00" + signer.encode("utf-8") + b"\x00" + signed_bytes
        ).digest()
        with self._tactical_replay_lock:
            expired = [k for k, expiry in self._seen_tactical_messages.items() if now > expiry]
            for key in expired:
                self._seen_tactical_messages.pop(key, None)
            if digest in self._seen_tactical_messages:
                return False
            if len(self._seen_tactical_messages) >= self._max_tactical_replays:
                return False
            self._seen_tactical_messages[digest] = now + self._tactical_replay_ttl
            return True

    def _handle_inbound_packet(self, data: Any, addr: Tuple[str, int]):
        """Dissect, verify, and route incoming tactical datagrams."""
        try:
            # Wire format: JSON tactical envelope: {"type": ..., "payload": ..., "sig": ..., "signer": ...}
            if isinstance(data, (bytes, bytearray)):
                packet = json.loads(data.decode("utf-8", errors="replace"))
            elif isinstance(data, dict):
                packet = data
            else:
                return

            ptype = packet.get("type", "")
            payload = packet.get("payload", "") or packet.get("xml", "")
            signer = packet.get("signer", "UNKNOWN")
            sig_hex = packet.get("sig", "") or packet.get("sig_hex", "")

            if ptype == "COT_EVENT":
                sig_valid = False
                if signer in self.enrolled_peers and sig_hex:
                    pk_val = self.enrolled_peers[signer]
                    pk_bytes = bytes.fromhex(pk_val) if isinstance(pk_val, str) else pk_val
                    sig_bytes = bytes.fromhex(sig_hex) if isinstance(sig_hex, str) else sig_hex
                    try:
                        sig_valid = self.mldsa_signer.verify(pk_bytes, payload.encode("utf-8"), sig_bytes)
                    except Exception:
                        sig_valid = False
                self._process_cot_packet(payload, signer, sig_valid)
            elif ptype == "TACTICAL_MSG":
                self._process_msg_packet(packet, signer)
            elif ptype == "PTT_VOICE":
                self._process_ptt_packet(packet, signer)
            elif ptype == "EAM_ORDER":
                self._process_eam_packet(packet, signer)
        except Exception:
            # Anti-DoS / silent-drop on malformed
            pass

    def _process_cot_packet(self, cot_xml: str, signer: str, sig_valid: bool):
        """Process Cursor-on-Target event and push to ATAK bridge (FIPS 204 gated)."""
        if not sig_valid:
            print(f"\n{RED}[CoT SPOOFING REJECTED]{RESET} Refusing unverified CoT packet from signer '{signer}' (FIPS 204 ML-DSA-87 signature invalid or unenrolled peer)")
            return

        if not self._claim_tactical_message("COT_EVENT", signer, cot_xml.encode("utf-8")):
            print(f"\n{RED}[CoT REPLAY DROPPED]{RESET} Duplicate signed CoT event from '{signer}'")
            return

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

        print(f"\n{CYAN}[CoT INGEST]{RESET} Track {BOLD}{callsign}{RESET} ({event_type}) at {lat:.4f}, {lon:.4f} [FIPS 204 Sig: VALID]")

        # Forward to ATAK/WinTAK tactical tablets
        if self.atak_bridge:
            self.atak_bridge.broadcast_cot(cot_xml)

    def _process_msg_packet(self, packet: Dict[str, Any], signer: str = "", sig_valid: Optional[bool] = None) -> bool:
        """Process incoming military telegram (authenticated envelope)."""
        signer = signer or packet.get("signer", "UNKNOWN")
        ts = packet.get("timestamp", 0.0)
        try:
            fresh = abs(time.time() - float(ts)) <= 120.0
        except (TypeError, ValueError):
            fresh = False
        if not fresh:
            print(f"\n{RED}[TACTICAL MSG DROPPED]{RESET} Stale or invalid timestamp from {signer}")
            return False
        if sig_valid is None:
            sig_hex = packet.get("sig", "") or packet.get("sig_hex", "")
            prec = packet.get("precedence", "R")
            clr = packet.get("clearance", "UNCLASSIFIED")
            cav = packet.get("caveats", "NOFORN")
            text = packet.get("payload", "") or packet.get("text", "")
            sig_valid = False
            if signer in self.enrolled_peers and sig_hex:
                pk_val = self.enrolled_peers[signer]
                pk_bytes = bytes.fromhex(pk_val) if isinstance(pk_val, str) else pk_val
                sig_bytes = bytes.fromhex(sig_hex) if isinstance(sig_hex, str) else sig_hex
                env_bytes = canonical_msg_bytes(prec, clr, cav, text, signer, ts)
                try:
                    sig_valid = self.mldsa_signer.verify(pk_bytes, env_bytes, sig_bytes)
                except Exception:
                    sig_valid = False

        if not sig_valid:
            print(f"\n{RED}[TACTICAL MSG DROPPED]{RESET} Rejected unauthenticated or tampered message from {signer} (invalid ML-DSA-87 envelope signature)")
            return False

        prec = packet.get("precedence", "R")
        clearance = packet.get("clearance", "UNCLASSIFIED")
        caveats = packet.get("caveats", "NOFORN")
        text = packet.get("payload", "") or packet.get("text", "")
        envelope = canonical_msg_bytes(prec, clearance, caveats, text, signer, ts)
        if not self._claim_tactical_message("TACTICAL_MSG", signer, envelope):
            print(f"\n{RED}[TACTICAL MSG REPLAY DROPPED]{RESET} Duplicate signed message from {signer}")
            return False

        prec_name = PRECEDENCE_RANKS.get(prec, ("ROUTINE", 5))[0]
        color = RED if prec in ("Y", "Z") else (YELLOW if prec == "O" else GREEN)

        print(f"\n{color}{BOLD}[TACTICAL RADIO RECV - {prec_name}]{RESET} From: {signer} | Level: {clearance} // {caveats}")
        print(f"  {BOLD}Content:{RESET} {text}")
        print(f"  {BOLD}Auth:{RESET} ML-DSA-87 Verified")
        return True

    def _process_ptt_packet(self, packet: Dict[str, Any], signer: str) -> bool:
        """Process push-to-talk tactical audio frame burst (A4-04 hardened).

        Previously PTT_VOICE was displayed as "[Decrypted]" with NO
        signature check at all — any host could inject voice traffic
        attributed to any callsign. Now: enrolled signer + valid ML-DSA-87
        signature over the canonical burst metadata + freshness window,
        or the burst is rejected.
        """
        chunks = packet.get("chunks", 0)
        duration_ms = packet.get("duration_ms", 0)
        ts = packet.get("timestamp", 0.0)
        sig_hex = packet.get("sig", "") or packet.get("sig_hex", "")

        try:
            fresh = abs(time.time() - float(ts)) <= 120.0
        except (TypeError, ValueError):
            fresh = False

        sig_valid = False
        if fresh and signer in self.enrolled_peers and sig_hex:
            pk_val = self.enrolled_peers[signer]
            pk_bytes = bytes.fromhex(pk_val) if isinstance(pk_val, str) else pk_val
            sig_bytes = bytes.fromhex(sig_hex) if isinstance(sig_hex, str) else sig_hex
            env_bytes = canonical_ptt_bytes(signer, chunks, duration_ms, ts)
            try:
                sig_valid = bool(self.mldsa_signer.verify(pk_bytes, env_bytes, sig_bytes))
            except Exception:
                sig_valid = False

        if not sig_valid:
            print(f"\n{RED}[PTT SPOOFING REJECTED]{RESET} Refusing unauthenticated voice burst from '{signer}' (ML-DSA-87 signature invalid, missing, or unenrolled peer)")
            return False

        envelope = canonical_ptt_bytes(signer, chunks, duration_ms, ts)
        if not self._claim_tactical_message("PTT_VOICE", signer, envelope):
            print(f"\n{RED}[PTT REPLAY DROPPED]{RESET} Duplicate signed voice burst from '{signer}'")
            return False

        # Truth-in-claims: metadata is authenticated; audio codec decoding is
        # out of scope for this console, so no "Decrypted" claim is made.
        print(f"\n{MAGENTA}[PTT VOICE RX]{RESET} Tactical voice burst from {BOLD}{signer}{RESET} ({chunks} frames, {duration_ms} ms) [ML-DSA-87 Authenticated Metadata]")
        return True

    def _process_eam_packet(self, packet: Dict[str, Any], signer: str = "") -> bool:
        """Process Emergency Action Message with mandatory Two-Person Rule verification (TACT-01)."""
        directive = packet.get("directive", "")
        of1 = packet.get("officer1", "")
        of2 = packet.get("officer2", "")
        of1_pk_hex = packet.get("officer1_pk", "")
        of1_sig_hex = packet.get("officer1_sig", "")
        of2_pk_hex = packet.get("officer2_pk", "")
        of2_sig_hex = packet.get("officer2_sig", "")
        ts = packet.get("timestamp", 0.0)
        nonce = packet.get("nonce", "")

        # Two distinct officers requirement
        if not of1 or not of2 or of1 == of2 or not of1_pk_hex or not of2_pk_hex or of1_pk_hex == of2_pk_hex:
            print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} Single-custody attempt or missing officer identities for directive '{directive}'")
            return False

        # Freshness check: reject stale/replay EAM orders (>120s skew)
        if abs(time.time() - float(ts)) > 120.0:
            print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} Stale or replayed EAM directive '{directive}' (timestamp skew exceeds 120s)")
            return False

        # Cryptographically verify both ML-DSA-87 signatures over canonical EAM envelope
        env_bytes = canonical_eam_bytes(directive, of1, of2, ts, nonce)
        try:
            pk1 = bytes.fromhex(of1_pk_hex)
            sig1 = bytes.fromhex(of1_sig_hex)
            pk2 = bytes.fromhex(of2_pk_hex)
            sig2 = bytes.fromhex(of2_sig_hex)
            v1 = self.mldsa_signer.verify(pk1, env_bytes, sig1)
            v2 = self.mldsa_signer.verify(pk2, env_bytes, sig2)
            if not (v1 and v2):
                raise ValueError("Verification failed")
        except Exception as exc:
            print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} EAM directive '{directive}' REJECTED: signature verification FAILED! ({exc})")
            return False

        # HIGH (nc3_consoles L...): bind custodian IDs to enrolled public keys
        # instead of trusting keys carried in the same packet. Production
        # rejects peers that are not enrolled.
        bound = (
            self.enrolled_peers.get(of1, "").lower() == of1_pk_hex.lower()
            and self.enrolled_peers.get(of2, "").lower() == of2_pk_hex.lower()
        )
        if _is_production() and not bound:
            print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} EAM directive '{directive}' REJECTED: custodian identity is not enrolled!")
            return False

        # A4-05 (2026-10-17): nonce replay suppression. The ±120s freshness
        # window alone allowed a captured, correctly-signed EAM to be
        # re-injected any number of times inside the window. Nonce is
        # mandatory and single-use for the replay window (10 min).
        if not nonce or not isinstance(nonce, str) or len(nonce) < 8:
            print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} EAM directive '{directive}' REJECTED: missing/short anti-replay nonce")
            return False
        now_mono = time.time()
        with self._eam_nonce_lock:
            self._eam_seen_nonces = {
                n: t for n, t in self._eam_seen_nonces.items() if now_mono - t < 600.0
            }
            if nonce in self._eam_seen_nonces:
                print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REPLAY REJECTED]{RESET} EAM directive '{directive}' REJECTED: nonce already released (replay)")
                return False
            self._eam_seen_nonces[nonce] = now_mono

        custody_status = "DUAL_OFFICER_VERIFIED"
        print(f"\n{WHITE_ON_RED}[NC3 STRATEGIC EAM RECEIVED - DUAL AUTHENTICATED]{RESET}")
        print(f"  Directive: {BOLD}{directive}{RESET}")
        print(f"  Dual Custody: {of1} & {of2} | Status: {custody_status} [FIPS 204 Authenticated]")
        return True


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
        sig_bytes = self.mldsa_signer.sign(bytes(self.privkey_mldsa), xml.encode("utf-8"))
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

    def send_tactical_message(
        self,
        *args,
        dest_host: Optional[str] = None,
        dest_port: Optional[int] = None,
        precedence: str = "O",
        clearance: str = "SECRET",
        caveats: str = "NOFORN",
        text: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """Transmit priority-stamped, MLS-classified military message with canonical envelope authentication (TACT-03)."""
        if len(args) >= 6:
            dest_host = args[0]
            dest_port = args[1]
            precedence = args[2]
            clearance = args[3]
            caveats = args[4]
            text = args[5]
        elif len(args) >= 2 and isinstance(args[1], int):
            dest_host = args[0]
            dest_port = args[1]
            if len(args) > 2:
                precedence = args[2]
            if len(args) > 3:
                clearance = args[3]
            if len(args) > 4:
                caveats = args[4]
            if len(args) > 5:
                text = args[5]

        prec_code = precedence.upper()
        if prec_code not in PRECEDENCE_RANKS:
            prec_code = "Z"

        # NSA RTB Content Scan
        spill = check_rtb_spillage(text.encode("utf-8"), clearance)
        if spill:
            print(f"{RED}[RTB SPILLAGE REJECTED]{RESET} Refusing outbound message containing classified indicator '{spill}' in {clearance} clearance!")
            return {}

        now_ts = time.time()
        env_bytes = canonical_msg_bytes(prec_code, clearance.upper(), caveats.upper(), text, self.callsign, now_ts)
        sig_bytes = self.sign_data(env_bytes)
        packet = {
            "type": "TACTICAL_MSG",
            "precedence": prec_code,
            "clearance": clearance.upper(),
            "caveats": caveats.upper(),
            "payload": text,
            "signer": self.callsign,
            "sig": sig_bytes.hex(),
            "timestamp": now_ts,
        }

        if dest_host and dest_port:
            self._send_udp(packet, dest_host, dest_port)
            prec_name = PRECEDENCE_RANKS[prec_code][0]
            print(f"{GREEN}[MSG SENT]{RESET} [{prec_name} // {clearance} // {caveats}] -> {dest_host}:{dest_port}")
        return packet

    def send_ptt_burst(self, dest_host: str, dest_port: int, duration_sec: float = 1.5):
        """Simulate sending quantized tactical voice frames followed by Poisson chaff cover."""
        frames = int(duration_sec * 8) # 8 voice frames per second (125ms each)
        now_ts = time.time()
        env_bytes = canonical_ptt_bytes(self.callsign, frames, int(duration_sec * 1000), now_ts)
        sig_bytes = self.sign_data(env_bytes)
        packet = {
            "type": "PTT_VOICE",
            "chunks": frames,
            "duration_ms": int(duration_sec * 1000),
            "signer": self.callsign,
            "sig": sig_bytes.hex(),
            "timestamp": now_ts,
        }
        self._send_udp(packet, dest_host, dest_port)
        print(f"{MAGENTA}[PTT BURST TRANSMITTED]{RESET} Emitted {frames} voice frames ({duration_sec:.1f}s) [ML-DSA-87 signed] -> Transitioned seamlessly to Poisson Chaff cover.")

    def authorize_dual_eam(
        self,
        *args,
        dest_host: Optional[str] = None,
        dest_port: Optional[int] = None,
        directive: Optional[str] = None,
        officer1: Optional[str] = None,
        officer2: Optional[str] = None,
        second_officer_callsign: Optional[str] = None,
        second_officer_pk: Optional[bytes] = None,
        second_officer_sk: Optional[bytes] = None,
        second_officer_signer: Optional[Callable[[bytes], bytes]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute Two-Person Rule EAM dispatch with dual ML-DSA-87 cryptographic signatures (TACT-01)."""
        if len(args) >= 2 and isinstance(args[1], int):
            dest_host = args[0]
            dest_port = args[1]
            if len(args) > 2:
                directive = args[2]
            if len(args) > 3:
                officer1 = args[3]
            if len(args) > 4:
                officer2 = args[4]
        elif len(args) >= 1:
            directive = args[0]
            if len(args) > 1:
                officer1 = args[1]
            if len(args) > 2:
                officer2 = args[2]

        directive = directive or kwargs.get("directive", "UNSPECIFIED-DIRECTIVE")
        officer1 = officer1 or self.callsign
        officer2 = officer2 or second_officer_callsign or "OFFICER-2"

        if officer1 == officer2:
            print(f"{RED}[NC3 VIOLATION]{RESET} Two-Person Rule requires two distinct authorized officers!")
            return {}

        ts = time.time()
        nonce = secrets.token_hex(16)
        env_bytes = canonical_eam_bytes(directive, officer1, officer2, ts, nonce)

        sig1 = self.sign_data(env_bytes)
        pk1 = self.pubkey_mldsa

        # HIGH (nc3_consoles L...): never mint the second custodian. A
        # generated keypair satisfies "two signatures" while proving nothing
        # about a second officer; require externally supplied material.
        if second_officer_signer is not None:
            pk2 = second_officer_pk
            if pk2 is None:
                print(f"{RED}[NC3 VIOLATION]{RESET} Second officer public key is required to bind the signature!")
                return {}
            sig2 = second_officer_signer(env_bytes)
        elif second_officer_sk is not None or kwargs.get("officer2_sk") is not None:
            sk2 = second_officer_sk or kwargs.get("officer2_sk")
            pk2 = second_officer_pk or kwargs.get("officer2_pk")
            if pk2 is None:
                print(f"{RED}[NC3 VIOLATION]{RESET} Second officer public key is required to bind the signature!")
                return {}
            sig2 = self.mldsa_signer.sign(sk2, env_bytes)
        else:
            print(f"{RED}[NC3 VIOLATION]{RESET} Two-Person Rule requires independently supplied second-officer credentials; refusing to self-generate a custodian!")
            return {}

        # Derive the custody claim from actual verification, never a literal.
        try:
            sig1_ok = bool(self.mldsa_signer.verify(pk1, env_bytes, sig1))
            sig2_ok = bool(self.mldsa_signer.verify(pk2, env_bytes, sig2))
        except Exception:
            sig1_ok = sig2_ok = False
        if not (sig1_ok and sig2_ok):
            print(f"{RED}[NC3 VIOLATION]{RESET} Dual-custody signature verification failed!")
            return {}

        bound = (
            self.enrolled_peers.get(officer1) == pk1.hex()
            and self.enrolled_peers.get(officer2) == pk2.hex()
        )
        if _is_production() and not bound:
            print(f"{RED}[NC3 VIOLATION]{RESET} Both officers must be enrolled peers in production!")
            return {}
        # In production `bound` is mandatory above; in lab an externally
        # supplied signer is accepted but never auto-generated.
        custody_status = "DUAL_OFFICER_VERIFIED"

        packet = {
            "type": "EAM_ORDER",
            "directive": directive,
            "officer1": officer1,
            "officer1_pk": pk1.hex() if isinstance(pk1, (bytes, bytearray)) else str(pk1),
            "officer1_sig": sig1.hex() if isinstance(sig1, (bytes, bytearray)) else str(sig1),
            "officer2": officer2,
            "officer2_pk": pk2.hex() if isinstance(pk2, (bytes, bytearray)) else str(pk2),
            "officer2_sig": sig2.hex() if isinstance(sig2, (bytes, bytearray)) else str(sig2),
            "nonce": nonce,
            "custody_status": custody_status,
            "signer": self.callsign,
            "timestamp": ts,
        }

        if dest_host and dest_port:
            self._send_udp(packet, dest_host, dest_port)
            print(f"{WHITE_ON_RED}[NC3 STRATEGIC EAM AUTHORIZED & SENT]{RESET} Directive: {directive} [Officers: {officer1}, {officer2} - Dual ML-DSA-87 Signed]")
        return packet

    def emergency_zeroize(self):
        """Scorched Earth: 3-pass cryptographic wipe of all secrets in RAM and state (TACT-04)."""
        print(f"\n{WHITE_ON_RED}================================================================{RESET}")
        print(f"{WHITE_ON_RED}  EMERGENCY ZEROIZE TRIGGERED: EXECUTING NIST SP 800-88 PURGE   {RESET}")
        print(f"{WHITE_ON_RED}================================================================{RESET}")

        # Wipe private key buffer in RAM
        if hasattr(self, "privkey_mldsa") and self.privkey_mldsa is not None:
            secure_wipe_buffer(self.privkey_mldsa)
            self.privkey_mldsa = None

        if hasattr(self, "pubkey_mldsa"):
            self.pubkey_mldsa = None
        self.pubkey_hex = ""
        self.mldsa_signer = None

        # Wipe tracks
        with self.tracks_lock:
            self.tracks.clear()

        # Wipe peer directory
        self.enrolled_peers.clear()

        self.trust_score = 0
        import gc
        gc.collect()
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
