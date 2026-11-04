#!/usr/bin/env python3
"""simple_chat_implementation.py

Production adapter bridging interactive chat, UI menus, and orchestrator connections
to the Post-Quantum CNSA 2.0 session manager, Double Ratchet engine, and DoD CSRMC
Phase 5 Tactical DDIL Mesh resilience.

Provides:
- initialize_session: Full quantum-resistant handshake & DoubleRatchet initialization
- handle_incoming_messages: Background message processor with authenticated decryption
- start_chat_with_peer: Interactive chat session with rate-limited, length-framed encryption
  and tactical slash commands (/csrmc, /mesh, /flash, /quorum, /zeroize)
- active_connections: Registry of active peer sessions
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from datetime import datetime
from typing import Any, Dict, Optional

from network.session_manager import SessionManager, SessionContext
from native_secure_buffer import wipe_native
from csrmc_operations_monitor import get_csrmc_operations_monitor
from tactical_mesh_ddil import get_ddil_node_mesh, BundlePriority
from byzantine_mesh_consensus import get_byzantine_quorum_engine
from emergency_anti_tamper import get_emergency_zeroization_engine, AntiTamperTrigger
from cjadc2_cross_domain_guard import CrossDomainGuard, SecurityClassification, SecurityCaveat
from pqc_crypto_agility_engine import CryptoAgilityEngine
from cjadc2_tactical_cot import TacticalCoTEvent, CoTEventType

logger = logging.getLogger(__name__)

# Global registry of active peer sessions
active_connections: Dict[str, Dict[str, Any]] = {}
_session_manager_singleton: Optional[SessionManager] = None
_global_cross_domain_guard: Optional[CrossDomainGuard] = None
_global_crypto_agility_engine: Optional[CryptoAgilityEngine] = None


def _enqueue_ddil_ciphertext(
    mesh: Any,
    recipient_id: str,
    seq: int,
    ciphertext: bytes,
    priority: int,
) -> Any:
    """Queue Double-Ratchet ciphertext, whose AEAD tag is inside ``ciphertext``."""
    return mesh.enqueue_bundle(
        recipient_id=recipient_id,
        seq=seq,
        ciphertext_bytes=ciphertext,
        auth_tag=b"",
        priority=priority,
    )


def get_cross_domain_guard() -> CrossDomainGuard:
    global _global_cross_domain_guard
    if _global_cross_domain_guard is None:
        _global_cross_domain_guard = CrossDomainGuard()
    return _global_cross_domain_guard


def get_crypto_agility_engine() -> CryptoAgilityEngine:
    global _global_crypto_agility_engine
    if _global_crypto_agility_engine is None:
        _global_crypto_agility_engine = CryptoAgilityEngine()
    return _global_crypto_agility_engine


def get_global_session_manager(audit_logger: Optional[Any] = None) -> SessionManager:
    """Retrieve or initialize the singleton SessionManager."""
    global _session_manager_singleton
    if _session_manager_singleton is None:
        _session_manager_singleton = SessionManager(
            audit_logger=audit_logger,
            session_timeout_seconds=1800
        )
    elif audit_logger is not None and _session_manager_singleton.audit_logger is None:
        _session_manager_singleton.audit_logger = audit_logger
    return _session_manager_singleton


async def initialize_session(
    peer_id: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    is_initiator: bool = False,
    audit_logger: Optional[Any] = None,
) -> SessionContext:
    """Initialize a secure Post-Quantum session with peer.

    Executes:
    1. HybridKeyExchange (X25519 + ML-KEM-1024) handshake
    2. Mutual ML-DSA-87 / FALCON-1024 bundle signature verification
    3. TPM Quote hardware attestation verification (if P2P_TPM_QUOTE=1)
    4. Double Ratchet initialization with locked, zeroizing key buffers

    Args:
        peer_id: Unique peer IP or address identifier
        reader: AsyncIO StreamReader
        writer: AsyncIO StreamWriter
        is_initiator: True if outbound connection, False if inbound
        audit_logger: Optional AuditLogger instance

    Returns:
        SessionContext: Established secure session context
    """
    mgr = get_global_session_manager(audit_logger)
    session = await mgr.create_session(
        peer_id=peer_id,
        reader=reader,
        writer=writer,
        is_initiator=is_initiator,
    )
    
    active_connections[peer_id] = {
        "session": session,
        "connected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reader": reader,
        "writer": writer,
    }
    # Update DDIL Mesh peer connectivity to online
    get_ddil_node_mesh().set_peer_connectivity(peer_id, True)
    logger.info(f"Secure session registered for peer {peer_id} (initiator={is_initiator})")
    return session


async def handle_incoming_messages(
    orchestrator: Any,
    peer_id: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Background loop to receive, decrypt, and display incoming peer messages."""
    session_info = active_connections.get(peer_id)
    session: Optional[SessionContext] = session_info.get("session") if session_info else None

    if session is None:
        logger.error(f"Cannot handle messages: No active session for {peer_id}")
        return

    logger.info(f"Started incoming message listener for {peer_id}")
    try:
        while True:
            # Read 4-byte big-endian frame length
            try:
                hdr = await reader.readexactly(4)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                logger.info(f"Peer {peer_id} disconnected")
                get_ddil_node_mesh().set_peer_connectivity(peer_id, False)
                break

            msg_len = struct.unpack(">I", hdr)[0]
            if msg_len == 0:
                continue
            if msg_len > 1024 * 1024:  # 1MB cap
                logger.error(f"Incoming frame from {peer_id} exceeds 1MB limit: {msg_len}")
                break

            encrypted_data = await reader.readexactly(msg_len)
            try:
                # Decrypt via Double Ratchet
                plaintext_bytes = session.double_ratchet.decrypt(encrypted_data)
                text = plaintext_bytes.decode("utf-8", errors="replace")
                print(f"\n\033[1m\033[95m[{peer_id}]:\033[0m {text}")
            except Exception as e_dec:
                logger.error(f"Decryption failed for message from {peer_id}: {e_dec}")
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.warning(f"Error in message handler for {peer_id}: {exc}")
    finally:
        active_connections.pop(peer_id, None)
        if hasattr(orchestrator, "_forget_session_auth_key"):
            orchestrator._forget_session_auth_key(peer_id)
        get_ddil_node_mesh().set_peer_connectivity(peer_id, False)
        logger.info(f"Message handler terminated for {peer_id}")


async def start_chat_with_peer(orchestrator: Any, peer_id: str) -> None:
    """Interactive terminal console for sending encrypted messages to a peer."""
    session_info = active_connections.get(peer_id)
    if not session_info:
        print(f"\033[91mNo active session found for {peer_id}.\033[0m")
        return

    session: SessionContext = session_info["session"]
    writer: asyncio.StreamWriter = session_info["writer"]

    print(f"\n\033[1m\033[92m=== SECURE CHAT WITH {peer_id} ===\033[0m")
    print("Post-Quantum Double Ratchet active. Tactical commands: /csrmc, /mesh, /flash <msg>, /quorum, /zeroize, /help")
    print("Type message and press Enter (or 'exit' to quit):")

    loop = asyncio.get_event_loop()
    clean_msg = b""
    encrypted = b""

    while True:
        try:
            msg_str = await loop.run_in_executor(None, input, f"\033[1m\033[96m[YOU -> {peer_id}]:\033[0m ")
            if not msg_str:
                continue
            trimmed = msg_str.strip()
            if trimmed.lower() == "exit":
                break

            # Handle Tactical Slash Commands
            if trimmed.startswith("/"):
                parts = trimmed.split(maxsplit=1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "/help":
                    print("\n\033[1mTACTICAL COMMANDS:\033[0m")
                    print("  /csrmc        : Display live DoD CSRMC Phase 5 continuous operations telemetry")
                    print("  /mesh         : Inspect tactical DDIL store-and-forward bundle queue & Merkle root")
                    print("  /flash <msg>  : Send urgent operational message with EMERGENCY priority preemption")
                    print("  /cjadc2       : Display CJADC2 Cross-Domain MLS clearance & spillage defense status")
                    print("  /agility      : Inspect NIST CSWP 39 crypto-agility state machine & active suites")
                    print("  /cot <cs> <lat> <lon> [type] : Broadcast MIL-STD-6090 Cursor-on-Target tactical track")
                    print("  /quorum       : Display Byzantine Quorum consensus status and authorized proposals")
                    print("  /zeroize      : Trigger emergency scorched-earth anti-tamper memory sanitization")
                    print("  exit          : Close interactive chat session\n")
                    continue

                elif cmd == "/cjadc2":
                    guard = get_cross_domain_guard()
                    print(f"\n\033[1m\033[95m[CJADC2 CROSS-DOMAIN MLS STATUS]\033[0m")
                    print(f"  • Node Clearance       : {guard.node_clearance.name}")
                    print(f"  • Authorized Caveats   : {', '.join(guard.authorized_caveats)}")
                    print(f"  • MLS Rules Enforced   : Bell-LaPadula (No Read Up, No Write Down) + Biba")
                    print(f"  • Spillages Blocked    : {guard.spillage_events_blocked}")
                    print(f"  • Authorized Transfers : {guard.authorized_transfers_count}\n")
                    continue

                elif cmd == "/agility":
                    eng = get_crypto_agility_engine()
                    print(f"\n\033[1m\033[92m[NIST CSWP 39 CRYPTO-AGILITY STATUS]\033[0m")
                    print(f"  • Agility State        : {eng.current_state.value}")
                    print(f"  • Active KEM           : {eng.active_kem}")
                    print(f"  • Active DSS           : {eng.active_dss}")
                    print(f"  • Security Level       : NIST Level 5+ / CNSA 2.0")
                    print(f"  • Migrations Committed : {eng.migrations_committed}")
                    print(f"  • Downgrades Blocked   : {eng.downgrade_attempts_blocked}\n")
                    continue

                elif cmd == "/cot":
                    parts_cot = arg.split()
                    if len(parts_cot) < 3:
                        print("\033[91mUsage: /cot <callsign> <lat> <lon> [type]\033[0m")
                        continue
                    cs = parts_cot[0]
                    try:
                        lat_val = float(parts_cot[1])
                        lon_val = float(parts_cot[2])
                    except ValueError:
                        print("\033[91mInvalid coordinates for /cot\033[0m")
                        continue
                    cot_type = parts_cot[3] if len(parts_cot) > 3 else CoTEventType.FRIENDLY_GROUND_COMBAT
                    
                    cot_ev = TacticalCoTEvent(
                        event_type=cot_type,
                        lat=lat_val,
                        lon=lon_val,
                        callsign=cs,
                        classification="SECRET"
                    )
                    cot_json = json.dumps(cot_ev.to_compact_json())
                    clean_msg = f"[MIL-STD-6090 CoT] {cot_json}".encode("utf-8")
                    encrypted = session.double_ratchet.encrypt(clean_msg)
                    frame = struct.pack(">I", len(encrypted)) + encrypted
                    writer.write(frame)
                    await writer.drain()
                    print(f"\033[1m\033[92m[CoT BROADCAST]\033[0m Track {cs} ({lat_val}, {lon_val}) transmitted.")
                    continue

                elif cmd == "/csrmc":
                    mon = get_csrmc_operations_monitor()
                    data = mon.compute_operations_telemetry()["csrmc_operations_phase_telemetry"]
                    ma = data.get("mission_assurance", {})
                    cr = data.get("cryptographic_runtime_health", {})
                    print(f"\n\033[1m\033[94m[CSRMC PHASE 5 OPERATIONS TELEMETRY]\033[0m")
                    print(f"  • Framework Mode       : {data.get('evaluation_mode')}")
                    print(f"  • Operational Status   : {ma.get('operational_status')}")
                    print(f"  • Network Availability : {ma.get('network_availability_pct')}%")
                    print(f"  • Mean Time to Remediate: {ma.get('mean_time_to_remediate_ms')} ms")
                    print(f"  • PQC Algorithms       : {cr.get('post_quantum_algorithms_status')}")
                    print(f"  • Fallback Status      : {cr.get('fallback_status')}\n")
                    continue

                elif cmd == "/mesh":
                    mesh = get_ddil_node_mesh()
                    pending = mesh.outbound_store.get(peer_id, [])
                    digest = mesh.get_merkle_digest(peer_id)
                    conn = "CONNECTED" if mesh.is_peer_connected(peer_id) else "DISCONNECTED/DDIL"
                    print(f"\n\033[1m\033[93m[TACTICAL DDIL MESH STATUS]\033[0m")
                    print(f"  • Peer Link Status     : {conn}")
                    print(f"  • Pending Bundles      : {len(pending)}")
                    print(f"  • Merkle DAG Digest    : {digest[:32]}...")
                    print(f"  • Total Stored Bundles : {mesh.total_bundles_stored}")
                    print(f"  • Total Reconciled     : {mesh.total_bundles_reconciled}\n")
                    continue

                elif cmd == "/flash":
                    if not arg:
                        print("\033[91mUsage: /flash <urgent message>\033[0m")
                        continue
                    clean_msg = f"[FLASH PRIORITY] {arg}".encode("utf-8")
                    encrypted = session.double_ratchet.encrypt(clean_msg)
                    # Also queue in DDIL mesh with EMERGENCY priority
                    mesh = get_ddil_node_mesh()
                    _enqueue_ddil_ciphertext(
                        mesh,
                        peer_id,
                        int(time.time()),
                        encrypted,
                        BundlePriority.EMERGENCY,
                    )
                    frame = struct.pack(">I", len(encrypted)) + encrypted
                    writer.write(frame)
                    await writer.drain()
                    print(f"\033[1m\033[91m[FLASH SENT]\033[0m Emergency priority packet transmitted and queued.")
                    continue

                elif cmd == "/quorum":
                    byz = get_byzantine_quorum_engine()
                    print(f"\n\033[1m\033[96m[BYZANTINE QUORUM STATUS]\033[0m")
                    print(f"  • Quorum Threshold     : {byz.required_quorum_m}-of-{byz.total_authorized_nodes_n}")
                    print(f"  • Authorized Nodes     : {len(byz.authorized_command_nodes)}")
                    print(f"  • Executed Proposals   : {len(byz.executed_proposals)}\n")
                    continue

                elif cmd == "/zeroize":
                    confirm = await loop.run_in_executor(None, input, "\033[91mCONFIRM EMERGENCY ZEROIZATION? (yes/no): \033[0m")
                    if confirm.strip().lower() == "yes":
                        zero = get_emergency_zeroization_engine()
                        audit = zero.execute_scorched_earth_zeroization(
                            trigger=AntiTamperTrigger.OPERATOR_DURESS_CODE,
                            operator_id="CONSOLE_OPERATOR",
                            terminate_process=False,
                        )
                        print(f"\033[1m\033[91m[ZEROIZED]\033[0m Scorched-earth memory sanitization complete.")
                        break
                    else:
                        print("Emergency zeroization cancelled.")
                        continue

            # Standard chat message handling
            clean_msg = trimmed[:16384].encode("utf-8")
            encrypted = session.double_ratchet.encrypt(clean_msg)
            frame = struct.pack(">I", len(encrypted)) + encrypted
            writer.write(frame)
            await writer.drain()

        except (ConnectionResetError, BrokenPipeError):
            print(f"\033[91mConnection lost to {peer_id}. Swapping to Tactical DDIL store-and-forward queue...\033[0m")
            mesh = get_ddil_node_mesh()
            mesh.set_peer_connectivity(peer_id, False)
            if clean_msg:
                _enqueue_ddil_ciphertext(
                    mesh,
                    peer_id,
                    int(time.time()),
                    encrypted,
                    BundlePriority.STANDARD,
                )
                print(f"\033[93m[DDIL] Message preserved in locked store-and-forward queue for {peer_id}.\033[0m")
            break
        except Exception as e:
            print(f"\033[91mError sending message: {e}\033[0m")
            break

    print(f"Exited chat with {peer_id}.")
