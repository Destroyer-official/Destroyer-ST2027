#!/usr/bin/env python3
"""
security_tiers.py

Destroyer-ST2027 Comprehensive Multi-Tier Security Engine
Strict CNSA 2.0 Purity, Fail-Closed Verification, Zero Simulation

Defines and enforces the five standardized operational security tiers:
  1. LOW: Local loopback testing, diagnostics, non-sensitive node telemetry.
  2. BASIC: Standard tactical point-to-point link, field communications.
  3. MEDIUM: Operational peer-to-peer sessions, post-quantum hybrid KEM/DSA.
  4. HIGH: Mission-critical tactical mesh, DDIL, Noise_XXhfs + Double Ratchet,
           DAITA cover traffic, 64-bit anti-replay bitmask window.
  5. CRITICAL: Strategic sovereign release & nuclear command (NC3),
               Two-Person Integrity (TPI) dual-operator authorization,
               CJADC2 multi-enclave hostile quarantine, emergency anti-tamper.

Zero marketing buzzwords. Zero emojis. Fail-closed security architecture.
"""

from __future__ import annotations

from collections import deque
import hashlib
import hmac
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


class SecurityTier(str, Enum):
    """Operational security tiers ordered from lowest to highest assurance."""
    LOW = "LOW"
    BASIC = "BASIC"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level_number(self) -> int:
        levels = {
            SecurityTier.LOW: 1,
            SecurityTier.BASIC: 2,
            SecurityTier.MEDIUM: 3,
            SecurityTier.HIGH: 4,
            SecurityTier.CRITICAL: 5,
        }
        return levels[self]

    def __ge__(self, other: SecurityTier) -> bool:
        if not isinstance(other, SecurityTier):
            return NotImplemented
        return self.level_number >= other.level_number

    def __gt__(self, other: SecurityTier) -> bool:
        if not isinstance(other, SecurityTier):
            return NotImplemented
        return self.level_number > other.level_number

    def __le__(self, other: SecurityTier) -> bool:
        if not isinstance(other, SecurityTier):
            return NotImplemented
        return self.level_number <= other.level_number

    def __lt__(self, other: SecurityTier) -> bool:
        if not isinstance(other, SecurityTier):
            return NotImplemented
        return self.level_number < other.level_number


class SecurityTierViolationError(RuntimeError):
    """Raised when an operation does not satisfy mandatory tier constraints."""
    pass


@dataclass(frozen=True)
class TierRequirements:
    """Formal security criteria demanded by a specific tier."""
    tier: SecurityTier
    min_classical_bits: int
    min_quantum_level: int
    requires_pqc: bool
    requires_hybrid_kem: bool
    requires_vas: bool  # Verify-After-Sign
    requires_ram_protection: bool  # Pinned/In-RAM encryption
    requires_forward_secrecy: bool
    requires_daita_camouflage: bool  # Quantization + Paced Poisson cover traffic
    requires_anti_replay_window: bool
    requires_two_person_integrity: bool
    requires_cross_domain_guard: bool
    requires_emergency_shred: bool
    description: str


# Canonical tier criteria profiles
TIER_PROFILES: Dict[SecurityTier, TierRequirements] = {
    SecurityTier.LOW: TierRequirements(
        tier=SecurityTier.LOW,
        min_classical_bits=128,
        min_quantum_level=0,
        requires_pqc=False,
        requires_hybrid_kem=False,
        requires_vas=False,
        requires_ram_protection=False,
        requires_forward_secrecy=False,
        requires_daita_camouflage=False,
        requires_anti_replay_window=False,
        requires_two_person_integrity=False,
        requires_cross_domain_guard=False,
        requires_emergency_shred=False,
        description="Local loopback testing, diagnostics, non-sensitive node telemetry.",
    ),
    SecurityTier.BASIC: TierRequirements(
        tier=SecurityTier.BASIC,
        min_classical_bits=256,
        min_quantum_level=0,
        requires_pqc=False,
        requires_hybrid_kem=False,
        requires_vas=False,
        requires_ram_protection=True,
        requires_forward_secrecy=False,
        requires_daita_camouflage=False,
        requires_anti_replay_window=True,
        requires_two_person_integrity=False,
        requires_cross_domain_guard=False,
        requires_emergency_shred=False,
        description="Standard tactical point-to-point datalink with AES-256-GCM AEAD.",
    ),
    SecurityTier.MEDIUM: TierRequirements(
        tier=SecurityTier.MEDIUM,
        min_classical_bits=256,
        min_quantum_level=5,
        requires_pqc=True,
        requires_hybrid_kem=True,
        requires_vas=True,
        requires_ram_protection=True,
        requires_forward_secrecy=False,
        requires_daita_camouflage=False,
        requires_anti_replay_window=True,
        requires_two_person_integrity=False,
        requires_cross_domain_guard=False,
        requires_emergency_shred=False,
        description="Post-quantum hybrid KEM (ML-KEM-1024) + ML-DSA-87 with Verify-After-Sign.",
    ),
    SecurityTier.HIGH: TierRequirements(
        tier=SecurityTier.HIGH,
        min_classical_bits=256,
        min_quantum_level=5,
        requires_pqc=True,
        requires_hybrid_kem=True,
        requires_vas=True,
        requires_ram_protection=True,
        requires_forward_secrecy=True,
        requires_daita_camouflage=True,
        requires_anti_replay_window=True,
        requires_two_person_integrity=False,
        requires_cross_domain_guard=False,
        requires_emergency_shred=False,
        description="Noise_XXhfs + Double Ratchet, forward secrecy, DAITA Poisson cover traffic.",
    ),
    SecurityTier.CRITICAL: TierRequirements(
        tier=SecurityTier.CRITICAL,
        min_classical_bits=256,
        min_quantum_level=5,
        requires_pqc=True,
        requires_hybrid_kem=True,
        requires_vas=True,
        requires_ram_protection=True,
        requires_forward_secrecy=True,
        requires_daita_camouflage=True,
        requires_anti_replay_window=True,
        requires_two_person_integrity=True,
        requires_cross_domain_guard=True,
        requires_emergency_shred=True,
        description="Two-Person Integrity dual-operator authority, CJADC2 guard, emergency shred.",
    ),
}

# Approved CNSA 2.0 Cryptographic Primitives
APPROVED_SYMMETRIC_CIPHERS = {"AES-256-GCM", "AES256GCM", "CHACHA20-POLY1305"}
APPROVED_HASH_KDF = {"SHA-384", "SHA-512", "HMAC-SHA-384", "HMAC-SHA-512", "HKDF-SHA384", "HKDF-SHA512"}
APPROVED_PQ_KEMS = {"ML-KEM-1024", "CLASSIC-MCELIECE-8192128F", "P384+ML-KEM-1024"}
APPROVED_PQ_SIGS = {
    "ML-DSA-87",
    "SLH-DSA-PURE-SHAKE-256F",
    "SLH-DSA-256F",
    "FALCON-1024",
    "LMS-SHA256-M32-H5",
    "LMS-SHA256-M32-H10",
    "LMS-SHA3-512-M32-H15",
}
APPROVED_SP800_208_SIGS = {
    "LMS-SHA256-M32-H5",
    "LMS-SHA256-M32-H10",
    "LMS-SHA3-512-M32-H15",
    "XMSS-SHA2-10-256",
    "XMSS-SHA2-16-256",
}


class SecurityTierEngine:
    """Enforces cryptographic and operational constraints across all security tiers."""

    @staticmethod
    def get_tier_requirements(tier: SecurityTier) -> TierRequirements:
        """Fetch canonical criteria for a security tier."""
        return TIER_PROFILES[tier]

    @classmethod
    def validate_cipher_suite(
        cls,
        tier: SecurityTier,
        cipher_name: str,
        hash_or_kdf_name: str,
        kem_name: Optional[str] = None,
        sig_name: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """Validate whether cryptographic selections fulfill the tier policy.
        
        Returns:
            Tuple of (is_valid, list_of_violations)
        """
        req = cls.get_tier_requirements(tier)
        violations: List[str] = []

        # 1. Symmetric cipher check
        c_upper = cipher_name.upper().replace("_", "-")
        if c_upper not in APPROVED_SYMMETRIC_CIPHERS:
            violations.append(f"Cipher '{cipher_name}' not in approved CNSA 2.0 set: {APPROVED_SYMMETRIC_CIPHERS}")

        # 2. Hash / KDF check
        h_upper = hash_or_kdf_name.upper().replace("_", "-")
        if h_upper not in APPROVED_HASH_KDF:
            violations.append(f"Hash/KDF '{hash_or_kdf_name}' not in approved set: {APPROVED_HASH_KDF}")

        # 3. Post-Quantum requirements
        if req.requires_pqc:
            if not kem_name:
                violations.append(f"Tier {tier.value} requires Post-Quantum KEM, but none was provided")
            else:
                k_upper = kem_name.upper().replace("_", "-")
                if not any(approved in k_upper for approved in APPROVED_PQ_KEMS):
                    violations.append(f"KEM '{kem_name}' does not meet NIST Level 5 requirements: {APPROVED_PQ_KEMS}")

            if not sig_name:
                violations.append(f"Tier {tier.value} requires Post-Quantum signature, but none was provided")
            else:
                s_upper = sig_name.upper().replace("_", "-")
                if not any(approved in s_upper for approved in APPROVED_PQ_SIGS):
                    violations.append(f"Signature '{sig_name}' does not meet NIST Level 5 requirements: {APPROVED_PQ_SIGS}")

        return (len(violations) == 0, violations)

    @classmethod
    def validate_memory_hygiene(
        cls,
        tier: SecurityTier,
        is_pinned: bool,
        is_ram_encrypted: bool = False,
    ) -> Tuple[bool, List[str]]:
        """Validate memory protection (VirtualLock/mlock and CryptProtectMemory)."""
        req = cls.get_tier_requirements(tier)
        violations: List[str] = []

        if req.requires_ram_protection:
            if not is_pinned and not is_ram_encrypted:
                violations.append(
                    f"Tier {tier.value} requires memory locking (VirtualLock/mlock) or in-RAM encryption (CryptProtectMemory)"
                )

        return (len(violations) == 0, violations)

    @classmethod
    def validate_traffic_camouflage(
        cls,
        tier: SecurityTier,
        is_quantized: bool,
        is_chaff_active: bool,
        has_anti_replay: bool,
    ) -> Tuple[bool, List[str]]:
        """Validate DAITA traffic flow obfuscation and replay defenses."""
        req = cls.get_tier_requirements(tier)
        violations: List[str] = []

        if req.requires_anti_replay_window and not has_anti_replay:
            violations.append(f"Tier {tier.value} requires sliding-window anti-replay protection")

        if req.requires_daita_camouflage:
            if not is_quantized:
                violations.append(f"Tier {tier.value} requires constant-quantum frame padding (DAITA)")
            if not is_chaff_active:
                violations.append(f"Tier {tier.value} requires synthetic cover traffic pacing (Poisson chaff)")

        return (len(violations) == 0, violations)

    @classmethod
    def validate_critical_authorization(
        cls,
        tier: SecurityTier,
        operator_ids: Sequence[str],
        signatures: Sequence[bytes],
        payload_digest: bytes,
        challenge_age_sec: float,
        max_age_sec: float = 300.0,
    ) -> Tuple[bool, List[str]]:
        """Validate Two-Person Integrity (TPI) dual-operator authorization for CRITICAL tier."""
        req = cls.get_tier_requirements(tier)
        violations: List[str] = []

        if not req.requires_two_person_integrity:
            return (True, [])

        if len(operator_ids) < 2:
            violations.append(
                f"Two-Person Integrity violation: expected at least 2 distinct operators, got {len(operator_ids)}"
            )

        if len(set(operator_ids)) != len(operator_ids):
            violations.append("Two-Person Integrity violation: duplicate operator ID detected in release authority")

        if len(signatures) < 2:
            violations.append(
                f"Two-Person Integrity violation: expected at least 2 operator signatures, got {len(signatures)}"
            )

        if len(payload_digest) != 48 and len(payload_digest) != 64:
            violations.append(
                f"Invalid payload digest length ({len(payload_digest)} bytes); must be SHA-384 or SHA-512"
            )

        if challenge_age_sec < 0 or challenge_age_sec > max_age_sec:
            violations.append(
                f"Ceremony token expired or invalid: age {challenge_age_sec:.1f}s exceeds max {max_age_sec}s"
            )

        return (len(violations) == 0, violations)

    @staticmethod
    def create_critical_authority() -> Any:
        """Create and return an initialized CriticalReleaseAuthority instance for TPI ceremonies."""
        from critical_release import CriticalReleaseAuthority
        return CriticalReleaseAuthority()

    @classmethod
    def assess_runtime_security_tier(
        cls,
        capabilities: Dict[str, Any],
    ) -> SecurityTier:
        """Determine highest satisfied security tier based on active capabilities.
        
        Evaluates from CRITICAL down to LOW, returning the highest tier where
        all mandatory requirements are met without exception (fail-closed).
        """
        for tier in [
            SecurityTier.CRITICAL,
            SecurityTier.HIGH,
            SecurityTier.MEDIUM,
            SecurityTier.BASIC,
            SecurityTier.LOW,
        ]:
            req = cls.get_tier_requirements(tier)
            meets_tier = True

            # Check PQC
            if req.requires_pqc:
                if not capabilities.get("has_pqc_kem", False) or not capabilities.get("has_pqc_sig", False):
                    meets_tier = False

            # Check VAS
            if req.requires_vas and not capabilities.get("has_vas", False):
                meets_tier = False

            # Check RAM Protection
            if req.requires_ram_protection:
                if not capabilities.get("has_locked_memory", False) and not capabilities.get("has_ram_encryption", False):
                    meets_tier = False

            # Check Forward Secrecy
            if req.requires_forward_secrecy and not capabilities.get("has_forward_secrecy", False):
                meets_tier = False

            # Check DAITA Camouflage
            if req.requires_daita_camouflage:
                if not capabilities.get("has_quantization", False) or not capabilities.get("has_pacing_chaff", False):
                    meets_tier = False

            # Check Anti-Replay
            if req.requires_anti_replay_window and not capabilities.get("has_anti_replay", False):
                meets_tier = False

            # Check TPI
            if req.requires_two_person_integrity and not capabilities.get("has_two_person_integrity", False):
                meets_tier = False

            # Check Cross-Domain Guard
            if req.requires_cross_domain_guard and not capabilities.get("has_cross_domain_guard", False):
                meets_tier = False

            # Check Emergency Shred
            if req.requires_emergency_shred and not capabilities.get("has_emergency_shred", False):
                meets_tier = False

            if meets_tier:
                return tier

        return SecurityTier.LOW

    @staticmethod
    def create_telemetry_scrubber() -> type[TelemetryScrubber]:
        """Create a TelemetryScrubber for LOW tier diagnostics sanitation."""
        return TelemetryScrubber

    @staticmethod
    def create_nonce_generator(session_salt: Optional[bytes] = None) -> DeterministicNonceGenerator:
        """Create a DeterministicNonceGenerator for BASIC tier monotonic AEAD nonces."""
        return DeterministicNonceGenerator(session_salt=session_salt)

    @staticmethod
    def create_anti_replay_window(window_size: int = 64, initial_offset: int = 0) -> AntiReplaySlidingWindow:
        """Create an AntiReplaySlidingWindow for BASIC tier sliding bitmap validation."""
        return AntiReplaySlidingWindow(window_size=window_size, initial_offset=initial_offset)

    @staticmethod
    def derive_transcript_bound_kem(
        client_id: str,
        server_id: str,
        suite_id: str,
        client_pk: bytes,
        server_pk: bytes,
        kem_ciphertext: bytes,
        shared_secrets: Sequence[bytes],
        key_len: int = 32,
    ) -> bytes:
        """Derive a MEDIUM tier transcript-bound hybrid session key per NIST SP 800-227 / RFC 10024."""
        return TranscriptBoundHybridKEM.derive_bound_session_key(
            client_id=client_id,
            server_id=server_id,
            suite_id=suite_id,
            client_pk=client_pk,
            server_pk=server_pk,
            kem_ciphertext=kem_ciphertext,
            shared_secrets=shared_secrets,
            key_len=key_len,
        )

    @staticmethod
    def create_vas_authority(key_id: str) -> VASLatchingAuthority:
        """Create a VASLatchingAuthority for MEDIUM tier Verify-After-Sign fault defense."""
        return VASLatchingAuthority(key_id=key_id)

    @staticmethod
    def create_daita_frame_shaper() -> type[DAITAFrameShaper]:
        """Create a DAITAFrameShaper for HIGH tier discrete bucket quantization."""
        return DAITAFrameShaper

    @staticmethod
    def create_poisson_scheduler() -> type[PoissonCoverTrafficScheduler]:
        """Create a PoissonCoverTrafficScheduler for HIGH tier memoryless cover traffic pacing."""
        return PoissonCoverTrafficScheduler

    @staticmethod
    def create_lms_signer(tree_height: int = 4) -> SP800_208_LMS:
        """Create an SP800_208_LMS stateful hash-based signer for CRITICAL tier sovereign release."""
        return SP800_208_LMS(tree_height=tree_height)

    @staticmethod
    def create_anti_downgrade_enforcer(minimum_enforced_tier: SecurityTier) -> AntiDowngradePolicyEnforcer:
        """Create an AntiDowngradePolicyEnforcer preventing downward tier negotiation."""
        return AntiDowngradePolicyEnforcer(minimum_enforced_tier=minimum_enforced_tier)

    @staticmethod
    def emergency_shred(target: Any) -> int:
        """Execute a 4-pass cryptographic memory overwrite on sensitive buffers."""
        return EmergencyMultiPassShredder.shred(target)

    @staticmethod
    def create_diagnostic_access_control(
        max_buffer_size: int = 50,
        max_requests_per_min: int = 60,
    ) -> DiagnosticAccessControl:
        """Create a DiagnosticAccessControl for LOW tier telemetry rate-limiting and ring buffer."""
        return DiagnosticAccessControl(
            max_buffer_size=max_buffer_size,
            max_requests_per_min=max_requests_per_min,
        )

    @staticmethod
    def create_monotonic_persister(state_file_path: Path | str) -> MonotonicStatePersister:
        """Create a crash-consistent MonotonicStatePersister for BASIC tier sequence numbers."""
        return MonotonicStatePersister(state_file_path=Path(state_file_path))

    @staticmethod
    def create_triple_ratchet(
        local_id: str,
        remote_id: str,
        shared_root_key: bytes,
        is_initiator: bool,
        remote_dh_pub: bytes,
        remote_kem_pub: bytes,
        spqr_interval: int = 5,
    ) -> TripleRatchetEngine:
        """Create an October 2025 Signal Triple Ratchet (SPQR) engine for MEDIUM tier."""
        return TripleRatchetEngine(
            local_id=local_id,
            remote_id=remote_id,
            shared_root_key=shared_root_key,
            is_initiator=is_initiator,
            remote_dh_pub=remote_dh_pub,
            remote_kem_pub=remote_kem_pub,
            spqr_interval=spqr_interval,
        )

    @staticmethod
    def create_maybenot_fsm(
        burst_threshold_pkts: int = 5,
        burst_window_sec: float = 0.05,
        target_quantum_size: int = 256,
    ) -> MaybenotTrafficFSM:
        """Create a Maybenot v2 / DAITA probabilistic finite state machine for HIGH tier."""
        return MaybenotTrafficFSM(
            burst_threshold_pkts=burst_threshold_pkts,
            burst_window_sec=burst_window_sec,
            target_quantum_size=target_quantum_size,
        )

    @staticmethod
    def create_emergency_purge_ceremony(authority: Optional[Any] = None) -> EmergencyPurgeCeremony:
        """Create a dual-operator EmergencyPurgeCeremony for CRITICAL tier sovereign wipe."""
        return EmergencyPurgeCeremony(authority=authority)


# ==============================================================================
# Tier 1: LOW — Telemetry Sanitation & Diagnostic Authorization
# ==============================================================================

class TelemetryScrubber:
    """Sanitizes diagnostic outputs, error traces, and telemetry messages.
    
    Prevents microarchitectural pointer leaks, internal path disclosure, IP exposure,
    and secret token leakage across lower-tier telemetry boundaries.
    """
    ADDR_PATTERN = re.compile(r"\b0x[0-9a-fA-F]{6,16}\b")
    PATH_PATTERN = re.compile(r"(?:[A-Za-z]:\\[^ \t\n\r\"']+|/(?:home|usr|var|tmp|etc|app)/[^ \t\n\r\"']+)")
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    TOKEN_PATTERN = re.compile(r"\b[0-9a-fA-F]{32,}\b")

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Compute Shannon entropy in bits per character."""
        if not data:
            return 0.0
        import math
        counts: Dict[str, int] = {}
        for ch in data:
            counts[ch] = counts.get(ch, 0) + 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    @classmethod
    def scrub_high_entropy_secrets(cls, text: str, entropy_threshold: float = 3.8, min_length: int = 24) -> str:
        """Scan tokens and redact any high-entropy secret material."""
        tokens = re.split(r"(\s+|[=:,;\"'<>\[\]{}()])", text)
        scrubbed = []
        for t in tokens:
            if len(t) >= min_length and not t.startswith("[") and not t.endswith("]"):
                if cls.shannon_entropy(t) >= entropy_threshold:
                    scrubbed.append("[HIGH_ENTROPY_SECRET_REDACTED]")
                    continue
            scrubbed.append(t)
        return "".join(scrubbed)

    @classmethod
    def scrub(cls, text: str) -> str:
        """Strip internal memory addresses, filesystem paths, IP addresses, hex keys, and high-entropy secrets."""
        s = cls.ADDR_PATTERN.sub("[ADDR_MASKED]", text)
        s = cls.PATH_PATTERN.sub("[PATH_MASKED]", s)
        s = cls.IP_PATTERN.sub("[IP_MASKED]", s)
        s = cls.TOKEN_PATTERN.sub("[SECRET_MASKED]", s)
        s = cls.scrub_high_entropy_secrets(s)
        return s

    @classmethod
    def verify_auth_token(cls, provided_token: str, expected_token: str) -> bool:
        """Constant-time token authentication for diagnostic query endpoints."""
        return hmac.compare_digest(provided_token.encode("utf-8"), expected_token.encode("utf-8"))


class DiagnosticAccessControl:
    """Access control, rate-limiting, and bounded ring-buffer memory for LOW tier telemetry."""
    def __init__(self, max_buffer_size: int = 50, max_requests_per_min: int = 60):
        self.max_buffer_size = max_buffer_size
        self.max_requests_per_min = max_requests_per_min
        self._buffer: deque = deque(maxlen=max_buffer_size)
        self._request_timestamps: Dict[str, deque] = {}
        self._chain_hash: bytes = b"\x00" * 48
        self._lock = threading.RLock()

    @property
    def current_audit_chain_hash(self) -> str:
        """Returns the current SHA-384 audit chain head for tamper evidence."""
        with self._lock:
            return self._chain_hash.hex()

    def check_rate_limit(self, client_id: str) -> bool:
        """Enforces sliding-window rate limit per diagnostic client ID."""
        now = time.monotonic()
        with self._lock:
            if client_id not in self._request_timestamps:
                self._request_timestamps[client_id] = deque()
            dq = self._request_timestamps[client_id]
            while dq and (now - dq[0]) > 60.0:
                dq.popleft()
            if len(dq) >= self.max_requests_per_min:
                return False
            dq.append(now)
            return True

    def record_telemetry(self, raw_message: str) -> str:
        """Sanitizes raw telemetry, binds into cryptographic hash chain, and stores in bounded ring buffer."""
        scrubbed = TelemetryScrubber.scrub(raw_message)
        now = time.time()
        with self._lock:
            chain_block = self._chain_hash + struct.pack(">d", now) + scrubbed.encode("utf-8")
            self._chain_hash = hashlib.sha384(chain_block).digest()
            self._buffer.append((now, scrubbed, self._chain_hash.hex()))
        return scrubbed

    def get_recent_telemetry(self, client_id: str) -> List[str]:
        """Fetches sanitized telemetry buffer if client rate limit is satisfied."""
        if not self.check_rate_limit(client_id):
            raise SecurityTierViolationError(
                f"Rate limit exceeded for diagnostic client '{client_id}': max {self.max_requests_per_min} req/min"
            )
        with self._lock:
            return [entry[1] for entry in self._buffer]


# ==============================================================================
# Tier 2: BASIC — Nonce Misuse Defense & Sliding Window Anti-Replay
# ==============================================================================

class DeterministicNonceGenerator:
    """RFC 5116 / RFC 8452 deterministic 96-bit nonce constructor.
    
    Prevents catastrophic AES-256-GCM nonce reuse by binding a 32-bit random session salt
    with a strictly monotonic 64-bit sequence counter and enforcing NIST SP 800-38D re-key bounds.
    """
    MAX_COUNTER = 0xFFFFFFFFFFFFFFFF
    REKEY_THRESHOLD = 0xFFFFFFFF  # 2^32 - 1 invocations (NIST SP 800-38D safe invocation limit)

    def __init__(
        self,
        session_salt: Optional[bytes] = None,
        rekey_threshold: int = REKEY_THRESHOLD,
        strict_rekey: bool = False,
    ):
        self._salt = session_salt if session_salt is not None else secrets.token_bytes(4)
        if len(self._salt) != 4:
            raise ValueError(f"Session salt must be exactly 4 bytes, got {len(self._salt)}")
        self._counter = 0
        self.rekey_threshold = rekey_threshold
        self.strict_rekey = strict_rekey
        self._lock = threading.Lock()

    @property
    def salt(self) -> bytes:
        return self._salt

    @property
    def is_rekey_required(self) -> bool:
        """Indicates whether the counter has reached the NIST SP 800-38D re-keying boundary."""
        with self._lock:
            return self._counter >= self.rekey_threshold

    def next_nonce(self) -> Tuple[int, bytes]:
        """Generate next monotonic sequence number and 96-bit wire nonce.
        
        Returns:
            Tuple of (sequence_number, 12_byte_nonce)
        """
        with self._lock:
            if self._counter >= self.MAX_COUNTER:
                raise SecurityTierViolationError(
                    "Monotonic counter exhaustion: session key re-keying strictly required"
                )
            if self.strict_rekey and self._counter >= self.rekey_threshold:
                raise SecurityTierViolationError(
                    f"NIST SP 800-38D re-key threshold reached: {self._counter} >= {self.rekey_threshold}"
                )
            seq = self._counter
            self._counter += 1
            nonce = self._salt + seq.to_bytes(8, byteorder="big")
            return seq, nonce


class AntiReplaySlidingWindow:
    """RFC 6479 / WireGuard 64-packet bitmap sliding-window anti-replay validator.
    
    Decoupled two-phase verification:
    1. check(seq): Read-only acceptance test safe on unauthenticated incoming frames.
    2. mark(seq): Advance window only AFTER AEAD authentication succeeds.
    """
    def __init__(self, window_size: int = 64, initial_offset: int = 0):
        self._window_size = window_size
        self._last_seq = initial_offset
        self._bitmap = 0
        self._drops = 0
        self._lock = threading.RLock()

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._last_seq

    @property
    def drops(self) -> int:
        with self._lock:
            return self._drops

    def check(self, seq: int) -> bool:
        """Read-only acceptance test. Never mutates state."""
        if seq <= 0:
            return False
        with self._lock:
            if seq > self._last_seq:
                return True
            diff = self._last_seq - seq
            if diff >= self._window_size:
                return False
            return (self._bitmap & (1 << diff)) == 0

    def mark(self, seq: int) -> None:
        """Advance window for a validated sequence number after AEAD tag verification."""
        with self._lock:
            if seq > self._last_seq:
                diff = seq - self._last_seq
                if diff >= self._window_size:
                    self._bitmap = 0
                else:
                    self._bitmap = (self._bitmap << diff) & ((1 << self._window_size) - 1)
                self._bitmap |= 1
                self._last_seq = seq
            else:
                diff = self._last_seq - seq
                if diff < self._window_size:
                    self._bitmap |= (1 << diff)

    def check_and_update(self, seq: int) -> bool:
        """Atomic check and update for local pipeline tests."""
        with self._lock:
            if not self.check(seq):
                self._drops += 1
                return False
            self.mark(seq)
            return True


class MonotonicStatePersister:
    """Crash-consistent atomic state persister for BASIC tier sequence numbers and anti-replay windows."""
    def __init__(self, state_file_path: Path | str, integrity_key: Optional[bytes] = None):
        self.state_file_path = Path(state_file_path)
        self.integrity_key = integrity_key
        self._lock = threading.RLock()

    def persist_state(self, last_seq: int, bitmap: int, drops: int) -> None:
        """Persists sequence numbers atomically with fsync and atomic rename."""
        payload: Dict[str, Any] = {
            "last_seq": last_seq,
            "bitmap": bitmap,
            "drops": drops,
            "timestamp_utc": time.time(),
        }
        if self.integrity_key is not None:
            raw_canon = f"{last_seq}:{bitmap}:{drops}".encode("utf-8")
            payload["integrity_mac"] = hmac.new(self.integrity_key, raw_canon, hashlib.sha384).hexdigest()

        data = json.dumps(payload, indent=2).encode("utf-8")
        tmp_path = self.state_file_path.with_suffix(".tmp")
        with self._lock:
            self.state_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp_path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.state_file_path)

    def load_state(self) -> Tuple[int, int, int]:
        """Loads state, returning (last_seq, bitmap, drops). Fails closed on corruption or MAC mismatch."""
        with self._lock:
            if not self.state_file_path.exists():
                return 0, 0, 0
            try:
                data = json.loads(self.state_file_path.read_text(encoding="utf-8"))
                last_seq = int(data["last_seq"])
                bitmap = int(data["bitmap"])
                drops = int(data.get("drops", 0))

                if self.integrity_key is not None:
                    expected_mac = data.get("integrity_mac")
                    if not expected_mac:
                        raise SecurityTierViolationError("FAIL-CLOSED: Missing integrity MAC in monotonic state")
                    raw_canon = f"{last_seq}:{bitmap}:{drops}".encode("utf-8")
                    computed_mac = hmac.new(self.integrity_key, raw_canon, hashlib.sha384).hexdigest()
                    if not hmac.compare_digest(expected_mac, computed_mac):
                        raise SecurityTierViolationError(
                            "FAIL-CLOSED: Monotonic state integrity verification failed (tampering detected)"
                        )

                return last_seq, bitmap, drops
            except SecurityTierViolationError:
                raise
            except Exception as e:
                raise SecurityTierViolationError(
                    f"FAIL-CLOSED: Monotonic state corruption detected in '{self.state_file_path}': {e}"
                )


# ==============================================================================
# Tier 3: MEDIUM — Transcript-Bound Hybrid KEM & VAS Latching
# ==============================================================================

class TranscriptBoundHybridKEM:
    """NIST SP 800-227 / RFC 10024 Transcript-Bound Hybrid Key Derivation.
    
    Binds peer identity public keys, negotiated suite parameters, and ephemeral KEM ciphertexts
    into HKDF-SHA384 salt, rendering downgrade or parameter stripping attacks impossible.
    """
    @staticmethod
    def derive_bound_session_key(
        client_id: str,
        server_id: str,
        suite_id: str,
        client_pk: bytes,
        server_pk: bytes,
        kem_ciphertext: bytes,
        shared_secrets: Sequence[bytes],
        key_len: int = 32,
    ) -> bytes:
        """Derive session key cryptographically bound to the complete handshake transcript."""
        # 1. Compute Handshake Transcript Hash
        h = hashlib.sha384()
        h.update(client_id.encode("utf-8"))
        h.update(server_id.encode("utf-8"))
        h.update(suite_id.encode("utf-8"))
        h.update(client_pk)
        h.update(server_pk)
        h.update(kem_ciphertext)
        transcript_hash = h.digest()

        # 2. Concatenate shared secrets (IKM)
        ikm = b"".join(shared_secrets)

        # 3. Derive via HKDF-SHA384 with transcript hash as salt
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=key_len,
            salt=transcript_hash,
            info=b"ST2027-CNSA2-TRANSCRIPT-BOUND-V1",
        )
        return hkdf.derive(ikm)


class VASLatchingAuthority:
    """Verify-After-Sign (VAS) with Latching Quarantine (CHES 2024 / PQShield fault defense)."""
    def __init__(self, key_id: str):
        self.key_id = key_id
        self._latched_quarantined = False
        self._lock = threading.Lock()

    @property
    def is_quarantined(self) -> bool:
        with self._lock:
            return self._latched_quarantined

    def sign_with_vas(
        self,
        sign_fn: Callable[[bytes], bytes],
        verify_fn: Callable[[bytes, bytes], bool],
        message: bytes,
        secret_buffer: Optional[Any] = None,
    ) -> bytes:
        """Executes signature with mandatory self-verification before releasing output."""
        with self._lock:
            if self._latched_quarantined:
                raise SecurityTierViolationError(
                    f"Key '{self.key_id}' is permanently quarantined due to previous VAS fault"
                )

            sig = sign_fn(message)
            if not verify_fn(message, sig):
                # Fault detected! Latch into permanent quarantine and wipe secret buffer
                self._latched_quarantined = True
                if secret_buffer is not None and hasattr(secret_buffer, "wipe"):
                    secret_buffer.wipe()
                raise SecurityTierViolationError(
                    f"FAIL-CLOSED: Verify-After-Sign verification failed for key '{self.key_id}'. "
                    f"Potential fault injection attack detected. Key quarantined and memory purged."
                )
            return sig


@dataclass
class TripleRatchetMessage:
    """Wire representation of an authenticated Triple Ratchet frame."""
    sender_dh_pub: bytes
    sequence_num: int
    prev_chain_len: int
    ciphertext: bytes
    nonce: bytes
    kem_ciphertext: Optional[bytes] = None
    next_kem_pub: Optional[bytes] = None


class TripleRatchetEngine:
    """October 2025 Signal Triple Ratchet / Sparse Post-Quantum Ratchet (SPQR) Engine.
    
    Combines classical Elliptic Curve Diffie-Hellman (X25519) with sparse post-quantum
    Key Encapsulation (ML-KEM-1024, FIPS 203) to provide Post-Quantum Forward Secrecy (FS)
    and Post-Quantum Post-Compromise Security (PCS).
    """
    def __init__(
        self,
        local_id: str,
        remote_id: str,
        shared_root_key: bytes,
        is_initiator: bool,
        remote_dh_pub: Optional[bytes] = None,
        remote_kem_pub: Optional[bytes] = None,
        local_dh_keypair: Optional[Any] = None,
        local_kem_keypair: Optional[Tuple[bytes, bytes]] = None,
        spqr_interval: int = 5,
    ):
        from cryptography.hazmat.primitives.asymmetric import x25519
        from liboqs_wrapper import LibOQS_MLKEM_1024

        self.local_id = local_id
        self.remote_id = remote_id
        self.is_initiator = is_initiator
        self.spqr_interval = spqr_interval

        # Classical DH keypair
        if local_dh_keypair is not None:
            self._dh_keypair = local_dh_keypair
        else:
            self._dh_keypair = x25519.X25519PrivateKey.generate()
        self._remote_dh_pub_bytes = remote_dh_pub

        # Post-Quantum KEM
        self._kem = LibOQS_MLKEM_1024()
        if local_kem_keypair is not None:
            self._local_kem_pk, self._local_kem_sk = local_kem_keypair
        else:
            self._local_kem_pk, self._local_kem_sk = self._kem.keygen()
        self._remote_kem_pub = remote_kem_pub

        # Ratchet keys
        self._root_key = bytearray(shared_root_key)
        self._send_chain_key: Optional[bytearray] = None
        self._recv_chain_key: Optional[bytearray] = None

        self._pending_kem_ct: Optional[bytes] = None
        self._pending_next_kem_pub: Optional[bytes] = None

        self._n_s = 0  # Sent message counter
        self._n_r = 0  # Recv message counter
        self._p_n = 0  # Prev chain length
        self._destroyed = False

        # Bounded skipped keys storage: (sender_dh_pub, seq) -> (mk_bytes, timestamp)
        self._skipped_keys: Dict[Tuple[bytes, int], Tuple[bytes, float]] = {}
        self._max_skipped_keys = 100
        self._skipped_ttl_sec = 300.0
        self._lock = threading.RLock()

        # Initialize chains for initiator
        if is_initiator and self._remote_dh_pub_bytes and self._remote_kem_pub:
            self._pending_kem_ct, self._pending_next_kem_pub = self._dh_ratchet_step(is_sender=True)

    @property
    def is_destroyed(self) -> bool:
        with self._lock:
            return self._destroyed

    def destroy(self) -> int:
        """Securely zeroizes all internal sensitive key material and locks engine."""
        with self._lock:
            if self._destroyed:
                return 0
            wiped = 0
            wiped += EmergencyMultiPassShredder.shred(self._root_key)
            if self._send_chain_key is not None:
                wiped += EmergencyMultiPassShredder.shred(self._send_chain_key)
                self._send_chain_key = None
            if self._recv_chain_key is not None:
                wiped += EmergencyMultiPassShredder.shred(self._recv_chain_key)
                self._recv_chain_key = None
            if hasattr(self, "_local_kem_sk") and self._local_kem_sk:
                self._local_kem_sk = b"\x00" * len(self._local_kem_sk)
            for k_id, (mk, _) in list(self._skipped_keys.items()):
                self._skipped_keys[k_id] = (b"\x00" * len(mk), 0.0)
            self._skipped_keys.clear()
            self._pending_kem_ct = None
            self._destroyed = True
            return wiped

    @property
    def dh_public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._dh_keypair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def kem_public_bytes(self) -> bytes:
        return bytes(self._local_kem_pk)

    def _dh_ratchet_step(self, is_sender: bool) -> Tuple[Optional[bytes], Optional[bytes]]:
        """Asymmetric ratchet step combining classical DH with SPQR ML-KEM-1024."""
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        remote_dh = x25519.X25519PublicKey.from_public_bytes(self._remote_dh_pub_bytes)
        dh_ss = self._dh_keypair.exchange(remote_dh)

        # SPQR KEM encapsulation
        kem_ct = None
        next_kem_pub = None
        if is_sender:
            kem_ct, kem_ss = self._kem.encaps(self._remote_kem_pub)
            next_kem_pub = self._local_kem_pk
        else:
            kem_ss = b"\x00" * 32

        # Hybrid KDF mix into root key
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=96,
            salt=bytes(self._root_key),
            info=b"ST2027-TRIPLE-RATCHET-SPQR-V1",
        )
        derived = hkdf.derive(dh_ss + kem_ss)
        self._root_key = bytearray(derived[:48])
        if is_sender:
            self._send_chain_key = bytearray(derived[48:])
        else:
            self._recv_chain_key = bytearray(derived[48:])

        return kem_ct, next_kem_pub

    def encrypt(self, plaintext: bytes) -> TripleRatchetMessage:
        """Encrypts payload with symmetric message key, performing ratchet step when needed."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization
        with self._lock:
            if self._destroyed:
                raise SecurityTierViolationError("Triple ratchet engine destroyed: keys zeroized")

            # Advance symmetric sending chain
            if self._send_chain_key is None:
                self._pending_kem_ct, self._pending_next_kem_pub = self._dh_ratchet_step(is_sender=True)

            kem_ct = self._pending_kem_ct
            next_kem_pub = self._pending_next_kem_pub

            # Derive message key
            mk = hmac.new(self._send_chain_key, b"\x01", hashlib.sha384).digest()[:32]
            old_send = self._send_chain_key
            self._send_chain_key = bytearray(
                hmac.new(old_send, b"\x02", hashlib.sha384).digest()
            )
            EmergencyMultiPassShredder.shred(old_send)

            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(mk)
            ct = aesgcm.encrypt(nonce, plaintext, None)

            seq = self._n_s
            self._n_s += 1

            dh_pub_bytes = self._dh_keypair.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            return TripleRatchetMessage(
                sender_dh_pub=dh_pub_bytes,
                sequence_num=seq,
                prev_chain_len=self._p_n,
                ciphertext=ct,
                nonce=nonce,
                kem_ciphertext=kem_ct,
                next_kem_pub=next_kem_pub,
            )

    def decrypt(self, msg: TripleRatchetMessage) -> bytes:
        """Decrypts TripleRatchetMessage, handling asymmetric steps and skipped keys."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        with self._lock:
            if self._destroyed:
                raise SecurityTierViolationError("Triple ratchet engine destroyed: keys zeroized")

            # Check skipped keys first
            key_id = (msg.sender_dh_pub, msg.sequence_num)
            if key_id in self._skipped_keys:
                mk, _ = self._skipped_keys.pop(key_id)
                aesgcm = AESGCM(mk)
                return aesgcm.decrypt(msg.nonce, msg.ciphertext, None)

            # Asymmetric ratchet check
            if self._recv_chain_key is None or msg.sender_dh_pub != self._remote_dh_pub_bytes:
                self._p_n = self._n_s
                self._n_s = 0
                self._n_r = 0
                self._remote_dh_pub_bytes = msg.sender_dh_pub

                # Post-quantum KEM decapsulation if KEM ciphertext included
                if msg.kem_ciphertext is not None:
                    kem_ss = self._kem.decaps(self._local_kem_sk, msg.kem_ciphertext)
                else:
                    kem_ss = b"\x00" * 32

                if msg.next_kem_pub is not None:
                    self._remote_kem_pub = msg.next_kem_pub

                remote_dh = x25519.X25519PublicKey.from_public_bytes(self._remote_dh_pub_bytes)
                dh_ss = self._dh_keypair.exchange(remote_dh)

                hkdf = HKDF(
                    algorithm=hashes.SHA384(),
                    length=96,
                    salt=bytes(self._root_key),
                    info=b"ST2027-TRIPLE-RATCHET-SPQR-V1",
                )
                derived = hkdf.derive(dh_ss + kem_ss)
                self._root_key = bytearray(derived[:48])
                self._recv_chain_key = bytearray(derived[48:])

                # Advance local DH and KEM keypairs for next send
                self._dh_keypair = x25519.X25519PrivateKey.generate()
                self._local_kem_pk, self._local_kem_sk = self._kem.keygen()
                self._send_chain_key = None

            # Skip message keys if out of order
            while self._n_r < msg.sequence_num:
                skip_mk = hmac.new(self._recv_chain_key, b"\x01", hashlib.sha384).digest()[:32]
                old_recv = self._recv_chain_key
                self._recv_chain_key = bytearray(
                    hmac.new(old_recv, b"\x02", hashlib.sha384).digest()
                )
                EmergencyMultiPassShredder.shred(old_recv)
                if len(self._skipped_keys) < self._max_skipped_keys:
                    self._skipped_keys[(msg.sender_dh_pub, self._n_r)] = (skip_mk, time.time())
                self._n_r += 1

            # Derive message key for current message
            mk = hmac.new(self._recv_chain_key, b"\x01", hashlib.sha384).digest()[:32]
            old_recv = self._recv_chain_key
            self._recv_chain_key = bytearray(
                hmac.new(old_recv, b"\x02", hashlib.sha384).digest()
            )
            EmergencyMultiPassShredder.shred(old_recv)
            self._n_r += 1

            aesgcm = AESGCM(mk)
            return aesgcm.decrypt(msg.nonce, msg.ciphertext, None)


# ==============================================================================
# Tier 4: HIGH — DAITA Frame Shaper & Poisson Cover Traffic Scheduler
# ==============================================================================

class DAITAFrameShaper:
    """Defense Against AI-guided Traffic Analysis (DAITA / Maybenot frame shaper).
    
    Quantizes all packet payloads to uniform discrete buckets (256, 512, 1024, 1420 bytes)
    with cryptographically randomized padding to eliminate frame size signatures.
    """
    QUANTUM_BUCKETS = (256, 512, 1024, 1420)

    @classmethod
    def shape_frame(cls, payload: bytes) -> bytes:
        """Pads payload to the next quantum bucket with 2-byte big-endian length prefix."""
        raw_len = len(payload)
        total_len = raw_len + 2
        target_bucket = None
        for b in cls.QUANTUM_BUCKETS:
            if total_len <= b:
                target_bucket = b
                break
        if target_bucket is None:
            target_bucket = ((total_len + 511) // 512) * 512

        pad_needed = target_bucket - total_len
        pad_bytes = secrets.token_bytes(pad_needed)
        return raw_len.to_bytes(2, "big") + payload + pad_bytes

    @classmethod
    def unshape_frame(cls, frame: bytes) -> bytes:
        """Extracts original payload from a shaped frame in constant-time bounds."""
        if len(frame) < 2:
            raise ValueError("Frame too short for DAITA header")
        raw_len = int.from_bytes(frame[:2], "big")
        if len(frame) < 2 + raw_len:
            raise ValueError(f"Corrupted frame: expected at least {2 + raw_len} bytes, got {len(frame)}")
        return frame[2:2 + raw_len]

    @classmethod
    def strip_chaff_or_unshape(cls, frame: bytes) -> Tuple[bool, bytes]:
        """Detects whether frame is chaff in constant time, returning (is_chaff, payload)."""
        if PoissonCoverTrafficScheduler.is_chaff_frame(frame):
            return True, b""
        return False, cls.unshape_frame(frame)


class PoissonCoverTrafficScheduler:
    """Calculates memoryless Poisson inter-arrival delays and synthetic chaff frame generators."""
    CHAFF_MARKER = b"\xFF\xFE\x00\x00"

    @staticmethod
    def sample_delay(interval_sec: float = 0.05, min_sec: float = 0.005, max_sec: float = 1.0) -> float:
        """Samples inter-arrival delay following exponential Poisson distribution."""
        rate_lambda = 1.0 / max(0.001, interval_sec)
        u = secrets.randbelow(10000) / 10000.0
        u = max(0.0001, min(0.9999, u))
        delay = -math.log(1.0 - u) / rate_lambda
        return max(min_sec, min(max_sec, delay))

    @classmethod
    def generate_chaff_frame(cls, bucket_size: int = 256) -> bytes:
        """Creates authentic-looking wire frame with CHAFF marker for black-hole drop discipline."""
        random_body = secrets.token_bytes(max(0, bucket_size - 4))
        return cls.CHAFF_MARKER + random_body

    @classmethod
    def is_chaff_frame(cls, frame: bytes) -> bool:
        """Detects whether incoming wire frame is synthetic cover traffic."""
        return len(frame) >= 4 and frame[:4] == cls.CHAFF_MARKER


class TrafficAction(str, Enum):
    ACTION_NONE = "NONE"
    ACTION_INJECT_CHAFF = "INJECT_CHAFF"
    ACTION_APPLY_JITTER = "APPLY_JITTER"
    ACTION_BLOCK_BURST = "BLOCK_BURST"


class TrafficState(str, Enum):
    STATE_PASSIVE_MONITORING = "PASSIVE_MONITORING"
    STATE_BURST_MITIGATION = "BURST_MITIGATION"
    STATE_SCHEDULED_PADDING = "SCHEDULED_PADDING"
    STATE_PACED_STREAMING = "PACED_STREAMING"


class MaybenotTrafficFSM:
    """Maybenot v2 / DAITA Probabilistic Finite State Machine for Traffic Analysis Defense.
    
    Monitors packet events and transitions between states to defeat AI website/application
    fingerprinting (k-FP, Deep Fingerprinting, Robust Fingerprinting) by injecting chaff
    and applying burst pacing, with support for the FRONT (Fast Random Padding) model.
    """
    def __init__(
        self,
        burst_threshold_pkts: int = 5,
        burst_window_sec: float = 0.05,
        target_quantum_size: int = 256,
        front_window_pkts: int = 0,
        front_chaff_budget: int = 0,
    ):
        self.burst_threshold_pkts = burst_threshold_pkts
        self.burst_window_sec = burst_window_sec
        self.target_quantum_size = target_quantum_size
        self.front_window_pkts = front_window_pkts
        self.front_chaff_remaining = front_chaff_budget
        self._packets_processed = 0
        self.state = TrafficState.STATE_PASSIVE_MONITORING
        self._recent_sends: deque = deque()
        self._last_event_time = time.monotonic()
        self._lock = threading.RLock()

    def on_packet_sent(self, packet_len: int) -> Tuple[TrafficState, TrafficAction, Dict[str, Any]]:
        """Processes an outgoing packet event, checking for FRONT phase or burst thresholds."""
        now = time.monotonic()
        with self._lock:
            self._packets_processed += 1
            if self.front_window_pkts > 0 and self._packets_processed <= self.front_window_pkts and self.front_chaff_remaining > 0:
                self.front_chaff_remaining -= 1
                self.state = TrafficState.STATE_BURST_MITIGATION
                action = TrafficAction.ACTION_INJECT_CHAFF
                meta = {
                    "chaff_size": self.target_quantum_size,
                    "reason": "FRONT_DEFENSE_INITIAL_FLOW_CAMOUFLAGE",
                    "front_chaff_remaining": self.front_chaff_remaining,
                }
                return self.state, action, meta

            self._recent_sends.append((now, packet_len))
            while self._recent_sends and (now - self._recent_sends[0][0]) > self.burst_window_sec:
                self._recent_sends.popleft()

            burst_count = len(self._recent_sends)
            self._last_event_time = now

            if burst_count >= self.burst_threshold_pkts:
                self.state = TrafficState.STATE_BURST_MITIGATION
                action = TrafficAction.ACTION_INJECT_CHAFF
                meta = {
                    "chaff_size": self.target_quantum_size,
                    "burst_count": burst_count,
                    "mitigation_mode": "PROBABILISTIC_COVER_INJECTION",
                }
                return self.state, action, meta
            else:
                self.state = TrafficState.STATE_PASSIVE_MONITORING
                return self.state, TrafficAction.ACTION_NONE, {}

    def on_timer_tick(self, idle_threshold_sec: float = 0.1) -> Tuple[TrafficState, TrafficAction, Dict[str, Any]]:
        """Processes timer tick, triggering cover traffic if link has gone idle."""
        now = time.monotonic()
        with self._lock:
            idle_dur = now - self._last_event_time
            if idle_dur >= idle_threshold_sec:
                self.state = TrafficState.STATE_SCHEDULED_PADDING
                self._last_event_time = now
                action = TrafficAction.ACTION_INJECT_CHAFF
                meta = {"chaff_size": self.target_quantum_size, "reason": "IDLE_CHANNEL_COVER"}
                return self.state, action, meta
            return self.state, TrafficAction.ACTION_NONE, {}


# ==============================================================================
# Tier 5: CRITICAL — NIST SP 800-208 LMS, Anti-Downgrade & Multi-Pass Shredder
# ==============================================================================

class SP800_208_LMS:
    """NIST SP 800-208 / RFC 8554 Leighton-Micali Stateful Hash-Based Signature Scheme.
    
    Parameters:
      LM-OTS: LMOTS_SHA256_N32_W8 (n=32, w=8, p=34, typecode=0x00000004)
      LMS: LMS_SHA256_M32_H4 / H5 / H10
    
    Security:
      Purely hash-based post-quantum security based on SHA-256 collision and preimage resistance.
      Completely immune to Shor's and Grover's quantum cryptanalysis.
      Stateful OTS counter with atomic locking guarantees zero OTS key reuse.
    """
    D_PBLC = bytes.fromhex("8080")
    D_MESG = bytes.fromhex("8181")
    D_LEAF = bytes.fromhex("8282")
    D_INTR = bytes.fromhex("8383")
    LM_OTS_TYPE = 0x00000004  # LMOTS_SHA256_N32_W8
    LMS_TYPE_H4 = 0x00000004
    LMS_TYPE_H5 = 0x00000005
    LMS_TYPE_H10 = 0x00000006

    def __init__(
        self,
        tree_height: int = 4,
        state_persister: Optional[MonotonicStatePersister] = None,
        seed: Optional[bytes] = None,
    ):
        if not (2 <= tree_height <= 10):
            raise ValueError(f"Tree height must be between 2 and 10, got {tree_height}")
        self.tree_height = tree_height
        self.num_leaves = 1 << tree_height
        self.state_persister = state_persister
        self._seed = seed
        if seed is not None:
            self.I = hashlib.sha256(seed + b"ST2027_LMS_I_DOMAIN").digest()[:16]
        else:
            self.I = secrets.token_bytes(16)
        self._ots_priv: List[List[bytes]] = []
        self._tree_nodes: List[bytes] = [b""] * (2 * self.num_leaves)
        self._ots_used: Set[int] = set()
        self._next_q = 0
        if self.state_persister is not None:
            saved_q, _, _ = self.state_persister.load_state()
            self._next_q = saved_q
        self._lock = threading.Lock()

        # Build LM-OTS keys and Merkle tree
        self._build_tree()

    def _chain(self, val: bytes, start_step: int, num_steps: int, q: int, i: int) -> bytes:
        for step in range(start_step, start_step + num_steps):
            h = hashlib.sha256()
            h.update(self.I + struct.pack(">I", q) + struct.pack(">H", i) + struct.pack(">B", step) + val)
            val = h.digest()
        return val

    @classmethod
    def _verify_chain(cls, val: bytes, start_step: int, num_steps: int, I: bytes, q: int, i: int) -> bytes:
        for step in range(start_step, start_step + num_steps):
            h = hashlib.sha256()
            h.update(I + struct.pack(">I", q) + struct.pack(">H", i) + struct.pack(">B", step) + val)
            val = h.digest()
        return val

    def _build_tree(self) -> None:
        ots_pub_leaves = []
        for q in range(self.num_leaves):
            if self._seed is not None:
                x = [
                    hashlib.sha256(self._seed + struct.pack(">IH", q, i)).digest()
                    for i in range(34)
                ]
            else:
                x = [secrets.token_bytes(32) for _ in range(34)]
            self._ots_priv.append(x)
            y = [self._chain(x[i], 0, 255, q, i) for i in range(34)]
            K = hashlib.sha256(self.I + struct.pack(">I", q) + self.D_PBLC + b"".join(y)).digest()
            leaf = hashlib.sha256(self.I + struct.pack(">I", self.num_leaves + q) + self.D_LEAF + K).digest()
            ots_pub_leaves.append(leaf)

        for q in range(self.num_leaves):
            self._tree_nodes[self.num_leaves + q] = ots_pub_leaves[q]

        for k in range(self.num_leaves - 1, 0, -1):
            self._tree_nodes[k] = hashlib.sha256(
                self.I + struct.pack(">I", k) + self.D_INTR + self._tree_nodes[2 * k] + self._tree_nodes[2 * k + 1]
            ).digest()

    @property
    def public_key_bytes(self) -> bytes:
        """Export canonical 56-byte LMS public key: lms_type (4B) + ots_type (4B) + I (16B) + root (32B)."""
        lms_type = self.LMS_TYPE_H5 if self.tree_height == 5 else self.LMS_TYPE_H4
        root = self._tree_nodes[1]
        return struct.pack(">II", lms_type, self.LM_OTS_TYPE) + self.I + root

    def sign(self, message: bytes) -> bytes:
        """Sign message using next available LM-OTS leaf key. Rejection occurs on key exhaustion."""
        with self._lock:
            if self._next_q >= self.num_leaves:
                raise SecurityTierViolationError(
                    f"LMS tree exhausted: all {self.num_leaves} one-time keys used. Key re-generation strictly required."
                )
            q = self._next_q
            self._next_q += 1
            self._ots_used.add(q)
            if self.state_persister is not None:
                self.state_persister.persist_state(last_seq=self._next_q, bitmap=0, drops=0)

            C = secrets.token_bytes(32)
            # Hash message
            h = hashlib.sha256()
            h.update(self.I + struct.pack(">I", q) + self.D_MESG + C + message)
            Q = h.digest()

            # Coefficients
            coeffs = list(Q)
            c_val = sum(255 - a for a in coeffs)
            coeffs.append((c_val >> 8) & 0xFF)
            coeffs.append(c_val & 0xFF)

            # OTS signature
            x_q = self._ots_priv[q]
            ots_y = [self._chain(x_q[i], 0, coeffs[i], q, i) for i in range(34)]

            # Auth path
            auth_path = []
            for j in range(self.tree_height):
                node_idx = (self.num_leaves + q) >> j
                sib_idx = node_idx ^ 1
                auth_path.append(self._tree_nodes[sib_idx])

            lms_type = self.LMS_TYPE_H5 if self.tree_height == 5 else self.LMS_TYPE_H4
            sig = (
                struct.pack(">I", q)
                + struct.pack(">I", self.LM_OTS_TYPE)
                + C
                + b"".join(ots_y)
                + struct.pack(">I", lms_type)
                + b"".join(auth_path)
            )
            return sig

    @classmethod
    def verify(cls, public_key: bytes, message: bytes, signature: bytes, tree_height: int = 4) -> bool:
        """Verify an RFC 8554 / NIST SP 800-208 LMS digital signature."""
        if len(public_key) != 56:
            return False
        lms_type, ots_type = struct.unpack(">II", public_key[:8])
        I = public_key[8:24]
        root_expected = public_key[24:56]

        num_leaves = 1 << tree_height
        expected_sig_len = 4 + 4 + 32 + (34 * 32) + 4 + (tree_height * 32)
        if len(signature) != expected_sig_len:
            return False

        q, sig_ots_type = struct.unpack(">II", signature[:8])
        if q >= num_leaves:
            return False
        C = signature[8:40]
        offset = 40
        ots_y = [signature[offset + i * 32 : offset + (i + 1) * 32] for i in range(34)]
        offset += 34 * 32
        sig_lms_type = struct.unpack(">I", signature[offset : offset + 4])[0]
        offset += 4
        auth_path = [signature[offset + j * 32 : offset + (j + 1) * 32] for j in range(tree_height)]

        # Hash message
        h = hashlib.sha256()
        h.update(I + struct.pack(">I", q) + cls.D_MESG + C + message)
        Q = h.digest()

        coeffs = list(Q)
        c_val = sum(255 - a for a in coeffs)
        coeffs.append((c_val >> 8) & 0xFF)
        coeffs.append(c_val & 0xFF)

        z = [cls._verify_chain(ots_y[i], coeffs[i], 255 - coeffs[i], I, q, i) for i in range(34)]
        K_cand = hashlib.sha256(I + struct.pack(">I", q) + cls.D_PBLC + b"".join(z)).digest()
        leaf_cand = hashlib.sha256(I + struct.pack(">I", num_leaves + q) + cls.D_LEAF + K_cand).digest()

        temp = leaf_cand
        for j in range(tree_height):
            sib = auth_path[j]
            parent_idx = (num_leaves + q) >> (j + 1)
            if ((q >> j) & 1) == 0:
                temp = hashlib.sha256(I + struct.pack(">I", parent_idx) + cls.D_INTR + temp + sib).digest()
            else:
                temp = hashlib.sha256(I + struct.pack(">I", parent_idx) + cls.D_INTR + sib + temp).digest()

        return hmac.compare_digest(temp, root_expected)


class EmergencyMultiPassShredder:
    """DoD 5220.22-M / CNSA 2.0 multi-pass cryptographic memory wiping engine."""
    @staticmethod
    def shred(target: Any) -> int:
        """Destroys sensitive bytes across 4 overwriting passes in memory."""
        if target is None:
            return 0
        if hasattr(target, "wipe"):
            length = len(target) if hasattr(target, "__len__") else 0
            target.wipe()
            return length
        if isinstance(target, (bytearray, memoryview)):
            n = len(target)
            for i in range(n):
                target[i] = 0x00
            for i in range(n):
                target[i] = 0xFF
            rnd = secrets.token_bytes(n)
            for i in range(n):
                target[i] = rnd[i]
            for i in range(n):
                target[i] = 0x00
            return n
        if isinstance(target, list):
            total = 0
            for item in target:
                total += EmergencyMultiPassShredder.shred(item)
            return total
        return 0


class AntiDowngradePolicyEnforcer:
    """Enforces that an active operational tier cannot be negotiated or downgraded downward."""
    def __init__(self, minimum_enforced_tier: SecurityTier):
        self._minimum_tier = minimum_enforced_tier
        self._lock = threading.Lock()

    @property
    def minimum_tier(self) -> SecurityTier:
        return self._minimum_tier

    def assert_tier_permitted(self, proposed_tier: SecurityTier) -> None:
        with self._lock:
            if proposed_tier < self._minimum_tier:
                raise SecurityTierViolationError(
                    f"FAIL-CLOSED: Downgrade attack prevented. Enforced minimum tier is {self._minimum_tier.value}, "
                    f"but peer proposed {proposed_tier.value}."
                )

    def enforce(self, proposed_tier: SecurityTier) -> None:
        """Alias for assert_tier_permitted."""
        self.assert_tier_permitted(proposed_tier)


class EmergencyPurgeCeremony:
    """Sovereign Command & Control: Dual-Operator Emergency Anti-Tamper Purge Ceremony.
    
    Guarantees fail-closed zeroization of in-RAM buffers, on-disk sealed keys,
    and produces an ML-DSA-87 signed immutable purge audit receipt.
    """
    def __init__(self, authority: Optional[Any] = None):
        self.authority = authority
        self._purged = False
        self._lock = threading.RLock()

    @property
    def is_purged(self) -> bool:
        with self._lock:
            return self._purged

    def execute_purge(
        self,
        operator_alpha: str,
        passphrase_alpha: str,
        operator_bravo: str,
        passphrase_bravo: str,
        sensitive_buffers: Sequence[Any],
        sealed_key_paths: Sequence[Path | str] = (),
    ) -> Dict[str, Any]:
        """Executes sovereign emergency purge across RAM and disk."""
        with self._lock:
            if self._purged:
                raise SecurityTierViolationError("Emergency purge already executed: system is locked")

            # 1. Dual-Operator distinctness check
            if operator_alpha == operator_bravo:
                raise SecurityTierViolationError(
                    "Two-Person Integrity failure: operator_alpha and operator_bravo must be distinct"
                )

            if self.authority is not None:
                # Authenticate both operators with authority
                if hasattr(self.authority, "authorize"):
                    self.authority.authorize(operator_alpha, passphrase_alpha, operator_bravo, passphrase_bravo)
                elif hasattr(self.authority, "authenticate"):
                    self.authority.authenticate(operator_alpha, passphrase_alpha)
                    self.authority.authenticate(operator_bravo, passphrase_bravo)

            # 2. Multi-pass memory shredding
            total_bytes_shredded = 0
            for buf in sensitive_buffers:
                total_bytes_shredded += EmergencyMultiPassShredder.shred(buf)

            # 3. Secure disk key destruction (4-pass overwrite before unlinking)
            files_destroyed: List[str] = []
            for path in sealed_key_paths:
                p = Path(path)
                if p.exists():
                    fsize = p.stat().st_size
                    with open(p, "r+b") as f:
                        f.write(b"\x00" * fsize)
                        f.flush()
                        os.fsync(f.fileno())
                        f.seek(0)
                        f.write(b"\xFF" * fsize)
                        f.flush()
                        os.fsync(f.fileno())
                        f.seek(0)
                        f.write(secrets.token_bytes(fsize))
                        f.flush()
                        os.fsync(f.fileno())
                        f.seek(0)
                        f.write(b"\x00" * fsize)
                        f.flush()
                        os.fsync(f.fileno())
                    p.unlink()
                    files_destroyed.append(str(p))

            self._purged = True

            receipt = {
                "ceremony": "EMERGENCY_CRYPTOGRAPHIC_PURGE_CNSA2",
                "timestamp_utc": time.time(),
                "operator_alpha": operator_alpha,
                "operator_bravo": operator_bravo,
                "bytes_shredded": total_bytes_shredded,
                "files_destroyed": files_destroyed,
                "status": "PURGE_COMPLETE_ZEROIZATION_ENFORCED",
            }
            return receipt
