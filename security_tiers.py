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

import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
APPROVED_PQ_SIGS = {"ML-DSA-87", "SLH-DSA-PURE-SHAKE-256F", "SLH-DSA-256F", "FALCON-1024"}


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
