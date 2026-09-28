#!/usr/bin/env python3
"""
Security Enhancements - Military Compatibility Layer
Superseded by enhanced_security_features.py for CNSA 2.0 / FIPS 140-3 compliance.
"""

from enhanced_security_features import (
    MilitarySecurityLevel as UltimateSecurityLevel,
    MilitarySecurityMetrics as UltimateSecurityMetrics,
    QuantumResistantProtection as QuantumSupremeProtection,
    MilitarySideChannelImmunity,
    MilitaryFaultInjectionResistance,
    MilitaryZeroKnowledgeProofs,
    MilitaryHomomorphicEncryption,
    MilitarySecurityOrchestrator as UltimateSecurityOrchestrator,
    get_military_security as get_ultimate_security,
    military_logger as ultimate_logger,
)

# Compatibility aliases
UltimateSideChannelImmunity = MilitarySideChannelImmunity
UltimateFaultInjectionResistance = MilitaryFaultInjectionResistance
UltimateZeroKnowledgeProofs = MilitaryZeroKnowledgeProofs
UltimateHomomorphicEncryption = MilitaryHomomorphicEncryption

__all__ = [
    "UltimateSecurityLevel",
    "UltimateSecurityMetrics",
    "QuantumSupremeProtection",
    "UltimateSideChannelImmunity",
    "UltimateFaultInjectionResistance",
    "UltimateZeroKnowledgeProofs",
    "UltimateHomomorphicEncryption",
    "UltimateSecurityOrchestrator",
    "get_ultimate_security",
    "ultimate_logger",
]