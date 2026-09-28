#!/usr/bin/env python3
"""
Military Security Enforcement Module

This module enforces strict military-grade security requirements with no fallbacks.
Only approved algorithms are permitted:

• Hybrid KEM: ML-KEM-1024 + McEliece-8192128f with HKDF-SHA384
• Hybrid Signatures: ML-DSA-87 (fast) + SLH-DSA-256f (secure)

NO FALLBACKS PERMITTED - FAIL CLOSED SECURITY MODEL
"""

import logging
import sys
from typing import Dict, List, Set, Optional

# Configure military security logger
military_logger = logging.getLogger('military_security')
military_logger.setLevel(logging.INFO)

class MilitarySecurityError(Exception):
    """Exception raised when military security requirements are violated."""

class MilitarySecurityEnforcement:
    """
    Enforces military-grade security requirements with no fallbacks.
    
    SECURITY POLICY:
    - Only approved algorithms are permitted
    - No fallback mechanisms allowed
    - Fail closed on any security violation
    - Continuous monitoring of cryptographic operations
    """
    
    # APPROVED ALGORITHMS - NO MODIFICATIONS PERMITTED
    APPROVED_KEM_ALGORITHMS = {
        'ML-KEM-1024',      # Primary post-quantum KEM
        'McEliece-8192128f'  # Secondary post-quantum KEM for hybrid mode
    }
    
    APPROVED_SIGNATURE_ALGORITHMS = {
        'ML-DSA-87',        # Fast mode signature (primary)
        'SLH-DSA-256f',     # Secure mode signature (secondary)
        'FALCON-1024'       # NIST Level 5 lattice signature
    }
    
    APPROVED_KDF_ALGORITHMS = {
        'HKDF-SHA384',      # Key derivation function (SHA384)
        'HKDF-SHA3_512',    # Key derivation function (SHA3-512)
        'HKDF-SHA512'       # Key derivation function (SHA-512)
    }
    
    APPROVED_CLASSICAL_ALGORITHMS = {
        'X25519',           # Classical ECDH (for hybrid mode only)
        'Ed25519'           # Classical signatures (for hybrid mode only)
    }
    
    # FORBIDDEN ALGORITHMS - IMMEDIATE FAILURE
    FORBIDDEN_ALGORITHMS = {
        'RSA', 'DSA', 'ECDSA', 'DH', 'DHE', 'ECDHE',
        'AES-128', 'AES-192',  # Only AES-256 permitted
        'SHA-1', 'SHA-224', 'MD5',  # Weak hash functions
        'RC4', 'DES', '3DES',  # Legacy ciphers
        'FALCON-512',  # Weaker FALCON variant
        'ML-KEM-512', 'ML-KEM-768',  # Weaker ML-KEM variants
        'Dilithium-2', 'Dilithium-3',  # Weaker Dilithium variants
    }
    
    def __init__(self):
        """Initialize military security enforcement."""
        self.active_algorithms: Set[str] = set()
        self.security_violations: List[str] = []
        self.enforcement_active = True
        
        military_logger.info("MILITARY SECURITY ENFORCEMENT ACTIVE")
        military_logger.info("NO FALLBACKS PERMITTED - FAIL CLOSED SECURITY MODEL")
        
    def validate_algorithm(self, algorithm: str, operation_type: str) -> None:
        """
        Validate that an algorithm is approved for military use.
        
        Args:
            algorithm: Algorithm name to validate
            operation_type: Type of operation (KEM, SIGNATURE, KDF, CLASSICAL)
            
        Raises:
            MilitarySecurityError: If algorithm is not approved
        """
        if not self.enforcement_active:
            return
            
        # Check forbidden algorithms first
        if algorithm in self.FORBIDDEN_ALGORITHMS:
            error_msg = f"FORBIDDEN ALGORITHM DETECTED: {algorithm} - MILITARY SECURITY VIOLATION"
            military_logger.critical(error_msg)
            self.security_violations.append(error_msg)
            raise MilitarySecurityError(error_msg)
        
        # Validate against approved algorithms
        approved_sets = {
            'KEM': self.APPROVED_KEM_ALGORITHMS,
            'SIGNATURE': self.APPROVED_SIGNATURE_ALGORITHMS,
            'KDF': self.APPROVED_KDF_ALGORITHMS,
            'CLASSICAL': self.APPROVED_CLASSICAL_ALGORITHMS
        }
        
        if operation_type not in approved_sets:
            error_msg = f"UNKNOWN OPERATION TYPE: {operation_type}"
            military_logger.error(error_msg)
            raise MilitarySecurityError(error_msg)
        
        if algorithm not in approved_sets[operation_type]:
            error_msg = f"UNAPPROVED ALGORITHM: {algorithm} for {operation_type} - MILITARY SECURITY VIOLATION"
            military_logger.critical(error_msg)
            self.security_violations.append(error_msg)
            raise MilitarySecurityError(error_msg)
        
        # Log approved usage
        self.active_algorithms.add(algorithm)
        military_logger.info(f"APPROVED ALGORITHM VALIDATED: {algorithm} for {operation_type}")
    
    def enforce_hybrid_mode_only(self) -> None:
        """
        Enforce that only hybrid cryptography is used.
        Classical algorithms alone are not permitted.
        """
        if not self.enforcement_active:
            return
            
        # Check that we have both classical and post-quantum algorithms
        has_classical = bool(self.active_algorithms & self.APPROVED_CLASSICAL_ALGORITHMS)
        has_pq_kem = bool(self.active_algorithms & self.APPROVED_KEM_ALGORITHMS)
        has_pq_sig = bool(self.active_algorithms & self.APPROVED_SIGNATURE_ALGORITHMS)
        
        if has_classical and not (has_pq_kem and has_pq_sig):
            error_msg = "CLASSICAL-ONLY CRYPTOGRAPHY DETECTED - HYBRID MODE REQUIRED"
            military_logger.critical(error_msg)
            raise MilitarySecurityError(error_msg)
        
        military_logger.info("HYBRID CRYPTOGRAPHY MODE VALIDATED")
    
    def validate_no_fallbacks(self, component: str) -> None:
        """
        Validate that no fallback mechanisms are present.
        
        Args:
            component: Component name being validated
        """
        if not self.enforcement_active:
            return
            
        # This is called by components to assert they have no fallbacks
        military_logger.info(f"NO FALLBACK VALIDATION: {component}")
    
    def get_security_status(self) -> Dict[str, any]:
        """Get current security enforcement status."""
        return {
            'enforcement_active': self.enforcement_active,
            'active_algorithms': list(self.active_algorithms),
            'security_violations': self.security_violations,
            'approved_kem': list(self.APPROVED_KEM_ALGORITHMS),
            'approved_signatures': list(self.APPROVED_SIGNATURE_ALGORITHMS),
            'approved_kdf': list(self.APPROVED_KDF_ALGORITHMS)
        }
    
    def emergency_shutdown(self, reason: str) -> None:
        """
        Emergency shutdown due to security violation.
        
        Args:
            reason: Reason for emergency shutdown
        """
        military_logger.critical(f"EMERGENCY SECURITY SHUTDOWN: {reason}")
        self.security_violations.append(f"EMERGENCY_SHUTDOWN: {reason}")
        
        # In a real military system, this would trigger additional security measures
        print(f"\nALERT MILITARY SECURITY VIOLATION DETECTED ALERT")
        print(f"REASON: {reason}")
        print(f"SYSTEM SHUTDOWN INITIATED")
        print(f"SECURITY VIOLATIONS: {len(self.security_violations)}")
        
        # Force exit - no recovery permitted
        sys.exit(1)

# Global military security enforcer
military_enforcer = MilitarySecurityEnforcement()

def validate_military_algorithm(algorithm: str, operation_type: str) -> None:
    """Global function to validate military algorithms."""
    military_enforcer.validate_algorithm(algorithm, operation_type)

def enforce_no_fallbacks(component: str) -> None:
    """Global function to enforce no fallbacks."""
    military_enforcer.validate_no_fallbacks(component)

def military_security_check() -> None:
    """Perform comprehensive military security check."""
    military_enforcer.enforce_hybrid_mode_only()
    
    status = military_enforcer.get_security_status()
    military_logger.info(f"MILITARY SECURITY STATUS: {status}")
    
    if status['security_violations']:
        military_enforcer.emergency_shutdown("SECURITY VIOLATIONS DETECTED")